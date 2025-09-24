<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class HttpCheck
{
    private Context $ctx;
    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }
    public function stub(array $args): array
    {
        return [true, 'HttpCheck stub PASS'];
    }
    /** Dispatch http_* checks */
    public function dispatch(string $name, array $args): array
    {
        return match ($name) {
            'http_force_https_redirect'     => $this->forceHttpsRedirect($args),
            'http_has_hsts'                 => $this->hasHsts($args),
            'http_no_mixed_content'         => $this->noMixedContent($args),
            'http_cookie_flags'             => $this->cookieFlags($args),
            'http_no_directory_listing'     => $this->noDirectoryListing($args),
            'http_no_public_artifacts'      => $this->noPublicArtifacts($args),
            'http_no_stacktrace'            => $this->noStacktrace($args),
            'http_no_xdebug_headers'        => $this->noXdebugHeaders($args),
            'http_admin_path_heuristics'    => $this->adminPathHeuristics($args),
            'http_magento_fingerprint'      => $this->magentoFingerprint($args),
            default => [false, 'Unknown HttpCheck: ' . $name],
        };
    }

    private function baseUrl(): string
    {
        $u = (string)$this->ctx->get('url', '');
        if ($u === '') return '';
        if (!preg_match('~^https?://~i', $u)) return '';
        return rtrim($u, '/');
    }

    private function fetch(string $url, string $method = 'GET', array $headers = [], int $timeoutMs = 8000, bool $follow = true): array
    {
        $ctxHeaders = [];
        foreach ($headers as $k => $v) $ctxHeaders[] = is_int($k) ? $v : ($k . ': ' . $v);
        // Prefer curl (if available) to capture headers + redirects
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, $timeoutMs);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $follow);
            curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Magebean-CLI/1.0');
            if ($ctxHeaders) curl_setopt($ch, CURLOPT_HTTPHEADER, $ctxHeaders);
            $resp = curl_exec($ch);
            if ($resp === false) {
                $err = curl_error($ch);
                curl_close($ch);
                return [false, 'HTTP error: ' . $err, ['url' => $url]];
            }
            $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $hdrSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $hdrRaw = substr((string)$resp, 0, (int)$hdrSize);
            $body = substr((string)$resp, (int)$hdrSize);
            $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            curl_close($ch);
            $headersAssoc = $this->parseHeaders($hdrRaw);
            return [true, '', ['status' => $status, 'headers' => $headersAssoc, 'body' => $body, 'final_url' => $finalUrl]];
        }
        // Fallback streams
        $opts = [
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $ctxHeaders),
                'ignore_errors' => true,
                'timeout' => max(1, (int)ceil($timeoutMs/1000)),
            ]
        ];
        $context = stream_context_create($opts);
        $body = @file_get_contents($url, false, $context);
        $hdrs = [];
        $status = 0;
        if (isset($http_response_header) && is_array($http_response_header)) {
            $hdrs = $this->parseHeaders(implode("\r\n", $http_response_header));
            if (preg_match('~HTTP/\S+\s+(\d{3})~', $http_response_header[0] ?? '', $m)) $status = (int)$m[1];
        }
        if ($body === false) return [false, 'HTTP error (stream)', ['url' => $url]];
        return [true, '', ['status' => $status, 'headers' => $hdrs, 'body' => $body, 'final_url' => $url]];
    }

    private function parseHeaders(string $raw): array
    {
        $out = [];
        foreach (preg_split("~\r?\n~", $raw) as $line) {
            if (strpos($line, ':') !== false) {
                [$k, $v] = array_map('trim', explode(':', $line, 2));
                $out[strtolower($k)] = $v;
            }
        }
        return $out;
    }

    private function forceHttpsRedirect(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $http = preg_replace('~^https://~i', 'http://', $base);
        if (!preg_match('~^http://~i', $http)) $http = 'http://' . preg_replace('~^https?://~i', '', $base);
        [$ok, $msg, $ev] = $this->fetch($http, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if (!$ok) return [false, $msg, $ev];
        $status = (int)($ev['status'] ?? 0);
        $final  = (string)($ev['final_url'] ?? '');
        $isRedirected = in_array($status, [301,302,307,308], true) && str_starts_with(strtolower($final), 'https://');
        return [$isRedirected, $isRedirected ? 'HTTP redirected to HTTPS' : 'No HTTP→HTTPS redirect', $ev];
    }

    private function hasHsts(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if (!$ok) return [false, $msg, $ev];
        $h = $ev['headers']['strict-transport-security'] ?? '';
        if ($h === '') return [false, 'HSTS header missing', ['observed' => $h]];
        if (preg_match('~max-age\s*=\s*(\d+)~i', $h, $m)) {
            $min = (int)($args['min_max_age'] ?? 15552000);
            $ok2 = ((int)$m[1] >= $min);
            return [$ok2, $ok2 ? 'HSTS present' : 'HSTS max-age too low', ['observed' => $h]];
        }
        return [false, 'HSTS header missing max-age', ['observed' => $h]];
    }

    private function noMixedContent(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if (!$ok) return [false, $msg, $ev];
        $body = (string)($ev['body'] ?? '');
        $found = preg_match('~http://[^\s"\']+~i', $body) === 1;
        return [!$found, $found ? 'Mixed content (http://) detected on homepage' : 'No mixed content on homepage', []];
    }

    private function cookieFlags(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if (!$ok) return [false, $msg, $ev];
        $headers = (array)($ev['headers'] ?? []);
        $cookies = [];
        foreach ($headers as $k => $v) {
            if (strtolower($k) === 'set-cookie') { $cookies = is_array($v) ? $v : [$v]; break; }
        }
        if (!$cookies) return [true, 'No cookies observed', []];
        $allOk = true;
        foreach ($cookies as $cookie) {
            $flags = strtolower((string)$cookie);
            $okf = str_contains($flags, 'secure') && str_contains($flags, 'httponly') && (str_contains($flags, 'samesite=lax') || str_contains($flags, 'samesite=strict'));
            if (!$okf) { $allOk = false; break; }
        }
        return [$allOk, $allOk ? 'Cookies have Secure/HttpOnly/SameSite' : 'Cookies missing security flags', []];
    }

    private function noDirectoryListing(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $paths = $args['paths'] ?? ['/media/','/static/','/errors/','/var/'];
        foreach ($paths as $p) {
            [$ok, $msg, $ev] = $this->fetch($base . $p, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if (!$ok) continue;
            $b = strtolower((string)($ev['body'] ?? ''));
            if (str_contains($b, 'index of /') || preg_match('~<title>\s*index of\s*/~i', $b)) {
                return [false, 'Directory listing enabled at ' . $p, ['path' => $p]];
            }
        }
        return [true, 'No directory listing in common paths', []];
    }

    private function noPublicArtifacts(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $paths = $args['paths'] ?? ['/.git/HEAD','/.env','/phpinfo.php','/composer.lock~','/dump.sql','/backup.zip'];
        foreach ($paths as $p) {
            [$ok, $msg, $ev] = $this->fetch($base . $p, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if (!$ok) continue;
            $status = (int)($ev['status'] ?? 0);
            if ($status === 200) return [false, 'Public artifact exposed: ' . $p, ['path' => $p]];
        }
        return [true, 'No public artifacts exposed', []];
    }

    private function noStacktrace(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if (!$ok) return [false, $msg, $ev];
        $b = (string)($ev['body'] ?? '');
        $has = preg_match('~(Stack trace:|Fatal error:|Warning:\s+|Notice:\s+|in\s+/.+?\.php\s+on\s+line\s+\d+)~i', $b) === 1;
        return [!$has, $has ? 'Error/stack trace visible on homepage' : 'No error traces observed', []];
    }

    private function noXdebugHeaders(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if (!$ok) return [false, $msg, $ev];
        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $bad = array_filter(array_keys($h), fn($k) => str_contains($k, 'x-debug') || str_contains($k, 'x-phpdebug') || str_contains($k, 'xdebug'));
        $ok2 = empty($bad);
        return [$ok2, $ok2 ? 'No debug headers' : 'Debug headers present: ' . implode(', ', $bad), []];
    }

    private function adminPathHeuristics(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $candidates = $args['paths'] ?? ['/admin/','/backend/','/index.php/admin/'];
        foreach ($candidates as $p) {
            [$ok, $msg, $ev] = $this->fetch($base . rtrim($p,'/').'/', 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if (!$ok) continue;
            $status = (int)($ev['status'] ?? 0);
            $b = strtolower((string)($ev['body'] ?? ''));
            if (in_array($status, [200, 401, 403], true) && (str_contains($b, 'admin') || str_contains($b, 'login'))) {
                return [false, 'Admin path appears exposed: ' . $p, ['path' => $p, 'status' => $status]];
            }
        }
        return [true, 'No obvious admin path exposure', []];
    }

    private function magentoFingerprint(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if (!$ok) return [false, $msg, $ev];
        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $body = (string)($ev['body'] ?? '');
        $hit = isset($hdrs['x-magento-tags']) || isset($hdrs['x-magento-cache-debug']) || preg_match('~mage-cache-storage|Magento~i', $body);
        return [$hit, $hit ? 'Magento fingerprint detected' : 'No Magento fingerprint', []];
    }
}
