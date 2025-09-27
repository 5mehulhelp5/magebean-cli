<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class HttpCheck
{
    private Context $ctx;
    private int $transportOk = 0;
    private int $transportTotal = 0;

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
            'http_force_https_redirect'              => $this->forceHttpsRedirect($args),
            'http_has_hsts'                          => $this->hasHsts($args),
            'http_no_mixed_content'                  => $this->noMixedContent($args),
            'http_cookie_flags'                      => $this->cookieFlags($args),
            'http_no_directory_listing'              => $this->noDirectoryListing($args),
            'http_no_public_artifacts'               => $this->noPublicArtifacts($args),
            'http_no_stacktrace'                     => $this->noStacktrace($args),
            'http_no_xdebug_headers'                 => $this->noXdebugHeaders($args),
            'http_admin_path_heuristics'             => $this->adminPathHeuristics($args),
            'http_magento_fingerprint'               => $this->magentoFingerprint($args),

            'http_header_equals'                     => $this->headerEquals($args),
            'http_header_in'                         => $this->headerIn($args),
            'http_header_absent'                     => $this->headerAbsent($args),

            'http_clickjacking_protection'           => $this->clickjackingProtection($args),
            'http_csp_present_min'                   => $this->cspPresent($args),
            'http_csp_not_overly_permissive'         => $this->cspNotOverlyPermissive($args),

            'http_cors_no_wildcard_with_credentials' => $this->corsNoWildcardWithCreds($args),
            'http_cors_preflight_safe'               => $this->corsPreflightSafe($args),

            'http_tls_min_version'                   => $this->tlsMinVersion($args),
            'http_tls_cert_days_left'                => $this->tlsCertDaysLeft($args),
            'http_hsts_preload_ready'                => $this->hstsPreloadReady($args),

            'http_method_disallowed'                 => $this->methodDisallowed($args),
            'http_options_not_overly_verbose'        => $this->optionsNotVerbose($args),
            'http_server_banner_not_verbose'         => $this->serverBannerNotVerbose($args),

            'http_block_path'                        => $this->blockPath($args),
            'http_graphql_introspection_disabled'    => $this->graphqlIntrospectionDisabled($args),
            'http_rest_sensitive_endpoints_closed'   => $this->restSensitiveEndpointsClosed($args),

            'http_static_assets_deployed'            => $this->staticAssetsDeployed($args),
            'http_cache_signals'                     => $this->cacheSignals($args),
            'http_logs_protected'                    => $this->logsProtected($args),
            'http_csrf_form_key_signal'              => $this->csrfFormKeySignal($args),
            'http_no_vcs_misc'                       => $this->noVcsMisc($args),
            'http_third_party_links_https'           => $this->thirdPartyLinksHttps($args),
            'http_no_debug_endpoints'                => $this->noDebugEndpoints($args),
            'http_payment_tls_min'                   => $this->paymentTlsMin($args),

            default => [false, 'Unknown HttpCheck: ' . $name],
        };
    }

    public function getTransportCounts(): array
    {
        return [
            'ok'    => $this->transportOk,
            'total' => $this->transportTotal,
        ];
    }

    private function baseUrl(): string
    {
        $u = (string)$this->ctx->get('url', '');
        if ($u === '') return '';
        if (!preg_match('~^https?://~i', $u)) return '';
        return rtrim($u, '/');
    }

    private function bump(bool $ok): void
    {
        $this->transportTotal++;
        if ($ok) $this->transportOk++;
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
                $this->bump(false);
                return [null, '[UNKNOWN] HTTP error: ' . $err, ['url' => $url]];
            }
            $status   = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $hdrSize  = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $hdrRaw   = substr((string)$resp, 0, (int)$hdrSize);
            $body     = substr((string)$resp, (int)$hdrSize);
            $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            curl_close($ch);
            $this->bump(true);
            $headersAssoc = $this->parseHeaders($hdrRaw);
            return [true, '', ['status' => $status, 'headers' => $headersAssoc, 'body' => $body, 'final_url' => $finalUrl]];
        }

        // Fallback streams
        $opts = [
            'http' => [
                'method'        => $method,
                'header'        => implode("\r\n", $ctxHeaders),
                'ignore_errors' => true,
                'timeout'       => max(1, (int)ceil($timeoutMs / 1000)),
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
        if ($body === false) {
            $this->bump(false);
            return [null, '[UNKNOWN] HTTP error (stream)', ['url' => $url]];
        }
        $this->bump(true);
        return [true, '', ['status' => $status, 'headers' => $hdrs, 'body' => $body, 'final_url' => $url]];
    }

    private function parseHeaders(string $raw): array
    {
        // Combine duplicate headers; keep 'set-cookie' as array of all values.
        $out = [];
        foreach (preg_split("~\r?\n~", $raw) as $line) {
            if (strpos($line, ':') !== false) {
                [$k, $v] = array_map('trim', explode(':', $line, 2));
                $lk = strtolower($k);
                if ($lk === 'set-cookie') {
                    if (!isset($out[$lk])) $out[$lk] = [];
                    if (is_array($out[$lk])) $out[$lk][] = $v;
                    else $out[$lk] = [$out[$lk], $v];
                } else {
                    if (isset($out[$lk])) {
                        if (is_array($out[$lk])) $out[$lk][] = $v;
                        else $out[$lk] = [$out[$lk], $v];
                    } else {
                        $out[$lk] = $v;
                    }
                }
            }
        }
        return $out;
    }

    /** Safely get header value as string (use last when multiple) */
    private function hget(array $hdrs, string $key): string
    {
        $key = strtolower($key);
        if (!array_key_exists($key, $hdrs)) return '';
        $v = $hdrs[$key];
        if (is_array($v)) {
            $last = end($v);
            return is_string($last) ? $last : (string)$last;
        }
        return (string)$v;
    }

    private function forceHttpsRedirect(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];

        // Always test HTTP entrypoint (no redirect follow)
        $http = preg_replace('~^https://~i', 'http://', $base);
        if (!preg_match('~^http://~i', $http)) {
            $http = 'http://' . preg_replace('~^https?://~i', '', $base);
        }

        [$ok, $msg, $ev] = $this->fetch($http, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $status  = (int)($ev['status'] ?? 0);
        $headers = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $loc     = $this->hget($headers, 'location');

        $isRedirect = in_array($status, [301, 302, 307, 308], true) && stripos($loc, 'https://') === 0;

        $evidence = [
            'request_url' => $http,
            'status'      => $status,
            'location'    => $loc,
            'final_url'   => $ev['final_url'] ?? null,
        ];

        return [$isRedirect, $isRedirect ? 'HTTP redirected to HTTPS' : 'No HTTP→HTTPS redirect', $evidence];
    }

    private function hasHsts(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $h = $this->hget(array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER), 'strict-transport-security');
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
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $body = (string)($ev['body'] ?? '');
        // Only count mixed content in attributes or CSS url(), not arbitrary text/JS strings
        $bad = preg_match('~\b(?:href|src|action|data-src|formaction)\s*=\s*["\']http://~i', $body) === 1
            || preg_match('~url\(\s*http://~i', $body) === 1;

        return [!$bad, $bad ? 'Mixed content (http://) detected in markup' : 'No mixed content in markup', []];
    }

    private function cookieFlags(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $setCookies = $hdrs['set-cookie'] ?? [];
        if (!is_array($setCookies)) $setCookies = $setCookies !== '' ? [$setCookies] : [];

        if (!$setCookies) return [true, 'No cookies observed', []];

        // Only enforce flags on sensitive cookies
        $sensitive = [
            'phpsessid',
            'frontend',
            'private_content_version',
            'mage-cache-sessid',
            'store',
            'section_data_ids'
        ];

        $allOk = true;
        foreach ($setCookies as $cookie) {
            $parts = explode(';', (string)$cookie);
            if (count($parts) === 0) continue;
            [$name,] = array_map('trim', explode('=', $parts[0], 2));
            $lname = strtolower($name);

            // Only check sensitive cookies
            if (!in_array($lname, $sensitive, true)) continue;

            $flags = ' ' . strtolower((string)$cookie) . ' '; // pad to match ' secure'/' httponly'
            $hasSecure   = str_contains($flags, ' secure');
            $hasHttpOnly = str_contains($flags, ' httponly');
            $sameSite    = null;

            foreach ($parts as $p) {
                $p = trim($p);
                if (stripos($p, 'samesite=') === 0) {
                    $sameSite = strtolower(substr($p, 9));
                    break;
                }
            }

            $okFlags = false;
            if ($sameSite === 'none') {
                // SameSite=None must be with Secure
                $okFlags = $hasSecure && $hasHttpOnly;
            } else {
                // Lax/Strict (or missing) require Secure+HttpOnly at minimum
                $okFlags = $hasSecure && $hasHttpOnly && ($sameSite === null || in_array($sameSite, ['lax', 'strict'], true));
            }

            if (!$okFlags) {
                $allOk = false;
                break;
            }
        }

        return [$allOk, $allOk ? 'Sensitive cookies have Secure/HttpOnly/SameSite' : 'Cookie flags missing on sensitive cookies', []];
    }

    private function noDirectoryListing(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $paths = $args['paths'] ?? ['/media/', '/static/', '/errors/', '/var/'];
        foreach ($paths as $p) {
            [$ok, $msg, $ev] = $this->fetch($base . $p, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if ($ok === null) continue;
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

        $paths = $args['paths'] ?? [
            '/.git/HEAD',
            '/.env',
            '/composer.json',
            '/var/report/',
            '/var/log/exception.log',
            '/backup.zip',
            '/dump.sql',
        ];
        $timeout = (int)($args['timeout_ms'] ?? 8000);

        $allowStatuses = [401, 403, 404, 405, 410, 301, 302, 307, 308];

        foreach ($paths as $p) {
            [$ok, $msg, $ev] = $this->fetch($base . $p, 'GET', [], $timeout, false);
            if ($ok === null) continue;
            if (!$ok) continue;

            $status = (int)($ev['status'] ?? 0);
            $hdrs   = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
            $body   = (string)($ev['body'] ?? '');
            $ctype  = strtolower($this->hget($hdrs, 'content-type'));
            $server = strtolower($this->hget($hdrs, 'server'));

            if (in_array($status, $allowStatuses, true)) continue;

            if ($status === 200) {
                // WAF/CDN challenge -> UNKNOWN (do not count as FAIL)
                if (
                    (str_contains($server, 'cloudflare') || str_contains($server, 'akamai') || str_contains($server, 'fastly'))
                    && stripos($body, 'attention required') !== false
                ) {
                    return [null, '[UNKNOWN] WAF challenge on ' . $p, ['path' => $p, 'status' => $status]];
                }

                // Soft-404: small HTML with not found/forbidden/error
                $soft404 = false;
                if (str_contains($ctype, 'text/html')) {
                    $b = strtolower(substr($body, 0, 4096));
                    $soft404 = (strlen($body) < 8192) && (
                        str_contains($b, 'not found') || str_contains($b, 'forbidden') || str_contains($b, 'error')
                    );
                }
                if ($soft404) continue;

                // Real exposure signatures
                $exposed = false;
                if ($p === '/.git/HEAD') {
                    $exposed = (strncmp($body, 'ref: refs/', 9) === 0);
                } elseif ($p === '/.env') {
                    $lb = strtolower($body);
                    $exposed = (str_contains($lb, 'app_env=') || str_contains($lb, 'db_password=') || str_contains($lb, 'secret='));
                } elseif ($p === '/composer.json') {
                    $exposed = (preg_match('~^\s*\{\s*\"name\"\s*:\s*\"~', $body) === 1);
                } elseif (str_ends_with($p, '/') && stripos($body, 'Index of /') !== false) {
                    $exposed = true; // directory index
                } else {
                    if (preg_match('~^(PK\x03\x04|SQL|-- MySQL dump)~', $body) === 1) $exposed = true;
                }

                if ($exposed) {
                    return [false, 'Public artifact exposed: ' . $p, ['path' => $p, 'status' => $status]];
                }
            }
        }

        return [true, 'No public artifacts exposed', []];
    }

    private function noStacktrace(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];

        $targets = [];
        $targets[] = rtrim($base, '/'); // home
        // 404 thử nghiệm
        $targets[] = rtrim($base, '/') . '/__mb-not-exist-' . time();
        // (tuỳ chọn) trang search đơn giản
        $targets[] = rtrim($base, '/') . '/search?q=test';

        $pattern = '~(Stack trace:|Fatal error:|Uncaught (?:Exception|Error)|'
            . ' in /[A-Za-z0-9._/\-]+\.php on line \d+|'
            . ' at /[A-Za-z0-9._/\-]+\.php:\d+|'
            . '<b>(?:Warning|Notice)</b>:.{0,240} in /[A-Za-z0-9._/\-]+\.php on line \d+)~i';

        foreach ($targets as $u) {
            [$ok, $msg, $ev] = $this->fetch($u, 'GET', ['Accept: text/html'], (int)($args['timeout_ms'] ?? 8000), true);
            if ($ok !== true) continue;

            $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
            $ctype = strtolower($this->hget($hdrs, 'content-type'));
            if ($ctype && stripos($ctype, 'text/html') === false) continue;

            $body = (string)($ev['body'] ?? '');
            // Loại trừ trang WAF/challenge
            $waf = preg_match('~(cloudflare|akamai|fastly|sucuri|incapsula|varnish|attention required|error reference number)~i', substr($body, 0, 8192)) === 1;
            if ($waf) continue;

            if (preg_match($pattern, $body) === 1) {
                return [false, 'Error/stack trace visible on pages', ['url' => $u]];
            }
        }

        return [true, 'No error traces observed', []];
    }


    private function noXdebugHeaders(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $keys = is_array($h) ? array_keys($h) : [];
        $badKeys = array_filter($keys, fn($k) => str_contains((string)$k, 'x-debug') || str_contains((string)$k, 'x-phpdebug') || str_contains((string)$k, 'xdebug'));
        $ok2 = empty($badKeys);
        return [$ok2, $ok2 ? 'No debug headers' : 'Debug headers present: ' . implode(', ', $badKeys), []];
    }

    private function adminPathHeuristics(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $candidates = $args['paths'] ?? ['/admin/', '/backend/', '/index.php/admin/'];
        foreach ($candidates as $p) {
            [$ok, $msg, $ev] = $this->fetch($base . rtrim($p, '/') . '/', 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if ($ok === null) continue;
            if (!$ok) continue;

            $status = (int)($ev['status'] ?? 0);
            $b = strtolower((string)($ev['body'] ?? ''));

            // 401/403 -> treated as protected
            if (in_array($status, [401, 403], true)) continue;

            // Consider exposed only when 200 + strong admin login signals
            $strong =
                (str_contains($b, 'name="login[username]"') || str_contains($b, 'name="login[password]"')) ||
                preg_match('~<title>.*admin.*</title>~i', $b) === 1 ||
                str_contains($b, 'Magento Admin');

            if ($status === 200 && $strong) {
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
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $body = (string)($ev['body'] ?? '');

        $headerHit = isset($hdrs['x-magento-tags']) || isset($hdrs['x-magento-cache-debug']);
        $bodyHit   = preg_match('~mage-cache-storage|/static/version\d+/|/static/_cache/merged/|Luma-Icons\.(?:woff2|woff|ttf)~i', $body) === 1
            || preg_match('~/static/frontend/[^"]+/(?:[a-z]{2}_[A-Z]{2}|en_[a-z]{2})/~i', $body) === 1;

        $hit = $headerHit || $bodyHit;
        return [$hit, $hit ? 'Magento fingerprint detected' : 'No Magento fingerprint', []];
    }

    // === Additional generic header checks ===
    private function headerEquals(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $header = strtolower((string)($args['header'] ?? ''));
        $expected = (string)($args['equals'] ?? '');
        if ($header === '' || $expected === '') return [null, '[UNKNOWN] Missing header/equals', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $val = $this->hget($hdrs, $header);
        $pass = strcasecmp($val, $expected) === 0;
        return [$pass, $pass ? "{$header}={$expected}" : "Header {$header} is '" . ($val !== '' ? $val : '<absent>') . "'", $ev];
    }

    private function headerIn(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $header = strtolower((string)($args['header'] ?? ''));
        $allowed = (array)($args['allowed'] ?? []);
        if ($header === '' || !$allowed) return [null, '[UNKNOWN] Missing header/allowed', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        if (!array_key_exists($header, $hdrs)) return [false, "Header {$header} absent", $ev];
        $val = $this->hget($hdrs, $header);
        $pass = false;
        foreach ($allowed as $a) {
            if (strcasecmp($val, (string)$a) === 0) {
                $pass = true;
                break;
            }
        }
        return [$pass, $pass ? "Header ok: {$header}={$val}" : "Header {$header} not in allowed list ({$val})", $ev];
    }

    private function headerAbsent(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $header = strtolower((string)($args['header'] ?? ''));
        if ($header === '') return [null, '[UNKNOWN] Missing header', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $absent = !array_key_exists($header, $hdrs);
        return [$absent, $absent ? "Header {$header} absent" : "Header {$header} present", $ev];
    }

    // === Security headers / policies ===
    private function clickjackingProtection(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $xfo = strtolower($this->hget($h, 'x-frame-options'));
        $csp = $this->hget($h, 'content-security-policy');
        $pass = false;
        if ($xfo !== '' && $xfo !== 'allowall') $pass = true;
        if (!$pass && $csp !== '') {
            $pass = (bool)preg_match('~frame-ancestors\s+([^;]+)~i', $csp) && !preg_match('~frame-ancestors\s+\*~i', $csp);
        }
        return [$pass, $pass ? 'Clickjacking protection present' : 'No X-Frame-Options or CSP frame-ancestors', $ev];
    }

    private function cspPresent(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $csp = trim($this->hget($h, 'content-security-policy'));
        $pass = ($csp !== '');
        return [$pass, $pass ? 'CSP present' : 'CSP header absent', $ev];
    }

    private function cspNotOverlyPermissive(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $csp = strtolower($this->hget($h, 'content-security-policy'));
        if ($csp === '') return [false, 'CSP header absent', $ev];

        $hasNonce = str_contains($csp, 'nonce-') || str_contains($csp, 'sha256-') || str_contains($csp, 'sha384-');
        $bad = (str_contains($csp, "default-src *")
            || (substr_count($csp, "unsafe-inline") > 0 && !$hasNonce)
            || substr_count($csp, "unsafe-eval") > 0);

        return [!$bad, !$bad ? 'CSP looks reasonable' : 'CSP overly permissive', $ev];
    }

    private function corsNoWildcardWithCreds(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $acao = strtolower($this->hget($h, 'access-control-allow-origin'));
        $acac = strtolower($this->hget($h, 'access-control-allow-credentials'));
        $bad = ($acao == '*' && $acac == 'true');
        return [!$bad, !$bad ? 'CORS ok' : 'CORS wildcard with credentials=true', $ev];
    }

    private function corsPreflightSafe(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];
        // Real preflight with Origin + Access-Control-Request-Method
        $headers = [
            'Origin: https://example.com',
            'Access-Control-Request-Method: POST',
            'Access-Control-Request-Headers: Content-Type'
        ];
        [$ok, $msg, $ev] = $this->fetch($base, 'OPTIONS', $headers, (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] OPTIONS not allowed', $ev];

        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $allow = strtolower($this->hget($h, 'access-control-allow-methods'));
        $bad = ($allow == '*');
        return [!$bad, !$bad ? 'OPTIONS looks safe' : 'OPTIONS allows * methods', $ev];
    }

    // === TLS / cert ===
    private function tlsMinVersion(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];

        $host = (string)parse_url($base, PHP_URL_HOST);
        if ($host === '') return [null, '[UNKNOWN] Invalid host', []];

        $probe = $this->probeTlsWithNmap($host, (int)($args['timeout_s'] ?? 10));
        if (empty($probe['ok'])) {
            return [null, '[UNKNOWN] TLS probing requires nmap', ['host' => $host, 'err' => $probe['err'] ?? '']];
        }

        $legacy = (array)$probe['legacy'];
        $hasLegacy = !empty($legacy['tls1.0']) || !empty($legacy['tls1.1']);
        $pass = !$hasLegacy;
        $msg  = $pass ? 'TLS < 1.2 disabled (nmap)' : 'Legacy TLS (1.0/1.1) still accepted (nmap)';

        return [$pass, $msg, ['host' => $host, 'legacy' => $legacy]];
    }


    private function tlsCertDaysLeft(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];
        $host = (string)parse_url($base, PHP_URL_HOST);
        if ($host === '') return [null, '[UNKNOWN] Invalid host', []];

        $context = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'SNI_enabled' => true]]);
        $client = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context);
        if (!$client) return [null, '[UNKNOWN] TLS connect failed', []];
        $params = stream_context_get_params($client);
        @fclose($client);
        $x = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$x) return [null, '[UNKNOWN] No certificate', []];
        $arr = openssl_x509_parse($x);
        $validTo = (int)($arr['validTo_time_t'] ?? 0);
        if ($validTo <= 0) return [null, '[UNKNOWN] No validTo', []];
        $days = (int)floor(($validTo - time()) / 86400);
        $minDays = (int)($args['min_days'] ?? 15);
        $pass = $days >= $minDays;
        return [$pass, $pass ? "Cert valid ~{$days} days" : "Cert expires in {$days} days", []];
    }

    private function hstsPreloadReady(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $hst = strtolower($this->hget($h, 'strict-transport-security'));
        $hasSub = str_contains($hst, 'includesubdomains');
        $hasPre = str_contains($hst, 'preload');
        preg_match('~max-age=(\d+)~', $hst, $m);
        $maxAge = (int)($m[1] ?? 0);
        $min = (int)($args['min_max_age'] ?? 31536000);
        $reqSub = (bool)($args['require_include_subdomains'] ?? true);
        $reqPre = (bool)($args['require_preload'] ?? true);
        $pass = ($maxAge >= $min) && (!$reqSub || $hasSub) && (!$reqPre || $hasPre);
        return [$pass, $pass ? 'HSTS preload-ready' : 'HSTS not preload-ready', $ev];
    }

    // === Methods & misc ===
    private function methodDisallowed(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];
        $method = strtoupper((string)($args['method'] ?? 'TRACE'));
        [$ok, $msg, $ev] = $this->fetch($base, $method, [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] Method not allowed', $ev];
        $status = (int)($ev['status'] ?? 0);
        $pass = !in_array($status, [200, 202], true);
        return [$pass, $pass ? "{$method} not allowed" : "{$method} allowed", $ev];
    }

    private function optionsNotVerbose(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'OPTIONS', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] OPTIONS not allowed', $ev];
        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $allow = strtolower($this->hget($h, 'allow'));
        $bad = (bool)preg_match('~\b(put|delete|trace)\b~', $allow);
        return [!$bad, !$bad ? 'OPTIONS ok' : 'OPTIONS reveals unsafe methods', $ev];
    }

    private function serverBannerNotVerbose(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $srv = $this->hget($h, 'server');
        $bad = (bool)preg_match('~/\d~', $srv);
        return [!$bad, !$bad ? 'Server banner ok' : "Server banner verbose: {$srv}", $ev];
    }

    private function blockPath(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];
        $paths = (array)($args['paths'] ?? []);
        $allowed = (array)($args['allowed_status'] ?? [404, 403, 401, 302, 301]);
        $timeout = (int)($args['timeout_ms'] ?? 8000);
        if (!$paths) return [null, '[UNKNOWN] No paths', []];
        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], $timeout, false);
            if ($ok === null) continue;
            if (!$ok) continue;
            $st = (int)($ev['status'] ?? 0);
            if (!in_array($st, $allowed, true)) {
                return [false, "Path {$p} status {$st}", $ev];
            }
        }
        return [true, 'Paths blocked/hidden', []];
    }

    private function graphqlIntrospectionDisabled(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];
        $path = (string)($args['path'] ?? '/graphql');
        $url = rtrim($base, '/') . $path;
        $query = '{"query":"query IntrospectionQuery { __schema { types { name } } }"}';
        $headers = ['Content-Type: application/json'];
        [$ok, $msg, $ev] = $this->fetch($url, 'POST', $headers, (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] GraphQL endpoint not responding', $ev];
        $body = (string)($ev['body'] ?? '');
        $hasSchema = str_contains($body, '__schema');
        return [!$hasSchema, !$hasSchema ? 'Introspection disabled' : 'Introspection enabled', $ev];
    }

    private function restSensitiveEndpointsClosed(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];
        $paths = (array)($args['paths'] ?? []);
        $timeout = (int)($args['timeout_ms'] ?? 8000);
        if (!$paths) return [null, '[UNKNOWN] No paths', []];
        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], $timeout, false);
            if ($ok === null) continue;
            if (!$ok) continue;
            $st = (int)($ev['status'] ?? 0);
            if ($st === 200) {
                return [false, "Sensitive endpoint {$p} accessible (200)", $ev];
            }
        }
        return [true, 'Sensitive endpoints not publicly accessible', []];
    }

    // === Hygiene & assets ===
    private function staticAssetsDeployed(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $body = strtolower((string)($ev['body'] ?? ''));
        $hits = 0;
        if (preg_match('~/static/version\d+/~', $body)) $hits++;
        if (preg_match('~/static/_cache/merged/~', $body)) $hits++;
        if (preg_match('~/static/frontend/[^"]+/(en_[a-z]{2}|[a-z]{2}_[A-Z]{2})/~', $body)) $hits++;
        if (preg_match('~luma-icons\.(woff2|woff|ttf)~', $body)) $hits++;
        $pass = $hits >= 2; // cần >=2 tín hiệu để chắc hơn
        return [$pass, $pass ? 'Static assets deployed/versioned' : 'No strong static asset signals', $ev];
    }

    private function cacheSignals(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        // First fetch
        [$ok1, $msg1, $ev1] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok1 === null) return [null, $msg1, $ev1];
        if (!$ok1) return [false, $msg1, $ev1];

        $h1 = array_change_key_case((array)($ev1['headers'] ?? []), CASE_LOWER);
        $age1 = (int)preg_replace('~\D+~', '', $this->hget($h1, 'age')) ?: 0;
        $xc1 = $this->hget($h1, 'x-cache');
        $via1 = $this->hget($h1, 'via');

        // Second fetch
        [$ok2, $msg2, $ev2] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok2 === null) return [null, $msg2, $ev1];
        if (!$ok2) return [false, $msg2, $ev1];

        $h2 = array_change_key_case((array)($ev2['headers'] ?? []), CASE_LOWER);
        $age2 = (int)preg_replace('~\D+~', '', $this->hget($h2, 'age')) ?: 0;
        $xc2 = $this->hget($h2, 'x-cache');
        $via2 = $this->hget($h2, 'via');

        $hits = 0;
        if ($age1 > 0 || $age2 > 0) $hits++;
        if ($age2 > $age1) $hits++;
        if (stripos($xc1 . $xc2, 'hit') !== false) $hits++;
        if (stripos($via1 . $via2, 'varnish') !== false) $hits++;

        $pass = $hits >= 1;
        return [$pass, $pass ? 'Cache/FPC signals present' : 'No cache/FPC signals', $ev2];
    }

    private function logsProtected(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];

        $paths = ['/var/log/', '/var/report/'];
        $allowStatuses = [401, 403, 404, 405, 410, 301, 302, 307, 308];
        $timeout = (int)($args['timeout_ms'] ?? 8000);

        $attempted = 0;
        $reachable = 0;
        $evidence  = [];

        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], $timeout, false);
            $attempted++;

            if ($ok === null) { // lỗi transport (UNKNOWN)
                $evidence[] = ['path' => $p, 'status' => 'unknown'];
                continue;
            }
            if (!$ok) { // fetch lỗi (timeout, TLS, v.v.)
                $evidence[] = ['path' => $p, 'status' => 'error'];
                continue;
            }

            $reachable++;
            $st = (int)($ev['status'] ?? 0);
            $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
            $ctype = strtolower($this->hget($hdrs, 'content-type'));
            $body  = (string)($ev['body'] ?? '');

            $evidence[] = ['path' => $p, 'status' => $st];

            // Các status coi như đã được bảo vệ
            if (in_array($st, $allowStatuses, true)) continue;

            if ($st === 200) {
                // Soft-404/forbidden dạng HTML nhỏ => coi như bảo vệ
                if (str_contains($ctype, 'text/html')) {
                    $b = strtolower(substr($body, 0, 4096));
                    $soft404 = (strlen($body) < 8192) && (
                        str_contains($b, 'not found') || str_contains($b, 'forbidden') || str_contains($b, 'error')
                    );
                    if ($soft404) continue;

                    // Directory index
                    if (stripos($body, 'Index of /') !== false) {
                        return [false, "{$p} directory index accessible", $ev];
                    }
                }

                // Heuristic: body có link/định danh file log/report
                if (preg_match('~\.(log|xml|txt|html|csv)(\?|")?~i', substr($body, 0, 8192)) === 1) {
                    return [false, "{$p} appears to expose logs/reports", $ev];
                }
            }
            // Các status khác: tiếp tục thử path khác
        }

        // Không path nào phản hồi được -> UNKNOWN chứ không PASS
        if ($reachable === 0) {
            return [null, '[UNKNOWN] Unable to verify logs/report paths (no HTTP response)', [
                'attempted' => $attempted,
                'evidence'  => $evidence
            ]];
        }

        return [true, 'Application logs/reports not publicly accessible', [
            'attempted' => $attempted,
            'evidence'  => $evidence
        ]];
    }


    private function csrfFormKeySignal(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $body = strtolower((string)($ev['body'] ?? ''));
        $has = (bool)preg_match('~name=["\\\']form_key["\\\']~i', $body);
        return [$has, $has ? 'form_key present in forms' : 'No form_key signal on homepage', $ev];
    }

    private function noVcsMisc(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $paths = ['/.git/HEAD', '/.svn/entries', '/.hg/', '/.DS_Store', '/composer.json', '/app/etc/env.php'];
        $allowStatuses = [401, 403, 404, 405, 410, 301, 302, 307, 308];

        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if ($ok === null) continue;
            if (!$ok) continue;

            $st = (int)($ev['status'] ?? 0);
            if (in_array($st, $allowStatuses, true)) continue;

            if ($st === 200) {
                $body  = (string)($ev['body'] ?? '');
                if ($p === '/composer.json' && preg_match('~^\s*\{\s*\"name\"\s*:\s*\"~', $body) === 1) {
                    return [false, "Artifact exposed: {$p}", $ev];
                }
                if (stripos($body, 'Index of /') !== false) {
                    return [false, "Artifact exposed: {$p}", $ev];
                }
            }
        }
        return [true, 'No VCS/misc artifacts exposed', []];
    }

    private function thirdPartyLinksHttps(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $body = (string)($ev['body'] ?? '');
        $clean = preg_replace('~<!--.*?-->~s', '', $body) ?? $body;
        $bad = (bool)preg_match('~\b(?:href|src|action)\s*=\s*["\']http://~i', $clean);
        return [!$bad, !$bad ? '3rd-party links use HTTPS' : 'Found http:// link in markup', $ev];
    }

    private function noDebugEndpoints(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $paths = ['/phpinfo.php', '/debug', '/adminer.php', '/errors/', '/setup/'];
        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if ($ok === null) continue;
            if (!$ok) continue;
            $st = (int)($ev['status'] ?? 0);
            if ($st === 200) return [false, "Debug/diagnostic path open: {$p}", $ev];
        }
        return [true, 'No debug endpoints publicly accessible', []];
    }

    private function paymentTlsMin(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Missing URL in context', []];

        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], 8000, true);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] Unable to fetch homepage', $ev];

        $html = (string)($ev['body'] ?? '');
        $origin = (string)parse_url($base, PHP_URL_HOST);

        $hosts = [];
        if (preg_match_all('#https?://([a-z0-9\.\-]+)(?:[:/][^\s"\'<]*)?#i', $html, $m)) {
            foreach ($m[1] as $h) {
                $h = strtolower($h);
                if ($h !== strtolower($origin)) $hosts[] = $h;
            }
        }
        $hosts = array_values(array_unique($hosts));
        if (empty($hosts)) return [true, 'No third-party endpoints to audit for TLS', []];

        // Yêu cầu có nmap
        $which = @trim((string)@shell_exec('command -v nmap 2>/dev/null'));
        if ($which === '') {
            return [null, '[UNKNOWN] TLS probing third-parties requires nmap', ['hosts' => $hosts]];
        }

        $weak = [];
        $evidences = [];
        foreach ($hosts as $h) {
            $probe = $this->probeTlsWithNmap($h, (int)($args['timeout_s'] ?? 10));
            if (empty($probe['ok'])) {
                $evidences[$h] = ['err' => $probe['err'] ?? 'n/a'];
                continue;
            }
            $legacy = (array)$probe['legacy'];
            $evidences[$h] = $legacy;
            if (!empty($legacy['tls1.0']) || !empty($legacy['tls1.1'])) $weak[] = $h;
        }

        if (empty($evidences)) return [null, '[UNKNOWN] No evidence collected', ['hosts' => $hosts]];

        $pass = empty($weak);
        $msg  = $pass ? 'Payment/3rd-party endpoints enforce TLS ≥ 1.2' : ('Legacy TLS accepted by: ' . implode(', ', $weak));
        return [$pass, $msg, ['hosts_checked' => $evidences]];
    }

    private function probeTlsWithNmap(string $host, int $timeout = 10): array
    {
        $host = trim($host);
        if ($host === '') return ['ok' => false, 'err' => 'empty host'];

        $which = @trim((string)@shell_exec('command -v nmap 2>/dev/null'));
        if ($which === '') return ['ok' => false, 'err' => 'nmap not found'];

        $cmd = sprintf(
            '%s --script ssl-enum-ciphers -p 443 %s 2>&1',
            escapeshellcmd($which),
            escapeshellarg($host)
        );
        $out = @shell_exec($cmd);
        if ($out === null || $out === '') return ['ok' => false, 'err' => 'empty nmap output'];



        // Helper: rút block cho 1 version, rồi xác định có cipher thật không
        $hasLegacy = function (string $out, string $verRegex): bool {
            // Lấy block từ "TLSvX.Y:" đến ngay trước dòng bắt đầu bằng "|   TLS" kế tiếp hoặc hết file
            if (!preg_match('/' . $verRegex . ':(.*?)(?:(?:\r?\n)\|\s*TLS|$)/si', $out, $m)) {
                // Không có section => coi như tắt version này
                return false;
            }
            $blk = $m[1];

            // Nếu block chứa câu "No supported ciphers found" -> không legacy
            if (stripos($blk, 'No supported ciphers found') !== false) return false;

            // Có cipher thực khi thấy "ciphers:" hoặc ít nhất một dòng cipher bắt đầu bằng "|       TLS_"
            if (preg_match('/\|\s*ciphers\s*:/i', $blk)) return true;
            if (preg_match('/\|\s+TLS[_A-Z0-9\-]+/i', $blk)) return true;

            // Nếu block hoàn toàn rỗng/không có chỉ dấu cipher -> không coi là legacy
            return false;
        };

        $has10 = $hasLegacy($out, 'TLSv?1\\.0');
        $has11 = $hasLegacy($out, 'TLSv?1\\.1');

        return ['ok' => true, 'legacy' => ['tls1.0' => $has10, 'tls1.1' => $has11], 'raw' => $out];
    }
}
