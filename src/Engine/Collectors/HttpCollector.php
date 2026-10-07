<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;
/** Always fresh: repeated probes and transport counts retain their semantics. */
final class HttpCollector
{
    public function __construct(private readonly ?CollectionSession $session = null) {}
    public function fetch(string $url, string $method = 'GET', array $headers = [], int $timeoutMs = 8000, bool $follow = true, ?string $requestBody = null, ?callable $observe = null): array
    {
        $this->session?->checkpoint();
        $deadline = $this->session?->deadline();
        if ($deadline !== null) {
            $remaining = $deadline->remainingMilliseconds();
            if ($remaining === 0) throw new \Magebean\Engine\ScanDeadlineExceeded('Scan deadline exceeded before HTTP request.');
            $timeoutMs = $timeoutMs > 0 ? min($timeoutMs, $remaining) : $remaining;
        }
        $observe ??= static function (bool $ok): void {};
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
            if ($requestBody !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $requestBody);
            $resp = curl_exec($ch);
            if ($resp === false) {
                $err = curl_error($ch);
                curl_close($ch);
                $observe(false);
                return [null, '[UNKNOWN] HTTP error: ' . $err, ['url' => $url]];
            }
            $status   = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $hdrSize  = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $hdrRaw   = substr((string)$resp, 0, (int)$hdrSize);
            $body     = substr((string)$resp, (int)$hdrSize);
            $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            curl_close($ch);
            $observe(true);
            $headersAssoc = $this->parseHeaders($hdrRaw);
            return [true, '', ['status' => $status, 'headers' => $headersAssoc, 'body' => $body, 'final_url' => $finalUrl]];
        }

        // Fallback streams
        $opts = [
            'http' => [
                'method'        => $method,
                'header'        => implode("\r\n", $ctxHeaders),
                'ignore_errors' => true,
                'follow_location' => $follow ? 1 : 0,
                'max_redirects' => 5,
                'timeout'       => max(1, (int)ceil($timeoutMs / 1000)),
                'content'       => $requestBody ?? '',
            ]
        ];
        $context = stream_context_create($opts);
        $body = @file_get_contents($url, false, $context);
        $hdrs = [];
        $status = 0;
        $finalUrl = $url;
        if (isset($http_response_header) && is_array($http_response_header)) {
            $hdrs = $this->parseHeaders(implode("\r\n", $http_response_header));
            foreach ($http_response_header as $line) {
                if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $m)) $status = (int)$m[1];
                elseif ($follow && $status >= 300 && $status < 400 && stripos($line, 'Location:') === 0) {
                    $finalUrl = $this->redirectUrl($finalUrl, trim(substr($line, 9)));
                }
            }
        }
        if ($body === false) {
            $observe(false);
            return [null, '[UNKNOWN] HTTP error (stream)', ['url' => $url]];
        }
        $observe(true);
        return [true, '', ['status' => $status, 'headers' => $hdrs, 'body' => $body, 'final_url' => $finalUrl]];
    }
    /** Resolve each redirect hop, including relative Location values, for stream evidence. */
    private function redirectUrl(string $base, string $location): string
    {
        if (preg_match('~^https?://~i', $location)) return $location;
        $parts = parse_url($base);
        if (!is_array($parts) || !isset($parts['host'])) return $base;
        $scheme = (string)($parts['scheme'] ?? 'http');
        if (str_starts_with($location, '//')) return $scheme . ':' . $location;
        $origin = $scheme . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        $basePath = (string)($parts['path'] ?? '/');
        if (str_starts_with($location, '?')) return $origin . $basePath . $location;
        if (str_starts_with($location, '#')) return preg_replace('~#.*$~', '', $base) . $location;
        $relative = parse_url($location);
        if (!is_array($relative)) return $base;
        $path = (string)($relative['path'] ?? '');
        if (!str_starts_with($path, '/')) $path = substr($basePath, 0, (int)strrpos($basePath, '/') + 1) . $path;
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '..') array_pop($segments);
            elseif ($segment !== '.' && $segment !== '') $segments[] = $segment;
        }
        $path = '/' . implode('/', $segments) . (str_ends_with($path, '/') && $segments !== [] ? '/' : '');
        return $origin . $path . (isset($relative['query']) ? '?' . $relative['query'] : '') . (isset($relative['fragment']) ? '#' . $relative['fragment'] : '');
    }
    private function parseHeaders(string $raw): array
    {
        // Combine duplicate headers; keep 'set-cookie' as array of all values.
        $out = [];
        foreach (preg_split("~\r?\n~", $raw) as $line) {
            if (preg_match('~^HTTP/\S+\s+\d{3}\b~i', $line)) {
                $out = [];
                continue;
            }
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
}
