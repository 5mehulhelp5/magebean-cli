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
                'timeout'       => max(1, (int)ceil($timeoutMs / 1000)),
                'content'       => $requestBody ?? '',
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
            $observe(false);
            return [null, '[UNKNOWN] HTTP error (stream)', ['url' => $url]];
        }
        $observe(true);
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
}
