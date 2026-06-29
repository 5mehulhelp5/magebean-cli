<?php declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class WebServerConfigCheck
{
    private Context $ctx;

    public function __construct(Context $ctx) { $this->ctx = $ctx; }

    /**
     * nginx_directive:
     *  args: { file: "nginx.conf", directive: "regex-or-literal", expects_regex: true|false }
     */
    public function nginxDirective(array $args): array
    {
        $file = (string)($args['file'] ?? 'nginx.conf');
        $path = $this->ctx->abs($file);
        if (!is_file($path)) return [null, "$file not found"]; 
        $needle = (string)($args['directive'] ?? '');
        $isRe   = (bool)($args['expects_regex'] ?? false);
        $txt = (string)file_get_contents($path);
        if ($txt === '') return [null, "$file is empty or unreadable"];

        if ($isRe) {
            if (@preg_match('/'.$needle.'/m', '') === false) {
                return [false, "Invalid regex: /$needle/"];
            }
            return [ (bool)preg_match('/'.$needle.'/m', $txt), "nginx matched /$needle/" ];
        }
        return [ str_contains($txt, $needle), "nginx contains '$needle'" ];
    }

    /**
     * apache_htaccess_directive:
     *  args: { file: "pub/.htaccess", directive: "regex-or-literal", expects_regex: true|false }
     */
    public function apacheDirective(array $args): array
    {
        $file = (string)($args['file'] ?? 'pub/.htaccess');
        $path = $this->ctx->abs($file);
        if (!is_file($path)) return [null, "$file not found"];
        $needle = (string)($args['directive'] ?? '');
        $isRe   = (bool)($args['expects_regex'] ?? false);
        $txt = (string)file_get_contents($path);
        if ($txt === '') return [null, "$file is empty or unreadable"];

        if ($isRe) {
            if (@preg_match('/'.$needle.'/m', '') === false) {
                return [false, "Invalid regex: /$needle/"];
            }
            return [ (bool)preg_match('/'.$needle.'/m', $txt), ".htaccess matched /$needle/" ];
        }
        return [ str_contains($txt, $needle), ".htaccess contains '$needle'" ];
    }

    public function tlsCiphers(array $args): array
    {
        $files = $args['files'] ?? ['nginx.conf', 'pub/.htaccess', '.htaccess', 'apache.conf'];
        if (!is_array($files)) {
            $files = ['nginx.conf', 'pub/.htaccess', '.htaccess', 'apache.conf'];
        }
        $requireProtocols = (bool)($args['require_protocols'] ?? true);
        $requireCiphers = (bool)($args['require_ciphers'] ?? true);

        $checked = [];
        $failures = [];
        foreach ($files as $file) {
            if (!is_scalar($file)) {
                continue;
            }

            $relative = (string)$file;
            $path = $this->ctx->abs($relative);
            if (!is_file($path)) {
                $checked[] = ['file' => $relative, 'present' => false];
                continue;
            }

            $content = @file_get_contents($path);
            if ($content === false || $content === '') {
                $checked[] = ['file' => $relative, 'present' => true, 'readable' => false];
                continue;
            }

            $analysis = $this->tlsCipherConfigEvidence($relative, $content, $requireProtocols, $requireCiphers);
            $checked[] = $analysis;
            if (!empty($analysis['configured']) && !empty($analysis['ok'])) {
                return [true, 'Strong TLS protocol and cipher configuration found in ' . $relative, ['checked' => $checked]];
            }
            if (!empty($analysis['configured']) && empty($analysis['ok'])) {
                $failures[] = $analysis;
            }
        }

        $evidence = ['checked' => $checked, 'failures' => $failures];
        if ($failures !== []) {
            $lines = ['Weak TLS protocol/cipher configuration detected:'];
            foreach ($failures as $failure) {
                $lines[] = sprintf(
                    '    - %s missing %s',
                    $failure['file'],
                    implode('+', $failure['missing'] ?? ['strong_tls_config'])
                );
            }
            return [false, implode("\n", $lines), $evidence];
        }

        return [false, 'TLS protocol/cipher configuration not found. Add nginx or Apache TLS config with TLSv1.2/TLSv1.3 and strong ciphers.', $evidence];
    }
    private function tlsCipherConfigEvidence(string $file, string $content, bool $requireProtocols, bool $requireCiphers): array
    {
        $protocols = $this->firstDirectiveValue($content, '~^\s*(?:ssl_protocols|SSLProtocol)\s+(?P<value>[^;\r\n]+)~im');
        $ciphers = $this->firstDirectiveValue($content, '~^\s*(?:ssl_ciphers|SSLCipherSuite)\s+(?P<value>[^;\r\n]+)~im');

        $protocolEvidence = $this->tlsProtocolEvidence($protocols);
        $cipherEvidence = $this->cipherSuiteEvidence($ciphers);

        $missing = [];
        if ($requireProtocols && empty($protocolEvidence['ok'])) {
            $missing[] = 'strong_protocols';
        }
        if ($requireCiphers && empty($cipherEvidence['ok'])) {
            $missing[] = 'strong_ciphers';
        }

        return [
            'file' => $file,
            'present' => true,
            'readable' => true,
            'configured' => $protocols !== null || $ciphers !== null,
            'protocols' => $protocolEvidence,
            'ciphers' => $cipherEvidence,
            'missing' => $missing,
            'ok' => $missing === [],
        ];
    }

    private function firstDirectiveValue(string $content, string $regex): ?string
    {
        if (preg_match($regex, $content, $match) !== 1) {
            return null;
        }

        return trim((string)$match['value'], " \t\n\r\0\x0B\"'");
    }

    private function tlsProtocolEvidence(?string $value): array
    {
        if ($value === null || $value === '') {
            return ['present' => false, 'ok' => false, 'missing' => ['protocol_directive']];
        }

        $normalized = strtolower($value);
        $hasStrong = preg_match('~\bTLSv1\.[23]\b~i', $value) === 1;
        $usesAll = preg_match('~(?:^|\s)all(?:\s|$)~', $normalized) === 1;
        $weakEnabled = [];
        foreach (['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'] as $proto) {
            if ($this->tlsProtocolEnabled($normalized, strtolower($proto))) {
                $weakEnabled[] = $proto;
            }
        }

        return [
            'present' => true,
            'value' => $value,
            'has_strong_protocol' => $hasStrong || ($usesAll && $weakEnabled === []),
            'weak_enabled' => $weakEnabled,
            'ok' => ($hasStrong || ($usesAll && $weakEnabled === [])) && $weakEnabled === [],
        ];
    }

    private function tlsProtocolEnabled(string $normalized, string $proto): bool
    {
        $quoted = preg_quote($proto, '~');
        if (preg_match('~(?:^|\s)-' . $quoted . '(?:\s|$)~', $normalized) === 1) {
            return false;
        }
        if (preg_match('~(?:^|\s)\+' . $quoted . '(?:\s|$)~', $normalized) === 1) {
            return true;
        }
        if (preg_match('~(?:^|\s)' . $quoted . '(?:\s|$)~', $normalized) === 1) {
            return true;
        }
        if ($proto === 'tlsv1' && preg_match('~(?:^|\s)all(?:\s|$)~', $normalized) === 1) {
            return true;
        }

        return false;
    }

    private function cipherSuiteEvidence(?string $value): array
    {
        if ($value === null || $value === '') {
            return ['present' => false, 'ok' => false, 'missing' => ['cipher_directive']];
        }

        $tokens = preg_split('~[:\s]+~', trim($value)) ?: [];
        $enabledTokens = [];
        foreach ($tokens as $token) {
            $token = trim((string)$token);
            if ($token === '' || str_starts_with($token, '!') || str_starts_with($token, '-')) {
                continue;
            }
            $enabledTokens[] = $token;
        }

        $joined = implode(':', $enabledTokens);
        $hasStrong = preg_match('~\b(?:ECDHE|TLS_AES|CHACHA20|AESGCM|EECDH|HIGH)\b~i', $joined) === 1;
        $weakEnabled = [];
        foreach ($enabledTokens as $token) {
            if (preg_match('~(?:RC4|3DES|DES|MD5|NULL|aNULL|eNULL|EXPORT|LOW|ADH)~i', $token) === 1) {
                $weakEnabled[] = $token;
            }
        }

        return [
            'present' => true,
            'value' => $value,
            'has_strong_cipher' => $hasStrong,
            'weak_enabled' => $weakEnabled,
            'ok' => $hasStrong && $weakEnabled === [],
        ];
    }
    public function hstsConfig(array $args): array
    {
        $files = $args['files'] ?? ['nginx.conf', 'pub/.htaccess', '.htaccess'];
        if (!is_array($files)) {
            $files = ['nginx.conf', 'pub/.htaccess', '.htaccess'];
        }
        $min = (int)($args['min_max_age'] ?? 15552000);
        $requireIncludeSubdomains = (bool)($args['require_include_subdomains'] ?? false);
        $requirePreload = (bool)($args['require_preload'] ?? false);

        $checked = [];
        foreach ($files as $file) {
            if (!is_scalar($file)) {
                continue;
            }
            $relative = (string)$file;
            $path = $this->ctx->abs($relative);
            if (!is_file($path)) {
                $checked[] = ['file' => $relative, 'present' => false];
                continue;
            }

            $txt = (string)file_get_contents($path);
            if (!preg_match_all('~(?:Strict-Transport-Security|strict-transport-security)[^"\']*["\'](?P<policy>[^"\']+)["\']|(?:Strict-Transport-Security|strict-transport-security)\s+(?P<bare>[^\r\n;]+(?:;[^\r\n;]+)*)~i', $txt, $matches, PREG_SET_ORDER)) {
                $checked[] = ['file' => $relative, 'present' => true, 'hsts' => false];
                continue;
            }

            foreach ($matches as $match) {
                $policy = trim((string)($match['policy'] ?? $match['bare'] ?? ''));
                if (!preg_match('~max-age\s*=\s*(\d+)~i', $policy, $ageMatch)) {
                    $checked[] = ['file' => $relative, 'present' => true, 'hsts' => true, 'policy' => $policy, 'ok' => false];
                    continue;
                }

                $maxAge = (int)$ageMatch[1];
                $includeSubdomains = stripos($policy, 'includesubdomains') !== false;
                $preload = stripos($policy, 'preload') !== false;
                $ok = $maxAge >= $min
                    && (!$requireIncludeSubdomains || $includeSubdomains)
                    && (!$requirePreload || $preload);
                $evidence = [
                    'file' => $relative,
                    'policy' => $policy,
                    'max_age' => $maxAge,
                    'min_max_age' => $min,
                    'include_subdomains' => $includeSubdomains,
                    'preload' => $preload,
                    'ok' => $ok,
                ];
                if ($ok) {
                    return [true, 'HSTS configured in web server config', $evidence];
                }
                $checked[] = $evidence;
            }
        }

        return [null, 'No passing HSTS web server config found', ['checked' => $checked]];
    }
}
