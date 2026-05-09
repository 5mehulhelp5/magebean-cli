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
