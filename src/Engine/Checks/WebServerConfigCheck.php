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
        if (!is_file($path)) return [false, "$file not found"];
        $needle = (string)($args['directive'] ?? '');
        $isRe   = (bool)($args['expects_regex'] ?? false);
        $txt = (string)file_get_contents($path);
        if ($txt === '') return [false, "$file is empty or unreadable"];

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
        if (!is_file($path)) return [false, "$file not found"];
        $needle = (string)($args['directive'] ?? '');
        $isRe   = (bool)($args['expects_regex'] ?? false);
        $txt = (string)file_get_contents($path);
        if ($txt === '') return [false, "$file is empty or unreadable"];

        if ($isRe) {
            if (@preg_match('/'.$needle.'/m', '') === false) {
                return [false, "Invalid regex: /$needle/"];
            }
            return [ (bool)preg_match('/'.$needle.'/m', $txt), ".htaccess matched /$needle/" ];
        }
        return [ str_contains($txt, $needle), ".htaccess contains '$needle'" ];
    }
}
