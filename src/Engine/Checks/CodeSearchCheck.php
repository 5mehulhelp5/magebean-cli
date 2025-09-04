<?php declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class CodeSearchCheck
{
    private Context $ctx;

    public function __construct(Context $ctx) { $this->ctx = $ctx; }

    /**
     * args:
     * - paths[]: thư mục tương đối để quét (vd: ["app","vendor","lib","app/design"])
     * - include_ext[]: đuôi file cần quét (mặc định: php, phtml, js, html, xml)
     * - must_match[]: danh sách regex (ít nhất MỖI regex phải xuất hiện 1 lần)
     * - must_not_match[]: danh sách regex (KHÔNG được xuất hiện ở bất kỳ file nào)
     * - max_results: số phát hiện tối đa báo cáo (default 50)
     */
    public function grep(array $args): array
    {
        $roots = $args['paths'] ?? ['app', 'vendor', 'lib', 'app/design'];
        $inc   = $args['include_ext'] ?? ['php','phtml','js','html','xml'];
        $must  = $args['must_match'] ?? [];
        $mustNot = $args['must_not_match'] ?? [];
        $max   = (int)($args['max_results'] ?? 50);

        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $files = $this->collectFiles($rootsAbs, $inc);

        $matches = [];      // offenders for must_not_match
        $foundMap = [];     // pattern => bool (for must_match)
        foreach ($must as $pat) $foundMap[$pat] = false;

        foreach ($files as $file) {
            $content = @file_get_contents($file);
            if ($content === false) continue;

            // must_not_match: fail ngay nếu có
            foreach ($mustNot as $pat) {
                if (@preg_match('/'.$pat.'/m', '') === false) {
                    return [false, "Invalid regex in must_not_match: /$pat/"];
                }
                if (preg_match('/'.$pat.'/m', $content)) {
                    $matches[] = $file;
                    if (count($matches) >= $max) break 2;
                }
            }

            // must_match: đánh dấu nếu thấy
            foreach ($must as $pat) {
                if ($foundMap[$pat] === true) continue;
                if (@preg_match('/'.$pat.'/m', '') === false) {
                    return [false, "Invalid regex in must_match: /$pat/"];
                }
                if (preg_match('/'.$pat.'/m', $content)) {
                    $foundMap[$pat] = true;
                }
            }
        }

        if (!empty($matches)) {
            return [false, 'Forbidden pattern found in: '.implode(', ', $matches)];
        }

        // verify all must_match satisfied
        foreach ($foundMap as $pat => $ok) {
            if (!$ok) {
                return [false, "Required pattern not found: /$pat/"];
            }
        }

        return [true, 'code_grep OK (patterns satisfied)'];
    }

    private function collectFiles(array $roots, array $inc): array
    {
        $ret = [];
        $incLower = array_map('strtolower', $inc);
        foreach ($roots as $root) {
            if (!is_dir($root)) continue;
            $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(
                $root, \FilesystemIterator::SKIP_DOTS
            ));
            foreach ($rii as $f) {
                if (!$f->isFile()) continue;
                $ext = strtolower(pathinfo($f->getFilename(), PATHINFO_EXTENSION));
                if ($ext === '' || !in_array($ext, $incLower, true)) continue;
                // mặc định bỏ qua file > 1MB để tránh tốn bộ nhớ
                if ($f->getSize() > 1024*1024) continue;
                $ret[] = $f->getPathname();
            }
        }
        return $ret;
    }
}
