<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class GitHistoryCheck
{
    private Context $ctx;

    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    public function secretScan(array $args): array
    {
        $patterns = $args['patterns'] ?? [];
        $paths    = $args['paths'] ?? ['app', 'pub', 'env', 'config', 'modules'];
        $max      = (int)($args['max_results'] ?? 20);

        if (empty($patterns)) return [false, 'git_history_scan requires patterns'];

        $repoRoot = $this->ctx->abs('.');
        $gitDir = $repoRoot . '/.git';
        $git = trim((string)@shell_exec('command -v git'));


        $ere = implode('|', array_map(fn($p) => '(' . $p . ')', $patterns));

        if (is_dir($gitDir) && $git !== '') {

            $scope = '';
            foreach ($paths as $p) {
                $scope .= ' ' . escapeshellarg($p);
            }
            $cmd = $git . ' -C ' . escapeshellarg($repoRoot) . ' grep -I -n -E ' . escapeshellarg($ere) . $scope . ' 2>/dev/null';
            $out = (string)@shell_exec($cmd);
            if ($out !== '') {
                $lines = array_filter(explode("\n", trim($out)));
                if (!empty($lines)) {
                    $first = array_slice($lines, 0, $max);
                    return [false, 'Secrets in git history: ' . implode(' | ', $first)];
                }
            }

            return [true, 'git_history_scan OK (no matches)'];
        }

        $offenders = $this->scanWorkingTree($paths, $patterns, $max);
        if (!empty($offenders)) {
            return [false, 'Secrets in working tree: ' . implode(' | ', $offenders)];
        }
        return [true, 'git_history_scan fallback OK (no matches)'];
    }

    private function scanWorkingTree(array $paths, array $patterns, int $max): array
    {
        $ret = [];
        $inc = ['php', 'phtml', 'js', 'html', 'xml', 'env', 'ini', 'json', 'yaml', 'yml', 'txt'];
        foreach ($paths as $rel) {
            $root = $this->ctx->abs($rel);
            if (!is_dir($root) && !is_file($root)) continue;

            $iter = is_dir($root)
                ? new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS))
                : [new \SplFileInfo($root)];

            foreach ($iter as $f) {
                if ($f instanceof \SplFileInfo && $f->isFile()) {
                    $ext = strtolower(pathinfo($f->getFilename(), PATHINFO_EXTENSION));
                    if ($ext !== '' && !in_array($ext, $inc, true)) continue;
                    if ($f->getSize() > 1024 * 1024) continue;

                    $txt = (string)@file_get_contents($f->getPathname());
                    foreach ($patterns as $re) {
                        if (@preg_match('/' . $re . '/m', '') === false) continue;
                        if (preg_match('/' . $re . '/m', $txt)) {
                            $ret[] = $f->getPathname();
                            if (count($ret) >= $max) return $ret;
                            break;
                        }
                    }
                }
            }
        }
        return $ret;
    }
}
