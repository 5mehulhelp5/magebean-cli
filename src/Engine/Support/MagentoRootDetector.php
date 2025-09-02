<?php
declare(strict_types=1);

namespace Magebean\Engine\Support;

final class MagentoRootDetector
{
    public function __construct(
        private int $minScore = 4,   
        private int $maxUp = 4       
    ) {}

    /**
     * @return array{ok:bool, root?:string, score?:int, reason?:string, details?:array<string, mixed>, version?:string}
     */
    public function detect(string $inputPath): array
    {
        $path = $this->normalize($inputPath);
        if (!is_dir($path)) {
            return ['ok' => false, 'reason' => "Path not found: {$path}"];
        }

        if (!is_dir($path)) {
            $path = dirname($path);
        }

        $cur = $path;
        $best = null;
        for ($i = 0; $i <= $this->maxUp; $i++) {
            $score = 0;
            $details = [];

            $f_env         = $cur . '/app/etc/env.php';
            $f_bin         = $cur . '/bin/magento';
            $f_comp_json   = $cur . '/composer.json';
            $f_comp_lock   = $cur . '/composer.lock';
            $d_vendor_fw   = $cur . '/vendor/magento/framework';
            $d_app_magento = $cur . '/app/code/Magento';
            $d_pub_static  = $cur . '/pub/static';

            if (is_file($f_env))         { $score += 2; $details['app/etc/env.php'] = true; }
            if (is_file($f_bin) && is_executable($f_bin)) { $score += 2; $details['bin/magento'] = true; }
            if (is_dir($d_vendor_fw))    { $score += 2; $details['vendor/magento/framework'] = true; }

            if (is_file($f_comp_json)) {
                $details['composer.json'] = true;
                $score += $this->composerJsonLooksMagento($f_comp_json) ? 2 : 0;
            }

            if (is_dir($d_app_magento))  { $score += 1; $details['app/code/Magento'] = true; }
            if (is_dir($d_pub_static))   { $score += 1; $details['pub/static'] = true; }

            $candidate = ['dir' => $cur, 'score' => $score, 'details' => $details];

            if ($best === null || $candidate['score'] > $best['score']) {
                $best = $candidate;
            }

            if ($score >= $this->minScore) {
                $version = $this->detectVersion($f_comp_lock);
                return ['ok' => true, 'root' => $cur, 'score' => $score, 'details' => $details, 'version' => $version];
            }

            $parent = dirname($cur);
            if ($parent === $cur) break;
            $cur = $parent;
        }

        return [
            'ok' => false,
            'score' => $best['score'] ?? 0,
            'details' => $best['details'] ?? [],
            'reason' => 'Not a Magento 2 root (insufficient markers)',
        ];
    }

    private function normalize(string $p): string
    {
        $p = trim($p);
        if ($p === '') return getcwd();
        if (str_starts_with($p, '~/')) {
            $home = getenv('HOME') ?: (function_exists('posix_getpwuid') ? posix_getpwuid(posix_getuid())['dir'] : '');
            if ($home) $p = $home . substr($p, 1);
        }
        if ($p[0] !== '/') {
            $p = rtrim(getcwd(), '/') . '/' . ltrim($p, '/');
        }
        return rtrim($p, '/');
    }

    private function composerJsonLooksMagento(string $composerJson): bool
    {
        $raw = @file_get_contents($composerJson);
        if (!is_string($raw)) return false;
        $data = json_decode($raw, true);
        if (!is_array($data)) return false;
        $sections = ['require', 'require-dev'];
        foreach ($sections as $sec) {
            if (!empty($data[$sec]) && is_array($data[$sec])) {
                foreach (array_keys($data[$sec]) as $pkg) {
                    // các package “hint” điển hình của M2
                    if (str_starts_with($pkg, 'magento/') || $pkg === 'magento/framework') {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private function detectVersion(string $composerLockPath): ?string
    {
        if (!is_file($composerLockPath)) return null;
        $raw = @file_get_contents($composerLockPath);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data)) return null;

        foreach (['packages', 'packages-dev'] as $bucket) {
            foreach (($data[$bucket] ?? []) as $pkg) {
                if (($pkg['name'] ?? '') === 'magento/product-community-edition') {
                    return (string)($pkg['version'] ?? '');
                }
                if (($pkg['name'] ?? '') === 'magento/framework') {
                    $v = (string)($pkg['version'] ?? '');
                    if ($v !== '') return $v;
                }
            }
        }
        return null;
    }
}
