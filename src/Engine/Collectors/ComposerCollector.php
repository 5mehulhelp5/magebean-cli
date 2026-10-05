<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;
final class ComposerCollector
{
    public function __construct(private FileCollector $files) {}
    public function json(string $path): ?array
    {
        if (!is_file($path)) {
            return null;
        }
        $raw = $this->files->read($path);
        if ($raw === false || $raw === '') {
            return null;
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }
    public function packages(string $lockPath): ?array
    {
        $j = $this->json($lockPath);
        if (!$j) return null;

        $pkgs = [];
        foreach (['packages', 'packages-dev'] as $key) {
            if (!empty($j[$key]) && is_array($j[$key])) {
                foreach ($j[$key] as $p) {
                    if (!empty($p['name'])) {
                        $pkgs[$p['name']] = [
                            'name'    => $p['name'],
                            'version' => $p['version'] ?? null,
                            'source'  => $p['source']['url'] ?? null,
                            'dist'    => $p['dist']['url'] ?? null,
                            'type'    => $p['type'] ?? null,
                            'replace' => is_array($p['replace'] ?? null) ? $p['replace'] : [],
                        ];
                    }
                }
            }
        }
        return $pkgs;
    }
}
