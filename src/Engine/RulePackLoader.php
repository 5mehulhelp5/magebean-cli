<?php

declare(strict_types=1);

namespace Magebean\Engine;

final class RulePackLoader
{
    private static function dir(): string
    {
        return __DIR__ . '/../Rules/controls';
    }
    private static function isControlFile(string $name): bool
    {
        return (bool)preg_match('/^MB-C\d{2}\.json$/', $name);
    }
    public static function loadAll(array $include = []): array
    {
        $dir = self::dir();
        $controls = [];
        $rules = [];
        foreach (scandir($dir) ?: [] as $file) {
            if (!self::isControlFile($file)) continue;
            $id = substr($file, 0, 6);
            if ($include && !in_array($id, $include, true)) continue;
            $data = json_decode((string)file_get_contents($dir . '/' . $file), true);
            $controls[] = $id;
            foreach ($data['rules'] ?? [] as $r) {
                $rules[] = $r;
            }
        }
        return ['controls' => $controls, 'rules' => $rules];
    }
    public static function loadExternalMagento(): array
    {
        $dir = __DIR__ . '/../Rules/external';
        $file = $dir . '/ExternalMagentoAudit.json';
        $rules = [];
        $controls = ['MB-C04','MB-C01','MB-C07']; // reference grouping
        if (is_file($file)) {
            $data = json_decode((string)file_get_contents($file), true);
            if (isset($data['rules']) && is_array($data['rules'])) {
                $rules = $data['rules'];
            }
        }
        return ['controls' => $controls, 'rules' => $rules];
    }
}
