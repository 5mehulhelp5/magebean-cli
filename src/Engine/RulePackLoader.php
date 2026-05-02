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

    public static function loadPath(string $path): array
    {
        if (is_dir($path)) {
            $controls = [];
            $rules = [];
            foreach (scandir($path) ?: [] as $file) {
                if (!preg_match('/\.json$/i', $file)) {
                    continue;
                }
                $pack = self::loadFile(rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $file);
                $controls = array_merge($controls, $pack['controls'] ?? []);
                $rules = array_merge($rules, $pack['rules'] ?? []);
            }
            return ['controls' => array_values(array_unique($controls)), 'rules' => $rules];
        }

        return self::loadFile($path);
    }

    public static function loadFile(string $file): array
    {
        if (!is_file($file)) {
            throw new \RuntimeException("Rule pack not found: {$file}");
        }

        $data = json_decode((string)file_get_contents($file), true);
        if (!is_array($data)) {
            throw new \RuntimeException("Invalid rule pack JSON: {$file}");
        }

        $controls = [];
        if (isset($data['control']) && is_scalar($data['control'])) {
            $controls[] = strtoupper((string)$data['control']);
        }
        if (isset($data['controls']) && is_array($data['controls'])) {
            foreach ($data['controls'] as $control) {
                if (is_scalar($control)) {
                    $controls[] = strtoupper((string)$control);
                }
            }
        }

        $rules = [];
        if (isset($data['rules']) && is_array($data['rules'])) {
            foreach ($data['rules'] as $rule) {
                if (is_array($rule)) {
                    $rules[] = $rule;
                    if (isset($rule['control']) && is_scalar($rule['control'])) {
                        $controls[] = strtoupper((string)$rule['control']);
                    }
                }
            }
        }

        return ['controls' => array_values(array_unique($controls)), 'rules' => $rules];
    }

    public static function loadExternalMagento(): array
    {
        $dir = __DIR__ . '/../Rules/external';
        $file = $dir . '/ExternalMagentoAudit.json';
        $rules = [];
        $controls = ['MB-C01','MB-C02','MB-C03','MB-C04','MB-C05','MB-C06','MB-C07','MB-C12']; // reference grouping
        if (is_file($file)) {
            $data = json_decode((string)file_get_contents($file), true);
            if (isset($data['rules']) && is_array($data['rules'])) {
                $rules = $data['rules'];
            }
        }
        return ['controls' => $controls, 'rules' => $rules];
    }
}
