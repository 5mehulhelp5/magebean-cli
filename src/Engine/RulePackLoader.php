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
            if (!is_array($data) || ($data['control'] ?? '') !== $id) continue;
            $controls[] = $id;
            foreach ($data['rules'] ?? [] as $r) {
                $rules[] = $r;
            }
        }
        return ['controls' => $controls, 'rules' => $rules];
    }
    public static function validate(): array
    {
        $dir = self::dir();
        $errors = [];
        $pack = ['controls' => [], 'rules' => []];
        foreach (scandir($dir) ?: [] as $file) {
            if (!self::isControlFile($file)) continue;
            $path = $dir . '/' . $file;
            $json = file_get_contents($path);
            if ($json === false) {
                $errors[] = "Cannot read $file";
                continue;
            }
            $data = json_decode((string)$json, true);
            if (!is_array($data)) {
                $errors[] = "$file is not valid JSON";
                continue;
            }
            $cid = $data['control'] ?? null;
            if (!$cid || !preg_match('/^MB-C\d{2}$/', (string)$cid)) $errors[] = "$file missing/invalid control id";
            foreach (($data['rules'] ?? []) as $i => $r) {
                foreach (Rule::requiredKeys() as $key) {
                    if (!array_key_exists($key, $r)) $errors[] = "$file rule[$i] missing '$key'";
                }
            }
        }
        if (!$errors) $pack = self::loadAll();
        return [$pack, $errors];
    }
}
