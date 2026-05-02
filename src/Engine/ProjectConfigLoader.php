<?php

declare(strict_types=1);

namespace Magebean\Engine;

final class ProjectConfigLoader
{
    /** @var string[] */
    private const DEFAULT_NAMES = ['.magebean.json', 'magebean.json', '.magebean.yml', '.magebean.yaml', 'magebean.yml', 'magebean.yaml'];

    public static function discover(string $projectPath): ?string
    {
        foreach (self::DEFAULT_NAMES as $name) {
            $candidate = rtrim($projectPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name;
            if (is_file($candidate)) {
                return $candidate;
            }
        }
        return null;
    }

    public static function load(?string $file): array
    {
        if ($file === null || trim($file) === '') {
            return [];
        }
        if (!is_file($file)) {
            throw new \RuntimeException("Magebean config not found: {$file}");
        }

        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if ($ext === 'json') {
            $data = self::loadJson($file);
            $data['_base_dir'] = dirname($file);
            return $data;
        }
        if ($ext === 'yml' || $ext === 'yaml') {
            $data = self::loadYaml($file);
            $data['_base_dir'] = dirname($file);
            return $data;
        }

        throw new \RuntimeException("Unsupported Magebean config format: {$file}");
    }

    private static function loadJson(string $file): array
    {
        $data = json_decode((string)file_get_contents($file), true);
        if (!is_array($data)) {
            throw new \RuntimeException("Invalid JSON Magebean config: {$file}");
        }
        return $data;
    }

    private static function loadYaml(string $file): array
    {
        if (!function_exists('yaml_parse_file')) {
            throw new \RuntimeException(
                "YAML config requires the PHP yaml extension. Use .magebean.json or install ext-yaml: {$file}"
            );
        }

        $data = yaml_parse_file($file);
        if (!is_array($data)) {
            throw new \RuntimeException("Invalid YAML Magebean config: {$file}");
        }
        return $data;
    }
}
