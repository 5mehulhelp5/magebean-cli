<?php

declare(strict_types=1);

namespace Magebean\Engine;

final class RulePackMerger
{
    public static function applyProjectConfig(array $pack, array $config): array
    {
        $pack = self::appendExternalRuleSources($pack, $config);

        $excludeControls = self::strings($config['exclude_controls'] ?? []);
        if ($excludeControls) {
            $pack['rules'] = array_values(array_filter(
                $pack['rules'] ?? [],
                static fn(array $rule): bool => !in_array(strtoupper((string)($rule['control'] ?? '')), $excludeControls, true)
            ));
            $pack['controls'] = array_values(array_filter(
                $pack['controls'] ?? [],
                static fn(string $control): bool => !in_array(strtoupper($control), $excludeControls, true)
            ));
        }

        $includeRules = self::strings($config['include_rules'] ?? $config['select_rules'] ?? []);
        if ($includeRules) {
            $pack['rules'] = array_values(array_filter(
                $pack['rules'] ?? [],
                static fn(array $rule): bool => in_array(strtoupper((string)($rule['id'] ?? '')), $includeRules, true)
            ));
        }

        $excludeRules = self::strings($config['exclude_rules'] ?? []);
        if ($excludeRules) {
            $pack['rules'] = array_values(array_filter(
                $pack['rules'] ?? [],
                static fn(array $rule): bool => !in_array(strtoupper((string)($rule['id'] ?? '')), $excludeRules, true)
            ));
        }

        $overrides = $config['override_rules'] ?? [];
        if (is_array($overrides) && $overrides) {
            $pack['rules'] = array_map(
                static function (array $rule) use ($overrides): array {
                    $id = (string)($rule['id'] ?? '');
                    if ($id !== '' && isset($overrides[$id]) && is_array($overrides[$id])) {
                        return self::mergeRecursive($rule, $overrides[$id]);
                    }
                    return $rule;
                },
                $pack['rules'] ?? []
            );
        }

        $customRules = $config['rules'] ?? [];
        if (is_array($customRules) && $customRules) {
            foreach ($customRules as $rule) {
                if (is_array($rule)) {
                    $pack = self::upsertRule($pack, $rule);
                }
            }
        }

        return $pack;
    }

    public static function applyRuleFilter(array $pack, array $includeRules, array $excludeRules): array
    {
        $includeRules = self::strings($includeRules);
        if ($includeRules) {
            $pack['rules'] = array_values(array_filter(
                $pack['rules'] ?? [],
                static fn(array $rule): bool => in_array(strtoupper((string)($rule['id'] ?? '')), $includeRules, true)
            ));
        }

        $excludeRules = self::strings($excludeRules);
        if ($excludeRules) {
            $pack['rules'] = array_values(array_filter(
                $pack['rules'] ?? [],
                static fn(array $rule): bool => !in_array(strtoupper((string)($rule['id'] ?? '')), $excludeRules, true)
            ));
        }

        return $pack;
    }

    private static function appendExternalRuleSources(array $pack, array $config): array
    {
        $paths = array_merge(
            self::pathStrings($config['rule_files'] ?? []),
            self::pathStrings($config['rule_packs'] ?? $config['rule_paths'] ?? [])
        );
        $baseDir = isset($config['_base_dir']) && is_string($config['_base_dir']) ? $config['_base_dir'] : getcwd();

        foreach ($paths as $path) {
            $path = self::resolvePath($path, $baseDir);
            $external = RulePackLoader::loadPath($path);
            foreach ($external['rules'] ?? [] as $rule) {
                if (is_array($rule)) {
                    $pack = self::upsertRule($pack, $rule);
                }
            }
            foreach ($external['controls'] ?? [] as $control) {
                $pack['controls'][] = $control;
            }
        }

        $pack['controls'] = array_values(array_unique($pack['controls'] ?? []));
        return $pack;
    }

    private static function upsertRule(array $pack, array $rule): array
    {
        $id = strtoupper((string)($rule['id'] ?? ''));
        if ($id === '') {
            $pack['rules'][] = $rule;
            return $pack;
        }

        foreach ($pack['rules'] ?? [] as $index => $existing) {
            if (strtoupper((string)($existing['id'] ?? '')) === $id) {
                $pack['rules'][$index] = self::mergeRecursive($existing, $rule);
                return $pack;
            }
        }

        $pack['rules'][] = $rule;
        return $pack;
    }

    private static function mergeRecursive(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            if (is_array($value) && isset($base[$key]) && is_array($base[$key]) && !self::isList($value)) {
                $base[$key] = self::mergeRecursive($base[$key], $value);
            } else {
                $base[$key] = $value;
            }
        }
        return $base;
    }

    private static function strings(mixed $value): array
    {
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $item) {
            if (!is_scalar($item)) {
                continue;
            }
            $item = strtoupper(trim((string)$item));
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return array_values(array_unique($out));
    }

    private static function pathStrings(mixed $value): array
    {
        if (is_string($value)) {
            $value = [$value];
        }
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $item) {
            if (!is_scalar($item)) {
                continue;
            }
            $item = trim((string)$item);
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return array_values(array_unique($out));
    }

    private static function resolvePath(string $path, string $baseDir): string
    {
        if ($path === '') {
            return $path;
        }
        if ($path[0] === '/' || (bool)preg_match('/^[A-Za-z]:[\\\\\\/]/', $path)) {
            return $path;
        }
        return rtrim($baseDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $path;
    }

    private static function isList(array $value): bool
    {
        if ($value === []) {
            return true;
        }
        return array_keys($value) === range(0, count($value) - 1);
    }
}
