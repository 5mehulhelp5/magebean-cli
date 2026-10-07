<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Defers canonical policy until requirement definitions exist; old evidence overrides remain legacy. */
final class LegacyAsvsRequirementPolicy
{
    public static function hasCanonical(array $config): bool
    {
        foreach (['include_rules', 'select_rules', 'exclude_rules'] as $field) foreach (self::ids($config[$field] ?? []) as $id) if (str_starts_with($id, 'OWASP-ASVS:')) return true;
        foreach (array_keys($config['override_rules'] ?? []) as $id) if (str_starts_with(strtoupper((string)$id), 'OWASP-ASVS:')) return true;
        return false;
    }

    public static function evidenceConfig(array $config): array
    {
        $copy = $config;
        foreach (['include_rules', 'select_rules'] as $field) {
            if (array_filter(self::ids($config[$field] ?? []), static fn(string $id): bool => str_starts_with($id, 'OWASP-ASVS:'))) unset($copy['include_rules'], $copy['select_rules']);
        }
        $copy['exclude_rules'] = array_values(array_filter(self::ids($config['exclude_rules'] ?? []), static fn(string $id): bool => !str_starts_with($id, 'OWASP-ASVS:')));
        foreach (array_keys($copy['override_rules'] ?? []) as $id) if (str_starts_with(strtoupper((string)$id), 'OWASP-ASVS:')) unset($copy['override_rules'][$id]);
        return $copy;
    }

    public static function apply(array $pack, array $config): array
    {
        if (($pack['assessment_model'] ?? '') !== 'requirement-v1') {
            if (self::hasCanonical($config)) throw new \RuntimeException('Canonical ASVS project policy requires an ASVS profile.');
            return $pack;
        }
        $include = self::ids($config['include_rules'] ?? $config['select_rules'] ?? []);
        $exclude = self::ids($config['exclude_rules'] ?? []);
        $selected = [];
        foreach ($pack['rules'] as $definition) {
            $aliases = array_merge([$definition['id']], $definition['legacy_rule_ids']);
            if ($include !== [] && array_intersect($aliases, $include) === []) continue;
            if (array_intersect($aliases, $exclude) !== []) continue;
            foreach ($config['override_rules'] ?? [] as $id => $override) {
                if (strtoupper((string)$id) !== $definition['id']) continue;
                if (!is_array($override) || array_diff(array_keys($override), ['title', 'severity', 'messages', 'remediation']) !== []) throw new \RuntimeException('Canonical overrides may change presentation/severity only; requirement identity and coverage are immutable.');
                $definition = array_replace($definition, $override);
            }
            $selected[] = $definition;
        }
        $pack['rules'] = $selected;
        $pack['controls'] = array_values(array_unique(array_column($selected, 'control')));
        return $pack;
    }

    private static function ids(mixed $value): array
    {
        if (is_string($value)) $value = explode(',', $value);
        if (!is_array($value)) return [];
        return array_values(array_unique(array_filter(array_map(static fn($id): string => strtoupper(trim((string)$id)), $value))));
    }
}
