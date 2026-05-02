<?php

declare(strict_types=1);

namespace Magebean\Engine;

use Magebean\Engine\Checks\CheckRegistry;

final class RuleValidator
{
    public static function validatePack(array $pack, CheckRegistry $registry): array
    {
        $errors = [];
        $seen = [];

        foreach ($pack['rules'] ?? [] as $index => $rule) {
            if (!is_array($rule)) {
                $errors[] = "Rule at index {$index} must be an object.";
                continue;
            }
            $id = (string)($rule['id'] ?? '');
            foreach (Rule::requiredKeys() as $key) {
                if (!array_key_exists($key, $rule)) {
                    $errors[] = self::label($id, $index) . " is missing required key '{$key}'.";
                }
            }
            if ($id !== '') {
                $idKey = strtoupper($id);
                if (isset($seen[$idKey])) {
                    $errors[] = "Duplicate rule id '{$id}'.";
                }
                $seen[$idKey] = true;
            }

            $op = (string)($rule['op'] ?? 'all');
            if (!in_array($op, ['all', 'any'], true)) {
                $errors[] = self::label($id, $index) . " has invalid op '{$op}'. Allowed: all, any.";
            }

            $checks = $rule['checks'] ?? null;
            if (!is_array($checks) || $checks === []) {
                $errors[] = self::label($id, $index) . ' must define at least one check.';
                continue;
            }

            foreach ($checks as $checkIndex => $check) {
                if (!is_array($check)) {
                    $errors[] = self::label($id, $index) . " check #{$checkIndex} must be an object.";
                    continue;
                }
                $name = (string)($check['name'] ?? '');
                if ($name === '') {
                    $errors[] = self::label($id, $index) . " check #{$checkIndex} is missing name.";
                    continue;
                }
                if (!$registry->has($name)) {
                    $errors[] = self::label($id, $index) . " references unknown check '{$name}'.";
                }
                if (isset($check['args']) && !is_array($check['args'])) {
                    $errors[] = self::label($id, $index) . " check '{$name}' args must be an object.";
                }
            }
        }

        return $errors;
    }

    private static function label(string $id, int $index): string
    {
        return $id !== '' ? "Rule {$id}" : "Rule at index {$index}";
    }
}
