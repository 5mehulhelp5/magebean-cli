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
            if (($pack['assessment_model'] ?? '') === 'internal-requirement-v1' || (preg_match('/^MB-[0-9]{4,}$/D', $id) === 1)) {
                if (isset($seen[strtoupper($id)])) $errors[] = "Duplicate requirement id '{$id}'.";
                $seen[strtoupper($id)] = true;
                foreach (RequirementDefinitionValidator::validate($rule, $registry) as $error) $errors[] = $error;
                continue;
            }
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

            if (isset($rule['remediation'])) {
                if (!is_array($rule['remediation']) || $rule['remediation'] === []) {
                    $errors[] = self::label($id, $index) . ' remediation must be a non-empty array of strings.';
                } else {
                    foreach ($rule['remediation'] as $stepIndex => $step) {
                        if (!is_string($step) || trim($step) === '') {
                            $errors[] = self::label($id, $index) . " remediation step #{$stepIndex} must be a non-empty string.";
                        }
                    }
                }
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
                if ($name === 'requirement_assessment' && is_array($check['args'] ?? null)) {
                    $groups = $check['args']['groups'] ?? null;
                    if (!is_array($groups)) $errors[] = self::label($id, $index) . ' requirement groups must be an array.';
                    else foreach ($groups as $group) {
                        if (!is_array($group) || !is_bool($group['missing'] ?? null) || !in_array($group['op'] ?? '', ['all', 'any'], true) || !is_array($group['checks'] ?? null)) {
                            $errors[] = self::label($id, $index) . ' has invalid requirement evidence group.'; continue;
                        }
                        if ($group['missing']) continue;
                        if (array_filter($group['checks'], static fn($child): bool => is_array($child) && ($child['name'] ?? '') === 'requirement_assessment')) {
                            $errors[] = self::label($id, $index) . ' recursively embeds a requirement assessment.'; continue;
                        }
                        $child = ['id' => $group['id'] ?? '', 'title' => 'Evidence group', 'control' => $rule['control'] ?? '', 'severity' => $rule['severity'] ?? '', 'op' => $group['op'], 'checks' => $group['checks']];
                        foreach (self::validatePack(['rules' => [$child]], $registry) as $error) $errors[] = self::label($id, $index) . ': ' . $error;
                    }
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
