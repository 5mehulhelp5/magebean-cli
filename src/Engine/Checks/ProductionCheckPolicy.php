<?php
declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

/** Small typed policy input. It carries expected state, never observed protection assertions. */
final class ProductionCheckPolicy
{
    private const INPUTS = [
        'production_bound_worker_code_readonly' => 'worker_pids',
        'production_direct_global_roles_approved' => 'approved_role_ids',
        'production_integration_debug_defaults_disabled' => 'paths',
        'dependency_mitigation_records' => 'expected_ids',
    ];

    public function __construct(private Context $ctx) {}

    /** Policy can supply only the one explicitly permitted argument per check. */
    public function run(string $check, array $args, callable $execute): array
    {
        if (!isset(self::INPUTS[$check])) return $this->unknown('Unsupported production policy check');
        [$policy, $reason] = $this->load();
        if (!is_array($policy)) return $this->unknown($reason);
        if (!isset($policy['checks'][$check])) return $this->unknown('The required check policy is missing from .magebean/production-checks.json');
        $key = self::INPUTS[$check];
        $args[$key] = $policy['checks'][$check][$key];
        return $execute($args);
    }

    private function load(): array
    {
        $root = realpath($this->ctx->path);
        if ($root === false || !is_dir($root)) return [null, 'Project root is unavailable'];
        $directory = $root . DIRECTORY_SEPARATOR . '.magebean';
        $path = $directory . DIRECTORY_SEPARATOR . 'production-checks.json';
        if (is_link($directory) || is_link($path)) return [null, 'Production policy symlinks are unsupported; provide a regular project-local policy file'];
        if (!is_file($path) || !is_readable($path)) return [null, 'Machine policy .magebean/production-checks.json is unavailable; supply explicit versioned check inputs'];
        $size = @filesize($path);
        if (!is_int($size) || $size < 2 || $size > 32768) return [null, 'Production policy exceeds the bounded file size or is empty'];
        $contents = @file_get_contents($path, false, null, 0, 32769);
        if (!is_string($contents) || strlen($contents) !== $size || strlen($contents) > 32768) return [null, 'Production policy could not be read completely'];
        try { $policy = json_decode($contents, true, 32, JSON_THROW_ON_ERROR); }
        catch (\Throwable $e) { return [null, 'Production policy is not valid bounded JSON']; }
        // All supported property names are unique across this small schema; reject JSON last-key-wins ambiguity.
        preg_match_all('~"(?:[^"\\\\]|\\\\.)*"\s*:~s', $contents, $properties);
        $keys = [];
        foreach ($properties[0] as $property) {
            try { $keyName = json_decode(rtrim(substr(rtrim($property), 0, -1)), true, 4, JSON_THROW_ON_ERROR); }
            catch (\Throwable $e) { return [null, 'Production policy property syntax is unsupported']; }
            if (!is_string($keyName) || isset($keys[$keyName])) return [null, 'Production policy contains duplicate property names'];
            $keys[$keyName] = true;
        }
        if (!is_array($policy) || array_diff(array_keys($policy), ['schema_version', 'checks']) !== [] || ($policy['schema_version'] ?? null) !== 1 || !isset($policy['checks']) || !is_array($policy['checks']) || array_is_list($policy['checks'])) return [null, 'Production policy must contain schema_version 1 and a checks object'];
        if (count($policy['checks']) > count(self::INPUTS)) return [null, 'Production policy contains unsupported check keys'];
        foreach ($policy['checks'] as $name => $entry) {
            if (!is_string($name) || !isset(self::INPUTS[$name]) || !is_array($entry)) return [null, 'Production policy contains unsupported check keys'];
            $key = self::INPUTS[$name];
            if (array_keys($entry) !== [$key] || !is_array($entry[$key]) || !array_is_list($entry[$key])) return [null, 'Production policy contains unsupported or missing check arguments'];
            $values = $entry[$key];
            if (count($values) > ($key === 'expected_ids' ? 256 : ($key === 'paths' ? 32 : 64))) return [null, 'Production check policy exceeds the bounded input count'];
            if ($key !== 'approved_role_ids' && $values === []) return [null, 'Production worker, integration and mitigation policies must not be empty'];
            foreach ($values as $value) {
                if ($key === 'worker_pids' || $key === 'approved_role_ids') {
                    if (!is_int($value) || $value < 1 || $value > 2147483647) return [null, 'Production identity policy values must be positive integers'];
                } elseif ($key === 'paths') {
                    if (!is_string($value) || strlen($value) > 256 || !preg_match('~^[a-zA-Z0-9_]+(?:/[a-zA-Z0-9_]+){2,}$~D', $value)) return [null, 'Integration policy paths must be explicit Magento configuration paths'];
                } elseif (!is_string($value) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/D', $value)) return [null, 'Expected mitigation IDs must be bounded identifiers'];
            }
            if (count(array_unique($values, SORT_REGULAR)) !== count($values)) return [null, 'Production check policy contains duplicate values'];
        }
        return [$policy, ''];
    }

    private function unknown(string $reason): array
    {
        return [null, '[UNKNOWN] ' . $reason, ['source' => '.magebean/production-checks.json', 'input_kind' => 'expected_policy_configuration', 'reason' => 'production_policy_unavailable_or_invalid']];
    }
}
