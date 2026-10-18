<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Checks\ProductionCheckPolicy;
use Magebean\Engine\Context;

$root = sys_get_temp_dir() . '/mb-production-policy-' . bin2hex(random_bytes(6));
mkdir($root . '/.magebean', 0777, true);
$file = $root . '/.magebean/production-checks.json';
$policy = new ProductionCheckPolicy(new Context($root, ''));
$n = 0; $calls = 0;
$run = static function (array $args) use (&$calls): array { ++$calls; return [true, 'fixture executed', $args]; };
$assert = static function (mixed $expected, array $result, string $label) use (&$n): void { ++$n; if ($result[0] !== $expected) throw new RuntimeException($label . ': ' . json_encode($result)); };
$write = static function (array $checks) use ($file): void { file_put_contents($file, json_encode(['schema_version' => 1, 'checks' => $checks], JSON_THROW_ON_ERROR)); };
try {
    $assert(null, $policy->run('production_bound_worker_code_readonly', [], $run), 'Missing policy is UNKNOWN');
    $write(['production_bound_worker_code_readonly' => ['worker_pids' => [1234]], 'production_direct_global_roles_approved' => ['approved_role_ids' => []], 'production_integration_debug_defaults_disabled' => ['paths' => ['payment/stripe/debug']], 'dependency_mitigation_records' => ['expected_ids' => ['CVE-2026-1234', 'APSB26-01:custom']]]);
    $result = $policy->run('production_bound_worker_code_readonly', ['dirs' => ['app']], $run);
    $assert(true, $result, 'Explicit worker identity policy executes');
    if (($result[2]['worker_pids'] ?? null) !== [1234] || ($result[2]['dirs'] ?? null) !== ['app']) throw new RuntimeException('Only allowed policy argument should merge with static args');
    $assert(true, $policy->run('production_direct_global_roles_approved', [], $run), 'Explicit deny-all role policy is legal');
    $assert(true, $policy->run('dependency_mitigation_records', [], $run), 'Expected mitigation IDs are typed inputs');
    $assert(true, $policy->run('production_integration_debug_defaults_disabled', [], $run), 'Explicit integration paths are typed inputs');
    $assert(null, $policy->run('not_a_check', [], $run), 'Unknown check cannot access policy data');
    $write(['production_bound_worker_code_readonly' => ['worker_pids' => [1234], 'observed_readonly' => true]]);
    $assert(null, $policy->run('production_bound_worker_code_readonly', [], $run), 'Protection self-attestation cannot enter runtime arguments');
    $write(['production_direct_global_roles_approved' => ['approved_role_ids' => [1], 'password' => 'DO_NOT_EMIT_POLICY_SECRET']]);
    $result = $policy->run('production_direct_global_roles_approved', [], $run);
    $assert(null, $result, 'Secrets and unsupported arguments are rejected');
    if (str_contains(json_encode($result), 'DO_NOT_EMIT_POLICY_SECRET')) throw new RuntimeException('Policy diagnostics leaked input contents');
    $write(['production_bound_worker_code_readonly' => ['worker_pids' => ['1234']]]);
    $assert(null, $policy->run('production_bound_worker_code_readonly', [], $run), 'String PID is not silently coerced');
    $write(['production_bound_worker_code_readonly' => ['worker_pids' => []]]);
    $assert(null, $policy->run('production_bound_worker_code_readonly', [], $run), 'Empty worker policy cannot vacuously pass');
    $write(['production_bound_worker_code_readonly' => ['worker_pids' => [1, 1]]]);
    $assert(null, $policy->run('production_bound_worker_code_readonly', [], $run), 'Duplicate worker identities rejected');
    $write(['production_integration_debug_defaults_disabled' => ['paths' => ['../../etc/passwd']]]);
    $assert(null, $policy->run('production_integration_debug_defaults_disabled', [], $run), 'Configuration paths cannot become filesystem selectors');
    $write(['dependency_mitigation_records' => ['expected_ids' => []]]);
    $assert(null, $policy->run('dependency_mitigation_records', [], $run), 'Empty expected mitigation inventory rejected');
    $write(['dependency_mitigation_records' => ['expected_ids' => ['CVE-1']]]);
    $assert(null, $policy->run('production_direct_global_roles_approved', [], $run), 'Missing individual policy is UNKNOWN');
    file_put_contents($file, '{"schema_version":1,"schema_version":1,"checks":{"production_direct_global_roles_approved":{"approved_role_ids":[]}}}');
    $assert(null, $policy->run('production_direct_global_roles_approved', [], $run), 'Duplicate JSON properties cannot hide policy');
    file_put_contents($file, '<?php throw new Exception("must never execute");');
    $assert(null, $policy->run('production_direct_global_roles_approved', [], $run), 'Policy is parsed as JSON and never executed');
    file_put_contents($file, str_repeat('x', 32769));
    $assert(null, $policy->run('production_direct_global_roles_approved', [], $run), 'Oversized policy rejected');
    unlink($file);
    $target = $root . '/outside-policy.json'; file_put_contents($target, '{}'); symlink($target, $file);
    $assert(null, $policy->run('production_direct_global_roles_approved', [], $run), 'Policy symlink rejected');
    if ($calls !== 4) throw new RuntimeException('Invalid policy invoked a check callback');
    echo "ProductionCheckPolicyTest: {$n} assertions passed\n";
} finally {
    if (is_link($file) || is_file($file)) unlink($file);
    if (is_file($root . '/outside-policy.json')) unlink($root . '/outside-policy.json');
    rmdir($root . '/.magebean'); rmdir($root);
}
