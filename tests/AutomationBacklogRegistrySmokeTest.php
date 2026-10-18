<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Context;
$root = sys_get_temp_dir() . '/magebean-registry-smoke-' . bin2hex(random_bytes(8)); mkdir($root);
$registry = CheckRegistry::fromContext(new Context($root, ''));
$names = ['automated_source_policy', 'dependency_source_policy', 'dependency_mitigation_records', 'production_bound_worker_code_readonly', 'production_upload_signatures_absent', 'production_direct_global_roles_approved', 'production_checkout_csp_response', 'production_runtime_nosniff', 'production_native_debug_defaults_disabled', 'production_integration_debug_defaults_disabled', 'production_worker_xdebug_absent'];
$count = 0;
try {
    foreach ($names as $name) {
        $count++; if (!$registry->has($name)) throw new RuntimeException('Registry missing ' . $name);
        $count++; $result = $registry->run($name, []);
        if ($result[0] !== null) throw new RuntimeException('Unavailable required data must be UNKNOWN: ' . $name);
    }
    $count++; if ($registry->run('automated_source_policy', ['kind' => 'unsupported'])[0] !== null) throw new RuntimeException('Unsupported source policy must be UNKNOWN');
    echo "Automation backlog registry: $count assertions passed\n";
} finally { rmdir($root); }
