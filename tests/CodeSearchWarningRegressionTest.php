<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Context;
use Magebean\Engine\RulePackLoader;
use Magebean\Engine\ScanRunner;

function assertWarningRegression(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$fixture = sys_get_temp_dir() . '/magebean-warning-regression-' . bin2hex(random_bytes(4));
mkdir($fixture . '/app/code/Test/Module', 0777, true);
file_put_contents(
    $fixture . '/app/code/Test/Module/Client.php',
    "<?php\n\$endpoint = 'https://api.example.com';\n\$payload = ['email' => \$tokenizedEmail];\n"
);

$catalog = RulePackLoader::loadAll();
$wanted = ['MB-R073' => true, 'MB-R077' => true];
$rules = array_values(array_filter(
    $catalog['rules'] ?? [],
    static fn(array $rule): bool => isset($wanted[(string)($rule['id'] ?? '')])
));
assertWarningRegression(count($rules) === 2, 'Could not load MB-R073 and MB-R077');

$warnings = [];
set_error_handler(static function (int $severity, string $message, string $file, int $line) use (&$warnings): bool {
    $warnings[] = compact('severity', 'message', 'file', 'line');
    return true;
});
try {
    $context = new Context($fixture, '');
    $result = (new ScanRunner(
        $context,
        ['rules' => $rules],
        null,
        CheckRegistry::fromContext($context)
    ))->run();
} finally {
    restore_error_handler();
    unlink($fixture . '/app/code/Test/Module/Client.php');
    rmdir($fixture . '/app/code/Test/Module');
    rmdir($fixture . '/app/code/Test');
    rmdir($fixture . '/app/code');
    rmdir($fixture . '/app');
    rmdir($fixture);
}

assertWarningRegression($warnings === [], 'MB-R073/MB-R077 emitted PHP warnings: ' . json_encode($warnings));
assertWarningRegression(count($result['findings'] ?? []) === 2, 'Expected findings for both regression rules');

echo "CodeSearchWarningRegressionTest: PASS\n";
