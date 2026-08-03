<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Context;
use Magebean\Engine\ScanRunner;

function assertAutomatedAsvs(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$catalog = json_decode(
    (string)file_get_contents(__DIR__ . '/../src/Rules/controls/MB-C14.json'),
    true,
    512,
    JSON_THROW_ON_ERROR
);
$rules = [];
foreach ($catalog['rules'] ?? [] as $rule) {
    $rules[$rule['id']] = $rule;
}
assertAutomatedAsvs(count($rules) === 6, 'Expected six new automated ASVS rules');

$root = sys_get_temp_dir() . '/magebean-asvs-auto-' . bin2hex(random_bytes(6));
mkdir($root . '/app', 0777, true);
file_put_contents($root . '/app/unsafe.js', <<<'JS'
const socket = new WebSocket('ws://example.com/events');
const endpoint = 'https://api.example.com/reset?access_token=secret';
const cipher = 'aes-256-ecb';
JS);

$context = new Context($root, '');
foreach (['MB-R131', 'MB-R132', 'MB-R133'] as $id) {
    $result = (new ScanRunner(
        $context,
        ['rules' => [$rules[$id]]],
        null,
        CheckRegistry::fromContext($context)
    ))->run();
    assertAutomatedAsvs(
        ($result['findings'][0]['status'] ?? '') === 'FAIL',
        $id . ' should detect its unsafe fixture'
    );
}

file_put_contents($root . '/app/unsafe.js', <<<'JS'
const socket = new WebSocket('wss://example.com/events');
const endpoint = 'https://api.example.com/reset';
const cipher = 'aes-256-gcm';
JS);
foreach (['MB-R131', 'MB-R132', 'MB-R133'] as $id) {
    $result = (new ScanRunner(
        $context,
        ['rules' => [$rules[$id]]],
        null,
        CheckRegistry::fromContext($context)
    ))->run();
    assertAutomatedAsvs(
        ($result['findings'][0]['status'] ?? '') === 'PASS',
        $id . ' should pass its safe fixture'
    );
}

unlink($root . '/app/unsafe.js');
rmdir($root . '/app');
rmdir($root);

echo "AutomatedAsvsRulesTest: PASS\n";
