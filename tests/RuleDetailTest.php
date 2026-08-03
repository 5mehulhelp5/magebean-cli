<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Console\ScanCommand;
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Context;
use Magebean\Engine\ScanRunner;
use Symfony\Component\Console\Output\BufferedOutput;

function assertRuleDetail(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "RuleDetailTest: {$message}\n");
        exit(1);
    }
}

$registry = new CheckRegistry();
$registry->register('test_pass', static fn(array $args): array => [true, "Pass detail\nsecond pass line", ['value' => 1]]);
$registry->register('test_fail', static fn(array $args): array => [false, "Fail detail\nsecond fail line", ['value' => 2]]);

$pack = ['rules' => [
    [
        'id' => 'MB-TEST-PASS',
        'title' => 'Passing detail rule',
        'control' => 'MB-TEST',
        'severity' => 'low',
        'checks' => [['name' => 'test_pass']],
    ],
    [
        'id' => 'MB-TEST-FAIL',
        'title' => 'Failing detail rule',
        'control' => 'MB-TEST',
        'severity' => 'high',
        'checks' => [['name' => 'test_fail']],
    ],
]];

$result = (new ScanRunner(new Context(__DIR__, ''), $pack, null, $registry))->run();
assertRuleDetail(count($result['findings']) === 2, 'expected two findings');
assertRuleDetail(($result['findings'][0]['detail'][0]['check'] ?? '') === 'test_pass', 'missing structured check name');
assertRuleDetail(($result['findings'][0]['detail'][0]['status'] ?? '') === 'PASS', 'missing PASS detail status');
assertRuleDetail(($result['findings'][1]['detail'][0]['status'] ?? '') === 'FAIL', 'missing FAIL detail status');
assertRuleDetail(str_contains($result['findings'][1]['detail'][0]['message'] ?? '', 'second fail line'), 'multiline detail was truncated');

$result['meta'] = [
    'rules_filter' => ['MB-TEST-PASS', 'MB-TEST-FAIL'],
    'standard' => 'magebean',
    'profile' => ['title' => 'Detail test'],
];
$output = new BufferedOutput();
$render = new ReflectionMethod(new ScanCommand(), 'renderPrettySummary');
$render->setAccessible(true);
$render->invoke(new ScanCommand(), $output, $result, __DIR__);
$text = $output->fetch();

assertRuleDetail(str_contains($text, 'Rule details'), 'selected-rule detail heading was not rendered');
assertRuleDetail(str_contains($text, '[PASS]'), 'selected PASS rule was not rendered');
assertRuleDetail(str_contains($text, 'MB-TEST-PASS'), 'selected PASS rule id was not rendered');
assertRuleDetail(str_contains($text, 'test_pass [PASS]: Pass detail'), 'PASS check detail was not rendered');
assertRuleDetail(str_contains($text, 'test_fail [FAIL]: Fail detail'), 'FAIL check detail was not rendered');
assertRuleDetail(str_contains($text, 'second fail line'), 'multiline check detail was not rendered');

echo "RuleDetailTest: PASS\n";
