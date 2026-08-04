<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Context;
use Magebean\Engine\ProfileLoader;
use Magebean\Engine\ScanRunner;

function assertL2Automated(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$control = json_decode(
    (string)file_get_contents(__DIR__ . '/../src/Rules/controls/MB-C17.json'),
    true,
    512,
    JSON_THROW_ON_ERROR
);
$rules = $control['rules'] ?? [];
assertL2Automated(array_column($rules, 'id') === ['MB-R273', 'MB-R274', 'MB-R275'], 'Unexpected L2 automated rule IDs');
assertL2Automated(($rules[2]['applicability']['capability'] ?? '') === 'graphql', 'GraphQL rule must be capability-dependent');

$context = new Context(__DIR__, '');
$result = (new ScanRunner(
    $context,
    ['rules' => $rules],
    null,
    CheckRegistry::fromContext($context)
))->run();
foreach ($result['findings'] ?? [] as $finding) {
    assertL2Automated(($finding['status'] ?? '') === 'UNKNOWN', 'HTTP-dependent L2 rule must be inconclusive without a URL');
}
assertL2Automated(($result['summary']['failed'] ?? -1) === 0, 'Missing URL must not create automated L2 failures');
assertL2Automated(($result['summary']['unknown'] ?? 0) === 3, 'All three HTTP-dependent rules must be unknown without a URL');

$profile = ProfileLoader::load('asvs-l2');
$profileRules = [];
foreach ($profile['rules'] ?? [] as $mapping) {
    if (is_array($mapping)) {
        $profileRules[(string)($mapping['id'] ?? '')] = $mapping;
    }
}
assertL2Automated(isset($profileRules['MB-R273'], $profileRules['MB-R274'], $profileRules['MB-R275']), 'Automated L2 profile mappings are incomplete');

echo "AsvsL2AutomatedRulesTest: PASS\n";
