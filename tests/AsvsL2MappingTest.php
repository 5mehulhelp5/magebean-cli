<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\ProfileLoader;
use Magebean\Engine\RulePackLoader;

function assertAsvsL2(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$raw = json_decode((string)file_get_contents(__DIR__ . '/../src/Rules/profiles/asvs-l2.json'), true);
assertAsvsL2(is_array($raw), 'ASVS L2 profile JSON is invalid');
assertAsvsL2(($raw['inherits'] ?? []) === ['asvs-l1'], 'ASVS L2 must inherit asvs-l1');
assertAsvsL2(count($raw['requirement_coverage'] ?? []) === 183, 'ASVS L2 must declare exactly 183 additions');

$profile = ProfileLoader::load('asvs-l2');
$coverage = $profile['requirement_coverage'] ?? [];
assertAsvsL2(count($coverage) === 253, 'Inherited ASVS L2 profile must contain 253 requirements');
$ids = array_map(static fn(array $entry): string => (string)($entry['id'] ?? ''), $coverage);
assertAsvsL2(count(array_unique($ids)) === 253, 'ASVS L2 requirement IDs must be unique');

$allowed = ['AUTOMATED', 'PARTIALLY_AUTOMATED', 'MANUAL_REVIEW', 'CONTEXT_REQUIRED', 'NOT_APPLICABLE', 'NOT_YET_COVERED'];
$counts = array_fill_keys($allowed, 0);
foreach ($coverage as $entry) {
    $status = (string)($entry['status'] ?? '');
    assertAsvsL2(in_array($status, $allowed, true), 'Unknown L2 coverage status for ' . ($entry['id'] ?? ''));
    $counts[$status]++;
    if (in_array($status, ['NOT_APPLICABLE', 'NOT_YET_COVERED'], true)) {
        assertAsvsL2(($entry['rules'] ?? []) === [], $status . ' requirement must not claim rule coverage');
    }
    if ($status === 'CONTEXT_REQUIRED') {
        assertAsvsL2(isset($entry['applicability']['capability']), 'Context-required entry must declare a capability');
    }
}

$summary = $profile['coverage_summary'] ?? [];
foreach ([
    'automated'=>'AUTOMATED',
    'partially_automated'=>'PARTIALLY_AUTOMATED',
    'manual_review'=>'MANUAL_REVIEW',
    'context_required'=>'CONTEXT_REQUIRED',
    'not_applicable'=>'NOT_APPLICABLE',
    'not_yet_covered'=>'NOT_YET_COVERED',
] as $key => $status) {
    assertAsvsL2((int)($summary[$key] ?? -1) === $counts[$status], 'L2 summary mismatch for ' . $key);
}

$catalog = RulePackLoader::loadAll();
$selected = ProfileLoader::apply($catalog, $profile);
assertAsvsL2(count($selected['rules'] ?? []) === 183, 'Default ASVS L2 selection must exclude contextual rules');

$byId = [];
foreach ($profile['rules'] ?? [] as $mapping) {
    if (is_array($mapping)) {
        $byId[strtoupper((string)($mapping['id'] ?? ''))] = $mapping;
    }
}
$r016Requirements = array_column($byId['MB-R016']['mappings'] ?? [], 'requirement');
assertAsvsL2(in_array('1.2.2', $r016Requirements, true), 'Inherited L1 mapping is missing from MB-R016');
assertAsvsL2(in_array('1.3.6', $r016Requirements, true), 'L2 mapping is missing from MB-R016');

echo "AsvsL2MappingTest: PASS\n";
