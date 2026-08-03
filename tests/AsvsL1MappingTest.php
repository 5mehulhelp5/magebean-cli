<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\ProfileLoader;
use Magebean\Engine\RulePackLoader;

function assertAsvsMapping(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$profile = ProfileLoader::load('asvs-l1');
$coverage = $profile['requirement_coverage'] ?? [];
assertAsvsMapping(count($coverage) === 70, 'ASVS L1 mapping must contain exactly 70 requirements');

$ids = array_map(static fn(array $entry): string => (string)($entry['id'] ?? ''), $coverage);
assertAsvsMapping(count(array_unique($ids)) === 70, 'ASVS L1 requirement IDs must be unique');
assertAsvsMapping(!in_array('', $ids, true), 'ASVS L1 mapping contains an empty requirement ID');

$allowedStatuses = ['AUTOMATED', 'PARTIALLY_AUTOMATED', 'MANUAL_REVIEW', 'NOT_YET_COVERED'];
$counts = array_fill_keys($allowedStatuses, 0);
foreach ($coverage as $entry) {
    $status = (string)($entry['status'] ?? '');
    assertAsvsMapping(in_array($status, $allowedStatuses, true), 'Unknown coverage status for ' . ($entry['id'] ?? ''));
    $counts[$status]++;
    if ($status === 'NOT_YET_COVERED') {
        assertAsvsMapping(($entry['rules'] ?? []) === [], 'NOT_YET_COVERED requirements must not claim rule coverage');
    }
}

$summary = $profile['coverage_summary'] ?? [];
assertAsvsMapping((int)($summary['automated'] ?? -1) === $counts['AUTOMATED'], 'Automated summary count mismatch');
assertAsvsMapping((int)($summary['partially_automated'] ?? -1) === $counts['PARTIALLY_AUTOMATED'], 'Partial summary count mismatch');
assertAsvsMapping((int)($summary['manual_review'] ?? -1) === $counts['MANUAL_REVIEW'], 'Manual summary count mismatch');
assertAsvsMapping((int)($summary['not_yet_covered'] ?? -1) === $counts['NOT_YET_COVERED'], 'Gap summary count mismatch');

$catalog = RulePackLoader::loadAll();
$catalogIds = array_fill_keys(array_map(
    static fn(array $rule): string => strtoupper((string)($rule['id'] ?? '')),
    $catalog['rules'] ?? []
), true);
foreach ($profile['rules'] ?? [] as $mapping) {
    $ruleId = strtoupper((string)($mapping['id'] ?? ''));
    assertAsvsMapping(isset($catalogIds[$ruleId]), 'Profile references unknown rule ' . $ruleId);
}

$selected = ProfileLoader::apply($catalog, $profile);
assertAsvsMapping(
    count($selected['rules'] ?? []) === count($profile['rules'] ?? []),
    'ProfileLoader did not select every mapped ASVS L1 rule'
);
foreach ($selected['rules'] ?? [] as $rule) {
    assertAsvsMapping(isset($rule['profile']['mapping']), 'Selected rule is missing profile mapping metadata');
}

echo "AsvsL1MappingTest: PASS\n";
