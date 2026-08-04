<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Context;
use Magebean\Engine\ProfileLoader;
use Magebean\Engine\RulePackLoader;
use Magebean\Engine\ScanRunner;

function assertL2Manual(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$control = json_decode(
    (string)file_get_contents(__DIR__ . '/../src/Rules/controls/MB-C15.json'),
    true,
    512,
    JSON_THROW_ON_ERROR
);
$rules = $control['rules'] ?? [];
assertL2Manual(count($rules) === 82, 'Expected 82 ASVS L2 human-review rules');

$expectedIds = array_map(static fn(int $id): string => sprintf('MB-R%03d', $id), range(136, 217));
$actualIds = array_column($rules, 'id');
assertL2Manual($actualIds === $expectedIds, 'ASVS L2 manual rule IDs must be sequential from MB-R136 to MB-R217');

$requirementIds = [];
foreach ($rules as $rule) {
    assertL2Manual(($rule['control'] ?? '') === 'MB-C15', 'L2 manual rule uses the wrong control');
    assertL2Manual(($rule['verification'] ?? '') === 'manual', 'L2 manual rule must declare manual verification');
    assertL2Manual(($rule['checks'][0]['name'] ?? '') === 'human_manual_review_required', 'L2 manual rule uses the wrong check');
    assertL2Manual(count($rule['requirements'] ?? []) === 1, 'Each L2 manual rule must map one requirement');
    $requirementIds[] = (string)($rule['requirements'][0]['id'] ?? '');
}
assertL2Manual(count(array_unique($requirementIds)) === 82, 'L2 manual requirements must be unique');

$rawProfile = json_decode(
    (string)file_get_contents(__DIR__ . '/../src/Rules/profiles/asvs-l2.json'),
    true,
    512,
    JSON_THROW_ON_ERROR
);
$manualCoverage = array_values(array_filter(
    $rawProfile['requirement_coverage'] ?? [],
    static fn(array $entry): bool => ($entry['status'] ?? '') === 'MANUAL_REVIEW'
));
assertL2Manual(count($manualCoverage) === 80, 'Two L2 manual requirements are now supplemented by automated evidence');

$profile = ProfileLoader::load('asvs-l2');
$catalog = RulePackLoader::loadAll();
$selected = ProfileLoader::apply($catalog, $profile);
assertL2Manual(count($selected['rules'] ?? []) === 183, 'ASVS L2 must select 183 non-contextual automated/manual rules');

$context = new Context(__DIR__, '');
$result = (new ScanRunner(
    $context,
    ['rules' => [$rules[0]]],
    null,
    CheckRegistry::fromContext($context)
))->run();
assertL2Manual(($result['findings'][0]['status'] ?? '') === 'MANUAL_REVIEW', 'L2 manual rule must report MANUAL_REVIEW');
assertL2Manual(($result['summary']['manual_review'] ?? 0) === 1, 'L2 manual result must increment manual review summary');
assertL2Manual(($result['summary']['failed'] ?? -1) === 0, 'L2 manual result must not count as failure');

echo "AsvsL2ManualReviewTest: PASS\n";
