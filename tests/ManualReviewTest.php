<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Console\ScanCommand;
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Context;
use Magebean\Engine\ScanRunner;
use Symfony\Component\Console\Output\BufferedOutput;

function assertManualReview(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$catalog = json_decode(
    (string)file_get_contents(__DIR__ . '/../src/Rules/controls/MB-C13.json'),
    true,
    512,
    JSON_THROW_ON_ERROR
);
assertManualReview(count($catalog['rules'] ?? []) === 28, 'Expected 28 ASVS L1 human-review rules');

$rule = ($catalog['rules'] ?? [])[0] ?? [];
$result = (new ScanRunner(
    new Context(__DIR__, ''),
    ['rules' => [$rule]],
    null,
    CheckRegistry::fromContext(new Context(__DIR__, ''))
))->run();

assertManualReview(($result['findings'][0]['status'] ?? '') === 'MANUAL_REVIEW', 'Manual rule must use MANUAL_REVIEW status');
assertManualReview(
    array_key_exists('passed', $result['findings'][0]) && $result['findings'][0]['passed'] === null,
    'Manual rule must not pass or fail automatically'
);
assertManualReview(($result['summary']['manual_review'] ?? 0) === 1, 'Summary must count manual review separately');
assertManualReview(($result['summary']['failed'] ?? -1) === 0, 'Manual review must not count as a failed finding');
assertManualReview(
    ($result['findings'][0]['detail'][0]['status'] ?? '') === 'MANUAL_REVIEW',
    'Check detail must preserve MANUAL_REVIEW status'
);

$result['meta']['rules_filter'] = [];
$result['meta']['standard'] = 'asvs';
$result['meta']['profile'] = ['title' => 'ASVS Level 1'];
$output = new BufferedOutput();
$render = new ReflectionMethod(new ScanCommand(), 'renderPrettySummary');
$render->setAccessible(true);
$render->invoke(new ScanCommand(), $output, $result, __DIR__);
$text = $output->fetch();

assertManualReview(str_contains($text, 'HUMAN REVIEW REQUIRED'), 'Console summary must announce required human review');
assertManualReview(str_contains($text, '[MANUAL REVIEW]'), 'Console result must label the manual-review rule');
assertManualReview(str_contains($text, 'MB-R102'), 'Console result must show the manual-review rule ID');

echo "ManualReviewTest: PASS\n";
