<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\{CheckOutcome, CheckResult, Context, ScanContext, ScanReport, ScanRequest, ScanRunner};
use Magebean\Engine\Checks\CheckRegistry;

function contractsAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException('ScanContractsTest: ' . $message);
}

$legacy = new Context('/fixture/', 'https://canonical.example', 'cve.json', ['url' => 'https://legacy.example', 'path' => '/wrong', 'meta' => ['mode' => 'LOCAL']]);
$context = $legacy->toScanContext();
contractsAssert($legacy->get('url') === 'https://legacy.example', 'Existing mutable Context semantics must remain intact.');
contractsAssert($context->url === $context->get('url') && $context->url === 'https://canonical.example', 'New context must have one canonical URL.');
contractsAssert($context->path === $context->get('path') && !array_key_exists('path', $context->settings) && !array_key_exists('url', $context->settings) && !array_key_exists('cve_data', $context->settings), 'Reserved settings cannot compete with canonical targets.');
contractsAssert($context->get('meta') === ['mode' => 'LOCAL'] && $context->get('absent', 'fallback') === 'fallback', 'Settings/defaults survive migration.');
contractsAssert($context->toLegacy()->get('url') === $context->url && $context->toLegacy()->cveData === 'cve.json', 'Legacy checks must see the canonical target.');
foreach (['', '.', 'app/etc/env.php', '/absolute/file', 'C:\\fixture\\file'] as $path)
    contractsAssert($context->abs($path) === $context->toLegacy()->abs($path), 'Path resolution compatibility: ' . $path);
$adapter = $context->toLegacy(); $adapter->url = 'changed';
contractsAssert($context->url === 'https://canonical.example', 'Mutating an adapter must not mutate the canonical context.');

$request = new ScanRequest($context, ['profile' => 'basic', 'rules' => ['MB-R001']]);
$immutable = false;
try { $request->options['profile'] = 'pci'; } catch (Error) { $immutable = true; }
contractsAssert($immutable && $request->options['profile'] === 'basic', 'Request options must be immutable.');
$immutable = false;
try { $context->url = 'changed'; } catch (Error) { $immutable = true; }
contractsAssert($immutable, 'ScanContext fields must be immutable.');

foreach ([
    [[true, 'pass'], CheckOutcome::Pass, [true, 'pass', []]],
    [[false, 'fail', ['file' => 'x']], CheckOutcome::Fail, [false, 'fail', ['file' => 'x']]],
    [[null, '[UNKNOWN] unavailable', 'scalar evidence'], CheckOutcome::Unknown, [null, '[UNKNOWN] unavailable', ['scalar evidence']]],
    [[null, '[MANUAL_REVIEW] review', null], CheckOutcome::ManualReview, [null, '[MANUAL_REVIEW] review', []]],
    [[1, 'historical non-boolean'], CheckOutcome::Unknown, [1, 'historical non-boolean', []]],
    [[], CheckOutcome::Unknown, [null, '', []]],
] as [$tuple, $outcome, $expected]) {
    $result = CheckResult::fromLegacy($tuple, 'fixture');
    contractsAssert($result->outcome === $outcome && $result->toLegacy() === $expected && $result->checkName === 'fixture', 'Legacy normalization must match the historical runner.');
}
$manual = CheckResult::of(CheckOutcome::ManualReview, 'Review deployment', ['scope' => ['admin']], 'human_confirmation');
contractsAssert($manual->message === 'Review deployment' && $manual->toLegacy() === [null, '[MANUAL_REVIEW] Review deployment', ['scope' => ['admin']]], 'Typed outcome must adapt without requiring a message prefix from producers.');
$named = $manual->forCheck('actual_check');
contractsAssert($named->reasonCode === 'human_confirmation' && $named->checkName === 'actual_check' && $manual->checkName === '', 'Naming must retain reason and not mutate the observation.');
$immutable = false;
try { $manual->evidence['scope'][] = 'other'; } catch (Error) { $immutable = true; }
contractsAssert($immutable, 'Result evidence array must be immutable.');
foreach ([CheckOutcome::Pass, CheckOutcome::Unknown] as $conflict) {
    $rejected = false;
    try { CheckResult::of($conflict, '[MANUAL_REVIEW] conflicting fixture'); } catch (InvalidArgumentException) { $rejected = true; }
    contractsAssert($rejected, 'New typed producers cannot conflict with reserved legacy status markers.');
}

$typed = new CheckRegistry(); $old = new CheckRegistry();
foreach ([CheckOutcome::Pass, CheckOutcome::Fail, CheckOutcome::Unknown, CheckOutcome::ManualReview] as $outcome) {
    $result = CheckResult::of($outcome, 'Fixture ' . $outcome->value, ['source' => $outcome->value], 'fixture_reason');
    $typed->register($outcome->value, static fn(array $args): CheckResult => $result);
    $old->register($outcome->value, static fn(array $args): array => $result->toLegacy());
    contractsAssert($typed->run($outcome->value, []) === $old->run($outcome->value, []), 'Typed registration must preserve the legacy registry API.');
    contractsAssert($typed->runResult($outcome->value, [])->reasonCode === 'fixture_reason' && $typed->runResult($outcome->value, [])->checkName === $outcome->value, 'Typed registry must retain reason/provenance.');
}
$rules = [];
foreach (['all', 'any'] as $op) foreach (CheckOutcome::cases() as $left) foreach (CheckOutcome::cases() as $right) {
    $rules[] = ['id' => $op . '-' . $left->value . '-' . $right->value, 'title' => 'Fixture', 'control' => 'QA', 'severity' => 'low', 'op' => $op, 'checks' => [['name' => $left->value], ['name' => $right->value]]];
}
$typedEvents = []; $legacyEvents = [];
$report = (new ScanRunner($context, ['rules' => $rules], static function (array $event) use (&$typedEvents): void { $typedEvents[] = $event; }, $typed))->runReport();
$array = (new ScanRunner($context->toLegacy(), ['rules' => $rules], static function (array $event) use (&$legacyEvents): void { $legacyEvents[] = $event; }, $old))->run();
contractsAssert($report->toLegacy() === $array && $typedEvents === $legacyEvents, 'Typed/legacy callers must agree on all 32 outcome combinations and progress events.');
contractsAssert($report->summary === $array['summary'] && $report->findings === $array['findings'], 'Report contract must expose the same summary/findings.');
contractsAssert($report->checkResults[0][0]->reasonCode === 'fixture_reason' && $report->checkResults[0][0]->checkName === 'PASS', 'Typed report must retain observations/reasons that are absent from the legacy wire format.');
contractsAssert($report->withMeta(['fixture' => true])->checkResults === $report->checkResults, 'Enrichment must retain internal observations.');
$anyPassIndex = 16;
contractsAssert(count($report->checkResults[$anyPassIndex]) === 1, 'Observations must reflect the existing any short circuit, not execute extra checks.');
contractsAssert($typed->runResult('missing', [])->toLegacy() === $typed->run('missing', []), 'Unknown registration fallback must stay compatible.');
$typed->registerPrefix('extension_', static fn(string $name, array $args): CheckResult => CheckResult::of(CheckOutcome::Unknown, 'Unavailable fixture', [], 'extension_unavailable'));
contractsAssert($typed->runResult('extension_fixture', [])->checkName === 'extension_fixture' && $typed->runResult('extension_fixture', [])->reasonCode === 'extension_unavailable', 'Prefix registration must retain the actual dispatched check name and reason.');
$old->register('short_tuple', static fn(array $args): array => [true, 'short']);
contractsAssert($old->run('short_tuple', []) === [true, 'short'] && $old->runResult('short_tuple', [])->toLegacy() === [true, 'short', []], 'Direct legacy registry callers must retain the original tuple length.');

$payload = ['summary' => ['total' => 0], 'findings' => [], 'meta' => ['profile' => 'pci'], 'pci' => ['requirements' => []], 'cve_audit' => null, 'future_extension' => ['x' => 1]];
$envelope = ScanReport::fromLegacy($payload);
contractsAssert($envelope->toLegacy() === $payload && json_encode($envelope) === json_encode($payload), 'Report adaptation must preserve wire keys, ordering, null values and extensions.');
$extended = $envelope->withMeta(['target_mode' => 'LOCAL'])->withSection('future_extension', ['x' => 2]);
contractsAssert($extended->meta === ['profile' => 'pci', 'target_mode' => 'LOCAL'] && $envelope->toLegacy() === $payload, 'Report enrichment must preserve the original immutable report.');
$noMeta = ['summary' => ['total' => 0], 'findings' => []];
contractsAssert(ScanReport::fromLegacy($noMeta)->toLegacy() === $noMeta, 'Adapters must not invent an absent meta wire field.');
$rejected = false;
try { $envelope->withSection('findings', []); } catch (InvalidArgumentException) { $rejected = true; }
contractsAssert($rejected, 'Extension API cannot overwrite reserved report sections.');
foreach ([[], ['summary' => [], 'findings' => 'wrong'], ['summary' => [], 'findings' => [], 'meta' => null]] as $bad) {
    $rejected = false;
    try { ScanReport::fromLegacy($bad); } catch (InvalidArgumentException) { $rejected = true; }
    contractsAssert($rejected, 'Malformed report envelopes must fail at the contract boundary.');
}
$rejected = false;
try { ScanReport::fromLegacy($noMeta, [[$manual]]); } catch (InvalidArgumentException) { $rejected = true; }
contractsAssert($rejected, 'Internal observations cannot be attached to nonexistent findings.');

echo "ScanContractsTest: PASS\n";
