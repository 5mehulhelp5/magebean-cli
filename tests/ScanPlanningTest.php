<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\{ScanContext, ScanRequest, ScanPlanner, ScanService, ScanPlan, ProfileLoader, RulePackLoader};
use Magebean\Engine\Checks\CheckRegistry;

function planningAssert(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}
$planner = new \Magebean\Engine\LegacyScanPlanner();
$root = sys_get_temp_dir() . '/magebean-planning-' . bin2hex(random_bytes(6));
mkdir($root);
try {
    $context = new ScanContext($root, '', '', ['meta' => ['target_mode' => 'LOCAL']]);
    $registry = CheckRegistry::fromContext($context->toLegacy());
    $make = static fn(array $options): ScanRequest => new ScanRequest($context, $options);
    $ids = static fn(ScanPlan $plan): array => array_column($plan->pack['rules'], 'id');
    $events = [];
    $plan = $planner->planCli($make(['rules' => 'MB-R037,missing,mb-r031', 'profile' => 'does-not-exist', 'exclude-rules' => 'mb-r031']), $registry, static function (\Magebean\Engine\ScanDiagnostic $message) use (&$events): void { $events[] = $message; });
    planningAssert($plan !== null && $ids($plan) === ['MB-R037'], 'Explicit selection preserves requested ordering and exclusions.');
    planningAssert($plan->metadata['standard'] === 'explicit-rules' && $plan->metadata['profileRulesTotal'] === 1, 'Explicit metadata counts final selection.');
    planningAssert(count($events) === 2 && str_contains($events[1]->message(), 'missing'), 'Unknown rule diagnostics follow profile bypass.');
    $basic = $planner->planCli($make([]), $registry);
    $expected = ProfileLoader::apply(RulePackLoader::loadAll(), ProfileLoader::load('basic', $root));
    $expected = array_values(array_filter($expected['rules'], static fn(array $rule): bool => strtolower((string)($rule['verification'] ?? 'automated')) !== 'manual'));
    planningAssert($ids($basic) === array_column($expected, 'id'), 'Default basic selection retains catalog/profile order.');
    $all = $planner->planCli($make(['profile' => 'baseline', 'include-manual-review' => true]), $registry);
    $auto = $planner->planCli($make(['profile' => 'baseline']), $registry);
    planningAssert(count($ids($all)) === 371 && count($ids($auto)) === 113 && $auto->metadata['manualRulesExcluded'] === 258, 'Manual policy preserves totals.');
    $invalidEvents = [];
    $invalid = $planner->planCli($make(['rules' => 'missing']), $registry, static function (\Magebean\Engine\ScanDiagnostic $message) use (&$invalidEvents): void { $invalidEvents[] = $message; });
    planningAssert($invalid === null && count($invalidEvents) === 3, 'Invalid explicit selection never becomes executable.');
    $invalid = $planner->planCli($make(['rules' => 'MB-R031', 'exclude-rules' => 'MB-R031']), $registry);
    planningAssert($invalid === null, 'CLI excludes every rule: reject plan before execution.');
    $remoteContext = new ScanContext('URL:https://fixture.example', 'https://fixture.example', '', ['meta' => ['target_mode' => 'REMOTE']]);
    $remote = $planner->planCli(new ScanRequest($remoteContext, ['profile' => 'baseline']), CheckRegistry::fromContext($remoteContext->toLegacy()));
    planningAssert(count($ids($remote)) === 10 && $remote->metadata['configFile'] === null, 'Remote catalog does not discover local project policy.');
    foreach ([['controls' => 'invalid'], ['pci-context' => 'context.json']] as $options) {
        $thrown = false;
        try { $planner->planCli($make($options), $registry); } catch (RuntimeException) { $thrown = true; }
        planningAssert($thrown, 'Invalid controls / PCI options retain exceptions.');
    }
    // A project policy must not affect agent manifest planning.
    file_put_contents($root . '/.magebean.json', '{broken');
    $manifest = ['schema_version' => '1.0', 'rules' => [
        ['rule_key' => 'MB-R037', 'assessment_item_id' => 'first'],
        ['rule_key' => 'mb-r031', 'assessment_item_id' => 'second'],
        ['rule_key' => 'mb-r037', 'assessment_item_id' => 'replacement'],
        ['rule_key' => 'missing', 'assessment_item_id' => 'third'],
    ]];
    $agent = $planner->planAgent($make(['manifest' => $manifest]));
    planningAssert($ids($agent) === ['MB-R037', 'MB-R031'] && $agent->metadata['manifestIndex']['MB-R037']['assessment_item_id'] === 'replacement', 'Agent manifest order and duplicate overwrite remain compatible.');
    planningAssert(count($agent->metadata['unsupported']) === 1 && $agent->metadata['unsupported'][0]['rule_key'] === 'MISSING', 'Unsupported results remain separate from executed findings.');
    $empty = $planner->planAgent($make(['manifest' => ['schema_version' => '1.0', 'rules' => [['rule_key' => 'missing', 'assessment_item_id' => 'id']]]]));
    $report = (new ScanService())->run($empty)->toLegacy();
    planningAssert($report['summary']['total'] === 0 && !isset($report['meta']), 'Unsupported-only agent payload preserves empty summary and absent metadata.');
    $thrown = false;
    try { (new ScanService())->run(new ScanPlan($make([]), ['rules' => []])); } catch (RuntimeException) { $thrown = true; }
    planningAssert($thrown, 'Service rejects empty plans without agent policy.');
    $progress = [];
    $rule = ['id' => 'TEST', 'title' => 'Fixture', 'control' => 'TEST', 'severity' => 'low', 'checks' => [['name' => 'phase3_fixture', 'args' => []]]];
    $registry->register('phase3_fixture', static fn(array $args): array => [true, 'Fixture pass', []]);
    $result = (new ScanService())->run(new ScanPlan($make([]), ['rules' => [$rule]]), static function (array $event) use (&$progress): void { $progress[] = $event; }, $registry);
    planningAssert($result->summary['passed'] === 1 && count($result->checkResults) === 1 && count($progress) === 2, 'Shared service retains injected registry, observations and progress.');
    $immutable = false;
    try { $agent->pack['rules'] = []; } catch (Error) { $immutable = true; }
    planningAssert($immutable, 'Plans are immutable.');
} finally {
    if (is_file($root . '/.magebean.json')) unlink($root . '/.magebean.json');
    rmdir($root);
}
echo "ScanPlanningTest passed\n";
