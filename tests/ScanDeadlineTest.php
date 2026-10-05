<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\{ScanDeadline, ScanDeadlineExceeded, ScanRunner, ScanService, ScanPlan, ScanRequest, ScanContext, Context};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Collectors\{CollectorSet, CollectionSession};

function deadlineAssert(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
$now = 10.0;
$clock = static function () use (&$now): float { return $now; };
$deadline = new ScanDeadline(1, $clock);
deadlineAssert($deadline->remainingMilliseconds() === 1000 && !$deadline->expired(), 'Budget starts at the monotonic duration.');
$now = 11;
deadlineAssert($deadline->expired() && $deadline->remainingMilliseconds() === 0, 'Budget expires at its boundary.');
foreach ([0, -1, INF, NAN] as $duration) {
    $thrown = false;
    try { new ScanDeadline($duration); } catch (InvalidArgumentException) { $thrown = true; }
    deadlineAssert($thrown, 'Invalid durations are rejected.');
}
$calls = 0;
$registry = new CheckRegistry();
$registry->register('fixture', static function (array $args) use (&$calls): array { $calls++; return [true, 'pass', []]; });
$rule = static fn(string $id, array $checks, string $op = 'all'): array => ['id' => $id, 'title' => 'Fixture', 'control' => 'T', 'severity' => 'low', 'op' => $op, 'checks' => $checks];
$checks = [['name' => 'fixture', 'args' => []]];
$pack = ['rules' => [$rule('A', $checks), $rule('B', $checks)]];
$report = (new ScanRunner(new Context('.', ''), $pack, null, $registry, $deadline))->runReport();
deadlineAssert($calls === 0 && $report->summary['unknown'] === 2 && $report->summary['failed'] === 0, 'Expired checks become UNKNOWN and never execute.');
deadlineAssert($report->checkResults[0][0]->reasonCode === 'SCAN_DEADLINE_EXCEEDED', 'Deadline reason stays in typed observations.');
$plain = (new ScanRunner(new Context('.', ''), $pack, null, $registry))->run();
deadlineAssert($calls === 2 && $plain['summary']['passed'] === 2, 'Default execution remains unlimited.');
$now = 20;
$deadline = new ScanDeadline(1, $clock);
$registry->register('consuming', static function (array $args) use (&$now): array { $now += 2; return [false, 'confirmed fail', []]; });
$mixed = ['rules' => [$rule('ANY', [['name' => 'consuming'], ['name' => 'fixture']], 'any')]];
$report = (new ScanRunner(new Context('.', ''), $mixed, null, $registry, $deadline))->runReport();
deadlineAssert($report->findings[0]['status'] === 'UNKNOWN', 'ANY must not fail when an alternative was skipped by deadline.');
$now = 20; $deadline = new ScanDeadline(1, $clock);
$mixed['rules'][0]['op'] = 'all';
$report = (new ScanRunner(new Context('.', ''), $mixed, null, $registry, $deadline))->runReport();
deadlineAssert($report->findings[0]['status'] === 'FAIL', 'Confirmed ALL failure remains a finding even if later checks time out.');
$now = 30; $deadline = new ScanDeadline(1, $clock);
$session = new CollectionSession(); $set = new CollectorSet($session);
$session->begin($deadline);
$now = 31;
$thrown = false;
try { $set->files->read('/unused'); } catch (ScanDeadlineExceeded) { $thrown = true; }
deadlineAssert($thrown, 'Deadline cannot masquerade as an unreadable source file that a check skips.');
$attempts = 0; $thrown = false;
try { $set->http->fetch('http://127.0.0.1:1', observe: static function (bool $ok) use (&$attempts): void { $attempts++; }); } catch (ScanDeadlineExceeded) { $thrown = true; }
deadlineAssert($thrown && $attempts === 0, 'Exhausted HTTP budget makes no transport attempt.');
$session->end();
deadlineAssert($session->deadline() === null, 'Cleanup removes the per-scan deadline.');
$now = 40;
$deadline = new ScanDeadline(1, $clock);
$context = new ScanContext('.', '');
$registry = CheckRegistry::fromContext($context->toLegacy(), $set);
$registry->register('interrupted', static function (array $args) use (&$now, $set): array { $now += 2; $set->files->read('/unused'); return [true, 'must never pass']; });
$request = new ScanRequest($context);
$plan = new ScanPlan($request, ['rules' => [$rule('I', [['name' => 'interrupted']])]]);
$heartbeats = 0;
$report = (new ScanService())->run($plan, null, $registry, $deadline, static function () use (&$heartbeats): void { $heartbeats++; });
deadlineAssert($report->summary['unknown'] === 1 && $heartbeats >= 2 && !$session->stats()['active'], 'Collector interruption maps to UNKNOWN and checkpoints/cleanup survive.');
$registry->register('broken', static function (array $args): array { throw new RuntimeException('original'); });
$plan = new ScanPlan($request, ['rules' => [$rule('E', [['name' => 'broken']])]]);
$thrown = false;
try { (new ScanService())->run($plan, null, $registry); } catch (RuntimeException $e) { $thrown = $e->getMessage() === 'original'; }
deadlineAssert($thrown, 'Non-deadline exceptions retain their existing behavior.');
echo "ScanDeadlineTest passed\n";
