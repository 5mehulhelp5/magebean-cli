<?php
declare(strict_types=1);
namespace Magebean\Engine;
use Magebean\Engine\Checks\CheckRegistry;

/** Shared execution entry point. Reporting and transport stay with their adapters. */
final class ScanService
{
    public function run(ScanPlan $plan, ?callable $progress = null, ?CheckRegistry $registry = null, ?ScanDeadline $deadline = null, ?callable $checkpoint = null): ScanReport
    {
        if (empty($plan->pack['rules'])) {
            if (!$plan->allowEmpty) throw new \RuntimeException('Cannot execute an empty scan plan.');
            // Agent compatibility: unsupported-only manifests have no runner metadata.
            return ScanReport::fromLegacy(['summary' => ['passed' => 0, 'failed' => 0, 'unknown' => 0, 'manual_review' => 0, 'total' => 0], 'findings' => []]);
        }
        return (new ScanRunner($plan->request->context, $plan->pack, $progress, $registry, $deadline, $checkpoint))->runReport();
    }
}
