<?php
declare(strict_types=1);
namespace Magebean\Agent;
use Magebean\Engine\{ScanContext, ScanRequest, ScanPlanner, ScanService, ScanDeadline};
final class AgentScanner
{
    public function run(string $magentoPath, array $manifest, ?callable $progress = null, ?ScanDeadline $deadline = null, ?callable $checkpoint = null): array
    {
        $request = new ScanRequest(new ScanContext($magentoPath, ''), ['manifest' => $manifest]);
        $plan = (new ScanPlanner())->planAgent($request);
        $manifestIndex = $plan->metadata['manifestIndex'];
        $unsupported = $plan->metadata['unsupported'];
        $result = (new ScanService())->run($plan, $progress, null, $deadline, $checkpoint)->toLegacy();
        return (new AgentResultMapper())->map($result, $manifest, $manifestIndex, $unsupported, $magentoPath, $plan->metadata['manifestBindings'] ?? []);
    }

    /** Compatibility wrapper for existing title callers. */
    private function resultTitle(array $result): string
    {
        return (new AgentResultMapper())->resultTitle($result);
    }
}
