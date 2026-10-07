<?php
declare(strict_types=1);
namespace Magebean\Engine;
final class ScanExitPolicy
{
    public function code(array $result): int
    {
        if (!empty($result['meta']['automation_only']) && !empty($result['execution_errors'])) return 3;
        $failedFindings = array_filter(
            $result['findings'] ?? [],
            static fn(array $finding): bool => strtoupper((string)($finding['status'] ?? '')) === 'FAIL'
        );
        if ($failedFindings === []) {
            return 0;
        }

        foreach ($failedFindings as $finding) {
            if (strtolower((string)($finding['severity'] ?? '')) === 'critical') {
                return 2;
            }
        }

        return 1;
    }
}
