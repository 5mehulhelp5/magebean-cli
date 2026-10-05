<?php
declare(strict_types=1);
namespace Magebean\Engine;
final class ScanExitPolicy
{
    public function code(array $result): int
    {
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
