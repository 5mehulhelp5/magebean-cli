<?php

declare(strict_types=1);

namespace Magebean\Engine\Reporting;

final class SarifReporter implements Reporter
{
    public function write(array $result, string $outFile): void
    {
        $runs = [];
        foreach ($result['findings'] ?? [] as $f) {
            $status = strtoupper((string)($f['status'] ?? 'UNKNOWN'));
            if ($status === 'PASS') continue;
            $runs[] = [
                'ruleId' => (string)$f['id'],
                'level' => $status === 'FAIL' ? 'error' : 'note',
                'message' => ['text' => (string)($f['message'] ?? $f['title'] ?? '')],
                'properties' => ['magebean_status' => $status],
            ];
        }
        $sarif = ['version' => '2.1.0', 'runs' => [['tool' => ['driver' => ['name' => 'magebean-cli']], 'results' => $runs]]];
        file_put_contents($outFile, json_encode($sarif, JSON_PRETTY_PRINT));
    }
}
