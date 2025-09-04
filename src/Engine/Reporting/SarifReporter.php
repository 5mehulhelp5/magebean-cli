<?php

declare(strict_types=1);

namespace Magebean\Engine\Reporting;

final class SarifReporter implements Reporter
{
    public function write(array $result, string $outFile): void
    {
        $runs = [];
        foreach ($result['findings'] as $f) {
            $runs[] = ['ruleId' => $f['id'], 'level' => $f['passed'] ? 'note' : 'error', 'message' => ['text' => $f['title']]];
        }
        $sarif = ['version' => '2.1.0', 'runs' => [['results' => $runs]]];
        file_put_contents($outFile, json_encode($sarif, JSON_PRETTY_PRINT));
    }
}
