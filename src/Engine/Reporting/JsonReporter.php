<?php

declare(strict_types=1);

namespace Magebean\Engine\Reporting;

final class JsonReporter implements Reporter
{
    public function write(array $result, string $outFile): void
    {
        file_put_contents($outFile, json_encode($result, JSON_PRETTY_PRINT));
    }
}
