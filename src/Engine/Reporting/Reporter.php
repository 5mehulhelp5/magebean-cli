<?php

declare(strict_types=1);

namespace Magebean\Engine\Reporting;

interface Reporter
{
    public function write(array $result, string $outFile): void;
}
