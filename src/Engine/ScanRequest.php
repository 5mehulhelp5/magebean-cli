<?php

declare(strict_types=1);

namespace Magebean\Engine;

/** Resolved target and caller options; selection/planning is not performed here. */
final class ScanRequest
{
    public function __construct(
        public readonly ScanContext $context,
        public readonly array $options = []
    ) {
    }
}
