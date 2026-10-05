<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** An immutable selection ready for execution, with adapter-specific metadata. */
final class ScanPlan
{
    public function __construct(
        public readonly ScanRequest $request,
        public readonly array $pack,
        public readonly array $metadata = [],
        public readonly bool $allowEmpty = false
    ) {}
}
