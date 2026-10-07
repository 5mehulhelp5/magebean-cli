<?php
declare(strict_types=1);
namespace Magebean\Engine;

final class RequirementAssessment
{
    public function __construct(
        public readonly RequirementOutcome $outcome,
        public readonly string $message,
        public readonly array $evidence,
        public readonly string $reasonCode,
        public readonly array $applicability
    ) {}
}
