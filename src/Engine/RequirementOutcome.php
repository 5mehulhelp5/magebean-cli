<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Requirement conclusions are distinct from bounded check observations. */
enum RequirementOutcome: string
{
    case Pass = 'PASS';
    case Fail = 'FAIL';
    case Unknown = 'UNKNOWN';
    case ManualReview = 'MANUAL_REVIEW';
}
