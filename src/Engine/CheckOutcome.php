<?php

declare(strict_types=1);

namespace Magebean\Engine;

/** Check-level outcomes; rule aggregation remains a separate concern. */
enum CheckOutcome: string
{
    case Pass = 'PASS';
    case Fail = 'FAIL';
    case Unknown = 'UNKNOWN';
    case ManualReview = 'MANUAL_REVIEW';
}
