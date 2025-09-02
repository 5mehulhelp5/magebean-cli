<?php

declare(strict_types=1);

namespace Magebean\Engine;

final class Rule
{
    public static function requiredKeys(): array
    {
        return ['id', 'title', 'control', 'severity', 'checks'];
    }
}
