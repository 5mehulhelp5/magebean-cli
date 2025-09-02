<?php

declare(strict_types=1);

namespace Magebean\Engine;

final class RulePack
{
    public array $controls = [];
    public array $rules = [];
    public static function fromArrays(array $controls, array $rules): self
    {
        $o = new self;
        $o->controls = $controls;
        $o->rules = $rules;
        return $o;
    }
}
