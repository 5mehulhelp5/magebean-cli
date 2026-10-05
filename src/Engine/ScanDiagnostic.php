<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Plain diagnostic segments; adapters decide how to present their importance. */
final class ScanDiagnostic
{
    public function __construct(public readonly string $level, public readonly string $label, public readonly string $detail = '') {}
    public function message(): string { return $this->label . $this->detail; }
}
