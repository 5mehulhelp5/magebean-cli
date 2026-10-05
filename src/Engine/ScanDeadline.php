<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Monotonic, cooperative budget. A null deadline preserves unlimited execution. */
final class ScanDeadline
{
    private $clock;
    private readonly float $expiresAt;

    public function __construct(float $seconds, ?callable $clock = null)
    {
        if (!is_finite($seconds) || $seconds <= 0) throw new \InvalidArgumentException('Scan deadline must be a positive finite duration.');
        $this->clock = $clock ?? static fn(): float => hrtime(true) / 1e9;
        $this->expiresAt = ($this->clock)() + $seconds;
    }

    public function expired(): bool { return ($this->clock)() >= $this->expiresAt; }
    public function remainingMilliseconds(): int
    {
        return max(0, (int)ceil(($this->expiresAt - ($this->clock)()) * 1000));
    }
}
