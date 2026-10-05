<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;

/** Bounded, in-memory observations belonging to one runner invocation. */
final class CollectionSession
{
    private ?\Magebean\Engine\ScanDeadline $deadline = null;
    private $checkpoint = null;
    private bool $active = false;
    private array $values = [];
    private int $bytes = 0;
    private array $counts = ['hits' => 0, 'misses' => 0];

    public function __construct(private int $maxBytes = 8388608, private int $maxEntries = 256) {}

    public function deadline(): ?\Magebean\Engine\ScanDeadline { return $this->deadline; }

    public function begin(?\Magebean\Engine\ScanDeadline $deadline = null, ?callable $checkpoint = null): void
    {
        if ($this->active) throw new \LogicException('Collection session is already active.');
        $this->values = []; $this->bytes = 0;
        $this->counts = ['hits' => 0, 'misses' => 0];
        $this->deadline = $deadline;
        $this->checkpoint = $checkpoint;
        $this->active = true;
    }

    public function end(): void
    {
        $this->active = false;
        $this->deadline = null;
        $this->checkpoint = null;
        $this->values = []; $this->bytes = 0;
    }

    public function checkpoint(): void
    {
        if ($this->checkpoint !== null) ($this->checkpoint)();
        if ($this->deadline?->expired()) throw new \Magebean\Engine\ScanDeadlineExceeded('Scan deadline exceeded.');
    }

    /** Failures and oversize values are never retained. Loader exceptions propagate. */
    public function remember(string $key, callable $load): mixed
    {
        $this->checkpoint();
        if ($this->active && array_key_exists($key, $this->values)) {
            $this->counts['hits']++;
            return $this->values[$key];
        }
        $this->counts['misses']++;
        $value = $load();
        if (!$this->active || $value === false || $value === null || count($this->values) >= $this->maxEntries) return $value;
        if (is_array($value) && count($value) > 50000) return $value;
        $size = is_string($value) ? strlen($value) : strlen(serialize($value));
        if ($size <= $this->maxBytes - $this->bytes) {
            $this->values[$key] = $value;
            $this->bytes += $size;
        }
        return $value;
    }

    public function stats(): array
    {
        return $this->counts + ['entries' => count($this->values), 'bytes' => $this->bytes, 'active' => $this->active];
    }
}
