<?php

declare(strict_types=1);

namespace Magebean\Engine;

/** Immutable report envelope; preserve the existing wire schema and extensions. */
final class ScanReport implements \JsonSerializable
{
    public readonly array $summary;
    public readonly array $findings;
    public readonly array $meta;

    /** @param list<list<CheckResult>> $checkResults Internal observations in finding order. */
    private function __construct(private readonly array $payload, public readonly array $checkResults = [])
    {
        $this->summary = $payload['summary'];
        $this->findings = $payload['findings'];
        $this->meta = $payload['meta'] ?? [];
    }

    /** @param list<list<CheckResult>> $checkResults */
    public static function fromLegacy(array $payload, array $checkResults = []): self
    {
        foreach (['summary', 'findings'] as $key) {
            if (!isset($payload[$key]) || !is_array($payload[$key])) {
                throw new \InvalidArgumentException('ScanReport requires an array ' . $key . '.');
            }
        }
        if (array_key_exists('meta', $payload) && !is_array($payload['meta'])) {
            throw new \InvalidArgumentException('ScanReport meta must be an array when present.');
        }
        if ($checkResults !== [] && count($checkResults) !== count($payload['findings'])) {
            throw new \InvalidArgumentException('Check observations must align with report findings.');
        }
        foreach ($checkResults as $group) {
            if (!is_array($group)) throw new \InvalidArgumentException('Check observations must be grouped by finding.');
            foreach ($group as $result) {
                if (!$result instanceof CheckResult) throw new \InvalidArgumentException('Check observations must contain CheckResult objects.');
            }
        }
        return new self($payload, $checkResults);
    }

    public function withMeta(array $updates): self
    {
        $payload = $this->payload;
        $payload['meta'] = array_replace($this->meta, $updates);
        return new self($payload, $this->checkResults);
    }

    /** Extension sections, e.g. pci/cve_audit, are owned by their producers. */
    public function withSection(string $name, mixed $value): self
    {
        if ($name === '' || in_array($name, ['summary', 'findings', 'meta'], true)) {
            throw new \InvalidArgumentException('Use the report contracts for reserved sections.');
        }
        $payload = $this->payload;
        $payload[$name] = $value;
        return new self($payload, $this->checkResults);
    }

    public function toLegacy(): array
    {
        return $this->payload;
    }

    public function jsonSerialize(): array
    {
        return $this->toLegacy();
    }
}
