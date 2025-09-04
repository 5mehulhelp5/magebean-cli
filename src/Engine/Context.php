<?php

declare(strict_types=1);

namespace Magebean\Engine;

final class Context
{
    public string $path;
    public function __construct(string $path)
    {
        $this->path = $path;
    }
    public static function fromArray(array $a): self
    {
        return new self($a['path']);
    }
    public function abs(string $p): string
    {
        if ($p === '' or $p === '.') return $this->path;
        return rtrim($this->path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $p;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }
}
