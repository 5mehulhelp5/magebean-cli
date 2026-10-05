<?php

declare(strict_types=1);

namespace Magebean\Engine;

/** One canonical target; legacy checks receive a separate mutable adapter. */
final class ScanContext
{
    public readonly string $path;
    public readonly array $settings;

    public function __construct(
        string $path,
        public readonly string $url,
        public readonly string $cveData = '',
        array $settings = []
    ) {
        $this->path = rtrim($path, DIRECTORY_SEPARATOR);
        $this->settings = array_diff_key($settings, array_flip(['path', 'url', 'cve_data']));
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return match ($key) {
            'path' => $this->path,
            'url' => $this->url,
            'cve_data' => $this->cveData,
            default => $this->settings[$key] ?? $default,
        };
    }

    public function abs(string $path): string
    {
        return $this->toLegacy()->abs($path);
    }

    public function toLegacy(): Context
    {
        return new Context($this->path, $this->url, $this->cveData, array_replace($this->settings, [
            'path' => $this->path,
            'url' => $this->url,
            'cve_data' => $this->cveData,
        ]));
    }
}
