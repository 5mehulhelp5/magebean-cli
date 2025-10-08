<?php
declare(strict_types=1);

namespace Magebean\Engine;

final class Context
{
    /** Project root to scan */
    public string $path;
    /** Project url to scan */
    public string $url;
    /** Path to CVE data (plain JSON/NDJSON) sau khi đã resolve/extract; rỗng nếu không dùng */
    public string $cveData;
    /** Extra key-values cho mở rộng */
    private array $extra;

    public function __construct(string $path, string $url, string $cveData = '', array $extra = [])
    {
        $this->path    = rtrim($path, DIRECTORY_SEPARATOR);
        $this->url     = $url;
        $this->cveData = $cveData;
        $this->extra   = $extra;
    }

    public static function fromArray(array $a): self
    {
        $path    = (string)($a['path'] ?? '.');
        $url    = (string)($a['url'] ?? '.');
        $cveData = (string)($a['cve_data'] ?? '');
        $extra   = $a['extra'] ?? [];
        if (!is_array($extra)) $extra = [];
        return new self($path, $url, $cveData, $extra);
    }

    /** Resolve to absolute path in project root (giữ nguyên nếu đã absolute) */
    public function abs(string $p): string
    {
        if ($p === '' || $p === '.') return $this->path;
        if ($this->isAbsolutePath($p)) return $p;
        return $this->path . DIRECTORY_SEPARATOR . $p;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->extra[$key] ?? $default;
    }

    private function isAbsolutePath(string $p): bool
    {
        if ($p === '') return false;
        if ($p[0] === DIRECTORY_SEPARATOR || $p[0] === '/') return true;
        return (bool)preg_match('/^[A-Za-z]:[\\\\\\/]/', $p);
    }
}
