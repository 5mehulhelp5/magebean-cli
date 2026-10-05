<?php
declare(strict_types=1);

namespace Magebean\Agent;

final class AtomicJsonStore
{
    public function read(string $path, array $default = []): array
    {
        if (!is_file($path)) return $default;
        $data = json_decode((string)file_get_contents($path), true);
        if (!is_array($data)) throw new \RuntimeException("Invalid JSON file: {$path}");
        return $data;
    }

    public function write(string $path, array $data): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException("Cannot create directory: {$dir}");
        }
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
        $temp = tempnam($dir, '.magebean-');
        if ($temp === false) throw new \RuntimeException("Cannot create temporary file in {$dir}");
        try {
            $handle = fopen($temp, 'wb');
            if ($handle === false) throw new \RuntimeException("Cannot write {$temp}");
            try {
                if (!flock($handle, LOCK_EX)) throw new \RuntimeException("Cannot lock {$temp}");
                $offset = 0;
                $length = strlen($json);
                while ($offset < $length) {
                    $written = fwrite($handle, substr($json, $offset));
                    if ($written === false || $written === 0) throw new \RuntimeException("Cannot write {$temp}");
                    $offset += $written;
                }
                if (!fflush($handle)) throw new \RuntimeException("Cannot flush {$temp}");
                if (function_exists('fsync') && !fsync($handle)) throw new \RuntimeException("Cannot sync {$temp}");
            } finally {
                fclose($handle);
            }
            @chmod($temp, 0600);
            if (!rename($temp, $path)) throw new \RuntimeException("Cannot replace {$path}");
            @chmod($path, 0600);
        } finally {
            if (is_file($temp)) @unlink($temp);
        }
    }

    public function permissionsArePrivate(string $path): bool
    {
        if (!is_file($path) || DIRECTORY_SEPARATOR === '\\') return true;
        return ((int)fileperms($path) & 0077) === 0;
    }
}
