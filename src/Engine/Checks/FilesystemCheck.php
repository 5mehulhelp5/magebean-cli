<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class FilesystemCheck
{
    private Context $ctx;
    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    public function noWorldWritable(array $args): array
    {
        $root = $this->ctx->abs($args['path'] ?? '.');
        $max = (int)($args['max_results'] ?? 50);
        $offenders = [];
        $flags = \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::FOLLOW_SYMLINKS;
        $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, $flags));
        foreach ($rii as $file) {
            $perm = @fileperms((string)$file);
            if ($perm === false) continue;
            $perm = $perm & 0777;
            if (($perm & 0002) === 0002) {
                $offenders[] = [$file->getPathname(), sprintf('%o', $perm)];
                if (count($offenders) >= $max) break;
            }
        }
        if ($offenders) {
            $msg = "World-writable found: " . implode(', ', array_map(fn($o) => $o[0] . '(' . $o[1] . ')', $offenders));
            return [false, $msg];
        }
        return [true, "No world-writable files/dirs under {$root}"];
    }

    public function fileModeMax(array $args): array
    {
        $rel = $args['file'] ?? 'app/etc/env.php';
        $file = $this->ctx->abs($rel);
        $max = octdec($args['max_octal'] ?? '0640');
        if (!is_file($file)) return [false, "{$rel} is missing"];
        $perm = fileperms($file) & 0777;
        if ($perm > $max) return [false, "{$rel} mode " . sprintf('%o', $perm) . " exceeds " . sprintf('%o', $max)];
        return [true, "{$rel} mode " . sprintf('%o', $perm) . " <= " . sprintf('%o', $max)];
    }

    public function webrootHygiene(array $args): array
    {
        $webroot = $this->ctx->abs($args['webroot'] ?? 'pub');
        $bad = $args['forbidden'] ?? ['.git', '.env', '.env.local', '*.bak', '*.old', '*~'];
        if (!is_dir($webroot)) return [true, "Webroot {$webroot} not found (skipped)"];
        $matches = [];
        $max = 50;
        $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($webroot, \FilesystemIterator::SKIP_DOTS));
        foreach ($rii as $file) {
            $name = $file->getFilename();
            foreach ($bad as $pattern) {
                $regex = '/^' . str_replace(['*', '?'], ['.*', '.?'], preg_quote($pattern, '/')) . '$/i';
                if (preg_match($regex, $name)) {
                    $matches[] = $file->getPathname();
                    break;
                }
            }
            if (count($matches) >= $max) break;
        }
        if ($matches) return [false, "Forbidden artifacts in webroot: " . implode(', ', $matches)];
        return [true, "Webroot clean: {$webroot}"];
    }

    public function codeDirsReadonly(array $args): array
    {
        $dirs = $args['dirs'] ?? ['app', 'vendor', 'lib'];
        $off = [];
        foreach ($dirs as $rel) {
            $path = $this->ctx->abs($rel);
            if (!is_dir($path)) continue;
            $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS));
            foreach ($rii as $file) {
                $perm = @fileperms((string)$file);
                if ($perm === false) continue;
                $perm = $perm & 0777;
                if (($perm & 0022) !== 0) {
                    $off[] = [$file->getPathname(), sprintf('%o', $perm)];
                    if (count($off) >= 50) break 2;
                }
            }
        }
        if ($off) return [false, "Group/other writable in code dirs: " . implode(', ', array_map(fn($o) => $o[0] . '(' . $o[1] . ')', $off))];
        return [true, "Code directories not group/other writable"];
    }

    public function noDirectoryListing(array $args): array
    {
        $pub = $this->ctx->abs($args['webroot'] ?? 'pub');
        $ht = $pub . '/.htaccess';
        if (is_file($ht)) {
            $c = (string)file_get_contents($ht);
            if (stripos($c, 'Options -Indexes') !== false) return [true, "Apache: Options -Indexes present"];
        }
        $ng = $this->ctx->abs('nginx.conf');
        if (is_file($ng)) {
            $c = (string)file_get_contents($ng);
            if (stripos($c, 'autoindex off') !== false) return [true, "Nginx: autoindex off"];
        }
        return [false, "Could not verify directory listing disabled"];
    }

    public function fsExists(array $args): array
    {
        $rel = (string)($args['path'] ?? '');
        if ($rel === '') return [false, 'fs_exists requires path'];
        $abs = $this->ctx->abs($rel);
        $ok  = file_exists($abs);
        return [$ok, ($ok ? 'Exists: ' : 'Not found: ') . $rel];
    }

    public function mtimeMaxAge(array $args): array
    {
        $rel = (string)($args['file'] ?? '');
        $max = (int)($args['seconds'] ?? 0);
        if ($rel === '' || $max <= 0) return [false, 'fs_mtime_max_age requires file & seconds'];

        $abs = $this->ctx->abs($rel);
        if (!is_file($abs)) return [false, "$rel not found"];

        $mtime = @filemtime($abs);
        if ($mtime === false) return [false, "Cannot stat $rel"];
        $age = time() - $mtime;

        $ok = ($age <= $max);
        return [$ok, "mtime age {$age}s (max {$max}s) for $rel"];
    }
}
