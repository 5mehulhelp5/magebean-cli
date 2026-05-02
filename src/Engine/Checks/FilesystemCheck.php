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
        $max = max(1, (int)($args['max_results'] ?? 50));
        if (!file_exists($root)) {
            return [false, "Path not found: {$root}"];
        }

        $offenders = [];
        $truncated = false;
        $flags = \FilesystemIterator::SKIP_DOTS;

        $this->collectWorldWritableOffender($root, $offenders, $max, $truncated);

        $rii = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, $flags),
            \RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($rii as $file) {
            if ($file->isLink()) {
                continue;
            }

            $this->collectWorldWritableOffender($file->getPathname(), $offenders, $max, $truncated);
            if ($truncated) {
                break;
            }
        }

        if ($offenders) {
            $shown = count($offenders);
            $msg = "World-writable entries found ({$shown}" . ($truncated ? '+' : '') . " shown): "
                . implode(', ', array_map(
                    static fn(array $o): string => $o['path'] . ' [' . $o['type'] . ':' . $o['mode'] . ']',
                    $offenders
                ));
            if ($truncated) {
                $msg .= ". More offenders exist; increase max_results to inspect additional entries.";
            }
            return [false, $msg, $offenders];
        }
        return [true, "No world-writable files or directories detected under {$root}"];
    }

    public function fileModeMax(array $args): array
    {
        $rel = $args['file'] ?? 'app/etc/env.php';
        $file = $this->ctx->abs($rel);
        $allowedModeRaw = (string)($args['max_octal'] ?? '0640');
        $allowedMode = octdec($allowedModeRaw);
        if (!is_file($file)) return [false, "{$rel} is missing"];
        $perm = fileperms($file) & 0777;

        $extraBits = $perm & (~$allowedMode & 0777);
        $evidence = [
            'path' => $file,
            'observed_mode' => sprintf('%o', $perm),
            'allowed_mode' => sprintf('%o', $allowedMode),
        ];
        if ($extraBits !== 0) {
            $evidence['excess_bits'] = sprintf('%o', $extraBits);
            return [
                false,
                "{$rel} mode " . sprintf('%o', $perm) . " is more permissive than allowed policy " . sprintf('%o', $allowedMode),
                $evidence,
            ];
        }

        return [
            true,
            "{$rel} mode " . sprintf('%o', $perm) . " complies with allowed policy " . sprintf('%o', $allowedMode),
            $evidence,
        ];
    }

    public function fileOwnerGroupMatches(array $args): array
    {
        $rel = (string)($args['file'] ?? '');
        if ($rel === '') {
            return [false, 'file_owner_group_matches requires file'];
        }

        $file = $this->ctx->abs($rel);
        if (!is_file($file)) {
            return [false, "{$rel} is missing"];
        }

        $ownerRefRel = (string)($args['owner_reference'] ?? '.');
        $groupRefRel = (string)($args['group_reference'] ?? $ownerRefRel);
        $ownerRef = $this->ctx->abs($ownerRefRel);
        $groupRef = $this->ctx->abs($groupRefRel);

        if (!file_exists($ownerRef)) {
            return [false, "Owner reference not found: {$ownerRefRel}"];
        }
        if (!file_exists($groupRef)) {
            return [false, "Group reference not found: {$groupRefRel}"];
        }

        $owner = @fileowner($file);
        $group = @filegroup($file);
        $expectedOwner = @fileowner($ownerRef);
        $expectedGroup = @filegroup($groupRef);
        if ($owner === false || $group === false || $expectedOwner === false || $expectedGroup === false) {
            return [false, "Could not stat ownership for {$rel}"];
        }

        $evidence = [
            'path' => $file,
            'owner' => $this->formatIdentity((int)$owner, true),
            'group' => $this->formatIdentity((int)$group, false),
            'owner_reference' => $ownerRef,
            'expected_owner' => $this->formatIdentity((int)$expectedOwner, true),
            'group_reference' => $groupRef,
            'expected_group' => $this->formatIdentity((int)$expectedGroup, false),
        ];

        if ($owner !== $expectedOwner || $group !== $expectedGroup) {
            return [
                false,
                "{$rel} ownership does not match expected application owner/group",
                $evidence,
            ];
        }

        return [
            true,
            "{$rel} ownership matches expected application owner/group",
            $evidence,
        ];
    }

    public function webrootHygiene(array $args): array
    {
        $webroot = $this->ctx->abs($args['webroot'] ?? 'pub');
        $bad = $args['forbidden'] ?? ['.git', '.env', '.env.local', '*.bak', '*.old', '*~'];
        if (!is_dir($webroot)) return [true, "Webroot {$webroot} not found (skipped)"];
        $matches = [];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $truncated = false;

        $this->collectForbiddenWebrootArtifact($webroot, $bad, $matches, $max, $truncated);

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($webroot, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        foreach ($iterator as $file) {
            $path = $file->getPathname();
            $this->collectForbiddenWebrootArtifact($path, $bad, $matches, $max, $truncated);
            if ($file->isLink()) {
                continue;
            }
            if ($truncated) {
                break;
            }
        }
        if ($matches) {
            $shown = count($matches);
            $msg = "Forbidden artifacts found in webroot ({$shown}" . ($truncated ? '+' : '') . " shown): "
                . implode(', ', array_map(
                    static fn(array $match): string => $match['path'] . ' [' . $match['type'] . ', pattern:' . $match['pattern'] . ']',
                    $matches
                ));
            if ($truncated) {
                $msg .= ". More matches exist; increase max_results to inspect additional entries.";
            }
            return [false, $msg, $matches];
        }
        return [true, "Webroot clean: {$webroot}"];
    }

    public function codeDirsReadonly(array $args): array
    {
        $dirs = $args['dirs'] ?? ['app', 'vendor', 'lib'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $off = [];
        $truncated = false;
        foreach ($dirs as $rel) {
            $path = $this->ctx->abs($rel);
            if (!is_dir($path)) continue;

            $this->collectWritableCodePath($path, $off, $max, $truncated);
            if ($truncated) {
                break;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $file) {
                $this->collectWritableCodePath($file->getPathname(), $off, $max, $truncated);
                if ($truncated) {
                    break 2;
                }
            }
        }

        if ($off) {
            $shown = count($off);
            $msg = "Writable code paths found ({$shown}" . ($truncated ? '+' : '') . " shown): "
                . implode(', ', array_map(
                    static fn(array $entry): string => $entry['path'] . ' [' . $entry['type'] . ':' . $entry['mode'] . ']'
                        . (isset($entry['target']) ? ' -> ' . $entry['target'] : ''),
                    $off
                ));
            if ($truncated) {
                $msg .= ". More offenders exist; increase max_results to inspect additional entries.";
            }
            return [false, $msg, $off];
        }

        return [true, "Code directories are read-only"];
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

    private function collectWorldWritableOffender(string $path, array &$offenders, int $max, bool &$truncated): void
    {
        if ($truncated || is_link($path)) {
            return;
        }

        $perm = @fileperms($path);
        if ($perm === false) {
            return;
        }

        $perm = $perm & 0777;
        if (($perm & 0002) !== 0002) {
            return;
        }

        if (count($offenders) >= $max) {
            $truncated = true;
            return;
        }

        $offenders[] = [
            'path' => $path,
            'mode' => sprintf('%o', $perm),
            'type' => is_dir($path) ? 'dir' : 'file',
        ];
    }

    private function formatIdentity(int $id, bool $user): string
    {
        $lookup = $user ? 'posix_getpwuid' : 'posix_getgrgid';
        if (function_exists($lookup)) {
            $info = $lookup($id);
            if (is_array($info) && isset($info['name']) && is_string($info['name']) && $info['name'] !== '') {
                return $info['name'] . " ({$id})";
            }
        }

        return (string)$id;
    }

    private function collectForbiddenWebrootArtifact(string $path, array $patterns, array &$matches, int $max, bool &$truncated): void
    {
        if ($truncated) {
            return;
        }

        $name = basename($path);
        $matchedPattern = null;
        foreach ($patterns as $pattern) {
            if ($this->matchesForbiddenArtifact($name, (string)$pattern)) {
                $matchedPattern = (string)$pattern;
                break;
            }
        }
        if ($matchedPattern === null) {
            return;
        }

        if (count($matches) >= $max) {
            $truncated = true;
            return;
        }

        $matches[] = [
            'path' => $path,
            'pattern' => $matchedPattern,
            'type' => is_link($path) ? 'link' : (is_dir($path) ? 'dir' : 'file'),
        ];
    }

    private function matchesForbiddenArtifact(string $name, string $pattern): bool
    {
        return fnmatch($pattern, $name, \FNM_PERIOD);
    }

    private function collectWritableCodePath(string $path, array &$offenders, int $max, bool &$truncated): void
    {
        if ($truncated) {
            return;
        }

        $statPath = $path;
        $target = null;
        if (is_link($path)) {
            $target = realpath($path);
            if ($target === false) {
                return;
            }
            $statPath = $target;
        }

        $perm = @fileperms($statPath);
        if ($perm === false) {
            return;
        }

        $perm = $perm & 0777;
        if (($perm & 0222) === 0) {
            return;
        }

        if (count($offenders) >= $max) {
            $truncated = true;
            return;
        }

        $entry = [
            'path' => $path,
            'mode' => sprintf('%o', $perm),
            'type' => is_link($path) ? 'link' : (is_dir($statPath) ? 'dir' : 'file'),
        ];
        if ($target !== null) {
            $entry['target'] = $target;
        }

        $offenders[] = $entry;
    }
}
