<?php
declare(strict_types=1);

namespace Magebean\Engine\Cve;

/** Verify API-provided fingerprints without executing patches or uploading source. */
final class HotfixVerifier
{
    public function verify(string $root, string $package, string $version, array $rules): array
    {
        $base = realpath($root);
        $attempts = [];
        foreach ($rules as $rule) {
            if (!is_array($rule) || ($rule['package'] ?? null) !== $package
                || !is_string($rule['id'] ?? null)
                || !in_array($version, (array)($rule['versions'] ?? []), true)) continue;
            foreach ((array)($rule['variants'] ?? []) as $variant) {
                if (!is_array($variant)) continue;
                $files = $variant['files'] ?? [];
                if (!is_array($files) || $files === [] || count($files) > 100) continue;
                $observations = [];
                $all = $base !== false;
                foreach ($files as $file) {
                    $path = is_array($file) ? ($file['path'] ?? null) : null;
                    $expected = is_array($file) ? ($file['sha256'] ?? null) : null;
                    if (!is_string($path) || $path === '' || strlen($path) > 1024
                        || str_contains($path, '\\') || str_contains($path, ':')
                        || str_contains($path, "\0") || str_starts_with($path, '/')
                        || in_array('..', explode('/', $path), true)
                        || !is_string($expected) || !preg_match('/^[a-f0-9]{64}$/D', $expected)) {
                        $all = false;
                        $observations[] = ['status' => 'invalid_fingerprint'];
                        continue;
                    }
                    $absolute = $base !== false ? realpath($base . '/' . $path) : false;
                    if ($absolute === false || !str_starts_with($absolute, $base . DIRECTORY_SEPARATOR)
                        || !is_file($absolute) || !is_readable($absolute)
                        || filesize($absolute) > 16 * 1024 * 1024) {
                        $all = false;
                        $observations[] = ['path' => $path, 'status' => 'unreadable_or_unsafe'];
                        continue;
                    }
                    $actual = @hash_file('sha256', $absolute);
                    $match = is_string($actual) && hash_equals($expected, $actual);
                    $all = $all && $match;
                    $observations[] = ['path' => $path, 'sha256' => $actual,
                        'status' => $match ? 'matched' : 'unrecognized_content'];
                }
                $proof = ['hotfix_id' => $rule['id'], 'variant' => $variant['id'] ?? null,
                    'source_url' => $rule['source_url'] ?? null, 'files' => $observations];
                if ($all) return ['status' => 'verified_fixed', 'proof' => $proof];
                $attempts[] = $proof;
            }
        }
        return ['status' => 'unverified', 'attempts' => $attempts];
    }
}
