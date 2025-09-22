<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class ComposerCheck
{
    private Context $ctx;

    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    public function stub(array $args): array
    {
        return [true, "ComposerCheck stub PASS"];
    }

    public function auditOffline(array $args): array
    {
        // 1. Xác định file CVE data
        $cveRel = $this->ctx->cveData !== '' ? $this->ctx->cveData : ($args['cve_db'] ?? '');
        if ($cveRel === '') {
            return [null, "[UNKNOWN] Missing CVE data (use --cve-data=path or args.cve_db)"];
        }
        $cvePath = $this->ctx->abs($cveRel);
        if (!is_file($cvePath)) {
            return [null, "[UNKNOWN] CVE file not found (requires --cve-data package)"];
        }

        // 2. Đọc composer.lock
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [false, "composer.lock not found"];
        }
        $lockJson = json_decode((string)file_get_contents($lockFile), true);
        if (!is_array($lockJson)) {
            return [false, "Invalid composer.lock"];
        }
        $pkgs = array_merge($lockJson['packages'] ?? [], $lockJson['packages-dev'] ?? []);
        $installed = [];
        foreach ($pkgs as $p) {
            if (!isset($p['name'], $p['version'])) continue;
            $ver = ltrim((string)$p['version'], 'v');
            $installed[$p['name']] = $ver;
        }
        if (!$installed) {
            return [true, "No packages in composer.lock (nothing to audit)"];
        }

        // 3. Đọc CVE data (JSON array hoặc NDJSON)
        $raw = (string)file_get_contents($cvePath);
        $cve = json_decode($raw, true);
        if (!is_array($cve)) {
            // fallback NDJSON
            $lines = preg_split('/\r?\n/', $raw, -1, PREG_SPLIT_NO_EMPTY);
            $cve = [];
            foreach ($lines as $ln) {
                $obj = json_decode($ln, true);
                if (is_array($obj)) $cve[] = $obj;
            }
            if (!$cve) {
                return [null, "[UNKNOWN] Unrecognized CVE format (expect JSON array or NDJSON)"];
            }
        }

        // 4. So khớp
        $sus = [];
        foreach ($cve as $vuln) {
            if (!isset($vuln['affected']) || !is_array($vuln['affected'])) continue;
            foreach ($vuln['affected'] as $aff) {
                $pkg = $aff['package']['name'] ?? null;
                $eco = $aff['package']['ecosystem'] ?? null;
                if (!$pkg || !$eco) continue;
                $ecoNorm = strtolower((string)$eco);
                if ($ecoNorm !== 'packagist' && $ecoNorm !== 'composer') continue;
                if (!array_key_exists($pkg, $installed)) continue;

                $current = $installed[$pkg];
                $hit = false;

                // match theo versions liệt kê
                if (!empty($aff['versions']) && is_array($aff['versions'])) {
                    foreach ($aff['versions'] as $v) {
                        $v = ltrim((string)$v, 'v');
                        if ($v !== '' && version_compare($current, $v, '==')) {
                            $hit = true;
                            break;
                        }
                    }
                }

                // match theo ranges
                if (!$hit && !empty($aff['ranges']) && is_array($aff['ranges'])) {
                    foreach ($aff['ranges'] as $rng) {
                        $events = $rng['events'] ?? [];
                        $intervals = $this->eventsToIntervals($events);
                        foreach ($intervals as [$a, $b]) {
                            if ($this->inRange($current, $a, $b)) {
                                $hit = true;
                                break 2;
                            }
                        }
                    }
                }

                if ($hit) {
                    $id  = $vuln['id'] ?? ($vuln['aliases'][0] ?? 'CVE');
                    $sev = $this->extractSeverity($vuln);
                    $sus[] = $pkg . '@' . $current . ' -> ' . $id . ($sev ? " (" . $sev . ")" : '');
                }
            }
        }

        if ($sus) {
            $msg = 'Vulnerable: ' . implode('; ', array_slice($sus, 0, 20));
            return [false, $msg, $sus];
        }
        return [true, "No vulnerable packages according to CVE data (" . count($installed) . " pkgs)"];
    }

    // helpers
    private function eventsToIntervals(array $events): array
    {
        $res = [];
        $curStart = null;
        foreach ($events as $ev) {
            if (isset($ev['introduced'])) {
                $curStart = ltrim((string)$ev['introduced'], 'v');
            } elseif (isset($ev['fixed'])) {
                $end = ltrim((string)$ev['fixed'], 'v');
                if ($curStart !== null) {
                    $res[] = [$curStart, $end];
                    $curStart = null;
                } else {
                    $res[] = [null, $end];
                }
            }
        }
        if ($curStart !== null) $res[] = [$curStart, null];
        return $res;
    }

    private function inRange(string $cur, ?string $a, ?string $b): bool
    {
        $cur = ltrim($cur, 'v');
        if ($a !== null && version_compare($cur, $a, '<')) return false;
        if ($b !== null && version_compare($cur, $b, '>=')) return false;
        return true;
    }

    private function extractSeverity(array $vuln): ?string
    {
        $sev = $vuln['severity'][0]['score'] ?? null;
        return is_string($sev) ? $sev : null;
    }


    public function coreAdvisoriesOffline(array $args): array
    {
        return [true, "composer_core_advisories_offline stub"];
    }

    public function fixVersion(array $args): array
    {
        return [true, "composer_fix_version suggestion stub"];
    }

    public function riskSurfaceTag(array $args): array
    {
        return [true, "composer_risk_surface_tag stub"];
    }

    public function matchList(array $args): array
    {
        return [true, "composer_match_list stub"];
    }

    public function constraintsConflict(array $args): array
    {
        return [true, "composer_constraints_conflict stub"];
    }

    public function yankedOffline(array $args): array
    {
        return [true, "composer_yanked_offline stub"];
    }

    public function outdatedOffline(array $args): array
    {
        return [true, "composer_outdated_offline stub"];
    }

    public function advisoryLatency(array $args): array
    {
        return [true, "composer_advisory_latency stub"];
    }

    public function vendorSupportOffline(array $args): array
    {
        return [true, "composer_vendor_support_offline stub"];
    }

    public function abandonedOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $meta = $this->ctx->abs($args['packagist_meta'] ?? 'rules/packagist-abandoned.json');
        return [true, "composer_abandoned_offline checked $lock with $meta"];
    }

    public function releaseRecencyOffline(array $args): array
    {
        $lock  = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $meta  = $this->ctx->abs($args['release_meta'] ?? 'rules/release-history.json');
        $months = (int)($args['months'] ?? 24);
        return [true, "composer_release_recency_offline $lock against $meta (max {$months}m)"];
    }

    public function repoArchivedOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $meta = $this->ctx->abs($args['repo_meta'] ?? 'rules/repo-status.json');
        return [true, "composer_repo_archived_offline checked $lock with $meta"];
    }

    public function riskyForkOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $meta = $this->ctx->abs($args['repo_meta'] ?? 'rules/repo-status.json');
        return [true, "composer_risky_fork_offline checked $lock with $meta"];
    }

    public function jsonConstraints(string $rootDir): array
    {
        $rootDir = rtrim($rootDir, '/');
        $path = $rootDir . '/composer.json';
        if (!is_file($path)) {
            return [];
        }
        $data = json_decode((string)file_get_contents($path), true);
        if (!is_array($data)) {
            return [];
        }
        $sections = ['require', 'require-dev', 'conflict', 'replace', 'provide'];
        $out = [];
        foreach ($sections as $sec) {
            if (!empty($data[$sec]) && is_array($data[$sec])) {
                foreach ($data[$sec] as $pkg => $ver) {
                    $out[$pkg] ??= (string)$ver;
                }
            }
        }
        return $out;
    }

    public function lockVersions(string $rootDir): array
    {
        $path = rtrim($rootDir, '/') . '/composer.lock';
        if (!is_file($path)) {
            return [];
        }
        $data = json_decode((string)file_get_contents($path), true);
        if (!is_array($data)) {
            return [];
        }
        $out = [];
        foreach (['packages', 'packages-dev'] as $bucket) {
            if (!empty($data[$bucket]) && is_array($data[$bucket])) {
                foreach ($data[$bucket] as $pkg) {
                    if (!empty($pkg['name']) && !empty($pkg['version'])) {
                        $out[$pkg['name']] = (string)$pkg['version'];
                    }
                }
            }
        }
        return $out;
    }

    public function jsonKv(array $args): array
    {
        $root = (string)$this->ctx->get('root', '');
        $root = $this->absPath($root);

        $jsonRel  = is_string($args['json_file'] ?? null) ? $args['json_file'] : 'composer.json';
        $jsonPath = $this->join($root, $jsonRel);

        if (!is_file($jsonPath)) {
            if ($found = $this->findUp($jsonPath, 6)) {
                $jsonPath = $found;
            } else {
                return [false, "composer.json not found at {$jsonPath}"];
            }
        }

        $raw  = @file_get_contents($jsonPath);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data)) {
            return [false, "Invalid composer.json at {$jsonPath}"];
        }

        $key = (string)($args['key'] ?? '');
        if ($key === '') {
            return [false, "Missing 'key' argument (dot-path)"];
        }

        // Traverse dot-path
        $exist = true;
        $val   = $data;
        foreach (explode('.', $key) as $seg) {
            // support wildcard '*' to check any child exists
            if ($seg === '*') {
                if (!is_array($val) || empty($val)) {
                    $exist = false;
                    break;
                }
                // For wildcard, consider "exists" true if array has at least one element
                // If expect/op provided, you could extend to iterate; keep simple for now.
                $val = reset($val);
                continue;
            }
            if (!is_array($val) || !array_key_exists($seg, $val)) {
                $exist = false;
                break;
            }
            $val = $val[$seg];
        }

        $op = $args['op'] ?? (array_key_exists('expect', $args) ? 'eq' : 'exists');

        if ($op === 'exists') {
            return [$exist, $exist ? "Key exists: {$key}" : "Key missing: {$key}"];
        }
        if ($op === 'not_exists') {
            return [!$exist, !$exist ? "Key not exists (as expected): {$key}" : "Key unexpectedly present: {$key}"];
        }

        // For eq/neq we require the key to exist
        if (!$exist) {
            return [false, "Key missing for comparison: {$key}"];
        }

        $expect = $args['expect'] ?? null;
        $equal  = $this->looseEqual($val, $expect);

        if ($op === 'eq') {
            return [$equal, $equal
                ? "OK: {$key} == " . $this->printVal($expect)
                : "Mismatch: {$key}=" . $this->printVal($val) . " != " . $this->printVal($expect)];
        }
        if ($op === 'neq') {
            return [!$equal, !$equal
                ? "OK: {$key} (" . $this->printVal($val) . ") != " . $this->printVal($expect)
                : "Unexpected equal: {$key} == " . $this->printVal($expect)];
        }

        return [false, "Unsupported op '{$op}'"];
    }

    private function looseEqual(mixed $a, mixed $b): bool
    {
        // Normalize scalars/arrays/objects to JSON for a stable comparison
        if (is_array($a) || is_object($a) || is_array($b) || is_object($b)) {
            return json_encode($a, JSON_UNESCAPED_SLASHES) === json_encode($b, JSON_UNESCAPED_SLASHES);
        }
        // Treat "true"/"false" strings like booleans, numeric strings like numbers
        $norm = static function ($v) {
            if (is_string($v)) {
                $t = strtolower(trim($v));
                if ($t === 'true') return true;
                if ($t === 'false') return false;
                if (is_numeric($v)) return $v + 0;
            }
            return $v;
        };
        return $norm($a) === $norm($b);
    }

    private function printVal(mixed $v): string
    {
        if (is_scalar($v) || $v === null) return var_export($v, true);
        return json_encode($v, JSON_UNESCAPED_SLASHES);
    }

    public function lockIntegrity(array $args): array
    {
        // Args (all optional):
        //  - lock_file: relative path to composer.lock (default 'composer.lock')
        //  - json_file: relative path to composer.json (default 'composer.json')
        //  - installed_file: relative path to vendor/composer/installed.json (default 'vendor/composer/installed.json')
        // Returns: [bool, string]

        $root = (string)$this->ctx->get('root', '');
        $root = $this->absPath($root);

        $lockRel      = is_string($args['lock_file'] ?? null) ? $args['lock_file'] : 'composer.lock';
        $jsonRel      = is_string($args['json_file'] ?? null) ? $args['json_file'] : 'composer.json';
        $installedRel = is_string($args['installed_file'] ?? null) ? $args['installed_file'] : 'vendor/composer/installed.json';

        $lockPath = $this->join($root, $lockRel);
        if (!is_file($lockPath) && ($found = $this->findUp($lockPath, 3))) {
            $lockPath = $found;
        }
        if (!is_file($lockPath)) {
            return [false, "composer.lock not found at {$lockPath}"];
        }

        $lockRaw = @file_get_contents($lockPath);
        $lock    = is_string($lockRaw) ? json_decode($lockRaw, true) : null;
        if (!is_array($lock)) {
            return [false, "Invalid composer.lock at {$lockPath}"];
        }

        // Merge packages + packages-dev into one map name => version
        $pkgs = [];
        $dups = [];
        foreach (['packages', 'packages-dev'] as $bucket) {
            foreach (($lock[$bucket] ?? []) as $p) {
                $name = (string)($p['name'] ?? '');
                $ver  = (string)($p['version'] ?? '');
                if ($name === '') {
                    continue;
                }
                if (isset($pkgs[$name])) {
                    $dups[$name] = true;
                }
                $pkgs[$name] = $ver;
            }
        }
        if (empty($pkgs)) {
            return [false, "composer.lock contains no packages"];
        }

        $problems = [];

        if ($dups) {
            $problems[] = 'duplicate package entries in lock: ' . implode(', ', array_keys($dups));
        }

        // Optional: check composer.json requires are present in lock (basic presence check)
        $jsonPath = $this->join($root, $jsonRel);
        if (!is_file($jsonPath) && ($found = $this->findUp($jsonPath, 3))) {
            $jsonPath = $found;
        }
        if (is_file($jsonPath)) {
            $jsonRaw = @file_get_contents($jsonPath);
            $json    = is_string($jsonRaw) ? json_decode($jsonRaw, true) : null;

            if (is_array($json)) {
                $required = [];
                foreach (['require', 'require-dev'] as $sec) {
                    foreach ((array)($json[$sec] ?? []) as $name => $constraint) {
                        // Skip platform packages that won’t appear in lock
                        if ($name === 'php' || str_starts_with((string)$name, 'ext-') || str_starts_with((string)$name, 'lib-')) {
                            continue;
                        }
                        $required[$name] = (string)$constraint;
                    }
                }

                $missing = [];
                foreach ($required as $name => $_constraint) {
                    if (!isset($pkgs[$name])) {
                        $missing[] = $name;
                    }
                }
                if ($missing) {
                    $problems[] = 'required packages not present in lock: ' . implode(', ', $missing);
                }

                // Staleness check: composer.json newer than composer.lock
                $tJson = @filemtime($jsonPath) ?: 0;
                $tLock = @filemtime($lockPath) ?: 0;
                if ($tJson > $tLock) {
                    $problems[] = 'composer.lock is older than composer.json (run composer update or composer install)';
                }
            } else {
                $problems[] = "invalid composer.json at {$jsonPath}";
            }
        } else {
            $problems[] = "composer.json not found (cannot compare requires)";
        }

        // Optional: compare with vendor/composer/installed.json
        $installedPath = $this->join($root, $installedRel);
        if (is_file($installedPath)) {
            $instRaw = @file_get_contents($installedPath);
            $installed = is_string($instRaw) ? json_decode($instRaw, true) : null;
            // installed.json can be either a flat object or use 'packages' key depending on Composer version
            $installedPkgs = [];
            if (is_array($installed)) {
                $list = $installed['packages'] ?? $installed; // tolerate both shapes
                foreach ((array)$list as $p) {
                    $n = (string)($p['name'] ?? '');
                    if ($n !== '') $installedPkgs[$n] = true;
                }
            }
            if ($installedPkgs) {
                // Warn if lock has pkgs that are not installed (or vice versa)
                $notInstalled = array_diff_key($pkgs, $installedPkgs);
                if ($notInstalled) {
                    $problems[] = 'packages present in lock but not in vendor/composer/installed.json: ' . implode(', ', array_keys($notInstalled));
                }
            }
        }

        if ($problems) {
            // Keep message concise; show first few issues then counts
            $head = array_slice($problems, 0, 3);
            $tail = count($problems) > 3 ? ' (+' . (count($problems) - 3) . ' more)' : '';
            return [false, 'composer.lock integrity issues: ' . implode(' | ', $head) . $tail];
        }

        return [true, 'composer.lock integrity OK (' . count($pkgs) . ' packages)'];
    }

    // Add these private helpers at the bottom of the class (before closing brace)

    /**
     * Normalize a path: expand relative paths to absolute.
     */
    private function absPath(string $p): string
    {
        $p = trim($p);
        if ($p === '') return getcwd();
        // expand relative
        if ($p[0] !== '/') {
            $p = rtrim(getcwd(), '/') . '/' . ltrim($p, '/');
        }
        return rtrim($p, '/');
    }

    /**
     * Join base directory with a relative path.
     */
    private function join(string $base, string $rel): string
    {
        if ($rel === '' || $rel === '.') return $base . '/composer.json';
        if ($rel[0] === '/') return $rel;
        return $base . '/' . $rel;
    }

    /**
     * Walk up parent directories (maxUp levels) to find a file.
     */
    private function findUp(string $path, int $maxUp = 3): ?string
    {
        $dir = dirname($path);
        $target = basename($path);
        for ($i = 0; $i <= $maxUp; $i++) {
            $candidate = $dir . '/' . $target;
            if (is_file($candidate)) {
                return $candidate;
            }
            $parent = dirname($dir);
            if ($parent === $dir) break; // reached root
            $dir = $parent;
        }
        return null;
    }
}
