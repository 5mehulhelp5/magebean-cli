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

    public function auditOffline(array $args): array
    {
        // 1. Xác định file CVE data
        $cveRel = $this->ctx->cveData !== '' ? $this->ctx->cveData : (is_string($args['cve_db'] ?? null) ? $args['cve_db'] : '');
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
            return [null, "[UNKNOWN] composer.lock not found"];
        }
        $lockJson = json_decode((string)file_get_contents($lockFile), true);
        if (!is_array($lockJson)) {
            return [null, "Invalid composer.lock"];
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

    public function yankedOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'yanked', 'yanked_meta', 'rules/packagist-yanked.json');
        if (!$metaPath) return [null, "[UNKNOWN] Yanked metadata not found"];

        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $meta = $this->loadJsonSafe($metaPath);
        if (!$meta || empty($meta['yanked']) || !is_array($meta['yanked'])) {
            return [null, "[UNKNOWN] Invalid yanked metadata JSON"];
        }

        $hits = [];
        foreach ($pkgs as $name => $p) {
            $ver = $p['version'] ?? '';
            $ylist = $meta['yanked'][$name] ?? [];
            if ($ver && is_array($ylist) && in_array($ver, $ylist, true)) {
                $hits[] = "{$name} {$ver}";
            }
        }

        if ($hits) return [false, "Yanked versions present: " . implode(', ', $hits)];
        return [true, "No yanked versions"];
    }


    public function coreAdvisoriesOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $meta = $this->metaPath($args, 'adobe_core', 'adobe_meta', 'DATA/adobe-core-advisories.json')
            ?? $this->metaPath($args, 'adobe_core', 'adobe_meta', 'rules/adobe-core-advisories.json');

        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        if (!$this->safeIsFile($meta)) return [null, "[UNKNOWN] Adobe core advisories metadata not found"];
    }

    public function fixVersion(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $meta = $this->metaPath($args, 'osv_db', 'cve_meta', 'DATA/osv-db.json')
            ?? $this->metaPath($args, 'osv_db', 'cve_meta', 'rules/osv-db.json')
            ?? ($this->ctx->cveData !== '' ? $this->ctx->cveData : null);

        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        if (!$this->safeIsFile($meta)) {
            return [null, "[UNKNOWN] CVE database not found (tried DATA/osv-db.json, rules/osv-db.json, Context->cveData)"];
        }

        // TODO: implement: for each affected package, compute minimal non-affected version and propose fix
        return [null, "[UNKNOWN] Fix-version suggestion not implemented (meta present)"];
    }

    public function riskSurfaceTag(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');

        $metaPath = $this->metaPath($args, 'tags', 'tags_meta', 'DATA/risk-surface.json')
            ?? $this->metaPath($args, 'tags', 'tags_meta', 'rules/risk-surface.json');

        $metaJson = null;
        if ($metaPath && is_file($metaPath)) {
            $raw = (string)@file_get_contents($metaPath);
            if (trim($raw) !== '') {
                $mj = json_decode($raw, true);
                // chỉ dùng khi có nội dung thực sự (patterns/file_ext); {} hoặc null -> bỏ qua
                if (is_array($mj) && (!empty($mj['patterns']) || !empty($mj['file_ext']))) {
                    $metaJson = $mj;
                }
            }
        }

        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        // 1) Đọc lockfile (map tên gói -> tồn tại)
        $lockJson = json_decode((string)@file_get_contents($lock), true);
        if (!is_array($lockJson)) {
            return [null, "[UNKNOWN] Unable to parse composer.lock"];
        }
        $pkgs = array_merge($lockJson['packages'] ?? [], $lockJson['packages-dev'] ?? []);
        $installedNames = [];
        foreach ($pkgs as $p) {
            if (!isset($p['name'])) continue;
            $installedNames[(string)$p['name']] = true;
        }

        // 2) Defaults + override qua meta.json (nếu có) + override qua $args (nếu truyền)
        $fileExt = ['php', 'phtml', 'xml', 'json', 'yaml', 'yml'];
        $patterns = [
            // payment / checkout
            'payment/checkout' => [
                '[/\\\\]Payment[/\\\\]',
                'authorize\s*\(',
                'capture\s*\(',
                'refund\s*\(',
                'Gateway',
                'PaymentInformation',
                'payment_method'
            ],
            // customer auth / admin controllers
            'admin_controllers' => [
                'Controller[/\\\\]Adminhtml',
                'Acl(?![A-Za-z])',
                'isAllowed\s*\('
            ],
            'customer_auth' => [
                'AccountManagementInterface',
                'authenticate\s*\(',
                'login(Post)?\s*\(',
                'twofactor',
                'Tfa[/\\\\]|TwoFactor'
            ],
            // file upload / deserialization
            'file_upload' => [
                'Uploader',
                'moveUploadedFile',
                'isAllowedExtension',
                'tmp_name',
                'upload\W',
            ],
            'deserialization' => [
                '\bunserialize\s*\(',
                'Serializer\\\\Php',
                'Igbinary',
                'PhpSerialize'
            ],
            // webhooks / integrations
            'webhook_integration' => [
                'webhook',
                'callback',
                'notify',
                'ipn',
                'webapi\.xml',
                'routes\.xml',
                'Controller[/\\\\](Webhook|Callback|Notify)'
            ],
            // remote http calls
            'remote_http' => [
                'Http\\\\Client',
                '\bcurl(_init|_exec|_setopt)\b',
                'Guzzle\\\\Http|GuzzleHttp',
                'ClientInterface',
                'file_get_contents\s*\(\s*[\'"]https?://'
            ],
        ];

        if (is_array($metaJson)) {
            if (!empty($metaJson['file_ext']) && is_array($metaJson['file_ext'])) {
                $fileExt = array_values(array_unique(array_map('strval', $metaJson['file_ext'])));
            }
            if (!empty($metaJson['patterns']) && is_array($metaJson['patterns'])) {
                // merge: meta ghi đè key trùng
                foreach ($metaJson['patterns'] as $k => $rxs) {
                    if (is_array($rxs)) $patterns[$k] = $rxs;
                }
            }
        }
        if (!empty($args['file_ext']) && is_array($args['file_ext'])) {
            $fileExt = array_values(array_unique(array_map('strval', $args['file_ext'])));
        }
        if (!empty($args['patterns']) && is_array($args['patterns'])) {
            foreach ($args['patterns'] as $k => $rxs) {
                if (is_array($rxs)) $patterns[$k] = $rxs;
            }
        }

        // 3) Roots để quét
        $roots = [];
        $appCode = $this->ctx->abs('app/code');
        if (is_dir($appCode)) $roots[] = $appCode;
        $vendorDir = $this->ctx->abs('vendor');
        if (is_dir($vendorDir)) $roots[] = $vendorDir;

        // 4) Quét và gắn tag
        $maxFiles = (int)($args['max_files'] ?? 20000);
        $maxHitsPerSubject = (int)($args['max_hits_per_subject'] ?? 200);
        $scan = $this->scanRiskSurface($roots, $fileExt, $patterns, $installedNames, $maxFiles, $maxHitsPerSubject);

        // 5) Xây evidence
        $subjects = [];
        foreach ($scan['hits'] as $hit) {
            $subj = $hit['subject'];
            if (!isset($subjects[$subj])) {
                $subjects[$subj] = ['subject' => $subj, 'tags' => [], 'hits' => 0, 'examples' => []];
            }
            $subjects[$subj]['tags'][$hit['tag']] = true;
            $subjects[$subj]['hits']++;
            if (count($subjects[$subj]['examples']) < 5) {
                $subjects[$subj]['examples'][] = ['path' => $hit['path'], 'match' => $hit['match']];
            }
        }
        foreach ($subjects as &$s) {
            $s['tags'] = array_values(array_keys($s['tags']));
            sort($s['tags']);
            sort($s['examples']);
        }
        unset($s);

        $msg = "Risk-surface tagging: {$scan['files_scanned']} files scanned; "
            . count($subjects) . " subjects tagged";
        $evidence = [
            'files_scanned' => $scan['files_scanned'],
            'subjects_count' => count($subjects),
            'items' => array_values($subjects),
        ];

        // Tagging chỉ để ưu tiên review → trả PASS (true). Nếu muốn coi là cảnh báo, đổi thành false khi có subject.
        return [true, $msg, $evidence];
    }


    public function matchList(array $args): array
    {
        // 1) composer.lock
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        $lockJson = json_decode((string)@file_get_contents($lock), true);
        if (!is_array($lockJson)) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $pkgs = array_merge($lockJson['packages'] ?? [], $lockJson['packages-dev'] ?? []);
        $installed = [];
        foreach ($pkgs as $p) {
            if (!isset($p['name'], $p['version'])) continue;
            $installed[(string)$p['name']] = ltrim((string)$p['version'], 'v');
        }
        if (!$installed) return [true, "composer_match_list (offline): no packages", ['items' => []]];

        // 2) Xác định bundle candidate (ưu tiên args['cve_data'], sau đó autodiscover)
        $cand = $this->findCveBundleCandidate($args['cve_data'] ?? null);
        if ($cand['status'] !== 'ok') {
            return [null, "[UNKNOWN] " . $cand['reason'], [
                'installed_total' => count($installed),
                'dataset_total'   => 0,
            ]];
        }

        // 3) Nếu đếm được số file trong VULNS và =0 -> PASS (dataset empty)
        if (isset($cand['vuln_count']) && (int)$cand['vuln_count'] === 0) {
            return [true, "composer_match_list (offline): dataset empty (no VULNS/*.json)", [
                'installed_total' => count($installed),
                'dataset_total'   => 0,
                'deny' => [],
                'warn' => []
            ]];
        }

        // 4) Nạp VULNS qua CveAuditor::readCveFile (đã xử lý zip/dir nội bộ)
        $auditor = new \Magebean\Engine\Cve\CveAuditor($this->ctx);
        $vulns = $this->loadVulnsViaAuditor($auditor, $cand['path']);
        if (!is_array($vulns)) $vulns = [];
        $datasetTotal = count($vulns);

        // Nếu vì lý do nào đó không đọc ra được bản ghi nào nhưng trước đó ta đã xác nhận có VULNS,
        // vẫn coi như dataset empty -> PASS (theo yêu cầu).
        if ($datasetTotal === 0) {
            return [true, "composer_match_list (offline): dataset empty (no advisories parsed)", [
                'installed_total' => count($installed),
                'dataset_total'   => 0,
                'deny' => [],
                'warn' => []
            ]];
        }

        // 5) Tham số cảnh báo
        $sevWarnMin = isset($args['sev_warn_min']) ? floatval($args['sev_warn_min']) : 7.0; // High+
        $failOnWarn = isset($args['fail_on_warn']) ? (bool)$args['fail_on_warn'] : false;

        // 6) Duyệt & match
        $deny = []; // KEV
        $warn = []; // High/Critical non-KEV

        foreach ($vulns as $vuln) {
            if (!is_array($vuln)) continue;
            $affList = $vuln['affected'] ?? null;
            if (!is_array($affList)) continue;

            // KEV?
            $isKev = false;
            if (isset($vuln['database_specific']['known_exploited']) && $vuln['database_specific']['known_exploited'] === true) {
                $isKev = true;
            } else {
                $refs = $vuln['references'] ?? [];
                if (is_array($refs)) {
                    foreach ($refs as $r) {
                        $u = strtolower((string)($r['url'] ?? ''));
                        if ($u !== '' && str_contains($u, 'cisa') && (str_contains($u, 'kev') || str_contains($u, 'known'))) {
                            $isKev = true;
                            break;
                        }
                    }
                }
            }

            // severity
            [$sevLabel, $cvssScore] = $this->extractSeveritySafe($vuln);
            $cvss = ($cvssScore !== '') ? floatval($cvssScore) : null;

            foreach ($affList as $aff) {
                $pkg = $aff['package']['name'] ?? null;
                $eco = strtolower((string)($aff['package']['ecosystem'] ?? ''));
                if (!$pkg || !isset($installed[$pkg])) continue;
                if ($eco !== 'packagist' && $eco !== 'composer') continue;

                $curVer = $installed[$pkg];
                $affected = false;

                // versions[]
                if (!$affected && !empty($aff['versions']) && is_array($aff['versions'])) {
                    foreach ($aff['versions'] as $v) {
                        $v = ltrim((string)$v, 'v');
                        if ($v !== '' && version_compare($curVer, $v, '==')) {
                            $affected = true;
                            break;
                        }
                    }
                }
                // ranges.events
                $minFixed = null;
                if (!$affected && !empty($aff['ranges']) && is_array($aff['ranges'])) {
                    foreach ($aff['ranges'] as $rng) {
                        $events = $rng['events'] ?? [];
                        $intervals = $this->eventsToIntervalsSafe($auditor, $events, $minFixedCandidate);
                        foreach ($intervals as [$a, $b]) {
                            if ($this->inRangeSafe($auditor, $curVer, $a, $b)) {
                                $affected = true;
                            }
                            if ($b !== null) $minFixed = $this->minVersionLocal($minFixed, $b);
                        }
                        if (isset($minFixedCandidate)) $minFixed = $this->minVersionLocal($minFixed, $minFixedCandidate);
                    }
                }

                if (!$affected) continue;

                $item = [
                    'package'   => $pkg,
                    'installed' => $curVer,
                    'severity'  => $sevLabel,
                    'cvss'      => $cvssScore,
                    'kev'       => $isKev,
                    'fixed'     => $minFixed ? [$minFixed] : [],
                    'id'        => (string)($vuln['id'] ?? ''),
                    'aliases'   => array_values(array_filter(($vuln['aliases'] ?? []), 'is_string')),
                ];

                if ($isKev) {
                    $deny[] = $item;
                } elseif ($cvss !== null && $cvss >= $sevWarnMin) {
                    $warn[] = $item;
                }
            }
        }

        // 7) Kết luận
        if ($deny) {
            return [false, "composer_match_list (offline): DENY — Known exploited vulns present (" . count($deny) . ")", [
                'installed_total' => count($installed),
                'dataset_total'   => $datasetTotal,
                'deny' => $deny,
                'warn' => $warn,
            ]];
        }
        if ($warn) {
            $msg = "composer_match_list (offline): WARN — High/Critical vulns present (" . count($warn) . ")";
            return [$failOnWarn ? false : true, $msg, [
                'installed_total' => count($installed),
                'dataset_total'   => $datasetTotal,
                'deny' => [],
                'warn' => $warn
            ]];
        }
        return [true, "composer_match_list (offline): PASS — no KEV or High+ vulns", [
            'installed_total' => count($installed),
            'dataset_total'   => $datasetTotal,
            'deny' => [],
            'warn' => []
        ]];
    }

    public function constraintsConflict(array $args): array
    {
        // --- 0) Input files ---
        $jsonPath = $this->ctx->abs($args['composer_json'] ?? 'composer.json');
        if (!is_file($jsonPath)) {
            return [null, "[UNKNOWN] composer.json not found"];
        }
        $cvePath = $this->ctx->cveData;
        if (!is_string($cvePath) || $cvePath === '' || !is_file($cvePath)) {
            return [null, "[UNKNOWN] CVE dataset file not found (use --cve-data=...)"];
        }

        // --- 1) Small helpers (closures to avoid class-level collisions) ---
        $vercmp = function (string $a, string $b): int {
            $norm = function (string $v): array {
                $v = ltrim($v, 'vV');
                // keep only digits and dots for compare
                $v = preg_replace('/[^0-9.]/', '.', $v) ?? $v;
                $parts = array_map('intval', array_filter(explode('.', $v), 'strlen'));
                while (count($parts) < 3) $parts[] = 0;
                return $parts;
            };
            [$a1, $a2, $a3] = $norm($a);
            [$b1, $b2, $b3] = $norm($b);
            if ($a1 !== $b1) return $a1 <=> $b1;
            if ($a2 !== $b2) return $a2 <=> $b2;
            if ($a3 !== $b3) return $a3 <=> $b3;
            return 0;
        };
        $nextMajor = function (string $v): string {
            $v = ltrim($v, 'vV');
            $p = preg_replace('/[^0-9.]/', '.', $v);
            $a = array_map('intval', array_filter(explode('.', $p), 'strlen')) + [0, 0, 0];
            return ($a[0] + 1) . '.0.0';
        };
        $nextMinor = function (string $v): string {
            $v = ltrim($v, 'vV');
            $p = preg_replace('/[^0-9.]/', '.', $v);
            $a = array_map('intval', array_filter(explode('.', $p), 'strlen')) + [0, 0, 0];
            return $a[0] . '.' . ($a[1] + 1) . '.0';
        };
        $caretUpper = function (string $v) use ($nextMajor, $vercmp): string {
            // ^ rules (Composer): ^1.2.3 -> <2.0.0 ; ^0.2.3 -> <0.3.0 ; ^0.0.3 -> <0.0.4
            $v = ltrim($v, 'vV');
            $p = preg_replace('/[^0-9.]/', '.', $v);
            $a = array_map('intval', array_filter(explode('.', $p), 'strlen')) + [0, 0, 0];
            if ($a[0] > 0) return $nextMajor($v);
            if ($a[1] > 0) return "0." . ($a[1] + 1) . ".0";
            return "0.0." . ($a[2] + 1);
        };
        $wildcardUpper = function (string $v) use ($nextMajor, $nextMinor): string {
            // 1.* => <2.0.0 ; 1.2.* => <1.3.0
            $v = ltrim($v, 'vV');
            $p = preg_replace('/[^0-9.*]/', '.', $v);
            $a = explode('.', $p);
            if (count($a) >= 2 && ($a[1] === '*' || $a[1] === 'x')) {
                return $nextMajor($v);
            }
            return $nextMinor($v);
        };

        $semverAllowsAtLeast = function (string $constraint, string $fixed) use ($vercmp, $nextMajor, $nextMinor, $caretUpper, $wildcardUpper) {
            $constraint = trim($constraint);
            if ($constraint === '' || $constraint === '*') return true;

            // If Composer\Semver available, use exact check: any version >= fixed that satisfies?
            if (class_exists(\Composer\Semver\Semver::class)) {
                try {
                    // quick path: if constraint already allows fixed itself, return true
                    if (\Composer\Semver\Semver::satisfies($fixed, $constraint)) {
                        return true;
                    }
                    // heuristic: bump fixed a bit and test a few candidates
                    $cands = [$fixed];
                    // add same major/minor small bumps
                    $cands[] = $nextMinor($fixed);
                    $cands[] = $nextMajor($fixed);
                    foreach ($cands as $cand) {
                        if (\Composer\Semver\Semver::satisfies($cand, $constraint)) {
                            // ensure cand >= fixed
                            if ($vercmp($cand, $fixed) >= 0) return true;
                        }
                    }
                } catch (\Throwable $e) {
                    // ignore -> fall back to naive
                }
            }

            // Naive solver for common forms:
            // split OR '||'
            foreach (preg_split('/\s*\|\|\s*/', $constraint) as $clause) {
                $clause = trim(str_replace(',', ' ', $clause));
                if ($clause === '') continue;

                $upper = null;       // string, exclusive unless $upperInclusive
                $upperInclusive = false;
                $exactHit = null;    // if exact version in clause

                $tokens = preg_split('/\s+/', $clause);
                foreach ($tokens as $tok) {
                    $tok = trim($tok);
                    if ($tok === '') continue;

                    // 1) Exact version (no operator)
                    if (preg_match('/^[vV]?\d+(\.\d+){0,2}$/', $tok)) {
                        $exactHit = $tok;
                        continue;
                    }

                    // 2) Wildcards like 1.* or 1.2.*
                    if (preg_match('/^[vV]?\d+(\.\d+)?\.\*$/', $tok) || preg_match('/^[vV]?\d+\.\*$/', $tok)) {
                        $u = $wildcardUpper($tok);
                        if ($upper === null || $vercmp($u, $upper) < 0) {
                            $upper = $u;
                            $upperInclusive = false;
                        }
                        continue;
                    }

                    // 3) Caret ^x.y.z
                    if ($tok[0] === '^') {
                        $base = substr($tok, 1);
                        $u = $caretUpper($base);
                        if ($upper === null || $vercmp($u, $upper) < 0) {
                            $upper = $u;
                            $upperInclusive = false;
                        }
                        continue;
                    }

                    // 4) Tilde ~x.y or ~x.y.z
                    if ($tok[0] === '~') {
                        $base = substr($tok, 1);
                        $u = $nextMinor($base);
                        if ($upper === null || $vercmp($u, $upper) < 0) {
                            $upper = $u;
                            $upperInclusive = false;
                        }
                        continue;
                    }

                    // 5) Operators
                    if (preg_match('/^(>=|>|<=|<|=)\s*([vV]?\d+(?:\.\d+){0,2})$/', $tok, $m)) {
                        $op = $m[1];
                        $v = $m[2];
                        if ($op === '<') {
                            if ($upper === null || $vercmp($v, $upper) < 0) {
                                $upper = $v;
                                $upperInclusive = false;
                            }
                        } elseif ($op === '<=') {
                            if ($upper === null || $vercmp($v, $upper) < 0) {
                                $upper = $v;
                                $upperInclusive = true;
                            } elseif ($upper !== null && $vercmp($v, $upper) === 0) {
                                // if same U but one is exclusive, keep exclusive
                                $upperInclusive = $upperInclusive && true;
                            }
                        } elseif ($op === '=') {
                            $exactHit = $v;
                        } else {
                            // >= or > only affect lower bound; lower bound never blocks ">= fixed" existence
                            // leave for simplicity
                        }
                        continue;
                    }
                }

                // Evaluate the clause
                if ($exactHit !== null) {
                    // exact version allowed
                    return ($vercmp($exactHit, $fixed) >= 0);
                }
                if ($upper === null) {
                    // no upper bound -> there exists some version >= fixed
                    return true;
                }
                // check fixed against upper bound
                $cmp = $vercmp($fixed, $upper);
                if ($cmp < 0) {
                    return true; // fixed is below the (exclusive) upper
                }
                if ($cmp === 0 && $upperInclusive) {
                    return true; // fixed equals inclusive upper
                }
                // otherwise this clause cannot accommodate fixed-or-higher
                // keep checking other OR clauses
            }
            return false;
        };

        // --- 2) Build minimal "fixed version" per package from CVE dataset ---
        $fixMin = []; // package => minimal fixed version that resolves each CVE; we will take MAX across CVEs
        $handleRow = function (array $row) use (&$fixMin, $vercmp) {
            if (empty($row['affected']) || !is_array($row['affected'])) return;
            foreach ($row['affected'] as $aff) {
                $pkg = $aff['package']['name'] ?? null;
                $eco = $aff['package']['ecosystem'] ?? null;
                if (!$pkg || !$eco) continue;
                if (strtolower($eco) !== 'packagist') continue;
                $pkg = strtolower($pkg);

                // collect minimal fixed in this CVE record for this package
                $minFixedThis = null;
                if (!empty($aff['ranges']) && is_array($aff['ranges'])) {
                    foreach ($aff['ranges'] as $rg) {
                        if (!empty($rg['events']) && is_array($rg['events'])) {
                            foreach ($rg['events'] as $ev) {
                                if (!empty($ev['fixed'])) {
                                    $fx = (string)$ev['fixed'];
                                    if ($minFixedThis === null || $vercmp($fx, $minFixedThis) < 0) {
                                        $minFixedThis = $fx;
                                    }
                                }
                            }
                        }
                    }
                }
                if ($minFixedThis !== null) {
                    if (!isset($fixMin[$pkg]) || $vercmp($minFixedThis, $fixMin[$pkg]) > 0) {
                        // take MAX across CVEs so that upgrading to this fixes all CVEs seen so far
                        $fixMin[$pkg] = $minFixedThis;
                    }
                }
            }
        };

        // read dataset (NDJSON or JSON array)
        $fh = @fopen($cvePath, 'rb');
        if (!$fh) return [null, "[UNKNOWN] Unable to open CVE dataset: {$cvePath}"];
        $peek = fread($fh, 1 << 15) ?: '';
        fclose($fh);

        if (preg_match('/^\s*\[/', $peek) === 1) {
            // JSON array
            $raw = @file_get_contents($cvePath);
            if ($raw === false || $raw === '') return [null, "[UNKNOWN] Empty CVE dataset"];
            $arr = json_decode($raw, true);
            if (!is_array($arr)) return [null, "[UNKNOWN] Invalid CVE JSON"];
            foreach ($arr as $row) {
                if (is_array($row)) $handleRow($row);
            }
        } else {
            // NDJSON
            $fh = @fopen($cvePath, 'rb');
            if (!$fh) return [null, "[UNKNOWN] Unable to open CVE dataset (ndjson): {$cvePath}"];
            while (!feof($fh)) {
                $line = fgets($fh);
                if ($line === false) break;
                $line = trim($line);
                if ($line === '') continue;
                $row = json_decode($line, true);
                if (is_array($row)) $handleRow($row);
            }
            fclose($fh);
        }

        if (empty($fixMin)) {
            return [null, "[UNKNOWN] No fixed-version data in CVE dataset; cannot evaluate constraints"];
        }

        // --- 3) Load composer.json constraints ---
        $composer = json_decode((string)file_get_contents($jsonPath), true);
        if (!is_array($composer)) {
            return [null, "[UNKNOWN] Invalid composer.json"];
        }
        $req = is_array($composer['require'] ?? null) ? $composer['require'] : [];
        $reqDev = is_array($composer['require-dev'] ?? null) ? $composer['require-dev'] : [];
        $constraints = [];
        foreach ([$req, $reqDev] as $bucket) {
            foreach ($bucket as $name => $con) {
                $constraints[strtolower((string)$name)] = (string)$con;
            }
        }
        if (empty($constraints)) {
            return [true, "No constraints to evaluate"];
        }

        // --- 4) Evaluate conflicts ---
        $conflicts = [];
        foreach ($fixMin as $pkg => $minFixed) {
            if (!isset($constraints[$pkg])) continue; // not directly required by the project
            $con = $constraints[$pkg];
            $allows = $semverAllowsAtLeast($con, $minFixed);
            if (!$allows) {
                $conflicts[] = "{$pkg} requires '{$con}' but needs >= {$minFixed}";
            }
        }

        if (!empty($conflicts)) {
            return [false, "Constraints block security upgrades: " . implode(' ; ', $conflicts) . " (dataset: {$cvePath})"];
        }

        return [true, "Composer constraints do not block required security update ranges (dataset: {$cvePath})"];
    }


    public function outdatedOffline(array $args): array
    {
        $lock   = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $market = $this->metaPath($args, 'market', 'market_meta', 'DATA/marketplace-versions.json')
            ?? $this->metaPath($args, 'market', 'release_meta', 'DATA/marketplace-versions.json')
            ?? $this->metaPath($args, 'market', 'market_meta', 'rules/marketplace-versions.json')
            ?? $this->metaPath($args, 'market', 'release_meta', 'rules/marketplace-versions.json');

        if (!is_file($lock)) {
            return [null, "[UNKNOWN] composer.lock not found"];
        }
        if (!$this->safeIsFile($market)) {
            return [null, "[UNKNOWN] Release/marketplace metadata not found"];
        }

        // TODO: Implement thực theo meta format → tạm UNKNOWN
        return [null, "[UNKNOWN] Outdated check not implemented (meta present)"];
    }

    public function advisoryLatency(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $meta = $this->metaPath($args, 'advisories', 'advisory_meta', 'DATA/advisories.json')
            ?? $this->metaPath($args, 'advisories', 'advisory_meta', 'rules/advisories.json');

        if (!is_file($lock))  return [null, "[UNKNOWN] composer.lock not found"];
        if (!$this->safeIsFile($meta))  return [null, "[UNKNOWN] Advisory metadata not found"];

        // TODO: implement real advisory latency evaluation (compare advisory publish_date vs local update/lock date)
        return [null, "[UNKNOWN] Advisory latency check not implemented (meta present)"];
    }

    public function vendorSupportOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'vendor_support', 'support_meta', 'rules/vendor-support.json');
        if (!$metaPath) return [null, "[UNKNOWN] Vendor support metadata not found"];

        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $meta = $this->loadJsonSafe($metaPath);
        if (!$meta) return [null, "[UNKNOWN] Invalid vendor-support metadata JSON"];

        $today = strtotime('today');
        $eol = [];
        foreach ($pkgs as $name => $_) {
            $info = $meta[$name] ?? null;
            if (!$info) continue;
            $supported = (bool)($info['supported'] ?? false);
            $untilStr  = (string)($info['until'] ?? '');
            $until     = $untilStr !== '' ? strtotime($untilStr) : null;

            if (!$supported) {
                $eol[] = "{$name} (unsupported)";
            } elseif ($until && $until < $today) {
                $eol[] = "{$name} (support ended {$untilStr})";
            }
        }

        if ($eol) return [false, "Unsupported/EOL packages: " . implode('; ', $eol)];
        return [true, "All packages are within vendor support windows"];
    }


    public function abandonedOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'abandoned', 'abandoned_meta', 'rules/packagist-abandoned.json');
        if (!$metaPath) return [null, "[UNKNOWN] Abandoned metadata not found (bundle or args)"];

        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $meta = $this->loadJsonSafe($metaPath);
        if (!$meta || !isset($meta['abandoned']) || !is_array($meta['abandoned'])) {
            return [null, "[UNKNOWN] Invalid abandoned metadata JSON: {$metaPath}"];
        }
        // Nếu metadata rỗng, coi như KHÔNG đủ dữ liệu => UNKNOWN (tránh PASS giả)
        if (count($meta['abandoned']) === 0) {
            return [null, "[UNKNOWN] Abandoned metadata is empty: {$metaPath}"];
        }

        $aband = $meta['abandoned'];
        $hits = [];
        foreach ($pkgs as $name => $_) {
            if (array_key_exists($name, $aband)) {
                $replacement = $aband[$name];
                $hits[] = $replacement ? "{$name} → {$replacement}" : $name;
            }
        }

        if ($hits) return [false, "Abandoned packages: " . implode(', ', $hits) . " (meta: {$metaPath})"];
        return [true, "No abandoned packages (meta: {$metaPath})"];
    }

    public function releaseRecencyOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'release_history', 'release_meta', 'rules/release-history.json');
        if (!$metaPath) return [null, "[UNKNOWN] Release-history metadata not found"];

        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $meta = $this->loadJsonSafe($metaPath);
        if (!$meta) return [null, "[UNKNOWN] Invalid release-history metadata JSON"];

        $maxAgeDays = (int)($args['max_age_days'] ?? 365);
        $today = strtotime('today');

        $stale = [];
        foreach ($pkgs as $name => $p) {
            $info = $meta[$name] ?? null;
            if (!$info || empty($info['latest_date'])) continue;
            $latestDate = strtotime((string)$info['latest_date']);
            if ($latestDate === false) continue;

            $ageDays = (int)floor(($today - $latestDate) / 86400);
            if ($ageDays > $maxAgeDays) {
                $latestVer = (string)($info['latest_version'] ?? '?');
                $stale[] = "{$name} (latest {$latestVer}, {$ageDays} days old)";
            }
        }

        if ($stale) return [false, "Stale releases: " . implode('; ', $stale)];
        return [true, "No stale releases over {$maxAgeDays} days"];
    }


    public function repoArchivedOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'repo_status', 'repo_meta', 'rules/repo-status.json');
        if (!$metaPath) return [null, "[UNKNOWN] Repo-status metadata not found"];

        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $meta = $this->loadJsonSafe($metaPath);
        if (!$meta) return [null, "[UNKNOWN] Invalid repo-status metadata JSON"];

        $archived = [];
        foreach ($pkgs as $name => $_) {
            $st = $meta[$name] ?? null;
            if ($st && !empty($st['archived'])) $archived[] = $name;
        }

        if ($archived) return [false, "Archived repositories detected: " . implode(', ', $archived)];
        return [true, "No archived repositories"];
    }

    public function riskyForkOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'repo_status', 'repo_meta', 'rules/repo-status.json');
        if (!$metaPath) return [null, "[UNKNOWN] Repo-status metadata not found"];

        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $meta = $this->loadJsonSafe($metaPath);
        if (!$meta) return [null, "[UNKNOWN] Invalid repo-status metadata JSON"];

        $risky = [];
        foreach ($pkgs as $name => $_) {
            $st = $meta[$name] ?? null;
            if ($st && !empty($st['is_fork']) && empty($st['upstream'])) {
                $risky[] = $name;
            }
        }

        if ($risky) return [false, "Risky forks without upstream detected: " . implode(', ', $risky)];
        return [true, "No risky forks"];
    }


    public function jsonConstraints(array $args): array
    {
        $root = (string)($this->ctx->path ?? '');

        $jsonRel  = is_string($args['json_file'] ?? null) ? $args['json_file'] : 'composer.json';
        $jsonPath = $this->join($root, $jsonRel);

        // Nếu không thấy ngay tại vị trí dự kiến, thử find-up với chữ ký: findUp(string $path, int $maxDepth)
        if (!is_file($jsonPath)) {
            $found = $this->findUp($jsonPath, 6); // ✅ tham số 2 là int
            if (is_string($found) && $found !== '') {
                $jsonPath = $found;
            } else {
                return [false, [], "{$jsonRel} not found at {$jsonPath}"];
            }
        }

        $raw = @file_get_contents($jsonPath);
        if ($raw === false) {
            return [false, [], "Cannot read {$jsonRel} at {$jsonPath}"];
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $jerr = function_exists('json_last_error_msg') ? json_last_error_msg() : 'unknown JSON error';
            return [false, [], "Invalid {$jsonRel} at {$jsonPath}: {$jerr}"];
        }

        $sections = ['require', 'require-dev', 'conflict', 'replace', 'provide'];
        $out = [];

        foreach ($sections as $sec) {
            if (!empty($data[$sec]) && is_array($data[$sec])) {
                foreach ($data[$sec] as $pkg => $ver) {
                    if (!array_key_exists($pkg, $out)) {
                        // composer.json thường là string; cast đề phòng
                        $out[$pkg] = (string)$ver;
                    }
                }
            }
        }

        $count = count($out);
        $msg = $count > 0
            ? "Collected {$count} constraints from {$jsonRel} at {$jsonPath}"
            : "No constraints found in {$jsonRel} at {$jsonPath} (sections: " . implode(', ', $sections) . ")";

        return [true, $msg];
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
        $root = (string)($this->ctx->path ?? '');

        $jsonRel  = is_string($args['json_file'] ?? null) ? $args['json_file'] : 'composer.json';
        $jsonPath = $this->join($root, $jsonRel);

        // Tìm ngay tại vị trí dự kiến; nếu không có thì find-up với chữ ký: findUp(string $path, int $maxDepth)
        if (!is_file($jsonPath)) {
            $found = $this->findUp($jsonPath, 6); // ✅ tham số 2 là int, không truyền basename
            if (is_string($found) && $found !== '') {
                $jsonPath = $found;
            } else {
                return [false, "{$jsonRel} not found at {$jsonPath}"];
            }
        }

        $raw = @file_get_contents($jsonPath);
        if ($raw === false) {
            return [false, "Cannot read {$jsonRel} at {$jsonPath}"];
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $jerr = function_exists('json_last_error_msg') ? json_last_error_msg() : 'unknown JSON error';
            return [false, "Invalid {$jsonRel} at {$jsonPath}: {$jerr}"];
        }

        $key = (string)($args['key'] ?? '');
        if ($key === '') {
            return [false, "Missing 'key' argument (dot-path)"];
        }

        // Traverse dot-path (giữ nguyên wildcard '*' như bạn đang dùng)
        $exist = true;
        $val   = $data;
        foreach (explode('.', $key) as $seg) {
            if ($seg === '*') {
                if (!is_array($val) || empty($val)) {
                    $exist = false;
                    break;
                }
                // với wildcard hiện tại: coi như tồn tại nếu có ít nhất 1 phần tử
                $val = reset($val);
                continue;
            }
            if (!is_array($val) || !array_key_exists($seg, $val)) {
                $exist = false;
                break;
            }
            $val = $val[$seg];
        }

        // op: chuẩn hoá chữ thường; mặc định 'eq' nếu có 'expect', ngược lại 'exists'
        $op = $args['op'] ?? (array_key_exists('expect', $args) ? 'eq' : 'exists');
        $op = is_string($op) ? strtolower($op) : 'exists';

        if ($op === 'exists') {
            return [$exist, $exist ? "Key exists: {$key}" : "Key missing: {$key}"];
        }
        if ($op === 'not_exists') {
            return [!$exist, !$exist ? "Key does not exist (as expected): {$key}" : "Key unexpectedly present: {$key}"];
        }

        // eq/neq yêu cầu key tồn tại
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
        $root = (string)$this->ctx->path;

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
        $base = rtrim($base, '/');
        if ($rel === '' || $rel === '.') return $base;            // <-- chỉ trả về base dir
        if ($rel[0] === '/' || preg_match('#^[A-Za-z]:[\\\\/]#', $rel)) return $rel; // hỗ trợ Windows path
        return $base . '/' . ltrim($rel, '/');
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

    /**
     * Helper: load JSON file safely.
     */
    private function loadJsonSafe(string $path): ?array
    {
        if (!is_file($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        if ($raw === false || $raw === '') {
            return null;
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    /**
     * Helper: read packages from composer.lock
     */
    private function readLockPackages(string $lockPath): ?array
    {
        $j = $this->loadJsonSafe($lockPath);
        if (!$j) return null;

        $pkgs = [];
        foreach (['packages', 'packages-dev'] as $key) {
            if (!empty($j[$key]) && is_array($j[$key])) {
                foreach ($j[$key] as $p) {
                    if (!empty($p['name'])) {
                        $pkgs[$p['name']] = [
                            'name'    => $p['name'],
                            'version' => $p['version'] ?? null,
                            'source'  => $p['source']['url'] ?? null,
                            'dist'    => $p['dist']['url'] ?? null,
                        ];
                    }
                }
            }
        }
        return $pkgs;
    }

    /** Lấy đường dẫn meta trong Context->extra['meta'] hoặc từ args, hoặc default */
    private function metaPath(array $args, string $metaKey, string $argKey, string $defaultRel): ?string
    {
        $metaBag = $this->ctx->get('meta', []);
        if (is_array($metaBag) && !empty($metaBag[$metaKey]) && is_string($metaBag[$metaKey])) {
            $p = $metaBag[$metaKey];
            if ($this->safeIsFile($p)) return $p;
        }
        $root = (string)($this->ctx->path ?? getcwd());
        $cand = $this->safeJoin($root, is_string($args[$argKey] ?? null) ? $args[$argKey] : $defaultRel);
        return $this->safeIsFile($cand) ? $cand : null;
    }

    /** Safe wrapper: return false unless $p is a non-empty string and is a file */
    private function safeIsFile($p): bool
    {
        return is_string($p) && $p !== '' && is_file($p);
    }

    /** Join that tolerates nulls and non-strings defensively */
    private function safeJoin($base, $rel): ?string
    {
        if (!is_string($base)) $base = '';
        if (!is_string($rel))  return null;
        $base = rtrim($base, '/');
        if ($rel === '' || $rel === '.') return $base;
        if ($rel[0] === '/' || preg_match('#^[A-Za-z]:[\\\\/]#', $rel)) return $rel;
        return $base . '/' . ltrim($rel, '/');
    }

    /**
     * Quét đệ quy các roots, lọc theo extension, match regex theo tập patterns.
     * Trả về: ['files_scanned'=>int, 'hits'=>[['subject','path','tag','match'], ...]]
     */
    private function scanRiskSurface(array $roots, array $exts, array $patterns, array $installedNames, int $maxFiles, int $maxHitsPerSubject): array
    {
        $extSet = [];
        foreach ($exts as $e) $extSet[strtolower($e)] = true;

        $hits = [];
        $filesScanned = 0;
        $subjectHitsCount = []; // limit spam per subject

        foreach ($roots as $r) {
            if (!is_dir($r)) continue;
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($r, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::FOLLOW_SYMLINKS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($it as $file) {
                if ($filesScanned >= $maxFiles) break 2;
                /** @var \SplFileInfo $file */
                if (!$file->isFile()) continue;
                $ext = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
                if ($ext !== '' && !isset($extSet[$ext])) continue;

                $path = $file->getPathname();
                $filesScanned++;

                // Determine subject: vendor/package or Vendor_Module
                $subject = $this->subjectFromPath($path, $installedNames);

                // Read up to 256 KB to search
                $buf = @file_get_contents($path, false, null, 0, 262144);
                if ($buf === false || $buf === '') continue;

                foreach ($patterns as $tag => $regexes) {
                    $matched = false;
                    foreach ($regexes as $rx) {
                        // delimiters + i for case-insensitive on paths/text
                        $ok = @preg_match('/' . $rx . '/i', $buf, $m);
                        if ($ok === 1) {
                            $matched = true;
                            $matchStr = isset($m[0]) ? (string)$m[0] : $rx;
                            break;
                        }
                        // Nếu không match nội dung, thử match theo path (có ích cho Controller/Adminhtml)
                        $ok2 = @preg_match('/' . $rx . '/i', $path);
                        if ($ok2 === 1) {
                            $matched = true;
                            $matchStr = $rx;
                            break;
                        }
                    }
                    if ($matched) {
                        $subjectHitsCount[$subject] = ($subjectHitsCount[$subject] ?? 0) + 1;
                        if ($subjectHitsCount[$subject] <= $maxHitsPerSubject) {
                            $hits[] = [
                                'subject' => $subject,
                                'path' => $this->relPath($path),
                                'tag' => $tag,
                                'match' => $matchStr,
                            ];
                        }
                    }
                }
            }
        }

        return ['files_scanned' => $filesScanned, 'hits' => $hits];
    }

    /** Trả về path tương đối so với project root (để report gọn) */
    private function relPath(string $abs): string
    {
        $root = rtrim($this->ctx->abs('.'), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (str_starts_with($abs, $root)) {
            return substr($abs, strlen($root));
        }
        return $abs;
    }

    /**
     * Suy ra "subject" từ đường dẫn:
     * - Nếu nằm trong vendor/{vendor}/{package}/... -> "vendor/package" (ưu tiên nếu package có trong composer.lock)
     * - Nếu nằm trong app/code/{Vendor}/{Module}/... -> "Vendor_Module"
     * - Nếu không thì gom về "project"
     */
    private function subjectFromPath(string $path, array $installedNames): string
    {
        $path = str_replace('\\', '/', $path);
        // vendor/{vendor}/{package}/...
        if (preg_match('#/(vendor)/([^/]+)/([^/]+)/#', $path, $m)) {
            $pkg = $m[2] . '/' . $m[3];
            if (isset($installedNames[$pkg])) return $pkg;
            return $pkg; // vẫn trả về để tag, dù không có trong lock (edge-case)
        }
        // app/code/{Vendor}/{Module}/...
        if (preg_match('#/app/code/([^/]+)/([^/]+)/#i', $path, $m)) {
            return $m[1] . '_' . $m[2];
        }
        return 'project';
    }

    // 1) Tự tìm bundle, phân biệt 'load fail' vs 'dataset empty'
    private function findCveBundleCandidate(?string $explicit): array
    {
        $cands = [];
        if ($explicit) $cands[] = $explicit;

        // vài vị trí thường gặp
        $cands[] = $this->ctx->abs('magebean-known-cve-data-202510.zip');
        $cands[] = $this->ctx->abs('magebean-known-cve-data.zip');
        $cands[] = $this->ctx->abs('cve-data.zip');
        $cands[] = $this->ctx->abs('.'); // bundle đã giải nén ngay trong project

        // /tmp loader patterns (nếu bạn có cơ chế giải nén tạm)
        foreach (glob('/tmp/magebean-cve-*') ?: [] as $d) $cands[] = $d;

        foreach ($cands as $p) {
            if (is_file($p) && str_ends_with(strtolower($p), '.zip')) {
                $z = new \ZipArchive();
                if ($z->open($p) !== true) {
                    // zip hỏng -> tiếp tục dò candidate khác
                    continue;
                }
                // đếm VULNS/*.json
                $count = 0;
                for ($i = 0; $i < $z->numFiles; $i++) {
                    $name = $z->getNameIndex($i);
                    if (!$name) continue;
                    $ln = strtolower($name);
                    if (str_starts_with($ln, 'vulns/') && str_ends_with($ln, '.json')) $count++;
                }
                $z->close();
                return ['status' => 'ok', 'type' => 'zip', 'path' => $p, 'vuln_count' => $count];
            }
            if (is_dir($p)) {
                $vdir = rtrim($p, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'VULNS';
                if (!is_dir($vdir)) {
                    // không coi là ok vì thiếu VULNS
                    continue;
                }
                $files = glob($vdir . DIRECTORY_SEPARATOR . '*.json') ?: [];
                return ['status' => 'ok', 'type' => 'dir', 'path' => $p, 'vuln_count' => count($files)];
            }
        }
        return ['status' => 'err', 'reason' => 'CVE bundle not found (zip or VULNS dir)'];
    }

    // 2) Dùng CveAuditor::readCveFile để gom VULNS/*
    private function loadVulnsViaAuditor(\Magebean\Engine\Cve\CveAuditor $auditor, string $cveDataPath): array
    {
        $ref = new \ReflectionClass($auditor);
        if ($ref->hasMethod('readCveFile')) {
            $m = $ref->getMethod('readCveFile');
            $m->setAccessible(true);
            $v = $m->invoke($auditor, $cveDataPath);
            return is_array($v) ? $v : [];
        }
        return [];
    }

    // 3) extractSeverity kiểu OSV
    private function extractSeveritySafe(array $vuln): array
    {
        $sevArr = $vuln['severity'] ?? null;
        if (is_array($sevArr) && isset($sevArr[0]['score'])) {
            $score = (string)$sevArr[0]['score'];
            $num = floatval($score);
            $label = ($num >= 9.0) ? 'Critical' : (($num >= 7.0) ? 'High' : (($num >= 4.0) ? 'Medium' : (($num > 0.0) ? 'Low' : 'Unknown')));
            return [$label, $score];
        }
        $ds = $vuln['database_specific']['severity'] ?? '';
        if (is_string($ds) && $ds !== '') return [ucfirst(strtolower($ds)), ''];
        return ['Unknown', ''];
    }

    // 4) Gọi lại helpers của CveAuditor nếu có; có fallback local
    private function eventsToIntervalsSafe($auditor, array $events, ?string &$minFixedCandidate = null): array
    {
        $ref = new \ReflectionClass($auditor);
        if ($ref->hasMethod('eventsToIntervals')) {
            $m = $ref->getMethod('eventsToIntervals');
            $m->setAccessible(true);
            return $m->invoke($auditor, $events, $minFixedCandidate);
        }
        // local
        $res = [];
        $curStart = null;
        $minFixedCandidate = null;
        foreach ($events as $ev) {
            if (isset($ev['introduced'])) {
                $curStart = ltrim((string)$ev['introduced'], 'v');
            } elseif (isset($ev['fixed'])) {
                $fx = ltrim((string)$ev['fixed'], 'v');
                $minFixedCandidate = $this->minVersionLocal($minFixedCandidate, $fx);
                if ($curStart !== null) {
                    $res[] = [$curStart, $fx];
                    $curStart = null;
                } else {
                    $res[] = [null, $fx];
                }
            }
        }
        if ($curStart !== null) $res[] = [$curStart, null];
        return $res;
    }

    private function inRangeSafe($auditor, string $cur, ?string $a, ?string $b): bool
    {
        $ref = new \ReflectionClass($auditor);
        if ($ref->hasMethod('inRange')) {
            $m = $ref->getMethod('inRange');
            $m->setAccessible(true);
            return $m->invoke($auditor, $cur, $a, $b);
        }
        $cur = ltrim($cur, 'v');
        if ($a !== null && version_compare($cur, $a, '<')) return false;
        if ($b !== null && version_compare($cur, $b, '>=')) return false;
        return true;
    }

    private function minVersionLocal(?string $cur, string $cand): string
    {
        if ($cur === null) return ltrim($cand, 'v');
        return version_compare(ltrim($cand, 'v'), $cur, '<') ? ltrim($cand, 'v') : $cur;
    }
}
