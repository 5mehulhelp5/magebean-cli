<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class ComposerPolicyChecks extends ComposerSupport
{
    public function riskSurfaceTag(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');

        $metaPath = $this->metaPath($args, 'tags', 'tags_meta', 'risk-surface.json')
            ?? $this->metaPath($args, 'tags', 'tags_meta', 'rules/risk-surface.json');

        $metaJson = null;
        if ($metaPath && is_file($metaPath)) {
            $raw = (string)$this->collectors->files->read($metaPath);
            if (trim($raw) !== '') {
                $mj = json_decode($raw, true);
                // chỉ dùng khi có nội dung thực sự (patterns/file_ext); {} hoặc null -> bỏ qua
                if (is_array($mj) && (!empty($mj['patterns']) || !empty($mj['file_ext']))) {
                    $metaJson = $mj;
                }
            }
        }

        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        // 1) Read installed Magento extension packages.
        $lockJson = json_decode((string)$this->collectors->files->read($lock), true);
        if (!is_array($lockJson)) {
            return [null, "[UNKNOWN] Unable to parse composer.lock"];
        }
        $pkgs = array_merge($lockJson['packages'] ?? [], $lockJson['packages-dev'] ?? []);
        $installedNames = [];
        $extensionPackages = [];
        $installedVersions = [];
        foreach ($pkgs as $p) {
            if (!isset($p['name'])) continue;
            $name = strtolower((string)$p['name']);
            $installedNames[$name] = true;
            $version = ltrim((string)($p['version'] ?? ''), 'vV');
            if ($version !== '') {
                $installedVersions[$name] = $version;
            }
            $type = strtolower((string)($p['type'] ?? ''));
            if ($type === 'magento2-module' && !$this->isAdobeCorePackage($name)) {
                $extensionPackages[$name] = true;
            }
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
                '\bwebhook\b',
                '\bcallback\b',
                '\bipn\b',
                'Controller[/\\\\](Webhook|Callback|Notify)',
            ],
            // remote http calls
            'remote_http' => [
                'Http\\\\Client',
                '\bcurl(_init|_exec|_setopt)\b',
                'Guzzle\\\\Http|GuzzleHttp',
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

        // 3) Scan custom modules and installed non-core Magento extension packages only.
        $roots = [];
        $moduleNamesBySubject = [];
        $appCode = $this->ctx->abs('app/code');
        if (is_dir($appCode)) $roots[] = $appCode;
        $vendorDir = $this->ctx->abs('vendor');
        if (is_dir($vendorDir)) {
            foreach (array_keys($extensionPackages) as $package) {
                $packageRoot = $vendorDir . '/' . $package;
                if (is_dir($packageRoot)) {
                    $roots[] = $packageRoot;
                    $moduleNamesBySubject[$package] = $this->magentoModuleNamesForRoot($packageRoot);
                }
            }
        }

        if ($roots === []) {
            if ($extensionPackages !== []) {
                return [
                    null,
                    '[UNKNOWN] Magento extension source is unavailable; vendor packages from composer.lock cannot be inspected',
                    [
                        'extension_packages' => array_keys($extensionPackages),
                        'scan_roots' => [],
                    ],
                ];
            }
            return [
                true,
                'No custom or third-party Magento modules found to inspect',
                [
                    'extension_packages' => [],
                    'files_scanned' => 0,
                    'subjects_count' => 0,
                    'items' => [],
                ],
            ];
        }

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

        if ($subjects === []) {
            return [
                true,
                "No high-risk surfaces detected in {$scan['files_scanned']} inspected files",
                [
                    'scan_roots' => array_values($roots),
                    'extension_packages' => array_keys($extensionPackages),
                    'files_scanned' => $scan['files_scanned'],
                    'subjects_count' => 0,
                    'items' => [],
                ],
            ];
        }

        $enabledModules = $this->enabledMagentoModules();
        if ($enabledModules === null) {
            return [
                null,
                '[UNKNOWN] Unable to determine enabled Magento modules from app/etc/config.php',
                [
                    'scan_roots' => array_values($roots),
                    'extension_packages' => array_keys($extensionPackages),
                    'files_scanned' => $scan['files_scanned'],
                    'subjects_count' => count($subjects),
                    'items' => array_values($subjects),
                ],
            ];
        }

        $activeSubjects = [];
        foreach ($subjects as $subject => $item) {
            $moduleNames = $moduleNamesBySubject[$subject] ?? [$subject];
            $activeModules = array_values(array_filter(
                $moduleNames,
                static fn(string $module): bool => isset($enabledModules[$module])
            ));
            $item['module_names'] = $moduleNames;
            $item['active_modules'] = $activeModules;
            $item['enabled'] = $activeModules !== [];
            $subjects[$subject] = $item;
            if ($item['enabled']) {
                $activeSubjects[$subject] = $item;
            }
        }

        if ($activeSubjects === []) {
            return [
                true,
                'High-risk surfaces were found only in disabled modules',
                [
                    'scan_roots' => array_values($roots),
                    'extension_packages' => array_keys($extensionPackages),
                    'files_scanned' => $scan['files_scanned'],
                    'subjects_count' => count($subjects),
                    'active_subjects_count' => 0,
                    'items' => array_values($subjects),
                ],
            ];
        }

        $statusPackages = [];
        foreach (array_keys($activeSubjects) as $subject) {
            if (isset($installedVersions[$subject])) {
                $statusPackages[] = [
                    'name' => $subject,
                    'version' => $installedVersions[$subject],
                ];
            }
        }

        $statuses = [];
        if ($statusPackages !== []) {
            [$statusOk, $statusMessage, $statuses] = $this->fetchPackageStatuses($args, $statusPackages);
            if (!$statusOk) {
                return [
                    null,
                    '[UNKNOWN] Package status API request failed: ' . $statusMessage,
                    $this->packageStatusApiFailureEvidence($statusPackages, [
                        'active_subjects_checked' => count($activeSubjects),
                    ]),
                ];
            }
        }

        $reportable = [];
        foreach ($activeSubjects as $subject => $item) {
            $status = $statuses[$subject] ?? null;
            $item['package_status'] = $status;
            $item['outdated'] = is_array($status) && !empty($status['outdated']);
            $item['abandoned'] = is_array($status) && !empty($status['abandoned']);
            $activeSubjects[$subject] = $item;
            $subjects[$subject] = $item;
            if ($item['outdated'] || $item['abandoned']) {
                $reportable[$subject] = $item;
            }
        }

        $evidence = [
            'scan_roots' => array_values($roots),
            'extension_packages' => array_keys($extensionPackages),
            'files_scanned' => $scan['files_scanned'],
            'subjects_count' => count($subjects),
            'active_subjects_count' => count($activeSubjects),
            'reportable_subjects_count' => count($reportable),
            'items' => array_values($subjects),
        ];

        if ($reportable !== []) {
            $visible = array_values($reportable);
            $details = array_map(
                static function (array $subject): string {
                    $status = is_array($subject['package_status'] ?? null)
                        ? $subject['package_status']
                        : [];
                    $reason = !empty($subject['abandoned'])
                        ? 'abandoned'
                        : 'outdated ' . ($status['installed'] ?? '?') . ' < ' . ($status['latest'] ?? '?');
                    return $subject['subject']
                        . ' [' . implode(', ', $subject['tags']) . '; ' . $reason . ']';
                },
                $visible
            );
            $message = "Enabled high-risk modules require attention:\n    - "
                . implode("\n    - ", $details);
            return [false, $message, $evidence];
        }

        return [
            true,
            'Enabled high-risk modules are current; disabled or unversioned modules were not reported',
            $evidence,
        ];
    }

    private function enabledMagentoModules(): ?array
    {
        $path = $this->ctx->abs('app/etc/config.php');
        if (!is_file($path) || !is_readable($path)) {
            return null;
        }

        try {
            $config = (static fn(string $file): mixed => include $file)($path);
        } catch (\Throwable) {
            return null;
        }
        if (!is_array($config) || !is_array($config['modules'] ?? null)) {
            return null;
        }

        $enabled = [];
        foreach ($config['modules'] as $module => $state) {
            if ((int)$state === 1) {
                $enabled[(string)$module] = true;
            }
        }
        return $enabled;
    }

    private function magentoModuleNamesForRoot(string $root): array
    {
        $registration = rtrim($root, '/') . '/registration.php';
        if (!is_file($registration)) {
            return [];
        }
        $content = $this->collectors->files->read($registration);
        if (!is_string($content)) {
            return [];
        }

        preg_match_all(
            '/ComponentRegistrar::MODULE\s*,\s*[\'"]([^\'"]+)[\'"]/',
            $content,
            $matches
        );
        return array_values(array_unique(array_map('strval', $matches[1] ?? [])));
    }

    public function matchList(array $args): array
    {
        // 1) composer.lock
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        $lockJson = json_decode((string)$this->collectors->files->read($lock), true);
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

            foreach ($affList as $aff) {
                $pkg = $aff['package']['name'] ?? null;
                $eco = strtolower((string)($aff['package']['ecosystem'] ?? ''));
                if (!$pkg || !isset($installed[$pkg])) continue;
                if ($eco !== 'packagist' && $eco !== 'composer') continue;

                [$sevLabel, $cvssScore, $cvssVector] = $this->extractSeveritySafe($vuln, $aff);
                $cvss = ($cvssScore !== '') ? (float)$cvssScore : null;
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
                        foreach ($intervals as [$a, $b, $inclusive, $kind]) {
                            if ($this->inRangeSafe($auditor, $curVer, $a, $b, $inclusive)) {
                                $affected = true;
                            }
                            if ($b !== null && $kind === 'fixed') $minFixed = $this->minVersionLocal($minFixed, $b);
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
                    'cvss_vector' => $cvssVector,
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
        // ---- 0) Guard & nền tảng
        $root = $this->ctx->path ?: getcwd();
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) {
            return [null, "[UNKNOWN] composer.lock not found"];
        }

        // Composer CLI bắt buộc cho why/why-not
        @exec('composer --version 2>&1', $vOut, $vCode);
        if ($vCode !== 0) {
            return [null, "[UNKNOWN] composer CLI not available (install composer or add it to PATH)"];
        }

        // Đọc package đang cài
        $installed = $this->readLockPackages($lock);
        if (!$installed || !is_array($installed)) {
            return [null, "[UNKNOWN] Unable to parse composer.lock"];
        }
        $installedVers = [];
        foreach ($installed as $name => $info) {
            $ver = $info['version'] ?? null;
            if (is_string($ver) && $ver !== '') {
                $installedVers[$name] = ltrim($ver, 'vV');
            }
        }
        if (!$installedVers) {
            return [true, "No packages in composer.lock (nothing to check)"];
        }

        // ---- 1) Resolve CVE dataset path (support meta/osv_db or bundle with VULNS/)
        $meta = $this->ctx->get('meta', []);
        $pathCandidates = [];
        if (is_string($args['cve_data'] ?? null) && $args['cve_data'] !== '') $pathCandidates[] = $this->ctx->abs((string)$args['cve_data']);
        if (is_string($this->ctx->cveData ?? null) && $this->ctx->cveData !== '') $pathCandidates[] = $this->ctx->cveData;
        if (is_array($meta)) {
            foreach (['osv_db', 'osv'] as $k) {
                if (!empty($meta[$k]) && is_string($meta[$k])) $pathCandidates[] = $meta[$k];
            }
        }
        $pathCandidates = array_values(array_unique(array_filter($pathCandidates, fn($p) => is_string($p) && $p !== '')));

        $datasetPath = null;
        foreach ($pathCandidates as $cand) {
            $p = $this->ctx->abs((string)$cand);
            if (is_file($p) || is_dir($p)) {
                $datasetPath = $p;
                break;
            }
        }

        $bundleInfo = null;
        if ($datasetPath === null) {
            $bundleInfo = $this->findCveBundleCandidate($args['cve_data'] ?? ($this->ctx->cveData ?: null));
            if (($bundleInfo['status'] ?? '') === 'ok') {
                $datasetPath = (string)$bundleInfo['path'];
            }
        }

        if ($datasetPath === null) {
            return [null, "[UNKNOWN] CVE dataset not found (supply --cve-data bundle or osv-db.json)"];
        }

        // ---- 2) Load advisories via CveAuditor helper (supports zip/dir/plain JSON/NDJSON)
        $auditor = new \Magebean\Engine\Cve\CveAuditor($this->ctx);
        $vulns = $this->loadVulnsViaAuditor($auditor, $datasetPath);
        if (!is_array($vulns)) $vulns = [];
        if (($bundleInfo['vuln_count'] ?? null) === 0) {
            return [true, "CVE dataset is empty (0 advisories)"];
        }
        if (!$vulns) {
            return [true, "No advisories parsed from CVE dataset (nothing to check)"];
        }

        // ---- 3) Tính phiên bản fixed tối thiểu theo OSV ranges
        $targets = [];
        foreach ($vulns as $vuln) {
            if (!is_array($vuln) || empty($vuln['affected']) || !is_array($vuln['affected'])) continue;

            foreach ($vuln['affected'] as $aff) {
                $pkg = $aff['package']['name'] ?? null;
                $eco = strtolower((string)($aff['package']['ecosystem'] ?? ''));
                if (!$pkg || !isset($installedVers[$pkg])) continue;
                if ($eco !== 'packagist' && $eco !== 'composer') continue;

                $cur = $installedVers[$pkg];
                $hit = false;
                $minFixed = $targets[$pkg][1] ?? null;

                // explicit versions
                if (!empty($aff['versions']) && is_array($aff['versions'])) {
                    foreach ($aff['versions'] as $v) {
                        $v = ltrim((string)$v, 'vV');
                        if ($v !== '' && version_compare($cur, $v, '==')) {
                            $hit = true;
                            break;
                        }
                    }
                }

                // ranges
                $minFixedCandidate = null;
                if (!empty($aff['ranges']) && is_array($aff['ranges'])) {
                    foreach ($aff['ranges'] as $rng) {
                        $events = is_array($rng['events'] ?? null) ? $rng['events'] : [];
                        $intervals = $this->eventsToIntervalsSafe($auditor, $events, $minFixedCandidate);
                        foreach ($intervals as [$a, $b, $inclusive, $kind]) {
                            if ($this->inRangeSafe($auditor, $cur, $a, $b, $inclusive)) {
                                $hit = true;
                                if ($b !== null && $kind === 'fixed') $minFixed = $this->minVersionLocal($minFixed, $b);
                            }
                        }
                        if (isset($minFixedCandidate)) $minFixed = $this->minVersionLocal($minFixed, $minFixedCandidate);
                    }
                }

                // fallback database_specific.fixed
                if (isset($aff['database_specific']['fixed'])) {
                    $fx = ltrim((string)$aff['database_specific']['fixed'], 'vV');
                    if ($fx !== '') $minFixed = $this->minVersionLocal($minFixed, $fx);
                }

                if ($hit && $minFixed !== null && version_compare($minFixed, $cur, '>')) {
                    $targets[$pkg] = [$cur, $minFixed];
                }
            }
        }

        // Không có gói nào có fixed > installed → xem như không có fix cần nâng
        if (!$targets) {
            return [true, "No packages require fixes (no fixed version greater than installed)"];
        }

        // ---- 4) Chạy composer why-not / why để chẩn đoán blockers
        $execIn = function (string $cmd) use ($root): array {
            $full = sprintf('cd %s && %s', escapeshellarg($root), $cmd . ' 2>&1');
            $out = [];
            $code = 0;
            @exec($full, $out, $code);
            return [$code, implode("\n", $out)];
        };

        // Đọc platform locks từ composer.json nếu có
        $platformCfg = null;
        $cjPath = rtrim($root, '/') . '/composer.json';
        if (is_file($cjPath)) {
            $cjRaw = $this->collectors->files->read($cjPath);
            if (is_string($cjRaw)) {
                $cj = json_decode($cjRaw, true);
                if (is_array($cj)) $platformCfg = $cj['config']['platform'] ?? null;
            }
        }

        $fail = [];
        foreach ($targets as $pkg => [$cur, $need]) {
            // why-not: nếu có output → có blockers (thông thường)
            [$c1, $o1] = $execIn(sprintf('composer why-not %s %s', escapeshellarg($pkg), escapeshellarg($need)));
            $o1 = trim($o1);

            // why: quan hệ phụ thuộc hiện tại
            [$c2, $o2] = $execIn(sprintf('composer why %s', escapeshellarg($pkg)));
            $o2 = trim($o2);

            $block = [];
            if ($o1 !== '') $block[] = "why-not:\n" . $o1;
            if ($o2 !== '') $block[] = "why:\n" . $o2;

            // (tuỳ chọn) validate để lộ red flags config
            [$cv, $ov] = $execIn('composer validate --no-check-all');
            $ov = trim($ov);
            if ($cv !== 0 && $ov !== '') {
                $block[] = "validate:\n" . $ov;
            }

            // platform hint
            if (is_array($platformCfg) && $platformCfg) {
                $block[] = "platform: " . json_encode($platformCfg);
            }

            if ($block) {
                $fail[] = sprintf(
                    '%s %s -> >= %s BLOCKED BY%s%s',
                    $pkg,
                    $cur,
                    $need,
                    PHP_EOL,
                    implode(PHP_EOL . PHP_EOL, $block)
                );
            }
        }

        if ($fail) {
            // Có ít nhất 1 package bị chặn
            return [false, "Constraints blocking fixes:\n" . implode("\n\n---\n\n", $fail)];
        }

        return [true, "No constraints blocking fixes (targets appear installable)"];
    }

    public function jsonConstraints(array $args): array
    {
        $root = (string)($this->ctx->path ?? '');

        $jsonRel  = is_string($args['json_file'] ?? null) ? $args['json_file'] : 'composer.json';
        $jsonPath = $this->join($root, $jsonRel);

        if (!is_file($jsonPath) && !empty($args['project_local_only'])) {
            return [null, '[UNKNOWN] Project-local Composer manifest is unavailable', ['json_file' => $jsonPath]];
        }
        if (!is_file($jsonPath)) {
            $found = $this->findUp($jsonPath, 6);
            if (is_string($found) && $found !== '') {
                $jsonPath = $found;
            } else {
                return [
                    null,
                    "[UNKNOWN] {$jsonRel} not found at {$jsonPath}",
                    ['json_file' => $jsonPath],
                ];
            }
        }

        $raw = $this->collectors->files->read($jsonPath);
        if ($raw === false) {
            return [
                null,
                "[UNKNOWN] Cannot read {$jsonRel} at {$jsonPath}",
                ['json_file' => $jsonPath],
            ];
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $jerr = function_exists('json_last_error_msg') ? json_last_error_msg() : 'unknown JSON error';
            return [
                null,
                "[UNKNOWN] Invalid {$jsonRel} at {$jsonPath}: {$jerr}",
                ['json_file' => $jsonPath, 'json_error' => $jerr],
            ];
        }

        if (!empty($args['project_local_only']) && !is_object(json_decode($raw))) {
            return [null, '[UNKNOWN] Composer manifest must be a JSON object', ['json_file' => $jsonPath]];
        }
        if (!empty($args['project_local_only'])) {
            $object = json_decode($raw);
            foreach ($args['sections'] ?? ['require', 'require-dev'] as $section) {
                if (property_exists($object, $section)) {
                    if (!is_object($object->$section)) return [null, '[UNKNOWN] Composer dependency section is malformed', ['section' => $section]];
                    foreach ($object->$section as $package => $constraint) {
                        if (!is_string($constraint)) return [null, '[UNKNOWN] Composer dependency constraint is malformed', ['package' => $package]];
                    }
                }
            }
        }
        $sections = is_array($args['sections'] ?? null)
            ? array_values(array_filter(array_map('strval', $args['sections'])))
            : ['require', 'require-dev'];
        $deny = array_values(array_map(
            static fn(mixed $value): string => strtolower(trim((string)$value)),
            (array)($args['deny'] ?? [])
        ));
        $denyPrefixes = array_values(array_filter(array_map(
            static fn(mixed $value): string => strtolower(trim((string)$value)),
            (array)($args['deny_prefix'] ?? [])
        )));
        $denyWildcard = !empty($args['deny_wildcard']);
        $denyDevConstraints = !empty($args['deny_dev_constraints']);
        $wildcardPattern = '/(^|[\\s,|()~^<>=])(?:v?\\d+(?:\\.\\d+)*\\.)?(?:\\*|x)(?=$|[\\s,|@()])/i';
        $devConstraintPattern = '/(^|[\\s,|()~^<>=])'
            . '(?:dev-[a-z0-9_.\\/-]+|v?\\d+(?:\\.(?:\\d+|x))*-dev)'
            . '(?=$|[\\s,|@()#])/i';
        $constraints = [];
        $findings = [];

        foreach ($sections as $sec) {
            if (!empty($data[$sec]) && is_array($data[$sec])) {
                foreach ($data[$sec] as $pkg => $ver) {
                    $package = strtolower(trim((string)$pkg));
                    $constraint = trim((string)$ver);
                    $item = [
                        'section' => $sec,
                        'package' => $package,
                        'constraint' => $constraint,
                    ];
                    $constraints[] = $item;

                    $reasons = [];
                    if (in_array(strtolower($constraint), $deny, true)) {
                        $reasons[] = 'denied_constraint';
                    }
                    foreach ($denyPrefixes as $prefix) {
                        $prefixPattern = '/(^|[\\s,|()~^<>=])'
                            . preg_quote($prefix, '/') . '/i';
                        if (preg_match($prefixPattern, $constraint) === 1) {
                            $reasons[] = 'denied_prefix:' . $prefix;
                        }
                    }
                    $platformPresenceConstraint = str_starts_with($package, 'ext-')
                        || str_starts_with($package, 'lib-');
                    if ($denyWildcard
                        && !$platformPresenceConstraint
                        && preg_match($wildcardPattern, $constraint) === 1
                    ) {
                        $reasons[] = 'wildcard_constraint';
                    }
                    if ($denyDevConstraints
                        && (preg_match($devConstraintPattern, $constraint) === 1
                            || preg_match('/@dev\\b/i', $constraint) === 1)
                    ) {
                        $reasons[] = 'development_constraint';
                    }
                    if ($reasons !== []) {
                        $findings[] = $item + ['reasons' => array_values(array_unique($reasons))];
                    }
                }
            }
        }

        $evidence = [
            'json_file' => $jsonPath,
            'sections' => $sections,
            'constraints_checked' => count($constraints),
            'findings' => $findings,
        ];
        if ($findings !== []) {
            $findingMessage = trim((string)($args['finding_message'] ?? ''));
            if ($findingMessage === '') {
                $findingMessage = 'Disallowed Composer constraints detected';
            }
            $details = array_map(
                static fn(array $item): string => $item['section'] . ': '
                    . $item['package'] . ' => ' . $item['constraint'],
                $findings
            );
            return [
                false,
                $findingMessage . ":\n    - " . implode("\n    - ", $details),
                $evidence,
            ];
        }

        return [
            true,
            'No disallowed constraints found across ' . count($constraints) . ' Composer requirement(s)',
            $evidence,
        ];
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

        if (!is_file($jsonPath) && !empty($args['project_local_only'])) {
            return [null, '[UNKNOWN] Project-local Composer manifest is unavailable', ['json_file' => $jsonPath]];
        }
        if (!is_file($jsonPath)) {
            $found = $this->findUp($jsonPath, 6);
            if (is_string($found) && $found !== '') {
                $jsonPath = $found;
            } else {
                return [
                    null,
                    "[UNKNOWN] {$jsonRel} not found at {$jsonPath}",
                    ['json_file' => $jsonPath],
                ];
            }
        }

        $raw = $this->collectors->files->read($jsonPath);
        if ($raw === false) {
            return [
                null,
                "[UNKNOWN] Cannot read {$jsonRel} at {$jsonPath}",
                ['json_file' => $jsonPath],
            ];
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $jerr = function_exists('json_last_error_msg') ? json_last_error_msg() : 'unknown JSON error';
            return [
                null,
                "[UNKNOWN] Invalid {$jsonRel} at {$jsonPath}: {$jerr}",
                ['json_file' => $jsonPath, 'json_error' => $jerr],
            ];
        }

        if (!empty($args['project_local_only']) && !is_object(json_decode($raw))) {
            return [null, '[UNKNOWN] Composer manifest must be a JSON object', ['json_file' => $jsonPath]];
        }
        $key = (string)($args['key'] ?? $args['path'] ?? '');
        if ($key === '') {
            return [
                null,
                "[UNKNOWN] Missing 'key' argument (dot-path)",
                ['json_file' => $jsonPath],
            ];
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

        $hasExpectedValue = array_key_exists('expect', $args) || array_key_exists('equals', $args);
        $expect = $args['expect'] ?? $args['equals'] ?? null;
        $op = $args['op'] ?? ($hasExpectedValue ? 'eq' : 'exists');
        $op = is_string($op) ? strtolower($op) : 'exists';
        $evidence = [
            'json_file' => $jsonPath,
            'key' => $key,
            'exists' => $exist,
            'actual' => $exist ? $val : null,
            'expected' => $hasExpectedValue ? $expect : null,
            'strict' => !empty($args['strict']),
        ];

        if ($op === 'exists') {
            return [$exist, $exist ? "Key exists: {$key}" : "Key missing: {$key}", $evidence];
        }
        if ($op === 'not_exists') {
            return [
                !$exist,
                !$exist ? "Key does not exist (as expected): {$key}" : "Key unexpectedly present: {$key}",
                $evidence,
            ];
        }

        // eq/neq yêu cầu key tồn tại
        if (!$exist) {
            return [false, "Key missing for comparison: {$key}", $evidence];
        }

        $equal = !empty($args['strict'])
            ? $val === $expect
            : $this->looseEqual($val, $expect);

        if ($op === 'eq') {
            return [$equal, $equal
                ? "OK: {$key} == " . $this->printVal($expect)
                : "Mismatch: {$key}=" . $this->printVal($val) . " != " . $this->printVal($expect),
                $evidence];
        }
        if ($op === 'neq') {
            return [!$equal, !$equal
                ? "OK: {$key} (" . $this->printVal($val) . ") != " . $this->printVal($expect)
                : "Unexpected equal: {$key} == " . $this->printVal($expect),
                $evidence];
        }

        return [null, "[UNKNOWN] Unsupported op '{$op}'", $evidence];
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
        $root = (string)$this->ctx->path;
        $lockRel      = is_string($args['lock_file'] ?? null) ? $args['lock_file'] : 'composer.lock';
        $jsonRel      = is_string($args['json_file'] ?? null) ? $args['json_file'] : 'composer.json';
        $installedRel = is_string($args['installed_file'] ?? null) ? $args['installed_file'] : 'vendor/composer/installed.json';

        $jsonPath = $this->join($root, $jsonRel);
        if (!is_file($jsonPath)) {
            return [null, "[UNKNOWN] composer.json not found at {$jsonPath}", ['json_file' => $jsonPath]];
        }
        $jsonRaw = $this->collectors->files->read($jsonPath);
        $json = is_string($jsonRaw) ? json_decode($jsonRaw, true) : null;
        if (!is_array($json)) {
            return [
                null,
                "[UNKNOWN] Invalid composer.json at {$jsonPath}",
                ['json_file' => $jsonPath, 'json_error' => json_last_error_msg()],
            ];
        }

        $lockPath = $this->join($root, $lockRel);
        if (!is_file($lockPath)) {
            return [
                false,
                "composer.lock not found at {$lockPath}",
                ['json_file' => $jsonPath, 'lock_file' => $lockPath, 'problems' => ['lock_missing']],
            ];
        }

        $lockRaw = $this->collectors->files->read($lockPath);
        $lock    = is_string($lockRaw) ? json_decode($lockRaw, true) : null;
        if (!is_array($lock)) {
            return [
                false,
                "Invalid composer.lock at {$lockPath}",
                ['json_file' => $jsonPath, 'lock_file' => $lockPath, 'problems' => ['lock_invalid']],
            ];
        }

        foreach (['packages', 'packages-dev'] as $bucket) {
            if (!array_key_exists($bucket, $lock)) {
                if ($bucket === 'packages-dev') continue;
                return [false, 'composer.lock is missing the packages array', ['problems' => ['package_list_missing']]];
            }
            if (!is_array($lock[$bucket]) || !array_is_list($lock[$bucket])) return [false, 'composer.lock has an invalid ' . $bucket . ' list', ['problems' => ['package_list_invalid']]];
            foreach ($lock[$bucket] as $package) {
                if (!is_array($package) || !is_string($package['name'] ?? null) || trim($package['name']) === '' || !is_string($package['version'] ?? null) || trim($package['version']) === '') {
                    return [false, 'composer.lock has a malformed package identity or version in ' . $bucket, ['problems' => ['package_identity_invalid']]];
                }
            }
        }
        $pkgs = [];
        $dups = [];
        $provided = [];
        foreach (['packages', 'packages-dev'] as $bucket) {
            foreach ((array)($lock[$bucket] ?? []) as $p) {
                if (!is_array($p)) {
                    continue;
                }
                $name = strtolower((string)($p['name'] ?? ''));
                $ver  = (string)($p['version'] ?? '');
                if ($name === '') {
                    continue;
                }
                if (isset($pkgs[$name])) {
                    $dups[$name] = true;
                }
                $pkgs[$name] = $ver;
                foreach (['provide', 'replace'] as $capability) {
                    foreach ((array)($p[$capability] ?? []) as $providedName => $_constraint) {
                        $provided[strtolower((string)$providedName)] = $name;
                    }
                }
            }
        }

        $problems = [];
        $problemCodes = [];
        $expectedHash = $this->composerContentHash($json);
        $actualHash = is_string($lock['content-hash'] ?? null)
            ? strtolower(trim($lock['content-hash']))
            : '';
        if ($actualHash === '') {
            $problemCodes[] = 'content_hash_missing';
            $problems[] = 'composer.lock is missing content-hash';
        } elseif ($expectedHash === null) {
            return [
                null,
                '[UNKNOWN] Unable to calculate Composer content-hash',
                ['json_file' => $jsonPath, 'lock_file' => $lockPath],
            ];
        } elseif (!hash_equals($expectedHash, $actualHash)) {
            $problemCodes[] = 'content_hash_mismatch';
            $problems[] = 'content-hash mismatch: lock ' . $actualHash . ', expected ' . $expectedHash;
        }

        if ($dups !== []) {
            $problemCodes[] = 'duplicate_packages';
            $problems[] = 'duplicate package entries in lock: ' . implode(', ', array_keys($dups));
        }

        $required = [];
        foreach (['require', 'require-dev'] as $section) {
            foreach ((array)($json[$section] ?? []) as $name => $constraint) {
                $name = strtolower((string)$name);
                if ($name === 'php'
                    || str_starts_with($name, 'ext-')
                    || str_starts_with($name, 'lib-')
                    || in_array($name, ['composer-plugin-api', 'composer-runtime-api'], true)
                ) {
                    continue;
                }
                $required[$name] = ['constraint' => (string)$constraint, 'section' => $section];
            }
        }

        $missing = [];
        foreach ($required as $name => $requirement) {
            if (!isset($pkgs[$name]) && !isset($provided[$name])) {
                $missing[] = $name;
            }
        }
        if ($missing !== []) {
            $problemCodes[] = 'direct_dependencies_missing';
            $problems[] = 'required packages not present or provided in lock: ' . implode(', ', $missing);
        }

        $installedComparison = null;
        if (!empty($args['check_installed'])) {
            $installedPath = $this->join($root, $installedRel);
            if (!is_file($installedPath)) {
                return [
                    null,
                    "[UNKNOWN] Installed package metadata not found at {$installedPath}",
                    ['json_file' => $jsonPath, 'lock_file' => $lockPath, 'installed_file' => $installedPath],
                ];
            }
            $instRaw = $this->collectors->files->read($installedPath);
            $installed = is_string($instRaw) ? json_decode($instRaw, true) : null;
            if (!is_array($installed)) {
                return [null, "[UNKNOWN] Invalid installed package metadata at {$installedPath}"];
            }
            $installedPkgs = [];
            $list = $installed['packages'] ?? $installed;
            foreach ((array)$list as $p) {
                $n = is_array($p) ? strtolower((string)($p['name'] ?? '')) : '';
                if ($n !== '') $installedPkgs[$n] = true;
            }
            $notInstalled = array_keys(array_diff_key($pkgs, $installedPkgs));
            $installedComparison = ['not_installed' => $notInstalled];
            if ($notInstalled !== []) {
                $problemCodes[] = 'locked_packages_not_installed';
                $problems[] = 'packages present in lock but not installed: ' . implode(', ', $notInstalled);
            }
        }

        $evidence = [
            'json_file' => $jsonPath,
            'lock_file' => $lockPath,
            'expected_content_hash' => $expectedHash,
            'actual_content_hash' => $actualHash,
            'locked_packages' => count($pkgs),
            'direct_requirements' => $required,
            'provided_packages' => $provided,
            'duplicate_packages' => array_keys($dups),
            'missing_direct_requirements' => $missing,
            'installed_comparison' => $installedComparison,
            'problem_codes' => $problemCodes,
        ];
        if ($problems !== []) {
            return [
                false,
                "composer.lock integrity issues:\n    - " . implode("\n    - ", $problems),
                $evidence,
            ];
        }

        return [
            true,
            'composer.lock integrity OK (' . count($pkgs) . ' packages, content-hash verified)',
            $evidence,
        ];
    }

    private function composerContentHash(array $composer): ?string
    {
        $relevantKeys = [
            'name',
            'version',
            'require',
            'require-dev',
            'conflict',
            'replace',
            'provide',
            'minimum-stability',
            'prefer-stable',
            'repositories',
            'extra',
        ];
        $relevant = [];
        foreach (array_intersect($relevantKeys, array_keys($composer)) as $key) {
            $relevant[$key] = $composer[$key];
        }
        if (isset($composer['config']['platform'])) {
            $relevant['config']['platform'] = $composer['config']['platform'];
        }
        ksort($relevant);
        $encoded = json_encode($relevant);
        return is_string($encoded) ? md5($encoded) : null;
    }

    private function join(string $base, string $rel): string
    {
        $base = rtrim($base, '/');
        if ($rel === '' || $rel === '.') return $base;            // <-- chỉ trả về base dir
        if ($rel[0] === '/' || preg_match('#^[A-Za-z]:[\\\\/]#', $rel)) return $rel; // hỗ trợ Windows path
        return $base . '/' . ltrim($rel, '/');
    }

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

    private function relPath(string $abs): string
    {
        $root = rtrim($this->ctx->abs('.'), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (str_starts_with($abs, $root)) {
            return substr($abs, strlen($root));
        }
        return $abs;
    }

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
}
