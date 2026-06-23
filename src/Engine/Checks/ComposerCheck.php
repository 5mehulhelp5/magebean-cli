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

    public function auditApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $installed = $this->readLockPackages($lockFile);
        if (!$installed || !is_array($installed)) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $installedVers = [];
        foreach ($installed as $name => $info) {
            $version = $info['version'] ?? null;
            if (is_string($version) && $version !== '') {
                $installedVers[(string)$name] = ltrim($version, 'vV');
            }
        }
        $packageScope = (string)($args['package_scope'] ?? 'all');
        if ($packageScope === 'adobe_core') {
            $installedVers = array_filter(
                $installedVers,
                fn(string $version, string $name): bool => $this->isAdobeCorePackage($name),
                ARRAY_FILTER_USE_BOTH
            );
        }
        if (is_array($args['package_names'] ?? null)) {
            $allowedPackages = array_fill_keys(array_map(
                static fn(mixed $name): string => strtolower((string)$name),
                $args['package_names']
            ), true);
            $installedVers = array_filter(
                $installedVers,
                static fn(string $version, string $name): bool => isset($allowedPackages[strtolower($name)]),
                ARRAY_FILTER_USE_BOTH
            );
        }
        if ($installedVers === []) {
            $message = $packageScope === 'adobe_core'
                ? 'No Adobe/Magento core packages found in composer.lock'
                : 'No packages in composer.lock (nothing to audit)';
            return [true, $message, ['package_scope' => $packageScope, 'packages' => 0]];
        }

        $endpoint = trim((string)($args['endpoint'] ?? $this->ctx->get(
            'osv_api_url',
            'https://api.magebean.com/v1/osv/advisories'
        )));
        if (!$this->isAllowedAdvisoryEndpoint($endpoint)) {
            return [null, '[UNKNOWN] Invalid OSV API endpoint; HTTPS is required', ['endpoint' => $endpoint]];
        }

        $timeoutMs = max(1000, (int)($args['timeout_ms'] ?? 10000));
        $batchSize = max(1, min(1000, (int)($args['batch_size'] ?? 500)));
        $allowPrivateHttpFallback = !empty($args['allow_private_http_fallback']);
        $token = trim((string)($args['token'] ?? $this->ctx->get(
            'osv_api_token',
            getenv('MAGEBEAN_OSV_API_TOKEN') ?: ''
        )));

        $packages = [];
        foreach ($installedVers as $name => $version) {
            $packages[] = ['name' => $name, 'version' => $version];
        }

        $advisories = [];
        $responses = [];
        foreach (array_chunk($packages, $batchSize) as $batchIndex => $batch) {
            $payload = [
                'schema_version' => 'magebean-osv-request-v1',
                'ecosystem' => 'Packagist',
                'packages' => $batch,
                'client' => [
                    'name' => 'magebean-cli',
                    'version' => (string)($args['client_version'] ?? 'dev'),
                ],
            ];

            [$transportOk, $transportMessage, $response] = $this->postJson(
                $endpoint,
                $payload,
                $timeoutMs,
                $token
            );
            $requestEndpoint = $endpoint;
            if (
                !$transportOk
                && $allowPrivateHttpFallback
                && $token === ''
                && $this->canFallbackToPrivateHttp($endpoint)
            ) {
                $requestEndpoint = 'http://' . substr($endpoint, strlen('https://'));
                [$transportOk, $transportMessage, $response] = $this->postJson(
                    $requestEndpoint,
                    $payload,
                    $timeoutMs,
                    $token
                );
            }
            if (!$transportOk) {
                return [
                    null,
                    '[UNKNOWN] OSV API request failed: ' . $transportMessage,
                    [
                        'endpoint' => $endpoint,
                        'request_endpoint' => $requestEndpoint,
                        'batch' => $batchIndex + 1,
                    ],
                ];
            }

            $status = (int)($response['status'] ?? 0);
            $body = (string)($response['body'] ?? '');
            $decoded = json_decode($body, true);
            if ($status !== 200) {
                $apiMessage = is_array($decoded)
                    ? (string)($decoded['error']['message'] ?? $decoded['message'] ?? '')
                    : '';
                $suffix = $apiMessage !== '' ? ': ' . $apiMessage : '';
                return [
                    null,
                    '[UNKNOWN] OSV API returned HTTP ' . $status . $suffix,
                    [
                        'endpoint' => $endpoint,
                        'request_endpoint' => $requestEndpoint,
                        'status' => $status,
                        'batch' => $batchIndex + 1,
                    ],
                ];
            }

            if (!is_array($decoded)) {
                return [
                    null,
                    '[UNKNOWN] OSV API returned invalid JSON',
                    ['endpoint' => $endpoint, 'batch' => $batchIndex + 1],
                ];
            }
            if (($decoded['schema_version'] ?? null) !== 'magebean-osv-response-v1') {
                return [
                    null,
                    '[UNKNOWN] Unsupported OSV API response schema',
                    [
                        'endpoint' => $endpoint,
                        'schema_version' => $decoded['schema_version'],
                        'batch' => $batchIndex + 1,
                    ],
                ];
            }
            if (!array_key_exists('advisories', $decoded) || !is_array($decoded['advisories'])) {
                return [
                    null,
                    '[UNKNOWN] OSV API response is missing advisories array',
                    ['endpoint' => $endpoint, 'batch' => $batchIndex + 1],
                ];
            }

            foreach ($decoded['advisories'] as $advisory) {
                if (!is_array($advisory)) {
                    continue;
                }
                $key = (string)($advisory['id'] ?? hash('sha256', json_encode($advisory)));
                if (!isset($advisories[$key])) {
                    $advisories[$key] = $advisory;
                    continue;
                }

                $existingAffected = is_array($advisories[$key]['affected'] ?? null)
                    ? $advisories[$key]['affected']
                    : [];
                $newAffected = is_array($advisory['affected'] ?? null)
                    ? $advisory['affected']
                    : [];
                $advisories[$key]['affected'] = array_merge($existingAffected, $newAffected);
            }
            $responses[] = [
                'batch' => $batchIndex + 1,
                'request_endpoint' => $requestEndpoint,
                'packages' => count($batch),
                'advisories' => count($decoded['advisories']),
                'dataset_revision' => $decoded['meta']['dataset_revision'] ?? null,
            ];
        }

        $sourceEvidence = [
            'source' => 'magebean_osv_api',
            'package_scope' => $packageScope,
            'endpoint' => $endpoint,
            'packages' => count($installedVers),
            'responses' => $responses,
        ];

        if ($advisories === []) {
            return [
                true,
                'No vulnerable packages according to Magebean OSV API (' . count($installedVers) . ' pkgs)',
                $sourceEvidence,
            ];
        }

        return $this->evaluateOsvAdvisories(
            array_values($advisories),
            $installedVers,
            $sourceEvidence
        );
    }

    public function coreAdvisoriesApi(array $args): array
    {
        $args['package_scope'] = 'adobe_core';
        return $this->auditApi($args);
    }

    public function fixVersionApi(array $args): array
    {
        $result = $this->auditApi($args);
        $status = $result[0] ?? null;
        if ($status !== false) {
            return $result;
        }

        $evidence = is_array($result[2] ?? null) ? $result[2] : [];
        $findings = is_array($evidence['findings'] ?? null) ? $evidence['findings'] : [];
        if ($findings === []) {
            return [
                null,
                '[UNKNOWN] Vulnerable packages were reported without usable fix evidence',
                $evidence,
            ];
        }

        $messages = [];
        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }
            $package = (string)($finding['package'] ?? 'unknown-package');
            $version = (string)($finding['version'] ?? 'unknown-version');
            $advisory = (string)($finding['advisory'] ?? 'unknown-advisory');
            $fixed = (string)($finding['fixed'] ?? '');
            $message = $package . '@' . $version . ' -> ' . $advisory;
            $message .= $fixed !== ''
                ? ', upgrade >= ' . $fixed
                : ', no fixed version published';
            $messages[] = $message;
        }

        if ($messages === []) {
            return [
                null,
                '[UNKNOWN] Vulnerable packages were reported without usable fix evidence',
                $evidence,
            ];
        }

        $visible = array_slice($messages, 0, 20);
        $message = 'Vulnerable packages require updates: ' . implode('; ', $visible);
        if (count($messages) > count($visible)) {
            $message .= '; +' . (count($messages) - count($visible)) . ' more';
        }

        return [false, $message, $evidence];
    }

    private function isAdobeCorePackage(string $package): bool
    {
        $package = strtolower($package);

        if (str_starts_with($package, 'adobe-commerce/')) {
            return true;
        }

        if (!str_starts_with($package, 'magento/')) {
            return false;
        }

        $name = substr($package, strlen('magento/'));
        if (str_starts_with($name, 'module-')) {
            return true;
        }

        return in_array($name, [
            'framework',
            'magento2-base',
            'product-community-edition',
            'product-enterprise-edition',
            'security-package',
        ], true);
    }

    public function auditOffline(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, "[UNKNOWN] composer.lock not found"];
        }

        $installed = $this->readLockPackages($lockFile);
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
            return [true, "No packages in composer.lock (nothing to audit)"];
        }

        $meta = $this->ctx->get('meta', []);
        $pathCandidates = [];
        foreach (['cve_data', 'cve_db', 'osv_db', 'osv'] as $key) {
            if (is_string($args[$key] ?? null) && $args[$key] !== '') {
                $pathCandidates[] = (string)$args[$key];
            }
        }
        if (is_string($this->ctx->cveData ?? null) && $this->ctx->cveData !== '') {
            $pathCandidates[] = $this->ctx->cveData;
        }
        if (is_array($meta)) {
            foreach (['osv_db', 'osv', 'cve_data'] as $key) {
                if (is_string($meta[$key] ?? null) && $meta[$key] !== '') {
                    $pathCandidates[] = (string)$meta[$key];
                }
            }
        }

        $datasetPath = null;
        $tried = [];
        foreach (array_values(array_unique($pathCandidates)) as $candidate) {
            $path = $this->ctx->abs((string)$candidate);
            $tried[] = $path;
            if (is_file($path) || is_dir($path)) {
                $datasetPath = $path;
                break;
            }
        }

        if ($datasetPath === null) {
            $bundle = $this->findCveBundleCandidate($args['cve_data'] ?? ($this->ctx->cveData ?: null));
            if (($bundle['status'] ?? '') === 'ok') {
                $datasetPath = (string)$bundle['path'];
                $tried[] = $datasetPath;
            }
        }

        if ($datasetPath === null) {
            return [null, "[UNKNOWN] CVE dataset not found (supply --cve-data bundle or osv-db.json)", ['tried' => $tried]];
        }

        $auditor = new \Magebean\Engine\Cve\CveAuditor($this->ctx);
        $vulns = $this->loadVulnsViaAuditor($auditor, $datasetPath);
        if ($vulns === []) {
            return [null, "[UNKNOWN] No advisories parsed from CVE dataset", ['dataset' => $datasetPath, 'packages' => count($installedVers)]];
        }

        return $this->evaluateOsvAdvisories(
            $vulns,
            $installedVers,
            ['source' => 'offline_dataset', 'dataset' => $datasetPath]
        );
    }

    private function evaluateOsvAdvisories(array $vulns, array $installedVers, array $sourceEvidence): array
    {
        $auditor = new \Magebean\Engine\Cve\CveAuditor($this->ctx);
        $sus = [];
        $unassessed = [];
        $usableAdvisories = 0;

        foreach ($vulns as $vuln) {
            if (!is_array($vuln) || empty($vuln['affected']) || !is_array($vuln['affected'])) {
                continue;
            }
            $usableAdvisories++;

            [$sevLabel, $cvssScore] = $this->extractSeveritySafe($vuln);
            $id = (string)($vuln['id'] ?? ($vuln['aliases'][0] ?? 'CVE'));
            $knownExploited = $this->isKnownExploitedAdvisory($vuln);

            foreach ($vuln['affected'] as $aff) {
                $pkg = $aff['package']['name'] ?? null;
                $eco = strtolower((string)($aff['package']['ecosystem'] ?? ''));
                if (!$pkg || !isset($installedVers[$pkg])) {
                    continue;
                }
                if ($eco !== 'packagist' && $eco !== 'composer') {
                    continue;
                }

                $current = $installedVers[$pkg];
                $hit = false;
                $fixed = null;
                $hasVersionEvidence = false;

                if (!empty($aff['versions']) && is_array($aff['versions'])) {
                    $hasVersionEvidence = true;
                    foreach ($aff['versions'] as $version) {
                        $version = ltrim((string)$version, 'vV');
                        if ($version !== '' && version_compare($current, $version, '==')) {
                            $hit = true;
                            break;
                        }
                    }
                }

                if (!empty($aff['ranges']) && is_array($aff['ranges'])) {
                    foreach ($aff['ranges'] as $range) {
                        $events = is_array($range['events'] ?? null) ? $range['events'] : [];
                        if ($events !== []) {
                            $hasVersionEvidence = true;
                        }
                        $fixedCandidate = null;
                        $intervals = $this->eventsToIntervalsSafe($auditor, $events, $fixedCandidate);
                        foreach ($intervals as [$start, $end]) {
                            if ($this->inRangeSafe($auditor, $current, $start, $end)) {
                                $hit = true;
                                if ($end !== null) {
                                    $fixed = $this->minVersionLocal($fixed, $end);
                                }
                            }
                        }
                    }
                }

                if (!$hasVersionEvidence) {
                    $unassessedKey = strtolower((string)$pkg) . '@' . $current . '|' . $id;
                    $unassessed[$unassessedKey] = [
                        'package' => (string)$pkg,
                        'version' => $current,
                        'advisory' => $id,
                        'reason' => 'missing_versions_or_ranges',
                    ];
                    continue;
                }

                if (!$hit) {
                    continue;
                }

                $findingKey = strtolower((string)$pkg) . '@' . $current . '|' . $id;
                $sus[$findingKey] = [
                    'package' => (string)$pkg,
                    'version' => $current,
                    'advisory' => $id,
                    'published' => is_string($vuln['published'] ?? null)
                        ? $vuln['published']
                        : null,
                    'severity' => $sevLabel,
                    'cvss' => $cvssScore,
                    'fixed' => $fixed,
                    'known_exploited' => $knownExploited,
                ];
            }
        }

        $evidence = $sourceEvidence + [
            'advisories' => count($vulns),
            'usable_advisories' => $usableAdvisories,
            'unassessed_affected_packages' => array_values($unassessed),
        ];
        if ($vulns !== [] && $usableAdvisories === 0) {
            return [null, '[UNKNOWN] No usable OSV advisories found in response', $evidence];
        }

        $sus = array_values($sus);
        if ($sus !== []) {
            $msg = "Vulnerable packages:\n    - " . implode("\n    - ", array_map(
                static function (array $item): string {
                    $message = $item['package'] . '@' . $item['version']
                        . ' -> ' . $item['advisory']
                        . ' (' . $item['severity'] . ')';
                    if (is_string($item['fixed'] ?? null) && $item['fixed'] !== '') {
                        $message .= ', fix >= ' . $item['fixed'];
                    }
                    return $message;
                },
                $sus
            ));
            if ($unassessed !== []) {
                $msg .= "\n    Version evidence unavailable for "
                    . count($unassessed) . ' additional affected package/advisory pair(s)';
            }
            return [false, $msg, $evidence + ['findings' => $sus]];
        }

        if ($unassessed !== []) {
            $details = array_map(
                static fn(array $item): string => $item['package'] . '@' . $item['version']
                    . ' -> ' . $item['advisory'] . ' (' . $item['reason'] . ')',
                array_values($unassessed)
            );
            return [
                null,
                "[UNKNOWN] Installed packages have advisories without version evidence:\n    - "
                    . implode("\n    - ", $details),
                $evidence,
            ];
        }

        return [
            true,
            'No vulnerable packages according to OSV advisories (' . count($installedVers) . ' pkgs, ' . count($vulns) . ' advisories)',
            $evidence,
        ];
    }

    public function kevAdvisoriesApi(array $args): array
    {
        $result = $this->auditApi($args);
        $status = $result[0] ?? null;
        if ($status === null || $status === true) {
            return $result;
        }

        $evidence = is_array($result[2] ?? null) ? $result[2] : [];
        $findings = array_values(array_filter(
            is_array($evidence['findings'] ?? null) ? $evidence['findings'] : [],
            static fn(mixed $finding): bool => is_array($finding)
                && !empty($finding['known_exploited'])
        ));

        $evidence['kev_findings'] = $findings;
        $evidence['kev_findings_count'] = count($findings);
        if ($findings === []) {
            return [
                true,
                'No installed package versions match CISA Known Exploited Vulnerabilities',
                $evidence,
            ];
        }

        $visible = array_slice($findings, 0, 20);
        $message = 'CISA KEV package matches: ' . implode('; ', array_map(
            static function (array $finding): string {
                $text = (string)($finding['package'] ?? 'unknown-package')
                    . '@' . (string)($finding['version'] ?? 'unknown-version')
                    . ' -> ' . (string)($finding['advisory'] ?? 'unknown-advisory');
                if (is_string($finding['fixed'] ?? null) && $finding['fixed'] !== '') {
                    $text .= ', fix >= ' . $finding['fixed'];
                } else {
                    $text .= ', no fixed version published';
                }
                return $text;
            },
            $visible
        ));
        if (count($findings) > count($visible)) {
            $message .= '; +' . (count($findings) - count($visible)) . ' more';
        }

        return [false, $message, $evidence];
    }

    public function advisoryLatencyApi(array $args): array
    {
        $audit = $this->auditApi($args);
        $status = $audit[0] ?? null;
        $evidence = is_array($audit[2] ?? null) ? $audit[2] : [];
        if ($status === null) {
            return $audit;
        }
        if ($status === true) {
            return [
                true,
                'No unresolved advisories affect installed package versions',
                $evidence + [
                    'sla_days' => max(1, (int)($args['latency_days'] ?? 30)),
                    'open_advisories' => [],
                ],
            ];
        }

        $slaDays = max(1, (int)($args['latency_days'] ?? 30));
        $now = time();
        $open = [];
        $overdue = [];
        $missingPublished = [];
        foreach ((array)($evidence['findings'] ?? []) as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $published = is_string($finding['published'] ?? null)
                ? trim($finding['published'])
                : '';
            $publishedAt = $published !== '' ? strtotime($published) : false;
            if ($publishedAt === false) {
                $finding['open_days'] = null;
                $finding['sla_days'] = $slaDays;
                $missingPublished[] = $finding;
                continue;
            }

            $finding['open_days'] = max(0, (int)floor(($now - $publishedAt) / 86400));
            $finding['sla_days'] = $slaDays;
            $finding['overdue'] = $finding['open_days'] > $slaDays;
            $open[] = $finding;
            if ($finding['overdue']) {
                $overdue[] = $finding;
            }
        }

        $latencyEvidence = $evidence + [
            'sla_days' => $slaDays,
            'open_advisories' => $open,
            'overdue_advisories' => $overdue,
            'missing_published_date' => $missingPublished,
        ];

        if ($overdue !== []) {
            $visible = array_slice($overdue, 0, 20);
            $details = array_map(static function (array $finding): string {
                $text = (string)($finding['package'] ?? 'unknown-package')
                    . '@' . (string)($finding['version'] ?? 'unknown-version')
                    . ' -> ' . (string)($finding['advisory'] ?? 'unknown-advisory')
                    . ' open ' . (string)($finding['open_days'] ?? '?') . ' days';
                if (is_string($finding['fixed'] ?? null) && $finding['fixed'] !== '') {
                    $text .= ', update to >= ' . $finding['fixed'];
                }
                return $text;
            }, $visible);
            $message = 'Unresolved advisories exceed the ' . $slaDays . '-day SLA: '
                . implode('; ', $details);
            if (count($overdue) > count($visible)) {
                $message .= '; +' . (count($overdue) - count($visible)) . ' more';
            }
            if ($missingPublished !== []) {
                $message .= '. Published date unavailable for '
                    . count($missingPublished) . ' additional advisory match(es)';
            }
            return [false, $message, $latencyEvidence];
        }

        if ($missingPublished !== []) {
            $visible = array_slice($missingPublished, 0, 20);
            $details = array_map(
                static fn(array $finding): string => (string)($finding['package'] ?? 'unknown-package')
                    . '@' . (string)($finding['version'] ?? 'unknown-version')
                    . ' -> ' . (string)($finding['advisory'] ?? 'unknown-advisory'),
                $visible
            );
            $message = '[UNKNOWN] Published date unavailable for unresolved advisories: '
                . implode('; ', $details);
            if (count($missingPublished) > count($visible)) {
                $message .= '; +' . (count($missingPublished) - count($visible)) . ' more';
            }
            return [null, $message, $latencyEvidence];
        }

        return [
            true,
            count($open) . ' unresolved advisory match(es) remain within the '
                . $slaDays . '-day remediation SLA',
            $latencyEvidence,
        ];
    }

    public function transitiveAuditApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $composerFile = $this->ctx->abs($args['composer_file'] ?? 'composer.json');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }
        if (!is_file($composerFile)) {
            return [null, '[UNKNOWN] composer.json not found; cannot distinguish direct and transitive dependencies'];
        }

        $lock = $this->loadJsonSafe($lockFile);
        $composer = $this->loadJsonSafe($composerFile);
        if (!is_array($lock)) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }
        if (!is_array($composer)) {
            return [null, '[UNKNOWN] Unable to parse composer.json'];
        }

        $direct = [];
        foreach (['require', 'require-dev'] as $section) {
            foreach ((array)($composer[$section] ?? []) as $name => $_constraint) {
                $name = strtolower((string)$name);
                if (str_contains($name, '/')) {
                    $direct[$name] = true;
                }
            }
        }

        $installed = [];
        $requiredBy = [];
        foreach (['packages', 'packages-dev'] as $section) {
            foreach ((array)($lock[$section] ?? []) as $package) {
                if (!is_array($package) || !is_string($package['name'] ?? null)) {
                    continue;
                }
                $name = strtolower($package['name']);
                $installed[$name] = true;
                foreach ((array)($package['require'] ?? []) as $dependency => $_constraint) {
                    $dependency = strtolower((string)$dependency);
                    if (!str_contains($dependency, '/')) {
                        continue;
                    }
                    $requiredBy[$dependency][] = $name;
                }
            }
        }

        $transitive = array_values(array_diff(array_keys($installed), array_keys($direct)));
        sort($transitive, SORT_STRING);
        if ($transitive === []) {
            return [
                true,
                'No transitive Composer dependencies found',
                [
                    'direct_packages' => array_keys($direct),
                    'transitive_packages' => [],
                ],
            ];
        }

        $args['package_names'] = $transitive;
        $args['package_scope'] = 'transitive';
        $result = $this->auditApi($args);
        $evidence = is_array($result[2] ?? null) ? $result[2] : [];
        $evidence['direct_packages'] = array_keys($direct);
        $evidence['transitive_packages'] = $transitive;

        if (is_array($evidence['findings'] ?? null)) {
            foreach ($evidence['findings'] as &$finding) {
                if (!is_array($finding)) {
                    continue;
                }
                $package = strtolower((string)($finding['package'] ?? ''));
                $parents = array_values(array_unique($requiredBy[$package] ?? []));
                sort($parents, SORT_STRING);
                $finding['required_by'] = $parents;
            }
            unset($finding);

            $visible = array_slice($evidence['findings'], 0, 20);
            $message = 'Vulnerable transitive dependencies: ' . implode('; ', array_map(
                static function (array $finding): string {
                    $text = (string)($finding['package'] ?? 'unknown-package')
                        . '@' . (string)($finding['version'] ?? 'unknown-version')
                        . ' -> ' . (string)($finding['advisory'] ?? 'unknown-advisory');
                    $parents = (array)($finding['required_by'] ?? []);
                    if ($parents !== []) {
                        $text .= ', required by ' . implode(', ', $parents);
                    }
                    if (is_string($finding['fixed'] ?? null) && $finding['fixed'] !== '') {
                        $text .= ', fix >= ' . $finding['fixed'];
                    }
                    return $text;
                },
                $visible
            ));
            if (count($evidence['findings']) > count($visible)) {
                $message .= '; +' . (count($evidence['findings']) - count($visible)) . ' more';
            }
            return [false, $message, $evidence];
        }

        return [$result[0] ?? null, (string)($result[1] ?? ''), $evidence];
    }

    public function constraintsConflictApi(array $args): array
    {
        $composerFile = $this->ctx->abs($args['json_file'] ?? 'composer.json');
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($composerFile)) {
            return [null, '[UNKNOWN] composer.json not found'];
        }
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $composer = $this->loadJsonSafe($composerFile);
        $lock = $this->loadJsonSafe($lockFile);
        if (!is_array($composer)) {
            return [null, '[UNKNOWN] Unable to parse composer.json'];
        }
        if (!is_array($lock)) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $audit = $this->auditApi($args);
        if (($audit[0] ?? null) !== false) {
            return $audit;
        }

        $evidence = is_array($audit[2] ?? null) ? $audit[2] : [];
        $findings = is_array($evidence['findings'] ?? null) ? $evidence['findings'] : [];
        $constraintsByPackage = [];

        foreach (['require', 'require-dev'] as $section) {
            foreach ((array)($composer[$section] ?? []) as $package => $constraint) {
                $package = strtolower((string)$package);
                if (!str_contains($package, '/') || !is_string($constraint)) {
                    continue;
                }
                $constraintsByPackage[$package][] = [
                    'source' => 'root:' . $section,
                    'constraint' => $constraint,
                ];
            }
        }

        foreach (['packages', 'packages-dev'] as $section) {
            foreach ((array)($lock[$section] ?? []) as $parent) {
                if (!is_array($parent) || !is_string($parent['name'] ?? null)) {
                    continue;
                }
                $parentName = strtolower($parent['name']);
                foreach ((array)($parent['require'] ?? []) as $package => $constraint) {
                    $package = strtolower((string)$package);
                    if (!str_contains($package, '/') || !is_string($constraint)) {
                        continue;
                    }
                    $constraintsByPackage[$package][] = [
                        'source' => $parentName,
                        'constraint' => $constraint,
                    ];
                }
            }
        }

        $parser = new \Composer\Semver\VersionParser();
        $blocked = [];
        $allowed = [];
        $notApplicable = [];
        $errors = [];

        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }
            $package = strtolower((string)($finding['package'] ?? ''));
            $fixed = ltrim((string)($finding['fixed'] ?? ''), 'vV');
            if ($package === '' || $fixed === '') {
                $notApplicable[] = $finding + [
                    'reason' => 'no fixed version published; no available security update can be blocked',
                ];
                continue;
            }

            $requirements = $constraintsByPackage[$package] ?? [];
            if ($requirements === []) {
                $notApplicable[] = $finding + [
                    'reason' => 'no requiring constraint found; no blocking constraint identified',
                    'required_safe_range' => '>=' . $fixed,
                ];
                continue;
            }

            try {
                $parsed = [];
                foreach ($requirements as $requirement) {
                    $parsed[] = $parser->parseConstraints($requirement['constraint']);
                }
                $combined = count($parsed) === 1
                    ? $parsed[0]
                    : new \Composer\Semver\Constraint\MultiConstraint($parsed, true);
                $safeRange = $parser->parseConstraints('>=' . $fixed);
                $allowsSafeVersion = \Composer\Semver\Intervals::haveIntersections($combined, $safeRange);
            } catch (\Throwable $exception) {
                $errors[] = $finding + [
                    'reason' => 'unable to parse constraint: ' . $exception->getMessage(),
                    'requirements' => $requirements,
                ];
                continue;
            }

            $item = $finding + [
                'requirements' => $requirements,
                'required_safe_range' => '>=' . $fixed,
            ];
            if ($allowsSafeVersion) {
                $allowed[] = $item;
            } else {
                $blocked[] = $item;
            }
        }

        $evidence['blocked'] = $blocked;
        $evidence['allowed'] = $allowed;
        $evidence['not_applicable'] = $notApplicable;
        $evidence['errors'] = $errors;

        if ($blocked !== []) {
            $visible = array_slice($blocked, 0, 20);
            $message = 'Composer constraints block security updates: ' . implode('; ', array_map(
                static function (array $item): string {
                    $requirements = array_map(
                        static fn(array $requirement): string => $requirement['source']
                            . ' requires ' . $requirement['constraint'],
                        (array)($item['requirements'] ?? [])
                    );
                    return (string)($item['package'] ?? 'unknown-package')
                        . '@' . (string)($item['version'] ?? 'unknown-version')
                        . ' needs ' . (string)($item['required_safe_range'] ?? '')
                        . ' but ' . implode(', ', $requirements);
                },
                $visible
            ));
            if (count($blocked) > count($visible)) {
                $message .= '; +' . (count($blocked) - count($visible)) . ' more';
            }
            return [false, $message, $evidence];
        }

        if ($errors !== []) {
            $visible = array_slice($errors, 0, 10);
            return [
                null,
                '[UNKNOWN] Unable to evaluate Composer constraints: ' . implode('; ', array_map(
                    static fn(array $item): string => (string)($item['package'] ?? 'unknown-package')
                        . '@' . (string)($item['version'] ?? 'unknown-version')
                        . ' (' . (string)($item['reason'] ?? 'unknown error') . ')',
                    $visible
                )),
                $evidence,
            ];
        }

        $suffix = $notApplicable !== []
            ? '; ' . count($notApplicable) . ' finding(s) had no applicable blocking constraint'
            : '';
        return [
            true,
            'Composer constraints allow the required security update ranges' . $suffix,
            $evidence,
        ];
    }

    private function isKnownExploitedAdvisory(array $advisory): bool
    {
        if (($advisory['database_specific']['known_exploited'] ?? false) === true) {
            return true;
        }
        if (!empty($advisory['source']['kev'])) {
            return true;
        }

        foreach ((array)($advisory['references'] ?? []) as $reference) {
            $url = strtolower((string)($reference['url'] ?? ''));
            if ($url !== ''
                && str_contains($url, 'cisa.gov')
                && (str_contains($url, 'known-exploited') || str_contains($url, '/kev'))
            ) {
                return true;
            }
        }
        return false;
    }

    private function isAllowedAdvisoryEndpoint(string $endpoint): bool
    {
        $parts = parse_url($endpoint);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }

        $scheme = strtolower((string)$parts['scheme']);
        if ($scheme === 'https') {
            return true;
        }

        $host = strtolower(trim((string)$parts['host'], '[]'));
        return $scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1'], true);
    }

    private function canFallbackToPrivateHttp(string $endpoint): bool
    {
        $parts = parse_url($endpoint);
        if (
            !is_array($parts)
            || strtolower((string)($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
        ) {
            return false;
        }

        $host = strtolower(trim((string)$parts['host'], '[]'));
        if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            return true;
        }

        $addresses = gethostbynamel($host);
        if (!is_array($addresses) || $addresses === []) {
            return false;
        }

        foreach ($addresses as $address) {
            if ($this->isPrivateOrLoopbackIpv4($address)) {
                return true;
            }
        }

        return false;
    }

    private function isPrivateOrLoopbackIpv4(string $address): bool
    {
        $ip = ip2long($address);
        if ($ip === false) {
            return false;
        }
        $ip = (int)sprintf('%u', $ip);

        foreach ([
            ['10.0.0.0', '10.255.255.255'],
            ['127.0.0.0', '127.255.255.255'],
            ['169.254.0.0', '169.254.255.255'],
            ['172.16.0.0', '172.31.255.255'],
            ['192.168.0.0', '192.168.255.255'],
        ] as [$start, $end]) {
            $rangeStart = (int)sprintf('%u', ip2long($start));
            $rangeEnd = (int)sprintf('%u', ip2long($end));
            if ($ip >= $rangeStart && $ip <= $rangeEnd) {
                return true;
            }
        }

        return false;
    }

    private function postJson(string $url, array $payload, int $timeoutMs, string $token = ''): array
    {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            return [false, 'Unable to encode request JSON', []];
        }

        $headers = [
            'Accept: application/json',
            'Content-Type: application/json',
            'User-Agent: Magebean-CLI/1.0',
        ];
        if ($token !== '') {
            $headers[] = 'Authorization: Bearer ' . $token;
        }

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $json,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT_MS => $timeoutMs,
                CURLOPT_CONNECTTIMEOUT_MS => min($timeoutMs, 5000),
                CURLOPT_ENCODING => '',
            ]);
            $body = curl_exec($ch);
            if ($body === false) {
                $message = curl_error($ch);
                curl_close($ch);
                return [false, $message !== '' ? $message : 'cURL request failed', []];
            }
            $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);
            return [true, '', ['status' => $status, 'body' => (string)$body]];
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headers),
                'content' => $json,
                'ignore_errors' => true,
                'timeout' => max(1, (int)ceil($timeoutMs / 1000)),
            ],
        ]);
        $body = @file_get_contents($url, false, $context);
        $rawHeaders = is_array($http_response_header ?? null) ? $http_response_header : [];
        $status = 0;
        foreach ($rawHeaders as $header) {
            if (preg_match('~^HTTP/\S+\s+(?P<status>\d{3})~i', (string)$header, $match) === 1) {
                $status = (int)$match['status'];
            }
        }
        if ($body === false) {
            return [false, 'HTTP stream request failed', ['status' => $status]];
        }

        return [true, '', ['status' => $status, 'body' => (string)$body]];
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
        // 0) Load composer.lock
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) {
            return [null, "[UNKNOWN] composer.lock not found"];
        }
        $installed = $this->readLockPackages($lock);
        if (!$installed || !is_array($installed)) {
            return [null, "[UNKNOWN] Unable to parse composer.lock"];
        }
        $installedVers = [];
        foreach ($installed as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') $installedVers[$name] = ltrim($v, 'vV');
        }
        if (!$installedVers) {
            return [true, "No packages in composer.lock (nothing to check)"];
        }

        // 1) Resolve yanked metadata path (zip/dir/file-inside-dir)
        $candidates = [];
        if (!empty($args['yanked_meta'])) $candidates[] = (string)$args['yanked_meta'];
        $candidates[] = 'packagist-yanked.json';
        $candidates[] = 'rules/packagist-yanked.json';      // legacy rules/ fallback

        $metaPath = null;
        $openedZip = null;
        $tried = [];

        $tryResolve = function (string $hint) use (&$openedZip, &$metaPath, &$tried) {
            $tried[] = $hint;

            // absolute file on disk
            if (is_file($hint)) {
                $metaPath = $hint;
                return true;
            }

            // try from ctx->cveData as zip/dir or file-inside-dir
            $cve = $this->ctx->cveData ?? '';
            if (is_string($cve) && $cve !== '') {
                // zip
                if (is_file($cve) && preg_match('/\.zip$/i', $cve)) {
                    $zip = new \ZipArchive();
                    if ($zip->open($cve) === true) {
                        $idx = $zip->locateName($hint, \ZipArchive::FL_NOCASE);
                        if ($idx !== false) {
                            $raw = $zip->getFromIndex($idx);
                            if (is_string($raw)) {
                                $tmp = tempnam(sys_get_temp_dir(), 'mb-yanked-');
                                @file_put_contents($tmp, $raw);
                                $openedZip = $zip;  // keep open until end
                                $metaPath = $tmp;
                                return true;
                            }
                        }
                        $zip->close();
                    }
                }
                // dir (or file inside dir → walk up)
                $dir = is_dir($cve) ? $cve : dirname($cve);
                $cur = $dir;
                for ($i = 0; $i < 5; $i++) {
                    $p = rtrim($cur, '/') . '/' . $hint;
                    if (is_file($p)) {
                        $metaPath = $p;
                        return true;
                    }
                    $parent = dirname($cur);
                    if ($parent === $cur) break;
                    $cur = $parent;
                }
            }

            // cwd fallback
            $p2 = getcwd() . '/' . $hint;
            if (is_file($p2)) {
                $metaPath = $p2;
                return true;
            }

            return false;
        };

        foreach ($candidates as $rel) {
            if ($tryResolve($rel)) break;
        }
        if (!$metaPath) {
            return [null, "[UNKNOWN] Yanked metadata not found; tried: " . implode(' | ', $tried)];
        }

        // 2) Load JSON (accept container form { "yanked": [...] })
        $raw = @file_get_contents($metaPath);
        if ($raw === false) {
            if ($openedZip instanceof \ZipArchive) @$openedZip->close();
            return [null, "[UNKNOWN] Failed to read yanked metadata at " . $metaPath];
        }
        $j = json_decode($raw, true);

        if (!is_array($j)) {
            if ($openedZip instanceof \ZipArchive) @$openedZip->close();
            return [null, "[UNKNOWN] Invalid yanked metadata JSON (not an array/object) at " . $metaPath];
        }

        // Support container shape: { "yanked": [...] }
        $payload = $j;
        if (array_key_exists('yanked', $j)) {
            // If the key exists but is not an array, treat as invalid
            if (!is_array($j['yanked'])) {
                if ($openedZip instanceof \ZipArchive) @$openedZip->close();
                return [null, "[UNKNOWN] Invalid yanked metadata JSON ('yanked' is not an array) at " . $metaPath];
            }
            // Empty yanked array => PASS (your requested behavior)
            if ($j['yanked'] === []) {
                if ($openedZip instanceof \ZipArchive) @$openedZip->close();
                return [true, "No yanked entries (empty list) (meta: {$metaPath})"];
            }
            $payload = $j['yanked'];
        }

        // 3) Normalize to map: name => set of yanked versions
        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };

        $yanked = []; // name => [ver => true]
        if ($isAssoc($payload)) {
            // Map form: { "vendor/pkg": ["1.2.3", ...], ... }
            foreach ($payload as $pkg => $vers) {
                if (!is_string($pkg) || !is_array($vers)) continue;
                foreach ($vers as $v) {
                    if (!is_string($v) || $v === '') continue;
                    $yanked[$pkg][ltrim($v, 'vV')] = true;
                }
            }
        } else {
            // List form: [ {"package":"vendor/pkg","versions":[...]}, ... ]
            foreach ($payload as $row) {
                if (!is_array($row)) continue;
                $pkg  = $row['package']  ?? null;
                $vers = $row['versions'] ?? null;
                if (!is_string($pkg) || !is_array($vers)) continue;
                foreach ($vers as $v) {
                    if (!is_string($v) || $v === '') continue;
                    $yanked[$pkg][ltrim($v, 'vV')] = true;
                }
            }
        }

        if ($openedZip instanceof \ZipArchive) {
            @$openedZip->close();
        }

        // Nếu vẫn không có entry sau khi normalize → coi như “không có yanked” → PASS
        if (!$yanked) {
            return [true, "No yanked entries (normalized empty) (meta: {$metaPath})"];
        }

        // 4) Match against installed
        $hits = [];
        foreach ($installedVers as $name => $ver) {
            if (isset($yanked[$name][$ver])) {
                $hits[] = "{$name} {$ver}";
            }
        }

        if ($hits) {
            return [false, "Yanked versions installed: " . implode('; ', $hits) . " (meta: {$metaPath})"];
        }
        return [true, "No yanked versions installed (meta: {$metaPath})"];
    }


    public function coreAdvisoriesOffline(array $args): array
    {
        // ===== 0) Load composer.lock (giống yankedOffline) =====
        $lockPath = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockPath)) {
            return [null, "[UNKNOWN] composer.lock not found at {$lockPath}"];
        }
        $installed = $this->readLockPackages($lockPath);
        if (!$installed || !is_array($installed)) {
            return [null, "[UNKNOWN] Unable to parse composer.lock"];
        }

        // Map: package(lc) => version (bỏ tiền tố v/V)
        $installedVers = [];
        foreach ($installed as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') {
                $installedVers[strtolower((string)$name)] = ltrim((string)$v, 'vV');
            }
        }
        if (!$installedVers) {
            return [true, "No packages in composer.lock (nothing to check); lock={$lockPath}"];
        }

        // ===== 1) Xác định root & vendor-dir =====
        // Root tiêu chuẩn: thư mục chứa lock
        $root = rtrim(str_replace('\\', '/', dirname($lockPath)), '/');
        $composerJsonPath = $root . '/composer.json';
        $vendorDirCfg = null;
        if (is_file($composerJsonPath)) {
            $composerJson = @json_decode((string)@file_get_contents($composerJsonPath), true) ?: [];
            $vendorDirCfg = $composerJson['config']['vendor-dir'] ?? null;
        }
        $vendor = $vendorDirCfg ? ($root . '/' . ltrim((string)$vendorDirCfg, '/')) : ($root . '/vendor');
        $vendor = rtrim($vendor, '/');
        if (!is_dir($vendor)) {
            // Theo yêu cầu: chỉ dựa lock + vendor ⇒ thiếu vendor thì UNKNOWN
            return [null, "[UNKNOWN] vendor directory not found at {$vendor}; lock={$lockPath}"];
        }

        // ===== 2) Định nghĩa nhóm core =====
        $patterns = $args['core_patterns'] ?? [
            '#^magento/#i',
            '#^adobe\-commerce/#i',
            '#^magento\/module\-#i',
        ];
        $isCore = static function (string $pkg, array $pats): bool {
            foreach ($pats as $re) {
                if (@preg_match($re, $pkg) && preg_match($re, $pkg)) return true;
            }
            return false;
        };

        // ===== 3) Helpers =====
        $readFile = static function (string $fp, int $max = 256 * 1024) {
            if (!is_file($fp) || !is_readable($fp)) return null;
            $size = filesize($fp);
            if ($size === false) return null;
            $limit = min($size, $max);
            $h = @fopen($fp, 'rb');
            if (!$h) return null;
            $data = @fread($h, $limit);
            @fclose($h);
            return is_string($data) ? $data : null;
        };
        $isSecurityLine = static function (string $line): bool {
            return (bool)preg_match('/\b(cve|security|vulnerab|advisory|hotfix|patch|sec\-)\b/i', $line);
        };
        $extractFixedFromLine = static function (string $line): ?string {
            $line = strtolower($line);
            // ưu tiên >= / ≥
            if (preg_match('/(?:>=|≥)\s*v?([0-9][0-9a-z\.\-\+]*?)\b/i', $line, $m)) {
                return ltrim($m[1], 'v');
            }
            // "fixed in / update to / patch to / use ..."
            if (preg_match('/(?:fixed\s+in|update\s+to|patch\s+to|use\s+)\s*v?([0-9][0-9a-z\.\-\+]*?)\b/i', $line, $m)) {
                return ltrim($m[1], 'v');
            }
            // ">=2.4.6" (không khoảng)
            if (preg_match('/(?:>=|≥)v?([0-9][0-9a-z\.\-\+]*?)\b/i', $line, $m)) {
                return ltrim($m[1], 'v');
            }
            // "2.4.7-p1 or later/and later/and above"
            if (preg_match('/\bv?([0-9][0-9a-z\.\-\+]*?)\b\s+(?:or\s+later|and\s+later|and\s+above)/i', $line, $m)) {
                return ltrim($m[1], 'v');
            }
            return null;
        };

        // ===== 4) Quét từng core package trong vendor =====
        $hits = [];
        $coreCount = 0;

        foreach ($installedVers as $pkgLc => $installedVer) {
            if (!$isCore($pkgLc, $patterns)) continue;
            $coreCount++;

            $pkgPath = $vendor . '/' . $pkgLc; // composer cài theo dạng lowercase "vendor/name"
            if (!is_dir($pkgPath)) {
                // không có thư mục vendor tương ứng → không có dữ liệu changelog ⇒ bỏ qua
                continue;
            }

            // Tập fixed-version candidates từ các file nhỏ thông dụng
            $cands = [
                'SECURITY.md',
                'SECURITY.txt',
                'SECURITY.adoc',
                'SECURITY',
                'CHANGELOG.md',
                'CHANGELOG.txt',
                'CHANGELOG',
                'RELEASE_NOTES.md',
                'RELEASE_NOTES.txt',
                'README.md',
            ];
            $bestFixed = null;

            foreach ($cands as $rel) {
                $fp = $pkgPath . '/' . $rel;
                $txt = $readFile($fp);
                if (!$txt) continue;

                foreach (preg_split('/\r?\n/', $txt) as $line) {
                    if ($line === '' || !$isSecurityLine($line)) continue;
                    $fx = $extractFixedFromLine($line);
                    if (!$fx) continue;

                    // chỉ xét fixed >= installed
                    if (version_compare($fx, $installedVer, '<')) continue;

                    // giữ fixed nhỏ nhất nhưng ≥ installed
                    if ($bestFixed === null || version_compare($fx, $bestFixed, '<')) {
                        $bestFixed = $fx;
                    }
                }
            }

            // Nếu tìm thấy fixed và installed < fixed ⇒ flag
            if ($bestFixed !== null && version_compare($installedVer, $bestFixed, '<')) {
                // tên hiển thị: ưu tiên tên gốc nếu còn
                $disp = $pkgLc;
                if (isset($installed[$pkgLc]['name']) && is_string($installed[$pkgLc]['name'])) {
                    $disp = $installed[$pkgLc]['name'];
                }
                $hits[] = sprintf('%s %s -> >= %s', $disp, $installedVer, $bestFixed);
            }
        }

        // ===== 5) Kết quả + evidence =====
        if ($hits) {
            return [false, 'Core advisories flagged: ' . implode('; ', $hits)
                . " — lock={$lockPath}; vendor={$vendor}; core_pkgs_scanned={$coreCount}"];
        }

        return [true, "No core advisories found (offline scan). lock={$lockPath}; vendor={$vendor}; core_pkgs_scanned={$coreCount}"];
    }


    public function fixVersion(array $args): array
    {
        // ---- composer.lock -> installed packages
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        $installed = $this->readLockPackages($lock);
        if (!$installed || !is_array($installed)) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $installedVers = [];
        foreach ($installed as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') $installedVers[$name] = ltrim($v, 'vV');
        }
        if (!$installedVers) return [true, "No packages in composer.lock (nothing to suggest)"];

        // ---- resolve bundle input (zip / dir / file-inside-dir)
        $candidates = [];
        if (!empty($args['cve_data'])) $candidates[] = (string)$args['cve_data'];
        if (!empty($this->ctx->cveData)) $candidates[] = (string)$this->ctx->cveData;
        $candidates = array_values(array_unique(array_filter($candidates, fn($p) => is_string($p) && $p !== '')));

        // Normalize to absolute without creating bogus concatenations
        $normalize = function (string $p): string {
            // If already absolute, keep; else relativize to CWD
            if (preg_match('#^/|^[A-Za-z]:[\\\\/]#', $p)) return $p;
            $abs = $this->ctx->abs($p);
            return is_string($abs) && $abs !== '' ? $abs : (getcwd() . '/' . $p);
        };

        // Find a usable "bundle root": either ['zip', zipPath] or ['dir', dirPath]
        $tried = [];
        $resolveBundleRoot = function (string $raw) use ($normalize, &$tried) {
            $p = $normalize($raw);
            $tried[] = $p;

            // case 1: ZIP file
            if (is_file($p) && preg_match('/\.zip$/i', $p)) return ['zip', $p];

            // case 2: Directory bundle root (contains INDEX/ or DATA/ etc.)
            $asDir = is_dir($p) ? $p : dirname($p); // if it's a file inside bundle, go up 1
            // climb up a few levels to find a dir that has INDEX or DATA
            $cur = $asDir;
            for ($i = 0; $i < 5; $i++) {
                if (is_dir($cur . '/INDEX') || is_dir($cur . '/DATA') || is_dir($cur . '/VULNS') || is_file($cur . '/INDEX/packages-index.json')) {
                    return ['dir', $cur];
                }
                $parent = dirname($cur);
                if ($parent === $cur) break;
                $cur = $parent;
            }

            // case 3: If input was a JSON inside DATA/, try up-two-levels explicitly
            if (preg_match('#/(DATA|VULNS|INDEX)/#', $p)) {
                $root = preg_replace('#/(DATA|VULNS|INDEX)/.*$#', '', $p);
                if (is_dir($root)) return ['dir', $root];
            }

            return null;
        };

        $root = null;
        foreach ($candidates as $cand) {
            $root = $resolveBundleRoot($cand);
            if ($root !== null) break;
        }
        if ($root === null) {
            $msgTried = $tried ? implode(' | ', $tried) : '(no candidates)';
            return [null, "[UNKNOWN] CVE bundle not found/openable; tried: " . $msgTried];
        }

        // ---- read packages-index.json from bundle (zip or dir)
        $pkg2vuln = null;
        if ($root[0] === 'zip') {
            $zip = new \ZipArchive();
            if ($zip->open($root[1]) !== true) {
                return [null, "[UNKNOWN] Unable to open CVE bundle zip: " . $root[1]];
            }
            $i = $zip->locateName('INDEX/packages-index.json', \ZipArchive::FL_NOCASE);
            if ($i === false) {
                $zip->close();
                return [true, "No vulnerable packages index found in bundle (INDEX/packages-index.json missing)"];
            }
            $raw = $zip->getFromIndex($i);
            $pkg2vuln = is_string($raw) ? json_decode($raw, true) : null;
            $zip->close();
        } else { // dir
            $idxPath = $root[1] . '/INDEX/packages-index.json';
            if (!is_file($idxPath)) {
                return [true, "No vulnerable packages index found in bundle dir (INDEX/packages-index.json missing at " . $idxPath . ")"];
            }
            $raw = @file_get_contents($idxPath);
            $pkg2vuln = $raw !== false ? json_decode($raw, true) : null;
        }

        if (!is_array($pkg2vuln) || !$pkg2vuln) {
            return [true, "No vulnerable packages index found in bundle (index empty at root " . $root[1] . ")"];
        }

        // ---- ensure composer CLI available (for available versions)
        @exec('composer --version 2>&1', $outV, $codeV);
        if ($codeV !== 0) {
            return [null, "[UNKNOWN] composer CLI not available for version discovery (install composer or add it to PATH)"];
        }

        $parseVersionsFromComposerShow = static function (string $text): array {
            $vers = [];
            foreach (preg_split('/\r?\n/', $text) as $line) {
                if (stripos($line, 'versions') === 0 || preg_match('/^\s*versions\s*:/i', $line)) {
                    [$l, $r] = array_pad(explode(':', $line, 2), 2, '');
                    $r = preg_replace('/^\*\s*/', '', trim($r));
                    foreach (explode(',', $r) as $tok) {
                        $tok = trim($tok);
                        if ($tok === '' || stripos($tok, 'dev') !== false) continue;
                        $vers[] = ltrim($tok, 'vV');
                    }
                    break;
                }
            }
            $vers = array_values(array_unique($vers));
            usort($vers, static fn($a, $b) => version_compare($a, $b)); // ascending (min >= current)
            return $vers;
        };
        $isStable = static fn(string $v) => !preg_match('/(?:alpha|beta|rc)\d*$/i', $v);

        $cwd = $args['path'] ?? getcwd();
        $suggest = [];
        $checked = 0;

        foreach ($installedVers as $pkg => $curVer) {
            if (!isset($pkg2vuln[$pkg])) continue; // only consider packages known in index
            $checked++;

            $cmd = sprintf('cd %s && composer show %s -a 2>&1', escapeshellarg($cwd), escapeshellarg($pkg));
            $out = [];
            $code = 0;
            @exec($cmd, $out, $code);
            if ($code !== 0) continue;

            $versions = $parseVersionsFromComposerShow(implode("\n", $out));
            if (!$versions) continue;

            $candidates = array_values(array_filter($versions, $isStable));
            if (!$candidates) $candidates = $versions;

            $target = null;
            foreach ($candidates as $v) {
                if (version_compare($v, $curVer, '>=')) {
                    $target = $v;
                    break;
                }
            }
            if ($target && version_compare($target, $curVer, '>')) {
                $suggest[$pkg] = [$curVer, $target];
            }
        }

        if (!$suggest) {
            $msg = $checked > 0
                ? "No upgrade suggestions found from composer (checked {$checked} packages; root " . $root[1] . ")"
                : "No vulnerable packages from bundle index match installed packages (root " . $root[1] . ")";
            return [true, $msg];
        }

        $parts = [];
        foreach ($suggest as $pkg => [$cur, $tgt]) $parts[] = "{$pkg} {$cur} -> >= {$tgt}";
        return [false, "Suggest fixed versions: " . implode('; ', $parts)];
    }

    public function riskSurfaceTag(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');

        $metaPath = $this->metaPath($args, 'tags', 'tags_meta', 'risk-surface.json')
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

        // 1) Read installed Magento extension packages.
        $lockJson = json_decode((string)@file_get_contents($lock), true);
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
                    [
                        'active_subjects' => array_keys($activeSubjects),
                        'packages' => $statusPackages,
                    ],
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
            $visible = array_slice(array_values($reportable), 0, 20);
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
            $message = 'Enabled high-risk modules require attention: ' . implode('; ', $details);
            if (count($reportable) > count($visible)) {
                $message .= '; +' . (count($reportable) - count($visible)) . ' more';
            }
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
        $content = @file_get_contents($registration);
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

    private function fetchPackageStatuses(array $args, array $packages): array
    {
        $endpoint = trim((string)($args['status_endpoint'] ?? $this->ctx->get(
            'package_status_api_url',
            'https://api.magebean.com/v1/packages/status'
        )));
        if (!$this->isAllowedAdvisoryEndpoint($endpoint)) {
            return [false, 'Invalid package status API endpoint; HTTPS is required', []];
        }

        $timeoutMs = max(1000, (int)($args['timeout_ms'] ?? 10000));
        $batchSize = max(1, min(1000, (int)($args['status_batch_size'] ?? $args['batch_size'] ?? 500)));
        $token = trim((string)($args['token'] ?? $this->ctx->get(
            'package_status_api_token',
            getenv('MAGEBEAN_PACKAGE_STATUS_API_TOKEN') ?: ''
        )));

        $byName = [];
        foreach (array_chunk($packages, $batchSize) as $batchIndex => $batch) {
            $requestEndpoint = $endpoint;
            [$ok, $message, $response] = $this->postJson(
                $requestEndpoint,
                [
                    'schema_version' => 'magebean-package-status-request-v1',
                    'packages' => $batch,
                ],
                $timeoutMs,
                $token
            );
            if (!$ok
                && !empty($args['allow_private_http_fallback'])
                && $token === ''
                && $this->canFallbackToPrivateHttp($endpoint)
            ) {
                $requestEndpoint = 'http://' . substr($endpoint, strlen('https://'));
                [$ok, $message, $response] = $this->postJson(
                    $requestEndpoint,
                    [
                        'schema_version' => 'magebean-package-status-request-v1',
                        'packages' => $batch,
                    ],
                    $timeoutMs,
                    $token
                );
            }
            if (!$ok) {
                return [
                    false,
                    $message . ' (batch ' . ($batchIndex + 1) . ', packages ' . count($batch) . ')',
                    [],
                ];
            }

            $status = (int)($response['status'] ?? 0);
            $decoded = json_decode((string)($response['body'] ?? ''), true);
            if ($status !== 200 || !is_array($decoded)) {
                return [
                    false,
                    'Package status API returned HTTP ' . $status
                        . ' (batch ' . ($batchIndex + 1) . ', packages ' . count($batch) . ')',
                    [],
                ];
            }
            if (($decoded['schema_version'] ?? null) !== 'magebean-package-status-response-v1') {
                return [
                    false,
                    'Unsupported package status API response schema'
                        . ' (batch ' . ($batchIndex + 1) . ')',
                    [],
                ];
            }

            foreach ((array)($decoded['packages'] ?? []) as $package) {
                if (is_array($package) && is_string($package['name'] ?? null)) {
                    $byName[strtolower($package['name'])] = $package;
                }
            }
        }
        return [true, 'Package status loaded (' . count($packages) . ' packages in '
            . (int)ceil(count($packages) / $batchSize) . ' batch(es))', $byName];
    }

    public function yankedApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $installed = $this->readLockPackages($lockFile);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach ($installed as $name => $info) {
            $version = ltrim((string)($info['version'] ?? ''), 'vV');
            if ($version !== '') {
                $packages[] = ['name' => (string)$name, 'version' => $version];
            }
        }
        if ($packages === []) {
            return [true, 'No packages in composer.lock (nothing to check)'];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [null, '[UNKNOWN] Package status API request failed: ' . $message];
        }

        $hits = array_values(array_filter(
            $statuses,
            static fn(array $status): bool => !empty($status['yanked'])
        ));
        $evidence = [
            'packages_checked' => count($packages),
            'yanked_packages' => $hits,
        ];
        if ($hits === []) {
            return [
                true,
                'No installed package versions are yanked or withdrawn',
                $evidence,
            ];
        }

        $visible = array_slice($hits, 0, 20);
        $text = array_map(
            static fn(array $status): string => (string)($status['name'] ?? 'unknown-package')
                . '@' . (string)($status['installed'] ?? 'unknown-version'),
            $visible
        );
        $resultMessage = 'Yanked or withdrawn package versions installed: ' . implode('; ', $text);
        if (count($hits) > count($visible)) {
            $resultMessage .= '; +' . (count($hits) - count($visible)) . ' more';
        }
        return [false, $resultMessage, $evidence];
    }

    public function marketplaceOutdatedApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $lock = json_decode((string)@file_get_contents($lockFile), true);
        if (!is_array($lock)) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach (array_merge($lock['packages'] ?? [], $lock['packages-dev'] ?? []) as $package) {
            if (!is_array($package)
                || ($package['type'] ?? '') !== 'magento2-module'
                || !is_string($package['name'] ?? null)
                || !is_string($package['version'] ?? null)
                || $this->isAdobeCorePackage($package['name'])
            ) {
                continue;
            }

            $version = ltrim(trim($package['version']), 'vV');
            if ($version !== '') {
                $packages[] = [
                    'name' => strtolower($package['name']),
                    'version' => $version,
                ];
            }
        }

        if ($packages === []) {
            return [
                true,
                'No third-party Magento Composer modules found in composer.lock',
                ['packages_checked' => 0, 'scope' => 'non-core magento2-module packages'],
            ];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $message,
                ['packages' => $packages],
            ];
        }

        $maxAgeDays = max(1, (int)($args['max_age_days'] ?? 365));
        $now = time();
        $findings = [];
        $unassessed = [];
        $unclassified = [];
        $excluded = [];
        $assessed = [];

        foreach ($packages as $package) {
            $name = $package['name'];
            $status = $statuses[$name] ?? null;
            if (!is_array($status) || empty($status['classification_known'])) {
                $unclassified[] = $package;
                continue;
            }
            if (empty($status['marketplace'])) {
                $excluded[] = [
                    'name' => $name,
                    'version' => $package['version'],
                    'category' => $status['category'] ?? 'other',
                ];
                continue;
            }
            if (empty($status['known'])) {
                $unassessed[] = $package;
                continue;
            }

            $latestDate = is_string($status['latest_date'] ?? null)
                ? trim($status['latest_date'])
                : '';
            $latestTimestamp = $latestDate !== '' ? strtotime($latestDate) : false;
            $ageDays = $latestTimestamp !== false
                ? max(0, (int)floor(($now - $latestTimestamp) / 86400))
                : null;
            $outdated = !empty($status['outdated']);
            $stale = $ageDays !== null && $ageDays > $maxAgeDays;

            $item = $status;
            $item['age_days'] = $ageDays;
            $item['stale'] = $stale;
            $assessed[] = $item;
            if ($outdated || $stale) {
                $findings[] = $item;
            }
        }

        $evidence = [
            'scope' => 'API-classified Marketplace magento2-module packages',
            'max_age_days' => $maxAgeDays,
            'packages_checked' => count($packages),
            'packages_excluded_by_category' => $excluded,
            'packages_unclassified' => $unclassified,
            'packages_assessed' => count($assessed),
            'packages_unassessed' => $unassessed,
            'findings' => $findings,
        ];

        if ($findings !== []) {
            $visible = array_slice($findings, 0, 20);
            $details = array_map(static function (array $status) use ($maxAgeDays): string {
                $name = (string)($status['name'] ?? 'unknown-package');
                $reasons = [];
                if (!empty($status['outdated'])) {
                    $reasons[] = (string)($status['installed'] ?? '?')
                        . ' < ' . (string)($status['latest'] ?? '?');
                }
                if (!empty($status['stale'])) {
                    $reasons[] = 'latest release is '
                        . (string)($status['age_days'] ?? '?')
                        . ' days old (limit ' . $maxAgeDays . ')';
                }
                return $name . ' [' . implode('; ', $reasons) . ']';
            }, $visible);

            $resultMessage = 'Third-party Magento modules require maintenance: ' . implode('; ', $details);
            if (count($findings) > count($visible)) {
                $resultMessage .= '; +' . (count($findings) - count($visible)) . ' more';
            }
            if ($unassessed !== []) {
                $resultMessage .= '. Metadata unavailable for ' . count($unassessed) . ' additional module(s)';
            }
            if ($unclassified !== []) {
                $resultMessage .= '. Classification unavailable for ' . count($unclassified) . ' additional module(s)';
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unassessed !== [] || $unclassified !== []) {
            $names = array_map(
                static fn(array $package): string => $package['name'] . '@' . $package['version'],
                array_slice(array_merge($unassessed, $unclassified), 0, 20)
            );
            $resultMessage = '[UNKNOWN] Marketplace classification or release metadata unavailable for: '
                . implode('; ', $names);
            $unknownCount = count($unassessed) + count($unclassified);
            if ($unknownCount > count($names)) {
                $resultMessage .= '; +' . ($unknownCount - count($names)) . ' more';
            }
            return [null, $resultMessage, $evidence];
        }

        if ($assessed === []) {
            return [
                true,
                'No API-classified Marketplace extensions found in composer.lock',
                $evidence,
            ];
        }

        return [
            true,
            'Third-party Magento modules are current and have a release within the freshness window',
            $evidence,
        ];
    }

    public function directOutdatedApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $jsonFile = $this->ctx->abs($args['json_file'] ?? 'composer.json');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }
        if (!is_file($jsonFile)) {
            return [null, '[UNKNOWN] composer.json not found'];
        }

        $installed = $this->readLockPackages($lockFile);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }
        $composer = json_decode((string)@file_get_contents($jsonFile), true);
        if (!is_array($composer)) {
            return [null, '[UNKNOWN] Unable to parse composer.json'];
        }

        $sections = ['require'];
        if (!array_key_exists('include_dev', $args) || !empty($args['include_dev'])) {
            $sections[] = 'require-dev';
        }
        $direct = [];
        foreach ($sections as $section) {
            foreach ((array)($composer[$section] ?? []) as $name => $constraint) {
                $name = strtolower(trim((string)$name));
                if ($name === ''
                    || $name === 'php'
                    || str_starts_with($name, 'ext-')
                    || str_starts_with($name, 'lib-')
                    || in_array($name, ['composer-plugin-api', 'composer-runtime-api'], true)
                ) {
                    continue;
                }
                $direct[$name] = [
                    'name' => $name,
                    'constraint' => (string)$constraint,
                    'section' => $section,
                ];
            }
        }

        if ($direct === []) {
            return [
                true,
                'No direct Composer package dependencies found',
                ['sections' => $sections, 'direct_dependencies' => []],
            ];
        }

        $packages = [];
        $unknown = [];
        foreach ($direct as $name => $dependency) {
            $info = $installed[$name] ?? null;
            $version = is_array($info) ? trim((string)($info['version'] ?? '')) : '';
            if ($version === '') {
                $unknown[] = $dependency + ['reason' => 'not_present_in_composer_lock'];
                continue;
            }
            $packages[] = [
                'name' => $name,
                'version' => ltrim($version, 'vV'),
            ];
        }

        if ($packages === []) {
            return [
                null,
                '[UNKNOWN] No direct dependencies could be resolved from composer.lock',
                ['sections' => $sections, 'direct_dependencies' => array_values($direct), 'unknown' => $unknown],
            ];
        }

        [$ok, $apiMessage, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $apiMessage,
                ['packages' => $packages, 'unknown' => $unknown],
            ];
        }

        $findings = [];
        $current = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            $dependency = $direct[$package['name']];
            if (!is_array($status)) {
                $unknown[] = $dependency + [
                    'installed' => $package['version'],
                    'reason' => 'missing_status',
                ];
                continue;
            }
            if (empty($status['release_history_known'])) {
                $unknown[] = $dependency + [
                    'installed' => $package['version'],
                    'reason' => 'release_history_unavailable',
                ];
                continue;
            }
            $latest = is_string($status['latest'] ?? null) ? trim($status['latest']) : '';
            if ($latest === '') {
                $unknown[] = $dependency + [
                    'installed' => $package['version'],
                    'reason' => 'latest_stable_version_unavailable',
                ];
                continue;
            }

            $item = $dependency + [
                'installed' => $package['version'],
                'latest' => $latest,
                'latest_date' => is_string($status['latest_date'] ?? null)
                    ? $status['latest_date']
                    : null,
            ];
            if (!empty($status['outdated'])
                || version_compare($package['version'], ltrim($latest, 'vV'), '<')
            ) {
                $findings[] = $item;
            } else {
                $current[] = $item;
            }
        }

        $evidence = [
            'scope' => $sections,
            'direct_dependencies' => array_values($direct),
            'packages_assessed' => count($current) + count($findings),
            'packages_current' => $current,
            'packages_outdated' => $findings,
            'packages_unknown' => $unknown,
        ];

        if ($findings !== []) {
            $details = array_map(
                static fn(array $item): string => $item['section'] . ': '
                    . $item['name'] . '@' . $item['installed']
                    . ' -> latest ' . $item['latest']
                    . ' (constraint ' . $item['constraint'] . ')',
                $findings
            );
            $resultMessage = "Outdated direct dependencies:\n    - " . implode("\n    - ", $details);
            if ($unknown !== []) {
                $resultMessage .= "\n    Status unavailable for "
                    . count($unknown) . ' additional direct dependency/dependencies';
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $details = array_map(static function (array $item): string {
                $installed = isset($item['installed']) ? '@' . $item['installed'] : '';
                return $item['section'] . ': ' . $item['name'] . $installed
                    . ' (' . $item['reason'] . ')';
            }, $unknown);
            return [
                null,
                "[UNKNOWN] Direct dependency status unavailable for:\n    - "
                    . implode("\n    - ", $details),
                $evidence,
            ];
        }

        return [
            true,
            'All ' . count($current) . ' direct dependencies use the latest stable release',
            $evidence,
        ];
    }

    public function vendorSupportApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $lock = json_decode((string)@file_get_contents($lockFile), true);
        if (!is_array($lock)) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach (array_merge($lock['packages'] ?? [], $lock['packages-dev'] ?? []) as $package) {
            if (!is_array($package)
                || ($package['type'] ?? '') !== 'magento2-module'
                || !is_string($package['name'] ?? null)
                || !is_string($package['version'] ?? null)
                || $this->isAdobeCorePackage($package['name'])
            ) {
                continue;
            }

            $version = ltrim(trim($package['version']), 'vV');
            if ($version !== '') {
                $packages[] = [
                    'name' => strtolower($package['name']),
                    'version' => $version,
                ];
            }
        }

        if ($packages === []) {
            return [
                true,
                'No third-party Magento Composer modules found in composer.lock',
                ['packages_checked' => 0],
            ];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $message,
                ['packages' => $packages],
            ];
        }

        $supported = [];
        $unsupported = [];
        $unknown = [];
        $excluded = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status) || empty($status['classification_known'])) {
                $unknown[] = $package + ['reason' => 'classification_unavailable'];
                continue;
            }
            if (empty($status['marketplace'])) {
                $excluded[] = $package + ['category' => $status['category'] ?? 'other'];
                continue;
            }

            $item = [
                'name' => $package['name'],
                'installed' => $package['version'],
                'status' => (string)($status['vendor_support_status'] ?? 'unknown'),
                'reasons' => array_values(array_map(
                    'strval',
                    (array)($status['vendor_support_reasons'] ?? [])
                )),
            ];
            if ($item['status'] === 'unsupported') {
                $unsupported[] = $item;
            } elseif ($item['status'] === 'active') {
                $supported[] = $item;
            } else {
                $unknown[] = $item;
            }
        }

        $evidence = [
            'scope' => 'API-classified Marketplace magento2-module packages',
            'packages_checked' => count($packages),
            'packages_supported' => $supported,
            'packages_unsupported' => $unsupported,
            'packages_unknown' => $unknown,
            'packages_excluded_by_category' => $excluded,
        ];

        if ($unsupported !== []) {
            $visible = array_slice($unsupported, 0, 20);
            $details = array_map(static function (array $item): string {
                $reasons = $item['reasons'] !== [] ? implode(', ', $item['reasons']) : 'unsupported';
                return $item['name'] . '@' . $item['installed'] . ' [' . $reasons . ']';
            }, $visible);
            $resultMessage = 'Marketplace extensions without active vendor support: '
                . implode('; ', $details);
            if (count($unsupported) > count($visible)) {
                $resultMessage .= '; +' . (count($unsupported) - count($visible)) . ' more';
            }
            if ($unknown !== []) {
                $resultMessage .= '. Support evidence unavailable for '
                    . count($unknown) . ' additional extension(s)';
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $visible = array_slice($unknown, 0, 20);
            $details = array_map(
                static fn(array $item): string => (string)($item['name'] ?? 'unknown-package')
                    . '@' . (string)($item['installed'] ?? $item['version'] ?? 'unknown-version'),
                $visible
            );
            $resultMessage = '[UNKNOWN] Vendor support evidence unavailable for: '
                . implode('; ', $details);
            if (count($unknown) > count($visible)) {
                $resultMessage .= '; +' . (count($unknown) - count($visible)) . ' more';
            }
            return [null, $resultMessage, $evidence];
        }

        if ($supported === []) {
            return [
                true,
                'No API-classified Marketplace extensions found in composer.lock',
                $evidence,
            ];
        }

        return [
            true,
            count($supported) . ' Marketplace extension(s) have active vendor support evidence',
            $evidence,
        ];
    }

    public function abandonedApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $installed = $this->readLockPackages($lockFile);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packageTypes = is_array($args['package_types'] ?? null)
            ? array_values(array_filter(array_map(
                static fn(mixed $type): string => strtolower(trim((string)$type)),
                $args['package_types']
            )))
            : [];
        $packages = [];
        foreach ($installed as $name => $info) {
            $type = strtolower(trim((string)($info['type'] ?? '')));
            if ($packageTypes !== [] && !in_array($type, $packageTypes, true)) {
                continue;
            }
            $version = ltrim(trim((string)($info['version'] ?? '')), 'vV');
            if ($version !== '') {
                $packages[] = [
                    'name' => strtolower((string)$name),
                    'version' => $version,
                    'type' => $type,
                ];
            }
        }
        if ($packages === []) {
            return [
                true,
                $packageTypes === []
                    ? 'No packages in composer.lock (nothing to check)'
                    : 'No installed packages match the requested Composer package types',
                ['package_types' => $packageTypes, 'packages_checked' => 0],
            ];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $message,
                ['package_types' => $packageTypes, 'packages' => $packages],
            ];
        }

        $abandoned = [];
        $unknown = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status) || empty($status['abandoned_status_known'])) {
                $unknown[] = $package;
                continue;
            }
            if (empty($status['abandoned'])) {
                continue;
            }

            $abandoned[] = [
                'name' => $package['name'],
                'installed' => $package['version'],
                'replacement' => is_string($status['replacement'] ?? null)
                    && trim($status['replacement']) !== ''
                        ? trim($status['replacement'])
                        : null,
            ];
        }

        $evidence = [
            'package_types' => $packageTypes,
            'packages_checked' => count($packages),
            'abandoned_packages' => $abandoned,
            'packages_unknown' => $unknown,
        ];
        if ($abandoned !== []) {
            $details = array_map(static function (array $item): string {
                $text = $item['name'] . '@' . $item['installed'];
                if (is_string($item['replacement']) && $item['replacement'] !== '') {
                    $text .= ' -> replace with ' . $item['replacement'];
                }
                return $text;
            }, $abandoned);
            $resultMessage = "Packages marked abandoned on Packagist:\n    - "
                . implode("\n    - ", $details);
            if ($unknown !== []) {
                $resultMessage .= "\n    Abandoned status unavailable for "
                    . count($unknown) . ' additional package(s)';
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $details = array_map(
                static fn(array $package): string => $package['name'] . '@' . $package['version'],
                $unknown
            );
            $resultMessage = "[UNKNOWN] Packagist abandoned status unavailable for:\n    - "
                . implode("\n    - ", $details);
            return [null, $resultMessage, $evidence];
        }

        return [
            true,
            $packageTypes === []
                ? 'No installed packages are marked abandoned in the Packagist snapshot'
                : 'No installed packages in the requested Composer type scope are marked abandoned',
            $evidence,
        ];
    }

    public function releaseRecencyApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $installed = $this->readLockPackages($lockFile);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach ($installed as $name => $info) {
            $version = ltrim(trim((string)($info['version'] ?? '')), 'vV');
            if ($version !== '') {
                $packages[] = [
                    'name' => strtolower((string)$name),
                    'version' => $version,
                ];
            }
        }
        if ($packages === []) {
            return [true, 'No packages in composer.lock (nothing to check)'];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $message,
                ['packages' => $packages],
            ];
        }

        $months = max(1, (int)($args['months'] ?? 24));
        $cutoff = (new \DateTimeImmutable('now'))->modify('-' . $months . ' months');
        $now = time();
        $tracked = [];
        $stale = [];
        $unknown = [];
        $excluded = [];

        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status)) {
                $unknown[] = $package + ['reason' => 'missing_status'];
                continue;
            }
            if (empty($status['release_history_known'])) {
                $excluded[] = $package + ['reason' => 'release_history_unavailable'];
                continue;
            }

            $latestDate = is_string($status['latest_date'] ?? null)
                ? trim($status['latest_date'])
                : '';
            try {
                $latestAt = $latestDate !== '' ? new \DateTimeImmutable($latestDate) : null;
            } catch (\Exception) {
                $latestAt = null;
            }
            if ($latestAt === null) {
                $unknown[] = $package + ['reason' => 'latest_date_invalid'];
                continue;
            }

            $item = [
                'name' => $package['name'],
                'installed' => $package['version'],
                'latest' => is_string($status['latest'] ?? null) ? $status['latest'] : null,
                'latest_date' => $latestAt->format(DATE_ATOM),
                'age_days' => max(0, (int)floor(($now - $latestAt->getTimestamp()) / 86400)),
            ];
            $tracked[] = $item;
            if ($latestAt < $cutoff) {
                $stale[] = $item;
            }
        }

        $evidence = [
            'months' => $months,
            'cutoff' => $cutoff->format(DATE_ATOM),
            'packages_checked' => count($packages),
            'packages_tracked' => $tracked,
            'packages_stale' => $stale,
            'packages_unknown' => $unknown,
            'packages_excluded_no_release_history' => $excluded,
        ];

        if ($stale !== []) {
            $visible = array_slice($stale, 0, 20);
            $details = array_map(static function (array $item): string {
                $latest = is_string($item['latest'] ?? null) && $item['latest'] !== ''
                    ? ' latest ' . $item['latest']
                    : '';
                return $item['name'] . '@' . $item['installed']
                    . $latest
                    . ', last release ' . $item['age_days'] . ' days ago';
            }, $visible);
            $resultMessage = 'Packagist-tracked packages without a release in the last '
                . $months . " months:\n    - " . implode("\n    - ", $details);
            if (count($stale) > count($visible)) {
                $resultMessage .= "\n    - +" . (count($stale) - count($visible)) . ' more';
            }
            if ($unknown !== []) {
                $resultMessage .= "\n    Release recency unavailable for "
                    . count($unknown) . ' additional package(s)';
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $visible = array_slice($unknown, 0, 20);
            $details = array_map(
                static fn(array $package): string => $package['name'] . '@' . $package['version'],
                $visible
            );
            $resultMessage = "[UNKNOWN] Release recency unavailable for:\n    - "
                . implode("\n    - ", $details);
            if (count($unknown) > count($visible)) {
                $resultMessage .= "\n    - +" . (count($unknown) - count($visible)) . ' more';
            }
            return [null, $resultMessage, $evidence];
        }

        if ($tracked === []) {
            return [
                true,
                'No Packagist release history is available for installed packages; nothing to assess',
                $evidence,
            ];
        }

        return [
            true,
            'Packagist-tracked packages have a release within the last ' . $months . ' months',
            $evidence,
        ];
    }

    public function repoArchivedApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $installed = $this->readLockPackages($lockFile);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach ($installed as $name => $info) {
            $version = ltrim(trim((string)($info['version'] ?? '')), 'vV');
            if ($version !== '') {
                $packages[] = [
                    'name' => strtolower((string)$name),
                    'version' => $version,
                    'repository_url' => is_string($info['source'] ?? null)
                        ? trim($info['source'])
                        : '',
                ];
            }
        }
        if ($packages === []) {
            return [true, 'No packages in composer.lock (nothing to check)'];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $message,
                ['packages' => $packages],
            ];
        }

        $findings = [];
        $unknown = [];
        $unassessed = [];
        $excluded = [];
        $active = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status)) {
                $unknown[] = $package + ['reason' => 'missing_status'];
                continue;
            }

            if (empty($status['repository_status_known'])) {
                $reason = trim((string)($status['repository_status_reason'] ?? ''));
                $item = $package + [
                    'installed' => $package['version'],
                    'reason' => $reason !== '' ? $reason : 'repository_status_unavailable',
                    'repository_url' => is_string($status['repository_url'] ?? null)
                        ? $status['repository_url']
                        : null,
                ];
                if ($item['reason'] === 'repository_missing') {
                    $findings[] = $item + [
                        'archived' => false,
                        'disabled' => false,
                        'missing' => true,
                    ];
                } elseif ($item['reason'] === 'repository_not_collected') {
                    $unassessed[] = $item;
                } elseif (in_array($item['reason'], [
                    'repository_not_applicable',
                    'repository_provider_unsupported',
                ], true)) {
                    $excluded[] = $item;
                } else {
                    $unknown[] = $item;
                }
                continue;
            }

            $item = [
                'name' => $package['name'],
                'installed' => $package['version'],
                'repository_url' => is_string($status['repository_url'] ?? null)
                    ? trim($status['repository_url'])
                    : '',
                'provider' => is_string($status['repository_provider'] ?? null)
                    ? trim($status['repository_provider'])
                    : null,
                'archived' => !empty($status['repository_archived']),
                'disabled' => !empty($status['repository_disabled']),
                'missing' => false,
                'checked_at' => is_string($status['repository_checked_at'] ?? null)
                    ? $status['repository_checked_at']
                    : null,
            ];
            if ($item['archived'] || $item['disabled']) {
                $findings[] = $item;
            } else {
                $active[] = $item;
            }
        }

        $evidence = [
            'packages_checked' => count($packages),
            'repositories_active' => $active,
            'repository_findings' => $findings,
            'packages_unknown' => $unknown,
            'packages_unassessed' => $unassessed,
            'packages_excluded' => $excluded,
        ];

        if ($findings !== []) {
            $details = array_map(static function (array $item): string {
                $states = [];
                if ($item['archived']) {
                    $states[] = 'archived';
                }
                if ($item['disabled']) {
                    $states[] = 'disabled';
                }
                if ($item['missing']) {
                    $states[] = 'missing';
                }
                $detail = $item['name'] . '@' . $item['installed'] . ' (' . implode(', ', $states) . ')';
                if ($item['repository_url'] !== '') {
                    $detail .= "\n      Repository: " . $item['repository_url'];
                }
                return $detail;
            }, $findings);
            $resultMessage = "Packages from archived, disabled, or missing repositories:\n    - "
                . implode("\n    - ", $details);
            if ($unknown !== []) {
                $resultMessage .= "\n    Repository checks failed for "
                    . count($unknown) . ' additional package(s)';
            }
            if ($unassessed !== []) {
                $resultMessage .= "\n    Repository status is awaiting collection for "
                    . count($unassessed) . ' additional package(s)';
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $details = array_map(static function (array $item): string {
                return $item['name'] . '@' . $item['version'] . ' (' . $item['reason'] . ')';
            }, $unknown);
            return [
                null,
                "[UNKNOWN] Repository status unavailable for:\n    - " . implode("\n    - ", $details),
                $evidence,
            ];
        }

        if ($active === [] && $unassessed !== []) {
            $details = array_map(static function (array $item): string {
                return $item['name'] . '@' . $item['version'];
            }, $unassessed);
            return [
                null,
                "[UNKNOWN] No applicable repository could be assessed; awaiting collection for:\n    - "
                    . implode("\n    - ", $details),
                $evidence,
            ];
        }

        if ($active === []) {
            return [
                true,
                'No installed packages have an applicable GitHub or GitLab source repository',
                $evidence,
            ];
        }

        $coverage = count($active) . ' repositories assessed';
        if ($unassessed !== []) {
            $coverage .= ', ' . count($unassessed) . ' awaiting collection';
        }
        return [
            true,
            'No assessed packages come from archived, disabled, or missing repositories ('
                . $coverage . ')',
            $evidence,
        ];
    }


    public function riskyForkApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }
        $installed = $this->readLockPackages($lockFile);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach ($installed as $name => $info) {
            $version = ltrim(trim((string)($info['version'] ?? '')), 'vV');
            if ($version === '') {
                continue;
            }
            $replaces = [];
            foreach ((array)($info['replace'] ?? []) as $replacement => $_constraint) {
                $replacement = strtolower(trim((string)$replacement));
                if ($replacement !== ''
                    && $replacement !== strtolower((string)$name)
                    && str_contains($replacement, '/')
                    && !str_ends_with($replacement, '-implementation')
                ) {
                    $replaces[] = $replacement;
                }
            }
            $packages[] = [
                'name' => strtolower((string)$name),
                'version' => $version,
                'repository_url' => is_string($info['source'] ?? null)
                    ? trim($info['source'])
                    : '',
                'type' => is_string($info['type'] ?? null) ? $info['type'] : null,
                'replaces' => array_values(array_unique($replaces)),
            ];
        }
        if ($packages === []) {
            return [true, 'No packages in composer.lock (nothing to check)'];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [null, '[UNKNOWN] Package status API request failed: ' . $message, ['packages' => $packages]];
        }

        $findings = [];
        $safe = [];
        $unknown = [];
        $excluded = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status)) {
                if ($package['replaces'] !== []) {
                    $unknown[] = $package + ['installed' => $package['version'], 'reason' => 'missing_status'];
                } else {
                    $excluded[] = $package + ['reason' => 'not_a_replacement_candidate'];
                }
                continue;
            }

            $sourceOverride = !empty($status['repository_source_override_known'])
                && !empty($status['repository_source_override']);
            if ($package['replaces'] === [] && !$sourceOverride) {
                $excluded[] = $package + ['reason' => 'not_a_replacement_candidate'];
                continue;
            }
            if ($package['type'] === 'metapackage' || $package['repository_url'] === '') {
                $excluded[] = $package + ['reason' => 'repository_not_applicable'];
                continue;
            }

            $reason = trim((string)($status['repository_status_reason'] ?? ''));
            $item = [
                'name' => $package['name'],
                'installed' => $package['version'],
                'repository_url' => (string)($status['repository_url'] ?? $package['repository_url']),
                'package_repository_url' => is_string($status['package_repository_url'] ?? null)
                    ? $status['package_repository_url']
                    : null,
                'upstream_url' => is_string($status['repository_upstream_url'] ?? null)
                    ? $status['repository_upstream_url']
                    : null,
                'replaces' => $package['replaces'],
                'source_override' => $sourceOverride,
                'is_fork' => !empty($status['repository_is_fork']),
                'trusted' => !empty($status['repository_trusted']),
            ];

            if ($reason === 'repository_missing') {
                $findings[] = $item + ['reason' => 'replacement_repository_missing'];
                continue;
            }
            if ($item['trusted']) {
                $safe[] = $item + ['reason' => 'trusted_repository'];
                continue;
            }
            if ($sourceOverride) {
                $findings[] = $item + ['reason' => 'untrusted_source_override'];
                continue;
            }
            if (empty($status['repository_status_known']) || empty($status['fork_status_known'])) {
                $unknown[] = $item + [
                    'reason' => $reason !== '' ? $reason : 'fork_status_unavailable',
                ];
                continue;
            }
            if ($item['is_fork']) {
                $findings[] = $item + [
                    'reason' => $item['upstream_url'] === null || $item['upstream_url'] === ''
                        ? 'fork_upstream_missing'
                        : 'unverified_fork_replacing_upstream',
                ];
                continue;
            }
            $safe[] = $item + ['reason' => 'replacement_not_from_fork'];
        }

        $evidence = [
            'packages_checked' => count($packages),
            'replacement_candidates_safe' => $safe,
            'risky_replacements' => $findings,
            'replacement_candidates_unknown' => $unknown,
            'packages_excluded' => $excluded,
        ];

        if ($findings !== []) {
            $details = array_map(static function (array $item): string {
                $detail = $item['name'] . '@' . $item['installed'] . ' (' . $item['reason'] . ')';
                if ($item['replaces'] !== []) {
                    $detail .= "\n      Replaces: " . implode(', ', $item['replaces']);
                }
                $detail .= "\n      Repository: " . $item['repository_url'];
                if (is_string($item['upstream_url']) && $item['upstream_url'] !== '') {
                    $detail .= "\n      Upstream: " . $item['upstream_url'];
                }
                return $detail;
            }, $findings);
            $resultMessage = "Risky replacement repositories detected:\n    - "
                . implode("\n    - ", $details);
            if ($unknown !== []) {
                $resultMessage .= "\n    Fork evidence unavailable for "
                    . count($unknown) . ' additional candidate(s)';
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $details = array_map(static function (array $item): string {
                return $item['name'] . '@' . $item['installed'] . ' (' . $item['reason'] . ')';
            }, $unknown);
            return [
                null,
                "[UNKNOWN] Fork evidence unavailable for replacement candidates:\n    - "
                    . implode("\n    - ", $details),
                $evidence,
            ];
        }

        return [
            true,
            $safe === []
                ? 'No installed packages replace upstream libraries from alternate repositories'
                : 'No risky forks detected among ' . count($safe) . ' replacement candidate(s)',
            $evidence,
        ];
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
                        foreach ($intervals as [$a, $b]) {
                            if ($this->inRangeSafe($auditor, $cur, $a, $b)) {
                                $hit = true;
                                if ($b !== null) $minFixed = $this->minVersionLocal($minFixed, $b);
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
            $cjRaw = @file_get_contents($cjPath);
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


    public function outdatedOffline(array $args): array
    {
        // 0) Load composer.lock
        $root = $args['path'] ?? getcwd();
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs || !is_array($pkgs)) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $installed = [];
        foreach ($pkgs as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') $installed[$name] = ltrim($v, 'vV');
        }
        if (!$installed) return [true, "No packages in composer.lock (nothing to check)"];

        // 1) Resolve bundle root (zip/dir/file-inside-bundle)
        $candidates = [];
        if (!empty($args['release_meta'])) $candidates[] = (string)$args['release_meta']; // optional direct hint
        if (!empty($args['cve_data']))     $candidates[] = (string)$args['cve_data'];
        if (!empty($this->ctx->cveData))   $candidates[] = (string)$this->ctx->cveData;
        $candidates = array_values(array_unique(array_filter($candidates, fn($p) => is_string($p) && $p !== '')));

        $normalize = function (string $p): string {
            if (preg_match('#^/|^[A-Za-z]:[\\\\/]#', $p)) return $p;
            $abs = $this->ctx->abs($p);
            return is_string($abs) && $abs !== '' ? $abs : (getcwd() . '/' . $p);
        };
        $tried = [];
        $resolveRoot = function (string $raw) use ($normalize, &$tried) {
            $p = $normalize($raw);
            $tried[] = $p;

            if (is_file($p) && preg_match('/\.zip$/i', $p)) return ['zip', $p];

            $asDir = is_dir($p) ? $p : dirname($p);
            $cur = $asDir;
            for ($i = 0; $i < 5; $i++) {
                if (is_dir($cur . '/INDEX') || is_dir($cur . '/DATA') || is_dir($cur . '/VULNS') || is_file($cur . '/INDEX/packages-index.json')) {
                    return ['dir', $cur];
                }
                $parent = dirname($cur);
                if ($parent === $cur) break;
                $cur = $parent;
            }
            if (preg_match('#/(DATA|VULNS|INDEX)/#', $p)) {
                $root = preg_replace('#/(DATA|VULNS|INDEX)/.*$#', '', $p);
                if (is_dir($root)) return ['dir', $root];
            }
            return null;
        };

        $bundle = null;
        foreach ($candidates as $cand) {
            if (($bundle = $resolveRoot($cand)) !== null) break;
        }
        if (!$bundle) {
            $msg = $tried ? implode(' | ', $tried) : '(no candidates)';
            return [null, "[UNKNOWN] Release metadata not found; bundle root unresolved; tried: " . $msg];
        }

        // 2) Load DATA/release-history.json (fallback rules/)
        $loadText = function (string $rel) use ($bundle) {
            if ($bundle[0] === 'zip') {
                $zip = new \ZipArchive();
                if ($zip->open($bundle[1]) !== true) return null;
                $idx = $zip->locateName($rel, \ZipArchive::FL_NOCASE);
                if ($idx === false) {
                    $zip->close();
                    return null;
                }
                $raw = $zip->getFromIndex($idx);
                $zip->close();
                return is_string($raw) ? $raw : null;
            } else {
                $path = rtrim($bundle[1], '/') . '/' . $rel;
                if (!is_file($path)) return null;
                $raw = @file_get_contents($path);
                return $raw === false ? null : $raw;
            }
        };

        $rawRelease = $loadText('release-history.json') ?? $loadText('rules/release-history.json');
        if ($rawRelease === null) {
            return [null, "[UNKNOWN] Release metadata not found (DATA/release-history.json)"];
        }

        $jRelease = json_decode($rawRelease, true);
        if (!is_array($jRelease)) {
            return [null, "[UNKNOWN] Invalid release-history.json (not JSON object/array)"];
        }

        // 3) Normalize → latestStable['vendor/pkg'] = 'x.y.z[-pN]'
        $latestStable = [];
        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };
        $isStable = static function (string $v): bool {
            if (stripos($v, 'dev') !== false) return false;
            return !preg_match('/(?:alpha|beta|rc)\d*$/i', $v);
        };

        // Hỗ trợ container { "packages": [...] }
        $payload = isset($jRelease['packages']) && is_array($jRelease['packages']) ? $jRelease['packages'] : $jRelease;

        if ($isAssoc($payload)) {
            // Map: "pkg" => [ ... ]  hoặc  "pkg" => { "versions":[...] }
            foreach ($payload as $pkg => $row) {
                $versions = [];
                if (is_array($row)) {
                    if (isset($row['versions']) && is_array($row['versions'])) {
                        $versions = $row['versions'];
                    } else {
                        $versions = $row; // có thể đã là list versions
                    }
                }
                $versions = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $versions), fn($v) => $v !== ''));
                if (!$versions) continue;
                $versions = array_values(array_filter($versions, $isStable));
                if (!$versions) continue;
                usort($versions, fn($a, $b) => version_compare($b, $a)); // desc
                $latestStable[$pkg] = $versions[0];
            }
        } else {
            // List: [{"package":"pkg","versions":[...]}]
            foreach ($payload as $row) {
                if (!is_array($row)) continue;
                $pkg = $row['package'] ?? null;
                $versions = $row['versions'] ?? null;
                if (!is_string($pkg) || !is_array($versions)) continue;
                $versions = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $versions), fn($v) => $v !== ''));
                if (!$versions) continue;
                $versions = array_values(array_filter($versions, $isStable));
                if (!$versions) continue;
                usort($versions, fn($a, $b) => version_compare($b, $a)); // desc
                $latestStable[$pkg] = $versions[0];
            }
        }

        if (!$latestStable) {
            return [true, "No latest versions resolvable from release-history.json (empty after normalize)"];
        }

        // 4) Compare installed vs latest
        $outdated = [];
        foreach ($installed as $pkg => $cur) {
            if (!isset($latestStable[$pkg])) continue;
            $latest = $latestStable[$pkg];
            if (version_compare($cur, $latest, '<')) {
                $outdated[] = "{$pkg} {$cur} -> < {$latest}";
            }
        }

        if ($outdated) {
            // In nhiều dòng cho dễ đọc
            $lines = array_map(static fn($s) => ' - ' . $s, $outdated);
            return [false, "Outdated packages (offline):\n" . implode(PHP_EOL, $lines)];
        }
        return [true, "All installed packages are up-to-date against release-history.json"];
    }

    public function advisoryLatency(array $args): array
    {
        // ---- 0) Guard: composer.lock (để biết project path), nhưng rule không bắt buộc phải match installed
        $root = $args['path'] ?? getcwd();

        // ---- 1) Resolve bundle root (zip/dir/file-inside-bundle)
        $candidates = [];
        if (!empty($args['cve_data']))   $candidates[] = (string)$args['cve_data'];
        if (!empty($this->ctx->cveData)) $candidates[] = (string)$this->ctx->cveData;
        $candidates = array_values(array_unique(array_filter($candidates, fn($p) => is_string($p) && $p !== '')));

        $normalize = function (string $p): string {
            if (preg_match('#^/|^[A-Za-z]:[\\\\/]#', $p)) return $p;
            $abs = $this->ctx->abs($p);
            return is_string($abs) && $abs !== '' ? $abs : (getcwd() . '/' . $p);
        };
        $tried = [];
        $resolveRoot = function (string $raw) use ($normalize, &$tried) {
            $p = $normalize($raw);
            $tried[] = $p;
            if (is_file($p) && preg_match('/\.zip$/i', $p)) return ['zip', $p];
            $asDir = is_dir($p) ? $p : dirname($p);
            $cur = $asDir;
            for ($i = 0; $i < 5; $i++) {
                if (is_dir($cur . '/INDEX') || is_dir($cur . '/DATA') || is_dir($cur . '/VULNS') || is_file($cur . '/INDEX/packages-index.json')) {
                    return ['dir', $cur];
                }
                $parent = dirname($cur);
                if ($parent === $cur) break;
                $cur = $parent;
            }
            if (preg_match('#/(DATA|VULNS|INDEX)/#', $p)) {
                $root = preg_replace('#/(DATA|VULNS|INDEX)/.*$#', '', $p);
                if (is_dir($root)) return ['dir', $root];
            }
            return null;
        };

        $bundle = null;
        foreach ($candidates as $cand) {
            if (($bundle = $resolveRoot($cand)) !== null) break;
        }
        if (!$bundle) {
            $msg = $tried ? implode(' | ', $tried) : '(no candidates)';
            return [null, "[UNKNOWN] Bundle not found/openable; tried: " . $msg];
        }

        // ---- 2) Helpers load text from bundle
        $loadText = function (string $rel) use ($bundle) {
            if ($bundle[0] === 'zip') {
                $zip = new \ZipArchive();
                if ($zip->open($bundle[1]) !== true) return null;
                $idx = $zip->locateName($rel, \ZipArchive::FL_NOCASE);
                if ($idx === false) {
                    $zip->close();
                    return null;
                }
                $raw = $zip->getFromIndex($idx);
                $zip->close();
                return is_string($raw) ? $raw : null;
            } else {
                $path = rtrim($bundle[1], '/') . '/' . $rel;
                if (!is_file($path)) return null;
                $raw = @file_get_contents($path);
                return $raw === false ? null : $raw;
            }
        };

        // ---- 3) Load index + release-history
        $rawIdx = $loadText('INDEX/packages-index.json');
        if ($rawIdx === null) return [null, "[UNKNOWN] packages-index.json missing in bundle"];
        $pkg2vuln = json_decode($rawIdx, true);
        if (!is_array($pkg2vuln) || !$pkg2vuln) return [null, "[UNKNOWN] packages-index.json invalid/empty"];

        $rawRel = $loadText('release-history.json') ?? $loadText('rules/release-history.json');
        if ($rawRel === null) return [null, "[UNKNOWN] release-history.json missing"];
        $relJ = json_decode($rawRel, true);
        if (!is_array($relJ)) return [null, "[UNKNOWN] release-history.json invalid JSON"];

        // ---- 4) Normalize release-history → map: pkg => (version => timestamp)
        $releaseMap = []; // 'vendor/pkg' => ['1.2.3' => '2024-01-02T..Z', ...]
        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };
        $normRel = isset($relJ['packages']) && is_array($relJ['packages']) ? $relJ['packages'] : $relJ;

        if ($isAssoc($normRel)) {
            // Map form: "pkg" => ["x.y.z", ...] OR "pkg" => { "versions":[...]} OR "pkg" => { "timeline":[{"version":"..","date":".."}] } OR "pkg" => {"map": {"x.y.z":"2024-..."}}
            foreach ($normRel as $pkg => $row) {
                if (!is_string($pkg)) continue;
                if (is_array($row)) {
                    // timeline/map first (preferred if available)
                    if (isset($row['map']) && is_array($row['map'])) {
                        foreach ($row['map'] as $ver => $ts) {
                            if (!is_string($ver) || !is_string($ts)) continue;
                            $releaseMap[$pkg][ltrim($ver, 'vV')] = $ts;
                        }
                    }
                    if (isset($row['timeline']) && is_array($row['timeline'])) {
                        foreach ($row['timeline'] as $it) {
                            $ver = $it['version'] ?? null;
                            $ts = $it['date'] ?? null;
                            if (!is_string($ver) || !is_string($ts)) continue;
                            $releaseMap[$pkg][ltrim($ver, 'vV')] = $ts;
                        }
                    }
                    // plain versions list without dates → still useful to know existence (but latency needs date)
                    $vers = $row['versions'] ?? (is_array($row) ? $row : null);
                    if (is_array($vers)) {
                        foreach ($vers as $ver) {
                            if (!is_string($ver) || $ver === '') continue;
                            $v = ltrim($ver, 'vV');
                            if (!isset($releaseMap[$pkg][$v])) $releaseMap[$pkg][$v] = null;
                        }
                    }
                }
            }
        } else {
            // List form: [{"package":"pkg","versions":[...]}, {"package":"pkg","timeline":[{"version":"..","date":".."}]}]
            foreach ($normRel as $row) {
                if (!is_array($row)) continue;
                $pkg = $row['package'] ?? null;
                if (!is_string($pkg) || $pkg === '') continue;
                if (isset($row['map']) && is_array($row['map'])) {
                    foreach ($row['map'] as $ver => $ts) {
                        if (!is_string($ver) || !is_string($ts)) continue;
                        $releaseMap[$pkg][ltrim($ver, 'vV')] = $ts;
                    }
                }
                if (isset($row['timeline']) && is_array($row['timeline'])) {
                    foreach ($row['timeline'] as $it) {
                        $ver = $it['version'] ?? null;
                        $ts = $it['date'] ?? null;
                        if (!is_string($ver) || !is_string($ts)) continue;
                        $releaseMap[$pkg][ltrim($ver, 'vV')] = $ts;
                    }
                }
                if (isset($row['versions']) && is_array($row['versions'])) {
                    foreach ($row['versions'] as $ver) {
                        if (!is_string($ver) || $ver === '') continue;
                        $v = ltrim($ver, 'vV');
                        if (!isset($releaseMap[$pkg][$v])) $releaseMap[$pkg][$v] = null;
                    }
                }
            }
        }

        if (!$releaseMap) {
            return [null, "[UNKNOWN] release-history.json has no version→date mapping"];
        }

        // ---- 5) Iterate vulnerabilities & compute latency
        $eventsToIntervals = function (array $events): array {
            $intervals = [];
            $curStart = null;
            foreach ($events as $e) {
                if (isset($e['introduced'])) {
                    $curStart = ltrim((string)$e['introduced'], 'vV');
                } elseif (isset($e['fixed'])) {
                    $fixed = ltrim((string)$e['fixed'], 'vV');
                    $intervals[] = [$curStart, $fixed];
                    $curStart = null;
                } elseif (isset($e['last_affected'])) {
                    $la = ltrim((string)$e['last_affected'], 'vV');
                    $intervals[] = [$curStart, $la];
                    $curStart = null;
                }
            }
            if ($curStart !== null) $intervals[] = [$curStart, null];
            return $intervals;
        };

        $parseDate = static function (?string $s): ?\DateTimeImmutable {
            if (!is_string($s) || $s === '') return null;
            try {
                return new \DateTimeImmutable($s);
            } catch (\Exception $e) {
                return null;
            }
        };

        $thresholdDays = isset($args['latency_days']) && is_numeric($args['latency_days']) ? (int)$args['latency_days'] : 30;

        $rows = []; // collected report lines
        $worst = 0;

        // read each vuln json on demand
        $readVulnJson = function (string $vid) use ($bundle) {
            if ($bundle[0] === 'zip') {
                $zip = new \ZipArchive();
                if ($zip->open($bundle[1]) !== true) return null;
                $idx = $zip->locateName("VULNS/{$vid}.json", \ZipArchive::FL_NOCASE);
                if ($idx === false) {
                    $zip->close();
                    return null;
                }
                $raw = $zip->getFromIndex($idx);
                $zip->close();
                return is_string($raw) ? json_decode($raw, true) : null;
            } else {
                $p = rtrim($bundle[1], '/') . "/VULNS/{$vid}.json";
                if (!is_file($p)) return null;
                $raw = @file_get_contents($p);
                return $raw === false ? null : json_decode($raw, true);
            }
        };

        foreach ($pkg2vuln as $pkg => $ids) {
            if (!is_array($ids)) continue;
            foreach ($ids as $vid) {
                $vj = $readVulnJson((string)$vid);
                if (!is_array($vj)) continue;

                // advisory publish date
                $pub = $vj['published'] ?? ($vj['database_specific']['published'] ?? ($vj['database_specific']['advisory_date'] ?? null));
                $pubDt = $parseDate(is_string($pub) ? $pub : null);

                $aff = $vj['affected'] ?? null;
                if (!is_array($aff)) continue;

                // Collect fixed versions for this package (Packagist only)
                $fixedVers = [];
                foreach ($aff as $a) {
                    $pname = $a['package']['name'] ?? null;
                    $eco   = $a['package']['ecosystem'] ?? null;
                    if (!is_string($pname) || $pname !== $pkg) continue;
                    if ($eco && is_string($eco) && !preg_match('/^packagist$/i', $eco)) continue;

                    $ranges = is_array($a['ranges'] ?? null) ? $a['ranges'] : [];
                    foreach ($ranges as $rng) {
                        $events = is_array($rng['events'] ?? null) ? $rng['events'] : [];
                        $intervals = $eventsToIntervals($events);
                        foreach ($intervals as [, $to]) {
                            if ($to !== null && $to !== '') $fixedVers[] = ltrim((string)$to, 'vV');
                        }
                    }
                    // fallback database_specific.fixed
                    if (isset($a['database_specific']['fixed']) && is_string($a['database_specific']['fixed']) && $a['database_specific']['fixed'] !== '') {
                        $fixedVers[] = ltrim($a['database_specific']['fixed'], 'vV');
                    }
                }

                $fixedVers = array_values(array_unique($fixedVers));
                if (!$fixedVers) {
                    // không có fixed version nào để tính latency
                    // $rows[] = "{$pkg} — {$vid} — no fixed version found";
                    continue;
                }

                // Find earliest fixed version release date among available mappings
                $bestLatency = null;
                $bestFixed = null;
                $bestFixedDate = null;
                $pubStr = $pubDt ? $pubDt->format(DATE_ATOM) : 'unknown';
                foreach ($fixedVers as $fv) {
                    $ts = $releaseMap[$pkg][$fv] ?? null;
                    if (!is_string($ts) || $ts === '') continue; // không có timestamp → không tính được
                    $fixDt = $parseDate($ts);
                    if (!$fixDt || !$pubDt) continue;
                    $latDays = (int)$fixDt->diff($pubDt)->format('%r%a'); // days (can be negative if dates inverted)
                    // latency = fix - advisory
                    $latency = ($fixDt->getTimestamp() - $pubDt->getTimestamp()) / 86400.0;
                    $latencyDays = (int)floor($latency + 0.00001);
                    if ($bestLatency === null || $latencyDays < $bestLatency) {
                        $bestLatency = $latencyDays;
                        $bestFixed = $fv;
                        $bestFixedDate = $fixDt->format(DATE_ATOM);
                    }
                }

                if ($bestLatency === null) {
                    $rows[] = "{$pkg} — {$vid} — publish={$pubStr} — fixed_date=unknown (no version→date mapping)";
                    continue;
                }

                $worst = max($worst, $bestLatency);
                $rows[] = "{$pkg} — {$vid} — publish={$pubStr} — fixed={$bestFixed} @ {$bestFixedDate} — latency_days={$bestLatency}";
            }
        }

        if (!$rows) {
            return [true, "No advisory timelines computed (no records or missing data)"];
        }

        // Kết luận theo threshold
        $failRows = array_filter($rows, function ($line) use ($thresholdDays) {
            if (preg_match('/latency_days=([\-]?\d+)/', $line, $m)) {
                return ((int)$m[1]) > $thresholdDays;
            }
            return false;
        });

        // In nhiều dòng cho dễ đọc (phần renderDetails đã hỗ trợ nl2br)
        $msg = "Advisory timeline (publish → fixed):\n - " . implode("\n - ", $rows);

        if (!empty($failRows)) {
            return [false, $msg . "\nThreshold: {$thresholdDays} days — flagged entries marked above"];
        }
        return [true, $msg . "\nThreshold: {$thresholdDays} days — all within limit"];
    }


    public function vendorSupportOffline(array $args): array
    {
        // 0) Load composer.lock
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs || !is_array($pkgs)) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $installed = [];
        foreach ($pkgs as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') $installed[strtolower($name)] = ltrim($v, 'vV');
        }
        if (!$installed) return [true, "No packages in composer.lock (nothing to check)"];

        // Prefer Context->meta (resolved from extracted bundle) before falling back to bundle root detection.
        $metaPath = $this->metaPath($args, 'vendor_support', 'vendor_support_meta', 'vendor-support.json')
            ?? $this->metaPath($args, 'vendor_support', 'vendor_support_meta', 'rules/vendor-support.json');
        $raw = null;
        if ($metaPath) {
            $raw = @file_get_contents($metaPath);
            if ($raw === false) $raw = null;
        }

        // 1) Resolve bundle root (zip/dir/path-inside-bundle)
        if ($raw === null) {
            $candidates = [];
            if (!empty($args['vendor_support_meta'])) $candidates[] = (string)$args['vendor_support_meta'];
            if (!empty($args['cve_data']))           $candidates[] = (string)$args['cve_data'];
            if (!empty($this->ctx->cveData))         $candidates[] = (string)$this->ctx->cveData;
            $candidates = array_values(array_unique(array_filter($candidates, fn($p) => is_string($p) && $p !== '')));

            $normalize = function (string $p): string {
                if (preg_match('#^/|^[A-Za-z]:[\\\\/]#', $p)) return $p;
                $abs = $this->ctx->abs($p);
                return is_string($abs) && $abs !== '' ? $abs : (getcwd() . '/' . $p);
            };
            $tried = [];
            $resolveRoot = function (string $raw) use ($normalize, &$tried) {
                $p = $normalize($raw);
                $tried[] = $p;
                if (is_file($p) && preg_match('/\.zip$/i', $p)) return ['zip', $p];
                $asDir = is_dir($p) ? $p : dirname($p);
                $cur = $asDir;
                for ($i = 0; $i < 5; $i++) {
                    if (is_dir($cur . '/INDEX') || is_dir($cur . '/DATA') || is_dir($cur . '/VULNS') || is_file($cur . '/INDEX/packages-index.json')) {
                        return ['dir', $cur];
                    }
                    $parent = dirname($cur);
                    if ($parent === $cur) break;
                    $cur = $parent;
                }
                if (preg_match('#/(DATA|VULNS|INDEX)/#', $p)) {
                    $root = preg_replace('#/(DATA|VULNS|INDEX)/.*$#', '', $p);
                    if (is_dir($root)) return ['dir', $root];
                }
                return null;
            };

            $bundle = null;
            foreach ($candidates as $cand) {
                if (($bundle = $resolveRoot($cand)) !== null) break;
            }
            if (!$bundle) {
                $msg = $tried ? implode(' | ', $tried) : '(no candidates)';
                return [null, "[UNKNOWN] Vendor-support metadata not found; bundle root unresolved; tried: " . $msg];
            }

            // 2) Load DATA/vendor-support.json (fallback rules/)
            $loadText = function (string $rel) use ($bundle) {
                if ($bundle[0] === 'zip') {
                    $zip = new \ZipArchive();
                    if ($zip->open($bundle[1]) !== true) return null;
                    $idx = $zip->locateName($rel, \ZipArchive::FL_NOCASE);
                    if ($idx === false) {
                        $zip->close();
                        return null;
                    }
                    $raw = $zip->getFromIndex($idx);
                    $zip->close();
                    return is_string($raw) ? $raw : null;
                } else {
                    $path = rtrim($bundle[1], '/') . '/' . $rel;
                    if (!is_file($path)) return null;
                    $raw = @file_get_contents($path);
                    return $raw === false ? null : $raw;
                }
            };

            $raw = $loadText('vendor-support.json') ?? $loadText('rules/vendor-support.json');
            if ($raw === null) {
                return [true, "Vendor-support metadata not provided; skipping check (add vendor-support.json in CVE bundle to enable)"];
            }
        }

        // 2.1) Loose JSON decode: strip BOM, comments, trailing commas; retry decode
        $looseDecode = static function (string $s) {
            // strip UTF-8 BOM
            if (substr($s, 0, 3) === "\xEF\xBB\xBF") $s = substr($s, 3);
            // remove //... and /* ... */
            $s = preg_replace('#//[^\r\n]*#', '', $s);
            $s = preg_replace('#/\*.*?\*/#s', '', $s);
            // remove trailing commas before } or ]
            $s = preg_replace('#,\s*(}|\])#', '$1', $s);
            // collapse repeated commas
            $s = preg_replace('#,\s*,+#', ',', $s);
            // trim
            $s = trim($s);
            $j = json_decode($s, true);
            if (is_array($j)) return $j;
            // final fallback: try to decode as empty container aliases
            if ($s === '' || $s === '{}' || $s === '[]') return [];
            return null;
        };

        $j = $looseDecode($raw);
        if (!is_array($j)) return [null, "[UNKNOWN] Invalid vendor-support metadata JSON"];

        // 3) Normalize payload → rules[pkg][] = ['versions'[], 'constraint', 'eol', 'seol', 'status']
        $payload = $j;
        if (isset($j['support']) && (is_array($j['support']) || $j['support'] === [])) $payload = $j['support'];
        if (isset($j['vendor_support']) && (is_array($j['vendor_support']) || $j['vendor_support'] === [])) $payload = $j['vendor_support'];
        if (isset($j['vendorSupport']) && (is_array($j['vendorSupport']) || $j['vendorSupport'] === [])) $payload = $j['vendorSupport'];

        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };
        $rules = []; // pkg => list of rule rows

        $addRule = static function (string $pkg, ?array $versions, ?string $constraint, ?string $eol, ?string $seol, ?string $status) use (&$rules) {
            $pkg = strtolower($pkg);
            $row = [
                'versions'   => $versions ?: null,
                'constraint' => $constraint ?: null,
                'eol'        => $eol ?: null,
                'seol'       => $seol ?: null,
                'status'     => $status ? strtolower($status) : null,
            ];
            $rules[$pkg][] = $row;
        };
        $canonSeol = static function (?array $row): ?string {
            if (!$row) return null;
            foreach (['security_eol', 'securityEOL', 'security-end', 'security_end'] as $k) {
                if (isset($row[$k]) && is_string($row[$k]) && $row[$k] !== '') return $row[$k];
            }
            return null;
        };

        if ((is_array($payload) && empty($payload)) || ($payload instanceof \stdClass && !get_object_vars($payload))) {
            return [true, "No vendor-support entries (empty list)"];
        }


        if ($isAssoc((array)$payload)) {
            foreach ($payload as $pkg => $row) {
                if (!is_string($pkg)) continue;
                if (!is_array($row)) continue;

                $eol  = is_string($row['eol'] ?? null) ? $row['eol'] : null;
                $seol = $canonSeol($row);
                $status = is_string($row['status'] ?? null) ? $row['status'] : null;
                if ($eol || $seol || $status) $addRule($pkg, null, null, $eol, $seol, $status);

                if (isset($row['tracks']) && is_array($row['tracks'])) {
                    foreach ($row['tracks'] as $t) {
                        if (!is_array($t)) continue;
                        $vers = null;
                        if (isset($t['versions']) && is_array($t['versions'])) {
                            $vers = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $t['versions']), fn($v) => $v !== ''));
                        }
                        $constraint = is_string($t['constraint'] ?? null) ? $t['constraint'] : null;
                        $teol  = is_string($t['eol'] ?? null) ? $t['eol'] : null;
                        $tseol = $canonSeol($t);
                        $tstat = is_string($t['status'] ?? null) ? $t['status'] : null;
                        if ($vers || $constraint || $teol || $tseol || $tstat) {
                            $addRule($pkg, $vers, $constraint, $teol, $tseol, $tstat);
                        }
                    }
                }
                if (isset($row['versions']) && is_array($row['versions'])) {
                    foreach ($row['versions'] as $expr => $meta) {
                        if (!is_array($meta)) continue;
                        $teol  = is_string($meta['eol'] ?? null) ? $meta['eol'] : null;
                        $tseol = $canonSeol($meta);
                        $tstat = is_string($meta['status'] ?? null) ? $meta['status'] : null;
                        $vlist = null;
                        if (isset($meta['versions']) && is_array($meta['versions'])) {
                            $vlist = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $meta['versions']), fn($v) => $v !== ''));
                        }
                        $addRule($pkg, $vlist, is_string($expr) ? $expr : null, $teol, $tseol, $tstat);
                    }
                }
            }
        } else {
            foreach ((array)$payload as $row) {
                if (!is_array($row)) continue;
                $pkg = $row['package'] ?? null;
                if (!is_string($pkg) || $pkg === '') continue;

                $eol  = is_string($row['eol'] ?? null) ? $row['eol'] : null;
                $seol = $canonSeol($row);
                $status = is_string($row['status'] ?? null) ? $row['status'] : null;
                if ($eol || $seol || $status) $addRule($pkg, null, null, $eol, $seol, $status);

                if (isset($row['tracks']) && is_array($row['tracks'])) {
                    foreach ($row['tracks'] as $t) {
                        if (!is_array($t)) continue;
                        $vers = null;
                        if (isset($t['versions']) && is_array($t['versions'])) {
                            $vers = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $t['versions']), fn($v) => $v !== ''));
                        }
                        $constraint = is_string($t['constraint'] ?? null) ? $t['constraint'] : null;
                        $teol  = is_string($t['eol'] ?? null) ? $t['eol'] : null;
                        $tseol = $canonSeol($t);
                        $tstat = is_string($t['status'] ?? null) ? $t['status'] : null;
                        if ($vers || $constraint || $teol || $tseol || $tstat) {
                            $addRule($pkg, $vers, $constraint, $teol, $tseol, $tstat);
                        }
                    }
                }
            }
        }

        if (!$rules) {
            return [true, "No vendor-support entries (empty or no usable rules)"];
        }

        // 4) Version matching (Composer-like, tối giản + các toán tử phổ biến)
        $cmp = static fn(string $a, string $b, string $op) => version_compare(ltrim($a, 'vV'), ltrim($b, 'vV'), $op);

        $expandCaret = static function (string $v): array {
            $v = ltrim($v, 'vV');
            $parts = array_map('intval', explode('.', $v) + [0, 0, 0]);
            if ($parts[0] > 0)        $upper = ($parts[0] + 1) . ".0.0";
            elseif ($parts[1] > 0)    $upper = "0." . ($parts[1] + 1) . ".0";
            else                      $upper = "0.0." . ($parts[2] + 1);
            return [">=" . $v, "<" . $upper];
        };
        $expandTilde = static function (string $v): array {
            $v = ltrim($v, 'vV');
            $parts = explode('.', $v);
            if (count($parts) === 1) {
                $upper = ((int)$parts[0] + 1) . ".0.0";
                $vmin = $parts[0] . ".0.0";
            } elseif (count($parts) === 2) {
                $upper = $parts[0] . "." . ((int)$parts[1] + 1) . ".0";
                $vmin = $parts[0] . "." . $parts[1] . ".0";
            } else {
                $upper = $parts[0] . "." . ((int)$parts[1] + 1) . ".0";
                $vmin = $v;
            }
            return [">=" . $vmin, "<" . $upper];
        };
        $expandWildcard = static function (string $v): array {
            $v = ltrim($v, 'vV');
            $parts = explode('.', str_replace(['x', 'X', '*'], '*', $v));
            if (count($parts) === 1 || ($parts[1] ?? '') === '*') {
                $lower = $parts[0] . ".0.0";
                $upper = ((int)$parts[0] + 1) . ".0.0";
            } elseif (($parts[2] ?? '') === '*') {
                $lower = $parts[0] . "." . $parts[1] . ".0";
                $upper = $parts[0] . "." . ((int)$parts[1] + 1) . ".0";
            } else {
                $lower = $v;
                $upper = null;
            }
            return $upper ? [">=" . $lower, "<" . $upper] : [">=" . $lower];
        };

        $matchExpr = null; // forward decl for recursion
        $matchExpr = static function (string $iv, string $expr) use (&$matchExpr, $cmp, $expandCaret, $expandTilde, $expandWildcard): bool {
            foreach (preg_split('/\s*\|\|\s*/', trim($expr)) as $orPart) {
                if ($orPart === '') continue;
                $ok = true;
                $tokens = preg_split('/\s*,\s*|\s+/', trim($orPart));
                foreach ($tokens as $t) {
                    if ($t === '') continue;
                    if ($t[0] === '^') {
                        foreach ($expandCaret(substr($t, 1)) as $c) if (!$matchExpr($iv, $c)) {
                            $ok = false;
                            break;
                        }
                        if (!$ok) break;
                        continue;
                    }
                    if ($t[0] === '~') {
                        foreach ($expandTilde(substr($t, 1)) as $c) if (!$matchExpr($iv, $c)) {
                            $ok = false;
                            break;
                        }
                        if (!$ok) break;
                        continue;
                    }
                    if (preg_match('/[*xX]/', $t)) {
                        foreach ($expandWildcard($t) as $c) if (!$matchExpr($iv, $c)) {
                            $ok = false;
                            break;
                        }
                        if (!$ok) break;
                        continue;
                    }
                    if (preg_match('/^(<=|>=|==|=|!=|<|>)\s*([vV]?\d[\w\.\-\+]*)$/', $t, $m)) {
                        $op = $m[1] === '=' ? '==' : $m[1];
                        if (!$cmp($iv, $m[2], $op)) {
                            $ok = false;
                            break;
                        }
                    } else {
                        if (!$cmp($iv, $t, '==')) {
                            $ok = false;
                            break;
                        }
                    }
                }
                if ($ok) return true;
            }
            return false;
        };

        $now = new \DateTimeImmutable('now');
        $parseDate = static function (?string $s): ?\DateTimeImmutable {
            if (!is_string($s) || $s === '') return null;
            try {
                return new \DateTimeImmutable($s);
            } catch (\Exception $e) {
                return null;
            }
        };

        // 5) Evaluate
        $hits = [];
        foreach ($installed as $pkg => $cur) {
            if (empty($rules[$pkg])) continue;

            foreach ($rules[$pkg] as $r) {
                $matched = false;
                if (is_array($r['versions'])) {
                    $matched = in_array($cur, $r['versions'], true);
                }
                if (!$matched && is_string($r['constraint']) && $r['constraint'] !== '') {
                    $matched = $matchExpr(ltrim($cur, 'vV'), $r['constraint']);
                }
                if (!$matched && !$r['versions'] && !$r['constraint']) {
                    $matched = true; // apply to all versions
                }
                if (!$matched) continue;

                $eol  = $parseDate($r['eol']);
                $seol = $parseDate($r['seol']);
                $status = $r['status'] ?? null;

                if ($status && in_array($status, ['eol', 'end_of_life', 'unsupported', 'security_eol', 'security-end'], true)) {
                    $label = ($status === 'security_eol' || $status === 'security-end') ? 'SECURITY-EOL' : 'EOL';
                    $dateStr = $eol ? $eol->format(DATE_ATOM) : ($seol ? $seol->format(DATE_ATOM) : 'n/a');
                    $hits[] = "{$pkg} {$cur} — {$label} (since {$dateStr})";
                    continue;
                }
                if ($eol && $now > $eol) {
                    $hits[] = "{$pkg} {$cur} — EOL on " . $eol->format(DATE_ATOM);
                    continue;
                }
                if ($seol && $now > $seol) {
                    $hits[] = "{$pkg} {$cur} — SECURITY-EOL on " . $seol->format(DATE_ATOM);
                    continue;
                }
            }
        }

        if ($hits) {
            $lines = array_map(fn($s) => ' - ' . $s, $hits);
            return [false, "Vendor support issues (offline):\n" . implode(PHP_EOL, $lines)];
        }
        return [true, "All installed packages are within vendor support"];
    }

    // alias giữ API cũ
    public function composer_vendor_support_offline(array $args): array
    {
        return $this->composerVendorSupportOffline($args);
    }



    public function abandonedOffline(array $args): array
    {
        // 0) Read composer.lock
        $root = $args['path'] ?? getcwd();
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs || !is_array($pkgs)) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $installed = [];
        foreach ($pkgs as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') $installed[$name] = ltrim($v, 'vV');
        }
        if (!$installed) return [true, "No packages in composer.lock (nothing to check)"];

        // 1) Resolve bundle root (zip/dir/path-inside-bundle)
        $candidates = [];
        if (!empty($args['abandoned_meta'])) $candidates[] = (string)$args['abandoned_meta'];
        if (!empty($args['cve_data']))       $candidates[] = (string)$args['cve_data'];
        if (!empty($this->ctx->cveData))     $candidates[] = (string)$this->ctx->cveData;
        $candidates = array_values(array_unique(array_filter($candidates, fn($p) => is_string($p) && $p !== '')));

        $normalize = function (string $p): string {
            if (preg_match('#^/|^[A-Za-z]:[\\\\/]#', $p)) return $p;
            $abs = $this->ctx->abs($p);
            return is_string($abs) && $abs !== '' ? $abs : (getcwd() . '/' . $p);
        };
        $tried = [];
        $resolveRoot = function (string $raw) use ($normalize, &$tried) {
            $p = $normalize($raw);
            $tried[] = $p;

            if (is_file($p) && preg_match('/\.zip$/i', $p)) return ['zip', $p];

            $asDir = is_dir($p) ? $p : dirname($p);
            $cur = $asDir;
            for ($i = 0; $i < 5; $i++) {
                if (is_dir($cur . '/INDEX') || is_dir($cur . '/DATA') || is_dir($cur . '/VULNS') || is_file($cur . '/INDEX/packages-index.json')) {
                    return ['dir', $cur];
                }
                $parent = dirname($cur);
                if ($parent === $cur) break;
                $cur = $parent;
            }
            if (preg_match('#/(DATA|VULNS|INDEX)/#', $p)) {
                $root = preg_replace('#/(DATA|VULNS|INDEX)/.*$#', '', $p);
                if (is_dir($root)) return ['dir', $root];
            }
            return null;
        };

        $bundle = null;
        foreach ($candidates as $cand) {
            if (($bundle = $resolveRoot($cand)) !== null) break;
        }
        if (!$bundle) {
            $msg = $tried ? implode(' | ', $tried) : '(no candidates)';
            return [null, "[UNKNOWN] Abandoned metadata not found; bundle root unresolved; tried: " . $msg];
        }

        // 2) Load DATA/packagist-abandoned.json (fallback rules/)
        $loadText = function (string $rel) use ($bundle) {
            if ($bundle[0] === 'zip') {
                $zip = new \ZipArchive();
                if ($zip->open($bundle[1]) !== true) return null;
                $idx = $zip->locateName($rel, \ZipArchive::FL_NOCASE);
                if ($idx === false) {
                    $zip->close();
                    return null;
                }
                $raw = $zip->getFromIndex($idx);
                $zip->close();
                return is_string($raw) ? $raw : null;
            } else {
                $path = rtrim($bundle[1], '/') . '/' . $rel;
                if (!is_file($path)) return null;
                $raw = @file_get_contents($path);
                return $raw === false ? null : $raw;
            }
        };

        $raw = $loadText('packagist-abandoned.json') ?? $loadText('rules/packagist-abandoned.json');
        if ($raw === null) return [null, "[UNKNOWN] Abandoned metadata not found"];

        $j = json_decode($raw, true);
        if (!is_array($j)) {
            return [null, "[UNKNOWN] Invalid abandoned metadata JSON: " . ($bundle[0] === 'zip' ? 'zip://' . $bundle[1] . '!/DATA/packagist-abandoned.json' : (rtrim($bundle[1], '/') . '/DATA/packagist-abandoned.json'))];
        }

        // 3) Normalize abandoned map: name => replacement|null  (replacement: string|null)
        // Hỗ trợ container { "abandoned": [...] }
        $payload = isset($j['abandoned']) && is_array($j['abandoned']) ? $j['abandoned'] : $j;

        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };
        $abandoned = []; // 'vendor/pkg' => 'replacement/pkg' | null

        if ($isAssoc($payload)) {
            // Map form:
            // - "vendor/pkg": true
            // - "vendor/pkg": "replacement/pkg"
            // - "vendor/pkg": {"replacement": "alt/pkg"}  (hoặc {"abandoned":true})
            foreach ($payload as $pkg => $val) {
                if (!is_string($pkg) || $pkg === '') continue;
                $rep = null;
                if ($val === true) {
                    $rep = null;
                } elseif (is_string($val) && $val !== '') {
                    $rep = $val;
                } elseif (is_array($val)) {
                    if (isset($val['replacement']) && is_string($val['replacement']) && $val['replacement'] !== '') {
                        $rep = $val['replacement'];
                    } elseif (isset($val['abandoned']) && ($val['abandoned'] === true || is_string($val['abandoned']))) {
                        $rep = is_string($val['abandoned']) ? $val['abandoned'] : null;
                    }
                }
                // Chỉ thêm khi thực sự đánh dấu bỏ (true hoặc có replacement)
                if ($val === true || is_string($val) || (is_array($val) && (isset($val['replacement']) || isset($val['abandoned'])))) {
                    $abandoned[$pkg] = $rep ? (string)$rep : null;
                }
            }
        } else {
            // List form:
            // [{"package":"vendor/pkg","abandoned":true},{"package":"foo/bar","replacement":"alt/pkg"}]
            foreach ($payload as $row) {
                if (!is_array($row)) continue;
                $pkg = $row['package'] ?? null;
                if (!is_string($pkg) || $pkg === '') continue;
                $rep = null;
                if (isset($row['replacement']) && is_string($row['replacement']) && $row['replacement'] !== '') {
                    $rep = $row['replacement'];
                } elseif (array_key_exists('abandoned', $row)) {
                    if ($row['abandoned'] === true) $rep = null;
                    elseif (is_string($row['abandoned']) && $row['abandoned'] !== '') $rep = $row['abandoned'];
                }
                if (array_key_exists('abandoned', $row)) {
                    // chỉ ghi nhận nếu có cờ 'abandoned'
                    $abandoned[$pkg] = $rep;
                }
            }
        }

        // Nếu metadata rỗng có chủ đích: PASS
        if (!$abandoned) {
            if (isset($j['abandoned']) && is_array($j['abandoned']) && $j['abandoned'] === []) {
                return [true, "No abandoned entries (empty list)"];
            }
            // Không có entries usable → UNKNOWN
            return [null, "[UNKNOWN] Invalid abandoned metadata JSON (no usable entries)"];
        }

        // 4) Match against installed
        $hits = [];
        foreach ($installed as $name => $ver) {
            if (isset($abandoned[$name])) {
                $rep = $abandoned[$name];
                if ($rep) {
                    $hits[] = "{$name} {$ver} — abandoned; replacement: {$rep}";
                } else {
                    $hits[] = "{$name} {$ver} — abandoned";
                }
            }
        }

        if ($hits) {
            // Multiline output
            $lines = array_map(fn($s) => ' - ' . $s, $hits);
            return [false, "Abandoned packages (offline):\n" . implode(PHP_EOL, $lines)];
        }

        return [true, "No abandoned packages installed"];
    }

    public function releaseRecencyOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'release_history', 'release_meta', 'release-history.json')
            ?? $this->metaPath($args, 'release_history', 'release_meta', 'rules/release-history.json');
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

        $metaPath = $this->metaPath($args, 'repo_status', 'repo_meta', 'repo-status.json')
            ?? $this->metaPath($args, 'repo_status', 'repo_meta', 'rules/repo-status.json');
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

        $metaPath = $this->metaPath($args, 'repo_status', 'repo_meta', 'repo-status.json')
            ?? $this->metaPath($args, 'repo_status', 'repo_meta', 'rules/repo-status.json');
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

        $raw = @file_get_contents($jsonPath);
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

        $raw = @file_get_contents($jsonPath);
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
        $jsonRaw = @file_get_contents($jsonPath);
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

        $lockRaw = @file_get_contents($lockPath);
        $lock    = is_string($lockRaw) ? json_decode($lockRaw, true) : null;
        if (!is_array($lock)) {
            return [
                false,
                "Invalid composer.lock at {$lockPath}",
                ['json_file' => $jsonPath, 'lock_file' => $lockPath, 'problems' => ['lock_invalid']],
            ];
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
            $instRaw = @file_get_contents($installedPath);
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
                            'type'    => $p['type'] ?? null,
                            'replace' => is_array($p['replace'] ?? null) ? $p['replace'] : [],
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

        /**
         * 4) Delegate to CveAuditor::eventsToIntervals() if available; otherwise use local fallback.
         */
        private function eventsToIntervalsSafe($auditor, array $events, ?string &$minFixedCandidate = null): array
        {
            // Try to use CveAuditor implementation if it exists
            if (is_object($auditor)) {
                try {
                    $ref = new \ReflectionClass($auditor);
                    if ($ref->hasMethod('eventsToIntervals')) {
                        $m = $ref->getMethod('eventsToIntervals');
                        $m->setAccessible(true);

                        $params = $m->getParameters();
                        if (count($params) >= 2) {
                            // Method expects (array $events, ?string &$minFixedCandidate)
                            $args = [$events, &$minFixedCandidate];
                        } else {
                            // Older signature: eventsToIntervals(array $events)
                            $args = [$events];
                        }

                        $result = $m->invokeArgs($auditor, $args);
                        if (is_array($result)) {
                            return $result;
                        }
                    }
                } catch (\Throwable $e) {
                    // If reflection / invocation fails, fall back to local implementation
                }
            }

            // Local fallback implementation
            $res = [];
            $curStart = null;
            $minFixedCandidate = null;

            foreach ($events as $ev) {
                if (isset($ev['introduced'])) {
                    $curStart = ltrim((string) $ev['introduced'], 'v');
                } elseif (isset($ev['fixed'])) {
                    $fx = ltrim((string) $ev['fixed'], 'v');
                    $minFixedCandidate = $this->minVersionLocal($minFixedCandidate, $fx);

                    if ($curStart !== null) {
                        $res[] = [$curStart, $fx];
                        $curStart = null;
                    } else {
                        $res[] = [null, $fx];
                    }
                }
            }

            if ($curStart !== null) {
                $res[] = [$curStart, null];
            }

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
