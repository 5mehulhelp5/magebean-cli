<?php
declare(strict_types=1);

namespace Magebean\Facade;

use DateTimeImmutable;
use DateTimeZone;
use JsonException;
use RuntimeException;
use ZipArchive;

final class AuditService
{
    /** @var array{rules_dir?:string|null,cve_path?:string|null,cve_dir?:string|null,template_path?:string|null} */
    private array $config;

    private $engineRunner;

    /**
     * @param array{rules_dir?:string|null,cve_path?:string|null,cve_dir?:string|null,template_path?:string|null} $config
     * @param callable|null $engineRunner
     */
    public function __construct(array $config = [], ?callable $engineRunner = null)
    {
        $this->config = [
            'rules_dir'     => $config['rules_dir']     ?? null,
            'cve_path'      => $config['cve_path']      ?? null,
            'cve_dir'       => $config['cve_dir']       ?? null,  // fallback legacy (tuỳ bạn dùng trong runEngine)
            'template_path' => $config['template_path'] ?? null,  // nếu sau này muốn render HTML/PDF ngay tại đây
        ];
        $this->engineRunner = $engineRunner;
    }

    /**
     * @param array{
     *
     * @return array Report array JSON-friendly
     */
    public function audit(array $options): array
    {
        $startedAt = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format(DATE_ATOM);
        $jobId     = $this->genUlidLike();

        $path        = $options['path'] ?? '';
        $storeDomain = (string)($options['store_domain'] ?? '');
        $owaspMode   = (bool)($options['owasp_mode'] ?? true);

        if (!is_string($path) || $path === '' || !is_dir($path)) {
            throw new RuntimeException('Invalid audit path: '.$path);
        }

        $rulesDir = $this->config['rules_dir'];
        if ($rulesDir === null || !is_dir($rulesDir)) {
            $rulesDir = $rulesDir ?? '';
        }

        $errors = [];

        try {
            $cveDataset = $this->loadCveDataset($options);
        } catch (\Throwable $e) {
            $errors[] = 'CVE dataset load error: '.$e->getMessage();
            $cveDataset = [
                'version'  => null,
                'packages' => [], 
                'origin'   => null,
            ];
        }

        $composerLock = $this->findComposerLock($path);
        $composerPkgs = [];
        if ($composerLock) {
            try {
                $composerPkgs = $this->readComposerPackages($composerLock);
            } catch (\Throwable $e) {
                $errors[] = 'composer.lock parse error: '.$e->getMessage();
            }
        } else {
            $errors[] = 'composer.lock not found under '.$path;
        }

        $engineSummary = [];
        $engineFindings = [];
        $engineVersions = [];

        if (is_callable($this->engineRunner)) {
            try {
                /** @var callable $runner */
                $runner = $this->engineRunner;

                $engineInput = [
                    'path'        => $path,
                    'rules_dir'   => $rulesDir,
                    'owasp_mode'  => $owaspMode,
                    'cve_index'   => $cveDataset['packages'] ?: null,
                    'options'     => $options,
                ];

                $engineResult = $runner($engineInput);

                $engineSummary  = isset($engineResult['summary'])  && is_array($engineResult['summary'])  ? $engineResult['summary']  : [];
                $engineFindings = isset($engineResult['findings']) && is_array($engineResult['findings']) ? $engineResult['findings'] : [];
                $engineVersions = isset($engineResult['versions']) && is_array($engineResult['versions']) ? $engineResult['versions'] : [];
            } catch (\Throwable $e) {
                $errors[] = 'Engine run error: '.$e->getMessage();
            }
        }

        $cveSection = $this->buildCveSection($composerPkgs, $cveDataset['packages']);

        $summary = $engineSummary ?: [
            'total_rules'     => 0,
            'passed'          => 0,
            'failed'          => 0,
            'skipped'         => 0,
            'severity_counts' => ['Critical'=>0,'High'=>0,'Medium'=>0,'Low'=>0],
            'score'           => null,
        ];

        $completedAt = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format(DATE_ATOM);
        $versions = [
            'cli'    => $engineVersions['cli']    ?? null,
            'rules'  => $engineVersions['rules']  ?? null,
            'cve'    => $cveDataset['version'],
        ];

        $report = [
            'meta' => [
                'job_id'       => $jobId,
                'started_at'   => $startedAt,
                'completed_at' => $completedAt,
                'target'       => [
                    'path'         => $path,
                    'store_domain' => $storeDomain,
                ],
                'versions'     => $versions,
                'options'      => [
                    'owasp_mode'    => $owaspMode,
                    'cta_thresholds'=> $options['cta_thresholds'] ?? null,
                ],
                'status'       => empty($errors) ? 'ok' : 'partial',
            ],
            'summary'  => $summary,
            'findings' => $engineFindings,
            'cve'      => $cveSection,
            'artifacts'=> [
                'html'     => null, 
                'pdf_path' => null, 
            ],
            'errors'   => $errors,
        ];

        return $report;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // CVE DATASET LOADING
    // ─────────────────────────────────────────────────────────────────────────────

    /**
     *
     * @param array $options
     * @return array{version:string|null,packages:array<string,array>,origin:string|null}
     */
    private function loadCveDataset(array $options): array
    {
        // 1) cve_data (array)
        if (isset($options['cve_data']) && is_array($options['cve_data'])) {
            $data = $options['cve_data'];
            return $this->normalizeCveData($data, 'options:cve_data');
        }

        // 2) cve_json (raw string)
        if (isset($options['cve_json']) && is_string($options['cve_json']) && $options['cve_json'] !== '') {
            try {
                /** @var array $decoded */
                $decoded = json_decode($options['cve_json'], true, 512, JSON_THROW_ON_ERROR);
                return $this->normalizeCveData($decoded, 'options:cve_json');
            } catch (JsonException $e) {
                throw new RuntimeException('Invalid cve_json: '.$e->getMessage(), 0, $e);
            }
        }

        // 3) cve_json_file
        if (isset($options['cve_json_file']) && is_string($options['cve_json_file']) && $options['cve_json_file'] !== '') {
            if (!is_file($options['cve_json_file'])) {
                throw new RuntimeException('cve_json_file not found: '.$options['cve_json_file']);
            }
            /** @var array $decoded */
            $decoded = json_decode((string)file_get_contents($options['cve_json_file']), true);
            if (!is_array($decoded)) {
                throw new RuntimeException('cve_json_file invalid JSON: '.$options['cve_json_file']);
            }
            return $this->normalizeCveData($decoded, $options['cve_json_file']);
        }

        $cvePath = $this->config['cve_path'];
        if (is_string($cvePath) && $cvePath !== '') {
            if (!is_file($cvePath)) {
                throw new RuntimeException('Configured cve_path not found: '.$cvePath);
            }

            if (str_ends_with(strtolower($cvePath), '.zip')) {
                return $this->loadCveFromZip($cvePath);
            }

            if (str_ends_with(strtolower($cvePath), '.json')) {
                /** @var array $decoded */
                $decoded = json_decode((string)file_get_contents($cvePath), true);
                if (!is_array($decoded)) {
                    throw new RuntimeException('cve_path JSON invalid: '.$cvePath);
                }
                return $this->normalizeCveData($decoded, $cvePath);
            }
        }

        return ['version'=>null,'packages'=>[],'origin'=>null];
    }

    /**
     *
     * @param string $zipPath
     * @return array{version:string|null,packages:array<string,array>,origin:string}
     */
    private function loadCveFromZip(string $zipPath): array
    {
        if (!class_exists(ZipArchive::class)) {
            throw new RuntimeException('ext-zip is required to read CVE ZIP bundles.');
        }

        $zip = new ZipArchive();
        if (true !== $zip->open($zipPath)) {
            throw new RuntimeException('Failed to open ZIP: '.$zipPath);
        }

        try {
            $cveJsonIndex = $zip->locateName('cve.json', ZipArchive::FL_NODIR);
            if ($cveJsonIndex !== false) {
                $raw = $zip->getFromIndex($cveJsonIndex);
                if (!is_string($raw)) {
                    throw new RuntimeException('cve.json cannot be read from ZIP');
                }
                /** @var array $decoded */
                $decoded = json_decode($raw, true);
                if (!is_array($decoded)) {
                    throw new RuntimeException('cve.json invalid JSON inside ZIP');
                }
                return $this->normalizeCveData($decoded, $zipPath.'::cve.json');
            }

            $manifestIndex = $zip->locateName('MANIFEST/manifest.json', ZipArchive::FL_NODIR);
            $version = null;
            if ($manifestIndex !== false) {
                $mraw = $zip->getFromIndex($manifestIndex);
                if (is_string($mraw)) {
                    /** @var array $m */
                    $m = json_decode($mraw, true);
                    if (is_array($m) && isset($m['version']) && is_string($m['version'])) {
                        $version = $m['version'];
                    }
                }
            }

            return [
                'version'  => $version,
                'packages' => [],
                'origin'   => $zipPath.'::PACKAGES/*',
            ];
        } finally {
            $zip->close();
        }
    }

    /**
     * @param array $data
     * @param string $origin
     * @return array{version:string|null,packages:array<string,array>,origin:string}
     */
    private function normalizeCveData(array $data, string $origin): array
    {
        $version  = isset($data['version']) && is_string($data['version']) ? $data['version'] : null;
        $packages = isset($data['packages']) && is_array($data['packages']) ? $data['packages'] : [];

        return [
            'version'  => $version,
            'packages' => $packages,
            'origin'   => $origin,
        ];
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // COMPOSER LOCK READER
    // ─────────────────────────────────────────────────────────────────────────────

    private function findComposerLock(string $rootPath): ?string
    {
        $lock = rtrim($rootPath, '/').'/composer.lock';
        return is_file($lock) ? $lock : null;
    }

    /**
     * @return array<string,string> map 'vendor/name' => 'version'
     */
    private function readComposerPackages(string $composerLockFile): array
    {
        /** @var array $data */
        $data = json_decode((string)file_get_contents($composerLockFile), true, 512, JSON_THROW_ON_ERROR);

        $map = [];
        foreach (['packages','packages-dev'] as $key) {
            if (!isset($data[$key]) || !is_array($data[$key])) {
                continue;
            }
            foreach ($data[$key] as $pkg) {
                if (!is_array($pkg)) {
                    continue;
                }
                $name = isset($pkg['name']) && is_string($pkg['name']) ? $pkg['name'] : null;
                $version = isset($pkg['version']) && is_string($pkg['version']) ? $pkg['version'] : null;
                if ($name && $version) {
                    $map[$name] = $version;
                }
            }
        }
        return $map;
    }

    private function buildCveSection(array $composerPkgs, array $cveIndex): array
    {
        $affected = [];
        $count = ['Critical'=>0,'High'=>0,'Medium'=>0,'Low'=>0];

        if (empty($composerPkgs)) {
            return [
                'packages_scanned' => 0,
                'vuln_counts'      => $count,
                'affected'         => [],
            ];
        }

        if (empty($cveIndex)) {
            return [
                'packages_scanned' => count($composerPkgs),
                'vuln_counts'      => $count,
                'affected'         => [],
            ];
        }

        foreach ($composerPkgs as $name => $ver) {
            if (!isset($cveIndex[$name]) || !is_array($cveIndex[$name])) {
                continue;
            }
            $pkgVulns = [];
            foreach ($cveIndex[$name] as $v) {
                if (!is_array($v)) {
                    continue;
                }
                $sev = $this->mapSeverity($v['sev'] ?? ($v['severity'] ?? ''));
                $pkgVulns[] = [
                    'id'        => (string)($v['id'] ?? ''),
                    'severity'  => $sev,
                    'fixed_in'  => isset($v['fixed_in']) ? (string)$v['fixed_in'] : null,
                    'cvss'      => isset($v['cvss']) && is_numeric($v['cvss']) ? (float)$v['cvss'] : null,
                    'refs'      => isset($v['refs']) && is_array($v['refs']) ? $v['refs'] : [],
                ];
                if (isset($count[$sev])) {
                    $count[$sev]++;
                }
            }
            if (!empty($pkgVulns)) {
                $affected[] = [
                    'package' => $name,
                    'version' => $ver,
                    'cves'    => $pkgVulns,
                ];
            }
        }

        return [
            'packages_scanned' => count($composerPkgs),
            'vuln_counts'      => $count,
            'affected'         => $affected,
        ];
    }

    private function mapSeverity(string $sev): string
    {
        $sev = strtoupper(trim($sev));
        return match ($sev) {
            'C', 'CRIT', 'CRITICAL' => 'Critical',
            'H', 'HIGH'             => 'High',
            'M', 'MED', 'MEDIUM'    => 'Medium',
            'L', 'LOW'              => 'Low',
            default                 => 'Medium',
        };
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // UTIL
    // ─────────────────────────────────────────────────────────────────────────────

    private function genUlidLike(): string
    {
        return bin2hex(random_bytes(8)).'-'.bin2hex(random_bytes(8));
    }
}
