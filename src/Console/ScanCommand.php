<?php

declare(strict_types=1);

namespace Magebean\Console;

use Magebean\Engine\Context;
use Magebean\Engine\ScanRunner;
use Magebean\Engine\RulePackLoader;
use Magebean\Engine\Reporting\HtmlReporter;
use Magebean\Bundle\BundleManager;
use Magebean\Engine\Cve\CveAuditor;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class ScanCommand extends Command
{
    protected static $defaultName = 'scan';

    /** Keep help text in one place */
    private const HELP = <<<'HELP'
Execute a comprehensive audit for a Magento 2 project using 12 controls and 81 rules.
Doc: https://magebean.com/documentation

What it checks
  • Security Auditing — unsafe code patterns, permissions, world-writable files, XSS, SQLi, SSRF
  • Configuration Auditing — production mode, cache, Elasticsearch, cron jobs, logging/monitoring
  • Performance Insights — runtime hotspots, cache effectiveness, DB indexing, static assets
  • Extension Auditing — parse composer.lock, match against known CVEs, flag abandoned modules

USAGE
  php magebean.phar scan --path=/var/www/html
  php magebean.phar scan --path=. --format=html --output=report.html

COMMON OPTIONS
  --path=PATH                 Path to the Magento 2 root to scan (default: current directory)
  --format=html|json          Output format for results (default: html)
  --output=FILE               Save results to a file (auto default based on format)
  --cve-data=PATH             Path to CVE data (JSON/NDJSON or ZIP bundle)
  --control=MB-Cxx            Only run a single control (e.g., MB-C03)

EXAMPLES
  # Scan current directory and print a quick summary
  php magebean.phar scan --path=.

  # Generate a shareable HTML report
  php magebean.phar scan --path=/var/www/html --format=html --output=report.html

  # Use a knowm CVE data when auditing installed extensions. Download: https://magebean.com/download
  php magebean.phar scan --path=. --cve-data=/downloads/magebean-known-cve-bundle-202509.zip

SEE ALSO
  rules:list           List all baseline rules
  rules:validate       Validate rule JSON files before scanning

NOTES
  • Ensure --path points to the Magento root that contains app/etc and vendor.
  • HTML reports are convenient for stakeholders; JSON can be archived in CI.

CONTACT: support@magebean.com

HELP;

    public function __construct()
    {
        parent::__construct('scan');
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Execute a comprehensive audit for a Magento 2 project using 12 controls and 81 rules.')
            ->addUsage('--path=/var/www/html')
            ->addUsage('--path=. --format=html --output=report.html')
            ->addUsage('--path=. --cve-data=./cve/magebean-known-cve-bundle-' . date('Ym') . '.zip')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: html|json', 'html')
            ->addOption('output', null, InputOption::VALUE_OPTIONAL, 'Output file (auto default by format)')
            ->addOption('cve-data', null, InputOption::VALUE_OPTIONAL, 'Path to CVE data (JSON/NDJSON or ZIP bundle)')
            ->addOption('control', null, InputOption::VALUE_OPTIONAL, 'Only run a single control id (e.g., MB-C03)')
            ->addOption(
                'path',
                null,
                InputOption::VALUE_OPTIONAL,
                'Magento root path (defaults to current working directory)',
                getcwd()
            );
    }

    public function getHelp(): string
    {
        return self::HELP;
    }

    protected function execute(InputInterface $in, OutputInterface $out): int
    {

        $io = new SymfonyStyle($in, $out);

        $requestedPath = (string)($in->getOption('path') ?? getcwd());
        $requestedPath = rtrim($requestedPath, DIRECTORY_SEPARATOR);

        try {
            // Cho phép tự dò lên trên tối đa 2 cấp nếu user chỉ định nhầm subfolder
            $magentoRoot = $this->findMagentoRoot($requestedPath, 2);

            if ($magentoRoot === null) {
                throw new \RuntimeException(
                    "Not a valid Magento 2 installation.\n" .
                        "- Expected files: bin/magento, composer.json, app/etc/config.php\n" .
                        "- Checked: {$requestedPath} (and up to 2 parents)"
                );
            }

            // Xác minh chi tiết (composer.json có magento/framework, bin/magento executable, v.v.)
            $this->assertMagento2Root($magentoRoot);

            // ✅ OK -> bắt đầu scan
            $projectPath = (string)$in->getOption('path');
            $format      = strtolower((string)$in->getOption('format'));
            $outFile     = (string)($in->getOption('output') ?? '');
            $controlsOpt = (string)($in->getOption('control') ?? '');
            $cveDataOpt  = trim((string)($in->getOption('cve-data') ?? ''));

            if ($outFile === '') {
                $outFile = match ($format) {
                    'json'  => 'magebean-report.json',
                    default => 'magebean-report.html',
                };
            }

            $cveDataFile = '';
            if ($cveDataOpt !== '') {
                $isZip = (bool)preg_match('/\.zip$/i', $cveDataOpt);
                if ($isZip) {
                    $bm = new BundleManager();
                    $extracted = $bm->extractOsvFileFromZip($cveDataOpt);
                    if ($extracted && is_file($extracted)) {
                        $cveDataFile = $extracted;
                    } else {
                        $out->writeln('<comment>Warning:</comment> Could not extract JSON/NDJSON from zip (cve-data).');
                        if (class_exists(\ZipArchive::class)) {
                            $zip = new \ZipArchive();
                            if ($zip->open($cveDataOpt) === true) {
                                $out->writeln('  Entries in ZIP:');
                                $listed = 0;
                                for ($i = 0; $i < $zip->numFiles && $listed < 50; $i++) {
                                    $st = $zip->statIndex($i);
                                    if (!$st) continue;
                                    $out->writeln('   - ' . $st['name'] . ' (' . $st['size'] . ' bytes)');
                                    $listed++;
                                }
                                $zip->close();
                            }
                        }
                    }
                } else {
                    $cveDataFile = $cveDataOpt;
                }
            }

            // Build context
            $controls = $controlsOpt ? array_map('trim', explode(',', $controlsOpt)) : [];
            $ctx  = new Context($projectPath, $cveDataFile);
            $pack = RulePackLoader::loadAll($controls);
            if (empty($pack['rules'])) {
                $out->writeln('<error>No rules found. Check rules directory or control filter.</error>');
                return Command::FAILURE;
            }

            // 1) Scan rules
            $runner = new ScanRunner($ctx, $pack);
            $result = $runner->run();
            $result['summary']['path'] = $projectPath;

            // 2) CVE audit (nếu có data)
            if ($cveDataFile !== '' && is_file($cveDataFile)) {
                $aud = new CveAuditor($ctx);
                $result['cve_audit'] = $aud->run($cveDataFile);
            } else {
                $result['cve_audit'] = null;
            }
            // 3) Write output
            // ---------- Pretty console output (mimic sample) ----------
            $this->renderPrettySummary($out, $result, $projectPath, $outFile);

            // 4) Render export
            // Write output file
            switch ($format) {
                case 'json':
                    file_put_contents($outFile, json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                    break;
                default:
                    $tpl = $this->resolveTemplatePath();
                    $rep = new HtmlReporter($tpl);
                    $rep->write($result, $outFile);
                    break;
            }

            // exit code theo số fail
            $sum = $result['summary'] ?? [];
            return ((int)($sum['failed'] ?? 0) > 0) ? Command::FAILURE : Command::SUCCESS;

            // TODO: gọi engine scan của bạn, truyền $magentoRoot vào context
            // $result = $this->scanner->run($magentoRoot, ...);

            // Demo:
            // $io->success('Scan completed.');
            return Command::SUCCESS;
        } catch (\RuntimeException $e) {
            $io->error($e->getMessage());
            return Command::FAILURE;
        } catch (\Throwable $e) {
            // Bắt mọi lỗi không lường trước, tránh stacktrace lộ ra ngoài
            $io->error('Unexpected error: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }

    private function renderPrettySummary(OutputInterface $out, array $result, string $path, string $outFile): void
    {
        $sum = $result['summary'] ?? [];
        $total  = (int)($sum['total']  ?? 0);
        $passed = (int)($sum['passed'] ?? 0);

        $env = strtoupper($this->detectMageMode($path));
        $phpShort = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

        // Header
        $out->writeln('');
        $out->writeln(sprintf('<options=bold>Magebean Security Audit v1.0</>        Target: %s', $path));
        $out->writeln(sprintf('Time: %s   PHP: %s   Env: %s', date('Y-m-d H:i'), $phpShort, $env));
        $out->writeln('');

        $failedFindings = array_values(array_filter(($result['findings'] ?? []), fn($f) => empty($f['passed']) === true));
        usort($failedFindings, fn($a, $b) => $this->sevOrder($a['severity'] ?? 'Low') <=> $this->sevOrder($b['severity'] ?? 'Low'));
        $top = array_slice($failedFindings, 0, 10);

        $out->writeln(sprintf('Findings (%d)', count($failedFindings)));
        foreach ($top as $f) {
            $sev = strtoupper((string)($f['severity'] ?? 'LOW'));
            $title = (string)($f['title'] ?? '');
            $msg = (string)($f['message'] ?? '');
            $line = sprintf('[%s] %s', $sev, $msg !== '' ? $msg : $title);
            $out->writeln('  ' . $line);
        }
        if (count($failedFindings) > count($top)) {
            $out->writeln(sprintf('  … and %d more', count($failedFindings) - count($top)));
        }
        $out->writeln('');

        $sevCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($failedFindings as $f) {
            $k = strtolower((string)($f['severity'] ?? 'low'));
            if (!isset($sevCounts[$k])) $k = 'low';
            $sevCounts[$k]++;
        }
        $out->writeln('Summary');
        $out->writeln(sprintf('Passed Rules: %d / %d', $passed, $total));
        $out->writeln(sprintf(
            'Issues: %d Critical, %d High, %d Medium, %d Low',
            $sevCounts['critical'],
            $sevCounts['high'],
            $sevCounts['medium'],
            $sevCounts['low']
        ));

        // CVE console
        if (!empty($result['cve_audit']) && is_array($result['cve_audit'])) {
            $cs = $result['cve_audit']['summary'] ?? [];
            $out->writeln(sprintf(
                "CVE Checks: %d packages against %d known CVEs | Affected: %d",
                (int)($cs['packages_total'] ?? 0),
                (int)($cs['dataset_total'] ?? 0),
                (int)($cs['packages_affected'] ?? 0)
            ));
        } else {
            $out->writeln('');
            $out->writeln('⚠ CVE checks skipped');
            $out->writeln('  → Requires CVE Bundle (--cve-data=magebean-cve-bundle-YYYYMM.zip)');
            $out->writeln('  → Visit https://magebean.com/download');
        }
        $out->writeln('');
        $out->writeln(sprintf('→ Report saved to %s', $outFile));
        $out->writeln('Contact: support@magebean.com');
    }

    private function sevOrder(string $sev): int
    {
        return match (strtolower($sev)) {
            'critical' => 0,
            'high'     => 1,
            'medium'   => 2,
            default    => 3
        };
    }

    private function detectMageMode(string $path): string
    {
        $envFile = rtrim($path, '/') . '/app/etc/env.php';
        if (!is_file($envFile)) return 'UNKNOWN';
        $arr = @include $envFile;
        if (is_array($arr)) {
            if (isset($arr['MAGE_MODE'])) return (string)$arr['MAGE_MODE'];
            // thử key kiểu nested
            $m = $arr['system']['default']['dev']['debug']['environment'] ?? null;
            if (is_string($m) && $m !== '') return $m;
        }
        return 'UNKNOWN';
    }
    private function resolveTemplatePath(): string
    {
        $candidates = [
            __DIR__ . '/../../resources/report-template.html',
            __DIR__ . '/../resources/report-template.html',
            getcwd() . '/resources/report-template.html',
        ];
        foreach ($candidates as $p) {
            if (is_file($p)) return $p;
        }
        $tmp = sys_get_temp_dir() . '/magebean-report-template.html';
        $html = <<<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Magebean Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:16px;}
table{width:100%;border-collapse:collapse;margin-top:12px}
td,th{border:1px solid #eee;padding:8px;vertical-align:top}
.status-pass{color:#0a0;background:#e9fbe9;font-weight:600;text-align:center}
.status-fail{color:#a00;background:#fdeaea;font-weight:600;text-align:center}
summary{cursor:pointer}
</style>
</head><body>
<h2>Magebean Scan</h2>
<div>Completed: {{scan_completed}}</div>
<div>Path: {{path_audited}}</div>
<div>Rules: {{rules_passed}} / {{rules_total}} ({{rules_passed_percent}}%) — Failed: {{rules_failed}}</div>
<div>Findings (Critical: {{findings_critical}}, High: {{findings_high}}, Medium: {{findings_medium}}, Low: {{findings_low}})</div>
<table>
<thead><tr><th>ID</th><th>Control</th><th>Severity</th><th>Status</th><th>Title / Message / Details</th></tr></thead>
<tbody>
{{table}}
</tbody>
</table>
</body></html>
HTML;
        file_put_contents($tmp, $html);
        return $tmp;
    }
    /**
     * Tìm root Magento 2, thử chính path và tối đa $maxParents cấp cha.
     * Trả về path hợp lệ hoặc null nếu không tìm thấy.
     */
    private function findMagentoRoot(string $path, int $maxParents = 0): ?string
    {
        $probe = function (string $p): bool {
            return is_dir($p)
                && is_file($p . '/composer.json')
                && is_file($p . '/bin/magento')
                && (is_file($p . '/app/etc/config.php') || is_file($p . '/app/etc/env.php'));
        };

        $current = $path;
        for ($i = 0; $i <= $maxParents; $i++) {
            if ($probe($current)) {
                return realpath($current) ?: $current;
            }
            $parent = dirname($current);
            if ($parent === $current) {
                break;
            }
            $current = $parent;
        }
        return null;
    }

    /**
     * Xác minh chi tiết cài đặt Magento 2.
     * Ném RuntimeException nếu thiếu thành phần quan trọng.
     */
    private function assertMagento2Root(string $root): void
    {
        // 1) Thư mục tồn tại & đọc được
        if (!is_dir($root) || !is_readable($root)) {
            throw new \RuntimeException("Path '{$root}' is not readable.");
        }

        // 2) Các file/binary quan trọng
        $required = [
            'composer.json',
            'bin/magento',
        ];
        foreach ($required as $rel) {
            $abs = $root . DIRECTORY_SEPARATOR . $rel;
            if (!file_exists($abs)) {
                throw new \RuntimeException("Missing required file: {$rel} at {$root}");
            }
        }

        // 3) Ít nhất phải có một trong hai: app/etc/config.php hoặc app/etc/env.php
        $hasConfig = is_file($root . '/app/etc/config.php') || is_file($root . '/app/etc/env.php');
        if (!$hasConfig) {
            throw new \RuntimeException("Missing app/etc/config.php or app/etc/env.php at {$root}");
        }

        // 4) bin/magento nên executable (không bắt buộc trên mọi OS, nhưng kiểm tra giúp debug)
        $binMagento = $root . '/bin/magento';
        if (!is_readable($binMagento)) {
            throw new \RuntimeException("bin/magento is not readable at {$root}");
        }
        // if (strncasecmp(PHP_OS, 'WIN', 3) !== 0 && !is_executable($binMagento)) {
        //     throw new \RuntimeException("bin/magento is not executable at {$root}");
        // }

        // 5) composer.json phải có "require": { "magento/framework": ... } hoặc name magento/*
        $composer = @file_get_contents($root . '/composer.json');
        if ($composer === false) {
            throw new \RuntimeException("Unable to read composer.json at {$root}");
        }

        $json = json_decode($composer, true);
        if (!is_array($json)) {
            throw new \RuntimeException("Invalid composer.json at {$root}");
        }

        $hasFramework =
            isset($json['require']['magento/framework']) ||
            (isset($json['name']) && is_string($json['name']) && str_starts_with($json['name'], 'magento/'));

        if (!$hasFramework) {
            throw new \RuntimeException(
                "composer.json does not look like a Magento 2 project (missing require: magento/framework)."
            );
        }
    }
}
