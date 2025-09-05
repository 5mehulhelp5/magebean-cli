<?php

declare(strict_types=1);

namespace Magebean\Console;

use Magebean\Engine\Context;
use Magebean\Engine\ScanRunner;
use Magebean\Engine\Reporting\HtmlReporter;
use Magebean\Bundle\BundleManager;
use Magebean\Engine\Cve\CveAuditor;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class ScanCommand extends Command
{
    public function __construct()
    {
        parent::__construct('scan');
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Run Magebean security scan')
            ->addOption('path', null, InputOption::VALUE_REQUIRED, 'Project path to scan', '.')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: html|json|sarif', 'html')
            ->addOption('output', null, InputOption::VALUE_OPTIONAL, 'Output file (auto default by format)')
            ->addOption('cve-data', null, InputOption::VALUE_OPTIONAL, 'Path to CVE data (JSON/NDJSON or ZIP bundle)')
            ->addOption('control', null, InputOption::VALUE_OPTIONAL, 'Only run a single control id (e.g., MB-C03)')
            ->addOption('rules-dir', null, InputOption::VALUE_OPTIONAL, 'Rules directory', __DIR__ . '/../Rules/controls');
    }

    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $projectPath = (string)$in->getOption('path');
        $format      = strtolower((string)$in->getOption('format'));
        $outFile     = (string)($in->getOption('output') ?? '');
        $rulesDir    = (string)$in->getOption('rules-dir');
        $onlyControl = (string)($in->getOption('control') ?? '');
        $cveDataOpt  = trim((string)($in->getOption('cve-data') ?? ''));

        if ($outFile === '') {
            $outFile = match ($format) {
                'json'  => 'magebean-report.json',
                'sarif' => 'magebean-report.sarif.json',
                default => 'magebean-report.html',
            };
        }

        // --cve-data: JSON/NDJSON hoặc .zip (extract)
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
        $ctx  = new Context($projectPath, $cveDataFile);
        $pack = $this->loadRulesPack($rulesDir, $onlyControl);
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
    }

    private function loadRulesPack(string $rulesDir, string $onlyControl): array
    {
        $pack = ['rules' => []];
        $base = realpath($rulesDir) ?: $rulesDir;
        if (!is_dir($base)) {
            $fallback = realpath(__DIR__ . '/../Rules/controls');
            $base = $fallback !== false ? $fallback : $rulesDir;
        }
        $files = glob(rtrim($base, '/') . '/*.json');
        if (!$files) return $pack;

        foreach ($files as $f) {
            $json = json_decode((string)file_get_contents($f), true);
            if (!is_array($json)) continue;
            $rules = $json['rules'] ?? null;
            if (!is_array($rules)) continue;

            if ($onlyControl !== '') {
                $controlId = (string)($json['control'] ?? '');
                if (strcasecmp($controlId, $onlyControl) !== 0) continue;
            }
            foreach ($rules as $r) {
                if (!isset($r['id'], $r['title'], $r['control'], $r['severity'], $r['checks'])) continue;
                $pack['rules'][] = $r;
            }
        }
        return $pack;
    }

    private function renderPrettySummary(OutputInterface $out, array $result, string $path, string $outFile): void
    {
        $sum = $result['summary'] ?? [];
        $total  = (int)($sum['total']  ?? 0);
        $passed = (int)($sum['passed'] ?? 0);
        $failed = (int)($sum['failed'] ?? 0);

        $env = strtoupper($this->detectMageMode($path));
        $phpShort = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

        // Header
        $out->writeln(sprintf('<options=bold>Magebean Security Audit v1.0</>            Target: %s', $path));
        $out->writeln(sprintf('Time: %s      PHP: %s   Env: %s', date('Y-m-d H:i'), $phpShort, $env));
        $out->writeln('');

        // Findings: list các FAIL theo thứ tự severity
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
}
