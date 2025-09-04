<?php declare(strict_types=1);

namespace Magebean\Console;

use Magebean\Engine\Context;
use Magebean\Engine\ScanRunner;
use Magebean\Engine\Reporting\HtmlReporter;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class ScanCommand extends Command
{
    public function __construct()
    {
        parent::__construct('scan'); // luôn có tên lệnh
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Run Magebean security scan')
            ->addOption('path', null, InputOption::VALUE_REQUIRED, 'Project path to scan', '.')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: html|json|sarif', 'html')
            ->addOption('output', null, InputOption::VALUE_OPTIONAL, 'Output file (auto default by format)')
            ->addOption('vuln-data', null, InputOption::VALUE_OPTIONAL, 'Path to OSV export (JSON) for offline audit')
            ->addOption('control', null, InputOption::VALUE_OPTIONAL, 'Only run a single control id (e.g., MB-C03)')
            ->addOption('rules-dir', null, InputOption::VALUE_OPTIONAL, 'Rules directory', __DIR__.'/../Rules/controls')
            ->addOption('show-fail', null, InputOption::VALUE_NONE, 'Print failed rule messages/evidence to console'); // vẫn giữ tuỳ chọn cũ
    }

    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $projectPath = (string)$in->getOption('path');
        $format      = strtolower((string)$in->getOption('format'));
        $outFile     = (string)($in->getOption('output') ?? '');
        $rulesDir    = (string)$in->getOption('rules-dir');
        $onlyControl = (string)($in->getOption('control') ?? '');
        $vulnData    = (string)($in->getOption('vuln-data') ?? '');

        if ($outFile === '') {
            $outFile = match ($format) {
                'json'  => 'magebean-report.json',
                'sarif' => 'magebean-report.sarif.json',
                default => 'magebean-report.html',
            };
        }

        // Context (đưa --vuln-data)
        $ctx  = new Context($projectPath, $vulnData);
        $pack = $this->loadRulesPack($rulesDir, $onlyControl);
        if (empty($pack['rules'])) {
            $out->writeln('<error>No rules found. Check rules directory or control filter.</error>');
            return Command::FAILURE;
        }

        // Run
        $runner = new ScanRunner($ctx, $pack);
        $result = $runner->run();
        $result['summary']['path'] = $projectPath;

        // Write output file
        switch ($format) {
            case 'json':
                file_put_contents($outFile, json_encode($result, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
                break;
            case 'sarif':
                if (class_exists('\\Magebean\\Engine\\Reporting\\SarifReporter')) {
                    /** @var \Magebean\Engine\Reporting\SarifReporter $rep */
                    $rep = new \Magebean\Engine\Reporting\SarifReporter();
                    $rep->write($result, $outFile);
                } else {
                    file_put_contents($outFile, json_encode($result, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
                }
                break;
            default:
                $tpl = $this->resolveTemplatePath();
                $rep = new HtmlReporter($tpl);
                $rep->write($result, $outFile);
                break;
        }

        // Pretty console output giống mẫu
        $this->renderPrettySummary($out, $result, $projectPath, $outFile, $vulnData);

        // exit code theo số fail
        $sum = $result['summary'] ?? [];
        return ((int)($sum['failed'] ?? 0) > 0) ? Command::FAILURE : Command::SUCCESS;
    }

    private function loadRulesPack(string $rulesDir, string $onlyControl): array
    {
        $pack = ['rules' => []];
        $base = realpath($rulesDir) ?: $rulesDir;
        if (!is_dir($base)) {
            $fallback = realpath(__DIR__.'/../Rules/controls');
            $base = $fallback !== false ? $fallback : $rulesDir;
        }
        $files = glob(rtrim($base, '/').'/*.json');
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

    private function resolveTemplatePath(): string
    {
        $candidates = [
            __DIR__.'/../../resources/report-template.html',
            __DIR__.'/../resources/report-template.html',
            getcwd().'/resources/report-template.html',
        ];
        foreach ($candidates as $p) {
            if (is_file($p)) return $p;
        }
        $tmp = sys_get_temp_dir().'/magebean-report-template.html';
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

    // ---------- Pretty console like sample ----------

    private function renderPrettySummary(OutputInterface $out, array $result, string $path, string $outFile, string $vulnData): void
    {
        $sum = $result['summary'] ?? [];
        $total  = (int)($sum['total']  ?? 0);
        $passed = (int)($sum['passed'] ?? 0);
        $failed = (int)($sum['failed'] ?? 0);

        $env = strtoupper($this->detectMageMode($path));
        $phpShort = PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;

        // Header
        $out->writeln(sprintf('<options=bold>Magebean Security Audit v1.0</>            Target: %s', $path));
        $out->writeln(sprintf('Time: %s      PHP: %s   Env: %s', date('Y-m-d H:i'), $phpShort, $env));
        $out->writeln('');

        // CVE/OSV section
        if ($vulnData === '') {
            $out->writeln('<comment>⚠ CVE check skipped</comment>');
            $out->writeln('  → Requires OSV export (use --vuln-data=rules/osv-export.json)');
            $out->writeln('  → See https://osv.dev or bundle update docs');
            $out->writeln('');
        }

        // Findings: list các FAIL theo thứ tự severity
        $failedFindings = array_values(array_filter(($result['findings'] ?? []), fn($f) => empty($f['passed']) === true));
        usort($failedFindings, fn($a,$b) => $this->sevOrder($a['severity'] ?? 'Low') <=> $this->sevOrder($b['severity'] ?? 'Low'));
        $top = array_slice($failedFindings, 0, 10);

        $out->writeln(sprintf('Findings (%d)', count($failedFindings)));
        foreach ($top as $f) {
            $sev = strtoupper((string)($f['severity'] ?? 'LOW'));
            $title = (string)($f['title'] ?? '');
            $msg = (string)($f['message'] ?? '');
            $line = sprintf('[%s] %s', $sev, $msg !== '' ? $msg : $title);
            $out->writeln('  '.$line);
        }
        if (count($failedFindings) > count($top)) {
            $out->writeln(sprintf('  … and %d more', count($failedFindings) - count($top)));
        }
        $out->writeln('');

        // Summary + issues by severity
        $sevCounts = ['critical'=>0,'high'=>0,'medium'=>0,'low'=>0];
        foreach ($failedFindings as $f) {
            $k = strtolower((string)($f['severity'] ?? 'low'));
            if (!isset($sevCounts[$k])) $k = 'low';
            $sevCounts[$k]++;
        }
        $out->writeln('Summary');
        $out->writeln(sprintf('Passed Rules: %d / %d', $passed, $total));
        $out->writeln(sprintf(
            'Issues: %d Critical, %d High, %d Medium, %d Low',
            $sevCounts['critical'], $sevCounts['high'], $sevCounts['medium'], $sevCounts['low']
        ));
        $out->writeln('');
        $out->writeln(sprintf('→ Report saved to %s', $outFile));
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
        $envFile = rtrim($path,'/').'/app/etc/env.php';
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

    private function printFailedRules(OutputInterface $out, array $result): void
    {
        // vẫn giữ cho -v hoặc --show-fail (đã không dùng trong pretty mặc định)
        foreach (($result['findings'] ?? []) as $f) {
            if (!empty($f['passed'])) continue;
            $out->writeln('');
            $out->writeln(sprintf('<error>FAIL %s [%s] %s</error>',
                (string)($f['id'] ?? ''),
                (string)($f['control'] ?? ''),
                (string)($f['title'] ?? '')
            ));
            if (!empty($f['message'])) {
                $out->writeln('  '.$f['message']);
            }
            foreach (($f['details'] ?? []) as $d) {
                $ok = (bool)($d[2] ?? false);
                if ($ok) continue;
                $out->writeln(sprintf('  - %s: %s', (string)$d[0], (string)$d[1]));
            }
            if (!empty($f['evidence']) && is_array($f['evidence'])) {
                $out->writeln('  Evidence:');
                foreach (array_slice($f['evidence'], 0, 8) as $ev) {
                    $line = is_array($ev) ? implode(' | ', array_map('strval', $ev)) : (string)$ev;
                    $out->writeln('    • '.$line);
                }
            }
        }
    }
}
