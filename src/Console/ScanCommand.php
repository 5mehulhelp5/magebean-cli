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
<fg=cyan;options=bold>Execute a comprehensive audit</> for a Magento 2 project using <fg=green;options=bold>12 controls</> and <fg=green;options=bold>81 rules</>.
Doc: <href=https://magebean.com/documentation>magebean.com/documentation</>

<options=bold>What it checks</>
  • <fg=red;options=bold>Security Auditing</> — unsafe code patterns, permissions, world-writable files, XSS, SQLi, SSRF
  • <fg=yellow;options=bold>Configuration Auditing</> — production mode, cache, Elasticsearch, cron jobs, logging/monitoring
  • <fg=blue;options=bold>Performance Insights</> — runtime hotspots, cache effectiveness, DB indexing, static assets
  • <fg=magenta;options=bold>Extension Auditing</> — parse composer.lock, match against known CVEs, flag abandoned modules

<options=bold>USAGE</>
  <fg=green>php magebean.phar scan --path=/var/www/html</>
  <fg=green>php magebean.phar scan --path=. --format=html --output=report.html</>

<options=bold>COMMON OPTIONS</>
  <fg=yellow>--path=PATH</>                 Path to the Magento 2 root to scan (default: current directory)
  <fg=yellow>--format=html|json</>          Output format for results (default: html)
  <fg=yellow>--output=FILE</>               Save results to a file (auto default based on format)
  <fg=yellow>--cve-data=PATH</>             Path to CVE data (JSON/NDJSON or ZIP bundle)
  <fg=yellow>--rules=MB-Rxx,MB-Rxx</>       Only run a list of specified rules (e.g., MB-R03,)

<options=bold>EXAMPLES</>
  # Scan current directory and print a quick summary
  <fg=green>php magebean.phar scan --path=.</>

  # Generate a shareable HTML report
  <fg=green>php magebean.phar scan --path=/var/www/html --format=html --output=report.html</>

  # Use a known CVE data when auditing installed extensions.
  # Download: <href=https://magebean.com/download>magebean.com/download</>
  <fg=green>php magebean.phar scan --path=. --cve-data=/downloads/magebean-known-cve-bundle-202509.zip</>

<options=bold>SEE ALSO</>
  <fg=cyan>rules:list</>           List all baseline rules

<options=bold>NOTES</>
  • Ensure <fg=yellow>--path</> points to the Magento root that contains app/etc and vendor.
  • <fg=blue>HTML reports</> are convenient for stakeholders; <fg=yellow>JSON</> can be archived in CI.

CONTACT: <href=mailto:support@magebean.com>support@magebean.com</>

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
            ->addUsage('--url=https://store.example')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: html|json', 'html')
            ->addOption('output', null, InputOption::VALUE_OPTIONAL, 'Output file (auto default by format)')
            ->addOption('cve-data', null, InputOption::VALUE_OPTIONAL, 'Path to CVE data (JSON/NDJSON or ZIP bundle)')
            ->addOption('standard', null, InputOption::VALUE_OPTIONAL, 'Report standard: magebean (default) | owasp | pci | cwe', 'magebean')
            ->addOption('rules', null, InputOption::VALUE_OPTIONAL, 'Comma-separated rule IDs to run (e.g., MB-R036,MB-R020)')
            ->addOption('path', null, InputOption::VALUE_OPTIONAL, 'Magento root path (omit to auto-detect from current working directory)', '')
            ->addOption('url',  null, InputOption::VALUE_OPTIONAL, 'Magento storefront URL to audit (external mode)');
    }

    public function getHelp(): string
    {
        return self::HELP;
    }

    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $io = new SymfonyStyle($in, $out);

        $pathOpt = (string)($in->getOption('path') ?? '');
        $requestedPath = $pathOpt !== '' ? $pathOpt : getcwd();
        $requestedPath = self::normalize($requestedPath);

        $urlOpt = (string)($in->getOption('url') ?? '');
        if ($urlOpt !== '' && $pathOpt !== '') {
            $out->writeln('<error>Usage error:</error> You must provide either --path or --url, not both.');
            return 64; // EX_USAGE
        }
        if ($urlOpt !== '') {
            // URL mode (ExternalMagentoAudit)
            $url = trim($urlOpt);
            if (!preg_match('/^https?:\\/\\//i', $url)) {
                $out->writeln('<error>Invalid --url: must start with http:// or https://</error>');
                return Command::FAILURE;
            }
            $format      = (string)$in->getOption('format');
            $outFile     = (string)($in->getOption('output') ?? '');
            $standard    = 'magebean';
            $rulesOpt    = (string)($in->getOption('rules') ?? '');

            if ($outFile === '') {
                $outFile = match ($format) {
                    'json'  => 'magebean-report.json',
                    default => 'magebean-report.html',
                };
            }

             // -------------------------
            // Preflight: Magento 2 detect (fail-fast nếu không phải M2)
            // -------------------------
            $det = $this->detectMagento2ByUrl($url, 7000);
            if (!$det['ok']) {
                $out->writeln('<error>Target does not appear to be a Magento 2 storefront.</error>');
                $out->writeln(sprintf('Confidence: <comment>%d%%</comment>', (int)$det['confidence']));
                if (!empty($det['signals'])) {
                    $out->writeln('Signals:');
                    foreach ($det['signals'] as $sig) {
                        $out->writeln('  - ' . $sig);
                    }
                }
                $out->writeln('<comment>Aborting.</comment> If this is a Magento site behind CDN/WAF that strips headers, try scanning the canonical store domain or whitelist our User-Agent.');
                return Command::FAILURE;
            }
            // (tiếp tục scan nếu ok)

            $ctx  = new Context(getcwd(), '', ['url' => $url]);
            $pack = RulePackLoader::loadExternalMagento();

            // --rules filter (optional)
            $requestedIds = [];
            if ($rulesOpt !== '') {
                $requestedIds = array_values(array_unique(array_filter(array_map('trim', explode(',', $rulesOpt)))));
                if ($requestedIds) {
                    $byId = [];
                    foreach ($pack['rules'] as $r) {
                        $byId[strtoupper((string)($r['id'] ?? ''))] = $r;
                    }
                    $selected = [];
                    $unknown  = [];
                    foreach ($requestedIds as $id) {
                        $key = strtoupper($id);
                        if (isset($byId[$key])) $selected[] = $byId[$key];
                        else $unknown[] = $id;
                    }
                    foreach ($unknown as $id) {
                        $out->writeln(sprintf('<comment>Unknown rule id:</comment> %s', $id));
                    }
                    if ($selected) {
                        $pack['rules'] = $selected;
                    } else {
                        $out->writeln('<error>No valid rules matched the --rules filter.</error>');
                        return Command::FAILURE;
                    }
                }
            }

            if (empty($pack['rules'])) {
                $out->writeln('<error>No rules found for ExternalMagentoAudit.</error>');
                return Command::FAILURE;
            }

            // 1) Scan rules (URL)
            $runner = new ScanRunner($ctx, $pack);
            $result = $runner->run();
            // attach meta
            $result['meta']['standard']     = $standard;
            $result['meta']['rules_filter'] = $requestedIds;
            $result['summary']['path']      = 'URL: ' . $url;

            $projectPath = 'URL: ' . $url;
            // No CVE in URL mode
            $result['cve_audit'] = null;

            // 3) Write output (reuse existing templating)
            // ---------- Pretty console output (mimic sample) ----------
            $this->renderPrettySummary($out, $result, $projectPath, $outFile);

            // 4) Render export
            // Write output file (dùng HtmlReporter như --path)
            if ($format === 'json') {
                file_put_contents($outFile, json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                $out->writeln(sprintf('<info>JSON report written:</info> %s', $outFile));
            } else {
                $tpl = $this->resolveTemplatePath();
                $rep = new HtmlReporter($tpl);
                $rep->write($result, $outFile);
            }
            // Exit code giống nhánh --path (để CI nhận biết fail)
            $sum = $result['summary'] ?? [];
            return ((int)($sum['failed'] ?? 0) > 0) ? Command::FAILURE : Command::SUCCESS;
        }

        // Nếu path không trỏ tới Magento root, thử leo lên tối đa 4 cấp
        if (!self::isMagentoRoot($requestedPath)) {
            $detected = self::detectMagentoRoot($requestedPath, 4);
            if ($detected !== null) {
                $out->writeln(sprintf('<info>Detected Magento root:</info> %s', $detected));
                $requestedPath = $detected;
            } else {
                $out->writeln("<error>Cannot locate Magento root from: {$requestedPath}</error>");
                $out->writeln('Hint: run from your Magento root or pass --path=/absolute/path/to/magento');
                return Command::FAILURE;
            }
        }

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
            $projectPath = (string)$requestedPath;
            $format      = (string)$in->getOption('format');
            $outFile     = (string)($in->getOption('output') ?? '');
            $cveDataFile = (string)($in->getOption('cve-data') ?? '');
            $standard    = strtolower((string)($in->getOption('standard') ?? 'magebean'));
            $rulesOpt    = (string)($in->getOption('rules') ?? '');

            // validate standard
            $allowed = ['magebean', 'owasp', 'pci', 'cwe'];
            if (!in_array($standard, $allowed, true)) {
                $out->writeln('<error>Invalid --standard. Allowed: magebean | owasp | pci | cwe</error>');
                return Command::FAILURE;
            }

            if ($outFile === '') {
                $outFile = match ($format) {
                    'json'  => 'magebean-report.json',
                    default => 'magebean-report.html',
                };
            }

            if ($cveDataFile !== '') {
                $isZip = (bool)preg_match('/\.zip$/i', $cveDataFile);
                if ($isZip) {
                    $bm = new BundleManager();
                    $extracted = $bm->extractOsvFileFromZip($cveDataFile);
                    if ($extracted && is_file($extracted)) {
                        $cveDataFile = $extracted;
                    } else {
                        $out->writeln('<comment>Warning:</comment> Could not extract JSON/NDJSON from zip (cve-data).');
                        if (class_exists(\ZipArchive::class)) {
                            $zip = new \ZipArchive();
                            if ($zip->open($cveDataFile) === true) {
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
                }
            }

            $ctx  = new Context($projectPath, $cveDataFile);

            $pack = RulePackLoader::loadAll();

            // filter by --rules (comma-separated IDs)
            $requestedIds = [];
            if ($rulesOpt !== '') {
                $requestedIds = array_values(array_unique(array_filter(array_map('trim', explode(',', $rulesOpt)))));
                if ($requestedIds) {
                    $byId = [];
                    foreach ($pack['rules'] as $r) {
                        $byId[strtoupper((string)($r['id'] ?? ''))] = $r;
                    }
                    $selected = [];
                    $unknown  = [];
                    foreach ($requestedIds as $id) {
                        $key = strtoupper($id);
                        if (isset($byId[$key])) $selected[] = $byId[$key];
                        else $unknown[] = $id;
                    }
                    foreach ($unknown as $id) {
                        $out->writeln(sprintf('<comment>Unknown rule id:</comment> %s', $id));
                    }
                    if ($selected) {
                        // giữ nguyên controls pack để render/summary, nhưng thay tập rules đã chọn
                        $pack['rules'] = $selected;
                    } else {
                        $out->writeln('<error>No valid rules matched the --rules filter.</error>');
                        return Command::FAILURE;
                    }
                }
            }

            if (empty($pack['rules'])) {
                $out->writeln('<error>No rules found. Check rules directory or control filter.</error>');
                return Command::FAILURE;
            }

            // 1) Scan rules
            $runner = new ScanRunner($ctx, $pack);
            $result = $runner->run();
            // attach meta
            $result['meta']['standard']    = $standard;
            $result['meta']['rules_filter'] = $requestedIds;
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
        $sum    = $result['summary'] ?? [];
        $total  = (int)($sum['total']  ?? 0);
        $passed = (int)($sum['passed'] ?? 0);

        $env      = strtoupper($this->detectMageMode($path));
        $isExternal = str_starts_with($path, 'URL:');
        $env        = $isExternal ? 'EXTERNAL' : strtoupper($this->detectMageMode($path));
        $phpShort = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

        // Helpers
        $sevBadge = function (string $sev): string {
            $sev = strtoupper($sev);
            return match ($sev) {
                'CRITICAL' => '<fg=white;bg=red;options=bold>[CRITICAL]</>',
                'HIGH'     => '<fg=red;options=bold>[HIGH]</>',
                'MEDIUM'   => '<fg=yellow;options=bold>[MEDIUM]</>',
                'LOW'      => '<fg=blue;options=bold>[LOW]</>',
                default    => sprintf('[%s]', $sev),
            };
        };
        $envTag = function (string $env) {
            return match ($env) {
                'PRODUCTION' => '<fg=white;bg=green;options=bold>PRODUCTION</>',
                'DEVELOPER'  => '<fg=yellow;options=bold>DEVELOPER</>',
                'DEFAULT'    => '<fg=cyan>DEFAULT</>',
                'EXTERNAL'   => '<fg=blue;options=bold>EXTERNAL</>',
                default      => sprintf('<fg=magenta>%s</>', $env),
            };
        };

        // Header
        $out->writeln('');
        $out->writeln(sprintf('<fg=cyan;options=bold>Magebean Security Audit v1.0</>        Target: <fg=green>%s</>', $path));
        $standard = (string)($result['meta']['standard'] ?? 'magebean');
        $out->writeln(sprintf('Standard: <info>%s</info>', strtoupper($standard)));
        $out->writeln(sprintf('Time: <comment>%s</comment>   PHP: <info>%s</info>   Env: %s', date('Y-m-d H:i'), $phpShort, $envTag($env)));
        $out->writeln('');

        // Findings
        $failedFindings = array_values(array_filter(($result['findings'] ?? []), fn($f) => empty($f['passed']) === true));
        usort($failedFindings, fn($a, $b) => $this->sevOrder($a['severity'] ?? 'Low') <=> $this->sevOrder($b['severity'] ?? 'Low'));
        $top = array_slice($failedFindings, 0, 10);

        $out->writeln(sprintf('<options=bold>Findings</> (<fg=red>%d</>)', count($failedFindings)));
        foreach ($top as $f) {
            $sev   = strtoupper((string)($f['severity'] ?? 'LOW'));
            $title = (string)($f['title'] ?? '');
            $msg   = (string)($f['message'] ?? '');
            $line  = sprintf('%s %s', $sevBadge($sev), $msg !== '' ? $msg : $title);
            $out->writeln('  ' . $line);
        }
        if (count($failedFindings) > count($top)) {
            $out->writeln(sprintf('  <comment>… and %d more</comment>', count($failedFindings) - count($top)));
        }
        $out->writeln('');

        // Severity counts
        $sevCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($failedFindings as $f) {
            $k = strtolower((string)($f['severity'] ?? 'low'));
            if (!isset($sevCounts[$k])) $k = 'low';
            $sevCounts[$k]++;
        }

        // Summary (colored)
        $out->writeln('<options=bold>Summary</>');
        $out->writeln(sprintf('Passed Rules: <info>%d</info> / <info>%d</info>', $passed, $total));
        $out->writeln(sprintf(
            'Issues: %s %d Critical</> | %s %d High</> | %s %d Medium</> | %s %d Low</>',
            '<fg=white;bg=red;options=bold>',
            $sevCounts['critical'],
            '<fg=red;options=bold>',
            $sevCounts['high'],
            '<fg=yellow;options=bold>',
            $sevCounts['medium'],
            '<fg=blue;options=bold>',
            $sevCounts['low'],
        ));

        // CVE console:
        if (!$isExternal) {
            if (!empty($result['cve_audit']) && is_array($result['cve_audit'])) {
                $cs = $result['cve_audit']['summary'] ?? [];
                $out->writeln(sprintf(
                    "\n<info>✓ CVE Checks</info>: %d packages against %d known CVEs | Affected: <fg=red;options=bold>%d</>",
                    (int)($cs['packages_total'] ?? 0),
                    (int)($cs['dataset_total'] ?? 0),
                    (int)($cs['packages_affected'] ?? 0)
                ));
            } else {
                $out->writeln('');
                $out->writeln('<comment>⚠ CVE checks skipped</comment>');
                $out->writeln('  → Requires CVE Bundle (<comment>--cve-data=magebean-cve-bundle-YYYYMM.zip</comment>)');
                $out->writeln('  → Visit <href=https://magebean.com/download>magebean.com/download</>');
            }
        }

        // Footer
        $out->writeln('');
        $out->writeln(sprintf('→ <info>Report saved to</info> <href=file://%1$s>%1$s</>', $outFile));
        $out->writeln('Contact: <href=mailto:support@magebean.com>support@magebean.com</>');
        $out->writeln('');
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

    private static function normalize(string $p): string
    {
        $rp = realpath($p);
        return $rp !== false ? rtrim($rp, DIRECTORY_SEPARATOR) : rtrim($p, DIRECTORY_SEPARATOR);
    }

    private static function isMagentoRoot(string $dir): bool
    {
        // Tiêu chí an toàn: có cả env.php và bin/magento
        return is_file($dir . '/app/etc/env.php') && is_file($dir . '/bin/magento');
    }

    private static function detectMagentoRoot(string $startDir, int $maxUp = 4): ?string
    {
        $dir = self::normalize($startDir);
        for ($i = 0; $i <= $maxUp; $i++) {
            if (self::isMagentoRoot($dir)) {
                return $dir;
            }
            $parent = dirname($dir);
            if ($parent === $dir) break; // đến root FS
            $dir = $parent;
        }
        return null;
    }

    private function detectMagento2ByUrl(string $url, int $timeoutMs = 6000): array
    {
        [$ok, $err, $resp] = $this->httpFetch($url, $timeoutMs);
        $signals = [];
        if (!$ok) {
            return ['ok' => false, 'confidence' => 0, 'signals' => ["Fetch error: {$err}"]];
        }
        $headers = array_change_key_case((array)($resp['headers'] ?? []), CASE_LOWER);
        $body    = (string)($resp['body'] ?? '');
        $conf    = 0;

        // 1) Headers đặc trưng Magento 2
        $hasMagentoHdr = false;
        foreach (['x-magento-tags','x-magento-cache-debug','x-magento-advanced'] as $hk) {
            if (array_key_exists($hk, $headers)) { $hasMagentoHdr = true; break; }
        }
        if ($hasMagentoHdr) { $conf += 60; $signals[] = 'Header: X-Magento-* present'; }
        else { $signals[] = 'Header: X-Magento-* NOT present'; }

        // 2) Token phổ biến trong HTML/JS của M2
        $bodyLc = strtolower($body);
        $hitBody = false;
        // data-mage-init (UI components), mage-cache-storage (LS), /static/version (asset), /static/frontend/ (theme assets)
        $patterns = [
            '~data-mage-init~i',
            '~mage-cache-storage~i',
            '~/static/version~i',
            '~/static/frontend/~i',         // theme assets
            '~/static/_cache/merged/~i',    // merged/bundled static
            '~window\\.checkoutConfig~i',
            '~Magento~i'
        ];
        foreach ($patterns as $rx) {
            if (preg_match($rx, $bodyLc) === 1) { $hitBody = true; break; }
        }
        if ($hitBody) { $conf += 40; $signals[] = 'HTML token(s): Magento UI/asset markers found'; }
        else { $signals[] = 'HTML token(s): no typical Magento markers'; }

        // 3) URL canonical/asset gợi ý
        $assetHits = [];
        if (preg_match('~/static/version\\d+/~i', $bodyLc))         $assetHits[] = '/static/version';
        if (preg_match('~/pub/static/~i', $bodyLc))                 $assetHits[] = '/pub/static';
        // /static/frontend/<Vendor>/<theme>/<locale>/...  (vd: Dowlis/cisco2/en_US/…)
        if (
            preg_match('~/static/frontend/[^"\']+/(en_[A-Z]{2}|[a-z]{2}_[A-Z]{2})/~i', $bodyLc)
            || preg_match('~/static/frontend/~i', $bodyLc)
        ) {
            $assetHits[] = '/static/frontend';
        }
        if (preg_match('~/static/_cache/merged/~i', $bodyLc))       $assetHits[] = '/static/_cache/merged';
        if (preg_match('~luma-icons\\.(woff2|woff|ttf)~i', $bodyLc))$assetHits[] = 'Luma-Icons';

        if ($assetHits) {
            // +10 điểm mỗi clue (tối đa +30), riêng Luma-Icons cộng thêm +20 (Magento đặc trưng)
            $base  = min(30, count($assetHits) * 10);
            $bonus = in_array('Luma-Icons', $assetHits, true) ? 20 : 0;
            $conf += ($base + $bonus);
            $signals[] = 'Asset clues: ' . implode(', ', $assetHits);
        } else {
            $signals[] = 'Asset clues: none';
        }

        // 4) Tránh false-positive với WordPress/Woo/Shopify
        $nonMagentoHints = 0;
        if (str_contains($bodyLc, 'wp-content') || str_contains($bodyLc, 'wp-json')) $nonMagentoHints++;
        if (str_contains($bodyLc, 'cdn.shopify.com') || str_contains($bodyLc, 'x-shopify')) $nonMagentoHints++;
        if ($nonMagentoHints > 0) { $conf = max(0, $conf - 40); $signals[] = 'Non-Magento hints present (WordPress/Shopify)'; }

        if ($conf > 100) $conf = 100;
        return ['ok' => $conf >= 60, 'confidence' => $conf, 'signals' => $signals];
    }

    /**
     * HTTP fetch đơn giản (curl nếu có, fallback streams).
     * @return array{0:bool,1:string,2:array{status:int,headers:array,body:string,final_url:string}}
     */
    private function httpFetch(string $url, int $timeoutMs = 6000): array
    {
        $ua = 'Magebean-CLI/1.0';
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_CUSTOMREQUEST => 'GET',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_TIMEOUT_MS => $timeoutMs,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_USERAGENT => $ua,
            ]);
            $resp = curl_exec($ch);
            if ($resp === false) {
                $err = curl_error($ch);
                curl_close($ch);
                return [false, $err, ['status' => 0, 'headers' => [], 'body' => '', 'final_url' => $url]];
            }
            $status  = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $hdrSize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $hdrRaw  = substr((string)$resp, 0, $hdrSize);
            $body    = substr((string)$resp, $hdrSize);
            $final   = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            curl_close($ch);
            return [true, '', ['status' => $status, 'headers' => $this->parseHeadersAssoc($hdrRaw), 'body' => $body, 'final_url' => $final]];
        }
        // streams fallback
        $opts = ['http' => [
            'method' => 'GET',
            'header' => "User-Agent: {$ua}\r\n",
            'ignore_errors' => true,
            'timeout' => max(1, (int)ceil($timeoutMs/1000)),
        ]];
        $ctx = stream_context_create($opts);
        $body = @file_get_contents($url, false, $ctx);
        $rawHeaders = is_array($http_response_header ?? null) ? implode("\r\n", $http_response_header) : '';
        $status = 0;
        if (preg_match('~HTTP/\S+\s+(\d{3})~', $rawHeaders, $m)) $status = (int)$m[1];
        if ($body === false) return [false, 'HTTP error (stream)', ['status' => 0, 'headers' => [], 'body' => '', 'final_url' => $url]];
        return [true, '', ['status' => $status, 'headers' => $this->parseHeadersAssoc($rawHeaders), 'body' => $body, 'final_url' => $url]];
    }

    /** Parse header raw thành assoc lowercase */
    private function parseHeadersAssoc(string $raw): array
    {
        $out = [];
        foreach (preg_split("~\r?\n~", $raw) as $line) {
            if (strpos($line, ':') !== false) {
                [$k, $v] = array_map('trim', explode(':', $line, 2));
                $k = strtolower($k);
                // gộp header trùng (vd: Set-Cookie)
                if (isset($out[$k])) {
                    if (is_array($out[$k])) $out[$k][] = $v; else $out[$k] = [$out[$k], $v];
                } else {
                    $out[$k] = $v;
                }
            }
        }
        return $out;
    }
}
