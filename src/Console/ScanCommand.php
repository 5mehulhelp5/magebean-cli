<?php

declare(strict_types=1);

namespace Magebean\Console;

use Magebean\Engine\{ScanDiagnostic, ScanRequest, ScanTargetResolver, ScanReportAssembler, ScanExitPolicy};
use Magebean\Engine\ScanPlanner;
use Magebean\Engine\ScanService;
use Magebean\Engine\Checks\CheckRegistry;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class ScanCommand extends Command
{
    protected static $defaultName = 'scan';

    private const MODE_REMOTE = 'REMOTE';

    /** Keep help text in one place */
    private const HELP = <<<'HELP'
<fg=cyan;options=bold>Audit Magento 2 production readiness</> using selectable Magebean security profiles.
The default <fg=green;options=bold>basic</> profile runs 21 fast, low-noise checks.
Docs: <href=https://magebean.com/documentation>magebean.com/documentation</>

<options=bold>USAGE</>
  <fg=green>php magebean.phar scan [--path=PATH] [--url=URL] [options]</>

<options=bold>TARGET MODES</>
  • <fg=green;options=bold>LOCAL</> — --path only, or omit both target options to auto-detect the Magento root
  • <fg=blue;options=bold>REMOTE</> — --url only; verifies Magento and runs externally observable rules
  • <fg=magenta;options=bold>HYBRID</> — --path plus --url; combines local and HTTP evidence
  • Basic contains 21 local rules and 9 applicable remote rules.
  • Use --profile=baseline remotely to run all 10 external rules.

<options=bold>PROFILES</>
  <fg=yellow>basic</>      Default; 21 basic production security and operations checks.
  <fg=yellow>asvs-l1</>    32 rules by default; 60 including 28 human-verification rules.
  <fg=yellow>asvs-l2</>    73 rules by default; 183 including 110 human-verification rules.
  <fg=yellow>asvs-l3</>    80 rules by default; 259 including 179 human-verification rules.
  <fg=yellow>owasp</>      77 application-security rules mapped to OWASP Top 10 2025.
  <fg=yellow>pci</>        67 rules by default; 68 including 1 human-verification rule.
  <fg=yellow>hardening</>  91 rules by default; 92 with human verification enabled.
  <fg=yellow>baseline</>   113 automated rules by default; 371 including manual review. Aliases: all, magebean.
  <fg=yellow>FILE</>       Custom JSON path or a profile under .magebean/profiles.

<options=bold>COMMAND OPTIONS</>
  <fg=yellow>--path=PATH</>                     Magento root. Omit to search from the current directory.
  <fg=yellow>--url=URL</>                       Absolute storefront URL; selects REMOTE or HYBRID mode.
  <fg=yellow>--profile=PROFILE|FILE</>          Built-in or custom profile. Default: basic.
  <fg=yellow>--include-manual-review</>           Include human-review rules; excluded by default.
  <fg=yellow>--capabilities=NAME,NAME</>         Enable contextual profile rules (for example graphql,oauth_oidc).
  <fg=yellow>--controls=MB-Cxx,MB-Cxx</>       Restrict the loaded pack to control IDs.
  <fg=yellow>--rules=MB-Rxxx,MB-Rxxx</>         Run listed rule IDs directly from the available catalog; bypasses profile selection.
  <fg=yellow>--exclude-rules=MB-Rxxx,...</>     Remove rules after profile and project configuration.
  <fg=yellow>--config=FILE</>                   Project policy file; auto-detected in LOCAL/HYBRID.
  <fg=yellow>--pci-context=FILE</>               PCI applicability context JSON (PCI profile only).
  <fg=yellow>--pci-evidence=FILE</>              Structured external evidence JSON (PCI profile only).
  <fg=yellow>--pci-report=FILE</>                Write the PCI evidence-readiness report as JSON.
  <fg=yellow>--standard=NAME</>                 Legacy selector: magebean, owasp, pci, or cwe.
                                          Prefer --profile; explicit --profile takes precedence.

<options=bold>GLOBAL OPTIONS</>
  <fg=yellow>-h, --help</>           Show help.
  <fg=yellow>-V, --version</>        Show version.
  <fg=yellow>-q, --quiet</>          Show errors only.
  <fg=yellow>--silent</>             Suppress all output.
  <fg=yellow>--ansi|--no-ansi</>     Force or disable ANSI formatting.
  <fg=yellow>-n, --no-interaction</> Disable interactive questions.
  <fg=yellow>-v|vv|vvv</>            Increase verbosity.

<options=bold>EXAMPLES</>
  # Default basic scan with Magento root auto-detection
  <fg=green>php magebean.phar scan</>

  # LOCAL, REMOTE, and HYBRID scans
  <fg=green>php magebean.phar scan --path=/var/www/magento</>
  <fg=green>php magebean.phar scan --url=https://store.example.com</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --url=https://store.example.com</>

  # ASVS Level 1, application security, payment readiness, deep hardening, or full catalog
  <fg=green>php magebean.phar scan --path=/var/www/magento --profile=asvs-l1</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --url=https://store.example.com --profile=asvs-l2 --include-manual-review --capabilities=graphql</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --url=https://store.example.com --profile=asvs-l3 --include-manual-review</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --profile=owasp</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --profile=pci</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --profile=hardening</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --profile=baseline</>

  # Rule and control filters
  <fg=green>php magebean.phar scan --path=/var/www/magento --rules=MB-R031,MB-R037</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --rules=MB-R020</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --profile=hardening --controls=MB-C01,MB-C05</>
  <fg=green>php magebean.phar scan --path=/var/www/magento --config=.magebean.yml --exclude-rules=MB-R032</>

<options=bold>SELECTION ORDER</>
  Target pack → project policy → (--rules OR profile) → --exclude-rules.
  --rules bypasses profile selection and selects IDs directly from the available catalog.

<options=bold>NOTES</>
  • REMOTE results cover only publicly observable behavior; local-only checks are omitted.
  • --path must point to, or be below, a Magento root containing app/etc and vendor.
  • Unknown rule IDs in a custom profile fail validation against a full local pack.
  • Confirmed findings determine the process exit code.

<options=bold>SEE ALSO</>
  <fg=cyan>rules:list --help</>  List and filter rules by profile, control, and severity.

CONTACT: <href=mailto:support@magebean.com>support@magebean.com</>

HELP;


    public function __construct()
    {
        parent::__construct('scan');
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Audit Magento 2 security using selectable Magebean security profiles.')
            ->addUsage('--url=https://magento-store.com')
            ->addUsage('--path=/var/www/html')
            ->addUsage('--path=/var/www/html --url=https://magento-store.com')
            // HTML report output is disabled, so the HTML-only detail option is hidden for now.
            // ->addOption('detail', null, InputOption::VALUE_NONE, 'Include Details column in HTML report')
            ->addOption('standard', null, InputOption::VALUE_OPTIONAL, 'Legacy report selector: magebean (default) | owasp | pci | cwe; prefer --profile', 'magebean')
            ->addOption('profile', null, InputOption::VALUE_OPTIONAL, 'Profile: basic (default) | asvs-l1 | asvs-l2 | asvs-l3 | owasp | pci | hardening | baseline | custom JSON')
            ->addOption('include-manual-review', null, InputOption::VALUE_NONE, 'Include human manual-review rules (excluded by default)')
            ->addOption('capabilities', null, InputOption::VALUE_OPTIONAL, 'Comma-separated application capabilities used to activate contextual profile rules')
            ->addOption('controls', null, InputOption::VALUE_OPTIONAL, 'Comma-separated control IDs to load (e.g., MB-C01,MB-C05 or MB-01,MB-05)')
            ->addOption('rules', null, InputOption::VALUE_OPTIONAL, 'Comma-separated rule IDs to run (e.g., MB-R036,MB-R020)')
            ->addOption('exclude-rules', null, InputOption::VALUE_OPTIONAL, 'Comma-separated rule IDs to exclude after loading')
            ->addOption('config', null, InputOption::VALUE_OPTIONAL, 'Project policy file (.magebean.json or .magebean.yml)')
            ->addOption('pci-context', null, InputOption::VALUE_OPTIONAL, 'PCI DSS applicability context JSON')
            ->addOption('pci-evidence', null, InputOption::VALUE_OPTIONAL, 'PCI DSS structured external evidence JSON')
            ->addOption('pci-report', null, InputOption::VALUE_OPTIONAL, 'Write PCI DSS evidence-readiness report JSON')
            ->addOption('url', null, InputOption::VALUE_OPTIONAL, 'Absolute store base URL (REMOTE without --path; HYBRID with --path)')
            ->addOption('path', null, InputOption::VALUE_OPTIONAL, 'Magento root path (omit to auto-detect from current working directory)', '');
    }

    public function getHelp(): string
    {
        return self::HELP;
    }

    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $io = new SymfonyStyle($in, $out);
        $hasPath = $in->hasParameterOption('--path');
        $hasUrl = $in->hasParameterOption('--url');
        $resolver = new ScanTargetResolver();
        $renderer = new ScanConsoleRenderer();
        $targetMode = $resolver->mode($hasPath, $hasUrl);
        $renderer->writePhase($out, 1, 4, sprintf('Resolving %s target and input options', $targetMode));

        $pathOpt = trim((string)($in->getOption('path') ?? ''));
        $urlOpt = trim((string)($in->getOption('url') ?? ''));

        try {
            $target = $resolver->resolve($hasPath, $hasUrl, $pathOpt, $urlOpt, static function (string $path) use ($out): void {
                $out->writeln(sprintf('<info>Detected Magento root:</info> %s', $path));
            });
            $projectPath = $target->path;
            $projectUrl = $target->url;

            $out->writeln(sprintf('<info>Target mode:</info> %s', $targetMode));

            $standard = strtolower((string)($in->getOption('standard') ?? 'magebean'));
            $allowed = ['magebean', 'owasp', 'pci', 'cwe'];
            if (!in_array($standard, $allowed, true)) {
                $out->writeln('<error>Invalid --standard. Allowed: magebean | owasp | pci | cwe</error>');
                return Command::FAILURE;
            }

            $request = new ScanRequest($target->context(), $in->getOptions());
            $ctx = $request->context->toLegacy();
            $registry = CheckRegistry::fromContext($ctx);

            $remoteDetection = null;
            if ($targetMode === self::MODE_REMOTE) {
                $out->writeln('<info>Preflight:</info> Confirming Magento 2 target');
                [$fingerprintOk, $fingerprintMessage, $fingerprintEvidence] = $registry->run(
                    'http_magento_fingerprint',
                    ['timeout_ms' => 8000]
                );
                $fingerprintEvidence = is_array($fingerprintEvidence) ? $fingerprintEvidence : [];
                $observedSignals = array_values(array_filter(array_map(
                    static fn(mixed $signal): string => is_scalar($signal) ? (string)$signal : '',
                    (array)($fingerprintEvidence['signals'] ?? [])
                )));
                $detectedVersion = trim((string)($fingerprintEvidence['version'] ?? ''));

                $remoteDetection = [
                    'confirmed' => $fingerprintOk === true,
                    'confidence' => $fingerprintOk === true ? 100 : 0,
                    'message' => (string)$fingerprintMessage,
                    'signals' => $observedSignals,
                    'version' => $detectedVersion !== '' ? $detectedVersion : null,
                    'evidence' => $fingerprintEvidence,
                ];

                if ($fingerprintOk !== true) {
                    $renderer->renderRemoteMagentoInconclusive(
                        $out,
                        $projectUrl,
                        (string)$fingerprintMessage
                    );
                    return Command::SUCCESS;
                }

                $out->writeln('<info>Magento 2 confirmed.</info>');
                $out->writeln($detectedVersion !== ''
                    ? sprintf('<info>Magento version:</info> %s', $detectedVersion)
                    : '<comment>Magento version:</comment> not publicly exposed');
            }

            $renderer->writePhase($out, 2, 4, 'Loading rule pack');
            $plan = (new ScanPlanner())->planCli($request, $registry, static function (ScanDiagnostic $diagnostic) use ($out, $renderer): void {
                $renderer->diagnostic($out, $diagnostic);
            });
            if ($plan === null) return Command::FAILURE;
            $pack = $plan->pack;
            $renderer->writePhase($out, 3, 4, sprintf('Running %d audit rules', count($pack['rules'])));
            $ruleProgress = $renderer->createRuleProgressBar($out, count($pack['rules']));
            // 1) Scan rules
            $service = new ScanService();
            $report = $service->run($plan, function (array $event) use ($ruleProgress, $renderer): void {
                $type = (string)($event['type'] ?? '');
                if ($type === 'rule_start') {
                    $ruleProgress->setMessage($renderer->formatRuleProgressMessage($event));
                    $ruleProgress->display();
                    return;
                }
                if ($type === 'rule_done') {
                    $ruleProgress->setMessage($renderer->formatRuleProgressMessage($event));
                    $ruleProgress->advance();
                }
            }, $registry);
            $ruleProgress->finish();
            $out->writeln('');
            $result = (new ScanReportAssembler())->assemble($report, $plan, $remoteDetection, static function (string $path) use ($out): void {
                $out->writeln(sprintf('<info>PCI report written:</info> %s', $path));
            })->toLegacy();

            $renderer->writePhase($out, 4, 4, 'Rendering command-line summary');
            $this->renderPrettySummary($out, $result, $projectPath);
            if (isset($result['pci']) && is_array($result['pci'])) {
                $renderer->renderPciAssessmentSummary($out, $result['pci']);
            }
            $out->writeln('');
            $out->writeln('Contact: <href=mailto:support@magebean.com>support@magebean.com</>');
            $out->writeln('');

            return (new ScanExitPolicy())->code($result);

        } catch (\RuntimeException $e) {
            $io->error($e->getMessage());
            return Command::FAILURE;
        } catch (\Throwable $e) {
            // Bắt mọi lỗi không lường trước, tránh stacktrace lộ ra ngoài
            $io->error('Unexpected error: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }

    private function renderPrettySummary(OutputInterface $out, array $result, string $path): void
    {
        (new ScanConsoleRenderer())->renderPrettySummary($out, $result, $path);
    }
}
