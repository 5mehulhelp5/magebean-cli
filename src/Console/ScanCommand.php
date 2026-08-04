<?php

declare(strict_types=1);

namespace Magebean\Console;

use Magebean\Application;
use Magebean\Engine\Context;
use Magebean\Engine\ScanRunner;
use Magebean\Engine\RulePackLoader;
use Magebean\Engine\ProfileLoader;
use Magebean\Engine\ProjectConfigLoader;
use Magebean\Engine\RulePackMerger;
use Magebean\Engine\RuleValidator;
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Pci\PciApplicabilityCompiler;
use Magebean\Engine\Pci\PciExternalEvidenceImporter;
use Magebean\Engine\Pci\PciAssessmentReportBuilder;

use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class ScanCommand extends Command
{
    protected static $defaultName = 'scan';

    private const MODE_REMOTE = 'REMOTE';
    private const MODE_LOCAL = 'LOCAL';
    private const MODE_HYBRID = 'HYBRID';

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
        $targetMode = $this->resolveTargetMode($hasPath, $hasUrl);
        $this->writePhase($out, 1, 4, sprintf('Resolving %s target and input options', $targetMode));

        $pathOpt = trim((string)($in->getOption('path') ?? ''));
        $urlOpt = trim((string)($in->getOption('url') ?? ''));

        try {
            if ($hasPath && $pathOpt === '') {
                throw new \RuntimeException('--path requires a non-empty value.');
            }
            if ($hasUrl && $urlOpt === '') {
                throw new \RuntimeException('--url requires a non-empty HTTP or HTTPS URL.');
            }

            $requestedUrl = $hasUrl ? $this->normalizeRemoteUrl($urlOpt) : '';

            if ($targetMode === self::MODE_REMOTE) {
                $projectUrl = $requestedUrl;
                $projectPath = 'URL:' . $projectUrl;
            } else {
                $requestedPath = self::normalize($hasPath ? $pathOpt : (string)getcwd());

                if (!self::isMagentoRoot($requestedPath)) {
                    $detected = self::detectMagentoRoot($requestedPath, 4);
                    if ($detected === null) {
                        throw new \RuntimeException(
                            "Cannot locate Magento root from: {$requestedPath}\n" .
                            'Hint: run from your Magento root or pass --path=/absolute/path/to/magento'
                        );
                    }
                    $out->writeln(sprintf('<info>Detected Magento root:</info> %s', $detected));
                    $requestedPath = $detected;
                }

                $magentoRoot = $this->findMagentoRoot($requestedPath, 2);
                if ($magentoRoot === null) {
                    throw new \RuntimeException(
                        "Not a valid Magento 2 installation.\n" .
                        "- Expected files: bin/magento, composer.json, app/etc/config.php\n" .
                        "- Checked: {$requestedPath} (and up to 2 parents)"
                    );
                }

                $this->assertMagento2Root($magentoRoot);
                $projectPath = (string)$magentoRoot;
                $projectUrl = $hasUrl
                    ? $requestedUrl
                    : (string)$this->autoDetectBaseUrl($projectPath);
            }

            $out->writeln(sprintf('<info>Target mode:</info> %s', $targetMode));

            $standard = strtolower((string)($in->getOption('standard') ?? 'magebean'));
            $profileOpt = trim((string)($in->getOption('profile') ?? ''));
            $rulesOpt = (string)($in->getOption('rules') ?? '');
            $excludeRulesOpt = (string)($in->getOption('exclude-rules') ?? '');
            $controlsOpt = (string)($in->getOption('controls') ?? '');
            $configOpt = trim((string)($in->getOption('config') ?? ''));
            $capabilitiesOpt = trim((string)($in->getOption('capabilities') ?? ''));
            $includeManualReview = (bool)$in->getOption('include-manual-review');
            $pciContextOpt = trim((string)($in->getOption('pci-context') ?? ''));
            $pciEvidenceOpt = trim((string)($in->getOption('pci-evidence') ?? ''));
            $pciReportOpt = trim((string)($in->getOption('pci-report') ?? ''));

            $allowed = ['magebean', 'owasp', 'pci', 'cwe'];
            if (!in_array($standard, $allowed, true)) {
                $out->writeln('<error>Invalid --standard. Allowed: magebean | owasp | pci | cwe</error>');
                return Command::FAILURE;
            }

            $bundleMeta = ['target_mode' => $targetMode];
            $ctx = new Context($projectPath, $projectUrl, '', [
                'path' => $projectPath,
                'url' => $projectUrl,
                'meta' => $bundleMeta,
            ]);
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
                    $this->renderRemoteMagentoInconclusive(
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

            $this->writePhase($out, 2, 4, 'Loading rule pack');
            $configBasePath = $targetMode === self::MODE_REMOTE ? (string)getcwd() : $projectPath;
            $configFile = $configOpt !== ''
                ? self::normalize($this->resolveProjectConfigPath($configOpt, $configBasePath))
                : ($targetMode === self::MODE_REMOTE ? null : ProjectConfigLoader::discover($projectPath));
            $projectConfig = ProjectConfigLoader::load($configFile);
            if ($configFile !== null) {
                $out->writeln(sprintf('<info>Loaded Magebean project config:</info> %s', $configFile));
            }
            $capabilities = is_array($projectConfig['capabilities'] ?? null) ? $projectConfig['capabilities'] : [];
            if ($capabilitiesOpt !== '') {
                foreach (array_filter(array_map('trim', explode(',', $capabilitiesOpt))) as $capability) {
                    $capabilities[strtolower($capability)] = true;
                }
            }

            // normalize controls filter
            $controlsFilter = $this->normalizeControlList($projectConfig['include_controls'] ?? []);
            if ($controlsOpt !== '') {
                $controlsFilter = $this->normalizeControlList($controlsOpt);
            }

            $pack = $targetMode === self::MODE_REMOTE
                ? RulePackLoader::loadExternalMagento($controlsFilter)
                : RulePackLoader::loadAll($controlsFilter);

            if ($controlsFilter) {
                $loaded = $pack['controls'] ?? [];
                $missing = array_values(array_diff($controlsFilter, $loaded));
                if ($missing) {
                    $message = $targetMode === self::MODE_REMOTE
                        ? 'Control(s) not supported in REMOTE mode: '
                        : 'Control file(s) not found: ';
                    $out->writeln('<error>' . $message . implode(', ', $missing) . '</error>');
                    return Command::FAILURE;
                }
            }

            $pack = RulePackMerger::applyProjectConfig($pack, $projectConfig);

            $activeProfile = $targetMode === self::MODE_REMOTE
                ? [
                    'id' => 'external',
                    'title' => 'Magebean External Magento Audit',
                    'description' => 'Publicly observable checks that require only a store URL.',
                    'report_template' => 'standard',
                    '_source' => 'builtin:external',
                ]
                : [
                    'id' => 'baseline',
                    'title' => 'Magebean Baseline',
                    'description' => 'All enabled rules from the Magebean rule catalog.',
                    'report_template' => 'standard',
                    '_source' => 'builtin:baseline',
                ];
            $hasExplicitRuleSelection = trim($rulesOpt) !== '';
            if ($hasExplicitRuleSelection) {
                $standard = 'explicit-rules';
                $activeProfile['id'] = 'explicit-rules';
                $activeProfile['title'] = 'Explicit Rule Selection';
                $activeProfile['description'] = 'Rules explicitly selected from the available catalog with --rules.';
                $activeProfile['_source'] = 'cli:--rules';
                $out->writeln('<info>Profile selection bypassed:</info> explicit --rules selection');
            } else {
                if ($profileOpt === '') {
                    $profileOpt = in_array($standard, ['owasp', 'pci'], true) ? $standard : 'basic';
                }
                if ($profileOpt !== '' && !in_array(strtolower($profileOpt), ['baseline', 'all', 'magebean', 'external'], true)) {
                    $profileBasePath = $targetMode === self::MODE_REMOTE ? (string)getcwd() : $projectPath;
                    $profile = ProfileLoader::load($profileOpt, $profileBasePath);
                    $profileCanBePartial = $targetMode === self::MODE_REMOTE
                        || $controlsFilter !== [] || $projectConfig !== [];
                    $pack = ProfileLoader::apply($pack, $profile, $profileCanBePartial, $capabilities);
                    $activeProfile = ProfileLoader::publicMetadata($profile);
                    $standard = (string)($activeProfile['id'] ?? $standard);
                    $out->writeln(sprintf(
                        '<info>Loaded profile:</info> %s',
                        (string)($activeProfile['id'] ?? $profileOpt)
                    ));
                }
            }

            $activeProfileId = strtolower((string)($activeProfile['id'] ?? ''));
            $isPciProfile = $standard === 'pci' || str_starts_with($activeProfileId, 'pci-dss');
            if (!$isPciProfile && ($pciContextOpt !== '' || $pciEvidenceOpt !== '' || $pciReportOpt !== '')) {
                throw new \RuntimeException('--pci-context, --pci-evidence, and --pci-report require the PCI profile.');
            }
            $profileRulesTotal = count($pack['rules'] ?? []);
            $profileManualRulesTotal = count(array_filter($pack['rules'] ?? [], static fn(array $rule): bool => strtolower((string)($rule['verification'] ?? 'automated')) === 'manual'));
            $manualRulesExcluded = 0;
            if (!$hasExplicitRuleSelection && !$includeManualReview) {
                $beforeManualFilter = count($pack['rules'] ?? []);
                $pack['rules'] = array_values(array_filter(
                    $pack['rules'] ?? [],
                    static fn(array $rule): bool => strtolower((string)($rule['verification'] ?? 'automated')) !== 'manual'
                ));
                $manualRulesExcluded = $beforeManualFilter - count($pack['rules']);

            }

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
                        $label = $targetMode === self::MODE_REMOTE
                            ? 'Rule not supported in REMOTE mode:'
                            : 'Unknown rule id:';
                        $out->writeln(sprintf('<comment>%s</comment> %s', $label, $id));
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

            if ($excludeRulesOpt !== '') {
                $excludedIds = array_values(array_unique(array_filter(array_map(
                    static fn(string $id): string => strtoupper(trim($id)),
                    explode(',', $excludeRulesOpt)
                ))));
                if ($excludedIds) {
                    $pack['rules'] = array_values(array_filter(
                        $pack['rules'],
                        static fn(array $rule): bool => !in_array(strtoupper((string)($rule['id'] ?? '')), $excludedIds, true)
                    ));
                }
            }

            if ($hasExplicitRuleSelection) {
                $profileRulesTotal = count($pack['rules'] ?? []);
                $profileManualRulesTotal = count(array_filter(
                    $pack['rules'] ?? [],
                    static fn(array $rule): bool => strtolower((string)($rule['verification'] ?? 'automated')) === 'manual'
                ));
                $manualRulesExcluded = 0;
            }
            $validationErrors = RuleValidator::validatePack($pack, $registry);
            if ($validationErrors) {
                $out->writeln('<error>Invalid rule pack:</error>');
                foreach (array_slice($validationErrors, 0, 20) as $error) {
                    $out->writeln('  - ' . $error);
                }
                if (count($validationErrors) > 20) {
                    $out->writeln(sprintf('  - ... and %d more', count($validationErrors) - 20));
                }
                return Command::FAILURE;
            }

            if (empty($pack['rules'])) {
                $out->writeln('<error>No rules found. Check rules directory or control filter.</error>');
                return Command::FAILURE;
            }

            $this->writePhase($out, 3, 4, sprintf('Running %d audit rules', count($pack['rules'])));
            $ruleProgress = $this->createRuleProgressBar($out, count($pack['rules']));
            // 1) Scan rules
            $runner = new ScanRunner($ctx, $pack, function (array $event) use ($ruleProgress): void {
                $type = (string)($event['type'] ?? '');
                if ($type === 'rule_start') {
                    $ruleProgress->setMessage($this->formatRuleProgressMessage($event));
                    $ruleProgress->display();
                    return;
                }
                if ($type === 'rule_done') {
                    $ruleProgress->setMessage($this->formatRuleProgressMessage($event));
                    $ruleProgress->advance();
                }
            }, $registry);
            $result = $runner->run();
            $ruleProgress->finish();
            $out->writeln('');
            // attach meta
            $result['meta']['standard'] = $standard;
            $result['meta']['profile'] = $activeProfile;
            $result['meta']['target_mode'] = $targetMode;
            $result['meta']['rules_filter'] = $requestedIds;
            $result['meta']['controls_filter'] = $controlsFilter;
            $result['meta']['project_config'] = $configFile;
            $result['meta']['profile_rules_total'] = $profileRulesTotal;
            $result['meta']['profile_manual_rules_total'] = $profileManualRulesTotal;
            $result['meta']['manual_rules_hidden'] = $manualRulesExcluded;
            $result['meta']['manual_rules_included'] = $includeManualReview || $hasExplicitRuleSelection;
            $result['summary']['path'] = $projectPath;
            $result['summary']['url'] = $projectUrl;

            if ($isPciProfile) {
                $registryData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1.json', 'PCI DSS registry');
                $coverageData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1-coverage.json', 'PCI DSS coverage matrix');
                $triageData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1-gap-triage.json', 'PCI DSS gap triage');
                $criterionReviewData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1-automation-candidate-review.json', 'PCI DSS criterion review');
                $requirement02ReviewData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1-requirement-02-review.json', 'PCI DSS Requirement 2 review');
                $criterionReviewData['requirements'] = array_merge($requirement02ReviewData['requirements'] ?? [], $criterionReviewData['requirements'] ?? []);
                $compiler = new PciApplicabilityCompiler();
                $pciContext = $pciContextOpt !== '' ? $compiler->load($this->resolveProjectConfigPath($pciContextOpt, $configBasePath)) : [
                    'schema_version' => 1, 'entity_type' => 'merchant', 'issuer_or_issuing_services' => false,
                    'scope_confirmed' => false, 'payment_architecture' => 'unknown', 'pan_handling' => 'unknown',
                    'overlays' => [], 'requirement_overrides' => [],
                ];
                $applicability = $compiler->compile($registryData, $pciContext);
                if (($applicability['valid'] ?? false) !== true) throw new \RuntimeException("Invalid PCI applicability context:\n- " . implode("\n- ", $applicability['errors'] ?? []));
                $externalEvidence = ['valid' => true, 'errors' => [], 'evidence_by_requirement' => [], 'summary' => ['items' => 0, 'requirements' => 0, 'credential_material_processed' => false]];
                if ($pciEvidenceOpt !== '') {
                    $externalEvidence = (new PciExternalEvidenceImporter(array_column($registryData['requirements'] ?? [], 'id')))->import($this->resolveProjectConfigPath($pciEvidenceOpt, $configBasePath));
                    if (($externalEvidence['valid'] ?? false) !== true) throw new \RuntimeException("Invalid PCI external evidence package:\n- " . implode("\n- ", $externalEvidence['errors'] ?? []));
                }
                $pciReport = (new PciAssessmentReportBuilder())->build($result, $coverageData, $triageData, $applicability, $externalEvidence, $includeManualReview, $criterionReviewData);
                $pciReport['context_source'] = $pciContextOpt !== '' ? $pciContextOpt : 'default:unconfirmed';
                $pciReport['evidence_source'] = $pciEvidenceOpt !== '' ? $pciEvidenceOpt : null;
                $result['pci'] = $pciReport;
                if ($pciReportOpt !== '') {
                    $pciReportFile = $this->resolveProjectConfigPath($pciReportOpt, $configBasePath);
                    $pciReportDir = dirname($pciReportFile);
                    if (!is_dir($pciReportDir) && !mkdir($pciReportDir, 0777, true) && !is_dir($pciReportDir)) throw new \RuntimeException('Cannot create PCI report directory: ' . $pciReportDir);
                    if (file_put_contents($pciReportFile, json_encode($pciReport, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) throw new \RuntimeException('Cannot write PCI report: ' . $pciReportFile);
                    $out->writeln(sprintf('<info>PCI report written:</info> %s', $pciReportFile));
                }
            }
            if ($targetMode === self::MODE_REMOTE) {
                $planned = (int)($result['meta']['planned_rules'] ?? 0);
                $executed = (int)($result['meta']['executed_rules'] ?? 0);
                $transportTotal = (int)($result['meta']['transport_total'] ?? 0);
                $transportOk = (int)($result['meta']['transport_ok'] ?? 0);
                $coveragePercent = $planned > 0
                    ? (int)round(($executed / $planned) * 100)
                    : 0;
                $transportPercent = $transportTotal > 0
                    ? (int)round(($transportOk / $transportTotal) * 100)
                    : 0;
                $detectionConfidence = (int)($remoteDetection['confidence'] ?? 0);

                $result['meta']['detected'] = $remoteDetection ?? [
                    'confirmed' => false,
                    'confidence' => 0,
                    'message' => 'Magento fingerprint was not checked.',
                    'signals' => [],
                ];
                $result['meta']['coverage_percent'] = $coveragePercent;
                $result['meta']['transport_success_percent'] = $transportPercent;
                $result['meta']['overall_confidence'] = (int)round(
                    ($detectionConfidence * 0.4)
                    + ($transportPercent * 0.3)
                    + ($coveragePercent * 0.3)
                );
                $result['meta']['assurance'] = 'externally_observable';
            }

            $result['cve_audit'] = null;

            // Render export
            // Report file output is intentionally disabled; Magebean currently
            // supports command-line output only.
            // $tpl = $this->resolveTemplatePath((string)($activeProfile['report_template'] ?? 'standard'));
            // $rep = new HtmlReporter($tpl, (bool)$in->getOption('detail'));
            // $rep->write($result, $outFile);

            // ---------- Pretty console output (mimic sample) ----------
            $this->writePhase($out, 4, 4, 'Rendering command-line summary');
            $this->renderPrettySummary($out, $result, $projectPath);
            if (isset($result['pci']) && is_array($result['pci'])) {
                $this->renderPciAssessmentSummary($out, $result['pci']);
            }
            $out->writeln('');
            $out->writeln('Contact: <href=mailto:support@magebean.com>support@magebean.com</>');
            $out->writeln('');

            return $this->determineExitCode($result);

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

    private function loadJsonDocument(string $path, string $label): array
    {
        try { $data = json_decode((string)file_get_contents($path), true, 512, JSON_THROW_ON_ERROR); }
        catch (\JsonException) { throw new \RuntimeException($label . ' contains malformed JSON.'); }
        if (!is_array($data)) throw new \RuntimeException($label . ' root must be an object.');
        return $data;
    }

    private function renderPciAssessmentSummary(OutputInterface $out, array $pci): void
    {
        $summary = $pci['summary'] ?? [];
        $statuses = $summary['statuses'] ?? [];
        $requirements = (int)($summary['human_verification_required'] ?? $summary['requirements'] ?? 0);
        $out->writeln('');
        $out->writeln('<options=bold>PCI DSS 4.0.1 EVIDENCE READINESS</>');
        $out->writeln(sprintf('  Registry requirements requiring human confirmation: <fg=cyan;options=bold>%d</>', $requirements));
        $out->writeln(sprintf('  Technical findings: %d · Evidence collected, human confirmation pending: %d', (int)($statuses['TECHNICAL_FINDING'] ?? 0), (int)($statuses['EVIDENCE_COLLECTED_HUMAN_VERIFICATION_REQUIRED'] ?? 0)));
        $out->writeln(sprintf('  Applicability undetermined: %d · Not applicable, confirmation pending: %d', (int)($statuses['NOT_DETERMINED'] ?? 0), (int)($statuses['NOT_APPLICABLE'] ?? 0)));
        $actions = $pci['human_actions'] ?? [];
        if ($actions === []) {
            $out->writeln('  <comment>Detailed human actions are hidden; use --include-manual-review to list them.</comment>');
        } else {
            $out->writeln(sprintf('  <fg=cyan;options=bold>Human actions (%d)</>', count($actions)));
            foreach ($actions as $action) {
                $out->writeln(sprintf('    <fg=cyan>[%s]</> %s', (string)($action['requirement'] ?? ''), (string)($action['scope'] ?? '')));
            }
        }
        $out->writeln('<comment>This is evidence-readiness output, not PCI DSS certification or an attestation of compliance.</comment>');
    }
    private function renderRemoteMagentoInconclusive(
        OutputInterface $out,
        string $url,
        string $reason
    ): void {
        $safeUrl = \Symfony\Component\Console\Formatter\OutputFormatter::escape($url);
        $safeReason = \Symfony\Component\Console\Formatter\OutputFormatter::escape($reason);

        $out->writeln('');
        $out->writeln('<fg=magenta;options=bold>INCONCLUSIVE: MAGENTO 2 NOT CONFIRMED</>');
        $out->writeln(sprintf('Target: <fg=green>%s</>', $safeUrl));
        $out->writeln(sprintf('Reason: <comment>%s</comment>', $safeReason));
        $out->writeln('No remote audit rules were executed.');
        $out->writeln('');
    }

    private function renderPrettySummary(OutputInterface $out, array $result, string $path): void
    {
        $sum    = $result['summary'] ?? [];
        $total  = (int)($sum['total']  ?? 0);
        $passed = (int)($sum['passed'] ?? 0);

        $env      = strtoupper($this->detectMageMode($path));
        $isExternal = str_starts_with($path, 'URL:');
        $env = $isExternal ? 'EXTERNAL' : strtoupper($this->detectMageMode($path));
        $targetOption = $isExternal
            ? '--url=' . substr($path, 4) . ' '
            : '--path=' . escapeshellarg($path) . ' ';
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
        $out->writeln(sprintf('<fg=cyan;options=bold>Magebean CLI %s</>', Application::VERSION));
        $out->writeln(sprintf('Audit         Security Audit · Baseline %s', Application::BASELINE_VERSION));
        $out->writeln(sprintf('Target        <fg=green>%s</>', $path));
        $standard = (string)($result['meta']['standard'] ?? 'magebean');
        $profile = (array)($result['meta']['profile'] ?? []);
        $profileTitle = (string)($profile['title'] ?? $profile['id'] ?? 'Magebean Baseline');
        $out->writeln(sprintf('Profile ID    <info>%s</info>', strtoupper($standard)));
        $out->writeln(sprintf('Profile       <info>%s</info>', $profileTitle));
        $profileRulesTotal = (int)($result['meta']['profile_rules_total'] ?? $total);
        $profileManualRulesTotal = (int)($result['meta']['profile_manual_rules_total'] ?? 0);
        $manualRulesHidden = (int)($result['meta']['manual_rules_hidden'] ?? 0);
        $manualRulesIncluded = (bool)($result['meta']['manual_rules_included'] ?? false);
        $out->writeln(sprintf('Rules         <info>%d</info> / <info>%d</info> selected', $total, $profileRulesTotal));
        if ($manualRulesHidden > 0) {
            $out->writeln(sprintf('Manual rules  <fg=cyan;options=bold>%d not evaluated</> (use <info>--include-manual-review</info> to include)', $manualRulesHidden));
        } elseif ($manualRulesIncluded && $profileManualRulesTotal > 0) {
            $out->writeln(sprintf('Manual rules  <fg=cyan;options=bold>%d included</>', $profileManualRulesTotal));
        } else {
            $out->writeln('Manual rules  <comment>None in the current profile selection</comment>');
        }
        $out->writeln(sprintf('Environment   PHP <info>%s</info> · %s · <comment>%s</comment>', $phpShort, $envTag($env), date('Y-m-d H:i')));
        if ($isExternal) {
            $det = $result['meta']['detected'] ?? [];
            $detConf = (int)($det['confidence'] ?? 0);
            $detConfirmed = (bool)($det['confirmed'] ?? false);
            $detVersion = trim((string)($det['version'] ?? ''));
            $signals = (array)($det['signals'] ?? []);
            $overall = (int)($result['meta']['overall_confidence'] ?? 0);
            $tPct    = (int)($result['meta']['transport_success_percent'] ?? 0);
            $cPct    = (int)($result['meta']['coverage_percent'] ?? 0);
            $planned = (int)($result['meta']['planned_rules'] ?? 0);
            $execd   = (int)($result['meta']['executed_rules'] ?? 0);
            $detectionLabel = $detConfirmed
                ? '<info>Magento 2</info>'
                : '<comment>Magento 2 not confirmed</comment>';
            $out->writeln(sprintf('Detected: %s (confidence <comment>%d%%</comment>)', $detectionLabel, $detConf));
            $out->writeln($detVersion !== ''
                ? sprintf('Magento version: <info>%s</info>', $detVersion)
                : 'Magento version: <comment>not publicly exposed</comment>');
            $out->writeln(sprintf('Scan confidence: <info>%d%%</info> (detect %d, transport %d, coverage %d)', $overall, $detConf, $tPct, $cPct));
            if ($planned > 0) {
                $out->writeln(sprintf('Coverage: <info>%d/%d</info> rules (%d%%)', $execd, $planned, $cPct));
            }
            if (!empty($signals)) {
                $out->writeln('Signals:');
                foreach (array_slice($signals, 0, 6) as $s) {
                    $out->writeln('  - ' . $s);
                }
                if (count($signals) > 6) $out->writeln('  - …');
            }
            $out->writeln('');
        }
        $out->writeln('');

        // Findings requiring attention
        $attentionFindings = array_values(array_filter(
            ($result['findings'] ?? []),
            static fn(array $finding): bool => empty($finding['passed'])
        ));
        usort($attentionFindings, fn($a, $b) => $this->sevOrder($a['severity'] ?? 'Low') <=> $this->sevOrder($b['severity'] ?? 'Low'));
        $allFindings = array_values((array)($result['findings'] ?? []));
        usort($allFindings, fn($a, $b) => $this->sevOrder($a['severity'] ?? 'Low') <=> $this->sevOrder($b['severity'] ?? 'Low'));
        $inconclusiveFindings = array_values(array_filter(
            $attentionFindings,
            static fn(array $finding): bool => strtoupper((string)($finding['status'] ?? '')) === 'UNKNOWN'
        ));
        $confirmedFindings = array_values(array_filter(
            $attentionFindings,
            static fn(array $finding): bool => strtoupper((string)($finding['status'] ?? '')) === 'FAIL'
        ));
        $manualReviewFindings = array_values(array_filter(
            $attentionFindings,
            static fn(array $finding): bool => strtoupper((string)($finding['status'] ?? '')) === 'MANUAL_REVIEW'
        ));

        $sevCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($confirmedFindings as $f) {
            $k = strtolower((string)($f['severity'] ?? 'low'));
            if (!isset($sevCounts[$k])) $k = 'low';
            $sevCounts[$k]++;
        }

        // Summary first, so the result remains visible even for long audits.
        $auditStatus = $confirmedFindings !== []
            ? '<fg=yellow;options=bold>AUDIT COMPLETE · ATTENTION REQUIRED</>'
            : ($manualReviewFindings !== []
                ? '<fg=cyan;options=bold>AUDIT COMPLETE · HUMAN REVIEW REQUIRED</>'
                : ($inconclusiveFindings !== []
                ? '<fg=magenta;options=bold>AUDIT COMPLETE · INCONCLUSIVE</>'
                : '<info>AUDIT COMPLETE</info>'));
        $out->writeln($auditStatus);
        $out->writeln('');
        $out->writeln(sprintf('  Passed                    <info>%d / %d</info>', $passed, $total));
        $out->writeln(sprintf('  Confirmed findings        <fg=yellow;options=bold>%d</>', count($confirmedFindings)));
        $out->writeln(sprintf('  Technical manual review   <fg=cyan;options=bold>%d</>', count($manualReviewFindings)));
        $out->writeln(sprintf('  Inconclusive              <fg=magenta;options=bold>%d</>', count($inconclusiveFindings)));
        if ($confirmedFindings !== []) {
            $out->writeln(sprintf(
                '  %sCritical %d</> · %sHigh %d</> · %sMedium %d</> · %sLow %d</>',
                '<fg=white;bg=red;options=bold>',
                $sevCounts['critical'],
                '<fg=red;options=bold>',
                $sevCounts['high'],
                '<fg=yellow;options=bold>',
                $sevCounts['medium'],
                '<fg=blue;options=bold>',
                $sevCounts['low'],
            ));
        }
        $out->writeln('');

        $rulesFilter = array_values(array_filter((array)($result['meta']['rules_filter'] ?? [])));
        $showRuleDetails = $rulesFilter !== [];
        if ($showRuleDetails) {
            $out->writeln(sprintf('<options=bold>Rule details</> (<fg=yellow>%d</>)', count($allFindings)));
        } elseif ($confirmedFindings !== [] || $manualReviewFindings !== []) {
            $out->writeln(sprintf('<options=bold>FINDINGS REQUIRING ATTENTION (%d)</>', count($confirmedFindings) + count($manualReviewFindings)));
        }

        $findingsToRender = $showRuleDetails ? $allFindings : array_merge($confirmedFindings, $manualReviewFindings);
        $currentSeverity = null;
        foreach ($findingsToRender as $f) {
            $sev = strtoupper((string)($f['severity'] ?? 'LOW'));
            $id = trim((string)($f['id'] ?? ''));
            $status = strtoupper((string)($f['status'] ?? ''));
            $text = $showRuleDetails
                ? $this->detailedFindingMessage($f)
                : $this->compactFindingDescription($f);
            $statusTag = $showRuleDetails
                ? match ($status) {
                    'PASS' => '<fg=green;options=bold>[PASS]</> ',
                    'MANUAL_REVIEW' => '<fg=cyan;options=bold>[HUMAN VERIFICATION REQUIRED]</> ',
                    'UNKNOWN' => '<fg=magenta;options=bold>[INCONCLUSIVE]</> ',
                    default => '<fg=red;options=bold>[FAIL]</> ',
                }
                : ($status === 'MANUAL_REVIEW'
                    ? '<fg=cyan;options=bold>[HUMAN VERIFICATION REQUIRED]</> '
                    : '');
            if (!$showRuleDetails && $status !== 'MANUAL_REVIEW' && $sev !== $currentSeverity) {
                $currentSeverity = $sev;
                $out->writeln('');
                $out->writeln(sprintf('  %s (%d)', $sevBadge($sev), $sevCounts[strtolower($sev)] ?? 0));
            }
            $line = $id !== ''
                ? sprintf('%s<href=https://magebean.com/baseline/%2$s>%2$s</>  %3$s', $statusTag, $id, $text)
                : sprintf('%s%s', $statusTag, $text);
            $out->writeln(($showRuleDetails ? '  ' . $sevBadge($sev) . ' ' : '    ') . $line);

            if ($id === 'MB-R072' && $status === 'UNKNOWN') {
                $out->writeln('    Git history was not verified; INCONCLUSIVE does not mean the history is clean.');
                $out->writeln('    Run this rule against the original source checkout containing .git:');
                $out->writeln("      <fg=green>php magebean.phar scan --path='/path/to/magento-source' --rules=MB-R072</>");
            }


            if ($showRuleDetails) {
                $this->renderCheckDetails($out, $f);
            }

            if ($showRuleDetails && in_array($status, ['FAIL', 'UNKNOWN'], true)) {
                $out->writeln('');
                $out->writeln(sprintf('  <options=bold>How to resolve %s</>', $id !== '' ? $id : 'this check'));
                $resolutionSteps = $status === 'UNKNOWN'
                    ? $this->inconclusiveResolutionSteps($f)
                    : $this->failureResolutionSteps($f);
                foreach ($resolutionSteps as $step) {
                    $out->writeln('    - ' . $step);
                }
                if ($id !== '' && !($id === 'MB-R072' && $status === 'UNKNOWN')) {
                    $out->writeln($status === 'UNKNOWN'
                        ? '    - Re-run after resolving the missing evidence:'
                        : '    - Re-run after applying the remediation:');
                    $out->writeln(sprintf('      <fg=green>php magebean.phar scan %s--rules=%s</>', $targetOption, $id));
                }
            }
        }

        if (!$showRuleDetails && $inconclusiveFindings !== []) {
            $out->writeln('');
            $out->writeln(sprintf(
                '<options=bold>INCONCLUSIVE CHECKS (%d)</>',
                count($inconclusiveFindings)
            ));
            foreach ($inconclusiveFindings as $f) {
                $sev = strtoupper((string)($f['severity'] ?? 'LOW'));
                $id = trim((string)($f['id'] ?? ''));
                $text = $this->compactFindingDescription($f);
                $line = $id !== ''
                    ? sprintf('<href=https://magebean.com/baseline/%1$s>%1$s</>  %2$s', $id, $text)
                    : $text;
                $out->writeln('  ' . $line);
                $out->writeln(sprintf('    Potential severity: %s', ucfirst(strtolower($sev))));
                if ($id === 'MB-R072') {
                    $out->writeln('    Git history was not verified; INCONCLUSIVE does not mean the history is clean.');
                    $out->writeln('    Run this rule against the original source checkout containing .git:');
                    $out->writeln("      <fg=green>php magebean.phar scan --path='/path/to/magento-source' --rules=MB-R072</>");
                }
            }
        }
        $out->writeln('');

        if (!$showRuleDetails && ($confirmedFindings !== [] || $inconclusiveFindings !== [])) {
            $exampleRules = array_values(array_filter(array_map(
                static fn(array $finding): string => trim((string)($finding['id'] ?? '')),
                array_slice($confirmedFindings, 0, 1)
            )));
            $out->writeln('<options=bold>NEXT STEPS</>');
            if ($exampleRules !== []) {
                $out->writeln('  Review the highest-priority finding:');
                $out->writeln(sprintf('    <fg=green>php magebean.phar scan %s--rules=%s</>', $targetOption, $exampleRules[0]));

            }
            if ($inconclusiveFindings !== []) {
                $inconclusiveId = trim((string)($inconclusiveFindings[0]['id'] ?? ''));
                if ($inconclusiveId !== '') {
                    $out->writeln('  Resolve an inconclusive check:');
                    $out->writeln(sprintf('    <fg=green>php magebean.phar scan %s--rules=%s</>', $targetOption, $inconclusiveId));
                }
            }
            $out->writeln('');
        }

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
            }
        }


    }

    private function normalizeControlId(string $raw): string
    {
        $id = strtoupper(trim($raw));
        if ($id === '') return '';
        if (preg_match('/^MB-C(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        if (preg_match('/^MB-(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        if (preg_match('/^C(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        if (preg_match('/^(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        return '';
    }

    private function normalizeControlList(mixed $raw): array
    {
        if (is_string($raw)) {
            $parts = array_map('trim', explode(',', $raw));
        } elseif (is_array($raw)) {
            $parts = $raw;
        } else {
            return [];
        }

        $normalized = [];
        $invalid = [];
        foreach ($parts as $control) {
            if (!is_scalar($control)) {
                $invalid[] = '[non-scalar]';
                continue;
            }
            $control = trim((string)$control);
            if ($control === '') {
                continue;
            }
            $nc = $this->normalizeControlId($control);
            if ($nc === '') {
                $invalid[] = $control;
            } else {
                $normalized[] = $nc;
            }
        }

        if ($invalid) {
            throw new \RuntimeException(
                'Invalid control id(s): ' . implode(', ', $invalid) . "\nExpected format: MB-C01 or MB-01"
            );
        }

        return array_values(array_unique($normalized));
    }

    private function resolveProjectConfigPath(string $config, string $projectPath): string
    {
        if ($config === '') {
            return $config;
        }
        if ($config[0] === '/' || (bool)preg_match('/^[A-Za-z]:[\\\\\\/]/', $config)) {
            return $config;
        }

        $cwdCandidate = getcwd() . DIRECTORY_SEPARATOR . $config;
        if (is_file($cwdCandidate)) {
            return $cwdCandidate;
        }

        return rtrim($projectPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $config;
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
    private function resolveTemplatePath(string $template = 'standard'): string
    {
        $template = preg_match('/^[a-z0-9_-]+$/i', $template) ? $template : 'standard';
        $candidates = [
            __DIR__ . '/../../resources/report-template-' . $template . '.html',
            __DIR__ . '/../../resources/report-template.html',
            __DIR__ . '/../resources/report-template-' . $template . '.html',
            __DIR__ . '/../resources/report-template.html',
            getcwd() . '/resources/report-template-' . $template . '.html',
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
<div>Profile: {{profile_title}} ({{profile_id}})</div>
<div>Rules: {{rules_passed}} / {{rules_total}} ({{rules_passed_percent}}%) — Failed: {{rules_failed}}</div>
<div>Findings (Critical: {{findings_critical}}, High: {{findings_high}}, Medium: {{findings_medium}}, Low: {{findings_low}})</div>
<table>
<thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Title / Message / Details</th></tr></thead>
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

    private function resolveTargetMode(bool $hasPath, bool $hasUrl): string
    {
        if ($hasUrl && !$hasPath) {
            return self::MODE_REMOTE;
        }
        if ($hasPath && $hasUrl) {
            return self::MODE_HYBRID;
        }

        return self::MODE_LOCAL;
    }

    private function normalizeRemoteUrl(string $url): string
    {
        $url = trim($url);
        if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw new \RuntimeException('Invalid --url. Expected an absolute HTTP or HTTPS URL.');
        }

        $parts = parse_url($url);
        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        $host = (string)($parts['host'] ?? '');
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            throw new \RuntimeException('Invalid --url. Only absolute HTTP and HTTPS URLs are supported.');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new \RuntimeException('Invalid --url. Credentials in the target URL are not supported.');
        }
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw new \RuntimeException('Invalid --url. Use a store base URL without a query string or fragment.');
        }

        return rtrim($url, '/');
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
            'timeout' => max(1, (int)ceil($timeoutMs / 1000)),
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
                    if (is_array($out[$k])) $out[$k][] = $v;
                    else $out[$k] = [$out[$k], $v];
                } else {
                    $out[$k] = $v;
                }
            }
        }
        return $out;
    }

    private function autoDetectBaseUrl(string $projectPath): string
    {
        $root    = rtrim($projectPath, DIRECTORY_SEPARATOR);
        $envFile = $root . '/app/etc/env.php';
        if (!is_file($envFile)) {
            return '';
        }

        $env = @include $envFile;
        if (!is_array($env) || empty($env['db']['connection']['default'])) {
            return '';
        }

        $db     = $env['db']['connection']['default'];
        $prefix = $env['db']['table_prefix'] ?? '';
        $table  = ($prefix ? $prefix : '') . 'core_config_data';

        $host     = $db['host'] ?? 'localhost';
        $dbname   = $db['dbname'] ?? '';
        $username = $db['username'] ?? '';
        $password = $db['password'] ?? '';
        $port     = null;

        if (strpos($host, ':') !== false) {
            [$host, $port] = explode(':', $host, 2);
        }
        if ($dbname === '' || $username === '') {
            return '';
        }

        $dsn = "mysql:host={$host};dbname={$dbname};charset=utf8mb4";
        if (!empty($port)) {
            $dsn .= ";port={$port}";
        }

        try {
            $pdo = new \PDO($dsn, $username, $password, [
                \PDO::ATTR_ERRMODE            => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            ]);
        } catch (\PDOException $e) {
            return '';
        }

        $paths = ['web/secure/base_url', 'web/unsecure/base_url'];
        $in    = implode(',', array_fill(0, count($paths), '?'));
        $sql   = "SELECT scope, scope_id, path, value FROM {$table} WHERE path IN ($in)";

        try {
            $stmt = $pdo->prepare($sql);
            $stmt->execute($paths);
            $rows = $stmt->fetchAll();
        } catch (\PDOException $e) {
            return '';
        }
        if (!$rows) {
            return '';
        }

        $bucket = [
            'web/secure/base_url'   => ['stores' => [], 'websites' => [], 'default' => []],
            'web/unsecure/base_url' => ['stores' => [], 'websites' => [], 'default' => []],
        ];
        foreach ($rows as $r) {
            $path    = (string)($r['path'] ?? '');
            $scope   = strtolower((string)($r['scope'] ?? 'default'));
            if (!isset($bucket[$path][$scope])) $scope = 'default';
            $scopeId = (int)($r['scope_id'] ?? 0);
            $val     = trim((string)($r['value'] ?? ''));
            if ($val !== '' && isset($bucket[$path])) {
                $bucket[$path][$scope][$scopeId] = $val;
            }
        }

        $pick = function (array $b): ?string {
            if (!empty($b['stores'])) {
                $https = array_filter($b['stores'], fn($v) => stripos($v, 'https://') === 0);
                $cand  = reset($https);
                if ($cand) return $cand;
                return reset($b['stores']);
            }
            if (!empty($b['websites'])) {
                $https = array_filter($b['websites'], fn($v) => stripos($v, 'https://') === 0);
                $cand  = reset($https);
                if ($cand) return $cand;
                return reset($b['websites']);
            }
            if (!empty($b['default'])) {
                $https = array_filter($b['default'], fn($v) => stripos($v, 'https://') === 0);
                $cand  = reset($https);
                if ($cand) return $cand;
                return reset($b['default']);
            }
            return null;
        };

        $secure = $pick($bucket['web/secure/base_url']);
        $unsec  = $pick($bucket['web/unsecure/base_url']);

        $base = $secure ?: $unsec;
        if (!$base) return '';

        // Normalize: strip trailing index.php and ensure trailing slash
        $base = preg_replace('~/index\.php/?$~i', '/', $base);
        if (substr($base, -1) !== '/') {
            $base .= '/';
        }

        return $base;
    }

    private function determineExitCode(array $result): int
    {
        $failedFindings = array_filter(
            $result['findings'] ?? [],
            static fn(array $finding): bool => strtoupper((string)($finding['status'] ?? '')) === 'FAIL'
        );
        if ($failedFindings === []) {
            return Command::SUCCESS;
        }

        foreach ($failedFindings as $finding) {
            if (strtolower((string)($finding['severity'] ?? '')) === 'critical') {
                return 2;
            }
        }

        return Command::FAILURE;
    }

    private function writePhase(OutputInterface $out, int $current, int $total, string $message): void
    {
        if ($out->isQuiet()) {
            return;
        }

        $out->writeln(sprintf('<fg=cyan>[%d/%d]</> %s', $current, $total, $message));
    }

    private function createRuleProgressBar(OutputInterface $out, int $totalRules): ProgressBar
    {
        $progress = new ProgressBar($out, max(1, $totalRules));
        $progress->setFormat(' %current%/%max% [%bar%] %percent:3s%%  %message%');
        $progress->setMessage('Starting rule scan');
        $progress->start();

        return $progress;
    }

    private function formatRuleProgressMessage(array $event): string
    {
        $ruleId = (string)($event['rule_id'] ?? '');
        $title = trim((string)($event['title'] ?? ''));
        $status = strtoupper((string)($event['status'] ?? ''));

        $label = $ruleId;
        if ($title !== '') {
            $label .= ($label !== '' ? ' - ' : '') . $this->truncateProgressTitle($title, 70);
        }
        if ($status !== '') {
            $label .= ' [' . $status . ']';
        }

        return $label !== '' ? $label : 'Scanning rules';
    }

    private function truncateProgressTitle(string $title, int $maxLength): string
    {
        if (strlen($title) <= $maxLength) {
            return $title;
        }

        return rtrim(substr($title, 0, $maxLength - 3)) . '...';
    }

    private function compactFindingDescription(array $finding): string
    {
        $message = trim((string)($finding['message'] ?? ''));
        $message = preg_replace('/^\[UNKNOWN\]\s*/', '', $message) ?? $message;
        if ($message === '') {
            return trim((string)($finding['title'] ?? ''));
        }

        // Check messages commonly use the first line as their description and
        // subsequent lines for paths, packages, or other supporting evidence.
        $firstLine = trim((string)strtok($message, "\r\n"));
        if ($firstLine !== $message) {
            return rtrim($firstLine, ': ');
        }

        // Some checks append large package/advisory lists on the same line.
        // Hide that payload in the default view while preserving ordinary
        // descriptions such as "HTTP error: certificate problem".
        if (preg_match('/^(.+?):\s+(.+)$/s', $firstLine, $parts) === 1) {
            $detail = $parts[2];
            if (
                str_contains($detail, ' -> ')
                || str_contains($detail, '; ')
                || preg_match('/\S+@\S+/', $detail) === 1
            ) {
                return rtrim(trim($parts[1]), ': ');
            }
        }

        return $firstLine;
    }

    private function detailedFindingMessage(array $finding): string
    {
        $message = trim((string)($finding['message'] ?? ''));
        $message = preg_replace('/^\[UNKNOWN\]\s*/', '', $message) ?? $message;
        return $message !== '' ? $message : trim((string)($finding['title'] ?? ''));
    }

    private function renderCheckDetails(OutputInterface $out, array $finding): void
    {
        $items = is_array($finding['detail'] ?? null) ? $finding['detail'] : [];
        if ($items === []) {
            foreach ((array)($finding['details'] ?? []) as $legacy) {
                if (!is_array($legacy)) continue;
                $items[] = [
                    'check' => (string)($legacy[0] ?? ''),
                    'message' => (string)($legacy[1] ?? ''),
                    'status' => ($legacy[2] ?? null) === true
                        ? 'PASS'
                        : (($legacy[2] ?? null) === false ? 'FAIL' : 'UNKNOWN'),
                ];
            }
        }
        if ($items === []) return;

        $out->writeln('    <options=bold>Detail</>');
        foreach ($items as $item) {
            if (!is_array($item)) continue;
            $check = trim((string)($item['check'] ?? 'check'));
            $status = strtoupper(trim((string)($item['status'] ?? 'UNKNOWN')));
            $message = trim((string)($item['message'] ?? ''));
            $lines = preg_split('/\R/', $message) ?: [];
            $first = array_shift($lines) ?: '';
            $out->writeln(sprintf('      - %s [%s]: %s', $check, $status, $first));
            foreach ($lines as $line) {
                if (trim($line) !== '') {
                    $out->writeln('        ' . rtrim($line));
                }
            }
        }
    }

    /** @return list<string> */
    private function inconclusiveResolutionSteps(array $finding): array
    {
        $id = strtoupper(trim((string)($finding['id'] ?? '')));
        $message = strtolower((string)($finding['message'] ?? ''));

        return match ($id) {
            'MB-R027' => [
                'Use a trusted TLS certificate, or install and trust the local CA when scanning a development URL.',
                'Confirm the HTTPS response includes a Strict-Transport-Security header with max-age >= 15552000.',
            ],
            'MB-R033' => [
                'Add a readable php.ini or .user.ini to the Magento root with display_errors=Off.',
                'If the rule also checks a URL, confirm application error pages do not expose stack traces.',
            ],
            'MB-R039' => [
                'Run bin/magento indexer:status and resolve indexers that are not ready.',
                'Provide readable normalized indexer evidence at var/.indexer_status using one "indexer: READY" entry per line.',
            ],
            'MB-R047' => [
                'Ensure Magento cron is running and updates var/cron/cron.timestamp, var/log/cron.log, or var/log/magento.cron.log.',
                'Make at least one heartbeat file readable and newer than 900 seconds when the scan runs.',
            ],
            'MB-R048' => [
                'Export a numeric cron backlog metric to var/cron/queue.size, var/cron/backlog.json, or var/cron/backlog.txt.',
                'Make the metric file readable and verify its value can be parsed before re-running the rule.',
            ],
            'MB-R061', 'MB-R063' => [
                'Verify HTTPS connectivity to api.magebean.com/v1/packages/status from the scan environment.',
                'Allow the endpoint through any proxy or firewall, then retry the rule.',
            ],
            'MB-R072' => [
                'Run the scan against the original Git checkout that contains its .git metadata, not a copied release directory.',
                'Ensure the scanner can read .git and the repository history.',
            ],
            'MB-R077' => [
                'Ensure app/code exists and contains the custom PHP files that should be assessed.',
                'Grant the scan process read permission to app/code and its files.',
            ],
            default => $this->genericInconclusiveResolutionSteps($message, $id),
        };
    }

    /** @return list<string> */
    private function failureResolutionSteps(array $finding): array
    {
        $steps = array_values(array_filter(
            (array)($finding['remediation'] ?? []),
            static fn($step): bool => is_string($step) && trim($step) !== ''
        ));
        if ($steps !== []) {
            return array_map(static fn(string $step): string => trim($step), $steps);
        }

        return [
            'Review the failed check message and evidence above.',
            'Apply the required configuration change, then verify the affected endpoint or file directly.',
        ];
    }


    /** @return list<string> */
    private function genericInconclusiveResolutionSteps(string $message, string $id): array
    {
        if (str_contains($message, 'api') || str_contains($message, 'http')) {
            return [
                'Verify network, DNS, TLS, proxy, and authentication requirements for the reported endpoint.',
                'Retry the rule after the endpoint is reachable from the scan environment.',
            ];
        }
        if (str_contains($message, 'not found') || str_contains($message, 'unable to read')) {
            return [
                'Restore the missing input named in the message and make it readable by the scan process.',
                'Retry the rule after confirming the file or directory exists under the scan target.',
            ];
        }

        return $id !== ''
            ? ['Review the rule requirements and remediation guidance: https://magebean.com/baseline/' . rawurlencode($id)]
            : ['Review the rule requirements and remediation guidance at https://magebean.com/baseline'];
    }
}
