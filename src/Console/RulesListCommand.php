<?php

declare(strict_types=1);

namespace Magebean\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\{InputInterface, InputOption};
use Symfony\Component\Console\Output\OutputInterface;
use Magebean\Engine\RulePackLoader;
use Magebean\Engine\ProfileLoader;

final class RulesListCommand extends Command
{
    protected static $defaultName = 'rules:list';

    private const HELP = <<<'HELP'
List Magebean rules after applying a profile and optional control/severity filters.

PROFILES
  basic      Default; 21 basic production-readiness rules.
  asvs-l1    32 rules by default; 60 including 28 human-verification rules.
  asvs-l2    73 rules by default; 183 including 110 human-verification rules.
  asvs-l3    80 rules by default; 259 including 179 human-verification rules.
  owasp      77 application-security rules mapped to OWASP Top 10 2025.
  pci        67 rules by default; 68 including 1 human-verification rule.
  hardening  91 rules by default; 92 with human verification enabled.
  baseline   113 automated rules by default; 371 including manual review. Aliases: all, magebean.
  FILE       Custom profile JSON path or a profile under .magebean/profiles.

OPTIONS
  --profile=PROFILE|FILE       Select the profile. Default: basic.
  --include-manual-review    Include human-review rules; excluded by default.
  --capabilities=NAME,NAME    Include contextual rules for enabled application capabilities.
  --control=MB-Cxx,MB-Cxx     Keep only the listed controls.
  --severity=LEVEL             Keep low, medium, high, or critical rules.
  -h, --help                   Show this help.
  -V, --version                Show the Magebean version.
  -q, --quiet                  Show errors only.
  --silent                     Suppress all output.
  --ansi|--no-ansi             Force or disable ANSI formatting.
  -n, --no-interaction         Disable interactive questions.
  -v|vv|vvv                    Increase verbosity.

EXAMPLES
  php magebean.phar rules:list
  php magebean.phar rules:list --profile=asvs-l1
  php magebean.phar rules:list --profile=asvs-l2 --include-manual-review --capabilities=oauth_oidc
  php magebean.phar rules:list --profile=asvs-l3 --include-manual-review
  php magebean.phar rules:list --profile=hardening
  php magebean.phar rules:list --profile=baseline --control=MB-C03
  php magebean.phar rules:list --profile=owasp --severity=critical
  php magebean.phar rules:list --profile=.magebean/profiles/acme.json

Filters are intersected: --control and --severity only reduce the selected profile.
HELP;

    protected function configure(): void
    {
        $this->setName('rules:list')
            ->setDescription('List and filter Magebean rules by profile, control, and severity.')
            ->addUsage('--profile=hardening')
            ->addUsage('--profile=baseline --control=MB-C03')
            ->addUsage('--profile=owasp --severity=critical')
            ->setHelp(self::HELP)
            ->addOption('include-manual-review', null, InputOption::VALUE_NONE, 'Include human manual-review rules (excluded by default)')
            ->addOption('capabilities', null, InputOption::VALUE_OPTIONAL, 'Comma list of application capabilities for contextual rules')
            ->addOption('control', null, InputOption::VALUE_OPTIONAL, 'Comma list of controls (e.g. MB-C01,MB-C02)')
            ->addOption('profile', null, InputOption::VALUE_OPTIONAL, 'Profile: basic (default) | asvs-l1 | asvs-l2 | asvs-l3 | owasp | pci | hardening | baseline | custom JSON')
            ->addOption('severity', null, InputOption::VALUE_OPTIONAL, 'low|medium|high|critical');
    }
    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $controlsOpt = (string)($in->getOption('control') ?? '');
        $capabilitiesOpt = trim((string)($in->getOption('capabilities') ?? ''));
        $includeManualReview = (bool)$in->getOption('include-manual-review');
        $capabilities = $capabilitiesOpt === '' ? [] : array_fill_keys(array_filter(array_map('trim', explode(',', strtolower($capabilitiesOpt)))), true);
        $profileOpt = trim((string)($in->getOption('profile') ?? ''));
        if ($profileOpt === '') {
            $profileOpt = 'basic';
        }
        $controls = $controlsOpt ? array_map('trim', explode(',', $controlsOpt)) : [];
        $pack = RulePackLoader::loadAll($controls);
        if ($profileOpt !== '' && !in_array(strtolower($profileOpt), ['baseline', 'all', 'magebean'], true)) {
            $profile = ProfileLoader::load($profileOpt, getcwd() ?: '');
            $pack = ProfileLoader::apply($pack, $profile, $controls !== [], $capabilities);
            $out->writeln(sprintf(
                '<info>Profile:</info> %s (%s)',
                (string)($profile['id'] ?? $profileOpt),
                (string)($profile['title'] ?? '')
            ));
        }
        $profileRulesTotal = count($pack['rules'] ?? []);
        $profileManualRulesTotal = count(array_filter($pack['rules'] ?? [], static fn(array $rule): bool => strtolower((string)($rule['verification'] ?? 'automated')) === 'manual'));
        if (!$includeManualReview) {
            $pack['rules'] = array_values(array_filter(
                $pack['rules'] ?? [],
                static fn(array $rule): bool => strtolower((string)($rule['verification'] ?? 'automated')) !== 'manual'
            ));
        }
        $sev = $in->getOption('severity');
        $count = 0;
        foreach ($pack['rules'] as $r) {
            if ($sev && strcasecmp($r['severity'], (string)$sev) !== 0) continue;
            $mapping = '';
            if (isset($r['profile']['mapping']) && is_array($r['profile']['mapping'])) {
                $m = $r['profile']['mapping'];
                $refs = $m['requirements'] ?? $m['categories'] ?? $m['map'] ?? [];
                if (is_array($refs) && $refs) {
                    $mapping = ' (' . implode(', ', array_map('strval', $refs)) . ')';
                }
            }
            $out->writeln("{$r['id']} [{$r['control']}] {$r['severity']} — {$r['title']}{$mapping}");
            $count++;
        }
        $out->writeln("<info>Total Rules Listed: {$count}</info>");
        $out->writeln(sprintf('<info>Total Profile Rules: %d</info> (including %d human verification %s)', $profileRulesTotal, $profileManualRulesTotal, $profileManualRulesTotal === 1 ? 'rule' : 'rules'));
        if (!$includeManualReview && $profileManualRulesTotal > 0) {
            $out->writeln(sprintf('<comment>Human verification rules hidden: %d. Use --include-manual-review to show them.</comment>', $profileManualRulesTotal));
        } elseif ($includeManualReview && $profileManualRulesTotal > 0) {
            $out->writeln(sprintf('<info>Human verification rules included: %d.</info>', $profileManualRulesTotal));
        } else {
            $out->writeln('<comment>Human verification rules: none in this profile. Use --include-manual-review when the selected profile provides them.</comment>');
        }        return Command::SUCCESS;
    }
}
