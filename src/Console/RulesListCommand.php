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
  standard   Default; 21 basic production-readiness rules.
  owasp      77 application-security rules mapped to OWASP Top 10 2025.
  pci        69 PCI DSS v4.0.1 payment-readiness rules.
  hardening  89 deep production-hardening rules.
  baseline   All 99 local catalog rules. Aliases: all, magebean.
  FILE       Custom profile JSON path or a profile under .magebean/profiles.

OPTIONS
  --profile=PROFILE|FILE       Select the profile. Default: standard.
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
            ->addOption('control', null, InputOption::VALUE_OPTIONAL, 'Comma list of controls (e.g. MB-C01,MB-C02)')
            ->addOption('profile', null, InputOption::VALUE_OPTIONAL, 'Profile: standard (default) | owasp | pci | hardening | baseline | custom JSON')
            ->addOption('severity', null, InputOption::VALUE_OPTIONAL, 'low|medium|high|critical');
    }
    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $controlsOpt = (string)($in->getOption('control') ?? '');
        $profileOpt = trim((string)($in->getOption('profile') ?? ''));
        if ($profileOpt === '') {
            $profileOpt = 'standard';
        }
        $controls = $controlsOpt ? array_map('trim', explode(',', $controlsOpt)) : [];
        $pack = RulePackLoader::loadAll($controls);
        if ($profileOpt !== '' && !in_array(strtolower($profileOpt), ['baseline', 'all', 'magebean'], true)) {
            $profile = ProfileLoader::load($profileOpt, getcwd() ?: '');
            $pack = ProfileLoader::apply($pack, $profile, $controls !== []);
            $out->writeln(sprintf(
                '<info>Profile:</info> %s (%s)',
                (string)($profile['id'] ?? $profileOpt),
                (string)($profile['title'] ?? '')
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
        return Command::SUCCESS;
    }
}
