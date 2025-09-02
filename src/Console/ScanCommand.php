<?php

declare(strict_types=1);

namespace Magebean\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Magebean\Engine\{ScanRunner, Context, RulePackLoader};
use Magebean\Engine\Reporting\{HtmlReporter, JsonReporter, SarifReporter};


final class ScanCommand extends Command
{
    protected function configure(): void
    {
        $this->setName('scan')
            ->setDescription('Run audit with built-in/dropped-in controls')
            ->addOption('path', null, InputOption::VALUE_REQUIRED, 'Magento root path', getcwd())
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'json|html|sarif', 'html')
            ->addOption('output', null, InputOption::VALUE_REQUIRED, 'Output file', 'report.html')
            ->addOption('controls', null, InputOption::VALUE_OPTIONAL, 'Comma list of controls (e.g. MB-C01,MB-C02)');
    }

    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $ctx = Context::fromArray(['path' => (string)$in->getOption('path')]);

        $controlsOpt = (string)($in->getOption('controls') ?? '');
        $controls = $controlsOpt ? array_map('trim', explode(',', $controlsOpt)) : [];

        $pack = RulePackLoader::loadAll($controls);
        $runner = new ScanRunner($ctx, $pack);
        $result = $runner->run();

        $format = strtolower((string)$in->getOption('format'));
        $reporter = match ($format) {
            'json' => new JsonReporter(),
            'sarif' => new SarifReporter(),
            default => new HtmlReporter(__DIR__ . '/../../resources/report-template.html')
        };

        $reportFile = (string)$in->getOption('output');
        $reporter->write($result, $reportFile);

        $io  = new SymfonyStyle($in, $out);

        $path    = (string)$in->getOption('path');
        $phpVer  = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        $now     = date('Y-m-d H:i');
        $env     = getenv('APP_ENV') ?: 'prod';
        $version = 'v1.0'; 

        // Header
        $io->newLine();
        $io->writeln(sprintf(
            '<options=bold>Magebean Security Audit %s</>    <comment>Target:</comment> <info>%s</info>',
            $version,
            $path
        ));
        $io->writeln(sprintf(
            'Time: <info>%s</info>    PHP: <info>%s</info>    Env: <info>%s</info>',
            $now,
            $phpVer,
            $env
        ));
        $io->newLine();

        $cveEnabled = (bool)($result['meta']['cve_enabled'] ?? false);
        if (!$cveEnabled) {
            $io->writeln('<comment>⚠ CVE check skipped</comment>');
            $io->writeln('  → Requires CVE Bundle (<info>--cve-data=magebean-cve-bundle-YYYYMM.zip</info>)');
            $io->writeln('  → Visit <info>https://magebean.com/downloads</info>');
            $io->newLine();
        }

        $failed = array_values(array_filter($result['findings'] ?? [], fn($f) => empty($f['passed'])));
        $io->writeln(sprintf('<options=bold>Findings</> (%d)', count($failed)));

        $sevTag = static function (string $sev): string {
            $sev = strtoupper($sev);
            return match ($sev) {
                'CRITICAL' => '<fg=red;options=bold>[CRITICAL]</>',
                'HIGH'     => '<fg=yellow;options=bold>[HIGH]</>',
                'MEDIUM'   => '<fg=cyan;options=bold>[MEDIUM]</>',
                default    => '<fg=white;options=bold>[LOW]</>',
            };
        };

        foreach ($failed as $f) {
            $severity = strtoupper((string)($f['severity'] ?? 'LOW'));
            $title    = (string)($f['title'] ?? ($f['id'] ?? ''));
            $io->writeln(sprintf('%s %s', $sevTag($severity), $title));
        }
        $io->newLine();

        // Summary
        $sum         = $result['summary'] ?? [];
        $rulesTotal  = (int)($sum['total']  ?? count($pack['rules']));
        $rulesPassed = (int)($sum['passed'] ?? ($rulesTotal - count($failed)));
        $rulesFailed = (int)($sum['failed'] ?? count($failed));

        $sevCounts = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0];
        foreach ($failed as $f) {
            $k = ucfirst(strtolower((string)($f['severity'] ?? 'Low')));
            if (!isset($sevCounts[$k])) {
                $k = 'Low';
            }
            $sevCounts[$k]++;
        }

        $io->writeln('<options=bold>Summary</>');
        $io->writeln(sprintf('Passed Rules: <info>%d</info> / %d', $rulesPassed, $rulesTotal));

        $issues = [];
        if ($sevCounts['Critical'] > 0) {
            $issues[] = $sevCounts['Critical'] . ' Critical';
        }
        if ($sevCounts['High']     > 0) {
            $issues[] = $sevCounts['High']     . ' High';
        }
        if ($sevCounts['Medium']   > 0) {
            $issues[] = $sevCounts['Medium']   . ' Medium';
        }
        if ($sevCounts['Low']      > 0) {
            $issues[] = $sevCounts['Low']      . ' Low';
        }
        $io->writeln('Issues: ' . ($issues ? implode(', ', $issues) : '0'));
        $io->newLine();

        // Footer
        $io->writeln(sprintf('→ Report saved to <info>%s</info>', $reportFile));
        $io->writeln('Contact: <info>support@magebean.com</info>');
        $io->newLine();

        return $result['summary']['failed'] > 0 ? Command::FAILURE : Command::SUCCESS;
    }
}
