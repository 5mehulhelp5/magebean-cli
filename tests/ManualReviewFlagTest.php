<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Application;
use Symfony\Component\Console\Tester\CommandTester;

function assertManualFlag(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$app = new Application();
$command = $app->find('rules:list');

$default = new CommandTester($command);
$default->execute(['--profile' => 'asvs-l2', '--no-ansi' => true]);
$defaultOutput = $default->getDisplay();
assertManualFlag(str_contains($defaultOutput, 'Total Rules Listed: 73'), 'ASVS L2 must list 73 rules by default');
assertManualFlag(!str_contains($defaultOutput, 'MB-R136'), 'Manual rule leaked into default L2 list');

$withManual = new CommandTester($command);
$withManual->execute(['--profile' => 'asvs-l2', '--include-manual-review' => true, '--no-ansi' => true]);
$manualOutput = $withManual->getDisplay();
assertManualFlag(str_contains($manualOutput, 'Total Rules Listed: 183'), 'ASVS L2 manual flag must list 183 rules');
assertManualFlag(str_contains($manualOutput, 'MB-R136'), 'Manual rule missing when flag is enabled');

$baseline = new CommandTester($command);
$baseline->execute(['--profile' => 'baseline', '--no-ansi' => true]);
assertManualFlag(str_contains($baseline->getDisplay(), 'Total Rules Listed: 113'), 'Baseline must exclude manual rules by default');

$baselineManual = new CommandTester($command);
$baselineManual->execute(['--profile' => 'baseline', '--include-manual-review' => true, '--no-ansi' => true]);
assertManualFlag(str_contains($baselineManual->getDisplay(), 'Total Rules Listed: 371'), 'Baseline manual flag must list all 371 rules');

$pci = new CommandTester($command);
$pci->execute(['--profile' => 'pci', '--no-ansi' => true]);
assertManualFlag(str_contains($pci->getDisplay(), 'Total Rules Listed: 67'), 'PCI must hide MB-R371 by default');
assertManualFlag(!str_contains($pci->getDisplay(), 'MB-R371'), 'PCI manual rule leaked without the flag');

$pciManual = new CommandTester($command);
$pciManual->execute(['--profile' => 'pci', '--include-manual-review' => true, '--no-ansi' => true]);
assertManualFlag(str_contains($pciManual->getDisplay(), 'Total Rules Listed: 68'), 'PCI manual flag must list 68 rules');
assertManualFlag(str_contains($pciManual->getDisplay(), 'MB-R371'), 'PCI manual rule is missing with the flag');

echo "ManualReviewFlagTest: PASS\n";
