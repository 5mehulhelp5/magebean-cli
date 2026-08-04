<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Application;
function assertPciCli(bool $c,string $m):void{if(!$c)throw new RuntimeException($m);}
$command=(new Application())->find('scan');$definition=$command->getDefinition();
foreach(['pci-context','pci-evidence','pci-report','include-manual-review'] as $option)assertPciCli($definition->hasOption($option),"Missing --{$option}");
$help=$command->getHelp();assertPciCli(str_contains($help,'--pci-context=FILE')&&str_contains($help,'--pci-evidence=FILE')&&str_contains($help,'--pci-report=FILE'),'PCI options are missing from help');
assertPciCli(str_contains($help,'371 including manual review'),'Baseline help count is stale');
echo "PciCliOptionsTest: PASS\n";
