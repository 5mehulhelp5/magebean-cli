<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Application;
use Symfony\Component\Console\Tester\CommandTester;
function assertProfileCount(bool $condition,string $message):void{if(!$condition)throw new RuntimeException($message);}
$command=(new Application())->find('rules:list');
$profiles=[
    'basic'=>[21,21,0],
    'asvs-l1'=>[32,60,28],
    'asvs-l2'=>[73,183,110],
    'asvs-l3'=>[80,259,179],
    'owasp'=>[77,77,0],
    'pci'=>[67,68,1],
    'hardening'=>[91,92,1],
    'baseline'=>[113,371,258],
];
foreach($profiles as $profile=>[$listed,$total,$human]){
    $tester=new CommandTester($command);$tester->execute(['--profile'=>$profile,'--no-ansi'=>true]);$out=$tester->getDisplay();
    assertProfileCount(str_contains($out,"Total Rules Listed: {$listed}"),"{$profile} default listed count is wrong");
    assertProfileCount(str_contains($out,"Total Profile Rules: {$total}"),"{$profile} total profile count is missing");
    if($human>0){assertProfileCount(str_contains($out,"Human verification rules hidden: {$human}"),"{$profile} hidden human count is missing");assertProfileCount(str_contains($out,'Use --include-manual-review to show them.'),"{$profile} manual flag guidance is missing");}
    else assertProfileCount(str_contains($out,'Human verification rules: none in this profile.'),"{$profile} zero-human explanation is missing");
}
echo "ProfileRuleCountOutputTest: PASS\n";
