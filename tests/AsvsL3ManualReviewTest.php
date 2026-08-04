<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Application;use Symfony\Component\Console\Tester\CommandTester;
function assertL3Manual(bool $c,string $m):void{if(!$c){fwrite(STDERR,$m."\n");exit(1);}}
$c=json_decode(file_get_contents(__DIR__.'/../src/Rules/controls/MB-C18.json'),true,512,JSON_THROW_ON_ERROR);$rules=$c['rules']??[];
assertL3Manual(count($rules)===92,'Expected 92 L3 human-assessment rules');
assertL3Manual(array_column($rules,'id')===array_map(fn($n)=>sprintf('MB-R%03d',$n),range(276,367)),'L3 manual IDs must be MB-R276..367');
foreach($rules as $r){$review=$r['checks'][0]['args']['review']??'';assertL3Manual(str_starts_with($review,'Human assessment scope'),'Concrete assessment scope missing');assertL3Manual(!str_contains($review,'Magebean CLI cannot determine or attest compliance'),'Description repeats CLI limitation disclaimer');assertL3Manual(preg_match('/[^\x09\x0A\x0D\x20-\x7E]/',$review)!==1,'Review guidance must be English-only');}
$app=new Application();$cmd=$app->find('rules:list');
$d=new CommandTester($cmd);$d->execute(['--profile'=>'asvs-l3','--no-ansi'=>true]);assertL3Manual(str_contains($d->getDisplay(),'Total Rules Listed: 80'),'L3 default must list 80 rules');assertL3Manual(!str_contains($d->getDisplay(),'MB-R276'),'L3 manual rule leaked by default');
$m=new CommandTester($cmd);$m->execute(['--profile'=>'asvs-l3','--include-manual-review'=>true,'--no-ansi'=>true]);assertL3Manual(str_contains($m->getDisplay(),'Total Rules Listed: 259'),'L3 manual flag must list 259 rules');assertL3Manual(str_contains($m->getDisplay(),'MB-R276'),'L3 manual rule missing with flag');
$oauth=new CommandTester($cmd);$oauth->execute(['--profile'=>'asvs-l3','--include-manual-review'=>true,'--capabilities'=>'oauth_oidc','--no-ansi'=>true]);assertL3Manual(str_contains($oauth->getDisplay(),'Total Rules Listed: 290'),'L3 OAuth capability must activate inherited and L3 contextual rules');
echo "AsvsL3ManualReviewTest: PASS\n";
