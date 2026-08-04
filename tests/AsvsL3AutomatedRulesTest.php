<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,ScanRunner};use Magebean\Engine\Checks\CheckRegistry;
function assertL3Auto(bool $c,string $m):void{if(!$c){fwrite(STDERR,$m."\n");exit(1);}}
$c=json_decode(file_get_contents(__DIR__.'/../src/Rules/controls/MB-C19.json'),true,512,JSON_THROW_ON_ERROR);$rules=$c['rules']??[];
assertL3Auto(array_column($rules,'id')===['MB-R368','MB-R369','MB-R370'],'Unexpected L3 automated IDs');
$ctx=new Context(__DIR__,'');$result=(new ScanRunner($ctx,['rules'=>$rules],null,CheckRegistry::fromContext($ctx)))->run();
foreach($result['findings']??[] as $f)assertL3Auto(($f['status']??'')==='UNKNOWN','L3 HTTP rule must be UNKNOWN without URL');
assertL3Auto(($result['summary']['failed']??-1)===0,'L3 HTTP rules false-failed without URL');
echo "AsvsL3AutomatedRulesTest: PASS\n";
