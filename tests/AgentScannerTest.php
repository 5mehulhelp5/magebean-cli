<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Agent\AgentScanner;
function scannerAssert(bool $ok,string $message):void{if(!$ok){fwrite(STDERR,"AgentScannerTest: {$message}\n");exit(1);}}
$scanner=new AgentScanner();
$manifest=['schema_version'=>'1.0','manifest_hash'=>'sha256:test','rules'=>[['assessment_item_id'=>'item-1','rule_key'=>'SERVER-COMMAND-NOT-ALLOWED']]];
$result=$scanner->run(__DIR__,$manifest);
scannerAssert(count($result['results'])===1,'unsupported rule must be reported');
scannerAssert($result['results'][0]['status']==='unsupported','unknown rule must not execute');
scannerAssert($result['results'][0]['assessment_item_id']==='item-1','assessment item mapping missing');
scannerAssert($result['manifest_hash']==='sha256:test','manifest hash missing');
$rejected=false;
try{$scanner->run(__DIR__,['schema_version'=>'2.0','rules'=>[['assessment_item_id'=>'item-1','rule_key'=>'MB-R001']]]);}catch(RuntimeException){$rejected=true;}
scannerAssert($rejected,'future manifest schema must be rejected');
echo "AgentScannerTest: PASS\n";
