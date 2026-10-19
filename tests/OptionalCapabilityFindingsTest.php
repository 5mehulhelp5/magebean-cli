<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{ScanContext,ScanRequest,ScanPlanner};
use Magebean\Agent\AgentScanner;
$n=0;$assert=static function(bool$ok,string$message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
$manifest=['schema_version'=>'1.0','manifest_hash'=>'sha256:scope','rules'=>[]];
foreach(['MB-0804','MB-0806','MB-0807']as$id)$manifest['rules'][]=['rule_key'=>$id,'assessment_item_id'=>$id];
$plan=(new ScanPlanner())->planAgent(new ScanRequest(new ScanContext(sys_get_temp_dir(),''),['manifest'=>$manifest]));
$assert($plan->pack['rules']===[],'No check is executed without its declared optional context');
$wire=(new AgentScanner())->run(sys_get_temp_dir(),$manifest);
$assert(count($wire['results'])===3,'Skipped items retain manifest correspondence');
foreach($wire['results']as$row){
 $assert($row['status']==='unsupported','Missing optional context is skipped, not an error finding');
 $assert(empty($row['evidence']['risk_observation']['needs_attention']),'No made-up applicability finding');
 $assert(!str_contains($row['message'],'no conformance conclusion'),'No generic assessment conclusion exposed');
}
$manifest['capabilities']=['integration_debug_policy','dependency_mitigation_policy','runtime_worker_inventory'];
$plan=(new ScanPlanner())->planAgent(new ScanRequest(new ScanContext(sys_get_temp_dir(),''),['manifest'=>$manifest]));
$assert(count($plan->pack['rules'])===3,'Checks become selectable when the context is explicitly enabled');
echo "OptionalCapabilityFindingsTest: $n assertions passed\n";
