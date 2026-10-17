<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{ScanContext,ScanRequest,ScanPlanner,ScanService,CheckResult,CheckOutcome};
use Magebean\Engine\Checks\CheckRegistry;
$context=new ScanContext(sys_get_temp_dir(),'');
$registry=CheckRegistry::fromContext($context->toLegacy());
$plan=(new ScanPlanner())->planCli(new ScanRequest($context,['profile'=>'basic']),$registry);
if($plan===null)throw new RuntimeException('Basic plan missing');
$fake=new CheckRegistry();
foreach($plan->pack['rules'] as $rule)foreach($rule['checks'] as $check){
 if(!$fake->has($check['name']))$fake->register($check['name'],static fn(array $args):CheckResult=>CheckResult::of(CheckOutcome::Pass,'Verified fixture'));
}
$report=(new ScanService())->run($plan,null,$fake)->toLegacy();
$definitions=array_column($plan->pack['rules'],null,'id');$n=0;
foreach($report['findings'] as $finding){
 foreach(['policy_source','guidance_sources','lane'] as $field){
  if(!isset($definitions[$finding['id']][$field]))throw new RuntimeException('Basic provenance not defined: '.$field);
  if(($finding['requirement'][$field]??null)!==$definitions[$finding['id']][$field])throw new RuntimeException('Finding dropped '.$field);
  ++$n;
 }
}
echo "BasicPolicyProvenanceTest: $n assertions passed\n";
