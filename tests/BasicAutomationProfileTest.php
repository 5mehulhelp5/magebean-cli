<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,ScanContext,ScanRequest,ScanPlanner,ScanService,ScanReportAssembler,ScanExitPolicy,CheckOutcome,CheckResult};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Console\ScanConsoleRenderer;
use Symfony\Component\Console\Output\BufferedOutput;
$n=0;function basicAutoAssert(bool$v,string$m):void{global$n;++$n;if(!$v)throw new RuntimeException($m);}
$root=sys_get_temp_dir().'/mb-basic-auto-'.bin2hex(random_bytes(6));mkdir($root);
try{
 $context=new ScanContext($root,'');$registry=CheckRegistry::fromContext($context->toLegacy());$plan=(new ScanPlanner())->planCli(new ScanRequest($context,['profile'=>'basic']),$registry);basicAutoAssert($plan!==null&&count($plan->pack['rules'])===20,'Basic selects twenty checks');
 basicAutoAssert(count(RequirementCatalog::forProfile('baseline')['rules'])===684,'Broad baseline does not also select basic scoped alternatives and double-count the same observation');
 $ids=array_column($plan->pack['rules'],'id');basicAutoAssert(!in_array('MB-0209',$ids,true)&&!in_array('MB-0379',$ids,true)&&!in_array('MB-0072',$ids,true),'Basic uses distinct deployment criteria rather than broad compliance/history');
 foreach($plan->pack['rules']as$r)basicAutoAssert(!$r['human_evidence']['required']&&$r['review_state']==='accepted_scoped_criterion','Every basic requirement is reviewed and automated');
 $catalog=array_column(RequirementCatalog::loadAll()['rules'],null,'id');basicAutoAssert($catalog['MB-0209']['human_evidence']['required']&&$catalog['MB-0379']['human_evidence']['required'],'Standard criterion meanings preserved');
 foreach(['PASS','ERROR','FAIL']as$case){$fake=new CheckRegistry();foreach($plan->pack['rules']as$r)foreach($r['checks']as$c){$name=$c['name'];if($fake->has($name))continue;$fake->register($name,static fn(array$args):CheckResult=>CheckResult::of($case==='ERROR'&&$name==='http_cookie_flags'?CheckOutcome::Unknown:($case==='FAIL'&&$name==='cache_type_enabled'?CheckOutcome::Fail:CheckOutcome::Pass),$case==='ERROR'&&$name==='http_cookie_flags'?'[UNKNOWN] Endpoint cannot be reached; provide a reachable --url.':'Verified fixture observation',[],null,$name));}
  $report=(new ScanService())->run($plan,null,$fake);$result=(new ScanReportAssembler())->assemble($report,$plan)->toLegacy();$out=new BufferedOutput();(new ScanConsoleRenderer())->renderPrettySummary($out,$result,$root);$text=$out->fetch();
  basicAutoAssert(!str_contains(strtoupper($text),'INCONCLUSIVE')&&!str_contains($text,'HUMAN VERIFICATION REQUIRED'),'Basic has no inconclusive/human presentation');
  basicAutoAssert($result['summary']['total']===20,'Alltwenty are attempted');
  if($case==='PASS'){basicAutoAssert($result['summary']['passed']===20&&$result['meta']['scan_complete'],'All verified basic checks pass');basicAutoAssert((new ScanExitPolicy())->code($result)===0,'Completed clean scan exits zero');}
  if($case==='ERROR'){basicAutoAssert(count($result['execution_errors'])===1&&str_contains($text,'EXECUTION ERRORS (1)')&&!$result['meta']['scan_complete'],'Collection failure blocks scan completion');basicAutoAssert($result['summary']['failed']===0&&$result['findings'][array_search('MB-0030',$ids,true)]['status']==='UNKNOWN','Execution gap is neither vulnerability nor false PASS; wire status remains compatible');basicAutoAssert((new ScanExitPolicy())->code($result)===3,'Execution error exits three');}
  if($case==='FAIL')basicAutoAssert((new ScanExitPolicy())->code($result)===1&&$result['summary']['failed']===1,'Verified policy violation remains finding exitone');
 }
 basicAutoAssert((new ScanExitPolicy())->code(['findings'=>[['status'=>'UNKNOWN']]])===0,'Other profile exit policy unchanged');
 echo "BasicAutomationProfileTest: $n assertions passed\n";
}finally{rmdir($root);}
