<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
use Magebean\Engine\{Context,CheckResult,CheckOutcome,RequirementOutcome,RequirementAssessmentEvaluator,RequirementCatalog,RuleValidator,ScanRunner,ScanDeadline,ScanDeadlineExceeded};
use Magebean\Engine\Checks\CheckRegistry;
$n=0;
function domainAssert(bool $ok,string $message):void {global$n;$n++;if(!$ok)throw new RuntimeException($message);}
$registry=new CheckRegistry();
foreach(['positive','negative','absent','human']as$key)$registry->register($key,static fn(array$args):CheckResult=>CheckResult::of(match($key){'positive'=>CheckOutcome::Pass,'negative'=>CheckOutcome::Fail,'human'=>CheckOutcome::ManualReview,default=>CheckOutcome::Unknown},$key));
function definition(array$checks=[],string$proof='verified_predicate',string$op='all',bool$human=false):array {
 return ['id'=>'MB-9999','revision'=>1,'title'=>'Scoped criterion','criterion'=>'The declared sample meets the required predicate.','control'=>'MB-C01','severity'=>'high','coverage'=>'PARTIAL','verification'=>'automated','review_state'=>'security_reviewed','human_evidence'=>['required'=>$human,'instructions'=>$human?'Obtain reviewer evidence.':''],'alignments'=>[],'target_modes'=>['LOCAL'],'checks'=>array_map(static fn($name):array=>['name'=>$name,'args'=>[]],$checks),'op'=>'all','obligations'=>$checks===[]?[]:[['id'=>'O001','role'=>'mandatory','proof'=>$proof,'op'=>$op,'checks'=>array_map(static fn($name):array=>['name'=>$name,'args'=>[]],$checks)]]];
}
$observe=static fn(string$name,array$args):CheckResult=>$registry->runResult($name,$args);
$r=definition(['positive']);domainAssert(RuleValidator::validatePack(['assessment_model'=>'internal-requirement-v1','rules'=>[$r]],$registry)===[],'Valid canonical schema accepted');
domainAssert(RequirementAssessmentEvaluator::evaluate($r,$observe)->outcome===RequirementOutcome::Pass,'Reviewed verified mandatory success passes');
$r=definition(['negative','absent']);domainAssert(RequirementAssessmentEvaluator::evaluate($r,$observe)->outcome===RequirementOutcome::Fail,'Reviewed verified counterexample proves failure despite incomplete positive coverage');
$r=definition(['negative','absent'],'heuristic');domainAssert(RequirementAssessmentEvaluator::evaluate($r,$observe)->outcome===RequirementOutcome::Unknown,'Heuristic failure cannot hide missing mandatory evidence');
$r=definition(['negative'],'heuristic');$a=RequirementAssessmentEvaluator::evaluate($r,$observe);domainAssert($a->outcome===RequirementOutcome::Unknown&&$a->reasonCode==='REQUIREMENT_AUTOMATION_INSUFFICIENT','Heuristic failure is inconclusive without an actual human obligation');
$r=definition(['negative','absent']);$r['review_state']='pending_security_review';domainAssert(RequirementAssessmentEvaluator::evaluate($r,$observe)->outcome===RequirementOutcome::Unknown,'Pending predicate binding cannot prove failure over missing evidence');
$r=definition(['positive','negative'],'verified_predicate','any');$calls=0;
$assessment=RequirementAssessmentEvaluator::evaluate($r,static function(string$name,array$args)use(&$calls,$observe):CheckResult{$calls++;return$observe($name,$args);});
domainAssert($assessment->outcome===RequirementOutcome::Pass&&$calls===1,'Verified true alternative short-circuits');
$r=definition(['positive','absent'],'heuristic','any');$a=RequirementAssessmentEvaluator::evaluate($r,$observe);domainAssert($a->outcome===RequirementOutcome::Unknown&&$a->reasonCode==='REQUIREMENT_AUTOMATION_INSUFFICIENT','Heuristic positive alternative is not conformance proof');
$r=definition(['positive']);$r['obligations'][]=['id'=>'O002','role'=>'supporting','proof'=>'heuristic','op'=>'all','checks'=>[['name'=>'absent','args'=>[]]]];$r['checks'][]=['name'=>'absent','args'=>[]];
domainAssert(RequirementAssessmentEvaluator::evaluate($r,$observe)->outcome===RequirementOutcome::Pass,'Supporting evidence does not gate mandatory success');
$r=definition([],human:true);domainAssert(RuleValidator::validatePack(['rules'=>[$r]],$registry)===[],'Human-only criterion needs no synthetic function');
domainAssert(RequirementAssessmentEvaluator::evaluate($r,$observe)->outcome===RequirementOutcome::ManualReview,'Human-only criterion remains review');
$r=definition(['positive']);$r['applicability']=['state'=>'UNKNOWN'];$calls=0;$a=RequirementAssessmentEvaluator::evaluate($r,static function()use(&$calls):CheckResult{$calls++;throw new LogicException();});
domainAssert($a->outcome===RequirementOutcome::Unknown&&$calls===0,'Unknown applicability invokes no probes');
$bad=definition(['positive']);$bad['checks']=[];domainAssert(RuleValidator::validatePack(['rules'=>[$bad]],$registry)!==[],'Flattened checks mismatch rejected');
$bad=definition([],human:true);$bad['human_evidence']['instructions']='';domainAssert(RuleValidator::validatePack(['rules'=>[$bad]],$registry)!==[],'Human-only evidence instructions required');
foreach(['requirement_assessment','manual_review','human_manual_review_required','asvs_source_evidence']as$name){$bad=definition([$name]);domainAssert(RuleValidator::validatePack(['rules'=>[$bad]],$registry)!==[],'Legacy wrapper/stub cannot enter primary domain');}
$bad=definition(['positive']);$bad['obligations'][0]['checks'][0]['args']=['requirement'=>'3.4.2'];$bad['checks']=$bad['obligations'][0]['checks'];domainAssert(RuleValidator::validatePack(['rules'=>[$bad]],$registry)!==[],'Standard criterion dispatch rejected');
$bad=definition(['positive']);$bad['obligations'][]=$bad['obligations'][0];$bad['checks'][]=$bad['checks'][0];domainAssert(RuleValidator::validatePack(['rules'=>[$bad]],$registry)!==[],'Duplicate obligation identities rejected');
$bad=definition(['positive']);$bad['revision']='1';domainAssert(RuleValidator::validatePack(['rules'=>[$bad]],$registry)!==[],'Revision cannot be string');
$bad=definition(['positive']);$bad['target_modes']=[[]];domainAssert(RuleValidator::validatePack(['rules'=>[$bad]],$registry)!==[],'Malformed nested target modes return errors');
$bad=definition([],human:true);$bad['human_evidence']['instructions']=[];domainAssert(RuleValidator::validatePack(['rules'=>[$bad]],$registry)!==[],'Malformed human policy returns errors');
$legacy=['id'=>'MB-R999','title'=>'legacy','control'=>'MB-C01','severity'=>'high','checks'=>[['name'=>'positive']]];
domainAssert(RuleValidator::validatePack(['rules'=>[$legacy]],$registry)===[],'Legacy validation behavior retained');
$actual=RequirementCatalog::loadAll();$realRegistry=CheckRegistry::fromContext(new Context('',''));
$errors=RuleValidator::validatePack($actual,$realRegistry);domainAssert($errors===[],'Actual catalog validates: '.implode('; ',array_slice($errors,0,3)));
$clock=0.0;$deadline=new ScanDeadline(1,static function()use(&$clock):float{return$clock;});$clock=2.0;
$r=definition([],human:true);$report=(new ScanRunner(new Context('',''),['rules'=>[$r]],null,$registry,$deadline))->run();
domainAssert($report['findings'][0]['status']==='UNKNOWN'&&$report['findings'][0]['reason_code']==='SCAN_DEADLINE_EXCEEDED','Human-only assessment honors expired deadline');
$report=(new ScanRunner(new Context('',''),['rules'=>[$r]],null,$registry,null,static function():void{throw new ScanDeadlineExceeded();}))->run();
domainAssert($report['findings'][0]['status']==='UNKNOWN'&&$report['findings'][0]['reason_code']==='SCAN_DEADLINE_EXCEEDED','Human-only assessment honors lease checkpoint');
echo "RequirementDomainValidationTest: $n assertions passed\n";

