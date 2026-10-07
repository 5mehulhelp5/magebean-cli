<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementAssessmentEvaluator,RequirementOutcome,CheckOutcome,CheckResult};
$n=0;
function gateAssert(bool $ok,string $message):void{global$n;$n++;if(!$ok)throw new RuntimeException($message);}
$base=['id'=>'MB-TEST','revision'=>1,'review_state'=>'pending_security_review','human_evidence'=>['required'=>false],'obligations'=>[['id'=>'O001','role'=>'mandatory','proof'=>'verified_predicate','checks'=>[['name'=>'test','args'=>[]]]]]];
$observe=static fn(CheckOutcome $o):Closure=>static fn(string $name,array $args):CheckResult=>CheckResult::of($o,'Scoped observation',[],null,$name);
foreach([CheckOutcome::Pass,CheckOutcome::Fail] as $o){
 $r=RequirementAssessmentEvaluator::evaluate($base,$observe($o));
 gateAssert($r->outcome===RequirementOutcome::Unknown,'Unvalidated binding cannot certify or fail');
 gateAssert($r->reasonCode==='REQUIREMENT_BINDING_UNVALIDATED','Development gate is identified without user human request');
}
$reviewed=$base;$reviewed['review_state']='security_reviewed';
gateAssert(RequirementAssessmentEvaluator::evaluate($reviewed,$observe(CheckOutcome::Pass))->outcome===RequirementOutcome::Pass,'Reviewed complete predicate passes');
$reviewed['human_evidence']['required']=true;
gateAssert(RequirementAssessmentEvaluator::evaluate($reviewed,$observe(CheckOutcome::Fail))->outcome===RequirementOutcome::Fail,'Verified counterexample proves failure despite other human work');
gateAssert(RequirementAssessmentEvaluator::evaluate($reviewed,$observe(CheckOutcome::Pass))->outcome===RequirementOutcome::ManualReview,'Real external evidence still requires user assessment');
$heuristic=$base;$heuristic['review_state']='security_reviewed';$heuristic['obligations'][0]['proof']='heuristic';
foreach([CheckOutcome::Pass,CheckOutcome::Fail,CheckOutcome::ManualReview] as $o){
 $r=RequirementAssessmentEvaluator::evaluate($heuristic,$observe($o));
 gateAssert($r->outcome===RequirementOutcome::Unknown,'Heuristic observations remain inconclusive');
 gateAssert($r->reasonCode==='REQUIREMENT_AUTOMATION_INSUFFICIENT','Heuristic insufficiency is distinct from actual human obligation');
}
$human=$base;$human['obligations'][0]['proof']='human';$human['obligations'][0]['checks']=[];
gateAssert(RequirementAssessmentEvaluator::evaluate($human,$observe(CheckOutcome::Pass))->outcome===RequirementOutcome::ManualReview,'Human mandatory obligation retained even with development review pending');
$r=RequirementAssessmentEvaluator::evaluate($base,$observe(CheckOutcome::Unknown));
gateAssert($r->outcome===RequirementOutcome::Unknown&&$r->reasonCode==='REQUIREMENT_EVIDENCE_INCOMPLETE','Missing observations are identified separately');
echo "RequirementHumanGateTest: $n assertions passed\n";
