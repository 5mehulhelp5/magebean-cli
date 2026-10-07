<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementAssessmentEvaluator,RequirementOutcome,CheckResult,CheckOutcome};
$n=0;
function criterionAssert(bool $ok,string $message):void{global$n;$n++;if(!$ok)throw new RuntimeException($message);}
$catalog=RequirementCatalog::loadAll()['rules'];$asvs=0;$pci=0;
foreach($catalog as$r){
 if($r['alignments']===[])continue;
 $reference=$r['alignments'][0];$standard=$reference['standard'];
 if(!in_array($standard,['OWASP-ASVS','PCI-DSS'],true))continue;
 if($standard==='OWASP-ASVS'){$asvs+=count(array_filter($r['alignments'],static fn(array$a):bool=>$a['standard']==='OWASP-ASVS'));criterionAssert(isset($r['source_metadata']),'ASVS normative content provenance');}
 else $pci+=count(array_filter($r['alignments'],static fn(array$a):bool=>$a['standard']==='PCI-DSS'));
 $r['applicability']=['state'=>'APPLICABLE'];
 $allPass=RequirementAssessmentEvaluator::evaluate($r,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Pass,'Positive scoped observation',[],null,$name));
 $allFail=RequirementAssessmentEvaluator::evaluate($r,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Fail,'Negative scoped observation',[],null,$name));
 criterionAssert($allPass->outcome===RequirementOutcome::ManualReview,'Positive partial signals cannot certify '.$r['id']);
 if($r['id']==='MB-0379')criterionAssert($allFail->outcome===RequirementOutcome::Fail,'Reviewed default debug counterexample can disprove the all-disabled policy');else criterionAssert($allFail->outcome===RequirementOutcome::ManualReview,'Unreviewed bindings cannot assert normative violation '.$r['id']);
 criterionAssert($r['criterion']!==$r['human_evidence']['instructions']||$r['checks']===[],'Technical scope notes must not replace normative criterion '.$r['id']);
}
criterionAssert($asvs===345&&$pci===280,'All version-qualified criteria present under internal IDs');
echo "RequirementCoverageSafetyTest: $n assertions passed\n";
