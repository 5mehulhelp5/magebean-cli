<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Pci\PciAssessmentReportBuilder;
function assertPciReport(bool $condition,string $message):void { if(!$condition) throw new RuntimeException($message); }
$coverage=['requirements'=>[['id'=>'4.2.1.1','coverage'=>'UNMAPPED','gap_action'=>'Assess certificate and key inventories.']]];
$triage=['requirements'=>[['requirement'=>'4.2.1.1','objective'=>'PAN is protected during transmission','testing_methods'=>['examine']]]];
$applicability=['requirements'=>[['requirement'=>'4.2.1.1','status'=>'APPLICABLE','rationale'=>'Confirmed scope.']]];
$evidence=['summary'=>['items'=>1],'evidence_by_requirement'=>['4.2.1.1'=>[['id'=>'ev-1']]]];
$scan=['findings'=>[]];
$builder=new PciAssessmentReportBuilder();
$hidden=$builder->build($scan,$coverage,$triage,$applicability,$evidence,false);
assertPciReport($hidden['requirements'][0]['assessment_status']==='EVIDENCE_COLLECTED_HUMAN_VERIFICATION_REQUIRED','Imported evidence must never become PASS');
assertPciReport($hidden['human_actions']===[]&&!isset($hidden['requirements'][0]['human_assessment_scope']),'Human prompts must be opt-in');
assertPciReport(($hidden['summary']['human_verification_required']??null)===1,'Human verification count must include every registry requirement even when detailed actions are hidden');
$shown=$builder->build($scan,$coverage,$triage,$applicability,$evidence,true);
assertPciReport(count($shown['human_actions'])===1&&$shown['requirements'][0]['human_assessment_scope']==='PAN is protected during transmission','Human prompt must describe the assessment scope');
assertPciReport(str_contains($shown['disclaimer'],'not PCI DSS certification'),'PCI disclaimer is missing');
echo "PciAssessmentReportBuilderTest: PASS\n";