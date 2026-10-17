<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{ScanContext, ScanRequest, ScanPlan, ScanReport, ScanReportAssembler, ScanExitPolicy};
use Magebean\Console\ScanConsoleRenderer;
use Symfony\Component\Console\Output\BufferedOutput;
use Magebean\Engine\Reporting\HtmlReporter;
$n=0;
function laneAssert(bool $value,string $message):void {global $n; ++$n; if(!$value)throw new RuntimeException($message);}
$task=['id'=>'backup','title'=>'Backup restore <test>','evidence_needed'=>['Restore log','Owner approval'],'applicability'=>'Production'];
$profile=['id'=>'basic','title'=>'Basic','automation_only'=>true,'evidence_tasks'=>[$task]];
$metadata=['configBasePath'=>__DIR__,'configFile'=>null,'activeProfile'=>$profile,'standard'=>'basic','isPciProfile'=>false,'profileRulesTotal'=>2,'profileManualRulesTotal'=>0,'manualRulesExcluded'=>0,'includeManualReview'=>false,'hasExplicitRuleSelection'=>false,'requestedIds'=>[],'controlsFilter'=>[],'assessment_model'=>'internal-requirement-v1','automationOnly'=>true];
$plan=new ScanPlan(new ScanRequest(new ScanContext('/nonexistent',''),[]),['rules'=>[['id'=>'MB-0001','lane'=>'security'],['id'=>'MB-0037','lane'=>'readiness']]],$metadata);
foreach(['PASS','FAIL','UNKNOWN'] as $status){
 $input=['summary'=>['total'=>2,'passed'=>$status==='PASS'?2:1,'failed'=>$status==='FAIL'?1:0],'findings'=>[['id'=>'MB-0001','status'=>'PASS','severity'=>'high'],['id'=>'MB-0037','status'=>$status,'severity'=>'low','message'=>'Cache observation']],'meta'=>[]];
 $result=(new ScanReportAssembler())->assemble(ScanReport::fromLegacy($input),$plan)->toLegacy();
 laneAssert($result['summary']['lanes']['security']===['total'=>1,'passed'=>1,'failed'=>0,'unresolved'=>0],'Security lane counts observed requirements');
 laneAssert($result['summary']['lanes']['readiness']['total']===1,'Readiness gets its own lane');
 laneAssert($result['evidence_tasks'][0]['status']==='NOT_ASSESSED'&&count($result['findings'])===2,'External evidence never becomes a finding or pass');
 laneAssert($result['summary']['total']===2,'Checklist does not inflate automated coverage');
 laneAssert((new ScanExitPolicy())->code($result)===match($status){'PASS'=>0,'FAIL'=>1,default=>3},'Existing exit semantics retained');
 $out=new BufferedOutput();(new ScanConsoleRenderer())->renderPrettySummary($out,$result,'URL:https://example.invalid');$text=$out->fetch();
 laneAssert(str_contains($text,'EXTERNAL EVIDENCE CHECKLIST')&&str_contains($text,'Backup restore <test>')&&str_contains($text,'Restore log; Owner approval'),'Evidence requirements are displayed safely');
 laneAssert($result['findings'][1]['requirement']['lane']==='readiness','Finding preserves criterion lane');
 $result['findings'][1]['requirement']['policy_source']=['owner'=>'Magebean','version'=>'basic-2','note'=>'Thresholds are Magebean policy <not Adobe mandates>.'];
 $file=tempnam(sys_get_temp_dir(),'mb-html-lanes-');
 try {
  (new HtmlReporter(__DIR__.'/../resources/report-template.html',true))->write($result,$file);
  $html=(string)file_get_contents($file);
  laneAssert(str_contains($html,'External evidence checklist')&&str_contains($html,'NOT ASSESSED: Backup restore &lt;test&gt;'),'HTML preserves and escapes external checklist');
  laneAssert(str_contains($html,'Requirement lanes')&&str_contains($html,'Readiness:'),'HTML exports lane coverage');
  laneAssert(str_contains($html,'Policy: Magebean basic-2')&&str_contains($html,'&lt;not Adobe mandates&gt;'),'HTML requirement details distinguish policy provenance');
 } finally {unlink($file);}
}
echo "BasicReportLanesTest: $n assertions passed\n";
