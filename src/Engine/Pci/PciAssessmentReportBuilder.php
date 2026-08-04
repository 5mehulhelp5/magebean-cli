<?php
declare(strict_types=1);
namespace Magebean\Engine\Pci;

final class PciAssessmentReportBuilder
{
    public function build(array $scan,array $coverage,array $triage,array $applicability,array $externalEvidence,bool $includeHuman,array $criterionReview=[]):array
    {
        $coverageBy=[];foreach($coverage['requirements']??[] as $r)$coverageBy[$r['id']]=$r;$triageBy=[];foreach($triage['requirements']??[] as $r)$triageBy[$r['requirement']]=$r;$reviewBy=[];foreach($criterionReview['requirements']??[] as $r)$reviewBy[$r['requirement']]=$r;$appBy=[];foreach($applicability['requirements']??[] as $r)$appBy[$r['requirement']]=$r;
        $findingBy=[];foreach($scan['findings']??[] as $f)foreach($f['profile']['mappings']??[] as $m)$findingBy[$m['requirement']][]=['rule'=>$f['id'],'status'=>$f['status'],'message'=>$f['message'],'coverage'=>$m['coverage']];
        $rows=[];$statusCounts=[];$human=[];$extBy=$externalEvidence['evidence_by_requirement']??[];
        foreach($coverageBy as $id=>$cov){$app=$appBy[$id]??['status'=>'NOT_DETERMINED','rationale'=>'No compiled applicability context was supplied.'];$findings=$findingBy[$id]??[];$external=$extBy[$id]??[];$status=$app['status'];if($status==='APPLICABLE'){$hasFail=false;foreach($findings as $f)if($f['status']==='FAIL')$hasFail=true;$status=$hasFail?'TECHNICAL_FINDING':($external!==[]?'EVIDENCE_COLLECTED_HUMAN_VERIFICATION_REQUIRED':'HUMAN_VERIFICATION_REQUIRED');}$statusCounts[$status]=($statusCounts[$status]??0)+1;$scope=($reviewBy[$id]['human_assessment_scope']??$reviewBy[$id]['criterion_summary']??null)??($triageBy[$id]['objective']??($cov['gap_action']??"Assess PCI DSS {$id} using the official testing procedures."));$row=['requirement'=>$id,'applicability'=>$app['status'],'applicability_rationale'=>$app['rationale'],'assessment_status'=>$status,'magebean_coverage'=>$cov['coverage'],'magebean_findings'=>$findings,'external_evidence'=>$external,'human_verification_required'=>true];if($includeHuman&&$app['status']!=='NOT_APPLICABLE'){$row['human_assessment_scope']=$scope;$human[]=['requirement'=>$id,'scope'=>$scope,'testing_methods'=>$triageBy[$id]['testing_methods']??[]];}$rows[]=$row;}
        return ['report_type'=>'PCI DSS 4.0.1 evidence-readiness','generated_at'=>gmdate(DATE_ATOM),'disclaimer'=>'This report is not PCI DSS certification or an attestation of compliance. Human assessment and authoritative evidence remain mandatory.','summary'=>['requirements'=>count($rows),'human_verification_required'=>count($rows),'statuses'=>$statusCounts,'external_evidence_items'=>$externalEvidence['summary']['items']??0,'human_actions_listed'=>$includeHuman?count($human):0],'requirements'=>$rows,'human_actions'=>$includeHuman?$human:[]];
    }
}
