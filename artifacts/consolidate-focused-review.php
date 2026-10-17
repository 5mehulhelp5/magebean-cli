<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\RequirementProfileCatalog;
$reviews=[];$rows=[];$unique=[];
foreach(['basic'=>'basic','hardening'=>'hardening','owasp'=>'owasp-top-10-2025']as$file=>$profile){
    $review=json_decode(file_get_contents(__DIR__.'/focused-'.$file.'-review.json'),true,512,JSON_THROW_ON_ERROR);
    $expected=RequirementProfileCatalog::load($profile)['requirement_ids'];$actual=array_column($review['items'],'id');
    $a=$actual;$b=$expected;sort($a);sort($b);
    if($a!==$b||count(array_unique($actual))!==count($actual))throw new RuntimeException('Missing, extra or duplicate review rows: '.$profile);
    $counts=[];
    foreach($review['items']as$item){
        if(!in_array($item['decision'],['KEEP','REVISE','OPTIONAL','REPLACE','SUPPORT'],true))throw new RuntimeException('Unknown decision');
        $unique[$item['id']]=true;$counts[$item['decision']]=($counts[$item['decision']]??0)+1;
        $rows[]=['profile'=>$profile,'id'=>$item['id'],'title'=>$item['title'],'decision'=>$item['decision'],'priority'=>$item['priority']??'see profile report','current_claim'=>$item['current_criterion']??$item['actual_claim']??'see binding inventory','action'=>$item['assessment_and_action']??$item['proposed_scope_and_evidence']??$item['proposed_claim']??'see report','boundary'=>$item['evidence_boundary']??$item['human_boundary']??$item['customer_risk']??'see report','fixtures'=>isset($item['fixtures'])?json_encode($item['fixtures'],JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR):($item['fixture_gap']??$item['fixture_acceptance']??'see report'),'references'=>implode(' | ',$item['references']??$item['implementation_refs']??$item['source_refs']??[])];
    }
    $reviews[$profile]=['membership_count'=>count($actual),'decision_counts'=>$counts,'detail_file'=>'focused-'.$file.'-review.json'];
}
$out=fopen(__DIR__.'/focused-profile-decisions.csv','w');fputcsv($out,array_keys($rows[0]),',','"','');foreach($rows as$row)fputcsv($out,array_values($row),',','"','');fclose($out);
file_put_contents(__DIR__.'/focused-profile-decisions.json',json_encode(['date'=>'2026-10-17','scope'=>'Review proposals, not applied catalog/runtime changes. KEEP retains membership/scoped intent; common collector/predicate fixes still apply to every profile sharing the check. Fixtures are proposed acceptance cases unless explicitly recorded as executed in source-scope observations.','membership_rows'=>count($rows),'unique_requirements'=>count($unique),'profiles'=>$reviews],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
echo json_encode(['reviewed_memberships'=>count($rows),'unique_requirements'=>count($unique),'profiles'=>$reviews],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),PHP_EOL;
