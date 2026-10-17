<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementProfileCatalog};
$all=RequirementCatalog::loadAll()['rules'];$index=array_column($all,null,'id');
$normalize=function(array$v)use(&$normalize):array{if(!array_is_list($v))ksort($v);foreach($v as&$x)if(is_array($x))$x=$normalize($x);unset($x);return$v;};
$signature=static fn(array$c):string=>json_encode($normalize([$c['name'],$c['args']??[]]),JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
$criteria=[];$sameChecks=[];$sharedBindings=[];$within=[];$withChecks=0;$occurrences=0;
foreach($all as$r){
    $criterion=strtolower(trim(preg_replace('/\s+/u',' ',$r['criterion'])));$criteria[$criterion][]=$r['id'];$bindings=[];
    foreach($r['obligations']as$o)foreach($o['checks']as$c){$key=$signature($c);$bindings[$key]=($bindings[$key]??0)+1;$sharedBindings[$key][$r['id']]=true;++$occurrences;}
    if($bindings!==[]){++$withChecks;$keys=array_keys($bindings);sort($keys);$sameChecks[json_encode($keys,JSON_THROW_ON_ERROR)][]=$r['id'];}
    $dupes=[];foreach($bindings as$key=>$count)if($count>1)$dupes[]=['check'=>json_decode($key,true),'occurrences'=>$count,'extra_occurrences'=>$count-1];
    if($dupes!==[])$within[]=['id'=>$r['id'],'title'=>$r['title'],'duplicates'=>$dupes];
}
$criterionGroups=[];foreach($criteria as$criterion=>$ids)if(count($ids)>1)$criterionGroups[]=['criterion'=>$criterion,'ids'=>$ids];
$checkGroups=[];foreach($sameChecks as$key=>$ids)if(count($ids)>1)$checkGroups[]=['ids'=>$ids,'titles'=>array_map(static fn($id)=>$index[$id]['title'],$ids),'checks'=>array_map(static fn($k)=>json_decode($k,true),json_decode($key,true))];
$shared=[];foreach($sharedBindings as$key=>$ids)if(count($ids)>1)$shared[]=['check'=>json_decode($key,true),'requirements'=>array_keys($ids),'count'=>count($ids)];usort($shared,static fn($a,$b)=>$b['count']<=>$a['count']);
$members=[];$profileRows=0;$duplicateMemberships=[];
foreach(RequirementProfileCatalog::all()as$key=>$profile){$members[$key]=$profile['requirement_ids'];$profileRows+=count($profile['requirement_ids']);if(count($profile['requirement_ids'])!==count(array_unique($profile['requirement_ids'])))$duplicateMemberships[]=$key;}
$overlap=[];foreach($members as$a=>$ids)foreach($members as$b=>$other)if($a!==$b)$overlap[$a][$b]=count(array_intersect($ids,$other));
$consolidations=RequirementCatalog::read('semantic-consolidations');
$report=['scope'=>'Current active catalog. Exact criterion normalization only lowercases and collapses whitespace. Same check+args set or repeated observations do NOT prove equivalent obligations, scope, applicability or conformance. Default obligations only for detector comparisons; mode variants counted separately in other binding inventories. Empty check sets excluded.','catalog_count'=>count($all),'unique_ids'=>count($index),'requirements_with_default_checks'=>$withChecks,'default_check_occurrences'=>$occurrences,'distinct_default_check_argument_bindings'=>count($sharedBindings),'within_requirement_repetition_count'=>count($within),'identical_criterion_group_count'=>count($criterionGroups),'identical_check_set_group_count'=>count($checkGroups),'shared_binding_group_count'=>count($shared),'profile_membership_rows'=>$profileRows,'distinct_profile_requirement_ids'=>count(array_unique(array_merge(...array_values($members)))),'duplicate_ids_within_profiles'=>$duplicateMemberships,'historical_consolidation_retired_count'=>$consolidations['retired_count'],'historical_consolidation_group_count'=>count($consolidations['groups']),'exact_criterion_groups'=>$criterionGroups,'same_check_set_groups'=>$checkGroups,'within_requirement_repetitions'=>$within,'shared_bindings'=>$shared,'profile_overlap'=>$overlap];
file_put_contents(__DIR__.'/requirement-overlap-audit.json',json_encode($report,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
$summary=$report;foreach(['exact_criterion_groups','same_check_set_groups','within_requirement_repetitions','shared_bindings','profile_overlap']as$key)unset($summary[$key]);echo json_encode($summary,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),PHP_EOL;
echo 'Examples of identical check sets: ',json_encode(array_slice(array_map(static fn($g)=>['ids'=>$g['ids'],'titles'=>$g['titles']],$checkGroups),0,8),JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),PHP_EOL;
