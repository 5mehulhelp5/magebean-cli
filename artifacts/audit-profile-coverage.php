<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementProfileCatalog,RequirementPolicy,RequirementAssessmentEvaluator,CheckResult,CheckOutcome,ScanContext,ScanRequest,ScanPlanner,Context};
use Magebean\Engine\Checks\CheckRegistry;

// Structural/evaluator audit only: fake observations, no target scans or network calls.
$all=RequirementCatalog::loadAll()['rules'];$index=array_column($all,null,'id');$caps=[];
foreach($all as$r)if(isset($r['applicability']['capability']))$caps[$r['applicability']['capability']]=true;
$summary=[];$rows=[];$members=[];$root=sys_get_temp_dir().'/mb-profile-review-'.bin2hex(random_bytes(5));mkdir($root,0700);
try{
    foreach(RequirementProfileCatalog::all()as$key=>$profile){
        $ids=$profile['requirement_ids'];$members[$key]=$ids;$human=0;$withChecks=0;$supportOnly=0;$edges=0;$functions=[];
        foreach($ids as$id){
            $r=$index[$id];$needsHuman=RequirementPolicy::requiresHuman($r);$human+=(int)$needsHuman;
            $checks=[];$proofs=[];$mandatory=0;$supporting=0;
            foreach($r['obligations']as$o){$proofs[$o['proof']]=($proofs[$o['proof']]??0)+1;foreach($o['checks']as$c){$checks[]=$c;$functions[$c['name']]=true;if($o['role']==='supporting')++$supporting;else ++$mandatory;}}
            $withChecks+=(int)($checks!==[]);$supportOnly+=(int)($checks!==[]&&$mandatory===0);$edges+=count($checks);
            $probe=$r;$probe['applicability']['state']='APPLICABLE';$outcomes=[];
            foreach(['all_pass'=>CheckOutcome::Pass,'all_fail'=>CheckOutcome::Fail,'all_unknown'=>CheckOutcome::Unknown]as$scenario=>$outcome){
                $assessment=RequirementAssessmentEvaluator::evaluate($probe,static fn(string$name,array$args):CheckResult=>CheckResult::of($outcome,'Synthetic evaluator audit',[],null,$name));
                $outcomes[$scenario]=['outcome'=>$assessment->outcome->value,'reason'=>$assessment->reasonCode];
            }
            $category=!$needsHuman?'automatic_scoped':($checks===[]?'human_only':($mandatory===0?'supporting_observations_plus_human':'mandatory_observations_plus_human'));
            $rows[]=['profile'=>$key,'id'=>$id,'title'=>$r['title'],'criterion'=>$r['criterion'],'category'=>$category,'human_required'=>$needsHuman?1:0,'coverage_label'=>$r['coverage'],'review_state'=>$r['review_state'],'capability'=>$r['applicability']['capability']??'','target_modes'=>implode('|',$r['target_modes']),'check_occurrences'=>count($checks),'check_functions'=>implode('|',array_values(array_unique(array_column($checks,'name')))),'mandatory_check_occurrences'=>$mandatory,'supporting_check_occurrences'=>$supporting,'proofs'=>json_encode($proofs),'synthetic_all_pass'=>$outcomes['all_pass']['outcome'],'synthetic_all_fail'=>$outcomes['all_fail']['outcome'],'synthetic_all_unknown'=>$outcomes['all_unknown']['outcome'],'human_instructions'=>$r['human_evidence']['instructions']??''];
        }
        $plans=[];
        foreach(['LOCAL','REMOTE']as$mode){
            $ctx=new ScanContext($root,$mode==='REMOTE'?'https://audit.invalid':'','',['meta'=>['target_mode'=>$mode]]);$registry=CheckRegistry::fromContext(new Context($root,$ctx->url));
            foreach(['default'=>[false,[]],'with_human'=>[true,[]],'all_capabilities_with_human'=>[true,$caps]]as$scenario=>[$include,$enabled]){
                $diagnostics=[];$options=['profile'=>$key,'include-manual-review'=>$include,'capabilities'=>implode(',',array_keys($enabled))];
                $plan=(new ScanPlanner())->planCli(new ScanRequest($ctx,$options),$registry,static function($d)use(&$diagnostics){$diagnostics[]=$d->message();});
                $plans[$mode][$scenario]=['selected'=>$plan===null?0:count($plan->pack['rules']),'plan_created'=>$plan!==null,'diagnostics'=>$diagnostics,'omitted'=>$plan?->metadata['omittedRequirements']??[]];
                if($plan!==null){$plans[$mode][$scenario]['synthetic_all_pass_outcomes']=[];foreach($plan->pack['rules']as$r){$outcome=RequirementAssessmentEvaluator::evaluate($r,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Pass,'Synthetic mode-specific audit',[],null,$name))->outcome->value;$plans[$mode][$scenario]['synthetic_all_pass_outcomes'][$outcome]=($plans[$mode][$scenario]['synthetic_all_pass_outcomes'][$outcome]??0)+1;}}
            }
        }
        $summary[$key]=['inventory'=>count($ids),'no_human'=>count($ids)-$human,'human'=>$human,'with_technical_checks'=>$withChecks,'supporting_only'=>$supportOnly,'check_occurrences'=>$edges,'distinct_check_functions'=>count($functions),'plans'=>$plans];
    }
}finally{rmdir($root);}
$overlap=[];foreach($members as$a=>$ids)foreach($members as$b=>$other)if($a!==$b)$overlap[$a][$b]=count(array_intersect($ids,$other));
$output=['date'=>'2026-10-17','scope'=>'Read-only structural coverage and synthetic evaluator/planner probes; not real detector outcomes or external standard certification.','catalog_count'=>count($all),'distinct_profile_members'=>count(array_unique(array_merge(...array_values($members)))),'profiles'=>$summary,'overlap'=>$overlap];
file_put_contents(__DIR__.'/profile-review-inventory.json',json_encode($output,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
$csv=fopen(__DIR__.'/profile-review-inventory.csv','w');fputcsv($csv,array_keys($rows[0]),',','"','');foreach($rows as$row)fputcsv($csv,array_values($row),',','"','');fclose($csv);
foreach($summary as$key=>$s)echo json_encode(['profile'=>$key,'inventory'=>$s['inventory'],'no_human'=>$s['no_human'],'human'=>$s['human'],'with_checks'=>$s['with_technical_checks'],'support_only'=>$s['supporting_only'],'check_occurrences'=>$s['check_occurrences'],'functions'=>$s['distinct_check_functions'],'default_local'=>$s['plans']['LOCAL']['default']['selected'],'all_context_local'=>$s['plans']['LOCAL']['all_capabilities_with_human']['selected'],'default_remote'=>$s['plans']['REMOTE']['default']],JSON_UNESCAPED_SLASHES),PHP_EOL;
