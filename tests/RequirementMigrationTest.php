<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog, LegacyAsvsRequirementAdapter, RequirementEvaluator, ProfileLoader, RulePackLoader, CheckResult, CheckOutcome, ScanRunner, ScanPlanner, ScanRequest, ScanContext, Context, RuleValidator};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Agent\AgentScanner;
use Magebean\Application;
use Symfony\Component\Console\Tester\CommandTester;
$count=0;
function requirementAssert(bool $condition,string $message):void {global $count;$count++;if(!$condition)throw new RuntimeException($message);}
$allCapabilities=[];
foreach (RulePackLoader::loadAll()['rules'] as $r) if(isset($r['applicability']['capability'])) $allCapabilities[$r['applicability']['capability']]=true;
foreach (['asvs-l1'=>70,'asvs-l2'=>253,'asvs-l3'=>345] as $name=>$expected) {
    $profile=ProfileLoader::loadBundled($name);
    $pack=ProfileLoader::applyRequirements(RulePackLoader::loadAll(),$profile,false,$allCapabilities);
    requirementAssert(count($pack['rules'])===$expected,'Complete requirement inventory, including gaps, must be present: '.$name);
    requirementAssert(count(array_unique(array_column($pack['rules'],'id')))===$expected,'Inherited requirement identities must be unique');
    foreach($pack['rules'] as $r) requirementAssert(count($r['requirements'])===1 && $r['requirements'][0]===$r['requirement'],'One definition must refer to exactly one requirement');
    requirementAssert(RuleValidator::validatePack($pack,CheckRegistry::fromContext(new Context(__DIR__,'')))===[],'Compiled catalog must be valid');
}
$legacy=RulePackLoader::loadAll();
requirementAssert(count($legacy['rules'])===371,'Legacy dashboard/catalog adapter must remain intact');
requirementAssert(count(ProfileLoader::apply($legacy,ProfileLoader::loadBundled('asvs-l1'))['rules'])===60,'Legacy ProfileLoader API must preserve its mappings');
$fixtureProfile=['id'=>'fixture','title'=>'Fixture','standard'=>['id'=>'owasp-asvs','version'=>'5.0.0','level'=>1], 'requirement_coverage'=>[['id'=>'6.2.2','status'=>'AUTOMATED','rules'=>['A','B']]]];
$source=static fn(string $id,array $checks,string $op='all'):array=>['id'=>$id,'title'=>$id,'control'=>'QA','severity'=>'high','op'=>$op,'checks'=>$checks];
$compiled=RequirementCatalog::compile(['controls'=>['QA'],'rules'=>[$source('A',[['name'=>'pass']]),$source('B',[['name'=>'fail'],['name'=>'pass']],'any')]],$fixtureProfile);
requirementAssert(count($compiled['rules'])===1 && count($compiled['rules'][0]['legacy_rule_ids'])===2,'Multiple evidence rules must merge into one requirement');
$eval=static function(string $name,array $args):CheckResult {return match($name){'pass'=>CheckResult::of(CheckOutcome::Pass,'pass evidence'),'fail'=>CheckResult::of(CheckOutcome::Fail,'failure evidence'),'human_manual_review_required'=>CheckResult::of(CheckOutcome::ManualReview,'human evidence'),'deadline'=>CheckResult::of(CheckOutcome::Unknown,'[UNKNOWN] deadline',[],'SCAN_DEADLINE_EXCEEDED'),default=>CheckResult::of(CheckOutcome::Unknown,'[UNKNOWN] unknown evidence')};};
$args=$compiled['rules'][0]['checks'][0]['args'];
requirementAssert(RequirementEvaluator::evaluate($args,$eval)->outcome===CheckOutcome::Pass,'A complete technical alternative may pass its obligation');
$args['groups'][1]['checks']=[['name'=>'fail'],['name'=>'unknown']];
requirementAssert(RequirementEvaluator::evaluate($args,$eval)->outcome===CheckOutcome::Unknown,'An unresolved alternative must not become confirmed FAIL');
$args['groups'][1]['op']='all';
$result=RequirementEvaluator::evaluate($args,$eval);
requirementAssert($result->outcome===CheckOutcome::Fail && $result->message==='failure evidence','Mandatory failure must use actual failure message, not a passing observation');
$args['coverage']='PARTIALLY_AUTOMATED';
requirementAssert(RequirementEvaluator::evaluate($args,$eval)->outcome===CheckOutcome::Unknown,'Partial failing signals plus missing evidence do not prove requirement failure');
$args['groups'][1]['checks']=[['name'=>'fail']];
requirementAssert(RequirementEvaluator::evaluate($args,$eval)->outcome===CheckOutcome::ManualReview,'A partial heuristic failure needs confirmation, rather than a false normative FAIL');
$args=$compiled['rules'][0]['checks'][0]['args'];$args['coverage']='PARTIALLY_AUTOMATED';
requirementAssert(RequirementEvaluator::evaluate($args,$eval)->outcome===CheckOutcome::ManualReview,'Partial observations cannot become requirement PASS');
requirementAssert(RequirementEvaluator::evaluate(['coverage'=>'NOT_YET_COVERED','groups'=>[]],$eval)->outcome===CheckOutcome::Unknown,'Unmapped criteria remain explicit unknown gaps');
$missing=RequirementCatalog::compile(['controls'=>['QA'],'rules'=>[$source('A',[['name'=>'pass']])]],$fixtureProfile);
requirementAssert(RequirementEvaluator::evaluate($missing['rules'][0]['checks'][0]['args'],$eval)->outcome===CheckOutcome::Unknown,'Missing source due to filtering cannot create a false PASS');
$mandatoryHuman=RequirementCatalog::compile(['controls'=>['QA'],'rules'=>[$source('A',[['name'=>'pass'],['name'=>'human_manual_review_required']],'any'),$source('B',[['name'=>'pass']])]],$fixtureProfile);
requirementAssert(RequirementEvaluator::evaluate($mandatoryHuman['rules'][0]['checks'][0]['args'],$eval)->outcome===CheckOutcome::ManualReview,'Legacy OR must not bypass mandatory human evidence');
$args=$compiled['rules'][0]['checks'][0]['args'];$args['groups'][0]['checks']=[['name'=>'deadline']];
requirementAssert(RequirementEvaluator::evaluate($args,$eval)->reasonCode==='SCAN_DEADLINE_EXCEEDED','Deadline reason must survive composite evaluation');
$bad=$fixtureProfile;$bad['requirement_coverage'][]=$bad['requirement_coverage'][0];$thrown=false;
try {RequirementCatalog::compile($legacy,$bad);} catch(RuntimeException) {$thrown=true;}
requirementAssert($thrown,'Duplicate requirement definitions must be rejected');
$bad=$fixtureProfile;$bad['requirement_coverage'][0]['id']='99.1.1';$thrown=false;
try {RequirementCatalog::compile($legacy,$bad);} catch(RuntimeException) {$thrown=true;}
requirementAssert($thrown,'Unknown standard identity must be rejected');
requirementAssert(count(LegacyAsvsRequirementAdapter::forProfile('asvs-l2')['rules'])===198,'Unspecified capabilities do not activate contextual criteria');
$graphql=LegacyAsvsRequirementAdapter::forProfile('asvs-l2',['graphql'=>false]);
requirementAssert(count($graphql['rules'])===198,'Explicitly false capability does not activate conditional evidence');
$root=sys_get_temp_dir().'/magebean-requirements-'.bin2hex(random_bytes(6));$cwd=getcwd();
try {
    foreach(['app/etc','bin','vendor','pub/media','.magebean/profiles'] as $dir)mkdir($root.'/'.$dir,0700,true);
    file_put_contents($root.'/composer.json','{"name":"magento/fixture","require":{"magento/framework":"103.0.7"}}');
    file_put_contents($root.'/bin/magento','<?php // fixture');
    file_put_contents($root.'/app/etc/env.php',"<?php return ['MAGE_MODE'=>'production'];");
    file_put_contents($root.'/app/etc/config.php',"<?php return ['modules'=>[]];");
    // Dashboard canonical context must not read a project shadow profile.
    file_put_contents($root.'/.magebean/profiles/asvs-l1.json','{"id":"asvs-l1","rules":["UNKNOWN"]}');
    chdir($root);
    $manifest=['schema_version'=>'1.0','profile'=>'asvs-l1','manifest_hash'=>'fixture','rules'=>[
        ['assessment_item_id'=>'legacy-item','rule_key'=>'MB-R091'],
        ['assessment_item_id'=>'requirement-item','rule_key'=>'OWASP-ASVS:5.0.0:2.1.1'],
    ]];
    $wire=(new AgentScanner())->run($root,$manifest);
    requirementAssert(array_keys($wire)===['schema_version','manifest_hash','summary','results'],'Wire envelope shape must remain unchanged');
    requirementAssert(count($wire['results'])===2,'Submit only manifest items, never expand them into unsolicited results');
    requirementAssert($wire['results'][0]['rule_key']==='MB-R091' && $wire['results'][0]['status']==='pass','Legacy manifest outcome must remain intact');
    $item=$wire['results'][1];
    requirementAssert($item['assessment_item_id']==='requirement-item' && $item['rule_key']==='OWASP-ASVS:5.0.0:2.1.1' && $item['status']==='error','Canonical manual requirement keeps identity and existing wire status mapping');
    requirementAssert(array_keys($item)===['assessment_item_id','rule_key','status','message','detail','evidence','checked_at','title'],'Wire result fields must remain unchanged');
    requirementAssert($item['evidence']['requirement']['id']==='2.1.1' && $item['evidence']['assessment_level']===1,'Scoped identity and level are retained in evidence');
    unset($manifest['profile']);$unsupported=(new AgentScanner())->run($root,$manifest);
    requirementAssert($unsupported['results'][1]['status']==='unsupported','Canonical jobs lacking level context must not silently guess a profile');
    $manifest['profile']='asvs-l1';$manifest['rules'][]=$manifest['rules'][1];$thrown=false;
    try {(new AgentScanner())->run($root,$manifest);}catch(RuntimeException){$thrown=true;}
    requirementAssert($thrown,'Duplicate canonical manifest IDs cannot overwrite assessment items');
    unlink($root.'/.magebean/profiles/asvs-l1.json');
    $tester=new CommandTester((new Application())->find('scan'));
    $exit=$tester->execute(['--path'=>$root,'--profile'=>'asvs-l1','--rules'=>'OWASP-ASVS:5.0.0:1.3.1','--no-ansi'=>true],['interactive'=>false]);
    $out=$tester->getDisplay();
    requirementAssert($exit===0 && str_contains($out,'OWASP-ASVS:5.0.0:1.3.1') && str_contains($out,'[UNKNOWN]'),'Canonical CLI selection reports a coverage gap without a fabricated failure');
    requirementAssert(str_contains($out,"--profile='asvs-l1'"),'Canonical rerun guidance must preserve assessment-level context');
    $duplicatePlan=(new ScanPlanner())->planCli(new ScanRequest(new ScanContext($root,''),['profile'=>'asvs-l1','rules'=>'OWASP-ASVS:5.0.0:1.3.1,owasp-asvs:5.0.0:1.3.1']),CheckRegistry::fromContext(new Context($root,'')));
    requirementAssert($duplicatePlan!==null && count($duplicatePlan->pack['rules'])===1,'Canonical selectors differing only in case must still produce one finding');
    file_put_contents($root.'/.magebean.json',json_encode(['include_rules'=>['OWASP-ASVS:5.0.0:1.3.1'],'override_rules'=>['OWASP-ASVS:5.0.0:1.3.1'=>['severity'=>'critical']]]));
    $canonicalPlan=(new ScanPlanner())->planCli(new ScanRequest(new ScanContext($root,''),['profile'=>'asvs-l1']),CheckRegistry::fromContext(new Context($root,'')));
    requirementAssert($canonicalPlan!==null && count($canonicalPlan->pack['rules'])===1 && $canonicalPlan->pack['rules'][0]['severity']==='critical','Canonical project include and display overrides apply after compilation');
    $explicit=new CommandTester((new Application())->find('scan'));
    requirementAssert($explicit->execute(['--path'=>$root,'--profile'=>'asvs-l1','--rules'=>'OWASP-ASVS:5.0.0:1.3.1','--no-ansi'=>true],['interactive'=>false])===0,'Canonical explicit selection with canonical policy must not duplicate definitions');
    $forbidden=false;
    try {\Magebean\Engine\RequirementPolicy::apply($canonicalPlan->pack,['override_rules'=>['OWASP-ASVS:5.0.0:1.3.1'=>['coverage'=>'AUTOMATED']]]);}catch(RuntimeException){$forbidden=true;}
    requirementAssert($forbidden,'Presentation policy cannot upgrade a coverage gap to automation');
    unlink($root.'/.magebean.json');
    $plan=(new ScanPlanner())->planCli(new ScanRequest(new ScanContext($root,''),['profile'=>'asvs-l1','include-manual-review'=>true,'exclude-rules'=>'MB-R016']),CheckRegistry::fromContext(new Context($root,'')));
    requirementAssert($plan!==null && !in_array('OWASP-ASVS:5.0.0:1.2.2',array_column($plan->pack['rules'],'id'),true),'Legacy exclusion alias must expand at the requirement boundary');
} finally {
    chdir($cwd);
    if(is_dir($root)){
        $nodes=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
        foreach($nodes as $node)$node->isDir()?rmdir($node->getPathname()):unlink($node->getPathname());rmdir($root);
    }
}
echo "RequirementMigrationTest: {$count} assertions passed\n";
