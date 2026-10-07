<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
use Magebean\Engine\{Context,CheckOutcome,ScanDeadline,ScanDeadlineExceeded};
use Magebean\Engine\Checks\{CheckRegistry,RuntimeEvidenceCheck};
use Magebean\Engine\Collectors\CollectorSet;
$n=0;
function genericAssert(bool $ok,string $message):void {global $n;$n++;if(!$ok)throw new RuntimeException($message);}
function genericReject(callable $call,string $message):void {try{$call();}catch(InvalidArgumentException){genericAssert(true,$message);return;}genericAssert(false,$message);}
$root=sys_get_temp_dir().'/magebean-generic-evidence-'.bin2hex(random_bytes(6));
mkdir($root);mkdir($root.'/app');mkdir($root.'/.magebean');mkdir($root.'/.magebean/evidence');
$collectors=new CollectorSet();
$registry=CheckRegistry::fromContext(new Context($root,''),$collectors);
try {
 foreach(['source_security_observations','http_response_media_evidence','identity_inventory_evidence']as$name)genericAssert($registry->has($name),'Generic registration available');
 $recipe=['patterns'=>[['safe_text','~\btextContent\b~','candidate_control'],['html_sink','~\binnerHTML\b~','review_sink']]];
 genericAssert($registry->runResult('source_security_observations',$recipe)->outcome===CheckOutcome::Unknown,'Empty source does not establish compliance');
 file_put_contents($root.'/app/example.js','/* target.innerHTML = password; */ target.textContent = input; const note = "innerHTML";');
 $result=$registry->runResult('source_security_observations',$recipe);
 genericAssert($result->outcome===CheckOutcome::ManualReview,'Observations require independent assessment');
 genericAssert(count($result->evidence['observations'])===1 && $result->evidence['observations'][0]['signal']==='safe_text','Comments and literal text excluded from observations');
 genericAssert(!isset($result->evidence['requirement']) && !str_contains(json_encode($result->evidence),'password'),'Generic result does not disclose standard identity or source');
 $other=$registry->runResult('source_security_observations',['patterns'=>[['generic_assignment','~\btextContent\b~','candidate_control']]]);
 genericAssert($other->evidence['observations'][0]['signal']==='generic_assignment','Same function supports independent recipe');
 genericReject(fn()=>$registry->runResult('source_security_observations',[]),'Missing recipe rejected');
 genericReject(fn()=>$registry->runResult('source_security_observations',['patterns'=>[['bad','~[~','signal']]]),'Invalid regex rejected');
 foreach(['../outside','..\\outside','/tmp','C:\\outside']as$path)genericReject(fn()=>$registry->runResult('source_security_observations',$recipe+['scope'=>[$path]]),'Scope escape rejected');
 genericAssert($registry->runResult('http_response_media_evidence',[])->outcome===CheckOutcome::Unknown,'Missing endpoint remains unknown');
 $media=RuntimeEvidenceCheck::inspectResponse(['status'=>200,'headers'=>['content-type'=>'application/json'],'body'=>'{"ok":true}']);
 genericAssert($media['assessable'] && !isset($media['requirement']),'Generic media analysis has no criterion identity');
 $artifact='.magebean/evidence/custom-accounts.json';
 file_put_contents($root.'/'.$artifact,json_encode(['schema_version'=>'1.0','scope'=>'application','complete'=>true,'generated_at'=>gmdate('c'),'accounts'=>[['username'=>'bootstrap','enabled'=>true]]]));
 $identity=$registry->runResult('identity_inventory_evidence',['artifact'=>$artifact,'default_names'=>['bootstrap']]);
 genericAssert($identity->outcome===CheckOutcome::ManualReview && $identity->evidence['enabled_default_names']===['bootstrap'],'Caller policy supports application-specific default identities');
 genericAssert(!isset($identity->evidence['requirement']),'Account observation has no criterion identity');
 foreach(['../outside','..\\outside','/tmp','C:\\outside']as$path)genericReject(fn()=>$registry->runResult('identity_inventory_evidence',['artifact'=>$path]),'Artifact escape rejected');
 file_put_contents($root.'/'.$artifact,json_encode(['schema_version'=>'1.0','scope'=>'application','complete'=>true,'generated_at'=>gmdate('c',time()-120),'accounts'=>[]]));
 genericAssert($registry->runResult('identity_inventory_evidence',['artifact'=>$artifact,'freshness_seconds'=>60])->outcome===CheckOutcome::Unknown,'Explicit freshness policy enforced');
 genericReject(fn()=>$registry->runResult('identity_inventory_evidence',['artifact'=>$artifact,'freshness_seconds'=>0]),'Invalid freshness policy rejected');
 $collectors->session->begin(null,static function():void {throw new ScanDeadlineExceeded();});
 try{$registry->runResult('source_security_observations',$recipe);genericAssert(false,'Collector checkpoint propagates deadline');}catch(ScanDeadlineExceeded){genericAssert(true,'Collector checkpoint propagates deadline');}finally{$collectors->session->end();}
} finally {
 foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST)as$file){$file->isDir()?rmdir($file->getPathname()):unlink($file->getPathname());}rmdir($root);
}
echo "GenericSecurityEvidenceTest: $n assertions passed\n";

