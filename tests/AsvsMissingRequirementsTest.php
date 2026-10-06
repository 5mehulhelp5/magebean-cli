<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog, ProfileLoader, RulePackLoader, Context, CheckOutcome, ScanDeadline, ScanDeadlineExceeded};
use Magebean\Engine\Checks\{CheckRegistry, AsvsRuntimeEvidenceCheck};
use Magebean\Engine\Collectors\{CollectorSet, CollectionSession};
$n=0;
function missingAssert(bool $ok,string $message):void {global $n;$n++;if(!$ok)throw new RuntimeException($message);}
$ids=['1.3.1','2.2.1','3.2.2','3.5.3','4.1.1','6.2.4','6.3.2','9.1.1','9.1.2','9.1.3','9.2.1','11.4.1'];
foreach(['asvs-l1','asvs-l2','asvs-l3'] as $profile){
 $pack=RequirementCatalog::forProfile($profile);$index=array_column($pack['rules'],null,'id');
 foreach($ids as $id){
  $r=$index['OWASP-ASVS:5.0.0:'.$id];
  missingAssert($r['coverage']==='PARTIALLY_AUTOMATED','New evidence does not justify fully automated conformance: '.$id);
  missingAssert(count($r['checks'][0]['args']['groups'])===1 && $r['checks'][0]['args']['groups'][0]['checks']!==[],'Each former gap has executable native evidence: '.$id);
 }
 missingAssert(ProfileLoader::loadBundled($profile)['coverage_summary']['not_yet_covered']===0,'Coverage summaries reflect native implementation');
}
missingAssert(count(RulePackLoader::loadAll()['rules'])===371,'Do not alter legacy dashboard evidence catalog');
$root=sys_get_temp_dir().'/magebean-asvs-native-'.bin2hex(random_bytes(6));mkdir($root);mkdir($root.'/app');mkdir($root.'/.magebean');mkdir($root.'/.magebean/evidence');
$server=null;
try{
 $registry=CheckRegistry::fromContext(new Context($root,''));
 foreach($ids as $id){
  $r=array_column(RequirementCatalog::forProfile('asvs-l1')['rules'],null,'id')['OWASP-ASVS:5.0.0:'.$id];
  missingAssert($registry->runResult('requirement_assessment',$r['checks'][0]['args'])->outcome===CheckOutcome::Unknown,'Missing evidence must be UNKNOWN, never PASS: '.$id);
 }
 $cases=[
  '1.3.1'=>['js','const clean = DOMPurify.sanitize(input); target.innerHTML = clean;'],
  '2.2.1'=>['php','<?php $value=$request->getParam("qty"); validate($value);'],
  '3.2.2'=>['js','target.textContent=input; target.innerHTML=input;'],
  '3.5.3'=>['php','<?php class Update implements HttpGetActionInterface { public function execute() { $model->save(); }}'],
  '6.2.4'=>['php','<?php validatePassword($password); isCommonPassword($password);'],
  '9.1.1'=>['php','<?php $claims=JWT::decode($token,$key);'],
  '9.1.2'=>['php','<?php $header=["alg"=>"none"]; $claims=JWT::decode($token,new Key($key,"RS256"));'],
  '9.1.3'=>['php','<?php $url=$header["jku"]; $key=$verificationKey;'],
  '9.2.1'=>['php','<?php $exp=$claims["exp"]; $nbf=$claims["nbf"]; new StrictValidAt($clock);'],
  '11.4.1'=>['php','<?php $digest=hash("md5",$value); $safe=hash("sha256",$value);'],
 ];
 foreach($cases as $id=>[$extension,$body]){
  $file=$root.'/app/check.'.$extension;file_put_contents($file,$body);
  $result=$registry->runResult('asvs_source_evidence',['requirement'=>$id]);
  missingAssert($result->outcome===CheckOutcome::ManualReview && $result->evidence['observations']!==[],'Collect relevant signals without unsupported PASS/FAIL: '.$id);
  missingAssert(!str_contains(json_encode($result->evidence),'$password') && !str_contains(json_encode($result->evidence),'$key'),'Evidence must omit raw source and secrets');
  file_put_contents($file,$extension==='php'?'<?php /* '.$body.' */':'/* '.$body.' */');
  missingAssert($registry->runResult('asvs_source_evidence',['requirement'=>$id])->outcome===CheckOutcome::Unknown,'Comments must not be implementation evidence: '.$id);
  unlink($file);
 }
 file_put_contents($root.'/app/example.php','<?php $documentation="DOMPurify.sanitize(input); JWT::decode(token); md5(value);";');
 foreach(['1.3.1','9.1.1','11.4.1'] as $id) missingAssert($registry->runResult('asvs_source_evidence',['requirement'=>$id])->outcome===CheckOutcome::Unknown,'Quoted example calls are not executable evidence');
 unlink($root.'/app/example.php');
 file_put_contents($root.'/app/example.js',"const documentation='DOMPurify.sanitize(input); target.innerHTML = input;';");
 missingAssert($registry->runResult('asvs_source_evidence',['requirement'=>'1.3.1'])->outcome===CheckOutcome::Unknown,'JS quoted examples are not implementation evidence');
 unlink($root.'/app/example.js');
 file_put_contents($root.'/app/image.php','<?php $image=base64_decode($value); hash_equals($a,$b);');
 missingAssert($registry->runResult('asvs_source_evidence',['requirement'=>'9.1.1'])->outcome===CheckOutcome::Unknown,'Generic decoding/comparison outside a token context does not establish token applicability');
 unlink($root.'/app/image.php');
 $remote=RequirementCatalog::compile(ProfileLoader::apply(RulePackLoader::loadExternalMagento(),ProfileLoader::loadBundled('asvs-l1'),true),ProfileLoader::loadBundled('asvs-l1'),[],true);
 missingAssert(in_array('OWASP-ASVS:5.0.0:4.1.1',array_column($remote['rules'],'id'),true),'Native HTTP evidence is available in remote scope');
 file_put_contents($root.'/app/safe.js',"// ignored innerHTML\nconst url='https://example.invalid/';\ntarget.textContent = input;");
 $result=$registry->runResult('asvs_source_evidence',['requirement'=>'3.2.2']);
 missingAssert($result->evidence['observations'][0]['line']===3,'Comment masking preserves source line numbers and quoted URL');unlink($root.'/app/safe.js');
 file_put_contents($root.'/outside.php','<?php md5($x);');symlink($root.'/outside.php',$root.'/app/link.php');
 // A symlink within the project is not outside source policy; an external target is rejected.
 unlink($root.'/app/link.php');symlink(__FILE__,$root.'/app/link.php');
 missingAssert($registry->runResult('asvs_source_evidence',['requirement'=>'11.4.1'])->outcome===CheckOutcome::Unknown,'Symlinks outside target must not count as project implementation');unlink($root.'/app/link.php');
 $artifact=$root.'/.magebean/evidence/asvs-default-accounts.json';
 $data=['schema_version'=>'1.0','scope'=>'application','complete'=>true,'generated_at'=>gmdate('c'),'accounts'=>[['username'=>'admin','enabled'=>true],['username'=>'sa','enabled'=>false],['username'=>'employee','enabled'=>true,'password'=>'SECRET-DO-NOT-OUTPUT']]];
 file_put_contents($artifact,json_encode($data));$result=$registry->runResult('asvs_default_accounts',[]);
 missingAssert($result->outcome===CheckOutcome::ManualReview && $result->evidence['enabled_default_names']===['admin'],'Enabled default accounts produce review evidence, disabled ones do not');
 missingAssert(!str_contains(json_encode($result),'SECRET-DO-NOT-OUTPUT'),'Account secrets must not appear in evidence');
 $remoteRegistry=CheckRegistry::fromContext(new Context($root,'https://example.invalid','',['meta'=>['target_mode'=>'REMOTE']]));
 missingAssert($remoteRegistry->runResult('asvs_default_accounts',[])->outcome===CheckOutcome::Unknown,'Remote scans must not attach local account inventories to the remote application');
 missingAssert($remoteRegistry->runResult('asvs_source_evidence',['requirement'=>'11.4.1'])->outcome===CheckOutcome::Unknown,'Remote scans must not treat local cwd as remote source');
 $data['accounts'][0]['enabled']=false;file_put_contents($artifact,json_encode($data));
 missingAssert($registry->runResult('asvs_default_accounts',[])->outcome===CheckOutcome::ManualReview,'A clean supplied inventory is not live conformance PASS');
 foreach(['stale'=>gmdate('c',time()-90000),'future'=>gmdate('c',time()+3600),'relative'=>'now'] as $case=>$timestamp){$data['generated_at']=$timestamp;file_put_contents($artifact,json_encode($data));missingAssert($registry->runResult('asvs_default_accounts',[])->outcome===CheckOutcome::Unknown,'Reject invalid/freshness evidence: '.$case);}
 $data['generated_at']=gmdate('c');$data['accounts'][0]['enabled']='false';file_put_contents($artifact,json_encode($data));missingAssert($registry->runResult('asvs_default_accounts',[])->outcome===CheckOutcome::Unknown,'String booleans cannot silently disable accounts');
 file_put_contents($artifact,'{invalid');missingAssert($registry->runResult('asvs_default_accounts',[])->outcome===CheckOutcome::Unknown,'Invalid JSON cannot pass');
 foreach([
  ['text/html; charset=UTF-8','<!doctype html><html>ok</html>',[]],
  ['text/html','<html>ok</html>',['missing_or_unverified_safe_charset']],
  ['application/json','<html>wrong</html>',['observed_body_type_mismatch']],
  ['application/json','{"ok":true}',[]],
  ['application/problem+json','{"ok":true}',[]],
  ['application/xml; charset=UTF-8','<?xml version="1.0"?><root/>',[]],
  ['','<html>none</html>',['missing_or_ambiguous_content_type']],
  [['text/html','application/json'],'<html>ambiguous</html>',['multiple_content_type_headers','missing_or_ambiguous_content_type']],
 ] as [$type,$body,$issues]){
  $observed=AsvsRuntimeEvidenceCheck::inspectResponse(['status'=>200,'headers'=>['content-type'=>$type],'body'=>$body]);
  missingAssert($observed['issues']===$issues,'Response checks match actual body/header issues: '.json_encode([$type,$observed['issues'],$issues]));
  missingAssert(!array_key_exists('body',$observed) && !array_key_exists('headers',$observed),'HTTP evidence omits response bodies and raw headers');
 }
 $set=new CollectorSet(new CollectionSession());$set->session->begin(new ScanDeadline(0.001));usleep(2000);$thrown=false;
 try{CheckRegistry::fromContext(new Context($root,''),$set)->runResult('asvs_default_accounts',[]);}catch(ScanDeadlineExceeded){$thrown=true;}finally{$set->session->end();}
 missingAssert($thrown,'New evidence collection respects scan deadlines');
 $socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);$address=stream_socket_get_name($socket,false);fclose($socket);
 $server=proc_open([PHP_BINARY,'-S',$address,__DIR__.'/support/AsvsResponseRouter.php'],[0=>['file','/dev/null','r'],1=>['file',$root.'/server.log','a'],2=>['file',$root.'/server.log','a']],$pipes,$root);
 missingAssert(is_resource($server),'Start local HTTP fixture');
 for($i=0;$i<100;$i++){ $c=@stream_socket_client('tcp://'.$address,$errno,$error,0.05);if(is_resource($c)){fclose($c);break;}usleep(20000);}
 foreach(['good','bad','redirect','empty','opaque'] as $case){
  $res=CheckRegistry::fromContext(new Context($root,'http://'.$address.'/'.$case))->runResult('asvs_response_content_type',[]);
  missingAssert($res->outcome===(in_array($case,['good','bad'],true)?CheckOutcome::ManualReview:CheckOutcome::Unknown),'HTTP sample cannot prove full requirement: '.$case);
 }
}finally{
 if(is_resource($server)){proc_terminate($server);proc_close($server);}
 $nodes=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
 foreach($nodes as $node){if($node->isLink()||!$node->isDir())unlink($node->getPathname());else rmdir($node->getPathname());}rmdir($root);
}
echo "AsvsMissingRequirementsTest: {$n} assertions passed\n";
