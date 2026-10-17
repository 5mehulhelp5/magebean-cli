<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Checks\HttpCheck;
use Magebean\Engine\Context;
$n=0;
function basicHttpAssert(bool $ok,string $message):void{global $n;++$n;if(!$ok)throw new RuntimeException($message);}
$check=new HttpCheck(new Context(sys_get_temp_dir(),''));
$policy=new ReflectionMethod($check,'assessClickjackingPolicy');
foreach (["frame-ancestors 'none'"=>true,"frame-ancestors 'self' https://trusted.example"=>true,'frame-ancestors https:'=>false,'frame-ancestors *'=>false,"frame-ancestors 'self' *"=>false,'frame-ancestors'=>false,"frame-ancestors 'none'; frame-ancestors *"=>false,"frame-ancestors 'none' https://trusted.example"=>false] as $csp=>$expected) basicHttpAssert($policy->invoke($check,['Content-Security-Policy'=>$csp])[0]===$expected,'Framing policy '.$csp);
basicHttpAssert($policy->invoke($check,['content-security-policy'=>["frame-ancestors 'self'","frame-ancestors *"]])[0]===false,'Duplicated CSP not claimed safe');
basicHttpAssert($policy->invoke($check,['x-frame-options'=>'DENY','content-security-policy'=>'frame-ancestors https:'])[0]===false,'Enforced permissive CSP overrides XFO');
basicHttpAssert($policy->invoke($check,['x-frame-options'=>'DENY','content-security-policy'=>"default-src 'self'"])[0]===true,'XFO fallback when CSP has no frame ancestors');
$certificate=new ReflectionMethod($check,'assessCertificateValidity');$now=time();
foreach ([[$now-60,$now+40*86400,true],[$now+86400,$now+40*86400,false],[$now-40*86400,$now-86400,false],[$now-60,$now+86400,false],[0,$now+86400,null]] as [$from,$to,$expected]) basicHttpAssert($certificate->invoke($check,['validFrom_time_t'=>$from,'validTo_time_t'=>$to],['min_days'=>15],[])[0]===$expected,'Certificate current validity and expiry policy');
$root=sys_get_temp_dir().'/mb-http-scope-'.bin2hex(random_bytes(5));mkdir($root);
$socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);$port=(int)substr(strrchr(stream_socket_get_name($socket,false),':'),1);fclose($socket);
file_put_contents($root.'/router.php', '<?php header("Location: https://127.0.0.1:'.$port.'".$_SERVER["REQUEST_URI"], true, 302);');
$process=proc_open([PHP_BINARY,'-S','127.0.0.1:'.$port,$root.'/router.php'],[['pipe','r'],['file',$root.'/server.log','a'],['file',$root.'/server.log','a']],$pipes);
try{
 for($i=0;$i<30;$i++){ $probe=@fsockopen('127.0.0.1',$port,$errno,$error,0.1);if($probe){fclose($probe);break;}usleep(50000); }
 $check=new HttpCheck(new Context($root,'https://127.0.0.1:'.$port));
 $store=$check->dispatch('http_force_https_redirect',['strict_scope'=>true,'include_admin'=>false]);
 basicHttpAssert($store[0]===true&&count($store[2]['checked'])===1,'URL-only storefront redirect works without env.php');
 $both=$check->dispatch('http_force_https_redirect',['strict_scope'=>true,'include_admin'=>true]);
 basicHttpAssert($both[0]===null&&count($both[2]['checked'])===1,'Missing mandatory Admin route preserves storefront evidence but cannot pass');
 $admin=$check->dispatch('http_force_https_redirect',['strict_scope'=>true,'admin_only'=>true,'admin_path'=>'/custom_admin/']);
 basicHttpAssert($admin[0]===true&&count($admin[2]['checked'])===1&&str_ends_with($admin[2]['checked'][0]['request_url'],'/custom_admin/'),'Explicit Admin route uses only Admin probe');
 foreach(['https://other.example/','../admin','admin?secret=1','admin/subpath'] as $bad) basicHttpAssert($check->dispatch('http_force_https_redirect',['strict_scope'=>true,'admin_only'=>true,'admin_path'=>$bad])[0]===null,'Unsafe Admin path rejected');
 $contextCheck=new HttpCheck(new Context($root,'https://127.0.0.1:'.$port,'',['admin_path'=>'context_admin']));
 basicHttpAssert($contextCheck->dispatch('http_force_https_redirect',['strict_scope'=>true,'admin_only'=>true])[0]===true,'Context Admin path supported');
}finally{if(is_resource($process)){proc_terminate($process);proc_close($process);}foreach(glob($root.'/*') as $file)unlink($file);rmdir($root);}
$unreachable=new HttpCheck(new Context(sys_get_temp_dir(),'https://127.0.0.1:1'));
basicHttpAssert($unreachable->dispatch('http_tls_cert_days_left',['timeout_ms'=>200])[0]===null,'Unreachable TLS endpoint unknown never vulnerability');
echo "BasicHttpScopeTest: $n assertions passed\n";
