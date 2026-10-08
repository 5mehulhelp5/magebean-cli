<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\HttpCheck;
use Magebean\Engine\Collectors\HttpCollector;
function networkDiagnosticAssert(bool $ok,string $why):void{if(!$ok)throw new RuntimeException($why);}
$root=sys_get_temp_dir().'/magebean-network-diagnostics-'.bin2hex(random_bytes(5));mkdir($root);$server=null;
try{
 file_put_contents($root.'/router.php', <<<'ROUTER'
<?php
$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
if($path==='/error'){http_response_code(503);return;}
if($path==='/redirect'){header('Location: https://other.invalid/',true,302);return;}
header('X-Frame-Options: '.($path==='/invalid-xfo'?'garbage':'SAMEORIGIN'));
if($path!=='/invalid-xfo')header("Content-Security-Policy: default-src 'self'; frame-ancestors 'self'");
header('Content-Type: text/html; charset=utf-8');echo '<html>Fixture</html>';
ROUTER);
 $socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);$address=stream_socket_get_name($socket,false);fclose($socket);
 $server=proc_open([PHP_BINARY,'-S',$address,$root.'/router.php'],[0=>['file','/dev/null','r'],1=>['file',$root.'/out','w'],2=>['file',$root.'/err','w']],$pipes);
 for($i=0;$i<100;$i++){$c=@stream_socket_client('tcp://'.$address,$errno,$error,.05);if(is_resource($c)){fclose($c);break;}usleep(20000);}
 set_error_handler(static function(int $severity,string $message):bool{throw new RuntimeException($message);});
 try{
  foreach(['http_clickjacking_protection','http_csp_not_overly_permissive','http_cors_no_wildcard_with_credentials']as$name){
   $check=new HttpCheck(new Context($root,'http://'.$address));
   networkDiagnosticAssert($check->dispatch($name,['timeout_ms'=>500])[0]===true,$name.' can inspect a successful HTTP response without undefined variables or unrelated HSTS gates.');
   foreach(['/error','/redirect']as$path){$r=(new HttpCheck(new Context($root,'http://'.$address.$path)))->dispatch($name,['timeout_ms'=>500]);networkDiagnosticAssert($r[0]===null&&isset($r[2]['action'])&&!str_contains($r[1],'HSTS'),$name.' does not conclude from errors/redirects and supplies a relevant action.');}
  }
  $r=(new HttpCheck(new Context($root,'http://'.$address)))->dispatch('http_hsts_preload_ready',['timeout_ms'=>500]);networkDiagnosticAssert($r[0]===null&&isset($r[2]['action']),'HSTS preload requires HTTPS, with action and no undefined variable.');
 }finally{restore_error_handler();}
 $invalid=(new HttpCheck(new Context($root,'http://'.$address.'/invalid-xfo')))->dispatch('http_clickjacking_protection',[]);networkDiagnosticAssert($invalid[0]===false,'Invalid X-Frame-Options is not accepted as clickjacking protection.');
 $guard=new ReflectionMethod(HttpCheck::class,'responseAssessmentIssue');$check=new HttpCheck(new Context($root,'https://shop.test'));
 networkDiagnosticAssert($guard->invoke($check,true,'',['status'=>200,'final_url'=>'https://shop.test/'],'https://shop.test','HSTS preload policy',true)===null,'Same-host successful HTTPS passes response prerequisites.');
 $failure=new ReflectionMethod(HttpCollector::class,'transportFailure');$collector=new HttpCollector();
 foreach(['SSL certificate problem'=>'HTTP_TLS_TRUST_FAILED','Could not resolve host'=>'HTTP_DNS_FAILED','Connection timed out'=>'HTTP_TIMEOUT','Connection refused'=>'HTTP_TRANSPORT_FAILED']as$message=>$code){$r=$failure->invoke($collector,'https://user:secret@shop.test/?token=secret',$message,'curl');networkDiagnosticAssert($r[0]===null&&$r[2]['reason_code']===$code&&$r[2]['action']!==''&&!str_contains(json_encode($r),'secret'),'Transport cause/action is classified and URL credentials/query redacted: '.$code);}
 $r=(new HttpCheck(new Context($root,'https://127.0.0.1:1')))->dispatch('http_tls_cert_days_left',['timeout_s'=>1]);networkDiagnosticAssert($r[0]===null&&$r[2]['port']===1&&isset($r[2]['action']),'Certificate check honors the configured port and tells clients how to unblock collection.');
 echo "NetworkDiagnosticsTest passed\n";
}finally{if(is_resource($server)){proc_terminate($server);proc_close($server);}foreach(glob($root.'/*')as$file)unlink($file);rmdir($root);}
