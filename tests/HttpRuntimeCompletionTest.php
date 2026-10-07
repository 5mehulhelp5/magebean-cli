<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\HttpCheck;
function runtimeHttpAssert(bool $ok,string $message):void{if(!$ok)throw new RuntimeException($message);}
$root=sys_get_temp_dir().'/magebean-runtime-http-'.bin2hex(random_bytes(5));mkdir($root);mkdir($root.'/app/etc',0777,true);$server=null;
try{
 file_put_contents($root.'/app/etc/env.php',"<?php return ['backend'=>['frontName'=>'secret']];");
 file_put_contents($root.'/router.php', <<<'ROUTER'
<?php
$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
if(str_starts_with($path,'/blocked')){http_response_code(403);return;}
if(str_starts_with($path,'/absent')){http_response_code(404);return;}
if(str_starts_with($path,'/listing')){echo '<title>Index of /media/</title>';return;}
if(str_starts_with($path,'/down')){http_response_code(503);return;}
if(str_starts_with($path,'/unsafe')){echo 'plaintext';return;}
if(str_starts_with($path,'/cross')){header('Location: https://unrelated.invalid/',true,301);return;}
if(str_starts_with($path,'/cookies')){header('Set-Cookie: PHPSESSID=x; Secure; HttpOnly; SameSite=Lax');echo 'ok';return;}
header('Location: https://'.$_SERVER['HTTP_HOST'].$path,true,301);
ROUTER);
 $socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);$address=stream_socket_get_name($socket,false);fclose($socket);
 $server=proc_open([PHP_BINARY,'-S',$address,$root.'/router.php'],[0=>['file','/dev/null','r'],1=>['file',$root.'/out','w'],2=>['file',$root.'/err','w']],$pipes);
 for($i=0;$i<100;$i++){$c=@stream_socket_client('tcp://'.$address,$errno,$error,.05);if(is_resource($c)){fclose($c);break;}usleep(20000);}
 foreach([['',true],['/unsafe',false],['/cross',false],['/down',null]] as [$path,$expected]){
  $check=new HttpCheck(new Context($root,'http://'.$address.$path,'',['url'=>'http://wrong.invalid']));
  $result=$check->dispatch('http_force_https_redirect',['strict_scope'=>true,'include_admin'=>true,'timeout_ms'=>500]);
  runtimeHttpAssert($result[0]===$expected,'Canonical Context URL used; scoped redirect outcome '.$path);
  runtimeHttpAssert(count($result[2]['checked'])===2,'Both storefront and declared backend probed.');
 }
 $check=new HttpCheck(new Context($root,'http://'.$address.'/cookies'));
 runtimeHttpAssert($check->dispatch('http_cookie_flags',['strict_scope'=>true,'paths'=>['/'],'timeout_ms'=>500])[0]===null,'HTTP cookie flags cannot prove HTTPS cookie emission.');
 $directory=new HttpCheck(new Context($root,'http://'.$address));
 runtimeHttpAssert($directory->dispatch('http_no_directory_listing',['strict_scope'=>true,'paths'=>['/blocked/','/absent/'],'timeout_ms'=>500])[0]===true,'403 and 404 fully assess protected/absent directory paths.');
 runtimeHttpAssert($directory->dispatch('http_no_directory_listing',['strict_scope'=>true,'paths'=>['/listing/'],'timeout_ms'=>500])[0]===false,'Actual index signature fails.');
 $partial=$directory->dispatch('http_no_directory_listing',['strict_scope'=>true,'paths'=>['/blocked/','/down/'],'timeout_ms'=>500]);
 runtimeHttpAssert($partial[0]===null && str_contains($partial[1],'/down/: Unassessable HTTP status 503'),'Server error remains collector failure with the exact path/status.');
 $method=new ReflectionMethod(HttpCheck::class,'assessCookieFlags');
 $assess=fn($cookie)=>$method->invoke($check,$cookie,['phpsessid'],['lax','strict'],['form_key']);
 runtimeHttpAssert($assess('PHPSESSID=x; Secure; HttpOnly; SameSite=Lax')['ok']===true,'Exact sensitive cookie attributes pass.');
 runtimeHttpAssert($assess('PHPSESSID=x; Securely; HttpOnlyFake; SameSite=Lax')['ok']===false,'Attribute substrings do not prove security flags.');
 runtimeHttpAssert($assess('PHPSESSID=x; Secure; HttpOnly; SameSite=None')['ok']===false,'Disallowed SameSite fails.');
 runtimeHttpAssert($assess('form_key=x')===null,'Client-readable Magento form key is excluded.');
 $missing=new HttpCheck(new Context($root,''));runtimeHttpAssert(str_contains($missing->dispatch('http_force_https_redirect',['strict_scope'=>true])[1],'--url'),'Missing URL produces actionable UNKNOWN.');
 echo "HttpRuntimeCompletionTest passed\n";
}finally{if(is_resource($server)){proc_terminate($server);proc_close($server);}foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST)as$f){$f->isDir()?rmdir($f->getPathname()):unlink($f->getPathname());}rmdir($root);}
