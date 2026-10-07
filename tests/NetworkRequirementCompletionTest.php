<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\{HttpCheck, FilesystemCheck, CodeSearchCheck};
function networkAssert(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
$root = sys_get_temp_dir() . '/magebean-network-completion-' . bin2hex(random_bytes(6)); mkdir($root);
$server = null; $tls = null;
try {
    mkdir($root . '/app'); mkdir($root . '/pub/static', 0777, true);
    file_put_contents($root . '/app/safe.phtml', '<a href="http://example.test/docs">Docs</a><!-- <img src="http://bad.test/a"> --><div xmlns="http://www.w3.org/1999/xhtml"></div>');
    $code = new CodeSearchCheck(new Context($root, '', '', []));
    $args = ['strict_scope' => true, 'paths' => ['app'], 'include_ext' => ['phtml','css']];
    networkAssert($code->noMixedContent($args)[0] === true, 'Anchor, namespace and commented resources are not mixed content.');
    file_put_contents($root . '/app/large.css', str_repeat(' ', 1048600) . 'body { background:url(http://assets.test/b.png) }');
    networkAssert($code->noMixedContent($args)[0] === false, 'Large files are inspected rather than silently skipped.');
    unlink($root . '/app/large.css');
    file_put_contents($root . '/app/safe.phtml', '<img src="http://www.w3.org/image.svg">');
    networkAssert($code->noMixedContent($args)[0] === false, 'Resource URLs do not gain namespace hostname exemptions.');
    $fs = new FilesystemCheck(new Context($root, '', '', []));
    networkAssert($fs->staticContentDeployed(['strict_scope'=>true])[0] === false, 'Empty static directory fails.');
    file_put_contents($root . '/pub/static/.htaccess', 'deny');
    networkAssert($fs->staticContentDeployed(['strict_scope'=>true])[0] === false, 'Static .htaccess alone is not deployment.');
    mkdir($root . '/pub/static/frontend/theme/en_US', 0777, true);
    file_put_contents($root . '/pub/static/frontend/theme/en_US/app.js', 'console.log(1)');
    networkAssert($fs->staticContentDeployed(['strict_scope'=>true])[0] === true, 'Published artifact proves bounded presence without disposable preprocessing output.');
    file_put_contents($root . '/router.php', <<<'ROUTER'
<?php
$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
if(str_starts_with($path,'/listing/')){echo '<title>Index of /media/</title>';return;}
if(str_starts_with($path,'/down/')){http_response_code(503);echo 'Busy';return;}
if(str_ends_with($path,'/static/a.js')){
 if(str_starts_with($path,'/soft/')){header('Content-Type: text/html');echo '<html>not found</html>';return;}
 header('Content-Type: application/javascript');echo 'console.log(1)';return;
}
$prefix = str_starts_with($path,'/soft')?'/soft':'/good';
echo '<script src="'.$prefix.'/static/a.js"></script>';
ROUTER);
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error); $address = stream_socket_get_name($socket, false); fclose($socket);
    $server = proc_open([PHP_BINARY,'-S',$address,$root.'/router.php'],[0=>['file','/dev/null','r'],1=>['file',$root.'/http.out','w'],2=>['file',$root.'/http.err','w']],$pipes);
    for($i=0;$i<100;$i++){ $c=@stream_socket_client('tcp://'.$address,$errno,$error,.05);if(is_resource($c)){fclose($c);break;}usleep(20000); }
    foreach ([['/good',true],['/soft',false]] as [$path,$expected]) {
        $url='http://'.$address.$path;$http=new HttpCheck(new Context($root,$url,'',['url'=>$url]));
        networkAssert($http->dispatch('http_static_assets_deployed',['strict_scope'=>true,'timeout_ms'=>500])[0]===$expected,'Referenced asset is retrieved and HTML soft404 fails: '.$path);
    }
    foreach ([['/good',true],['/listing',false],['/down',null]] as [$path,$expected]) {
        $url='http://'.$address.$path;$http=new HttpCheck(new Context($root,$url,'',['url'=>$url]));
        networkAssert($http->dispatch('http_no_directory_listing',['strict_scope'=>true,'paths'=>['/media/'],'timeout_ms'=>500])[0]===$expected,'Directory response distinguishes supported/unsafe/incomplete: '.$path);
    }
    $http=new HttpCheck(new Context($root,'http://'.$address,'',['url'=>'http://'.$address]));
    networkAssert($http->dispatch('http_no_mixed_content',['strict_scope'=>true,'paths'=>['/'],'timeout_ms'=>500])[0]===null,'HTTP page cannot establish HTTPS mixed-content safety.');
    $method=new ReflectionMethod(HttpCheck::class,'mixedContentInMarkup');
    networkAssert($method->invoke($http,'<a href="http://docs.test">Docs</a>')===[],'Rendered anchors do not create mixed content.');
    networkAssert(count($method->invoke($http,'<img src="http://assets.test/a.png">'))===1,'Rendered HTTP resource is detected.');
    $missing=new HttpCheck(new Context($root,'','',[]));
    networkAssert(str_contains($missing->dispatch('http_no_directory_listing',['strict_scope'=>true])[1],'--url'),'Missing runtime evidence gives a concrete URL hint.');
    $policy = new ReflectionMethod(HttpCheck::class, 'assessHstsPolicy');
    foreach ([['max-age=31536000; includeSubDomains',true],['max-age="31536000"',true],['xmax-age=31536000',false],['max-age=31536000evil',false],['max-age=31536000; max-age=0',false],['max-age=31536000; includeSubDomains=true',false]] as [$header,$expected]) {
        networkAssert($policy->invoke($http,['Strict-Transport-Security'=>[$header]],'https://store.test','https://store.test',[])[0] === $expected,'Exact HSTS directives: '.$header);
    }
    networkAssert($policy->invoke($http,['strict-transport-security'=>['max-age=31536000','max-age=0']],'https://store.test','https://store.test',[])[0] === false,'Duplicate HSTS headers cannot prove the scoped policy.');
    // Real OpenSSL endpoint proves protocol rejection, not merely the negotiated preferred version.
    $cmd=proc_open(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',$root.'/key.pem','-out',$root.'/cert.pem','-days','1','-subj','/CN=localhost'],[0=>['file','/dev/null','r'],1=>['file',$root.'/cert.out','w'],2=>['file',$root.'/cert.err','w']],$pipes);
    networkAssert(is_resource($cmd)&&proc_close($cmd)===0,'TLS fixture certificate generation.');
    foreach (['-tls1_2'=>true,'-tls1'=>false] as $protocol=>$expected) {
        $socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);$address=stream_socket_get_name($socket,false);fclose($socket);
        $tls=proc_open(['openssl','s_server','-accept',$address,'-cert',$root.'/cert.pem','-key',$root.'/key.pem',$protocol,'-cipher','ALL:@SECLEVEL=0','-www'],[0=>['file','/dev/null','r'],1=>['file',$root.'/tls.out','w'],2=>['file',$root.'/tls.err','w']],$pipes);
        for($i=0;$i<100;$i++){$c=@stream_socket_client('tcp://'.$address,$errno,$error,.05);if(is_resource($c)){fclose($c);break;}usleep(20000);}
        $url='https://'.$address;$http=new HttpCheck(new Context($root,$url,'',['url'=>$url]));
        $result=$http->dispatch('http_tls_min_version',['strict_scope'=>true,'timeout_ms'=>1000]);
        networkAssert($result[0]===$expected,'Active TLS probe '.$protocol.': '.json_encode($result));
        if ($protocol === '-tls1_2') {
            $hsts = $http->dispatch('http_has_hsts', ['strict_scope'=>true,'timeout_ms'=>1000]);
            networkAssert($hsts[0] === null && str_contains($hsts[1], 'trusted CA'), 'Untrusted TLS does not establish HSTS failure and supplies trust-chain remediation.');
            $cookies = $http->dispatch('http_cookie_flags', ['strict_scope'=>true,'paths'=>['/'],'timeout_ms'=>1000]);
            networkAssert($cookies[0] === null && str_contains($cookies[1], $url) && str_contains($cookies[1], 'trust chain'), 'Cookie collection failure preserves endpoint and concrete trust-chain action.');
        }
        proc_terminate($tls);proc_close($tls);$tls=null;
    }
    echo "NetworkRequirementCompletionTest passed\n";
} finally {
    foreach([$server,$tls] as $process)if(is_resource($process)){proc_terminate($process);proc_close($process);}
    if(is_dir($root)){ $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as $f){if($f->isDir())rmdir($f->getPathname());else unlink($f->getPathname());}rmdir($root); }
}
