<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Checks\BasicExposureCheck;
use Magebean\Engine\Context;
$n=0;function exposureAssert(bool $v,string $m):void{global $n;++$n;if(!$v)throw new RuntimeException($m);}
$root=sys_get_temp_dir().'/mb-exposure-'.bin2hex(random_bytes(5));mkdir($root);
try{
 $ctx=new Context($root,'https://store.invalid');$check=new BasicExposureCheck($ctx);
 exposureAssert($check->mediaExecutableFiles([])[0]===null,'Missing media is unknown');
 mkdir($root.'/pub/media',0777,true);file_put_contents($root.'/pub/media/image.jpg','image');
 exposureAssert($check->mediaExecutableFiles([])[0]===true,'Collected benign filenames pass');
 file_put_contents($root.'/pub/media/shell.php.jpg','never executed');
 exposureAssert($check->mediaExecutableFiles([])[0]===false,'Double extension detected');
 unlink($root.'/pub/media/shell.php.jpg');
 exposureAssert($check->mediaExecutableFiles(['max_entries'=>1])[0]===true,'Exact budget complete');
 file_put_contents($root.'/pub/media/second.jpg','image');
 exposureAssert($check->mediaExecutableFiles(['max_entries'=>1])[0]===null,'Budget gap unknown');
 unlink($root.'/pub/media/second.jpg');symlink($root.'/pub/media/image.jpg',$root.'/pub/media/link.jpg');
 exposureAssert($check->mediaExecutableFiles([])[0]===null,'Unfollowed link cannot pass');
 foreach([403=>true,404=>true,302=>null,429=>null,500=>null,200=>null] as $status=>$expected){
  $check=new BasicExposureCheck($ctx,static fn($url)=>['status'=>$status,'prefix'=>'<html>generic page</html>']);
  exposureAssert($check->sensitiveHttpPaths([])[0]===$expected,'Status '.$status.' does not invent exposure or denial');
 }
 $secret='DO_NOT_RETAIN_fixture_secret';
 $check=new BasicExposureCheck($ctx,static fn($url)=>['status'=>200,'prefix'=>str_ends_with($url,'env.php')?'<?php return ["crypt"=>["key"=>"'.$secret.'"]];':'generic']);
 $result=$check->sensitiveHttpPaths([]);
 exposureAssert($result[0]===false,'Specific exposed signature fails');
 exposureAssert(!str_contains(json_encode($result),$secret)&&!str_contains(json_encode($result),'<?php'),'No secret or response body in evidence');
 exposureAssert(count($result[2]['checked'])===6,'Named path scope retained');
 exposureAssert((new BasicExposureCheck(new Context($root,'')))->sensitiveHttpPaths([])[0]===null,'Missing URL unknown');
 echo "BasicExposureCheckTest: $n assertions passed\n";
}finally{foreach(glob($root.'/pub/media/*')?:[] as $f)unlink($f);if(is_dir($root.'/pub/media'))rmdir($root.'/pub/media');if(is_dir($root.'/pub'))rmdir($root.'/pub');rmdir($root);}
