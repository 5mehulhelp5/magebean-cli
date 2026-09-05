<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Update\SelfUpdater;
function updateAssert(bool $ok,string $message):void{if(!$ok){fwrite(STDERR,"SelfUpdaterTest: {$message}\n");exit(1);}}
function expectUpdateFailure(callable $run,string $message):void{try{$run();}catch(RuntimeException){return;}updateAssert(false,$message);}
$dir=sys_get_temp_dir().'/magebean-update-'.bin2hex(random_bytes(5));mkdir($dir);
try{
 $current=$dir.'/magebean.phar';file_put_contents($current,'old');chmod($current,0751);
 $valid='#!/usr/bin/env php'."\n".'<?php echo "Magebean 2.0.0\\n";';
 $release=['version'=>'2.0.0','url'=>'https://releases.example/magebean.phar','sha256'=>hash('sha256',$valid)];
 (new SelfUpdater(fn($url,$file)=>file_put_contents($file,$valid),fn($file)=>true))->update($release,$current);
 updateAssert(file_get_contents($current)===$valid,'successful update did not replace current PHAR');
 updateAssert((fileperms($current)&0777)===0751,'executable permissions were not preserved');
 updateAssert(!file_exists($current.'.update'),'successful update left .update behind');
 file_put_contents($current,'old');
 expectUpdateFailure(fn()=>(new SelfUpdater(fn($u,$f)=>file_put_contents($f,$valid),fn($f)=>true))->update([...$release,'sha256'=>str_repeat('0',64)],$current),'bad checksum was accepted');
 updateAssert(!file_exists($current.'.update'),'checksum failure left .update behind');
 expectUpdateFailure(fn()=>(new SelfUpdater(fn()=>throw new RuntimeException('network down'),fn($f)=>true))->update($release,$current),'download failure was accepted');
 updateAssert(!file_exists($current.'.update'),'download failure left .update behind');
 expectUpdateFailure(fn()=>(new SelfUpdater(fn($u,$f)=>file_put_contents($f,'not a phar')))->update([...$release,'sha256'=>hash('sha256','not a phar')],$current),'invalid PHAR was accepted');
 updateAssert(!file_exists($current.'.update'),'PHAR validation failure left .update behind');
}finally{foreach(glob($dir.'/*')?:[]as$file)unlink($file);rmdir($dir);}
echo "SelfUpdaterTest: PASS\n";
