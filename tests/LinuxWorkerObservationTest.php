<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\LinuxWorkerObservationCheck;
$root=sys_get_temp_dir().'/mb-worker-'.bin2hex(random_bytes(5));mkdir($root.'/.magebean',0777,true);mkdir($root.'/proc/123',0777,true);
$n=0;function workerAssert(bool$v,string$m):void{global$n;++$n;if(!$v)throw new RuntimeException($m);}
try{
 $check=new LinuxWorkerObservationCheck(new Context($root,''),$root.'/proc');
 workerAssert($check->xdebugModulesAbsent([])[0]===null,'Missing worker inventory unknown');
 $policy=['schema_version'=>1,'workers'=>[['pid'=>123,'pool'=>'store','start_ticks'=>'500']]];
 file_put_contents($root.'/.magebean/php-fpm-workers.json',json_encode($policy));
 $fields=array_fill(0,20,'0');$fields[0]='S';$fields[19]='500';file_put_contents($root.'/proc/123/stat','123 (php-fpm8.4) '.implode(' ',$fields));
 file_put_contents($root.'/proc/123/cmdline',"php-fpm: pool store\0");symlink('/usr/sbin/php-fpm8.4',$root.'/proc/123/exe');
 file_put_contents($root.'/proc/123/maps',"0000-1111 r-xp 0 00:00 1 /usr/lib/php/opcache.so\n");
 workerAssert($check->xdebugModulesAbsent([])[0]===true,'Bound worker maps without Xdebug pass');
 file_put_contents($root.'/proc/123/maps',"0000-1111 r-xp 0 00:00 1 /usr/lib/php/xdebug.so\n");
 $result=$check->xdebugModulesAbsent([]);workerAssert($result[0]===false,'Loaded Xdebug module fails regardless of response headers');
 workerAssert(!str_contains(json_encode($result),'0000-1111'),'Mapping addresses are not retained');
 $fields[19]='501';file_put_contents($root.'/proc/123/stat','123 (php-fpm8.4) '.implode(' ',$fields));
 workerAssert($check->xdebugModulesAbsent([])[0]===null,'Reused or restarted PID requires current inventory');
 $fields[19]='500';file_put_contents($root.'/proc/123/stat','123 (php-fpm8.4) '.implode(' ',$fields));
 file_put_contents($root.'/proc/123/cmdline',"php-fpm: pool other\0");workerAssert($check->xdebugModulesAbsent([])[0]===null,'Wrong pool never proves target worker state');
 workerAssert($check->xdebugModulesAbsent(['policy_file'=>'../outside.json'])[0]===null,'Policy path traversal rejected');
 echo "LinuxWorkerObservationTest: $n assertions passed\n";
}finally{foreach(['stat','maps','cmdline','exe']as$f)if(file_exists($root.'/proc/123/'.$f)||is_link($root.'/proc/123/'.$f))unlink($root.'/proc/123/'.$f);unlink($root.'/.magebean/php-fpm-workers.json');rmdir($root.'/.magebean');rmdir($root.'/proc/123');rmdir($root.'/proc');rmdir($root);}
