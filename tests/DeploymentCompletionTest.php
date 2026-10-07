<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\{DeploymentStateCheck,InstalledCronCheck};
$n=0;function deploymentAssert(bool $v,string $m):void{global$n;++$n;if(!$v)throw new RuntimeException($m);}
$dir=sys_get_temp_dir().'/mb-deployment-'.bin2hex(random_bytes(5));mkdir($dir);mkdir($dir.'/pub');mkdir($dir.'/app');mkdir($dir.'/app/etc');
$ctx=new Context($dir,'');
try{
 $check=new DeploymentStateCheck($ctx);deploymentAssert($check->webrootArtifacts([])[0]===true,'Complete clean webroot passes');
 file_put_contents($dir.'/pub/secrets.bak','secret');deploymentAssert($check->webrootArtifacts([])[0]===false,'Direct forbidden artifact fails');unlink($dir.'/pub/secrets.bak');
 file_put_contents($dir.'/.env','secret');symlink($dir.'/.env',$dir.'/pub/assets');deploymentAssert($check->webrootArtifacts([])[0]===false,'Alias to forbidden target fails');unlink($dir.'/pub/assets');
 mkdir($dir.'/assets');symlink($dir.'/assets',$dir.'/pub/assets');symlink($dir.'/pub',$dir.'/assets/cycle');deploymentAssert($check->webrootArtifacts([])[0]===true,'Inside-project symlink cycle terminates and is fully inspected');unlink($dir.'/assets/cycle');unlink($dir.'/pub/assets');rmdir($dir.'/assets');
 symlink('/nonexistent-magebean-deployment',$dir.'/pub/broken');deploymentAssert($check->webrootArtifacts([])[0]===null,'Unresolved target is unknown');unlink($dir.'/pub/broken');
 symlink(sys_get_temp_dir(),$dir.'/pub/external');deploymentAssert($check->webrootArtifacts([])[0]===null,'External symlink is unknown');unlink($dir.'/pub/external');
 file_put_contents($dir.'/pub/ok','ok');deploymentAssert($check->webrootArtifacts(['max_entries'=>1])[0]===null,'Traversal budget cannot produce clean conclusion');unlink($dir.'/pub/ok');
 foreach([1=>true,0=>false]as$value=>$expected){file_put_contents($dir.'/app/etc/env.php','<?php return '.var_export(['cache_types'=>['full_page'=>$value]],true).';');deploymentAssert((new DeploymentStateCheck($ctx))->cacheTypeEnabled([])[0]===$expected,'Declared cache state interpreted');}
 foreach([[],['cache_types'=>['full_page'=>2]],['cache_types'=>'invalid']]as$value){file_put_contents($dir.'/app/etc/env.php','<?php return '.var_export($value,true).';');deploymentAssert((new DeploymentStateCheck($ctx))->cacheTypeEnabled([])[0]===null,'Missing/malformed cache state unknown');}
 unlink($dir.'/app/etc/env.php');deploymentAssert((new DeploymentStateCheck($ctx))->cacheTypeEnabled([])[0]===null,'Missing env unknown');
 $cron=static function(string $content,bool $system=false,array $extra=[] )use($ctx):array{return(new InstalledCronCheck($ctx,static fn()=>[array_merge(['name'=>'trusted-installed-fixture','available'=>true,'content'=>$content,'system'=>$system],$extra)]))->configured([]);};
 foreach(['* * * * *','*/5 0-23 * JAN,MAR MON-FRI','@daily','@reboot']as$schedule)deploymentAssert($cron($schedule.' php '.$dir.'/bin/magento cron:run')[0]===true,'Valid installed schedule detected');
 deploymentAssert($cron('0 1 * * * owner /usr/bin/php '.$dir.'/bin/magento cron:run',true)[0]===true,'System crontab user field accepted');
 deploymentAssert($cron('* * * * * cd '.$dir.' && php bin/magento cron:run')[0]===true,'Scoped relative invocation accepted');
 foreach(['99 * * * *','* 24 * * *','* * 0 * *','* * * 13 *','* * * * 8','*/0 * * * *','* * * * MON-JAN','@never']as$schedule)deploymentAssert($cron($schedule.' php '.$dir.'/bin/magento cron:run')[0]===false,'Invalid cron schedule cannot establish installed cron');
 foreach(['# * * * * * php '.$dir.'/bin/magento cron:run','* * * * * echo php '.$dir.'/bin/magento cron:run','* * * * * php /another/deployment/bin/magento cron:run','* * * * * true # php '.$dir.'/bin/magento cron:run']as$line)deploymentAssert($cron($line)[0]===false,'Comment, echo and other deployment do not establish cron');
 deploymentAssert($cron('* * * * * php '.$dir.'/bin/magento cron:run',false,['complete'=>false])[0]===null,'Partial collector output unknown even with apparent entry');
 deploymentAssert($cron('',false,['available'=>false])[0]===null,'Unreadable installed source unknown');
 deploymentAssert($cron('')[0]===false,'Complete empty installed source fails');
 echo "DeploymentCompletionTest passed ($n assertions)\n";
}finally{
 foreach([$dir.'/pub/ok',$dir.'/.env',$dir.'/app/etc/env.php']as$f)if(file_exists($f))unlink($f);
 rmdir($dir.'/pub');rmdir($dir.'/app/etc');rmdir($dir.'/app');rmdir($dir);
}
