<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\BasicPracticeCheck;
use Magebean\Engine\Checks\InstalledCronCheck;
function practiceAssert(bool $ok,string $message):void {if(!$ok)throw new RuntimeException($message);}
$ctx=new Context('/tmp/magebean-basic-practice','');
foreach([[0,true,false],[1,true,true],[128,true,null],[1,false,null]] as [$exit,$complete,$expected]){
    $check=new BasicPracticeCheck($ctx,fn($command)=>['exit'=>$exit,'complete'=>$complete]);
    practiceAssert($check->envNotTracked([])[0]===$expected,'Git index tri-state');
}
foreach([['* * * * *',true],['0-59 0-23 1-31 1-12 0-6',true],['0,1 * * * *',null],['@yearly',false],['*/5 * * * *',false]] as [$schedule,$expected]){
    $check=new InstalledCronCheck($ctx,fn()=>[['name'=>'fixture','available'=>true,'content'=>$schedule.' php /tmp/magebean-basic-practice/bin/magento cron:run']]);
    practiceAssert($check->cadence([])[0]===$expected,'Cron cadence '.$schedule);
}
practiceAssert((new InstalledCronCheck($ctx,fn()=>[['name'=>'cloud','available'=>false]]))->cadence([])[0]===null,'External scheduler unknown');
$emptyCron=new InstalledCronCheck($ctx,fn()=>[['name'=>'complete','available'=>true,'content'=>'']]);
practiceAssert($emptyCron->configured([])[0]===false,'Legacy installed-only absence fails');
practiceAssert($emptyCron->configured(['allow_external_scheduler'=>true])[0]===null,'External scheduler absence unverified');
foreach([[['successes'=>1,'overdue'=>0],true],[['successes'=>0,'overdue'=>0],false],[['successes'=>5,'overdue'=>2],false],[[],null]] as [$snapshot,$expected]){
    $check=new BasicPracticeCheck(new Context('/nonexistent','', '',['cron_health_snapshot'=>$snapshot]));
    practiceAssert($check->cronHealth([])[0]===$expected,'Cron health tri-state');
}
$root=sys_get_temp_dir().'/basic-practice-'.bin2hex(random_bytes(6));
$path=$root.'/pub/static/frontend/Acme/shop/en_US';
mkdir($path.'/css',0777,true);mkdir($path.'/requirejs',0777,true);
$check=new BasicPracticeCheck(new Context($root,''));$args=['scopes'=>[['theme'=>'Acme/shop','locale'=>'en_US']]];
practiceAssert($check->staticScopesReady([])[0]===false,'Discovered empty published scope fails');
practiceAssert($check->staticScopesReady($args)[0]===false,'Missing assets fail');
file_put_contents($path.'/css/styles-m.css','body{}');file_put_contents($path.'/requirejs/require.js','define([])');
practiceAssert($check->staticScopesReady($args)[0]===true,'Explicit deployed scope passes');
practiceAssert($check->staticScopesReady([])[0]===true,'Published scope discovery passes');
practiceAssert($check->staticScopesReady([])[2]['scope']==='observed_published_scopes','Observed scope label');
practiceAssert((new BasicPracticeCheck(new Context('/nonexistent','')))->staticScopesReady([])[0]===null,'Absent static root unknown');
unlink($path.'/css/styles-m.css');unlink($path.'/requirejs/require.js');
rmdir($path.'/css');rmdir($path.'/requirejs');rmdir($path);rmdir(dirname($path));rmdir(dirname($path,2));rmdir(dirname($path,3));rmdir(dirname($path,4));rmdir(dirname($path,5));rmdir($root);
echo "BasicPracticeCheckTest OK\n";
