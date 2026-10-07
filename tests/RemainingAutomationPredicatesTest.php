<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\MagentoCheck;
use Magebean\Engine\Checks\ComposerCheck;
use Magebean\Engine\Checks\FilesystemCheck;
$root=sys_get_temp_dir().'/magebean-remaining-'.bin2hex(random_bytes(4));
mkdir($root.'/app/etc',0777,true);
$count=0;
$assert=static function($actual,$expected,string $message)use(&$count):void{$count++;if($actual!==$expected)throw new RuntimeException($message);};
$write=static function(array $env,array $config)use($root):MagentoCheck{file_put_contents($root.'/app/etc/env.php','<?php return '.var_export($env,true).';');file_put_contents($root.'/app/etc/config.php','<?php return '.var_export($config,true).';');return new MagentoCheck(new Context($root,''));};
try {
 mkdir($root.'/vendor/magento/module-backend/etc',0777,true);
 file_put_contents($root.'/vendor/magento/module-backend/etc/config.xml','<config><default><admin><security><session_lifetime>3600</session_lifetime></security></admin></default></config>');
 $modules=['modules'=>['Magento_Backend'=>1]];
 $assert($write([],$modules)->adminSessionTimeout([])[0],false,'installed3600default violates900policy');
 mkdir($root.'/vendor/magento/module-security/etc',0777,true);
 file_put_contents($root.'/vendor/magento/module-security/etc/config.xml','<config><default><admin><security><session_lifetime>900</session_lifetime></security></admin></default></config>');
 $assert($write([],['modules'=>['Magento_Backend'=>1,'Magento_Security'=>1]])->adminSessionTimeout([])[0],true,'installed Security900default overrides Backenddefault');
 $assert($write(['system'=>['default'=>['admin/security/session_lifetime'=>900]]],$modules)->adminSessionTimeout([])[0],true,'explicit900boundary overrides installeddefault');
 $assert($write(['system'=>['default'=>['admin/security/session_lifetime'=>901]]],$modules)->adminSessionTimeout([])[0],false,'901violates900');
 $assert($write(['system'=>['default'=>['admin/security/session_lifetime'=>0]]],$modules)->adminSessionTimeout([])[0],false,'zeroinvalid lifetime');
 $assert($write(['system'=>['default'=>['admin/security/session_lifetime'=>'900.5']]],$modules)->adminSessionTimeout([])[0],null,'fractionnot silentlytruncated');
 $assert($write(['db'=>['connection'=>['default'=>['host'=>'invalid;','dbname'=>'x']]]],$modules)->adminSessionTimeout([])[0],null,'unavailableDBnotfalseFAILor defaultfallback');
 $assert($write([],['modules'=>[]])->adminSessionTimeout([])[0],null,'missinglifetime notfalseFAIL');
 $json=['require'=>['vendor/pkg'=>'^1.0']];file_put_contents($root.'/composer.json',json_encode($json));
 $lock=['content-hash'=>md5(json_encode($json)),'packages'=>[['name'=>'vendor/pkg','version'=>'1.0.0']],'packages-dev'=>[]];
 $testLock=static function(array $input)use($root):array{file_put_contents($root.'/composer.lock',json_encode($input));return(new ComposerCheck(new Context($root,'')))->lockIntegrity([]);};
 $assert($testLock($lock)[0],true,'validlockhashidentitypasses');
 $bad=$lock;$bad['packages'][]=['name'=>'vendor/other'];$assert($testLock($bad)[0],false,'missingversionnotignored');
 $bad=$lock;$bad['packages'][]='malformed';$assert($testLock($bad)[0],false,'scalarentrynotignored');
 $bad=$lock;unset($bad['packages']);$assert($testLock($bad)[0],false,'missingpackagesnotignored');
 $bad=$lock;$bad['content-hash']=str_repeat('0',32);$assert($testLock($bad)[0],false,'hashmismatchfails');
 $fs=new FilesystemCheck(new Context($root,''));
 $assert($fs->diCompiled([])[0],false,'missingDIartifactdirectoriesfail');
 mkdir($root.'/generated/code',0777,true);mkdir($root.'/generated/metadata',0777,true);
 $assert($fs->diCompiled([])[0],false,'emptyDIartifactdirectoriesfail');
 file_put_contents($root.'/generated/code/Example.php','<?php class Example {}');file_put_contents($root.'/generated/metadata/global.php','<?php return [];');
 $assert($fs->diCompiled([])[0],true,'existentialPHPartifactpresencepasses');
 mkdir($root.'/generated/code/blocked');chmod($root.'/generated/code/blocked',0000);
 if (!is_readable($root.'/generated/code/blocked')) $assert($fs->diCompiled([])[0],null,'unreadableDIchildcannot silentlypass');
 chmod($root.'/generated/code/blocked',0700);
 echo "PASS $count remaining automation predicate assertions\n";
} finally {
 $remove=static function(string $path)use(&$remove):void{if(is_dir($path)){foreach(scandir($path)as$name)if($name!=='.'&&$name!=='..')$remove($path.'/'.$name);rmdir($path);}else unlink($path);};$remove($root);
}
