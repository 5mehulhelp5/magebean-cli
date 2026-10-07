<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\{MagentoCheck, FilesystemCheck};
use Magebean\Engine\Checks\Families\ComposerPolicyChecks;
$n=0;function gateAssert(bool $v,string $m):void{global $n;++$n;if(!$v)throw new RuntimeException($m);}
$dir=sys_get_temp_dir().'/mb-gates-'.bin2hex(random_bytes(6));mkdir($dir,0755);mkdir($dir.'/app',0755);mkdir($dir.'/app/etc',0755);
try {
 $fs=new FilesystemCheck(new Context($dir,''));
 gateAssert($fs->noWorldWritable(['strict_observation'=>true])[0]===true,'Complete clean traversal can PASS');
 file_put_contents($dir.'/bad','x');chmod($dir.'/bad',0666);
 gateAssert($fs->noWorldWritable(['strict_observation'=>true])[0]===false,'World-writable entry proves FAIL');
 chmod($dir.'/bad',0644);symlink('/definitely-missing-magebean-target',$dir.'/link');
 gateAssert($fs->noWorldWritable(['strict_observation'=>true])[0]===null,'Unassessed link cannot establish whole-tree PASS');unlink($dir.'/link');
 gateAssert($fs->noWorldWritable(['strict_observation'=>true,'path'=>'missing'])[0]===null,'Missing root is UNKNOWN');
 gateAssert($fs->fileModeMax(['strict_observation'=>true])[0]===null,'Missing env is UNKNOWN');
 file_put_contents($dir.'/app/etc/env.php','<?php return [];');chmod($dir.'/app/etc/env.php',0640);clearstatcache();
 gateAssert($fs->fileModeMax(['strict_observation'=>true])[0]===true,'Owner/group mode policy PASS');
 chmod($dir.'/app/etc/env.php',0644);clearstatcache();gateAssert($fs->fileModeMax(['strict_observation'=>true])[0]===false,'World readable env FAIL');
 gateAssert($fs->fileOwnerGroupMatches(['strict_observation'=>true,'file'=>'app/etc/env.php'])[0]===true,'Owner matches root');
 gateAssert($fs->fileOwnerGroupMatches(['strict_observation'=>true,'file'=>'app/etc/env.php','owner_reference'=>'missing'])[0]===null,'Missing ownership reference UNKNOWN');
 $magento=new MagentoCheck(new Context($dir,''));$moduleArgs=['declared_scope_only'=>true];
 gateAssert($magento->adminTwoFactorAuthEnabled($moduleArgs)[0]===null,'Missing config UNKNOWN');
 foreach ([['modules'=>[]],['modules'=>['Magento_TwoFactorAuth'=>0,'Magento_GoogleAuthenticator'=>1]],['modules'=>['Magento_TwoFactorAuth'=>1,'Magento_GoogleAuthenticator'=>1]]] as $i=>$cfg){file_put_contents($dir.'/app/etc/config.php','<?php return '.var_export($cfg,true).';');gateAssert($magento->adminTwoFactorAuthEnabled($moduleArgs)[0]===($i===2),'Declared core plus provider state evaluated');}
 file_put_contents($dir.'/app/etc/config.php','<?php return ["modules"=>["Magento_TwoFactorAuth"=>"invalid"]];');gateAssert($magento->adminTwoFactorAuthEnabled($moduleArgs)[0]===null,'Malformed declared state UNKNOWN');
 $composer=new ComposerPolicyChecks(new Context($dir,''));$policy=['project_local_only'=>true,'sections'=>['require','require-dev'],'deny_wildcard'=>true];
 gateAssert($composer->jsonConstraints($policy)[0]===null,'Missing project manifest UNKNOWN');
 foreach ([['require'=>['vendor/package'=>'^1.2']],['require'=>['vendor/package'=>'*']],['require'=>['vendor/package'=>12]]] as $i=>$data){file_put_contents($dir.'/composer.json',json_encode($data));gateAssert($composer->jsonConstraints($policy)[0]===([true,false,null][$i]),'Manifest constraint shape and policy checked');}
 file_put_contents($dir.'/composer.json','{"require":[]}');gateAssert($composer->jsonConstraints($policy)[0]===null,'Array dependency section cannot PASS');
 file_put_contents($dir.'/composer.json','[]');gateAssert($composer->jsonConstraints($policy)[0]===null,'Nonobject manifest cannot PASS');
 $kv=['project_local_only'=>true,'key'=>'prefer-stable','op'=>'eq','expect'=>true,'strict'=>true];
 foreach ([true,false,'true'] as $v){file_put_contents($dir.'/composer.json',json_encode(['prefer-stable'=>$v]));gateAssert($composer->jsonKv($kv)[0]===($v===true),'Strict prefer-stable Boolean policy');}
 file_put_contents($dir.'/composer.json','{"require":{"vendor/package":"dev-main"}}');gateAssert($composer->jsonConstraints(['project_local_only'=>true,'deny_dev_constraints'=>true])[0]===false,'Development constraint FAIL');
 // An ancestor manifest must not provide evidence for the scanned child project.
 mkdir($dir.'/child');$child=new ComposerPolicyChecks(new Context($dir.'/child',''));gateAssert($child->jsonKv($kv)[0]===null,'Ancestor manifest cannot satisfy project-local policy');rmdir($dir.'/child');
 echo "BaselineAutomationGateTest: $n assertions passed\n";
} finally {
 foreach(['app/etc/env.php','app/etc/config.php','composer.json','bad','link'] as $f)if(is_file($dir.'/'.$f)||is_link($dir.'/'.$f))unlink($dir.'/'.$f);
 rmdir($dir.'/app/etc');rmdir($dir.'/app');rmdir($dir);
}
