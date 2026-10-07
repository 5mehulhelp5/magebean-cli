<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\MagentoCheck;
$root=sys_get_temp_dir().'/magebean-basic-policy-'.bin2hex(random_bytes(4));
mkdir($root.'/app/etc',0777,true);
$assertions=0;
$assert=static function($actual,$expected,string $message)use(&$assertions):void{$assertions++;if($actual!==$expected)throw new RuntimeException($message);};
$write=static function(array $env,array $config)use($root):MagentoCheck{file_put_contents($root.'/app/etc/env.php','<?php return '.var_export($env,true).';');file_put_contents($root.'/app/etc/config.php','<?php return '.var_export($config,true).';');return new MagentoCheck(new Context($root,''));};
try{
 foreach(['backend','developer','user']as$module)mkdir($root.'/vendor/magento/module-'.$module.'/etc',0777,true);
 file_put_contents($root.'/vendor/magento/module-backend/etc/config.xml','<config><default><admin><security><lockout_failures>6</lockout_failures><lockout_threshold>30</lockout_threshold></security></admin></default></config>');
 file_put_contents($root.'/vendor/magento/module-developer/etc/config.xml','<config><default><dev><debug><template_hints>0</template_hints><template_hints_storefront>0</template_hints_storefront></debug><translate_inline><active>0</active></translate_inline></dev></default></config>');
 $modules=['modules'=>['Magento_Backend'=>1,'Magento_Developer'=>1,'Magento_User'=>1]];
 $assert($write([],$modules)->adminLoginProtectionConfigured([])[0],true,'installed lockout defaults resolve');
 $assert($write([],$modules)->deploymentDebugFlagsDisabled([])[0],true,'installed disabled debug defaults resolve');
 $assert($write(['system'=>['default'=>['dev/debug/template_hints'=>1]]],$modules)->deploymentDebugFlagsDisabled([])[0],false,'explicit enabled debug overrides default');
 file_put_contents($root.'/.user.ini','display_errors=On');
 $assert($write([],$modules)->deploymentDebugFlagsDisabled([])[0],false,'project error display enabled');
 file_put_contents($root.'/.user.ini','xdebug.mode=debug');
 $assert($write([],$modules)->deploymentDebugFlagsDisabled([])[0],false,'declared Xdebug debug mode violates basic policy');
 file_put_contents($root.'/.user.ini',"zend_extension=xdebug.so\nxdebug.mode=off");
 $assert($write([],$modules)->deploymentDebugFlagsDisabled([])[0],true,'explicitly disabled Xdebug mode is not enabled debugging');
 unlink($root.'/.user.ini');
 $assert($write(['db'=>['connection'=>['default'=>['host'=>'invalid;','dbname'=>'x']]]],$modules)->deploymentDebugFlagsDisabled([])[0],null,'unreadable DB cannot safely fall back');
 mkdir($root.'/vendor/magento/module-user/Model');
 file_put_contents($root.'/vendor/magento/module-user/Model/User.php','<?php class User { const MIN_PASSWORD_LENGTH = 8; }');
 $assert($write([],$modules)->adminPasswordMinimumConfigured([])[0],true,'installed explicit validator minimum');
 file_put_contents($root.'/vendor/magento/module-user/Model/UserValidationRules.php','<?php class UserValidationRules { public const MIN_PASSWORD_LENGTH = 7; }');
 $assert($write([],$modules)->adminPasswordMinimumConfigured([])[0],false,'shipped minimum seven does not meet minimum eight');
 $assert($write(['system'=>['default'=>['admin/security/minimum_password_length'=>12]]],$modules)->adminPasswordMinimumConfigured([])[0],true,'current Magento config path overrides validator default');
 unlink($root.'/vendor/magento/module-user/Model/UserValidationRules.php');

 $assert($write(['system'=>['default'=>['admin/security/password_min_length'=>4]]],$modules)->adminPasswordMinimumConfigured([])[0],false,'explicit weak configured minimum');
 $assert($write(['system'=>['default'=>['admin/security/password_min_length'=>'bad']]],$modules)->adminPasswordMinimumConfigured([])[0],null,'malformed override never replaced by default');
 unlink($root.'/vendor/magento/module-user/Model/User.php');
 $assert($write([],$modules)->adminPasswordMinimumConfigured([])[0],null,'absent validator is not assumed');
 file_put_contents($root.'/vendor/magento/module-developer/etc/config.xml','<!DOCTYPE config [<!ENTITY bad SYSTEM "file:///etc/passwd">]><config/>');
 $assert($write([],$modules)->deploymentDebugFlagsDisabled([])[0],null,'external XML entity declarations rejected');
 echo "PASS {$assertions} basic deployment policy assertions\n";
}finally{$remove=static function(string $path)use(&$remove):void{if(is_dir($path)){foreach(scandir($path)as$name)if($name!=='.'&&$name!=='..')$remove($path.'/'.$name);rmdir($path);}else unlink($path);};$remove($root);}
