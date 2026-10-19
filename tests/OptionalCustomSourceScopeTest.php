<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,CheckOutcome,CheckResult,RequirementCatalog,RequirementAssessmentEvaluator,MagebeanRiskObservation};
use Magebean\Engine\Checks\AutomatedSourcePolicyCheck;
$root=sys_get_temp_dir().'/mb-optional-source-'.bin2hex(random_bytes(5));mkdir($root.'/app/etc',0755,true);mkdir($root.'/bin',0755,true);
$n=0;$assert=static function(bool$ok,string$message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
try{
 $check=new AutomatedSourcePolicyCheck(new Context($root,''));
 $assert($check->run(['kind'=>'native_unserialize'])->outcome===CheckOutcome::Unknown,'Wrong/unidentified project remains a collection gap');
 file_put_contents($root.'/bin/magento',"<?php // deployment marker\n");file_put_contents($root.'/app/etc/config.php',"<?php return ['modules'=>[]];\n");
 $definitions=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
 $sourceRequirements=array_filter($definitions,static fn(array $definition):bool=>($definition['checks'][0]['name']??'')==='automated_source_policy');
 // Include the reported requirement and every source policy, not just three examples.
 foreach(array_unique(array_merge(['MB-0787','MB-0789','MB-0790','MB-0791'],array_keys($sourceRequirements)))as$id){
  $result=$check->run($definitions[$id]['checks'][0]['args']);
  $assert($result->reasonCode==='SOURCE_SCOPE_EMPTY','Absent optional app/code is not a problem: '.$id);
  $risk=MagebeanRiskObservation::fromAssessment($definitions[$id],RequirementAssessmentEvaluator::evaluate($definitions[$id],static fn():CheckResult=>$result));
  $assert(!$risk['needs_attention']&&$risk['findings']===[],'No duplicate missing-app/code findings: '.$id);
 }
 mkdir($root.'/app/code');$assert($check->run(['kind'=>'native_unserialize'])->reasonCode==='SOURCE_SCOPE_EMPTY','Empty optional scope is also legitimate');
 file_put_contents($root.'/app/code/Unsafe.php',"<?php unserialize(\$input);\n");
 $assert($check->run(['kind'=>'native_unserialize'])->outcome===CheckOutcome::Fail,'Real source is scanned when present');unlink($root.'/app/code/Unsafe.php');
 $assert($check->run(['kind'=>'native_unserialize','paths'=>['app/custom-missing']])->outcome===CheckOutcome::Unknown,'An explicitly different missing scope is not suppressed');
 rmdir($root.'/app/code');symlink($root.'/missing-target',$root.'/app/code');
 $assert($check->run(['kind'=>'native_unserialize'])->outcome===CheckOutcome::Unknown,'Broken symlink is not treated as an absent optional directory');unlink($root.'/app/code');
 echo "OptionalCustomSourceScopeTest: $n assertions passed\n";
}finally{if(is_dir($root.'/app/code'))rmdir($root.'/app/code');foreach(['bin/magento','app/etc/config.php']as$file)if(is_file($root.'/'.$file))unlink($root.'/'.$file);rmdir($root.'/bin');rmdir($root.'/app/etc');rmdir($root.'/app');rmdir($root);}
