<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,CheckOutcome};
use Magebean\Engine\Checks\AutomatedSourcePolicyCheck;
$root=sys_get_temp_dir().'/mb-source-policy-'.bin2hex(random_bytes(6));mkdir($root);mkdir($root.'/app');
$count=0;
$assert=static function(bool $condition,string $message)use(&$count):void{$count++;if(!$condition)throw new RuntimeException($message);};
$run=static function(string $kind,string $source,array $extra=[])use($root){file_put_contents($root.'/app/test.php',$source);return(new AutomatedSourcePolicyCheck(new Context($root,'')))->run(['kind'=>$kind,'paths'=>['app']]+$extra);};
try{
    foreach(['native_unserialize'=>'unserialize','shell_execution'=>'shell_exec','dynamic_execution'=>'eval','weak_prng'=>'mt_rand','raw_crypto_session'=>'session_start','native_network'=>'curl_exec','native_filesystem'=>'file_get_contents','native_upload'=>'move_uploaded_file'] as $kind=>$fn){
        $result=$run($kind,'<?php '.$fn.'($value);');$assert($result->outcome===CheckOutcome::Fail,$kind.' fails actual forbidden call');
        $assert($result->evidence['violations'][0]['line']===1&&!isset($result->evidence['violations'][0]['snippet']),'Evidence gives location without snippets');
        $result=$run($kind,'<?php /* '.$fn.'($value); */ $s = \''.$fn.'($value)\'; return 1;');$assert($result->outcome===CheckOutcome::Pass,$kind.' ignores comments and string examples');
        $assert($run($kind,'<?php $callback($value);')->outcome===CheckOutcome::Unknown,'Indirect call cannot certify global call ban');
    }
    $assert($run('native_unserialize','<?php unserialize($x, ["allowed_classes"=>false]);')->outcome===CheckOutcome::Fail,'allowed_classes=false does not bypass ban');
    $assert($run('shell_execution','<?php $unused=escapeshellarg("fixed"); shell_exec($input);')->outcome===CheckOutcome::Fail,'Unrelated guard does not suppress shell call');
    $assert($run('shell_execution','<?php $x = `whoami`;')->outcome===CheckOutcome::Fail,'Backtick execution banned');
    $assert($run('native_unserialize','<?php \\unserialize($x);')->outcome===CheckOutcome::Fail,'Fully qualified native call banned');
    $assert($run('native_unserialize','<?php use function unserialize as decode; decode($x);')->outcome===CheckOutcome::Unknown,'Alias never creates false pass');
    $assert($run('native_unserialize','<?php $object->unserialize($x);')->outcome===CheckOutcome::Pass,'Object method is outside explicitly native function ban');
    $assert($run('sql_literal_query','<?php $db->query("SELECT id FROM t WHERE id = ?", [$id]);')->outcome===CheckOutcome::Pass,'Literal SQL and separate binding meet syntax policy');
    $assert($run('sql_literal_query','<?php $db->query("SELECT id FROM t WHERE id = ".$input);')->outcome===CheckOutcome::Fail,'Concatenation in query argument fails');
    $assert($run('sql_literal_query','<?php $db->query("SELECT id FROM t WHERE id = $input");')->outcome===CheckOutcome::Fail,'Interpolated query fails');
    $assert($run('sql_literal_query','<?php $db->query($sql);')->outcome===CheckOutcome::Unknown,'Unresolved first argument cannot pass');
    $assert($run('xml_external_features','<?php simplexml_load_string($x,null,LIBXML_NOENT);')->outcome===CheckOutcome::Fail,'Unsafe XML constant fails');
    $assert($run('xml_external_features','<?php simplexml_load_string($x,null,\\LIBXML_NOENT);')->outcome===CheckOutcome::Fail,'Fully-qualified unsafe XML constant fails');
    $assert($run('xml_external_features','<?php /* LIBXML_NOENT */ $s="LIBXML_DTDLOAD"; $dom->resolveExternals=false;')->outcome===CheckOutcome::Pass,'Comments and disabled property pass exact policy');
    $assert($run('literal_https','<?php $endpoint="http://internal.example";')->outcome===CheckOutcome::Fail,'Plain HTTP literal fails');
    $assert($run('literal_https','<?php /* "http://bad.example" */ $endpoint="https://good.example";')->outcome===CheckOutcome::Pass,'Comment ignored and HTTPS passes');
    $assert($run('csrf_unconditional_bypass','<?php class B {public function validateForCsrf($r): ?bool {return true;}}')->outcome===CheckOutcome::Fail,'Unconditional CSRF validation bypass fails');
    $assert($run('csrf_unconditional_bypass','<?php class B {public function validateForCsrf($r): ?bool {return null;}}')->outcome===CheckOutcome::Pass,'Framework-delegated validation passes exact bypass ban');
    $assert($run('csrf_unconditional_bypass','<?php /* function validateForCsrf($r) {return true;} */ return true;')->outcome===CheckOutcome::Pass,'Bypass comment cannot fail');
    $assert($run('direct_request_logging','<?php $logger->error("error", ["context" => $_POST]);')->outcome===CheckOutcome::Fail,'Direct raw request logging fails');
    $assert($run('direct_request_logging','<?php $logger->error("safe summary"); /* $_POST */')->outcome===CheckOutcome::Pass,'Static safe log meets exact request argument ban');
    $assert($run('direct_request_logging','<?php $logger->error(\'$_POST\');')->outcome===CheckOutcome::Pass,'Quoted superglobal name is not runtime request data');
    $assert($run('shell_execution','<?php return [;')->outcome===CheckOutcome::Unknown,'Malformed PHP cannot pass');
    $assert($run('shell_execution','<?php return 1;',['max_file_bytes'=>5])->outcome===CheckOutcome::Unknown,'Oversized source cannot pass');
    $assert($run('shell_execution','<?php return 1;',['max_total_bytes'=>5])->outcome===CheckOutcome::Unknown,'Total byte budget cannot pass');
    $assert($run('shell_execution','<?php return 1;',['timeout_seconds'=>0.001])->outcome!==CheckOutcome::Fail,'Deadline never yields false security failure');
    unlink($root.'/app/test.php');
    $assert((new AutomatedSourcePolicyCheck(new Context($root,'')))->run(['kind'=>'shell_execution','paths'=>['missing']])->outcome===CheckOutcome::Unknown,'Missing scope cannot pass');
    $assert((new AutomatedSourcePolicyCheck(new Context($root,'')))->run(['kind'=>'shell_execution','paths'=>['app']])->outcome===CheckOutcome::Unknown,'Empty scope cannot pass');
    file_put_contents($root.'/app/test.php','<?php return 1;');file_put_contents($root.'/app/extra.php','<?php return 2;');
    $assert((new AutomatedSourcePolicyCheck(new Context($root,'')))->run(['kind'=>'shell_execution','paths'=>['app'],'max_files'=>1])->outcome===CheckOutcome::Unknown,'Truncated file inventory cannot pass');unlink($root.'/app/extra.php');
    symlink($root.'/app',$root.'/link');
    $assert((new AutomatedSourcePolicyCheck(new Context($root,'')))->run(['kind'=>'shell_execution','paths'=>['link']])->outcome===CheckOutcome::Unknown,'Link scope cannot pass');unlink($root.'/link');
    mkdir($root.'/app/sub');file_put_contents($root.'/app/sub/nested.php','<?php return 1;');symlink($root.'/app',$root.'/parentlink');
    $assert((new AutomatedSourcePolicyCheck(new Context($root,'')))->run(['kind'=>'shell_execution','paths'=>['parentlink/sub']])->outcome===CheckOutcome::Unknown,'Link ancestor cannot pass');unlink($root.'/parentlink');unlink($root.'/app/sub/nested.php');rmdir($root.'/app/sub');
    file_put_contents($root.'/app/test.php','<?php return 1;');chmod($root.'/app/test.php',0000);
    if(function_exists('posix_geteuid')&&posix_geteuid()!==0)$assert((new AutomatedSourcePolicyCheck(new Context($root,'')))->run(['kind'=>'shell_execution','paths'=>['app']])->outcome===CheckOutcome::Unknown,'Unreadable source cannot pass');
    chmod($root.'/app/test.php',0644);
    $r=(new AutomatedSourcePolicyCheck(new Context($root,'','',['meta'=>['target_mode'=>'REMOTE']])))->run(['kind'=>'shell_execution','paths'=>['app']]);$assert($r->outcome===CheckOutcome::Unknown,'Remote lacks local source');
    echo "Automated source policy: $count assertions passed\n";
}finally{if(is_file($root.'/app/test.php')){chmod($root.'/app/test.php',0644);unlink($root.'/app/test.php');}rmdir($root.'/app');rmdir($root);}
