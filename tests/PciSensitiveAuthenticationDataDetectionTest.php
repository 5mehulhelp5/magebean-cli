<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\CheckRegistry;
function assertSad(bool $condition,string $message):void{if(!$condition)throw new RuntimeException($message);}
$dir=sys_get_temp_dir().'/magebean-pci-sad-'.bin2hex(random_bytes(5));
mkdir($dir.'/app/code/Test/Module',0777,true);
file_put_contents($dir.'/app/code/Test/Module/schema.sql','CREATE TABLE payment_auth (pin_block VARCHAR(255));');
$registry=CheckRegistry::fromContext(new Context($dir,'',''));
[$ok,$message,$evidence]=$registry->run('code_cardholder_data_storage',['paths'=>['app/code'],'include_ext'=>['sql']]);
assertSad($ok===false,'A stored PIN block field must fail MB-R082 evidence collection');
assertSad(str_contains((string)$message,'pin_block'),'The finding must identify the PIN-block field without exposing a value');
assertSad(($evidence['findings'][0]['field']??null)==='pin_block','PIN-block evidence is missing');
unlink($dir.'/app/code/Test/Module/schema.sql');rmdir($dir.'/app/code/Test/Module');rmdir($dir.'/app/code/Test');rmdir($dir.'/app/code');rmdir($dir.'/app');rmdir($dir);
echo "PciSensitiveAuthenticationDataDetectionTest: PASS\n";
