<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,CheckOutcome};
use Magebean\Engine\Checks\{ProviderWebhookSourceCheck,CheckRegistry};
$root=sys_get_temp_dir().'/mb-provider-source-'.bin2hex(random_bytes(5));mkdir($root);mkdir($root.'/app');mkdir($root.'/app/code');$files=[];$dirs=[];$count=0;
$assert=static function(bool $v,string $why)use(&$count):void{$count++;if(!$v)throw new RuntimeException($why);};
$write=static function(string $path,string $content)use($root,&$files,&$dirs):void{
 $absolute=$root.'/'.$path;$missing=[];$dir=dirname($absolute);while(!is_dir($dir)){$missing[]=$dir;$dir=dirname($dir);}foreach(array_reverse($missing)as$d){mkdir($d);$dirs[]=$d;}file_put_contents($absolute,$content);$files[$absolute]=true;
};
$sdk=[
 'stripe'=>['stripe/stripe-php','16.0.0','vendor/stripe/stripe-php/lib/Webhook.php','<?php namespace Stripe; class Webhook {public static function constructEvent($payload,$sigHeader,$secret,$tolerance=300){return null;}}'],
 'adyen'=>['adyen/php-api-library','20.0.0','vendor/adyen/php-api-library/src/Adyen/Util/HmacSignature.php','<?php namespace Adyen\\Util; class HmacSignature {public function isValidNotificationHMAC($hmacKey,$params){return false;} public function validateHMACSignature($hmacKey,$hmacSign,$webhook):bool{return false;}}'],
 'paypal'=>['paypal/rest-api-sdk-php','1.14.0','vendor/paypal/rest-api-sdk-php/lib/PayPal/Api/VerifyWebhookSignature.php','<?php namespace PayPal\\Api; class VerifyWebhookSignature {public function post($apiContext=null,$restCall=null){return null;}public function setWebhookId($webhook_id){return $this;}}'],
];
$run=static function(string $provider,string $code,array $extra=[])use($root,$write,$sdk){[$package,$version,$path,$source]=$sdk[$provider];$write('composer.lock',json_encode(['packages'=>[['name'=>$package,'version'=>$version]]]));$write($path,$source);$write('app/code/Handler.php',$code);return(new ProviderWebhookSourceCheck(new Context($root,'')))->run(['provider'=>$provider]+$extra);};
try{
 $r=$run('stripe','<?php \\Stripe\\Webhook::constructEvent($raw,$header,"");');$assert($r->outcome===CheckOutcome::Fail,'Stripe empty endpoint secret diagnosed');$assert($r->evidence['diagnostics'][0]['reason']==='empty_literal_endpoint_secret','Precise Stripe reason');
 $assert($run('stripe','<?php use Stripe\\Webhook as Verify; Verify::constructEvent($raw,"",$secret);')->outcome===CheckOutcome::Fail,'Imported alias and empty signature diagnosed');
 $assert($run('stripe','<?php \\Stripe\\Webhook::constructEvent($raw,$header,$secret);')->outcome===CheckOutcome::Unknown,'SDK presence does not prove request binding');
 $assert($run('stripe','<?php /* \\Stripe\\Webhook::constructEvent($raw,$header,""); */ $x=\'constructEvent\';')->outcome===CheckOutcome::Unknown,'Comment and literal never create provider misuse');
 $assert($run('stripe','<?php class Webhook {static function constructEvent($a,$b,$c){}} Webhook::constructEvent($raw,$header,"");')->outcome===CheckOutcome::Unknown,'Unrelated custom class never resolves to Stripe');
 $assert($run('adyen','<?php $validator=new \\Adyen\\Util\\HmacSignature(); $validator->isValidNotificationHMAC($key,$item);')->outcome===CheckOutcome::Fail,'Adyen boolean result discarded diagnosed');
 $assert($run('adyen','<?php $validator=new \\Adyen\\Util\\HmacSignature(); $ok=$validator->isValidNotificationHMAC("",$item);')->outcome===CheckOutcome::Fail,'Adyen empty HMAC key diagnosed');
 $assert($run('adyen','<?php use Adyen\\Util\\HmacSignature as H; $validator=new H(); $ok=$validator->isValidNotificationHMAC($key,$item);')->outcome===CheckOutcome::Unknown,'Assigned Adyen boolean not global validation PASS');
 $assert($run('adyen','<?php $validator=new \\Adyen\\Util\\HmacSignature(); $validator=$other; $validator->isValidNotificationHMAC("",$item);')->outcome===CheckOutcome::Unknown,'Reassigned variable does not retain SDK identity');
 $assert($run('adyen','<?php function first() {$validator=new \\Adyen\\Util\\HmacSignature();} function other() {$validator->isValidNotificationHMAC("",$item);}')->outcome===CheckOutcome::Unknown,'Object identity never leaks across function boundaries');
 $assert($run('paypal','<?php $v=new \\PayPal\\Api\\VerifyWebhookSignature(); $v->setWebhookId("");')->outcome===CheckOutcome::Fail,'Legacy PayPal empty configured webhook ID diagnosed');
 $assert($run('paypal','<?php $v=new \\PayPal\\Api\\VerifyWebhookSignature(); $v->post($api);')->outcome===CheckOutcome::Fail,'Legacy PayPal discarded status response diagnosed');
 $assert($run('paypal','<?php $v=new \\PayPal\\Api\\VerifyWebhookSignature(); $response=$v->post($api);')->outcome===CheckOutcome::Unknown,'Assigned response does not prove SUCCESS enforcement');
 $assert($run('paypal','<?php $modernClient->verifyWebhookSignature($request);')->outcome===CheckOutcome::Unknown,'Modern/custom PayPal SDK remains unsupported');
 $assert($run('stripe','<?php return [;')->outcome===CheckOutcome::Unknown,'Malformed handler unknown');
 $assert($run('stripe','<?php return 1;',['paths'=>['absent']])->outcome===CheckOutcome::Unknown,'Missing scope unknown');
 $assert($run('stripe','<?php return 1;',['max_file_bytes'=>5])->outcome===CheckOutcome::Unknown,'Oversized handler unknown');
 $r=$run('stripe','<?php \\Stripe\\Webhook::constructEvent($raw,$header,"");');$assert(!str_contains(json_encode($r->evidence),'$raw'),'Evidence contains no source snippets');
 $write($sdk['stripe'][2],'<?php namespace Stripe; class Webhook {static function constructEvent($wrong){}}');
 $assert((new ProviderWebhookSourceCheck(new Context($root,'')))->run(['provider'=>'stripe'])->outcome===CheckOutcome::Unknown,'Installed incompatible SDK signature unknown');
 $write($sdk['stripe'][2],'<?php namespace Custom; class Webhook {public static function constructEvent($payload,$sigHeader,$secret){}}');
 $assert((new ProviderWebhookSourceCheck(new Context($root,'')))->run(['provider'=>'stripe'])->outcome===CheckOutcome::Unknown,'Installed class identity mismatch unknown despite matching method parameters');
 $write('composer.lock',json_encode(['packages'=>[['name'=>'paypal/paypal-server-sdk','version'=>'1.0.0']]]));
 $assert((new ProviderWebhookSourceCheck(new Context($root,'')))->run(['provider'=>'paypal'])->outcome===CheckOutcome::Unknown,'Unsupported PayPal package cannot use legacy adapter');
 $assert(CheckRegistry::fromContext(new Context($root,''))->has('provider_webhook_source_diagnostics'),'Registry exposes separate diagnostics');
 echo "Provider webhook source diagnostics: $count assertions passed\n";
}finally{foreach(array_keys($files)as$f)unlink($f);foreach(array_reverse($dirs)as$d)rmdir($d);rmdir($root.'/app/code');rmdir($root.'/app');rmdir($root);}
