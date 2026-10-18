<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

use Magebean\Engine\{Context,CheckOutcome,CheckResult};
use Magebean\Engine\Collectors\BoundedSourceInventory;

/** Negative diagnostics only. A recognizable SDK call never proves a secure handler. */
final class ProviderWebhookSourceCheck
{
    private const SDK=[
        'stripe'=>['stripe/stripe-php','Stripe\\Webhook','vendor/stripe/stripe-php/lib/Webhook.php',['constructevent'=>['$payload','$sigHeader','$secret']]],
        'adyen'=>['adyen/php-api-library','Adyen\\Util\\HmacSignature','vendor/adyen/php-api-library/src/Adyen/Util/HmacSignature.php',['isvalidnotificationhmac'=>['$hmacKey','$params'],'validatehmacsignature'=>['$hmacKey','$hmacSign','$webhook']]],
        'paypal'=>['paypal/rest-api-sdk-php','PayPal\\Api\\VerifyWebhookSignature','vendor/paypal/rest-api-sdk-php/lib/PayPal/Api/VerifyWebhookSignature.php',['post'=>['$apiContext','$restCall'],'setwebhookid'=>['$webhook_id'],'settransmissionsig'=>['$transmission_sig'],'settransmissionid'=>['$transmission_id'],'settransmissiontime'=>['$transmission_time'],'setauthalgo'=>['$auth_algo'],'setcerturl'=>['$cert_url'],'setrequestbody'=>['$request_body']]],
    ];
    public function __construct(private readonly Context $ctx){}
    public function run(array $args):CheckResult
    {
        $provider=strtolower((string)($args['provider']??''));
        if(!isset(self::SDK[$provider]))throw new \InvalidArgumentException('Supported webhook diagnostics: stripe, adyen, paypal.');
        [$package,$class,$sdkFile,$methods]=self::SDK[$provider];
        $evidence=['provider'=>$provider,'package'=>$package,'diagnostics'=>[],'observed_calls'=>[],'limitations'=>['Negative source diagnostics only; no PASS or payment-security coverage claim.','No proof of raw-body/header/secret binding, rejection-before-side-effects, replay protection or exception handling.','PayPal adapter supports legacy paypal/rest-api-sdk-php only; current REST/self-verification and other SDKs require separate adapters.']];
        $collector=new BoundedSourceInventory();
        $lock=$collector->collect($this->ctx,['paths'=>['composer.lock'],'include_ext'=>['lock']]);
        if(!$lock['complete'])return $this->unknown('Composer SDK version inventory unavailable.',$evidence);
        try{$json=json_decode($lock['files'][0]['content'],true,512,JSON_THROW_ON_ERROR);}catch(\JsonException){return $this->unknown('Composer lock is malformed.',$evidence);}
        $version=null;
        foreach($json['packages']??[] as $p)if(($p['name']??null)===$package)$version=$p['version']??null;
        if(!is_string($version)||!preg_match('/^[v0-9A-Za-z.+_-]{1,80}$/D',$version))return $this->unknown('Supported installed SDK package/version not found.',$evidence);
        $evidence['installed_version']=$version;
        $sdk=$collector->collect($this->ctx,['paths'=>[$sdkFile],'include_ext'=>['php']]);
        if(!$sdk['complete'])return $this->unknown('Installed SDK source unavailable for API-shape matching.',$evidence);
        try{$sdkTokens=self::tokens($sdk['files'][0]['content']);}catch(\ParseError){return $this->unknown('Installed SDK source cannot be parsed.',$evidence);}
        $declaredNamespace='';$declaredClass='';
        foreach($sdkTokens as $i=>$t){
            if($t['id']===T_NAMESPACE)$declaredNamespace=$sdkTokens[$i+1]['text']??'';
            if($t['id']===T_CLASS&&($sdkTokens[$i+1]['id']??null)===T_STRING){$declaredClass=$declaredNamespace.'\\'.$sdkTokens[$i+1]['text'];break;}
        }
        if(strcasecmp($declaredClass,$class)!==0)return $this->unknown('Installed SDK class identity differs from the supported adapter.',$evidence);
        $supported=[];
        foreach($sdkTokens as $i=>$t){
            if($t['id']!==T_FUNCTION)continue;
            $name=strtolower($sdkTokens[$i+1]['text']??'');if(!isset($methods[$name]))continue;
            $parameters=[];$depth=0;
            for($j=$i+2;$j<count($sdkTokens);$j++){
                $v=$sdkTokens[$j]['text'];if($v==='(')$depth++;elseif($v===')'){if(--$depth===0)break;}
                elseif($depth===1&&$sdkTokens[$j]['id']===T_VARIABLE)$parameters[]=$v;
            }
            if(array_slice($parameters,0,count($methods[$name]))===$methods[$name])$supported[$name]=true;
        }
        if($supported===[])return $this->unknown('Installed SDK method signatures differ from the supported adapter.',$evidence);
        $evidence['sdk_source_sha256']=hash('sha256',$sdk['files'][0]['content']);$evidence['matched_sdk_methods']=array_keys($supported);
        $source=$collector->collect($this->ctx,$args+['paths'=>['app/code'],'include_ext'=>['php','phtml']]);
        $evidence['collection_gaps']=$source['gaps'];$evidence['files_read']=$source['files_read'];
        foreach($source['files'] as $file){
            try{$tokens=self::tokens($file['content']);}catch(\ParseError){$evidence['collection_gaps'][]=['file'=>$file['file'],'reason'=>'malformed_php'];continue;}
            $aliases=[];$variables=[];$namespaced=false;
            foreach($tokens as $i=>$t){
                if($t['id']===T_NAMESPACE){$namespaced=true;$aliases=[];$variables=[];}
                if(in_array($t['text'],['{','}'],true))$variables=[]; // Avoid carrying object identities across control/scope boundaries.
                if($t['id']===T_USE&&isset($tokens[$i+1])&&in_array($tokens[$i+1]['id'],[T_NAME_QUALIFIED,T_NAME_FULLY_QUALIFIED,T_STRING],true)){
                    $import=ltrim($tokens[$i+1]['text'],'\\');
                    if(strcasecmp($import,$class)===0){$alias=strtolower(($tokens[$i+2]['id']??null)===T_AS?($tokens[$i+3]['text']??''):substr($class,strrpos($class,'\\')+1));$aliases[$alias]=true;}
                }
                $resolve=static function(array $token)use($class,$aliases,$namespaced):bool{
                    $name=$token['text'];return isset($aliases[strtolower($name)])||(($token['id']===T_NAME_FULLY_QUALIFIED||!$namespaced)&&strcasecmp(ltrim($name,'\\'),$class)===0);
                };
                if($t['id']===T_VARIABLE&&($tokens[$i+1]['text']??'')==='='){
                    unset($variables[$t['text']]);
                    if(($tokens[$i+2]['id']??null)===T_NEW&&isset($tokens[$i+3])&&$resolve($tokens[$i+3]))$variables[$t['text']]=true;
                }
                $method=null;$receiver=null;
                if($provider==='stripe'&&$resolve($t)&&($tokens[$i+1]['text']??'')==='::'){$method=strtolower($tokens[$i+2]['text']??'');$receiver=$i;}
                elseif($t['id']===T_VARIABLE&&isset($variables[$t['text']])&&($tokens[$i+1]['text']??'')==='->'){$method=strtolower($tokens[$i+2]['text']??'');$receiver=$i;}
                if($method===null||!isset($supported[$method])||($tokens[$i+3]['text']??'')!=='(')continue;
                [$arguments,$end]=self::arguments($tokens,$i+3);
                $location=['file'=>$file['file'],'line'=>$t['line'],'method'=>$method];
                if(count($evidence['observed_calls'])<50)$evidence['observed_calls'][]=$location;
                $report=function(string $reason)use(&$evidence,$location):void{if(count($evidence['diagnostics'])<50)$evidence['diagnostics'][]=$location+['reason'=>$reason];};
                $empty=static fn(array $arg):bool=>count($arg)===1&&($arg[0]['id']??null)===T_CONSTANT_ENCAPSED_STRING&&in_array($arg[0]['text'],["''",'""'],true);
                if($provider==='stripe')foreach([0=>'empty_literal_payload',1=>'empty_literal_signature',2=>'empty_literal_endpoint_secret'] as $offset=>$reason)if(isset($arguments[$offset])&&$empty($arguments[$offset]))$report($reason);
                if($provider==='adyen'){
                    if(isset($arguments[0])&&$empty($arguments[0]))$report('empty_literal_hmac_key');
                    if(in_array($tokens[$receiver-1]['text']??'', [';','{','}'],true)&&($tokens[$end+1]['text']??'')===';')$report('discarded_boolean_signature_result');
                }
                if($provider==='paypal'){
                    if($method!=='post'&&isset($arguments[0])&&$empty($arguments[0]))$report('empty_literal_verification_field');
                    if($method==='post'&&in_array($tokens[$receiver-1]['text']??'', [';','{','}'],true)&&($tokens[$end+1]['text']??'')===';')$report('discarded_verification_status_response');
                }
            }
        }
        if($evidence['diagnostics']!==[])return CheckResult::of(CheckOutcome::Fail,'Provider SDK source contains explicit verification argument/result-handling diagnostics; investigate the reported locations.',$evidence,'WEBHOOK_PROVIDER_DIAGNOSTIC');
        return $this->unknown('No supported definite misuse was observed; actual webhook verification and request binding remain unverified.',$evidence);
    }
    private function unknown(string $message,array $evidence):CheckResult{return CheckResult::of(CheckOutcome::Unknown,'[UNKNOWN] '.$message,$evidence,'WEBHOOK_PROVIDER_UNVERIFIED');}
    private static function tokens(string $source):array
    {
        $out=[];$line=1;
        foreach(token_get_all($source,TOKEN_PARSE) as $token){$text=is_array($token)?$token[1]:$token;$start=is_array($token)?$token[2]:$line;$line+=substr_count($text,"\n");if(is_array($token)&&in_array($token[0],[T_WHITESPACE,T_COMMENT,T_DOC_COMMENT,T_OPEN_TAG,T_CLOSE_TAG],true))continue;$out[]=['id'=>is_array($token)?$token[0]:null,'text'=>$text,'line'=>$start];}
        return $out;
    }
    private static function arguments(array $tokens,int $open):array
    {
        $args=[[]];$depth=1;
        for($j=$open+1;$j<count($tokens);$j++){
            $v=$tokens[$j]['text'];if(in_array($v,['(','[','{'],true))$depth++;elseif(in_array($v,[')',']','}'],true)){if(--$depth===0)return[$args,$j];}
            if($v===','&&$depth===1)$args[]=[];else $args[count($args)-1][]=$tokens[$j];
        }
        return[$args,count($tokens)-1];
    }
}
