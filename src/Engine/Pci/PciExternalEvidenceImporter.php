<?php
declare(strict_types=1);
namespace Magebean\Engine\Pci;

final class PciExternalEvidenceImporter
{
    private const METHODS=['examine','observe','interview'];
    private const SOURCE_TYPES=['document','configuration_export','screenshot','log_export','ticket','attestation','interview_record','observation_record','vendor_report','other'];
    private const FORBIDDEN=['password','password_hash','credential_value','secret','token','private_key','authentication_cookie','pan','cvv','cvc','pin','pin_block','track_data'];
    private array $requirementIds;
    public function __construct(array $requirementIds){$this->requirementIds=array_fill_keys(array_map('strval',$requirementIds),true);}

    public function import(string $path):array
    {
        if(!is_file($path)||!is_readable($path))return $this->result(false,["Evidence package is missing or unreadable: {$path}"],[],0);
        try{$data=json_decode((string)file_get_contents($path),true,512,JSON_THROW_ON_ERROR);}catch(\JsonException $e){return $this->result(false,['Evidence package contains malformed JSON.'],[],0);}
        if(!is_array($data))return $this->result(false,['Evidence package root must be an object.'],[],0);
        $errors=[];$this->rejectForbiddenKeys($data,'$',$errors);$this->rejectUnknownKeys($data,['schema_version','standard','version','assessment_id','collected_at','evidence'],'$',$errors);
        foreach(['schema_version','standard','version','assessment_id','collected_at','evidence'] as $key)if(!array_key_exists($key,$data))$errors[]="Missing top-level field: {$key}.";
        if(($data['schema_version']??null)!==1)$errors[]='schema_version must be 1.';
        if(($data['standard']??null)!=='PCI DSS'||($data['version']??null)!=='4.0.1')$errors[]='Evidence package must target PCI DSS 4.0.1.';
        if(!$this->validId((string)($data['assessment_id']??'')))$errors[]='assessment_id must be a stable non-empty identifier.';
        if(!$this->validTimestamp($data['collected_at']??null))$errors[]='collected_at must be an ISO-8601 timestamp.';
        $items=$data['evidence']??null;if(!is_array($items)||$items===[])$errors[]='evidence must contain at least one item.';
        $seen=[];$by=[];$accepted=0;
        if(is_array($items))foreach($items as $i=>$item){$prefix="evidence[{$i}]";if(!is_array($item)){$errors[]="{$prefix} must be an object.";continue;}$this->rejectUnknownKeys($item,['id','requirement','method','source_type','source_ref','collected_at','sha256','description','owner','attestation'],$prefix,$errors);foreach(['id','requirement','method','source_type','source_ref','collected_at','sha256','description','owner','attestation'] as $key)if(!array_key_exists($key,$item))$errors[]="{$prefix}.{$key} is required.";$id=(string)($item['id']??'');$rid=(string)($item['requirement']??'');if(!$this->validId($id))$errors[]="{$prefix}.id is invalid.";elseif(isset($seen[$id]))$errors[]="Duplicate evidence id: {$id}.";else $seen[$id]=true;if(!isset($this->requirementIds[$rid]))$errors[]="{$prefix}.requirement is not in the PCI DSS 4.0.1 registry.";if(!in_array($item['method']??null,self::METHODS,true))$errors[]="{$prefix}.method is invalid.";if(!in_array($item['source_type']??null,self::SOURCE_TYPES,true))$errors[]="{$prefix}.source_type is invalid.";if(!$this->validId((string)($item['source_ref']??'')))$errors[]="{$prefix}.source_ref is invalid.";if(!$this->validTimestamp($item['collected_at']??null))$errors[]="{$prefix}.collected_at must be ISO-8601.";if(preg_match('/^[a-f0-9]{64}$/',(string)($item['sha256']??''))!==1)$errors[]="{$prefix}.sha256 must be a lowercase SHA-256 digest.";foreach(['description','owner'] as $key)if(trim((string)($item[$key]??''))==='')$errors[]="{$prefix}.{$key} must be non-empty.";$att=$item['attestation']??null;if(!is_array($att))$errors[]="{$prefix}.attestation must be an object.";else{$this->rejectUnknownKeys($att,['complete','reviewer','reviewed_at'],$prefix.'.attestation',$errors);foreach(['complete','reviewer','reviewed_at'] as $key)if(!array_key_exists($key,$att))$errors[]="{$prefix}.attestation.{$key} is required.";if(($att['complete']??null)!==true)$errors[]="{$prefix}.attestation.complete must be true before import.";if(trim((string)($att['reviewer']??''))==='')$errors[]="{$prefix}.attestation.reviewer must be non-empty.";if(!$this->validTimestamp($att['reviewed_at']??null))$errors[]="{$prefix}.attestation.reviewed_at must be ISO-8601.";}$by[$rid][]=['id'=>$id,'method'=>$item['method']??null,'source_type'=>$item['source_type']??null,'source_ref'=>$item['source_ref']??null,'collected_at'=>$item['collected_at']??null,'sha256'=>$item['sha256']??null,'description'=>$item['description']??null,'owner'=>$item['owner']??null,'attested'=>($att['complete']??false)===true];$accepted++;}
        if($errors!==[])return $this->result(false,array_values(array_unique($errors)),[],0);
        ksort($by);return $this->result(true,[],$by,$accepted);
    }
    private function result(bool $valid,array $errors,array $by,int $count):array{return ['valid'=>$valid,'errors'=>$errors,'evidence_by_requirement'=>$by,'summary'=>['items'=>$count,'requirements'=>count($by),'credential_material_processed'=>false]];}
    private function validId(string $v):bool{return $v!==''&&strlen($v)<=200&&preg_match('/^[A-Za-z0-9][A-Za-z0-9._:\/-]*$/',$v)===1;}
    private function validTimestamp(mixed $v):bool{if(!is_string($v)||trim($v)==='')return false;try{new \DateTimeImmutable($v);return true;}catch(\Throwable){return false;}}
    private function rejectUnknownKeys(array $value,array $allowed,string $path,array &$errors):void{foreach(array_diff(array_keys($value),$allowed) as $key)$errors[]="Unknown field at {$path}.{$key}.";}
    private function rejectForbiddenKeys(mixed $v,string $path,array &$errors):void{if(!is_array($v))return;foreach($v as $k=>$child){$key=strtolower((string)$k);if(in_array($key,self::FORBIDDEN,true))$errors[]="Forbidden sensitive field at {$path}.{$k}; use references and fingerprints only.";$this->rejectForbiddenKeys($child,$path.'.'.$k,$errors);}}
}
