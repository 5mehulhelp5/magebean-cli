<?php
declare(strict_types=1);
namespace Magebean\Engine;
final class RequirementProfileCatalog
{
    public static function load(string $name):array
    {
        if(is_file($name)){$p=json_decode((string)file_get_contents($name),true,512,JSON_THROW_ON_ERROR);if(!is_array($p['requirement_ids']??null))throw new \RuntimeException('Primary profiles require requirement_ids.');$p+=['id'=>basename($name,'.json'),'title'=>'Custom requirements'];return self::validate($p);}
        $name=strtolower(trim($name));$name=['default'=>'basic','best-practices'=>'basic','owasp'=>'owasp-top-10-2025','pci'=>'pci-dss-v4.0.1','pci-dss'=>'pci-dss-v4.0.1','production'=>'hardening','production-hardening'=>'hardening','all'=>'baseline','magebean'=>'baseline'][$name]??$name;
        $all=RequirementCatalog::read('internal-profiles')['profiles'];foreach($all as $key=>$p)if($key===$name||in_array($name,$p['aliases']??[],true))return self::validate($p);throw new \RuntimeException('Unknown internal requirement profile: '.$name);
    }
    public static function all():array{return RequirementCatalog::read('internal-profiles')['profiles'];}
    private static function validate(array $p):array
    {
        if(!is_array($p['requirement_ids']??null))throw new \RuntimeException('Profile requires requirement_ids.');$known=array_column(RequirementCatalog::loadAll()['rules'],null,'id');$seen=[];
        foreach($p['requirement_ids'] as $id){if(!is_string($id)||preg_match('/^MB-[0-9]+$/D',$id)!==1)throw new \RuntimeException('Unknown internal requirement identity in profile.');$resolved=isset($known[$id])?[$id]:LegacyRequirementAliases::resolve($id);if(count($resolved)!==1||!isset($known[$resolved[0]]))throw new \RuntimeException('Unknown internal requirement identity in profile.');$seen[$resolved[0]]=true;}
        $p['requirement_ids']=array_keys($seen);
        if(isset($p['assessment_level'])&&!in_array($p['assessment_level'],[1,2,3],true))throw new \RuntimeException('Invalid profile assessment level.');return $p;
    }
}
