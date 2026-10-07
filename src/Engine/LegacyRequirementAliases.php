<?php
declare(strict_types=1);
namespace Magebean\Engine;
/** Compatibility redirects are separate from independently scoped identities. */
final class LegacyRequirementAliases
{
    public static function resolve(string $id,?string $profile=null):array
    {
        $id=strtoupper(trim($id));$known=array_column(RequirementCatalog::loadAll()['rules'],null,'id');$data=RequirementCatalog::read('legacy-aliases');$aliases=$data['aliases'];
        if($profile!==null&&!(preg_match('/^MB-[0-9]{4,}$/D', $id) === 1)){$p=RequirementProfileCatalog::load($profile);foreach($data['profile_aliases'][$p['id']]??[] as $key=>$values)$aliases[$key]=$values;}
        $resolve=function(string $key,array $trail=[])use(&$resolve,$known,$aliases):array{
            if(isset($trail[$key]))throw new \RuntimeException('Requirement alias redirect cycle: '.$key);
            if(isset($known[$key]))return [$key];
            $trail[$key]=true;$out=[];foreach($aliases[$key]??[] as $next)$out=array_merge($out,$resolve(strtoupper((string)$next),$trail));return array_values(array_unique($out));
        };
        $ids=$resolve($id);
        if($profile!==null&&!(preg_match('/^MB-[0-9]{4,}$/D', $id) === 1))$ids=array_values(array_intersect($ids,$p['requirement_ids']));
        return $ids;
    }
}
