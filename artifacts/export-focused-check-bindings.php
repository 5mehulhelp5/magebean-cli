<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementProfileCatalog};
$index=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
$registry=file(__DIR__.'/../src/Engine/Checks/CheckRegistry.php');$tests=[];
foreach(glob(__DIR__.'/../tests/*Test.php')as$file)$tests[basename($file)]=file_get_contents($file);
$normalize=function(array$args)use(&$normalize):array{if(!array_is_list($args))ksort($args);foreach($args as&$value)if(is_array($value))$value=$normalize($value);unset($value);return$args;};
$rows=[];$members=[];
foreach(['basic','hardening','owasp-top-10-2025']as$profile){
    foreach(RequirementProfileCatalog::load($profile)['requirement_ids']as$id){
        $members[$id]=true;$r=$index[$id];$recipes=['DEFAULT'=>$r['obligations']];
        foreach($r['execution_variants']??[]as$mode=>$variant)$recipes[$mode]=$variant['obligations'];
        foreach($recipes as$mode=>$obligations)foreach($obligations as$o)foreach($o['checks']as$c){
            $lines=[];foreach($registry as$n=>$line)if(str_contains($line,"register('".$c['name']."'"))$lines[]=$n+1;
            $mentions=[];foreach($tests as$file=>$source)if(str_contains($source,$c['name']))$mentions[]=$file;
            $args=$c['args']??[];
            $rows[]=['profile'=>$profile,'requirement_id'=>$id,'recipe'=>$mode,'obligation'=>$o['id'],'role'=>$o['role'],'proof'=>$o['proof'],'operator'=>$o['op']??'all','check'=>$c['name'],'args'=>$args,'binding_hash'=>hash('sha256',json_encode([$c['name'],$normalize($args)],JSON_THROW_ON_ERROR)),'registry_lines'=>$lines,'test_name_mentions_only'=>$mentions];
        }
    }
}
file_put_contents(__DIR__.'/focused-check-bindings.json',json_encode(['note'=>'Every current obligation/check binding including mode variants for three focused profiles. Test-name mentions are navigation hints, NOT proof of assertion coverage, correctness or runnable fixtures. Registry empty line list may be prefix dispatch.','unique_requirements'=>count($members),'bindings'=>$rows],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
echo count($members),' unique requirements; ',count($rows)," check-binding occurrences including profile overlaps and mode variants.\n";
