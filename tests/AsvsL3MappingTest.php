<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{ProfileLoader,RulePackLoader};
function assertL3(bool $c,string $m):void{if(!$c){fwrite(STDERR,$m."\n");exit(1);}}
$raw=json_decode(file_get_contents(__DIR__.'/../src/Rules/profiles/asvs-l3.json'),true,512,JSON_THROW_ON_ERROR);
assertL3(($raw['inherits']??[])===['asvs-l2'],'L3 must inherit L2');
assertL3(count($raw['requirement_coverage']??[])===92,'L3 must declare 92 additions');
$p=ProfileLoader::load('asvs-l3');$coverage=$p['requirement_coverage']??[];
assertL3(count($coverage)===345,'Cumulative L3 must contain 345 requirements');
$ids=array_column($coverage,'id');assertL3(count(array_unique($ids))===345,'L3 requirement IDs must be unique');
$allowed=['AUTOMATED','PARTIALLY_AUTOMATED','MANUAL_REVIEW','CONTEXT_REQUIRED','NOT_APPLICABLE','NOT_YET_COVERED'];$counts=array_fill_keys($allowed,0);
foreach($coverage as $e){$status=$e['status']??'';assertL3(in_array($status,$allowed,true),'Unknown L3 status');$counts[$status]++;if($status==='CONTEXT_REQUIRED')assertL3(isset($e['applicability']['capability']),'Context requirement lacks capability');}
foreach(['automated'=>'AUTOMATED','partially_automated'=>'PARTIALLY_AUTOMATED','manual_review'=>'MANUAL_REVIEW','context_required'=>'CONTEXT_REQUIRED','not_applicable'=>'NOT_APPLICABLE','not_yet_covered'=>'NOT_YET_COVERED'] as $key=>$status)assertL3((int)$p['coverage_summary'][$key]===$counts[$status],'L3 summary mismatch '.$key);
$selected=ProfileLoader::apply(RulePackLoader::loadAll(),$p);
assertL3(count($selected['rules']??[])===259,'L3 no-capability profile selection must contain 259 rules before CLI manual filtering');
echo "AsvsL3MappingTest: PASS\n";
