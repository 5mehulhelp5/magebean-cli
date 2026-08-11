<?php
declare(strict_types=1);
namespace Magebean\Agent;
use Magebean\Engine\{Context, RulePackLoader, ScanRunner};
final class AgentScanner
{
    public function run(string $magentoPath, array $manifest, ?callable $progress = null): array
    {
        $schema=(string)($manifest['schema_version']??''); if($schema!=='1.0') throw new \RuntimeException("Unsupported manifest schema version {$schema}.");
        $entries=is_array($manifest['rules']??null)?$manifest['rules']:[];
        $manifestIndex=[];foreach($entries as $entry){$key=strtoupper((string)($entry['rule_key']??''));if($key!=='')$manifestIndex[$key]=$entry;}
        $requested=array_keys($manifestIndex);
        if($requested===[]) throw new \RuntimeException('Manifest contains no rule IDs.');
        $all=RulePackLoader::loadAll(); $index=[]; foreach($all['rules'] as $rule) $index[strtoupper((string)($rule['id']??''))]=$rule;
        $selected=[];$unsupported=[];
        foreach($requested as $id){$entry=$manifestIndex[$id];$base=['assessment_item_id'=>(string)$entry['assessment_item_id'],'rule_key'=>$id];if(!isset($index[$id])){$unsupported[]=$base+['status'=>'unsupported','message'=>'Rule is not bundled in this CLI version.'];continue;}$rule=$index[$id];if($this->isManual($rule)){$unsupported[]=$base+['status'=>'unsupported','message'=>'Manual-review rules are not executed by agents.'];continue;}$selected[]=$rule;}
        $result=$selected===[]?['summary'=>['passed'=>0,'failed'=>0,'unknown'=>0,'manual_review'=>0,'total'=>0],'findings'=>[]]:(new ScanRunner(new Context($magentoPath,''),['rules'=>$selected],$progress))->run();
        $findings=[];foreach($result['findings'] as $finding){$ruleKey=strtoupper((string)$finding['id']);$entry=$manifestIndex[$ruleKey];$status=match($finding['status']??'UNKNOWN'){'PASS'=>'pass','FAIL'=>'fail',default=>'error'};$findings[]=['assessment_item_id'=>(string)$entry['assessment_item_id'],'rule_key'=>$ruleKey,'status'=>$status,'message'=>$this->redact((string)$finding['message'],$magentoPath),'evidence'=>$this->sanitize($finding['evidence']??[],$magentoPath),'checked_at'=>gmdate(DATE_ATOM)];}
        return ['schema_version'=>'1.0','manifest_hash'=>(string)($manifest['manifest_hash']??''),'summary'=>$result['summary'],'results'=>array_merge($findings,$unsupported)];
    }
    private function isManual(array $rule): bool { foreach($rule['checks']??[] as $check) if(($check['name']??'')==='manual_review') return true; return false; }
    private function sanitize(mixed $value,string $root): mixed { if(is_string($value)) return $this->redact($value,$root); if(!is_array($value)) return $value; $out=[];foreach(array_slice($value,0,50,true) as $k=>$v){if(in_array(strtolower((string)$k),['password','token','secret','authorization','cookie'],true)){$out[$k]='[REDACTED]';continue;}$out[$k]=$this->sanitize($v,$root);}return $out; }
    private function redact(string $value,string $root): string { $value=str_replace($root,'[MAGENTO_ROOT]',$value); return preg_replace('/(password|token|secret|authorization|cookie)\s*[:=]\s*\S+/i','$1=[REDACTED]',$value)??$value; }
}
