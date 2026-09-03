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
        $findings=[];foreach($result['findings'] as $finding){$ruleKey=strtoupper((string)$finding['id']);$entry=$manifestIndex[$ruleKey];$status=match($finding['status']??'UNKNOWN'){'PASS'=>'pass','FAIL'=>'fail',default=>'error'};$findings[]=['assessment_item_id'=>(string)$entry['assessment_item_id'],'rule_key'=>$ruleKey,'status'=>$status,'message'=>$this->redact((string)$finding['message'],$magentoPath),'detail'=>$this->sanitize($finding['detail']??$finding['details']??[],$magentoPath),'evidence'=>$this->sanitize($finding['evidence']??[],$magentoPath),'checked_at'=>gmdate(DATE_ATOM)];}
        foreach ($findings as $position => $payload) {
            $findings[$position]['title'] = $this->resultTitle($payload);
        }
        return ['schema_version'=>'1.0','manifest_hash'=>(string)($manifest['manifest_hash']??''),'summary'=>$result['summary'],'results'=>array_merge($findings,$unsupported)];
    }
    private function resultTitle(array $result): string
    {
        // Use the redacted outcome, never the rule's desired-state title.
        $message = trim((string)($result['message'] ?? ''));
        if ($message === '') {
            foreach ($result['detail'] ?? [] as $detail) {
                if (is_array($detail)
                    && strtolower((string)($detail['status'] ?? '')) === $result['status']
                    && trim((string)($detail['message'] ?? '')) !== '') {
                    $message = trim((string)$detail['message']);
                    break;
                }
            }
        }
        $title = rtrim(trim((string)(preg_split('/\R/u', $message, 2)[0] ?? '')), ': ');
        // Rule messages can put remediation on the same line as the issue.
        // Keep the first sentence; dots within paths and versions are not boundaries.
        if (preg_match('/^(.+?[.!?])\s+(?=\p{Lu})/u', $title, $sentence) === 1) {
            $title = $sentence[1];
        }
        if ($title === '') {
            $title = match ($result['status']) {
                'fail' => 'Security check failed',
                'pass' => 'Security check passed',
                default => 'Security check could not be completed',
            };
        }
        // Console accepts at most 255 characters; preserve UTF-8 without mbstring.
        if (preg_match('/^(.{252}).{4}/us', $title, $match) === 1) {
            return rtrim($match[1]) . '...';
        }
        return $title;
    }
    private function isManual(array $rule): bool { foreach($rule['checks']??[] as $check) if(($check['name']??'')==='manual_review') return true; return false; }
    private function sanitize(mixed $value,string $root): mixed { if(is_string($value)) return $this->redact($value,$root); if(!is_array($value)) return $value; $out=[];foreach(array_slice($value,0,50,true) as $k=>$v){if(in_array(strtolower((string)$k),['password','token','secret','authorization','cookie'],true)){$out[$k]='[REDACTED]';continue;}$out[$k]=$this->sanitize($v,$root);}return $out; }
    private function redact(string $value,string $root): string { $value=str_replace($root,'[MAGENTO_ROOT]',$value); return preg_replace('/(password|token|secret|authorization|cookie)\s*[:=]\s*\S+/i','$1=[REDACTED]',$value)??$value; }
}
