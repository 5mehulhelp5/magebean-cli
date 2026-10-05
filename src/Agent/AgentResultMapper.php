<?php
declare(strict_types=1);
namespace Magebean\Agent;
/** Maps scan observations into the existing redacted Console transport schema. */
final class AgentResultMapper
{
    public function map(array $result, array $manifest, array $manifestIndex, array $unsupported, string $magentoPath): array
    {
        $findings=[];foreach($result['findings'] as $finding){$ruleKey=strtoupper((string)$finding['id']);$entry=$manifestIndex[$ruleKey];$status=match($finding['status']??'UNKNOWN'){'PASS'=>'pass','FAIL'=>'fail',default=>'error'};$findings[]=['assessment_item_id'=>(string)$entry['assessment_item_id'],'rule_key'=>$ruleKey,'status'=>$status,'message'=>$this->redact((string)$finding['message'],$magentoPath),'detail'=>$this->sanitize($finding['detail']??$finding['details']??[],$magentoPath),'evidence'=>$this->sanitize($finding['evidence']??[],$magentoPath),'checked_at'=>gmdate(DATE_ATOM)];}
        foreach ($findings as $position => $payload) {
            $findings[$position]['title'] = $this->resultTitle($payload);
        }
        return ['schema_version'=>'1.0','manifest_hash'=>(string)($manifest['manifest_hash']??''),'summary'=>$result['summary'],'results'=>array_merge($findings,$unsupported)];
    }
    public function resultTitle(array $result): string
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
    private function sanitize(mixed $value,string $root): mixed { if(is_string($value)) return $this->redact($value,$root); if(!is_array($value)) return $value; $out=[];foreach(array_slice($value,0,50,true) as $k=>$v){if(in_array(strtolower((string)$k),['password','token','secret','authorization','cookie'],true)){$out[$k]='[REDACTED]';continue;}$out[$k]=$this->sanitize($v,$root);}return $out; }
    private function redact(string $value,string $root): string { $value=str_replace($root,'[MAGENTO_ROOT]',$value); return preg_replace('/(password|token|secret|authorization|cookie)\s*[:=]\s*\S+/i','$1=[REDACTED]',$value)??$value; }
}
