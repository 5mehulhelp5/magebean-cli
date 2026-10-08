<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;
use Magebean\Engine\{Context, CheckResult, CheckOutcome};
use Magebean\Engine\Collectors\CollectorSet;

/** Read-only probes/artifact inspection; human confirmation remains necessary. */
final class RuntimeEvidenceCheck
{
    public function __construct(private readonly Context $ctx, private readonly CollectorSet $collectors) {}

    public function contentType(array $args): CheckResult
    {
        $url = $this->ctx->url;
        if (!preg_match('~^https?://~i', $url)) return $this->unknown('A store URL is required for response evidence.', []);
        [$ok,$message,$response] = $this->collectors->http->fetch($url, 'GET', [], 5000, false);
        if ($ok !== true) return $this->unknown('HTTP response could not be collected: ' . $message, $response + ['transport_error'=>true]);
        $evidence = self::inspectResponse($response);
        $evidence['required_follow_up']=(string)($args['review']??'');
        $status = (int)($response['status'] ?? 0);
        if ($status<200 || $status>=300 || ($response['body']??'')==='') return $this->unknown('Response has no assessable successful body; redirects/errors are not coverage of the application.', $evidence);
        if (!$evidence['assessable']) return $this->unknown('Response media type/body classification is indeterminate.', $evidence);
        return CheckResult::of(CheckOutcome::ManualReview, 'One response was inspected; review observed header/body issues and verify all response types and endpoints.', $evidence, 'RESPONSE_MEDIA_CONFIRMATION');
    }

    public static function inspectResponse(array $response): array
    {
        $headers = $response['headers']??[]; $type = $headers['content-type']??''; $issues=[];
        if (is_array($type)) { $issues[]='multiple_content_type_headers'; $type=''; }
        $type=is_string($type)?strtolower(trim($type)):'';
        $body=(string)($response['body']??''); $trim=ltrim($body); $media=trim(explode(';',$type)[0]);
        $evidence=['status'=>(int)($response['status']??0),'media_type'=>$media,'body_bytes'=>strlen($body),'issues'=>$issues,'assessable'=>true,
            'limitations'=>['Single unauthenticated response; no proof of complete endpoint coverage.', 'Body sniffing supports HTML, JSON and XML only; bodies and raw headers are not retained.']];
        if ($type==='') $evidence['issues'][]='missing_or_ambiguous_content_type';
        elseif (!preg_match('~^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$~D',$media)) $evidence['issues'][]='invalid_media_type';
        if ($media!=='' && !preg_match('~^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$~D',$media)) $evidence['media_type']='';
        $charsetRequired=str_starts_with($media,'text/') || $media==='application/xml' || str_ends_with($media,'+xml');
        if ($charsetRequired && !preg_match('~;\s*charset\s*=\s*[\x22\x27]?(?:utf-8|us-ascii|iso-8859-1)[\x22\x27]?(?:\s*;|\s*$)~i',$type)) $evidence['issues'][]='missing_or_unverified_safe_charset';
        $looksHtml=preg_match('~^(?:<!doctype\s+html\b|<html\b)~i',$trim)===1;
        $looksXml=str_starts_with($trim,'<?xml');
        $looksJson=false;
        if (preg_match('~^[\[{]~',$trim)) {json_decode($trim);$looksJson=json_last_error()===JSON_ERROR_NONE;}
        if ($media !== '' && (($looksHtml && !in_array($media,['text/html','application/xhtml+xml'],true)) || ($looksXml && $media!=='application/xml' && $media!=='text/xml' && !str_ends_with($media,'+xml')) || ($looksJson && $media!=='application/json' && !str_ends_with($media,'+json')))) $evidence['issues'][]='observed_body_type_mismatch';
        if (!$looksHtml && !$looksXml && !$looksJson && $type!=='') $evidence['assessable']=false;
        return $evidence;
    }

    public function defaultAccounts(array $args): CheckResult
    {
        if (isset($args['artifact']) && !is_string($args['artifact'])) throw new \InvalidArgumentException('Account artifact must be a relative path string.');
        $relative=(string)($args['artifact']??'.magebean/evidence/default-accounts.json');
        if ($relative==='' || preg_match('~(?:^/|^[A-Za-z]:|(?:^|/)\.\.(?:/|$))~',str_replace('\\','/',$relative))) throw new \InvalidArgumentException('Account artifact must remain inside project.'); $file=$this->ctx->abs($relative);
        $evidence=['file'=>$relative,'required_follow_up'=>(string)($args['review']??''),'limitations'=>['Supplied inventory is not independently verified live account state.', 'Requires complete identity-provider/application coverage and reviewer confirmation.']];
        if (($this->ctx->get('meta', [])['target_mode'] ?? '') === 'REMOTE') return $this->unknown('Live/local account evidence is unavailable in remote mode.', $evidence);
        $this->collectors->session->checkpoint();
        if (!is_file($file) || filesize($file)>1048576) return $this->unknown('A bounded account inventory artifact is required.', $evidence);
        $real=realpath($file);$root=realpath($this->ctx->path);
        if ($real!==false) $real=str_replace('\\','/',$real);
        if ($root!==false) $root=str_replace('\\','/',$root);
        if ($real===false || $root===false || !str_starts_with($real,rtrim($root,'/').'/')) return $this->unknown('Account artifact must resolve inside the project.', $evidence);
        $text=$this->collectors->files->read($file);
        if ($text === false || strlen($text)>1048576) return $this->unknown('Account inventory could not be read within the size limit.', $evidence);
        try {$data=json_decode($text===false?'':$text,true,32,JSON_THROW_ON_ERROR);}catch(\JsonException){return $this->unknown('Account inventory is invalid JSON.', $evidence);}
        if (!is_array($data) || ($data['schema_version']??'')!=='1.0' || ($data['scope']??'')!=='application' || ($data['complete']??null)!==true || !is_array($data['accounts']??null) || !array_is_list($data['accounts'])) return $this->unknown('Account inventory requires schema 1.0, application scope, complete=true and an accounts list.', $evidence);
        $freshness=$args['freshness_seconds']??86400;
        $names=$args['default_names']??['root','admin','administrator','sa','guest','demo','test'];
        if (!is_int($freshness) || $freshness<1 || $freshness>604800 || !is_array($names) || !array_is_list($names)) throw new \InvalidArgumentException('Invalid identity evidence policy.');
        foreach($names as $name) if(!is_string($name)||trim($name)==='') throw new \InvalidArgumentException('Default account names must be nonempty strings.');
        $names=array_map(static fn(string $name):string=>strtolower(trim($name)),$names);
        $stamp=$data['generated_at']??null;
        $time=is_string($stamp) && preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/D',$stamp) ? strtotime($stamp) : false;
        if ($time===false || $time>time()+60 || $time<time()-$freshness) return $this->unknown('Account inventory timestamp is absent, future or older than the permitted freshness window.', $evidence);
        $flagged=[];
        foreach ($data['accounts'] as $account) {
            $this->collectors->session->checkpoint();
            if (!is_array($account) || !is_string($account['username']??null) || trim($account['username'])==='' || !is_bool($account['enabled']??null)) return $this->unknown('Account inventory contains an invalid account record.', $evidence);
            $name=strtolower(trim($account['username']));
            if ($account['enabled'] && in_array($name,$names,true)) $flagged[$name]=true;
        }
        $evidence+=['generated_at'=>gmdate('c',$time),'accounts_inspected'=>count($data['accounts']),'enabled_default_names'=>array_keys($flagged)];
        return CheckResult::of(CheckOutcome::ManualReview, $flagged ? 'Enabled default account names were observed; confirm whether these are default identities and remediate.' : 'No listed enabled default names were observed; independently verify inventory completeness and custom default identities.', $evidence, 'IDENTITY_INVENTORY_CONFIRMATION');
    }

    private function unknown(string $message,array $evidence): CheckResult
    {
        if (!isset($evidence['action'])) $evidence['action'] = isset($evidence['file']) ? 'Provide a fresh application account inventory at ' . $evidence['file'] . ' with schema_version=1.0, scope=application, complete=true, generated_at in ISO 8601 and accounts containing username/enabled; protect the artifact from public access, then rerun.' : 'Use a canonical reachable storefront URL returning a successful HTML/JSON/XML body with an explicit Content-Type; inspect redirects, WAF challenges and HTTP errors, then rerun.';
        return CheckResult::of(CheckOutcome::Unknown,'[UNKNOWN] '.$message,$evidence,'RUNTIME_EVIDENCE_MISSING');
    }
}
