<?php
declare(strict_types=1);
namespace Magebean\Engine;
/** Collection guidance belongs to scan execution, never to vulnerability remediation. */
final class RequirementDiagnostics
{
    public static function forFinding(array $finding): array
    {
        $id=(string)($finding['id']??'');$reason=(string)($finding['reason_code']??'');
        $message=strtolower((string)($finding['message']??''));
        if(in_array($reason,['REQUIREMENT_BINDING_UNVALIDATED','REQUIREMENT_AUTOMATION_INSUFFICIENT'],true))return ['category'=>'tool_coverage','owner'=>'magebean','action'=>'This check cannot establish the declared criterion. No deployment change is justified by this result; inspect technical observations or use the reviewed/manual assessment scope.'];
        if(str_contains($message,'certificate')||str_contains($message,'self-signed')||str_contains($message,'issuer'))return ['category'=>'tls_trust','owner'=>'scan_operator','action'=>'Trust the site CA in the scanner PHP/cURL trust store, or fix the served certificate chain for a public site. The endpoint was identified; this error does not establish that the site is offline. Keep TLS verification enabled.'];
        if($id==='MB-0072')return ['category'=>'source_history','owner'=>'scan_operator','action'=>'Run MB-0072 against the source checkout containing readable .git metadata. For deployed files without Git, use MB-0730 instead; it does not assess history.'];
        if($id==='MB-0005')return ['category'=>'runtime_endpoint','owner'=>'scan_operator','action'=>'Verify the exact timed-out path from this scanner and use --url for the canonical reachable store. Check proxy/firewall behavior for directory probes; a timed-out response is not proof of directory listing.'];
        if($id==='MB-0030' && str_contains($message,'cookie probe needs a successful same-host https'))return ['category'=>'https_response_required','owner'=>'scan_operator','action'=>'The identified URL did not produce successful same-host HTTPS responses for this cookie policy. Check the effective web/secure/base_url, redirects, response status and TLS endpoint; use --url only to override an incorrect discovered URL. Site availability and cookie protection are separate observations.'];
        if($id==='MB-0030')return ['category'=>'runtime_endpoint','owner'=>'scan_operator','action'=>'Provide --url=https://your-store reachable from this scanner; verify the login/cart pages return successful same-host HTTPS responses that emit session cookies. See per-path collection details.'];
        if(str_contains($message,'api')||str_contains($message,'endpoint'))return ['category'=>'api_collection','owner'=>'scan_operator','action'=>'Check reachability, DNS, proxy and TLS trust for the named endpoint. If its response schema or per-package coverage is incomplete, retry after the data provider resolves it; do not change application code based on missing API data.'];
        if($id==='MB-0009')return ['category'=>'magento_configuration','owner'=>'scan_operator','action'=>'Make app/etc/env.php, app/etc/config.php and installed Magento_Backend defaults readable; if DB-backed configuration is used, allow read access to default-scope core_config_data. Do not infer a weak timeout from an unreadable setting.'];
        if($id==='MB-0043')return ['category'=>'logging_scope','owner'=>'security_reviewer','action'=>'Review effective system logrotate, journald or managed-log retention. A missing project devops/logrotate.conf does not prove missing rotation.'];
        return ['category'=>'required_input','owner'=>'scan_operator','action'=>'Make the exact file, directory or setting named in the collection details available and readable to the scanner, then rerun this requirement. Missing evidence is not a confirmed security defect.'];
    }
}
