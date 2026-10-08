<?php
declare(strict_types=1);
namespace Magebean\Engine;
/** Collection guidance belongs to scan execution, never to vulnerability remediation. */
final class RequirementDiagnostics
{
    public static function forFinding(array $finding, array $definition = []): array
    {
        $reason = (string)($finding['reason_code'] ?? '');
        $checks = [];
        foreach ($finding['evidence']['obligations'] ?? [] as $obligation) {
            if (($obligation['role'] ?? 'mandatory') === 'supporting') continue;
            foreach ($obligation['checks'] ?? [] as $check) if (($check['status'] ?? '') === 'UNKNOWN') $checks[] = $check;
        }
        $resources = [];
        foreach ($definition['checks'] ?? [] as $check) {
            foreach ($check['args'] ?? [] as $key => $value) {
                if (!in_array($key, ['file','files','path','paths','lock_file','json_file','env_file','status_file','endpoint','status_endpoint'], true)) continue;
                foreach (is_array($value) ? $value : [$value] as $input) {
                    if (!is_string($input) || trim($input) === '') continue;
                    if (str_contains($key, 'endpoint')) {
                        $url = parse_url($input);
                        $input = isset($url['host']) ? ($url['scheme'] ?? 'https').'://'.$url['host'].(isset($url['port']) ? ':'.$url['port'] : '').($url['path'] ?? '') : '[configured API endpoint]';
                    }
                    $resources[] = $input;
                }
            }
        }
        $resources = array_values(array_unique($resources));
        $make = static fn(string $category, string $owner, string $action, ?string $code = null): array => ['category'=>$category,'owner'=>$owner,'action'=>$action,'resources'=>$resources,'reason_code'=>$code ?? $reason];
        if (in_array($reason, ['REQUIREMENT_BINDING_UNVALIDATED','REQUIREMENT_AUTOMATION_INSUFFICIENT'], true)) return $make('tool_coverage','magebean','Report this requirement ID and technical observations to Magebean support for criterion/check review. No deployment change is justified by this result.');
        if ($reason === 'REQUIREMENT_APPLICABILITY_UNRESOLVED') return $make('assessment_scope','security_reviewer','Confirm the requirement applicability and target capabilities in the assessment context before rerunning; no security conclusion can be produced for an unresolved scope.');
        foreach ($checks as $check) {
            if (($check['reason_code'] ?? '') === 'CHECK_EXECUTION_FAILED') return $make('check_execution','magebean','Report requirement ID and check '.($check['check'] ?? '').' to Magebean support with the scanner version. The check failed internally; rerun after the tool fix. Do not change deployment security settings based on this error.','CHECK_EXECUTION_FAILED');
        }
        if ($reason === 'SCAN_DEADLINE_EXCEEDED' || array_filter($checks, static fn(array $c): bool => ($c['reason_code'] ?? '') === 'SCAN_DEADLINE_EXCEEDED')) return $make('scan_deadline','scan_operator','Increase the scan deadline or run this requirement separately; check slow filesystem, database or endpoint operations identified in its collection details.','SCAN_DEADLINE_EXCEEDED');
        // Prefer typed collector actions over guesses from a generic assessment message.
        $actions = []; $codes = [];
        $visit = static function (array $value) use (&$visit, &$actions, &$codes): void {
            if (is_string($value['action'] ?? null) && trim($value['action']) !== '') $actions[] = $value['action'];
            if (is_string($value['reason_code'] ?? null)) $codes[] = $value['reason_code'];
            foreach ($value as $child) if (is_array($child)) $visit($child);
        };
        foreach ($checks as $check) $visit($check['evidence'] ?? []);
        if ($actions !== []) return $make('collection_failure','scan_operator',implode(' ', array_slice(array_values(array_unique($actions)),0,3)), $codes[0] ?? $reason);
        $message = strtolower((string)($finding['message'] ?? '').' '.implode(' ', array_column($checks,'message')));
        $id = (string)($finding['id'] ?? '');
        if (str_contains($message,'unknown check:') || str_contains($message,'unsupported check')) return $make('tool_coverage','magebean','Report the requirement ID and unregistered check name to Magebean support. Install a scanner build containing this check binding; no deployment change is justified by an unsupported check.');
        if (str_contains($message,'certificate') || str_contains($message,'self-signed') || str_contains($message,'issuer')) return $make('tls_trust','scan_operator','Trust the site CA in the scanner PHP/cURL trust store, or fix the served certificate chain for a public site. The endpoint was identified; this error does not establish that the site is offline. Keep TLS verification enabled.');
        if (str_contains($message,'resolve host') || str_contains($message,'dns')) return $make('dns_resolution','scan_operator','Resolve the identified hostname from the scanner environment; check its DNS resolver and proxy configuration, then rerun this requirement.');
        if ($id === 'MB-0072') return $make('source_history','scan_operator','Run MB-0072 against the source checkout containing readable .git metadata and a Git executable supporting PCRE searches. For deployed files without Git, use MB-0730 instead; it does not assess history.');
        if ($id === 'MB-0030' && str_contains($message,'cookie probe needs a successful same-host https')) return $make('https_response_required','scan_operator','The identified URL did not produce successful same-host HTTPS responses for this cookie policy. Check the effective web/secure/base_url, redirects, response status and TLS endpoint; use --url only to override an incorrect discovered URL. Site availability and cookie protection are separate observations.');
        if ($id === 'MB-0030') return $make('runtime_endpoint','scan_operator','Check the discovered Magento secure base URL, login/cart response status, redirects and TLS trust from this scanner. Use --url=https://your-store if discovery is unavailable or incorrect; successful same-host HTTPS responses must emit session cookies. See per-path details.');
        if (str_contains($message,'pdo') || str_contains($message,'database') || str_contains($message,'db ') || str_contains($message,'query') || in_array($id,['MB-0039','MB-0047','MB-0048','MB-0100'],true)) return $make('database_collection','scan_operator','Allow the scanner to read app/etc/env.php and connect using its configured database credentials; enable PHP pdo_mysql and verify read-only SELECT access to the named Magento tables and configured table prefix. Check the database schema/version if the query is unsupported. Never attach credentials to the report.');
        if (str_contains($message,'api') || str_contains($message,'endpoint') || str_contains($message,'package status') || in_array($id,['MB-0049','MB-0050','MB-0055','MB-0056','MB-0057','MB-0059','MB-0061','MB-0062','MB-0063','MB-0065','MB-0066','MB-0067','MB-0069'],true)) return $make('api_collection','scan_operator','Check the named API endpoint DNS, proxy, TLS trust and response coverage for every selected package. Make composer.lock readable and valid. If the response schema or package coverage is incomplete, retry after the data provider resolves it; missing API data is not an application vulnerability.');
        if ($id === 'MB-0005' || str_contains($message,'http') || str_contains($message,'url') || str_contains($message,'timed out')) return $make('runtime_endpoint','scan_operator','Check the exact URL and response status from the scanner, including DNS, proxy/firewall, redirects and timeout. Verify the discovered base URL; use --url only if unavailable or incorrect. An inaccessible response cannot establish this security policy.');
        if (str_contains($message,'configuration') || str_contains($message,'setting') || str_starts_with((string)($checks[0]['check'] ?? ''),'magento_') || str_starts_with((string)($checks[0]['check'] ?? ''),'php_')) return $make('configuration_collection','scan_operator','Make the named configuration files and installed Magento module defaults readable and parseable. For effective DB-backed settings, verify read access to default-scope core_config_data. Inspect the exact missing or malformed setting in collection details, then rerun.');
        $input = $resources === [] ? 'the files/directories and declared input scope named in the check details' : implode(', ', $resources);
        return $make('input_collection','scan_operator','Verify read permission, existence and format for '.$input.'. Resolve any size limit or incomplete traversal identified in collection details, then rerun this requirement. Supply the complete declared scope; missing evidence is not a confirmed security defect.');
    }
}
