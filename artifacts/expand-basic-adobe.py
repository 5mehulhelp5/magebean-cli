"""Versioned Basic expansion; preserves independently owned ASVS/PCI definitions."""
import copy
import json
from pathlib import Path

base = Path(__file__).resolve().parents[1] / 'src/Rules/requirements'
if (base/'magebean-automation-backlog.json').exists():
    raise SystemExit('Historical expansion superseded by the automated-only Magebean profile contract; edit current automated definitions/profiles instead.')
def read(name): return json.loads((base / (name + '.json')).read_text())
def write(name, value): (base / (name + '.json')).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')
catalog = read('magebean-catalog')
rules = {r['id']: r for r in catalog['requirements']}
profiles = read('internal-profiles')
allocation = read('allocation-manifest')
ledger = read('reconciliation-ledger')
adobe = 'https://experienceleague.adobe.com/en/docs/commerce-'
admin = adobe + 'admin/systems/security/security-admin'
security = adobe + 'operations/implementation-playbook/best-practices/launch/security-best-practices'

def recipe(name, **args): return {'name': name, 'args': args}
def obligation(checks): return [{'id': 'O001', 'op': 'all', 'role': 'mandatory', 'proof': 'verified_predicate', 'checks': checks}]
def revise(identity, title, criterion, checks=None):
    r = rules[identity]
    if r['criterion'] != criterion:
        r.setdefault('criterion_history', []).append({'revision': r['revision'], 'criterion': r['criterion'], 'reason': 'Basic Adobe best-practices review: explicit observation scope and corrected binding.'})
        r['revision'] += 1
    r.update(title=title, criterion=criterion)
    if checks is not None:
        r.update(checks=checks, obligations=obligation(checks))
    return r

revise('MB-0006', 'Declared Admin route avoids common names', 'The collected backend.frontName is a valid nonempty route other than admin or backend. Route obscurity is not authentication or access control.')
revise('MB-0007', 'Native Admin MFA provider configuration declared', 'For a native Admin authentication deployment, Magento_TwoFactorAuth is declared enabled and resolved twofactorauth/general/force_providers names recognized native engines. Possible Adobe IMS mode, unforced providers or an unsupported provider require additional evidence. An empty force_providers setting does not prove MFA is disabled. This predicate does not prove enrollment, enforcement or absence of bypass.', [recipe('magento_admin_2fa_enabled')])
r = revise('MB-0026', 'Observed storefront entrypoint redirects to HTTPS', 'The observed HTTP storefront root redirects directly with 301/302/303/307/308 to same-host HTTPS. Admin and other store entrypoints are assessed separately.', [recipe('http_force_https_redirect', strict_scope=True, include_admin=False)])
r['execution_variants']['REMOTE']['obligations'] = copy.deepcopy(r['obligations'])
r = rules['MB-0027']
r['execution_variants']['REMOTE']['obligations'] = copy.deepcopy(r['obligations'])
for identity in ['MB-0027','MB-0037']:
    r=rules[identity]
    if r.get('basic_review_version') != 2:
        r.setdefault('criterion_history', []).append({'revision':r['revision'],'criterion':r['criterion'],'reason':'Align mode-specific recipes with the same observed criterion; remove heuristic remote FPC declaration proof.'})
        r['revision']+=1; r['basic_review_version']=2
# A response cache heuristic cannot prove a persisted deployment declaration.
r = rules['MB-0037']; r['target_modes'] = ['LOCAL']; r.pop('execution_variants', None)
revise('MB-0046', 'Installed Magento scheduler observed', 'A collected installed cron:run entry targets this deployment. Missing installed entries remain unresolved when an external/cloud/container scheduler may apply; cadence and execution health are separate observations.', [recipe('installed_magento_cron', allow_external_scheduler=True)])

new = [
 ('MB-0773', 'Admin secret URL keys enabled', 'The resolved default-scope native Admin admin/security/use_form_key configuration is enabled. Authenticated route enforcement requires separate verification.', 'MB-C02', 'medium', 'security', [recipe('magento_admin_security_flag', path='admin/security/use_form_key')], ['LOCAL'], admin),
 ('MB-0774', 'Admin login names are case sensitive', 'The resolved default-scope native Admin admin/security/use_case_sensitive_login configuration is enabled; this is a configuration observation, not an authentication flow test.', 'MB-C02', 'medium', 'security', [recipe('magento_admin_security_flag', path='admin/security/use_case_sensitive_login')], ['LOCAL'], admin),
 ('MB-0775', 'Admin account sharing disabled', 'The resolved default-scope native Admin admin/security/admin_account_sharing configuration is disabled. This does not establish that each person has a unique approved account.', 'MB-C02', 'medium', 'security', [recipe('magento_admin_security_flag', path='admin/security/admin_account_sharing')], ['LOCAL'], admin),
 ('MB-0776', 'Admin password reset protection configured', 'Resolved native Admin reset protection is enabled with bounded hourly requests and a positive cooldown meeting Magebean policy (at most 5 requests/hour and at least 1 minute). This does not exercise reset tokens or email delivery.', 'MB-C02', 'medium', 'security', [recipe('magento_admin_password_reset_protection', max_requests_per_hour=5, min_interval_minutes=1)], ['LOCAL'], admin),
 ('MB-0777', 'Observed Admin entrypoint redirects to HTTPS', 'The explicitly supplied or locally resolved Admin HTTP entrypoint redirects directly to same-host HTTPS. Missing Admin route evidence remains unresolved without preventing the separate storefront probe.', 'MB-C04', 'high', 'security', [recipe('http_force_https_redirect', strict_scope=True, admin_only=True)], ['LOCAL'], security),
 ('MB-0778', 'Observed TLS certificate has trusted hostname and renewal margin', 'The configured endpoint completes a peer-verified TLS connection for its hostname with a currently valid certificate and at least 15 days remaining under Magebean renewal policy. Uncollectable trust or network evidence is unresolved.', 'MB-C04', 'medium', 'security', [recipe('http_tls_cert_days_left', min_days=15, timeout_ms=8000)], ['LOCAL','REMOTE'], security),
 ('MB-0779', 'Observed page restricts framing', 'A successful same-host application response emits an unambiguous enforced restrictive CSP frame-ancestors policy, or valid X-Frame-Options DENY/SAMEORIGIN when no enforced frame-ancestors overrides it. This scopes the observation to the requested page.', 'MB-C04', 'medium', 'security', [recipe('http_clickjacking_protection', strict_scope=True, timeout_ms=8000)], ['LOCAL','REMOTE'], security),
 ('MB-0780', 'Media inventory has no executable PHP-like filenames', 'The bounded readable pub/media filename inventory contains no PHP-like executable extension, including double extensions. Symlinks, unreadable subtrees and budget gaps remain unresolved. Web-server execution policy is separate evidence.', 'MB-C01', 'high', 'security', [recipe('basic_media_executable_files', max_entries=10000)], ['LOCAL'], security),
 ('MB-0781', 'Named sensitive HTTP paths are denied or absent', 'Six named deployment artifact paths are denied or absent over HTTP. A bounded prefix containing a recognizable artifact signature is a violation; ambiguous 200 pages, redirects and transport gaps remain unresolved. No response contents are retained.', 'MB-C01', 'high', 'security', [recipe('basic_sensitive_http_paths', timeout_ms=2000)], ['LOCAL','REMOTE'], security),
 ('MB-0782', 'Sensitive deployment configuration excluded from Git index', 'The readable current deployment Git index does not track app/etc/env.php. Historical commits, remote repositories and deployments without a readable Git index require separate evidence.', 'MB-C01', 'high', 'security', [recipe('env_not_tracked')], ['LOCAL'], adobe+'operations/configuration-guide/deployment/overview'),
 ('MB-0783', 'Installed Magento cron has every-minute cadence', 'The observed installed cron:run schedule has every-minute cadence for the assessed project. External/cloud/container scheduling without a matching installed entry requires separate scheduler evidence; presence alone is insufficient.', 'MB-C07', 'low', 'readiness', [recipe('installed_cron_cadence')], ['LOCAL'], adobe+'operations/configuration-guide/cli/configure-cron-jobs'),
 ('MB-0784', 'Published theme and locale static scopes have representative assets', 'The bounded observed published frontend theme/locale scopes contain representative readable nonempty CSS and JavaScript artifacts. Explicit intended scopes may refine this observation. Active-store coverage, asset freshness and headless deployment applicability require separate evidence.', 'MB-C05', 'low', 'readiness', [recipe('static_scopes_ready')], ['LOCAL'], adobe+'operations/configuration-guide/cli/static-view/static-view-file-deployment'),
 ('MB-0785', 'Magento cron execution has recent success and bounded backlog', 'The read-only bounded cron_schedule observation contains recent successful execution within 24 hours and no overdue pending jobs beyond 15 minutes under Magebean readiness policy. The reported collection window is explicit; job-group completeness and external schedulers require separate evidence.', 'MB-C07', 'low', 'readiness', [recipe('cron_health', recent_hours=24, overdue_minutes=15)], ['LOCAL'], adobe+'operations/configuration-guide/cli/configure-cron-jobs'),
]
for identity, title, criterion, control, severity, lane, checks, modes, source in new:
    if identity in rules:
        # Re-running the expansion retains allocated identity and aligns its reviewed text.
        rules[identity]['criterion']=criterion
        continue
    assert int(identity[3:]) == allocation['next_id'], 'Never reuse or skip allocated identities'
    ref='magebean/basic-adobe/'+identity
    r = dict(id=identity, revision=1, title=title, criterion=criterion, control=control, severity=severity, alignments=[], obligations=obligation(checks), coverage='AUTOMATED', verification='automated', review_state='accepted_scoped_criterion', human_evidence={'required':False,'instructions':'','evidence_types':['scoped_observation']}, target_modes=modes, checks=checks, op='all', family='magebean', source={'document':'Magebean security requirements','version':'1','reference':ref}, lane=lane, guidance_sources=[source])
    rules[identity]=r; catalog['requirements'].append(r)
    allocation['allocations'].append({'id':identity,'allocation_key':ref,'revision':1,'verdict':r['review_state']})
    allocation['next_id'] += 1

basic=profiles['profiles']['basic']
basic['requirement_ids']=list(dict.fromkeys(basic['requirement_ids']+['MB-0009','MB-0027','MB-0042','MB-0100']+[r[0] for r in new]))
basic['revision']=2
basic['description']='Magebean checks informed by Adobe guidance, separated into security, readiness and external evidence. Observations are scoped; this is not Adobe compliance certification.'
basic['evidence_tasks']=[
 {'id':'basic-auth-enforcement','title':'Admin authentication and least privilege','evidence_needed':['Identify native authentication versus Adobe IMS and retain provider/MFA policy evidence.','Verify administrator enrollment, bypass resistance, unique accounts and approved least-privilege roles.','Confirm authenticated Admin session expiry and protections at the actual Admin origin.'],'applicability':'All Admin deployments; native settings may not apply to IMS.'},
 {'id':'basic-runtime-boundary','title':'Web runtime permissions and effective document root','evidence_needed':['Confirm the effective web document root is pub, or document an equivalent reviewed boundary.','Demonstrate that the actual PHP/web identity cannot write production code, including ACLs and mounts.','Verify media execution denial and sensitive configuration locks/precedence.'],'applicability':'Local or hosted Magento deployments; deployment-owner write access is not runtime access.'},
 {'id':'basic-edge-access','title':'WAF, Admin access restrictions and SSH MFA','evidence_needed':['Retain WAF policy and monitoring evidence for the chosen hosting architecture.','Review Admin network access controls and SSH MFA or equivalent controlled administrative access.'],'applicability':'Hosting/access model dependent; Fastly or Adobe Cloud is not mandatory.'},
 {'id':'basic-monitoring','title':'Scheduled security scanning and notification ownership','evidence_needed':['Provide an Adobe Security Scan or equivalent schedule, recent results and remediation owner.','Verify notification routing and follow-up on findings.'],'applicability':'Public and operational deployments; scanner access must match scope.'},
 {'id':'basic-recovery','title':'Backups and tested restore','evidence_needed':['Retain backup schedule, retention/access controls and a recent successful restore exercise.'],'applicability':'Production data and recovery architecture.'},
 {'id':'basic-deployment-coverage','title':'Store, cache, static and scheduler runtime coverage','evidence_needed':['Confirm all active store and Admin origins use valid TLS and secure policies.','Match active themes/locales to deployed artifacts or document headless delivery.','Verify actual cache behavior and external/cloud/container scheduler execution, job groups and old failed/missed jobs.','Review effective runtime mode, worker/store debug overrides and lock precedence.'],'applicability':'Production readiness; bounded CLI observations do not establish complete runtime coverage.'},
]
readiness={'MB-0031','MB-0035','MB-0037','MB-0046'}
for identity in basic['requirement_ids']:
    r=rules[identity]; r.setdefault('lane','readiness' if identity in readiness else 'security')
    r.setdefault('guidance_sources',[security])
    r['policy_source']={'owner':'Magebean','version':'basic-2','note':'Numeric thresholds are Magebean policy; Adobe guidance informs topics and applicability.'}

active = {r['id']:r for r in catalog['requirements']}
for entry in allocation['allocations']:
    if entry['id'] in basic['requirement_ids']:
        entry['revision']=active[entry['id']]['revision']; entry['verdict']=active[entry['id']]['review_state']
identities={e['id']:e for e in ledger['identities']}
for identity in basic['requirement_ids']:
    r=rules[identity]; a=next(e for e in allocation['allocations'] if e['id']==identity)
    identities[identity]=dict(id=identity, allocation_key=a['allocation_key'], revision=r['revision'], criterion=r['criterion'], verdict=r['review_state'], reviewer='basic-adobe-review', limitations='Scoped technical observation; external evidence checklist remains unassessed.', obligation_count=len(r['obligations']), alignments=[], family='magebean')
ledger['identities']=list(identities.values())
aggregate=read('internal-catalog')
aggregate['requirements']=sorted(catalog['requirements']+read('asvs-catalog')['requirements']+read('pci-catalog')['requirements'], key=lambda r:int(r['id'][3:]))
ledger['counts'].update(active_internal_requirements=len(aggregate['requirements']), historical_allocations=len(allocation['allocations']), families={'magebean':len(catalog['requirements']),'asvs':345,'pci':280}, accepted_scoped_criteria=sum(not r['human_evidence']['required'] for r in aggregate['requirements']), human_evidence_required=sum(r['human_evidence']['required'] for r in aggregate['requirements']))
for name,value in [('magebean-catalog',catalog),('internal-catalog',aggregate),('internal-profiles',profiles),('allocation-manifest',allocation),('reconciliation-ledger',ledger)]: write(name,value)
print('Basic',len(basic['requirement_ids']),'Magebean',len(catalog['requirements']),'Total',len(aggregate['requirements']))
