"""Hardening includes Basic and OWASP by native identity, without merging standards."""
import json
from pathlib import Path
base=Path(__file__).resolve().parents[1]/'src/Rules'
if (base/'requirements/magebean-automation-backlog.json').exists():
 raise SystemExit('Historical expansion superseded by the automated-only Magebean profile contract; use magebean-automated-profiles.py and review current automated coverage.')
path=base/'requirements/internal-profiles.json'
data=json.loads(path.read_text()); profiles=data['profiles']; h=profiles['hardening']
h['requirement_ids']=list(dict.fromkeys(h['requirement_ids']+profiles['basic']['requirement_ids']+profiles['owasp-top-10-2025']['requirement_ids']))
h['revision']=2
h['coverage_includes']=['basic','owasp-top-10-2025']
h['show_unassessed_requirements']=True
h['evidence_tasks']=profiles['basic']['evidence_tasks']
h['description']='Production security assessment covering all Magebean Basic and OWASP Top 10 profile requirements plus deeper production hardening. Separates security, readiness and external evidence; human-required controls remain explicit and need independent review. Payment-specific scope and formal ASVS/PCI assessments are separate. A clean technical scan does not establish complete production protection.'
path.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n')
catalog_path=base/'requirements/magebean-catalog.json'; catalog=json.loads(catalog_path.read_text())
readiness={'MB-0031','MB-0034','MB-0035','MB-0037','MB-0038','MB-0039','MB-0043','MB-0046','MB-0047','MB-0048','MB-0783','MB-0784','MB-0785'}
for r in catalog['requirements']:
 if r['id'] in h['requirement_ids']: r['lane']='readiness' if r['id'] in readiness else 'security'
catalog_path.write_text(json.dumps(catalog,indent=2,ensure_ascii=False)+'\n')
aggregate_path=base/'requirements/internal-catalog.json'; aggregate=json.loads(aggregate_path.read_text()); index={r['id']:r for r in catalog['requirements']}
aggregate['requirements']=[index.get(r['id'],r) for r in aggregate['requirements']]; aggregate_path.write_text(json.dumps(aggregate,indent=2,ensure_ascii=False)+'\n')
compat=base/'profiles/hardening.json'; old=compat.read_text(); legacy=json.loads(old)
old=old.replace(json.dumps(legacy['description']),json.dumps(h['description']),1);compat.write_text(old)
print('Hardening:',len(h['requirement_ids']),'requirements;',len(h['evidence_tasks']),'external evidence groups')
