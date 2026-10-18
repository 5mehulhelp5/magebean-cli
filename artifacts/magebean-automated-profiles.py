"""Keep human-dependent criteria in a tracked backlog, never promote weak checks to PASS."""
import json
from pathlib import Path
base=Path(__file__).resolve().parents[1]/'src/Rules'
path=base/'requirements/internal-profiles.json'; data=json.loads(path.read_text()); profiles=data['profiles']
rules={r['id']:r for r in json.loads((base/'requirements/magebean-catalog.json').read_text())['requirements']}
def human(r):
 return r.get('verification')=='manual' or r.get('human_evidence',{}).get('required',False) or any(o.get('role')!='supporting' and o.get('proof')=='human' for o in r['obligations'])
backlog_path=base/'requirements/magebean-automation-backlog.json'
backlog=json.loads(backlog_path.read_text()) if backlog_path.exists() else {'schema_version':1,'purpose':'Internal automation engineering backlog; not an executable assessment profile. Original criteria, identities and historical results are preserved.','requirements':[], 'removed_external_tasks':{}}
entries={r['id']:r for r in backlog['requirements']}
for name in ['basic','hardening','owasp-top-10-2025']:
 p=profiles[name]
 for identity in p['requirement_ids']:
  if human(rules[identity]):
   entry=entries.setdefault(identity,{'id':identity,'title':rules[identity]['title'],'criterion':rules[identity]['criterion'],'previous_profiles':[],'status':'AUTOMATION_DESIGN_REQUIRED','reason':'Independent evidence or heuristic supporting checks cannot establish the current criterion automatically.'})
   if name not in entry['previous_profiles']:entry['previous_profiles'].append(name)
 p['requirement_ids']=[i for i in p['requirement_ids'] if not human(rules[i])]
 if p.get('evidence_tasks'):backlog['removed_external_tasks'][name]=p['evidence_tasks']
 p.pop('evidence_tasks',None);p.pop('show_unassessed_requirements',None)
 p['automation_only']=True;p['automation_contract_version']=1
 p['revision']=3 if name in ['basic','hardening'] else 2
 p['description']={
  'basic':'Automated Magebean checks informed by Adobe guidance for Magento production security and operational readiness. Reports verified observations and collection errors within the available deployment scope. Contains no human-evidence requirements or manual checklist.',
  'hardening':'Automated production hardening covering every Basic and Magebean OWASP automated requirement plus deeper technical checks. Reports security and readiness observations; unavailable data is an execution gap, never a manual task or implicit PASS. Does not claim complete production protection or ASVS/PCI compliance.',
  'owasp-top-10-2025':'Automated Magebean technical checks organized around OWASP Top 10 2025 risk categories for Magento. Contains no human-evidence requirements; reports only the verified scope and collection gaps. Does not claim complete OWASP coverage, ASVS compliance or a penetration test.',
 }[name]
 compat=base/'profiles'/(name+'.json');text=compat.read_text();old=json.loads(text);text=text.replace(json.dumps(old['description']),json.dumps(p['description']),1);compat.write_text(text)
backlog['requirements']=list(entries.values());backlog_path.write_text(json.dumps(backlog,indent=2,ensure_ascii=False)+'\n')
path.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n')
for name in ['basic','hardening','owasp-top-10-2025']:print(name,len(profiles[name]['requirement_ids']),'automated requirements; no human evidence')
print('Automation backlog:',len(entries),'preserved criteria')
