#!/usr/bin/env python3
"""Separate authoritative families, preserving retired identities. Idempotent migration."""
import json, copy, hashlib
from pathlib import Path
from collections import Counter
P=Path(__file__).resolve().parents[1]/'src/Rules/requirements'
def read(n): return json.loads((P/n).read_text())
def write(n,v): (P/n).write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n')
if (P/'family-separation-manifest.json').exists():
    print('Family separation already applied; no changes.'); raise SystemExit(0)
ledger_snapshot_name='reconciliation-ledger-before-family-separation.json'
ledger_snapshot_bytes=(P/'reconciliation-ledger.json').read_bytes()
(P/ledger_snapshot_name).write_bytes(ledger_snapshot_bytes)
ledger_snapshot={'document':ledger_snapshot_name,'sha256':hashlib.sha256(ledger_snapshot_bytes).hexdigest(),'purpose':'Immutable pre-separation reviewer, limitations and reconciliation history.'}
cat=read('internal-catalog.json'); before=copy.deepcopy(cat); manifest=read('allocation-manifest.json'); profiles=read('internal-profiles.json'); aliases=read('legacy-aliases.json'); groups=read('semantic-consolidations.json')['groups']; alloc={x['id']:x for x in manifest['allocations']}; req={x['id']:x for x in cat['requirements']}
def family(i):
    k=alloc[i]['allocation_key'].split('/')[0]
    return {'baseline':'magebean','basic-deployment':'magebean','asvs':'asvs','pci':'pci'}[k]
original={x['id']:x for g in groups for x in g['original_definitions']}; retired=sorted({i for g in groups for i in g['retired_ids']}); remap={}; next_id=manifest['next_id']
for old in retired:
    new=f'MB-{next_id:04d}'; next_id+=1; remap[old]=new
    a=copy.deepcopy(alloc[old]); a.update(id=new,allocation_key='family-separation/'+a['allocation_key'],revision=1,status='active',verdict='family_separated_source_restoration',restored_from=old); a.pop('redirect_to',None)
    manifest['allocations'].append(a)
for g in groups:
    i=g['canonical_id']; same_magebean=all(family(x['id'])=='magebean' for x in g['original_definitions']); restored=copy.deepcopy(req[i] if same_magebean else original[i]); restored['revision']=req[i]['revision']+1
    restored['criterion_history']=copy.deepcopy(req[i].get('criterion_history',[]))+[{'revision':req[i]['revision'],'criterion':req[i]['criterion'],'reason':'Remove semantic union; restore source family obligation.'}]
    req[i]=restored; alloc[i]['revision']=restored['revision']; alloc[i]['verdict']='family_separated_source_restoration'
for old,new in remap.items():
    r=copy.deepcopy(original[old]); r.update(id=new,revision=1,restored_from=old); req[new]=r
asvs={d['id']:d for d in read('criterion-definitions.json')['definitions']}; pci=read('pci-criterion-definitions.json')['criteria']
for i,r in req.items():
    old=r.get('restored_from',i); f=family(old); r['family']=f
    if f=='asvs':
        d=asvs[old]; r['criterion']=d['criterion']; r['title']=d['title']; r['source_metadata']=copy.deepcopy(d['source_metadata']); ref=d['source_metadata']['reference']; r['introduced_level']=d['source_metadata']['introduced_level']; r['alignments']=[{'standard':'OWASP-ASVS','version':'5.0.0','reference':ref,'relationship':'partial'}]; r['source']={'document':'OWASP ASVS','version':'5.0.0','reference':ref}
    elif f=='pci':
        ref=alloc[old]['allocation_key'].split('/',1)[1]; d=pci[ref]; r['criterion']=d['criterion']; r['title']=d['title']; r['source_metadata']=copy.deepcopy(d['source_metadata']); r['source']={'document':'PCI DSS','version':'4.0.1','reference':ref}; r['alignments']=[{'standard':'PCI-DSS','version':'4.0.1','reference':ref,'relationship':'partial'}]
    else:
        r['alignments']=[]; r.pop('source_metadata',None); r.pop('introduced_level',None); r['source']={'document':'Magebean security requirements','version':'1','reference':alloc[old]['allocation_key']}
    r.pop('control_tags',None)
# Preserve reviewed proof boundaries while removing cross-family source unions.
previous={r['id']:r for r in before['requirements']}
for r in req.values():
    if not r['human_evidence']['required']: continue
    for o in r['obligations']:
        if o.get('proof')=='heuristic' or r['family']=='pci': o['role']='supporting'
    if r['family']=='asvs' and r['id']=='MB-0379':
        reviewed=[copy.deepcopy(o) for o in previous[r['id']]['obligations'] if o.get('proof')=='verified_predicate' and o.get('role')=='mandatory']
        for o in reviewed:
            if not any(x.get('checks')==o.get('checks') for x in r['obligations']):
                o['id']=f"O{len(r['obligations'])+1:03d}"; r['obligations'].append(o)
                for check in o.get('checks',[]):
                    if check not in r['checks']: r['checks'].append(copy.deepcopy(check))
    if r['family'] in ('asvs','pci') or r.get('restored_from'):
        ref=r['source']['reference']
        r['human_evidence']['instructions']=r['criterion']+' Review '+ref+' in the declared assessment scope. Record expected versus observed behavior, dated evidence, relevant configuration or test results, exceptions and reviewer rationale for every condition. Do not attach credentials, secret values, personal data or unredacted payment data. Technical observations are supporting evidence and do not establish full compliance.'

# Existing Magebean profile selections resolve merged IDs only to the original Magebean
# constituents actually selected by that legacy profile, avoiding accidental expansion.
profile_mappings={}
for name,p in profiles['profiles'].items():
    f='asvs' if name.startswith('asvs-') else 'pci' if name.startswith('pci-') else 'magebean'; p['family']=f
    if f=='asvs':
        level=p['assessment_level']; ids=[i for i,r in req.items() if r['family']==f and r['introduced_level']<=level]
    elif f=='pci': ids=[i for i,r in req.items() if r['family']==f]
    else:
        legacydoc=json.loads((P.parent/'profiles'/f'{name}.json').read_text()); legacy=legacydoc.get('rules',[a['allocation_key'].split('/',1)[1] for a in alloc.values() if a['allocation_key'].startswith('baseline/')]); legacy={x if isinstance(x,str) else x['id'] for x in legacy}-set(legacydoc.get('exclude',{}).get('rules',[])); ids=[]
        for i in p['requirement_ids']:
            g=next((g for g in groups if g['canonical_id']==i),None)
            candidates=[x['id'] for x in g['original_definitions'] if family(x['id'])==f and alloc[x['id']]['allocation_key'].split('/',1)[1] in legacy] if g else [i]
            if req[i]['family']==f and i not in candidates: candidates.insert(0,i)
            assert candidates, (name,i,'No same-family replacement')
            for c in candidates:
                n=remap.get(c,c); assert req[n]['family']==f
                if n not in ids: ids.append(n)
    profile_mappings[name]={'before':p['requirement_ids'],'after':ids}; p['requirement_ids']=ids
# Source-specific aliases retain unambiguous ownership. Historical canonical IDs stay
# canonical; profile mappings describe their former union without silently redirecting.
for a,ids in aliases['aliases'].items():
    if a.startswith('MB-R'):
        matches=[x for x in alloc.values() if x['allocation_key']=='baseline/'+a]
        if matches:
            old=matches[0]['id']; aliases['aliases'][a]=[remap.get(old,old) if old!='MB-0068' else 'MB-0049']
    elif a.startswith('OWASP-ASVS:5.0.0:'):
        ref=a.split(':',2)[2]; old=next(i for i,d in asvs.items() if d['source_metadata']['reference']==ref); aliases['aliases'][a]=[remap.get(old,old)]
    elif a.startswith('PCI-DSS:4.0.1:'):
        ref=a.split(':',2)[2]; old=next(i for i,a2 in alloc.items() if a2['allocation_key']=='pci/'+ref); aliases['aliases'][a]=[remap.get(old,old)]
    elif a in remap: aliases['aliases'][a]=[remap[a]]
manifest['next_id']=next_id; cat['requirements']=sorted(req.values(),key=lambda r:r['id']); counts=Counter(r['family'] for r in req.values()); assert counts=={'magebean':104,'asvs':345,'pci':280},counts
for f in counts: write(f+'-catalog.json',dict(schema_version=cat['schema_version'],assessment_model=cat['assessment_model'],family=f,requirements=[r for r in cat['requirements'] if r['family']==f]))
write('internal-catalog.json',cat); write('internal-profiles.json',profiles); write('allocation-manifest.json',manifest); write('legacy-aliases.json',aliases)
ledger=read('reconciliation-ledger.json'); ledger['identities']=[dict(id=r['id'],allocation_key=next(a['allocation_key'] for a in manifest['allocations'] if a['id']==r['id']),revision=r['revision'],criterion=r['criterion'],verdict=r['review_state'],reviewer='family-separation',limitations='Source-family isolation does not establish evidence sufficiency or compliance.',obligation_count=len(r['obligations']),alignments=r['alignments'],family=r['family']) for r in cat['requirements']]; ledger['counts']={'active_internal_requirements':len(req),'historical_allocations':len(manifest['allocations']),'retired_identity_count':sum(a['id'] not in req for a in manifest['allocations']),'families':dict(counts),'asvs_alignment_references':345,'pci_alignment_references':280,'accepted_scoped_criteria':sum(not r['human_evidence']['required'] for r in req.values()),'human_evidence_required':sum(r['human_evidence']['required'] for r in req.values())}; write('reconciliation-ledger.json',ledger)
write('family-separation-manifest.json',{'schema_version':'1.0','previous_reconciliation_ledger':ledger_snapshot,'retired_identity_replacements':remap,'family_counts':dict(counts),'profiles':profile_mappings,'previous_union_members':{g['canonical_id']:{f:[remap.get(x['id'],x['id']) for x in g['original_definitions'] if family(x['id'])==f] for f in ('magebean','asvs','pci')} for g in groups},'identity_policy':'Retired IDs remain retired. Historical canonical IDs retain their original source family. Cross-family historical unions require explicit profile context.'})
print(dict(counts)); print({n:len(p['requirement_ids']) for n,p in profiles['profiles'].items()})



