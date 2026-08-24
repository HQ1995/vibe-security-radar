#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, re, subprocess
ROOT=Path('/home/hanqing/agents/ai-slop')
OWN=ROOT/'autoresearch/herdr-260814-nextqueue-v2-grok46-low'
res=json.loads((OWN/'result.json').read_text())
pins=res['current_input_hashes']

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical91/ledger.jsonl')==pins['canonical91_ledger.jsonl']
assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json')==pins['canonical91_summary.json']
assert h(ROOT/'autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md')==pins['CONTRACT.md']
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==['assignment.jsonl','cases.jsonl','replay.zsh','report.md','result.json'], names
assert not (OWN/'work').exists()
a=[json.loads(l) for l in (OWN/'assignment.jsonl').read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/'cases.jsonl').read_text().splitlines() if l.strip()]
assert len(a)==len(c)==20
ids=[x['case_id'] for x in a]
assert ids==[x['case_id'] for x in c]==res['queued_ids']
assert len(set(ids))==20
assert all(x.get('never_pass') and x.get('routing_only') for x in a+c)
assert all(x.get('verdict')=='UNREVIEWED' for x in c)
assert all(x.get('proposed_pass') is False for x in c)
assert res['counts']['PASS']==0 and res['pass_proposals']==[]
assert res['canonical91_strict_count']==91
assert res['conservation']['holds'] and res['conservation']['equation']=='20=0+20'
canon=set(str(x).upper() for x in json.loads((ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json').read_text())['strict_released_case_ids'])
assert not set(ids)&canon
text=(OWN/'report.md').read_text()
assert 'does not call a PASS' in text
assert 'does not infer causality' in text
for p in OWN.iterdir():
    if p.is_file():
        assert all(b<128 for b in p.read_bytes()), p
ADV=Path('/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database')
got=subprocess.check_output(['git','-C',str(ADV),'rev-parse','HEAD'],text=True).strip()
assert got==res['advisory_database']['head'], (got, res['advisory_database']['head'])
tree=subprocess.check_output(['git','-C',str(ADV),'rev-parse','HEAD:advisories/github-reviewed'],text=True).strip()
assert tree==res['advisory_database']['github_reviewed_tree']
commit_re=re.compile(r'https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})')
for row in a:
    owner,name=row['repository'].split('/')
    ghsa=row['case_id']
    fname='GHSA-'+ghsa[5:].lower()+'.json'
    matches=list((ADV/'advisories/github-reviewed').rglob(fname))
    assert matches, (ghsa, fname)
    data=json.loads(matches[0].read_text())
    shas=set()
    for ref in data.get('references') or []:
        u=ref.get('url') if isinstance(ref, dict) else ref
        if not isinstance(u,str):
            continue
        m=commit_re.search(u)
        if m and m.group(1).lower()==owner.lower() and m.group(2).lower()==name.lower():
            shas.add(m.group(3).lower())
    assert set(row['same_repo_fixes'])<=shas, (row['case_id'], row['same_repo_fixes'], shas)
    assert row['pre_fix_ai_candidates']
print('REPLAY_OK queued=20 PASS=0 canonical91=91 universe=%s' % res['counts']['reviewed_identities'])
PY
