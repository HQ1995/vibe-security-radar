#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat GIT_ASKPASS= GCM_INTERACTIVE=never
export GIT_CONFIG_NOSYSTEM=1 HOME=/tmp XDG_CONFIG_HOME=/tmp LC_ALL=C LANG=C
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, os, re, shutil, subprocess, sys, tempfile

ROOT=Path('/home/hanqing/agents/ai-slop')
OWN=ROOT/'autoresearch/herdr-260814-gn-heavy-deferred-grok46-xhigh'
GN=ROOT/'autoresearch/herdr-260813-ghsa200-commitfirst-gn'
CAN=ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94'
ADV=Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database')
AR=ROOT/'autoresearch'
HEAVY=('n8n-io/n8n','go-gitea/gitea','jdx/mise','MervinPraison/PraisonAI','gogs/gogs')
SKIP=('/work/','/notes/','/pages/','/snapshot/','/clones/','/cache/','/tmp/')
GHSA=re.compile(r'^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$')
TV={'PASS','PASS_PROPOSAL','REJECT','FALSE_POSITIVE','NARROW','UNKNOWN','BLOCKED','FAIL','CONFIRM','HOLD_REJECT','WRONG_EDGE'}
sys.path.insert(0, str(ROOT/'cve-analyzer/src'))
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit

ENV={
 'PATH':'/usr/local/bin:/usr/bin:/bin','GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0',
 'GIT_NO_LAZY_FETCH':'1','GIT_PAGER':'cat','GIT_ASKPASS':'','GCM_INTERACTIVE':'never',
 'GIT_CONFIG_NOSYSTEM':'1','HOME':'/tmp','XDG_CONFIG_HOME':'/tmp','LC_ALL':'C','LANG':'C',
}

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

res=json.loads((OWN/'result.json').read_text())
pins=res['current_input_hashes']
assert h(ROOT/'autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md')==pins['CONTRACT.md']
assert h(CAN/'ledger.jsonl')==pins['canonical94_ledger.jsonl']
assert h(CAN/'summary.json')==pins['canonical94_summary.json']
assert h(GN/'cases.jsonl')==pins['gn_cases.jsonl']
assert h(GN/'result.json')==pins['gn_result.json']
assert h(GN/'ai-ghsa-intersections.jsonl')==pins['gn_intersections.jsonl']
assert h(GN/'assigned.jsonl')==pins['gn_assigned.jsonl']
assert h(GN/'ai-commit-scans.jsonl')==pins['gn_scans.jsonl']
assert h(GN/'gn-excluded.jsonl')==pins['gn_excluded.jsonl']
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==['assignment.jsonl','cases.jsonl','replay.zsh','report.md','result.json'], names
assert not (OWN/'work').exists()
for p in OWN.iterdir():
    if p.is_file():
        b=p.read_bytes()
        assert b'\x00' not in b
        b.decode('ascii')
want=['GHSA-38C7-23HJ-2WGQ','GHSA-49MX-FJ45-Q3P6','GHSA-5VJ6-WJR7-5V9F','GHSA-825Q-W924-XHGX','GHSA-9GM9-C8MQ-VQ7M','GHSA-F3F2-MCXC-PWJX','GHSA-FVFV-PPW4-7H2W','GHSA-GGJM-F3G4-RWMM','GHSA-GQ57-V332-7666','GHSA-HFMV-HHH3-43F2','GHSA-JF52-3F2H-H9J5','GHSA-PR9R-GXGP-9RM8']
a=[json.loads(l) for l in (OWN/'assignment.jsonl').read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/'cases.jsonl').read_text().splitlines() if l.strip()]
assert [x['case_id'] for x in a]==[x['case_id'] for x in c]==want==res['assigned_ids']
assert all(x['verdict']=='REJECT' for x in c)
assert all(x['proposed_pass'] is False and x['countable_pass'] is False for x in c)
assert all(x['gates']['ai_hunk_gate']=='FAIL' for x in c)
assert all(x['gates']['identity_gate']=='PASS' for x in c)
assert res['counts']['PASS']==0 and res['pass_proposals']==[]
assert res['conservation']['equation']=='228=12+216' and res['conservation']['holds']
assert res['canonical94_strict_count']==94
assert MATCHER_CONTRACT==res['matcher_contract']
canon=set(str(x).upper() for x in json.loads((CAN/'summary.json').read_text())['strict_released_case_ids'])
assert not set(want)&canon

def load_jsonl(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]

def add(dst, x):
    if not x: return
    u=str(x).upper()
    if GHSA.match(u): dst.add(u)

post=set()
for d in sorted(AR.iterdir()):
    if not d.is_dir(): continue
    n=d.name
    if n=='herdr-260814-gn-heavy-deferred-grok46-xhigh': continue
    if not (n.startswith('herdr-260813') or n.startswith('herdr-260814') or n.startswith('orchestrator-260813') or n.startswith('orchestrator-260814')):
        continue
    for p in d.rglob('cases.jsonl'):
        rel='/'+str(p.relative_to(d)).replace('\\','/')
        if any(s in rel for s in SKIP): continue
        for r in load_jsonl(p):
            verd=str(r.get('verdict') or r.get('worker_verdict') or r.get('terminal_verdict') or r.get('disposition') or '').upper()
            if verd in TV:
                add(post, r.get('case_id') or r.get('ghsa_id'))
src=set(); 
for r in load_jsonl(GN/'cases.jsonl'): add(src, r.get('case_id'))
cf2=set();
for r in load_jsonl(AR/'herdr-260814-cf2-gn-copy-blame-grok46-high/assignment.jsonl'): add(cf2, r.get('case_id'))
ix=load_jsonl(GN/'ai-ghsa-intersections.jsonl')
assigned={r['ghsa_id'].upper(): r for r in load_jsonl(GN/'assigned.jsonl')}
so=[r for r in ix if r.get('subject_overlap_hits') and not r.get('matched_ai_commit_refs')]
heavy=[r for r in so if r['repository'] in HEAVY]
excl=canon|src|cf2|post
remaining=[]
for r in heavy:
    gid=r['ghsa_id'].upper()
    if gid in excl: continue
    remaining.append(gid)
remaining.sort()
assert len(heavy)==294
assert len(remaining)==228
assert sha256(('\n'.join(remaining)+'\n').encode()).hexdigest()==res['remaining_ids_sha256']
assert [e for e in res['excluded_heavy_terminal_ids']]==sorted(set(res['excluded_heavy_terminal_ids']))
assert set(res['excluded_heavy_terminal_ids']).issubset(excl)
assert set(want).isdisjoint(set(res['excluded_heavy_terminal_ids']))

# rank: among remaining, local atomic closer first then case_id; cap 12
scans={s['repository']: s for s in load_jsonl(GN/'ai-commit-scans.jsonl')}

def git(repo,*args,timeout=12):
    p=subprocess.run(['git','-C',str(repo),*args],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    return p.returncode, p.stdout.decode().strip()

closer_ok=[]
for gid in remaining:
    a=assigned.get(gid) or {}
    repo=a.get('repository')
    clone=(scans.get(repo) or {}).get('path')
    refs=list(a.get('commit_refs') or [])[:2]
    ok=False
    if clone and Path(clone).is_dir():
        for ref in refs:
            rc,sha=git(clone,'rev-parse','--verify',ref+'^{commit}')
            if rc!=0:
                continue
            rc2,parts=git(clone,'rev-list','--parents','-n','1',sha)
            n=max(len(parts.split())-1,0) if rc2==0 else 0
            if n==1:
                ok=True
                break
    if ok:
        closer_ok.append(gid)
closer_ok.sort()
assert closer_ok[:12]==want
assert closer_ok[12:]==res['tied_closer_not_in_cap12']

# objects/parents/trees on shared clones
for cid,po in res['pinned_objects'].items():
    rec=next(x for x in c if x['case_id']==cid)
    clone=res['read_only_clones'][rec['repository']]
    rc,got=git(clone,'rev-parse',po['closer'])
    assert rc==0 and got==po['closer']
    rc,got=git(clone,'rev-parse',po['parent'])
    assert rc==0 and got==po['parent']
    rc,got=git(clone,'rev-parse',po['closer']+'^{tree}')
    assert rc==0 and got==po['closer_tree']
    rc,got=git(clone,'rev-parse',po['parent']+'^{tree}')
    assert rc==0 and got==po['parent_tree']
    rc,parts=git(clone,'rev-list','--parents','-n','1',po['closer'])
    assert parts.split()==[po['closer'], po['parent']]
    # matcher on closer
    rc,raw=git(clone,'log','-1','--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%aI%x00%B',po['closer'])
    parts=raw.split('\0')
    ci=CommitInfo(sha=parts[0],author_name=parts[1],author_email=parts[2],committer_name=parts[3],committer_email=parts[4],authored_date=parts[5],message=parts[6])
    assert matches_for_commit(ci)==()
    # advisory hash
    assert h(ADV/po['advisory_path'])==po['advisory_sha256']==res['first_party_advisory_sha256'][cid]

# anonymous blob fetch for semantic hashes
def fetch_and_check(url, po):
    tmp=tempfile.mkdtemp(prefix='gn-heavy-replay-')
    try:
        subprocess.run(['git','-c','credential.helper=','-c','init.defaultBranch=main','init','-q','--bare',tmp],env=ENV,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for sha in (po['closer'], po['parent']):
            p=subprocess.run(['git','--git-dir='+tmp,'-c','credential.helper=','fetch','--quiet','--no-tags','--depth=2',url,sha],env=ENV,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=90)
            if p.returncode!=0:
                p=subprocess.run(['git','--git-dir='+tmp,'-c','credential.helper=','fetch','--quiet','--no-tags','--depth=1',url,sha],env=ENV,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=90)
                assert p.returncode==0, p.stderr.decode()[:200]
        for path,blobs in (po.get('blobs') or {}).items():
            if blobs.get('fixed'):
                p=subprocess.run(['git','--git-dir='+tmp,'rev-parse',po['closer']+':'+path],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
                assert p.returncode==0 and p.stdout.decode().strip()==blobs['fixed'], path
            if blobs.get('parent'):
                p=subprocess.run(['git','--git-dir='+tmp,'rev-parse',po['parent']+':'+path],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
                assert p.returncode==0 and p.stdout.decode().strip()==blobs['parent'], path
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

for cid,po in res['pinned_objects'].items():
    rec=next(x for x in c if x['case_id']==cid)
    fetch_and_check('https://github.com/'+rec['repository']+'.git', po)

text=(OWN/'report.md').read_text()
assert 'PASS=0' in text and '228=12+216' in text
assert 'Worker PASS is proposal-only' in text
print('REPLAY_OK assigned=12 reviewed=12 unreviewed=216 PASS=0 canonical94=94 equation=228=12+216')
PY
