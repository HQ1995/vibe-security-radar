#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, os, re, subprocess

ROOT=Path('/home/hanqing/agents/ai-slop')
OWN=ROOT/'autoresearch/herdr-260814-recover-no-local-clone5-grok46-high'
SRC=ROOT/'autoresearch/herdr-260814-nextqueue-v2-grok46-low'
res=json.loads((OWN/'result.json').read_text())
pins=res['current_input_hashes']

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT/'autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md')==pins['CONTRACT.md']
assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl')==pins['canonical94_ledger.jsonl']
assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json')==pins['canonical94_summary.json']
assert h(SRC/'result.json')==pins['source_result.json']
assert h(SRC/'report.md')==pins['source_report.md']
assert h(SRC/'replay.zsh')==pins['source_replay.zsh']
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==['assignment.jsonl','cases.jsonl','replay.zsh','report.md','result.json'], names
assert not (OWN/'work').exists()
for p in OWN.iterdir():
    if p.is_file():
        assert all(b<128 for b in p.read_bytes()), p.name

want=['GHSA-5WXR-W449-57CM','GHSA-F5GC-QXF8-MH9G','GHSA-2FMJ-P74R-3WJM','GHSA-5G9F-CWWG-4P8G','GHSA-X8G9-H984-PC36']
a=[json.loads(l) for l in (OWN/'assignment.jsonl').read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/'cases.jsonl').read_text().splitlines() if l.strip()]
assert [x['case_id'] for x in a]==[x['case_id'] for x in c]==want==res['assigned_ids']
assert len(set(want))==5
assert all(x['verdict']=='REJECT' for x in c)
assert all(x['proposed_pass'] is False and x['countable_pass'] is False for x in c)
assert all(x['gates']['ai_hunk_gate']=='FAIL' for x in c)
assert all(x['gates']['identity_gate']=='PASS' for x in c)
assert all(x['gates'][g] in ('PASS','FAIL') for x in c for g in res['seven_gates'])
assert res['counts']['PASS']==0 and res['pass_proposals']==[]
assert res['conservation']['equation']=='5=5+0' and res['conservation']['holds']
assert res['canonical94_strict_count']==94
assert res['bucket_reconstruction']['pinned_source_count']==5
assert res['bucket_reconstruction']['reconstructed_count']==5
assert json.loads((SRC/'result.json').read_text())['buckets']['no_local_clone']==5
canon=set(str(x).upper() for x in json.loads((ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json').read_text())['strict_released_case_ids'])
assert len(canon)==94
assert not set(want)&canon
text=(OWN/'report.md').read_text()
assert 'PASS=0' in text and '5=5+0' in text
assert 'Worker PASS is proposal-only' in text
assert 'did not pad' in text.lower()

ADV=Path('/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database')
env=os.environ.copy()
env['GIT_OPTIONAL_LOCKS']='0'
env['GIT_TERMINAL_PROMPT']='0'
env['GIT_NO_LAZY_FETCH']='1'

def git_out(repo,*args):
    p=subprocess.run(['git','-C',str(repo),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,check=True)
    err=p.stderr.decode()
    keep=[]
    for line in err.splitlines():
        if 'unable to normalize alternate object path' in line: continue
        if 'lazy fetching disabled' in line: continue
        if line.strip():
            keep.append(line)
    if keep:
        raise SystemExit('git stderr: '+'\n'.join(keep))
    return p.stdout.decode().strip()

assert git_out(ADV,'rev-parse','HEAD')==res['advisory_database']['head']
assert git_out(ADV,'rev-parse','HEAD:advisories/github-reviewed')==res['advisory_database']['github_reviewed_tree']
paths={
 'GHSA-5WXR-W449-57CM':'advisories/github-reviewed/2026/05/GHSA-5wxr-w449-57cm/GHSA-5wxr-w449-57cm.json',
 'GHSA-F5GC-QXF8-MH9G':'advisories/github-reviewed/2026/06/GHSA-f5gc-qxf8-mh9g/GHSA-f5gc-qxf8-mh9g.json',
 'GHSA-2FMJ-P74R-3WJM':'advisories/github-reviewed/2026/06/GHSA-2fmj-p74r-3wjm/GHSA-2fmj-p74r-3wjm.json',
 'GHSA-5G9F-CWWG-4P8G':'advisories/github-reviewed/2026/06/GHSA-5g9f-cwwg-4p8g/GHSA-5g9f-cwwg-4p8g.json',
 'GHSA-X8G9-H984-PC36':'advisories/github-reviewed/2026/06/GHSA-x8g9-h984-pc36/GHSA-x8g9-h984-pc36.json',
}
commit_re=re.compile(r'https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})')
for cid,rel in paths.items():
    got=h(ADV/rel)
    assert got==res['first_party_advisory_sha256'][cid], (cid,got)
    data=json.loads((ADV/rel).read_text())
    assert not data.get('withdrawn')
    shas=set()
    for ref in data.get('references') or []:
        u=ref.get('url') if isinstance(ref, dict) else ref
        if isinstance(u,str):
            m=commit_re.search(u)
            if m:
                shas.add(m.group(3).lower())
    row=next(x for x in c if x['case_id']==cid)
    assert set(row['minimum_fix_set'])<=shas, (cid, row['minimum_fix_set'], shas)
po=res['pinned_objects']
assert po['phpweasy_fix_f5gc'] in (ADV/paths['GHSA-F5GC-QXF8-MH9G']).read_text()
assert po['setupphp_fix'] in (ADV/paths['GHSA-5WXR-W449-57CM']).read_text()
print('REPLAY_OK assigned=5 reviewed=5 unreviewed=0 PASS=0 canonical94=94 equation=5=5+0 bucket=5')
PY
