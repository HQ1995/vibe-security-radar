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
OWN=ROOT/'autoresearch/herdr-260814-recover-fix-missing-ranks25-32-grok46-low'
PRIOR=ROOT/'autoresearch/herdr-260814-recover-fix-missing-ranks17-24-grok46-low'
SRC=ROOT/'autoresearch/herdr-260814-nextqueue-v2-grok46-low'
res=json.loads((OWN/'result.json').read_text())
pins=res['current_input_hashes']

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT/'autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md')==pins['CONTRACT.md']
assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl')==pins['canonical94_ledger.jsonl']
assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json')==pins['canonical94_summary.json']
assert h(SRC/'result.json')==pins['source_result.json']
assert h(SRC/'replay.zsh')==pins['source_replay.zsh']
assert h(PRIOR/'result.json')==pins['prior_reconstruction_result.json']
assert h(PRIOR/'replay.zsh')==pins['prior_reconstruction_replay.zsh']
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==['assignment.jsonl','cases.jsonl','replay.zsh','report.md','result.json'], names
assert not (OWN/'work').exists()
assert not (OWN/'_tmp_clones').exists()
for p in OWN.iterdir():
    if p.is_file():
        assert all(b<128 for b in p.read_bytes()), p.name
arts=res['artifact_hashes']
for name in ['assignment.jsonl','cases.jsonl','replay.zsh','report.md']:
    assert h(OWN/name)==arts[name], name

a=[json.loads(l) for l in (OWN/'assignment.jsonl').read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/'cases.jsonl').read_text().splitlines() if l.strip()]
want=res['assigned_ids']
assert want==[
 'GHSA-HJ5C-MHH2-G7JQ','GHSA-J99G-7RQW-Q9JG','GHSA-MW3Q-R9WH-H2FF','GHSA-PF4J-PF3W-95F9',
 'GHSA-PM4M-PH32-GHV5','GHSA-PPPJ-HQ3G-57PJ','GHSA-Q49M-57VM-C8CC','GHSA-QRPW-GJVH-X5GM']
assert [x['case_id'] for x in a]==[x['case_id'] for x in c]==want
assert [x['assigned_order'] for x in a]==[x['bucket_rank'] for x in a]==list(range(25,33))
assert len(set(want))==8
first8=res['ranks_1_8_owned_elsewhere']
next8=res['ranks_9_16_owned_elsewhere']
mid8=res['ranks_17_24_owned_elsewhere']
assert len(first8)==8 and len(next8)==8 and len(mid8)==8
assert set(first8).isdisjoint(set(want)) and set(next8).isdisjoint(set(want)) and set(mid8).isdisjoint(set(want))
assert set(first8).isdisjoint(set(next8)) and set(first8).isdisjoint(set(mid8)) and set(next8).isdisjoint(set(mid8))
missing=res['reconstructed_fix_object_missing_ids']
assert len(missing)==38==res['counts']['fix_object_missing_reconstructed']
assert missing==sorted(missing)
assert first8==missing[:8]
assert next8==missing[8:16]
assert mid8==missing[16:24]
assert want==missing[24:32]
src=json.loads((SRC/'result.json').read_text())
assert src['buckets']['fix_object_missing']==38
prior=json.loads((PRIOR/'result.json').read_text())
assert prior['reconstructed_fix_object_missing_ids']==missing
queue=set(src['queued_ids'])|set(src['leftover_ids'])
canon=set(str(x).upper() for x in json.loads((ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json').read_text())['strict_released_case_ids'])
assert len(canon)==94==res['canonical94_strict_count']
assert not set(want)&canon
assert not set(want)&queue
assert not set(missing)&queue
assert not set(missing)&canon
assert all(x['verdict']=='REJECT' for x in c)
assert all(x['proposed_pass'] is False and x['countable_pass'] is False for x in c)
assert all(x['gates']['ai_hunk_gate']=='FAIL' for x in c)
assert all(x['gates']['identity_gate']=='PASS' for x in c)
assert all(x['gates']['uniqueness_gate']=='PASS' for x in c)
assert all(x['gates']['release_gate']=='UNKNOWN' for x in c)
assert all(x['fixed_release_evidence'] is None and x['vulnerable_release_evidence'] is None for x in c)
assert all(x['ai_marker_evidence']==[] and x['pre_fix_ai_candidates']==[] for x in c)
assert c[6]['gates']['topology_gate']=='FAIL' and c[6]['parent_count']==2
assert all((i==6) or x['gates']['topology_gate']=='PASS' for i,x in enumerate(c))
parents={x['case_id']:x['candidate_parent'] for x in c}
assert parents['GHSA-HJ5C-MHH2-G7JQ']=='e836555032f64b035233f441a2f320f892b95882'
assert parents['GHSA-J99G-7RQW-Q9JG']=='28d1bce5e7786537cb102e343b7517019b6d906d'
assert parents['GHSA-MW3Q-R9WH-H2FF']=='64d89e1e89785995aeaaccc819fbbf926b4c47d1'
assert parents['GHSA-PF4J-PF3W-95F9']=='5a405ffe69a457dadac5ba923521c13301cbd764'
assert parents['GHSA-PM4M-PH32-GHV5']=='bd7ebb2b7818873407c942c6371504e427c99cba'
assert parents['GHSA-PPPJ-HQ3G-57PJ']=='a555fe1dcb4a4d6b135236ae89319a9f303780d9'
assert parents['GHSA-Q49M-57VM-C8CC']=='47dea24409952ea793d52512794d60d087bfc213'
assert parents['GHSA-QRPW-GJVH-X5GM']=='36cde7148a207234de6212ec074f321dbc9d1b5b'
assert res['counts']['PASS']==0 and res['pass_proposals']==[]
assert res['counts']['REJECT']==8 and res['counts']['UNKNOWN']==0
assert res['conservation']['equation']=='8=8+0' and res['conservation']['holds']
assert res['conservation']['disjoint_from_ranks_1_24'] is True
text=(OWN/'report.md').read_text()
assert 'PASS=0' in text and '8=8+0' in text
assert 'Worker PASS is proposal-only' in text
assert 'ranks 25-32' in text

ADV=Path('/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database')
env=os.environ.copy()
env['GIT_OPTIONAL_LOCKS']='0'
env['GIT_TERMINAL_PROMPT']='0'
env['GIT_NO_LAZY_FETCH']='1'

def git_out(repo,*args):
    p=subprocess.run(['git','-C',str(repo),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,check=False)
    err=p.stderr.decode()
    keep=[]
    for line in err.splitlines():
        if 'unable to normalize alternate object path' in line: continue
        if 'lazy fetching disabled' in line: continue
        if line.strip():
            keep.append(line)
    if p.returncode!=0 or keep:
        raise SystemExit('git fail '+str(args)+' '+chr(10).join(keep))
    return p.stdout.decode().strip()

assert git_out(ADV,'rev-parse','HEAD')==res['advisory_database']['head']
assert git_out(ADV,'rev-parse','HEAD:advisories/github-reviewed')==res['advisory_database']['github_reviewed_tree']
commit_re=re.compile(r'https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{40})')
for row,case in zip(a,c):
    owner,name=row['repository'].split('/')
    ghsa=row['case_id']
    fname='GHSA-'+ghsa[5:].lower()+'.json'
    matches=list((ADV/'advisories/github-reviewed').rglob(fname))
    assert matches, ghsa
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
    raw=matches[0].read_bytes()
    assert sha256(raw).hexdigest()==res['first_party_advisory_sha256'][ghsa]
    assert case['probe_fix'] in shas
print('REPLAY_OK assigned=8 PASS=0 canonical94=94 ranks=25-32 disjoint bucket=38')
PY
