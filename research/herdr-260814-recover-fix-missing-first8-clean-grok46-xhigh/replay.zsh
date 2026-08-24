#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, subprocess

ROOT=Path('/home/hanqing/agents/ai-slop')
OWN=ROOT/'autoresearch/herdr-260814-recover-fix-missing-first8-clean-grok46-xhigh'
SRC=ROOT/'autoresearch/herdr-260814-nextqueue-v2-grok46-low'
AUTH=ROOT/'autoresearch/herdr-260814-recover-fix-missing-ranks17-24-grok46-low/result.json'
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
assert h(AUTH)==pins['ranks17_24_result.json']
assert pins['ranks17_24_result.json']=='04206ea707bec13f0ec351dc34d95f97b43ec5ce9bf969c71226506f351886e8'
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==['assignment.jsonl','cases.jsonl','replay.zsh','report.md','result.json'], names
assert not (OWN/'work').exists()
for p in OWN.iterdir():
    if p.is_file():
        assert all(b<128 for b in p.read_bytes()), p.name

auth=json.loads(AUTH.read_text())
missing=auth['reconstructed_fix_object_missing_ids']
assert len(missing)==38==len(set(missing))
assert missing==sorted(missing)
want=missing[:8]
assert want==[
 'GHSA-264V-M8FM-76JM','GHSA-27W2-87XV-37C6','GHSA-2VQ4-854F-5C72','GHSA-36XV-JGW5-4Q75',
 'GHSA-3763-QP59-59VF','GHSA-44QC-PGVP-WX7V','GHSA-46WQ-28CX-MHW4','GHSA-48CH-P4GQ-X46X']
assert res['assigned_ids']==want
assert res['ranks_9_16_owned_elsewhere']==missing[8:16]
assert res['ranks_17_24_owned_elsewhere']==missing[16:24]
assert set(want).isdisjoint(res['ranks_9_16_owned_elsewhere'])
assert set(want).isdisjoint(res['ranks_17_24_owned_elsewhere'])
a=[json.loads(l) for l in (OWN/'assignment.jsonl').read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/'cases.jsonl').read_text().splitlines() if l.strip()]
assert [x['case_id'] for x in a]==[x['case_id'] for x in c]==want
assert [x['assigned_order'] for x in a]==[x['bucket_rank'] for x in a]==list(range(1,9))
assert len(set(want))==8
src=json.loads((SRC/'result.json').read_text())
assert src['buckets']['fix_object_missing']==38
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
assert not any(all(v=='PASS' for v in x['gates'].values()) for x in c)
assert res['counts']['PASS']==0 and res['pass_proposals']==[]
assert res['conservation']['equation']=='8=8+0' and res['conservation']['holds']
assert res['conservation']['disjoint_from_ranks_9_16'] is True
assert res['did_not_inherit_sibling_verdicts'] is True
text=(OWN/'report.md').read_text()
assert 'PASS=0' in text and '8=8+0' in text
assert 'Worker PASS is proposal-only' in text
assert 'ranks 1-8' in text
assert 'Did not inherit' in text or 'did not inherit' in text

ADV=Path('/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database')
git_env={
 'PATH':'/usr/local/bin:/usr/bin:/bin',
 'HOME':'/nonexistent',
 'LC_ALL':'C',
 'GIT_CONFIG_NOSYSTEM':'1',
 'GIT_CONFIG_GLOBAL':'/dev/null',
 'GIT_CONFIG_SYSTEM':'/dev/null',
 'GIT_OPTIONAL_LOCKS':'0',
 'GIT_TERMINAL_PROMPT':'0',
 'GIT_NO_LAZY_FETCH':'1',
 'GIT_PAGER':'cat',
}

def git_out(repo,*args):
    p=subprocess.run(['/usr/bin/git','--no-optional-locks','-c','gc.auto=0','-c','credential.helper=','-C',str(repo),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=git_env,check=False)
    err=p.stderr.decode()
    keep=[]
    for line in err.splitlines():
        if 'unable to normalize alternate object path' in line: continue
        if 'lazy fetching disabled' in line: continue
        if line.strip():
            keep.append(line)
    if keep:
        raise SystemExit('git stderr nonempty')
    if p.returncode!=0:
        raise SystemExit('git failed')
    return p.stdout.decode().strip()

assert git_out(ADV,'rev-parse','HEAD')==res['advisory_database']['head']
assert git_out(ADV,'rev-parse','HEAD:advisories/github-reviewed')==res['advisory_database']['github_reviewed_tree']
for row in c:
    rel=None
    for srcs in row['first_party_sources']:
        if srcs.startswith('advisory:'):
            rel=srcs.split('advisory:',1)[1].split()[0]
    assert rel
    got=h(ADV/rel)
    assert got==res['first_party_advisory_sha256'][row['case_id']], row['case_id']
    data=json.loads((ADV/rel).read_text())
    assert not data.get('withdrawn')
    text=(ADV/rel).read_text()
    for sha in row['minimum_fix_set']:
        assert sha in text
    nest=row['gates']
    assert set(nest)==set(res['seven_gates'])
assert c[2]['gates']['fix_reversal_gate']=='FAIL'
assert c[3]['gates']['topology_gate']=='FAIL'
assert c[7]['gates']['fix_reversal_gate']=='FAIL'
print('REPLAY_OK assigned=8 reviewed=8 unreviewed=0 PASS=0 canonical94=94 equation=8=8+0 bucket=38 ranks=1-8')
PY
