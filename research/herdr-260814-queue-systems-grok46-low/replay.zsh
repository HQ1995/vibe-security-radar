#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json, subprocess, os

ROOT=Path('/home/hanqing/agents/ai-slop')
OWN=ROOT/'autoresearch/herdr-260814-queue-systems-grok46-low'
SRC=ROOT/'autoresearch/herdr-260814-nextqueue-v2-grok46-low'
res=json.loads((OWN/'result.json').read_text())
pins=res['current_input_hashes']

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

assert h(ROOT/'autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md')==pins['CONTRACT.md']
assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical93/ledger.jsonl')==pins['canonical93_ledger.jsonl']
assert h(ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical93/summary.json')==pins['canonical93_summary.json']
assert h(SRC/'assignment.jsonl')==pins['source_assignment.jsonl']
assert h(SRC/'cases.jsonl')==pins['source_cases.jsonl']
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==['assignment.jsonl','cases.jsonl','replay.zsh','report.md','result.json'], names
assert not (OWN/'work').exists()
for p in OWN.iterdir():
    if p.is_file():
        assert all(b<128 for b in p.read_bytes()), p.name

want=['GHSA-G6W2-Q45F-XRP4','GHSA-WWJ6-VGHV-5P64','GHSA-X744-4WPC-V9H2','GHSA-F7VP-7XGX-4W4R','GHSA-HRXH-6V49-42GF']
a=[json.loads(l) for l in (OWN/'assignment.jsonl').read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/'cases.jsonl').read_text().splitlines() if l.strip()]
assert [x['case_id'] for x in a]==[x['case_id'] for x in c]==want
assert len(set(want))==5
assert all(x['verdict']=='REJECT' for x in c)
assert all(x['proposed_pass'] is False and x['countable_pass'] is False for x in c)
assert all(x['gates']['ai_hunk_gate']=='FAIL' for x in c)
assert all(x['gates']['identity_gate']=='PASS' for x in c)
assert res['counts']['PASS']==0 and res['pass_proposals']==[]
assert res['conservation']['equation']=='5=5+0' and res['conservation']['holds']
assert res['canonical93_strict_count']==93
canon=set(str(x).upper() for x in json.loads((ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical93/summary.json').read_text())['strict_released_case_ids'])
assert not set(want)&canon
text=(OWN/'report.md').read_text()
assert 'PASS=0' in text and '5=5+0' in text
assert 'Worker PASS is proposal-only' in text

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
 'GHSA-G6W2-Q45F-XRP4':'advisories/github-reviewed/2026/02/GHSA-g6w2-q45f-xrp4/GHSA-g6w2-q45f-xrp4.json',
 'GHSA-WWJ6-VGHV-5P64':'advisories/github-reviewed/2026/02/GHSA-wwj6-vghv-5p64/GHSA-wwj6-vghv-5p64.json',
 'GHSA-X744-4WPC-V9H2':'advisories/github-reviewed/2026/03/GHSA-x744-4wpc-v9h2/GHSA-x744-4wpc-v9h2.json',
 'GHSA-F7VP-7XGX-4W4R':'advisories/github-reviewed/2026/08/GHSA-f7vp-7xgx-4w4r/GHSA-f7vp-7xgx-4w4r.json',
 'GHSA-HRXH-6V49-42GF':'advisories/github-reviewed/2026/07/GHSA-hrxh-6v49-42gf/GHSA-hrxh-6v49-42gf.json',
}
for cid,rel in paths.items():
    got=h(ADV/rel)
    assert got==res['first_party_advisory_sha256'][cid], (cid,got)

cl=res['read_only_clones']
po=res['pinned_objects']
assert git_out(cl['facturascripts'],'rev-parse',po['factura_fix'])==po['factura_fix']
assert git_out(cl['facturascripts'],'rev-parse',po['factura_origin'])==po['factura_origin']
assert git_out(cl['facturascripts'],'rev-parse',po['factura_fix']+':Core/View/Macro/Utils.html.twig')==po['factura_twig_fixed']
assert git_out(cl['facturascripts'],'rev-parse',po['factura_fix']+'^:Core/View/Macro/Utils.html.twig')==po['factura_twig_parent']
blame=git_out(cl['facturascripts'],'blame','-L','28,28',po['factura_fix']+'^','--','Core/View/Macro/Utils.html.twig')
assert po['factura_origin'][:8] in blame
assert git_out(cl['kata'],'rev-parse',po['kata_fix'])==po['kata_fix']
assert git_out(cl['kata'],'rev-parse','3.27.0^{}')==po['kata_tag_3.27.0']
assert git_out(cl['moby'],'rev-parse',po['moby_fix']+':pkg/authorization/authz.go')==po['moby_authz_blob']
assert git_out(cl['moby'],'rev-parse','docker-v29.3.1:pkg/authorization/authz.go')==po['moby_authz_blob']
assert git_out(cl['guzzle'],'rev-parse',po['guzzle_ai'])==po['guzzle_ai']
assert git_out(cl['guzzle'],'rev-parse',po['guzzle_fix8'])==po['guzzle_fix8']
assert git_out(cl['guzzle'],'rev-parse',po['guzzle_fix7'])==po['guzzle_fix7']
stat=git_out(cl['guzzle'],'show','--name-only','--format=',po['guzzle_ai'])
assert 'src/Cookie/SetCookie.php' not in stat
assert git_out(cl['grpc'],'rev-parse',po['grpc_fix'])==po['grpc_fix']
assert git_out(cl['grpc'],'rev-parse',po['grpc_candidate'])==po['grpc_candidate']
print('REPLAY_OK assigned=5 reviewed=5 unreviewed=0 PASS=0 canonical93=93 equation=5=5+0')
PY
