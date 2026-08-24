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
OWN=ROOT/'autoresearch/herdr-260814-queue-leftover-a-grok46-low'
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
assert h(SRC/'result.json')==pins['source_result.json']
names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==['assignment.jsonl','cases.jsonl','replay.zsh','report.md','result.json'], names
assert not (OWN/'work').exists()
for p in OWN.iterdir():
    if p.is_file():
        assert all(b<128 for b in p.read_bytes()), p.name

src=json.loads((SRC/'result.json').read_text())
want=['GHSA-R54C-2XMF-2CF3','GHSA-V5MV-P594-2X33','GHSA-V95X-XHQ5-4929','GHSA-WVMP-6R4V-J6CV','GHSA-375F-4R2H-F99J']
assert src['leftover_ids'][:5]==want
assert set(want).isdisjoint(src['queued_ids'])
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
assert 'leftover_ids prefix exactly' in text

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
        raise SystemExit('git fail '+str(args)+' '+'\n'.join(keep))
    return p.stdout.decode().strip()

assert git_out(ADV,'rev-parse','HEAD')==res['advisory_database']['head']
assert git_out(ADV,'rev-parse','HEAD:advisories/github-reviewed')==res['advisory_database']['github_reviewed_tree']
paths={
 'GHSA-R54C-2XMF-2CF3':'advisories/github-reviewed/2025/07/GHSA-r54c-2xmf-2cf3/GHSA-r54c-2xmf-2cf3.json',
 'GHSA-V5MV-P594-2X33':'advisories/github-reviewed/2026/08/GHSA-v5mv-p594-2x33/GHSA-v5mv-p594-2x33.json',
 'GHSA-V95X-XHQ5-4929':'advisories/github-reviewed/2026/07/GHSA-v95x-xhq5-4929/GHSA-v95x-xhq5-4929.json',
 'GHSA-WVMP-6R4V-J6CV':'advisories/github-reviewed/2026/07/GHSA-wvmp-6r4v-j6cv/GHSA-wvmp-6r4v-j6cv.json',
 'GHSA-375F-4R2H-F99J':'advisories/github-reviewed/2026/05/GHSA-375f-4r2h-f99j/GHSA-375f-4r2h-f99j.json',
}
for cid,rel in paths.items():
    got=h(ADV/rel)
    assert got==res['first_party_advisory_sha256'][cid], (cid,got)

cl=res['read_only_clones']
po=res['pinned_objects']
assert git_out(cl['ms_swift'],'rev-parse',po['swift_fix'])==po['swift_fix']
assert git_out(cl['ms_swift'],'rev-parse',po['swift_fix']+'^:swift/tuners/base.py')==po['swift_base_parent']
assert git_out(cl['ms_swift'],'rev-parse',po['swift_fix']+':swift/tuners/base.py')==po['swift_base_fixed']
assert git_out(cl['ms_swift'],'rev-parse','v3.6.3^{commit}')==po['swift_v363']
assert git_out(cl['ms_swift'],'rev-parse','v3.6.3:swift/tuners/base.py')==po['swift_base_parent']
blame=git_out(cl['ms_swift'],'blame','-L','257,259',po['swift_fix']+'^','--','swift/tuners/base.py')
assert po['swift_origin'][:8] in blame
assert 'torch.load' in git_out(cl['ms_swift'],'show',po['swift_fix']+'^:swift/tuners/base.py')
assert 'NotImplementedError' in git_out(cl['ms_swift'],'show','v3.7.0:swift/tuners/base.py')
stat=git_out(cl['ms_swift'],'show','--name-only','--format=',po['swift_gemini'])
assert 'swift/tuners/base.py' not in stat
assert git_out(cl['guzzle'],'rev-parse',po['guzzle_ai'])==po['guzzle_ai']
assert git_out(cl['guzzle'],'rev-parse',po['guzzle_fix8']+':src/Handler/HostValidator.php')==po['guzzle_hv8']
assert git_out(cl['guzzle'],'rev-parse',po['guzzle_fix7']+':src/Handler/HostValidator.php')==po['guzzle_hv7']
assert 'src/Handler/HostValidator.php' not in git_out(cl['guzzle'],'show','--name-only','--format=',po['guzzle_ai'])
assert git_out(cl['kuma'],'rev-parse',po['kuma_fix']+':pkg/util/http/tls.go')==po['kuma_tls_fixed']
assert git_out(cl['kuma'],'rev-parse',po['kuma_fix']+'^:pkg/util/http/tls.go')==po['kuma_tls_parent']
assert git_out(cl['kuma'],'rev-parse',po['kuma_fix']+':app/kuma-dp/pkg/dataplane/envoy/remote_bootstrap.go')==po['kuma_dp_fixed']
kstat=git_out(cl['kuma'],'show','--name-only','--format=',po['kuma_copilot'])
assert 'pkg/util/http/tls.go' not in kstat
assert 'remote_bootstrap.go' not in kstat
assert git_out(cl['bandit'],'rev-parse',po['bandit_fix']+':lib/bandit/pipeline.ex')==po['bandit_pipe_fixed']
assert git_out(cl['bandit'],'rev-parse',po['bandit_fix']+'^:lib/bandit/pipeline.ex')==po['bandit_pipe_parent']
assert git_out(cl['bandit'],'rev-parse',po['bandit_origin'])==po['bandit_origin']
bstat=git_out(cl['bandit'],'show','--name-only','--format=',po['bandit_claude'])
assert 'lib/bandit/pipeline.ex' not in bstat
print('REPLAY_OK assigned=5 reviewed=5 unreviewed=0 PASS=0 canonical93=93 equation=5=5+0')
PY
