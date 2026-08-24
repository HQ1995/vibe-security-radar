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
OWN=ROOT/'autoresearch/herdr-260814-recover-fix-missing-ranks33-38-grok46-high'
PRIOR=ROOT/'autoresearch/herdr-260814-recover-fix-missing-ranks17-24-grok46-low'
MID=ROOT/'autoresearch/herdr-260814-recover-fix-missing-ranks25-32-grok46-low'
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
assert pins['prior_reconstruction_result.json']=='04206ea707bec13f0ec351dc34d95f97b43ec5ce9bf969c71226506f351886e8'
assert h(MID/'result.json')==pins['ranks25_32_result.json']
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
 'GHSA-R292-9MHP-454M','GHSA-V3R7-H72X-CJCM','GHSA-V479-VF79-MG83',
 'GHSA-VC34-39Q2-M6Q3','GHSA-VGHX-352F-93JM','GHSA-WHVH-WF3X-G77J']
assert [x['case_id'] for x in a]==[x['case_id'] for x in c]==want
assert [x['assigned_order'] for x in a]==[x['bucket_rank'] for x in a]==list(range(33,39))
assert len(set(want))==6
first8=res['ranks_1_8_owned_elsewhere']
next8=res['ranks_9_16_owned_elsewhere']
mid8=res['ranks_17_24_owned_elsewhere']
late8=res['ranks_25_32_owned_elsewhere']
assert len(first8)==8 and len(next8)==8 and len(mid8)==8 and len(late8)==8
owned=first8+next8+mid8+late8
assert set(owned).isdisjoint(set(want))
assert len(owned)==len(set(owned))==32
missing=res['reconstructed_fix_object_missing_ids']
assert len(missing)==38==res['counts']['fix_object_missing_reconstructed']
assert missing==sorted(missing)
assert first8==missing[:8]
assert next8==missing[8:16]
assert mid8==missing[16:24]
assert late8==missing[24:32]
assert want==missing[32:38]
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
assert all(x['gates']['topology_gate']=='PASS' for x in c)
assert all(x['gates']['fix_reversal_gate']=='PASS' for x in c)
assert all(x['gates']['but_for_gate']=='FAIL' for x in c)
assert all(x['gates']['release_gate']=='FAIL' for x in c)
assert all(x['parent_count']==1 for x in c)
assert all(x['ai_marker_evidence']==[] and x['pre_fix_ai_candidates']==[] for x in c)
assert all(x['canonical_overlap'] is False for x in c)
parents={x['case_id']:x['candidate_parent'] for x in c}
assert parents['GHSA-R292-9MHP-454M']=='ebbb72094159d003f428dcd1cb28255d37ea4873'
assert parents['GHSA-V3R7-H72X-CJCM']=='a17e30134238fb208e9c02064711bdfe117156a8'
assert parents['GHSA-V479-VF79-MG83']=='27a88dd17a7beb5e7ca44cfe69b4da074c2de812'
assert parents['GHSA-VC34-39Q2-M6Q3']=='9199364b60c7acae4219800d194bbe07d2997b8c'
assert parents['GHSA-VGHX-352F-93JM']=='cec4c3f5e95e083f906ccc44eb27186e034ddc31'
assert parents['GHSA-WHVH-WF3X-G77J']=='a555fe1dcb4a4d6b135236ae89319a9f303780d9'
assert c[0]['vulnerable_release_evidence']['sha256']=='b6ca3811723738faade28125aa09634c27b313260cd7c7f9c409021f939bd7a6'
assert c[0]['fixed_release_evidence']['sha256']=='e66fe666cc16f232393a4314a8572dfcd7312e2f06db32ce7aee90e7899c273b'
assert c[1]['vulnerable_release_evidence']['sha256']=='74d0520111e9857542b14b141c4f15ea423475ecfc5917d187f4e9462e3e41e4'
assert c[1]['fixed_release_evidence']['sha256']=='87d0ed0bc0c00a6446a25a439d0b79d9191a12c461185850bbbc054dcb268d32'
assert c[2]['vulnerable_release_evidence']['sha256']=='9a1ef16f443b4919facd0d63883674fa3c6226e48c6a6cfccf8fe202b5ad43e9'
assert c[2]['fixed_release_evidence']['sha256']=='5fd42c350d12fb3041109813ff1423a4a799da41f475264ce1324280f694a8ed'
assert c[3]['vulnerable_release_evidence']['sha256']=='b6da6c16e9b0c3916ecea67abd4d8dfd192fa2b713c1dfb0be3b926f34971cc1'
assert c[3]['fixed_release_evidence']['sha256']=='e2d9bb4f5ac1868244aac5810c54d27571146983f2a5204ba0175b7d79e4619e'
assert c[4]['vulnerable_release_evidence']['sha256']=='0a5aa029b943ba0ae49882adc8d3c84c0a71b615d7bb1b1231bc6b19b405388a'
assert c[4]['fixed_release_evidence']['sha256']=='86ea8b1a4df74a685d01fcdd598ce41f052345ae6e28f6d2d05e20cbec3f3112'
assert c[5]['vulnerable_release_evidence']['sha256']=='f8f08b653d4f92edbdd007e949427b9f603e50543457c165e79738bb0b6a7147'
assert c[5]['fixed_release_evidence']['sha256']=='7e62ac6daa749fcc2d2d85a8a664604159a12876395d94c72e99dfd703eed448'
assert res['pinned_objects']['GHSA-R292-9MHP-454M']=='631ae59121bf8fc8a22bbae35f074cb9b789cd4a'
assert res['pinned_objects']['GHSA-V3R7-H72X-CJCM']=='10d93fc332f2c8c161982dec3833201de29891b5'
assert res['pinned_objects']['GHSA-V479-VF79-MG83']=='6a0f39b252a81fa4b19dc56dc889183acc9225ae'
assert res['pinned_objects']['GHSA-VC34-39Q2-M6Q3']=='4d01946f0b3d6c6e31786f91cdfb3eb902908da0'
assert res['pinned_objects']['GHSA-VGHX-352F-93JM']=='8e8b0abdb1b66f5e9b25b3833879f05c173a5596'
assert res['pinned_objects']['GHSA-WHVH-WF3X-G77J']=='be9303f5bcd5308eaeae953c5a3c903046682c2c'
assert res['counts']['PASS']==0 and res['pass_proposals']==[]
assert res['counts']['REJECT']==6 and res['counts']['UNKNOWN']==0
assert res['conservation']['equation']=='6=6+0' and res['conservation']['holds']
assert res['conservation']['assigned']==6 and res['conservation']['reviewed']==6 and res['conservation']['unreviewed']==0
assert res['conservation']['disjoint_from_ranks_1_32'] is True
text=(OWN/'report.md').read_text()
assert 'PASS=0' in text and '6=6+0' in text
assert 'Worker PASS is proposal-only' in text
assert 'ranks 33-38' in text

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
    assert not data.get('withdrawn')
    nest=case['gates']
    assert set(nest)==set(res['seven_gates'])
print('REPLAY_OK assigned=6 reviewed=6 unreviewed=0 PASS=0 canonical94=94 equation=6=6+0 bucket=38 ranks=33-38')
PY
