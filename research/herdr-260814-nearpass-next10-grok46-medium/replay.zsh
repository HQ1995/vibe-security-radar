#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 GIT_PAGER=cat
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json
ROOT=Path('/home/hanqing/agents/ai-slop')
OWN=ROOT/'autoresearch/herdr-260814-nearpass-next10-grok46-medium'
res=json.loads((OWN/'result.json').read_text())

def h(p):
    return sha256(Path(p).read_bytes()).hexdigest()

pins=res['current_input_hashes']
paths=res['current_input_paths']
for k,rel in paths.items():
    got=h(ROOT/rel)
    assert got==pins[k], (k, got, pins[k])
for item in res['frozen_scanned_manifest']:
    got=h(ROOT/item['path'])
    assert got==item['sha256'], (item['path'], got, item['sha256'])

names=sorted(p.name for p in OWN.iterdir() if p.is_file())
assert names==['assignment.jsonl','cases.jsonl','replay.zsh','report.md','result.json'], names
assert not (OWN/'work').exists()
a=[json.loads(l) for l in (OWN/'assignment.jsonl').read_text().splitlines() if l.strip()]
c=[json.loads(l) for l in (OWN/'cases.jsonl').read_text().splitlines() if l.strip()]
assert len(a)==len(c)==10
ids=[x['case_id'] for x in a]
assert ids==[x['case_id'] for x in c]==res['queued_ids']
assert len(set(ids))==10
assert all(x.get('never_pass') and x.get('routing_only') for x in a+c)
assert all(x.get('proposed_pass') is False for x in c)
assert all(x.get('verdict') in ('NARROW','UNKNOWN') for x in c)
assert all(x.get('verdict')!='PASS' for x in c)
assert res['counts']['PASS']==0 and res['pass_proposals']==[] and res['PASS_PROPOSAL']==[]
assert res['canonical94_strict_count']==94
assert res['conservation']['holds'] and res['conservation']['universe_holds'] and res['conservation']['eligible_holds']
assert res['conservation']['universe_equation']=='1648 = 32 + 1312 + 1 + 7 + 142 + 154'
assert res['conservation']['eligible_equation']=='154 = 10 + 144'
assert res['conservation']['equation']=='10=0+10'
canon=set(str(x).upper() for x in json.loads((ROOT/'autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json').read_text())['strict_released_case_ids'])
assert len(canon)==94
assert not set(ids)&canon
text=(OWN/'report.md').read_text()
assert 'does not call a PASS' in text
assert 'does not infer causality' in text
for p in OWN.iterdir():
    if p.is_file():
        raw=p.read_bytes()
        assert all(b<128 for b in raw), p.name
print('REPLAY_OK queued=10 PASS=0 canonical94=94 eligible=154 leftover=144 scanned=%s' % res['counts']['scanned_files'])
PY
