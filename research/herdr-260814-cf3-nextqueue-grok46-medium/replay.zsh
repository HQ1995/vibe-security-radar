#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
ROOT=${0:A:h:h:h}
cd "$ROOT"
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import json
ROOT=Path('.').resolve()
OWN=ROOT/'autoresearch/herdr-260814-cf3-nextqueue-grok46-medium'
res=json.loads((OWN/'result.json').read_text())
pins=res['current_input_hashes']
rel={
 'foundation165_result.json':'autoresearch/herdr-260814-foundation165-authority-audit-grok46-low/result.json',
 'foundation165_report.md':'autoresearch/herdr-260814-foundation165-authority-audit-grok46-low/report.md',
 'canonical87_summary.json':'autoresearch/orchestrator-260814-ghsa200-canonical87/summary.json',
 'canonical87_ledger.jsonl':'autoresearch/orchestrator-260814-ghsa200-canonical87/ledger.jsonl',
 'foundation.jsonl':'autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl',
 'cf3_release6_assignment.jsonl':'autoresearch/herdr-260814-cf3-release6-grok46-low/assignment.jsonl',
 'cf3_release6_result.json':'autoresearch/herdr-260814-cf3-release6-grok46-low/result.json',
 'cf3_singlegate5_assignment.jsonl':'autoresearch/herdr-260814-cf3-singlegate5-grok46-high/assignment.jsonl',
 'cf3_singlegate5_result.json':'autoresearch/herdr-260814-cf3-singlegate5-grok46-high/result.json',
 'cf3_confirm5_assignment.jsonl':'autoresearch/herdr-260814-cf3-confirm5-grok46-high/assignment.jsonl',
}
for k,p in rel.items():
    got=sha256((ROOT/p).read_bytes()).hexdigest()
    assert got==pins[k], (k,got,pins[k])
q=[json.loads(l) for l in (OWN/'queue.jsonl').read_text().splitlines() if l.strip()]
a=[json.loads(l) for l in (OWN/'assignment.jsonl').read_text().splitlines() if l.strip()]
assert len(q)==len(a)==20
assert len({x['case_id'] for x in q})==20
assert all(x['never_pass'] for x in q)
assert all(x['latest_verdict']!='PASS' for x in q)
assert res['conservation']['holds'] and res['conservation']['queue_holds']
assert res['counts']['PASS']==0 and res['pass_proposals']==[]
assert res['canonical87_strict_count']==87
text=(OWN/'report.md').read_text()
assert 'does not call a PASS' in text
assert all(ord(c)<128 for c in text)
print('REPLAY_OK universe=74 assigned19=19 later_reject=%s remaining=%s queued=20 PASS=0' % (res['counts']['later_terminal_reject'], res['counts']['remaining']))
PY
