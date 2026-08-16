#!/usr/bin/env python3
"""Derive the research total-account summary from the evidence ledger."""
import json
from collections import Counter
from pathlib import Path

ROOT = Path('/home/hanqing/agents/ai-slop')
LED = ROOT / 'artifacts/ledger.jsonl'

# denominator pools
fix_ids = set(); nofix_ids = set(); repos = set()
for l in (ROOT / 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fixrefs.jsonl').read_text().splitlines():
    if not l.strip(): continue
    try: r = json.loads(l)
    except Exception: continue
    d = str(r.get('published') or '')[:10]
    if not ('2025-05-01' <= d <= '2026-08-14'): continue
    cid = r.get('case_id')
    if isinstance(cid, str): fix_ids.add(cid.upper())
    if isinstance(r.get('repository'), str) and r['repository'].strip():
        repos.add(r['repository'].lower().replace('github.com/', '').strip('/'))
for l in (ROOT / 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/nofix-advisories.jsonl').read_text().splitlines():
    if not l.strip(): continue
    try: r = json.loads(l)
    except Exception: continue
    cid = r.get('ghsa')
    if isinstance(cid, str): nofix_ids.add(cid.upper())
    if isinstance(r.get('repo'), str) and r['repo'].strip():
        repos.add(r['repo'].lower().replace('github.com/', '').strip('/'))
denom = len(fix_ids | nofix_ids)

# verdict buckets: latest non-audit verdict per ledger row
rows = [json.loads(l) for l in LED.read_text().splitlines() if l.strip()]
buckets = Counter()
adjudicated = Counter()
for r in rows:
    latest = None
    for v in r.get('verdicts', []):
        if v.get('kind') in ('audit', 'prefilter'): continue
        latest = v.get('verdict')
    if latest in ('B1_AI_FAULT', 'B1_CONFIRM', 'BUT_FOR_PASS_UPGRADE'):
        buckets['B1_AI_FAULT'] += 1
    elif latest in ('B2_NOT_AI', 'B2_OVERTURN'):
        buckets['B2_NOT_AI'] += 1
    elif latest in ('B3_BLOCKED', 'B3_UNCLEAR', 'UNRECOVERED'):
        buckets['B3_BLOCKED'] += 1
    elif latest and latest.startswith('RECOVERED'):
        buckets['fix_recovered_pending_review'] += 1
    elif latest:
        buckets['other:' + str(latest)] += 1
    else:
        buckets['unreviewed'] += 1

fixrec = buckets.pop('fix_recovered_pending_review', 0)
b1 = buckets.pop('B1_AI_FAULT', 0)
b2 = buckets.pop('B2_NOT_AI', 0)
b3 = buckets.pop('B3_BLOCKED', 0)
unrev = buckets.pop('unreviewed', 0)
others = dict(buckets)

print('denominator:', denom)
print('distinct repos:', len(repos))
print('B1_AI_FAULT:', b1)
print('B2_NOT_AI:', b2)
print('B3_BLOCKED:', b3)
print('fix recovered, pending review:', fixrec)
print('unreviewed rows:', unrev)
print('other verdict tags:', others)
print('total ledger rows:', len(rows))
