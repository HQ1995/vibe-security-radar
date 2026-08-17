#!/usr/bin/env python3
"""Derive the publish input (foundation.jsonl) from artifacts/ledger.jsonl.

The ledger is the system of record; foundation.jsonl is a derived snapshot in
the schema publish_research_ledger.py expects. Re-run this before publishing.
"""
import json
from pathlib import Path

ROOT = Path('/home/hanqing/agents/ai-slop')
LEDGER = ROOT / 'artifacts/ledger.jsonl'
OUT = ROOT / 'autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl'

rows = []
for line in LEDGER.read_text().splitlines():
    if not line.strip():
        continue
    r = json.loads(line)
    adj = r.get('adjudication')
    if not adj:
        continue
    tier = r.get('tier') or 'scoped_contribution'
    verdict = adj.get('verdict') or ('STRICT' if tier == 'all_pass' else 'NARROW')
    fp211 = adj.get('fp211_verdict') or verdict
    gates = r.get('gates') or {}
    out = {
        'candidate_set': [r['candidate_sha']] if r.get('candidate_sha') else [],
        'case_id': r['case_id'],
        'contribution_class': r.get('contribution_class') or 'UNKNOWN',
        'counted': adj.get('counted', True),
        'counterevidence': [],
        'decisive_evidence': r.get('evidence_text') or [
            f"{r.get('repo') or ''} cand={r.get('candidate_sha')} fix={r.get('fix_sha')}"],
        'fp211_verdict': fp211,
        'gates': {f'{k}_gate': v for k, v in gates.items()},
        'minimum_fix_set': [r['fix_sha']] if r.get('fix_sha') else [],
        'repository': r.get('repo'),
        'row_key': f"ledger:{r['row_key']}",
        'scope': adj.get('scope') or r.get('contribution_class') or 'UNKNOWN',
        'source': 'artifacts/ledger.jsonl',
        'source_row': 'artifacts/ledger.jsonl',
        'tier': tier,
        'verdict': verdict,
        'zero_fp_scope': adj.get('zero_fp_scope', 'adjudicated'),
    }
    if adj.get('carrier_set'):
        out['carrier_set'] = adj['carrier_set']
    rows.append(out)

with open(OUT, 'w') as f:
    for r in rows:
        f.write(json.dumps(r, ensure_ascii=False) + '\n')
print(f'foundation rows derived: {len(rows)} -> {OUT}')
