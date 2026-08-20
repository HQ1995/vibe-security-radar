#!/usr/bin/env python3
"""Cross-check semantic, lineage, provenance, and boundary records."""
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / 'artifacts/funnel-account-20260817.jsonl'
NOTAI_SECOND = ROOT / '.ai-slop/state/notai-review/notai-second-review-20260819.jsonl'
NOTAI_CANON = ROOT / '.ai-slop/state/notai-review/notai-causal-canonical-20260819.jsonl'
NOTAI_PROV = ROOT / '.ai-slop/state/notai-review/notai-provenance-audit-20260819.jsonl'
NOTAI_SOURCE = ROOT / '.ai-slop/state/notai-review/notai-independent-source-manifest-20260819.jsonl'
BLOCKED_REVIEW = ROOT / '.ai-slop/state/blocked-deepwave/worker-blocked-second-review-20260820.jsonl'
OUT = ROOT / '.ai-slop/state/reconciliation/merged-notai-blocked-audit-20260820.jsonl'
REPORT = ROOT / '.ai-slop/state/reconciliation/merged-notai-blocked-audit-20260820.md'

def read(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]

ledger_rows = read(LEDGER)
ledger = {r['class_id']: r for r in ledger_rows}
second = {r['class_id']: r for r in read(NOTAI_SECOND)}
canon = {r['class_id']: r for r in read(NOTAI_CANON)}
prov = {r['class_id']: r for r in read(NOTAI_PROV)}
source = {r['class_id']: r for r in read(NOTAI_SOURCE)}
blocked = {r['class_id']: r for r in read(BLOCKED_REVIEW)}

notai_ids = {cid for cid, r in ledger.items() if r.get('status') == 'NOT_AI'}
blocked_ids = {cid for cid, r in ledger.items() if r.get('status') == 'BLOCKED'}
errors = []
records = []

def require_set(name, actual, expected):
    if actual != expected:
        errors.append({'scope': name, 'missing': sorted(expected - actual), 'extra': sorted(actual - expected)})

require_set('notai-second', set(second), notai_ids)
require_set('notai-canonical', set(canon), notai_ids)
require_set('notai-provenance', set(prov), notai_ids)
require_set('notai-independent-source', set(source), notai_ids)
require_set('blocked-review', set(blocked), blocked_ids)

for cid in sorted(notai_ids):
    l = ledger[cid]
    s = second[cid]
    c = canon[cid]
    p = prov[cid]
    m = source[cid]
    cr = l.get('causal_research') or {}
    row_errors = []
    for name, left, right in (
        ('repo', l.get('repo'), s.get('repo')),
        ('case_id', cr.get('case_id'), s.get('case_id')),
        ('canonical_case_id', c.get('case_id'), s.get('case_id')),
        ('provenance_case_id', p.get('case_id'), s.get('case_id')),
        ('second_verdict', s.get('verdict'), 'NOT_AI'),
        ('canonical_verdict', c.get('verdict'), 'NOT_AI'),
        ('ledger_verdict', cr.get('verdict'), 'NOT_AI'),
    ):
        if left != right:
            row_errors.append({'field': name, 'left': left, 'right': right})
    checks = {
        'mechanism_understood': s.get('mechanism_understood') is True and c.get('mechanism_understood') is True and p.get('mechanism_understood') is True,
        'causal_closure': c.get('causal_closure') is True and p.get('causal_closure') is True,
        'introducer_present': bool(cr.get('introducer_sha')) and bool(c.get('introducer_sha')),
        'parent_boundary': bool(c.get('parent_sha_verified') or c.get('root_boundary_verified') or c.get('multi_introducer_parent_map')),
        'fix_or_no_fix': bool(c.get('direct_fix_sha')) or c.get('no_fix_proven') is True,
        'ai_role_recorded': c.get('ai_role_recorded') is True and p.get('ai_role_evidence_present') is True,
        'squash_shape_valid': c.get('squash_shape_valid') is True,
        'independent_source_complete': m.get('evidence_strength') == 'SOURCE_COMPLETE' and not m.get('source_missing_fields'),
        # Detailed evidence may live in the canonical causal/direct-recheck
        # record; second-review text length is not an acceptance gate.
        'second_review_present': cid in second and s.get('verdict') == 'NOT_AI',
    }
    row_errors.extend({'field': name, 'left': value, 'right': True} for name, value in checks.items() if not value)
    if row_errors:
        errors.append({'scope': 'NOT_AI', 'class_id': cid, 'errors': row_errors})
    records.append({'class_id': cid, 'repo': l.get('repo'), 'dataset': 'NOT_AI', 'checks': checks, 'errors': row_errors, 'review_state': c.get('review_state')})

for cid in sorted(blocked_ids):
    l = ledger[cid]
    b = blocked[cid]
    row_errors = []
    if not str(b.get('conclusion', '')).startswith('RETAIN_BLOCKED'):
        row_errors.append({'field': 'conclusion', 'left': b.get('conclusion'), 'right': 'RETAIN_BLOCKED'})
    checks = {
        'mechanism_status': bool(b.get('mechanism_status')),
        'fix_status': bool(b.get('fix_status')),
        'lineage_status': bool(b.get('lineage_status')),
        'ai_role_status': bool(b.get('ai_role_status')),
        'evidence_refs': bool(b.get('evidence_refs')),
        'next_boundary': bool(b.get('next_boundary')),
        'ledger_bucket_blocked': l.get('status') == 'BLOCKED',
    }
    row_errors.extend({'field': name, 'left': value, 'right': True} for name, value in checks.items() if not value)
    if row_errors:
        errors.append({'scope': 'BLOCKED', 'class_id': cid, 'errors': row_errors})
    records.append({'class_id': cid, 'repo': l.get('repo'), 'dataset': 'BLOCKED', 'checks': checks, 'errors': row_errors, 'review_state': 'RETAIN_BLOCKED'})

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(''.join(json.dumps(r, ensure_ascii=False, separators=(',', ':')) + '\n' for r in records), encoding='utf-8')
summary = {
    'ledger_rows': len(ledger_rows), 'notai_rows': len(notai_ids), 'blocked_rows': len(blocked_ids),
    'notai_review_states': dict(Counter(str(canon[cid].get('review_state')) for cid in notai_ids)),
    'blocked_lineage_states': dict(Counter(str(blocked[cid].get('lineage_status')) for cid in blocked_ids)),
    'errors': len(errors), 'passed': not errors, 'error_details': errors,
}
REPORT.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(summary, ensure_ascii=False))
if errors:
    raise SystemExit(1)
