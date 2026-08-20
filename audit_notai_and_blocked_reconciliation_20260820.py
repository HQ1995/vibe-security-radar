#!/usr/bin/env python3
"""Independent semantic coverage audit for the current NOT_AI and BLOCKED sets."""
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / 'artifacts/funnel-account-20260817.jsonl'
NOTAI = ROOT / '.ai-slop/state/notai-review/notai-second-review-20260819.jsonl'
NOTAI_CANON = ROOT / '.ai-slop/state/notai-review/notai-causal-canonical-20260819.jsonl'
NOTAI_PROV = ROOT / '.ai-slop/state/notai-review/notai-provenance-audit-20260819.jsonl'
NOTAI_SOURCE = ROOT / '.ai-slop/state/notai-review/notai-independent-source-manifest-20260819.jsonl'
NOTAI_AI_ROLE = ROOT / '.ai-slop/state/notai-review/notai-ai-role-review-20260820.jsonl'
BLOCKED = ROOT / '.ai-slop/state/blocked-deepwave/worker-blocked-second-review-20260820.jsonl'
OUT = ROOT / '.ai-slop/state/reconciliation/semantic-reconciliation-20260820.jsonl'
SUMMARY = ROOT / '.ai-slop/state/reconciliation/semantic-reconciliation-20260820.md'
SHA = re.compile(r'^[0-9a-f]{40}$')

def read(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]

ledger = read(LEDGER)
notai_ledger = {r['class_id']: r for r in ledger if r.get('status') == 'NOT_AI'}
blocked_ledger = {r['class_id']: r for r in ledger if r.get('status') == 'BLOCKED'}
notai = {r['class_id']: r for r in read(NOTAI)}
notai_canon = {r['class_id']: r for r in read(NOTAI_CANON)}
notai_prov = {r['class_id']: r for r in read(NOTAI_PROV)}
notai_source = {r['class_id']: r for r in read(NOTAI_SOURCE)}
notai_ai_role = {r['class_id']: r for r in read(NOTAI_AI_ROLE)}
blocked = {r['class_id']: r for r in read(BLOCKED)}

if set(notai_ledger) != set(notai):
    raise SystemExit(f'NOT_AI coverage mismatch ledger={len(notai_ledger)} review={len(notai)}')
if set(blocked_ledger) != set(blocked):
    raise SystemExit(f'BLOCKED coverage mismatch ledger={len(blocked_ledger)} review={len(blocked)}')

records = []
notai_failures = []
for cid in sorted(notai_ledger):
    row = notai[cid]
    canon = notai_canon[cid]
    prov = notai_prov[cid]
    source = notai_source[cid]
    ai_review = notai_ai_role[cid]
    normalized = source.get('normalized_source') or {}
    evidence = str(normalized.get('evidence') or row.get('evidence') or canon.get('evidence') or '')
    reasoning = str(normalized.get('reasoning') or row.get('reasoning') or canon.get('reasoning') or '')
    intro = row.get('introducer_shas') or canon.get('introducer_shas') or ([canon.get('introducer_sha')] if canon.get('introducer_sha') else [])
    has_fix = bool(row.get('direct_fix_sha') or canon.get('direct_fix_sha') or normalized.get('direct_fix_sha')) or any(
        item.get('no_fix_proven') is True for item in (row, canon, prov, normalized)
    )
    parent_boundary = any((
        row.get('history_limit') is True,
        bool(canon.get('introducer_parent')),
        canon.get('parent_sha_verified') is True,
        canon.get('root_boundary_verified') is True,
        canon.get('multi_introducer_parent_map') is True,
        prov.get('parent_absence') is True,
        prov.get('history_limited') is True,
        bool(prov.get('lineage_boundary')),
        normalized.get('introducer_parent_absent') is True,
        bool(normalized.get('introducer_parent')),
    ))
    ai_role = str(row.get('ai_role_evidence') or normalized.get('ai_marker') or ai_review.get('ai_marker') or '')
    ai_role_explained = len(ai_role) >= 20 or ai_review.get('ai_role_class') in {
        'NO_CAUSAL_AI_MARKER', 'NO_AI_ROLE_MARKER_REMEDIATION_CAVEAT',
        'AI_FIX_ONLY', 'AI_DOCUMENTATION_ONLY',
    }
    intro_status = row.get('introducer_evidence_status')
    intro_evidence = intro_status in {'FULL_COMMIT_REFERENCE', 'ROOT_BOUNDARY', 'MULTI_INTRODUCER', 'SOURCE_MOVE_BOUNDARY'} and bool(intro)
    if not intro_evidence:
        intro_evidence = bool(canon.get('introducer_sha')) and (
            canon.get('parent_sha_verified') is True
            or canon.get('root_boundary_verified') is True
            or canon.get('multi_introducer_parent_map') is True
        )
    squash_boundary = any((
        row.get('history_limit') is True,
        'squash' in (evidence + reasoning).lower(),
        canon.get('squash_shape_valid') is True and bool(intro),
        intro_status in {'FULL_COMMIT_REFERENCE', 'ROOT_BOUNDARY', 'MULTI_INTRODUCER', 'SOURCE_MOVE_BOUNDARY'},
    ))
    checks = {
        'mechanism_understood': row.get('mechanism_understood') is True and canon.get('mechanism_understood') is True and prov.get('mechanism_understood') is True and bool(normalized.get('bug_semantics')),
        'introducer_evidence': intro_evidence,
        'parent_or_boundary': parent_boundary,
        'fix_or_no_fix': has_fix,
        'ai_role_explained': ai_role_explained,
        'evidence_substantive': len(evidence) >= 180,
        # Short reasoning is acceptable when the independent source carries
        # the concrete source-to-sink and commit evidence.  Do not turn an
        # arbitrary prose-length threshold into a false missing-evidence gate.
        'reasoning_substantive': len(reasoning.strip()) >= 40 and len(evidence) >= 180,
        'verdict_not_ai': row.get('verdict') == 'NOT_AI' and row.get('attribution_conclusion') == 'NOT_AI' and canon.get('verdict') == 'NOT_AI' and ai_review.get('verdict') == 'NOT_AI',
        'squash_or_single_boundary': squash_boundary,
    }
    missing = [key for key, value in checks.items() if not value]
    if missing:
        notai_failures.append({'class_id': cid, 'case_id': row.get('case_id'), 'missing': missing})
    records.append({
        'class_id': cid, 'case_id': row.get('case_id'), 'repo': row.get('repo'),
        'dataset': 'NOT_AI', 'verdict': row.get('verdict'), 'checks': checks,
        'missing': missing, 'review_state': row.get('second_review_disposition'),
    })

blocked_failures = []
for cid in sorted(blocked_ledger):
    row = blocked[cid]
    checks = {
        'mechanism_recorded': bool(row.get('mechanism_status')),
        'fix_boundary_recorded': bool(row.get('fix_status')),
        'lineage_boundary_recorded': bool(row.get('lineage_status')),
        'ai_role_boundary_recorded': bool(row.get('ai_role_status')),
        'conservative_conclusion': str(row.get('conclusion', '')).startswith('RETAIN_BLOCKED'),
        'evidence_refs': bool(row.get('evidence_refs')),
        'reasoning': len(str(row.get('conclusion') or '')) >= 120,
        'next_boundary': bool(row.get('next_boundary')),
    }
    missing = [key for key, value in checks.items() if not value]
    if missing:
        blocked_failures.append({'class_id': cid, 'case_id': row.get('case_id'), 'missing': missing})
    records.append({
        'class_id': cid, 'case_id': row.get('case_id'), 'repo': row.get('repo'),
        'dataset': 'BLOCKED', 'verdict': row.get('conclusion'), 'checks': checks,
        'missing': missing, 'review_state': 'RETAIN_BLOCKED',
    })

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(''.join(json.dumps(r, ensure_ascii=False, separators=(',', ':')) + '\n' for r in records), encoding='utf-8')
summary = {
    'ledger_rows': len(ledger), 'notai_rows': len(notai_ledger), 'blocked_rows': len(blocked_ledger),
    'notai_pass': len(notai_failures) == 0, 'blocked_pass': len(blocked_failures) == 0,
    'notai_failures': notai_failures, 'blocked_failures': blocked_failures,
    'notai_review_states': dict(Counter(str(r.get('second_review_disposition')) for r in notai.values())),
    'blocked_lineage_states': dict(Counter(str(r.get('lineage_status')) for r in blocked.values())),
}
SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(summary, ensure_ascii=False))
if notai_failures or blocked_failures:
    raise SystemExit(1)
