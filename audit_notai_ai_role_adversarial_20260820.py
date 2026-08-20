#!/usr/bin/env python3
"""Adversarial consistency check for the current NOT_AI causal dossiers."""
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / 'artifacts/funnel-account-20260817.jsonl'
CANON = ROOT / '.ai-slop/state/notai-review/notai-causal-canonical-20260819.jsonl'
DIRECT = ROOT / '.ai-slop/state/notai-review/notai-direct-recheck-20260819.jsonl'
AI_ROLE = ROOT / '.ai-slop/state/notai-review/notai-ai-role-review-20260820.jsonl'
OUT = ROOT / '.ai-slop/state/notai-review/notai-ai-role-adversarial-20260820.jsonl'

def read(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]

def text_fields(row):
    return ' '.join(str(row.get(key) or '') for key in (
        'ai_marker', 'flaw_origin', 'evidence', 'reasoning', 'remaining_gap',
        'source_kind', 'source_commands', 'fix_sha', 'direct_fix_sha',
    ))

def main():
    ledger = {row['class_id']: row for row in read(LEDGER) if row.get('status') == 'NOT_AI'}
    canon = {row['class_id']: row for row in read(CANON)}
    direct = {row['class_id']: row for row in read(DIRECT)}
    ai_role = {row['class_id']: row for row in read(AI_ROLE)}
    if set(ledger) != set(canon):
        raise SystemExit(f'NOT_AI denominator is not aligned: ledger={len(ledger)} canonical={len(canon)}')
    records = []
    for cid in sorted(ledger):
        review = ai_role[cid]
        role_class = review.get('ai_role_class')
        remediation = (ledger[cid].get('causal_research') or {}).get('remediation_status')
        # The role review is the semantic source of truth.  Raw keyword hits
        # are intentionally not used: negative sentences such as "no Copilot
        # marker" must not become positive AI evidence.
        positive_role = role_class in {'AI_FIX_ONLY', 'AI_DOCUMENTATION_ONLY', 'AI_CODE_ORIGIN', 'AI_ASSISTED_ORIGIN'}
        hits = [{'role_class': role_class}] if positive_role else []
        negative = [0] if role_class in {'NO_CAUSAL_AI_MARKER', 'NO_AI_ROLE_MARKER_REMEDIATION_CAVEAT'} else []
        challenge = role_class in {'AI_CODE_ORIGIN', 'AI_ASSISTED_ORIGIN'} or (
            role_class == 'AI_FIX_ONLY' and remediation != 'FIX_VERIFIED'
        )
        records.append({
            'class_id': cid,
            'repo': ledger[cid].get('repo'),
            'case_id': (ledger[cid].get('causal_research') or {}).get('case_id'),
            'verdict': (ledger[cid].get('causal_research') or {}).get('verdict'),
            'ai_role_positive_hits': hits,
            'ai_role_negative_evidence_sources': negative,
            'remediation_status': remediation,
            'incomplete_or_residual_fix_is_explicit': remediation in {
                'FIXED_AFTER_INCOMPLETE_INTERMEDIATE_FIX',
                'FIX_WITH_KNOWN_DNS_REBINDING_RESIDUAL',
                'NO_FIX_HEAD_STILL_VULNERABLE',
            },
            'status': 'REVIEW_REQUIRED' if challenge else ('AI_ROLE_RECORDED_NO_CODE_ORIGIN' if positive_role else 'NO_POSITIVE_AI_ROLE_EVIDENCE'),
        })
    OUT.write_text(''.join(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n' for row in records), encoding='utf-8')
    print(json.dumps({
        'rows': len(records),
        'positive_ai_role_rows': sum(bool(row['ai_role_positive_hits']) for row in records),
        'review_required': [row['class_id'] for row in records if row['status'] == 'REVIEW_REQUIRED'],
        'explicit_incomplete_or_residual_fix_rows': sum(row['incomplete_or_residual_fix_is_explicit'] for row in records),
        'remediation': dict(Counter(row['remediation_status'] for row in records)),
        'ai_role_classes': dict(Counter(ai_role[row['class_id']].get('ai_role_class') for row in records)),
        'output': str(OUT),
    }, ensure_ascii=False))

if __name__ == '__main__':
    main()
