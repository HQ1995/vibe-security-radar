#!/usr/bin/env python3
"""Audit legacy NOT_AI records without changing the canonical ledger."""
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / 'artifacts/funnel-account-20260817.jsonl'
OUT = ROOT / '.ai-slop/state/notai-review/notai-causal-gate-v4-20260819.jsonl'

NO_FIX_RE = re.compile(r'no (?:direct )?fix|unfixed|still flawed|remains? vulnerable|project has not responded|no patch', re.I)
PARENT_ABSENCE_RE = re.compile(r'parent (?:commit )?(?:has )?no |parent absence|absent in (?:the )?parent|not present in (?:the )?parent|root commit|zero parents|first appears', re.I)

def present(value):
    return value not in (None, '', [], {})

def readable_text(value, minimum=30):
    return isinstance(value, str) and len(value.strip()) >= minimum

def candidate_records(row):
    found = []
    for source in ('causal_research', 'notai_causal_review'):
        value = row.get(source)
        if isinstance(value, dict):
            found.append((source, value))
    value = row.get('partial_wave')
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, dict):
                found.append((f'partial_wave[{index}]', item))
    return found

def audit(row, source, record):
    identity = row.get('advisory_identity') or {}
    evidence = record.get('evidence')
    evidence_text = json.dumps(evidence, ensure_ascii=False) if evidence is not None else ''
    parent_absent = present(record.get('introducer_parent_absent')) or present(record.get('parent_absence'))
    # Some independently produced dossiers keep the structured parent proof
    # under evidence. Treat that as the same gate evidence; do not require a
    # duplicated top-level field merely because the producer used the nested
    # evidence schema.
    if isinstance(evidence, dict):
        parent_absent = parent_absent or present(evidence.get('parent_absence'))
    parent_absent = parent_absent or bool(PARENT_ABSENCE_RE.search(evidence_text))
    no_fix = bool(NO_FIX_RE.search(evidence_text + ' ' + str(record.get('reasoning', '')) + ' ' + str(record.get('flaw_origin', ''))))
    direct_fix = present(record.get('direct_fix_sha')) or present(record.get('fix_sha'))
    fix_closed = direct_fix or no_fix
    squash_value = record.get('squash_decomposed')
    squash_reviewed = isinstance(squash_value, bool) and isinstance(record.get('decomposed_shas', []), list)
    marker = record.get('ai_marker')
    flags = {
        'identity': bool(identity.get('member_ids')) or present(record.get('advisory_ids')) or present(record.get('case_id')),
        'mechanism': present(record.get('bug_semantics')),
        'atomic_introducer': present(record.get('introducer_sha')),
        'parent_absence': parent_absent,
        'direct_fix_or_explicit_no_fix': fix_closed,
        'source_evidence': readable_text(evidence),
        'reasoning': readable_text(record.get('reasoning')),
        'ai_role_evidence': present(marker),
        'squash_reviewed': squash_reviewed,
    }
    verdict = record.get('verdict')
    gate_pass = verdict == 'NOT_AI' and all(flags.values())
    return {
        'class_id': row['class_id'],
        'repo': row.get('repo'),
        'source': source,
        'record_verdict': verdict,
        'gate_pass': gate_pass,
        'missing': [key for key, value in flags.items() if not value],
        'flags': flags,
        'case_id': record.get('case_id'),
        'advisory_ids': identity.get('member_ids') or record.get('advisory_ids') or [],
    }

rows = [json.loads(line) for line in LEDGER.read_text(encoding='utf-8').splitlines() if line.strip()]
legacy = [row for row in rows if row.get('legacy_status') == 'NOT_AI' or row.get('status') == 'NOT_AI']
results = []
for row in legacy:
    candidates = [audit(row, source, record) for source, record in candidate_records(row)]
    passing = [item for item in candidates if item['gate_pass']]
    # Keep every candidate for review, but expose the strongest candidate as the recommendation.
    if passing:
        chosen = passing[0]
        disposition = 'CAUSAL_CHAIN_CLOSED'
    elif candidates:
        chosen = max(candidates, key=lambda item: sum(item['flags'].values()))
        disposition = 'CAUSAL_REVIEW_PENDING'
    else:
        chosen = None
        disposition = 'NO_CAUSAL_RECORD'
    results.append({
        'class_id': row['class_id'],
        'repo': row.get('repo'),
        'current_status': row.get('status'),
        'legacy_status': row.get('legacy_status'),
        'candidate_count': len(candidates),
        'candidate_gate_pass_count': len(passing),
        'recommended_disposition': disposition,
        'best_candidate': chosen,
        'all_candidates': candidates,
    })

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(''.join(json.dumps(item, ensure_ascii=False, separators=(',', ':')) + '\n' for item in results), encoding='utf-8')
print('legacy_not_ai=', len(results))
print('dispositions=', json.dumps(dict(Counter(item['recommended_disposition'] for item in results)), sort_keys=True))
print('candidate_sources=', json.dumps(dict(Counter(item['best_candidate']['source'] if item['best_candidate'] else 'none' for item in results)), sort_keys=True))
print('missing=', json.dumps(dict(Counter(key for item in results for key in ((item['best_candidate'] or {}).get('missing') or []))), sort_keys=True))
print('output=', OUT)
