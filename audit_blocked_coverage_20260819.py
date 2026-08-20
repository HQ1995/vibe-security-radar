from collections import Counter
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / 'artifacts/funnel-account-20260817.jsonl'
SEMANTIC = ROOT / '.ai-slop/state/blocked-deepwave/blocked-semantic-review-20260819.jsonl'
INDEX = ROOT / '.ai-slop/state/blocked-deepwave/blocked-boundary-evidence-index-20260819.jsonl'
SOURCE_MAP = ROOT / '.ai-slop/state/blocked-deepwave/claude-code-source-map-evidence-20260820.jsonl'
DEEP_REVIEW = ROOT / '.ai-slop/state/blocked-deepwave/claude-deep-review-20260820.jsonl'
SECOND_REVIEW = ROOT / '.ai-slop/state/blocked-deepwave/worker-blocked-second-review-20260820.jsonl'
OUT = ROOT / '.ai-slop/state/blocked-deepwave/blocked-coverage-audit-20260819.jsonl'
SUMMARY = ROOT / '.ai-slop/state/blocked-deepwave/blocked-coverage-summary-20260819.md'
ledger = [json.loads(x) for x in LEDGER.read_text(encoding='utf-8').splitlines() if x.strip()]
semantic = [json.loads(x) for x in SEMANTIC.read_text(encoding='utf-8').splitlines() if x.strip()]
index = [json.loads(x) for x in INDEX.read_text(encoding='utf-8').splitlines() if x.strip()]
source_map = [json.loads(x) for x in SOURCE_MAP.read_text(encoding='utf-8').splitlines() if x.strip()]
deep_review = [json.loads(x) for x in DEEP_REVIEW.read_text(encoding='utf-8').splitlines() if x.strip()]
second_review = [json.loads(x) for x in SECOND_REVIEW.read_text(encoding='utf-8').splitlines() if x.strip()]
blocked = [x for x in ledger if x.get('status') == 'BLOCKED']
blocked_ids = {x['class_id'] for x in blocked}
if (
    len(blocked) != 22
    or len(semantic) != 22
    or len(index) != 22
    or len(second_review) != 22
    or blocked_ids != {x['class_id'] for x in semantic}
    or blocked_ids != {x['class_id'] for x in index}
    or blocked_ids != {x['class_id'] for x in second_review}
):
    raise ValueError('BLOCKED coverage mismatch')
by_id = {x['class_id']: x for x in semantic}
index_by_id = {x['class_id']: x for x in index}
deep_by_id = {x['class_id']: x for x in deep_review}
second_by_id = {x['class_id']: x for x in second_review}
claude_ids = {x['class_id'] for x in blocked if x.get('repo') == 'anthropics/claude-code'}
if len(deep_review) != 20 or set(deep_by_id) != claude_ids:
    raise ValueError('Claude deep-review coverage mismatch')
for cid, review in deep_by_id.items():
    if review.get('conclusion') != 'RETAIN_BLOCKED':
        raise ValueError(f'invalid Claude deep-review disposition for {cid}')
    if not str(review.get('mechanism_status') or '').startswith('UNDERSTOOD_'):
        raise ValueError(f'Claude mechanism status is not specific for {cid}')
    if len(str(review.get('reasoning') or '')) < 200:
        raise ValueError(f'Claude deep-review reasoning is too thin for {cid}')
    for ref in review.get('evidence_refs') or []:
        target = str(ref).split('#', 1)[0]
        if not (ROOT / target).exists():
            raise ValueError(f'missing Claude deep-review evidence for {cid}: {ref}')
for cid, review in second_by_id.items():
    mechanism_status = str(review.get('mechanism_status') or '')
    mechanism_understood = (
        mechanism_status == 'KNOWN'
        or 'UNDERSTOOD' in mechanism_status
        or 'SOURCE_TO_SINK_VERIFIED' in mechanism_status
    )
    if not mechanism_understood:
        raise ValueError(f'BLOCKED detailed mechanism status is not understood for {cid}: {mechanism_status}')
    if not str(review.get('conclusion') or '').startswith('RETAIN_BLOCKED:'):
        raise ValueError(f'invalid detailed BLOCKED disposition for {cid}')
    if len(str(review.get('conclusion') or '')) < 180:
        raise ValueError(f'BLOCKED detailed conclusion is too thin for {cid}')
    if not review.get('next_boundary'):
        raise ValueError(f'missing detailed next boundary for {cid}')
    refs = review.get('evidence_refs') or []
    if not refs:
        raise ValueError(f'missing detailed evidence references for {cid}')
    for ref in refs:
        target = str(ref).split('#', 1)[0]
        if target.startswith(('http://', 'https://')):
            continue
        if not (ROOT / target).exists():
            raise ValueError(f'missing detailed BLOCKED evidence for {cid}: {ref}')
audited = []
for row in blocked:
    old = by_id[row['class_id']]
    indexed = index_by_id[row['class_id']]
    expected_ref = indexed.get('evidence_ref')
    if not expected_ref or not (ROOT / expected_ref).exists():
        raise ValueError(f'missing BLOCKED evidence ref for {row["class_id"]}: {expected_ref}')
    if indexed.get('status') != 'BLOCKED' or indexed.get('github_api_used') is not False:
        raise ValueError(f'invalid BLOCKED index control fields for {row["class_id"]}')
    for key in ('implementation_boundary', 'causal_status', 'fix_status', 'ai_role_status'):
        if indexed.get(key) != row.get('blocked_' + key):
            raise ValueError(f'BLOCKED index/ledger mismatch {row["class_id"]} {key}')
    evidence_text = str(old.get('evidence') or '')
    reasoning_text = str(old.get('reasoning') or '')
    remaining_gap = str(old.get('remaining_gap') or '')
    if old.get('verdict') != 'BLOCKED' or old.get('mechanism_status') != 'KNOWN':
        raise ValueError(f'invalid semantic BLOCKED disposition for {row["class_id"]}')
    if len(evidence_text) < 300 or len(reasoning_text) < 200 or len(remaining_gap) < 150:
        raise ValueError(f'BLOCKED semantic dossier is too thin for {row["class_id"]}')
    if indexed.get('mechanism_understood') is not True:
        raise ValueError(f'missing mechanism understanding for {row["class_id"]}')
    audited.append({
        **old,
        'implementation_boundary': row.get('blocked_implementation_boundary'),
        'causal_status': row.get('blocked_causal_status'),
        'fix_status': row.get('blocked_fix_status'),
        'ai_role_status': row.get('blocked_ai_role_status'),
        'research_confidence': row.get('blocked_research_confidence'),
        'machine_evidence_ref': row.get('blocked_boundary_review_ref'),
        # The semantic review is historical input; the current boundary index
        # is authoritative after the package/bundle review.
        'mechanism_understood': indexed.get('mechanism_understood') is True,
        'indexed_evidence_ref': expected_ref,
        'github_api_used': indexed.get('github_api_used'),
        'semantic_quality': {
            'evidence_chars': len(evidence_text),
            'reasoning_chars': len(reasoning_text),
            'remaining_gap_chars': len(remaining_gap),
            'mechanism_status': old.get('mechanism_status'),
        },
        'source_map_evidence_used': False,
        'deep_review_evidence_used': row.get('repo') == 'anthropics/claude-code',
    })
OUT.write_text(''.join(json.dumps(x, ensure_ascii=False, separators=(',', ':')) + '\n' for x in audited), encoding='utf-8')
counts = Counter(x['causal_status'] for x in audited)
source_map_usable = sum(bool(x.get('class_id')) for x in source_map)
SUMMARY.write_text(
    '# BLOCKED causal coverage audit\n\n'
    'This audit consumes the canonical semantic dossier and boundary index. '
    'The Claude source-map snapshot is raw material only: '
    f'{len(source_map)} records were present, but only {source_map_usable} had a class_id.\n\n'
    + '\n'.join(f'- {k}: {counts[k]}' for k in sorted(counts))
    + f'\n- semantic dossiers with content gate: {len(audited)}/{len(semantic)}\n'
    + f'- Claude deep-review coverage and references: {len(deep_review)}/{len(claude_ids)}\n'
    + f'\nTotal BLOCKED rows audited: {len(semantic)}\n',
    encoding='utf-8',
)
print(dict(counts)); print('rows', len(audited))
print('detailed_second_review_rows', len(second_review))
