from collections import Counter
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / 'artifacts/funnel-account-20260817.jsonl'
OUT = ROOT / '.ai-slop/state/notai-review/notai-coverage-audit-20260819.jsonl'
SUMMARY = ROOT / '.ai-slop/state/notai-review/notai-coverage-summary-20260819.md'
STRUCTURED = ROOT / '.ai-slop/state/notai-review/notai-causal-canonical-20260819.jsonl'

ledger = [json.loads(x) for x in LEDGER.read_text(encoding='utf-8').splitlines() if x.strip()]
notai = [x for x in ledger if x.get('status') == 'NOT_AI']
NO_FIX_RE = re.compile(
    r"no (?:direct )?fix|no fix upstream|unfixed|still (?:has )?vulnerab|"
    r"remains? vulnerable|project has not responded|no patch|not fixed",
    re.I,
)
GENERIC_ORIGINS = {
    "human",
    "introduced_by_human_commit",
    "human_import_root",
    "missing input validation",
}

def present(value):
    return value not in (None, '', [], {})

def readable_text(value, minimum=30):
    return isinstance(value, str) and len(value.strip()) >= minimum

audit = []
structured = {item['class_id']: item for item in (json.loads(x) for x in STRUCTURED.read_text(encoding='utf-8').splitlines() if x.strip())}
for row in notai:
    research = row.get('causal_research') or {}
    evidence = research.get('evidence')
    evidence_text = json.dumps(evidence, ensure_ascii=False) if not isinstance(evidence, str) else evidence
    shape = structured.get(row['class_id'], {})
    lineage_boundary_verified = (
        shape.get('parent_sha_verified') is True
        or shape.get('root_boundary_verified') is True
        or shape.get('multi_introducer_parent_map') is True
    )
    direct_fix_or_no_fix = (
        present(research.get('direct_fix_sha'))
        or present(research.get('fix_sha'))
        or research.get('no_fix_proven') is True
        or research.get('head_still_vulnerable') is True
        or bool(NO_FIX_RE.search(
            evidence_text + ' ' + str(research.get('no_fix_evidence', '')) + ' '
            + str(research.get('reasoning', ''))
        ))
    )
    flags = {
        'bug_semantics': present(research.get('bug_semantics')),
        'specific_flaw_origin': (
            present(research.get('flaw_origin'))
            and str(research.get('flaw_origin')).strip().lower() not in GENERIC_ORIGINS
            and len(str(research.get('flaw_origin')).strip()) >= 80
        ),
        'introducer_sha': present(research.get('introducer_sha')),
        'lineage_boundary_verified': lineage_boundary_verified,
        'direct_fix_sha': direct_fix_or_no_fix,
        'ai_marker': present(research.get('ai_marker')),
        'evidence': readable_text(evidence),
        'reasoning': readable_text(research.get('reasoning')),
    }
    flags['verdict'] = research.get('verdict') == 'NOT_AI'
    flags['squash_reviewed'] = shape.get('squash_shape_valid', False)
    introducers = research.get('introducer_shas') or ([research.get('introducer_sha')] if present(research.get('introducer_sha')) else [])
    flags['single_or_mapped_lineage'] = len(introducers) <= 1 or shape.get('multi_introducer_parent_map', False)
    flags['multi_introducer_parents_mapped'] = (
        len(introducers) <= 1
        or (
            isinstance(research.get('introducer_parent_map'), dict)
            and len(research['introducer_parent_map']) == len(introducers)
        )
    )
    gate_pass = all(flags.values())
    audit.append({
        'class_id': row['class_id'], 'repo': row.get('repo'), 'verdict': research.get('verdict'),
        'attribution_status': research.get('attribution_status'),
        'remediation_status': research.get('remediation_status'),
        'lineage_status': research.get('lineage_status'),
        'causal_review_status': research.get('causal_review_status'),
        'review_state': research.get('review_state'), 'flags': flags,
        'lineage_boundary_verified': lineage_boundary_verified,
        'parent_absence': shape.get('root_boundary_verified') is True,
        'direct_fix_or_no_fix': direct_fix_or_no_fix,
        'missing': [key for key, value in flags.items() if not value], 'gate_pass': gate_pass,
        'lineage_gap': shape.get('lineage_gap', True), 'parent_boundary': shape.get('parent_boundary'),
    })
OUT.write_text(''.join(json.dumps(x, ensure_ascii=False, separators=(',', ':')) + '\n' for x in audit), encoding='utf-8')
counts = Counter((row.get('causal_research') or {}).get('causal_review_status') or 'DIMENSIONS_MISSING' for row in notai)
SUMMARY.write_text('# NOT_AI causal coverage audit\n\nThis audit consumes canonical ledger causal_research for the current NOT_AI denominator.\n\n'
    + '\n'.join(f'- {k}: {counts[k]}' for k in sorted(counts))
    + f'\n\nNOT_AI is attribution, not remediation status.\nRows audited: {len(audit)}\nEvidence-gate rows: {sum(x["gate_pass"] for x in audit)}\n', encoding='utf-8')
print(dict(counts)); print('rows', len(audit)); print('evidence_gate_pass', sum(x['gate_pass'] for x in audit)); print('lineage_gap', sum(x['lineage_gap'] for x in audit))
