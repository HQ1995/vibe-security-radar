#!/usr/bin/env python3
"""Select the round7 priority pool: 200 highest-opportunity PARTIALLY_ANALYZED cases.

Opportunity tiers (deterministic, reproducible from the ledger + census):

C  TP-flip candidates: rows the ledger already flags as AI-adjacent but which
   never closed - ledger_best in {AI_FAULT_LEGACY, CAUSAL_CHAIN_CLOSED} or a
   site_scope is present. Closing one of these can flip the row to a terminal
   TP (AI_ROOT_CAUSE / AI_CODE_FLAWED). All 90 selected.
A  partial-wave re-review: row verdict NOT_AI with both introducer_sha and
   fix_sha on record and a usable local clone. These rows carry
   CAUSAL_REVIEW_PENDING; protocol requires BIC-level re-verification
   (parent absence, AI marker on the vulnerable lines only). Top 90, ranked
   by AI-marker signal on the partial-wave entry, then by recency of the
   fix_sha (shorter tail = fresher evidence).
D  round6 EVIDENCE_GAP rows whose only recorded gap is advisory-identity
   pinning and whose class resolves (census class-repo-precise) to a real
   public repo with a cached clone. Top 20.

Score is triage metadata, not a verdict. Workers must establish mechanism ->
atomic introducer -> parent boundary -> direct fix -> squash decomposition ->
AI role before the ledger is updated.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path('/home/hanqing/agents/ai-slop')
LEDGER = ROOT / 'artifacts/funnel-account-20260817.jsonl'
CENSUS = ROOT / '.ai-slop/state/census-research/class-repo-precise.jsonl'
REPOTS = ROOT / '.ai-slop/state/repos'
OUT = ROOT / '.ai-slop/state/research-queue/round7/priority-pool.jsonl'

TARGET = 200
QUOTA = {'C': 90, 'A': 90, 'D': 20}

AI_SIGNAL = re.compile(
    r'claude|copilot|co-author|cursor|codex|generated with|gemini|chatgpt', re.I
)


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def repo_slug_names() -> set[str]:
    return {p.name for p in REPOTS.iterdir() if p.is_dir()}


def have_clone(repo: str, cache: set[str]) -> bool:
    if not repo:
        return False
    s = repo.replace('/', '_')
    if s in cache:
        return True
    o, sep, n = repo.partition('/')
    if not sep:
        return False
    return any(c.lower().endswith(n.lower()) for c in cache if c.lower().split('_')[0] == o.lower())


def main() -> int:
    rows = load_jsonl(LEDGER)
    assert len(rows) == len({r['class_id'] for r in rows})
    pa = [r for r in rows if r.get('status') == 'PARTIALLY_ANALYZED']

    precise: dict[str, str] = {}
    for p in load_jsonl(CENSUS):
        cid, repos = p.get('class_id'), p.get('repos') or []
        if cid and repos:
            precise[cid] = repos[0].replace('github.com/', '')

    def real_repo(r: dict) -> str:
        rr = precise.get(r['class_id'])
        if rr and not rr.startswith('git.'):
            return rr.replace('gitlab.com/', '')
        return r.get('repo') or ''

    cache = repo_slug_names()

    # ---- Tier C: TP-flip candidates -------------------------------------
    tier_c = [
        r for r in pa
        if r.get('ledger_best') in ('AI_FAULT_LEGACY', 'CAUSAL_CHAIN_CLOSED')
        or r.get('site_scope')
    ]

    # ---- Tier A: partial-wave NOT_AI re-review --------------------------
    tier_a = []
    for r in pa:
        pw = r.get('partial_wave') or []
        e = pw[0] if pw else {}
        if (
            r.get('partial_wave_verdict') == 'NOT_AI'
            and e.get('introducer_sha') and e.get('fix_sha')
            and have_clone(real_repo(r), cache)
            and r['class_id'] not in {x['class_id'] for x in tier_c}
        ):
            sig = 1 if AI_SIGNAL.search(e.get('ai_marker') or '') else 0
            tier_a.append((sig, str(e.get('fix_sha') or ''), r['class_id'], r))

    # ---- Tier D: round6 identity-pinning gaps ---------------------------
    tier_c_ids = {x['class_id'] for x in tier_c}
    tier_a_ids = {x[2] for x in tier_a}
    tier_d = []
    for r in pa:
        if r['class_id'] in tier_c_ids or r['class_id'] in tier_a_ids:
            continue
        if r.get('round6_verdict') != 'EVIDENCE_GAP':
            continue
        rr = real_repo(r)
        if rr == r.get('repo') and r.get('repo') in ('pypa/advisory-database', 'rubysec/ruby-advisory-db'):
            continue  # real repo not recoverable -> not actionable here
        if not have_clone(rr, cache):
            continue
        gap = ((r.get('round6_research') or {}).get('remaining_gap') or '').lower()
        if 'unpublished' in gap or 'unavailable' in gap:
            continue
        tier_d.append(r)

    # ---- Assemble with quotas, deterministic ----------------------------
    picked: list[tuple[str, int, dict]] = []
    picked_ids: set[str] = set()

    def add(tier: str, rank: int, row: dict, reason: str) -> None:
        picked_ids.add(row['class_id'])
        picked.append((tier, rank, {
            'class_id': row['class_id'],
            'repo': row.get('repo'),
            'real_repo': real_repo(row),
            'advisories': row.get('advisories'),
            'advisory_identity': row.get('advisory_identity'),
            'tier': tier,
            'score': rank,
            'selection_reason': reason,
            'status_before': row.get('status'),
            'ledger_best': row.get('ledger_best'),
            'site_scope': row.get('site_scope'),
            'site_tier': row.get('site_tier'),
            'partial_wave_verdict': row.get('partial_wave_verdict'),
            'round6_verdict': row.get('round6_verdict'),
            'selection_state': 'pending',
            'evidence': {
                'partial_wave': row.get('partial_wave'),
                'round6_research': row.get('round6_research'),
                'squash_audit': row.get('squash_audit'),
            },
        }))

    n_c = 0
    for i, r in enumerate(tier_c, 1):
        why = r.get('site_scope') or r.get('ledger_best')
        add('C', i, r, f'tp-flip candidate ({why})')
        n_c += 1
    assert n_c <= QUOTA['C'], f'tier C has {n_c} > quota {QUOTA["C"]}'

    tier_a.sort(key=lambda t: (-t[0], t[2]))
    n_a = 0
    for sig, _, cid, r in tier_a:
        if n_a >= QUOTA['A']:
            break
        e = (r.get('partial_wave') or [{}])[0]
        add('A', n_a + 1, r,
            f'partial-wave NOT_AI re-review; ai_signal={sig}; '
            f'introducer={e.get("introducer_sha", "")[:12]} fix={e.get("fix_sha", "")[:12]}')
        n_a += 1

    tier_d.sort(key=lambda r: r['class_id'])
    n_d = 0
    for r in tier_d:
        if n_d >= QUOTA['D']:
            break
        add('D', n_d + 1, r,
            f'round6 identity-pinning gap; real repo {real_repo(r)} cached')
        n_d += 1

    assert len(picked) == TARGET, f'selected {len(picked)} != {TARGET}'
    assert len(picked_ids) == len(picked)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    compact = dict(ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    OUT.write_text('\n'.join(json.dumps(p[2], **compact) for p in picked) + '\n')

    from collections import Counter
    print(json.dumps({
        'ledger_rows': len(rows),
        'partial_rows': len(pa),
        'selected': len(picked),
        'tiers': dict(Counter(p[0] for p in picked)),
        'pool': str(OUT),
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
