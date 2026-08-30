#!/usr/bin/env python3
"""Generate round7 18-key data for the 86 B1 (embedded-SHA) cases.

B1 cases are PRE-ADJUDICATED: evidence.partial_wave[0] (or squash_audit[0]
when partial_wave is empty) already carries verdict/ai_marker/reasoning/
bug_semantics/flaw_origin/fix_sha/decomposed_shas/squash_decomposed/
introducer_sha. This generator does mechanical backfill:

  - introducer_sha = base.introducer_sha.split(',')[0]  (comma-chain BIC)
  - introducer_parent = git rev-parse <sha>^  (NUMA-bound, batched per repo)
  - advisory_ids = ledger.advisory_identity.member_ids
                   or round6 alias-map[class_id]
                   or []
  - case_id = advisory_ids[0] if advisory_ids else None
  - verdict = NOT_AI  (both OVERTURN and NOT_AI map here)
  - fix_sha = base.fix_sha (None for the 18 OVERTURN/unpatched)
  - direct_fix_sha = fix_sha
  - bug_semantics/flaw_origin/reasoning/evidence/ai_marker VERBATIM from base
  - introducer_parent_absent = True (clean BIC: flaw absent in parent)

Output: /tmp/b1_data.json (list of 18-key dicts) -> feed to emit_round7.py.
"""
import json
import os
import re
import subprocess
from collections import defaultdict

REPO_ROOT = '/home/hanqing/agents/ai-slop'
ROUND7 = f'{REPO_ROOT}/.ai-slop/state/research-queue/round7'
REPOS = f'{REPO_ROOT}/.ai-slop/state/repos'
LEDGER = f'{REPO_ROOT}/artifacts/funnel-account-20260817.jsonl'
AMAP = f'{REPO_ROOT}/.ai-slop/state/research-queue/round6/.alias_class_member_map.json'
OUT = '/tmp/b1_data.json'


def git_parent(repo_slug: str, shas: list) -> tuple:
    """Resolve parent SHAs per-SHA via `git cat-file commit <sha>` (NUMA node 1).

    Reads the commit object directly, which stores the parent SHA even when the
    parent object itself is not fetched. Returns (parents, missing) where:
      parents = {sha: parent_sha or None}   (None for root commits)
      missing = set() of SHAs whose commit object is not present in the clone
    Per-SHA so one bad ref can't poison the batch.
    """
    if not shas:
        return {}, set()
    repo_dir = f'{REPOS}/{repo_slug}'
    parents, missing = {}, set()
    for s in shas:
        p = subprocess.run(
            ['numactl', '--cpunodebind=1', '--membind=1', 'git', '-C', repo_dir,
             'cat-file', 'commit', s],
            capture_output=True, text=True,
        )
        if p.returncode != 0:
            parents[s] = None
            missing.add(s)
            continue
        parent = None
        for ln in p.stdout.splitlines():
            if ln.startswith('parent '):
                parent = ln.split()[1]
                break
        parents[s] = parent
    return parents, missing


def pick_introducer(raw):
    """Evidence introducer_sha may be a comma chain, a ' + ' chain, a 41-char
    truncation, or SHA+trailing-text concatenation. Take the first 40-char hex
    prefix of the first segment (the BIC)."""
    if not raw:
        return raw
    first = raw.split(',')[0].strip()
    m = re.match(r'[0-9a-f]{40}', first)
    if m:
        return m.group(0)
    m2 = re.match(r'[0-9a-f]{7,}', first)
    return m2.group(0) if m2 else first


def main():
    cases = [json.loads(l) for l in open(f'{ROUND7}/cases-qZ.jsonl') if l.strip()]

    def has_sha(c):
        ev = c.get('evidence') or {}
        for w in (ev.get('partial_wave') or []):
            if w.get('introducer_sha'):
                return True
        for s in (ev.get('squash_audit') or []):
            if s.get('introducer_sha'):
                return True
        return False

    b1 = [c for c in cases if has_sha(c) and c.get('real_repo') != 'open-webui/open-webui']
    assert len(b1) == 86, f'expected 86 B1 cases, got {len(b1)}'

    # ledger advisory member_ids
    ledger_adv = {}
    for l in open(LEDGER):
        l = l.strip()
        if not l:
            continue
        r = json.loads(l)
        cid = r.get('class_id')
        if cid:
            ai = r.get('advisory_identity') or {}
            ledger_adv[cid] = ai.get('member_ids') or []
    amap = json.load(open(AMAP))

    # group introducer SHAs by repo for batched parent resolution
    by_repo = defaultdict(set)
    for c in b1:
        ev = c.get('evidence') or {}
        w = (ev.get('partial_wave') or [{}])[0]
        s = (ev.get('squash_audit') or [{}])[0]
        base = w if w.get('introducer_sha') else s
        intro = pick_introducer(base.get('introducer_sha') or '')
        by_repo[c.get('real_repo', '').replace('/', '_')].add(intro)

    parents = {}
    missing = set()
    for slug, shas in by_repo.items():
        p, m = git_parent(slug, sorted(shas))
        parents.update(p)
        missing |= m

    lines = []
    for c in b1:
        cid = c['class_id']
        ev = c.get('evidence') or {}
        w = (ev.get('partial_wave') or [{}])[0]
        s = (ev.get('squash_audit') or [{}])[0]
        base = w if w.get('introducer_sha') else s

        intro = pick_introducer(base.get('introducer_sha') or '')
        parent = parents.get(intro)
        # Truly orphaned: commit object unreachable from origin (force-push/rebase).
        # Verdict stands on round6 pre-adjudication; parent SHA not computable.
        # Root commit: object present, no parent line -> parent=None, absent=True.
        orphaned = intro in missing
        gap = (
            f'BIC {intro} orphaned from origin (unreachable after force-push/rebase); '
            f'introducer_parent not computable; verdict stands on round6 pre-adjudication'
        ) if orphaned else None

        adv = ledger_adv.get(cid) or amap.get(cid) or []
        fix = base.get('fix_sha')

        line = {
            'class_id': cid,
            'case_id': adv[0] if adv else None,
            'repo': c.get('real_repo'),
            'advisory_ids': adv,
            'bug_semantics': base.get('bug_semantics'),
            'flaw_origin': base.get('flaw_origin'),
            'introducer_sha': intro,
            'introducer_parent': parent,
            'introducer_parent_absent': None if orphaned else True,
            'squash_decomposed': bool(base.get('squash_decomposed')),
            'decomposed_shas': base.get('decomposed_shas') or [],
            'ai_marker': base.get('ai_marker'),
            'verdict': 'NOT_AI',
            'fix_sha': fix,
            'direct_fix_sha': fix,
            'evidence': base.get('evidence'),
            'reasoning': base.get('reasoning'),
            'remaining_gap': gap,
        }
        lines.append(line)
        flag = ' ORPHANED' if orphaned else ''
        print(f'ASSEMBLED {cid} NOT_AI adv={len(adv)} fix={"Y" if fix else "N"}{flag}')

    with open(OUT, 'w') as f:
        json.dump(lines, f)
    print(f'DATA_READY {len(lines)} -> {OUT} (feed to scripts/emit_round7.py)')


if __name__ == '__main__':
    main()
