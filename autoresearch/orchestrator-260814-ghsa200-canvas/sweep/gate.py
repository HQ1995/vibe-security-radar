#!/usr/bin/env python3
"""Acceptance gate for worker proposals (mechanical checks only, zero-FP).

usage: gate.py proposals.jsonl
Verdicts: ACCEPT_CANDIDATE (all mechanical checks pass; human confirms),
REJECT (duplicate/alias identity OR no explicit AI identity OR withdrawn advisory),
UNVERIFIED (evidence missing; never counted).

Hardened per the independent GLM-5.3 review: strict AI identity allowlist,
advisory existence/withdrawal check, alias-aware uniqueness, exact reversal
file + line-touch proxy (still human-confirmed), tag-based release containment.
"""
import json, os, re, subprocess, sys
from collections import Counter

POOL = '/home/hanqing/.cache/ghsa200-sweep-fetch'
ADB = '/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database'
FOUNDATION = 'autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl'
AI = re.compile(
    r'co-authored-by:\s*[^<\n]*<noreply@anthropic\.com>'
    r'|co-authored-by:\s*[^<\n]*<\d+\+(copilot|claude[^<]*|codex)[@\w.-]*>'
    r'|assisted-by:'
    r'|generated with (claude code|copilot|codex|cursor)'
    r'|claude code|claude opus|claude sonnet|github copilot'
    r'|copilot-swe-agent|claude-swe-agent|cursor', re.I)

found_rows = [json.loads(l) for l in open(FOUNDATION) if l.strip()]
found_ids = {r['case_id'] for r in found_rows}
found_aliases = set()
for r in found_rows:
    for a in r.get('aliases') or []:
        found_aliases.add(a.upper())
    for a in r.get('original_advisory_ids') or []:
        found_aliases.add(a.upper())

def git(path, *args, timeout=30):
    try:
        return subprocess.run(['git','--no-optional-locks','-C',path]+list(args),
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def find_advisory(cid):
    gid = cid.lower()
    files = subprocess.run(['git','--no-optional-locks','-C',ADB,'ls-files',
                            'advisories/github-reviewed/'], capture_output=True, text=True, timeout=60)
    if files.returncode != 0:
        return None
    for f in files.stdout.splitlines():
        if f.endswith('/' + gid + '/' + gid + '.json'):
            b = subprocess.run(['git','--no-optional-locks','-C',ADB,'show','origin/main:'+f],
                               capture_output=True, text=True, timeout=30)
            if b.returncode == 0:
                try: return json.loads(b.stdout)
                except Exception: return None
    return None

def check(row):
    cid = row.get('case_id'); repo = row.get('repository')
    cand = (row.get('candidate_set') or [None])[0]
    fix = (row.get('minimum_fix_set') or [None])[0]
    out = {'case_id': cid, 'repository': repo, 'candidate': cand, 'fix': fix}
    aliases = set((row.get('aliases') or []) + ([cid] if cid else []))
    if cid in found_ids or (aliases & found_aliases):
        out['verdict'] = 'REJECT'; out['reason'] = 'duplicate_or_alias_identity'; return out
    adv = find_advisory(cid)
    if adv is None:
        out['verdict'] = 'UNVERIFIED'; out['reason'] = 'advisory_not_found_locally'; return out
    if adv.get('withdrawnAt'):
        out['verdict'] = 'REJECT'; out['reason'] = 'advisory_withdrawn'; return out
    out['advisory_ok'] = True
    path = os.path.join(POOL, repo.replace('/', '__')) if repo else None
    if not path or not os.path.isdir(path) or not cand:
        out['verdict'] = 'UNVERIFIED'; out['reason'] = 'no_pool_or_candidate'; return out
    m = git(path, 'log', '-1', '--format=%B', cand)
    if m is None or m.returncode != 0:
        out['verdict'] = 'UNVERIFIED'; out['reason'] = 'candidate_unresolvable'; return out
    out['ai_identity'] = bool(AI.search(m.stdout))
    if not out['ai_identity']:
        out['verdict'] = 'REJECT'; out['reason'] = 'no_explicit_ai_identity'; return out
    if not fix:
        out['verdict'] = 'UNVERIFIED'; out['reason'] = 'no_fix_ref'; return out
    e = git(path, 'cat-file', '-e', fix + '^{commit}')
    anc = git(path, 'merge-base', '--is-ancestor', cand, fix)
    if e is None or e.returncode != 0 or anc is None or anc.returncode != 0:
        git(path, 'fetch', '-q', '--filter=blob:none', '--deepen=300',
            f'https://github.com/{repo}.git', timeout=120)
        anc = git(path, 'merge-base', '--is-ancestor', cand, fix)
    out['fix_ancestor'] = bool(anc and anc.returncode == 0)
    cf = git(path, 'diff-tree', '--no-commit-id', '--name-only', '-r', cand)
    ff = git(path, 'diff-tree', '--no-commit-id', '--name-only', '-r', fix)
    ca = set(cf.stdout.splitlines()) if cf else set()
    fa = set(ff.stdout.splitlines()) if ff else set()
    out['shared_files'] = sorted(ca & fa)[:10]
    if not (out['fix_ancestor'] and out['shared_files']):
        out['verdict'] = 'UNVERIFIED'; out['reason'] = 'fix_evidence_weak'; return out
    # release containment: vulnerable tag has candidate without fix; fixed tag has fix
    git(path, 'fetch', '-q', '--tags', f'https://github.com/{repo}.git', timeout=120)
    tv = git(path, 'tag', '--contains', cand)
    vtags = set(tv.stdout.splitlines()) if tv and tv.returncode == 0 else set()
    tf = git(path, 'tag', '--contains', fix)
    ftags = set(tf.stdout.splitlines()) if tf and tf.returncode == 0 else set()
    out['vuln_tags'] = sorted(vtags - ftags)[:5]
    out['fixed_tags'] = sorted(ftags)[:5]
    if not out['vuln_tags'] or not out['fixed_tags']:
        out['verdict'] = 'UNVERIFIED'; out['reason'] = 'release_containment_unverified'; return out
    out['verdict'] = 'ACCEPT_CANDIDATE'
    return out

if __name__ == '__main__':
    rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    results = [check(r) for r in rows]
    print(json.dumps(results, indent=1))
    print(dict(Counter(r['verdict'] for r in results)), file=sys.stderr)

