#!/usr/bin/env python3
"""Leader replay verifier for wave-2 worker proposals (local, no API).

Checks only what local git objects can prove:
  - candidate and fix SHAs resolve in a local clone
  - candidate commit carries an explicit AI trailer/identity
  - candidate is an ancestor of the minimum fix in that clone
Anything not provable locally is UNVERIFIED, never FAIL.
"""
import json, os, re, subprocess, sys
from pathlib import Path

CLONE_ROOTS = [
    Path('/home/hanqing/.cache/ghsa200-worker-clones'),
    Path('/home/hanqing/agents/ai-slop/.ai-slop/cache/cve-analyzer/repos'),
]
AI_RE = re.compile(
    r'(Co-Authored-By:|Assisted-by:|Authored-by:|\bCodex\b|\bClaude (Code|Opus|Sonnet)\b|\bCopilot\b|\bCursor\b|\bDevin\b|\bJules\b|\bRovo\b|\bQwen Code\b|\bOpenWork\b|\bQoder\b|\bCodeRabbit\b|\bKimi\b|\bGrok\b|\bTrae\b)',
    re.I)

def find_clone(repo):
    if not repo: return None
    owner, _, name = repo.partition('/')
    for root in CLONE_ROOTS:
        for cand in root.rglob(f'{owner}__{name}/.git'):
            if cand.is_dir(): return cand.parent
    for root in CLONE_ROOTS:
        for cand in root.rglob('.git'):
            if cand.is_dir():
                try:
                    out = subprocess.run(['git','-C',str(cand.parent),'remote','get-url','origin'],
                                         capture_output=True,text=True,timeout=5).stdout.strip()
                    if f'{owner}/{name}' in out: return cand.parent
                except Exception: pass
    return None

def git(clone, *args):
    return subprocess.run(['git','--no-optional-locks','-C',str(clone)]+list(args),
                          capture_output=True,text=True,timeout=20)

def resolve(clone, sha):
    if not sha or not clone: return False
    return git(clone,'cat-file','-e',f'{sha}^{{commit}}').returncode == 0

def message(clone, sha):
    r = git(clone,'log','-1','--format=%B',sha)
    return r.stdout if r.returncode == 0 else ''

def ancestor(clone, a, b):
    r = git(clone,'merge-base','--is-ancestor',a,b)
    return r.returncode == 0

def check(row):
    repo = row.get('repository'); clone = find_clone(repo)
    cand = (row.get('candidate_set') or [None])[0]
    fix = (row.get('minimum_fix_set') or [None])[0]
    res = {'case_id': row.get('case_id'), 'repository': repo,
           'clone': str(clone) if clone else None}
    res['candidate_resolvable'] = resolve(clone, cand)
    res['fix_resolvable'] = resolve(clone, fix)
    msg = message(clone, cand) if (clone and cand) else ''
    res['ai_marker_in_candidate'] = bool(AI_RE.search(msg))
    res['candidate_ancestor_of_fix'] = (
        ancestor(clone, cand, fix) if (clone and cand and fix and res['candidate_resolvable'] and res['fix_resolvable']) else None)
    res['verified'] = bool(clone and res['candidate_resolvable'] and res['fix_resolvable']
                           and res['ai_marker_in_candidate'])
    return res

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: leader_replay.py proposals.jsonl'); sys.exit(2)
    rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    out = [check(r) for r in rows]
    print(json.dumps(out, indent=1))
    verified = sum(1 for r in out if r['verified'])
    print(f'LOCAL_VERIFIED={verified}/{len(rows)}', file=sys.stderr)
