#!/usr/bin/env python3
"""Batched git metadata extractor for round7 BIC verification.

Usage:
  python3 scripts/gitmeta.py <repo_slug> <sha-or-ref> [more...]

For each ref, prints: full sha, short, author, committer, author-date,
subject, parent(s), and any AI-related trailers (Co-Authored-By,
Generated-with, etc.). Also prints `git log -1 --format` raw for the
commit. All git calls are NUMA-pinned to node 1.
"""
import os
import re
import subprocess
import sys

REPOS = '/home/hanqing/agents/ai-slop/.ai-slop/state/repos'
AI_TRAILER = re.compile(
    r'^(co-authored-by|generated-with|generated-by|ai-model|ai-author'
    r'|co-developed-by|created-with|tool|signed-off-by).*$',
    re.I,
)


def git(repo: str, *args: str) -> str:
    env = dict(os.environ)
    cmd = ['numactl', '--cpunodebind=1', '--membind=1', 'git', '-C', f'{REPOS}/{repo}'] + list(args)
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return p.stdout


def main() -> int:
    if len(sys.argv) < 3:
        print('usage: gitmeta.py <repo_slug> <sha> [sha ...]', file=sys.stderr)
        return 2
    repo = sys.argv[1]
    for ref in sys.argv[2:]:
        # resolve to full sha
        full = git(repo, 'rev-parse', ref).strip()
        if not full:
            print(f'== {ref}: UNRESOLVED')
            continue
        # full metadata
        meta = git(
            repo, 'log', '-1', '--format=%H%n%h%n%an <%ae>%n%cn <%ce>%n%ad%n%P%n%s',
            full,
        ).splitlines()
        # trailers
        trail = git(repo, 'log', '-1', '--format=%B', full)
        ai = [ln for ln in trail.splitlines() if AI_TRAILER.match(ln.strip())]
        print(f'== {ref} -> {full}')
        if len(meta) >= 5:
            print(f'   short: {meta[1]}')
            print(f'   author: {meta[2]}')
            print(f'   committer: {meta[3]}')
            print(f'   date: {meta[4]}')
            print(f'   parent(s): {meta[5]}')
            print(f'   subject: {meta[6] if len(meta) > 6 else ""}')
        if ai:
            print(f'   AI trailers: {ai}')
        else:
            print('   AI trailers: none')
    return 0


if __name__ == '__main__':
    sys.exit(main())
