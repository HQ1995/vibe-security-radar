#!/usr/bin/env python3
"""Shared local-clone lookup helpers for the research-ledger build steps.

Finds candidate git clones across every pool the workers/cve-analyzer use,
with lazy-fetch disabled so stale partial clones fail fast instead of hanging
on network. Imported by publish_research_ledger.py and build_site_enrichment.py.
"""
import os, glob, subprocess

SWEEP = '/home/hanqing/.cache/ghsa200-sweep-fetch'
CVE_REPOS = '/home/hanqing/.cache/cve-analyzer/repos'
WORKER_CLONES = '/home/hanqing/.cache/ghsa200-worker-clones'

_GIT_ENV = dict(os.environ)
_GIT_ENV['GIT_NO_LAZY_FETCH'] = '1'
_GIT_ENV['GIT_TERMINAL_PROMPT'] = '0'

def git(path, *a, timeout=20):
    try:
        return subprocess.run(['git','--no-optional-locks','-C',path]+list(a),
                              capture_output=True,text=True,timeout=timeout,env=_GIT_ENV)
    except subprocess.TimeoutExpired:
        return None

def find_clones(repo):
    if not repo: return []
    o, n = (repo.split('/') + [''])[:2] if '/' in repo else ('', repo)
    cands = [os.path.join(SWEEP, f'{o}__{n}'),
             os.path.join(CVE_REPOS, f'{o}_{n}'),
             os.path.join(CVE_REPOS, f'{o.lower()}_{n.lower()}')]
    for pat in (f'{WORKER_CLONES}/*/clones/{o}__{n}', f'{WORKER_CLONES}/*/clones/{n}',
                f'{WORKER_CLONES}/*/clones/{n.lower()}', f'{WORKER_CLONES}/*/clones/{o}_{n}',
                '/tmp/*/clones/' + n, '/tmp/*/clones/' + n.lower()):
        cands += glob.glob(pat)
    out = []
    for c in cands:
        if c not in out and os.path.isdir(c):
            out.append(c)
    return out

def clone_with_commit(repo, sha):
    """First clone in the pools that actually contains sha (no lazy fetch)."""
    for path in find_clones(repo):
        m = git(path, 'cat-file', '-e', sha, timeout=8)
        if m is not None and m.returncode == 0:
            return path
    return None

def commit_text(path, sha, timeout=20):
    m = git(path, 'log', '-1', '--format=%an%x1f%ae%x1f%s%x1f%b', sha, timeout=timeout)
    if m is None or m.returncode != 0:
        return None
    parts = m.stdout.split('\x1f', 3)
    return {'author_name': parts[0] if len(parts)>0 else '',
            'author_email': parts[1] if len(parts)>1 else '',
            'subject': parts[2].splitlines()[0] if len(parts)>2 else '',
            'body': parts[3] if len(parts)>3 else ''}
