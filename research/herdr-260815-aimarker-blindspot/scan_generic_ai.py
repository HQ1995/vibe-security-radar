#!/usr/bin/env python3
import json, os, re, sys
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, '/home/hanqing/agents/ai-slop/scripts')
from research_lib import git, find_clones

ROOT = '/home/hanqing/agents/ai-slop'
WORK = '/home/hanqing/agents/ai-slop/autoresearch/herdr-260815-aimarker-blindspot'
SINCE = '2025-05-01'
UNTIL = '2026-08-16'
# generic AI marker in the SUBJECT line, no tool name
GEN = re.compile(r'\[ai\]|\[ai-assisted\]|\[ai-generated\]|\(ai-assisted\)|\bai-assisted\b', re.I)

def scan_repo(repo):
    cands = sorted(find_clones(repo), key=lambda c: os.path.exists(os.path.join(c, '.git', 'shallow')))
    for c in cands:
        r = git(c, 'log', '--no-merges', f'--since={SINCE}', f'--until={UNTIL}',
                '--format=%x1e%H%x1f%an%x1f%ae%x1f%s%x1f%b', timeout=300)
        if r is None or r.returncode != 0:
            continue
        out = []
        for rec in r.stdout.split('\x1e'):
            rec = rec.strip()
            if not rec:
                continue
            parts = rec.split('\x1f', 4)
            if len(parts) < 5:
                continue
            sha, an, ae, subj, body = parts
            if GEN.search(subj):
                out.append({'repo': repo, 'sha': sha, 'author_name': an,
                            'author_email': ae, 'subject': subj})
        return repo, out
    return repo, []

def main():
    census = json.load(open(f'{ROOT}/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-commit-census.json'))
    repos = sorted(census['per_repo'].keys())
    results = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        for repo, out in ex.map(scan_repo, repos):
            results[repo] = out
    total = sum(len(v) for v in results.values())
    print('TOTAL generic [AI] subject commits:', total)
    byrepo = sorted(results.items(), key=lambda kv: -len(kv[1]))
    for repo, out in byrepo:
        if out: print(f'  {repo}: {len(out)}')
    with open(f'{WORK}/generic_ai_commits.jsonl', 'w') as f:
        for repo, rows in results.items():
            for row in rows:
                f.write(json.dumps(row) + '\n')

if __name__ == '__main__':
    main()
