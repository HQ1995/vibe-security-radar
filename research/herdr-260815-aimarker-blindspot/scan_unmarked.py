#!/usr/bin/env python3
import json, os, re, sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, '/home/hanqing/agents/ai-slop/scripts')
from research_lib import git, find_clones

ROOT = '/home/hanqing/agents/ai-slop'
WORK = '/home/hanqing/agents/ai-slop/autoresearch/herdr-260815-aimarker-blindspot'
SINCE = '2025-05-01'
UNTIL = '2026-08-16'

AI = re.compile(
    r'co-authored-by:|assisted-by:|generated with (claude|codex|copilot|cursor)|'
    r'claude code|claude opus|claude sonnet|github copilot|\bcursor\b|\bdevin\b|'
    r'\bjules\b|\brovo\b|qwen code|openwork|\bqoder\b|coderabbit|\bkimi\b|\bgrok\b|'
    r'\btrae\b|ai-assisted|ai-generated|\[ai\]|\[ai-assisted\]|\[ai-generated\]',
    re.I)

FAMILY_PATTERNS = [
    ('claude_flow', re.compile(r'claude[- ]?flow', re.I)),
    ('copilot', re.compile(r'copilot', re.I)),
    ('cursor', re.compile(r'cursor', re.I)),
    ('openai_gpt_codex', re.compile(r'codex|gpt-|openai', re.I)),
    ('claude', re.compile(r'claude|anthropic', re.I)),
]

def family_of(t):
    for f, p in FAMILY_PATTERNS:
        if p.search(t):
            return f
    return None

def _strong_hits(full):
    return [m.group(0) for m in AI.finditer(full)]

def scan_repo(repo):
    cands = sorted(find_clones(repo), key=lambda c: os.path.exists(os.path.join(c, '.git', 'shallow')))
    r = None
    for c in cands:
        r = git(c, 'log', '--no-merges', f'--since={SINCE}', f'--until={UNTIL}',
                '--format=%x1e%H%x1f%an%x1f%ae%x1f%s%x1f%b', timeout=300)
        if r is not None and r.returncode == 0:
            break
    if r is None or r.returncode != 0:
        return repo, None, 'git_failed'
    out = []
    for rec in r.stdout.split('\x1e'):
        rec = rec.strip()
        if not rec:
            continue
        parts = rec.split('\x1f', 4)
        if len(parts) < 5:
            continue
        sha, an, ae, subj, body = parts
        full = subj + '\n' + body
        trail_f = None
        for line in body.splitlines():
            if 'co-auth' in line.lower():
                trail_f = family_of(line)
                if trail_f:
                    break
        auth_f = family_of(an + ' ' + ae)
        marked = bool(trail_f or auth_f)
        strong = bool(AI.search(full))
        if strong and not marked:
            out.append({'repo': repo, 'sha': sha, 'author_name': an,
                        'author_email': ae, 'subject': subj,
                        'family_hint': family_of(full),
                        'strong_hit': _strong_hits(full)})
    return repo, out, 'ok'

def main():
    census = json.load(open(f'{ROOT}/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-commit-census.json'))
    repos = sorted(census['per_repo'].keys())
    results = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        for repo, out, status in ex.map(scan_repo, repos):
            if out is None:
                print('FAILED', repo, status, file=sys.stderr)
                continue
            results[repo] = out
            print(f'{repo}: {len(out)} unmarked strong-text commits')
    total = sum(len(v) for v in results.values())
    print('TOTAL unmarked strong-text commits:', total)
    with open(f'{WORK}/unmarked_commits.jsonl', 'w') as f:
        for repo, rows in results.items():
            for row in rows:
                f.write(json.dumps(row) + '\n')

if __name__ == '__main__':
    main()
