#!/usr/bin/env python3
import json, os, re, sys
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, '/home/hanqing/agents/ai-slop/scripts')
from research_lib import git, find_clones, commit_text

ROOT = '/home/hanqing/agents/ai-slop'
WORK = '/home/hanqing/agents/ai-slop/autoresearch/herdr-260815-aimarker-blindspot'
SINCE = '2025-05-01'
UNTIL = '2026-08-16'

TOOLS = r'claude|codex|copilot|cursor|gpt|chatgpt|openai|anthropic|gemini|grok|qwen|kimi|devin|trae|rovo|jules|qoder|coderabbit|perplexity|windsurf|aider|mintlify|lovable|replit'
ATTRIB = re.compile(
    r'(made[- ]with|made[- ]by|generated[- ]with|generated[- ]by|authored[- ]with|'
    r'authored[- ]by|built[- ]with|written[- ]with|coded[- ]with|developed[- ]with|'
    r'created[- ]with)\s*[:by]?\s*(' + TOOLS + r')', re.I)

def scan_repo(repo):
    cands = sorted(find_clones(repo), key=lambda c: os.path.exists(os.path.join(c, '.git', 'shallow')))
    out = []
    for c in cands:
        r = git(c, 'log', '--no-merges', f'--since={SINCE}', f'--until={UNTIL}',
                '--format=%x1e%H%x1f%an%x1f%ae%x1f%s%x1f%b', timeout=300)
        if r is None or r.returncode != 0:
            continue
        for rec in r.stdout.split('\x1e'):
            rec = rec.strip()
            if not rec:
                continue
            parts = rec.split('\x1f', 4)
            if len(parts) < 5:
                continue
            sha, an, ae, subj, body = parts
            full = subj + '\n' + body
            m = ATTRIB.search(full)
            if not m:
                continue
            # is it a co-auth trailer naming a tool? (would be "marked")
            marked = False
            for line in body.splitlines():
                if 'co-auth' in line.lower() and re.search(TOOLS, line, re.I):
                    marked = True
                    break
            if marked:
                continue
            out.append({'repo': repo, 'sha': sha, 'author_name': an,
                        'author_email': ae, 'subject': subj,
                        'attribution': m.group(0), 'tool': m.group(2),
                        'verb': m.group(1)})
        break
    return repo, out

def main():
    census = json.load(open(f'{ROOT}/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-commit-census.json'))
    repos = sorted(census['per_repo'].keys())
    results = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        for repo, out in ex.map(scan_repo, repos):
            results[repo] = out
            if out:
                print(f'{repo}: {len(out)} attribution commits')
    total = sum(len(v) for v in results.values())
    print('TOTAL attribution-verb unmarked commits:', total)
    with open(f'{WORK}/attribution_commits.jsonl', 'w') as f:
        for repo, rows in results.items():
            for row in rows:
                f.write(json.dumps(row) + '\n')

if __name__ == '__main__':
    main()
