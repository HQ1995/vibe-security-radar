#!/usr/bin/env python3
"""Ancestry AI-marker scan over in-window fixrefs (blobless deepen 150)."""
import json, os, re, subprocess, sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

ROOT = '/home/hanqing/.cache/ghsa200-sweep-fetch'
AI = re.compile(r'co-authored-by:|assisted-by:|generated with (claude|codex|copilot|cursor)|claude code|claude opus|claude sonnet|github copilot|\bcursor\b|\bdevin\b|\bjules\b|\brovo\b|qwen code|openwork|\bqoder\b|coderabbit|\bkimi\b|\bgrok\b|\btrae\b|ai-assisted|ai-generated', re.I)
DEPTH = 150

INPUT = sys.argv[1] if len(sys.argv) > 1 else 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fixrefs.jsonl'
OUTPUT = sys.argv[2] if len(sys.argv) > 2 else 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-ancestry-candidates.jsonl'
rows = [json.loads(l) for l in open(INPUT) if l.strip()]
rows = [r for r in rows if r.get('repository')]
rows = [r for r in rows if (r.get('published') or '') >= '2025-05-01']
by_repo = defaultdict(list)
for r in rows:
    by_repo[r['repository']].append(r)

def key(repo): return repo.replace('/', '__')

def scan_repo(repo, items):
    path = os.path.join(ROOT, key(repo))
    subprocess.run(['git','--no-optional-locks','-C',path,'fetch','-q','--filter=blob:none',
                    '--deepen='+str(DEPTH), f'https://github.com/{repo}.git'],
                   capture_output=True, timeout=180)
    out = []
    for it in items:
        fix = it['fix_ref']
        try:
            m = subprocess.run(['git','--no-optional-locks','-C',path,'log','-n',str(DEPTH),
                                '--format=%H%x1f%s%x1f%b%x1e',fix+'~'+str(DEPTH)+'..'+fix],
                               capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            continue
        if m.returncode != 0:
            continue
        entries = m.stdout.split('\x1e')
        for e in entries:
            if not e.strip(): continue
            parts = e.strip().split('\x1f', 2)
            if len(parts) < 3: continue
            sha, subject, body = parts[0], parts[1], parts[2]
            if sha == fix:
                continue
            if AI.search(subject + '\n' + body):
                out.append({'case_id': it['case_id'], 'repository': repo, 'fix_ref': fix,
                            'ai_ancestor': sha, 'subject': subject[:150],
                            'published': it.get('published')})
                break
    return out

results = []
with ThreadPoolExecutor(max_workers=10) as ex:
    for chunk in ex.map(lambda kv: scan_repo(kv[0], kv[1]), by_repo.items()):
        results.extend(chunk)

with open(OUTPUT,'w') as f:
    for r in results: f.write(json.dumps(r)+'\n')
print('in-window rows:', len(rows), 'repos:', len(by_repo), 'AI-ancestry candidates:', len(results))
