#!/usr/bin/env python3
"""Stage 2: blobless-fetch fix commits grouped by repo, then detect AI authorship."""
import json, os, re, subprocess, sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

ROOT = '/home/hanqing/.cache/ghsa200-sweep-fetch'
os.makedirs(ROOT, exist_ok=True)
AI = re.compile(r'co-authored-by:|assisted-by:|generated with (claude|codex|copilot|cursor)|claude code|claude opus|claude sonnet|github copilot|\bcursor\b|\bdevin\b|\bjules\b|\brovo\b|qwen code|openwork|\bqoder\b|coderabbit|\bkimi\b|\bgrok\b|\btrae\b|ai-assisted|ai-generated', re.I)

INPUT = sys.argv[1] if len(sys.argv) > 1 else 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fixrefs.jsonl'
OUTPUT = sys.argv[2] if len(sys.argv) > 2 else 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fix-marker-scan.json'
by_repo = defaultdict(list)
for l in open(INPUT):
    r = json.loads(l)
    if not r.get('repository'):
        continue
    by_repo[r['repository']].append((r['case_id'], r['fix_ref']))

def key(repo):
    return repo.replace('/', '__')

def fetch_repo(repo, items):
    k = key(repo)
    path = os.path.join(ROOT, k)
    url = f'https://github.com/{repo}.git'
    shas = sorted({s for _, s in items})
    if not os.path.isdir(path):
        subprocess.run(['git','--no-optional-locks','init','-q','--bare',path], capture_output=True)
    subprocess.run(['git','--no-optional-locks','-C',path,'fetch','-q','--filter=blob:none','--depth','1',url]+shas,
                   capture_output=True, timeout=120)
    out = []
    for cid, s in items:
        msg = ''
        fetched = False
        try:
            m = subprocess.run(['git','--no-optional-locks','-C',path,'cat-file','-p',s],
                               capture_output=True, text=True, timeout=15)
            if m.returncode == 0:
                fetched = True
                parts = m.stdout.split('\n\n', 1)
                msg = parts[1] if len(parts) > 1 else m.stdout
        except subprocess.TimeoutExpired:
            pass
        out.append({'case_id': cid, 'repository': repo, 'fix_ref': s,
                    'fetched': fetched, 'ai_authored_fix': bool(AI.search(msg)),
                    'subject': msg.splitlines()[0][:120] if msg else ''})
    return out

results = []
with ThreadPoolExecutor(max_workers=12) as ex:
    for chunk in ex.map(lambda kv: fetch_repo(kv[0], kv[1]), by_repo.items()):
        results.extend(chunk)

with open(OUTPUT,'w') as f:
    json.dump(results, f, indent=1)
hits = [r for r in results if r['ai_authored_fix']]
print('repos:', len(by_repo), 'rows:', len(results),
      'fetched:', sum(1 for r in results if r['fetched']), 'AI-authored fixes:', len(hits))
