#!/usr/bin/env python3
"""Incremental weekly/monthly runner: refresh ADB, compute delta, emit next-run manifest.

Stages (deterministic; LLM adjudication is dispatched separately per SPEC):
  1. git fetch origin main in the local advisory-database clone
  2. diff name-status since state.adb_head -> new/changed advisory files
  3. term-scan those files for AI signals (excludes counted ids)
  4. collect first-party fix refs for the delta rows
  5. write next-run-manifest.jsonl and advance state.adb_head

Usage: python3 incremental.py   (writes state.json + next-run-manifest.jsonl)
"""
import json, os, re, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADB = '/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database'
STATE = HERE / 'state.json'
MANIFEST = HERE / 'next-run-manifest.jsonl'
TERMS = re.compile(r'claude code|copilot|cursor|codex|devin|jules|rovo|qwen code|opencode|vibe cod|coderabbit|kimi|grok 3|qoder|trae|aider|assisted by|co-authored-by|ai-generated|ai-assisted|generated with', re.I)
COMMIT_REF = re.compile(r'github\.com/([^/]+/[^/]+)/(?:commit|pull)/([0-9a-f]{7,40})', re.I)

def git(*args):
    return subprocess.run(['git','--no-optional-locks','-C',ADB]+list(args), capture_output=True, text=True)

state = {}
if STATE.exists():
    state = json.loads(STATE.read_text())
prev_head = state.get('adb_head')

git('fetch','-q','origin','main:refs/remotes/origin/main')
head = git('rev-parse','origin/main').stdout.strip()
print('adb head:', head, '(prev', prev_head, ')')

if prev_head and prev_head != head:
    diff = git('diff','--name-status','-M',prev_head+'..origin/main').stdout
else:
    diff = ''
new_files = [l.split('\t',1)[1] for l in diff.splitlines()
             if l.startswith(('A\t','M\t','R')) and l.split('\t',1)[1].endswith('.json')
             and '/advisories/github-reviewed/' in l]

# counted ids for exclusion
counted = set()
for p in ['autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl']:
    try:
        for l in open(p):
            r = json.loads(l)
            if r.get('case_id'): counted.add(r['case_id'])
    except FileNotFoundError:
        pass

rows = []
for f in new_files:
    blob = git('show','origin/main:'+f).stdout
    if not blob: continue
    try:
        a = json.loads(blob)
    except Exception:
        continue
    gid = (a.get('ghsa_id') or Path(f).parent.name).upper()
    if gid in counted: continue
    if not TERMS.search(json.dumps(a)): continue
    fix = None; repo = None
    for r in a.get('references', []):
        m = COMMIT_REF.search(r.get('url') or '')
        if m:
            repo = m.group(1); fix = m.group(2).lower(); break
    rows.append({'ghsa': gid, 'repo': repo, 'fix_ref': fix,
                 'published': a.get('published'),
                 'summary': (a.get('summary') or '')[:200],
                 'path': f, 'stage': 'term_hit'})

# de-dupe
seen = set(); uniq = []
for r in rows:
    k = (r['ghsa'], r['fix_ref'])
    if k in seen: continue
    seen.add(k); uniq.append(r)

MANIFEST.write_text('\n'.join(json.dumps(r) for r in uniq) + '\n')
state = {'adb_head': head, 'last_run_utc': __import__('datetime').datetime.utcnow().isoformat() + 'Z',
         'counted_ids': len(counted), 'new_candidates': len(uniq)}
STATE.write_text(json.dumps(state, indent=1) + '\n')
print('new AI-term candidate rows:', len(uniq), '-> next-run-manifest.jsonl')

