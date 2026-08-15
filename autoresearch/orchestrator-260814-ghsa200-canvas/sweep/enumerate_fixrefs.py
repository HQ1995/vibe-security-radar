#!/usr/bin/env python3
"""Enumerate first-party fix commit refs from the advisory-database tree (local, no API)."""
import json, re, subprocess

ADB = '/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database'
COMMIT_REF = re.compile(r'github\.com/([^/]+/[^/]+)/(?:commit|pull)/([0-9a-f]{7,40})', re.I)

def git(*args):
    return subprocess.run(['git','--no-optional-locks','-C',ADB]+list(args), capture_output=True, text=True)

files = [f for f in git('ls-tree','-r','--name-only','origin/main','advisories/github-reviewed/').stdout.split() if f.endswith('.json')]

exclude = set()
for p in ['autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl',
          'autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl']:
    try:
        for l in open(p):
            r = json.loads(l)
            for k in ('case_id','ghsa_id'):
                if r.get(k): exclude.add(r[k].upper())
    except FileNotFoundError:
        pass

specs = ''.join('origin/main:'+f+'\n' for f in files)
proc = subprocess.run(['git','--no-optional-locks','-C',ADB,'cat-file','--batch'],
                      input=specs.encode(), capture_output=True)
data = proc.stdout
pos = 0
rows = []
for f in files:
    nl = data.find(b'\n', pos)
    if nl < 0:
        break
    header = data[pos:nl].decode()
    try:
        size = int(header.split()[-1])
    except (IndexError, ValueError):
        break
    blob = data[nl+1:nl+1+size]
    pos = nl+1+size+1
    try:
        a = json.loads(blob.decode())
    except Exception:
        continue
    gid = (a.get('ghsa_id') or f.split('/')[-2]).upper()
    if gid in exclude:
        continue
    for r in a.get('references', []):
        m = COMMIT_REF.search(r.get('url') or '')
        if m:
            rows.append({'case_id': gid, 'repository': m.group(1), 'fix_ref': m.group(2).lower(),
                         'published': a.get('published'), 'summary': (a.get('summary') or '')[:200]})
            break

seen = set(); uniq = []
for r in rows:
    k = (r['case_id'], r['fix_ref'])
    if k in seen: continue
    seen.add(k); uniq.append(r)
with open('autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fixrefs.jsonl','w') as f:
    for r in uniq: f.write(json.dumps(r)+'\n')
print('advisory files:', len(files), 'excluded ids:', len(exclude), 'fixref rows:', len(uniq))
