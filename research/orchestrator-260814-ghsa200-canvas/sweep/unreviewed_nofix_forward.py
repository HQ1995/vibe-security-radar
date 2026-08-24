#!/usr/bin/env python3
"""Enumerate in-window unreviewed advisories WITHOUT fix refs and forward-join
them with the local AI-commit corpus (repo + time). Output ranked candidates."""
import json, re, subprocess
from collections import defaultdict

ADB='/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database'
inwin=set()
for l in open('/tmp/unr-inwin.txt'):
    p=l.split(':',1)[1].strip()
    if p.endswith('.json'): inwin.add(p)
fixref=set()
for l in open('/tmp/unr-fixref.txt'):
    p=l.split(':',1)[1].strip()
    if p.endswith('.json'): fixref.add(p)
files=sorted(inwin-fixref)
print('no-fix unreviewed files:',len(files),flush=True)
GHSA=re.compile(r'(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})',re.I)
REPO=re.compile(r'github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)',re.I)
rows=[]
specs=''.join('origin/main:'+f+'\n' for f in files)
proc=subprocess.run(['git','--no-optional-locks','-C',ADB,'cat-file','--batch'],input=specs.encode(),capture_output=True)
data=proc.stdout; pos=0
for f in files:
    nl=data.find(b'\n',pos)
    if nl<0: break
    header=data[pos:nl].decode()
    try: size=int(header.split()[-1])
    except Exception: break
    blob=data[nl+1:nl+1+size]; pos=nl+1+size+1
    try: a=json.loads(blob.decode())
    except Exception: continue
    if a.get('withdrawnAt'): continue
    pub=a.get('published') or ''
    if not (pub>='2025-05-01'): continue
    gid=(a.get('ghsa_id') or f.split('/')[-2]).upper()
    repo=None
    for r in a.get('references',[]):
        m=REPO.search(r.get('url') or '')
        if m and not m.group(1).lower().endswith(('advisories','security')): 
            repo=m.group(1); break
    rows.append({'ghsa':gid,'repo':repo,'published':pub,'summary':(a.get('summary') or (a.get('description') or '')[:120])[:160]})
print('rows:',len(rows),flush=True)
# AI-commit corpus by repo
ai=defaultdict(list)
for l in open('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260809-0539/current-ai-scan/commits.jsonl'):
    r=json.loads(l)
    repo=(r.get('repository_identity') or '').lower().replace('github.com/','').strip('/')
    ai[repo].append({'sha':r.get('sha'),'date':r.get('authored_date') or ''})
cands=[]
for a in rows:
    repo=(a['repo'] or '').lower().strip('/')
    pre=[x for x in ai.get(repo,[]) if x['date'] < (a['published'] or '9999')]
    if pre:
        a['ai_commits_before']=len(pre)
        cands.append(a)
cands.sort(key=lambda c:(c['ai_commits_before'], c['published'] or ''))
with open('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unreviewed-nofix-forward.jsonl','w') as fh:
    for c in cands: fh.write(json.dumps(c)+'\n')
print('forward candidates (>=1 AI commit in repo):',len(cands),flush=True)
small=[c for c in cands if c['ai_commits_before']<=30]
print('small-repo candidates:',len(small),flush=True)

