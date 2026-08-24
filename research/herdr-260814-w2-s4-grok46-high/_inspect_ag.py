#!/usr/bin/env python3
import json, os, re, subprocess
from pathlib import Path

OWN = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s4-grok46-high')
SLICE = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-1.jsonl')
ADV_ROOT = Path('/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database')
CLONE_ROOT = Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones')
SCAN = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/scan.jsonl')
AI_RE = re.compile(r'(Co-authored-by:.*Copilot|Generated-by:|Signed-off-by: Copilot|Made-with: Cursor|Claude|GPT-|ChatGPT|OpenAI|anthropic|gemini|cursor\[bot\]|copilot|codex)', re.I)

rows=[]
with SLICE.open() as f:
    for line in f:
        line=line.strip()
        if line:
            rows.append(json.loads(line))
scan={}
with SCAN.open() as f:
    for line in f:
        rec=json.loads(line)
        scan[rec.get('ghsa_id') or rec.get('advisory_id')]=rec

out=[]
for rec in rows:
    gid=rec['ghsa_id']
    repo=rec['repository']
    shas=rec.get('commit_refs') or []
    slug=gid.lower()
    adv=None
    adv_path=None
    for p in ADV_ROOT.glob(f'advisories/github-reviewed/*/*/GHSA-{slug[5:]}/GHSA-{slug[5:]}.json') if False else []:
        pass
    # find advisory by glob of last 3 parts
    parts=slug.split('-')
    cand=list(ADV_ROOT.glob(f'advisories/github-reviewed/*/*/GHSA-{parts[1]}-{parts[2]}-{parts[3]}/GHSA-{parts[1]}-{parts[2]}-{parts[3]}.json'))
    if cand:
        adv_path=str(cand[0])
        adv=json.loads(Path(cand[0]).read_text())
    owner, name = repo.split('/',1)
    clone=CLONE_ROOT/f'{owner}__{name}'
    sha_info=[]
    for sha in shas:
        info={'sha':sha,'exists':False}
        if clone.is_dir():
            r=subprocess.run(['git','-C',str(clone),'cat-file','-t',sha],capture_output=True,text=True)
            info['exists']=r.returncode==0 and r.stdout.strip()=='commit'
            if info['exists']:
                meta=subprocess.run(['git','-C',str(clone),'log','-1','--format=%H%n%an <%ae>%n%cn <%ce>%n%s%n%b',sha],capture_output=True,text=True)
                info['meta']=meta.stdout[:2000]
                info['ai']=bool(AI_RE.search(meta.stdout or ''))
                trail=subprocess.run(['git','-C',str(clone),'log','-1','--format=%B',sha],capture_output=True,text=True)
                info['ai_body']=bool(AI_RE.search(trail.stdout or ''))
        sha_info.append(info)
    out.append({
        'ghsa_id':gid,
        'repository':repo,
        'adv_path':adv_path,
        'aliases': (adv or {}).get('aliases') if adv else None,
        'withdrawn': (adv or {}).get('withdrawn') if adv else None,
        'summary': ((adv or {}).get('summary') if adv else None),
        'affected': [a.get('package',{}) for a in (adv or {}).get('affected',[])] if adv else None,
        'refs': [r.get('url') for r in (adv or {}).get('references',[])][:12] if adv else None,
        'clone': str(clone) if clone.is_dir() else None,
        'sha_info': sha_info,
        'scan': {k: scan.get(gid,{}).get(k) for k in ['aliases','summary','added_source_files','notes','hard_hit','n_hits','best','status']},
    })
print(json.dumps(out, indent=2)[:12000])
print('---TRUNC---')
print('N',len(out))
print('adv found', sum(1 for x in out if x['adv_path']))
print('clone found', sum(1 for x in out if x['clone']))
