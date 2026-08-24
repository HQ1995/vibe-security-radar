#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path

SLICE = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-fix-slice-2.jsonl')
CLONE_ROOT = Path('/home/hanqing/.cache/ghsa200-worker-clones')
POOL = Path('/home/hanqing/.cache/ghsa200-sweep-fetch')
OUT = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-af2-grok46-high/work')
OUT.mkdir(exist_ok=True)

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
adv_dbs = sorted({p.parent for p in CLONE_ROOT.glob('*/advisory-database/advisories')})
index = []
for i, row in enumerate(rows, 1):
    cid = row['case_id']
    mixed = cid[:5] + cid[5:].lower()
    low = cid.lower()
    names = {f'{mixed}.json', f'{low}.json', f'{cid}.json'}
    found = None
    for db in adv_dbs:
        for dirpath, _, files in os.walk(db / 'advisories'):
            hit = names.intersection(files)
            if hit:
                found = str(Path(dirpath) / next(iter(hit)))
                break
        if found:
            break
    rec = {'n': i, 'case_id': cid, 'repo': row['repository'], 'sha': row['fix_ref'], 'subject': row.get('subject'), 'advisory_path': found}
    if found:
        data = json.loads(Path(found).read_text())
        rec['ghsa'] = data.get('id') or data.get('ghsaId')
        rec['summary'] = data.get('summary')
        rec['withdrawn'] = data.get('withdrawn')
        rec['aliases'] = data.get('aliases')
        rec['severity'] = data.get('severity')
        rec['published'] = data.get('published')
        rec['modified'] = data.get('modified')
        rec['refs'] = data.get('references')
        rec['affected'] = data.get('affected')
        rec['credits'] = data.get('credits')
        rec['database_specific'] = data.get('database_specific')
        rec['details'] = data.get('details')
    pool = POOL / row['repository'].replace('/', '__')
    rec['pool'] = str(pool)
    rec['pool_exists'] = pool.exists()
    if pool.exists():
        try:
            rec['commit'] = subprocess.check_output(['git','-C',str(pool),'log','-1','--format=%H%n%P%n%an <%ae>%n%cn <%ce>%n%s%n%b', row['fix_ref']], text=True, stderr=subprocess.STDOUT)[:8000]
        except subprocess.CalledProcessError as e:
            rec['commit_err'] = (e.output or str(e))[:1500]
        try:
            rec['stat'] = subprocess.check_output(['git','-C',str(pool),'show','--stat','--format=', row['fix_ref']], text=True, stderr=subprocess.STDOUT)[:4000]
        except subprocess.CalledProcessError as e:
            rec['stat_err'] = (e.output or str(e))[:800]
        try:
            rec['name_status'] = subprocess.check_output(['git','-C',str(pool),'show','--name-status','--format=', row['fix_ref']], text=True, stderr=subprocess.STDOUT)[:4000]
        except subprocess.CalledProcessError as e:
            rec['name_status_err'] = (e.output or str(e))[:800]
    Path(OUT / f'row-{i:02d}.json').write_text(json.dumps(rec, indent=2, default=str))
    index.append({'n': i, 'case_id': cid, 'found': bool(found), 'pool': rec['pool_exists'], 'has_commit': 'commit' in rec, 'path': found})
Path(OUT / 'index.json').write_text(json.dumps(index, indent=2))
print(json.dumps(index, indent=2))
