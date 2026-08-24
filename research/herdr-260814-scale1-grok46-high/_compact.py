#!/usr/bin/env python3
import json, hashlib, os, subprocess
from pathlib import Path
owned = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale1-grok46-high')
slicep = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fwd-slice-5.jsonl')
adv_root = Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database/advisories/github-reviewed')
rows = [json.loads(l) for l in slicep.read_text().splitlines() if l.strip()]
out = []
for row in rows:
    ghsa = row['ghsa']
    low = ghsa.lower()
    year = row['published'][:4]
    month = row['published'][5:7]
    p = adv_root / year / month / low / (low + '.json')
    rec = {
        'ghsa': ghsa,
        'repo': row['repo'],
        'published': row['published'],
        'summary': row['summary'],
        'recent': row.get('recent') or [],
        'advisory_path': str(p) if p.exists() else None,
    }
    if p.exists():
        d = json.loads(p.read_text())
        rec['aliases'] = d.get('aliases') or []
        rec['withdrawn'] = d.get('withdrawn')
        rec['severity'] = d.get('severity')
        rec['summary_adv'] = d.get('summary')
        rec['details'] = (d.get('details') or '')[:4000]
        rec['affected'] = []
        for aff in d.get('affected') or []:
            pkg = aff.get('package') or {}
            rec['affected'].append({
                'ecosystem': pkg.get('ecosystem'),
                'name': pkg.get('name'),
                'ranges': aff.get('ranges'),
                'versions': aff.get('versions'),
                'database_specific': aff.get('database_specific'),
            })
        rec['refs'] = d.get('references') or []
        rec['db'] = d.get('database_specific')
    out.append(rec)
(owned / 'advisories.json').write_text(json.dumps({'nrows': len(out), 'advisories': out}, indent=2))
print('WROTE', len(out), 'found', sum(1 for r in out if r['advisory_path']))
for r in out:
    print('ROW', r['ghsa'], r['repo'], 'adv='+str(bool(r['advisory_path'])), 'aliases='+str(r.get('aliases') or [])[:3], 'naff='+str(len(r.get('affected') or [])), 'nref='+str(len(r.get('refs') or [])), 'sha='+(r['recent'][0]['sha'] if r['recent'] else ''))
