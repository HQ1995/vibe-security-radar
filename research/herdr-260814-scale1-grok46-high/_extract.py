#!/usr/bin/env python3
import json, hashlib, os
from pathlib import Path

owned = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale1-grok46-high')
spec = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/FWD-SPEC.md')
slicep = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fwd-slice-5.jsonl')
contract = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md')
adv_root = Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database/advisories/github-reviewed')

def sha256(p):
    h = hashlib.sha256()
    with open(p,'rb') as f:
        for chunk in iter(lambda: f.read(1<<16), b''):
            h.update(chunk)
    return h.hexdigest()

rows = [json.loads(l) for l in slicep.read_text().splitlines() if l.strip()]
out = {
    'spec_sha256': sha256(spec),
    'slice_sha256': sha256(slicep),
    'contract_sha256': sha256(contract),
    'nrows': len(rows),
    'advisories': []
}
for row in rows:
    ghsa = row['ghsa']
    low = ghsa.lower()
    year = row['published'][:4]
    p = adv_root / year / low / (low + '.json')
    rec = {
        'ghsa': ghsa,
        'repo': row['repo'],
        'published': row['published'],
        'summary': row['summary'],
        'ai_commits_before': row.get('ai_commits_before'),
        'recent': row.get('recent', []),
        'advisory_path': str(p) if p.exists() else None,
    }
    if p.exists():
        d = json.loads(p.read_text())
        rec['id'] = d.get('id') or d.get('ghsaId') or d.get('schema_version')
        rec['aliases'] = d.get('aliases')
        rec['withdrawn'] = d.get('withdrawn')
        rec['severity'] = d.get('severity')
        rec['summary_adv'] = d.get('summary')
        rec['details'] = (d.get('details') or '')[:2500]
        rec['affected'] = []
        for aff in d.get('affected') or []:
            pkg = aff.get('package') or {}
            rec['affected'].append({
                'ecosystem': pkg.get('ecosystem'),
                'name': pkg.get('name'),
                'purl': pkg.get('purl'),
                'ranges': aff.get('ranges'),
                'versions': aff.get('versions'),
                'database_specific': aff.get('database_specific'),
            })
        rec['refs'] = d.get('references')
        rec['database_specific'] = d.get('database_specific')
    out['advisories'].append(rec)
(owned / 'advisories.json').write_text(json.dumps(out, indent=2))
print('WROTE', owned / 'advisories.json', 'n=', len(out['advisories']))
print('SPEC', out['spec_sha256'])
print('SLICE', out['slice_sha256'])
print('CONTRACT', out['contract_sha256'])
for a in out['advisories']:
    print(a['ghsa'], 'path='+str(bool(a['advisory_path'])), 'aliases='+str((a.get('aliases') or [])[:4]), 'nref='+str(len(a.get('refs') or [])))
