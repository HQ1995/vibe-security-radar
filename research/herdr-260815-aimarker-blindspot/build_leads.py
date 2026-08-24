#!/usr/bin/env python3
import json
from collections import defaultdict

ROOT = '/home/hanqing/agents/ai-slop'
WORK = '/home/hanqing/agents/ai-slop/autoresearch/herdr-260815-aimarker-blindspot'

rd = json.load(open(f'{ROOT}/web/src/generated/research-data.json'))
cases = rd['cases']

sha_to_case = defaultdict(list)
for c in cases:
    for s in (c.get('candidate_set') or []):
        sha_to_case[s].append(('candidate', c))
    for fx in ((c.get('fix_authorship') or {}).get('fixes') or []):
        if fx.get('sha'):
            sha_to_case[fx['sha']].append(('fix', c))

fixref = defaultdict(list)
for line in open(f'{ROOT}/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fixrefs.jsonl'):
    r = json.loads(line)
    fixref[r['fix_ref']].append(r)

def case_note(c):
    aliases = ', '.join(c.get('aliases') or [])
    mech = c.get('cause_category') or ''
    return f"{c['case_id']} ({aliases}) cause={mech}".strip()

def fix_sha_for(c, role):
    if role == 'fix':
        return None
    fixes = [f['sha'] for f in ((c.get('fix_authorship') or {}).get('fixes') or []) if f.get('sha')]
    return fixes[0] if fixes else None

leads = []

# A: relyra Made-with Cursor
for line in open(f'{WORK}/attribution_commits.jsonl'):
    r = json.loads(line)
    for role, c in sha_to_case.get(r['sha'], []):
        leads.append(dict(repo=r['repo'], sha=r['sha'], role=role,
            signal=f'body: "{r["attribution"]}" (repo convention; no tool trailer)',
            tool=r['tool'].lower(), excerpt=r['subject'],
            security_note=case_note(c), fix_sha=fix_sha_for(c, role),
            confidence='medium', status='LEAD', case_id=c['case_id']))

# B: openclaw generic [AI] / [AI-assisted]
for line in open(f'{WORK}/generic_ai_commits.jsonl'):
    r = json.loads(line)
    for role, c in sha_to_case.get(r['sha'], []):
        leads.append(dict(repo=r['repo'], sha=r['sha'], role=role,
            signal='subject has generic AI marker, no tool name',
            tool=None, excerpt=r['subject'],
            security_note=case_note(c), fix_sha=fix_sha_for(c, role),
            confidence='medium', status='LEAD', case_id=c['case_id']))
    # broader fixrefs (fix commit for a GHSA not in the 168-case study)
    if r['sha'] not in sha_to_case:
        for fr in fixref.get(r['sha'], []):
            if fr['case_id'] in [x['case_id'] for x in sha_to_case.get(r['sha'], [])]:
                continue
            leads.append(dict(repo=r['repo'], sha=r['sha'], role='fix',
                signal='subject has generic AI marker, no tool name',
                tool=None, excerpt=r['subject'],
                security_note=f"{fr['case_id']} {fr['summary']}".strip(),
                fix_sha=None, confidence='medium', status='LEAD',
                case_id=fr['case_id']))

# dedupe
seen = set(); out = []
for l in leads:
    k = (l['sha'], l['role'], l['case_id'])
    if k in seen:
        continue
    seen.add(k)
    out.append(l)

with open(f'{WORK}/leads.jsonl', 'w') as f:
    for l in out:
        f.write(json.dumps(l) + '\n')

from collections import Counter
print('total leads:', len(out))
print('by role:', Counter(l['role'] for l in out))
print('by tool:', Counter((l['tool'] or 'generic') for l in out))
print('by case in 168-study:', sum(1 for l in out if l['security_note'].startswith('GHSA') and l['case_id'] in {c['case_id'] for c in cases}))
