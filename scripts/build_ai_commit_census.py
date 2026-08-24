#!/usr/bin/env python3
"""Census of AI-marked commits across the 168-case repo set (local git only).

Window mirrors the study cutoff. Three signals per commit:
  trailer  - Co-Authored-By / co-authored-by line names a tool
  author   - author name/email is an AI identity (noreply@anthropic.com etc.)
  text     - subject+body mention a tool keyword (sensitivity only, prose noise)
Primary marked count = trailer OR author. Never fetches; shallow clones are
used only when no full clone exists.
"""
import json, os, re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from research_lib import git, find_clones

ROOT = Path('/home/hanqing/agents/ai-slop')
OUT = ROOT/'research/orchestrator-260814-ghsa200-canvas/sweep/ai-commit-census.json'
SINCE = '2025-05-01'
UNTIL = '2026-08-16'

FAMILY_PATTERNS = [
    ('claude_flow', re.compile(r'claude[- ]?flow', re.I)),
    ('copilot', re.compile(r'copilot', re.I)),
    ('cursor', re.compile(r'cursor', re.I)),
    ('openai_gpt_codex', re.compile(r'codex|gpt-|openai', re.I)),
    ('claude', re.compile(r'claude|anthropic', re.I)),
]

def family_of(t):
    for f, p in FAMILY_PATTERNS:
        if p.search(t):
            return f
    return None

def scan(repo):
    cands = sorted(find_clones(repo),
                   key=lambda c: os.path.exists(os.path.join(c, '.git', 'shallow')))
    r = None
    for c in cands:
        r = git(c, 'log', '--no-merges', f'--since={SINCE}', f'--until={UNTIL}',
                '--format=%x1e%an%x1f%ae%x1f%s%x1f%b', timeout=300)
        if r is not None and r.returncode == 0:
            break
    if not cands:
        return repo, None, 'missing'
    if r is None or r.returncode != 0:
        return repo, None, 'git_failed'
    fams = {f: {'trailer': 0, 'author': 0, 'text': 0, 'marked': 0} for f, _ in FAMILY_PATTERNS}
    total = 0
    for rec in r.stdout.split('\x1e'):
        rec = rec.strip()
        if not rec:
            continue
        total += 1
        parts = rec.split('\x1f', 3)
        an, ae, subj, body = (parts + ['']*4)[:4]
        trail_f = auth_f = None
        for line in body.splitlines():
            if 'co-auth' in line.lower():
                trail_f = family_of(line)
                if trail_f:
                    break
        auth_f = family_of(an + ' ' + ae)
        text_f = family_of(subj + ' ' + body)
        if trail_f:
            fams[trail_f]['trailer'] += 1
            fams[trail_f]['marked'] += 1
        if auth_f:
            fams[auth_f]['author'] += 1
            if not trail_f:
                fams[auth_f]['marked'] += 1
        if text_f:
            fams[text_f]['text'] += 1
    shallow = os.path.exists(os.path.join(c, '.git', 'shallow'))
    return repo, {'total': total, 'families': fams}, ('shallow' if shallow else 'full')

cases = json.load(open(ROOT/'web/src/generated/research-data.json'))['cases']
repos = sorted({c['repository'] for c in cases if c.get('repository')})
agg = {'window': {'since': SINCE, 'until': UNTIL}, 'repos_scanned': 0, 'repos_missing': [],
       'total_commits': 0, 'marked_ai_commits': 0,
       'families': {f: {'trailer': 0, 'author': 0, 'text': 0, 'marked': 0} for f, _ in FAMILY_PATTERNS},
       'per_repo': {}}
with ThreadPoolExecutor(max_workers=6) as ex:
    for repo, res, status in ex.map(scan, repos):
        if res is None:
            agg['repos_missing'].append(repo)
            agg['repos_failed'] = agg.get('repos_failed', []) + [repo]
            continue
        agg['repos_scanned'] += 1
        agg['total_commits'] += res['total']
        agg['per_repo'][repo] = res
        for f, v in res['families'].items():
            for k in v:
                agg['families'][f][k] += v[k]
            agg['marked_ai_commits'] += v['marked']
OUT.write_text(json.dumps(agg, indent=1, sort_keys=True))
total = agg['total_commits']
marked = agg['marked_ai_commits']
print('repos scanned:', agg['repos_scanned'], 'missing:', len(agg['repos_missing']))
print('total commits:', total, 'marked AI:', marked, f'({100*marked/max(total,1):.2f}%)')
for f in [x[0] for x in FAMILY_PATTERNS]:
    v = agg['families'][f]
    print(f'{f:16s} marked={v["marked"]:5d} trailer={v["trailer"]:5d} author={v["author"]:5d} text={v["text"]:5d}')
