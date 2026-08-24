#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path

owned = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale1-grok46-high')
slicep = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fwd-slice-5.jsonl')
adv_root = Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database/advisories/github-reviewed')
pool = Path('/home/hanqing/.cache/ghsa200-sweep-fetch')
rows = [json.loads(l) for l in slicep.read_text().splitlines() if l.strip()]

def git(repo, args, timeout=20):
    env = os.environ.copy()
    env['GIT_TERMINAL_PROMPT'] = '0'
    env['GIT_OPTIONAL_LOCKS'] = '0'
    env['GIT_NO_LAZY_FETCH'] = '1'
    try:
        r = subprocess.run(['git','-C',str(repo)]+args, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, (r.stdout or ''), (r.stderr or '')
    except Exception as e:
        return 99, '', str(e)

advs = []
for row in rows:
    ghsa = row['ghsa']
    low = ghsa.lower()
    year = row['published'][:4]
    month = row['published'][5:7]
    p = adv_root / year / month / low / (low + '.json')
    rec = {'ghsa': ghsa, 'repo': row['repo'], 'published': row['published'], 'summary': row['summary'], 'path': str(p), 'exists': p.exists()}
    if p.exists():
        d = json.loads(p.read_text())
        rec['id'] = d.get('id')
        rec['aliases'] = d.get('aliases') or []
        rec['withdrawn'] = d.get('withdrawn')
        rec['severity'] = d.get('severity')
        rec['summary_adv'] = d.get('summary')
        rec['details'] = (d.get('details') or '')[:4000]
        rec['affected'] = []
        for aff in d.get('affected') or []:
            pkg = aff.get('package') or {}
            rec['affected'].append({'eco': pkg.get('ecosystem'), 'name': pkg.get('name'), 'ranges': aff.get('ranges'), 'versions': aff.get('versions')})
        rec['refs'] = [{'type': r.get('type'), 'url': r.get('url')} for r in (d.get('references') or [])]
        ds = d.get('database_specific') or {}
        rec['cwe'] = ds.get('cwe_ids')
        rec['github_reviewed'] = ds.get('github_reviewed')
        rec['nvd'] = ds.get('nvd_published_at')
    advs.append(rec)
(owned/'advisories_compact.json').write_text(json.dumps(advs, indent=2))

seen = {}
commit_info = []
for row in rows:
    for c in row.get('recent') or []:
        sha = c['sha']
        if sha in seen:
            continue
        seen[sha] = True
        owner, repo = row['repo'].split('/', 1)
        prepo = pool / f'{owner}__{repo}'
        info = {'sha': sha, 'repo': row['repo'], 'pool': str(prepo), 'pool_exists': prepo.exists(), 'files': c.get('files'), 'kinds': c.get('kinds'), 'date': c.get('date')}
        if prepo.exists():
            code, out, err = git(prepo, ['cat-file','-t', sha])
            info['type'] = (out or err).strip().splitlines()[:3]
            code2, out2, err2 = git(prepo, ['log','-1','--format=%H%n%s%n%an <%ae>%n%b', sha])
            info['log'] = (out2 or err2)[:2500]
            code3, out3, err3 = git(prepo, ['show','--stat','--format=fuller','--find-renames', sha])
            info['stat'] = (out3 or err3)[:4000]
            code4, out4, err4 = git(prepo, ['show','--format=','--find-renames', sha])
            diff = out4 or err4
            info['diff_len'] = len(diff)
            info['diff_head'] = diff[:8000]
            dpath = owned / f'diff_{sha[:12]}.txt'
            dpath.write_text(diff[:200000])
            info['diff_file'] = str(dpath)
        commit_info.append(info)
(owned/'commits_compact.json').write_text(json.dumps(commit_info, indent=2))
print('ADVS', sum(1 for a in advs if a['exists']), '/', len(advs))
print('COMMITS', len(commit_info))
for a in advs:
    print('A', a['ghsa'], a['exists'], 'aliases', len(a.get('aliases') or []), 'refs', len(a.get('refs') or []))
for c in commit_info:
    print('C', c['repo'], c['sha'][:12], 'pool', c['pool_exists'], 'type', c.get('type'))
