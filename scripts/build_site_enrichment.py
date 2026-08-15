#!/usr/bin/env python3
"""Build enrichment-fixes.json and code-evidence.json from local git clones.

Mechanical only: no network, no fabrication. Missing clone/commit => no row.
"""
import json, re, hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from research_lib import git, find_clones, clone_with_commit, commit_text

ROOT = Path('/home/hanqing/agents/ai-slop')
OUT_ENR = ROOT/'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/enrichment-fixes.json'
OUT_CE = ROOT/'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/code-evidence.json'

CAUSE = [('ssrf', r'ssrf|server-side request|outbound (url|dial)|private (ip|address)'),
         ('injection', r'xss|cross-site|injection|command|exec|sqli|ssti|rce|deserializ'),
         ('path_link', r'travers|symlink|path (confin|bypass|escape)|link following'),
         ('auth_access', r'auth|access control|permission|privilege|idor|tenant|session'),
         ('resource_abuse', r'dos|denial|resource|unbounded|memory|overflow|exhaust'),
         ('validation_fail_open', r'validat|fail[- ]open|saniti|bypass|denylist|allowlist')]

def cause_of(text):
    t = (text or '').lower()
    for k, pat in CAUSE:
        if re.search(pat, t):
            return k
    return 'other_ambiguous'

def file_list(clone, sha):
    m = git(clone, 'show', '--format=', '--name-only', sha, timeout=30)
    if m is None or m.returncode != 0:
        return []
    return [l for l in m.stdout.splitlines() if l.strip()]

def file_hunk(clone, sha, path):
    m = git(clone, 'show', '--format=', '--unified=3', '--no-ext-diff', sha, '--', path, timeout=30)
    if m is None or m.returncode != 0:
        return None
    keep = [l for l in m.stdout.splitlines() if l.startswith(('+', '-', ' ', '@@'))]
    return '\n'.join(keep[:120]) or None

def one(c):
    cid = c['case_id']
    cand = (c.get('candidate_set') or [None])[0]
    fix = (c.get('minimum_fix_set') or [None])[0]
    repo = c.get('repository')
    e = {}
    if not c.get('cause_category'):
        e['cause_category'] = cause_of(c.get('mechanism') or c.get('scope_statement'))
    ce = None
    if cand and fix and repo:
        cc = clone_with_commit(repo, cand)
        if cc:
            cm = commit_text(cc, cand)
            if cm:
                fc = clone_with_commit(repo, fix)
                fm = commit_text(fc, fix) if fc else None
                if fm:
                    cf = file_list(cc, cand)
                    ff = file_list(fc, fix)
                    shared = [f for f in cf if f in set(ff)]
                    cand_files = (shared[:3] or cf[:3])
                    fix_files = (shared[:3] or ff[:3])
                    ch = [{'file': f, 'code': t, 'annotation': ''}
                          for f in cand_files if (t := file_hunk(cc, cand, f))]
                    fh = [{'file': f, 'code': t, 'annotation': ''}
                          for f in fix_files if (t := file_hunk(fc, fix, f))]
                    marker = ''
                    for line in cm['body'].splitlines():
                        if 'co-auth' in line.lower() or 'assist' in line.lower() or line.strip().startswith('[AI'):
                            marker = line.strip()
                            break
                    if not marker:
                        marker = cm['subject'] if re.search(r'\[ai\]|ai[- ]assist', cm['subject'], re.I) else None
                    ce = {
                        'ai_marker': marker,
                        'fix_marker': None,
                        'candidate_url': f'https://github.com/{repo}/commit/{cand}',
                        'fix_url': f'https://github.com/{repo}/commit/{fix}',
                        'advisory_url': f'https://github.com/advisories/{cid.lower()}',
                        'summary': c.get('mechanism') or c.get('scope_statement') or '',
                        'steps': [
                            {'title': 'AI change', 'detail': cm['subject']},
                            {'title': 'Fix', 'detail': fm['subject']},
                        ],
                        'candidate_hunks': ch,
                        'fix_hunks': fh,
                        'comparison_hunks': (ch + fh)[:6],
                        'candidate_patch_sha256': hashlib.sha256('\n'.join(h['code'] for h in ch).encode()).hexdigest(),
                        'fix_patch_sha256': hashlib.sha256('\n'.join(h['code'] for h in fh).encode()).hexdigest(),
                    }
    return cid, e, ce

cases = json.load(open(ROOT/'web/src/generated/research-data.json'))['cases']
enr, ce_map = {}, {}
with ThreadPoolExecutor(max_workers=8) as ex:
    for cid, e, ce in ex.map(one, cases):
        if e:
            enr[cid] = e
        if ce:
            ce_map[cid] = ce
OUT_ENR.write_text(json.dumps(enr, indent=1, sort_keys=True))
OUT_CE.write_text(json.dumps(ce_map, indent=1, sort_keys=True))
print('enrichment rows:', len(enr))
print('code-evidence rows:', len(ce_map))
