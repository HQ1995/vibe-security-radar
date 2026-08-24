#!/usr/bin/env python3
import json, subprocess, os, hashlib, datetime, re
from pathlib import Path

OWN = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-final-unknown9-grok46-high')
EV = OWN / 'evidence'
EV.mkdir(exist_ok=True)

def sh(args, cwd=None, timeout=30):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return {
        'cmd': args,
        'cwd': cwd,
        'rc': r.returncode,
        'stdout': (r.stdout or '')[-8000:],
        'stderr': (r.stderr or '')[-2000:],
    }

def git(clone, args, timeout=30):
    return sh(['git', '--no-optional-locks', '-c', 'gc.auto=0', '-C', clone] + args, timeout=timeout)

def cat_json(path):
    p = Path(path)
    if not p.exists():
        return {'exists': False, 'path': str(p)}
    try:
        data = json.loads(p.read_text(errors='replace'))
    except Exception as e:
        return {'exists': True, 'path': str(p), 'parse_error': str(e), 'head': p.read_text(errors='replace')[:500]}
    keep = {}
    for k in ['ghsa_id','cve_id','summary','severity','published_at','updated_at','withdrawn_at','html_url','url','identifiers','vulnerabilities','credits','description','message','status','aliases']:
        if k in data:
            v = data[k]
            if k == 'description' and isinstance(v, str):
                v = v[:2500]
            keep[k] = v
    keep['all_keys'] = sorted(data.keys())
    return {'exists': True, 'path': str(p), 'data': keep}

# ---- advisories ----
adv_paths = {
  '35': [
    '/tmp/fp211-adjudicate-05/pages/repo-advisory/coollabsio__coolify__GHSA-4mpw-wcj4-v9pp.json',
  ],
  '51': [
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages/repo/GHSA-vjp8-wprm-2jw9.json',
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages/ghsa/GHSA-vjp8-wprm-2jw9.json',
  ],
  '53': [
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages/repo/GHSA-8jqh-598v-rfxc.json',
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages/cve/CVE-2026-67530.json',
  ],
  '56': [
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages/repo/GHSA-8g98-m4j9-qww5.json',
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages/ghsa/GHSA-8g98-m4j9-qww5.json',
  ],
  '84': [
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages/repo/GHSA-vh5j-5fhq-9xwg.json',
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages/ghsa/GHSA-vh5j-5fhq-9xwg.json',
  ],
  '116': [
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh/work/pages/repo-advisory/coollabsio__coolify__GHSA-CGJ8-7M5Q-X5GV.json',
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh/work/pages/ghsa/GHSA-CGJ8-7M5Q-X5GV.json',
  ],
  '129': [
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh/work/pages/repo-advisory/argoproj__argo-workflows__GHSA-48P8-G2FX-3WWM.json',
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh/work/pages/ghsa/GHSA-48P8-G2FX-3WWM.json',
  ],
  '153': [
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh/work/pages/repo-advisory/MISP__MISP__GHSA-MF7V-X7R6-FQ57.json',
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh/work/pages/ghsa/GHSA-MF7V-X7R6-FQ57.json',
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh/work/pages/advisory-database/GHSA-MF7V-X7R6-FQ57.json',
  ],
  '154': [
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh/work/pages/repo-advisory/omnifaces__omnifaces__GHSA-FP43-VJ7G-PG92.json',
    '/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh/work/pages/ghsa/GHSA-FP43-VJ7G-PG92.json',
  ],
}

# extra searches for 35 and 153
extra_search_roots = [
    Path('/tmp'),
    Path('/home/hanqing/agents/ai-slop/autoresearch'),
    Path('/home/hanqing/.cache/ghsa200-worker-clones'),
    Path('/home/hanqing/agents/ai-slop/.ai-slop/cache'),
]
needles = {
    '4mpw': 'GHSA-4mpw',
    'mf7v': 'GHSA-mf7v',
    '4MPW': 'GHSA-4MPW',
    'MF7V': 'GHSA-MF7V',
}
found_extra = {}
for root in extra_search_roots:
    if not root.exists():
        continue
    for dirpath, dirnames, filenames in os.walk(root):
        # prune huge/irrelevant
        base = os.path.basename(dirpath).lower()
        if base in {'.git','node_modules','target','dist'} and root != Path('/home/hanqing/.cache/ghsa200-worker-clones'):
            dirnames[:] = []
            continue
        if 'advisory-database' in dirpath or 'pages' in dirpath or 'ghsa' in dirpath.lower() or 'repo-advisory' in dirpath:
            for fn in filenames:
                low = fn.lower()
                if '4mpw' in low or 'mf7v' in low:
                    found_extra.setdefault(fn, []).append(os.path.join(dirpath, fn))
        # don't walk entire /tmp too deep except known prefixes
        if root == Path('/tmp'):
            keep = []
            for d in dirnames:
                if d.startswith('fp211') or 'ghsa' in d.lower() or 'advisory' in d.lower():
                    keep.append(d)
            dirnames[:] = keep

advisories = {}
for ord_, paths in adv_paths.items():
    advisories[ord_] = [cat_json(p) for p in paths]

# attach extras
advisories['extra_files'] = found_extra

(EV/'advisories.json').write_text(json.dumps(advisories, indent=2))
print('advisories_written', len(advisories), 'extras', len(found_extra))
