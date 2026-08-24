import json, os
from pathlib import Path
OWN = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s5-grok46-high')
SLICE = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-2.jsonl')
ROOT = Path('/home/hanqing/.cache/ghsa200-worker-clones')
rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
repos = sorted({r['repository'] for r in rows})
wanted = {r.replace('/', '__') for r in repos}
found = {w: [] for w in wanted}
for dirpath, dirnames, filenames in os.walk(str(ROOT)):
    base = os.path.basename(dirpath)
    if base in wanted:
        git = os.path.join(dirpath, '.git')
        if os.path.isdir(git) or os.path.isfile(git):
            found[base].append(dirpath)
    # prune huge walks a bit
    if 'objects' in dirnames and os.path.basename(dirpath) == '.git':
        dirnames[:] = []
out = []
for repo in repos:
    key = repo.replace('/', '__')
    out.append(f"REPO {repo} clones={len(found[key])}")
    for p in found[key][:8]:
        out.append('  '+p)
text = '
'.join(out)+'
'
(OWN/'_clones.txt').write_text(text)
print('wrote', len(text), 'bytes', 'repos', len(repos))
