#!/usr/bin/env python3
import json, subprocess
from pathlib import Path
OWNED = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-unknown9-grok46-high')
ev = json.loads((OWNED/'_evidence.json').read_text())

def git(clone, *args, timeout=20):
    r = subprocess.run(['git','-C',clone,*args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout or '', r.stderr or ''

want = {0,1,4,5,8,9,17,19,20,22,23,24,25,27,29}
out = []
for rec in ev:
    i = rec['i']
    if i not in want:
        continue
    clone = rec['clone']
    ai = rec['ai']
    fix = rec['fix']
    parent = rec['parent']
    rc, files, _ = git(clone, 'diff-tree', '--no-commit-id', '--name-only', '-r', ai)
    ai_files = [l for l in files.splitlines() if l.strip()]
    rc, ffiles, _ = git(clone, 'diff-tree', '--no-commit-id', '--name-only', '-r', fix)
    fix_files = [l for l in ffiles.splitlines() if l.strip()]
    item = {
        'i': i, 'ghsa': rec['ghsa'], 'repo': rec['repo'],
        'ai_files': ai_files, 'fix_files': fix_files,
        'ai_n': len(ai_files), 'fix_n': len(fix_files),
        'overlap': sorted(set(ai_files)&set(fix_files)),
    }
    # small diffs for overlapping production files
    diffs = {}
    for f in item['overlap'][:6]:
        if any(x in f.lower() for x in ['.md', 'test', 'spec', 'snapshot', 'changelog', 'lock']):
            continue
        rc, d, e = git(clone, 'show', f'{ai}^!','--', f)
        diffs['AI:'+f] = (d if rc==0 else e)[:2500]
        rc, d, e = git(clone, 'show', f'{fix}^!','--', f)
        diffs['FIX:'+f] = (d if rc==0 else e)[:2500]
    item['diffs'] = diffs
    # tags containing shas
    rc, tags_ai, _ = git(clone, 'tag', '--contains', ai)
    rc, tags_fix, _ = git(clone, 'tag', '--contains', fix)
    item['tags_ai'] = [t for t in tags_ai.splitlines() if t.strip()][:12]
    item['tags_fix'] = [t for t in tags_fix.splitlines() if t.strip()][:12]
    out.append(item)
(OWNED/'_hunks.json').write_text(json.dumps(out, indent=2)[:400000])
print('wrote', len(out))
