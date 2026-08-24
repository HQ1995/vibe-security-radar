import json
from pathlib import Path
src = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fwd-slice-4.jsonl")
out = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-fwd4-grok46-high/_rows.txt")
lines = []
for i, line in enumerate(src.read_text().splitlines(), 1):
    if not line.strip():
        continue
    d = json.loads(line)
    rec = d.get("recent") or []
    lines.append(f"ROW {i} ghsa={d.get('ghsa')} repo={d.get('repo')} published={d.get('published')} ai_commits_before={d.get('ai_commits_before')} n_recent={len(rec)}")
    lines.append(f"  summary={(d.get('summary') or '')[:240]!r}")
    for j, c in enumerate(rec[:6], 1):
        files = c.get('files') or []
        kinds = c.get('kinds') or []
        lines.append(f"  C{j} sha={c.get('sha')} date={c.get('date')} kinds={kinds} files={files}")
    lines.append('')
out.write_text('
'.join(lines))
print('wrote', out, 'bytes', out.stat().st_size)
