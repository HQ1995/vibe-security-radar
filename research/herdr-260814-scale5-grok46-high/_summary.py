import json
from pathlib import Path

p = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale5-grok46-high/_evidence.json")
rows = json.loads(p.read_text())
out = []
out.append(f"nrows {len(rows)}")
for r in rows:
    adv = r.get("advisory") or {}
    git = r.get("git") or {}
    out.append(
        f"{r.get('case_id')} adv={bool(adv.get('path'))} withdrawn={adv.get('withdrawn')} "
        f"anc={git.get('ancestor_present')} fix={git.get('fix_present')} "
        f"files={git.get('ancestor_files')} marker={git.get('ai_marker')!r} "
        f"err={git.get('diff_error')}"
    )
Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale5-grok46-high/_summary.txt").write_text("\n".join(out) + "\n")
print("wrote", len(rows))
