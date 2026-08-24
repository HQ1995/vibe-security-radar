import json, os, glob
from pathlib import Path
slice_path = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-fix-slice-2.jsonl")
rows = [json.loads(l) for l in slice_path.read_text().splitlines() if l.strip()]
print("NROWS", len(rows))
clone_root = Path("/home/hanqing/.cache/ghsa200-worker-clones")
adv_dbs = sorted({p.parent for p in clone_root.glob("*/advisory-database/advisories")})
print("ADV_DBS", len(adv_dbs))
for r in rows:
    cid = r["case_id"].lower()
    found = []
    for db in adv_dbs:
        hits = list(db.rglob(cid + ".json"))
        if hits:
            found.append(str(hits[0]))
            break
    print(r["case_id"], found[0] if found else "MISSING")
