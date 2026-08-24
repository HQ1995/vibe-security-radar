from pathlib import Path
import json, os
ROOT = Path("/home/hanqing/agents/ai-slop")
OWN = ROOT / "autoresearch/herdr-260814-w2-s5-grok46-high"
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-2.jsonl"
CLONE = Path("/home/hanqing/.cache/ghsa200-worker-clones")
rows = [json.loads(x) for x in SLICE.read_text().splitlines() if x.strip()]
repos = sorted({r["repository"] for r in rows})
out = []
out.append("NROWS " + str(len(rows)))
out.append("REPOS " + " ".join(repos))
hits = {}
for p in CLONE.rglob("*"):
    name = p.name
    if "__" in name and p.is_dir():
        hits.setdefault(name, []).append(str(p))
out.append("CLONE_DIRS " + str(len(hits)))
for repo in repos:
    key = repo.replace("/", "__")
    out.append("REPO " + repo + " KEY " + key + " N " + str(len(hits.get(key, []))))
    for h in hits.get(key, [])[:8]:
        out.append("  " + h)
adv_roots = []
for p in [CLONE, Path("/home/hanqing/agents/ai-slop/.ai-slop/cache")]:
    if p.exists():
        for q in p.rglob("advisory-database"):
            if q.is_dir():
                adv_roots.append(str(q))
out.append("ADV_ROOTS " + str(len(adv_roots)))
for a in adv_roots[:20]:
    out.append("ADV " + a)
ids = [r["ghsa_id"] for r in rows]
out.append("GHSA " + " ".join(ids))
(OWN/"_discover.txt").write_text("
".join(out) + "
")
print("WROTE", OWN/"_discover.txt", "lines", len(out))
