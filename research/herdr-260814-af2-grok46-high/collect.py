#!/usr/bin/env python3
import json, os, subprocess, hashlib
from pathlib import Path

SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-fix-slice-2.jsonl")
ADV_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database")
POOL = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")
OUT = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-af2-grok46-high/work")
OUT.mkdir(exist_ok=True)

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
summary = []
for i, row in enumerate(rows, 1):
    cid = row["case_id"]
    low = cid.lower()
    repo = row["repository"]
    sha = row["fix_ref"]
    found = None
    for dirpath, _, files in os.walk(ADV_ROOT / "advisories"):
        if f"{low}.json" in files:
            found = str(Path(dirpath) / f"{low}.json")
            break
    rec = {"n": i, "case_id": cid, "repo": repo, "sha": sha, "advisory_path": found}
    if found:
        data = json.loads(Path(found).read_text())
        rec["ghsa"] = data.get("id") or data.get("ghsaId")
        rec["summary"] = (data.get("summary") or "")[:240]
        rec["withdrawn"] = data.get("withdrawn")
        rec["aliases"] = data.get("aliases")
        rec["refs"] = data.get("references")
        rec["affected"] = data.get("affected")
        rec["details"] = (data.get("details") or "")[:1200]
    pool = POOL / repo.replace("/", "__")
    rec["pool"] = str(pool)
    rec["pool_exists"] = pool.exists()
    if pool.exists():
        try:
            show = subprocess.check_output(["git","-C",str(pool),"log","-1","--format=%H%n%P%n%an <%ae>%n%s%n%b", sha], text=True, stderr=subprocess.STDOUT)
            rec["commit"] = show[:2500]
        except subprocess.CalledProcessError as e:
            rec["commit_err"] = (e.output or str(e))[:500]
    Path(OUT / f"row-{i:02d}.json").write_text(json.dumps(rec, indent=2)[:200000])
    summary.append({"n": i, "case_id": cid, "found": bool(found), "pool": rec["pool_exists"], "has_commit": "commit" in rec})
Path(OUT / "index.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
