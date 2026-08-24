#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path

SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/ai-fix-slice-2.jsonl")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones")
POOL = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")
OUT = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-af2-grok46-high/work")
OUT.mkdir(exist_ok=True)

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
dbs = sorted(p for p in CLONE_ROOT.glob("*/advisory-database") if p.is_dir())

def find_adv(cid):
    name = cid.lower() + ".json"
    mixed = cid[:5] + cid[5:].lower() + ".json" if False else cid + ".json"
    mixed = cid + ".json"
    mixed2 = "GHSA-" + cid[5:].lower() + ".json"
    names = {name, mixed, mixed2, cid.lower() + ".json"}
    for db in dbs:
        adv = db / "advisories" / "github-reviewed"
        if not adv.exists():
            continue
        for dirpath, _, files in os.walk(adv):
            for fn in files:
                if fn.lower() == name.lower() or fn in names:
                    return str(Path(dirpath) / fn)
    return None

summary = []
for i, row in enumerate(rows, 1):
    cid = row["case_id"]
    repo = row["repository"]
    sha = row["fix_ref"]
    found = find_adv(cid)
    rec = {"n": i, "case_id": cid, "repo": repo, "sha": sha, "advisory_path": found, "subject": row.get("subject")}
    if found:
        data = json.loads(Path(found).read_text())
        rec["ghsa"] = data.get("id") or data.get("ghsaId")
        rec["summary"] = data.get("summary")
        rec["withdrawn"] = data.get("withdrawn")
        rec["aliases"] = data.get("aliases")
        rec["refs"] = data.get("references")
        rec["affected"] = data.get("affected")
        rec["details"] = (data.get("details") or "")[:4000]
        rec["database_specific"] = data.get("database_specific")
    pool = POOL / repo.replace("/", "__")
    rec["pool"] = str(pool)
    rec["pool_exists"] = pool.exists()
    if pool.exists():
        try:
            show = subprocess.check_output(["git","-C",str(pool),"log","-1","--format=%H%n%P%n%an <%ae>%n%s%n%b", sha], text=True, stderr=subprocess.STDOUT)
            rec["commit"] = show[:8000]
        except subprocess.CalledProcessError as e:
            rec["commit_err"] = (e.output or str(e))[:1500]
        try:
            stat = subprocess.check_output(["git","-C",str(pool),"show","--stat","--format=", sha], text=True, stderr=subprocess.STDOUT)
            rec["stat"] = stat[:4000]
        except subprocess.CalledProcessError as e:
            rec["stat_err"] = (e.output or str(e))[:500]
    Path(OUT / f"row-{i:02d}.json").write_text(json.dumps(rec, indent=2)[:400000])
    summary.append({"n": i, "case_id": cid, "found": bool(found), "path": found, "pool": rec["pool_exists"], "has_commit": "commit" in rec})
Path(OUT / "index.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
