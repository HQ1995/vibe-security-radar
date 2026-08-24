#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s3-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-3.jsonl")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones")
rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
print("NROWS", len(rows), flush=True)

def sh(cmd):
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()

adv_dbs = []
for p in CLONE_ROOT.iterdir():
    d = p / "advisory-database"
    if d.is_dir():
        adv_dbs.append(d)
print("ADV_DBS", len(adv_dbs), flush=True)

def find_adv(gid):
    name = gid.lower() + ".json"
    hits = []
    for db in adv_dbs:
        cmd = f"find {db} -name {name} -type f 2>/dev/null | head -n 3"
        out = sh(cmd)
        if out:
            hits.extend(out.splitlines())
        if len(hits) >= 3:
            break
    return hits

def find_clones(repo):
    owner, name = repo.split("/", 1)
    key = f"{owner}__{name}"
    cmd = f"find {CLONE_ROOT} -maxdepth 4 -type d -name {key} 2>/dev/null | head -n 8"
    out = sh(cmd)
    hits = out.splitlines() if out else []
    if not hits:
        cmd = f"find {CLONE_ROOT} -maxdepth 5 -type d -name '*{name}*' 2>/dev/null | head -n 12"
        out = sh(cmd)
        hits = [x for x in (out.splitlines() if out else []) if (Path(x)/".git").exists() or (Path(x)/"HEAD").exists()]
    return hits[:8]

out = []
for i, r in enumerate(rows):
    gid = r["ghsa_id"]
    repo = r["repository"]
    refs = r.get("commit_refs") or []
    advs = find_adv(gid)
    clones = find_clones(repo)
    rec = {"i": i, "ghsa": gid, "repo": repo, "refs": refs, "advs": advs, "clones": clones}
    print(f"{i:02d} {gid} adv={len(advs)} clones={len(clones)} firstclone={clones[0] if clones else '-'}", flush=True)
    out.append(rec)

(OWNED / "_map.json").write_text(json.dumps(out, indent=2))
print("WROTE", OWNED / "_map.json", flush=True)
