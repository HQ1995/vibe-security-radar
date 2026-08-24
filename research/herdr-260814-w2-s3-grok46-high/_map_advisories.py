#!/usr/bin/env python3
import json, os, glob, hashlib
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s3-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-3.jsonl")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones")
rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
print("NROWS", len(rows), flush=True)

adv_dbs = []
for p in CLONE_ROOT.glob("*/advisory-database"):
    if p.is_dir():
        adv_dbs.append(p)
print("ADV_DBS", len(adv_dbs), flush=True)

# find clones matching owner__repo
clone_dirs = []
for p in CLONE_ROOT.rglob("*"):
    if p.is_dir() and "__" in p.name and (p / ".git").exists():
        clone_dirs.append(p)
print("GIT_CLONES", len(clone_dirs), flush=True)

def find_adv(gid):
    low = gid.lower()
    name = low + ".json"
    hits = []
    for db in adv_dbs:
        for hit in db.rglob(name):
            hits.append(str(hit))
            if len(hits) >= 3:
                return hits
    return hits

def find_clones(repo):
    owner, name = repo.split("/", 1)
    key = f"{owner}__{name}"
    hits = []
    for d in clone_dirs:
        if d.name == key or d.name.endswith("__" + name):
            hits.append(str(d))
    # also match by path fragment
    if not hits:
        for d in clone_dirs:
            if name.lower() in d.name.lower() and owner.lower().replace("-","") in d.name.lower().replace("-",""):
                hits.append(str(d))
    return hits[:8]

out = []
for i, r in enumerate(rows):
    gid = r["ghsa_id"]
    repo = r["repository"]
    refs = r.get("commit_refs") or []
    advs = find_adv(gid)
    clones = find_clones(repo)
    rec = {
        "i": i,
        "ghsa": gid,
        "repo": repo,
        "refs": refs,
        "advs": advs,
        "clones": clones,
    }
    print(f"{i:02d} {gid} adv={len(advs)} clones={len(clones)} firstclone={clones[0] if clones else '-'}", flush=True)
    out.append(rec)

(OWNED / "_map.json").write_text(json.dumps(out, indent=2))
print("WROTE", OWNED / "_map.json", flush=True)
