#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s3-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-3.jsonl")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones")
rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]

adv_dbs = [p for p in CLONE_ROOT.glob("*/advisory-database") if p.is_dir()]
print("ADV_DBS", len(adv_dbs), flush=True)

# targeted clone listing: one-level batches then owner__repo dirs
clone_index = {}
batches = [p for p in CLONE_ROOT.iterdir() if p.is_dir()]
print("BATCHES", len(batches), flush=True)
for b in batches:
    try:
        for d in b.iterdir():
            if d.is_dir() and "__" in d.name:
                clone_index.setdefault(d.name, []).append(d)
            elif d.is_dir():
                try:
                    for d2 in d.iterdir():
                        if d2.is_dir() and "__" in d2.name:
                            clone_index.setdefault(d2.name, []).append(d2)
                except PermissionError:
                    pass
    except PermissionError:
        pass
print("CLONE_KEYS", len(clone_index), flush=True)

def find_adv(gid):
    low = gid.lower()
    hits = []
    for db in adv_dbs:
        # typical layout advisories/github-reviewed/YYYY/MM/ghsa/ghsa.json
        base = db / "advisories" / "github-reviewed"
        if not base.exists():
            continue
        for year in base.iterdir() if base.is_dir() else []:
            if not year.is_dir():
                continue
            for month in year.iterdir():
                if not month.is_dir():
                    continue
                cand = month / low / (low + ".json")
                if cand.exists():
                    hits.append(str(cand))
                    return hits
    return hits

def find_clones(repo):
    owner, name = repo.split("/", 1)
    key = f"{owner}__{name}"
    hits = clone_index.get(key, [])
    if not hits:
        # fallback suffix match
        for k, vs in clone_index.items():
            if k.endswith("__" + name):
                hits.extend(vs)
    return [str(p) for p in hits[:8]]

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
