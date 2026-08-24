#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-w2-unknown9-grok46-high"
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/slice-01.jsonl"
ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database")

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]

def find_adv(ghsa):
    slug = ghsa.lower()
    fname = f"{slug}.json"
    for dirpath, dirnames, filenames in os.walk(ADV / "advisories"):
        if fname in filenames:
            return os.path.join(dirpath, fname)
        base = os.path.basename(dirpath)
        if base in {".git", "unreviewed"}:
            dirnames[:] = []
    return None

out = []
for r in rows:
    ghsa = r["ghsa_id"]
    p = find_adv(ghsa)
    rec = {"ghsa": ghsa, "path": p}
    if p:
        obj = json.loads(Path(p).read_text())
        rec["aliases"] = obj.get("aliases")
        rec["summary"] = (obj.get("summary") or "")[:300]
        rec["details_head"] = (obj.get("details") or "")[:800]
        rec["severity"] = obj.get("severity")
        rec["withdrawn"] = obj.get("withdrawn")
        rec["nvd_published"] = None
        refs = []
        for ref in obj.get("references") or []:
            url = ref.get("url") if isinstance(ref, dict) else str(ref)
            refs.append(url)
        rec["refs"] = refs[:20]
        pkgs = []
        ranges = []
        for aff in obj.get("affected") or []:
            pkg = aff.get("package") or {}
            pkgs.append({"eco": pkg.get("ecosystem"), "name": pkg.get("name")})
            for rng in aff.get("ranges") or []:
                ranges.append({
                    "type": rng.get("type"),
                    "events": rng.get("events"),
                    "repo": rng.get("repo"),
                })
        rec["packages"] = pkgs
        rec["ranges"] = ranges
        rec["database_specific"] = {
            k: (obj.get("database_specific") or {}).get(k)
            for k in ("github_reviewed", "severity", "cwe_ids", "nvd_published_at")
        }
    out.append(rec)

(OWNED / "_advisories.json").write_text(json.dumps(out, indent=2)[:400000])
print("found", sum(1 for x in out if x.get("path")), "of", len(out))
for x in out:
    print(x["ghsa"], "path=" + str(bool(x.get("path"))), "aliases=" + str(x.get("aliases")), "pkgs=" + str(x.get("packages")))
