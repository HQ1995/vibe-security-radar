#!/usr/bin/env python3
import hashlib, json
from pathlib import Path

OWN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale3-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fwd-slice-7.jsonl")
CLONE = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database")

def ghsa_path(ghsa, published):
    y, m = published[:7].split("-")
    ident = "GHSA-" + ghsa[5:].lower()
    return CLONE / "advisories/github-reviewed" / y / m / ident / f"{ident}.json"

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
out = []
found = 0
for row in rows:
    p = ghsa_path(row["ghsa"], row["published"])
    rec = {
        "ghsa": row["ghsa"],
        "repo": row["repo"],
        "published": row["published"],
        "summary": row["summary"],
        "path": str(p) if p.is_file() else None,
    }
    if p.is_file():
        found += 1
        data = json.loads(p.read_text())
        rec["aliases"] = data.get("aliases") or []
        rec["summary_adv"] = data.get("summary") or ""
        rec["details"] = (data.get("details") or "")[:4000]
        rec["withdrawn"] = data.get("withdrawn")
        rec["severity"] = (data.get("database_specific") or {}).get("severity")
        rec["cwe"] = (data.get("database_specific") or {}).get("cwe_ids")
        affected = []
        for pkg in data.get("affected") or []:
            pkg_id = (pkg.get("package") or {}).get("name")
            eco = (pkg.get("package") or {}).get("ecosystem")
            ranges = []
            for r in pkg.get("ranges") or []:
                ranges.append({"type": r.get("type"), "events": r.get("events")})
            affected.append({"package": pkg_id, "ecosystem": eco, "ranges": ranges, "versions": pkg.get("versions")})
        rec["affected"] = affected
        rec["refs"] = [r.get("url") for r in (data.get("references") or [])][:30]
        rec["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
        rec["id"] = data.get("id")
    print(row["ghsa"], "OK" if rec["path"] else "MISS")
    out.append(rec)
(OWN / "advisories.json").write_text(json.dumps(out, indent=2))
print(f"found {found}/{len(rows)}")
