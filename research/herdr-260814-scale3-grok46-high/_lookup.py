import hashlib, json, os, glob, sys
from pathlib import Path

OWN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale3-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fwd-slice-7.jsonl")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones")
FETCH = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
clones = sorted(CLONE_ROOT.glob("*/advisory-database"))
print("clones", len(clones), file=sys.stderr)
out = []
for row in rows:
    ghsa = row["ghsa"].lower()
    y, m = row["published"][:7].split("-")
    found = None
    for c in clones:
        p = c / "advisories/github-reviewed" / y / m / ghsa / f"{ghsa}.json"
        if p.is_file():
            found = str(p)
            break
    if not found:
        for c in clones:
            hits = list(c.glob(f"advisories/github-reviewed/*/*/{ghsa}/{ghsa}.json"))
            if hits:
                found = str(hits[0])
                break
    rec = {"ghsa": row["ghsa"], "repo": row["repo"], "published": row["published"], "summary": row["summary"], "path": found}
    if found:
        data = json.loads(Path(found).read_text())
        rec["aliases"] = data.get("aliases") or []
        rec["summary_adv"] = (data.get("summary") or "")[:400]
        details = data.get("details") or ""
        rec["details"] = details[:2500]
        rec["withdrawn"] = data.get("withdrawn")
        rec["severity"] = data.get("database_specific", {}).get("severity")
        rec["cwe"] = data.get("database_specific", {}).get("cwe_ids")
        affected = []
        for pkg in data.get("affected") or []:
            pkg_id = (pkg.get("package") or {}).get("name")
            eco = (pkg.get("package") or {}).get("ecosystem")
            ranges = []
            for r in pkg.get("ranges") or []:
                ranges.append({"type": r.get("type"), "events": r.get("events")})
            affected.append({"package": pkg_id, "ecosystem": eco, "ranges": ranges, "versions": pkg.get("versions")})
        rec["affected"] = affected
        rec["refs"] = [r.get("url") for r in (data.get("references") or [])][:20]
        rec["sha256"] = hashlib.sha256(Path(found).read_bytes()).hexdigest()
    out.append(rec)
    print(row["ghsa"], "OK" if found else "MISS", found or "")

(OWN / "advisories.json").write_text(json.dumps(out, indent=2))
print("wrote", OWN / "advisories.json")
