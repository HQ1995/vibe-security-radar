import json
from pathlib import Path
ADV=Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed")
OWNED=Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-fwd4-grok46-high")
slice_path=Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/fwd-slice-4.jsonl")
rows=[json.loads(l) for l in slice_path.read_text().splitlines() if l.strip()]
out=[]
for row in rows:
    ghsa=row["ghsa"]
    found=None
    needle=ghsa.lower()".json"
    for pth in ADV.rglob(needle):
        found=pth
        break
    rec={"ghsa":ghsa,"path":str(found) if found else None}
    if found:
        data=json.loads(found.read_text())
        rec["id"]=data.get("id")
        rec["aliases"]=data.get("aliases")
        rec["summary"]=data.get("summary")
        rec["details"]=(data.get("details") or "")[:4000]
        rec["severity"]=(data.get("database_specific") or {}).get("severity")
        rec["cwe"]=(data.get("database_specific") or {}).get("cwe_ids")
        rec["refs"]=data.get("references")
        rec["withdrawn"]=data.get("withdrawn")
        rec["affected"]=[]
        for a in data.get("affected") or []:
            rec["affected"].append({"package":a.get("package"),"ranges":a.get("ranges"),"versions":a.get("versions"),"database_specific":a.get("database_specific")})
    out.append(rec)
(OWNED/"advisories.json").write_text(json.dumps(out, indent=2))
print("WROTE", len(out), "found", sum(1 for r in out if r.get("path")))
for rec in out:
    print("GHSA", rec["ghsa"])
    print("PATH", rec.get("path"))
    print("ALIASES", rec.get("aliases"))
    print("SUMMARY", rec.get("summary"))
    print("CWE", rec.get("cwe"))
    print("WITHDRAWN", rec.get("withdrawn"))
    aff=rec.get("affected") or []
    for a in aff[:2]:
        pkg=a.get("package") or {}
        print("PKG", pkg.get("name"), "ECO", pkg.get("ecosystem"))
        for r in (a.get("ranges") or [])[:2]:
            print(" RANGE", r.get("type"), r.get("events"))
    details=rec.get("details") or ""
    print("DETAILS", details[:900].replace(chr(10), " | "))
    print("---")
