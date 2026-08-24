#!/usr/bin/env python3
import json
from pathlib import Path

ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/advisory-database")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/slice-05.jsonl")
OUT = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s5-grok46-high/advisory_extract.jsonl")

rows = []
for line in SLICE.read_text().splitlines():
    if line.strip():
        rows.append(json.loads(line))

def pick_refs(obj):
    refs = obj.get("references") or []
    out = []
    for r in refs:
        if isinstance(r, dict):
            url = r.get("url") or ""
            typ = r.get("type") or ""
        else:
            url = str(r)
            typ = ""
        out.append({"type": typ, "url": url})
    return out

with OUT.open("w") as fh:
    for i, row in enumerate(rows, 1):
        p = ADV / row["path"]
        obj = json.loads(p.read_text())
        rec = {
            "ord": i,
            "ghsa": row["ghsa"],
            "aliases": row.get("aliases") or obj.get("aliases") or [],
            "packages": row.get("packages") or [],
            "ecosystems": row.get("ecosystems") or [],
            "path": row["path"],
            "published": row.get("published"),
            "collisions": row.get("collisions") or [],
            "id": obj.get("id"),
            "summary": obj.get("summary"),
            "details": (obj.get("details") or "")[:800],
            "severity": obj.get("severity"),
            "withdrawn": obj.get("withdrawn"),
            "nvd_published_at": obj.get("nvd_published_at"),
            "github_reviewed": obj.get("github_reviewed"),
            "github_reviewed_at": obj.get("github_reviewed_at"),
            "cwe_ids": obj.get("cwe_ids"),
            "affected": obj.get("affected"),
            "references": pick_refs(obj),
            "credits": obj.get("credits"),
            "database_specific": obj.get("database_specific"),
        }
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"wrote {len(rows)} {OUT}")
