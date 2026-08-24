#!/usr/bin/env python3
"""Copy official reviewed JSON for the 80 assigned IDs into batch2 evidence."""

from __future__ import annotations

import json
import re
from pathlib import Path

LANE = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-delta-even-batch2")
ADVISORY = Path("/tmp/ghsa200-worker-clones/delta-even/advisory-database/advisories/github-reviewed")
EVIDENCE = LANE / "evidence"
EVIDENCE.mkdir(parents=True, exist_ok=True)
REPO_RE = re.compile(r"https?://github\.com/([^/]+)/([^/#?\s]+)")


def extract_repo(blob: dict) -> str | None:
    package, advisory, other = [], [], []
    for ref in blob.get("references") or []:
        url = ref.get("url") or ""
        m = REPO_RE.search(url)
        if not m:
            continue
        owner, repo = m.group(1), m.group(2)
        if owner.lower() in {"advisories", "github", "nvd"}:
            continue
        ident = f"{owner}/{repo}"
        rtype = (ref.get("type") or "").upper()
        if rtype == "PACKAGE":
            package.append(ident)
        elif "/security/advisories/" in url:
            advisory.append(ident)
        else:
            other.append(ident)
    for pool in (package, advisory, other):
        if pool:
            return pool[0]
    return None


def commit_refs(blob: dict) -> list[str]:
    out = []
    for ref in blob.get("references") or []:
        url = ref.get("url") or ""
        m = re.search(r"github\.com/[^/]+/[^/]+/commit/([0-9a-f]{7,40})", url, re.I)
        if m:
            out.append(m.group(1))
    return out


def main() -> None:
    ids = [ln.strip() for ln in (LANE / "assignment_ids.txt").read_text().splitlines() if ln.strip()]
    index = {p.stem.upper(): p for p in ADVISORY.rglob("GHSA-*.json")}
    packets = []
    for gid in ids:
        src = index[gid]
        dest = EVIDENCE / f"{gid}.official-github-reviewed.json"
        dest.write_bytes(src.read_bytes())
        blob = json.loads(src.read_text())
        packets.append(
            {
                "ghsa_id": gid,
                "repository": extract_repo(blob),
                "aliases": [str(a).upper() for a in (blob.get("aliases") or [])],
                "summary": blob.get("summary") or "",
                "published": blob.get("published"),
                "withdrawn": blob.get("withdrawn"),
                "commit_refs": commit_refs(blob),
                "affected": [
                    {
                        "ecosystem": (a.get("package") or {}).get("ecosystem"),
                        "name": (a.get("package") or {}).get("name"),
                        "events": [e for rng in (a.get("ranges") or []) for e in (rng.get("events") or [])],
                        "last_known": (a.get("database_specific") or {}).get("last_known_affected_version_range"),
                    }
                    for a in (blob.get("affected") or [])
                ],
                "official_json": str(src),
                "evidence_copy": str(dest.relative_to(LANE)),
            }
        )
    (LANE / "advisory_packets.jsonl").write_text("".join(json.dumps(p, ensure_ascii=True) + "\n" for p in packets))
    repos = sorted({p["repository"] for p in packets if p["repository"]})
    print(json.dumps({"packets": len(packets), "repos": repos, "missing_repo": [p["ghsa_id"] for p in packets if not p["repository"]]}, indent=2))


if __name__ == "__main__":
    main()
