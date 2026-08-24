#!/usr/bin/env python3
"""Intersect mined AI commits with assigned first-party GHSAs.

An intersection is routing, never a seven-gate PASS by itself.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

OUT = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gn")
ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database")

TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_./-]{3,}")
STOP = {
    "this",
    "that",
    "with",
    "from",
    "have",
    "been",
    "were",
    "when",
    "where",
    "which",
    "their",
    "there",
    "about",
    "after",
    "before",
    "into",
    "over",
    "under",
    "vulnerability",
    "security",
    "advisory",
    "github",
    "commit",
    "fixed",
    "affected",
    "version",
    "versions",
    "package",
    "packages",
}


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def tokens(text: str) -> set[str]:
    return {m.group(0).lower() for m in TOKEN_RE.finditer(text or "") if m.group(0).lower() not in STOP}


def file_names(path: Path, sha: str) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), "show", "--name-only", "--pretty=format:", sha],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return []
    if completed.returncode != 0:
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def main() -> None:
    assigned = load_jsonl(OUT / "assigned.jsonl")
    scans = load_jsonl(OUT / "ai-commit-scans.jsonl")
    by_repo_ghsa = defaultdict(list)
    for row in assigned:
        by_repo_ghsa[row["repository"]].append(row)
    intersections = []
    for scan in scans:
        repo = scan["repository"]
        commits = scan.get("ai_commits") or []
        if not commits:
            continue
        ghsas = by_repo_ghsa.get(repo) or []
        if not ghsas:
            continue
        path = Path(scan.get("path") or "")
        sha_index = {c["sha"].lower(): c for c in commits}
        short_index = {c["sha"][:12].lower(): c for c in commits}
        for ghsa in ghsas:
            matched_refs = []
            for ref in ghsa.get("commit_refs") or []:
                hit = sha_index.get(ref.lower()) or short_index.get(ref[:12].lower())
                if hit:
                    matched_refs.append(hit)
            # token overlap between advisory summary and AI commit subjects
            summary_toks = tokens(ghsa.get("summary") or "")
            subject_hits = []
            for commit in commits:
                subj_toks = tokens(commit.get("subject") or "")
                overlap = summary_toks & subj_toks
                securityish = any(
                    w in (commit.get("subject") or "").lower()
                    for w in ("secur", "xss", "ssrf", "inject", "auth", "bypass", "travers", "rce", "csrf")
                )
                if len(overlap) >= 2 or (securityish and overlap):
                    subject_hits.append(
                        {
                            "sha": commit["sha"],
                            "subject": commit["subject"],
                            "overlap": sorted(overlap)[:12],
                            "date": commit.get("date"),
                            "marker_pattern": commit.get("marker_pattern"),
                        }
                    )
            if not matched_refs and not subject_hits:
                continue
            intersections.append(
                {
                    "ghsa_id": ghsa["ghsa_id"],
                    "repository": repo,
                    "summary": ghsa.get("summary"),
                    "commit_refs": ghsa.get("commit_refs") or [],
                    "matched_ai_commit_refs": matched_refs,
                    "subject_overlap_hits": subject_hits[:8],
                    "ai_commit_count_in_repo": len(commits),
                    "routing_only": True,
                }
            )
    intersections.sort(key=lambda r: (0 if r["matched_ai_commit_refs"] else 1, r["ghsa_id"]))
    with (OUT / "ai-ghsa-intersections.jsonl").open("w", encoding="utf-8") as fh:
        for row in intersections:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "intersection_rows": len(intersections),
        "exact_ref_matches": sum(1 for r in intersections if r["matched_ai_commit_refs"]),
        "subject_only": sum(1 for r in intersections if r["subject_overlap_hits"] and not r["matched_ai_commit_refs"]),
        "note": "Intersections are commit-first routing pointers, not causal proof.",
    }
    (OUT / "ai-ghsa-intersection-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True))


if __name__ == "__main__":
    main()
