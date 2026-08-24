#!/usr/bin/env python3
"""Freeze the first 80 SCREENED_NO_PLAUSIBLE_AI IDs. Writes only batch2."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

LANE = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-delta-even-batch2")
ROOT = Path("/home/hanqing/agents/ai-slop")
MANIFEST = ROOT / "autoresearch/herdr-260813-ghsa200-delta-even/routing_manifest.jsonl"
EVEN_IDS = ROOT / "autoresearch/herdr-260813-ghsa200-delta-even/partition_even_ids.txt"
DECLARED = ROOT / "autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/leader_declared_ids.txt"
WINDOW = ROOT / "autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/github_reviewed_window_added_ids.txt"
EVEN_NIBBLES = set("02468ace")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def nibble(gid: str) -> str:
    return hashlib.sha256(gid.upper().encode("ascii")).hexdigest()[-1]


def main() -> None:
    LANE.mkdir(parents=True, exist_ok=True)
    rows = [json.loads(l) for l in MANIFEST.read_text().splitlines() if l.strip()]
    screened = [r for r in rows if r.get("final_route") == "SCREENED_NO_PLAUSIBLE_AI"]
    deep = {r["ghsa_id"].upper() for r in rows if r.get("deep_reviewed") or r.get("final_route") == "DEEP_REVIEWED_REJECT"}
    declared = {ln.strip().upper() for ln in DECLARED.read_text().splitlines() if ln.strip()}
    even = {ln.strip().upper() for ln in EVEN_IDS.read_text().splitlines() if ln.strip()}
    window = {ln.strip().upper() for ln in WINDOW.read_text().splitlines() if ln.strip()}

    screened_sorted = sorted(screened, key=lambda r: r["ghsa_id"].upper())
    assigned = screened_sorted[:80]
    ids = [r["ghsa_id"].upper() for r in assigned]
    if len(ids) != 80:
        raise SystemExit(f"expected 80, got {len(ids)}")
    if len(set(ids)) != 80:
        raise SystemExit("assigned IDs not unique")
    bad_part = [i for i in ids if nibble(i) not in EVEN_NIBBLES or i not in even]
    if bad_part:
        raise SystemExit(f"not even: {bad_part}")
    overlap_decl = [i for i in ids if i in declared]
    if overlap_decl:
        raise SystemExit(f"declared overlap: {overlap_decl}")
    overlap_deep = [i for i in ids if i in deep]
    if overlap_deep:
        raise SystemExit(f"prior deep overlap: {overlap_deep}")
    missing_window = [i for i in ids if i not in window]
    if missing_window:
        raise SystemExit(f"not in 731 window: {missing_window}")

    freeze = {
        "schema_version": 1,
        "lane": "herdr-260813-ghsa200-delta-even-batch2",
        "selection_rule": "From delta-even/routing_manifest.jsonl rows with final_route=SCREENED_NO_PLAUSIBLE_AI, sort uppercase ghsa_id lexicographically, take first 80",
        "assigned_count": 80,
        "unique": True,
        "all_even": True,
        "leader_declared_overlap": 0,
        "prior_deep_reviewed_overlap": 0,
        "in_731_window": True,
        "assigned_ids": ids,
        "assigned_rows": [
            {
                "ordinal": i + 1,
                "ghsa_id": r["ghsa_id"].upper(),
                "sha256_last_nibble": r.get("sha256_last_nibble") or nibble(r["ghsa_id"]),
                "repository": r.get("repository"),
                "aliases": r.get("aliases") or [],
                "source_final_route": r.get("final_route"),
            }
            for i, r in enumerate(assigned)
        ],
        "input_hashes": {
            "delta_even_routing_manifest.jsonl": sha256_file(MANIFEST),
            "delta_even_partition_even_ids.txt": sha256_file(EVEN_IDS),
            "leader_declared_ids.txt": sha256_file(DECLARED),
            "github_reviewed_window_added_ids.txt": sha256_file(WINDOW),
        },
        "assertions": {
            "count_80": True,
            "unique_80": True,
            "all_even_partition": True,
            "no_leader_declared_overlap": True,
            "no_prior_deep_reviewed_overlap": True,
        },
    }
    (LANE / "assignment_manifest.json").write_text(json.dumps(freeze, indent=2) + "\n")
    (LANE / "assignment_ids.txt").write_text("".join(i + "\n" for i in ids))
    print(json.dumps({
        "assigned": 80,
        "repos": sorted({r.get("repository") for r in assigned}),
        "repo_count": len({r.get("repository") for r in assigned}),
        "hashes": freeze["input_hashes"],
    }, indent=2))


if __name__ == "__main__":
    main()
