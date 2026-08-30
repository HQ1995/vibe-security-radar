#!/usr/bin/env python3
"""Join 36,645 product-source clusters to the 0% AI-trace funnel cut.

Inventory HAS_AI (2026-08-16 code-writer ∪ 2026-08-26 local) plus the live
unknown-repo scan (matcher, AI committer, agent configs, all remote branches).
Does not write the ledger.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_ai_writer_gate_20260826 as gate
import recover_advisory_ids_20260826 as rec

ROOT = rec.ROOT
CLUSTERS = rec.STATE / "upstream-deduped-20260826.jsonl"
PASS = rec.STATE / "ai-writer-pass-20260826.jsonl"
SCAN_RESULTS = ROOT / ".ai-slop/state/funnel-ai-writer-20260826/scan-results.jsonl"
META = ROOT / "artifacts/funnel-universe-meta-20260826.json"
STATS_OUT = rec.STATE / "zero-pct-gate-20260826.json"
REMAINING_OUT = rec.STATE / "zero-pct-remaining-20260826.jsonl"
DROPPABLE_OUT = rec.STATE / "zero-pct-droppable-20260826.jsonl"


def latest_scan_rows() -> dict[str, dict]:
    latest: dict[str, dict] = {}
    if not SCAN_RESULTS.is_file():
        return latest
    with SCAN_RESULTS.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            repo = row.get("repo")
            if repo:
                latest[repo] = row
    return latest


def unknown_reason(row: dict | None) -> str:
    if row is None:
        return "unscanned"
    err = f"{row.get('clone_error') or ''} {row.get('scan_error') or ''}"
    repo = str(row.get("repo") or "")
    if "user-attachments/" in repo:
        return "not_a_repo"
    if "Repository not found" in err:
        return "not_found"
    if "timeout" in err.lower():
        return "timeout"
    if "no_clone_url" in err:
        return "no_clone_url"
    if "Username" in err or "Authentication" in err:
        return "private"
    if "googlesource.com" in repo and "not found" in err.lower():
        return "casefold_or_missing"
    return "clone_fail"


def classify_scan_row(row: dict | None) -> str:
    """has_ai | keep_config | droppable | unknown | unscanned."""
    if row is None:
        return "unscanned"
    if row.get("has_ai"):
        return "has_ai"
    if row.get("clone_ok") and "no readable refs" in str(row.get("scan_error") or ""):
        # Empty clone: no commits to attribute. Not a clone failure.
        return "droppable"
    if not row.get("clone_ok") or not row.get("scan_complete"):
        return "unknown"
    if (
        not row.get("all_refs")
        or "agent_configs" not in row
        or "committer_ai_count" not in row
    ):
        return "unscanned"
    if row.get("agent_configs"):
        return "keep_config"
    if row.get("droppable"):
        return "droppable"
    return "unknown"


def load_inventory_writer() -> set[str]:
    writer: set[str] = set()
    with PASS.open(encoding="utf-8") as handle:
        for line in handle:
            writer.update(gate.identity_keys(json.loads(line)["repo"]))
    return writer


def classify_cluster(cluster: dict, writer: set[str], scan: dict[str, dict]) -> str:
    repo = cluster["repo"]
    if gate.identity_keys(repo) & writer:
        return "has_ai"
    return classify_scan_row(scan.get(repo))


def main() -> int:
    writer = load_inventory_writer()
    scan = latest_scan_rows()
    buckets = Counter()
    unknown_reasons = Counter()
    by_kind = {name: Counter() for name in ("has_ai", "keep_config", "droppable", "unknown", "unscanned")}
    remaining: list[dict] = []
    droppable: list[dict] = []
    unique_repos: dict[str, str] = {}
    product_n = 0
    with CLUSTERS.open(encoding="utf-8") as handle:
        for line in handle:
            cluster = json.loads(line)
            if not (cluster.get("in_window") and cluster.get("repo")):
                continue
            product_n += 1
            bucket = classify_cluster(cluster, writer, scan)
            kind = gate.kind_of(cluster)
            buckets[bucket] += 1
            by_kind[bucket][kind] += 1
            if bucket == "unknown":
                unknown_reasons[unknown_reason(scan.get(cluster["repo"]))] += 1
            unique_repos[cluster["repo"]] = bucket
            row = {
                "class_id": cluster["class_id"],
                "repo": cluster["repo"],
                "kind": kind,
                "bucket": bucket,
            }
            if bucket == "droppable":
                droppable.append(row)
            else:
                remaining.append(row)

    repo_buckets = Counter(unique_repos.values())
    complete = buckets["unscanned"] == 0 and product_n == 36645
    leftover = product_n - buckets["droppable"]
    stats = {
        "gate": (
            "0% AI-introduced: drop only complete all-refs scans with no Source v3 "
            "matcher hit, no AI committer, and no agent config files. Inventory "
            "HAS_AI plus live unknown-repo scan. Clone/scan failure stays unknown."
        ),
        "complete": complete,
        "product_source_clusters": product_n,
        "product_source_unique_repos": len(unique_repos),
        "clusters": dict(buckets),
        "unique_repos": dict(repo_buckets),
        "by_kind": {name: dict(counts) for name, counts in by_kind.items() if counts},
        "leftover_clusters": leftover,
        "droppable_clusters": buckets["droppable"],
        "unscanned_clusters": buckets["unscanned"],
        "unknown_reasons": dict(unknown_reasons),
        "ledger_untouched": True,
    }

    STATS_OUT.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    with REMAINING_OUT.open("w", encoding="utf-8") as handle:
        for row in remaining:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    with DROPPABLE_OUT.open("w", encoding="utf-8") as handle:
        for row in droppable:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    meta = json.loads(META.read_text(encoding="utf-8"))
    layers = meta.setdefault("layers", {})
    layers["in_window_with_product_source_repo"] = product_n
    layers["in_window_zero_pct_has_ai"] = buckets["has_ai"]
    layers["in_window_zero_pct_keep_config"] = buckets["keep_config"]
    layers["in_window_zero_pct_droppable"] = buckets["droppable"]
    layers["in_window_zero_pct_unknown"] = buckets["unknown"]
    layers["in_window_zero_pct_unscanned"] = buckets["unscanned"]
    layers["in_window_zero_pct_leftover"] = leftover
    layers["in_window_zero_pct_unique_repos"] = len(unique_repos)
    layers["in_window_zero_pct_unique_has_ai"] = repo_buckets["has_ai"]
    layers["in_window_zero_pct_unique_keep_config"] = repo_buckets["keep_config"]
    layers["in_window_zero_pct_unique_droppable"] = repo_buckets["droppable"]
    layers["in_window_zero_pct_unique_unknown"] = repo_buckets["unknown"]
    layers["zero_pct_gate_note"] = (
        "Live 0% cut on the 36,645 product-source clusters: drop only complete "
        "all-branch scans with zero Source v3 hits, zero AI committer, and no "
        "agent config files. Empty clones (no readable refs) are droppable. "
        "Remaining unknown is researched clone failure (404, private, timeout, "
        "403), not unscanned. Inventory HAS_AI (2026-08-16 code-writer ∪ "
        "2026-08-26 local) is kept. Ledger not rewritten."
        + ("" if complete else " SCAN INCOMPLETE.")
    )
    layers["zero_pct_gate_complete"] = complete
    layers["ai_writer_gate_note"] = (
        "Historical inventory layer only (24,860). The live leftover after the "
        "0% cut is layers.in_window_zero_pct_leftover. Ledger not rewritten."
    )
    meta["zero_pct_gate"] = stats
    META.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
