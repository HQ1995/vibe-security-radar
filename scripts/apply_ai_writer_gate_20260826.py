#!/usr/bin/env python3
"""Apply the next funnel cut after product-source git: AI-writer repo.

Does not write the ledger. Reuses the 2026-08-16 current-ai-scan inventory
(code-writing HAS_AI since 2025-05-01) plus the 2026-08-26 local clone rescan.
Unscanned repos are out of this layer, same as the original book construction.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oss_git_repos as oss
import recover_advisory_ids_20260826 as rec

ROOT = rec.ROOT
STATE = rec.STATE
CLUSTERS = STATE / "upstream-deduped-20260826.jsonl"
AI_REPOS = ROOT / ".ai-slop/state/census-research/ai-code-repos.json"
LOCAL_SCAN = STATE / "ai-scan-state-repos/summary.json"
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
NARROWED = ROOT / ".ai-slop/state/census-research/funnel-narrowed.jsonl"
META = ROOT / "artifacts/funnel-universe-meta-20260826.json"
PASS_OUT = STATE / "ai-writer-pass-20260826.jsonl"
STATS_OUT = STATE / "ai-writer-gate-20260826.json"

KERNEL_KEYS = frozenset(
    {
        oss.KERNEL_REPO,
        "git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux",
        "git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next",
        "github.com/torvalds/linux",
        "github.com/gregkh/linux",
        "torvalds/linux",
        "gregkh/linux",
    }
)


def identity_keys(ident: str) -> set[str]:
    raw = (ident or "").strip().lower().rstrip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    if not raw:
        return set()
    keys = {raw}
    host, owner, name = oss.split_identity(raw)
    if host == "git.kernel.org" or raw in KERNEL_KEYS:
        keys.update(KERNEL_KEYS)
    if host == "github.com" and owner and name:
        keys.add(f"{owner}/{name}")
        keys.add(f"github.com/{owner}/{name}")
    elif owner and name:
        keys.add(f"{host}/{owner}/{name}")
        if "." not in raw.split("/")[0]:
            keys.add(f"github.com/{owner}/{name}")
            keys.add(f"{owner}/{name}")
    return keys


def expand(idents: list[str] | set[str]) -> set[str]:
    out: set[str] = set()
    for ident in idents:
        out.update(identity_keys(ident))
    return out


def kind_of(cluster: dict) -> str:
    if cluster.get("reviewed"):
        return "reviewed"
    if cluster.get("unreviewed_only"):
        return "unreviewed"
    return "nvd_only"


def load_local_has_ai() -> tuple[set[str], set[str], int, int]:
    payload = json.loads(LOCAL_SCAN.read_text(encoding="utf-8"))
    has_ai: set[str] = set()
    no_ai: set[str] = set()
    for rec_row in payload.get("repositories") or []:
        ident = rec_row.get("repository_identity") or ""
        if int(rec_row.get("ai_commit_count") or 0) > 0:
            has_ai.add(ident)
        else:
            no_ai.add(ident)
    return expand(has_ai), expand(no_ai) - expand(has_ai), len(has_ai), len(no_ai)


def main() -> int:
    inventory = json.loads(AI_REPOS.read_text(encoding="utf-8"))
    code_writer = expand(inventory["code_writer_repos"])
    has_ai_any = expand(inventory["ai_repos"])
    local_has, local_no, local_has_n, local_no_n = load_local_has_ai()
    # Historical book gate: code-writing AI commits since 2025-05-01.
    # Local rescan can add repos the 2026-08-16 inventory never saw.
    writer = code_writer | local_has

    ledger_ids: set[str] = set()
    ledger_repos: set[str] = set()
    with LEDGER.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            ledger_ids.add(row["class_id"])
            ledger_repos.update(identity_keys(row.get("repo") or ""))

    narrowed_ids: set[str] = set()
    if NARROWED.is_file():
        with NARROWED.open(encoding="utf-8") as handle:
            for line in handle:
                narrowed_ids.add(json.loads(line)["class_id"])

    product: list[dict] = []
    with CLUSTERS.open(encoding="utf-8") as handle:
        for line in handle:
            cluster = json.loads(line)
            if cluster.get("in_window") and cluster.get("repo"):
                product.append(cluster)

    pass_rows: list[dict] = []
    fail_by_kind = Counter()
    pass_by_kind = Counter()
    pass_in_ledger = 0
    fail_in_ledger = 0
    pass_repos: set[str] = set()
    fail_repos: Counter[str] = Counter()
    fail_reviewed = 0
    local_no_clusters = 0
    for cluster in product:
        keys = identity_keys(cluster["repo"])
        kind = kind_of(cluster)
        in_led = cluster["class_id"] in ledger_ids
        if keys & writer:
            pass_by_kind[kind] += 1
            if in_led:
                pass_in_ledger += 1
            pass_repos.add(sorted(keys)[0])
            pass_rows.append(
                {
                    "class_id": cluster["class_id"],
                    "repo": cluster["repo"],
                    "kind": kind,
                    "in_ledger": in_led,
                    "in_funnel_narrowed": cluster["class_id"] in narrowed_ids,
                }
            )
        else:
            fail_by_kind[kind] += 1
            if in_led:
                fail_in_ledger += 1
            fail_repos[cluster["repo"]] += 1
            if kind == "reviewed":
                fail_reviewed += 1
            if keys & local_no:
                local_no_clusters += 1

    pass_n = len(pass_rows)
    fail_n = len(product) - pass_n
    pass_not_ledger = pass_n - pass_in_ledger
    fail_not_ledger = fail_n - fail_in_ledger

    unique_product_repos = {cluster["repo"] for cluster in product}
    unique_pass_repos = {row["repo"] for row in pass_rows}
    unique_fail_repos = unique_product_repos - unique_pass_repos
    unique_pass_in_writer = sum(
        1 for repo in unique_product_repos if identity_keys(repo) & writer
    )

    stats = {
        "gate": "repo has AI code-writing commits since 2025-05-01",
        "inventory": {
            "current_ai_scan_code_writer_repos": len(inventory["code_writer_repos"]),
            "current_ai_scan_has_ai_repos": len(inventory["ai_repos"]),
            "local_rescan_20260826_has_ai_identities": local_has_n,
            "local_rescan_20260826_no_ai_identities": local_no_n,
            "note": "Unscanned product-source repos stay out of this layer; they are not proven NO_AI.",
        },
        "product_source_clusters": len(product),
        "product_source_unique_repos": len(unique_product_repos),
        "ai_writer_repo_clusters": pass_n,
        "not_ai_writer_repo_clusters": fail_n,
        "ai_writer_unique_repos": len(unique_pass_repos),
        "not_ai_writer_unique_repos": len(unique_fail_repos),
        "unique_product_repos_in_writer_inventory": unique_pass_in_writer,
        "by_kind": {
            "pass": dict(pass_by_kind),
            "fail": dict(fail_by_kind),
        },
        "vs_ledger": {
            "pass_in_ledger": pass_in_ledger,
            "pass_not_in_ledger": pass_not_ledger,
            "fail_in_ledger": fail_in_ledger,
            "fail_not_in_ledger": fail_not_ledger,
        },
        "vs_funnel_narrowed_23868": {
            "pass_in_narrowed": sum(1 for row in pass_rows if row["in_funnel_narrowed"]),
            "pass_not_in_narrowed": sum(1 for row in pass_rows if not row["in_funnel_narrowed"]),
        },
        "sensitivity_has_ai_any_not_just_code_writer": sum(
            1 for cluster in product if identity_keys(cluster["repo"]) & (has_ai_any | local_has)
        ),
        "locally_scanned_no_ai_clusters": local_no_clusters,
        "fail_reviewed": fail_reviewed,
        "fail_top_repos": fail_repos.most_common(15),
    }

    with PASS_OUT.open("w", encoding="utf-8") as handle:
        for row in pass_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    STATS_OUT.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")

    meta = json.loads(META.read_text(encoding="utf-8"))
    layers = meta.setdefault("layers", {})
    layers["in_window_with_product_source_repo"] = len(product)
    layers["in_window_ai_writer_repo"] = pass_n
    layers["in_window_product_source_not_ai_writer_repo"] = fail_n
    layers["ai_writer_gate_note"] = (
        "Next cut after product-source git: repository is in the 2026-08-16 "
        "code-writer HAS_AI inventory (2,844 repos, since=2025-05-01) or the "
        "2026-08-26 local clone rescan. Unscanned repos are excluded, not "
        "proven NO_AI. Ledger not rewritten."
    )
    meta["ai_writer_gate"] = stats
    meta["ledger_vs_in_window"]["product_source_ai_writer_not_in_ledger"] = pass_not_ledger
    meta["ledger_vs_in_window"]["product_source_not_ai_writer_in_ledger"] = fail_in_ledger
    META.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
