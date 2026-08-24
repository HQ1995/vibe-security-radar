#!/usr/bin/env python3
"""Build the current unresolved inventory from the frozen shard snapshots."""

import json
from pathlib import Path


ROOT = Path(__file__).parent
SNAPSHOT = ROOT / "snapshot"

TOP = {
    "alias-ca6d2a3f1502af18d7b26f0a": 1,   # AutoBangumi
    "alias-8538427ee8176063d07be08b": 2,   # NLTK
    "alias-172a289e1ac154ff6d30231e": 3,   # RAGFlow
    "alias-2373aad54cebb4008599377e": 4,   # Orthanc Explorer 2
    "alias-67cfc72d991be60e3db27051": 5,   # Docker sbx
    "alias-8305e161d25d606db4d7b13c": 6,   # excel-mcp-server
    "alias-ce1d9f66002431d96bb0b12d": 7,   # Fleet
    "alias-d9dbaec34c997a2ae4d8fe78": 8,   # Sim
    "alias-26d4d892f2a00f2e9aa95e3e": 9,   # better-auth
    "alias-ef6dfe6621233b7381cc1bd7": 10,  # RustFS
    "alias-1c5fcae57f7d7d2b65c5a439": 11,  # vLLM
    "alias-a4a28f3a33b4e55d0a16c311": 12,  # MCP Python SDK
}

SUPERSEDED_AUDIT = {
    "alias-9dd227fdd8e2b88da77a7ff2": "strict-v3 PASS: CVE-2026-67530",
    "alias-a353279bb68efda133071d61": "new-components PASS: GHSA-539m-9xh6-q6rr",
}


def rows(name):
    with (SNAPSHOT / name).open() as handle:
        return [json.loads(line) for line in handle if line.strip()]


def audit_score(row):
    return {
        "ROUTED_EDGES_REJECTED_ORIGIN_UNATTRIBUTED": 82,
        "ROUTED_EDGE_REJECTED_ORIGIN_UNATTRIBUTED": 81,
        "ROUTED_EDGES_RETAINED_ORIGIN_UNATTRIBUTED": 78,
        "ROUTED_EDGE_RETAINED_ORIGIN_UNATTRIBUTED": 77,
        "GROUPED_FIX_CARRIER_MECHANISM_MISMATCH": 74,
        "NONEXHAUSTIVE_CANDIDATE_REVIEW": 55,
        "NO_EXACT_FIX": 42,
        "NO_OBSERVED_AI_ANCESTOR": 32,
        "HISTORY_BLOCKED": 12,
    }.get(row["reason_code"], 20)


inventory = []
for row in rows("refresh-overlay.jsonl"):
    if row["enrichment_status"] not in {"UNKNOWN", "BLOCKED"}:
        continue
    has_clone = any(row["local_clone_paths"].values())
    inventory.append({
        "class_id": row["class_id"],
        "public_ids": row["member_ids"],
        "analysis_subject": row["analysis_subject"],
        "current_status": row["enrichment_status"],
        "source_status": row["enrichment_status"],
        "reason_code": "REFRESH_NO_EXACT_FIX" if not row["fix_references"] else "REFRESH_UNRESOLVED",
        "reason": row["next_action"],
        "missing_history": bool(row["blocked_reasons"]),
        "missing_exact_fix": not row["fix_references"],
        "source_artifacts": ["snapshot/refresh-overlay.jsonl", "snapshot/refresh-handoff.md"],
        "source_evidence": {
            "blocked_reasons": row["blocked_reasons"],
            "repository_associations": row["repository_associations"],
            "official_records": row["official_records"],
        },
        "resolvability_score": 58 if has_clone else 18,
    })

for row in rows("refresh-exact-adjudications.jsonl"):
    if row["verdict"] != "INCONCLUSIVE":
        continue
    inventory.append({
        "class_id": row["class_id"],
        "public_ids": row["member_ids"],
        "analysis_subject": row["advisory"],
        "current_status": "UNKNOWN",
        "source_status": "INCONCLUSIVE",
        "reason_code": "EXACT_ORIGIN_UNATTRIBUTED",
        "reason": row["reason"],
        "missing_history": False,
        "missing_exact_fix": False,
        "source_artifacts": ["snapshot/refresh-exact-adjudications.jsonl", "snapshot/audit-handoff.md"],
        "source_evidence": {
            "repository_identity": row["repository_identity"],
            "fix": row["fix"],
            "origin_boundary": row["origin_boundary"],
            "candidate_review": row["candidate_review"],
        },
        "resolvability_score": 64,
    })

for row in rows("audit-adjudications.jsonl"):
    if row["review_label"] != "INCONCLUSIVE" or row["class_id"] in SUPERSEDED_AUDIT:
        continue
    blocked = row["reason_code"] == "HISTORY_BLOCKED"
    inventory.append({
        "class_id": row["class_id"],
        "public_ids": row["member_ids"],
        "analysis_subject": row["analysis_subject"],
        "current_status": "BLOCKED" if blocked else "UNKNOWN",
        "source_status": "INCONCLUSIVE",
        "reason_code": row["reason_code"],
        "reason": row["reason"],
        "missing_history": blocked,
        "missing_exact_fix": row["reason_code"] == "NO_EXACT_FIX",
        "source_artifacts": ["snapshot/audit-adjudications.jsonl", *row["artifact_paths"]],
        "source_evidence": {
            "fix_root_statuses": row["fix_root_statuses"],
            "p0_edge_count": row["p0_edge_count"],
            "reviewed_p0_edges": row["reviewed_p0_edges"],
            "git_refs": row["git_refs"],
        },
        "resolvability_score": audit_score(row),
    })

inventory.append({
    "class_id": "alias-ca6d2a3f1502af18d7b26f0a",
    "public_ids": ["CVE-2026-59101", "GHSA-p8rr-9cvg-cx5j"],
    "analysis_subject": "CVE-2026-59101",
    "current_status": "NEEDS_REVIEW",
    "source_status": "NEEDS_REVIEW/NR",
    "reason_code": "MISSING_EXACT_FIX_AND_RELEASED_CONTAINMENT",
    "reason": "AI origin and reintroduction are strong, but public 487bdfec still permits private/loopback targets and no later exact closure was recorded.",
    "missing_history": False,
    "missing_exact_fix": True,
    "source_artifacts": ["snapshot/consolidated-156.md", "snapshot/needs-review-closure.md", "snapshot/new-components-main.md"],
    "source_evidence": {
        "candidate_shas": ["5382aec8", "61ff20fe"],
        "intermediate_guard": "c7c709fa",
        "published_fix_claim": "487bdfec",
    },
    "resolvability_score": 100,
})

assert len(inventory) == 393, len(inventory)
assert len({row["class_id"] for row in inventory}) == len(inventory)
assert set(TOP) <= {row["class_id"] for row in inventory}

inventory.sort(key=lambda row: (TOP.get(row["class_id"], 10_000), -row["resolvability_score"], row["class_id"]))
for index, row in enumerate(inventory, 1):
    row["resolvability_rank"] = index
    row["selected_top12"] = index <= 12

with (ROOT / "unresolved-inventory.jsonl").open("w") as handle:
    for row in inventory:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

summary = {
    "current_distinct_components": len(inventory),
    "by_status": {status: sum(row["current_status"] == status for row in inventory) for status in ("UNKNOWN", "BLOCKED", "NEEDS_REVIEW")},
    "missing_history": sum(row["missing_history"] for row in inventory),
    "missing_exact_fix": sum(row["missing_exact_fix"] for row in inventory),
    "selected_top12": [row["analysis_subject"] for row in inventory[:12]],
    "source_reconciliation": {
        "strict_v3_unresolved": 0,
        "consolidated_raw_needs_review": 23,
        "consolidated_superseded": 22,
        "consolidated_current": 1,
        "refresh_unknown_or_blocked": 41,
        "refresh_exact_fix_inconclusive": 2,
        "audit_inconclusive_raw": 351,
        "audit_superseded": SUPERSEDED_AUDIT,
        "audit_current": 349,
        "cross_source_duplicate_current": "AutoBangumi appears in consolidated and new-components and is represented once",
    },
}
with (ROOT / "inventory-summary.json").open("w") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")

print(json.dumps(summary, sort_keys=True))
