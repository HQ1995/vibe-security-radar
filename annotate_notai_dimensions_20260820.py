#!/usr/bin/env python3
"""Materialize NOT_AI attribution, remediation, and lineage dimensions."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
BACKUP = LEDGER.with_name(LEDGER.name + ".bak-notai-dimensions-20260820")


def classify(research):
    gap = (research.get("remaining_gap") or "").lower()
    if research.get("no_fix_proven") is True or research.get("head_still_vulnerable") is True:
        remediation = "NO_FIX_HEAD_STILL_VULNERABLE"
    elif "rebinding" in gap:
        remediation = "FIX_WITH_KNOWN_DNS_REBINDING_RESIDUAL"
    elif "incomplete" in gap or "completing fix" in gap:
        remediation = "FIXED_AFTER_INCOMPLETE_INTERMEDIATE_FIX"
    else:
        remediation = "FIX_VERIFIED"

    boundary = research.get("parent_boundary")
    if boundary == "public_source_move_boundary":
        lineage = "PUBLIC_SOURCE_MOVE_BOUNDARY"
    elif boundary == "root_or_import_boundary" or research.get("root_boundary_verified") is True:
        lineage = "ROOT_OR_IMPORT_BOUNDARY"
    elif research.get("multi_introducer_parent_map") is True or len(research.get("introducer_shas") or []) > 1:
        lineage = "MULTI_INTRODUCER_BOUNDARY"
    else:
        lineage = "PARENT_VERIFIED"

    if remediation == "NO_FIX_HEAD_STILL_VULNERABLE":
        causal = "MECHANISM_AND_ATTRIBUTION_CLOSED_NO_FIX"
    elif remediation != "FIX_VERIFIED":
        causal = "MECHANISM_AND_ATTRIBUTION_CLOSED_REMEDIATION_BOUNDARY"
    elif lineage in {"ROOT_OR_IMPORT_BOUNDARY", "PUBLIC_SOURCE_MOVE_BOUNDARY"}:
        causal = "MECHANISM_AND_ATTRIBUTION_CLOSED_HISTORY_BOUNDARY"
    else:
        causal = "MECHANISM_AND_ATTRIBUTION_CLOSED"
    return {
        "attribution_status": "NOT_AI_CONFIRMED",
        "remediation_status": remediation,
        "lineage_status": lineage,
        "causal_review_status": causal,
    }


rows = [json.loads(line) for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.strip()]
assert len(rows) == len({row["class_id"] for row in rows})
notai = [row for row in rows if row.get("status") == "NOT_AI"]
assert len(notai) == sum(row.get("status") == "NOT_AI" for row in rows)
if not BACKUP.exists():
    BACKUP.write_text(LEDGER.read_text(encoding="utf-8"), encoding="utf-8")

for row in notai:
    research = row.setdefault("causal_research", {})
    dimensions = classify(research)
    research.update(dimensions)
    row.update({f"notai_{key}": value for key, value in dimensions.items()})

LEDGER.write_text(
    "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows),
    encoding="utf-8",
)
print(json.dumps({"rows": len(rows), "not_ai": len(notai)}, ensure_ascii=False))
