#!/usr/bin/env python3
"""Refresh the canonical ledger after the final NOT_AI causal re-audit.

This keeps the old review artifacts as backups, records the three requeues,
and repairs the three retained causal boundaries discovered during review.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
STATE = ROOT / ".ai-slop/state/notai-review"
SOURCE_MANIFEST = STATE / "notai-independent-source-manifest-20260819.jsonl"
STAMP = "20260820-final-reaudit"

REQUEUE = {
    "alias-06725de6a87deb43bb1e0984": (
        "The ciguard root and security-header cases have source-level fix evidence, but the available root/aggregate metadata does not resolve the introducer AI role; the deep review also found the original mechanism/metadata boundary unresolved."
    ),
    "alias-5894b3201dac1fb635ff1c72": (
        "The ciguard root and security-header cases have source-level fix evidence, but the available root/aggregate metadata does not resolve the introducer AI role; the deep review also found the original mechanism/metadata boundary unresolved."
    ),
    "alias-c204d4115a6d3cbe40f345e7": (
        "The vulnerable endpoint is understood, but it first appears in a 199-file Code-transfer import root. The local repository cannot recover pre-import authorship or AI provenance."
    ),
}

RETAINED_CORRECTIONS = {
    "alias-0742089938f64f837c305eaf": {
        "introducer_sha": "3ed852eea50f9d4cd633efb8c2b054b8e33c2530",
        "introducer_parent": None,
        "introducer_parent_absent": True,
        "parent_sha_verified": True,
        "root_boundary_verified": True,
        "introducer_shas": ["3ed852eea50f9d4cd633efb8c2b054b8e33c2530"],
        "direct_fix_sha": "b2dc602e175ee07b0794f3e31f1a29ae6b7267d1",
        "fix_sha": "b2dc602e175ee07b0794f3e31f1a29ae6b7267d1",
        "lineage_status": "ROOT_OR_IMPORT_BOUNDARY",
        "remaining_gap": "History before the 2009 import is unavailable, but the vulnerable allocation/error-path boundary and direct cleanup fix are proven in the available repository.",
    },
    "alias-0acdb6ce30c38f84f58f9ef7": {
        "introducer_sha": "263771792ed48bef0e1293323aa32c66d0e3617d",
        "introducer_parent": "a73c0f8d6cd8acb8fc0d0fa9c7e25ff6601a94a5",
        "introducer_parent_absent": True,
        "parent_sha_verified": True,
        "root_boundary_verified": False,
        "introducer_shas": ["263771792ed48bef0e1293323aa32c66d0e3617d"],
        "direct_fix_sha": "188fcf538f58a60109ebd008e2c40d29cf3966d7",
        "fix_sha": "188fcf538f58a60109ebd008e2c40d29cf3966d7",
        "lineage_status": "PARENT_VERIFIED",
        "remaining_gap": "The first LZMA writer is 263771792; 330af6c and 9d72f1a800 are later retaining/refactoring history, not the first writer.",
    },
    "alias-c69cd343e601dfd573008037": {
        "introducer_parent": "dd3169bbf2fd8bace8393035d42bf7ec83b35ccb",
        "introducer_parent_absent": True,
        "parent_sha_verified": True,
        "remaining_gap": "No direct security fix is present in the checked HEAD; the GetC2d tool's atomic addition and actual immediate parent are verified.",
        "parent_absence_evidence": "git rev-list identifies dd3169bbf2fd8bace8393035d42bf7ec83b35ccb as the first parent of d479c04ad9d848ad380349111aafbcbe4c6cd5a2; that parent lacks src/tools/get-c2d.ts.",
        "source_note": "The introducer adds src/tools/get-c2d.ts; its actual immediate parent is dd3169bbf2fd8bace8393035d42bf7ec83b35ccb, which lacks that path. HEAD remains vulnerable and no security fix was found.",
    },
}

NOTAI_PROJECTION_KEYS = {
    "notai_attribution_status",
    "notai_remediation_status",
    "notai_lineage_status",
    "notai_causal_review_status",
    "notai_parent_boundary_materialized",
    "notai_semantic_review_state",
    "notai_semantic_review_ref",
    "notai_semantic_review_refreshed",
    "notai_second_review_disposition",
    "notai_second_review_coverage",
    "notai_second_review_ref",
    "notai_second_review_refreshed",
    "notai_causal_source",
    "notai_review_state",
    "notai_review_refreshed",
    "notai_review_reason",
    "notai_causal_review_refreshed",
    "notai_causal_review",
}

def canonical_dimensions(research: dict) -> dict:
    remediation = research.get("remediation_status")
    if research.get("no_fix_proven") is True or research.get("head_still_vulnerable") is True:
        remediation = "NO_FIX_HEAD_STILL_VULNERABLE"
    elif remediation not in {
        "FIX_VERIFIED",
        "FIXED_AFTER_INCOMPLETE_INTERMEDIATE_FIX",
        "FIX_WITH_KNOWN_DNS_REBINDING_RESIDUAL",
        "NO_FIX_HEAD_STILL_VULNERABLE",
    }:
        gap = str(research.get("remaining_gap") or "").lower()
        if "rebinding" in gap:
            remediation = "FIX_WITH_KNOWN_DNS_REBINDING_RESIDUAL"
        elif "incomplete" in gap or "completing fix" in gap:
            remediation = "FIXED_AFTER_INCOMPLETE_INTERMEDIATE_FIX"
        else:
            remediation = "FIX_VERIFIED"

    lineage = research.get("lineage_status")
    if lineage == "ATOMIC_PARENT_BOUNDARY":
        lineage = "PARENT_VERIFIED"
    if lineage not in {
        "ROOT_OR_IMPORT_BOUNDARY",
        "PUBLIC_SOURCE_MOVE_BOUNDARY",
        "MULTI_INTRODUCER_BOUNDARY",
        "PARENT_VERIFIED",
    }:
        if research.get("root_boundary_verified") is True:
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

CURRENT_ARTIFACTS = (
    "canonical-notai-semantic-review-20260819.jsonl",
    "notai-causal-canonical-20260819.jsonl",
    "notai-second-review-20260819.jsonl",
    "notai-provenance-audit-20260819.jsonl",
    "notai-independent-source-manifest-20260819.jsonl",
    "notai-ai-role-review-20260820.jsonl",
    "notai-ai-role-adversarial-20260820.jsonl",
    "canonical-notai-audit-20260819.jsonl",
    "notai-coverage-audit-20260819.jsonl",
    "notai-causal-gate-v4-20260819.jsonl",
)

def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")

def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def backup(path: Path) -> None:
    target = path.with_name(path.name + ".bak-" + STAMP)
    if path.exists() and not target.exists():
        shutil.copy2(path, target)

ledger = read_jsonl(LEDGER)
source_manifest = {row["class_id"]: row.get("normalized_source") or {} for row in read_jsonl(SOURCE_MANIFEST)} if SOURCE_MANIFEST.exists() else {}
backup(LEDGER)
changes = []
for row in ledger:
    cid = row.get("class_id")
    if cid in REQUEUE:
        old = row.get("status")
        row["status"] = "PARTIALLY_ANALYZED"
        row["partial_wave_verdict"] = "EVIDENCE_GAP"
        row["notai_reaudit_status"] = "REQUEUED_PARTIALLY_ANALYZED"
        row["notai_reaudit_reason"] = REQUEUE[cid]
        causal = row.setdefault("causal_research", {})
        causal.update({
            "verdict": "EVIDENCE_GAP",
            "review_state": "CAUSAL_REVIEW_PENDING",
            "causal_closure": False,
            "lineage_gap": True,
            "attribution_status": "UNRESOLVED",
            "causal_review_status": "EVIDENCE_GAP_REAUDIT_20260820",
            "remaining_gap": REQUEUE[cid],
        })
        for key in NOTAI_PROJECTION_KEYS:
            row.pop(key, None)
        changes.append({"class_id": cid, "repo": row.get("repo"), "from_status": old, "to_status": row["status"], "reason": REQUEUE[cid]})
    elif cid in RETAINED_CORRECTIONS:
        causal = row.setdefault("causal_research", {})
        causal.update(RETAINED_CORRECTIONS[cid])
        causal.update({
            "verdict": "NOT_AI",
            "review_state": "CAUSAL_CHAIN_CLOSED",
            "causal_closure": True,
            "lineage_gap": False,
        })
        causal.update(canonical_dimensions(causal))
        row.update({f"notai_{key}": value for key, value in canonical_dimensions(causal).items()})
        row["notai_parent_boundary_materialized"] = True
        changes.append({"class_id": cid, "repo": row.get("repo"), "from_status": "NOT_AI", "to_status": "NOT_AI", "reason": "Causal boundary corrected from targeted Git evidence."})

# Keep the canonical ledger self-contained. Older merges stored boolean
# placeholders for evidence/reasoning; only replace those placeholders with
# the independent manifest's concrete text, never overwrite targeted causal
# corrections.
for row in ledger:
    if row.get("status") != "NOT_AI":
        continue
    research = row.setdefault("causal_research", {})
    source = source_manifest.get(row["class_id"], {})
    for key in ("evidence", "reasoning"):
        if isinstance(research.get(key), bool) and isinstance(source.get(key), str) and source[key].strip():
            research[key] = source[key]

# Keep per-row coverage metadata aligned with the current canonical denominator.
current_notai_ids = {row["class_id"] for row in ledger if row.get("status") == "NOT_AI"}
current_notai_coverage = f"{len(current_notai_ids)}/{len(current_notai_ids)}"
for row in ledger:
    if row.get("status") == "NOT_AI":
        row["notai_second_review_coverage"] = current_notai_coverage
write_jsonl(LEDGER, ledger)

current_ids = current_notai_ids
for name in CURRENT_ARTIFACTS:
    path = STATE / name
    if not path.exists():
        continue
    rows = read_jsonl(path)
    backup(path)
    rows = [row for row in rows if row.get("class_id") in current_ids]
    for row in rows:
        cid = row.get("class_id")
        if cid in RETAINED_CORRECTIONS:
            if cid == "alias-0742089938f64f837c305eaf":
                row.update(introducer_sha="3ed852eea50f9d4cd633efb8c2b054b8e33c2530", introducer_shas=["3ed852eea50f9d4cd633efb8c2b054b8e33c2530"], introducer_parent=None, parent_sha_verified=True, root_boundary_verified=True, direct_fix_sha="b2dc602e175ee07b0794f3e31f1a29ae6b7267d1", verdict="NOT_AI", review_state="CAUSAL_CHAIN_CLOSED")
            elif cid == "alias-0acdb6ce30c38f84f58f9ef7":
                row.update(introducer_sha="263771792ed48bef0e1293323aa32c66d0e3617d", introducer_shas=["263771792ed48bef0e1293323aa32c66d0e3617d"], introducer_parent="a73c0f8d6cd8acb8fc0d0fa9c7e25ff6601a94a5", parent_sha_verified=True, root_boundary_verified=False, direct_fix_sha="188fcf538f58a60109ebd008e2c40d29cf3966d7", verdict="NOT_AI", review_state="CAUSAL_CHAIN_CLOSED")
            elif cid == "alias-c69cd343e601dfd573008037":
                row.update(introducer_parent="dd3169bbf2fd8bace8393035d42bf7ec83b35ccb", introducer_parent_absent=True, parent_sha_verified=True, verdict="NOT_AI", review_state="CAUSAL_CHAIN_CLOSED")
    write_jsonl(path, rows)

deep = STATE / "notai-semantic-deep-review-20260820.jsonl"
if deep.exists():
    backup(deep)
    deep_rows = [row for row in read_jsonl(deep) if row.get("class_id") in current_ids or row.get("class_id") in REQUEUE]
    for row in deep_rows:
        if row.get("class_id") in REQUEUE:
            row["verdict"] = "REQUEUED_PARTIALLY_ANALYZED"
            row["reasoning"] = REQUEUE[row["class_id"]]
    write_jsonl(deep, deep_rows)

audit = STATE / "notai-reaudit-corrections-20260820.jsonl"
write_jsonl(audit, changes)
print(json.dumps({
    "ledger_rows": len(ledger),
    "not_ai": sum(row.get("status") == "NOT_AI" for row in ledger),
    "partially_analyzed": sum(row.get("status") == "PARTIALLY_ANALYZED" for row in ledger),
    "changes": changes,
    "audit": str(audit),
}, ensure_ascii=False, indent=2))
