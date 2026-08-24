#!/usr/bin/env python3
"""Verify 46-row conservation and fail-closed enrichment semantics."""

import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUN = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def specific_anchor(value: str) -> bool:
    return bool(
        re.fullmatch(r"(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}(?:-[0-9a-z]{4}){2}|#[0-9]+)", value, re.I)
        or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value, re.I)
        or len(value) >= 8 and value.count("-") >= 2 and any(character.isdigit() for character in value) and "." not in value
    )


def main() -> int:
    contract = json.loads((RUN / "goal_contract.json").read_text())
    input_path = ROOT / contract["input"]["path"]
    overlay_path = RUN / "enrichment-overlay.jsonl"
    summary_path = RUN / "summary.json"
    input_rows = rows(input_path)
    overlay = rows(overlay_path) if overlay_path.is_file() else []
    summary = json.loads(summary_path.read_text()) if summary_path.is_file() else {}
    input_ids = {row["class_id"] for row in input_rows}
    overlay_ids = {row.get("class_id") for row in overlay}
    allowed = {"CANDIDATE_EVIDENCE", "BLOCKED", "UNKNOWN"}
    parent = subprocess.run(
        ["python3", str(ROOT / "autoresearch/orchestrator-260809-2331/verify_refresh_preprocess.py")],
        capture_output=True,
        text=True,
    )
    gates = {
        "input_hash_frozen": sha256(input_path) == contract["input"]["sha256"],
        "input_count_frozen": len(input_rows) == contract["input"]["rows"] == 46,
        "overlay_exists": overlay_path.is_file() and summary_path.is_file(),
        "class_conservation": len(overlay) == 46 and overlay_ids == input_ids,
        "one_row_per_class": len(overlay_ids) == len(overlay),
        "official_record_conservation": all(
            {item["id"] for item in row.get("official_records", [])} == set(row.get("member_ids", []))
            for row in overlay
        ),
        "statuses_fail_closed": all(row.get("enrichment_status") in allowed for row in overlay),
        "no_negative_inference": all("NEGATIVE" not in row.get("enrichment_status", "") for row in overlay),
        "history_anchors_specific": all(
            specific_anchor(anchor["value"])
            for row in overlay
            for association in row.get("repository_associations", [])
            for anchor in association.get("anchors", [])
        ),
        "candidate_evidence_present": all(
            row.get("enrichment_status") != "CANDIDATE_EVIDENCE"
            or row.get("fix_references")
            or row.get("history_carriers")
            for row in overlay
        ),
        "blocked_reason_present": all(
            row.get("enrichment_status") != "BLOCKED" or row.get("blocked_reasons")
            for row in overlay
        ),
        "overlay_hash_bound": bool(overlay) and summary.get("overlay_sha256") == sha256(overlay_path),
        "model_free": summary.get("model_api_calls") == 0 and summary.get("model_cost_usd") == 0.0,
        "source_archives_frozen": all(
            sha256(ROOT / source["path"]) == source["sha256"]
            for source in contract["source_archives"].values()
        ),
        "parent_preprocess_still_complete": parent.returncode == 0 and "refresh_preprocess_status=COMPLETE" in parent.stdout,
    }
    failed = [name for name, passed in gates.items() if not passed]
    print(json.dumps({"gates": gates, "failed_gates": failed, "passed": not failed}, sort_keys=True))
    print(f"refresh_delta_status={'COMPLETE' if not failed else 'INCOMPLETE'}")
    print(f"refresh_delta_gates={len(gates) - len(failed)}/{len(gates)}")
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
