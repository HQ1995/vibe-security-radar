#!/usr/bin/env python3
"""Apply the accepted Grok-111 corrections to Round11 primary records."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))
from audit_record_gates import check_record  # noqa: E402

ACCEPT_CORRECTIONS = {
    "w393", "w394", "w396", "w415", "w421", "w425", "w427", "w434",
    "w442", "w445", "w465", "w470", "w475", "w480", "w481", "w482",
}
SPECIAL = {"w350", "w440", "w454", "w496"}
MARKER_BACKFILL = {"w385", "w470", "w476", "w477", "w482", "w490", "w493"}


def main() -> int:
    decisions = []
    changed_files = 0
    changed_fields = 0

    for worker in sorted(ACCEPT_CORRECTIONS | SPECIAL | MARKER_BACKFILL):
        primary_path = LANE / "primary" / f"{worker}.json"
        review_path = LANE / "independent-review-111" / f"{worker}.json"
        primary = json.loads(primary_path.read_text())
        review = json.loads(review_path.read_text())
        before = dict(primary)

        if worker in ACCEPT_CORRECTIONS:
            assert review["review_verdict"] == "CORRECTION_REQUIRED"
            corrections = review.get("corrected_fields") or {}
            assert corrections, f"{worker}: accepted correction has no fields"
            unknown = set(corrections) - set(primary)
            assert not unknown, f"{worker}: unknown corrected fields {sorted(unknown)}"
            primary.update(corrections)
            decision = "ACCEPT_CORRECTIONS"
        elif worker == "w350":
            assert review["review_verdict"] == "EVIDENCE_GAP"
            primary["verdict"] = "EVIDENCE_GAP"
            primary["remaining_gap"] = review["remaining_gap"]
            decision = "ACCEPT_EVIDENCE_GAP"
        elif worker == "w440":
            assert primary["verdict"] == "FALSE_POSITIVE"
            decision = "REJECT_VERDICT_FLIP"
        elif worker == "w454":
            assert primary["verdict"] == "EVIDENCE_GAP"
            decision = "CONFIRM_EVIDENCE_GAP"
        elif worker in MARKER_BACKFILL:
            assert review["review_verdict"] in {"CONFIRMED", "CORRECTION_REQUIRED"}
            decision = "CONFIRM"
        else:
            assert worker == "w496" and primary["remaining_gap"]
            decision = "CONFIRM_WITH_RELEASE_CAVEAT"

        if worker in MARKER_BACKFILL and primary.get("ai_marker") is None:
            marker = (review.get("protocol_checks") or {}).get("bic_only_ai_attribution")
            assert isinstance(marker, str) and marker.startswith("PASS:"), worker
            primary["ai_marker"] = marker.removeprefix("PASS:").strip()
            decision += "+BACKFILL_AI_MARKER"

        problems = check_record(primary)
        assert not problems, f"{worker}: {problems}"
        changed = [key for key in primary if primary.get(key) != before.get(key)]
        if changed:
            primary_path.write_text(json.dumps(primary, ensure_ascii=False, indent=2) + "\n")
            changed_files += 1
            changed_fields += len(changed)
        decisions.append({
            "worker": worker,
            "class_id": primary["class_id"],
            "primary_verdict": primary["verdict"],
            "review_verdict": review["review_verdict"],
            "decision": decision,
            "changed_fields": changed,
            "primary_source": str(primary_path.relative_to(ROOT)),
            "review_source": str(review_path.relative_to(ROOT)),
        })

    out = LANE / "review-111-reconciliation.jsonl"
    out.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in decisions))
    assert len(decisions) == 25
    print(json.dumps({
        "cases": len(decisions),
        "changed_files": changed_files,
        "changed_fields": changed_fields,
        "output": str(out.relative_to(ROOT)),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
