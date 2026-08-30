#!/usr/bin/env python3
"""Choose blind agreement/adjudication records and build atomic Neon patches."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"
sys.path.insert(0, str(ROOT / "scripts"))
from audit_envelope import violations
from audit_record_gates import check_record
from merge_funnel_lane import detect_duplicate_tps

STATUS = {
    "EVIDENCE_GAP": "PARTIALLY_ANALYZED",
    "NOT_AI": "NOT_AI",
    "AI_ROOT_CAUSE": "AI_ROOT_CAUSE",
    "AI_CODE_FLAWED": "AI_CODE_FLAWED",
    "BLOCKED": "BLOCKED",
    "FALSE_POSITIVE": "FALSE_POSITIVE",
}


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    manifest = jsonl(LANE / "manifest.jsonl")
    comparisons = {row["worker"]: row for row in jsonl(LANE / "comparison.jsonl")}
    corrections = {
        (row["role"], row["worker"]): row
        for row in jsonl(LANE / "correction-index.jsonl")
    }
    def accepted_record(role: str, worker: str, original: Path) -> dict:
        correction = corrections.get((role, worker))
        path = ROOT / correction["correction"] if correction else original
        return json.loads(path.read_text())
    ledger = jsonl(ROOT / "artifacts/funnel-account-20260817.jsonl")
    by_class = {row["class_id"]: row for row in ledger}
    fold_owners = {}
    for existing in ledger:
        if existing.get("status") not in {"AI_ROOT_CAUSE", "AI_CODE_FLAWED"}:
            continue
        for member in existing.get("merged_dual_classes") or []:
            if member != existing["class_id"]:
                fold_owners[member] = existing["class_id"]
    finals = []
    patches = []
    for item in manifest:
        worker = item["worker"]
        comparison = comparisons[worker]
        primary = json.loads((ROOT / item["primary_out"]).read_text())
        review = accepted_record("review", worker, ROOT / item["review_out"])
        assessment_ids = [f"round9-primary-{worker}", f"round9-review-{worker}"]
        if ("review", worker) in corrections:
            assessment_ids.append(f"round9-correction-review-{worker}")
        if comparison["needs_adjudication"]:
            path = LANE / "adjudication" / f"{worker}.json"
            if not path.exists():
                raise SystemExit(f"missing adjudication: {path}")
            final = accepted_record("adjudication", worker, path)
            assessment_ids.append(f"round9-adjudication-{worker}")
            if ("adjudication", worker) in corrections:
                assessment_ids.append(f"round9-correction-adjudication-{worker}")
            source = "adjudication"
        else:
            final = primary
            source = "blind_agreement"
        problems = check_record(final)
        if problems:
            raise SystemExit("; ".join(problems))
        row = dict(by_class[item["class_id"]])
        if row["status"] not in {"UNANALYZED", "PARTIALLY_ANALYZED"}:
            raise SystemExit(f"selection status changed: {item['class_id']} -> {row['status']}")
        row["status"] = STATUS[final["verdict"]]
        row["ledger_best"] = final["verdict"]
        row["causal_research"] = final
        row["round9_assessment_ids"] = assessment_ids
        row["round9_resolution"] = source
        duplicate_owner = fold_owners.get(item["class_id"])
        if duplicate_owner and row["status"] in {"AI_ROOT_CAUSE", "AI_CODE_FLAWED"}:
            row["site_publication"] = {
                "publish": False,
                "reason": f"duplicate advisory identity already published by {duplicate_owner}",
            }
            row["duplicate_of_class_id"] = duplicate_owner
        row["round9_scan_runs"] = [
            "round9-top200-primary-20260828",
            "round9-top200-review-20260828",
        ] + (["round9-top200-adjudication-20260828"] if source == "adjudication" else [])
        if any(key[1] == worker for key in corrections):
            row["round9_scan_runs"].append("round9-top200-contract-corrections-20260828")
        if row["status"] in {"NOT_AI", "AI_ROOT_CAUSE", "AI_CODE_FLAWED", "BLOCKED"}:
            envelope = violations(row)
            if envelope:
                raise SystemExit(f"{item['class_id']}: {'; '.join(envelope)}")
        finals.append(
            {
                "worker": worker,
                "class_id": item["class_id"],
                "final_source": source,
                "assessment_ids": assessment_ids,
                "ledger_status": row["status"],
                "audit_record": final,
                "primary_record": primary,
                "review_record": review,
                "correction_assessment_ids": [
                    value for value in assessment_ids if value.startswith("round9-correction-")
                ],
                "disagreement_topics": comparison["disagreement_topics"],
                "duplicate_of_class_id": duplicate_owner,
            }
        )
        patches.append(
            {
                "expected_revision": item["base_ledger_revision"],
                "assessment_ids": assessment_ids,
                "row": row,
            }
        )
    if len(finals) != 200 or len({row["class_id"] for row in finals}) != 200:
        raise SystemExit("final coverage is not exactly 200 unique cases")
    projected = dict(by_class)
    for patch in patches:
        projected[patch["row"]["class_id"]] = patch["row"]
    duplicate_problems = detect_duplicate_tps(list(projected.values()))
    if duplicate_problems:
        raise SystemExit("duplicate TP gate: " + "; ".join(duplicate_problems))
    (LANE / "final-records.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in finals)
    )
    (LANE / "finalize-patches.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in patches)
    )
    summary = {
        "cases": len(finals),
        "final_sources": dict(Counter(row["final_source"] for row in finals)),
        "verdicts": dict(Counter(row["audit_record"]["verdict"] for row in finals)),
        "ledger_statuses": dict(Counter(row["ledger_status"] for row in finals)),
        "duplicate_tp_gate": "PASS",
        "terminal_envelope_gate": "PASS",
    }
    (LANE / "finalization-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
