#!/usr/bin/env python3
"""Supersede adjudication marker corrections and build revision-3 patches."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"
RUN_ID = "round9-top200-contract-corrections2-20260828"
NOTE = (
    " Contract normalization note: the canonical audit contract represents an "
    "inspected marker absence with the explicit ai_marker string above; the prior "
    "null representation was superseded and is not the accepted field value."
)


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    manifest = {row["worker"]: row for row in jsonl(LANE / "manifest.jsonl")}
    ledger = {row["class_id"]: row for row in jsonl(ROOT / "artifacts/funnel-account-20260817.jsonl")}
    finals = jsonl(LANE / "final-records.jsonl")
    finals_by_worker = {row["worker"]: row for row in finals}
    correction_index = [
        row for row in jsonl(LANE / "correction-index.jsonl")
        if row["role"] == "adjudication"
    ]
    output_dir = LANE / "corrections2"
    output_dir.mkdir(exist_ok=True)
    envelopes = []
    patches = []
    index = []
    for item in correction_index:
        worker = item["worker"]
        selected = manifest[worker]
        record = json.loads((ROOT / item["correction"]).read_text())
        record["reasoning"] = record["reasoning"].rstrip() + NOTE
        output = output_dir / f"adjudication-{worker}.json"
        output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
        assessment_id = f"round9-correction2-adjudication-{worker}"
        supersedes = f"round9-correction-adjudication-{worker}"
        envelopes.append(
            {
                "assessment_id": assessment_id,
                "class_id": selected["class_id"],
                "run_id": RUN_ID,
                "base_ledger_revision": 2,
                "verdict": record["verdict"],
                "confidence": None,
                "reasoning": record["reasoning"],
                "causal_chain": {
                    key: record[key]
                    for key in (
                        "case_id", "repo", "advisory_ids", "bug_semantics",
                        "flaw_origin", "introducer_sha", "introducer_parent",
                        "introducer_parent_absent", "squash_decomposed",
                        "decomposed_shas", "fix_sha", "direct_fix_sha",
                    )
                },
                "evidence": {
                    "schema_version": "causal-audit/1",
                    "role": "contract-correction2",
                    "audit_record": record,
                },
                "raw_output": output.read_text(),
                "agent_id": "Main-contract-normalizer",
                "metadata": {
                    "worker_id": worker,
                    "mechanical_only": True,
                    "bundle_path": selected["bundle"],
                    "bundle_sha256": selected["bundle_sha256"],
                    "clean_context": False,
                },
                "supersedes_assessment_id": supersedes,
            }
        )
        final = finals_by_worker[worker]
        final["audit_record"] = record
        final["assessment_ids"].append(assessment_id)
        final["correction_assessment_ids"].append(assessment_id)
        row = dict(ledger[selected["class_id"]])
        row["causal_research"] = record
        row["round9_assessment_ids"].append(assessment_id)
        row["round9_scan_runs"].append(RUN_ID)
        patches.append(
            {
                "expected_revision": 2,
                "assessment_ids": final["assessment_ids"],
                "row": row,
            }
        )
        index.append(
            {
                "worker": worker,
                "class_id": selected["class_id"],
                "assessment_id": assessment_id,
                "supersedes_assessment_id": supersedes,
                "correction": str(output.relative_to(ROOT)),
                "change": "reasoning aligned with explicit textual ai_marker absence",
            }
        )
    (LANE / "correction2-index.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in index)
    )
    (LANE / "correction2-assessments.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in envelopes)
    )
    (LANE / "postfinal-correction-patches.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in patches)
    )
    (LANE / "final-records.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in finals)
    )
    print(json.dumps({"corrections": len(index), "patches": len(patches)}))


if __name__ == "__main__":
    main()
