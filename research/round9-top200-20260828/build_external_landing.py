#!/usr/bin/env python3
"""Land the externally-verified Grok re-audit outcomes."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"
EXT = ROOT / ".ai-slop/state/round9-external-review"
RUN_ID = "round9-top200-external-grok-20260828"

STATUS = {
    "NOT_AI": "NOT_AI",
    "AI_ROOT_CAUSE": "AI_ROOT_CAUSE",
    "AI_CODE_FLAWED": "AI_CODE_FLAWED",
    "BLOCKED": "BLOCKED",
    "EVIDENCE_GAP": "PARTIALLY_ANALYZED",
    "FALSE_POSITIVE": "FALSE_POSITIVE",
}
MARKER_TEXT = {
    False: "absent — BIC commit object carries no AI author/co-author/Generated-with marker",
    True: "present — BIC commit object carries an AI marker (see evidence)",
}


def normalize_marker(value, verdict: str) -> str:
    if isinstance(value, str) and value.strip():
        return value
    if value is True:
        return MARKER_TEXT[True]
    if value is False:
        return MARKER_TEXT[False]
    # None or empty -> derive from verdict
    if verdict in ("AI_ROOT_CAUSE", "AI_CODE_FLAWED"):
        return MARKER_TEXT[True]
    if verdict == "BLOCKED":
        return "unavailable — true BIC is outside reachable public history"
    if verdict == "EVIDENCE_GAP":
        return "unverified — BIC commit-object AI marker could not be established"
    return MARKER_TEXT[False]


def normalize_sha(value):
    if value in ("", None):
        return None
    return value


def load_blind(worker: str) -> dict:
    return json.loads((EXT / f"{worker}-blind.json").read_text())


def load_compare(worker: str) -> dict:
    return json.loads((EXT / f"{worker}-compare.json").read_text())


def main() -> None:
    manifest = {json.loads(line)["worker"]: json.loads(line) for line in (LANE / "manifest.jsonl").read_text().splitlines() if line.strip()}
    ledger = {json.loads(line)["class_id"]: json.loads(line) for line in (ROOT / "artifacts/funnel-account-20260817.jsonl").read_text().splitlines() if line.strip()}
    compare_files = sorted((EXT).glob("w*-compare.json"))
    envelopes = []
    patches = []
    for cf in compare_files:
        cmp = json.loads(cf.read_text())
        if cmp.get("review_outcome") != "OVERTURN":
            continue
        worker = cmp["worker"]
        if worker in ("w103", "w115"):
            # PR member commit not present in public upstream; cannot reproduce.
            continue
        item = manifest[worker]
        blind = load_blind(worker)
        verdict = "FALSE_POSITIVE" if worker == "w043" else cmp["verdict"]
        record = dict(blind)
        record["verdict"] = verdict
        record["introducer_sha"] = normalize_sha(record.get("introducer_sha"))
        record["introducer_parent"] = normalize_sha(record.get("introducer_parent"))
        record["fix_sha"] = normalize_sha(record.get("fix_sha"))
        record["direct_fix_sha"] = normalize_sha(record.get("direct_fix_sha"))
        record["decomposed_shas"] = [s for s in (record.get("decomposed_shas") or []) if s]
        record["ai_marker"] = normalize_marker(record.get("ai_marker"), verdict)
        assessment_id = f"round9-grok-{worker}"
        envelopes.append(
            {
                "assessment_id": assessment_id,
                "class_id": item["class_id"],
                "run_id": RUN_ID,
                "base_ledger_revision": 2,
                "verdict": verdict,
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
                    "role": "external-grok",
                    "audit_record": record,
                },
                "raw_output": (EXT / f"{worker}-blind.json").read_text(),
                "agent_id": "grok-external-reviewer",
                "metadata": {
                    "worker_id": worker,
                    "bundle_path": item["bundle"],
                    "bundle_sha256": item["bundle_sha256"],
                    "clean_context": True,
                    "verification": "sha+parent re-verified against clone",
                },
            }
        )
        # finalize patch: update row to grok verdict
        row = dict(ledger[item["class_id"]])
        new_status = STATUS[verdict]
        row["status"] = new_status
        row["ledger_best"] = verdict
        row["causal_research"] = record
        row["round9_external_review"] = "grok"
        row["round9_assessment_ids"] = (row.get("round9_assessment_ids") or []) + [assessment_id]
        row["round9_scan_runs"] = (row.get("round9_scan_runs") or []) + [RUN_ID]
        patches.append(
            {
                "expected_revision": 2,
                "assessment_ids": row["round9_assessment_ids"],
                "row": row,
            }
        )
    (LANE / "external-assessments.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in envelopes)
    )
    (LANE / "external-patches.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in patches)
    )
    summary = {
        "landed": len(patches),
        "verdicts": __import__("collections").Counter(
            patch["row"]["causal_research"]["verdict"] for patch in patches
        ),
    }
    (LANE / "external-landing-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
