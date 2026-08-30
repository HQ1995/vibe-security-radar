#!/usr/bin/env python3
"""Create superseding assessments for null ai_marker contract violations."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"
RUN_ID = "round9-top200-contract-corrections-20260828"


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def marker(record: dict) -> str:
    if record["verdict"] == "NOT_AI":
        return "absent — BIC commit object has no AI author/co-author/Generated-with marker; see evidence"
    if record["verdict"] == "BLOCKED":
        return "unavailable — true BIC commit object is outside reachable public history; see remaining_gap"
    if record["verdict"] == "EVIDENCE_GAP":
        return "unverified — BIC commit-object AI marker could not be established; see remaining_gap"
    raise ValueError(f"AI verdict cannot have null ai_marker: {record['class_id']}")


def main() -> None:
    manifest = jsonl(LANE / "manifest.jsonl")
    corrections_dir = LANE / "corrections"
    corrections_dir.mkdir(exist_ok=True)
    index = []
    envelopes = []
    for item in manifest:
        for role in ("review", "adjudication"):
            source = (
                ROOT / item["review_out"]
                if role == "review"
                else LANE / "adjudication" / f"{item['worker']}.json"
            )
            if not source.exists():
                continue
            record = json.loads(source.read_text())
            if record.get("ai_marker") is not None:
                continue
            corrected = dict(record)
            corrected["ai_marker"] = marker(record)
            output = corrections_dir / f"{role}-{item['worker']}.json"
            output.write_text(json.dumps(corrected, ensure_ascii=False, indent=2) + "\n")
            original_id = f"round9-{role}-{item['worker']}"
            correction_id = f"round9-correction-{role}-{item['worker']}"
            index.append(
                {
                    "worker": item["worker"],
                    "role": role,
                    "source": str(source.relative_to(ROOT)),
                    "correction": str(output.relative_to(ROOT)),
                    "supersedes_assessment_id": original_id,
                    "assessment_id": correction_id,
                    "change": "ai_marker null -> explicit textual marker state; all causal fields preserved",
                }
            )
            envelopes.append(
                {
                    "assessment_id": correction_id,
                    "class_id": item["class_id"],
                    "run_id": RUN_ID,
                    "base_ledger_revision": item["base_ledger_revision"],
                    "verdict": corrected["verdict"],
                    "confidence": None,
                    "reasoning": corrected["reasoning"],
                    "causal_chain": {
                        key: corrected[key]
                        for key in (
                            "case_id", "repo", "advisory_ids", "bug_semantics",
                            "flaw_origin", "introducer_sha", "introducer_parent",
                            "introducer_parent_absent", "squash_decomposed",
                            "decomposed_shas", "fix_sha", "direct_fix_sha",
                        )
                    },
                    "evidence": {
                        "schema_version": "causal-audit/1",
                        "role": "contract-correction",
                        "corrected_role": role,
                        "audit_record": corrected,
                    },
                    "raw_output": output.read_text(),
                    "agent_id": "Main-contract-normalizer",
                    "metadata": {
                        "worker_id": item["worker"],
                        "bundle_path": item["bundle"],
                        "bundle_sha256": item["bundle_sha256"],
                        "clean_context": False,
                        "mechanical_only": True,
                    },
                    "supersedes_assessment_id": original_id,
                }
            )
    (LANE / "correction-index.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in index)
    )
    (LANE / "correction-assessments.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in envelopes)
    )
    print(json.dumps({"corrections": len(index), "assessments": len(envelopes)}))


if __name__ == "__main__":
    main()
