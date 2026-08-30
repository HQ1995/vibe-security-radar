#!/usr/bin/env python3
"""Verify the frozen selection, audit outputs, gates, coverage, and ledger non-mutation."""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round11-top500-20260829"
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
EXCLUDED = ROOT / "research/round10-top200-20260828/manifest.jsonl"
EXPECTED_KEYS = [
    "class_id", "case_id", "repo", "advisory_ids", "bug_semantics", "flaw_origin",
    "introducer_sha", "introducer_parent", "introducer_parent_absent", "squash_decomposed",
    "decomposed_shas", "ai_marker", "verdict", "fix_sha", "direct_fix_sha", "evidence",
    "reasoning", "remaining_gap",
]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(LANE))
from audit_record_gates import check_record  # noqa: E402
from rank import recompute_selection  # noqa: E402


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> int:
    manifest = jsonl(LANE / "manifest.jsonl")
    excluded = jsonl(EXCLUDED)
    selection = json.loads((LANE / "selection-summary.json").read_text())
    freeze_sha = selection["ledger_sha256_at_freeze"]
    live_sha = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    selected = recompute_selection() if live_sha == freeze_sha else None

    assert len(manifest) == 500
    assert [row["ordinal"] for row in manifest] == list(range(500))
    assert [row["worker"] for row in manifest] == [f"w{value:03d}" for value in range(500)]
    assert len({row["class_id"] for row in manifest}) == 500
    assert {row["status_at_selection"] for row in manifest} <= {"UNANALYZED", "PARTIALLY_ANALYZED"}
    assert selection["target"] == 500
    assert selection["excluded_overlap"] == 0
    assert selection["score_max"] == max(row["score"] for row in manifest)
    assert selection["score_min"] == min(row["score"] for row in manifest)
    if selected is not None:
        assert [row["class_id"] for row in manifest] == [item[1] for item in selected]

    excluded_classes = {row["class_id"] for row in excluded}
    excluded_ids = {
        str(value).upper()
        for row in excluded
        for value in row.get("advisory_ids") or []
    }
    selected_ids = {
        str(value).upper()
        for row in manifest
        for value in row.get("advisory_ids") or []
    }
    assert not ({row["class_id"] for row in manifest} & excluded_classes)
    assert not (selected_ids & excluded_ids)

    output_paths = sorted((LANE / "primary").glob("w*.json"), key=lambda path: path.name)
    assert len(output_paths) == 500, f"primary outputs {len(output_paths)}/500"
    problems = []
    verdicts: Counter[str] = Counter()
    for item, path in zip(manifest, output_paths, strict=True):
        assert path == ROOT / item["primary_out"]
        record = json.loads(path.read_text())
        assert list(record)[: len(EXPECTED_KEYS)] == EXPECTED_KEYS
        assert set(record) - set(EXPECTED_KEYS) <= {"unpatched"}
        assert record["class_id"] == item["class_id"]
        assert record["repo"] == item["repo"]
        assert record["advisory_ids"] == item["advisory_ids"]
        assert str(record["evidence"]).strip()
        problems.extend(check_record(record))
        verdicts[str(record.get("verdict"))] += 1
    if problems:
        print("\n".join(problems), file=sys.stderr)
        raise SystemExit(f"{len(problems)} gate failure(s)")

    by_id = {
        json.loads(line)["class_id"]: json.loads(line)
        for line in LEDGER.read_text().splitlines()
        if line.strip()
    }
    for item in manifest:
        live = by_id[item["class_id"]]
        assert live.get("round11_research") is None
        if live_sha == freeze_sha:
            assert live["status"] == item["status_at_selection"]

    coverage = {
        "selected": 500,
        "records": len(output_paths),
        "unique_class_ids": len({row["class_id"] for row in manifest}),
        "missing": 0,
        "duplicates": 0,
        "round10_overlap": 0,
        "verdict_histogram": dict(verdicts),
        "ledger_sha256_at_freeze": freeze_sha,
        "ledger_sha256_live": live_sha,
        "ledger_changed_since_freeze": live_sha != freeze_sha,
        "selection_recomputed": selected is not None,
        "ledger_mutated_by_this_wave": False,
    }
    (LANE / "coverage.json").write_text(json.dumps(coverage, indent=1) + "\n")
    print(json.dumps({"ok": True, **coverage}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
