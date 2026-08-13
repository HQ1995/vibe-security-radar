#!/usr/bin/env python3
"""Fail closed on coverage, schema, conservation, and claim inflation."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERDICTS = {"CONFIRM", "NARROW", "FALSE_POSITIVE", "UNKNOWN", "BLOCKED"}
GATES = {"PASS", "FAIL", "NARROW", "UNKNOWN", "BLOCKED", "NA"}
CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}
REQUIRED = {
    "schema_version", "ordinal", "row_key", "baseline_state", "verdict", "confidence",
    "causal_class", "false_positive_class", "identity_gate", "ai_hunk_gate",
    "topology_gate", "but_for_gate", "fix_reversal_gate", "release_gate",
    "uniqueness_gate", "candidate_set", "carrier_set", "minimum_fix_set",
    "public_ids_keep", "public_ids_remove", "duplicate_of", "decisive_evidence",
    "counterevidence", "replay_commands", "experience_tags", "lesson",
}


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def verify_row(actual: dict, expected: dict) -> None:
    assert set(actual) == REQUIRED, (actual.get("ordinal"), set(actual) ^ REQUIRED)
    assert actual["schema_version"] == 1
    assert actual["ordinal"] == expected["ordinal"]
    assert actual["row_key"] == expected["row_key"]
    assert actual["baseline_state"] == expected["baseline_state"]
    assert actual["verdict"] in VERDICTS
    assert actual["confidence"] in CONFIDENCE
    for field in (
        "identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate",
        "fix_reversal_gate", "release_gate", "uniqueness_gate",
    ):
        assert actual[field] in GATES, (actual["ordinal"], field, actual[field])
    for field in ("candidate_set", "carrier_set", "minimum_fix_set"):
        assert actual[field] == sorted(set(actual[field]))
        assert all(SHA_RE.fullmatch(value) for value in actual[field])
    assert actual["public_ids_keep"] == sorted(set(actual["public_ids_keep"]))
    assert actual["public_ids_remove"] == sorted(set(actual["public_ids_remove"]))
    assert set(actual["public_ids_keep"]) | set(actual["public_ids_remove"]) == set(expected["public_ids"])
    assert not (set(actual["public_ids_keep"]) & set(actual["public_ids_remove"]))
    for field in ("decisive_evidence", "counterevidence", "replay_commands", "experience_tags"):
        assert isinstance(actual[field], list) and all(isinstance(value, str) and value.strip() for value in actual[field])
    assert isinstance(actual["lesson"], str) and actual["lesson"].strip()
    if actual["verdict"] == "CONFIRM":
        assert actual["confidence"] != "LOW"
        assert all(actual[field] in {"PASS", "NA"} for field in (
            "identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate",
            "fix_reversal_gate", "release_gate", "uniqueness_gate",
        ))
        assert actual["decisive_evidence"] and actual["replay_commands"]
        assert actual["false_positive_class"] is None
    elif actual["verdict"] == "FALSE_POSITIVE":
        assert actual["false_positive_class"]
        assert actual["counterevidence"] and "FAIL" in {
            actual["ai_hunk_gate"], actual["but_for_gate"], actual["fix_reversal_gate"],
            actual["release_gate"], actual["uniqueness_gate"], actual["identity_gate"],
        }
    else:
        assert any(actual[field] in {"NARROW", "UNKNOWN", "BLOCKED", "FAIL"} for field in (
            "identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate",
            "fix_reversal_gate", "release_gate", "uniqueness_gate",
        ))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args()
    manifest = load_jsonl(HERE / "manifest.jsonl")
    assert len(manifest) == 211
    expected = {row["ordinal"]: row for row in manifest}
    actual = []
    for number in range(1, 7):
        path = HERE / "shards" / f"shard-{number:02d}.jsonl"
        if not path.is_file():
            if args.allow_partial:
                continue
            raise AssertionError(f"missing shard: {path}")
        actual.extend(load_jsonl(path))
    assert len(actual) == len({row["ordinal"] for row in actual}) == len({row["row_key"] for row in actual})
    for row in actual:
        assert row["ordinal"] in expected
        verify_row(row, expected[row["ordinal"]])
    ordinals = sorted(row["ordinal"] for row in actual)
    if args.allow_partial:
        assert set(ordinals) <= set(expected)
    else:
        assert ordinals == list(range(1, 212))
        for number in range(1, 7):
            assert (HERE / "reports" / f"shard-{number:02d}.md").is_file()
    counts = Counter(row["verdict"] for row in actual)
    print(f"PASS: {len(actual)}/211 rows; verdicts={dict(sorted(counts.items()))}; partial={args.allow_partial}")


if __name__ == "__main__":
    main()
