#!/usr/bin/env python3
"""Verify the frozen GHSA-200 leader baseline and disjoint shard assignment."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    baseline = json.loads((HERE / "baseline.json").read_text())
    inputs = baseline["inputs"]
    paths = {
        "contract_sha256": HERE / "CONTRACT.md",
        "fp211_final_mechanisms_sha256": ROOT
        / "autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl",
        "fp211_public_cases_sha256": ROOT
        / "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl",
        "fp211_canonical_ledger_sha256": ROOT
        / "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl",
        "publication_adjudications_sha256": ROOT / "scripts/publication_adjudications.json",
    }
    assert {name: sha256(path) for name, path in paths.items()} == inputs

    mechanisms = jsonl(paths["fp211_final_mechanisms_sha256"])
    cases = jsonl(paths["fp211_public_cases_sha256"])
    assert len(mechanisms) == 211
    assert len(cases) == 212
    assert Counter(case["verdict"] for case in cases) == {
        "CONFIRM": 65,
        "NARROW": 84,
        "FALSE_POSITIVE": 54,
        "UNKNOWN": 9,
    }

    selected = [
        row["ordinal"]
        for row in mechanisms
        if row["verdict"] in {"NARROW", "UNKNOWN"}
        or (row["verdict"] == "CONFIRM" and row["confidence"] == "MEDIUM")
    ]
    shards = baseline["upgrade_shards"]
    upgrade_a = shards["upgrade_a"]["ordinals"]
    upgrade_b = shards["upgrade_b"]["ordinals"]
    assert len(upgrade_a) == shards["upgrade_a"]["expected_rows"] == 58
    assert len(upgrade_b) == shards["upgrade_b"]["expected_rows"] == 48
    assert not set(upgrade_a) & set(upgrade_b)
    assert sorted([*upgrade_a, *upgrade_b]) == selected

    strict = [
        row
        for row in mechanisms
        if row["verdict"] == "CONFIRM" and row["confidence"] == "HIGH"
    ]
    assert len(strict) == baseline["baseline"]["confirm_high_mechanisms"] == 51
    assert baseline["baseline"]["strict_released_case_lower_bound"] == 48
    assert baseline["baseline"]["minimum_net_admissions_required_for_more_than_200"] == 153
    assert baseline["baseline"]["public_200_claim_supported"] is False
    print("PASS: frozen baseline=48 strict released; 106 disjoint upgrades; gap=153")


if __name__ == "__main__":
    main()
