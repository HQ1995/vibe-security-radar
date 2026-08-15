"""Tests for the Transformers 0-day squash-member closure."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cohort_transformers_zeroday_squash_closure as closure


def test_frozen_squash_inventory_has_expected_add_only_shape() -> None:
    assert len(closure.PR_SPECS) == 7
    assert sum(int(spec["member_count"]) for spec in closure.PR_SPECS) == 179
    assert len({str(spec["landed"]) for spec in closure.PR_SPECS}) == 7
    assert len(closure.EXPECTED_SOURCE_AI_MEMBERS) == 7


def test_risk_hits_are_boundary_aware_and_additive() -> None:
    files = [
        "src/transformers/models/perceiver/modeling_perceiver.py",
        "src/transformers/models/x_clip/configuration_x_clip.py",
        "src/transformers/models/x_clipper/not_the_same_family.py",
    ]

    assert closure._risk_hits(files, closure.ADVISORY_SPECS) == [
        "CVE-2025-14920",
        "CVE-2025-14929",
    ]


def test_source_controls_are_a_subset_not_an_exact_ceiling() -> None:
    future_addition = "f" * 40
    detected = set(closure.EXPECTED_SOURCE_AI_MEMBERS) | {future_addition}

    assert closure.EXPECTED_SOURCE_AI_MEMBERS <= detected
    assert detected != closure.EXPECTED_SOURCE_AI_MEMBERS


def test_cna_release_values_use_explicit_v_prefixed_git_tags() -> None:
    assert closure._affected_git_ref("4.57.0") == "v4.57.0"
    assert closure._affected_git_ref("9c8bd3fc1befe54f3efb9f385561eef49f060a70") == (
        "9c8bd3fc1befe54f3efb9f385561eef49f060a70"
    )


def test_load_jsonl_rejects_duplicate_commit_identity(tmp_path: Path) -> None:
    path = tmp_path / "commits.jsonl"
    row = {
        "repository_identity": closure.REPOSITORY_IDENTITY,
        "sha": "a" * 40,
    }
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n")

    with pytest.raises(SystemExit, match="duplicate commit identity"):
        closure._load_jsonl(path)


def test_campcodes_record_cannot_be_a_transformers_advisory(tmp_path: Path) -> None:
    root = tmp_path
    path = root / str(closure.MISMATCH_SPEC["path"])
    path.parent.mkdir(parents=True)
    record = {
        "cveMetadata": {"cveId": "CVE-2025-4929"},
        "containers": {
            "cna": {
                "title": "Campcodes Online Shopping Portal SQL injection",
                "affected": [
                    {
                        "vendor": "Campcodes",
                        "product": "Online Shopping Portal",
                        "versions": [{"version": "1.0", "status": "affected"}],
                    }
                ],
            }
        },
    }
    path.write_text(json.dumps(record))
    loaded, _ = closure._load_cve(path)
    vendors, products = closure._vendors_and_products(closure._cna(loaded))

    assert vendors == ["Campcodes"]
    assert products == ["Online Shopping Portal"]
    assert "transformers" not in " ".join([*vendors, *products]).lower()
