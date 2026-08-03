"""Tests for the prospective pre-history projection and frozen selector."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cohort.prospective_intake import (
    ASSOCIATION_ONLY,
    PUBLIC_EXACT_PRESENT,
    ProspectiveIntakeContractError,
    aggregate_ai_exposure,
    build_pre_history_pool,
    build_prior_exclusion_projection,
    build_prospective_intake,
    description_associations,
    public_exact_pairs,
)
from cohort_prepare_prospective_pool import _ground_truth_controls


def _pool_row(
    repository: str,
    advisory: str,
    source_class: str,
    *,
    count: int = 12,
) -> dict[str, object]:
    from cohort.prospective_intake import _candidate_id

    return {
        "candidate_id": _candidate_id(repository, advisory),
        "repository_identity": repository,
        "advisory": advisory,
        "ai_unit_count": count,
        "ai_routes": ["assistant_direct"],
        "ai_tools": ["copilot"],
        "source_class": source_class,
    }


def _exclusions(
    advisories: list[str] | None = None,
    repositories: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "artifact_kind": "prospective_prior_exclusion_projection",
        "advisories": sorted(advisories or []),
        "repositories": sorted(repositories or []),
    }


def test_projection_does_not_retain_commit_history_or_model_search_fields() -> None:
    payloads = [
        {
            "cve_id": "CVE-1",
            "input": {
                "repo_url": "https://github.com/acme/project",
                "description": "secret vulnerability text",
            },
            "phase2": {"fix_sha": "a" * 40},
            "search": {"top_scored": [{"sha": "b" * 40}]},
            "status": "FOUND",
        }
    ]
    outcomes = [
        {
            "repository_identity": "github.com/acme/project",
            "sha": "c" * 40,
            "route": "assistant_direct",
            "tools": ["copilot"],
            "message": "secret commit text",
        }
    ]
    associations, _ = description_associations(payloads, {})
    exposure = aggregate_ai_exposure(outcomes, {})
    pool, _ = build_pre_history_pool(associations, exposure, set())

    assert pool == [
        _pool_row(
            "github.com/acme/project", "CVE-1", ASSOCIATION_ONLY, count=1
        )
    ]
    assert "secret" not in str(pool)
    assert "a" * 40 not in str(pool)
    assert "c" * 40 not in str(pool)


def test_selector_rejects_forbidden_fix_sha_even_if_all_other_fields_are_valid() -> None:
    row = _pool_row("github.com/acme/a", "CVE-1", ASSOCIATION_ONLY)
    row["fix_sha"] = "a" * 40
    with pytest.raises(ProspectiveIntakeContractError, match="forbidden history"):
        build_prospective_intake(
            [row], _exclusions(), split_id="frozen", per_stratum=1
        )


def test_short_public_reference_is_a_carrier_not_an_exact_pair() -> None:
    rows = [
        {
            "repository_identity": "github.com/acme/a",
            "advisory": "CVE-1",
            "fix_sha": "abcdef0",
        },
        {
            "repository_identity": "github.com/acme/b",
            "advisory": "CVE-2",
            "fix_sha": "b" * 40,
        },
    ]
    assert public_exact_pairs(rows, {}) == {("github.com/acme/b", "CVE-2")}


def test_generated_version_boundary_is_not_an_exact_pair() -> None:
    rows = [
        {
            "repository_identity": "github.com/acme/a",
            "advisory": "CVE-boundary",
            "fix_sha": "a" * 40,
            "reference_kind": "converted_version_boundary",
        }
    ]

    assert public_exact_pairs(rows, {}) == set()


def test_selection_is_deterministic_balanced_and_repository_disjoint() -> None:
    rows = [
        _pool_row("github.com/acme/shared", "CVE-hard", ASSOCIATION_ONLY),
        _pool_row("github.com/acme/shared", "CVE-easy", PUBLIC_EXACT_PRESENT),
    ]
    for index in range(4):
        rows.append(
            _pool_row(
                f"github.com/acme/hard-{index}",
                f"CVE-H-{index}",
                ASSOCIATION_ONLY,
            )
        )
        rows.append(
            _pool_row(
                f"github.com/acme/easy-{index}",
                f"CVE-E-{index}",
                PUBLIC_EXACT_PRESENT,
            )
        )

    first = build_prospective_intake(
        rows, _exclusions(), split_id="frozen", per_stratum=2
    )
    second = build_prospective_intake(
        list(reversed(rows)), _exclusions(), split_id="frozen", per_stratum=2
    )

    assert first["selected"] == second["selected"]
    assert first["gate_status"] == "READY_FOR_HISTORY_ENUMERATION"
    assert first["selected_source_class_counts"] == {
        ASSOCIATION_ONLY: 2,
        PUBLIC_EXACT_PRESENT: 2,
    }
    repositories = [row["repository_identity"] for row in first["selected"]]
    assert len(repositories) == len(set(repositories)) == 4


def test_prior_exclusion_projection_includes_controls_audits_and_cached_repos() -> None:
    projection = build_prior_exclusion_projection(
        control_payloads=[
            {
                "controls": [
                    {
                        "advisory": "CVE-control",
                        "repository_identity": "https://github.com/acme/control.git",
                    }
                ]
            }
        ],
        audit_records_by_advisory={
            "CVE-audit": {"evidence": {"repo": "https://github.com/acme/audit"}}
        },
        cached_results_by_advisory={
            "CVE-ledger": {
                "fix_commits": [
                    {"repo_url": "https://github.com/acme/from-cache"}
                ]
            }
        },
        adjudicated_advisories=["CVE-ledger"],
        aliases={},
    )

    assert projection["advisories"] == [
        "cve-audit",
        "cve-control",
        "cve-ledger",
    ]
    assert projection["repositories"] == [
        "github.com/acme/audit",
        "github.com/acme/control",
        "github.com/acme/from-cache",
    ]


def test_prior_rows_and_small_exposure_are_accounted_not_silently_dropped() -> None:
    rows = [
        _pool_row("github.com/acme/old", "CVE-old", ASSOCIATION_ONLY),
        _pool_row(
            "github.com/acme/small", "CVE-small", PUBLIC_EXACT_PRESENT, count=2
        ),
    ]
    result = build_prospective_intake(
        rows,
        _exclusions(repositories=["github.com/acme/old"]),
        split_id="frozen",
        per_stratum=1,
        minimum_ai_units=8,
    )
    assert result["selected"] == []
    assert result["gate_status"] == "BLOCKED_QUOTA"
    assert result["intake_status_counts"] == {
        "EXCLUDED_BELOW_MINIMUM_AI_UNITS": 1,
        "EXCLUDED_PRIOR_REPOSITORY": 1,
    }


def test_opened_prospective_v1_rows_are_permanent_control_exclusions() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    controls_path = repo_root / "scripts" / "cohort_prospective_v1_controls.json"
    selected_path = (
        repo_root
        / ".ai-slop/state/cohort-v1/prospective-intake-20260801-v1/selected.jsonl"
    )
    controls = json.loads(controls_path.read_text(encoding="utf-8"))["controls"]
    selected = [
        json.loads(line)
        for line in selected_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    def identity(row: dict[str, object]) -> tuple[object, object]:
        return row["advisory"], row["repository_identity"]

    assert {identity(row) for row in controls} == {identity(row) for row in selected}


def test_verified_ground_truth_is_projected_to_identity_only(tmp_path: Path) -> None:
    path = tmp_path / "ground-truth.json"
    path.write_text(
        json.dumps(
            [
                {
                    "cve_id": "CVE-1",
                    "repo_url": "https://github.com/acme/project",
                    "expected_shas": ["a" * 40],
                }
            ]
        ),
        encoding="utf-8",
    )

    assert _ground_truth_controls(path) == {
        "controls": [
            {
                "advisory": "CVE-1",
                "repository_identity": "https://github.com/acme/project",
            }
        ]
    }
