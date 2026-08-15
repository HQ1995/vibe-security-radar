"""Contracts preventing discovery and maturity-estimation population swaps."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cohort.populations import (
    DISCOVERY_POPULATION,
    ESTIMATION_POPULATION,
    PopulationContractError,
    build_exposure_population_contract,
    build_population_split_manifest,
    load_exposure_population_contract,
    load_outcomes_population_contract,
    sha256_file,
    validate_population_parameters,
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _scan(tmp_path: Path) -> Path:
    scan = tmp_path / "scan"
    scan.mkdir()
    _write_json(
        scan / "summary.json",
        {"schema_version": 1, "artifact_kind": "cohort_ai_commit_scan"},
    )
    (scan / "commits.jsonl").write_text('{"sha":"abc"}\n', encoding="utf-8")
    return scan


def _exposure(
    tmp_path: Path,
    scan: Path,
    *,
    name: str,
    role: str,
    min_followup_days: int,
) -> Path:
    exposure = tmp_path / name
    exposure.mkdir()
    contract = build_exposure_population_contract(
        scan, role=role, min_followup_days=min_followup_days
    )
    _write_json(
        exposure / "summary.json",
        {
            "schema_version": 1,
            "artifact_kind": "cohort_exposure_classification",
            "scan_dir": str(scan),
            "min_followup_days": min_followup_days,
            "population_contract": contract,
        },
    )
    (exposure / "exposure.jsonl").write_text("", encoding="utf-8")
    return exposure


def _outcomes(tmp_path: Path, exposure: Path, *, name: str) -> Path:
    outcomes = tmp_path / name
    outcomes.mkdir()
    contract = load_exposure_population_contract(exposure)
    _write_json(
        outcomes / "summary.json",
        {
            "schema_version": 1,
            "artifact_kind": "cohort_stated_outcomes",
            "exposure_dir": str(exposure),
            "exposure_summary_sha256": sha256_file(exposure / "summary.json"),
            "population_contract": contract,
        },
    )
    (outcomes / "outcomes.jsonl").write_text("", encoding="utf-8")
    return outcomes


@pytest.mark.parametrize(
    ("role", "days"),
    [
        (DISCOVERY_POPULATION, 1),
        (ESTIMATION_POPULATION, 0),
    ],
)
def test_population_role_rejects_the_opposite_threshold(role: str, days: int) -> None:
    with pytest.raises(PopulationContractError):
        validate_population_parameters(role, days)


def test_discovery_outcomes_accept_only_the_all_age_branch(tmp_path: Path) -> None:
    scan = _scan(tmp_path)
    discovery = _exposure(
        tmp_path,
        scan,
        name="discovery",
        role=DISCOVERY_POPULATION,
        min_followup_days=0,
    )
    estimation = _exposure(
        tmp_path,
        scan,
        name="estimation",
        role=ESTIMATION_POPULATION,
        min_followup_days=180,
    )
    discovery_outcomes = _outcomes(tmp_path, discovery, name="discovery-outcomes")
    estimation_outcomes = _outcomes(tmp_path, estimation, name="estimation-outcomes")

    accepted = load_outcomes_population_contract(
        discovery_outcomes, expected_role=DISCOVERY_POPULATION
    )
    assert accepted["min_followup_days"] == 0
    with pytest.raises(PopulationContractError, match="population role mismatch"):
        load_outcomes_population_contract(
            estimation_outcomes, expected_role=DISCOVERY_POPULATION
        )


def test_upstream_scan_drift_fails_closed(tmp_path: Path) -> None:
    scan = _scan(tmp_path)
    discovery = _exposure(
        tmp_path,
        scan,
        name="discovery",
        role=DISCOVERY_POPULATION,
        min_followup_days=0,
    )
    (scan / "commits.jsonl").write_text('{"sha":"changed"}\n', encoding="utf-8")

    with pytest.raises(PopulationContractError, match="scan commits drifted"):
        load_exposure_population_contract(discovery)


def test_split_manifest_binds_both_roles_to_one_scan(tmp_path: Path) -> None:
    scan = _scan(tmp_path)
    discovery = _exposure(
        tmp_path,
        scan,
        name="discovery",
        role=DISCOVERY_POPULATION,
        min_followup_days=0,
    )
    estimation = _exposure(
        tmp_path,
        scan,
        name="estimation",
        role=ESTIMATION_POPULATION,
        min_followup_days=180,
    )

    manifest = build_population_split_manifest(scan, discovery, estimation)

    assert manifest["artifact_kind"] == "cohort_population_split"
    assert manifest["scan_commits_sha256"] == sha256_file(scan / "commits.jsonl")
