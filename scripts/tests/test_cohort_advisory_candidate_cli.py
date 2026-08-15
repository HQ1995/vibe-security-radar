"""Boundary tests for the read-only advisory candidate CLI."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import cohort_advisory_candidates as cli
from cohort.populations import (
    DISCOVERY_POPULATION,
    ESTIMATION_POPULATION,
    build_exposure_population_contract,
    sha256_file,
)
from cohort.relations import normalize_repository_aliases


REPOSITORY = "github.com/example/project"
PARENT = "2" * 40
FIX = "4" * 40


def test_local_parent_scan_has_no_time_exclusion(monkeypatch, tmp_path) -> None:
    calls: list[list[str]] = []

    def fake_run_git(command: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(command)
        if "--absolute-git-dir" in command:
            return SimpleNamespace(returncode=0, stdout=str(tmp_path))
        return SimpleNamespace(
            returncode=0,
            stdout=f"> {FIX} {PARENT} 1700000000\n> {PARENT} 1600000000\n",
        )

    monkeypatch.setattr(cli, "run_git", fake_run_git)

    index = cli._local_parent_index(
        tmp_path,
        REPOSITORY,
        roots=[FIX],
        timeout=30,
    )

    assert index["complete"] is True
    assert index["since"] == ""
    assert len(index["commits"]) == 2
    assert not any(argument.startswith("--since=") for argument in calls[-1])


def test_units_and_clone_paths_share_the_same_canonical_alias() -> None:
    aliases = normalize_repository_aliases(
        [{"alias": "github.com/old/project", "canonical": REPOSITORY}]
    )
    units, applied = cli._group_units_by_repository(
        [
            {
                "repository_identity": "github.com/old/project",
                "sha": FIX,
            }
        ],
        aliases,
    )
    paths = cli._canonicalize_repository_paths(
        {"github.com/old/project": cli.Path("/cache/old")},
        aliases,
    )

    assert applied == 1
    assert set(units) == {REPOSITORY}
    assert units[REPOSITORY][0]["repository_identity"] == REPOSITORY
    assert units[REPOSITORY][0]["observed_repository_identity"] == (
        "github.com/old/project"
    )
    assert paths == {REPOSITORY: cli.Path("/cache/old")}


def test_positive_control_overlay_is_explicit_and_canonical(tmp_path) -> None:
    control_path = tmp_path / "controls.json"
    control_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "controls": [
                    {
                        "advisory": "CVE-2026-1000",
                        "repository_identity": "github.com/old/project",
                        "atomic_origin_sha": PARENT,
                        "fix_sha": FIX,
                        "expected_relation": "direct_ancestry",
                        "source": "audit.json",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    aliases = normalize_repository_aliases(
        [{"alias": "github.com/old/project", "canonical": REPOSITORY}]
    )

    fixes, controls = cli._load_positive_control_overlay(control_path, aliases)

    assert controls[0]["repository_identity"] == REPOSITORY
    assert fixes == {
        REPOSITORY: [
            {
                "advisory": "CVE-2026-1000",
                "fix_sha": FIX,
                "published": "",
                "source": "positive_control:audit.json",
            }
        ]
    }


def test_complex_control_overlay_hides_origins_and_exposes_all_fix_roots(
    tmp_path,
) -> None:
    origin = "1" * 40
    second_fix = "5" * 40
    control_path = tmp_path / "complex-controls.json"
    control_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "controls": [
                    {
                        "advisory": "CVE-2026-2000",
                        "dimensions": ["MULTI_FIX"],
                        "source": "audit/complex.json",
                        "source_sha256": "a" * 64,
                        "target_repository_identity": "github.com/old/project",
                        "target_edges": [
                            {
                                "candidate_sha": origin,
                                "fix_sha": FIX,
                                "expected_relation": "reachable_ancestor",
                            },
                            {
                                "candidate_sha": origin,
                                "fix_sha": second_fix,
                                "expected_relation": "reachable_ancestor",
                            },
                        ],
                        "upstream_imports": [],
                        "public_fixes": [FIX],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    aliases = normalize_repository_aliases(
        [{"alias": "github.com/old/project", "canonical": REPOSITORY}]
    )

    fixes, controls = cli._load_complex_control_overlay(control_path, aliases)

    assert controls[0]["target_repository_identity"] == REPOSITORY
    assert fixes == {
        REPOSITORY: [
            {
                "advisory": "CVE-2026-2000",
                "fix_sha": FIX,
                "published": "",
                "source": "complex_control:audit/complex.json",
            },
            {
                "advisory": "CVE-2026-2000",
                "fix_sha": second_fix,
                "published": "",
                "source": "complex_control:audit/complex.json",
            },
        ]
    }
    assert origin not in json.dumps(fixes, sort_keys=True)


def test_public_fix_references_are_flattened_without_overlay_provenance() -> None:
    rows = cli._flatten_fix_references(
        {
            REPOSITORY: [
                {"advisory": "CVE-2026-1000", "fix_sha": FIX, "published": "2026-01-01"}
            ]
        }
    )

    assert rows == [
        {
            "repository_identity": REPOSITORY,
            "advisory": "CVE-2026-1000",
            "fix_sha": FIX,
            "published": "2026-01-01",
        }
    ]


def test_sealed_fix_manifest_loader_never_accepts_origin_fields(tmp_path) -> None:
    manifest_path = tmp_path / "fix-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_kind": "sealed_fix_manifest",
                "split_id": "heldout-v1",
                "frozen_at": "2026-07-31T00:00:00Z",
                "fixes": [
                    {
                        "advisory": "CVE-2026-1000",
                        "repository_identity": REPOSITORY,
                        "fix_sha": FIX,
                        "candidate_sha": PARENT,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="invalid sealed fix manifest"):
        cli._load_fix_manifest(manifest_path, {})


def test_sealed_fix_manifest_is_mutually_exclusive_with_golden_ledgers() -> None:
    with pytest.raises(SystemExit):
        cli._parse_args(
            [
                "--fix-manifest",
                "fixes.json",
                "--complex-controls",
                "golden.json",
            ]
        )


def _population_outcomes(tmp_path, *, role: str, days: int):
    scan = tmp_path / f"scan-{days}"
    scan.mkdir()
    (scan / "commits.jsonl").write_text('{"sha":"abc"}\n', encoding="utf-8")
    (scan / "summary.json").write_text(
        json.dumps({"schema_version": 1, "artifact_kind": "cohort_ai_commit_scan"}),
        encoding="utf-8",
    )
    exposure = tmp_path / f"exposure-{days}"
    exposure.mkdir()
    contract = build_exposure_population_contract(
        scan, role=role, min_followup_days=days
    )
    (exposure / "summary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_kind": "cohort_exposure_classification",
                "scan_dir": str(scan),
                "min_followup_days": days,
                "population_contract": contract,
            }
        ),
        encoding="utf-8",
    )
    outcomes = tmp_path / f"outcomes-{days}"
    outcomes.mkdir()
    (outcomes / "outcomes.jsonl").write_text("", encoding="utf-8")
    (outcomes / "summary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_kind": "cohort_stated_outcomes",
                "exposure_dir": str(exposure),
                "exposure_summary_sha256": sha256_file(exposure / "summary.json"),
                "population_contract": contract,
            }
        ),
        encoding="utf-8",
    )
    return outcomes


def test_candidate_generation_refuses_mature_estimation_population(tmp_path) -> None:
    outcomes = _population_outcomes(
        tmp_path, role=ESTIMATION_POPULATION, days=180
    )

    with pytest.raises(SystemExit, match="expected all_age_discovery"):
        cli._require_discovery_population(outcomes)


def test_candidate_generation_accepts_all_age_discovery_population(tmp_path) -> None:
    outcomes = _population_outcomes(tmp_path, role=DISCOVERY_POPULATION, days=0)

    contract = cli._require_discovery_population(outcomes)

    assert contract["population_role"] == DISCOVERY_POPULATION
