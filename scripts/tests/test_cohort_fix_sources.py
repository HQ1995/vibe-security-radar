"""Tests for recall-first fix-source union and repository fallback rows."""

from __future__ import annotations

import json
from types import SimpleNamespace

import cohort.fix_sources as sources


REPOSITORY = "github.com/example/project"
FIRST_FIX = "1" * 40
SECOND_FIX = "2" * 40
UNIT = "3" * 40


def _cache_payload(*, status: str, phase2_sha: str = "") -> dict[str, object]:
    return {
        "cve_id": "CVE-2025-55526",
        "model": "cached-model",
        "status": status,
        "input": {
            "repo_url": "https://github.com/example/project",
            "description": "path traversal in download_workflow",
        },
        "search": {
            "top_scored": [
                {"sha": FIRST_FIX[:12], "score": 11.0, "message": "candidate one"},
                {"sha": SECOND_FIX[:12], "score": 10.0, "message": "candidate two"},
            ]
        },
        "phase2": {"fix_sha": phase2_sha},
        # The source projection must never import unrelated audit-shaped fields.
        "introduced_commits": [{"sha": UNIT}],
        "golden_origin_sha": UNIT,
    }


def _write_cvelist(tmp_path) -> object:
    root = tmp_path / "cvelist"
    path = root / "2025" / "55xxx" / "CVE-2025-55526.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "containers": {
                    "cna": {
                        "references": [
                            {
                                "url": (
                                    "https://github.com/example/project/issues/48"
                                )
                            }
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return root


def test_cached_model_rejection_never_deletes_ranked_carriers(tmp_path) -> None:
    cache = tmp_path / "desc-search"
    cache.mkdir()
    (cache / "CVE-2025-55526.json").write_text(
        json.dumps(_cache_payload(status="NOT_FOUND")),
        encoding="utf-8",
    )

    result = sources.load_description_search_sources(
        cache,
        {REPOSITORY},
        {},
        cvelist_dir=_write_cvelist(tmp_path),
    )

    assert len(result["associations"]) == 1
    association = result["associations"][0]
    assert {anchor["value"] for anchor in association["anchors"]} == {
        "#48",
        "CVE-2025-55526",
    }
    observations = result["observations"]
    assert {row["fix_ref"] for row in observations} == {
        FIRST_FIX[:12],
        SECOND_FIX[:12],
    }
    assert {row["evidence_kind"] for row in observations} == {
        sources.RANKED_SEARCH_CARRIER
    }
    assert UNIT not in json.dumps(result, sort_keys=True)


def test_found_phase2_is_enriched_not_public_exact(tmp_path) -> None:
    cache = tmp_path / "desc-search"
    cache.mkdir()
    (cache / "CVE-2025-55526.json").write_text(
        json.dumps(_cache_payload(status="FOUND", phase2_sha=FIRST_FIX)),
        encoding="utf-8",
    )

    result = sources.load_description_search_sources(cache, {REPOSITORY}, {})
    exact = [
        row
        for row in result["observations"]
        if row["evidence_kind"] == sources.ENRICHED_SELECTED
    ]

    assert len(exact) == 1
    assert exact[0]["fix_ref"] == FIRST_FIX
    assert exact[0]["inherited_model"] == "cached-model"
    assert not any(
        row["evidence_kind"] == sources.PUBLIC_EXACT
        for row in result["observations"]
    )


def test_converted_version_boundary_is_retained_but_not_public_exact() -> None:
    observations = sources.public_fix_observations(
        [
            {
                "repository_identity": REPOSITORY,
                "advisory": "CVE-2026-1000",
                "fix_sha": FIRST_FIX,
                "published": "2026-01-01T00:00:00Z",
                "reference_kind": "converted_version_boundary",
            }
        ]
    )

    assert observations[0]["fix_ref"] == FIRST_FIX
    assert observations[0]["evidence_kind"] == sources.PUBLIC_VERSION_BOUNDARY


def test_repository_reference_scan_is_unbounded_and_retains_every_match(
    monkeypatch,
    tmp_path,
) -> None:
    commands: list[list[str]] = []

    def fake_run_git(command: list[str], **_kwargs: object) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout=f"{FIRST_FIX}\n{SECOND_FIX}\n")

    monkeypatch.setattr(sources, "run_git", fake_run_git)
    associations = [
        {
            "repository_identity": REPOSITORY,
            "advisory": "CVE-2025-55526",
            "anchors": [
                {"kind": "github_issue", "value": "#48", "source_url": "issue"}
            ],
        }
    ]

    observations, stats = sources.scan_repository_reference_carriers(
        {REPOSITORY: tmp_path},
        associations,
        timeout=30,
        git_global_arguments_by_repository={
            REPOSITORY: ["--shallow-file", ""]
        },
    )

    assert {row["fix_ref"] for row in observations} == {FIRST_FIX, SECOND_FIX}
    assert stats["matched_commits"] == 2
    assert "--all" in commands[0]
    assert "--fixed-strings" in commands[0]
    assert commands[0][3:5] == ["--shallow-file", ""]
    assert not any(argument.startswith("--since") for argument in commands[0])


def test_source_resolution_conserves_unavailable_refs(monkeypatch, tmp_path) -> None:
    def fake_run_git(command: list[str], **_kwargs: object) -> SimpleNamespace:
        ref = command[-1].removesuffix("^{commit}")
        if ref == FIRST_FIX[:12]:
            return SimpleNamespace(returncode=0, stdout=f"{FIRST_FIX}\n")
        return SimpleNamespace(returncode=128, stdout="")

    monkeypatch.setattr(sources, "run_git", fake_run_git)
    observations = [
        {
            "observation_id": "one",
            "repository_identity": REPOSITORY,
            "advisory": "CVE-2025-55526",
            "fix_ref": FIRST_FIX[:12],
            "evidence_kind": sources.RANKED_SEARCH_CARRIER,
            "source": "ranked",
            "published": "",
        },
        {
            "observation_id": "two",
            "repository_identity": REPOSITORY,
            "advisory": "CVE-2025-55526",
            "fix_ref": SECOND_FIX[:12],
            "evidence_kind": sources.RANKED_SEARCH_CARRIER,
            "source": "ranked",
            "published": "",
        },
    ]

    rows, fixes, stats = sources.resolve_source_observations(
        observations,
        {REPOSITORY: tmp_path},
        timeout=30,
    )

    assert {row["resolution_status"] for row in rows} == {"RESOLVED", "BLOCKED"}
    assert stats["resolved"] == 1
    assert stats["blocked"] == 1
    assert {row["fix_sha"] for row in fixes[REPOSITORY]} == {
        FIRST_FIX,
        SECOND_FIX[:12],
    }


def test_repository_recall_floor_keeps_every_unit_without_fabricating_fix_sha() -> None:
    units = {
        REPOSITORY: [
            {
                "repository_identity": REPOSITORY,
                "sha": UNIT,
                "tools": ["claude"],
                "route": "trailer",
            },
            {
                "repository_identity": REPOSITORY,
                "sha": FIRST_FIX,
                "tools": ["codex"],
                "route": "regex",
            },
        ]
    }
    associations = [
        {
            "repository_identity": REPOSITORY,
            "advisory": "CVE-2025-55526",
            "description": "path traversal",
            "source": "description_search_cache",
        }
    ]

    result = sources.build_repository_recall_floor(units, associations)

    assert result["summary"]["association_count"] == 1
    assert result["summary"]["fallback_candidate_count"] == 2
    assert {row["candidate_sha"] for row in result["candidates"]} == {
        UNIT,
        FIRST_FIX,
    }
    assert all("fix_sha" not in row for row in result["candidates"])
    assert all(row["initial_status"] == "DEFER" for row in result["candidates"])


def test_fix_source_recall_keeps_public_selected_and_carrier_tiers_separate() -> None:
    fixes = [
        {
            "repository_identity": REPOSITORY,
            "advisory": "CVE-2025-1000",
            "fix_sha": FIRST_FIX,
        },
        {
            "repository_identity": REPOSITORY,
            "advisory": "CVE-2025-2000",
            "fix_sha": SECOND_FIX,
        },
    ]
    observations = [
        {
            "observation_id": "public",
            "repository_identity": REPOSITORY,
            "advisory": "CVE-2025-1000",
            "fix_sha": FIRST_FIX,
            "resolution_status": "RESOLVED",
            "evidence_kind": sources.PUBLIC_EXACT,
        },
        {
            "observation_id": "carrier",
            "repository_identity": REPOSITORY,
            "advisory": "CVE-2025-2000",
            "fix_sha": SECOND_FIX,
            "resolution_status": "RESOLVED",
            "evidence_kind": sources.REPOSITORY_REFERENCE_CARRIER,
        },
    ]
    fallback = [
        {
            "repository_identity": REPOSITORY,
            "advisory": advisory,
            "candidate_sha": UNIT,
            "relation": sources.REPOSITORY_ADVISORY_FALLBACK,
        }
        for advisory in ("CVE-2025-1000", "CVE-2025-2000")
    ]

    result = sources.evaluate_fix_source_recall(fixes, observations, fallback)

    assert result["public_exact_pass_count"] == 1
    assert result["enriched_selected_union_pass_count"] == 1
    assert result["source_candidate_pass_count"] == 2
    assert result["repository_fallback_pass_count"] == 2
    assert result["source_candidate_gate_passed"] is True
