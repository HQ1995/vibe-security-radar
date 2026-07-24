from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import build_no_token_pilot as pilot
from cve_analyzer.models import (
    AiSignal,
    AiTool,
    BlameStrategy,
    BugIntroducingCommit,
    CommitInfo,
    CveAnalysisResult,
    CveScreeningResult,
    FixCommit,
)
from cve_analyzer.screening_router import apply_screening_route
from cve_analyzer.source_matcher import candidate_evidence_complete, match_result


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _class_record(lane: str, stratum: str, index: int) -> dict:
    if stratum == "ghsa_only":
        subject = f"GHSA-{lane[:2]}{index:02d}-aaaa-bbbb"
    else:
        year = "2023" if stratum == "le_2023" else stratum
        lane_digit = "1" if lane == "mapped" else "2"
        subject = f"CVE-{year}-{lane_digit}{index:04d}"
    class_id = f"alias-{lane}-{stratum}-{index}"
    git_ranges = (
        [{"repo": f"https://github.com/example/{stratum}-{index}"}]
        if lane == "mapped"
        else []
    )
    return {
        "class_id": class_id,
        "component_sha256": hashlib.sha256(class_id.encode()).hexdigest(),
        "all_member_ids": [subject],
        "analysis_subject": subject,
        "analysis_input": {
            "member_ids": [subject],
            "git_ranges": git_ranges,
            "fixed_events": [],
            "reference_urls": [],
        },
    }


def _write_source_delta(path: Path, *, cell_size: int = 3) -> None:
    classes = [
        _class_record(lane, stratum, index)
        for lane in pilot.LANES
        for stratum in pilot.STRATA
        for index in range(cell_size)
    ]
    payload = {
        "schema_version": 3,
        "population_policy": "formal_full",
        "production_discovery": {
            "alias_class_manifest": {
                "schema_version": 1,
                "source_snapshot_sha256": "a" * 64,
                "class_count": len(classes),
                "classes_sha256": _canonical_sha256(classes),
                "classes": classes,
            }
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_selection_is_deterministic_and_exactly_stratified(tmp_path: Path) -> None:
    source_delta = tmp_path / "source-delta.json"
    _write_source_delta(source_delta)

    first = pilot.build_selection(source_delta, per_cell=2)
    second = pilot.build_selection(source_delta, per_cell=2)

    assert first == second
    assert first["expected_subject_count"] == 20
    assert len(first["subjects"]) == 20
    assert set(first["selected_counts"].values()) == {2}
    assert sum(
        row["lane"] == "mapped" for row in first["subjects"]
    ) == 10
    assert sum(
        row["lane"] == "unmapped" for row in first["subjects"]
    ) == 10
    assert first["execution_contract"]["llm_allowed"] is False
    assert first["execution_contract"]["candidate_edge_cap"] is None


def test_selection_fails_when_any_cell_is_too_small(tmp_path: Path) -> None:
    source_delta = tmp_path / "source-delta.json"
    _write_source_delta(source_delta, cell_size=1)

    with pytest.raises(pilot.NoTokenPilotError, match="cannot satisfy"):
        pilot.build_selection(source_delta, per_cell=2)


def test_selection_can_rebind_exact_frozen_subject_cohort(tmp_path: Path) -> None:
    source_delta = tmp_path / "source-delta.json"
    _write_source_delta(source_delta)
    original = pilot.build_selection(source_delta, per_cell=2)
    original_path = tmp_path / "original-selection.json"
    original_path.write_text(json.dumps(original), encoding="utf-8")
    subject_ids, cells, binding = pilot._load_frozen_cohort(original_path)

    rebound = pilot.build_selection(
        source_delta,
        per_cell=2,
        cohort_subject_ids=subject_ids,
        cohort_cells=cells,
        cohort_binding=binding,
    )

    assert [row["analysis_subject"] for row in rebound["subjects"]] == subject_ids
    assert rebound["selected_subjects_sha256"] == original["selected_subjects_sha256"]
    assert rebound["source_delta_sha256"] == original["source_delta_sha256"]
    assert rebound["cohort_rebind"] == {
        "contract": "frozen-subject-cohort-rebind-v1",
        **binding,
        "current_cell_drift_count": 0,
        "current_cell_drift_sha256": _canonical_sha256([]),
    }
    assert rebound["cohort_cell_drift"] == []


def _write_no_token_result(
    path: Path,
    subject_id: str,
    *,
    positive: bool,
    legacy_positive: bool,
) -> None:
    repository = "github.com/example/repo"
    matched_text = "Co-authored-by: Claude <noreply@anthropic.com>"
    signal = AiSignal(
        tool=AiTool.CLAUDE_CODE,
        signal_type="co_author_trailer",
        matched_text=matched_text,
        confidence=0.99,
        origin="commit_metadata",
    )
    result = CveAnalysisResult(
        cve_id=subject_id,
        fix_commits=[
            FixCommit(
                sha="f" * 40,
                repo_url="https://github.com/example/repo",
                source="fixture",
            )
        ],
        candidate_set_refs=[
            {
                "schema_version": 1,
                "artifact_kind": "causal_candidate_set",
                "repository_identity": repository,
                "complete": True,
                "edge_count": 1 if positive else 0,
                "edge_ids": ["edge-test"] if positive else [],
                "primary_matches": (
                    [
                        {
                            "subject_sha": "a" * 40,
                            "tool": "claude_code",
                            "source_module": "coauthor_trailer",
                            "signal_type": "co_author_trailer",
                            "origin": "commit_metadata",
                            "matched_text": matched_text,
                            "matched_text_sha256": hashlib.sha256(
                                matched_text.encode()
                            ).hexdigest(),
                        }
                    ]
                    if positive
                    else []
                ),
            }
        ],
    )
    if legacy_positive:
        result.bug_introducing_commits.append(
            BugIntroducingCommit(
                commit=CommitInfo(
                    sha="a" * 40,
                    author_name="Human",
                    author_email="human@example.com",
                    committer_name="Human",
                    committer_email="human@example.com",
                    message=matched_text,
                    authored_date="2026-01-01T00:00:00Z",
                    ai_signals=[signal],
                ),
                fix_commit_sha="f" * 40,
                blamed_file="src/app.py",
                blamed_lines=[1],
                repository_identity=repository,
                blame_strategy=BlameStrategy.BLAME_DELETED,
            )
        )
    candidate_match = match_result(
        result,
        complete=candidate_evidence_complete(result),
    )
    result.candidate_match = candidate_match.to_dict()
    apply_screening_route(result, candidate_match)
    path.write_text(json.dumps(result.to_dict()), encoding="utf-8")


def test_result_report_proves_no_llm_and_no_legacy_drop(tmp_path: Path) -> None:
    source_delta = tmp_path / "source-delta.json"
    _write_source_delta(source_delta, cell_size=2)
    selection = pilot.build_selection(source_delta, per_cell=1)
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(json.dumps(selection), encoding="utf-8")
    results = tmp_path / "results"
    results.mkdir()
    for index, row in enumerate(selection["subjects"]):
        _write_no_token_result(
            results / f"{row['analysis_subject']}.json",
            row["analysis_subject"],
            positive=index == 0,
            legacy_positive=index == 0,
        )

    report = pilot.evaluate_results(selection_path, results)

    assert report["valid_result_count"] == 10
    assert report["candidate_subject_count"] == 1
    assert report["candidate_edge_count"] == 1
    assert report["legacy_shadow_candidate_count"] == 1
    assert report["exact_trailer_legacy_shadow_recall"] == 1.0
    assert report["acceptance"]["all_subjects_terminal"] is True
    assert report["acceptance"]["no_llm_outputs"] is True
    assert report["acceptance"]["zero_legacy_candidate_drop"] is True


def test_result_report_rejects_any_llm_output(tmp_path: Path) -> None:
    source_delta = tmp_path / "source-delta.json"
    _write_source_delta(source_delta, cell_size=1)
    selection = pilot.build_selection(source_delta, per_cell=1)
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(json.dumps(selection), encoding="utf-8")
    results = tmp_path / "results"
    results.mkdir()
    for row in selection["subjects"]:
        result_path = results / f"{row['analysis_subject']}.json"
        _write_no_token_result(
            result_path,
            row["analysis_subject"],
            positive=False,
            legacy_positive=False,
        )
    first = results / f"{selection['subjects'][0]['analysis_subject']}.json"
    payload = json.loads(first.read_text(encoding="utf-8"))
    payload["screening"] = CveScreeningResult(
        worth_investigating=False,
        reasoning="LLM output must not exist",
        model="gemini-3.5-flash-lite",
    ).to_dict()
    first.write_text(json.dumps(payload), encoding="utf-8")

    report = pilot.evaluate_results(selection_path, results)

    assert report["llm_output_count"] == 1
    assert report["acceptance"]["all_subjects_terminal"] is False
    assert report["acceptance"]["no_llm_outputs"] is False
