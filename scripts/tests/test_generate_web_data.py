"""Regression tests for the Web data generation orchestrator."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import generate_web_data as generator
import web_data.release_evidence as release_evidence
from cve_analyzer.models import (
    AiSignal,
    AiTool,
    BugIntroducingCommit,
    CommitInfo,
    CveAnalysisResult,
    CveScreeningResult,
    FixCommit,
)
from generate_web_data import (
    BuiltPublication,
    ReleaseGateError,
    _build_detector_inventory,
    _deduplicate_alias_entries,
    _load_exact_campaign_results,
    _require_release_gates,
    _select_publication_results,
    _strict_build_alias_map,
    generate_release,
)
from web_data.entry_builder import QuarantineLog
from web_data.writer import PublishedWebData, load_published_web_data, write_web_data


def _candidate_entries(publication: PublishedWebData) -> list[dict]:
    return [
        {key: value for key, value in entry.items() if key != "generation_id"}
        for entry in publication.entries
    ]


def test_formal_entries_preserve_clean_verifier_scope_without_bytecode(
    tmp_path: Path,
) -> None:
    """A normal Python entry must not manufacture its own verifier failure."""

    source_root = Path(generator.__file__).resolve().parents[1]
    repo_root = tmp_path / "repo"
    ignored = shutil.ignore_patterns(
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        "tests",
        "audit_results",
        "heldout_studies",
    )
    for relative in (
        "scripts",
        "cve-analyzer/src",
        "web/scripts",
        "web/src",
    ):
        shutil.copytree(source_root / relative, repo_root / relative, ignore=ignored)
    for relative in generator.verifier_contract_builder.FILE_SCOPES:
        destination = repo_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_root / relative, destination)

    subprocess.run(
        ["git", "init", "-q", str(repo_root)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["git", "-C", str(repo_root), "add", "--", "."],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "-c",
            "user.name=Formal Entry Test",
            "-c",
            "user.email=formal-entry@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "Create clean formal release checkout",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    environment = dict(os.environ)
    environment.pop("PYTHONDONTWRITEBYTECODE", None)
    environment.pop("PYTHONPYCACHEPREFIX", None)

    for entrypoint in ("generate_web_data.py", "verify_formal_release.py"):
        result = subprocess.run(
            [sys.executable, str(repo_root / "scripts" / entrypoint), "--help"],
            cwd=repo_root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
    assert list(repo_root.rglob("*.pyc")) == []
    contract = generator.verifier_contract_builder.build_verifier_contract(repo_root)
    assert contract["git_commit"]


def test_alias_dedup_prefers_cve_for_actual_osv_pair() -> None:
    cve_id = "CVE-2026-32890"
    ghsa_id = "GHSA-qpmq-6wjc-w28q"
    alias_group = {cve_id, ghsa_id}
    entries = [
        {"id": ghsa_id, "confidence": 0.99},
        {"id": cve_id, "confidence": 0.80},
    ]

    deduplicated = _deduplicate_alias_entries(
        entries,
        {cve_id: alias_group, ghsa_id: alias_group},
    )

    assert [entry["id"] for entry in deduplicated] == [cve_id]


def test_publication_selection_quarantines_unadjudicated_pipeline_positive() -> None:
    audited = SimpleNamespace(cve_id="CVE-2026-1")
    unadjudicated = SimpleNamespace(cve_id="CVE-2026-2")

    selected = _select_publication_results(
        [audited, unadjudicated],
        adjudicated_positive_ids={"CVE-2026-1"},
        audit_exclusions=set(),
        inclusion_predicate=lambda *_args: True,
    )

    assert [result.cve_id for result in selected] == ["CVE-2026-1"]


def _complete_stage_receipts() -> dict[str, dict]:
    return {
        stage: {"outcome": "resolved"}
        for stage in (
            "source_discovery",
            "fix_resolution",
            "bic_resolution",
            "signal_classification",
            "causal_verification",
        )
    }


def _inventory_context() -> dict:
    return {
        "generated_at": "2026-07-19T00:00:00+00:00",
        "source_snapshot_sha256": "a" * 64,
        "source_receipt_sha256": "b" * 64,
        "campaign_id": "c" * 64,
        "contract_sha256": "d" * 64,
        "campaign_mode": "formal",
        "coverage_to": "2026-07-19",
    }


def _inventory_bic(
    signal_type: str | None,
    *,
    confirmed: bool = False,
    tool: AiTool = AiTool.CLAUDE_CODE,
) -> BugIntroducingCommit:
    signals = (
        [
            AiSignal(
                tool=tool,
                signal_type=signal_type,
                matched_text=(
                    "Co-authored-by: Claude <noreply@anthropic.com>"
                    if signal_type == "co_author_trailer"
                    and tool is AiTool.CLAUDE_CODE
                    else "fixture"
                ),
                confidence=0.95,
            )
        ]
        if signal_type
        else []
    )
    return BugIntroducingCommit(
        commit=CommitInfo(
            sha="1" * 40,
            author_name="Fixture",
            author_email="fixture@example.invalid",
            committer_name="Fixture",
            committer_email="fixture@example.invalid",
            message=(
                "fixture\n\nCo-authored-by: Claude <noreply@anthropic.com>"
                if signal_type == "co_author_trailer"
                and tool is AiTool.CLAUDE_CODE
                else "fixture"
            ),
            authored_date="2026-07-18T00:00:00Z",
            ai_signals=signals,
        ),
        fix_commit_sha="2" * 40,
        blamed_file="src/main.py",
        blamed_lines=[1],
        repository_identity="github.com/example/repo",
        deep_verification={"verdict": "CONFIRMED" if confirmed else "UNRELATED"},
    )


def test_detector_inventory_keeps_catalog_candidates_and_rejection_strata_separate() -> (
    None
):
    fix = FixCommit(
        sha="2" * 40,
        repo_url="https://github.com/example/repo",
        source="osv",
    )
    results = (
        CveAnalysisResult(
            cve_id="CVE-2026-1",
            analysis_stage_receipts=_complete_stage_receipts(),
        ),
        CveAnalysisResult(
            cve_id="CVE-2026-2",
            fix_commits=[fix],
            analysis_stage_receipts=_complete_stage_receipts(),
        ),
        CveAnalysisResult(
            cve_id="CVE-2026-3",
            fix_commits=[fix],
            bug_introducing_commits=[_inventory_bic("merge_workflow")],
            analysis_stage_receipts=_complete_stage_receipts(),
        ),
        CveAnalysisResult(
            cve_id="CVE-2026-4",
            fix_commits=[fix],
            bug_introducing_commits=[
                _inventory_bic("co_author_trailer", confirmed=True)
            ],
            analysis_stage_receipts=_complete_stage_receipts(),
        ),
    )
    alias_map = {result.cve_id: {result.cve_id} for result in results}

    inventory = _build_detector_inventory(
        results,
        alias_map=alias_map,
        adjudicated_positive_ids={"CVE-2026-4"},
        audit_exclusions=set(),
        published_ids={"CVE-2026-4"},
        **_inventory_context(),
    )

    rows = {row["class_id"]: row for row in inventory["rows"]}
    assert rows["CVE-2026-1"]["recall_stratum"] == "no_fix_commit"
    assert rows["CVE-2026-2"]["recall_stratum"] == "fix_no_bic"
    assert rows["CVE-2026-3"]["detector_state"] == "negative"
    assert rows["CVE-2026-3"]["recall_stratum"] == "bic_no_trusted_authorship"
    assert rows["CVE-2026-4"]["detector_state"] == "positive"
    assert rows["CVE-2026-4"]["publication_state"] == "published"
    assert inventory["detector_candidate_count"] == 1
    assert inventory["complete"] is True


def test_cve_2025_11445_ellipsis_review_signal_cannot_become_positive() -> None:
    """Regression: Ellipsis review attribution remains shadow-only."""
    cve_id = "CVE-2025-11445"
    fix = FixCommit(
        sha="2" * 40,
        repo_url="https://github.com/example/repo",
        source="osv",
    )
    result = CveAnalysisResult(
        cve_id=cve_id,
        fix_commits=[fix],
        bug_introducing_commits=[
            _inventory_bic(
                "co_author_trailer",
                confirmed=True,
                tool=AiTool.ELLIPSIS,
            )
        ],
        analysis_stage_receipts=_complete_stage_receipts(),
    )

    inventory = _build_detector_inventory(
        (result,),
        alias_map={cve_id: {cve_id}},
        adjudicated_positive_ids=set(),
        audit_exclusions={cve_id},
        published_ids=set(),
        **_inventory_context(),
    )

    row = inventory["rows"][0]
    assert row["detector_state"] == "negative"
    assert row["recall_stratum"] == "bic_no_trusted_authorship"
    assert row["publication_state"] == "not_applicable"


def test_detector_inventory_exposes_missing_current_alias_class_as_coverage_failure() -> (
    None
):
    result = CveAnalysisResult(
        cve_id="CVE-2026-1",
        analysis_stage_receipts=_complete_stage_receipts(),
    )
    inventory = _build_detector_inventory(
        (result,),
        alias_map={
            "CVE-2026-1": {"CVE-2026-1"},
            "CVE-2026-2": {"CVE-2026-2"},
        },
        adjudicated_positive_ids=set(),
        audit_exclusions=set(),
        published_ids=set(),
        **_inventory_context(),
    )

    assert inventory["complete"] is False
    assert inventory["coverage_failure_count"] == 1
    assert inventory["counts"]["coverage_status"] == {"complete": 1, "missing": 1}
    missing = next(
        row for row in inventory["rows"] if row["coverage_status"] == "missing"
    )
    assert missing["recall_stratum"] == "coverage_failure"


def test_detector_inventory_never_counts_coverage_failures_as_negatives() -> None:
    api_failure = CveAnalysisResult(
        cve_id="CVE-2026-1",
        error="GitHub API unavailable",
        error_category="api_error",
        analysis_stage_receipts=_complete_stage_receipts(),
    )
    pr_failure_receipts = _complete_stage_receipts()
    pr_failure_receipts["signal_classification"] = {
        "outcome": "incomplete",
        "reason": "incomplete:pr_lookup_failed",
    }
    pr_failure = CveAnalysisResult(
        cve_id="CVE-2026-2",
        analysis_stage_receipts=pr_failure_receipts,
    )
    inventory = _build_detector_inventory(
        (api_failure, pr_failure),
        alias_map={
            "CVE-2026-1": {"CVE-2026-1"},
            "CVE-2026-2": {"CVE-2026-2"},
            "CVE-2026-3": {"CVE-2026-3"},  # uncached current-epoch class
            "CVE-2026-4": {"CVE-2026-4"},  # missing campaign result
        },
        adjudicated_positive_ids=set(),
        audit_exclusions=set(),
        published_ids=set(),
        **_inventory_context(),
    )

    rows = {row["class_id"]: row for row in inventory["rows"]}
    assert rows["CVE-2026-1"]["coverage_status"] == "error"
    assert rows["CVE-2026-2"]["coverage_status"] == "incomplete"
    assert rows["CVE-2026-3"]["coverage_status"] == "missing"
    assert rows["CVE-2026-4"]["coverage_status"] == "missing"
    assert {row["recall_stratum"] for row in rows.values()} == {"coverage_failure"}
    assert inventory["coverage_failure_count"] == 4


def test_prelabel_inventory_identity_replays_from_fixed_source_cutoff() -> None:
    cutoff = {"checked_at_utc": "2026-07-19T04:00:00+00:00"}
    generated_at = generator._inventory_generated_at(cutoff)
    result = CveAnalysisResult(
        cve_id="CVE-2026-1",
        analysis_stage_receipts=_complete_stage_receipts(),
    )
    arguments = {
        **_inventory_context(),
        "generated_at": generated_at,
    }
    first = _build_detector_inventory(
        (result,),
        alias_map={result.cve_id: {result.cve_id}},
        adjudicated_positive_ids=set(),
        audit_exclusions=set(),
        published_ids=set(),
        **arguments,
    )
    prelabel_selection_inventory_id = first["inventory_id"]

    replayed = _build_detector_inventory(
        (result,),
        alias_map={result.cve_id: {result.cve_id}},
        adjudicated_positive_ids=set(),
        audit_exclusions=set(),
        published_ids=set(),
        **arguments,
    )

    assert replayed["inventory_id"] == prelabel_selection_inventory_id
    assert replayed["generated_at"] == cutoff["checked_at_utc"]


@pytest.mark.parametrize(
    "timestamp",
    ["2026-07-19T04:00:00Z", "2026-07-19T00:00:00-04:00", "2026-07-19"],
)
def test_inventory_cutoff_timestamp_requires_canonical_utc(timestamp: str) -> None:
    with pytest.raises(ReleaseGateError, match="canonical UTC"):
        generator._inventory_generated_at({"checked_at_utc": timestamp})


def test_release_input_hashes_bind_end_to_end_recall_evaluator() -> None:
    hashes = generator._release_input_hashes()

    assert "scripts/build_recall_audit.py" in hashes
    assert len(hashes["scripts/build_recall_audit.py"]) == 64


def test_detector_inventory_rejects_unscheduled_formal_alias_class() -> None:
    subject = "CVE-2026-1"
    component_sha256 = hashlib.sha256(f"{subject}\n".encode()).hexdigest()
    analysis_input = {
        "member_ids": [subject],
        "git_ranges": [],
        "fixed_events": [],
        "reference_urls": [],
    }
    classes = [
        {
            "class_id": f"alias-{component_sha256[:24]}",
            "component_sha256": component_sha256,
            "all_member_ids": [subject],
            "eligible_seed_ids": [subject],
            "scheduled_seed_ids": [],
            "source_record_references": [],
            "merged_source_evidence_sha256": hashlib.sha256(
                generator.refresh_runner._canonical_json_bytes(
                    {"records": [], "analysis_input": analysis_input}
                )
            ).hexdigest(),
            "analysis_subject": subject,
            "analysis_input": analysis_input,
            "source_snapshot_sha256": "a" * 64,
        }
    ]
    manifest = {
        "schema_version": 1,
        "source_snapshot_sha256": "a" * 64,
        "class_count": 1,
        "eligible_seed_id_count": 1,
        "all_eligible_seed_ids_exactly_once": True,
        "scheduled_class_count": 0,
        "scheduled_analysis_subject_count": 0,
        "scheduled_classes_exactly_once": True,
        "classes_sha256": hashlib.sha256(
            generator.refresh_runner._canonical_json_bytes(classes)
        ).hexdigest(),
        "classes": classes,
    }

    with pytest.raises(generator.ReleaseGateError, match="unscheduled"):
        _build_detector_inventory(
            (),
            alias_map={subject: {subject}},
            adjudicated_positive_ids=set(),
            audit_exclusions=set(),
            published_ids=set(),
            alias_class_manifest=manifest,
            **_inventory_context(),
        )


def _write_result(path: Path, cve_id: str) -> None:
    signal = AiSignal(
        tool=AiTool.CURSOR,
        signal_type="co_author_trailer",
        matched_text="Co-authored-by: Cursor <cursoragent@cursor.com>",
        confidence=0.95,
    )
    commit = CommitInfo(
        sha="a" * 40,
        author_name="Fixture",
        author_email="fixture@example.invalid",
        committer_name="Fixture",
        committer_email="fixture@example.invalid",
        message=(
            "fixture campaign result\n\n"
            "Co-authored-by: Cursor <cursoragent@cursor.com>"
        ),
        authored_date="2026-07-18T12:00:00Z",
        ai_signals=[signal],
    )
    bic = BugIntroducingCommit(
        commit=commit,
        fix_commit_sha="b" * 40,
        blamed_file="src/fixture.py",
        blamed_lines=[1],
        repository_identity="https://github.com/example/project",
        deep_verification={
            "verdict": "CONFIRMED",
            "reasoning": "Fixture causal evidence.",
            "model": "gpt-5.6-luna",
            "reasoning_effort": "max",
            "ai_signal_attested": True,
            "ai_signal_source": "cursor",
            "confidence": "high",
            "tool_calls_made": 1,
            "steps_completed": ["verify"],
            "evidence": ["fixture"],
        },
    )
    payload = CveAnalysisResult(
        cve_id=cve_id,
        fix_commits=[
            FixCommit(
                sha="b" * 40,
                repo_url="https://github.com/example/project",
                source="fixture",
            )
        ],
        bug_introducing_commits=[bic],
        screening=CveScreeningResult(
            worth_investigating=True,
            reasoning="Fixture screening retains the candidate.",
            relevant_commits=[bic.commit.sha],
            model="gemini-3.5-flash-lite",
        ),
        ai_involved=True,
        investigation_scope_hash=hashlib.sha256(
            "\0".join(bic.subject_key()).encode("utf-8")
        ).hexdigest(),
        analysis_stage_receipts={
            **_complete_stage_receipts(),
            "adjudication": {"outcome": "resolved"},
        },
    ).to_dict()
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_exact_campaign_loader_binds_complete_inventory(tmp_path: Path) -> None:
    campaign_id = "a" * 64
    result_dir = tmp_path / "campaigns-v1" / campaign_id / "results"
    result_dir.mkdir(parents=True)
    _write_result(result_dir / "CVE-2026-1.json", "CVE-2026-1")
    _write_result(result_dir / "GHSA-aaaa-bbbb-cccc.json", "GHSA-aaaa-bbbb-cccc")
    context = SimpleNamespace(
        campaign_id=campaign_id,
        result_dir=result_dir,
        batches=(SimpleNamespace(ids=("CVE-2026-1", "GHSA-aaaa-bbbb-cccc")),),
    )

    snapshot = _load_exact_campaign_results(context)

    assert [result.cve_id for result in snapshot.results] == [
        "CVE-2026-1",
        "GHSA-aaaa-bbbb-cccc",
    ]
    assert [item["subject_id"] for item in snapshot.manifest] == [
        "CVE-2026-1",
        "GHSA-aaaa-bbbb-cccc",
    ]
    assert len(snapshot.manifest_sha256) == 64


def test_exact_campaign_loader_bounds_each_result_on_first_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_id = "a" * 64
    result_dir = tmp_path / "campaigns-v1" / campaign_id / "results"
    result_dir.mkdir(parents=True)
    _write_result(result_dir / "CVE-2026-1.json", "CVE-2026-1")
    context = SimpleNamespace(
        campaign_id=campaign_id,
        result_dir=result_dir,
        batches=(SimpleNamespace(ids=("CVE-2026-1",)),),
    )
    monkeypatch.setattr(generator, "_MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES", 1)

    with pytest.raises(ReleaseGateError, match="archive size bound"):
        _load_exact_campaign_results(context)


def test_exact_campaign_loader_bounds_aggregate_result_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_id = "a" * 64
    result_dir = tmp_path / "campaigns-v1" / campaign_id / "results"
    result_dir.mkdir(parents=True)
    _write_result(result_dir / "CVE-2026-1.json", "CVE-2026-1")
    _write_result(result_dir / "CVE-2026-2.json", "CVE-2026-2")
    context = SimpleNamespace(
        campaign_id=campaign_id,
        result_dir=result_dir,
        batches=(SimpleNamespace(ids=("CVE-2026-1", "CVE-2026-2")),),
    )
    monkeypatch.setattr(
        generator,
        "_MAX_ARCHIVED_CAMPAIGN_RESULTS_TOTAL_BYTES",
        1,
    )

    with pytest.raises(ReleaseGateError, match="aggregate archive size bound"):
        _load_exact_campaign_results(context)


def test_release_input_reader_rejects_symlinks_without_following_them(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"safe":true}\n', encoding="utf-8")
    link = tmp_path / "input.json"
    link.symlink_to(target)

    with pytest.raises(ReleaseGateError, match="cannot open"):
        generator._stable_regular_file(link, "release input")


def test_campaign_population_archiver_rejects_symlinks_without_following_them(
    tmp_path: Path,
) -> None:
    subject_id = "CVE-2026-1"
    real_result = tmp_path / "real-result.json"
    _write_result(real_result, subject_id)
    result_dir = tmp_path / "campaigns-v1" / ("a" * 64) / "results"
    result_dir.mkdir(parents=True)
    (result_dir / f"{subject_id}.json").symlink_to(real_result)
    result_bytes = real_result.read_bytes()
    manifest = (
        {
            "subject_id": subject_id,
            "file_name": f"{subject_id}.json",
            "size_bytes": len(result_bytes),
            "sha256": hashlib.sha256(result_bytes).hexdigest(),
        },
    )
    snapshot = generator.CampaignResultSnapshot(
        results=(),
        manifest=manifest,
        manifest_sha256=generator._canonical_sha256(list(manifest)),
    )

    with pytest.raises(ReleaseGateError, match="cannot open"):
        generator._heldout_campaign_population_artifact(
            SimpleNamespace(result_dir=result_dir),
            snapshot,
            {},
            {},
        )


@pytest.mark.parametrize("extra_name", ["CVE-2026-2.json", "notes.txt"])
def test_exact_campaign_loader_rejects_unplanned_inventory(
    tmp_path: Path,
    extra_name: str,
) -> None:
    campaign_id = "b" * 64
    result_dir = tmp_path / "campaigns-v1" / campaign_id / "results"
    result_dir.mkdir(parents=True)
    _write_result(result_dir / "CVE-2026-1.json", "CVE-2026-1")
    (result_dir / extra_name).write_text("{}", encoding="utf-8")
    context = SimpleNamespace(
        campaign_id=campaign_id,
        result_dir=result_dir,
        batches=(SimpleNamespace(ids=("CVE-2026-1",)),),
    )

    with pytest.raises(ReleaseGateError, match="inventory"):
        _load_exact_campaign_results(context)


def test_release_gate_requires_complete_detector_and_both_point_targets() -> None:
    detector_report = {
        "evaluation_complete": True,
        "detector_inventory": {
            "stage_quality_gate": {
                "screening_zero_false_negatives": True,
                "final_precision_lower_bound_at_least_0_95": True,
                "final_recall_lower_bound_at_least_0_95": True,
                "passed": True,
            }
        },
        "fixed_contract_campaign_proof": {
            "complete": True,
            "campaign_mode": "formal",
            "population_policy": "formal_full",
            "formal_population_complete": True,
            "incremental_plan_complete": False,
            "full_incremental_plan_campaign_complete": False,
            "proof_scope": "formal_current_source_alias_class_plan",
            "population_uniform_luna_max_proof": False,
            "expected_contract": {
                "campaign_id": "1" * 64,
                "contract_sha256": "2" * 64,
                "source_snapshot_sha256": "3" * 64,
            },
        },
    }
    curation_report = {
        "curation_consistent": True,
        "targets": {"curation_precision": 0.95, "curation_recall": 0.95},
        "curation_precision": {"point": 0.96},
        "curation_recall": {"point": 0.95},
    }
    heldout_report = {
        "evaluation_complete": True,
        "point_gate_passed": True,
        "certified_gate_passed": True,
        "release_gate_passed": True,
        "precision": {"one_sided_95pct_lower_bound": 0.96},
        "recall": {"one_sided_95pct_lower_bound": 0.96},
        "stage_metrics": {
            "screening": {
                "confusion": {"tp": 59, "fp": 0, "fn": 0, "tn": 0},
                "screening_zero_false_negatives": True,
            }
        },
        "campaign": {
            "campaign_id": "1" * 64,
            "contract_sha256": "2" * 64,
            "source_snapshot_sha256": "3" * 64,
        },
    }
    recall_report = {
        "schema_version": 2,
        "evaluation_kind": "stratified_end_to_end_finite_population_recall",
        "selection_replayed_from_inventory": True,
        "evaluation_complete": True,
        "evaluation_blockers": [],
        "artifact_order": {"selection_commit": "1" * 40},
        "resolved_labels": {"packet": "AI_CAUSAL"},
        "unresolved_packet_ids": [],
        "coverage_failure_count": 0,
        "protected_overlap_class_count": 0,
        "protected_census_manifest_sha256": "4" * 64,
        "protected_census_complete": True,
        "protected_census_resolved_labels": {},
        "protected_census_unresolved_packet_ids": [],
        "protected_excluded_class_count": 0,
        "covered_unprotected_diagnostic_complete": True,
        "recall": {
            "recall_point": 1.0,
            "recall_interval": [1.0, 1.0],
            "protected_census": {"class_count": 0},
        },
    }

    _require_release_gates(
        detector_report,
        curation_report,
        heldout_report,
        recall_report,
        precision_target=0.95,
        recall_target=0.95,
    )

    for recall in (
        {"recall_point": 0.01, "recall_interval": [0.0, 0.02]},
        {"recall_point": 1.0, "recall_interval": [0.94, 1.0]},
    ):
        with pytest.raises(ReleaseGateError, match="end-to-end recall.*target"):
            _require_release_gates(
                detector_report,
                curation_report,
                heldout_report,
                {
                    **recall_report,
                    "recall": {**recall_report["recall"], **recall},
                },
                precision_target=0.95,
                recall_target=0.95,
            )

    for field, value in (
        ("evaluation_complete", False),
        ("fixed_contract_campaign_proof", {"complete": False}),
    ):
        broken = {**detector_report, field: value}
        with pytest.raises(ReleaseGateError):
            _require_release_gates(
                broken,
                curation_report,
                heldout_report,
                recall_report,
                precision_target=0.95,
                recall_target=0.95,
            )

    with pytest.raises(ReleaseGateError, match="recall"):
        _require_release_gates(
            detector_report,
            {
                **curation_report,
                "curation_recall": {"point": 0.949},
            },
            heldout_report,
            recall_report,
            precision_target=0.95,
            recall_target=0.95,
        )


def test_strict_alias_loader_fails_on_one_malformed_record(tmp_path: Path) -> None:
    ghsa_dir = tmp_path / "advisories"
    (ghsa_dir / "github-reviewed").mkdir(parents=True)
    (ghsa_dir / "unreviewed").mkdir()
    (ghsa_dir / "github-reviewed" / "bad.json").write_text(
        '{"id":"GHSA-aaaa-bbbb-cccc","aliases":"CVE-2026-1"}',
        encoding="utf-8",
    )
    osv_dir = tmp_path / "osv"
    osv_dir.mkdir()

    with pytest.raises(ReleaseGateError, match="aliases"):
        _strict_build_alias_map(ghsa_dir, osv_dir)


def test_strict_alias_loader_normalizes_source_whitespace(tmp_path: Path) -> None:
    ghsa_dir = tmp_path / "advisories"
    (ghsa_dir / "github-reviewed").mkdir(parents=True)
    (ghsa_dir / "unreviewed").mkdir()
    (ghsa_dir / "github-reviewed" / "record.json").write_text(
        '{"id":"GHSA-aaaa-bbbb-cccc","aliases":[]}',
        encoding="utf-8",
    )
    osv_dir = tmp_path / "osv"
    osv_dir.mkdir()
    with zipfile.ZipFile(osv_dir / "test.zip", "w") as archive:
        archive.writestr(
            "OSV-2026-1.json",
            json.dumps(
                {
                    "id": "OSV-2026-1",
                    "aliases": [" CVE-2026-1 ", "GHSA-aaaa-bbbb-cccc"],
                }
            ),
        )

    alias_map = _strict_build_alias_map(ghsa_dir, osv_dir)

    assert alias_map["CVE-2026-1"] == {
        "CVE-2026-1",
        "GHSA-aaaa-bbbb-cccc",
        "OSV-2026-1",
    }


def _publication_entry(cve_id: str) -> dict:
    return {
        "id": cve_id,
        "description": "A test vulnerability",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwes": [],
        "ecosystem": "",
        "published": "2026-06-01",
        "ai_tools": ["cursor"],
        "ai_involved": None,
        "signal_source": "commit",
        "languages": ["Python"],
        "confidence": 0.85,
        "verified_by": "",
        "how_introduced": "",
        "verdict": "CONFIRMED",
        "bug_commits": [],
        "fix_commits": [],
        "references": [],
    }


def _publication_stats(entries: list[dict]) -> dict:
    count = len(entries)
    return {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "total_cves": count,
        "total_analyzed": max(1, count),
        "with_fix_commits": 0,
        "coverage_from": "2026-01-01",
        "coverage_to": "2026-06-01" if entries else "",
        "by_tool": {"cursor": count} if count else {},
        "by_severity": {"HIGH": count} if count else {},
        "by_language": {"Python": count} if count else {},
        "by_repo": {},
        "by_month": [
            {
                "month": "2026-06",
                "count": count,
                "by_tool": {"cursor": count},
            }
        ]
        if entries
        else [],
    }


def _schema3_remote_cutoff() -> dict:
    checked_at = "2026-07-18T12:00:00+00:00"
    return {
        "checked_at_utc": checked_at,
        "receipt_file": {
            "name": "source-remote-check-now.json",
            "path": "/tmp/source-remote-check-now.json",
            "sha256": "e" * 64,
            "size_bytes": 100,
        },
        "remote_parity": True,
        "receipt": {
            "schema_version": 3,
            "checked_at_utc": checked_at,
            "git_sources": [
                {
                    "branch": "main",
                    "head": "1" * 40,
                    "name": "cvelistV5",
                    "origin": "https://example.invalid/cvelist.git",
                    "path": "/tmp/sources/cvelist",
                    "remote_head": "1" * 40,
                    "tree": "2" * 40,
                }
            ],
            "nvd_feeds": [
                {
                    "feed_path": "/tmp/sources/nvd.json.gz",
                    "feed_sha256": "3" * 64,
                    "feed_size": 10,
                    "meta_path": "/tmp/sources/nvd.meta",
                    "meta_sha256": "2" * 64,
                    "remote_etag": '"etag"',
                    "remote_last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
                    "remote_meta_sha256": "2" * 64,
                    "year": 2026,
                }
            ],
            "osv_ecosystem_manifest": {
                "ecosystem_count": 1,
                "ecosystems": ["PyPI"],
                "etag": '"' + "0" * 32 + '"',
                "filename": "ecosystems.txt",
                "generation": "1784376000000000",
                "last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
                "md5_base64": "AAAAAAAAAAAAAAAAAAAAAA==",
                "path": "/tmp/sources/ecosystems.txt",
                "remote_size": 5,
                "sha256": "7" * 64,
                "size": 5,
                "url": (
                    "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt"
                ),
            },
            "osv_archive_count": 1,
            "osv_archives": [
                {
                    "crc32c_base64": "AAAAAA==",
                    "etag": '"' + "0" * 32 + '"',
                    "filename": "PyPI.zip",
                    "generation": "1784376000000000",
                    "last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
                    "md5_base64": "AAAAAAAAAAAAAAAAAAAAAA==",
                    "path": "/tmp/sources/PyPI.zip",
                    "remote_size": 1,
                    "sha256": "4" * 64,
                    "size": 1,
                    "url": (
                        "https://storage.googleapis.com/osv-vulnerabilities/"
                        "PyPI/all.zip"
                    ),
                }
            ],
            "remote_parity": True,
        },
    }


def _commit_minimal_verifier_scope(repo_root: Path) -> None:
    files = {
        "cve-analyzer/src/cve_analyzer/__init__.py": b'"""fixture"""\n',
        "cve-analyzer/pyproject.toml": b"[project]\nname='fixture'\nversion='0'\n",
        "cve-analyzer/uv.lock": b"version = 1\n",
        "web/scripts/verify.mjs": b"export const fixture = true;\n",
        "web/src/index.ts": b"export const fixture = true;\n",
        "web/package.json": b'{"name":"fixture","version":"0.0.0"}\n',
        "web/package-lock.json": b'{"lockfileVersion":3,"name":"fixture"}\n',
        "web/next.config.ts": b"export default {};\n",
    }
    for relative, content in files.items():
        path = repo_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "add",
            "--",
            *generator.verifier_contract_builder.TREE_SCOPES,
            *generator.verifier_contract_builder.FILE_SCOPES,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "-c",
            "user.name=Generate Release Fixture",
            "-c",
            "user.email=generate-release@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "Bind verifier fixture",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _source_snapshot(cutoff: dict) -> dict:
    return {
        "schema_version": 2,
        "git_mirrors": {
            "cvelist_v5": {
                "clean": True,
                "head": "1" * 40,
                "origin": "https://github.com/CVEProject/cvelistV5.git",
                "path": "/tmp/sources/cvelist",
                "tree": "2" * 40,
            },
            "gemnasium_advisories": {
                "clean": True,
                "head": "3" * 40,
                "origin": "https://gitlab.com/gitlab-org/advisories-community.git",
                "path": "/tmp/sources/gemnasium",
                "tree": "4" * 40,
            },
            "github_advisories": {
                "clean": True,
                "head": "5" * 40,
                "origin": "https://github.com/github/advisory-database.git",
                "path": "/tmp/sources/ghsa",
                "tree": "6" * 40,
            },
        },
        "nvd_feeds": [
            {
                "name": f"nvdcve-2.0-{year}.json.gz",
                "path": f"/tmp/sources/nvdcve-2.0-{year}.json.gz",
                "sha256": str(year)[-1] * 64,
                "size_bytes": 10,
            }
            for year in (2025, 2026)
        ],
        "osv_ecosystem_manifest": {
            "name": "ecosystems.txt",
            "path": "/tmp/sources/ecosystems.txt",
            "sha256": "7" * 64,
            "size_bytes": 5,
            "ecosystem_count": 1,
            "ecosystems": ["PyPI"],
            "archive_names": ["PyPI.zip"],
        },
        "osv_archives": [
            {
                "name": "PyPI.zip",
                "path": "/tmp/sources/PyPI.zip",
                "sha256": "4" * 64,
                "size_bytes": 1,
            }
        ],
        "remote_cutoff": cutoff,
    }


def _mock_release_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    curation_report: dict,
) -> tuple[SimpleNamespace, dict, Path, Path, dict, SimpleNamespace]:
    remote_cutoff = _schema3_remote_cutoff()
    source_snapshot = _source_snapshot(remote_cutoff)
    source_snapshot_sha256 = hashlib.sha256(
        json.dumps(
            source_snapshot,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    litellm_transport = {"schema_version": 1}
    litellm_transport_sha256 = hashlib.sha256(
        generator.refresh_runner._canonical_json_bytes(litellm_transport)
    ).hexdigest()
    contract_sha256 = "a" * 64
    analyzer_contract_sha256 = "e" * 64
    signature_sha256 = "f" * 64
    subject_ids = tuple(f"CVE-2026-{10_000 + index}" for index in range(59))
    alias_source_snapshot_sha256 = "d" * 64
    alias_classes: list[dict] = []
    class_id_by_subject: dict[str, str] = {}
    for subject_id in subject_ids:
        component_sha256 = hashlib.sha256(f"{subject_id}\n".encode()).hexdigest()
        class_id = f"alias-{component_sha256[:24]}"
        class_id_by_subject[subject_id] = class_id
        analysis_input = {
            "member_ids": [subject_id],
            "git_ranges": [],
            "fixed_events": [],
            "reference_urls": [],
        }
        alias_classes.append(
            {
                "class_id": class_id,
                "component_sha256": component_sha256,
                "all_member_ids": [subject_id],
                "eligible_seed_ids": [subject_id],
                "source_record_references": [],
                "merged_source_evidence_sha256": hashlib.sha256(
                    generator.refresh_runner._canonical_json_bytes(
                        {"records": [], "analysis_input": analysis_input}
                    )
                ).hexdigest(),
                "analysis_subject": subject_id,
                "analysis_input": analysis_input,
                "source_snapshot_sha256": alias_source_snapshot_sha256,
                "scheduled_seed_ids": [subject_id],
            }
        )
    alias_classes.sort(key=lambda item: item["class_id"])
    alias_class_manifest_sha256 = hashlib.sha256(
        generator.refresh_runner._canonical_json_bytes(alias_classes)
    ).hexdigest()
    alias_class_manifest = {
        "schema_version": 1,
        "source_snapshot_sha256": alias_source_snapshot_sha256,
        "class_count": len(alias_classes),
        "eligible_seed_id_count": len(subject_ids),
        "all_eligible_seed_ids_exactly_once": True,
        "classes_sha256": alias_class_manifest_sha256,
        "scheduled_class_count": len(subject_ids),
        "scheduled_analysis_subject_count": len(subject_ids),
        "scheduled_classes_exactly_once": True,
        "classes": alias_classes,
    }
    campaign_id = hashlib.sha256(
        generator.refresh_runner._canonical_json_bytes(
            {
                "schema_version": generator.refresh_runner.MARKER_SCHEMA_VERSION,
                "source_snapshot_sha256": source_snapshot_sha256,
                "contract_sha256": contract_sha256,
                "analyzer_contract_sha256": analyzer_contract_sha256,
                "signature_sha256": signature_sha256,
                "alias_class_manifest_sha256": alias_class_manifest_sha256,
                "screening_model": generator.refresh_runner.SCREENING_MODEL,
                "verification_model": generator.refresh_runner.VERIFY_MODEL,
                "screening_reasoning_effort": (
                    generator.refresh_runner.SCREENING_REASONING_EFFORT
                ),
                "verification_reasoning_effort": (
                    generator.refresh_runner.REASONING_EFFORT
                ),
                "workers": generator.refresh_runner.WORKERS,
                "no_token_child_processes": (
                    generator.refresh_runner.NO_TOKEN_CHILD_PROCESSES
                ),
                "no_token_total_workers": (
                    generator.refresh_runner.NO_TOKEN_TOTAL_WORKERS
                ),
                "screening_gates_verification": True,
                "result_cache_reads": True,
                "llm_cache_reads": False,
                "pipeline_phases": [
                    "no_token",
                    "screening",
                    "verification",
                    "aggregation_publication",
                ],
                "llm_plan_digest_approval_required": True,
                "litellm_transport_sha256": litellm_transport_sha256,
                "batch_timeout_seconds": (
                    generator.refresh_runner.BATCH_TIMEOUT_SECONDS
                ),
            }
        )
    ).hexdigest()
    state_dir = tmp_path / "refresh-runner-v1"
    marker_dir = state_dir / "completed"
    result_dir = state_dir.parent / "campaigns-v1" / campaign_id / "results"
    result_dir.mkdir(parents=True)
    result_hashes: dict[str, str] = {}
    for subject_id in subject_ids:
        result_path = result_dir / f"{subject_id}.json"
        _write_result(result_path, subject_id)
        result_hashes[subject_id] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    plan_subject_ids_sha256 = hashlib.sha256(
        ("\n".join(sorted(subject_ids)) + "\n").encode("utf-8")
    ).hexdigest()
    incremental_plan_proof = {
        "schema_version": 2,
        "scope": "formal_current_source_alias_class_plan",
        "campaign_mode": "formal",
        "population_policy": "formal_full",
        "formal_release_eligible": True,
        "source_delta_schema_version": (
            generator.refresh_runner.SOURCE_DELTA_SCHEMA_VERSION
        ),
        "source_delta_path": "source-delta-current.json",
        "source_delta_sha256": "1" * 64,
        "source_delta_integrity_payload_sha256": "2" * 64,
        "input_snapshot_sha256": "3" * 64,
        "result_cache_inventory_manifest_sha256": "4" * 64,
        "production_discovered_id_count": len(subject_ids),
        "cache_covered_discovered_id_count": 0,
        "uncached_discovered_id_count": len(subject_ids),
        "candidate_id_count": len(subject_ids),
        "candidate_sha256": "5" * 64,
        "plan_subject_id_count": len(subject_ids),
        "plan_subject_ids_sha256": plan_subject_ids_sha256,
        "alias_class_manifest_sha256": alias_class_manifest_sha256,
        "source_alias_class_count": len(alias_classes),
        "scheduled_alias_class_count": len(subject_ids),
        "plan_alias_classes_exactly_once": True,
        "analyzer_contract_sha256": analyzer_contract_sha256,
        "signature_sha256": signature_sha256,
        "candidate_union_exact": True,
        "plan_exactly_matches_candidate": True,
        "frozen_local_sources": True,
        "network_advisory_api_included": False,
        "historical_cache_suppresses_current_classes": False,
        "formal_current_epoch_stage_receipt_required": True,
        "boundary": "fixture formal alias-class campaign boundary",
    }
    batch_spec = generator.refresh_runner.BatchSpec(
        key="batch-001",
        path=tmp_path / "grouped-batches-v1/batch-001.txt",
        kind="fixture",
        ids=subject_ids,
        repos=frozenset(),
    )
    batch_spec.path.parent.mkdir(parents=True, exist_ok=True)
    batch = SimpleNamespace(
        key=batch_spec.key,
        path=batch_spec.path,
        ids=batch_spec.ids,
        command=tuple(
            generator.refresh_runner.build_command(batch_spec, phase="verification")
        ),
        class_ids=tuple(class_id_by_subject[item] for item in batch_spec.ids),
    )
    batch.path.write_text("\n".join(subject_ids) + "\n", encoding="utf-8")
    context = SimpleNamespace(
        campaign_id=campaign_id,
        repo_root=tmp_path,
        marker_dir=marker_dir,
        result_dir=result_dir,
        contract_sha256=contract_sha256,
        source_snapshot_sha256=source_snapshot_sha256,
        source_snapshot=source_snapshot,
        model="gpt-5.6-luna",
        reasoning_effort="max",
        workers=generator.refresh_runner.WORKERS,
        no_token_child_processes=(
            generator.refresh_runner.NO_TOKEN_CHILD_PROCESSES
        ),
        no_token_total_workers=(
            generator.refresh_runner.NO_TOKEN_TOTAL_WORKERS
        ),
        marker_schema_version=generator.refresh_runner.MARKER_SCHEMA_VERSION,
        litellm_transport_sha256=litellm_transport_sha256,
        litellm_transport=litellm_transport,
        batch_timeout_seconds=generator.refresh_runner.BATCH_TIMEOUT_SECONDS,
        incremental_plan_proof=incremental_plan_proof,
        campaign_mode="formal",
        population_policy="formal_full",
        analyzer_contract_sha256=analyzer_contract_sha256,
        signature_sha256=signature_sha256,
        alias_class_manifest_sha256=alias_class_manifest_sha256,
        alias_class_manifest=alias_class_manifest,
        batches=(batch,),
    )
    paths = SimpleNamespace(
        ghsa_dir=tmp_path / "ghsa",
        osv_bulk_dir=tmp_path / "osv",
        nvd_feeds_dir=tmp_path / "nvd",
        state_dir=state_dir,
    )
    marker_started_at_ns = 1_784_376_000_000_000_000
    marker_completed_at_ns = 1_784_376_001_000_000_000
    batch_sha256 = hashlib.sha256(batch.path.read_bytes()).hexdigest()
    command_sha256 = generator._canonical_sha256(list(batch.command))
    result_manifest_sha256 = generator._canonical_sha256(
        [
            {
                "subject_id": subject_id,
                "size_bytes": (result_dir / f"{subject_id}.json").stat().st_size,
                "sha256": result_hashes[subject_id],
            }
            for subject_id in sorted(subject_ids)
        ]
    )
    receipt_campaign = generator.refresh_runner.CampaignExecution(
        campaign_id=campaign_id,
        root=result_dir.parent,
        result_dir=result_dir,
        api_cache_dir=result_dir.parent / "api-responses",
        derived_cache_root=result_dir.parent / "derived-cache",
        source_snapshot_sha256=source_snapshot_sha256,
        contract_sha256=contract_sha256,
        litellm_transport_sha256=litellm_transport_sha256,
        litellm_transport=litellm_transport,
        analyzer_contract_sha256=analyzer_contract_sha256,
        signature_sha256=signature_sha256,
        alias_class_manifest_sha256=alias_class_manifest_sha256,
    )
    class_record_by_subject = {item["analysis_subject"]: item for item in alias_classes}
    class_receipts: list[dict] = []
    for subject_id in subject_ids:
        result_path = result_dir / f"{subject_id}.json"
        result_bytes = result_path.read_bytes()
        problem, class_receipt = generator.refresh_runner._analysis_stage_receipt_proof(
            json.loads(result_bytes),
            class_record=class_record_by_subject[subject_id],
            campaign=receipt_campaign,
            result_sha256=hashlib.sha256(result_bytes).hexdigest(),
        )
        assert problem is None
        assert class_receipt is not None
        class_receipts.append(class_receipt)
    class_receipts.sort(key=lambda item: item["class_id"])
    class_receipts_sha256 = hashlib.sha256(
        generator.refresh_runner._canonical_json_bytes(class_receipts)
    ).hexdigest()
    marker_payload = {
        "schema_version": generator.refresh_runner.MARKER_SCHEMA_VERSION,
        "batch": batch.key,
        "kind": "fixture",
        "batch_file": batch.path.relative_to(tmp_path).as_posix(),
        "batch_sha256": batch_sha256,
        "contract_sha256": context.contract_sha256,
        "analyzer_contract_sha256": context.analyzer_contract_sha256,
        "signature_sha256": context.signature_sha256,
        "alias_class_manifest_sha256": context.alias_class_manifest_sha256,
        "source_snapshot_sha256": context.source_snapshot_sha256,
        "source_snapshot": source_snapshot,
        "id_line_count": len(subject_ids),
        "unique_id_count": len(subject_ids),
        "command": list(batch.command),
        "reasoning_effort": context.reasoning_effort,
        "model": context.model,
        "workers": context.workers,
        "campaign_id": context.campaign_id,
        "campaign_result_dir": str(context.result_dir),
        "campaign_api_cache_dir": str(context.result_dir.parent / "api-responses"),
        "campaign_derived_cache_root": str(context.result_dir.parent / "derived-cache"),
        "litellm_transport_sha256": context.litellm_transport_sha256,
        "litellm_transport": context.litellm_transport,
        "batch_timeout_seconds": context.batch_timeout_seconds,
        "free_bytes_before": 10_000,
        "free_bytes_after": 9_000,
        "log_file": ".ai-slop/logs/data-refresh/batch-001.log",
        "started_at": "2026-07-18T12:00:00+00:00",
        "completed_at": "2026-07-18T12:00:01+00:00",
        "exit_code": 0,
        "result_validation": {
            "result_count": len(subject_ids),
            "terminal_count": len(subject_ids),
            "result_manifest_sha256": result_manifest_sha256,
            "class_receipt_count": len(class_receipts),
            "class_receipts_sha256": class_receipts_sha256,
            "class_receipts": class_receipts,
            "alias_classes_exactly_once": True,
        },
    }
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker_path = marker_dir / f"{batch.key}.json"
    marker_path.write_text(
        json.dumps(marker_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    marker_sha256 = hashlib.sha256(marker_path.read_bytes()).hexdigest()
    adjudications_path = tmp_path / "audit_adjudications.json"
    adjudications_payload = {
        "schema_version": 1,
        "adjudications": [
            {
                "cve_id": subject_ids[0],
                "label": "AI_CAUSAL",
                "aliases": [],
            }
        ],
    }
    adjudications_bytes = (
        json.dumps(adjudications_payload, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    adjudications_path.write_bytes(adjudications_bytes)
    adjudications_sha256 = hashlib.sha256(adjudications_bytes).hexdigest()
    corpus_manifest = [
        {
            "canonical_id": subject_ids[0],
            "label": "AI_CAUSAL",
            "subject_ids": [subject_ids[0]],
        }
    ]
    formal_results = tuple(
        CveAnalysisResult.from_dict(
            json.loads((result_dir / f"{subject_id}.json").read_text(encoding="utf-8"))
        )
        for subject_id in subject_ids
    )
    detector_inventory = _build_detector_inventory(
        formal_results,
        alias_map={},
        adjudicated_positive_ids={subject_ids[0]},
        audit_exclusions=set(),
        published_ids={subject_ids[0]},
        generated_at=remote_cutoff["checked_at_utc"],
        source_snapshot_sha256=source_snapshot_sha256,
        source_receipt_sha256=generator._canonical_sha256(remote_cutoff),
        campaign_id=campaign_id,
        contract_sha256=contract_sha256,
        campaign_mode="formal",
        coverage_to="2026-07-18",
        require_stage_receipts=True,
        alias_class_manifest=alias_class_manifest,
    )
    assert detector_inventory["complete"] is True
    recall_selection_digest = "b" * 64
    recall_selection = {
        "selection_manifest_sha256": recall_selection_digest,
        "inventory": {
            "inventory_id": detector_inventory["inventory_id"],
            "source_snapshot_sha256": detector_inventory["source_snapshot_sha256"],
            "campaign_id": detector_inventory["campaign_id"],
            "campaign_mode": "formal",
            "complete": True,
        },
    }
    recall_labels = {"selection_manifest_sha256": recall_selection_digest}
    recall_report = {
        "schema_version": 2,
        "evaluation_kind": "stratified_end_to_end_finite_population_recall",
        "selection_manifest_sha256": recall_selection_digest,
        "selection_replayed_from_inventory": True,
        "artifact_order": {"selection_commit": "1" * 40},
        "evaluation_complete": True,
        "evaluation_blockers": [],
        "resolved_labels": {"packet": "AI_CAUSAL"},
        "unresolved_packet_ids": [],
        "coverage_failure_count": 0,
        "protected_overlap_class_count": 0,
        "protected_census_manifest_sha256": "4" * 64,
        "protected_census_complete": True,
        "protected_census_resolved_labels": {},
        "protected_census_unresolved_packet_ids": [],
        "protected_excluded_class_count": 0,
        "covered_unprotected_diagnostic_complete": True,
        "recall": {
            "recall_point": 1.0,
            "recall_interval": [1.0, 1.0],
            "protected_census": {"class_count": 0},
        },
    }
    detector_report = {
        "evaluation_complete": True,
        "corpus_manifest": corpus_manifest,
        "corpus_manifest_sha256": generator._canonical_sha256(corpus_manifest),
        "input_provenance": {
            "adjudications": {
                "path": str(adjudications_path.resolve()),
                "sha256": adjudications_sha256,
            }
        },
        "detector_inventory": {
            "inventory_id": detector_inventory["inventory_id"],
            "source_snapshot_sha256": detector_inventory["source_snapshot_sha256"],
            "source_alias_class_manifest_sha256": detector_inventory[
                "source_alias_class_manifest_sha256"
            ],
            "campaign_id": detector_inventory["campaign_id"],
            "contract_sha256": detector_inventory["contract_sha256"],
            "campaign_mode": detector_inventory["campaign_mode"],
            "complete": detector_inventory["complete"],
            "alias_class_count": detector_inventory["alias_class_count"],
            "stage_metrics": {
                "screening": {"confusion_counts": {"tp": 1, "fp": 0, "fn": 0, "tn": 0}},
                "final_publication": {
                    "confusion_counts": {"tp": 1, "fp": 0, "fn": 0, "tn": 0}
                },
            },
            "stage_quality_gate": {
                "screening_zero_false_negatives": True,
                "final_precision_lower_bound_at_least_0_95": True,
                "final_recall_lower_bound_at_least_0_95": True,
                "passed": True,
            },
        },
        "fixed_contract_campaign_proof": {
            "complete": True,
            "campaign_mode": "formal",
            "population_policy": "formal_full",
            "formal_population_complete": True,
            "incremental_plan_complete": False,
            "full_incremental_plan_campaign_complete": False,
            "proof_scope": "formal_current_source_alias_class_plan",
            "population_uniform_luna_max_proof": False,
            "incremental_plan_proof": incremental_plan_proof,
            "required_subject_count": 1,
            "required_campaign_subject_count": 1,
            "mapped_subject_count": 1,
            "campaign_subject_count": len(subject_ids),
            "campaign_batch_count": 1,
            "completed_marker_count": 1,
            "relevant_marker_count": 1,
            "expected_contract": {
                "marker_schema_version": context.marker_schema_version,
                "campaign_id": context.campaign_id,
                "result_dir": str(context.result_dir),
                "contract_sha256": context.contract_sha256,
                "analyzer_contract_sha256": context.analyzer_contract_sha256,
                "signature_sha256": context.signature_sha256,
                "alias_class_manifest_sha256": (context.alias_class_manifest_sha256),
                "source_snapshot_sha256": context.source_snapshot_sha256,
                "model": context.model,
                "reasoning_effort": context.reasoning_effort,
                "workers": context.workers,
                "no_token_child_processes": (
                    context.no_token_child_processes
                ),
                "no_token_total_workers": context.no_token_total_workers,
                "litellm_transport_sha256": context.litellm_transport_sha256,
                "litellm_transport": context.litellm_transport,
                "batch_timeout_seconds": context.batch_timeout_seconds,
                "campaign_mode": context.campaign_mode,
                "population_policy": context.population_policy,
                "incremental_plan_proof": incremental_plan_proof,
            },
            "failure_counts": {},
            "failures": [],
            "marker_proofs": [
                {
                    "batch": batch.key,
                    "path": str(marker_path),
                    "marker_sha256": marker_sha256,
                    "batch_sha256": batch_sha256,
                    "command_sha256": command_sha256,
                    "result_manifest_sha256": result_manifest_sha256,
                    "class_receipts_sha256": class_receipts_sha256,
                    "started_at_ns": marker_started_at_ns,
                    "completed_at_ns": marker_completed_at_ns,
                }
            ],
            "subject_proofs": [
                {
                    "subject_id": subject_id,
                    "batch": batch.key,
                    "marker_sha256": marker_sha256,
                    "result_sha256": result_hashes[subject_id],
                    "result_mtime_ns": marker_started_at_ns + 500_000_000,
                    "marker_started_at_ns": marker_started_at_ns,
                    "marker_completed_at_ns": marker_completed_at_ns,
                    "terminal_validation": "passed",
                }
                for subject_id in subject_ids[:1]
            ],
        },
    }
    heldout_units = tuple(
        generator.heldout_quality.SelectionUnit(
            canonical_id=f"CVE-2026-{10_000 + index}",
            subject_ids=(f"CVE-2026-{10_000 + index}",),
            predicted_positive=True,
            candidate_positive=True,
            screening_positive=True,
            prediction_reasons=("included",),
            infrastructure_categories=(),
            unresolved_reasons=(),
            results=(
                generator.heldout_quality.ResultReference(
                    f"CVE-2026-{10_000 + index}",
                    result_hashes[f"CVE-2026-{10_000 + index}"],
                ),
            ),
        )
        for index in range(59)
    )
    heldout_unit_manifest = [
        {
            "canonical_id": unit.canonical_id,
            "subject_ids": list(unit.subject_ids),
            "results": [
                {"subject_id": result.subject_id, "sha256": result.sha256}
                for result in unit.results
            ],
        }
        for unit in heldout_units
    ]
    heldout_campaign = generator.heldout_quality.CampaignSnapshot(
        campaign_id=context.campaign_id,
        contract_sha256=context.contract_sha256,
        source_snapshot_sha256=context.source_snapshot_sha256,
        campaign_proof_sha256=generator._canonical_sha256(
            detector_report["fixed_contract_campaign_proof"]
        ),
        campaign_result_manifest_sha256=generator._canonical_sha256(
            heldout_unit_manifest
        ),
        proof_complete=True,
        units=heldout_units,
    )
    empty_digest = generator.heldout_quality.canonical_sha256([])
    protected = generator.heldout_quality.ProtectedInventory(
        subject_ids=frozenset(),
        source_roots=(),
        files=(),
        files_manifest_sha256=empty_digest,
        subject_ids_sha256=empty_digest,
    )
    selection = generator.heldout_quality.build_selection_manifest(
        heldout_campaign,
        protected,
        precision_sample_size=59,
        recall_sample_size=59,
        selection_code_sha256="9" * 64,
    )
    selection_relative = "scripts/heldout_studies/selection-fixture.json"
    labels_relative = "scripts/heldout_studies/labels-fixture.json"
    heldout_selection_path = tmp_path / selection_relative
    heldout_labels_path = tmp_path / labels_relative
    heldout_selection_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-q", str(tmp_path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    heldout_selection_path.write_bytes(
        generator.heldout_quality.canonical_artifact_bytes(selection)
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "--", selection_relative],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Generate Release Fixture",
            "-c",
            "user.email=generate-release@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "Seal held-out selection",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    selection_commit = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    selection_reference = f"{selection_commit}:{selection_relative}"
    labels = generator.heldout_quality.build_label_template(selection)
    labels["audit_protocol"] = {
        "selection_commit_reference": selection_reference,
        "audit_started_from_null_label_template": True,
        "reviewers_independent_from_detector_development": True,
        "reviewers_independent_from_each_other": True,
        "reviews_completed_without_access_to_other_review": True,
        "detector_predictions_hidden_from_reviewers": True,
        "sample_lane_membership_hidden_from_reviewers": True,
        "aggregate_quality_scores_hidden_until_resolution_complete": True,
        "all_disagreements_resolved_before_sealing": True,
    }
    for entry in labels["adjudications"]:
        evidence_refs = [f"https://evidence.invalid/{entry['sample_id']}"]
        entry["primary_review"] = {
            "reviewer_id": "independent-primary",
            "label": "AI_CAUSAL",
            "reviewed_at_utc": "2026-07-18T12:00:00+00:00",
            "evidence_refs": evidence_refs,
            "rationale": "Repository evidence establishes causal AI authorship.",
        }
        entry["secondary_review"] = {
            "reviewer_id": "independent-secondary",
            "label": "AI_CAUSAL",
            "reviewed_at_utc": "2026-07-18T12:01:00+00:00",
            "evidence_refs": evidence_refs,
            "rationale": "Independently verified causal AI authorship.",
        }
        entry["resolved_label"] = "AI_CAUSAL"
        entry["resolution"] = {
            "status": "agreed",
            "resolver_id": None,
            "resolved_at_utc": None,
            "evidence_refs": [],
            "rationale": "",
        }
    heldout_labels_path.write_bytes(
        generator.heldout_quality.canonical_artifact_bytes(labels)
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "--", labels_relative],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Generate Release Fixture",
            "-c",
            "user.email=generate-release@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "Seal independent labels",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    labels_commit = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    _commit_minimal_verifier_scope(tmp_path)
    quality = generator.heldout_quality.recompute_archived_quality_evidence(
        selection,
        labels,
        precision_target=0.95,
        recall_target=0.95,
        require_certified=True,
    )
    heldout_report = {
        "schema_version": 3,
        "evaluation_kind": "independent_heldout_fixed_campaign_detector_quality",
        "selection_manifest_sha256": selection["selection_manifest_sha256"],
        "campaign": selection["campaign"],
        "evaluation_complete": quality["evaluation_complete"],
        "targets": {
            "precision": 0.95,
            "recall": 0.95,
            "require_certified": True,
        },
        "precision": quality["precision"],
        "recall": quality["recall"],
        "stage_metrics": quality["stage_metrics"],
        "denominators": quality["denominators"],
        "strata": quality["strata"],
        "point_gate_passed": quality["point_gate_passed"],
        "certified_gate_passed": quality["certified_gate_passed"],
        "release_gate_passed": quality["release_gate_passed"],
        "measurement_boundary": selection["measurement_boundary"],
        "manual_evidence": {
            "label_file_sha256": generator._canonical_sha256(labels),
            "artifact_order": {
                "selection_commit_reference": selection_reference,
                "selection_commit": selection_commit,
                "selection_path": selection_relative,
                "labels_commit": labels_commit,
                "labels_path": labels_relative,
                "labels_blob_sha256": hashlib.sha256(
                    generator.heldout_quality.canonical_artifact_bytes(labels)
                ).hexdigest(),
                "selection_is_strict_ancestor": True,
                "labels_absent_from_selection_commit": True,
                "labels_exact_bytes_tracked_at_head": True,
            },
            "independent_audit_attested": True,
        },
    }
    entries = [_publication_entry(subject_ids[0])]
    publication_stats = _publication_stats(entries)
    publication_stats["inventory"] = generator._inventory_summary(detector_inventory)
    adjudications_path = tmp_path / "audit_adjudications.json"
    adjudications_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "adjudications": [
                    {
                        "cve_id": subject_ids[0],
                        "label": "AI_CAUSAL",
                        "aliases": [],
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    adjudication_corpus = generator.publication_quality.AdjudicationCorpus(
        (generator.publication_quality.AdjudicationEntry(subject_ids[0], "AI_CAUSAL"),)
    )
    if (
        curation_report.get("curation_consistent") is True
        and "counts" not in curation_report
    ):
        curation_report = generator.publication_quality.evaluate(
            {subject_ids[0]: "AI_CAUSAL"},
            {subject_ids[0]},
            precision_target=0.95,
            recall_target=0.95,
        )

    monkeypatch.setattr(generator, "_refresh_context", lambda: context)
    monkeypatch.setattr(generator, "_ADJUDICATIONS_PATH", adjudications_path)
    monkeypatch.setattr(
        generator,
        "_evaluate_heldout_quality_inputs",
        lambda **_kwargs: (selection, labels, heldout_report, heldout_campaign),
    )
    monkeypatch.setattr(
        generator,
        "_evaluate_recall_audit_inputs",
        lambda **_kwargs: (recall_selection, recall_labels, recall_report),
    )
    # The existing release fixture represents the future separately sealed
    # protected-class census. Dedicated recall replay tests exercise the real
    # validator; other release tests retain their original failure focus.
    monkeypatch.setattr(
        release_evidence,
        "_validate_recall_evidence",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        generator.refresh_runner,
        "RunnerPaths",
        SimpleNamespace(defaults=lambda _root: paths),
    )
    monkeypatch.setattr(generator, "_strict_build_alias_map", lambda *_args: {})
    monkeypatch.setattr(generator, "load_nvd_published_dates", lambda *_args: {})
    monkeypatch.setattr(generator, "load_ghsa_published_dates", lambda *_args: {})
    monkeypatch.setattr(generator, "load_ghsa_severities", lambda *_args: {})
    monkeypatch.setattr(
        generator,
        "_release_input_hashes",
        lambda: {"scripts/audit_adjudications.json": "e" * 64},
    )
    monkeypatch.setattr(
        generator,
        "_build_publication",
        lambda *_args, **_kwargs: BuiltPublication(
            entries=entries,
            stats=publication_stats,
            quarantine=QuarantineLog(),
            inventory=detector_inventory,
        ),
    )
    monkeypatch.setattr(
        generator.detector_quality,
        "build_report",
        lambda **_kwargs: detector_report,
    )
    monkeypatch.setattr(
        generator.publication_quality,
        "load_adjudications",
        lambda *_args, **_kwargs: adjudication_corpus,
    )
    monkeypatch.setattr(
        generator.publication_quality,
        "evaluate",
        lambda *_args, **_kwargs: curation_report,
    )
    return (
        context,
        detector_report,
        heldout_selection_path,
        heldout_labels_path,
        heldout_report,
        heldout_campaign,
    )


@pytest.mark.parametrize(
    "mutation",
    ["stale_campaign", "failed_certification", "infrastructure", "target_drift"],
)
def test_heldout_report_validator_fails_closed_on_incomplete_or_stale_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    context, _, _, _, report, campaign = _mock_release_dependencies(
        tmp_path,
        monkeypatch,
        curation_report={},
    )
    broken = json.loads(json.dumps(report))
    if mutation == "stale_campaign":
        broken["campaign"]["source_snapshot_sha256"] = "0" * 64
    elif mutation == "failed_certification":
        broken["certified_gate_passed"] = False
    elif mutation == "infrastructure":
        broken["denominators"]["infrastructure_error"] = 1
    else:
        broken["targets"]["precision"] = 0.96

    with pytest.raises(ReleaseGateError):
        generator._validate_heldout_quality_report(
            broken,
            context=context,
            campaign_snapshot=campaign,
            precision_target=0.95,
            recall_target=0.95,
        )


def test_formal_heldout_evaluation_runs_in_process_with_certification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection = {
        "protected_inputs": {"source_roots": []},
        "selection_policy": {
            "precision_sample_size": 59,
            "recall_sample_size": 59,
        },
    }
    labels = {"adjudications": []}
    report = {"release_gate_passed": True}
    campaign = SimpleNamespace(campaign_id="1" * 64)
    calls: list[dict] = []
    monkeypatch.setattr(
        generator,
        "_load_heldout_input",
        lambda _path, description: (
            selection if description == "held-out selection" else labels
        ),
    )
    monkeypatch.setattr(
        generator.heldout_quality,
        "validate_selection_seal",
        lambda _selection: "2" * 64,
    )
    monkeypatch.setattr(
        generator.heldout_quality,
        "_authoritative_protected_sources",
        lambda *_args: (),
    )
    monkeypatch.setattr(generator, "_heldout_campaign_snapshot", lambda _map: campaign)
    monkeypatch.setattr(
        generator.heldout_quality,
        "build_protected_inventory",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        generator.heldout_quality,
        "build_selection_manifest",
        lambda *_args, **_kwargs: selection,
    )
    monkeypatch.setattr(
        generator.heldout_quality,
        "_selection_code_sha256",
        lambda: "3" * 64,
    )
    monkeypatch.setattr(
        generator.heldout_quality,
        "evaluate_selection",
        lambda *_args, **kwargs: calls.append(kwargs) or report,
    )
    monkeypatch.setattr(
        generator,
        "_validate_heldout_quality_report",
        lambda *_args, **_kwargs: None,
    )

    _, _, actual, _ = generator._evaluate_heldout_quality_inputs(
        selection_path=tmp_path / "selection.json",
        labels_path=tmp_path / "labels.json",
        alias_map={},
        context=object(),
        precision_target=0.95,
        recall_target=0.95,
    )

    assert actual is report
    assert calls == [
        {
            "precision_target": 0.95,
            "recall_target": 0.95,
            "require_certified": True,
            "selection_path": tmp_path / "selection.json",
            "labels_path": tmp_path / "labels.json",
            "repo_root": generator._REPO_ROOT,
        }
    ]


def test_generate_release_holds_campaign_global_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    class RecordedLock:
        def __enter__(self) -> None:
            events.append("entered")

        def __exit__(self, *_args: object) -> None:
            events.append("exited")

    monkeypatch.setattr(
        generator.refresh_runner,
        "RunnerPaths",
        SimpleNamespace(
            defaults=lambda _root: SimpleNamespace(state_dir=tmp_path / "state")
        ),
    )
    monkeypatch.setattr(
        generator.refresh_runner,
        "batch_singleton_lock",
        lambda state_dir, key: events.append((state_dir, key)) or RecordedLock(),
    )
    monkeypatch.setattr(
        generator,
        "_generate_release_locked",
        lambda **_kwargs: events.append("generated") or ({}, {}, {}, {}),
    )

    result = generate_release(
        output_dir=tmp_path / "published",
        coverage_since="2025-05",
        precision_target=0.95,
        recall_target=0.95,
        heldout_selection_path=tmp_path / "selection.json",
        heldout_labels_path=tmp_path / "labels.json",
        recall_selection_path=tmp_path / "recall-selection.json",
        recall_labels_path=tmp_path / "recall-labels.json",
        recall_report_path=tmp_path / "recall-report.json",
    )

    assert result == ({}, {}, {}, {})
    assert events == [
        (tmp_path / "state", generator.refresh_runner.CAMPAIGN_LOCK_KEY),
        "entered",
        "generated",
        "exited",
    ]


def test_failed_quality_gate_preserves_the_live_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [_publication_entry("CVE-2025-1")]
    write_web_data(
        old_entries,
        _publication_stats(old_entries),
        output_dir,
        generated_at="2026-01-01T00:00:00+00:00",
        allow_unreceipted=True,
    )
    _, _, selection_path, labels_path, _, _ = _mock_release_dependencies(
        tmp_path,
        monkeypatch,
        curation_report={
            "schema_version": 2,
            "evaluation_kind": "publication_curation_consistency",
            "curation_consistent": False,
            "targets": {
                "curation_precision": 0.95,
                "curation_recall": 0.95,
            },
            "curation_precision": {"point": 1.0},
            "curation_recall": {"point": 1.0},
        },
    )

    with pytest.raises(ReleaseGateError, match="curation-consistency"):
        generate_release(
            output_dir=output_dir,
            coverage_since="2025-05",
            precision_target=0.95,
            recall_target=0.95,
            heldout_selection_path=selection_path,
            heldout_labels_path=labels_path,
            recall_selection_path=tmp_path / "recall-selection.json",
            recall_labels_path=tmp_path / "recall-labels.json",
            recall_report_path=tmp_path / "recall-report.json",
            trusted_repo_root=tmp_path,
        )

    assert _candidate_entries(load_published_web_data(output_dir)) == old_entries
    assert list(tmp_path.glob(".published.staging-*")) == []


def test_generate_release_rejects_campaign_declared_repository_as_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, selection_path, labels_path, _, _ = _mock_release_dependencies(
        tmp_path,
        monkeypatch,
        curation_report={},
    )

    with pytest.raises(ReleaseGateError, match="trusted release repository"):
        generate_release(
            output_dir=tmp_path / "published",
            coverage_since="2025-05",
            precision_target=0.95,
            recall_target=0.95,
            heldout_selection_path=selection_path,
            heldout_labels_path=labels_path,
            recall_selection_path=tmp_path / "recall-selection.json",
            recall_labels_path=tmp_path / "recall-labels.json",
            recall_report_path=tmp_path / "recall-report.json",
        )


def test_passing_quality_gate_receipts_and_promotes_the_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [_publication_entry("CVE-2025-10000")]
    write_web_data(
        old_entries,
        _publication_stats(old_entries),
        output_dir,
        generated_at="2026-01-01T00:00:00+00:00",
        allow_unreceipted=True,
    )
    context, _, selection_path, labels_path, _, _ = _mock_release_dependencies(
        tmp_path,
        monkeypatch,
        curation_report={
            "schema_version": 2,
            "evaluation_kind": "publication_curation_consistency",
            "curation_consistent": True,
            "targets": {
                "curation_precision": 0.95,
                "curation_recall": 0.95,
            },
            "curation_precision": {"point": 1.0},
            "curation_recall": {"point": 1.0},
        },
    )
    evaluation_calls: list[dict] = []
    evaluate_heldout = generator._evaluate_heldout_quality_inputs
    monkeypatch.setattr(
        generator,
        "_evaluate_heldout_quality_inputs",
        lambda **kwargs: evaluation_calls.append(kwargs) or evaluate_heldout(**kwargs),
    )

    receipt, _, _, _ = generate_release(
        output_dir=output_dir,
        coverage_since="2025-05",
        precision_target=0.95,
        recall_target=0.95,
        heldout_selection_path=selection_path,
        heldout_labels_path=labels_path,
        recall_selection_path=tmp_path / "recall-selection.json",
        recall_labels_path=tmp_path / "recall-labels.json",
        recall_report_path=tmp_path / "recall-report.json",
        trusted_repo_root=tmp_path,
    )

    assert receipt["campaign_id"] == context.campaign_id
    published = load_published_web_data(output_dir)
    assert receipt["generation_id"] == published.index["generation_id"]
    assert receipt["generated_at"] == published.index["generated_at"]
    assert receipt["evaluation_complete"] is True
    assert receipt["release_safe"] is True
    assert _candidate_entries(published) == [_publication_entry("CVE-2026-10000")]
    persisted_receipt = json.loads(
        (output_dir / "release-receipt.json").read_text(encoding="utf-8")
    )
    assert persisted_receipt == receipt
    evidence_dir = tmp_path / "release-evidence-v1" / receipt["generation_id"]
    assert {child.name for child in evidence_dir.iterdir()} == {
        "campaign-contract.json",
        "campaign-result-manifest.json",
        "campaign-results",
        "detector-inventory.json",
        "detector-report.json",
        "heldout-campaign-population.json",
        "heldout-labels.json",
        "heldout-quality-report.json",
        "heldout-selection.json",
        "manifest.json",
        "publication-manifest.json",
        "publication-curation-consistency-report.json",
        "publication-curation-inputs.json",
        "recall-selection.json",
        "recall-labels.json",
        "recall-report.json",
        "release-receipt.json",
        "source-remote-cutoff.json",
        "source-snapshot.json",
        "verifier-contract.json",
    }
    population = json.loads(
        (evidence_dir / "heldout-campaign-population.json").read_text(encoding="utf-8")
    )
    assert {path.name for path in (evidence_dir / "campaign-results").iterdir()} == {
        entry["file_name"] for entry in population["results"]
    }
    activation = (
        tmp_path
        / "release-evidence-v1"
        / "activations"
        / (f"{receipt['generation_id']}.json")
    )
    assert activation.is_file()
    assert len(evaluation_calls) == 5
    assert list(tmp_path.glob(".published.staging-*")) == []


def test_release_evidence_failure_blocks_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "published"
    _, _, selection_path, labels_path, _, _ = _mock_release_dependencies(
        tmp_path,
        monkeypatch,
        curation_report={
            "schema_version": 2,
            "evaluation_kind": "publication_curation_consistency",
            "curation_consistent": True,
            "targets": {
                "curation_precision": 0.95,
                "curation_recall": 0.95,
            },
            "curation_precision": {"point": 1.0},
            "curation_recall": {"point": 1.0},
        },
    )
    monkeypatch.setattr(
        generator,
        "archive_release_evidence",
        lambda **_kwargs: (_ for _ in ()).throw(
            generator.ReleaseEvidenceError("durability failure")
        ),
    )

    with pytest.raises(ReleaseGateError, match="archive failed validation"):
        generate_release(
            output_dir=output_dir,
            coverage_since="2025-05",
            precision_target=0.95,
            recall_target=0.95,
            heldout_selection_path=selection_path,
            heldout_labels_path=labels_path,
            recall_selection_path=tmp_path / "recall-selection.json",
            recall_labels_path=tmp_path / "recall-labels.json",
            recall_report_path=tmp_path / "recall-report.json",
            trusted_repo_root=tmp_path,
        )

    assert not output_dir.exists()
    assert list(tmp_path.glob(".published.staging-*")) == []
    assert not (tmp_path / "release-evidence-v1" / "activations").exists()


def test_activation_failure_before_durable_commit_rolls_back_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [_publication_entry("CVE-2025-10000")]
    write_web_data(
        old_entries,
        _publication_stats(old_entries),
        output_dir,
        generated_at="2026-01-01T00:00:00+00:00",
        allow_unreceipted=True,
    )
    previous_generation = load_published_web_data(output_dir).index["generation_id"]
    _, _, selection_path, labels_path, _, _ = _mock_release_dependencies(
        tmp_path,
        monkeypatch,
        curation_report={
            "schema_version": 2,
            "evaluation_kind": "publication_curation_consistency",
            "curation_consistent": True,
            "targets": {
                "curation_precision": 0.95,
                "curation_recall": 0.95,
            },
            "curation_precision": {"point": 1.0},
            "curation_recall": {"point": 1.0},
        },
    )
    monkeypatch.setattr(
        generator,
        "write_release_activation_record",
        lambda **_kwargs: (_ for _ in ()).throw(
            generator.ReleaseEvidenceError("simulated finalize failure")
        ),
    )

    with pytest.raises(ReleaseGateError, match="atomically rolled back"):
        generate_release(
            output_dir=output_dir,
            coverage_since="2025-05",
            precision_target=0.95,
            recall_target=0.95,
            heldout_selection_path=selection_path,
            heldout_labels_path=labels_path,
            recall_selection_path=tmp_path / "recall-selection.json",
            recall_labels_path=tmp_path / "recall-labels.json",
            recall_report_path=tmp_path / "recall-report.json",
            trusted_repo_root=tmp_path,
        )

    publication = load_published_web_data(output_dir)
    pending_records = list(
        (tmp_path / "release-evidence-v1" / "activations" / "pending").glob("*.json")
    )
    assert pending_records == []
    assert publication.index["generation_id"] == previous_generation
    assert _candidate_entries(publication) == [_publication_entry("CVE-2025-10000")]
    assert list(tmp_path.glob(".published.staging-*")) == []


def test_activation_failure_after_durable_commit_is_reconciled_to_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [_publication_entry("CVE-2025-10000")]
    write_web_data(
        old_entries,
        _publication_stats(old_entries),
        output_dir,
        generated_at="2026-01-01T00:00:00+00:00",
        allow_unreceipted=True,
    )
    _, _, selection_path, labels_path, _, _ = _mock_release_dependencies(
        tmp_path,
        monkeypatch,
        curation_report={
            "schema_version": 2,
            "evaluation_kind": "publication_curation_consistency",
            "curation_consistent": True,
            "targets": {
                "curation_precision": 0.95,
                "curation_recall": 0.95,
            },
            "curation_precision": {"point": 1.0},
            "curation_recall": {"point": 1.0},
        },
    )
    real_finalize = release_evidence._finalize_activation_payload
    finalize_calls = 0

    def fail_once_then_finalize(**kwargs: object) -> Path:
        nonlocal finalize_calls
        finalize_calls += 1
        if finalize_calls == 1:
            raise release_evidence.ReleaseEvidenceError(
                "simulated active-record failure"
            )
        return real_finalize(**kwargs)

    monkeypatch.setattr(
        release_evidence, "_finalize_activation_payload", fail_once_then_finalize
    )

    receipt, _, _, _ = generate_release(
        output_dir=output_dir,
        coverage_since="2025-05",
        precision_target=0.95,
        recall_target=0.95,
        heldout_selection_path=selection_path,
        heldout_labels_path=labels_path,
        recall_selection_path=tmp_path / "recall-selection.json",
        recall_labels_path=tmp_path / "recall-labels.json",
        recall_report_path=tmp_path / "recall-report.json",
        trusted_repo_root=tmp_path,
    )

    assert finalize_calls == 2
    assert (
        load_published_web_data(output_dir).index["generation_id"]
        == receipt["generation_id"]
    )
    activation = (
        tmp_path
        / "release-evidence-v1"
        / "activations"
        / f"{receipt['generation_id']}.json"
    )
    assert json.loads(activation.read_text(encoding="utf-8"))["state"] == "active"
    assert list(tmp_path.glob(".published.staging-*")) == []


def _interrupt_release_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path, str]:
    output_dir = tmp_path / "published"
    old_entries = [_publication_entry("CVE-2025-10000")]
    write_web_data(
        old_entries,
        _publication_stats(old_entries),
        output_dir,
        generated_at="2026-01-01T00:00:00+00:00",
        allow_unreceipted=True,
    )
    previous_generation = load_published_web_data(output_dir).index["generation_id"]
    _, _, selection_path, labels_path, _, _ = _mock_release_dependencies(
        tmp_path,
        monkeypatch,
        curation_report={
            "schema_version": 2,
            "evaluation_kind": "publication_curation_consistency",
            "curation_consistent": True,
            "targets": {
                "curation_precision": 0.95,
                "curation_recall": 0.95,
            },
            "curation_precision": {"point": 1.0},
            "curation_recall": {"point": 1.0},
        },
    )
    return output_dir, selection_path, labels_path, previous_generation


def test_keyboard_interrupt_before_durable_activation_commit_rolls_back_safely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir, selection_path, labels_path, previous_generation = (
        _interrupt_release_fixture(tmp_path, monkeypatch)
    )
    monkeypatch.setattr(
        release_evidence,
        "_persist_committed_activation_payload",
        lambda **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        generate_release(
            output_dir=output_dir,
            coverage_since="2025-05",
            precision_target=0.95,
            recall_target=0.95,
            heldout_selection_path=selection_path,
            heldout_labels_path=labels_path,
            recall_selection_path=tmp_path / "recall-selection.json",
            recall_labels_path=tmp_path / "recall-labels.json",
            recall_report_path=tmp_path / "recall-report.json",
            trusted_repo_root=tmp_path,
        )

    assert load_published_web_data(output_dir).index["generation_id"] == (
        previous_generation
    )
    assert list(tmp_path.glob(".published.staging-*")) == []
    assert (
        list(
            (tmp_path / "release-evidence-v1" / "activations" / "pending").glob(
                "*.json"
            )
        )
        == []
    )


def test_keyboard_interrupt_after_durable_commit_finalizes_active_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir, selection_path, labels_path, previous_generation = (
        _interrupt_release_fixture(tmp_path, monkeypatch)
    )
    real_finalize = release_evidence._finalize_activation_payload
    calls = 0

    def interrupt_once(**kwargs: object) -> Path:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt
        return real_finalize(**kwargs)

    monkeypatch.setattr(
        release_evidence, "_finalize_activation_payload", interrupt_once
    )

    with pytest.raises(KeyboardInterrupt):
        generate_release(
            output_dir=output_dir,
            coverage_since="2025-05",
            precision_target=0.95,
            recall_target=0.95,
            heldout_selection_path=selection_path,
            heldout_labels_path=labels_path,
            recall_selection_path=tmp_path / "recall-selection.json",
            recall_labels_path=tmp_path / "recall-labels.json",
            recall_report_path=tmp_path / "recall-report.json",
            trusted_repo_root=tmp_path,
        )

    active_generation = load_published_web_data(output_dir).index["generation_id"]
    assert calls == 2
    assert active_generation != previous_generation
    assert (
        tmp_path / "release-evidence-v1" / "activations" / f"{active_generation}.json"
    ).is_file()
    assert list(tmp_path.glob(".published.staging-*")) == []


def test_keyboard_interrupt_after_active_record_cleans_retained_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir, selection_path, labels_path, previous_generation = (
        _interrupt_release_fixture(tmp_path, monkeypatch)
    )
    real_write_activation = generator.write_release_activation_record

    def activate_then_interrupt(**kwargs: object) -> Path:
        real_write_activation(**kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr(
        generator, "write_release_activation_record", activate_then_interrupt
    )

    with pytest.raises(KeyboardInterrupt):
        generate_release(
            output_dir=output_dir,
            coverage_since="2025-05",
            precision_target=0.95,
            recall_target=0.95,
            heldout_selection_path=selection_path,
            heldout_labels_path=labels_path,
            recall_selection_path=tmp_path / "recall-selection.json",
            recall_labels_path=tmp_path / "recall-labels.json",
            recall_report_path=tmp_path / "recall-report.json",
            trusted_repo_root=tmp_path,
        )

    active_generation = load_published_web_data(output_dir).index["generation_id"]
    assert active_generation != previous_generation
    assert (
        tmp_path / "release-evidence-v1" / "activations" / f"{active_generation}.json"
    ).is_file()
    assert list(tmp_path.glob(".published.staging-*")) == []


def test_post_promotion_revalidation_failure_rolls_back_the_exchange(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [_publication_entry("CVE-2025-10000")]
    write_web_data(
        old_entries,
        _publication_stats(old_entries),
        output_dir,
        generated_at="2026-01-01T00:00:00+00:00",
        allow_unreceipted=True,
    )
    previous_generation = load_published_web_data(output_dir).index["generation_id"]
    context, _, selection_path, labels_path, _, _ = _mock_release_dependencies(
        tmp_path,
        monkeypatch,
        curation_report={
            "schema_version": 2,
            "evaluation_kind": "publication_curation_consistency",
            "curation_consistent": True,
            "targets": {
                "curation_precision": 0.95,
                "curation_recall": 0.95,
            },
            "curation_precision": {"point": 1.0},
            "curation_recall": {"point": 1.0},
        },
    )
    refresh_calls = 0

    def context_that_drifts_after_exchange() -> SimpleNamespace:
        nonlocal refresh_calls
        refresh_calls += 1
        if refresh_calls < 5:
            return context
        return SimpleNamespace(**{**vars(context), "campaign_id": "0" * 64})

    monkeypatch.setattr(
        generator, "_refresh_context", context_that_drifts_after_exchange
    )

    with pytest.raises(ReleaseGateError, match="changed after promotion"):
        generate_release(
            output_dir=output_dir,
            coverage_since="2025-05",
            precision_target=0.95,
            recall_target=0.95,
            heldout_selection_path=selection_path,
            heldout_labels_path=labels_path,
            recall_selection_path=tmp_path / "recall-selection.json",
            recall_labels_path=tmp_path / "recall-labels.json",
            recall_report_path=tmp_path / "recall-report.json",
            trusted_repo_root=tmp_path,
        )

    publication = load_published_web_data(output_dir)
    assert publication.index["generation_id"] == previous_generation
    assert _candidate_entries(publication) == old_entries
    assert list(tmp_path.glob(".published.staging-*")) == []
    assert (
        list(
            (tmp_path / "release-evidence-v1" / "activations" / "pending").glob(
                "*.json"
            )
        )
        == []
    )
