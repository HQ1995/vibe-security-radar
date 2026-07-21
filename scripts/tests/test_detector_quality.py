"""Tests for the cached-pipeline-snapshot quality evaluator."""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import evaluate_detector_quality as detector_quality


def _detector_inventory(rows: list[dict]) -> dict:
    normalized_rows: list[dict] = []
    for original in rows:
        row = dict(original)
        member_ids = sorted(row["member_ids"])
        row["member_ids"] = member_ids
        row["analysis_subject"] = row.get(
            "analysis_subject", row["result_subject_ids"][0]
        )
        row["component_sha256"] = hashlib.sha256(
            ("\n".join(member_ids) + "\n").encode("utf-8")
        ).hexdigest()
        row["source_evidence_sha256"] = detector_quality.canonical_sha256(
            {"class_id": row["class_id"], "member_ids": member_ids}
        )
        normalized_rows.append(row)
    dimensions = (
        "coverage_status",
        "detector_state",
        "adjudication_state",
        "publication_state",
        "recall_stratum",
    )
    payload = {
        "schema_version": 2,
        "kind": "ai_vulnerability_detector_inventory",
        "generated_at": "2026-07-19T00:00:00+00:00",
        "source_snapshot_sha256": "a" * 64,
        "source_receipt_sha256": "b" * 64,
        "source_alias_class_manifest_sha256": detector_quality.canonical_sha256(
            [
                {
                    "analysis_subject": row["analysis_subject"],
                    "class_id": row["class_id"],
                    "component_sha256": row["component_sha256"],
                    "member_ids": row["member_ids"],
                    "source_evidence_sha256": row["source_evidence_sha256"],
                }
                for row in normalized_rows
            ]
        ),
        "campaign_id": "c" * 64,
        "contract_sha256": "d" * 64,
        "campaign_mode": "formal",
        "complete": True,
        "coverage_to": "2026-07-19",
        "alias_class_count": len(normalized_rows),
        "detector_candidate_count": sum(
            row["detector_state"] in {"positive", "candidate"}
            for row in normalized_rows
        ),
        "pending_adjudication_count": sum(
            row["adjudication_state"] in {"unknown", "unreviewed"}
            for row in normalized_rows
        ),
        "coverage_failure_count": sum(
            row["coverage_status"] != "complete" for row in normalized_rows
        ),
        "counts": {
            dimension: dict(
                sorted(
                    {
                        value: sum(row[dimension] == value for row in normalized_rows)
                        for value in {row[dimension] for row in normalized_rows}
                    }.items()
                )
            )
            for dimension in dimensions
        },
        "rows": normalized_rows,
    }
    payload["inventory_id"] = detector_quality.canonical_sha256(payload)
    return payload


def test_detector_metrics_project_inventory_state_independently_from_publication() -> (
    None
):
    rows = [
        {
            "class_id": "CVE-2026-1",
            "member_ids": ["CVE-2026-1", "GHSA-aaaa-bbbb-cccc"],
            "result_subject_ids": ["CVE-2026-1"],
            "coverage_status": "complete",
            "detector_state": "positive",
            "adjudication_state": "ai_causal",
            "publication_state": "withheld",
            "recall_stratum": "detected_positive",
            "reasons": [],
        },
        {
            "class_id": "CVE-2026-2",
            "member_ids": ["CVE-2026-2"],
            "result_subject_ids": ["CVE-2026-2"],
            "coverage_status": "complete",
            "detector_state": "negative",
            "adjudication_state": "not_ai_causal",
            "publication_state": "not_applicable",
            "recall_stratum": "fix_no_bic",
            "reasons": [],
        },
    ]
    corpus = (
        detector_quality.CorpusEntry(
            canonical_id="CVE-2026-1",
            label="AI_CAUSAL",
            subject_ids=("CVE-2026-1", "GHSA-aaaa-bbbb-cccc"),
        ),
        detector_quality.CorpusEntry(
            canonical_id="CVE-2026-2",
            label="NOT_AI_CAUSAL",
            subject_ids=("CVE-2026-2",),
        ),
    )

    manifest = detector_quality._inventory_prediction_manifest(
        corpus, _detector_inventory(rows)
    )
    metrics = detector_quality._metrics(
        manifest,
        prediction_key="inventory_detector_prediction",
        outcome_key="inventory_detector_outcome",
    )

    assert metrics["confusion_counts"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 1}
    assert [row["inventory_class_id"] for row in manifest] == [
        "CVE-2026-1",
        "CVE-2026-2",
    ]


def _write_adjudications(path: Path, entries: list[dict]) -> None:
    path.write_text(
        json.dumps({"schema_version": 1, "adjudications": entries}),
        encoding="utf-8",
    )


def _raw_result(
    cve_id: str,
    *,
    positive: bool = False,
    fallback: bool = False,
    error: str = "",
    error_category: str = "",
) -> dict:
    result: dict = {
        "cve_id": cve_id,
        "description": "fixture",
        "fix_commits": [],
        "bug_introducing_commits": [],
        "error": error,
        "error_category": error_category,
        "repo_ai_activity": [],
    }
    if positive:
        verification = {
            "verdict": "CONFIRMED",
            "reasoning": "fixture verdict",
            "model": "gpt-5.6-luna",
            "reasoning_effort": "max",
            "ai_signal_attested": True,
            "ai_signal_source": "claude_code",
            "evidence": [],
        }
        if fallback:
            verification["is_fallback"] = True
            verification.pop("ai_signal_attested")
            verification.pop("ai_signal_source")
        result["bug_introducing_commits"] = [
            {
                "commit": {
                    "sha": "1" * 40,
                    "author_name": "Fixture",
                    "author_email": "fixture@example.com",
                    "committer_name": "Fixture",
                    "committer_email": "fixture@example.com",
                    "message": "Co-Authored-By: Claude <noreply@anthropic.com>",
                    "authored_date": "2026-01-01T00:00:00Z",
                    "ai_signals": [
                        {
                            "tool": "claude_code",
                            "signal_type": "co_author_trailer",
                            "matched_text": "Co-Authored-By: Claude",
                            "confidence": 0.95,
                        }
                    ],
                },
                "fix_commit_sha": "2" * 40,
                "blamed_file": "src/fixture.py",
                "blamed_lines": [1],
                "repository_identity": "https://github.com/example/fixture",
                "blame_confidence": 1.0,
                "blame_strategy": "blame_deleted",
                "deep_verification": verification,
            }
        ]
        scope_subject = "\0".join(
            (
                "github.com/example/fixture",
                "2" * 40,
                "1" * 40,
                "src/fixture.py",
            )
        )
        result.update(
            {
                "ai_involved": True,
                "ai_contribution": "fixture contribution",
                "investigation_scope_hash": hashlib.sha256(
                    scope_subject.encode()
                ).hexdigest(),
                "screening": {
                    "worth_investigating": True,
                    "reasoning": "fixture screening",
                    "relevant_commits": ["1" * 40],
                    "model": "gpt-5.6-luna",
                },
            }
        )
    return result


def _write_result(cache_dir: Path, cve_id: str, payload: dict | None = None) -> Path:
    path = cache_dir / f"{cve_id}.json"
    path.write_text(json.dumps(payload or _raw_result(cve_id)), encoding="utf-8")
    return path


def _source_snapshot(details: dict | None = None) -> tuple[dict, str]:
    source_details = details or {"schema_version": 1, "fixture": "source"}
    return source_details, detector_quality._runner_source_snapshot_sha256(
        source_details
    )


def _fixed_campaign_fixture(
    tmp_path: Path,
    cache_dir: Path,
    subject_ids: tuple[str, ...],
    *,
    alias_members: dict[str, tuple[str, ...]] | None = None,
) -> tuple[detector_quality.FixedCampaignProofContext, Path, dict]:
    repo_root = tmp_path / "repo"
    batch_dir = repo_root / "batches"
    marker_dir = repo_root / "state" / "completed"
    batch_dir.mkdir(parents=True)
    marker_dir.mkdir(parents=True)
    batch_path = batch_dir / "batch-001.txt"
    batch_path.write_text("\n".join(subject_ids) + "\n", encoding="utf-8")
    command = tuple(
        detector_quality.refresh_runner.build_command(
            detector_quality.refresh_runner.BatchSpec(
                key="grouped-001",
                path=batch_path,
                kind="fixed_contract_fixture",
                ids=subject_ids,
                repos=frozenset(),
            )
        )
    )
    all_members_by_subject = {
        subject_id: tuple(sorted((alias_members or {}).get(subject_id, (subject_id,))))
        for subject_id in subject_ids
    }
    class_records: list[dict] = []
    class_id_by_subject: dict[str, str] = {}
    for subject_id, member_ids in all_members_by_subject.items():
        component_sha256 = hashlib.sha256(
            ("\n".join(member_ids) + "\n").encode("utf-8")
        ).hexdigest()
        analysis_input = {
            "member_ids": list(member_ids),
            "git_ranges": [],
            "fixed_events": [],
            "reference_urls": [],
        }
        source_records = [
            {
                "source": "fixture",
                "record_id": member_id,
                "record_sha256": hashlib.sha256(member_id.encode()).hexdigest(),
                "reference": f"fixture:{member_id}",
            }
            for member_id in member_ids
        ]
        class_id = f"alias-{component_sha256[:24]}"
        class_id_by_subject[subject_id] = class_id
        class_records.append(
            {
                "class_id": class_id,
                "component_sha256": component_sha256,
                "all_member_ids": list(member_ids),
                "eligible_seed_ids": list(member_ids),
                "source_record_references": source_records,
                "merged_source_evidence_sha256": hashlib.sha256(
                    detector_quality.refresh_runner._canonical_json_bytes(
                        {"records": source_records, "analysis_input": analysis_input}
                    )
                ).hexdigest(),
                "analysis_subject": subject_id,
                "analysis_input": analysis_input,
                "source_snapshot_sha256": "9" * 64,
                "scheduled_seed_ids": list(member_ids),
            }
        )
    class_records.sort(key=lambda item: item["class_id"])
    alias_manifest_sha256 = hashlib.sha256(
        detector_quality.refresh_runner._canonical_json_bytes(class_records)
    ).hexdigest()
    alias_manifest = {
        "schema_version": 1,
        "source_snapshot_sha256": "9" * 64,
        "class_count": len(class_records),
        "eligible_seed_id_count": sum(
            len(members) for members in all_members_by_subject.values()
        ),
        "all_eligible_seed_ids_exactly_once": True,
        "classes_sha256": alias_manifest_sha256,
        "scheduled_class_count": len(class_records),
        "scheduled_analysis_subject_count": len(subject_ids),
        "scheduled_classes_exactly_once": True,
        "classes": class_records,
    }
    batch = detector_quality.FixedCampaignBatch(
        key="grouped-001",
        path=batch_path,
        ids=subject_ids,
        command=command,
        class_ids=tuple(class_id_by_subject[subject_id] for subject_id in subject_ids),
    )
    source_details, source_sha256 = _source_snapshot()
    campaign_id = hashlib.sha256(b"fixture-campaign").hexdigest()
    result_dir = repo_root / "campaigns-v1" / campaign_id / "results"
    result_dir.mkdir(parents=True)
    context = detector_quality.FixedCampaignProofContext(
        repo_root=repo_root,
        marker_dir=marker_dir,
        marker_schema_version=detector_quality.refresh_runner.MARKER_SCHEMA_VERSION,
        batches=(batch,),
        contract_sha256="a" * 64,
        source_snapshot_sha256=source_sha256,
        source_snapshot=source_details,
        model="gpt-5.6-luna",
        reasoning_effort="max",
        workers=32,
        campaign_id=campaign_id,
        result_dir=result_dir,
        litellm_transport_sha256="c" * 64,
        litellm_transport={
            "schema_version": 1,
            "api_base_sha256": "d" * 64,
            "base_env_vars": ["LITELLM_API_BASE"],
            "key_env_vars": ["LITELLM_API_KEY"],
            "api_modes": ["responses"],
            "api_key_configured": True,
        },
        batch_timeout_seconds=12 * 60 * 60,
        incremental_plan_proof={
            "schema_version": 2,
            "scope": "formal_current_source_alias_class_plan",
            "campaign_mode": "formal",
            "population_policy": "formal_full",
            "formal_release_eligible": True,
            "source_delta_schema_version": (
                detector_quality.refresh_runner.SOURCE_DELTA_SCHEMA_VERSION
            ),
            "source_delta_path": "source-delta-current.json",
            "source_delta_sha256": "1" * 64,
            "source_delta_integrity_payload_sha256": "2" * 64,
            "input_snapshot_sha256": "3" * 64,
            "result_cache_inventory_manifest_sha256": "4" * 64,
            "production_discovered_id_count": sum(
                len(members) for members in all_members_by_subject.values()
            ),
            "cache_covered_discovered_id_count": 0,
            "uncached_discovered_id_count": sum(
                len(members) for members in all_members_by_subject.values()
            ),
            "candidate_id_count": len(subject_ids),
            "candidate_sha256": "5" * 64,
            "plan_subject_id_count": len(subject_ids),
            "plan_subject_ids_sha256": hashlib.sha256(
                ("\n".join(sorted(subject_ids)) + "\n").encode()
            ).hexdigest(),
            "alias_class_manifest_sha256": alias_manifest_sha256,
            "source_alias_class_count": len(class_records),
            "scheduled_alias_class_count": len(class_records),
            "plan_alias_classes_exactly_once": True,
            "analyzer_contract_sha256": "e" * 64,
            "signature_sha256": "f" * 64,
            "candidate_union_exact": True,
            "plan_exactly_matches_candidate": True,
            "frozen_local_sources": True,
            "network_advisory_api_included": False,
            "historical_cache_suppresses_current_classes": False,
            "formal_current_epoch_stage_receipt_required": True,
            "boundary": "fixture formal alias-class campaign boundary",
        },
        campaign_mode="formal",
        population_policy="formal_full",
        analyzer_contract_sha256="e" * 64,
        signature_sha256="f" * 64,
        alias_class_manifest_sha256=alias_manifest_sha256,
        alias_class_manifest=alias_manifest,
    )
    started_at = datetime.now(UTC) - timedelta(seconds=2)
    receipt_completed_at = started_at + timedelta(seconds=2)
    completed_at = started_at + timedelta(seconds=4)
    midpoint_ns = int((started_at + timedelta(seconds=2)).timestamp() * 1_000_000_000)
    result_manifest: list[dict] = []
    for subject_id in subject_ids:
        source_path = cache_dir / f"{subject_id}.json"
        if not source_path.is_file():
            continue
        payload = json.loads(source_path.read_text(encoding="utf-8"))
        has_ai = bool(payload.get("bug_introducing_commits"))
        if has_ai:
            payload["analysis_stage_receipts"] = {
                stage: {"outcome": "resolved"}
                for stage in (
                    "source_discovery",
                    "fix_resolution",
                    "bic_resolution",
                    "signal_classification",
                    "causal_verification",
                    "adjudication",
                )
            }
        else:
            payload["error_category"] = "no_fix_commits"
            payload["analysis_stage_receipts"] = {
                "source_discovery": {"outcome": "resolved"},
                "fix_resolution": {
                    "outcome": "exhausted_no_match",
                    "configured_methods": ["fixture_source_evidence"],
                    "methods": [
                        {
                            "method": "fixture_source_evidence",
                            "outcome": "exhausted_no_match",
                            "input_sha256": "6" * 64,
                            "output_sha256": "7" * 64,
                        }
                    ],
                },
                "bic_resolution": {"outcome": "not_applicable"},
                "signal_classification": {"outcome": "not_applicable"},
                "causal_verification": {"outcome": "not_applicable"},
                "adjudication": {"outcome": "not_applicable"},
            }
        payload["campaign_receipt"] = {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "batch": batch.key,
            "started_at": started_at.isoformat(),
            "completed_at": receipt_completed_at.isoformat(),
            "source_snapshot_sha256": source_sha256,
            "contract_sha256": context.contract_sha256,
            "litellm_transport_sha256": context.litellm_transport_sha256,
            "requested_model": "gpt-5.6-luna",
            "reasoning_effort": "max",
            "llm_cache_disabled": True,
            "stages": {
                "phase_c_screening": (
                    {"status": "success", "actual_model": "gpt-5.6-luna"}
                    if has_ai
                    else {"status": "not_applicable"}
                ),
                "phase_d_deep_verification": (
                    {
                        "status": "success",
                        "actual_models": ["gpt-5.6-luna"],
                        "actual_reasoning_efforts": ["max"],
                    }
                    if has_ai
                    else {"status": "not_applicable"}
                ),
            },
            "status": "success",
            "failed_stages": [],
        }
        result_path = result_dir / f"{subject_id}.json"
        content = json.dumps(payload).encode()
        result_path.write_bytes(content)
        os.utime(result_path, ns=(midpoint_ns, midpoint_ns))
        result_manifest.append(
            {
                "subject_id": subject_id,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    result_manifest.sort(key=lambda item: item["subject_id"])
    receipt_campaign = detector_quality.refresh_runner.CampaignExecution(
        campaign_id=context.campaign_id,
        root=result_dir.parent,
        result_dir=result_dir,
        api_cache_dir=result_dir.parent / "api-responses",
        derived_cache_root=result_dir.parent / "derived-cache",
        source_snapshot_sha256=context.source_snapshot_sha256,
        contract_sha256=context.contract_sha256,
        litellm_transport_sha256=context.litellm_transport_sha256,
        litellm_transport=context.litellm_transport,
        analyzer_contract_sha256=context.analyzer_contract_sha256,
        signature_sha256=context.signature_sha256,
        alias_class_manifest_sha256=context.alias_class_manifest_sha256,
    )
    class_records_by_subject = {
        item["analysis_subject"]: item for item in class_records
    }
    class_receipts: list[dict] = []
    for entry in result_manifest:
        subject_id = entry["subject_id"]
        payload = json.loads(
            (result_dir / f"{subject_id}.json").read_text(encoding="utf-8")
        )
        problem, receipt = (
            detector_quality.refresh_runner._analysis_stage_receipt_proof(
                payload,
                class_record=class_records_by_subject[subject_id],
                campaign=receipt_campaign,
                result_sha256=entry["sha256"],
            )
        )
        assert problem is None
        assert receipt is not None
        class_receipts.append(receipt)
    class_receipts.sort(key=lambda item: item["class_id"])
    class_receipts_sha256 = hashlib.sha256(
        detector_quality.refresh_runner._canonical_json_bytes(class_receipts)
    ).hexdigest()
    marker = {
        "schema_version": detector_quality.refresh_runner.MARKER_SCHEMA_VERSION,
        "batch": batch.key,
        "kind": "fixture",
        "batch_file": batch_path.relative_to(repo_root).as_posix(),
        "batch_sha256": detector_quality._file_sha256(batch_path),
        "contract_sha256": context.contract_sha256,
        "analyzer_contract_sha256": context.analyzer_contract_sha256,
        "signature_sha256": context.signature_sha256,
        "alias_class_manifest_sha256": context.alias_class_manifest_sha256,
        "source_snapshot_sha256": source_sha256,
        "source_snapshot": source_details,
        "id_line_count": len(subject_ids),
        "unique_id_count": len(set(subject_ids)),
        "command": list(command),
        "reasoning_effort": "max",
        "model": "gpt-5.6-luna",
        "workers": 32,
        "campaign_id": campaign_id,
        "campaign_result_dir": str(result_dir),
        "campaign_api_cache_dir": str(result_dir.parent / "api-responses"),
        "campaign_derived_cache_root": str(result_dir.parent / "derived-cache"),
        "litellm_transport_sha256": context.litellm_transport_sha256,
        "litellm_transport": context.litellm_transport,
        "batch_timeout_seconds": context.batch_timeout_seconds,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "exit_code": 0,
        "result_validation": {
            "result_count": len(set(subject_ids)),
            "terminal_count": len(set(subject_ids)),
            "result_manifest_sha256": detector_quality._runner_result_manifest_sha256(
                result_manifest
            ),
            "class_receipt_count": len(class_receipts),
            "class_receipts_sha256": class_receipts_sha256,
            "class_receipts": class_receipts,
            "alias_classes_exactly_once": True,
        },
    }
    marker_path = marker_dir / f"{batch.key}.json"
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    return context, marker_path, marker


def test_cached_pipeline_snapshot_and_curated_publication_are_separate_alias_class_metrics(
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [
            {"cve_id": "POS-RAW", "aliases": ["ALIAS-POS"], "label": "AI_CAUSAL"},
            {"cve_id": "POS-CURATED", "label": "AI_CAUSAL"},
            {"cve_id": "NEG-CURATED", "label": "NOT_AI_CAUSAL"},
            {"cve_id": "NEG-RAW", "label": "NOT_AI_CAUSAL"},
            {"cve_id": "REVIEW", "label": "INCONCLUSIVE"},
        ],
    )
    _write_result(cache_dir, "POS-RAW", _raw_result("POS-RAW", positive=True))
    _write_result(cache_dir, "ALIAS-POS", _raw_result("ALIAS-POS"))
    _write_result(cache_dir, "POS-CURATED", _raw_result("POS-CURATED"))
    _write_result(cache_dir, "NEG-CURATED", _raw_result("NEG-CURATED", positive=True))
    _write_result(cache_dir, "NEG-RAW", _raw_result("NEG-RAW"))
    _write_result(cache_dir, "REVIEW", _raw_result("REVIEW", positive=True))

    alias_group = {"POS-RAW", "ALIAS-POS"}
    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={subject_id: alias_group for subject_id in alias_group},
        published_ids={"ALIAS-POS", "POS-CURATED"},
        publication_provenance={"fixture": True},
    )

    assert report["cached_pipeline_snapshot_metrics"]["confusion_counts"] == {
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "tn": 1,
    }
    assert report["cached_pipeline_snapshot_metrics"]["precision"] == 0.5
    assert report["cached_pipeline_snapshot_metrics"]["recall"] == 0.5
    assert math.isclose(
        report["cached_pipeline_snapshot_metrics"][
            "precision_one_sided_95pct_lower_bound"
        ],
        0.02532056551910361,
        rel_tol=0,
        abs_tol=1e-12,
    )
    assert math.isclose(
        report["cached_pipeline_snapshot_metrics"][
            "recall_one_sided_95pct_lower_bound"
        ],
        0.02532056551910361,
        rel_tol=0,
        abs_tol=1e-12,
    )
    assert report["curated_publication_metrics"]["confusion_counts"] == {
        "tp": 2,
        "fp": 0,
        "fn": 0,
        "tn": 2,
    }
    assert report["curated_publication_metrics"]["precision"] == 1.0
    assert report["curated_publication_metrics"]["recall"] == 1.0
    assert [row["canonical_id"] for row in report["corpus_manifest"]] == [
        "NEG-CURATED",
        "NEG-RAW",
        "POS-CURATED",
        "POS-RAW",
        "REVIEW",
    ]
    assert len(report["prediction_manifest"]) == 5
    pos_raw = next(
        row for row in report["prediction_manifest"] if row["canonical_id"] == "POS-RAW"
    )
    assert pos_raw["subject_ids"] == ["ALIAS-POS", "POS-RAW"]
    assert pos_raw["cached_pipeline_snapshot_prediction"] == "positive"
    assert pos_raw["alias_prediction_disagreement"] is True
    assert report["strata"]["adjudication_inconclusive"]["ids"] == ["REVIEW"]
    assert report["corpus_manifest_sha256"] == detector_quality.canonical_sha256(
        report["corpus_manifest"]
    )
    assert report["prediction_manifest_sha256"] == detector_quality.canonical_sha256(
        report["prediction_manifest"]
    )
    assert report["selection_bias"]["probability_sample"] is False
    assert "cached_pipeline_snapshot_metrics" in report["interpretation"]
    assert "curated_publication_metrics" in report["interpretation"]
    assert (
        report["methodology"]["result_kind"] == "mixed_version_cached_pipeline_results"
    )
    assert report["methodology"]["signature_replay"] is False
    assert report["fixed_contract_campaign_proof"]["complete"] is False
    assert report["fixed_contract_campaign_proof"]["failures"] == [
        {"code": "campaign_proof_not_configured"}
    ]
    assert "raw_detector_metrics" not in report
    assert "raw_detector_prediction" not in pos_raw


def test_code_provenance_covers_signature_and_pipeline_projection() -> None:
    paths = {entry["path"] for entry in detector_quality._code_provenance()["files"]}

    assert "cve-analyzer/src/cve_analyzer/ai_signatures.py" in paths
    assert "cve-analyzer/src/cve_analyzer/pipeline.py" in paths
    assert "cve-analyzer/src/cve_analyzer/pr_enrichment.py" in paths
    assert "cve-analyzer/src/cve_analyzer/verifier/coding_agent.py" in paths
    assert "scripts/run_data_refresh.py" in paths


def test_complete_runner_proof_promotes_fixed_contract_campaign_metrics(
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [
            {
                "cve_id": "CVE-FIXED",
                "aliases": ["GHSA-fixed"],
                "label": "AI_CAUSAL",
            }
        ],
    )
    _write_result(cache_dir, "CVE-FIXED", _raw_result("CVE-FIXED", positive=True))
    _write_result(cache_dir, "GHSA-fixed", _raw_result("GHSA-fixed"))
    context, _, _ = _fixed_campaign_fixture(
        tmp_path,
        cache_dir,
        ("CVE-FIXED",),
        alias_members={"CVE-FIXED": ("CVE-FIXED", "GHSA-fixed")},
    )
    aliases = {"CVE-FIXED", "GHSA-fixed"}

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={subject_id: aliases for subject_id in aliases},
        published_ids={"CVE-FIXED"},
        publication_provenance={"fixture": True},
        fixed_campaign_context=context,
    )

    assert report["evaluation_kind"] == (
        "frozen_adjudication_fixed_contract_campaign_vs_curated_publication"
    )
    assert report["evaluation_complete"] is True
    assert report["fixed_contract_campaign_proof"]["complete"] is True
    assert report["fixed_contract_campaign_proof"]["failures"] == []
    assert report["code_provenance"]["generation_contract_status"] == (
        "fixed_current_contract"
    )
    assert report["methodology"]["signature_generation"] == "fixed_runner_contract"
    assert report["fixed_contract_campaign_metrics"]["confusion_counts"]["tp"] == 1
    assert "cached_pipeline_snapshot_metrics" not in report
    row = report["prediction_manifest"][0]
    assert row["fixed_contract_campaign_prediction"] == "positive"
    assert "cached_pipeline_snapshot_prediction" not in row
    proofs = report["fixed_contract_campaign_proof"]["subject_proofs"]
    assert [proof["subject_id"] for proof in proofs] == ["CVE-FIXED"]
    assert all(len(proof["result_sha256"]) == 64 for proof in proofs)
    assert all(isinstance(proof["result_mtime_ns"], int) for proof in proofs)
    assert all(
        proof["marker_started_at_ns"]
        <= proof["result_mtime_ns"]
        <= proof["marker_completed_at_ns"]
        for proof in proofs
    )
    marker_proof = report["fixed_contract_campaign_proof"]["marker_proofs"][0]
    assert marker_proof["batch"] == "grouped-001"
    assert len(marker_proof["marker_sha256"]) == 64
    assert len(marker_proof["batch_sha256"]) == 64
    assert len(marker_proof["command_sha256"]) == 64
    assert report["selection_bias"]["status"] == "known_selection_bias"


def test_fixed_campaign_metrics_read_content_addressed_staged_results(
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "canonical-results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-STAGED", "label": "AI_CAUSAL"}],
    )
    _write_result(cache_dir, "CVE-STAGED", _raw_result("CVE-STAGED"))
    context, _, _ = _fixed_campaign_fixture(
        tmp_path,
        cache_dir,
        ("CVE-STAGED",),
    )
    # Drift the canonical cache after the immutable campaign snapshot is built.
    _write_result(
        cache_dir,
        "CVE-STAGED",
        _raw_result("CVE-STAGED", positive=True),
    )

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids=set(),
        publication_provenance={"fixture": True},
        fixed_campaign_context=context,
    )

    assert report["fixed_contract_campaign_proof"]["complete"] is True
    assert report["fixed_contract_campaign_metrics"]["confusion_counts"]["fn"] == 1
    staged_inputs = report["input_provenance"]["fixed_contract_campaign_results"]
    assert staged_inputs["directory"] == str(context.result_dir)


def test_fixed_campaign_requires_every_plan_batch_marker(tmp_path: Path) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-CORPUS", "label": "AI_CAUSAL"}],
    )
    _write_result(cache_dir, "CVE-CORPUS", _raw_result("CVE-CORPUS", positive=True))
    context, _, _ = _fixed_campaign_fixture(
        tmp_path,
        cache_dir,
        ("CVE-CORPUS",),
    )
    second_path = context.repo_root / "batches" / "batch-002.txt"
    second_path.write_text("CVE-OUTSIDE-CORPUS\n", encoding="utf-8")
    second_spec = detector_quality.refresh_runner.BatchSpec(
        key="grouped-002",
        path=second_path,
        kind="fixture",
        ids=("CVE-OUTSIDE-CORPUS",),
        repos=frozenset(),
    )
    second_batch = detector_quality.FixedCampaignBatch(
        key=second_spec.key,
        path=second_spec.path,
        ids=second_spec.ids,
        command=tuple(detector_quality.refresh_runner.build_command(second_spec)),
    )
    context = replace(context, batches=(*context.batches, second_batch))

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids=set(),
        publication_provenance={"fixture": True},
        fixed_campaign_context=context,
    )

    proof = report["fixed_contract_campaign_proof"]
    assert proof["complete"] is False
    assert proof["incremental_plan_complete"] is False
    assert proof["campaign_batch_count"] == 2
    assert "missing_or_invalid_marker" in proof["failure_counts"]
    assert "fixed_contract_campaign_metrics" not in report


@pytest.mark.parametrize(
    ("mutation", "failure_code"),
    [
        ("receipt", "result_campaign_receipt_mismatch"),
        ("receipt_mtime", "result_campaign_receipt_precedes_result_write"),
        ("manifest", "marker_result_manifest_mismatch"),
    ],
)
def test_fixed_campaign_rejects_receipt_or_manifest_tampering(
    mutation: str,
    failure_code: str,
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-TAMPER", "label": "AI_CAUSAL"}],
    )
    _write_result(cache_dir, "CVE-TAMPER", _raw_result("CVE-TAMPER", positive=True))
    context, marker_path, marker = _fixed_campaign_fixture(
        tmp_path,
        cache_dir,
        ("CVE-TAMPER",),
    )
    if mutation in {"receipt", "receipt_mtime"}:
        result_path = context.result_dir / "CVE-TAMPER.json"
        if mutation == "receipt":
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            payload["campaign_receipt"]["requested_model"] = "gpt-5.4"
            result_path.write_text(json.dumps(payload), encoding="utf-8")
        midpoint = datetime.fromisoformat(marker["started_at"]) + timedelta(
            seconds=3 if mutation == "receipt_mtime" else 2
        )
        midpoint_ns = int(midpoint.timestamp() * 1_000_000_000)
        os.utime(result_path, ns=(midpoint_ns, midpoint_ns))
    else:
        marker["result_validation"]["result_manifest_sha256"] = "b" * 64
        marker_path.write_text(json.dumps(marker), encoding="utf-8")

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids=set(),
        publication_provenance={"fixture": True},
        fixed_campaign_context=context,
    )

    assert failure_code in report["fixed_contract_campaign_proof"]["failure_counts"]
    assert "fixed_contract_campaign_metrics" not in report


@pytest.mark.parametrize(
    ("model", "reasoning_effort", "failure_code"),
    [
        ("gpt-5.4", "max", "result_llm_model_mismatch"),
        ("gpt-5.6-luna", "high", "result_deep_verification_effort_mismatch"),
    ],
)
def test_fixed_campaign_rejects_stale_result_llm_provenance(
    model: str,
    reasoning_effort: str,
    failure_code: str,
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-STALE-PROVENANCE", "label": "AI_CAUSAL"}],
    )
    payload = _raw_result("CVE-STALE-PROVENANCE", positive=True)
    verification = payload["bug_introducing_commits"][0]["deep_verification"]
    verification["model"] = model
    verification["reasoning_effort"] = reasoning_effort
    _write_result(cache_dir, "CVE-STALE-PROVENANCE", payload)
    context, _, _ = _fixed_campaign_fixture(
        tmp_path,
        cache_dir,
        ("CVE-STALE-PROVENANCE",),
    )

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids=set(),
        publication_provenance={"fixture": True},
        fixed_campaign_context=context,
    )

    proof = report["fixed_contract_campaign_proof"]
    assert proof["complete"] is False
    assert failure_code in {failure["code"] for failure in proof["failures"]}
    assert "fixed_contract_campaign_metrics" not in report


@pytest.mark.parametrize(
    ("field", "value", "failure_code"),
    [
        ("model", "other-model", "current_campaign_model_invalid"),
        (
            "reasoning_effort",
            "high",
            "current_campaign_reasoning_effort_invalid",
        ),
    ],
)
def test_campaign_context_itself_must_be_luna_max(
    field: str,
    value: str,
    failure_code: str,
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-CONTRACT", "label": "AI_CAUSAL"}],
    )
    _write_result(cache_dir, "CVE-CONTRACT", _raw_result("CVE-CONTRACT", positive=True))
    context, marker_path, marker = _fixed_campaign_fixture(
        tmp_path,
        cache_dir,
        ("CVE-CONTRACT",),
    )
    context = replace(context, **{field: value})
    marker[field] = value
    marker_path.write_text(json.dumps(marker), encoding="utf-8")

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids={"CVE-CONTRACT"},
        publication_provenance={"fixture": True},
        fixed_campaign_context=context,
    )

    failures = report["fixed_contract_campaign_proof"]["failures"]
    assert failure_code in {failure["code"] for failure in failures}
    assert "fixed_contract_campaign_metrics" not in report


@pytest.mark.parametrize(
    ("field", "bad_value", "failure_code"),
    [
        ("schema_version", 3, "marker_schema_mismatch"),
        ("contract_sha256", "b" * 64, "marker_contract_mismatch"),
        ("source_snapshot_sha256", "b" * 64, "marker_source_mismatch"),
        ("model", "other-model", "marker_model_mismatch"),
        ("reasoning_effort", "high", "marker_reasoning_effort_mismatch"),
        ("batch_sha256", "b" * 64, "marker_batch_hash_mismatch"),
        ("command", ["false"], "marker_command_mismatch"),
    ],
)
def test_invalid_marker_contract_retains_mixed_snapshot_claim(
    field: str,
    bad_value: object,
    failure_code: str,
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-MIXED", "label": "AI_CAUSAL"}],
    )
    _write_result(cache_dir, "CVE-MIXED", _raw_result("CVE-MIXED", positive=True))
    context, marker_path, marker = _fixed_campaign_fixture(
        tmp_path,
        cache_dir,
        ("CVE-MIXED",),
    )
    marker[field] = bad_value
    marker_path.write_text(json.dumps(marker), encoding="utf-8")

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids={"CVE-MIXED"},
        publication_provenance={"fixture": True},
        fixed_campaign_context=context,
    )

    assert report["evaluation_kind"] == (
        "frozen_adjudication_mixed_version_cached_pipeline_snapshot_vs_curated_publication"
    )
    assert report["evaluation_complete"] is False
    assert report["fixed_contract_campaign_proof"]["complete"] is False
    assert failure_code in {
        failure["code"]
        for failure in report["fixed_contract_campaign_proof"]["failures"]
    }
    assert "cached_pipeline_snapshot_metrics" in report
    assert "fixed_contract_campaign_metrics" not in report
    assert report["code_provenance"]["generation_contract_status"] == (
        "mixed_or_unknown"
    )


@pytest.mark.parametrize(
    ("result_mode", "failure_code"),
    [
        ("before_start", "result_mtime_outside_marker_window"),
        ("after_completion", "result_mtime_outside_marker_window"),
        ("nonterminal", "result_not_terminal"),
    ],
)
def test_result_proof_must_be_fresh_terminal_and_bound_to_marker_window(
    result_mode: str,
    failure_code: str,
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-RESULT", "label": "AI_CAUSAL"}],
    )
    result_path = _write_result(
        cache_dir,
        "CVE-RESULT",
        _raw_result("CVE-RESULT", positive=True),
    )
    context, _, marker = _fixed_campaign_fixture(
        tmp_path,
        cache_dir,
        ("CVE-RESULT",),
    )
    result_path = context.result_dir / "CVE-RESULT.json"
    if result_mode == "nonterminal":
        payload = _raw_result("CVE-RESULT", positive=True)
        payload["repo_ai_activity"] = ["incomplete:git_log_timeout"]
        result_path.write_text(json.dumps(payload), encoding="utf-8")
        midpoint = datetime.fromisoformat(marker["started_at"]) + timedelta(seconds=1)
        mtime_ns = int(midpoint.timestamp() * 1_000_000_000)
    else:
        boundary = datetime.fromisoformat(
            marker["started_at"]
            if result_mode == "before_start"
            else marker["completed_at"]
        )
        offset = -1 if result_mode == "before_start" else 1
        mtime_ns = int(
            (boundary + timedelta(seconds=offset)).timestamp() * 1_000_000_000
        )
    os.utime(result_path, ns=(mtime_ns, mtime_ns))

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids={"CVE-RESULT"},
        publication_provenance={"fixture": True},
        fixed_campaign_context=context,
    )

    failures = report["fixed_contract_campaign_proof"]["failures"]
    assert failure_code in {failure["code"] for failure in failures}
    assert report["evaluation_complete"] is False


def test_every_subject_requires_one_unambiguous_marker_and_cache_proof(
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [
            {
                "cve_id": "CVE-COVERED",
                "aliases": ["GHSA-MISSING"],
                "label": "AI_CAUSAL",
            }
        ],
    )
    _write_result(cache_dir, "CVE-COVERED", _raw_result("CVE-COVERED", positive=True))
    context, _, _ = _fixed_campaign_fixture(
        tmp_path,
        cache_dir,
        ("CVE-COVERED",),
    )
    duplicate_batch_path = context.repo_root / "batches" / "batch-002.txt"
    duplicate_batch_path.write_text("CVE-COVERED\n", encoding="utf-8")
    duplicate_batch = detector_quality.FixedCampaignBatch(
        key="grouped-002",
        path=duplicate_batch_path,
        ids=("CVE-COVERED",),
        command=("duplicate",),
    )
    context = replace(context, batches=(*context.batches, duplicate_batch))
    aliases = {"CVE-COVERED", "GHSA-MISSING"}

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={subject_id: aliases for subject_id in aliases},
        published_ids={"CVE-COVERED"},
        publication_provenance={"fixture": True},
        fixed_campaign_context=context,
    )

    failures = report["fixed_contract_campaign_proof"]["failures"]
    codes = {failure["code"] for failure in failures}
    assert "ambiguous_subject_batch" in codes
    assert "adjudicated_subject_absent_from_formal_population" in codes


def test_report_is_deterministic_and_captures_model_effort_and_error_strata(
    tmp_path: Path,
) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [
            {"cve_id": "POS-INFRA", "label": "AI_CAUSAL"},
            {"cve_id": "NEG-FALLBACK", "label": "NOT_AI_CAUSAL"},
        ],
    )
    infra = _raw_result(
        "POS-INFRA",
        error="clone failed",
        error_category="clone_failed",
    )
    infra["repo_ai_activity"] = ["incomplete:git_log_timeout"]
    _write_result(cache_dir, "POS-INFRA", infra)
    _write_result(
        cache_dir,
        "NEG-FALLBACK",
        _raw_result("NEG-FALLBACK", positive=True, fallback=True),
    )

    first = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids=set(),
        publication_provenance={"fixture": True},
    )
    second = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids=set(),
        publication_provenance={"fixture": True},
    )

    assert first == second
    assert first["cached_pipeline_snapshot_metrics"]["confusion_counts"] == {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
    }
    assert first["cached_pipeline_snapshot_metrics"]["incomplete_excluded"] == 2
    assert first["strata"]["infrastructure_error"] == {
        "count": 1,
        "ids": ["POS-INFRA"],
        "categories": {"clone_failed": 1, "incomplete:git_log_timeout": 1},
    }
    assert first["strata"]["detector_unresolved"]["ids"] == ["NEG-FALLBACK"]
    fallback = next(
        row
        for row in first["prediction_manifest"]
        if row["canonical_id"] == "NEG-FALLBACK"
    )
    assert fallback["cached_pipeline_snapshot_prediction"] == "incomplete"
    assert fallback["cached_pipeline_snapshot_outcome"] == "excluded_incomplete"
    assert fallback["cached_pipeline_inputs"][0]["llm_provenance"] == [
        {
            "json_path": "$.bug_introducing_commits[0].deep_verification",
            "model": "gpt-5.6-luna",
            "reasoning_effort": "max",
        },
        {
            "json_path": "$.screening",
            "model": "gpt-5.6-luna",
        },
    ]
    assert first["evaluation_complete"] is False


def test_publication_outside_corpus_makes_evaluation_incomplete(tmp_path: Path) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-REQUIRED", "label": "AI_CAUSAL"}],
    )
    _write_result(cache_dir, "CVE-REQUIRED", _raw_result("CVE-REQUIRED", positive=True))

    report = detector_quality.build_report(
        adjudications_path=adjudications,
        cache_dir=cache_dir,
        alias_map={},
        published_ids={"CVE-REQUIRED", "GHSA-unadjudicated"},
        publication_provenance={"fixture": True},
    )

    assert report["strata"]["publication_outside_corpus"] == {
        "count": 1,
        "ids": ["GHSA-unadjudicated"],
    }
    assert report["evaluation_complete"] is False


@pytest.mark.parametrize("failure", ["missing", "malformed", "id_mismatch"])
def test_cache_inputs_fail_closed(failure: str, tmp_path: Path) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-REQUIRED", "label": "AI_CAUSAL"}],
    )
    if failure == "malformed":
        (cache_dir / "CVE-REQUIRED.json").write_text("{", encoding="utf-8")
    elif failure == "id_mismatch":
        _write_result(
            cache_dir,
            "CVE-REQUIRED",
            _raw_result("CVE-DIFFERENT"),
        )

    expected = {
        "missing": "Missing cached pipeline snapshot input",
        "malformed": "Cannot read cached pipeline snapshot input",
        "id_mismatch": "Cached pipeline snapshot filename/id mismatch",
    }[failure]
    with pytest.raises(ValueError, match=expected):
        detector_quality.build_report(
            adjudications_path=adjudications,
            cache_dir=cache_dir,
            alias_map={},
            published_ids=set(),
            publication_provenance={"fixture": True},
        )


def test_cache_read_rejects_symlink_escape(tmp_path: Path) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-REQUIRED", "label": "AI_CAUSAL"}],
    )
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_raw_result("CVE-REQUIRED")), encoding="utf-8")
    (cache_dir / "CVE-REQUIRED.json").symlink_to(outside)

    with pytest.raises(ValueError, match="escapes|unsafe"):
        detector_quality.build_report(
            adjudications_path=adjudications,
            cache_dir=cache_dir,
            alias_map={},
            published_ids=set(),
            publication_provenance={"fixture": True},
        )


@pytest.mark.parametrize(
    "unsafe_id",
    ["../escape", "nested/id", ".", "-leading"],
)
def test_public_ids_must_be_path_safe(unsafe_id: str, tmp_path: Path) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": unsafe_id, "label": "AI_CAUSAL"}],
    )

    with pytest.raises(ValueError, match="path-safe public ID"):
        detector_quality.build_report(
            adjudications_path=adjudications,
            cache_dir=cache_dir,
            alias_map={},
            published_ids=set(),
            publication_provenance={"fixture": True},
        )


def test_published_ids_must_be_path_safe(tmp_path: Path) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [{"cve_id": "CVE-REQUIRED", "label": "AI_CAUSAL"}],
    )
    _write_result(cache_dir, "CVE-REQUIRED")

    with pytest.raises(ValueError, match="path-safe public ID"):
        detector_quality.build_report(
            adjudications_path=adjudications,
            cache_dir=cache_dir,
            alias_map={},
            published_ids={"../outside"},
            publication_provenance={"fixture": True},
        )


def test_conflicting_alias_closure_fails_closed(tmp_path: Path) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [
            {"cve_id": "CVE-POS", "label": "AI_CAUSAL"},
            {"cve_id": "CVE-NEG", "label": "NOT_AI_CAUSAL"},
        ],
    )
    _write_result(cache_dir, "CVE-POS")
    _write_result(cache_dir, "CVE-NEG")
    shared = {"CVE-POS", "CVE-NEG"}

    with pytest.raises(ValueError, match="Conflicting audit adjudications"):
        detector_quality.build_report(
            adjudications_path=adjudications,
            cache_dir=cache_dir,
            alias_map={subject_id: shared for subject_id in shared},
            published_ids=set(),
            publication_provenance={"fixture": True},
        )


def test_duplicate_adjudication_fails_closed(tmp_path: Path) -> None:
    adjudications = tmp_path / "adjudications.json"
    cache_dir = tmp_path / "results"
    cache_dir.mkdir()
    _write_adjudications(
        adjudications,
        [
            {"cve_id": "CVE-DUP", "label": "AI_CAUSAL"},
            {"cve_id": "CVE-DUP", "label": "AI_CAUSAL"},
        ],
    )
    _write_result(cache_dir, "CVE-DUP")

    with pytest.raises(ValueError, match="Duplicate adjudication"):
        detector_quality.build_report(
            adjudications_path=adjudications,
            cache_dir=cache_dir,
            alias_map={},
            published_ids=set(),
            publication_provenance={"fixture": True},
        )


def test_uncategorized_errors_are_infrastructure_failures() -> None:
    assert detector_quality._infrastructure_categories(
        {"error": "network timeout", "error_category": ""}
    ) == ("uncategorized_error",)
    assert (
        detector_quality._infrastructure_categories(
            {"error": "no fix commits", "error_category": "no_fix_commits"}
        )
        == ()
    )
