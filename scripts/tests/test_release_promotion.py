"""Tests for gated staging and atomic Web-data promotion."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import web_data.writer as writer
from web_data.writer import (
    PublishedDataError,
    PublicationWriteError,
    WriteResult,
    discard_staged_web_data,
    load_published_web_data,
    promote_staged_web_data,
    publication_promotion_transaction,
    staged_publication_bundle_sha256,
    write_staged_release_receipt,
    write_web_data,
)

_GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _write_unreceipted_web_data(
    entries: list[dict],
    stats: dict,
    output_dir: Path,
    *,
    generated_at: str,
) -> WriteResult:
    return write_web_data(
        entries,
        stats,
        output_dir,
        generated_at=generated_at,
        allow_unreceipted=True,
    )


def make_entry(cve_id: str) -> dict:
    return {
        "id": cve_id,
        "description": "A test vulnerability",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwes": [],
        "ecosystem": "",
        "published": "2025-06-01",
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


def make_stats(entries: list[dict]) -> dict:
    count = len(entries)
    return {
        "generated_at": "2025-12-31T00:00:00+00:00",
        "total_cves": count,
        "total_analyzed": max(100, count),
        "with_fix_commits": 50,
        "coverage_from": "2025-05-01",
        "coverage_to": "2025-06-01" if entries else "",
        "by_tool": {"cursor": count} if count else {},
        "by_severity": {"HIGH": count} if count else {},
        "by_language": {"Python": count} if count else {},
        "by_repo": {},
        "by_month": [
            {
                "month": "2025-06",
                "count": count,
                "by_tool": {"cursor": count},
            }
        ]
        if entries
        else [],
    }


def _make_test_inventory(subject_id: str, *, generated_at: str) -> dict:
    member_ids = [subject_id]
    component_sha256 = hashlib.sha256(f"{subject_id}\n".encode()).hexdigest()
    source_evidence_sha256 = writer._canonical_sha256(
        {"class_id": subject_id, "member_ids": member_ids}
    )
    row = {
        "class_id": subject_id,
        "component_sha256": component_sha256,
        "source_evidence_sha256": source_evidence_sha256,
        "analysis_subject": subject_id,
        "member_ids": member_ids,
        "result_subject_ids": member_ids,
        "coverage_status": "complete",
        "detector_state": "positive",
        "adjudication_state": "ai_causal",
        "publication_state": "published",
        "recall_stratum": "detected_positive",
        "reasons": [],
    }
    alias_rows = [
        {
            "analysis_subject": row["analysis_subject"],
            "class_id": row["class_id"],
            "component_sha256": row["component_sha256"],
            "member_ids": row["member_ids"],
            "source_evidence_sha256": row["source_evidence_sha256"],
        }
    ]
    inventory = {
        "schema_version": 2,
        "kind": "ai_vulnerability_detector_inventory",
        "generated_at": generated_at,
        "source_snapshot_sha256": "f" * 64,
        "source_receipt_sha256": "b" * 64,
        "source_alias_class_manifest_sha256": writer._canonical_sha256(alias_rows),
        "campaign_id": "a" * 64,
        "contract_sha256": "d" * 64,
        "campaign_mode": "formal",
        "complete": True,
        "coverage_to": "2026-01-01",
        "alias_class_count": 1,
        "detector_candidate_count": 1,
        "pending_adjudication_count": 0,
        "coverage_failure_count": 0,
        "counts": {
            "coverage_status": {"complete": 1},
            "detector_state": {"positive": 1},
            "adjudication_state": {"ai_causal": 1},
            "publication_state": {"published": 1},
            "recall_stratum": {"detected_positive": 1},
        },
        "rows": [row],
    }
    inventory["inventory_id"] = writer._canonical_sha256(inventory)
    return inventory


def _bind_test_inventory(stats: dict, inventory: dict) -> None:
    stats["inventory"] = {
        "path": "inventory.json",
        "inventory_id": inventory["inventory_id"],
        "source_snapshot_sha256": inventory["source_snapshot_sha256"],
        "source_alias_class_manifest_sha256": inventory[
            "source_alias_class_manifest_sha256"
        ],
        "campaign_id": inventory["campaign_id"],
        "campaign_mode": inventory["campaign_mode"],
        "complete": inventory["complete"],
        "coverage_to": inventory["coverage_to"],
        "alias_class_count": inventory["alias_class_count"],
        "detector_candidate_count": inventory["detector_candidate_count"],
        "pending_adjudication_count": inventory["pending_adjudication_count"],
        "coverage_failure_count": inventory["coverage_failure_count"],
    }


def stage_web_data(
    entries: list[dict],
    stats: dict,
    output_dir: Path,
    *,
    generated_at: str,
) -> writer.StagedWebData:
    inventory = _make_test_inventory(entries[0]["id"], generated_at=generated_at)
    bound_stats = dict(stats)
    _bind_test_inventory(bound_stats, inventory)
    return writer.stage_web_data(
        entries,
        bound_stats,
        output_dir,
        generated_at=generated_at,
        inventory=inventory,
    )


def _candidate_entries(publication: writer.PublishedWebData) -> list[dict]:
    return [
        {key: value for key, value in entry.items() if key != "generation_id"}
        for entry in publication.entries
    ]


def _test_receipt_payload(staged: writer.StagedWebData) -> dict:
    publication = load_published_web_data(staged.staging_dir)
    inventory = publication.inventory
    assert inventory is not None
    manifest_entry = {
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
        "url": "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt",
    }
    remote_cutoff = {
        "checked_at_utc": "2026-07-18T12:00:00+00:00",
        "receipt_file": {
            "name": "source-remote-check-now.json",
            "path": "/tmp/source-remote-check-now.json",
            "sha256": "e" * 64,
            "size_bytes": 100,
        },
        "remote_parity": True,
        "receipt": {
            "schema_version": 3,
            "checked_at_utc": "2026-07-18T12:00:00+00:00",
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
            "osv_ecosystem_manifest": manifest_entry,
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
                    "url": "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip",
                }
            ],
            "remote_parity": True,
        },
    }
    return {
        "schema_version": 4,
        "generation_id": publication.index["generation_id"],
        "generated_at": publication.index["generated_at"],
        "campaign_id": inventory["campaign_id"],
        "campaign_result_manifest_sha256": "b" * 64,
        "analyzer_contract_sha256": "c" * 64,
        "signature_sha256": "d" * 64,
        "alias_class_manifest_sha256": inventory["source_alias_class_manifest_sha256"],
        "campaign_mode": "formal",
        "population_policy": "formal_full",
        "source_snapshot_sha256": inventory["source_snapshot_sha256"],
        "source_remote_cutoff": remote_cutoff,
        "publication_bundle_sha256": staged_publication_bundle_sha256(staged),
        "publication_manifest_sha256": "8" * 64,
        "publication_curation_consistency_report_sha256": "1" * 64,
        "publication_curation_inputs_sha256": "9" * 64,
        "heldout_quality_report_sha256": "2" * 64,
        "heldout_selection_sha256": "3" * 64,
        "heldout_labels_sha256": "4" * 64,
        "heldout_campaign_population_sha256": "7" * 64,
        "heldout_campaign_proof_sha256": "5" * 64,
        "heldout_campaign_result_manifest_sha256": "6" * 64,
        "recall_selection_sha256": "0" * 64,
        "recall_labels_sha256": "a" * 64,
        "recall_report_sha256": "b" * 64,
        "recall_inventory_id": inventory["inventory_id"],
        "recall_selection_manifest_sha256": "d" * 64,
        "protected_census_manifest_sha256": "e" * 64,
        "protected_overlap_class_count": 0,
        "protected_census_complete": True,
        "verifier_contract_sha256": "f" * 64,
        "verifier_git_commit": "1" * 40,
        "verifier_git_tree": "2" * 40,
        "verifier_files_manifest_sha256": "3" * 64,
        "verifier_dependency_lock_sha256": "4" * 64,
        "recall_evaluation_status": "complete_end_to_end",
        "recall_evaluation_complete": True,
        "recall_point_estimate": 1.0,
        "recall_interval": [1.0, 1.0],
        "detector_inventory_id": inventory["inventory_id"],
        "detector_inventory_sha256": writer._canonical_sha256(inventory),
        "detector_inventory_campaign_mode": inventory["campaign_mode"],
        "detector_inventory_complete": inventory["complete"],
        "detector_inventory_source_snapshot_sha256": inventory[
            "source_snapshot_sha256"
        ],
        "detector_inventory_alias_class_manifest_sha256": inventory[
            "source_alias_class_manifest_sha256"
        ],
        "detector_inventory_alias_class_count": inventory["alias_class_count"],
        "targets": {"precision": 0.95, "recall": 0.95},
        "curation_consistency_point_estimates": {
            "precision": 1.0,
            "recall": 1.0,
        },
        "heldout_point_estimates": {"precision": 1.0, "recall": 1.0},
        "heldout_measurement_boundary": {
            "precision": "final detector precision among predicted positives",
            "recall": "final classifier recall in the AI-signal candidate population",
            "excluded": (
                "upstream advisory discovery and AI-signature discovery recall"
            ),
        },
        "evaluation_complete": True,
        "release_safe": True,
        "curation_consistent": True,
        "heldout_certified": True,
    }


def _attach_test_receipt(staged: writer.StagedWebData) -> None:
    write_staged_release_receipt(staged, _test_receipt_payload(staged))


def _inode(path: Path) -> tuple[int, int]:
    metadata = path.stat(follow_symlinks=False)
    return metadata.st_dev, metadata.st_ino


def test_staging_and_failed_gate_preserve_live_generation(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    old_entries = [make_entry("CVE-2025-00001")]
    new_entries = [make_entry("CVE-2025-00002")]
    _write_unreceipted_web_data(
        old_entries,
        make_stats(old_entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )

    staged = stage_web_data(
        new_entries,
        make_stats(new_entries),
        output_dir,
        generated_at="2026-01-02T00:00:00+00:00",
    )
    try:
        assert _candidate_entries(load_published_web_data(output_dir)) == old_entries
        with pytest.raises(PublishedDataError, match="release receipt"):
            promote_staged_web_data(staged)
        assert _candidate_entries(load_published_web_data(output_dir)) == old_entries
    finally:
        discard_staged_web_data(staged)


def test_promotion_transaction_retains_previous_generation_and_rolls_back(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [make_entry("CVE-2025-00001")]
    new_entries = [make_entry("CVE-2025-00002")]
    _write_unreceipted_web_data(
        old_entries,
        make_stats(old_entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    old_inode = _inode(output_dir)
    staged = stage_web_data(
        new_entries,
        make_stats(new_entries),
        output_dir,
        generated_at="2026-01-02T00:00:00+00:00",
    )
    candidate_inode = _inode(staged.staging_dir)
    _attach_test_receipt(staged)

    with pytest.raises(RuntimeError, match="postcheck failed"):
        with publication_promotion_transaction(staged):
            assert _inode(output_dir) == candidate_inode
            assert _inode(staged.staging_dir) == old_inode
            raise RuntimeError("postcheck failed")

    assert _inode(output_dir) == old_inode
    assert _inode(staged.staging_dir) == candidate_inode
    assert _candidate_entries(load_published_web_data(output_dir)) == old_entries
    discard_staged_web_data(staged)


def test_promotion_transaction_deletes_previous_only_after_body_success(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [make_entry("CVE-2025-00001")]
    new_entries = [make_entry("CVE-2025-00002")]
    _write_unreceipted_web_data(
        old_entries,
        make_stats(old_entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    old_inode = _inode(output_dir)
    staged = stage_web_data(
        new_entries,
        make_stats(new_entries),
        output_dir,
        generated_at="2026-01-02T00:00:00+00:00",
    )
    _attach_test_receipt(staged)

    with publication_promotion_transaction(staged):
        assert _inode(staged.staging_dir) == old_inode
        assert _candidate_entries(
            writer._load_published_web_data_unlocked(staged.staging_dir)
        ) == (old_entries)

    assert not staged.staging_dir.exists()
    assert _candidate_entries(load_published_web_data(output_dir)) == new_entries


def test_receipted_staging_promotes_as_one_generation(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry("CVE-2025-00002")]
    staged = stage_web_data(
        entries,
        make_stats(entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    _attach_test_receipt(staged)

    result = promote_staged_web_data(staged)

    assert result.written == 1
    assert _candidate_entries(load_published_web_data(output_dir)) == entries
    assert (output_dir / "release-receipt.json").is_file()


def test_receipt_rejects_publication_without_detector_inventory(
    tmp_path: Path,
) -> None:
    entries = [make_entry("CVE-2025-00002")]
    bound = stage_web_data(
        entries,
        make_stats(entries),
        tmp_path / "bound",
        generated_at=_GENERATED_AT,
    )
    unbound = writer.stage_web_data(
        entries,
        make_stats(entries),
        tmp_path / "unbound",
        generated_at=_GENERATED_AT,
    )
    try:
        payload = _test_receipt_payload(bound)
        with pytest.raises(PublishedDataError, match="detector inventory is missing"):
            write_staged_release_receipt(unbound, payload)
    finally:
        discard_staged_web_data(bound)
        discard_staged_web_data(unbound)


def test_receipt_rejects_a_mismatched_publication_hash(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry("CVE-2025-00002")]
    staged = stage_web_data(
        entries,
        make_stats(entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    try:
        with pytest.raises(PublishedDataError, match="publication_bundle_sha256"):
            payload = _test_receipt_payload(staged)
            payload["publication_bundle_sha256"] = "c" * 64
            write_staged_release_receipt(
                staged,
                payload,
            )
    finally:
        discard_staged_web_data(staged)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("generation_id", None, "missing required fields"),
        ("generated_at", None, "missing required fields"),
        ("source_snapshot_sha256", None, "missing required fields"),
        ("source_remote_cutoff", None, "missing required fields"),
        ("heldout_quality_report_sha256", None, "missing required fields"),
        ("heldout_selection_sha256", None, "missing required fields"),
        ("heldout_labels_sha256", None, "missing required fields"),
        ("heldout_campaign_population_sha256", None, "missing required fields"),
        ("recall_selection_sha256", None, "missing required fields"),
        ("recall_labels_sha256", None, "missing required fields"),
        ("recall_report_sha256", None, "missing required fields"),
        ("recall_inventory_id", None, "missing required fields"),
        ("recall_evaluation_complete", False, "recall proof is invalid"),
        ("recall_evaluation_status", "incomplete", "recall proof is invalid"),
        ("recall_point_estimate", None, "missing required fields"),
        ("evaluation_complete", False, "evaluation_complete must be true"),
        ("release_safe", False, "release_safe must be true"),
        ("curation_consistent", False, "curation_consistent must be true"),
        ("heldout_certified", False, "heldout_certified must be true"),
        ("generation_id", "c" * 64, "generation_id does not match"),
        ("generated_at", "2026-01-03T00:00:00+00:00", "generated_at does not match"),
    ],
)
def test_receipt_writer_rejects_incomplete_or_mismatched_generation_proof(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry("CVE-2025-00002")]
    staged = stage_web_data(
        entries,
        make_stats(entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    try:
        payload = _test_receipt_payload(staged)
        if value is None:
            payload.pop(field)
        else:
            payload[field] = value
        with pytest.raises(PublishedDataError, match=message):
            write_staged_release_receipt(staged, payload)
        assert not (staged.staging_dir / "release-receipt.json").exists()
    finally:
        discard_staged_web_data(staged)


@pytest.mark.parametrize(
    ("point", "interval"),
    [
        (0.01, [0.0, 0.02]),
        (1.0, [0.94, 1.0]),
    ],
)
def test_receipt_writer_requires_end_to_end_recall_to_meet_target(
    tmp_path: Path,
    point: float,
    interval: list[float],
) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry("CVE-2025-00002")]
    staged = stage_web_data(
        entries,
        make_stats(entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    try:
        payload = _test_receipt_payload(staged)
        payload["recall_point_estimate"] = point
        payload["recall_interval"] = interval
        with pytest.raises(PublishedDataError, match="must meet the recall target"):
            write_staged_release_receipt(staged, payload)
    finally:
        discard_staged_web_data(staged)


@pytest.mark.parametrize(
    "mutation",
    [
        "remote_parity",
        "git_head",
        "nvd_meta",
        "osv_generation",
        "osv_size",
    ],
)
def test_receipt_writer_rejects_invalid_remote_cutoff_proof(
    tmp_path: Path,
    mutation: str,
) -> None:
    entries = [make_entry("CVE-2025-00002")]
    staged = stage_web_data(
        entries,
        make_stats(entries),
        tmp_path / "published",
        generated_at=_GENERATED_AT,
    )
    try:
        payload = _test_receipt_payload(staged)
        cutoff = payload["source_remote_cutoff"]
        remote = cutoff["receipt"]
        if mutation == "remote_parity":
            cutoff["remote_parity"] = False
        elif mutation == "git_head":
            remote["git_sources"][0]["remote_head"] = "0" * 40
        elif mutation == "nvd_meta":
            remote["nvd_feeds"][0]["remote_meta_sha256"] = "0" * 64
        elif mutation == "osv_generation":
            remote["osv_archives"][0]["generation"] = "unknown"
        else:
            remote["osv_archives"][0]["remote_size"] = 2
        with pytest.raises(PublishedDataError, match="source_remote_cutoff"):
            write_staged_release_receipt(staged, payload)
    finally:
        discard_staged_web_data(staged)


def test_receipt_reader_rejects_generation_tampering_before_promotion(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry("CVE-2025-00002")]
    staged = stage_web_data(
        entries,
        make_stats(entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    try:
        _attach_test_receipt(staged)
        receipt_path = staged.staging_dir / "release-receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["generation_id"] = "c" * 64
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

        with pytest.raises(PublishedDataError, match="generation_id does not match"):
            promote_staged_web_data(staged)
        assert not output_dir.exists()
    finally:
        discard_staged_web_data(staged)


def test_reader_waits_for_exchange_and_observes_one_complete_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [make_entry("CVE-2025-00001")]
    new_entries = [make_entry("CVE-2025-00002")]
    _write_unreceipted_web_data(
        old_entries,
        make_stats(old_entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    staged = stage_web_data(
        new_entries,
        make_stats(new_entries),
        output_dir,
        generated_at="2026-01-02T00:00:00+00:00",
    )
    _attach_test_receipt(staged)

    real_exchange = writer._rename_exchange
    exchange_complete = threading.Event()
    allow_publisher_to_continue = threading.Event()
    reader_complete = threading.Event()

    def pause_after_exchange(
        first: Path,
        second: Path,
        parent_lock: writer.PublicationParentLock | None = None,
    ) -> None:
        real_exchange(first, second, parent_lock)
        exchange_complete.set()
        assert allow_publisher_to_continue.wait(timeout=5)

    def read_live() -> writer.PublishedWebData:
        try:
            return load_published_web_data(output_dir)
        finally:
            reader_complete.set()

    monkeypatch.setattr(writer, "_rename_exchange", pause_after_exchange)
    with ThreadPoolExecutor(max_workers=2) as executor:
        promotion = executor.submit(promote_staged_web_data, staged)
        assert exchange_complete.wait(timeout=5)
        read = executor.submit(read_live)
        assert not reader_complete.wait(timeout=0.1)
        assert output_dir.is_dir()
        allow_publisher_to_continue.set()
        promotion.result(timeout=5)
        assert _candidate_entries(read.result(timeout=5)) == new_entries


def test_concurrent_promotions_are_serialized_by_parent_flock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [make_entry("CVE-2025-00001")]
    _write_unreceipted_web_data(
        old_entries,
        make_stats(old_entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    staged_generations = []
    for suffix in ("2", "3"):
        entries = [make_entry(f"CVE-2025-0000{suffix}")]
        staged = stage_web_data(
            entries,
            make_stats(entries),
            output_dir,
            generated_at=f"2026-01-0{suffix}T00:00:00+00:00",
        )
        _attach_test_receipt(staged)
        staged_generations.append(staged)

    real_exchange = writer._rename_exchange
    counter_lock = threading.Lock()
    first_exchange_entered = threading.Event()
    allow_first_exchange = threading.Event()
    second_exchange_entered = threading.Event()
    exchange_calls = 0

    def counted_exchange(
        first: Path,
        second: Path,
        parent_lock: writer.PublicationParentLock | None = None,
    ) -> None:
        nonlocal exchange_calls
        with counter_lock:
            exchange_calls += 1
            call_number = exchange_calls
        if call_number == 1:
            first_exchange_entered.set()
            assert allow_first_exchange.wait(timeout=5)
        else:
            second_exchange_entered.set()
        real_exchange(first, second, parent_lock)

    monkeypatch.setattr(writer, "_rename_exchange", counted_exchange)
    with ThreadPoolExecutor(max_workers=2) as executor:
        promotions = [
            executor.submit(promote_staged_web_data, staged)
            for staged in staged_generations
        ]
        assert first_exchange_entered.wait(timeout=5)
        assert not second_exchange_entered.wait(timeout=0.1)
        allow_first_exchange.set()
        for promotion in promotions:
            promotion.result(timeout=5)

    assert second_exchange_entered.is_set()
    assert exchange_calls == 2
    assert _candidate_entries(load_published_web_data(output_dir)) in [
        [make_entry("CVE-2025-00002")],
        [make_entry("CVE-2025-00003")],
    ]


def test_parent_directory_swap_cannot_create_an_independent_lock_domain(
    tmp_path: Path,
) -> None:
    publication_parent = tmp_path / "publication-parent"
    publication_parent.mkdir()
    moved_parent = tmp_path / "publication-parent-moved"
    output_dir = publication_parent / "published"
    second_acquired = threading.Event()

    def acquire_replacement_parent() -> None:
        with writer._publication_parent_lock(
            output_dir,
            exclusive=True,
            error_type=PublicationWriteError,
        ):
            second_acquired.set()

    executor = ThreadPoolExecutor(max_workers=1)
    try:
        with pytest.raises(PublicationWriteError, match="parent path changed"):
            with writer._publication_parent_lock(
                output_dir,
                exclusive=True,
                error_type=PublicationWriteError,
            ) as first_lock:
                publication_parent.rename(moved_parent)
                publication_parent.mkdir()
                second = executor.submit(acquire_replacement_parent)
                assert not second_acquired.wait(timeout=0.1)
                first_lock.assert_current()
        second.result(timeout=5)
    finally:
        executor.shutdown(wait=True)

    publication_parent.rmdir()
    moved_parent.rename(publication_parent)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires Linux process semantics")
def test_sigkill_after_exchange_never_leaves_live_missing(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    old_entries = [make_entry("CVE-2025-00001")]
    new_entries = [make_entry("CVE-2025-00002")]
    _write_unreceipted_web_data(
        old_entries,
        make_stats(old_entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    staged = stage_web_data(
        new_entries,
        make_stats(new_entries),
        output_dir,
        generated_at="2026-01-02T00:00:00+00:00",
    )
    _attach_test_receipt(staged)

    read_descriptor, write_descriptor = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_descriptor)
        real_fsync_parent = writer._fsync_publication_parent

        def pause_before_parent_fsync(
            parent_lock: writer.PublicationParentLock,
        ) -> None:
            os.write(write_descriptor, b"x")
            signal.pause()
            real_fsync_parent(parent_lock)

        writer._fsync_publication_parent = pause_before_parent_fsync
        try:
            promote_staged_web_data(staged)
        finally:
            os._exit(1)

    os.close(write_descriptor)
    try:
        assert os.read(read_descriptor, 1) == b"x"
        os.kill(child, signal.SIGKILL)
        _, wait_status = os.waitpid(child, 0)
        assert os.WIFSIGNALED(wait_status)
        assert os.WTERMSIG(wait_status) == signal.SIGKILL
    finally:
        os.close(read_descriptor)

    assert output_dir.is_dir()
    assert _candidate_entries(load_published_web_data(output_dir)) == new_entries
    assert (
        _candidate_entries(load_published_web_data(staged.staging_dir)) == old_entries
    )
    discard_staged_web_data(staged)


def test_existing_live_fails_closed_without_linux_atomic_exchange(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [make_entry("CVE-2025-00001")]
    new_entries = [make_entry("CVE-2025-00002")]
    _write_unreceipted_web_data(
        old_entries,
        make_stats(old_entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    staged = stage_web_data(
        new_entries,
        make_stats(new_entries),
        output_dir,
        generated_at="2026-01-02T00:00:00+00:00",
    )
    _attach_test_receipt(staged)
    monkeypatch.setattr(writer.sys, "platform", "portable-test")

    try:
        with pytest.raises(PublicationWriteError, match="requires Linux renameat2"):
            promote_staged_web_data(staged)
        assert _candidate_entries(load_published_web_data(output_dir)) == old_entries
        assert (
            _candidate_entries(load_published_web_data(staged.staging_dir))
            == new_entries
        )
    finally:
        discard_staged_web_data(staged)
