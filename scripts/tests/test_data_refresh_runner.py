"""Tests for the resumable incremental data-refresh runner."""

from __future__ import annotations

import base64
import fcntl
import gzip
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import zipfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import build_data_refresh_batches as batch_builder
import run_data_refresh as runner
import web_data.writer as web_writer


_REAL_CURRENT_OPENCLAW_SMOKE_GATE_STATUS = runner._current_openclaw_smoke_gate_status


@pytest.fixture(autouse=True)
def _fixed_litellm_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "LITELLM_API_BASE",
        "LITELLM_URL",
        "EXTERNAL_LITELLM_API_BASE",
        "LITELLM_API_KEY",
        "LITELLM_KEY",
        "EXTERNAL_LITELLM_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LITELLM_API_BASE", "https://litellm.example.invalid/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "fixture-proxy-key")


@pytest.fixture(autouse=True)
def _completed_openclaw_smoke_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep legacy runner tests focused on their original execution boundary."""

    monkeypatch.setattr(
        runner,
        "_current_openclaw_smoke_gate_status",
        lambda _paths: {
            "status": "ready",
            "smoke_id": "a" * 64,
            "class_count": 30,
        },
    )


def _init_git_source(path: Path, origin: str) -> None:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / "source.json").write_text('{"source": true}\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "source.json"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Refresh Test",
            "-c",
            "user.email=refresh@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(path), "remote", "add", "origin", origin], check=True
    )


def _commit_fixture(path: Path, message: str) -> None:
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Refresh Test",
            "-c",
            "user.email=refresh@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            message,
        ],
        check=True,
    )


def _init_current_openclaw_checkout(path: Path) -> str:
    _init_git_source(path, runner._OPENCLAW_ORIGIN)
    (path / "AGENTS.md").write_text("OpenClaw fixture\n", encoding="utf-8")
    (path / "CLAUDE.md").symlink_to("AGENTS.md")
    subprocess.run(
        ["git", "-C", str(path), "add", "AGENTS.md", "CLAUDE.md"],
        check=True,
    )
    _commit_fixture(path, "add safe tracked symlink")
    subprocess.run(
        ["git", "-C", str(path), "branch", "-M", runner._OPENCLAW_BRANCH],
        check=True,
    )
    head = subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "update-ref",
            runner._OPENCLAW_REMOTE_TRACKING_REF,
            head,
        ],
        check=True,
    )
    return head


def _write_nvd_feed(path: Path, cve_id: str = "CVE-2026-1") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump({"vulnerabilities": [{"cve": {"id": cve_id}}]}, handle)


def _write_osv_archive(
    path: Path,
    osv_ids: str | Sequence[str] = "OSV-2026-1",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    identifiers = (osv_ids,) if isinstance(osv_ids, str) else tuple(osv_ids)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for identifier in identifiers:
            archive.writestr(
                f"{identifier}.json",
                json.dumps(
                    {
                        "id": identifier,
                        "published": "2026-07-18T00:00:00Z",
                        "affected": [
                            {
                                "ranges": [
                                    {
                                        "type": "GIT",
                                        "repo": "https://example.invalid/repo.git",
                                    }
                                ]
                            }
                        ],
                    }
                ),
            )


def _write_campaign(tmp_path: Path) -> runner.RunnerPaths:
    repo_root = tmp_path / "repo"
    grouped_dir = repo_root / ".ai-slop/state/data-refresh/grouped-batches-v1"
    legacy_batch = repo_root / ".ai-slop/state/data-refresh/batches-v1/batch-001.txt"
    collision_inventory = (
        repo_root / ".ai-slop/state/data-refresh/missing-required-repos.txt"
    )
    state_dir = repo_root / ".ai-slop/state/data-refresh/refresh-runner-v1"
    log_dir = repo_root / ".ai-slop/logs/data-refresh"
    result_dir = repo_root / ".cache/results"
    analyzer_dir = repo_root / "cve-analyzer"
    source_root = repo_root / ".cache/sources"
    cvelist_dir = source_root / "cvelistV5"
    ghsa_dir = source_root / "advisory-database"
    gemnasium_dir = source_root / "gemnasium-db"
    nvd_feeds_dir = source_root / "nvd-feeds"
    osv_bulk_dir = source_root / "osv-bulk"
    source_remote_receipt = (
        repo_root / ".ai-slop/state/data-refresh/source-remote-check-now.json"
    )

    grouped_dir.mkdir(parents=True)
    legacy_batch.parent.mkdir(parents=True)
    analyzer_dir.mkdir(parents=True)
    (analyzer_dir / "src/cve_analyzer").mkdir(parents=True)
    (analyzer_dir / "src/cve_analyzer/analyzer.py").write_text(
        "ANALYZER_CONTRACT = 1\n",
        encoding="utf-8",
    )
    (analyzer_dir / "src/cve_analyzer/ai_signatures.py").write_text(
        "SIGNATURES = ['codex']\n",
        encoding="utf-8",
    )
    (analyzer_dir / "pyproject.toml").write_text(
        "[project]\nname = 'cve-analyzer'\n",
        encoding="utf-8",
    )
    (analyzer_dir / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (repo_root / "scripts/web_data").mkdir(parents=True)
    (repo_root / "scripts/run_data_refresh.py").write_text(
        "RUNNER_CONTRACT = 1\n",
        encoding="utf-8",
    )
    (repo_root / "scripts/run_data_refresh.sh").write_text(
        '#!/bin/sh\nexec python3 scripts/run_data_refresh.py "$@"\n',
        encoding="utf-8",
    )
    (repo_root / "scripts/build_data_refresh_batches.py").write_text(
        "BATCH_BUILDER_CONTRACT = 1\n",
        encoding="utf-8",
    )
    (repo_root / "scripts/build_source_delta.py").write_text(
        "SOURCE_DELTA_CONTRACT = 1\n",
        encoding="utf-8",
    )
    (repo_root / "scripts/analysis_contract.py").write_text(
        "ANALYSIS_CONTRACT = 1\n",
        encoding="utf-8",
    )
    (repo_root / "scripts/refresh_source_inputs.py").write_text(
        "SOURCE_REFRESH_CONTRACT = 1\n",
        encoding="utf-8",
    )
    (repo_root / "scripts/generate_web_data.py").write_text(
        "GENERATOR_CONTRACT = 1\n",
        encoding="utf-8",
    )
    (repo_root / "scripts/web_data/filters.py").write_text(
        "GENERATOR_FILTER_CONTRACT = 1\n",
        encoding="utf-8",
    )
    legacy_batch.write_text("CVE-OLD-1\n", encoding="utf-8")

    entries = []
    for number in range(1, 35):
        file_name = f"batch-{number:03d}.txt"
        cve_id = f"CVE-GROUPED-{number}"
        repos = [f"github.com/example/repo-{number}"] if number <= 30 else []
        (grouped_dir / file_name).write_text(f"{cve_id}\n", encoding="utf-8")
        entries.append(
            {
                "batch": number,
                "file": file_name,
                "kind": "large_component" if number == 1 else "repo_affinity",
                "id_count": 1,
                "repo_count": len(repos),
                "component_count": 1 if repos else 0,
                "ids": [cve_id],
                "repos": repos,
                "within_target_limits": number != 1,
            }
        )

    grouped_candidate_ids = sorted(f"CVE-GROUPED-{number}" for number in range(1, 35))

    collision_inventory.write_text(
        "https://github.com/example/repo-2\t/cache/github.com_example_repo-2\tlegacy-origin-collision:/cache/legacy\n",
        encoding="utf-8",
    )
    _init_git_source(cvelist_dir, "https://github.com/CVEProject/cvelistV5.git")
    _init_git_source(ghsa_dir, "https://github.com/github/advisory-database.git")
    (ghsa_dir / "advisories").mkdir()
    (ghsa_dir / "advisories/.keep").write_text("fixture\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(ghsa_dir), "add", "advisories/.keep"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(ghsa_dir),
            "-c",
            "user.name=Refresh Test",
            "-c",
            "user.email=refresh@example.invalid",
            "commit",
            "-q",
            "-m",
            "add advisory root",
        ],
        check=True,
    )
    _init_git_source(
        gemnasium_dir,
        "https://gitlab.com/gitlab-org/advisories-community.git",
    )
    _write_nvd_feed(nvd_feeds_dir / "nvdcve-2.0-2025.json.gz", "CVE-2025-1")
    _write_nvd_feed(nvd_feeds_dir / "nvdcve-2.0-2026.json.gz")
    for year in (2025, 2026):
        (nvd_feeds_dir / f"nvdcve-2.0-{year}.meta").write_text(
            json.dumps({"year": year, "fixture": True}) + "\n",
            encoding="utf-8",
        )
    _write_osv_archive(osv_bulk_dir / "PyPI.zip", grouped_candidate_ids)
    osv_ecosystems_file = osv_bulk_dir / "ecosystems.txt"
    osv_ecosystems_file.write_text("PyPI\n", encoding="utf-8")
    result_dir.mkdir(parents=True)
    paths = runner.RunnerPaths(
        repo_root=repo_root,
        analyzer_dir=analyzer_dir,
        grouped_dir=grouped_dir,
        legacy_batch=legacy_batch,
        collision_inventory=collision_inventory,
        state_dir=state_dir,
        log_dir=log_dir,
        result_dir=result_dir,
        cvelist_dir=cvelist_dir,
        ghsa_dir=ghsa_dir,
        gemnasium_dir=gemnasium_dir,
        nvd_feeds_dir=nvd_feeds_dir,
        osv_bulk_dir=osv_bulk_dir,
        osv_ecosystems_file=osv_ecosystems_file,
        source_remote_receipt=source_remote_receipt,
    )

    git_receipt_entries = []
    for name, source_dir in (
        ("cvelistV5", cvelist_dir),
        ("github-advisory-database", ghsa_dir),
        ("gemnasium-db", gemnasium_dir),
    ):
        head = subprocess.run(
            ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "-C", str(source_dir), "rev-parse", "HEAD^{tree}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        origin = subprocess.run(
            ["git", "-C", str(source_dir), "remote", "get-url", "origin"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        git_receipt_entries.append(
            {
                "branch": "main",
                "head": head,
                "name": name,
                "origin": origin,
                "path": str(source_dir.resolve()),
                "remote_head": head,
                "tree": tree,
            }
        )

    nvd_receipt_entries = []
    for year in (2025, 2026):
        feed = nvd_feeds_dir / f"nvdcve-2.0-{year}.json.gz"
        meta = nvd_feeds_dir / f"nvdcve-2.0-{year}.meta"
        nvd_receipt_entries.append(
            {
                "feed_path": str(feed.resolve()),
                "feed_sha256": runner.file_sha256(feed),
                "feed_size": feed.stat().st_size,
                "meta_path": str(meta.resolve()),
                "meta_sha256": runner.file_sha256(meta),
                "remote_etag": f'"fixture-{year}"',
                "remote_last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
                "remote_meta_sha256": runner.file_sha256(meta),
                "year": year,
            }
        )

    osv_archive = osv_bulk_dir / "PyPI.zip"
    manifest_md5 = hashlib.md5(osv_ecosystems_file.read_bytes(), usedforsecurity=False)
    archive_md5 = hashlib.md5(osv_archive.read_bytes(), usedforsecurity=False)
    source_remote_receipt.parent.mkdir(parents=True, exist_ok=True)
    source_remote_receipt.write_text(
        json.dumps(
            {
                "checked_at_utc": "2026-07-18T12:00:00+00:00",
                "git_sources": git_receipt_entries,
                "nvd_feeds": nvd_receipt_entries,
                "osv_ecosystem_manifest": {
                    "ecosystem_count": 1,
                    "ecosystems": ["PyPI"],
                    "etag": f'"{manifest_md5.hexdigest()}"',
                    "filename": "ecosystems.txt",
                    "generation": "1784375999999999",
                    "last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
                    "md5_base64": base64.b64encode(manifest_md5.digest()).decode(),
                    "path": str(osv_ecosystems_file.resolve()),
                    "remote_size": osv_ecosystems_file.stat().st_size,
                    "sha256": runner.file_sha256(osv_ecosystems_file),
                    "size": osv_ecosystems_file.stat().st_size,
                    "url": "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt",
                },
                "osv_archive_count": 1,
                "osv_archives": [
                    {
                        "crc32c_base64": "AAAAAA==",
                        "etag": f'"{archive_md5.hexdigest()}"',
                        "filename": "PyPI.zip",
                        "generation": "1784376000000000",
                        "last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
                        "md5_base64": base64.b64encode(archive_md5.digest()).decode(),
                        "path": str(osv_archive.resolve()),
                        "remote_size": osv_archive.stat().st_size,
                        "sha256": runner.file_sha256(osv_archive),
                        "size": osv_archive.stat().st_size,
                        "url": "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip",
                    }
                ],
                "remote_parity": True,
                "schema_version": 3,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    refresh_root = grouped_dir.parent
    baseline_dir = refresh_root / "source-before-final"
    baseline_dir.mkdir()
    baseline_candidate = baseline_dir / "new-osv-candidates.txt"
    baseline_candidate.write_text("CVE-OLD-1\n", encoding="utf-8")
    for feed_name in (
        "nvdcve-2.0-2025.json.gz",
        "nvdcve-2.0-2026.json.gz",
    ):
        (baseline_dir / feed_name).write_bytes((nvd_feeds_dir / feed_name).read_bytes())
    for name, source_dir in (
        ("cvelistV5", cvelist_dir),
        ("github-advisory-database", ghsa_dir),
        ("gemnasium-db", gemnasium_dir),
    ):
        head = subprocess.run(
            ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        (baseline_dir / f"{name}.head").write_text(f"{head}\n", encoding="ascii")
    manifest_lines = [
        f"{runner.file_sha256(path)}  {path.name}"
        for path in sorted(baseline_dir.iterdir(), key=lambda item: item.name)
    ]
    (baseline_dir / "SHA256SUMS").write_text(
        "\n".join(manifest_lines) + "\n",
        encoding="utf-8",
    )

    candidate_path = grouped_dir.parent / "new-osv-candidates.txt"
    delta_path = grouped_dir.parent / "source-delta-current.json"
    build_paths = runner._source_delta_paths(
        paths,
        delta_path=delta_path,
        candidate_path=candidate_path,
        discovery_since="2025-05-01",
        corpus_present=False,
    )
    runner.source_delta_builder.build_source_delta(
        build_paths,
        generated_at_utc="2026-07-18T12:00:00+00:00",
    )
    candidate_ids = candidate_path.read_text(encoding="utf-8").splitlines()
    assert candidate_ids == ["CVE-OLD-1", *grouped_candidate_ids]
    source_delta = json.loads(delta_path.read_text(encoding="utf-8"))
    alias_manifest = source_delta["production_discovery"]["alias_class_manifest"]
    subject_classes = {
        item["analysis_subject"]: item["class_id"]
        for item in alias_manifest["classes"]
        if item["scheduled_seed_ids"]
    }
    for entry in entries:
        entry["class_ids"] = [subject_classes[item] for item in entry["ids"]]
    archive_path = osv_bulk_dir / "PyPI.zip"
    (grouped_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": runner.BATCH_MANIFEST_SCHEMA_VERSION,
                "purpose": "formal full alias-class analysis batches",
                "inputs": {
                    "candidate_file": ".ai-slop/state/data-refresh/new-osv-candidates.txt",
                    "candidate_line_count": len(candidate_ids),
                    "candidate_unique_id_count": len(candidate_ids),
                    "candidate_sha256": runner.file_sha256(candidate_path),
                    "excluded_file": ".ai-slop/state/data-refresh/batches-v1/batch-001.txt",
                    "excluded_sha256": runner.file_sha256(legacy_batch),
                    "delta_file": ".ai-slop/state/data-refresh/source-delta-current.json",
                    "delta_sha256": runner.file_sha256(delta_path),
                    "osv_archive_dir": ".cache/sources/osv-bulk",
                    "archives": [
                        {
                            "name": archive_path.name,
                            "size_bytes": archive_path.stat().st_size,
                            "sha256": runner.file_sha256(archive_path),
                        }
                    ],
                    "population_policy": "formal_full",
                    "formal_release_eligible": True,
                    "alias_class_manifest_sha256": alias_manifest["classes_sha256"],
                    "analyzer_contract_sha256": source_delta["analyzer_contract"][
                        "sha256"
                    ],
                    "signature_sha256": source_delta["analyzer_contract"][
                        "signature_sha256"
                    ],
                },
                "verification": {
                    "all_remaining_ids_exactly_once": True,
                    "alias_classes_exactly_once": True,
                    "shared_repositories_are_scheduling_affinity": True,
                    "normal_batches_within_targets": True,
                },
                "batches": entries,
            }
        ),
        encoding="utf-8",
    )

    return paths


def _validated(batch: runner.BatchSpec, _started_at_ns: int) -> dict[str, int]:
    count = len(set(batch.ids))
    return {"result_count": count, "terminal_count": count}


def _rewrite_delta(
    paths: runner.RunnerPaths,
    mutate: Callable[[dict[str, Any]], None],
    *,
    refresh_integrity: bool,
) -> None:
    delta_path = paths.grouped_dir.parent / "source-delta-current.json"
    payload = json.loads(delta_path.read_text(encoding="utf-8"))
    mutate(payload)
    if refresh_integrity:
        payload.pop("integrity_payload_sha256", None)
        unsigned = (json.dumps(payload, indent=2, sort_keys=False) + "\n").encode()
        payload["integrity_payload_sha256"] = runner.hashlib.sha256(
            unsigned
        ).hexdigest()
    delta_path.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    manifest_path = paths.grouped_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["inputs"]["delta_sha256"] = runner.file_sha256(delta_path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _bound_campaign(paths: runner.RunnerPaths) -> runner.CampaignExecution:
    return runner.campaign_execution(
        paths,
        runner.SourceSnapshot(sha256="a" * 64, details={}),
        "b" * 64,
    )


def _receipt_fixture(
    tmp_path: Path,
    *,
    receipt_completed_at: str,
    result_mtime: str,
) -> tuple[
    runner.BatchSpec,
    runner.CampaignExecution,
    str,
    int,
    int,
]:
    started_at = "2026-07-18T12:00:00+00:00"
    batch_completed_at = "2026-07-18T12:00:10+00:00"
    started_at_ns = runner._iso_timestamp_ns(started_at)
    completed_at_ns = runner._iso_timestamp_ns(batch_completed_at)
    result_mtime_ns = runner._iso_timestamp_ns(result_mtime)
    assert started_at_ns is not None
    assert completed_at_ns is not None
    assert result_mtime_ns is not None

    result_dir = tmp_path / "results"
    result_dir.mkdir()
    campaign_root = tmp_path / "campaign"
    campaign = runner.CampaignExecution(
        campaign_id="c" * 64,
        root=campaign_root,
        result_dir=result_dir,
        api_cache_dir=campaign_root / "api-responses",
        derived_cache_root=campaign_root / "derived-cache",
        source_snapshot_sha256="a" * 64,
        contract_sha256="b" * 64,
        litellm_transport_sha256="d" * 64,
        litellm_transport={"schema_version": 1},
        analyzer_contract_sha256="e" * 64,
        signature_sha256="f" * 64,
    )
    batch = runner.BatchSpec(
        key="test-batch",
        path=tmp_path / "batch.txt",
        kind="test",
        ids=("CVE-TEST",),
        repos=frozenset(),
    )
    payload = {
        "cve_id": "CVE-TEST",
        "error_category": "no_fix_commits",
        "repo_ai_activity": [],
        "analysis_stage_receipts": {
            "source_discovery": {"outcome": "resolved"},
            "fix_resolution": {
                "outcome": "exhausted_no_match",
                "configured_methods": ["osv_git_range"],
                "methods": [
                    {
                        "method": "osv_git_range",
                        "outcome": "exhausted_no_match",
                        "input_sha256": "1" * 64,
                        "output_sha256": "2" * 64,
                    }
                ],
            },
            "bic_resolution": {"outcome": "not_applicable"},
            "signal_classification": {"outcome": "not_applicable"},
            "causal_verification": {"outcome": "not_applicable"},
            "adjudication": {"outcome": "not_applicable"},
        },
        "campaign_receipt": {
            "schema_version": 1,
            "campaign_id": campaign.campaign_id,
            "batch": batch.key,
            "started_at": started_at,
            "completed_at": receipt_completed_at,
            "source_snapshot_sha256": campaign.source_snapshot_sha256,
            "contract_sha256": campaign.contract_sha256,
            "litellm_transport_sha256": campaign.litellm_transport_sha256,
            "requested_model": runner.MODEL,
            "reasoning_effort": runner.REASONING_EFFORT,
            "llm_cache_disabled": True,
            "status": "success",
            "failed_stages": [],
            "stages": {
                "phase_c_screening": {"status": "not_applicable"},
                "phase_d_deep_verification": {"status": "not_applicable"},
            },
        },
    }
    result_path = result_dir / "CVE-TEST.json"
    result_path.write_text(json.dumps(payload), encoding="utf-8")
    os.utime(result_path, ns=(result_mtime_ns, result_mtime_ns))
    return batch, campaign, started_at, started_at_ns, completed_at_ns


def test_signal_exhaustion_receipts_bind_every_persisted_bic_subject() -> None:
    actual_subject = ["github.com/owner/repo", "f" * 40, "b" * 40, "src/app.py"]
    wrong_subject = ["github.com/owner/repo", "f" * 40, "c" * 40, "src/app.py"]
    methods = []
    for method_name in runner.SIGNAL_CLASSIFICATION_METHODS:
        subject_receipt = {
            "subject_key": wrong_subject,
            "outcome": "exhausted_no_match",
            "input_sha256": "1" * 64,
            "output_sha256": "2" * 64,
        }
        if method_name == "decomposition":
            subject_receipt["scan_complete"] = True
        methods.append(
            {
                "method": method_name,
                "outcome": "exhausted_no_match",
                "subjects": [subject_receipt],
                "input_sha256": "3" * 64,
                "output_sha256": "4" * 64,
            }
        )
    payload = {
        "analysis_stage_receipts": {
            "source_discovery": {"outcome": "resolved"},
            "fix_resolution": {"outcome": "resolved"},
            "bic_resolution": {"outcome": "resolved"},
            "signal_classification": {
                "outcome": "exhausted_no_match",
                "configured_methods": list(runner.SIGNAL_CLASSIFICATION_METHODS),
                "methods": methods,
                "input_sha256": "5" * 64,
                "output_sha256": "6" * 64,
            },
            "causal_verification": {"outcome": "not_applicable"},
            "adjudication": {"outcome": "not_applicable"},
        },
        "bug_introducing_commits": [
            {
                "repository_identity": actual_subject[0],
                "fix_commit_sha": actual_subject[1],
                "commit": {"sha": actual_subject[2]},
                "blamed_file": actual_subject[3],
            }
        ],
    }

    problem, proof = runner._analysis_stage_receipt_proof(
        payload,
        class_record={},
        campaign=MagicMock(),
        result_sha256="7" * 64,
    )

    assert problem == "signal exhaustion does not cover every causal subject"
    assert proof is None


def test_formal_campaign_orders_each_alias_class_batch_once(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)

    plan = runner.load_plan(paths)

    assert [batch.key for batch in plan] == [
        "legacy-001",
        *(f"grouped-{number:03d}" for number in range(1, 35)),
    ]


def test_formal_campaign_rejects_duplicate_or_mismatched_class_proof(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    manifest_path = paths.grouped_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["batches"][0]["class_ids"] = ["alias-wrong"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(runner.RunnerError, match="class IDs do not match"):
        runner.RefreshRunner(paths)


def test_formal_runner_rejects_explicit_incremental_population(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    refresh_root = paths.grouped_dir.parent
    delta_path = refresh_root / "source-delta-current.json"
    candidate_path = refresh_root / "new-osv-candidates.txt"
    build_paths = runner._source_delta_paths(
        paths,
        delta_path=delta_path,
        candidate_path=candidate_path,
        discovery_since="2025-05-01",
        corpus_present=False,
        population_policy=runner.source_delta_builder.INCREMENTAL_POLICY,
    )
    runner.source_delta_builder.build_source_delta(
        build_paths,
        generated_at_utc="2026-07-18T12:00:00+00:00",
    )
    manifest_path = paths.grouped_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["inputs"]["population_policy"] = "incremental"
    manifest["inputs"]["formal_release_eligible"] = False
    manifest["inputs"]["delta_sha256"] = runner.file_sha256(delta_path)
    for field in (
        "alias_class_manifest_sha256",
        "analyzer_contract_sha256",
        "signature_sha256",
    ):
        manifest["inputs"].pop(field, None)
    manifest["verification"]["each_repo_owned_by_one_batch"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(runner.RunnerError, match="formal campaign requires"):
        runner.RefreshRunner(paths)


def test_dry_run_reuses_the_initial_semantic_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_campaign(tmp_path)
    original = runner.source_delta_builder.build_artifacts
    replay_calls = 0

    def counted_replay(*args: Any, **kwargs: Any) -> Any:
        nonlocal replay_calls
        replay_calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(
        runner.source_delta_builder,
        "build_artifacts",
        counted_replay,
    )
    refresh = runner.RefreshRunner(paths)

    assert refresh.run(dry_run=True, batch_key="legacy-001") == [
        {
            "batch": "openclaw-smoke-gate",
            "status": "gate_ready",
            "smoke_id": "a" * 64,
            "class_count": 30,
        },
        {"batch": "legacy-001", "status": "dry_run"},
    ]
    assert replay_calls == 1


def test_schema_one_source_delta_is_rejected(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    _rewrite_delta(
        paths,
        lambda payload: payload.__setitem__("schema_version", 1),
        refresh_integrity=True,
    )

    with pytest.raises(runner.RunnerError, match="requires schema_version 3"):
        runner.load_plan(paths)


def test_source_delta_integrity_tamper_is_rejected(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    _rewrite_delta(
        paths,
        lambda payload: payload["candidate"].__setitem__("union_exact", False),
        refresh_integrity=False,
    )

    with pytest.raises(runner.RunnerError, match="integrity payload hash is invalid"):
        runner.load_plan(paths)


def test_self_consistent_candidate_proof_tamper_is_rejected(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    _rewrite_delta(
        paths,
        lambda payload: payload["candidate"].__setitem__(
            "output_id_count", payload["candidate"]["output_id_count"] + 1
        ),
        refresh_integrity=True,
    )

    with pytest.raises(runner.RunnerError, match="candidate metadata is inconsistent"):
        runner.load_plan(paths)


def test_semantic_replay_rejects_self_consistent_discovery_omission(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    omitted = "CVE-GROUPED-1"

    def omit_and_reclassify(payload: dict[str, Any]) -> None:
        production = payload["production_discovery"]
        for prefix, field in (
            ("production_discovered", "production_discovered_ids"),
            ("uncached_discovered", "uncached_discovered_ids"),
            ("uncached_osv", "uncached_osv_ids"),
        ):
            values = [value for value in production[field] if value != omitted]
            production[field] = values
            production[f"{prefix}_id_count"] = len(values)
            production[f"{prefix}_ids_sha256"] = runner._id_sequence_sha256(values)
        production["osv_discovered_id_count"] -= 1

        git_entry = payload["git"]["cvelistV5"]
        git_entry["subject_ids"] = sorted([*git_entry["subject_ids"], omitted])
        git_entry["subject_id_count"] = len(git_entry["subject_ids"])
        payload["all_ids"] = sorted([*payload["all_ids"], omitted])
        payload["all_id_count"] = len(payload["all_ids"])

        candidate = payload["candidate"]
        candidate["delta_id_count"] += 1
        candidate["uncached_production_discovery_id_count"] -= 1
        candidate["uncached_production_discovery_added_id_count"] -= 1

    _rewrite_delta(paths, omit_and_reclassify, refresh_integrity=True)

    # Every previously checked count, hash, partition, input guard, candidate,
    # and plan remains internally consistent after the coordinated omission.
    runner.load_plan(paths, replay_delta_semantics=False)
    with pytest.raises(runner.RunnerError, match="semantic replay does not match"):
        runner.load_plan(paths)


def test_missing_manifest_derived_osv_archive_is_rejected_before_campaign_start(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    (paths.osv_bulk_dir / "PyPI.zip").unlink()

    with pytest.raises(runner.RunnerError, match="ecosystem manifest"):
        runner.load_plan(paths)


def test_result_cache_inventory_drift_is_rejected(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    (paths.result_dir / "CVE-CACHED-1.json").write_text(
        json.dumps(
            {
                "cve_id": "CVE-CACHED-1",
                "description": "fixture",
                "severity": "UNKNOWN",
                "fix_commits": [],
                "bug_introducing_commits": [],
                "ai_signals": [],
                "references": [],
                "cwes": [],
                "cvss_score": 0.0,
                "error": "no fix commits",
                "error_category": "no_fix_commits",
                "ai_confidence": 0.0,
                "repo_ai_activity": [],
                "phase_times": {"Phase A (discovery)": 0.0},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        runner.RunnerError,
        match="source delta inputs or result-cache inventory have drifted",
    ):
        runner.load_plan(paths)


@pytest.mark.parametrize(
    "repo",
    [
        "https://github.com/Example/Project.GIT",
        "ssh://git@github.com/Example/Project.GiT",
    ],
)
def test_batch_builder_normalizes_git_suffix_case_insensitively(repo: str) -> None:
    assert batch_builder.normalize_repo(repo) == "github.com/example/project"


def test_command_locks_luna_max_refresh_contract(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    batch = runner.load_plan(paths)[0]

    command = runner.build_command(batch, analyzer_dir=paths.analyzer_dir)
    environment = runner.build_environment(
        {
            "CVE_REASONING_EFFORT": "low",
            "CVE_LLM_MODEL_OVERRIDE": "wrong-model",
            "CVE_LLM_STRICT_MODEL": "0",
            "CVE_LLM_CONCURRENCY": "99",
            "PYTHONHOME": "/tmp/attacker-home",
            "PYTHONPATH": "/tmp/attacker-path",
            "KEEP": "yes",
        }
    )
    source = runner.capture_source_snapshot(paths)
    campaign = runner.campaign_execution(
        paths,
        source,
        runner.contract_sha256(paths),
    )
    campaign_environment = runner.build_environment(
        {
            "LITELLM_API_BASE": "https://litellm.example.invalid/v1",
            "LITELLM_API_KEY": "fixture-proxy-key",
        },
        campaign=campaign,
        batch_key=batch.key,
        started_at="2026-07-18T12:00:00+00:00",
    )

    assert command == [
        sys.executable,
        "-I",
        str(paths.analyzer_dir.resolve() / "src" / "cve_analyzer" / "cli.py"),
        "--no-cache",
        "batch",
        "--cve-list",
        str(batch.path),
        "--recheck",
        "--force-verify",
        "--workers",
        "32",
        "--no-deep-discovery",
        "--llm-verify",
        "--llm-model",
        "gpt-5.6-luna",
        "--verify-model",
        "gpt-5.6-luna",
        "--coding-agent",
        "off",
    ]
    assert command.count("--force-verify") == 1
    assert environment["CVE_REASONING_EFFORT"] == "max"
    assert environment["CVE_ANALYZER_FROZEN_LOCAL_SOURCES"] == "1"
    assert environment["CVE_LLM_MODEL_OVERRIDE"] == "gpt-5.6-luna"
    assert environment["CVE_LLM_STRICT_MODEL"] == "1"
    assert environment["CVE_LLM_DISABLE_CACHE"] == "1"
    assert environment["CVE_LLM_CONCURRENCY"] == "4"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert "PYTHONHOME" not in environment
    assert "PYTHONPATH" not in environment
    assert environment["KEEP"] == "yes"
    assert campaign_environment["CVE_ANALYZER_RESULT_DIR"] == str(campaign.result_dir)
    assert campaign_environment["CVE_ANALYZER_API_CACHE_DIR"] == str(
        campaign.api_cache_dir
    )
    assert campaign_environment["CVE_ANALYZER_DERIVED_CACHE_ROOT"] == str(
        campaign.derived_cache_root
    )
    assert campaign_environment["CVE_ANALYZER_CAMPAIGN_ID"] == campaign.campaign_id
    assert campaign_environment["CVE_ANALYZER_CAMPAIGN_BATCH"] == batch.key
    assert campaign_environment["CVE_ANALYZER_SOURCE_SHA256"] == source.sha256
    assert campaign_environment["CVE_ANALYZER_LITELLM_TRANSPORT_SHA256"] == (
        campaign.litellm_transport_sha256
    )
    assert campaign_environment["CVE_ANALYZER_ALIAS_CLASS_SOURCE_DELTA"] == (
        campaign.alias_class_delta_path
    )
    assert campaign_environment["CVE_ANALYZER_ALIAS_CLASS_MANIFEST_SHA256"] == (
        campaign.alias_class_manifest_sha256
    )
    assert campaign.litellm_transport["api_key_configured"] is True
    assert campaign.litellm_transport["api_modes"] == ["responses"]
    assert campaign.litellm_transport["max_concurrent_requests"] == 4
    assert campaign.litellm_transport["request_timeout_seconds"] == 180
    assert campaign.litellm_transport["max_reasoning_output_tokens_floor"] == 16_384


def test_litellm_execution_limits_are_part_of_campaign_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_campaign(tmp_path)
    bound_campaign = _bound_campaign(paths)

    monkeypatch.setattr(runner, "LLM_CONCURRENCY", runner.LLM_CONCURRENCY + 1)
    rebound_campaign = _bound_campaign(paths)

    assert rebound_campaign.campaign_id != bound_campaign.campaign_id
    assert rebound_campaign.litellm_transport_sha256 != (
        bound_campaign.litellm_transport_sha256
    )


@pytest.mark.parametrize(
    "drifted_environment",
    [
        {
            "LITELLM_API_BASE": "https://other-litellm.example.invalid/v1",
            "LITELLM_API_KEY": "fixture-proxy-key",
        },
        {
            "LITELLM_URL": "https://litellm.example.invalid/v1",
            "LITELLM_API_KEY": "fixture-proxy-key",
        },
    ],
    ids=["base-url", "base-alias"],
)
def test_litellm_transport_drift_rebinds_campaign_and_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drifted_environment: dict[str, str],
) -> None:
    paths = _write_campaign(tmp_path)
    bound_campaign = _bound_campaign(paths)

    for name in (
        "LITELLM_API_BASE",
        "LITELLM_URL",
        "EXTERNAL_LITELLM_API_BASE",
        "LITELLM_API_KEY",
        "LITELLM_KEY",
        "EXTERNAL_LITELLM_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in drifted_environment.items():
        monkeypatch.setenv(name, value)

    rebound_campaign = _bound_campaign(paths)

    assert rebound_campaign.campaign_id != bound_campaign.campaign_id
    assert (
        rebound_campaign.litellm_transport_sha256
        != bound_campaign.litellm_transport_sha256
    )
    with pytest.raises(
        runner.RunnerError,
        match="LiteLLM campaign transport changed after binding",
    ):
        runner.build_environment(
            drifted_environment,
            campaign=bound_campaign,
            batch_key="legacy-001",
            started_at="2026-07-18T12:00:00+00:00",
        )


def test_completed_marker_is_rerun_when_litellm_transport_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []

    first = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )
    assert first.run(batch_key="legacy-001") == [
        {"batch": "legacy-001", "status": "completed"}
    ]
    first_marker = json.loads(
        (paths.state_dir / "completed/legacy-001.json").read_text(encoding="utf-8")
    )

    monkeypatch.setenv(
        "LITELLM_API_BASE",
        "https://replacement-litellm.example.invalid/v1",
    )
    second = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )

    assert second.run(batch_key="legacy-001") == [
        {"batch": "legacy-001", "status": "completed"}
    ]
    second_marker = json.loads(
        (paths.state_dir / "completed/legacy-001.json").read_text(encoding="utf-8")
    )
    assert len(calls) == 2
    assert second_marker["campaign_id"] != first_marker["campaign_id"]
    assert (
        second_marker["litellm_transport_sha256"]
        != (first_marker["litellm_transport_sha256"])
    )


def test_missing_litellm_configuration_fails_campaign_construction_early(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_campaign(tmp_path)
    for name in (
        "LITELLM_API_BASE",
        "LITELLM_URL",
        "EXTERNAL_LITELLM_API_BASE",
        "LITELLM_API_KEY",
        "LITELLM_KEY",
        "EXTERNAL_LITELLM_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(
        runner.RunnerError,
        match="LiteLLM campaign transport is not configured",
    ):
        _bound_campaign(paths)

    assert not (paths.state_dir.parent / "campaigns-v1").exists()


def test_dry_run_fails_closed_without_litellm_transport_and_writes_no_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_campaign(tmp_path)
    refresh = runner.RefreshRunner(paths)
    for name in (
        "LITELLM_API_BASE",
        "LITELLM_URL",
        "EXTERNAL_LITELLM_API_BASE",
        "LITELLM_API_KEY",
        "LITELLM_KEY",
        "EXTERNAL_LITELLM_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(
        runner.RunnerError,
        match="LiteLLM campaign transport is not configured",
    ):
        refresh.run(dry_run=True, limit=1)

    assert not paths.state_dir.exists()


def test_collision_batches_fail_closed_before_execution(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    legacy_path = Path(
        paths.collision_inventory.read_text(encoding="utf-8")
        .split("\t", 2)[2]
        .split(":", 1)[1]
        .strip()
    )
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        cache_resolver=lambda _url: legacy_path,
        batch_validator=_validated,
    )

    with pytest.raises(runner.RunnerError, match=r"grouped-002.*repo-2"):
        refresh.run(batch_key="grouped-002")

    assert calls == []
    assert not (paths.state_dir / "completed/grouped-002.json").exists()
    assert (paths.state_dir / f"locks/{runner.CAMPAIGN_LOCK_KEY}.lock").is_file()


def test_verified_host_qualified_collision_path_runs_batch(tmp_path: Path) -> None:
    """Static collision entries are safe once the resolver isolates the host."""
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    expected_new = Path(
        paths.collision_inventory.read_text(encoding="utf-8").split("\t", 2)[1]
    )
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        cache_resolver=lambda _url: expected_new,
        batch_validator=_validated,
    )

    report = refresh.run(batch_key="grouped-002")

    assert report == [{"batch": "grouped-002", "status": "completed"}]
    assert len(calls) == 1


def test_verified_v2_identity_collision_path_runs_batch(tmp_path: Path) -> None:
    """Digest-backed cache identities supersede historical flattened paths."""
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    v2_path = Path("/cache/v2_github.com_repo-2_" + "a" * 64)
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        cache_resolver=lambda _url: v2_path,
        batch_validator=_validated,
    )

    report = refresh.run(batch_key="grouped-002")

    assert report == [{"batch": "grouped-002", "status": "completed"}]
    assert len(calls) == 1


def test_explicit_collision_skip_omits_risky_batch_and_runs_next_safe_batch(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    legacy_path = Path(
        paths.collision_inventory.read_text(encoding="utf-8")
        .split("\t", 2)[2]
        .split(":", 1)[1]
        .strip()
    )
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        cache_resolver=lambda _url: legacy_path,
        batch_validator=_validated,
    )

    report = refresh.run(limit=3, skip_legacy_origin_collisions=True)

    assert [entry["batch"] for entry in report if entry["status"] == "completed"] == [
        "legacy-001",
        "grouped-001",
        "grouped-003",
    ]
    assert any(
        entry == {"batch": "grouped-002", "status": "collision_skipped"}
        for entry in report
    )
    assert len(calls) == 3


def test_success_writes_atomic_marker_and_rerun_resumes_without_execution(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    free_values = iter(
        [
            runner.MIN_FREE_BYTES + 10,
            runner.MIN_FREE_BYTES + 9,
        ]
    )
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: next(free_values),
        batch_validator=_validated,
    )

    first_report = refresh.run(batch_key="legacy-001")
    marker_path = paths.state_dir / "completed/legacy-001.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))

    assert first_report == [{"batch": "legacy-001", "status": "completed"}]
    assert marker["batch"] == "legacy-001"
    assert marker["schema_version"] == runner.MARKER_SCHEMA_VERSION
    assert marker["batch_sha256"] == runner.file_sha256(paths.legacy_batch)
    assert marker["contract_sha256"] == runner.contract_sha256(paths)
    assert (
        marker["source_snapshot_sha256"] == runner.capture_source_snapshot(paths).sha256
    )
    assert marker["source_snapshot"] == runner.capture_source_snapshot(paths).details
    assert marker["campaign_id"]
    assert marker["campaign_result_dir"].endswith(f"/{marker['campaign_id']}/results")
    assert marker["campaign_api_cache_dir"].endswith(
        f"/{marker['campaign_id']}/api-responses"
    )
    assert marker["litellm_transport"]["max_concurrent_requests"] == 4
    assert marker["litellm_transport"]["request_timeout_seconds"] == 180
    assert marker["litellm_transport"]["max_reasoning_output_tokens_floor"] == 16_384
    assert marker["free_bytes_before"] == runner.MIN_FREE_BYTES + 10
    assert marker["free_bytes_after"] == runner.MIN_FREE_BYTES + 9
    assert not list(marker_path.parent.glob("*.tmp"))

    second_report = refresh.run(batch_key="legacy-001")

    assert second_report == [{"batch": "legacy-001", "status": "already_completed"}]
    assert len(calls) == 1


def test_failure_keeps_stable_log_and_leaves_no_completion_marker(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda _command, **_kwargs: 17,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )

    with pytest.raises(runner.RunnerError, match="exit code 17"):
        refresh.run(batch_key="legacy-001")

    assert (paths.log_dir / "legacy-001.log").exists()
    assert not (paths.state_dir / "completed/legacy-001.json").exists()


@pytest.mark.parametrize("low_check", ["before", "after"])
def test_disk_floor_fails_closed_without_marker(tmp_path: Path, low_check: str) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    if low_check == "before":
        free_values = iter([runner.MIN_FREE_BYTES - 1])
    else:
        free_values = iter([runner.MIN_FREE_BYTES + 1, runner.MIN_FREE_BYTES - 1])
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: next(free_values),
        batch_validator=_validated,
    )

    with pytest.raises(runner.RunnerError, match=f"disk floor {low_check}"):
        refresh.run(batch_key="legacy-001")

    assert len(calls) == (0 if low_check == "before" else 1)
    assert not (paths.state_dir / "completed/legacy-001.json").exists()


def test_dry_run_and_limit_do_not_execute_or_write_state(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: (_ for _ in ()).throw(
            AssertionError("dry run checked disk")
        ),
        batch_validator=_validated,
    )

    report = refresh.run(
        dry_run=True,
        limit=3,
        skip_legacy_origin_collisions=True,
    )

    assert [entry["batch"] for entry in report if entry["status"] == "dry_run"] == [
        "legacy-001",
        "grouped-001",
        "grouped-003",
    ]
    assert calls == []
    assert not paths.state_dir.exists()


def test_changed_batch_after_completion_fails_closed(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda _command, **_kwargs: 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )
    refresh.run(batch_key="legacy-001")
    paths.legacy_batch.write_text("CVE-CHANGED\n", encoding="utf-8")

    with pytest.raises(runner.RunnerError, match="campaign plan changed"):
        refresh.run(batch_key="legacy-001")


def test_plan_drift_after_initialization_fails_before_execution(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )
    paths.legacy_batch.write_text("CVE-CHANGED\n", encoding="utf-8")

    with pytest.raises(runner.RunnerError, match="campaign plan changed"):
        refresh.run(batch_key="legacy-001")

    assert calls == []
    assert not (paths.state_dir / "completed/legacy-001.json").exists()


def test_contract_drift_after_initialization_fails_before_execution(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )
    contract_file = paths.analyzer_dir / "src/cve_analyzer/analyzer.py"
    contract_file.write_text("ANALYZER_CONTRACT = 2\n", encoding="utf-8")

    with pytest.raises(runner.RunnerError, match="campaign contract changed"):
        refresh.run(batch_key="legacy-001")

    assert calls == []
    assert not (paths.state_dir / "completed/legacy-001.json").exists()


@pytest.mark.parametrize(
    "relative_path",
    [
        "cve-analyzer/src/cve_analyzer/analyzer.py",
        "cve-analyzer/pyproject.toml",
        "cve-analyzer/uv.lock",
        "scripts/run_data_refresh.py",
        "scripts/refresh_source_inputs.py",
        "scripts/generate_web_data.py",
        "scripts/web_data/filters.py",
    ],
)
def test_contract_change_invalidates_old_marker_and_reruns(
    tmp_path: Path,
    relative_path: str,
) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []

    def execute(command: list[str], **_kwargs: object) -> int:
        calls.append(command)
        return 0

    first = runner.RefreshRunner(
        paths,
        command_runner=execute,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )
    first.run(batch_key="legacy-001")
    old_marker = json.loads(
        (paths.state_dir / "completed/legacy-001.json").read_text(encoding="utf-8")
    )

    contract_file = paths.repo_root / relative_path
    contract_file.write_text(
        contract_file.read_text(encoding="utf-8") + "# changed\n",
        encoding="utf-8",
    )
    if relative_path.startswith("cve-analyzer/"):
        with pytest.raises(
            runner.RunnerError, match="analyzer contract epoch is stale"
        ):
            runner.RefreshRunner(
                paths,
                command_runner=execute,
                disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
                batch_validator=_validated,
            )
        assert len(calls) == 1
        return

    second = runner.RefreshRunner(
        paths,
        command_runner=execute,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )

    report = second.run(batch_key="legacy-001")
    new_marker = json.loads(
        (paths.state_dir / "completed/legacy-001.json").read_text(encoding="utf-8")
    )

    assert report == [{"batch": "legacy-001", "status": "completed"}]
    assert len(calls) == 2
    assert new_marker["contract_sha256"] != old_marker["contract_sha256"]


def test_old_marker_schema_is_invalidated_and_replaced(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )
    refresh.run(batch_key="legacy-001")
    marker_path = paths.state_dir / "completed/legacy-001.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema_version"] = 3
    marker.pop("contract_sha256")
    marker_path.write_text(json.dumps(marker), encoding="utf-8")

    report = refresh.run(batch_key="legacy-001")

    assert report == [{"batch": "legacy-001", "status": "completed"}]
    assert len(calls) == 2
    assert (
        json.loads(marker_path.read_text(encoding="utf-8"))["schema_version"]
        == runner.MARKER_SCHEMA_VERSION
    )


def test_missing_contract_input_fails_closed(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    (paths.analyzer_dir / "uv.lock").unlink()

    with pytest.raises(runner.RunnerError, match=r"contract input.*uv\.lock"):
        runner.RefreshRunner(paths)


def test_contract_change_during_batch_withholds_completion_marker(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    contract_file = paths.analyzer_dir / "src/cve_analyzer/analyzer.py"

    def mutate_contract(_command: list[str], **_kwargs: object) -> int:
        contract_file.write_text("ANALYZER_CONTRACT = 2\n", encoding="utf-8")
        return 0

    refresh = runner.RefreshRunner(
        paths,
        command_runner=mutate_contract,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )

    with pytest.raises(
        runner.RunnerError, match=r"contract changed.*completion withheld"
    ):
        refresh.run(batch_key="legacy-001")

    assert not (paths.state_dir / "completed/legacy-001.json").exists()


def test_plan_change_during_batch_withholds_completion_marker(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)

    def mutate_plan(_command: list[str], **_kwargs: object) -> int:
        paths.legacy_batch.write_text("CVE-CHANGED\n", encoding="utf-8")
        return 0

    refresh = runner.RefreshRunner(
        paths,
        command_runner=mutate_plan,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )

    with pytest.raises(
        runner.RunnerError,
        match=r"campaign plan changed.*completion withheld",
    ):
        refresh.run(batch_key="legacy-001")

    assert not (paths.state_dir / "completed/legacy-001.json").exists()


def test_source_snapshot_captures_canonical_git_and_archive_hashes(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)

    snapshot = runner.capture_source_snapshot(paths)

    assert len(snapshot.sha256) == 64
    assert snapshot.details["schema_version"] == 2
    assert set(snapshot.details["git_mirrors"]) == {
        "cvelist_v5",
        "gemnasium_advisories",
        "github_advisories",
    }
    for source in snapshot.details["git_mirrors"].values():
        assert len(source["head"]) in {40, 64}
        assert len(source["tree"]) in {40, 64}
        assert source["clean"] is True
    assert [entry["name"] for entry in snapshot.details["nvd_feeds"]] == [
        "nvdcve-2.0-2025.json.gz",
        "nvdcve-2.0-2026.json.gz",
    ]
    assert [entry["name"] for entry in snapshot.details["osv_archives"]] == ["PyPI.zip"]
    remote_cutoff = snapshot.details["remote_cutoff"]
    assert remote_cutoff["checked_at_utc"] == "2026-07-18T12:00:00+00:00"
    assert remote_cutoff["remote_parity"] is True
    assert remote_cutoff["receipt"]["remote_parity"] is True
    assert remote_cutoff["receipt_file"]["sha256"] == runner.file_sha256(
        paths.source_remote_receipt
    )
    for entry in [
        *snapshot.details["nvd_feeds"],
        *snapshot.details["osv_archives"],
    ]:
        assert len(entry["sha256"]) == 64
        assert entry["size_bytes"] > 0


@pytest.mark.parametrize(
    "mutation",
    ["extra_top_level", "missing_git_mirror", "malformed_nvd", "osv_mismatch"],
)
def test_source_snapshot_validator_requires_exact_source_inventory_schema(
    tmp_path: Path,
    mutation: str,
) -> None:
    details = json.loads(
        json.dumps(runner.capture_source_snapshot(_write_campaign(tmp_path)).details)
    )
    if mutation == "extra_top_level":
        details["self_asserted"] = True
    elif mutation == "missing_git_mirror":
        details["git_mirrors"].pop("github_advisories")
    elif mutation == "malformed_nvd":
        details["nvd_feeds"][0]["unexpected"] = "field"
    else:
        details["osv_ecosystem_manifest"]["archive_names"] = ["Other.zip"]

    with pytest.raises(runner.RunnerError, match="source snapshot"):
        runner.validate_source_snapshot_details(details)


def test_refresh_runner_caches_successful_fsck_per_instance_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_campaign(tmp_path)
    original = runner._git_output
    fsck_calls = 0

    def counted_git_output(source_dir: Path, *arguments: str) -> str:
        nonlocal fsck_calls
        if arguments and arguments[0] == "fsck":
            fsck_calls += 1
        return original(source_dir, *arguments)

    monkeypatch.setattr(runner, "_git_output", counted_git_output)
    first_runner = runner.RefreshRunner(paths)

    first = first_runner._capture_source_snapshot()
    second = first_runner._capture_source_snapshot()

    assert first == second
    assert fsck_calls == 3

    second_runner = runner.RefreshRunner(paths)
    assert second_runner._capture_source_snapshot() == first
    assert fsck_calls == 6


def test_git_source_capture_ignores_ambient_repository_redirects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_campaign(tmp_path)
    source_head = subprocess.check_output(
        ["git", "-C", str(paths.cvelist_dir), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    redirected = tmp_path / "redirected-git"
    _init_git_source(redirected, runner._CVELIST_ORIGIN)
    subprocess.run(
        [
            "git",
            "-C",
            str(redirected),
            "-c",
            "user.name=Refresh Test",
            "-c",
            "user.email=refresh@example.invalid",
            "commit",
            "--amend",
            "-q",
            "-m",
            "redirected fixture",
        ],
        check=True,
    )
    redirected_head = subprocess.check_output(
        ["git", "-C", str(redirected), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    assert redirected_head != source_head

    monkeypatch.setenv("GIT_DIR", str(redirected / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(paths.cvelist_dir))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.filemode")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")

    details = runner._git_source_details(
        paths.cvelist_dir,
        label="cvelistV5",
        expected_origin=runner._CVELIST_ORIGIN,
    )

    assert details["head"] == source_head
    assert details["head"] != redirected_head


def test_openclaw_checkout_contract_binds_clean_current_full_clone(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "openclaw"
    head = _init_current_openclaw_checkout(checkout)

    contract = runner._openclaw_checkout_contract(lambda _url: checkout)

    assert contract == {
        "repository_identity": runner._OPENCLAW_REPOSITORY_MARKER,
        "origin": runner._OPENCLAW_ORIGIN,
        "branch": runner._OPENCLAW_BRANCH,
        "remote_tracking_ref": runner._OPENCLAW_REMOTE_TRACKING_REF,
        "head_sha": head,
        "remote_tracking_sha": head,
        "tree_sha": subprocess.check_output(
            ["git", "-C", str(checkout), "rev-parse", "HEAD^{tree}"], text=True
        ).strip(),
        "cache_path": str(checkout.resolve()),
        "clean": True,
        "full_clone": True,
        "head_matches_remote_tracking": True,
        "git_integrity": "fsck_full_strict",
        "tracked_symlink_policy": "relative_target_to_tracked_regular_file",
    }


def test_openclaw_checkout_contract_rejects_escaping_tracked_symlink(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "openclaw"
    _init_current_openclaw_checkout(checkout)
    (checkout / "CLAUDE.md").unlink()
    (checkout / "CLAUDE.md").symlink_to("../outside")
    subprocess.run(
        ["git", "-C", str(checkout), "add", "CLAUDE.md"],
        check=True,
    )
    _commit_fixture(checkout, "unsafe tracked symlink")
    head = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
    ).strip()
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "update-ref",
            runner._OPENCLAW_REMOTE_TRACKING_REF,
            head,
        ],
        check=True,
    )

    with pytest.raises(runner.RunnerError, match="unsafe tracked symlink"):
        runner._openclaw_checkout_contract(lambda _url: checkout)


def test_openclaw_checkout_contract_rejects_stale_head(tmp_path: Path) -> None:
    checkout = tmp_path / "openclaw"
    _init_current_openclaw_checkout(checkout)
    (checkout / "source.json").write_text('{"source": "new"}\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "source.json"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "-c",
            "user.name=Refresh Test",
            "-c",
            "user.email=refresh@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "new local head",
        ],
        check=True,
    )

    with pytest.raises(runner.RunnerError, match="HEAD is stale"):
        runner._openclaw_checkout_contract(lambda _url: checkout)


def test_prepare_openclaw_checkout_fetches_and_fast_forwards_advertised_tip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "openclaw"
    old_head = _init_current_openclaw_checkout(checkout)
    tree = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD^{tree}"], text=True
    ).strip()
    commit_environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Remote Fixture",
        "GIT_AUTHOR_EMAIL": "remote@example.invalid",
        "GIT_COMMITTER_NAME": "Remote Fixture",
        "GIT_COMMITTER_EMAIL": "remote@example.invalid",
    }
    remote_tip = subprocess.check_output(
        ["git", "-C", str(checkout), "commit-tree", tree, "-p", old_head],
        input="remote fixture tip\n",
        text=True,
        env=commit_environment,
    ).strip()

    def fetch_tip(path: Path) -> str:
        assert path == checkout.resolve()
        subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "update-ref",
                runner._OPENCLAW_REMOTE_TRACKING_REF,
                remote_tip,
            ],
            check=True,
        )
        return remote_tip

    monkeypatch.setattr(runner, "_fetch_openclaw_remote_tip", fetch_tip)

    contract = runner._prepare_openclaw_checkout(lambda _url: checkout)

    assert contract["head_sha"] == remote_tip
    assert contract["remote_tracking_sha"] == remote_tip
    assert contract["remote_tip_sha"] == remote_tip
    assert contract["remote_tip_fetch_verified"] is True


def test_openclaw_checkout_contract_rejects_dirty_worktree(tmp_path: Path) -> None:
    checkout = tmp_path / "openclaw"
    _init_current_openclaw_checkout(checkout)
    (checkout / "source.json").write_text('{"source": "dirty"}\n', encoding="utf-8")

    with pytest.raises(runner.RunnerError, match="Git source is dirty"):
        runner._openclaw_checkout_contract(lambda _url: checkout)


def test_openclaw_checkout_contract_rejects_wrong_origin(tmp_path: Path) -> None:
    checkout = tmp_path / "openclaw"
    _init_current_openclaw_checkout(checkout)
    subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "remote",
            "set-url",
            "origin",
            "https://github.com/example/not-openclaw",
        ],
        check=True,
    )

    with pytest.raises(runner.RunnerError, match="unexpected origin"):
        runner._openclaw_checkout_contract(lambda _url: checkout)


def test_openclaw_checkout_contract_rejects_symlink(tmp_path: Path) -> None:
    checkout = tmp_path / "openclaw"
    _init_current_openclaw_checkout(checkout)
    link = tmp_path / "openclaw-link"
    link.symlink_to(checkout, target_is_directory=True)

    with pytest.raises(runner.RunnerError, match="symlink"):
        runner._openclaw_checkout_contract(lambda _url: link)


@pytest.mark.parametrize(
    "index_flag",
    ["--assume-unchanged", "--skip-worktree"],
)
def test_git_source_capture_rejects_index_flags_that_hide_forged_worktree_bytes(
    tmp_path: Path,
    index_flag: str,
) -> None:
    paths = _write_campaign(tmp_path)
    subprocess.run(
        [
            "git",
            "-C",
            str(paths.cvelist_dir),
            "update-index",
            index_flag,
            "source.json",
        ],
        check=True,
    )
    (paths.cvelist_dir / "source.json").write_text(
        '{"source":"forged"}\n',
        encoding="utf-8",
    )
    status = subprocess.check_output(
        [
            "git",
            "-C",
            str(paths.cvelist_dir),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        text=True,
    )
    assert status == ""

    with pytest.raises(runner.RunnerError, match="index flags"):
        runner._git_source_details(
            paths.cvelist_dir,
            label="cvelistV5",
            expected_origin=runner._CVELIST_ORIGIN,
        )


def test_git_source_capture_rejects_ignored_untracked_advisory_files(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    (paths.cvelist_dir / ".git/info/exclude").write_text(
        "ignored/\n",
        encoding="utf-8",
    )
    ignored = paths.cvelist_dir / "ignored/CVE-2026-9000.json"
    ignored.parent.mkdir()
    ignored.write_text('{"id":"CVE-2026-9000"}\n', encoding="utf-8")
    status = subprocess.check_output(
        [
            "git",
            "-C",
            str(paths.cvelist_dir),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        text=True,
    )
    assert status == ""

    with pytest.raises(runner.RunnerError, match="worktree differs"):
        runner._git_source_details(
            paths.cvelist_dir,
            label="cvelistV5",
            expected_origin=runner._CVELIST_ORIGIN,
        )


def test_git_output_uses_a_strict_environment_whitelist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dangerous_environment = {
        "GIT_DIR": "redirected-git-dir",
        "GIT_WORK_TREE": "redirected-worktree",
        "GIT_INDEX_FILE": "redirected-index",
        "GIT_OBJECT_DIRECTORY": "redirected-objects",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "redirected-alternates",
        "GIT_NAMESPACE": "redirected-namespace",
        "GIT_REPLACE_REF_BASE": "refs/redirected",
        "GIT_SHALLOW_FILE": "redirected-shallow-file",
        "GIT_CEILING_DIRECTORIES": "redirected-ceiling",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.worktree",
        "GIT_CONFIG_VALUE_0": "redirected-config-worktree",
        "PATH": "/ambient/malicious/path",
        "UNRELATED_SECRET": "must-not-reach-git",
    }
    for name, value in dangerous_environment.items():
        monkeypatch.setenv(name, value)

    invocation: dict[str, Any] = {}

    def run_git(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        invocation["command"] = command
        invocation["environment"] = kwargs["env"]
        invocation["max_stdout_bytes"] = kwargs["max_stdout_bytes"]
        invocation["max_stderr_bytes"] = kwargs["max_stderr_bytes"]
        return subprocess.CompletedProcess(command, 0, "captured\n", "")

    monkeypatch.setattr(runner, "_run_argv_bounded", run_git)
    source = tmp_path / "source"

    assert runner._git_output(source, "rev-parse", "HEAD") == "captured"
    command = invocation["command"]
    assert command[0] == runner.source_delta_builder.system_git_binary()
    assert command[1] == "--no-replace-objects"
    assert command[2] == "--literal-pathspecs"
    assert command[-4:] == ["-C", str(source), "rev-parse", "HEAD"]
    assert ["-c", "core.fsmonitor=false"] == command[3:5]
    assert f"core.hooksPath={os.devnull}" in command
    assert (
        invocation["max_stdout_bytes"]
        == runner.source_delta_builder.MAX_GIT_STDOUT_BYTES
    )
    assert (
        invocation["max_stderr_bytes"]
        == runner.source_delta_builder.MAX_GIT_STDERR_BYTES
    )
    assert int(invocation["max_stdout_bytes"]) > 72_107_801
    environment = invocation["environment"]
    assert set(environment) == {
        "GIT_ALLOW_PROTOCOL",
        "GIT_ASKPASS",
        "GIT_ATTR_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_GRAFT_FILE",
        "GIT_NO_LAZY_FETCH",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OPTIONAL_LOCKS",
        "GIT_PAGER",
        "GIT_TERMINAL_PROMPT",
        "LC_ALL",
        "PATH",
    }
    assert environment["GIT_ALLOW_PROTOCOL"] == "file:https"
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["PATH"] == os.defpath
    assert (set(dangerous_environment) - {"PATH"}).isdisjoint(environment)


@pytest.mark.parametrize(
    "incomplete_flag",
    [
        "stdout_limit_exceeded",
        "stderr_limit_exceeded",
        "stdout_drain_incomplete",
        "stderr_drain_incomplete",
    ],
)
def test_git_output_rejects_limits_and_incomplete_drains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    incomplete_flag: str,
) -> None:
    def bounded(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        result = subprocess.CompletedProcess(command, 0, "partial", "")
        setattr(result, incomplete_flag, True)
        return result

    monkeypatch.setattr(runner, "_run_argv_bounded", bounded)

    with pytest.raises(runner.RunnerError, match="output was incomplete"):
        runner._git_output(tmp_path, "status")


@pytest.mark.parametrize(
    ("indirection", "error_pattern"),
    [
        ("alternates", "alternates"),
        ("http-alternates", "http-alternates"),
        ("grafts", "grafts"),
        ("replace", "replace"),
        ("shallow", "shallow"),
        ("promisor-pack", "promisor"),
        ("partial-clone", "partial"),
        ("promisor-config", "promisor"),
    ],
)
def test_git_source_capture_rejects_object_indirections(
    tmp_path: Path,
    indirection: str,
    error_pattern: str,
) -> None:
    paths = _write_campaign(tmp_path)
    git_dir = paths.cvelist_dir / ".git"
    if indirection in {"alternates", "http-alternates"}:
        control = git_dir / "objects/info" / indirection
        control.parent.mkdir(parents=True, exist_ok=True)
        control.write_text(
            str(paths.ghsa_dir / ".git/objects") + "\n",
            encoding="utf-8",
        )
    elif indirection == "grafts":
        control = git_dir / "info/grafts"
        control.parent.mkdir(parents=True, exist_ok=True)
        control.write_text("0" * 40 + "\n", encoding="ascii")
    elif indirection == "replace":
        head = subprocess.check_output(
            ["git", "-C", str(paths.cvelist_dir), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        control = git_dir / "refs/replace" / head
        control.parent.mkdir(parents=True, exist_ok=True)
        control.write_text(head + "\n", encoding="ascii")
    elif indirection == "shallow":
        head = subprocess.check_output(
            ["git", "-C", str(paths.cvelist_dir), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        (git_dir / "shallow").write_text(head + "\n", encoding="ascii")
    elif indirection == "promisor-pack":
        (git_dir / "objects/pack/injected.promisor").write_text(
            "promisor\n",
            encoding="ascii",
        )
    elif indirection == "partial-clone":
        subprocess.run(
            [
                "git",
                "-C",
                str(paths.cvelist_dir),
                "config",
                "core.repositoryFormatVersion",
                "1",
            ],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(paths.cvelist_dir),
                "config",
                "extensions.partialClone",
                "origin",
            ],
            check=True,
        )
    else:
        subprocess.run(
            [
                "git",
                "-C",
                str(paths.cvelist_dir),
                "config",
                "remote.origin.promisor",
                "true",
            ],
            check=True,
        )

    with pytest.raises(runner.RunnerError, match=error_pattern):
        runner._git_source_details(
            paths.cvelist_dir,
            label="cvelistV5",
            expected_origin=runner._CVELIST_ORIGIN,
        )


def test_captured_schema3_remote_cutoff_is_accepted_by_release_receipt_writer(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path / "campaign")
    remote_cutoff = runner.capture_source_snapshot(paths).details["remote_cutoff"]
    output_dir = tmp_path / "published"
    stats = {
        "generated_at": "2026-07-18T12:00:00+00:00",
        "total_cves": 0,
        "total_analyzed": 1,
        "with_fix_commits": 0,
        "coverage_from": "2025-05-01",
        "coverage_to": "",
        "by_tool": {},
        "by_severity": {},
        "by_language": {},
        "by_repo": {},
        "by_month": [],
    }
    inventory = {
        "schema_version": 2,
        "kind": "ai_vulnerability_detector_inventory",
        "generated_at": remote_cutoff["checked_at_utc"],
        "source_snapshot_sha256": "c" * 64,
        "source_receipt_sha256": web_writer._canonical_sha256(remote_cutoff),
        "source_alias_class_manifest_sha256": "f" * 64,
        "campaign_id": "a" * 64,
        "contract_sha256": "0" * 64,
        "campaign_mode": "formal",
        "complete": True,
        "coverage_to": remote_cutoff["checked_at_utc"][:10],
        "alias_class_count": 0,
        "detector_candidate_count": 0,
        "pending_adjudication_count": 0,
        "coverage_failure_count": 0,
        "counts": {
            "coverage_status": {},
            "detector_state": {},
            "adjudication_state": {},
            "publication_state": {},
            "recall_stratum": {},
        },
        "rows": [],
    }
    inventory["inventory_id"] = web_writer._canonical_sha256(inventory)
    stats["inventory"] = {
        "path": "inventory.json",
        "inventory_id": inventory["inventory_id"],
        "source_snapshot_sha256": inventory["source_snapshot_sha256"],
        "source_alias_class_manifest_sha256": inventory[
            "source_alias_class_manifest_sha256"
        ],
        "campaign_id": inventory["campaign_id"],
        "campaign_mode": "formal",
        "complete": True,
        "coverage_to": inventory["coverage_to"],
        "alias_class_count": 0,
        "detector_candidate_count": 0,
        "pending_adjudication_count": 0,
        "coverage_failure_count": 0,
    }
    staged = web_writer.stage_web_data(
        [],
        stats,
        output_dir,
        generated_at="2026-07-18T13:00:00+00:00",
        inventory=inventory,
    )
    publication = web_writer.load_published_web_data(staged.staging_dir)
    receipt = {
        "schema_version": 4,
        "generation_id": publication.index["generation_id"],
        "generated_at": publication.index["generated_at"],
        "campaign_id": "a" * 64,
        "contract_sha256": "0" * 64,
        "campaign_mode": "formal",
        "population_policy": "formal_full",
        "campaign_result_manifest_sha256": "b" * 64,
        "source_snapshot_sha256": "c" * 64,
        "analyzer_contract_sha256": "d" * 64,
        "signature_sha256": "e" * 64,
        "alias_class_manifest_sha256": "f" * 64,
        "source_remote_cutoff": remote_cutoff,
        "publication_bundle_sha256": web_writer.staged_publication_bundle_sha256(
            staged
        ),
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
        "detector_inventory_sha256": web_writer._canonical_sha256(inventory),
        "detector_inventory_campaign_mode": "formal",
        "detector_inventory_complete": True,
        "detector_inventory_source_snapshot_sha256": "c" * 64,
        "detector_inventory_alias_class_manifest_sha256": "f" * 64,
        "detector_inventory_alias_class_count": 0,
        "targets": {"precision": 0.95, "recall": 0.95},
        "curation_consistency_point_estimates": {
            "precision": 1.0,
            "recall": 1.0,
        },
        "heldout_point_estimates": {"precision": 1.0, "recall": 1.0},
        "heldout_measurement_boundary": {
            "precision": "final detector precision among predicted positives",
            "recall": "final classifier recall in the AI-signal candidate population",
            "excluded": "upstream advisory discovery and AI-signature discovery recall",
        },
        "evaluation_complete": True,
        "release_safe": True,
        "curation_consistent": True,
        "heldout_certified": True,
    }
    try:
        receipt_path = web_writer.write_staged_release_receipt(staged, receipt)
        assert receipt_path.is_file()
    finally:
        web_writer.discard_staged_web_data(staged)


def test_source_snapshot_rejects_legacy_fixed_osv_receipt_schema(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    receipt = json.loads(paths.source_remote_receipt.read_text(encoding="utf-8"))
    receipt["schema_version"] = 2
    paths.source_remote_receipt.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(runner.RunnerError, match="exact schema 3"):
        runner.capture_source_snapshot(paths)


def test_osv_archive_validation_caps_member_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "oversized.zip"
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr(
            "oversized.json",
            json.dumps({"id": "OSV-OVERSIZED-1", "padding": "x" * 1024}),
        )
    monkeypatch.setattr(
        runner.source_delta_builder,
        "MAX_OSV_ARCHIVE_MEMBER_BYTES",
        128,
    )
    runner._validate_osv_archive.cache_clear()

    with pytest.raises(runner.RunnerError, match="member exceeds 128 bytes"):
        runner._validate_osv_archive(
            str(archive_path.resolve()),
            runner.file_sha256(archive_path),
        )


def test_nvd_validation_binds_expected_sha256(tmp_path: Path) -> None:
    feed = tmp_path / "nvdcve-2.0-2026.json.gz"
    _write_nvd_feed(feed)
    runner._validate_nvd_feed.cache_clear()

    with pytest.raises(runner.RunnerError, match="SHA-256|sha256|snapshot"):
        runner._validate_nvd_feed(str(feed.resolve()), "0" * 64)


def test_nvd_validation_uses_nofollow_descriptor_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = tmp_path / "nvdcve-2.0-2026.json.gz"
    replacement = tmp_path / "replacement.json.gz"
    _write_nvd_feed(feed, "CVE-2026-1")
    _write_nvd_feed(replacement, "CVE-2026-2")
    expected_sha256 = runner.file_sha256(feed)
    real_open = os.open
    opened = False

    def replace_before_open(raw_path: object, flags: int, *args: object) -> int:
        nonlocal opened
        if Path(raw_path) == feed:
            opened = True
            feed.unlink()
            feed.symlink_to(replacement)
        return real_open(raw_path, flags, *args)

    runner._validate_nvd_feed.cache_clear()
    monkeypatch.setattr(runner.source_delta_builder.os, "open", replace_before_open)

    with pytest.raises(runner.RunnerError, match="open|symlink|non-symlink"):
        runner._validate_nvd_feed(str(feed), expected_sha256)
    assert opened


def test_nvd_validation_enforces_builder_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = tmp_path / "nvdcve-2.0-2026.json.gz"
    _write_nvd_feed(feed)
    runner._validate_nvd_feed.cache_clear()
    monkeypatch.setattr(
        runner.source_delta_builder,
        "_check_nvd_deadline",
        lambda _started, _label: (_ for _ in ()).throw(
            runner.source_delta_builder.SourceDeltaError("NVD deadline")
        ),
    )

    with pytest.raises(runner.RunnerError, match="NVD deadline"):
        runner._validate_nvd_feed(str(feed.resolve()), runner.file_sha256(feed))


def test_nvd_validation_identity_guard_rejects_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = tmp_path / "nvdcve-2.0-2026.json.gz"
    replacement = tmp_path / "replacement.json.gz"
    _write_nvd_feed(feed, "CVE-2026-1")
    _write_nvd_feed(replacement, "CVE-2026-2")
    expected_sha256 = runner.file_sha256(feed)
    real_deadline = runner.source_delta_builder._check_nvd_deadline
    deadline_checks = 0

    def replace_during_read(started_at: float, label: str) -> None:
        nonlocal deadline_checks
        real_deadline(started_at, label)
        deadline_checks += 1
        if deadline_checks == 2:
            os.replace(replacement, feed)

    runner._validate_nvd_feed.cache_clear()
    monkeypatch.setattr(
        runner.source_delta_builder,
        "_check_nvd_deadline",
        replace_during_read,
    )

    with pytest.raises(runner.RunnerError, match="changed while being read"):
        runner._validate_nvd_feed(str(feed), expected_sha256)


def test_osv_validation_binds_expected_sha256(tmp_path: Path) -> None:
    archive_path = tmp_path / "PyPI.zip"
    _write_osv_archive(archive_path)
    runner._validate_osv_archive.cache_clear()

    with pytest.raises(runner.RunnerError, match="SHA-256|sha256|snapshot"):
        runner._validate_osv_archive(str(archive_path.resolve()), "0" * 64)


def test_osv_validation_never_reopens_validated_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "PyPI.zip"
    _write_osv_archive(archive_path, "OSV-ORIGINAL-1")
    original_init = zipfile.ZipFile.__init__
    reopened_by_path = False

    def observe_zipfile_input(
        self: zipfile.ZipFile,
        file: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal reopened_by_path
        if isinstance(file, (str, os.PathLike)) and Path(file) == archive_path:
            reopened_by_path = True
        original_init(self, file, *args, **kwargs)

    runner._validate_osv_archive.cache_clear()
    monkeypatch.setattr(zipfile.ZipFile, "__init__", observe_zipfile_input)

    runner._validate_osv_archive(
        str(archive_path),
        runner.file_sha256(archive_path),
    )

    assert reopened_by_path is False


def test_osv_validation_close_guard_rejects_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "PyPI.zip"
    replacement = tmp_path / "replacement.zip"
    _write_osv_archive(archive_path, "OSV-ORIGINAL-1")
    _write_osv_archive(replacement, "OSV-REPLACED-1")
    expected_sha256 = runner.file_sha256(archive_path)
    real_scan = runner.source_delta_builder._scan_osv_records

    def replace_during_scan(*args: object, **kwargs: object) -> dict[str, Any]:
        os.replace(replacement, archive_path)
        return real_scan(*args, **kwargs)

    runner._validate_osv_archive.cache_clear()
    monkeypatch.setattr(
        runner.source_delta_builder,
        "_scan_osv_records",
        replace_during_scan,
    )

    with pytest.raises(runner.RunnerError, match="changed while being scanned"):
        runner._validate_osv_archive(str(archive_path), expected_sha256)


def test_osv_validation_enforces_builder_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "PyPI.zip"
    _write_osv_archive(archive_path)
    runner._validate_osv_archive.cache_clear()
    monkeypatch.setattr(
        runner.source_delta_builder,
        "_check_osv_archive_deadline",
        lambda _started, _label: (_ for _ in ()).throw(
            runner.source_delta_builder.SourceDeltaError("OSV deadline")
        ),
    )

    with pytest.raises(runner.RunnerError, match="OSV deadline"):
        runner._validate_osv_archive(
            str(archive_path),
            runner.file_sha256(archive_path),
        )


def test_osv_archive_validation_caps_central_directory_before_zipfile_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "oversized-central-directory.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("long-record-name.json", json.dumps({"id": "OSV-GOOD-1"}))
    monkeypatch.setattr(
        runner.source_delta_builder,
        "MAX_OSV_CENTRAL_DIRECTORY_BYTES",
        1,
    )
    runner._validate_osv_archive.cache_clear()

    with pytest.raises(runner.RunnerError, match="central directory exceeds 1 byte"):
        runner._validate_osv_archive(
            str(archive_path.resolve()),
            runner.file_sha256(archive_path),
        )


def test_nvd_validation_caps_decompressed_json_before_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = tmp_path / "oversized.json.gz"
    with gzip.open(feed, "wb") as handle:
        handle.write(
            json.dumps(
                {"vulnerabilities": [], "padding": "x" * 1024},
                separators=(",", ":"),
            ).encode()
        )
    monkeypatch.setattr(runner.source_delta_builder, "MAX_NVD_JSON_BYTES", 128)
    runner._validate_nvd_feed.cache_clear()

    with pytest.raises(runner.RunnerError, match="decompressed JSON exceeds 128 bytes"):
        runner._validate_nvd_feed(str(feed.resolve()), runner.file_sha256(feed))


def test_nvd_campaign_limit_tracks_the_source_builder() -> None:
    assert runner.MAX_NVD_JSON_BYTES == runner.source_delta_builder.MAX_NVD_JSON_BYTES


def test_source_snapshot_is_captured_before_and_after_child_and_on_resume(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)
    snapshot = runner.capture_source_snapshot(paths)
    captures: list[runner.SourceSnapshot] = []

    def source_provider(_paths: runner.RunnerPaths) -> runner.SourceSnapshot:
        captures.append(snapshot)
        return snapshot

    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda _command, **_kwargs: 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
        source_snapshot_provider=source_provider,
    )

    assert refresh.run(batch_key="legacy-001") == [
        {"batch": "legacy-001", "status": "completed"}
    ]
    assert len(captures) == 2
    assert refresh.run(batch_key="legacy-001") == [
        {"batch": "legacy-001", "status": "already_completed"}
    ]
    assert len(captures) == 3


def test_source_change_during_batch_withholds_completion_marker(
    tmp_path: Path,
) -> None:
    paths = _write_campaign(tmp_path)

    def mutate_source(_command: list[str], **_kwargs: object) -> int:
        _write_nvd_feed(
            paths.nvd_feeds_dir / "nvdcve-2.0-2026.json.gz",
            "CVE-2026-2",
        )
        return 0

    refresh = runner.RefreshRunner(
        paths,
        command_runner=mutate_source,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )

    with pytest.raises(
        runner.RunnerError,
        match=r"source snapshot changed.*completion withheld|remote-parity receipt NVD mismatch",
    ):
        refresh.run(batch_key="legacy-001")

    assert not (paths.state_dir / "completed/legacy-001.json").exists()


def test_source_change_requires_a_new_delta_before_rerun(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    calls: list[list[str]] = []
    refresh = runner.RefreshRunner(
        paths,
        command_runner=lambda command, **_kwargs: calls.append(command) or 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )
    refresh.run(batch_key="legacy-001")
    marker_path = paths.state_dir / "completed/legacy-001.json"
    old_marker = json.loads(marker_path.read_text(encoding="utf-8"))
    _write_nvd_feed(
        paths.nvd_feeds_dir / "nvdcve-2.0-2026.json.gz",
        "CVE-2026-2",
    )

    with pytest.raises(
        runner.RunnerError,
        match="source delta inputs or result-cache inventory have drifted",
    ):
        refresh.run(batch_key="legacy-001")

    assert len(calls) == 1
    assert json.loads(marker_path.read_text(encoding="utf-8")) == old_marker


@pytest.mark.parametrize(
    ("corrupt", "error"),
    [
        ("missing_git", r"Git source directory is missing"),
        ("symlink_git", r"Git source directory is a symlink"),
        ("missing_nvd", r"required NVD feed is missing"),
        ("symlink_osv", r"OSV archive is a symlink"),
        ("dirty_git", r"Git source is dirty"),
        ("wrong_origin", r"unexpected origin"),
        ("malformed_nvd", r"malformed NVD feed"),
        ("malformed_osv_container", r"malformed OSV archive"),
        ("malformed_osv_record", r"malformed OSV archive"),
        ("missing_remote_receipt", r"remote-parity receipt is missing"),
        ("symlink_remote_receipt", r"remote-parity receipt is a symlink"),
        ("remote_parity_false", r"does not prove remote parity"),
        ("remote_git_mismatch", r"Git mismatch"),
        ("remote_nvd_mismatch", r"NVD mismatch"),
        ("remote_osv_malformed", r"malformed OSV entry"),
    ],
)
def test_source_snapshot_fails_closed_on_unsafe_or_malformed_sources(
    tmp_path: Path,
    corrupt: str,
    error: str,
) -> None:
    paths = _write_campaign(tmp_path)
    nvd_path = paths.nvd_feeds_dir / "nvdcve-2.0-2026.json.gz"
    osv_path = paths.osv_bulk_dir / "PyPI.zip"
    if corrupt == "missing_git":
        paths.cvelist_dir.rename(paths.cvelist_dir.with_name("cvelistV5.missing"))
    elif corrupt == "symlink_git":
        target = paths.cvelist_dir.with_name("cvelistV5.target")
        paths.cvelist_dir.rename(target)
        paths.cvelist_dir.symlink_to(target, target_is_directory=True)
    elif corrupt == "missing_nvd":
        nvd_path.unlink()
    elif corrupt == "symlink_osv":
        target = paths.osv_bulk_dir / "payload"
        osv_path.replace(target)
        osv_path.symlink_to(target)
    elif corrupt == "dirty_git":
        (paths.cvelist_dir / "source.json").write_text("dirty\n", encoding="utf-8")
    elif corrupt == "wrong_origin":
        subprocess.run(
            [
                "git",
                "-C",
                str(paths.ghsa_dir),
                "remote",
                "set-url",
                "origin",
                "https://github.com/example/wrong.git",
            ],
            check=True,
        )
    elif corrupt == "malformed_nvd":
        with gzip.open(nvd_path, "wt", encoding="utf-8") as handle:
            handle.write("not-json")
    elif corrupt == "malformed_osv_container":
        osv_path.write_bytes(b"not-a-zip")
    elif corrupt == "malformed_osv_record":
        with zipfile.ZipFile(osv_path, "w") as archive:
            archive.writestr("first.json", json.dumps({"id": "OSV-GOOD-1"}))
            archive.writestr("bad.json", "not-json")
            archive.writestr("last.json", json.dumps({"id": "OSV-GOOD-2"}))
    elif corrupt == "missing_remote_receipt":
        paths.source_remote_receipt.unlink()
    elif corrupt == "symlink_remote_receipt":
        target = paths.source_remote_receipt.with_name("remote-receipt.target")
        paths.source_remote_receipt.replace(target)
        paths.source_remote_receipt.symlink_to(target)
    elif corrupt in {
        "remote_parity_false",
        "remote_git_mismatch",
        "remote_nvd_mismatch",
        "remote_osv_malformed",
    }:
        receipt = json.loads(paths.source_remote_receipt.read_text(encoding="utf-8"))
        if corrupt == "remote_parity_false":
            receipt["remote_parity"] = False
        elif corrupt == "remote_git_mismatch":
            receipt["git_sources"][0]["remote_head"] = "0" * 40
        elif corrupt == "remote_nvd_mismatch":
            receipt["nvd_feeds"][0]["remote_meta_sha256"] = "0" * 64
        else:
            del receipt["osv_archives"][0]["generation"]
        paths.source_remote_receipt.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:  # pragma: no cover - parametrization exhaustiveness guard
        raise AssertionError(corrupt)

    with pytest.raises(runner.RunnerError, match=error):
        runner.capture_source_snapshot(paths)


@pytest.mark.parametrize("second_batch", ["grouped-032", "grouped-033"])
def test_campaign_runner_is_a_fail_closed_singleton(
    tmp_path: Path,
    second_batch: str,
) -> None:
    paths = _write_campaign(tmp_path)
    command_started = threading.Event()
    release_command = threading.Event()
    first_errors: list[BaseException] = []

    def blocking_command(_command: list[str], **_kwargs: object) -> int:
        command_started.set()
        if not release_command.wait(timeout=5):
            raise AssertionError("test did not release the first runner")
        return 0

    first = runner.RefreshRunner(
        paths,
        command_runner=blocking_command,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )
    second = runner.RefreshRunner(
        paths,
        command_runner=lambda _command, **_kwargs: 0,
        disk_free=lambda _path: runner.MIN_FREE_BYTES + 1,
        batch_validator=_validated,
    )

    def run_first() -> None:
        try:
            first.run(batch_key="grouped-032")
        except BaseException as exc:  # noqa: BLE001 - preserve thread failures
            first_errors.append(exc)

    thread = threading.Thread(target=run_first)
    thread.start()
    assert command_started.wait(timeout=5)
    try:
        with pytest.raises(
            runner.RunnerError,
            match=rf"{runner.CAMPAIGN_LOCK_KEY}.*already running",
        ):
            second.run(batch_key=second_batch)
    finally:
        release_command.set()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert first_errors == []


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX process locks")
def test_batch_lock_recovers_after_abrupt_process_exit(tmp_path: Path) -> None:
    paths = _write_campaign(tmp_path)
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        with runner.batch_singleton_lock(paths.state_dir, "grouped-032"):
            os.write(write_fd, b"locked")
            os._exit(0)

    os.close(write_fd)
    try:
        assert os.read(read_fd, 6) == b"locked"
    finally:
        os.close(read_fd)
        _, child_status = os.waitpid(child_pid, 0)

    assert os.waitstatus_to_exitcode(child_status) == 0
    with runner.batch_singleton_lock(paths.state_dir, "grouped-032"):
        pass


@pytest.mark.skipif(
    not hasattr(os, "fork") or not hasattr(os, "killpg"),
    reason="requires POSIX process groups and inherited file descriptors",
)
def test_campaign_lock_survives_abrupt_runner_exit_while_child_is_active(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    child_pid_path = tmp_path / "child.pid"
    log_path = tmp_path / "child.log"
    owner_pid = os.fork()
    if owner_pid == 0:
        try:
            with runner.batch_singleton_lock(
                state_dir,
                runner.CAMPAIGN_LOCK_KEY,
            ) as lock_fd:
                script = (
                    "import os, pathlib, time; "
                    f"pathlib.Path({str(child_pid_path)!r}).write_text(str(os.getpid())); "
                    "time.sleep(120)"
                )
                runner._run_subprocess(
                    [sys.executable, "-c", script],
                    cwd=tmp_path,
                    env=dict(os.environ),
                    log_path=log_path,
                    inherited_fds=(lock_fd,),
                )
        except BaseException:  # noqa: BLE001 - child reports failure by exit status
            os._exit(70)
        os._exit(0)

    analyzer_pid: int | None = None
    try:
        deadline = time.monotonic() + 5
        while not child_pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert child_pid_path.exists()
        analyzer_pid = int(child_pid_path.read_text(encoding="utf-8"))

        os.kill(owner_pid, signal.SIGKILL)
        _, owner_status = os.waitpid(owner_pid, 0)
        assert os.waitstatus_to_exitcode(owner_status) == -signal.SIGKILL

        with pytest.raises(
            runner.RunnerError,
            match=rf"{runner.CAMPAIGN_LOCK_KEY}.*already running",
        ):
            with runner.batch_singleton_lock(state_dir, runner.CAMPAIGN_LOCK_KEY):
                pass
    finally:
        try:
            waited_pid, _status = os.waitpid(owner_pid, os.WNOHANG)
            if waited_pid == 0:
                os.kill(owner_pid, signal.SIGKILL)
                os.waitpid(owner_pid, 0)
        except ChildProcessError:
            pass
        if analyzer_pid is not None:
            try:
                os.killpg(analyzer_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with runner.batch_singleton_lock(state_dir, runner.CAMPAIGN_LOCK_KEY):
                return
        except runner.RunnerError:
            time.sleep(0.02)
    raise AssertionError("campaign lock was not released after the analyzer exited")


def test_batch_lock_rejects_symlink_without_truncating_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    locks = state_dir / "locks"
    locks.mkdir(parents=True)
    target = tmp_path / "valuable.txt"
    target.write_text("preserve me\n", encoding="utf-8")
    (locks / "grouped-032.lock").symlink_to(target)

    with pytest.raises(runner.RunnerError, match="unsafe singleton lock"):
        with runner.batch_singleton_lock(state_dir, "grouped-032"):
            pass

    assert target.read_text(encoding="utf-8") == "preserve me\n"


def test_batch_lock_rejects_path_replacement_during_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "state"
    locks = state_dir / "locks"
    locks.mkdir(parents=True)
    lock_path = locks / "grouped-032.lock"
    lock_path.write_text("old lock\n", encoding="utf-8")
    real_open = os.open
    swapped = False

    def swapping_open(
        path: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if str(path) == lock_path.name and dir_fd is not None and not swapped:
            swapped = True
            lock_path.replace(locks / "detached.lock")
            lock_path.write_text("replacement\n", encoding="utf-8")
        return descriptor

    monkeypatch.setattr(runner.os, "open", swapping_open)
    with pytest.raises(runner.RunnerError, match="changed while being opened"):
        with runner.batch_singleton_lock(state_dir, "grouped-032"):
            pass

    assert lock_path.read_text(encoding="utf-8") == "replacement\n"


def test_batch_lock_rejects_file_replacement_while_acquiring_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "state"
    lock_path = state_dir / "locks" / "grouped-032.lock"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_text("old lock\n", encoding="utf-8")
    real_flock = fcntl.flock
    swapped = False

    def swapping_flock(descriptor: int, operation: int) -> None:
        nonlocal swapped
        real_flock(descriptor, operation)
        if operation & fcntl.LOCK_EX and not swapped:
            swapped = True
            lock_path.replace(lock_path.with_name("detached.lock"))
            lock_path.write_text("replacement\n", encoding="utf-8")

    monkeypatch.setattr(runner.fcntl, "flock", swapping_flock)
    with pytest.raises(runner.RunnerError, match="changed while acquiring"):
        with runner.batch_singleton_lock(state_dir, "grouped-032"):
            pass

    assert swapped is True
    assert lock_path.read_text(encoding="utf-8") == "replacement\n"


def test_batch_lock_rejects_intermediate_symlink_without_touching_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    redirected_parent = tmp_path / "redirected"
    redirected_parent.symlink_to(target, target_is_directory=True)
    state_dir = redirected_parent / "state"

    with pytest.raises(runner.RunnerError, match="not a safe directory"):
        with runner.batch_singleton_lock(state_dir, "grouped-032"):
            pass

    assert not (target / "state").exists()


def test_batch_lock_rejects_intermediate_directory_replacement_during_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "state"
    locks = state_dir / "locks"
    locks.mkdir(parents=True)
    real_open = os.open
    swapped = False

    def swapping_open(
        path: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if str(path) == "locks" and dir_fd is not None and not swapped:
            swapped = True
            locks.replace(state_dir / "detached-locks")
            locks.mkdir()
        return descriptor

    monkeypatch.setattr(runner.os, "open", swapping_open)
    with pytest.raises(runner.RunnerError, match="changed while being opened"):
        with runner.batch_singleton_lock(state_dir, "grouped-032"):
            pass

    assert swapped is True
    assert not (locks / "grouped-032.lock").exists()


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="requires POSIX process groups")
def test_successful_leader_with_lingering_descendant_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pid_path = tmp_path / "child.pid"
    log_path = tmp_path / "batch.log"
    environment = dict(os.environ)
    environment["CHILD_PID_PATH"] = str(child_pid_path)
    leader_script = """
import os
import subprocess
import sys

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
with open(os.environ["CHILD_PID_PATH"], "w", encoding="utf-8") as handle:
    handle.write(str(child.pid))
    handle.flush()
    os.fsync(handle.fileno())
"""
    monkeypatch.setattr(runner, "BATCH_TERMINATION_GRACE_SECONDS", 0.25)
    child_pid: int | None = None
    try:
        with pytest.raises(
            subprocess.SubprocessError,
            match="process group was still alive",
        ):
            runner._run_subprocess(
                [sys.executable, "-c", leader_script],
                cwd=tmp_path,
                env=environment,
                log_path=log_path,
                timeout_seconds=5,
            )
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))

        def child_exists() -> bool:
            assert child_pid is not None
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                return False
            return True

        deadline = time.monotonic() + 2
        while child_exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not child_exists()
        assert "lingering descendants" in log_path.read_text(encoding="utf-8")
    finally:
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="requires POSIX process groups")
def test_batch_timeout_terminates_the_entire_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pid_path = tmp_path / "child.pid"
    log_path = tmp_path / "batch.log"
    environment = dict(os.environ)
    environment["CHILD_PID_PATH"] = str(child_pid_path)
    leader_script = """
import os
import signal
import subprocess
import sys
import time

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

def terminate(_signum, _frame):
    child.wait(timeout=5)
    raise SystemExit(0)

signal.signal(signal.SIGTERM, terminate)
with open(os.environ["CHILD_PID_PATH"], "w", encoding="utf-8") as handle:
    handle.write(str(child.pid))
    handle.flush()
    os.fsync(handle.fileno())
time.sleep(60)
"""
    monkeypatch.setattr(runner, "BATCH_TERMINATION_GRACE_SECONDS", 0.25)
    child_pid: int | None = None

    def process_exists(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    try:
        with pytest.raises(subprocess.TimeoutExpired):
            runner._run_subprocess(
                [sys.executable, "-c", leader_script],
                cwd=tmp_path,
                env=environment,
                log_path=log_path,
                timeout_seconds=0.5,
            )

        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while process_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.01)

        assert not process_exists(child_pid)
        assert "terminating process group" in log_path.read_text(encoding="utf-8")
    finally:
        if child_pid is None and child_pid_path.exists():
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        if child_pid is not None and process_exists(child_pid):
            os.kill(child_pid, signal.SIGKILL)


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="requires POSIX process groups")
def test_batch_keyboard_interrupt_terminates_the_entire_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pid_path = tmp_path / "child.pid"
    log_path = tmp_path / "batch.log"
    environment = dict(os.environ)
    environment["CHILD_PID_PATH"] = str(child_pid_path)
    leader_script = """
import os
import signal
import subprocess
import sys
import time

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

def terminate(_signum, _frame):
    child.wait(timeout=5)
    raise SystemExit(0)

signal.signal(signal.SIGTERM, terminate)
with open(os.environ["CHILD_PID_PATH"], "w", encoding="utf-8") as handle:
    handle.write(str(child.pid))
    handle.flush()
    os.fsync(handle.fileno())
time.sleep(60)
"""
    real_popen = subprocess.Popen

    class InterruptingPopen:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._process = real_popen(*args, **kwargs)
            self.pid = self._process.pid
            self._interrupted = False

        def wait(self, timeout: float | None = None) -> int:
            if not self._interrupted:
                self._interrupted = True
                deadline = time.monotonic() + 5
                while not child_pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not child_pid_path.exists():
                    raise AssertionError("leader did not publish child PID")
                raise KeyboardInterrupt
            return self._process.wait(timeout=timeout)

        def poll(self) -> int | None:
            return self._process.poll()

    monkeypatch.setattr(runner.subprocess, "Popen", InterruptingPopen)
    monkeypatch.setattr(runner, "BATCH_TERMINATION_GRACE_SECONDS", 0.25)
    child_pid: int | None = None

    def process_exists(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    try:
        with pytest.raises(KeyboardInterrupt):
            runner._run_subprocess(
                [sys.executable, "-c", leader_script],
                cwd=tmp_path,
                env=environment,
                log_path=log_path,
                timeout_seconds=60,
            )

        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while process_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.01)

        assert not process_exists(child_pid)
        log_content = log_path.read_text(encoding="utf-8")
        assert "batch interrupted by KeyboardInterrupt" in log_content
        assert "batch deadline exceeded" not in log_content
    finally:
        if child_pid is None and child_pid_path.exists():
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        if child_pid is not None and process_exists(child_pid):
            os.kill(child_pid, signal.SIGKILL)


@pytest.mark.skipif(
    not hasattr(os, "killpg") or not hasattr(signal, "SIGHUP"),
    reason="requires POSIX process groups and signals",
)
@pytest.mark.parametrize("signum", [signal.SIGHUP, signal.SIGTERM])
def test_campaign_signal_terminates_the_entire_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signum: int,
) -> None:
    child_pid_path = tmp_path / "child.pid"
    log_path = tmp_path / "batch.log"
    environment = dict(os.environ)
    environment["CHILD_PID_PATH"] = str(child_pid_path)
    leader_script = """
import os
import subprocess
import sys
import time

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open(os.environ["CHILD_PID_PATH"], "w", encoding="utf-8") as handle:
    handle.write(str(child.pid))
    handle.flush()
    os.fsync(handle.fileno())
time.sleep(60)
"""
    monkeypatch.setattr(runner, "BATCH_TERMINATION_GRACE_SECONDS", 0.25)
    child_pid: int | None = None

    def send_signal_when_ready() -> None:
        deadline = time.monotonic() + 5
        while not child_pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if child_pid_path.exists():
            os.kill(os.getpid(), signum)

    sender = threading.Thread(target=send_signal_when_ready, daemon=True)
    try:
        sender.start()
        with runner._campaign_signal_handlers():
            with pytest.raises(runner.CampaignSignalInterrupt) as raised:
                runner._run_subprocess(
                    [sys.executable, "-c", leader_script],
                    cwd=tmp_path,
                    env=environment,
                    log_path=log_path,
                    timeout_seconds=60,
                )
        sender.join(timeout=5)
        assert not sender.is_alive()
        assert raised.value.signum == signum

        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while runner._process_group_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.01)

        assert not runner._process_group_exists(child_pid)
        signal_name = signal.Signals(signum).name
        assert (
            f"batch interrupted by CampaignSignalInterrupt({signal_name})"
            in log_path.read_text(encoding="utf-8")
        )
    finally:
        sender.join(timeout=5)
        if child_pid is None and child_pid_path.exists():
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        if child_pid is not None and runner._process_group_exists(child_pid):
            os.killpg(child_pid, signal.SIGKILL)


@pytest.mark.skipif(
    not hasattr(signal, "pthread_sigmask"),
    reason="requires POSIX signal masking during spawn",
)
def test_campaign_signal_during_spawn_cleans_up_returned_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = MagicMock(pid=424242)
    terminate = MagicMock()

    def spawn_with_pending_signal(*_args: object, **_kwargs: object) -> MagicMock:
        os.kill(os.getpid(), signal.SIGTERM)
        return process

    monkeypatch.setattr(runner.subprocess, "Popen", spawn_with_pending_signal)
    monkeypatch.setattr(runner, "_terminate_process_group", terminate)

    with runner._campaign_signal_handlers():
        with pytest.raises(runner.CampaignSignalInterrupt):
            runner._run_subprocess(
                ["synthetic-child"],
                cwd=tmp_path,
                env={},
                log_path=tmp_path / "spawn-signal.log",
            )

    terminate.assert_called_once()
    assert terminate.call_args.args[0] is process


@pytest.mark.parametrize(
    "receipt_completed_at",
    [
        "2026-07-18T11:59:59+00:00",
        "2026-07-18T12:00:11+00:00",
    ],
    ids=["before-start", "after-completion"],
)
def test_result_validation_rejects_receipt_completed_outside_batch_window(
    tmp_path: Path,
    receipt_completed_at: str,
) -> None:
    batch, campaign, started_at, started_at_ns, completed_at_ns = _receipt_fixture(
        tmp_path,
        receipt_completed_at=receipt_completed_at,
        result_mtime="2026-07-18T12:00:01+00:00",
    )

    with pytest.raises(
        runner.RunnerError,
        match="campaign receipt completion time is outside the batch window",
    ):
        runner.validate_batch_results(
            batch,
            campaign.result_dir,
            started_at_ns,
            completed_at_ns=completed_at_ns,
            started_at=started_at,
            campaign=campaign,
        )


def test_result_validation_rejects_result_written_after_receipt_completion(
    tmp_path: Path,
) -> None:
    batch, campaign, started_at, started_at_ns, completed_at_ns = _receipt_fixture(
        tmp_path,
        receipt_completed_at="2026-07-18T12:00:05+00:00",
        result_mtime="2026-07-18T12:00:06+00:00",
    )

    with pytest.raises(runner.RunnerError, match="receipt"):
        runner.validate_batch_results(
            batch,
            campaign.result_dir,
            started_at_ns,
            completed_at_ns=completed_at_ns,
            started_at=started_at,
            campaign=campaign,
        )


def test_result_validation_rejects_incomplete_early_exit_categories(
    tmp_path: Path,
) -> None:
    result_dir = tmp_path / "results"
    result_dir.mkdir()
    batch = runner.BatchSpec(
        key="test",
        path=tmp_path / "batch.txt",
        kind="test",
        ids=(
            "CVE-GOOD",
            "CVE-SKIPPED",
            "CVE-NOFIX",
            "CVE-FIX-UNAVAILABLE",
        ),
        repos=frozenset(),
    )
    for cve_id, category in (
        ("CVE-GOOD", ""),
        ("CVE-SKIPPED", "skipped_advisory"),
        ("CVE-NOFIX", "no_fix_commits"),
        ("CVE-FIX-UNAVAILABLE", "fix_commit_unavailable"),
    ):
        (result_dir / f"{cve_id}.json").write_text(
            json.dumps(
                {
                    "cve_id": cve_id,
                    "error_category": category,
                    "repo_ai_activity": [],
                }
            ),
            encoding="utf-8",
        )

    with pytest.raises(runner.RunnerError, match="incomplete result category"):
        runner.validate_batch_results(batch, result_dir, 1)


def test_formal_result_validation_emits_exact_bound_stage_receipt(
    tmp_path: Path,
) -> None:
    batch, campaign, started_at, started_at_ns, completed_at_ns = _receipt_fixture(
        tmp_path,
        receipt_completed_at="2026-07-18T12:00:05+00:00",
        result_mtime="2026-07-18T12:00:05+00:00",
    )
    component_sha256 = hashlib.sha256(b"CVE-TEST\n").hexdigest()
    class_record = {
        "class_id": "alias-test",
        "component_sha256": component_sha256,
        "source_snapshot_sha256": "9" * 64,
        "merged_source_evidence_sha256": "8" * 64,
        "analysis_input": {"git_ranges": []},
    }

    report = runner.validate_batch_results(
        batch,
        campaign.result_dir,
        started_at_ns,
        completed_at_ns=completed_at_ns,
        started_at=started_at,
        campaign=campaign,
        class_records={"CVE-TEST": class_record},
    )

    assert report["alias_classes_exactly_once"] is True
    assert report["class_receipt_count"] == 1
    receipt = report["class_receipts"][0]
    assert receipt["class_id"] == "alias-test"
    assert receipt["analyzer_contract_sha256"] == "e" * 64
    assert list(receipt["stages"]) == list(runner.ANALYSIS_STAGE_NAMES)
    assert all(
        len(stage["input_sha256"]) == len(stage["output_sha256"]) == 64
        for stage in receipt["stages"].values()
    )


def test_formal_no_fix_without_method_receipts_remains_pending(tmp_path: Path) -> None:
    batch, campaign, started_at, started_at_ns, completed_at_ns = _receipt_fixture(
        tmp_path,
        receipt_completed_at="2026-07-18T12:00:05+00:00",
        result_mtime="2026-07-18T12:00:05+00:00",
    )
    result_path = campaign.result_dir / "CVE-TEST.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    payload["analysis_stage_receipts"]["fix_resolution"]["methods"] = []
    result_path.write_text(json.dumps(payload), encoding="utf-8")
    written_at = runner._iso_timestamp_ns("2026-07-18T12:00:05+00:00")
    assert written_at is not None
    os.utime(result_path, ns=(written_at, written_at))
    class_record = {
        "class_id": "alias-test",
        "component_sha256": hashlib.sha256(b"CVE-TEST\n").hexdigest(),
        "source_snapshot_sha256": "9" * 64,
        "merged_source_evidence_sha256": "8" * 64,
        "analysis_input": {"git_ranges": []},
    }

    with pytest.raises(
        runner.RunnerError, match="invalid complete analysis stage receipts"
    ):
        runner.validate_batch_results(
            batch,
            campaign.result_dir,
            started_at_ns,
            completed_at_ns=completed_at_ns,
            started_at=started_at,
            campaign=campaign,
            class_records={"CVE-TEST": class_record},
        )


def test_result_validation_rejects_expected_result_symlink(tmp_path: Path) -> None:
    result_dir = tmp_path / "results"
    result_dir.mkdir()
    batch = runner.BatchSpec(
        key="test",
        path=tmp_path / "batch.txt",
        kind="test",
        ids=("CVE-X",),
        repos=frozenset(),
    )
    target = result_dir / "unlisted.json"
    target.write_text(
        json.dumps(
            {
                "cve_id": "CVE-X",
                "error_category": "no_fix_commits",
                "repo_ai_activity": [],
            }
        ),
        encoding="utf-8",
    )
    (result_dir / "CVE-X.json").symlink_to(target.name)

    with pytest.raises(runner.RunnerError, match="unsafe symlink result for CVE-X"):
        runner.validate_batch_results(batch, result_dir, 1)


def test_result_validation_rejects_oversized_result(tmp_path: Path) -> None:
    result_dir = tmp_path / "results"
    result_dir.mkdir()
    batch = runner.BatchSpec(
        key="test",
        path=tmp_path / "batch.txt",
        kind="test",
        ids=("CVE-X",),
        repos=frozenset(),
    )
    with (result_dir / "CVE-X.json").open("wb") as handle:
        handle.truncate(runner.MAX_RESULT_JSON_BYTES + 1)

    with pytest.raises(runner.RunnerError, match="oversized result for CVE-X"):
        runner.validate_batch_results(batch, result_dir, 1)


def test_result_validation_rejects_result_replaced_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result_dir = tmp_path / "results"
    result_dir.mkdir()
    result_path = result_dir / "CVE-X.json"
    payload = {
        "cve_id": "CVE-X",
        "error_category": "no_fix_commits",
        "repo_ai_activity": [],
    }
    result_path.write_text(json.dumps(payload), encoding="utf-8")
    replacement = tmp_path / "replacement.json"
    replacement.write_text(
        json.dumps({**payload, "replacement": True}), encoding="utf-8"
    )
    batch = runner.BatchSpec(
        key="test",
        path=tmp_path / "batch.txt",
        kind="test",
        ids=("CVE-X",),
        repos=frozenset(),
    )
    original_read = runner.os.read
    replaced = False

    def read_then_replace(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        chunk = original_read(descriptor, size)
        if chunk and not replaced:
            replaced = True
            os.replace(replacement, result_path)
        return chunk

    monkeypatch.setattr(runner.os, "read", read_then_replace)

    with pytest.raises(runner.RunnerError, match="result changed while read for CVE-X"):
        runner.validate_batch_results(batch, result_dir, 1)
    assert replaced


def test_result_validation_rejects_unlisted_batch_result(tmp_path: Path) -> None:
    result_dir = tmp_path / "results"
    result_dir.mkdir()
    batch = runner.BatchSpec(
        key="test",
        path=tmp_path / "batch.txt",
        kind="test",
        ids=("CVE-X",),
        repos=frozenset(),
    )
    for cve_id in ("CVE-X", "CVE-EXTRA"):
        (result_dir / f"{cve_id}.json").write_text(
            json.dumps(
                {
                    "cve_id": cve_id,
                    "error_category": "no_fix_commits",
                    "repo_ai_activity": [],
                }
            ),
            encoding="utf-8",
        )

    with pytest.raises(runner.RunnerError, match="unexpected result file"):
        runner.validate_batch_results(batch, result_dir, 1)


def test_result_validation_allows_prior_planned_result_inventory(
    tmp_path: Path,
) -> None:
    result_dir = tmp_path / "results"
    result_dir.mkdir()
    batch = runner.BatchSpec(
        key="current",
        path=tmp_path / "batch.txt",
        kind="test",
        ids=("CVE-CURRENT",),
        repos=frozenset(),
    )
    for cve_id in ("CVE-PRIOR", "CVE-CURRENT"):
        (result_dir / f"{cve_id}.json").write_text(
            json.dumps(
                {
                    "cve_id": cve_id,
                    "error_category": "no_fix_commits",
                    "repo_ai_activity": [],
                }
            ),
            encoding="utf-8",
        )

    report = runner.validate_batch_results(
        batch,
        result_dir,
        1,
        allowed_result_ids=("CVE-PRIOR", "CVE-CURRENT"),
    )

    assert report["result_count"] == 1
    assert report["terminal_count"] == 1


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (None, "missing result"),
        ({"cve_id": "CVE-X", "error_category": "clone_failed"}, "transient result"),
        (
            {"cve_id": "CVE-X", "error_category": "no_ai_activity"},
            "non-terminal result category",
        ),
        (
            {"cve_id": "CVE-X", "error_category": "future_category"},
            "unsupported result category",
        ),
        (
            {"cve_id": "CVE-X", "error_category": 7},
            "invalid error_category",
        ),
        (
            {"cve_id": "CVE-X", "error": ["failure"], "error_category": ""},
            "invalid error field",
        ),
        (
            {"cve_id": "CVE-X", "error": "failure", "error_category": ""},
            "unterminated error",
        ),
        (
            {"cve_id": "CVE-X", "error_category": "", "repo_ai_activity": "present"},
            "invalid repo_ai_activity",
        ),
        (
            {
                "cve_id": "CVE-X",
                "error_category": "",
                "repo_ai_activity": ["incomplete:git_log_timeout"],
            },
            "incomplete Tier-0",
        ),
        (
            {
                "cve_id": "CVE-X",
                "error_category": "",
                "repo_ai_activity": [],
                "screening": {"model": "gpt-5.4"},
            },
            "LLM model provenance mismatch",
        ),
        (
            {
                "cve_id": "CVE-X",
                "error_category": "",
                "repo_ai_activity": [],
                "bug_introducing_commits": [
                    {
                        "deep_verification": {
                            "model": "gpt-5.6-luna",
                            "reasoning_effort": "high",
                        }
                    }
                ],
            },
            "deep verification reasoning effort mismatch",
        ),
    ],
)
def test_result_validation_rejects_incomplete_work(
    tmp_path: Path,
    payload: dict | None,
    error: str,
) -> None:
    result_dir = tmp_path / "results"
    result_dir.mkdir()
    batch = runner.BatchSpec(
        key="test",
        path=tmp_path / "batch.txt",
        kind="test",
        ids=("CVE-X",),
        repos=frozenset(),
    )
    if payload is not None:
        (result_dir / "CVE-X.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(runner.RunnerError, match=error):
        runner.validate_batch_results(batch, result_dir, 1)


def _pilot_selection_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    openclaw_count: int = 30,
) -> runner.RunnerPaths:
    paths = runner.RunnerPaths.defaults(tmp_path)
    delta_path = paths.grouped_dir.parent / "source-delta-current.json"
    delta_path.parent.mkdir(parents=True)
    records: list[dict[str, Any]] = []
    for number in range(openclaw_count):
        subject = f"CVE-2026-{number + 1}"
        component = hashlib.sha256(f"{subject}\n".encode()).hexdigest()
        analysis_input = {
            "member_ids": [subject],
            "git_ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/openclaw/openclaw.git",
                }
            ],
            "fixed_events": [],
            "reference_urls": [
                f"https://github.com/openclaw/openclaw/commit/{number:040x}"
            ],
        }
        records.append(
            {
                "class_id": f"alias-{component[:24]}",
                "component_sha256": component,
                "all_member_ids": [subject],
                "eligible_seed_ids": [subject],
                "scheduled_seed_ids": [subject],
                "source_record_references": [],
                "merged_source_evidence_sha256": hashlib.sha256(
                    runner._canonical_json_bytes(
                        {"records": [], "analysis_input": analysis_input}
                    )
                ).hexdigest(),
                "analysis_subject": subject,
                "analysis_input": analysis_input,
                "source_snapshot_sha256": "d" * 64,
            }
        )
    records.sort(key=lambda item: item["class_id"])
    manifest = {
        "schema_version": 1,
        "source_snapshot_sha256": "d" * 64,
        "class_count": len(records),
        "eligible_seed_id_count": len(records),
        "all_eligible_seed_ids_exactly_once": True,
        "scheduled_class_count": len(records),
        "scheduled_analysis_subject_count": len(records),
        "scheduled_classes_exactly_once": True,
        "classes_sha256": hashlib.sha256(
            runner._canonical_json_bytes(records)
        ).hexdigest(),
        "classes": records,
    }
    delta_path.write_text(
        json.dumps(
            {
                "schema_version": runner.SOURCE_DELTA_SCHEMA_VERSION,
                "population_policy": "formal_full",
                "production_discovery": {"alias_class_manifest": manifest},
            }
        ),
        encoding="utf-8",
    )
    by_subject = {item["analysis_subject"]: item for item in records}
    batch_path = tmp_path / "formal-batch.txt"
    batch_path.write_text("\n".join(by_subject) + "\n", encoding="utf-8")
    plan = [
        runner.BatchSpec(
            key="grouped-001",
            path=batch_path,
            kind="repo_affinity",
            ids=tuple(by_subject),
            repos=frozenset({"github.com/openclaw/openclaw"}),
            class_ids=tuple(item["class_id"] for item in records),
        )
    ]
    monkeypatch.setattr(runner, "load_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(
        runner,
        "_current_formal_class_records",
        lambda _paths: by_subject,
    )
    return paths


def test_openclaw_pilot_selection_is_deterministic_and_exactly_24(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _pilot_selection_fixture(tmp_path, monkeypatch)

    first = runner._openclaw_pilot_selection(paths)
    second = runner._openclaw_pilot_selection(paths)

    assert first[1] == second[1]
    assert first[1]["artifact_kind"] == "pilot"
    assert first[1]["formal_release_eligible"] is False
    assert first[1]["selected_class_count"] == 24
    assert first[1]["selected_classes_exactly_once"] is True
    assert len(first[2]) == 24
    assert len({item["class_id"] for item in first[1]["classes"]}) == 24


def test_openclaw_smoke_selection_covers_every_current_class_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _pilot_selection_fixture(tmp_path, monkeypatch, openclaw_count=30)

    selection, records, population_count = runner._openclaw_smoke_selection(paths)

    assert selection["artifact_kind"] == "openclaw_smoke"
    assert selection["selected_class_count"] == population_count == 30
    assert selection["selected_classes_exactly_once"] is True
    assert set(records) == {item["analysis_subject"] for item in selection["classes"]}
    assert len({item["class_id"] for item in selection["classes"]}) == 30


def test_openclaw_pilot_rejects_population_below_class_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _pilot_selection_fixture(
        tmp_path,
        monkeypatch,
        openclaw_count=23,
    )

    with pytest.raises(runner.RunnerError, match="fewer than 24"):
        runner._openclaw_pilot_selection(paths)


def test_formal_alias_manifest_rejects_an_unscheduled_class(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _pilot_selection_fixture(tmp_path, monkeypatch)
    delta = json.loads(
        (paths.grouped_dir.parent / "source-delta-current.json").read_text(
            encoding="utf-8"
        )
    )
    manifest = delta["production_discovery"]["alias_class_manifest"]
    classes = manifest["classes"]
    omitted = classes[0]["analysis_subject"]
    classes[0]["scheduled_seed_ids"] = []
    manifest["classes_sha256"] = hashlib.sha256(
        runner._canonical_json_bytes(classes)
    ).hexdigest()
    manifest["scheduled_class_count"] -= 1
    manifest["scheduled_analysis_subject_count"] -= 1

    with pytest.raises(runner.RunnerError, match="unscheduled"):
        runner._validate_alias_class_manifest(
            manifest,
            production_ids=[item["analysis_subject"] for item in classes],
            candidate_ids=[
                item["analysis_subject"]
                for item in classes
                if item["analysis_subject"] != omitted
            ],
            source_snapshot_sha256="d" * 64,
        )


def test_formal_alias_manifest_rejects_schedule_outside_eligible_population(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _pilot_selection_fixture(tmp_path, monkeypatch)
    delta = json.loads(
        (paths.grouped_dir.parent / "source-delta-current.json").read_text(
            encoding="utf-8"
        )
    )
    manifest = delta["production_discovery"]["alias_class_manifest"]
    classes = manifest["classes"]
    class_record = classes[0]
    scheduled_alias = "GHSA-aaaa-bbbb-cccc"
    eligible_subject = class_record["analysis_subject"]
    members = sorted([eligible_subject, scheduled_alias])
    component_sha256 = hashlib.sha256(
        ("\n".join(members) + "\n").encode("utf-8")
    ).hexdigest()
    class_record["class_id"] = f"alias-{component_sha256[:24]}"
    class_record["component_sha256"] = component_sha256
    class_record["all_member_ids"] = members
    class_record["eligible_seed_ids"] = [eligible_subject]
    class_record["scheduled_seed_ids"] = [scheduled_alias]
    manifest["classes_sha256"] = hashlib.sha256(
        runner._canonical_json_bytes(classes)
    ).hexdigest()

    with pytest.raises(runner.RunnerError, match="eligible alias class"):
        runner._validate_alias_class_manifest(
            manifest,
            production_ids=[item["analysis_subject"] for item in classes],
            candidate_ids=[item["analysis_subject"] for item in classes],
            source_snapshot_sha256="d" * 64,
        )


def test_formal_alias_manifest_rejects_inconsistent_full_schedule_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _pilot_selection_fixture(tmp_path, monkeypatch)
    delta = json.loads(
        (paths.grouped_dir.parent / "source-delta-current.json").read_text(
            encoding="utf-8"
        )
    )
    manifest = delta["production_discovery"]["alias_class_manifest"]
    classes = manifest["classes"]
    manifest["scheduled_class_count"] -= 1

    with pytest.raises(runner.RunnerError, match="full scheduling"):
        runner._validate_alias_class_manifest(
            manifest,
            production_ids=[item["analysis_subject"] for item in classes],
            candidate_ids=[item["analysis_subject"] for item in classes],
            source_snapshot_sha256="d" * 64,
        )


def test_pilot_pricing_enforces_all_three_hard_caps() -> None:
    contract, reservation = runner._pilot_pricing_contract(
        runner.PilotPricing(
            input_usd_per_million_tokens="1",
            output_usd_per_million_tokens="2",
            max_input_tokens=100_000,
            max_output_tokens=runner.MAX_REASONING_OUTPUT_TOKENS_CEILING,
            max_cost_microusd=25_000_000,
            max_attempts=72,
        )
    )
    assert contract["model"] == runner.MODEL
    assert reservation == 165_536

    with pytest.raises(runner.RunnerError, match="between 1 and 72"):
        runner._pilot_pricing_contract(
            runner.PilotPricing("1", "2", 100_000, 32_768, 25_000_000, 73)
        )
    with pytest.raises(runner.RunnerError, match="no greater than USD 25"):
        runner._pilot_pricing_contract(
            runner.PilotPricing("1", "2", 100_000, 32_768, 25_000_001, 72)
        )
    with pytest.raises(runner.RunnerError, match="maximum reasoning output"):
        runner._pilot_pricing_contract(
            runner.PilotPricing("1", "2", 100_000, 16_384, 25_000_000, 72)
        )


def test_pilot_pricing_attestation_binds_live_model_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response_payload = {
        "data": [
            {
                "model_name": runner.MODEL,
                "litellm_params": {"model": runner.MODEL},
                "model_info": {
                    "input_cost_per_token": 0.000001,
                    "output_cost_per_token": 0.000006,
                    "max_input_tokens": 1_050_000,
                    "max_output_tokens": 128_000,
                },
            }
        ]
    }
    monkeypatch.setattr(
        runner.httpx,
        "get",
        lambda *_args, **_kwargs: runner.httpx.Response(
            200,
            json=response_payload,
        ),
    )

    attestation = runner._pilot_pricing_attestation(
        runner.PilotPricing("1", "6", 128_000, 32_768, 25_000_000, 72)
    )

    assert attestation["provider_input_usd_per_million_tokens"] == "1"
    assert attestation["provider_output_usd_per_million_tokens"] == "6"
    assert attestation["provider_max_input_tokens"] == 1_050_000
    assert attestation["provider_max_output_tokens"] == 128_000
    assert attestation["configured_prices_at_or_above_provider"] is True
    assert attestation["configured_token_bounds_within_provider"] is True


def test_pilot_pricing_attestation_rejects_underpriced_or_oversized_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response_payload = {
        "data": [
            {
                "model_name": runner.MODEL,
                "litellm_params": {"model": runner.MODEL},
                "model_info": {
                    "input_cost_per_token": "0.000001",
                    "output_cost_per_token": "0.000006",
                    "max_input_tokens": 128_000,
                    "max_output_tokens": 32_768,
                },
            }
        ]
    }
    monkeypatch.setattr(
        runner.httpx,
        "get",
        lambda *_args, **_kwargs: runner.httpx.Response(
            200,
            json=response_payload,
        ),
    )

    with pytest.raises(runner.RunnerError, match="below the live"):
        runner._pilot_pricing_attestation(
            runner.PilotPricing("0.99", "6", 128_000, 32_768, 25_000_000, 72)
        )
    with pytest.raises(runner.RunnerError, match="exceed the live"):
        runner._pilot_pricing_attestation(
            runner.PilotPricing("1", "6", 128_001, 32_768, 25_000_000, 72)
        )


def test_pilot_pricing_attestation_rejects_backend_alias_without_exact_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner.httpx,
        "get",
        lambda *_args, **_kwargs: runner.httpx.Response(
            200,
            json={
                "data": [
                    {
                        "model_name": "different-request-route",
                        "litellm_params": {"model": runner.MODEL},
                        "model_info": {
                            "input_cost_per_token": "0.000001",
                            "output_cost_per_token": "0.000006",
                            "max_input_tokens": 128_000,
                            "max_output_tokens": 32_768,
                        },
                    }
                ]
            },
        ),
    )

    with pytest.raises(runner.RunnerError, match="no exact"):
        runner._pilot_pricing_attestation(
            runner.PilotPricing("1", "6", 128_000, 32_768, 25_000_000, 72)
        )


def test_pilot_artifact_resume_preserves_deadline_and_reserved_budget(
    tmp_path: Path,
) -> None:
    pilots_root = tmp_path / "pilots-v1"
    pilot_id = "a" * 64
    pricing = {
        "model": runner.MODEL,
        "input_usd_per_million_tokens": "1",
        "output_usd_per_million_tokens": "2",
        "max_input_tokens": 100_000,
        "max_output_tokens": 32_768,
    }
    immutable = {
        "schema_version": 1,
        "artifact_kind": "pilot",
        "pilot_id": pilot_id,
        "selection_sha256": "b" * 64,
        "pricing_contract_sha256": hashlib.sha256(
            runner._canonical_json_bytes(pricing)
        ).hexdigest(),
        "pricing_contract": pricing,
        "max_attempts": 72,
        "max_cost_microusd": 25_000_000,
        "reservation_microusd": 165_536,
    }
    deadline = time.time() + 3600
    initial = {
        **immutable,
        "deadline_epoch_seconds": deadline,
        "attempts_reserved": 0,
        "attempts_completed": 0,
        "reserved_cost_microusd": 0,
        "spent_cost_microusd": 0,
        "attempt_receipts": [],
        "budget_breached": False,
    }
    selection = {
        "schema_version": 1,
        "artifact_kind": "pilot",
        "pilot_id": pilot_id,
    }
    pilot_root, _ledger = runner._prepare_pilot_artifacts(
        pilots_root,
        pilot_id=pilot_id,
        selection_document=selection,
        batch_bytes=b"CVE-2026-1\n",
        initial_ledger=initial,
        immutable_ledger=immutable,
    )
    mutated = json.loads(
        (pilot_root / "budget-ledger.json").read_text(encoding="utf-8")
    )
    mutated.update(
        {
            "attempts_reserved": 1,
            "reserved_cost_microusd": 165_536,
            "attempt_receipts": [
                {
                    "sequence": 1,
                    "admitted_at_epoch_seconds": time.time(),
                    "completed_at_epoch_seconds": None,
                    "status": "reserved",
                    "actual_cost_microusd": None,
                    "input_tokens": None,
                    "output_tokens": None,
                }
            ],
        }
    )
    runner._atomic_write_json(pilot_root / "budget-ledger.json", mutated)
    os.chmod(pilot_root / "budget-ledger.json", 0o600)

    _same_root, resumed = runner._prepare_pilot_artifacts(
        pilots_root,
        pilot_id=pilot_id,
        selection_document=selection,
        batch_bytes=b"CVE-2026-1\n",
        initial_ledger={**initial, "deadline_epoch_seconds": deadline + 3600},
        immutable_ledger=immutable,
    )

    assert resumed["deadline_epoch_seconds"] == deadline
    assert resumed["attempts_reserved"] == 1
    assert resumed["reserved_cost_microusd"] == 165_536


def test_pilot_budget_snapshot_rejects_incoherent_completed_attempt(
    tmp_path: Path,
) -> None:
    pricing = {
        "model": runner.MODEL,
        "input_usd_per_million_tokens": "1",
        "output_usd_per_million_tokens": "2",
        "max_input_tokens": 100_000,
        "max_output_tokens": 32_768,
    }
    immutable = {
        "schema_version": 1,
        "artifact_kind": "pilot",
        "pilot_id": "a" * 64,
        "selection_sha256": "b" * 64,
        "pricing_contract_sha256": hashlib.sha256(
            runner._canonical_json_bytes(pricing)
        ).hexdigest(),
        "pricing_contract": pricing,
        "max_attempts": 72,
        "max_cost_microusd": 25_000_000,
        "reservation_microusd": 165_536,
    }
    ledger = {
        **immutable,
        "deadline_epoch_seconds": time.time() + 3600,
        "attempts_reserved": 1,
        "attempts_completed": 1,
        "reserved_cost_microusd": 165_536,
        "spent_cost_microusd": 100,
        "attempt_receipts": [
            {
                "sequence": 1,
                "admitted_at_epoch_seconds": time.time(),
                "completed_at_epoch_seconds": time.time(),
                "status": "success",
                "actual_cost_microusd": 100,
                "input_tokens": None,
                "output_tokens": 10,
            }
        ],
        "budget_breached": False,
    }
    ledger_path = tmp_path / "budget-ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(
        runner.RunnerError,
        match="completed attempt receipt is invalid",
    ):
        runner._pilot_budget_snapshot(ledger_path, immutable=immutable)


def test_budget_attempt_window_rejects_admission_before_execution() -> None:
    ledger = {
        "attempt_receipts": [
            {
                "admitted_at_epoch_seconds": 10.0,
                "completed_at_epoch_seconds": 12.0,
            }
        ]
    }

    with pytest.raises(runner.RunnerError, match="outside its execution window"):
        runner._validate_budget_attempt_window(
            ledger,
            started_at_ns=11_000_000_000,
            completed_at_ns=13_000_000_000,
            deadline_ns=14_000_000_000,
        )


def test_pilot_cost_ceiling_requires_micro_usd_precision() -> None:
    assert runner._pilot_cost_ceiling_microusd("25") == 25_000_000
    with pytest.raises(runner.RunnerError, match="six decimal places"):
        runner._pilot_cost_ceiling_microusd("1.0000001")
    with pytest.raises(runner.RunnerError, match="no greater than USD 25"):
        runner._pilot_cost_ceiling_microusd("25.000001")


def test_openclaw_smoke_budget_requires_pilot_projection_to_fit() -> None:
    report = {
        "projected_openclaw_attempt_count": 40,
        "projected_openclaw_known_cost_floor_microusd": 2_000_000,
        "projected_openclaw_reservation_ceiling_microusd": 8_000_000,
    }

    with pytest.raises(runner.RunnerError, match="projected.*cost"):
        runner._openclaw_smoke_budget_contract(
            report,
            max_attempts=40,
            max_cost_microusd=7_999_999,
        )
    with pytest.raises(runner.RunnerError, match="projected.*attempt"):
        runner._openclaw_smoke_budget_contract(
            report,
            max_attempts=39,
            max_cost_microusd=8_000_000,
        )

    contract = runner._openclaw_smoke_budget_contract(
        report,
        max_attempts=40,
        max_cost_microusd=8_000_000,
    )
    assert contract["projection_fits_operator_budget"] is True
    assert contract["max_attempts"] == 40
    assert contract["max_cost_microusd"] == 8_000_000


def test_current_pilot_gate_rejects_pre_projection_identity(
    tmp_path: Path,
) -> None:
    paths = runner.RunnerPaths.defaults(tmp_path)
    legacy_identity = {
        "schema_version": 1,
        "artifact_kind": "pilot",
        "formal_release_eligible": False,
    }
    pilot_id = hashlib.sha256(runner._canonical_json_bytes(legacy_identity)).hexdigest()
    pilot_root = paths.state_dir.parent / "pilots-v1" / pilot_id
    pilot_root.mkdir(parents=True)
    (pilot_root / "selection.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_kind": "pilot",
                "formal_release_eligible": False,
                "pilot_id": pilot_id,
                "selection_sha256": "a" * 64,
                "identity": legacy_identity,
                "pricing_attestation": {},
                "selection": {},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(runner.RunnerError, match="pilot identity is malformed"):
        runner._validated_openclaw_pilot_completion(paths, pilot_id)


def test_openclaw_smoke_status_records_every_class_and_blocks_incomplete(
    tmp_path: Path,
) -> None:
    batch, campaign, started_at, started_at_ns, completed_at_ns = _receipt_fixture(
        tmp_path,
        receipt_completed_at="2026-07-18T12:00:05+00:00",
        result_mtime="2026-07-18T12:00:05+00:00",
    )
    smoke_batch = runner.BatchSpec(
        key=batch.key,
        path=batch.path,
        kind="openclaw_full_smoke",
        ids=("CVE-TEST", "CVE-MISSING"),
        repos=frozenset({"github.com/openclaw/openclaw"}),
        class_ids=("alias-test", "alias-missing"),
    )
    class_records = {
        subject: {
            "class_id": class_id,
            "component_sha256": hashlib.sha256(
                f"{subject}\n".encode("utf-8")
            ).hexdigest(),
            "source_snapshot_sha256": "9" * 64,
            "merged_source_evidence_sha256": "8" * 64,
            "analysis_input": {"git_ranges": []},
        }
        for subject, class_id in zip(
            smoke_batch.ids,
            smoke_batch.class_ids,
            strict=True,
        )
    }

    status = runner._openclaw_smoke_terminal_status(
        smoke_id="b" * 64,
        batch=smoke_batch,
        campaign=campaign,
        class_records=class_records,
        started_at=started_at,
        started_at_ns=started_at_ns,
        completed_at="2026-07-18T12:00:10+00:00",
        completed_at_ns=completed_at_ns,
        subprocess_exit_code=0,
        execution_error=None,
    )

    assert status["expected_class_count"] == 2
    assert status["terminal_class_count"] == 1
    assert status["incomplete_class_count"] == 1
    assert status["all_classes_terminal"] is False
    assert status["smoke_complete"] is False
    assert {item["analysis_subject"] for item in status["classes"]} == {
        "CVE-TEST",
        "CVE-MISSING",
    }
    terminal = next(
        item for item in status["classes"] if item["analysis_subject"] == "CVE-TEST"
    )
    incomplete = next(
        item for item in status["classes"] if item["analysis_subject"] == "CVE-MISSING"
    )
    assert terminal["terminal"] is True
    assert set(terminal["stages"]) == set(runner.ANALYSIS_STAGE_NAMES)
    assert incomplete["terminal"] is False
    assert "missing result" in incomplete["problem"]


def test_missing_current_openclaw_smoke_pointer_blocks_formal_gate(
    tmp_path: Path,
) -> None:
    status = _REAL_CURRENT_OPENCLAW_SMOKE_GATE_STATUS(
        runner.RunnerPaths.defaults(tmp_path)
    )

    assert status["status"] == "blocked"
    assert "current OpenClaw smoke pointer" in status["reason"]


def test_formal_dry_run_cannot_bypass_blocked_openclaw_smoke_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_campaign(tmp_path)
    refresh = runner.RefreshRunner(paths)
    monkeypatch.setattr(
        runner,
        "_current_openclaw_smoke_gate_status",
        lambda _paths: {"status": "blocked", "reason": "missing current smoke"},
    )

    with pytest.raises(runner.RunnerError, match="OpenClaw smoke gate.*blocked"):
        refresh.run(dry_run=True, batch_key="legacy-001")


def test_formal_dry_run_reports_ready_openclaw_smoke_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_campaign(tmp_path)
    refresh = runner.RefreshRunner(paths)
    monkeypatch.setattr(
        runner,
        "_current_openclaw_smoke_gate_status",
        lambda _paths: {
            "status": "ready",
            "smoke_id": "a" * 64,
            "class_count": 30,
        },
    )

    report = refresh.run(dry_run=True, batch_key="legacy-001")

    assert report[0] == {
        "batch": "openclaw-smoke-gate",
        "status": "gate_ready",
        "smoke_id": "a" * 64,
        "class_count": 30,
    }
    assert report[1] == {"batch": "legacy-001", "status": "dry_run"}


def test_parser_exposes_openclaw_smoke_budget_surface() -> None:
    args = runner.build_parser().parse_args(
        [
            "--openclaw-smoke",
            "--pilot-id",
            "a" * 64,
            "--smoke-cost-ceiling-usd",
            "8",
            "--smoke-max-attempts",
            "40",
        ]
    )

    assert args.openclaw_smoke is True
    assert args.pilot_id == "a" * 64
    assert args.smoke_cost_ceiling_usd == "8"
    assert args.smoke_max_attempts == 40


def test_main_requires_explicit_openclaw_smoke_budget(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = runner.main(
        [
            "--repo-root",
            str(tmp_path),
            "--openclaw-smoke",
            "--dry-run",
        ]
    )

    assert exit_code == 2
    assert (
        "OpenClaw smoke requires explicit pilot and budget inputs"
        in capsys.readouterr().err
    )
