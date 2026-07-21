"""Focused tests for the fail-closed source-delta builder."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import subprocess
import zipfile
import dataclasses
from pathlib import Path
from collections.abc import Sequence
from typing import Any

import pytest

import build_source_delta as builder
from web_data import release_evidence


_OFFICIAL_OSV_ECOSYSTEMS_2026_06_02 = (
    "AlmaLinux",
    "Alpaquita",
    "Alpine",
    "Android",
    "Azure Linux",
    "BellSoft Hardened Containers",
    "Bitnami",
    "CRAN",
    "Chainguard",
    "CleanStart",
    "Debian",
    "Echo",
    "GHC",
    "GIT",
    "GSD",
    "GitHub Actions",
    "Go",
    "Hackage",
    "Hex",
    "Julia",
    "Linux",
    "Mageia",
    "Maven",
    "MinimOS",
    "NuGet",
    "OSS-Fuzz",
    "Packagist",
    "Pub",
    "PyPI",
    "Red Hat",
    "Rocky Linux",
    "Root",
    "RubyGems",
    "SUSE",
    "SwiftURL",
    "TuxCare",
    "UVI",
    "Ubuntu",
    "VSCode",
    "Wolfi",
    "[EMPTY]",
    "crates.io",
    "npm",
    "opam",
    "openEuler",
    "openSUSE",
)


def test_official_osv_ecosystem_manifest_derives_all_46_archives_deterministically() -> (
    None
):
    raw = ("\n".join(_OFFICIAL_OSV_ECOSYSTEMS_2026_06_02) + "\n").encode()

    inventory = builder.parse_osv_ecosystems_manifest(raw)

    assert len(inventory.ecosystems) == 46
    assert set(inventory.ecosystems) == set(_OFFICIAL_OSV_ECOSYSTEMS_2026_06_02)
    assert inventory.archive_names == tuple(
        sorted(
            (f"{name}.zip" for name in _OFFICIAL_OSV_ECOSYSTEMS_2026_06_02),
            key=lambda name: (name.casefold(), name),
        )
    )
    assert "BellSoft Hardened Containers.zip" in inventory.archive_names
    assert "GitHub Actions.zip" in inventory.archive_names
    assert "[EMPTY].zip" in inventory.archive_names


@pytest.mark.parametrize(
    "raw",
    [
        b"PyPI\npypi\n",
        b"PyPI\nPyPI\n",
        b"PyPI\n../escape\n",
        b"PyPI\ntrailing \n",
        b"PyPI\n\x00bad\n",
        b"PyPI\n\xff\n",
    ],
)
def test_osv_ecosystem_manifest_rejects_unsafe_or_duplicate_names(raw: bytes) -> None:
    with pytest.raises(builder.SourceDeltaError, match="OSV ecosystem manifest"):
        builder.parse_osv_ecosystems_manifest(raw)


_GENERATED_AT = "2026-07-18T12:00:00+00:00"


def _git(directory: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(directory), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _loose_object_path(directory: Path, oid: str) -> Path:
    return directory / ".git" / "objects" / oid[:2] / oid[2:]


def _make_git_source(
    directory: Path,
    *,
    name: str,
    head_file: Path,
    origin: str,
    baseline_files: dict[str, str],
    current_files: dict[str, str],
) -> builder.GitSource:
    directory.mkdir(parents=True)
    _git(directory, "init", "-q")
    _git(directory, "config", "user.name", "Source Delta Test")
    _git(directory, "config", "user.email", "source-delta@example.invalid")
    _git(directory, "remote", "add", "origin", origin)
    for raw_path, content in baseline_files.items():
        path = directory / raw_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(directory, "add", ".")
    _git(directory, "commit", "-qm", "baseline")
    baseline_head = _git(directory, "rev-parse", "HEAD")
    head_file.write_text(baseline_head + "\n", encoding="ascii")
    for raw_path, content in current_files.items():
        path = directory / raw_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(directory, "add", ".")
    _git(directory, "commit", "-qm", "current")
    return builder.GitSource(name, directory, head_file, origin)


def _nvd_record(identifier: str, detail: str) -> dict[str, Any]:
    return {
        "cve": {"id": identifier, "descriptions": [{"lang": "en", "value": detail}]}
    }


def _write_nvd(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": records,
    }
    path.write_bytes(
        gzip.compress(json.dumps(payload, sort_keys=True).encode(), mtime=0)
    )


def test_nvd_loader_streams_and_enforces_compressed_and_expanded_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "nvdcve-2.0-2026.json.gz"
    _write_nvd(path, [_nvd_record("CVE-2026-4242", "bounded")])
    expanded_size = len(gzip.decompress(path.read_bytes()))

    def reject_unbounded_json_load(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("json.load must not consume an unbounded gzip stream")

    monkeypatch.setattr(builder.json, "load", reject_unbounded_json_load)
    assert set(builder._load_nvd(path, "test NVD")) == {"CVE-2026-4242"}

    monkeypatch.setattr(builder, "MAX_NVD_GZIP_BYTES", path.stat().st_size - 1)
    with pytest.raises(builder.SourceDeltaError, match="compressed size exceeds"):
        builder._load_nvd(path, "test NVD")

    monkeypatch.setattr(builder, "MAX_NVD_GZIP_BYTES", path.stat().st_size)
    monkeypatch.setattr(builder, "MAX_NVD_JSON_BYTES", expanded_size - 1)
    with pytest.raises(builder.SourceDeltaError, match="decompressed JSON exceeds"):
        builder._load_nvd(path, "test NVD")


def test_nvd_loader_enforces_validation_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "nvdcve-2.0-2026.json.gz"
    _write_nvd(path, [_nvd_record("CVE-2026-4242", "bounded")])
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(builder.time, "monotonic", lambda: next(ticks, 2.0))
    monkeypatch.setattr(builder, "NVD_VALIDATION_TIMEOUT_SECONDS", 1)

    with pytest.raises(builder.SourceDeltaError, match="validation exceeded 1 seconds"):
        builder._load_nvd(path, "test NVD")


def test_nvd_loader_checks_deadline_after_last_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "nvdcve-2.0-2026.json.gz"
    _write_nvd(path, [_nvd_record("CVE-2026-4242", "bounded")])
    calls = 0

    def deadline_after_record(_started: float, _label: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 6:
            raise builder.SourceDeltaError("deadline after final NVD record")

    monkeypatch.setattr(builder, "_check_nvd_deadline", deadline_after_record)
    with pytest.raises(builder.SourceDeltaError, match="after final NVD record"):
        builder._load_nvd(path, "test NVD")


def test_nvd_loader_parses_the_content_addressed_descriptor_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "nvdcve-2.0-2026.json.gz"
    _write_nvd(path, [_nvd_record("CVE-2026-1111", "original")])
    original = path.read_bytes()
    malicious_payload = {
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [_nvd_record("CVE-2026-2222", "switched")],
    }
    malicious = gzip.compress(
        json.dumps(malicious_payload, sort_keys=True).encode(),
        mtime=0,
    )
    width = max(len(original), len(malicious))
    original = original.ljust(width, b"\0")
    malicious = malicious.ljust(width, b"\0")
    path.write_bytes(original)
    inode = path.stat().st_ino
    expected = {
        "size_bytes": len(original),
        "sha256": hashlib.sha256(original).hexdigest(),
    }
    real_gzip_file = gzip.GzipFile

    class SwitchingGzipFile:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._inner = real_gzip_file(*args, **kwargs)
            self._switched = False

        def __enter__(self) -> SwitchingGzipFile:
            self._inner.__enter__()
            return self

        def __exit__(self, *args: object) -> object:
            return self._inner.__exit__(*args)

        def read(self, size: int = -1) -> bytes:
            if not self._switched:
                self._switched = True
                path.write_bytes(malicious)
                assert path.stat().st_ino == inode
                data = self._inner.read(size)
                path.write_bytes(original)
                assert path.stat().st_ino == inode
                return data
            return self._inner.read(size)

    monkeypatch.setattr(builder.gzip, "GzipFile", SwitchingGzipFile)

    assert set(builder._load_nvd(path, "test NVD", expected_snapshot=expected)) == {
        "CVE-2026-1111"
    }
    assert path.read_bytes() == original


def test_nvd_loader_uses_nofollow_open_for_the_validated_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "nvdcve-2.0-2026.json.gz"
    replacement = tmp_path / "replacement.json.gz"
    _write_nvd(path, [_nvd_record("CVE-2026-1111", "original")])
    _write_nvd(replacement, [_nvd_record("CVE-2026-2222", "replacement")])
    expected = {
        "size_bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    real_open = os.open
    called = False

    def replace_before_open(raw_path: object, flags: int, *args: object) -> int:
        nonlocal called
        if Path(raw_path) == path:
            called = True
            path.unlink()
            path.symlink_to(replacement)
        return real_open(raw_path, flags, *args)

    monkeypatch.setattr(builder.os, "open", replace_before_open)
    with pytest.raises(builder.SourceDeltaError, match="cannot open|non-symlink"):
        builder._load_nvd(path, "test NVD", expected_snapshot=expected)
    assert called


def _write_zip(path: Path, records: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for index, (name, record) in enumerate(sorted(records.items()), 1):
            info = zipfile.ZipInfo(
                name,
                date_time=(2026, 7, 18, 12, 0, index * 2),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, json.dumps(record, sort_keys=True))


def _write_manifest(baseline: Path) -> None:
    entries = []
    for path in sorted(baseline.iterdir(), key=lambda item: item.name):
        if path.name == "SHA256SUMS":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {path.name}")
    (baseline / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")


def _write_cached_result(
    directory: Path,
    subject_id: str,
    *,
    error_category: str = "",
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    result = builder.CveAnalysisResult(
        cve_id=subject_id,
        error_category=error_category,
        phase_times={
            "Phase A (discovery)": 0.1,
            "Phase B (blame)": 0.2,
        },
    )
    (directory / f"{subject_id}.json").write_text(
        json.dumps(result.to_dict(), sort_keys=True),
        encoding="utf-8",
    )


def _fixture_paths(tmp_path: Path) -> builder.BuildPaths:
    root = tmp_path / "repo"
    analyzer_source = root / "cve-analyzer/src/cve_analyzer"
    analyzer_source.mkdir(parents=True)
    (root / "cve-analyzer/pyproject.toml").write_text(
        "[project]\nname='fixture'\n", encoding="utf-8"
    )
    (root / "cve-analyzer/uv.lock").write_text("version = 1\n", encoding="utf-8")
    (analyzer_source / "ai_signatures.py").write_text(
        "SIGNATURES = ['codex']\n", encoding="utf-8"
    )
    (analyzer_source / "pipeline.py").write_text("CONTRACT = 1\n", encoding="utf-8")
    baseline = root / ".ai-slop/state/data-refresh/source-before-final"
    state = baseline.parent
    cache = tmp_path / "cache"
    baseline.mkdir(parents=True)
    (baseline / "new-osv-candidates.txt").write_text(
        "CVE-BASE-1\nCVE-BASE-1\nGHSA-base-base-base\n",
        encoding="utf-8",
    )
    corpus = state / "adjudicated-corpus-subjects.txt"
    corpus.write_text("CVE-CORPUS-1\nCVE-2025-3000\n", encoding="utf-8")

    cvelist = _make_git_source(
        cache / "cvelistV5",
        name="cvelistV5",
        head_file=baseline / "cvelistV5.head",
        origin=builder._CVELIST_ORIGIN,
        baseline_files={
            "cves/CVE-2026-1000.json": json.dumps(
                {"cveMetadata": {"cveId": "CVE-2026-1000"}}
            )
        },
        current_files={
            "cves/CVE-2026-1000.json": json.dumps(
                {
                    "cveMetadata": {"cveId": "CVE-2026-1000"},
                    "aliases": ["GHSA-aaaa-bbbb-cccc"],
                }
            )
        },
    )
    ghsa = _make_git_source(
        cache / "advisory-database",
        name="github-advisory-database",
        head_file=baseline / "github-advisory-database.head",
        origin=builder._GHSA_ORIGIN,
        baseline_files={
            "advisories/github-reviewed/2026/06/GHSA-old1-old2-old3/GHSA-old1-old2-old3.json": json.dumps(
                {
                    "id": "GHSA-old1-old2-old3",
                    "aliases": ["CVE-2026-1100"],
                    "published": "2026-06-01T00:00:00Z",
                }
            ),
            "advisories/github-reviewed/2025/06/GHSA-unc1-unc2-unc3/GHSA-unc1-unc2-unc3.json": json.dumps(
                {
                    "id": "GHSA-unc1-unc2-unc3",
                    "aliases": [],
                    "published": "2025-06-02T00:00:00Z",
                }
            ),
            "advisories/github-reviewed/2025/07/GHSA-cach-cach-cach/GHSA-cach-cach-cach.json": json.dumps(
                {
                    "id": "GHSA-cach-cach-cach",
                    "aliases": ["CVE-2025-5555"],
                    "published": "2025-07-03T00:00:00Z",
                }
            ),
        },
        current_files={
            "advisories/github-reviewed/2026/06/GHSA-old1-old2-old3/GHSA-old1-old2-old3.json": json.dumps(
                {
                    "id": "GHSA-old1-old2-old3",
                    "aliases": ["CVE-2026-1100", "CVE-2026-1101"],
                    "published": "2026-06-01T00:00:00Z",
                }
            )
        },
    )
    gemnasium = _make_git_source(
        cache / "gemnasium-db",
        name="gemnasium-db",
        head_file=baseline / "gemnasium-db.head",
        origin=builder._GEMNASIUM_ORIGIN,
        baseline_files={
            "npm/pkg/CVE-2026-1200.yml": (
                'identifier: "CVE-2026-1200"\nidentifiers:\n- "CVE-2026-1200"\n'
            )
        },
        current_files={
            "npm/pkg/CVE-2026-1200.yml": (
                'identifier: "CVE-2026-1200"\nidentifiers:\n'
                '- "CVE-2026-1200"\n- "GHSA-dddd-eeee-ffff"\n'
            )
        },
    )

    _write_nvd(
        baseline / "nvdcve-2.0-2025.json.gz",
        [
            _nvd_record("CVE-2025-1000", "old"),
            _nvd_record("CVE-2025-2000", "removed"),
        ],
    )
    _write_nvd(
        cache / "nvd-feeds/nvdcve-2.0-2025.json.gz",
        [
            _nvd_record("CVE-2025-1000", "new"),
            _nvd_record("CVE-2025-3000", "added"),
        ],
    )
    _write_nvd(
        baseline / "nvdcve-2.0-2026.json.gz",
        [_nvd_record("CVE-2026-2000", "same")],
    )
    _write_nvd(
        cache / "nvd-feeds/nvdcve-2.0-2026.json.gz",
        [_nvd_record("CVE-2026-2000", "same")],
    )

    _write_zip(
        baseline / "GIT.zip",
        {
            "changed.json": {"id": "OSV-GIT-1", "aliases": ["CVE-2026-2100"]},
            "removed.json": {"id": "OSV-GIT-REMOVED"},
        },
    )
    _write_zip(
        cache / "osv-bulk/GIT.zip",
        {
            "changed.json": {
                "id": "OSV-GIT-1",
                "aliases": ["CVE-2026-2100", "GHSA-gggg-hhhh-iiii"],
            },
            "added.json": {"id": "OSV-GIT-ADDED"},
            "blameable.json": {
                "id": "OSV-GIT-BLAMEABLE",
                "aliases": ["CVE-2025-7777"],
                "published": "2025-06-01T00:00:00Z",
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "GIT",
                                "repo": "https://example.test/repo.git",
                            }
                        ]
                    }
                ],
            },
            "covered.json": {
                "id": "OSV-GIT-COVERED",
                "aliases": ["CVE-2025-8888", "GHSA-osvc-osvc-osvc"],
                "published": "2025-06-02T00:00:00Z",
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "GIT",
                                "repo": "https://example.test/repo.git",
                            }
                        ]
                    }
                ],
            },
        },
    )
    _write_zip(
        cache / "osv-bulk/npm.zip",
        {"npm.json": {"id": "OSV-NPM-UNCHANGED-BASELINE"}},
    )
    _write_cached_result(cache / "results", "GHSA-cach-cach-cach")
    _write_cached_result(cache / "results", "GHSA-osvc-osvc-osvc")
    _write_cached_result(
        cache / "results",
        "GHSA-unc1-unc2-unc3",
        error_category="clone_failed",
    )
    ecosystems_file = cache / "osv-bulk" / builder.OSV_ECOSYSTEMS_FILENAME
    ecosystems_file.write_text("GIT\nnpm\n", encoding="utf-8")
    _write_manifest(baseline)
    return builder.BuildPaths(
        repo_root=root,
        baseline_dir=baseline,
        git_sources=(cvelist, ghsa, gemnasium),
        nvd_dir=cache / "nvd-feeds",
        osv_dir=cache / "osv-bulk",
        osv_ecosystems_file=ecosystems_file,
        result_cache_dir=cache / "results",
        delta_output=state / "source-delta-current.json",
        candidate_output=state / "new-osv-candidates.txt",
        adjudicated_corpus_file=corpus,
    )


def test_builds_complete_delta_and_exact_candidate_union(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)

    delta = builder.build_source_delta(paths, generated_at_utc=_GENERATED_AT)

    assert delta["schema_version"] == builder.SCHEMA_VERSION
    assert delta["population_policy"] == builder.FORMAL_FULL_POLICY
    assert delta["candidate"]["formal_release_eligible"] is True
    assert delta["analyzer_contract"]["input_count"] == 4
    assert delta["source_snapshot_time"] == _GENERATED_AT
    assert delta["input_snapshot"]["osv_archive_names"] == ["GIT.zip", "npm.zip"]
    assert delta["coverage"] == {
        "git_mirror_count": 3,
        "nvd_feed_count": 2,
        "current_osv_archive_count": 2,
        "member_diff_osv_archive_count": 1,
        "sparse_baseline_osv_archive_count": 1,
        "sparse_baseline_osv_archives": ["npm"],
        "sparse_baseline_semantics": (
            "archives absent from the preserved baseline are validated and hashed, but contribute no inferred member delta"
        ),
    }
    assert delta["git"]["cvelistV5"]["subject_ids"] == [
        "CVE-2026-1000",
        "GHSA-aaaa-bbbb-cccc",
    ]
    assert delta["git"]["gemnasium-db"]["subject_ids"] == [
        "CVE-2026-1200",
        "GHSA-dddd-eeee-ffff",
    ]
    assert delta["nvd"]["2025"]["added"] == ["CVE-2025-3000"]
    assert delta["nvd"]["2025"]["changed"] == ["CVE-2025-1000"]
    assert delta["nvd"]["2025"]["removed"] == ["CVE-2025-2000"]
    assert delta["osv"]["GIT"]["added_members"] == [
        "added.json",
        "blameable.json",
        "covered.json",
    ]
    assert delta["osv"]["GIT"]["changed_members"] == ["changed.json"]
    assert delta["osv"]["GIT"]["removed_members"] == ["removed.json"]
    assert delta["osv"]["npm"]["comparison"] == "baseline_not_preserved"
    assert "OSV-NPM-UNCHANGED-BASELINE" not in delta["all_ids"]
    assert delta["candidate"]["baseline_line_count"] == 3
    assert delta["candidate"]["baseline_unique_id_count"] == 2
    assert delta["candidate"]["baseline_duplicate_line_count"] == 1
    assert delta["production_discovery"]["production_discovered_id_count"] == 5
    assert delta["production_discovery"]["cache_covered_discovered_id_count"] == 2
    assert delta["production_discovery"]["uncached_discovered_id_count"] == 3
    assert delta["production_discovery"]["uncached_osv_id_count"] == 1
    assert delta["production_discovery"]["uncached_ghsa_supplement_id_count"] == 2
    assert delta["production_discovery"]["alias_aware_cache_coverage"] is True
    discovery = delta["production_discovery"]
    discovered_ids = set(discovery["production_discovered_ids"])
    covered_ids = set(discovery["cache_covered_discovered_ids"])
    uncached_ids = set(discovery["uncached_discovered_ids"])
    assert discovery["production_discovered_ids"] == sorted(discovered_ids)
    assert discovery["cache_covered_discovered_ids"] == sorted(covered_ids)
    assert discovery["uncached_discovered_ids"] == sorted(uncached_ids)
    assert covered_ids.isdisjoint(uncached_ids)
    assert discovered_ids == covered_ids | uncached_ids
    assert uncached_ids == set(discovery["uncached_osv_ids"]) | set(
        discovery["uncached_ghsa_supplement_ids"]
    )
    assert delta["result_cache"]["schema_valid_result_count"] == 3
    assert delta["result_cache"]["coverage_eligible_result_count"] == 2
    assert delta["result_cache"]["coverage_ineligible_result_count"] == 1
    assert delta["result_cache"]["coverage_ineligible_reason_counts"] == {
        "nonterminal_or_unsupported_clone_failed": 1
    }
    assert delta["result_cache"]["all_json_results_schema_valid"] is True
    assert (
        delta["result_cache"]["coverage_policy"]["current_luna_max_receipt_required"]
        is False
    )
    assert delta["candidate"]["output_duplicate_id_count"] == 0
    assert delta["candidate"]["union_exact"] is True
    candidate_ids = paths.candidate_output.read_text(encoding="utf-8").splitlines()
    assert "CVE-2025-5555" in candidate_ids
    assert "CVE-2025-8888" in candidate_ids  # preserved independently by source delta
    assert candidate_ids[:2] == ["CVE-BASE-1", "GHSA-base-base-base"]
    assert len(candidate_ids) == len(set(candidate_ids))
    alias_manifest = delta["production_discovery"]["alias_class_manifest"]
    assert alias_manifest["scheduled_classes_exactly_once"] is True
    assert alias_manifest["scheduled_analysis_subject_count"] == len(candidate_ids)
    assert set(candidate_ids) == {
        item["analysis_subject"]
        for item in alias_manifest["classes"]
        if item["scheduled_seed_ids"]
    }
    assert all(
        item["source_snapshot_sha256"]
        == builder.advisory_source_snapshot_sha256(delta["input_snapshot"])
        for item in alias_manifest["classes"]
    )
    assert json.loads(paths.delta_output.read_text()) == delta


def test_incremental_policy_is_explicit_and_cache_can_suppress(tmp_path: Path) -> None:
    paths = dataclasses.replace(
        _fixture_paths(tmp_path),
        population_policy=builder.INCREMENTAL_POLICY,
    )
    delta = builder.build_source_delta(paths, generated_at_utc=_GENERATED_AT)
    candidate_ids = paths.candidate_output.read_text(encoding="utf-8").splitlines()

    assert delta["population_policy"] == builder.INCREMENTAL_POLICY
    assert delta["candidate"]["formal_release_eligible"] is False
    assert delta["candidate"]["historical_cache_suppresses_current_classes"] is True
    assert "CVE-2025-5555" not in candidate_ids


def test_explicit_timestamp_makes_rebuild_byte_reproducible(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    builder.build_source_delta(paths, generated_at_utc=_GENERATED_AT)
    first_delta = paths.delta_output.read_bytes()
    first_candidates = paths.candidate_output.read_bytes()

    builder.build_source_delta(paths, generated_at_utc=_GENERATED_AT)

    assert paths.delta_output.read_bytes() == first_delta
    assert paths.candidate_output.read_bytes() == first_candidates


def test_corrupt_baseline_checksum_fails_without_replacing_outputs(
    tmp_path: Path,
) -> None:
    paths = _fixture_paths(tmp_path)
    paths.delta_output.write_text("old delta\n", encoding="utf-8")
    paths.candidate_output.write_text("OLD-CANDIDATE-1\n", encoding="utf-8")
    baseline_candidate = paths.baseline_dir / "new-osv-candidates.txt"
    baseline_candidate.write_text("CVE-TAMPERED-1\n", encoding="utf-8")

    with pytest.raises(builder.SourceDeltaError, match="checksum mismatch"):
        builder.build_source_delta(paths, generated_at_utc=_GENERATED_AT)

    assert paths.delta_output.read_text() == "old delta\n"
    assert paths.candidate_output.read_text() == "OLD-CANDIDATE-1\n"


def test_wrong_git_history_and_origin_fail_closed(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    source = paths.git_sources[0]
    source.baseline_head_file.write_text("0" * 40 + "\n", encoding="ascii")
    _write_manifest(paths.baseline_dir)

    with pytest.raises(builder.SourceDeltaError, match="not an ancestor"):
        builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)

    paths = _fixture_paths(tmp_path / "second")
    _git(
        paths.git_sources[1].directory,
        "remote",
        "set-url",
        "origin",
        "https://evil.invalid/wrong.git",
    )
    with pytest.raises(builder.SourceDeltaError, match="wrong Git origin"):
        builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)


def test_git_state_ignores_ambient_repository_redirects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "https://example.invalid/advisories.git"
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin=origin,
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    redirected = _make_git_source(
        tmp_path / "redirected",
        name="redirected",
        head_file=tmp_path / "redirected.head",
        origin=origin,
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    _git(redirected.directory, "commit", "--amend", "-qm", "redirected fixture")
    source_head = _git(source.directory, "rev-parse", "HEAD")
    redirected_head = _git(redirected.directory, "rev-parse", "HEAD")
    assert source_head != redirected_head

    monkeypatch.setenv("GIT_DIR", str(redirected.directory / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(source.directory))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.filemode")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")

    state = builder._git_state(source)

    assert state["head"] == source_head
    assert state["head"] != redirected_head


def test_safe_git_command_disables_fsmonitor_external_helper(
    tmp_path: Path,
) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    sentinel = tmp_path / "fsmonitor-invoked"
    fsmonitor = tmp_path / "fsmonitor.sh"
    fsmonitor.write_text(
        f"#!/bin/sh\nprintf invoked > {sentinel}\n",
        encoding="utf-8",
    )
    fsmonitor.chmod(0o755)
    _git(source.directory, "config", "core.fsmonitor", str(fsmonitor))

    builder._run_git(source, ["status", "--porcelain=v1"])

    assert not sentinel.exists()
    with pytest.raises(builder.SourceDeltaError, match="external Git config"):
        builder._git_state(source)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("fsck.skipList", "ignored-oids.txt"),
        ("fsck.missingEmail", "ignore"),
        ("receive.fsckObjects", "false"),
        ("fetch.fsckObjects", "false"),
    ],
)
def test_git_state_rejects_local_fsck_downgrades(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    if key == "fsck.skipList":
        (source.directory / value).write_text("0" * 40 + "\n", encoding="ascii")
    _git(source.directory, "config", key, value)

    with pytest.raises(builder.SourceDeltaError, match="external Git config"):
        builder._git_state(source)


def test_safe_git_environment_blocks_external_remote_helpers(tmp_path: Path) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    sentinel = tmp_path / "external-helper-invoked"
    external_remote = f"ext::sh -c 'printf invoked > {sentinel}'"

    with pytest.raises(builder.SourceDeltaError, match="Git command failed"):
        builder._run_git(source, ["ls-remote", external_remote, "HEAD"])

    assert not sentinel.exists()


def test_git_capture_cap_accepts_measured_july_2026_inventories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    measured_outputs = {
        "cvelist_stage": 31_984_666,
        "cvelist_debug": 61_343_367,
        "cvelist_tree": 32_351_844,
        "ghsa_stage": 44_388_241,
        "ghsa_debug": 72_107_801,
        "ghsa_tree": 44_736_445,
        "gemnasium_debug": 8_715_249,
    }
    assert builder.MAX_GIT_STDOUT_BYTES > max(measured_outputs.values())

    captured: dict[str, object] = {}

    def bounded(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, b"complete", b"")

    monkeypatch.setattr(builder, "_run_argv_bounded", bounded)
    source = builder.GitSource(
        "measured",
        tmp_path,
        tmp_path / "baseline.head",
        "https://example.invalid/advisories.git",
    )

    assert builder._run_git(source, ["status"]) == b"complete"
    assert captured["max_stdout_bytes"] == builder.MAX_GIT_STDOUT_BYTES
    assert captured["max_stderr_bytes"] == builder.MAX_GIT_STDERR_BYTES
    assert captured["timeout"] == builder.GIT_COMMAND_TIMEOUT_SECONDS

    assert (
        builder._run_git(
            source,
            ["fsck", "--full", "--strict", "--no-dangling", "--no-progress"],
        )
        == b"complete"
    )
    assert captured["timeout"] == builder.GIT_FSCK_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    "incomplete_flag",
    [
        "stdout_limit_exceeded",
        "stderr_limit_exceeded",
        "stdout_drain_incomplete",
        "stderr_drain_incomplete",
    ],
)
def test_git_capture_rejects_limits_and_incomplete_drains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    incomplete_flag: str,
) -> None:
    def bounded(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.CompletedProcess(command, 0, b"partial", b"")
        setattr(result, incomplete_flag, True)
        return result

    monkeypatch.setattr(builder, "_run_argv_bounded", bounded)
    source = builder.GitSource(
        "bounded",
        tmp_path,
        tmp_path / "baseline.head",
        "https://example.invalid/advisories.git",
    )

    with pytest.raises(builder.SourceDeltaError, match="output was incomplete"):
        builder._run_git(source, ["status"])


@pytest.mark.parametrize(
    "index_flag",
    ["--assume-unchanged", "--skip-worktree"],
)
def test_git_state_rejects_index_flags_that_hide_forged_worktree_bytes(
    tmp_path: Path,
    index_flag: str,
) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": '{"id":"CVE-2026-1000"}\n'},
        current_files={"source.json": '{"id":"CVE-2026-2000"}\n'},
    )
    _git(source.directory, "update-index", index_flag, "source.json")
    (source.directory / "source.json").write_text(
        '{"id":"CVE-2026-9000"}\n',
        encoding="utf-8",
    )
    assert (
        _git(
            source.directory,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
        == ""
    )

    with pytest.raises(builder.SourceDeltaError, match="index flags"):
        builder._git_state(source)


def test_git_state_rejects_symlinked_object_fanout(
    tmp_path: Path,
) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    objects = source.directory / ".git/objects"
    fanout = next(
        path
        for path in objects.iterdir()
        if path.is_dir() and path.name not in {"info", "pack"}
    )
    external = tmp_path / "external-objects"
    fanout.rename(external)
    fanout.symlink_to(external, target_is_directory=True)

    with pytest.raises(builder.SourceDeltaError, match="redirected or unsupported"):
        builder._git_state(source)


def test_git_state_rejects_missing_head_blob_object(tmp_path: Path) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    oid = _git(source.directory, "rev-parse", "HEAD:source.json")
    _loose_object_path(source.directory, oid).unlink()

    with pytest.raises(builder.SourceDeltaError, match="Git command failed"):
        builder._git_state(source)


def test_git_state_rejects_missing_reachable_history_blob_object(
    tmp_path: Path,
) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    oid = _git(source.directory, "rev-parse", "HEAD^:source.json")
    _loose_object_path(source.directory, oid).unlink()

    with pytest.raises(builder.SourceDeltaError, match="Git command failed"):
        builder._git_state(source)


def test_git_state_rejects_corrupt_reachable_blob_object(tmp_path: Path) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    oid = _git(source.directory, "rev-parse", "HEAD:source.json")
    object_path = _loose_object_path(source.directory, oid)
    object_path.chmod(0o644)
    object_path.write_bytes(b"corrupt object")

    with pytest.raises(builder.SourceDeltaError, match="Git command failed"):
        builder._git_state(source)


def _validate_with_fsck_cache(
    source: builder.GitSource,
    cache: builder.SuccessfulGitFsckCache,
    fsck_calls: list[int],
) -> None:
    def git_output(arguments: Sequence[str]) -> str:
        if arguments and arguments[0] == "fsck":
            fsck_calls[0] += 1
        return builder._decode_git_text(source, arguments).strip()

    builder.validate_git_repository_safety(
        source.directory,
        f"{source.name} Git mirror",
        git_output,
        fsck_cache=cache,
    )


@pytest.mark.parametrize("object_storage", ["loose", "pack"])
def test_successful_fsck_cache_skips_same_key_and_invalidates_object_metadata(
    tmp_path: Path,
    object_storage: str,
) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    if object_storage == "pack":
        _git(source.directory, "gc", "--prune=now")
        target = next((source.directory / ".git/objects/pack").glob("*.pack"))
    else:
        oid = _git(source.directory, "rev-parse", "HEAD:source.json")
        target = _loose_object_path(source.directory, oid)
    cache = builder.SuccessfulGitFsckCache(max_entries=4)
    fsck_calls = [0]

    _validate_with_fsck_cache(source, cache, fsck_calls)
    _validate_with_fsck_cache(source, cache, fsck_calls)
    assert fsck_calls == [1]

    metadata = target.stat()
    os.utime(
        target,
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
    )
    _validate_with_fsck_cache(source, cache, fsck_calls)
    assert fsck_calls == [2]


def test_failed_fsck_is_never_cached(tmp_path: Path) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    cache = builder.SuccessfulGitFsckCache(max_entries=4)

    def failing_output(arguments: Sequence[str]) -> str:
        if arguments and arguments[0] == "fsck":
            raise builder.SourceDeltaError("forced fsck failure")
        return builder._decode_git_text(source, arguments).strip()

    with pytest.raises(builder.SourceDeltaError, match="forced fsck failure"):
        builder.validate_git_repository_safety(
            source.directory,
            "source Git mirror",
            failing_output,
            fsck_cache=cache,
        )
    assert len(cache) == 0

    fsck_calls = [0]
    _validate_with_fsck_cache(source, cache, fsck_calls)
    assert fsck_calls == [1]
    assert len(cache) == 1


def test_successful_fsck_cache_is_bounded_lru() -> None:
    cache = builder.SuccessfulGitFsckCache(max_entries=2)
    keys = [
        (f"/repo/{index}", f"head-{index}", f"tree-{index}", f"meta-{index}")
        for index in range(3)
    ]
    for key in keys:
        cache.record_success(key)

    assert len(cache) == 2
    assert cache.contains(keys[0]) is False
    assert cache.contains(keys[1]) is True
    assert cache.contains(keys[2]) is True


def test_one_build_reuses_successful_fsck_across_all_input_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture_paths(tmp_path)
    original = builder._run_git
    fsck_calls = 0

    def counted_run_git(
        source: builder.GitSource,
        arguments: Sequence[str],
    ) -> bytes:
        nonlocal fsck_calls
        if arguments and arguments[0] == "fsck":
            fsck_calls += 1
        return original(source, arguments)

    monkeypatch.setattr(builder, "_run_git", counted_run_git)

    builder.build_source_delta(paths, generated_at_utc=_GENERATED_AT)

    assert fsck_calls == len(paths.git_sources)


def test_builder_strict_state_never_uses_process_fsck_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    original = builder._run_git
    fsck_calls = 0

    def counted_run_git(
        target: builder.GitSource,
        arguments: Sequence[str],
    ) -> bytes:
        nonlocal fsck_calls
        if arguments and arguments[0] == "fsck":
            fsck_calls += 1
        return original(target, arguments)

    monkeypatch.setattr(builder, "_run_git", counted_run_git)

    builder._git_state(source)
    builder._git_state(source)
    assert fsck_calls == 2


def test_git_state_rejects_worktree_config_before_filter_execution(
    tmp_path: Path,
) -> None:
    trusted = '{"id":"CVE-2026-2000"}\n'
    forged = '{"id":"CVE-2026-9000"}\n'
    assert len(trusted) == len(forged)
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={
            ".gitattributes": "source.json filter=evil\n",
            "source.json": '{"id":"CVE-2026-1000"}\n',
        },
        current_files={"source.json": trusted},
    )
    sentinel = tmp_path / "filter-invoked"
    filter_program = tmp_path / "evil-filter.sh"
    filter_program.write_text(
        "#!/bin/sh\n"
        f"printf invoked > {sentinel}\n"
        f"printf '%s\\n' '{trusted.rstrip()}'\n",
        encoding="utf-8",
    )
    filter_program.chmod(0o755)
    _git(source.directory, "config", "extensions.worktreeConfig", "true")
    (source.directory / ".git/config.worktree").write_text(
        f'[filter "evil"]\n\tclean = {filter_program}\n\trequired = true\n',
        encoding="utf-8",
    )
    (source.directory / "source.json").write_text(forged, encoding="utf-8")

    with pytest.raises(builder.SourceDeltaError, match="worktree config"):
        builder._git_state(source)

    assert not sentinel.exists()


def test_compare_git_treats_magic_looking_filename_as_a_literal_path(
    tmp_path: Path,
) -> None:
    magic_path = ":(literal)CVE-MAGIC.json"
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"baseline.json": '{"id":"CVE-2026-1000"}\n'},
        current_files={magic_path: '{"id":"CVE-2026-4242"}\n'},
    )

    evidence = builder._compare_git(source, builder._git_state(source))

    assert evidence["changed_files"] == [magic_path]
    assert evidence["parsed_advisory_files"] == [magic_path]
    assert evidence["subject_ids"] == ["CVE-2026-4242"]


def test_git_state_rejects_ignored_untracked_advisory_files(tmp_path: Path) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={
            ".gitignore": "ignored/\n",
            "source.json": '{"id":"CVE-2026-1000"}\n',
        },
        current_files={"source.json": '{"id":"CVE-2026-2000"}\n'},
    )
    ignored = source.directory / "ignored/CVE-2026-9000.json"
    ignored.parent.mkdir()
    ignored.write_text('{"id":"CVE-2026-9000"}\n', encoding="utf-8")
    assert (
        _git(
            source.directory,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
        == ""
    )

    with pytest.raises(builder.SourceDeltaError, match="worktree differs"):
        builder._git_state(source)


def test_git_state_rejects_intent_to_add_index_entries(tmp_path: Path) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": '{"id":"CVE-2026-1000"}\n'},
        current_files={"source.json": '{"id":"CVE-2026-2000"}\n'},
    )
    (source.directory / "intent.json").write_text(
        '{"id":"CVE-2026-9000"}\n',
        encoding="utf-8",
    )
    _git(source.directory, "add", "--intent-to-add", "intent.json")

    with pytest.raises(builder.SourceDeltaError, match="index flags"):
        builder._git_state(source)


def test_git_state_rejects_unmerged_index_entries(tmp_path: Path) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": '{"id":"CVE-2026-1000"}\n'},
        current_files={"source.json": '{"id":"CVE-2026-2000"}\n'},
    )
    blob = _git(source.directory, "rev-parse", "HEAD:source.json")
    subprocess.run(
        ["git", "-C", str(source.directory), "update-index", "--index-info"],
        input=(
            f"0 {'0' * len(blob)}\tsource.json\n"
            f"100644 {blob} 1\tsource.json\n"
            f"100644 {blob} 2\tsource.json\n"
            f"100644 {blob} 3\tsource.json\n"
        ),
        check=True,
        text=True,
    )

    with pytest.raises(builder.SourceDeltaError, match="unmerged"):
        builder._git_state(source)


def test_git_state_rejects_gitlink_tree_entries(tmp_path: Path) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": '{"id":"CVE-2026-1000"}\n'},
        current_files={"source.json": '{"id":"CVE-2026-2000"}\n'},
    )
    head = _git(source.directory, "rev-parse", "HEAD")
    _git(
        source.directory,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{head},advisories/github-reviewed",
    )
    _git(source.directory, "commit", "-qm", "add forbidden gitlink")

    with pytest.raises(builder.SourceDeltaError, match="gitlink"):
        builder._git_state(source)


def test_git_state_rejects_nested_git_metadata(tmp_path: Path) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"nested/source.json": '{"id":"CVE-2026-1000"}\n'},
        current_files={"nested/source.json": '{"id":"CVE-2026-2000"}\n'},
    )
    nested_metadata = source.directory / "nested/.git"
    nested_metadata.mkdir()
    (nested_metadata / "forged.json").write_text(
        '{"id":"CVE-2026-9000"}\n',
        encoding="utf-8",
    )
    assert (
        _git(
            source.directory,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
        == ""
    )

    with pytest.raises(builder.SourceDeltaError, match="nested Git metadata"):
        builder._git_state(source)


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
def test_git_state_rejects_object_and_history_indirections(
    tmp_path: Path,
    indirection: str,
    error_pattern: str,
) -> None:
    source = _make_git_source(
        tmp_path / "source",
        name="source",
        head_file=tmp_path / "source.head",
        origin="https://example.invalid/advisories.git",
        baseline_files={"source.json": "baseline\n"},
        current_files={"source.json": "current\n"},
    )
    git_dir = source.directory / ".git"
    head = _git(source.directory, "rev-parse", "HEAD")
    if indirection in {"alternates", "http-alternates"}:
        alternate_objects = tmp_path / "alternate-objects"
        alternate_objects.mkdir()
        control = git_dir / "objects/info" / indirection
        control.write_text(str(alternate_objects) + "\n", encoding="utf-8")
    elif indirection == "grafts":
        control = git_dir / "info/grafts"
        control.parent.mkdir(parents=True, exist_ok=True)
        control.write_text("0" * 40 + "\n", encoding="ascii")
    elif indirection == "replace":
        control = git_dir / "refs/replace" / head
        control.parent.mkdir(parents=True, exist_ok=True)
        control.write_text(source.baseline_head_file.read_text(), encoding="ascii")
    elif indirection == "shallow":
        (git_dir / "shallow").write_text(head + "\n", encoding="ascii")
    elif indirection == "promisor-pack":
        (git_dir / "objects/pack/injected.promisor").write_text(
            "promisor\n",
            encoding="ascii",
        )
    elif indirection == "partial-clone":
        _git(source.directory, "config", "core.repositoryFormatVersion", "1")
        _git(source.directory, "config", "extensions.partialClone", "origin")
    else:
        _git(source.directory, "config", "remote.origin.promisor", "true")

    with pytest.raises(builder.SourceDeltaError, match=error_pattern):
        builder._git_state(source)


def test_git_rename_is_compared_as_delete_plus_add(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    source = paths.git_sources[0]
    _git(
        source.directory,
        "mv",
        "cves/CVE-2026-1000.json",
        "cves/CVE-2026-1002.json",
    )
    (source.directory / "cves/CVE-2026-1002.json").write_text(
        json.dumps({"cveMetadata": {"cveId": "CVE-2026-1002"}}),
        encoding="utf-8",
    )
    _git(source.directory, "add", ".")
    _git(source.directory, "commit", "-qm", "rename advisory")

    artifacts = builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)
    evidence = artifacts.delta["git"]["cvelistV5"]

    assert evidence["changed_files"] == [
        "cves/CVE-2026-1000.json",
        "cves/CVE-2026-1002.json",
    ]
    assert set(evidence["subject_ids"]) == {
        "CVE-2026-1000",
        "CVE-2026-1002",
    }


def test_archive_inventory_and_unsafe_member_fail_closed(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    paths.osv_ecosystems_file.write_text("GIT\nmissing\nnpm\n", encoding="utf-8")
    with pytest.raises(builder.SourceDeltaError, match="ecosystem manifest"):
        builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)

    paths = _fixture_paths(tmp_path / "missing")
    (paths.osv_dir / "npm.zip").unlink()
    with pytest.raises(
        builder.SourceDeltaError,
        match=r"ecosystem manifest: missing=\['npm.zip'\]",
    ):
        builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)

    paths = _fixture_paths(tmp_path / "unsafe")
    unsafe = paths.osv_dir / "npm.zip"
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("../escape.json", '{"id":"OSV-ESCAPE-1"}')
    with pytest.raises(builder.SourceDeltaError, match="unsafe ZIP member"):
        builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)


def test_osv_zip_preflight_rejects_physical_and_central_directory_oversize(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "bounded.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("first-long-record-name.json", '{"id":"OSV-FIRST-1"}')
        archive.writestr("second-long-record-name.json", '{"id":"OSV-SECOND-1"}')

    archive_size, central_size, member_count = builder._inspect_zip_physical_bounds(
        archive_path,
        "test OSV archive",
    )
    assert archive_size == archive_path.stat().st_size
    assert central_size > 1
    assert member_count == 2
    with pytest.raises(builder.SourceDeltaError, match="archive size is outside"):
        builder._inspect_zip_physical_bounds(
            archive_path,
            "test OSV archive",
            max_archive_bytes=archive_size - 1,
        )
    with pytest.raises(builder.SourceDeltaError, match="central directory exceeds"):
        builder._inspect_zip_physical_bounds(
            archive_path,
            "test OSV archive",
            max_central_directory_bytes=central_size - 1,
        )


def test_osv_zip_scanner_streams_members_and_enforces_expansion_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "streamed.zip"
    with zipfile.ZipFile(
        archive_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr("first.json", '{"id":"OSV-FIRST-1"}')
        archive.writestr("second.json", '{"id":"OSV-SECOND-1"}')

    def reject_whole_member_read(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("ZipFile.read must not be used for OSV records")

    monkeypatch.setattr(zipfile.ZipFile, "read", reject_whole_member_read)
    opened, members = builder._safe_zip_members(archive_path, "test OSV archive")
    try:
        records = builder._scan_osv_records(opened, members, "test OSV archive")
    finally:
        opened.close()
    assert set(records["records"]) == {"first.json", "second.json"}

    monkeypatch.setattr(builder, "MAX_OSV_ARCHIVE_MEMBER_BYTES", 8)
    with pytest.raises(builder.SourceDeltaError, match="ZIP member exceeds 8 bytes"):
        builder._safe_zip_members(archive_path, "test OSV archive")

    monkeypatch.setattr(builder, "MAX_OSV_ARCHIVE_MEMBER_BYTES", 1024)
    monkeypatch.setattr(builder, "MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES", 16)
    with pytest.raises(
        builder.SourceDeltaError, match="uncompressed content exceeds 16"
    ):
        builder._safe_zip_members(archive_path, "test OSV archive")


def test_source_zip_preflight_and_scan_use_one_open_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "stable.zip"
    _write_zip(archive_path, {"original.json": {"id": "OSV-ORIGINAL-1"}})
    original_init = zipfile.ZipFile.__init__

    def replace_if_reopened_by_path(
        self: zipfile.ZipFile,
        file: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        if isinstance(file, (str, os.PathLike)) and Path(file) == archive_path:
            replacement = archive_path.with_suffix(".replacement")
            _write_zip(replacement, {"replacement.json": {"id": "OSV-REPLACED-1"}})
            os.replace(replacement, archive_path)
        original_init(self, file, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "__init__", replace_if_reopened_by_path)
    opened, members = builder._safe_zip_members(
        archive_path,
        "test OSV archive",
        expected_size=archive_path.stat().st_size,
        expected_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
    )
    try:
        assert set(members) == {"original.json"}
    finally:
        opened.close()


def test_source_zip_close_rejects_path_replacement_and_closes_descriptor(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "stable.zip"
    _write_zip(archive_path, {"original.json": {"id": "OSV-ORIGINAL-1"}})
    opened, _members = builder._safe_zip_members(
        archive_path,
        "test OSV archive",
        expected_size=archive_path.stat().st_size,
        expected_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
    )
    replacement = archive_path.with_suffix(".replacement")
    _write_zip(replacement, {"replacement.json": {"id": "OSV-REPLACED-1"}})
    os.replace(replacement, archive_path)

    with pytest.raises(builder.SourceDeltaError, match="changed while being scanned"):
        opened.close()
    assert opened._source_handle.closed


def test_osv_scanner_checks_deadline_after_last_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "deadline.zip"
    _write_zip(archive_path, {"record.json": {"id": "OSV-DEADLINE-1"}})
    opened, members = builder._safe_zip_members(archive_path, "test OSV archive")
    calls = 0

    def deadline_after_record(_started: float, _label: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise builder.SourceDeltaError("deadline after final OSV record")

    monkeypatch.setattr(builder, "_check_osv_archive_deadline", deadline_after_record)
    try:
        with pytest.raises(builder.SourceDeltaError, match="after final OSV record"):
            builder._scan_osv_records(opened, members, "test OSV archive")
    finally:
        opened.close()


def test_osv_scanner_quarantines_invalid_primary_and_keeps_valid_aliases(
    tmp_path: Path,
) -> None:
    """One malformed upstream vendor ID cannot hide its valid alias or stop refresh."""

    archive_path = tmp_path / "vendor.zip"
    with zipfile.ZipFile(
        archive_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "SUSE-SU-403 Forbidden-1.json",
            json.dumps(
                {
                    "id": "SUSE-SU-403 Forbidden-1",
                    "aliases": ["CVE-2026-4242", "also invalid"],
                    "related": ["CVE-2026-9999"],
                    "upstream": ["CVE-2026-8888"],
                }
            ),
        )

    opened, members = builder._safe_zip_members(
        archive_path,
        "test OSV archive",
    )
    try:
        records = builder._scan_osv_records(
            opened,
            members,
            "test OSV archive",
        )
    finally:
        opened.close()

    assert records["records"] == {"SUSE-SU-403 Forbidden-1.json": ("CVE-2026-4242",)}
    assert records["invalid_primary_count"] == 1
    assert records["invalid_primaries"] == [
        {
            "member": "SUSE-SU-403 Forbidden-1.json",
            "preview": "SUSE-SU-403 Forbidden-1",
            "sha256": hashlib.sha256(b"SUSE-SU-403 Forbidden-1").hexdigest(),
            "value_length": len("SUSE-SU-403 Forbidden-1"),
        }
    ]
    assert records["invalid_alias_count"] == 1
    assert records["invalid_aliases"] == [
        {
            "member": "SUSE-SU-403 Forbidden-1.json",
            "preview": "also invalid",
            "sha256": hashlib.sha256(b"also invalid").hexdigest(),
            "value_length": len("also invalid"),
        }
    ]
    # OSV related/upstream relationships are not identity aliases.
    assert "CVE-2026-9999" not in records["records"]["SUSE-SU-403 Forbidden-1.json"]
    assert "CVE-2026-8888" not in records["records"]["SUSE-SU-403 Forbidden-1.json"]


def test_osv_quarantine_never_persists_complete_oversized_values(
    tmp_path: Path,
) -> None:
    invalid_primary = "invalid-primary-" + ("\N{SNOWMAN}" * 100_000)
    invalid_alias = "invalid-alias-" + ("\N{CJK UNIFIED IDEOGRAPH-754C}" * 100_000)
    archive_path = tmp_path / "oversized-quarantine.zip"
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr(
            "oversized.json",
            json.dumps(
                {
                    "id": invalid_primary,
                    "aliases": ["CVE-2026-4242", invalid_alias],
                },
                ensure_ascii=False,
            ),
        )

    opened, members = builder._safe_zip_members(archive_path, "test OSV archive")
    try:
        records = builder._scan_osv_records(
            opened,
            members,
            "test OSV archive",
        )
    finally:
        opened.close()

    assert records["records"] == {"oversized.json": ("CVE-2026-4242",)}
    for entry, original in (
        (records["invalid_primaries"][0], invalid_primary),
        (records["invalid_aliases"][0], invalid_alias),
    ):
        assert set(entry) == {"member", "preview", "sha256", "value_length"}
        assert len(entry["preview"].encode("utf-8")) <= (
            builder.MAX_OSV_QUARANTINE_PREVIEW_BYTES
        )
        assert entry["preview"] != original
        assert entry["sha256"] == hashlib.sha256(original.encode("utf-8")).hexdigest()
        assert entry["value_length"] == len(original)
    serialized = json.dumps(records, ensure_ascii=False)
    assert invalid_primary not in serialized
    assert invalid_alias not in serialized
    assert len(serialized.encode("utf-8")) < 4 * 1024


def test_osv_quarantine_rejects_non_scalar_unicode() -> None:
    with pytest.raises(builder.SourceDeltaError, match="not strict UTF-8"):
        builder._quarantine_value("invalid-\ud800", "test OSV record")


def test_osv_scanner_fails_when_invalid_primary_quarantine_is_exhausted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("first.json", '{"id":"invalid primary one"}')
        archive.writestr("second.json", '{"id":"invalid primary two"}')

    monkeypatch.setattr(builder, "MAX_OSV_INVALID_PRIMARY_IDS", 1)
    opened, members = builder._safe_zip_members(
        archive_path,
        "test OSV archive",
    )
    try:
        with pytest.raises(
            builder.SourceDeltaError,
            match="invalid primary-ID quarantine exceeds 1",
        ):
            builder._scan_osv_records(
                opened,
                members,
                "test OSV archive",
            )
    finally:
        opened.close()


@pytest.mark.parametrize(
    ("target", "content", "message"),
    [
        ("corpus", "CVE-DUPLICATE-1\nCVE-DUPLICATE-1\n", "duplicate subject IDs"),
        ("baseline", "CVE-GOOD-1\nbad value\n", "invalid vulnerability subject ID"),
    ],
)
def test_invalid_or_nonlegacy_duplicate_ids_fail_closed(
    tmp_path: Path,
    target: str,
    content: str,
    message: str,
) -> None:
    paths = _fixture_paths(tmp_path)
    if target == "corpus":
        assert paths.adjudicated_corpus_file is not None
        paths.adjudicated_corpus_file.write_text(content, encoding="utf-8")
    else:
        (paths.baseline_dir / "new-osv-candidates.txt").write_text(
            content, encoding="utf-8"
        )
        _write_manifest(paths.baseline_dir)
    with pytest.raises(builder.SourceDeltaError, match=message):
        builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)


def test_input_drift_before_publish_preserves_existing_outputs(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    artifacts = builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)
    paths.delta_output.write_text("old delta\n", encoding="utf-8")
    paths.candidate_output.write_text("OLD-CANDIDATE-1\n", encoding="utf-8")
    with paths.git_sources[0].directory.joinpath("drift.txt").open("w") as handle:
        handle.write("drift")

    with pytest.raises(
        builder.SourceDeltaError, match="inputs changed before publication|dirty"
    ):
        builder.publish_artifacts(paths, artifacts)

    assert paths.delta_output.read_text() == "old delta\n"
    assert paths.candidate_output.read_text() == "OLD-CANDIDATE-1\n"


def test_result_cache_drift_before_publish_preserves_existing_outputs(
    tmp_path: Path,
) -> None:
    paths = _fixture_paths(tmp_path)
    artifacts = builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)
    paths.delta_output.write_text("old delta\n", encoding="utf-8")
    paths.candidate_output.write_text("OLD-CANDIDATE-1\n", encoding="utf-8")
    _write_cached_result(paths.result_cache_dir, "CVE-NEW-CACHE-1")

    with pytest.raises(builder.SourceDeltaError, match="source inputs changed"):
        builder.publish_artifacts(paths, artifacts)

    assert paths.delta_output.read_text() == "old delta\n"
    assert paths.candidate_output.read_text() == "OLD-CANDIDATE-1\n"


def test_invalid_result_cache_entry_fails_closed(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    (paths.result_cache_dir / "CVE-BROKEN-1.json").write_text(
        '{"cve_id":"CVE-DIFFERENT-1"}', encoding="utf-8"
    )

    with pytest.raises(builder.SourceDeltaError, match="filename/subject mismatch"):
        builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)


def test_alias_components_make_cache_coverage_transitive() -> None:
    components, metadata = builder._alias_components(
        [
            {
                "id": "GHSA-root-root-root",
                "aliases": ["CVE-2025-9000"],
            },
            {
                "id": "GHSA-cache-cache-cache",
                "aliases": ["GHSA-root-root-root"],
            },
        ],
        label="test aliases",
    )

    assert components["CVE-2025-9000"] == {
        "CVE-2025-9000",
        "GHSA-root-root-root",
        "GHSA-cache-cache-cache",
    }
    assert metadata["subject_id_count"] == 3
    assert metadata["component_count"] == 1
    assert metadata["transitive"] is True


def test_alias_class_manifest_merges_all_source_evidence() -> None:
    manifest = builder._build_alias_class_manifest(
        [
            (
                "osv",
                {
                    "id": "OSV-MERGED-1",
                    "aliases": ["CVE-2026-9000"],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "GIT",
                                    "repo": "https://github.com/example/project",
                                    "events": [{"fixed": "abc123"}],
                                }
                            ]
                        }
                    ],
                },
            ),
            (
                "ghsa",
                {
                    "id": "GHSA-merge-merge-merge",
                    "aliases": ["CVE-2026-9000"],
                    "references": [
                        {"url": "https://github.com/example/project/pull/1"}
                    ],
                },
            ),
        ],
        production_ids=["CVE-2026-9000"],
        source_snapshot_sha256="a" * 64,
    )

    assert manifest["class_count"] == 1
    class_record = manifest["classes"][0]
    assert class_record["all_member_ids"] == [
        "CVE-2026-9000",
        "GHSA-merge-merge-merge",
        "OSV-MERGED-1",
    ]
    assert len(class_record["source_record_references"]) == 2
    assert class_record["analysis_input"]["git_ranges"][0]["repo"] == (
        "https://github.com/example/project"
    )
    assert class_record["analysis_input"]["fixed_events"] == [
        {"kind": "fixed", "value": "abc123"}
    ]
    assert class_record["analysis_input"]["reference_urls"] == [
        "https://github.com/example/project/pull/1"
    ]


def test_scheduled_nonproduction_alias_is_release_eligible() -> None:
    source_snapshot_sha256 = "a" * 64
    manifest = builder._build_alias_class_manifest(
        [
            (
                "osv",
                {
                    "id": "GHSA-alias-alias-alias",
                    "aliases": ["CVE-2026-9100"],
                },
            )
        ],
        production_ids=["GHSA-alias-alias-alias"],
        source_snapshot_sha256=source_snapshot_sha256,
    )

    scheduled, candidate_ids = builder._schedule_alias_classes(
        manifest,
        ["CVE-2026-9100"],
    )

    class_record = scheduled["classes"][0]
    assert class_record["scheduled_seed_ids"] == ["CVE-2026-9100"]
    assert class_record["eligible_seed_ids"] == [
        "CVE-2026-9100",
        "GHSA-alias-alias-alias",
    ]
    assert candidate_ids == ["CVE-2026-9100"]
    scheduled_by_subject, member_to_subject = (
        release_evidence._validate_formal_alias_class_manifest(
            scheduled,
            expected_manifest_sha256=scheduled["classes_sha256"],
            expected_source_snapshot_sha256=source_snapshot_sha256,
        )
    )
    assert set(scheduled_by_subject) == {"CVE-2026-9100"}
    assert member_to_subject["GHSA-alias-alias-alias"] == "CVE-2026-9100"


def test_supplemental_seed_recomputes_release_eligible_population() -> None:
    source_snapshot_sha256 = "b" * 64
    manifest = builder._build_alias_class_manifest(
        [("osv", {"id": "CVE-2026-9200", "aliases": []})],
        production_ids=["CVE-2026-9200"],
        source_snapshot_sha256=source_snapshot_sha256,
    )

    scheduled, candidate_ids = builder._schedule_alias_classes(
        manifest,
        ["CVE-2026-9200", "CVE-2024-9201"],
    )

    assert candidate_ids == ["CVE-2026-9200", "CVE-2024-9201"]
    assert scheduled["eligible_seed_id_count"] == 2
    assert scheduled["all_eligible_seed_ids_exactly_once"] is True
    assert sum(
        class_record.get("supplemental_candidate") is True
        for class_record in scheduled["classes"]
    ) == 1
    scheduled_by_subject, member_to_subject = (
        release_evidence._validate_formal_alias_class_manifest(
            scheduled,
            expected_manifest_sha256=scheduled["classes_sha256"],
            expected_source_snapshot_sha256=source_snapshot_sha256,
        )
    )
    assert set(scheduled_by_subject) == {"CVE-2026-9200", "CVE-2024-9201"}
    assert member_to_subject["CVE-2024-9201"] == "CVE-2024-9201"


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (
            builder.CveAnalysisResult(
                cve_id="CVE-2025-9100",
                error_category="no_ai_activity",
                phase_times={"Phase A (discovery)": 0.1},
            ),
            "known_nonterminal_no_ai_activity",
        ),
        (
            builder.CveAnalysisResult(
                cve_id="CVE-2025-9101",
                repo_ai_activity=["incomplete: tier-0 clone timed out"],
                phase_times={
                    "Phase A (discovery)": 0.1,
                    "Phase B (blame)": 0.2,
                },
            ),
            "incomplete_tier0_telemetry",
        ),
    ],
)
def test_nonterminal_cache_results_do_not_cover_discovery(
    result: builder.CveAnalysisResult,
    expected: str,
) -> None:
    assert builder._cache_coverage_ineligibility(result.to_dict(), result) == expected


def test_second_replace_failure_rolls_back_candidate_and_delta(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture_paths(tmp_path)
    artifacts = builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)
    paths.delta_output.write_text("old delta\n", encoding="utf-8")
    paths.candidate_output.write_text("OLD-CANDIDATE-1\n", encoding="utf-8")
    real_replace = os.replace
    failed = False

    def fail_delta_once(
        source: os.PathLike[str] | str, destination: os.PathLike[str] | str
    ) -> None:
        nonlocal failed
        if (
            Path(destination) == paths.delta_output
            and ".source-delta.staging-" in Path(source).name
            and not failed
        ):
            failed = True
            raise OSError("injected delta publication failure")
        real_replace(source, destination)

    monkeypatch.setattr(builder.os, "replace", fail_delta_once)

    with pytest.raises(builder.SourceDeltaError, match="cannot publish"):
        builder.publish_artifacts(paths, artifacts)

    assert paths.delta_output.read_text() == "old delta\n"
    assert paths.candidate_output.read_text() == "OLD-CANDIDATE-1\n"
    assert not list(paths.delta_output.parent.glob(".source-*.staging-*"))
    assert not list(paths.delta_output.parent.glob(".source-*.backup-*"))


def test_post_replace_source_drift_rolls_back_both_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture_paths(tmp_path)
    artifacts = builder.build_artifacts(paths, generated_at_utc=_GENERATED_AT)
    paths.delta_output.write_text("old delta\n", encoding="utf-8")
    paths.candidate_output.write_text("OLD-CANDIDATE-1\n", encoding="utf-8")
    real_capture = builder._capture_input_guard
    capture_count = 0

    def inject_post_replace_drift(
        input_paths: builder.BuildPaths,
        **kwargs: object,
    ) -> dict[str, Any]:
        nonlocal capture_count
        capture_count += 1
        snapshot = real_capture(input_paths, **kwargs)
        if capture_count == 2:
            snapshot = {**snapshot, "sha256": "0" * 64}
        return snapshot

    monkeypatch.setattr(builder, "_capture_input_guard", inject_post_replace_drift)

    with pytest.raises(builder.SourceDeltaError, match="during output publication"):
        builder.publish_artifacts(paths, artifacts)

    assert paths.delta_output.read_text() == "old delta\n"
    assert paths.candidate_output.read_text() == "OLD-CANDIDATE-1\n"


def test_cli_supports_repo_relative_temp_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paths = _fixture_paths(tmp_path)
    root = paths.repo_root

    exit_code = builder.main(
        [
            "--repo-root",
            str(root),
            "--cvelist-dir",
            str(paths.git_sources[0].directory),
            "--ghsa-dir",
            str(paths.git_sources[1].directory),
            "--gemnasium-dir",
            str(paths.git_sources[2].directory),
            "--nvd-dir",
            str(paths.nvd_dir),
            "--osv-dir",
            str(paths.osv_dir),
            "--osv-ecosystems-file",
            str(paths.osv_ecosystems_file),
            "--result-cache-dir",
            str(paths.result_cache_dir),
            "--generated-at-utc",
            _GENERATED_AT,
        ]
    )

    assert exit_code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["schema_version"] == builder.SCHEMA_VERSION
    assert summary["current_osv_archive_count"] == 2
    assert summary["production_discovered_id_count"] == 5
    assert summary["uncached_ghsa_supplement_id_count"] == 2
    assert summary["candidate_id_count"] >= summary["delta_id_count"]
