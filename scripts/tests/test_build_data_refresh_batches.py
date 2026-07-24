"""Focused tests for deterministic repository-affinity batch generation."""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest

import build_data_refresh_batches as builder

_GENERATED_AT = "2026-07-18T10:00:00+00:00"


def _write_zip(path: Path, records: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for index, (name, record) in enumerate(records.items(), 1):
            info = zipfile.ZipInfo(
                f"{name}.json",
                date_time=(2026, 7, 18, 10, 0, index * 2),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, json.dumps(record, sort_keys=True))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_delta(
    path: Path,
    subject_ids: list[str],
    archive_dir: Path,
) -> None:
    archive_paths = sorted(
        archive_dir.glob("*.zip"),
        key=lambda item: (item.name.casefold(), item.name),
    )
    path.write_text(
        json.dumps(
            {
                "all_ids": subject_ids,
                "input_snapshot": {
                    "osv_archive_names": [item.name for item in archive_paths],
                    "osv": {
                        item.name: {
                            "size_bytes": item.stat().st_size,
                            "sha256": _sha256(item),
                        }
                        for item in archive_paths
                    },
                },
                "source": "fixture",
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _fixture_paths(tmp_path: Path) -> builder.BuildPaths:
    root = tmp_path / "repo"
    state = root / ".ai-slop/state/data-refresh"
    candidate_file = state / "new-osv-candidates.txt"
    excluded_file = state / "batches-v1/batch-001.txt"
    delta_file = state / "source-delta-current.json"
    quality_corpus_file = state / "adjudicated-corpus-subjects.txt"
    archive_dir = root / ".cache/osv-bulk"

    excluded_file.parent.mkdir(parents=True)
    candidate_file.write_text(
        "\n".join(
            [
                "CVE-EXCLUDED",
                "OSV-A",
                "ALIAS-A",
                "OSV-B",
                "OSV-C",
                "OSV-UNMAPPED",
                "OSV-B",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    excluded_file.write_text("CVE-EXCLUDED\nCVE-EXCLUDED\n", encoding="utf-8")
    quality_corpus_file.write_text("ALIAS-A\nOSV-UNMAPPED\n", encoding="utf-8")
    _write_zip(
        archive_dir / "GIT.zip",
        {
            "OSV-A": {
                "id": "OSV-A",
                "aliases": ["ALIAS-A"],
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "GIT",
                                "repo": "git@github.com:Org/Repo.git",
                            }
                        ]
                    }
                ],
            },
            "OSV-B": {
                "id": "OSV-B",
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "GIT",
                                "repo": "https://github.com/org/repo",
                            }
                        ]
                    }
                ],
            },
            "OSV-C": {
                "id": "OSV-C",
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "GIT",
                                "repo": "https://gitlab.example.com/Team/Other.git",
                            }
                        ]
                    }
                ],
            },
            "OSV-UNMAPPED": {"id": "OSV-UNMAPPED"},
            "UNRELATED": {"id": "UNRELATED"},
        },
    )
    _write_delta(delta_file, ["OSV-B", "OSV-C"], archive_dir)
    return builder.BuildPaths(
        repo_root=root,
        candidate_file=candidate_file,
        excluded_file=excluded_file,
        delta_file=delta_file,
        quality_corpus_file=quality_corpus_file,
        osv_archive_dir=archive_dir,
        output_dir=state / "grouped-batches-v1",
    )


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def test_builds_affinity_partition_with_multi_source_and_quality_metadata(
    tmp_path: Path,
) -> None:
    paths = _fixture_paths(tmp_path)

    manifest = builder.build_batches(paths, generated_at_utc=_GENERATED_AT)

    assert manifest["schema_version"] == builder.SCHEMA_VERSION
    assert manifest["generated_at_utc"] == _GENERATED_AT
    assert (
        manifest["purpose"] == "repo-affinity multi-source incremental analysis batches"
    )
    inputs = manifest["inputs"]
    assert inputs["candidate_file"] == ".ai-slop/state/data-refresh/new-osv-candidates.txt"
    assert inputs["candidate_line_count"] == 7
    assert inputs["candidate_unique_id_count"] == 6
    assert inputs["candidate_duplicates"] == {"OSV-B": 2}
    assert inputs["excluded_duplicates"] == {"CVE-EXCLUDED": 2}
    assert inputs["remaining_unique_id_count"] == 5
    assert inputs["delta_file"] == ".ai-slop/state/data-refresh/source-delta-current.json"
    assert inputs["delta_subject_id_count"] == 2
    assert inputs["candidate_sha256"] == _sha256(paths.candidate_file)
    assert inputs["delta_sha256"] == _sha256(paths.delta_file)
    assert inputs["quality_corpus_file"] == (
        ".ai-slop/state/data-refresh/adjudicated-corpus-subjects.txt"
    )
    assert inputs["quality_corpus_subject_id_count"] == 2
    assert inputs["quality_corpus_sha256"] == _sha256(paths.quality_corpus_file)
    assert inputs["archive_count"] == 1
    assert inputs["archives"][0]["mtime_utc"] == "2026-07-18T10:00:10+00:00"
    assert inputs["archives"][0]["sha256"] == _sha256(paths.osv_archive_dir / "GIT.zip")

    assert manifest["mapping"] == {
        "ids_matched_by_primary_or_alias": 5,
        "ids_not_matched_by_any_record": 0,
        "ids_not_matched": [],
        "ids_with_git_repo": 4,
        "ids_without_git_repo": 1,
        "unique_normalized_repos": 2,
        "matched_osv_records": 4,
        "mapped_components": 2,
        "large_components": 0,
        "largest_component_id_count": 3,
        "largest_component_repo_count": 1,
        "repo_normalization_variant_count": 1,
        "repo_variants": {
            "github.com/org/repo": [
                "git@github.com:Org/Repo.git",
                "https://github.com/org/repo",
            ]
        },
    }
    assert manifest["verification"]["all_remaining_ids_exactly_once"] is True
    assert manifest["verification"]["each_repo_owned_by_one_batch"] is True
    assert manifest["verification"]["normal_batches_within_targets"] is True
    assert [
        (batch["kind"], batch["ids"], batch["repos"]) for batch in manifest["batches"]
    ] == [
        (
            "repo_affinity",
            ["OSV-A", "ALIAS-A", "OSV-B", "OSV-C"],
            ["github.com/org/repo", "gitlab.example.com/team/other"],
        ),
        ("unmapped", ["OSV-UNMAPPED"], []),
    ]
    assert (paths.output_dir / "batch-001.txt").read_text(encoding="utf-8") == (
        "OSV-A\nALIAS-A\nOSV-B\nOSV-C\n"
    )
    assert json.loads((paths.output_dir / "manifest.json").read_text()) == manifest


def test_formal_batches_consume_alias_manifest_and_cover_classes_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture_paths(tmp_path)
    candidate_ids = list(
        dict.fromkeys(paths.candidate_file.read_text(encoding="utf-8").splitlines())
    )
    payload = json.loads(paths.delta_file.read_text(encoding="utf-8"))
    classes = []
    for index, subject in enumerate(candidate_ids):
        git_ranges = (
            [{"type": "GIT", "repo": "https://github.com/org/shared"}]
            if subject in {"OSV-A", "OSV-B"}
            else []
        )
        classes.append(
            {
                "class_id": f"class-{index}",
                "analysis_subject": subject,
                "all_member_ids": [subject],
                "scheduled_seed_ids": [subject],
                "analysis_input": {"git_ranges": git_ranges},
            }
        )
    classes[0]["all_member_ids"].extend(
        ["ALIAS-DELTA-MEMBER", "QUALITY-ALIAS-NOT-A-CANDIDATE"]
    )
    payload["all_ids"].append("ALIAS-DELTA-MEMBER")
    paths.quality_corpus_file.write_text(
        "QUALITY-ALIAS-NOT-A-CANDIDATE\nOSV-UNMAPPED\n", encoding="utf-8"
    )
    classes_sha256 = hashlib.sha256(
        json.dumps(classes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload.update(
        {
            "population_policy": "formal_full",
            "analyzer_contract": {
                "sha256": "a" * 64,
                "signature_sha256": "b" * 64,
            },
            "production_discovery": {
                "alias_class_manifest": {
                    "classes": classes,
                    "classes_sha256": classes_sha256,
                    "scheduled_classes_exactly_once": True,
                    "scheduled_analysis_subject_count": len(candidate_ids),
                }
            },
        }
    )
    paths.delta_file.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        builder,
        "_scan_archives",
        lambda *_args, **_kwargs: pytest.fail("formal builder rescanned archives"),
    )

    manifest = builder.build_batches(paths, generated_at_utc=_GENERATED_AT)

    assert manifest["purpose"] == "formal full alias-class analysis batches"
    assert manifest["inputs"]["formal_release_eligible"] is True
    assert manifest["inputs"]["remaining_unique_id_count"] == len(candidate_ids)
    assert manifest["inputs"]["quality_corpus_subject_id_count"] == 2
    assert manifest["inputs"]["quality_corpus_analysis_subject_id_count"] == 2
    assert manifest["inputs"]["quality_corpus_alias_mapped_subject_id_count"] == 1
    assert manifest["inputs"]["quality_corpus_subject_to_analysis_subject"] == {
        "OSV-UNMAPPED": "OSV-UNMAPPED",
        "QUALITY-ALIAS-NOT-A-CANDIDATE": candidate_ids[0],
    }
    assert len(manifest["inputs"]["quality_corpus_subject_mapping_sha256"]) == 64
    assert manifest["verification"]["alias_classes_exactly_once"] is True
    assert manifest["verification"]["shared_repositories_are_scheduling_affinity"] is True
    assert "CVE-EXCLUDED" in {
        subject for batch in manifest["batches"] for subject in batch["ids"]
    }
    assert sorted(
        class_id for batch in manifest["batches"] for class_id in batch["class_ids"]
    ) == sorted(item["class_id"] for item in classes)


def test_formal_batches_reject_delta_id_not_covered_by_an_alias_class(
    tmp_path: Path,
) -> None:
    paths = _fixture_paths(tmp_path)
    candidate_ids = list(
        dict.fromkeys(paths.candidate_file.read_text(encoding="utf-8").splitlines())
    )
    payload = json.loads(paths.delta_file.read_text(encoding="utf-8"))
    classes = [
        {
            "class_id": f"class-{index}",
            "analysis_subject": subject,
            "all_member_ids": [subject],
            "scheduled_seed_ids": [subject],
            "analysis_input": {"git_ranges": []},
        }
        for index, subject in enumerate(candidate_ids)
    ]
    payload.update(
        {
            "all_ids": [*payload["all_ids"], "UNMAPPED-DELTA-MEMBER"],
            "population_policy": "formal_full",
            "analyzer_contract": {
                "sha256": "a" * 64,
                "signature_sha256": "b" * 64,
            },
            "production_discovery": {
                "alias_class_manifest": {
                    "classes": classes,
                    "classes_sha256": hashlib.sha256(
                        json.dumps(
                            classes, sort_keys=True, separators=(",", ":")
                        ).encode()
                    ).hexdigest(),
                    "scheduled_classes_exactly_once": True,
                    "scheduled_analysis_subject_count": len(candidate_ids),
                }
            },
        }
    )
    paths.delta_file.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    with pytest.raises(builder.BatchBuildError, match="manifest omits 1"):
        builder.build_batches(paths, generated_at_utc=_GENERATED_AT)


def test_output_is_reproducible_and_failed_rebuild_preserves_previous_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture_paths(tmp_path)
    builder.build_batches(paths, generated_at_utc=_GENERATED_AT)
    expected = _snapshot(paths.output_dir)

    (paths.output_dir / "stale.txt").write_text("stale\n", encoding="utf-8")
    archive = paths.osv_archive_dir / "GIT.zip"
    os.utime(archive, (archive.stat().st_atime + 100, archive.stat().st_mtime + 100))
    monkeypatch.setattr(builder, "_try_atomic_exchange", lambda _left, _right: False)
    builder.build_batches(paths, generated_at_utc=_GENERATED_AT)

    assert _snapshot(paths.output_dir) == expected
    assert not (paths.output_dir / "stale.txt").exists()
    assert not list(paths.output_dir.parent.glob(f".{paths.output_dir.name}.staging-*"))
    assert not (paths.output_dir.parent / f".{paths.output_dir.name}.previous").exists()

    paths.delta_file.write_text(
        '{"all_ids": ["MISSING-FROM-CANDIDATES"]}\n', encoding="utf-8"
    )
    with pytest.raises(builder.BatchBuildError, match="candidate file omits"):
        builder.build_batches(paths, generated_at_utc=_GENERATED_AT)
    assert _snapshot(paths.output_dir) == expected


def test_oversized_connected_component_is_a_verified_large_batch(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    state = root / ".ai-slop/state/data-refresh"
    candidates = [f"OSV-{index:03d}" for index in range(501)]
    candidate_file = state / "new-osv-candidates.txt"
    excluded_file = state / "batches-v1/batch-001.txt"
    delta_file = state / "source-delta-current.json"
    archive_dir = root / "osv"
    excluded_file.parent.mkdir(parents=True)
    candidate_file.write_text("\n".join(candidates) + "\n", encoding="utf-8")
    excluded_file.write_text("LEGACY-ONLY\n", encoding="utf-8")
    _write_zip(
        archive_dir / "GIT.zip",
        {
            "connected": {
                "id": candidates[0],
                "aliases": candidates[1:],
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "GIT",
                                "repo": "https://github.com/example/large.git",
                            }
                        ]
                    }
                ],
            }
        },
    )
    _write_delta(delta_file, candidates, archive_dir)
    paths = builder.BuildPaths(
        repo_root=root,
        candidate_file=candidate_file,
        excluded_file=excluded_file,
        delta_file=delta_file,
        quality_corpus_file=None,
        osv_archive_dir=archive_dir,
        output_dir=state / "grouped-batches-v1",
    )

    manifest = builder.build_batches(paths, generated_at_utc=_GENERATED_AT)

    assert manifest["packing"]["batch_count"] == 1
    assert manifest["packing"]["large_component_batch_count"] == 1
    assert manifest["packing"]["batches_over_id_preference"] == 1
    assert manifest["batches"][0]["kind"] == "large_component"
    assert manifest["batches"][0]["id_count"] == 501
    assert manifest["batches"][0]["within_target_limits"] is False
    assert manifest["verification"]["normal_batches_within_targets"] is True


def test_cli_resolves_repo_relative_defaults_and_can_omit_quality_corpus(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _fixture_paths(tmp_path)

    exit_code = builder.main(
        [
            "--repo-root",
            str(paths.repo_root),
            "--osv-archive-dir",
            ".cache/osv-bulk",
            "--no-quality-corpus",
            "--generated-at-utc",
            _GENERATED_AT,
        ]
    )

    assert exit_code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["all_exactly_once"] is True
    manifest = json.loads((paths.output_dir / "manifest.json").read_text())
    assert "quality_corpus_file" not in manifest["inputs"]
    defaults = builder.BuildPaths.defaults(paths.repo_root)
    assert defaults.candidate_file == paths.candidate_file
    assert defaults.excluded_file == paths.excluded_file
    assert defaults.delta_file == paths.delta_file
    assert defaults.quality_corpus_file == paths.quality_corpus_file
    assert defaults.output_dir == paths.output_dir


def test_missing_default_quality_corpus_is_optional(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _fixture_paths(tmp_path)
    paths.quality_corpus_file.unlink()

    exit_code = builder.main(
        [
            "--repo-root",
            str(paths.repo_root),
            "--osv-archive-dir",
            ".cache/osv-bulk",
            "--generated-at-utc",
            _GENERATED_AT,
        ]
    )

    assert exit_code == 0
    capsys.readouterr()
    manifest = json.loads((paths.output_dir / "manifest.json").read_text())
    assert "quality_corpus_file" not in manifest["inputs"]
    assert builder.BuildPaths.defaults(paths.repo_root).quality_corpus_file is None


def test_batch_archive_preflight_rejects_physical_central_and_member_oversize(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "bounded.zip"
    _write_zip(
        archive_path,
        {
            "first-long-record-name": {"id": "OSV-FIRST-1"},
            "second-long-record-name": {"id": "OSV-SECOND-1"},
        },
    )

    archive_size, central_size, member_count = builder._inspect_zip_physical_bounds(
        archive_path,
        "test OSV archive",
    )
    assert archive_size == archive_path.stat().st_size
    assert central_size > 1
    assert member_count == 2
    with pytest.raises(builder.BatchBuildError, match="archive size is outside"):
        builder._inspect_zip_physical_bounds(
            archive_path,
            "test OSV archive",
            max_archive_bytes=archive_size - 1,
        )
    with pytest.raises(builder.BatchBuildError, match="central directory exceeds"):
        builder._inspect_zip_physical_bounds(
            archive_path,
            "test OSV archive",
            max_central_directory_bytes=central_size - 1,
        )
    with pytest.raises(builder.BatchBuildError, match="member count is outside"):
        builder._inspect_zip_physical_bounds(
            archive_path,
            "test OSV archive",
            max_members=member_count - 1,
        )


def test_batch_archive_scanner_streams_members_and_enforces_expansion_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture_paths(tmp_path)

    def reject_whole_member_read(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("ZipFile.read must not be used for OSV records")

    monkeypatch.setattr(zipfile.ZipFile, "read", reject_whole_member_read)
    manifest = builder.build_manifest(paths, generated_at_utc=_GENERATED_AT)
    assert manifest["inputs"]["records_scanned"] == 5

    archive_path = paths.osv_archive_dir / "GIT.zip"
    started = builder.time.monotonic()
    opened, infos, _archive_size = builder._safe_zip_members(
        archive_path,
        "test OSV archive",
        started_at=started,
    )
    monkeypatch.setattr(builder, "MAX_OSV_ARCHIVE_MEMBER_BYTES", 8)
    try:
        with pytest.raises(
            builder.BatchBuildError,
            match="expanded ZIP member exceeds 8 bytes",
        ):
            builder._read_zip_member(
                opened,
                infos[0],
                "test OSV archive",
                started_at=started,
            )
    finally:
        opened.close()

    monkeypatch.setattr(builder, "MAX_OSV_ARCHIVE_MEMBER_BYTES", 1024 * 1024)
    monkeypatch.setattr(builder, "MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES", 16)
    with pytest.raises(
        builder.BatchBuildError,
        match="uncompressed content exceeds 16 bytes",
    ):
        builder.build_manifest(paths, generated_at_utc=_GENERATED_AT)


def test_batch_archive_scanner_enforces_validation_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture_paths(tmp_path)
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(builder.time, "monotonic", lambda: next(ticks, 2.0))
    monkeypatch.setattr(builder, "OSV_ARCHIVE_VALIDATION_TIMEOUT_SECONDS", 1)

    with pytest.raises(builder.BatchBuildError, match="validation exceeded 1 seconds"):
        builder.build_manifest(paths, generated_at_utc=_GENERATED_AT)


def test_batch_zip_preflight_and_scan_use_one_open_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture_paths(tmp_path)
    archive_path = paths.osv_archive_dir / "GIT.zip"
    original_init = zipfile.ZipFile.__init__

    def replace_if_reopened_by_path(
        self: zipfile.ZipFile,
        file: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        if isinstance(file, (str, os.PathLike)) and Path(file) == archive_path:
            replacement = archive_path.with_suffix(".replacement")
            _write_zip(replacement, {"replacement": {"id": "OSV-REPLACED-1"}})
            os.replace(replacement, archive_path)
        original_init(self, file, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "__init__", replace_if_reopened_by_path)
    opened, infos, _archive_size = builder._safe_zip_members(
        archive_path,
        "test OSV archive",
        started_at=builder.time.monotonic(),
        expected_size=archive_path.stat().st_size,
        expected_sha256=_sha256(archive_path),
    )
    try:
        assert {info.filename for info in infos} == {
            "OSV-A.json",
            "OSV-B.json",
            "OSV-C.json",
            "OSV-UNMAPPED.json",
            "UNRELATED.json",
        }
    finally:
        opened.close()


def test_batch_zip_close_rejects_path_replacement_and_closes_descriptor(
    tmp_path: Path,
) -> None:
    paths = _fixture_paths(tmp_path)
    archive_path = paths.osv_archive_dir / "GIT.zip"
    opened, _infos, _archive_size = builder._safe_zip_members(
        archive_path,
        "test OSV archive",
        started_at=builder.time.monotonic(),
        expected_size=archive_path.stat().st_size,
        expected_sha256=_sha256(archive_path),
    )
    replacement = archive_path.with_suffix(".replacement")
    _write_zip(replacement, {"replacement": {"id": "OSV-REPLACED-1"}})
    os.replace(replacement, archive_path)

    with pytest.raises(builder.BatchBuildError, match="changed while being scanned"):
        opened.close()
    assert opened._source_handle.closed


@pytest.mark.parametrize(
    "drift", ["missing_snapshot", "extra_archive", "changed_bytes"]
)
def test_batch_builder_binds_exact_delta_osv_snapshot(
    tmp_path: Path,
    drift: str,
) -> None:
    paths = _fixture_paths(tmp_path)
    if drift == "missing_snapshot":
        payload = json.loads(paths.delta_file.read_text(encoding="utf-8"))
        payload.pop("input_snapshot")
        paths.delta_file.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        expected = "input_snapshot"
    elif drift == "extra_archive":
        _write_zip(
            paths.osv_archive_dir / "unexpected.zip",
            {"unexpected": {"id": "OSV-UNEXPECTED-1"}},
        )
        expected = "inventory differs"
    else:
        archive_path = paths.osv_archive_dir / "GIT.zip"
        _write_zip(archive_path, {"changed": {"id": "OSV-CHANGED-1"}})
        expected = "snapshot"

    with pytest.raises(builder.BatchBuildError, match=expected):
        builder.build_manifest(paths, generated_at_utc=_GENERATED_AT)
