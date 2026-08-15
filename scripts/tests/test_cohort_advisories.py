"""Tests for the shared OSV advisory-fix index used by cohort workflows."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from cohort.advisories import (
    COMMIT_URL,
    CONVERTED_VERSION_BOUNDARY,
    NATIVE_GIT_FIXED,
    commit_reference_rows_from_record,
    commit_refs_from_record,
    index_advisory_observations,
    index_advisory_fixes,
    introduced_reference_rows_from_record,
)


REPOSITORY = "github.com/example/project"
FIX = "4" * 40
OLD_FIX = "5" * 40


def _record(advisory: str, fix: str, published: str) -> dict:
    return {
        "id": advisory,
        "published": published,
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": f"https://{REPOSITORY}.git",
                        "events": [{"fixed": fix}],
                    }
                ]
            }
        ],
    }


def test_commit_refs_uses_git_ranges_and_commit_urls() -> None:
    record = _record("CVE-2026-1000", FIX, "2026-01-01T00:00:00Z")
    record["references"] = [
        {"url": f"https://github.com/example/project/commit/{OLD_FIX}"}
    ]

    assert commit_refs_from_record(record) == [
        (REPOSITORY, FIX),
        (REPOSITORY, OLD_FIX),
    ]
    assert [
        row["reference_kind"] for row in commit_reference_rows_from_record(record)
    ] == [NATIVE_GIT_FIXED, COMMIT_URL]


def test_generated_cpe_git_boundary_is_not_labeled_native_exact() -> None:
    record = _record("CVE-2026-1000", FIX, "2026-01-01T00:00:00Z")
    git_range = record["affected"][0]["ranges"][0]
    git_range["database_specific"] = {
        "source": ["CPE_RANGE", "REFERENCES"],
        "extracted_events": [
            {"introduced": "1.0.0"},
            {"last_affected": "1.1.0"},
        ],
    }

    rows = commit_reference_rows_from_record(record)

    assert rows[0]["reference_kind"] == CONVERTED_VERSION_BOUNDARY


def test_introduced_observation_keeps_public_aliases() -> None:
    introduced = "3" * 40
    record = _record("GHSA-aaaa-bbbb-cccc", FIX, "2026-01-01T00:00:00Z")
    record["aliases"] = ["CVE-2026-1000"]
    record["affected"][0]["ranges"][0]["events"].insert(
        0, {"introduced": introduced}
    )

    rows = introduced_reference_rows_from_record(record)

    assert rows == [
        {
            "repository_identity": REPOSITORY,
            "introduced_sha": introduced,
            "record_id": "GHSA-aaaa-bbbb-cccc",
            "public_ids": ["CVE-2026-1000", "GHSA-AAAA-BBBB-CCCC"],
            "published": "2026-01-01T00:00:00Z",
        }
    ]


def test_one_archive_pass_returns_fix_and_introduced_lanes(tmp_path: Path) -> None:
    introduced = "3" * 40
    record = _record("CVE-2026-1000", FIX, "2026-01-01T00:00:00Z")
    record["affected"][0]["ranges"][0]["events"].insert(
        0, {"introduced": introduced}
    )
    with zipfile.ZipFile(tmp_path / "all.zip", "w") as handle:
        handle.writestr("one.json", json.dumps(record))

    fixes, introductions, stats = index_advisory_observations(
        tmp_path, {REPOSITORY}, cutoff="2025-08-10", until="2026-08-10"
    )

    assert fixes[REPOSITORY][0]["fix_sha"] == FIX
    assert introductions[REPOSITORY][0]["introduced_sha"] == introduced
    assert stats["introduced_landing_in_cohort"] == 1


def test_empty_cutoff_keeps_all_local_osv_records(tmp_path) -> None:
    archive = tmp_path / "all.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "old.json",
            json.dumps(_record("CVE-2020-1000", OLD_FIX, "2020-01-01T00:00:00Z")),
        )
        handle.writestr(
            "new.json",
            json.dumps(_record("CVE-2026-1000", FIX, "2026-01-01T00:00:00Z")),
        )

    all_fixes, all_stats = index_advisory_fixes(
        tmp_path, {REPOSITORY}, cutoff=""
    )
    recent_fixes, _ = index_advisory_fixes(
        tmp_path, {REPOSITORY}, cutoff="2025-01-01"
    )

    assert {entry["fix_sha"] for entry in all_fixes[REPOSITORY]} == {FIX, OLD_FIX}
    assert {entry["fix_sha"] for entry in recent_fixes[REPOSITORY]} == {FIX}
    assert all_stats["records"] == 2
    assert all_stats["landing_in_cohort"] == 2


def test_content_addressed_cache_hits_without_changing_results(tmp_path: Path) -> None:
    archive = tmp_path / "all.zip"
    cache_dir = tmp_path / "cache"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "one.json",
            json.dumps(_record("CVE-2026-1000", FIX, "2026-01-01T00:00:00Z")),
        )

    cold_fixes, cold_stats = index_advisory_fixes(
        tmp_path, {REPOSITORY}, cache_dir=cache_dir
    )
    warm_fixes, warm_stats = index_advisory_fixes(
        tmp_path, {REPOSITORY}, cache_dir=cache_dir
    )

    assert warm_fixes == cold_fixes
    assert cold_stats["cache_status"] == "cold_build"
    assert cold_stats["cache_misses"] == 1
    assert warm_stats["cache_status"] == "hit"
    assert warm_stats["cache_hits"] == 1


def test_changed_archive_content_uses_a_new_cache_shard(tmp_path: Path) -> None:
    archive = tmp_path / "all.zip"
    cache_dir = tmp_path / "cache"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "one.json",
            json.dumps(_record("CVE-2026-1000", FIX, "2026-01-01T00:00:00Z")),
        )
    first_fixes, first_stats = index_advisory_fixes(
        tmp_path, {REPOSITORY}, cache_dir=cache_dir
    )
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "two.json",
            json.dumps(_record("CVE-2026-2000", OLD_FIX, "2026-02-01T00:00:00Z")),
        )

    second_fixes, second_stats = index_advisory_fixes(
        tmp_path, {REPOSITORY}, cache_dir=cache_dir
    )

    assert first_fixes[REPOSITORY][0]["fix_sha"] == FIX
    assert second_fixes[REPOSITORY][0]["fix_sha"] == OLD_FIX
    assert first_stats["archive_manifest_sha256"] != second_stats["archive_manifest_sha256"]
    assert second_stats["cache_status"] == "cold_build"


def test_corrupt_cache_shard_is_rebuilt_fail_closed(tmp_path: Path) -> None:
    archive = tmp_path / "all.zip"
    cache_dir = tmp_path / "cache"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "one.json",
            json.dumps(_record("CVE-2026-1000", FIX, "2026-01-01T00:00:00Z")),
        )
    expected, _ = index_advisory_fixes(tmp_path, {REPOSITORY}, cache_dir=cache_dir)
    shard = next(cache_dir.glob("*.json.gz"))
    shard.write_bytes(b"not a gzip stream")

    observed, stats = index_advisory_fixes(
        tmp_path, {REPOSITORY}, cache_dir=cache_dir
    )

    assert observed == expected
    assert stats["cache_status"] == "cold_build"
    assert stats["cache_misses"] == 1


def test_reproduction_cutoff_bypasses_cache(tmp_path: Path) -> None:
    archive = tmp_path / "all.zip"
    cache_dir = tmp_path / "cache"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "old.json",
            json.dumps(_record("CVE-2020-1000", OLD_FIX, "2020-01-01T00:00:00Z")),
        )
        handle.writestr(
            "new.json",
            json.dumps(_record("CVE-2026-1000", FIX, "2026-01-01T00:00:00Z")),
        )

    fixes, stats = index_advisory_fixes(
        tmp_path,
        {REPOSITORY},
        cutoff="2025-01-01",
        cache_dir=cache_dir,
    )

    assert [row["fix_sha"] for row in fixes[REPOSITORY]] == [FIX]
    assert stats["cache_status"] == "bypassed_reproduction_cutoff"
    assert not cache_dir.exists()
