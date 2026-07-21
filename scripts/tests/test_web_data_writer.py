"""Regression tests for the fail-closed per-CVE publication boundary."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

import web_data.writer as writer
from web_data.schema import SchemaValidationError
from web_data.writer import PublishedDataError, WriteResult, load_published_web_data

_GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _write_unreceipted_web_data(
    entries: list[dict],
    stats: dict,
    output_dir: Path,
    *,
    generated_at: str,
    inventory: dict | None = None,
) -> WriteResult:
    return writer.write_web_data(
        entries,
        stats,
        output_dir,
        generated_at=generated_at,
        allow_unreceipted=True,
        inventory=inventory,
    )


def make_entry(cve_id: str = "CVE-2025-12345", **overrides: object) -> dict:
    entry = {
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
    entry.update(overrides)
    return entry


def make_stats(entries: list[dict]) -> dict:
    count = len(entries)
    months: dict[str, int] = {}
    for entry in entries:
        published = entry["published"]
        if len(published) == 10:
            month = published[:7]
            months[month] = months.get(month, 0) + 1
    coverage_dates = [
        f"{entry['published']}-01-01"
        if len(entry["published"]) == 4
        else entry["published"]
        for entry in entries
    ]
    return {
        # The writer replaces this with the shared generation timestamp.
        "generated_at": "2025-12-31T00:00:00+00:00",
        "total_cves": count,
        "total_analyzed": max(100, count),
        "with_fix_commits": 50,
        "coverage_from": "2025-05-01",
        "coverage_to": max(coverage_dates, default=""),
        "by_tool": {"cursor": count} if count else {},
        "by_severity": {"HIGH": count} if count else {},
        "by_language": {"Python": count} if count else {},
        "by_repo": {},
        "by_month": [
            {"month": month, "count": month_count, "by_tool": {"cursor": month_count}}
            for month, month_count in sorted(months.items())
        ],
    }


def make_inventory() -> dict:
    member_ids = ["CVE-2025-12345"]
    component_sha256 = hashlib.sha256(
        ("\n".join(member_ids) + "\n").encode("utf-8")
    ).hexdigest()
    source_evidence_sha256 = hashlib.sha256(
        json.dumps(
            {"class_id": "CVE-2025-12345", "member_ids": member_ids},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    row = {
        "class_id": "CVE-2025-12345",
        "component_sha256": component_sha256,
        "source_evidence_sha256": source_evidence_sha256,
        "analysis_subject": "CVE-2025-12345",
        "member_ids": member_ids,
        "result_subject_ids": ["CVE-2025-12345"],
        "coverage_status": "complete",
        "detector_state": "positive",
        "adjudication_state": "ai_causal",
        "publication_state": "published",
        "recall_stratum": "detected_positive",
        "reasons": [],
    }
    inventory = {
        "schema_version": 2,
        "kind": "ai_vulnerability_detector_inventory",
        "generated_at": _GENERATED_AT,
        "source_snapshot_sha256": "a" * 64,
        "source_receipt_sha256": "b" * 64,
        "source_alias_class_manifest_sha256": hashlib.sha256(
            json.dumps(
                [
                    {
                        "analysis_subject": row["analysis_subject"],
                        "class_id": row["class_id"],
                        "component_sha256": row["component_sha256"],
                        "member_ids": row["member_ids"],
                        "source_evidence_sha256": row["source_evidence_sha256"],
                    }
                ],
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
        "campaign_id": "c" * 64,
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
    inventory["inventory_id"] = hashlib.sha256(
        json.dumps(
            inventory,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return inventory


def bind_inventory(stats: dict, inventory: dict) -> None:
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


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file()
    }


def _candidate_entries(published: writer.PublishedWebData) -> list[dict]:
    return [
        {key: value for key, value in entry.items() if key != "generation_id"}
        for entry in published.entries
    ]


def test_writes_and_reads_one_consistent_generation(tmp_path: Path) -> None:
    entries = [
        make_entry("CVE-2025-00001"),
        make_entry("GHSA-2mc2-g238-722j"),
        make_entry("OSV-2026-371"),
        make_entry("JLSEC-2025-60"),
    ]
    output_dir = tmp_path / "published"

    result = _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    published = load_published_web_data(output_dir)

    assert published.index == {
        "generation_id": published.index["generation_id"],
        "generated_at": _GENERATED_AT,
        "total": 4,
        "ids": [entry["id"] for entry in entries],
    }
    assert _candidate_entries(published) == entries
    assert len(published.index["generation_id"]) == 64
    assert {entry["generation_id"] for entry in published.entries} == {
        published.index["generation_id"]
    }
    assert published.stats["generation_id"] == published.index["generation_id"]
    assert published.stats["generated_at"] == _GENERATED_AT
    assert published.stats["total_cves"] == len(entries)
    assert result.written == 4
    assert result.removed_stale == 0
    assert result.removed_legacy is False


def test_inventory_is_separate_content_addressed_data_bound_from_stats(
    tmp_path: Path,
) -> None:
    entries = [make_entry()]
    stats = make_stats(entries)
    inventory = make_inventory()
    bind_inventory(stats, inventory)

    result = _write_unreceipted_web_data(
        entries,
        stats,
        tmp_path / "published",
        generated_at=_GENERATED_AT,
        inventory=inventory,
    )
    published = load_published_web_data(tmp_path / "published")

    assert published.inventory == inventory
    assert published.stats["inventory"]["inventory_id"] == inventory["inventory_id"]
    assert result.inventory_path == tmp_path / "published" / "inventory.json"


def test_inventory_reference_fails_closed_on_missing_or_mutated_artifact(
    tmp_path: Path,
) -> None:
    entries = [make_entry()]
    stats = make_stats(entries)
    inventory = make_inventory()
    bind_inventory(stats, inventory)

    with pytest.raises(PublishedDataError, match="missing inventory"):
        _write_unreceipted_web_data(
            entries,
            stats,
            tmp_path / "missing",
            generated_at=_GENERATED_AT,
        )

    mismatched_stats = make_stats(entries)
    bind_inventory(mismatched_stats, inventory)
    mismatched_stats["inventory"]["source_alias_class_manifest_sha256"] = "f" * 64
    with pytest.raises(PublishedDataError, match="inventory binding"):
        _write_unreceipted_web_data(
            entries,
            mismatched_stats,
            tmp_path / "mismatched-alias-manifest",
            generated_at=_GENERATED_AT,
            inventory=inventory,
        )

    output = tmp_path / "mutated"
    _write_unreceipted_web_data(
        entries,
        stats,
        output,
        generated_at=_GENERATED_AT,
        inventory=inventory,
    )
    payload = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    payload["rows"][0]["reasons"] = ["mutated"]
    (output / "inventory.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SchemaValidationError, match="inventory_id"):
        load_published_web_data(output)


def test_reader_enforces_per_entry_size_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [make_entry()]
    output_dir = tmp_path / "published"
    _write_unreceipted_web_data(
        entries,
        make_stats(entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    entry_size = (output_dir / "cves" / f"{entries[0]['id']}.json").stat().st_size
    monkeypatch.setattr(writer, "_MAX_PUBLISHED_ENTRY_BYTES", entry_size - 1)

    with pytest.raises(PublishedDataError, match="size bound"):
        load_published_web_data(output_dir)


def test_reader_enforces_aggregate_input_size_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [make_entry()]
    output_dir = tmp_path / "published"
    _write_unreceipted_web_data(
        entries,
        make_stats(entries),
        output_dir,
        generated_at=_GENERATED_AT,
    )
    monkeypatch.setattr(writer, "_MAX_PUBLISHED_INPUT_BYTES", 1)

    with pytest.raises(PublishedDataError, match="aggregate input size bound"):
        load_published_web_data(output_dir)


def test_year_only_date_is_excluded_from_months_and_normalized_for_coverage(
    tmp_path: Path,
) -> None:
    entries = [make_entry(published="2025")]
    stats = make_stats(entries)
    stats["coverage_from"] = "2025-01-01"

    _write_unreceipted_web_data(
        entries, stats, tmp_path / "published", generated_at=_GENERATED_AT
    )
    published = load_published_web_data(tmp_path / "published")

    assert published.stats["by_month"] == []
    assert published.stats["coverage_to"] == "2025-01-01"


def test_generation_swap_removes_stale_files_and_legacy_monolith(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry()]
    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    (output_dir / "cves" / "CVE-2024-99999.json").write_text("{}", encoding="utf-8")
    (output_dir / "cves.json").write_text("{}", encoding="utf-8")

    result = _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )

    assert result.removed_stale == 1
    assert result.removed_legacy is True
    assert not (output_dir / "cves.json").exists()
    assert not (output_dir / "cves" / "CVE-2024-99999.json").exists()
    load_published_web_data(output_dir)


def test_generation_swap_preserves_existing_directory_permissions(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "published"
    old_entries = [make_entry("CVE-2025-00001")]
    new_entries = [make_entry("CVE-2025-00002")]
    _write_unreceipted_web_data(
        old_entries, make_stats(old_entries), output_dir, generated_at=_GENERATED_AT
    )
    output_dir.chmod(0o750)

    _write_unreceipted_web_data(
        new_entries,
        make_stats(new_entries),
        output_dir,
        generated_at="2026-01-02T00:00:00+00:00",
    )

    assert stat.S_IMODE(output_dir.stat().st_mode) == 0o750
    assert _candidate_entries(load_published_web_data(output_dir)) == new_entries


def test_first_generation_inherits_parent_directory_permissions(tmp_path: Path) -> None:
    parent = tmp_path / "public"
    parent.mkdir()
    parent.chmod(0o751)
    output_dir = parent / "published"
    entries = [make_entry()]

    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )

    assert stat.S_IMODE(output_dir.stat().st_mode) == 0o751


@pytest.mark.parametrize(
    "unsafe_id",
    ["../escape", "CVE-2025-1234/../../escape", ".hidden", "bad id"],
)
def test_rejects_unsafe_entry_ids_before_writing(
    tmp_path: Path, unsafe_id: str
) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry(unsafe_id)]

    with pytest.raises((PublishedDataError, SchemaValidationError), match="id|pattern"):
        _write_unreceipted_web_data(
            entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
        )

    assert not output_dir.exists()
    assert not (tmp_path / "escape.json").exists()


def test_rejects_duplicate_ids_before_writing(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry(), make_entry()]

    with pytest.raises(
        (PublishedDataError, SchemaValidationError), match="duplicate|unique"
    ):
        _write_unreceipted_web_data(
            entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
        )

    assert not output_dir.exists()


def test_invalid_entry_preserves_existing_generation(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry()]
    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    before = _snapshot(output_dir)

    invalid_entries = [make_entry(published="June 2025")]
    with pytest.raises(SchemaValidationError):
        _write_unreceipted_web_data(
            invalid_entries,
            make_stats(invalid_entries),
            output_dir,
            generated_at="2026-01-02T00:00:00+00:00",
        )

    assert _snapshot(output_dir) == before


def test_rejects_stats_that_do_not_describe_entries(tmp_path: Path) -> None:
    entries = [make_entry()]
    stats = make_stats(entries)
    stats["by_tool"] = {"cursor": 99}

    with pytest.raises(PublishedDataError, match=r"stats\.by_tool"):
        _write_unreceipted_web_data(
            entries, stats, tmp_path / "published", generated_at=_GENERATED_AT
        )


@pytest.mark.parametrize("manifest_contents", [None, "{broken"])
def test_reader_fails_closed_on_missing_or_corrupt_manifest(
    tmp_path: Path,
    manifest_contents: str | None,
) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry()]
    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    manifest_path = output_dir / "index.json"
    if manifest_contents is None:
        manifest_path.unlink()
    else:
        manifest_path.write_text(manifest_contents, encoding="utf-8")

    with pytest.raises(PublishedDataError, match="manifest"):
        load_published_web_data(output_dir)


def test_reader_fails_closed_when_manifest_entry_is_missing(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry()]
    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    (output_dir / "cves" / f"{entries[0]['id']}.json").unlink()

    with pytest.raises(PublishedDataError, match="manifest/file mismatch"):
        load_published_web_data(output_dir)


def test_reader_fails_closed_when_manifest_entry_is_corrupt(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry()]
    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    (output_dir / "cves" / f"{entries[0]['id']}.json").write_text(
        "{broken", encoding="utf-8"
    )

    with pytest.raises(PublishedDataError, match=f"entry {entries[0]['id']}"):
        load_published_web_data(output_dir)


def test_reader_rejects_an_entry_from_another_generation(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry()]
    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    entry_path = output_dir / "cves" / f"{entries[0]['id']}.json"
    entry = json.loads(entry_path.read_text(encoding="utf-8"))
    entry["generation_id"] = "b" * 64
    entry_path.write_text(json.dumps(entry), encoding="utf-8")

    with pytest.raises(PublishedDataError, match="different generation"):
        load_published_web_data(output_dir)


def test_reader_rejects_content_that_does_not_match_generation_id(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry()]
    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    entry_path = output_dir / "cves" / f"{entries[0]['id']}.json"
    entry = json.loads(entry_path.read_text(encoding="utf-8"))
    entry["description"] = "tampered after publication"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")

    with pytest.raises(PublishedDataError, match="bundle contents"):
        load_published_web_data(output_dir)


def test_reader_fails_closed_when_manifest_omits_a_disk_entry(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry()]
    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    (output_dir / "cves" / "CVE-2025-99999.json").write_text("{}", encoding="utf-8")

    with pytest.raises(PublishedDataError, match="manifest/file mismatch"):
        load_published_web_data(output_dir)


def test_reader_fails_closed_on_entry_filename_id_mismatch(tmp_path: Path) -> None:
    output_dir = tmp_path / "published"
    entries = [make_entry()]
    _write_unreceipted_web_data(
        entries, make_stats(entries), output_dir, generated_at=_GENERATED_AT
    )
    entry_path = output_dir / "cves" / f"{entries[0]['id']}.json"
    entry_path.write_text(
        json.dumps(make_entry("CVE-2025-99999")),
        encoding="utf-8",
    )

    with pytest.raises(PublishedDataError, match="filename/id mismatch"):
        load_published_web_data(output_dir)


def test_interrupted_promotion_restores_the_previous_generation(
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
    before = _snapshot(output_dir)
    real_exchange = writer._rename_exchange

    def interrupt_after_exchange(
        first: Path,
        second: Path,
        parent_lock: writer.PublicationParentLock,
    ) -> None:
        real_exchange(first, second, parent_lock)
        raise KeyboardInterrupt("simulated interruption")

    monkeypatch.setattr(writer, "_rename_exchange", interrupt_after_exchange)

    with pytest.raises(KeyboardInterrupt, match="simulated interruption"):
        _write_unreceipted_web_data(
            new_entries,
            make_stats(new_entries),
            output_dir,
            generated_at="2026-01-02T00:00:00+00:00",
        )

    assert _snapshot(output_dir) == before
    assert _candidate_entries(load_published_web_data(output_dir)) == old_entries
    assert list(tmp_path.glob(".published.staging-*")) == []


def test_direct_unreceipted_publication_requires_explicit_opt_in(
    tmp_path: Path,
) -> None:
    entries = [make_entry()]

    with pytest.raises(PublishedDataError, match="unreceipted publication is disabled"):
        writer.write_web_data(
            entries,
            make_stats(entries),
            tmp_path / "published",
            generated_at=_GENERATED_AT,
        )

    assert not (tmp_path / "published").exists()
