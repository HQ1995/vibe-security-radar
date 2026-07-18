"""Tests for scripts/web_data/writer.py (per-CVE artifact layout)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from web_data.schema import SchemaValidationError
from web_data.writer import write_web_data


def make_entry(cve_id: str = "CVE-2025-12345", **overrides) -> dict:
    """A minimal schema-valid CveEntry (mirrors test_web_data_schema.py)."""
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


def make_stats() -> dict:
    return {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "total_cves": 1,
        "total_analyzed": 100,
        "with_fix_commits": 50,
        "coverage_from": "2025-05-01",
        "coverage_to": "2026-01-01",
        "by_tool": {"cursor": 1},
        "by_severity": {"HIGH": 1},
        "by_language": {"Python": 1},
        "by_repo": {"org/repo": 1},
        "by_month": [{"month": "2025-06", "count": 1, "by_tool": {"cursor": 1}}],
    }


def test_writes_per_cve_layout(tmp_path: Path) -> None:
    entries = [make_entry("CVE-2025-00001"), make_entry("CVE-2025-00002")]
    result = write_web_data(entries, make_stats(), tmp_path, generated_at="2026-01-01T00:00:00+00:00")

    index = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert index == {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "total": 2,
        "ids": ["CVE-2025-00001", "CVE-2025-00002"],
    }
    for entry in entries:
        on_disk = json.loads((tmp_path / "cves" / f"{entry['id']}.json").read_text(encoding="utf-8"))
        assert on_disk == entry
    assert (tmp_path / "stats.json").exists()
    assert result.written == 2
    assert result.removed_stale == 0
    assert result.removed_legacy is False


def test_removes_stale_files_and_legacy_monolith(tmp_path: Path) -> None:
    cves_dir = tmp_path / "cves"
    cves_dir.mkdir()
    (cves_dir / "CVE-2024-99999.json").write_text("{}", encoding="utf-8")
    (tmp_path / "cves.json").write_text("{}", encoding="utf-8")

    result = write_web_data(
        [make_entry()], make_stats(), tmp_path, generated_at="2026-01-01T00:00:00+00:00"
    )

    assert result.removed_stale == 1
    assert result.removed_legacy is True
    assert not (cves_dir / "CVE-2024-99999.json").exists()
    assert not (tmp_path / "cves.json").exists()
    assert (cves_dir / "CVE-2025-12345.json").exists()


def test_invalid_entry_aborts_before_any_write(tmp_path: Path) -> None:
    bad = make_entry(published="June 2025")
    with pytest.raises(SchemaValidationError):
        write_web_data([bad], make_stats(), tmp_path, generated_at="x")

    assert not (tmp_path / "index.json").exists()
    assert not (tmp_path / "cves").exists() or list((tmp_path / "cves").glob("*.json")) == []
