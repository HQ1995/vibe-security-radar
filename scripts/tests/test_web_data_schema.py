"""Tests for scripts/web_data/schema.py and the producer-side contract fixes.

Covers: the hand-rolled schema validator, published-date normalization,
month bucketing, and quarantine reason recording.  The TestCommittedArtifacts
class is a release gate: the tracked web/data/*.json files must validate
against the published schema.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cve_analyzer.models import (
    AiSignal,
    AiTool,
    BugIntroducingCommit,
    CommitInfo,
    CveAnalysisResult,
    FixCommit,
)
from web_data.entry_builder import QuarantineLog, build_entry
from web_data.loader import normalize_published
from web_data.schema import (
    CVES_SCHEMA,
    STATS_SCHEMA,
    SchemaValidationError,
    validate,
    validate_or_raise,
)
from web_data.stats import _extract_month

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WEB_DATA_DIR = _REPO_ROOT / "web" / "data"


# ---------------------------------------------------------------------------
# Helpers (mirrors test_web_data_entry.py)
# ---------------------------------------------------------------------------

def make_signal() -> AiSignal:
    return AiSignal(
        tool=AiTool.CURSOR,
        signal_type="co_author_trailer",
        matched_text="Co-authored-by: Cursor",
        confidence=0.95,
        origin="commit_metadata",
    )


def make_bic(*, fix_commit_sha: str = "fix111") -> BugIntroducingCommit:
    return BugIntroducingCommit(
        commit=CommitInfo(
            sha="abc123",
            author_name="Alice",
            author_email="alice@example.com",
            committer_name="Alice",
            committer_email="alice@example.com",
            message="some commit",
            authored_date="2025-06-01T00:00:00Z",
            ai_signals=[make_signal()],
        ),
        fix_commit_sha=fix_commit_sha,
        blamed_file="src/main.py",
        blamed_lines=[10, 11, 12],
    )


def make_result(
    cve_id: str = "CVE-2025-12345",
    bics: list[BugIntroducingCommit] | None = None,
    fix_commits: list[FixCommit] | None = None,
) -> CveAnalysisResult:
    return CveAnalysisResult(
        cve_id=cve_id,
        description="A test vulnerability",
        severity="HIGH",
        bug_introducing_commits=bics if bics is not None else [make_bic()],
        fix_commits=fix_commits
        if fix_commits is not None
        else [FixCommit(sha="fix111", repo_url="https://github.com/org/repo", source="osv")],
    )


def make_entry(**overrides) -> dict:
    """A minimal schema-valid CveEntry."""
    entry = {
        "id": "CVE-2025-12345",
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


# ---------------------------------------------------------------------------
# Release gate: committed artifacts must validate
# ---------------------------------------------------------------------------

class TestCommittedArtifacts:
    def test_cves_json_validates(self) -> None:
        payload = json.loads((_WEB_DATA_DIR / "cves.json").read_text(encoding="utf-8"))
        errors = validate(payload, CVES_SCHEMA)
        assert errors == [], "\n".join(errors)

    def test_stats_json_validates(self) -> None:
        payload = json.loads((_WEB_DATA_DIR / "stats.json").read_text(encoding="utf-8"))
        errors = validate(payload, STATS_SCHEMA)
        assert errors == [], "\n".join(errors)


# ---------------------------------------------------------------------------
# Validator unit tests
# ---------------------------------------------------------------------------

class TestValidator:
    def test_valid_entry_passes(self) -> None:
        payload = {"generated_at": "2026-01-01T00:00:00+00:00", "total": 1, "cves": [make_entry()]}
        assert validate(payload, CVES_SCHEMA) == []

    def test_error_names_cve_id_and_field(self) -> None:
        entry = make_entry(published="2025-06-01T19:15:43.490")
        payload = {"generated_at": "x", "total": 1, "cves": [entry]}
        errors = validate(payload, CVES_SCHEMA)
        assert len(errors) == 1
        assert "CVE-2025-12345" in errors[0]
        assert "published" in errors[0]

    def test_missing_required_key(self) -> None:
        entry = make_entry()
        del entry["verdict"]
        payload = {"generated_at": "x", "total": 1, "cves": [entry]}
        errors = validate(payload, CVES_SCHEMA)
        assert any("verdict" in e for e in errors)

    def test_unexpected_key_rejected(self) -> None:
        payload = {"generated_at": "x", "total": 1, "cves": [make_entry(ecosystem_note="PyPI")]}
        errors = validate(payload, CVES_SCHEMA)
        assert any("ecosystem_note" in e for e in errors)

    def test_bool_is_not_a_number(self) -> None:
        payload = {"generated_at": "x", "total": 1, "cves": [make_entry(confidence=True)]}
        errors = validate(payload, CVES_SCHEMA)
        assert any("confidence" in e for e in errors)

    def test_nullable_fields_accept_null(self) -> None:
        entry = make_entry(cvss=None, ai_involved=None)
        payload = {"generated_at": "x", "total": 1, "cves": [entry]}
        assert validate(payload, CVES_SCHEMA) == []

    def test_validate_or_raise_includes_path(self) -> None:
        payload = {"generated_at": "x", "total": 1, "cves": [make_entry(published="June 2025")]}
        with pytest.raises(SchemaValidationError, match="CVE-2025-12345"):
            validate_or_raise(payload, CVES_SCHEMA, label="cves.json")


# ---------------------------------------------------------------------------
# published normalization
# ---------------------------------------------------------------------------

class TestNormalizePublished:
    def test_iso_millis(self) -> None:
        assert normalize_published("2025-10-03T19:15:43.490") == "2025-10-03"

    def test_iso_zulu(self) -> None:
        assert normalize_published("2026-03-24T00:00:00Z") == "2026-03-24"

    def test_iso_offset(self) -> None:
        assert normalize_published("2026-03-15T12:34:56+00:00") == "2026-03-15"

    def test_year_only_kept(self) -> None:
        assert normalize_published("2026") == "2026"

    def test_empty(self) -> None:
        assert normalize_published("") == ""

    def test_none(self) -> None:
        assert normalize_published(None) == ""

    def test_month_only_dropped(self) -> None:
        assert normalize_published("2026-03") == ""

    def test_garbage_dropped(self) -> None:
        assert normalize_published("June 2025") == ""

    def test_whitespace_stripped(self) -> None:
        assert normalize_published("  2025-06-18T00:00:00  ") == "2025-06-18"


# ---------------------------------------------------------------------------
# Month bucketing
# ---------------------------------------------------------------------------

class TestExtractMonth:
    def test_full_date(self) -> None:
        assert _extract_month("2026-03-24") == "2026-03"

    def test_year_only_ignored(self) -> None:
        assert _extract_month("2026") == ""

    def test_empty_ignored(self) -> None:
        assert _extract_month("") == ""


# ---------------------------------------------------------------------------
# Quarantine recording
# ---------------------------------------------------------------------------

class TestQuarantineLog:
    def test_records_reason_for_multi_repo(self) -> None:
        result = make_result(
            fix_commits=[
                FixCommit(sha="f1", repo_url="https://github.com/org/repo1", source="osv"),
                FixCommit(sha="f2", repo_url="https://github.com/org/repo2", source="osv"),
            ],
            bics=[make_bic(fix_commit_sha="f1")],
        )
        log = QuarantineLog()
        assert build_entry(result, quarantine=log) is None
        assert len(log) == 1
        record = log.records[0]
        assert record.cve_id == "CVE-2025-12345"
        assert "repositories" in record.reason

    def test_records_reason_for_unparseable_repo(self) -> None:
        result = make_result(
            fix_commits=[FixCommit(sha="fix111", repo_url="not-a-url", source="osv")],
        )
        log = QuarantineLog()
        assert build_entry(result, quarantine=log) is None
        assert len(log) == 1
        assert "not-a-url" in log.records[0].reason

    def test_empty_on_success(self) -> None:
        log = QuarantineLog()
        assert build_entry(make_result(), quarantine=log) is not None
        assert len(log) == 0

    def test_optional_argument(self) -> None:
        # Without a log, build_entry still returns None (backwards compatible).
        result = make_result(
            fix_commits=[FixCommit(sha="fix111", repo_url="not-a-url", source="osv")],
        )
        assert build_entry(result) is None
