"""Tests for generate_web_data.py - seed data generation script.

TDD: Written before the implementation.
"""

import json
import os
import tempfile

import pytest

from generate_web_data import (
    build_cve_entry,
    build_stats,
    filter_ai_results,
    load_cached_results,
    _extract_cvss_score,
    _parse_severity_label,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_result(
    cve_id="CVE-2026-99999",
    description="Test vulnerability",
    severity="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    ai_confidence=0.855,
    error="",
    ai_signals=None,
    bug_introducing_commits=None,
    fix_commits=None,
    cwes=None,
    references=None,
):
    """Build a minimal cached-result dict for testing."""
    if ai_signals is None:
        ai_signals = [
            {
                "tool": "cursor",
                "signal_type": "co_author_trailer",
                "matched_text": "Co-authored-by: Cursor",
                "confidence": 0.95,
            }
        ]
    if bug_introducing_commits is None:
        bug_introducing_commits = [
            {
                "commit": {
                    "sha": "def456abc",
                    "author_name": "dev",
                    "author_email": "dev@example.com",
                    "committer_name": "dev",
                    "committer_email": "dev@example.com",
                    "message": "feat: add new endpoint\n\nCo-authored-by: Cursor <cursor@cursor.com>",
                    "authored_date": "2026-01-15T02:58:20Z",
                    "ai_signals": [
                        {
                            "tool": "cursor",
                            "signal_type": "co_author_trailer",
                            "matched_text": "Co-authored-by: Cursor",
                            "confidence": 0.95,
                        }
                    ],
                },
                "fix_commit_sha": "abc123",
                "blamed_file": "src/main.py",
                "blamed_lines": [10, 11],
                "blame_confidence": 0.9,
            }
        ]
    if fix_commits is None:
        fix_commits = [
            {"sha": "abc123", "repo_url": "https://github.com/owner/repo", "source": "osv"}
        ]
    if cwes is None:
        cwes = ["CWE-78"]
    if references is None:
        references = ["https://github.com/owner/repo/commit/abc123"]

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "fix_commits": fix_commits,
        "bug_introducing_commits": bug_introducing_commits,
        "ai_signals": ai_signals,
        "references": references,
        "cwes": cwes,
        "error": error,
        "error_category": "",
        "ai_confidence": ai_confidence,
    }


# ---------------------------------------------------------------------------
# TestFilterAiResults
# ---------------------------------------------------------------------------

class TestFilterAiResults:
    """filter_ai_results should keep only entries with positive confidence and no errors."""

    def test_filters_zero_confidence(self):
        results = [
            _make_result(cve_id="CVE-A", ai_confidence=0.9),
            _make_result(cve_id="CVE-B", ai_confidence=0.0),
        ]
        filtered = filter_ai_results(results)
        ids = [r["cve_id"] for r in filtered]
        assert "CVE-A" in ids
        assert "CVE-B" not in ids

    def test_filters_errors(self):
        results = [
            _make_result(cve_id="CVE-A", ai_confidence=0.9, error=""),
            _make_result(cve_id="CVE-B", ai_confidence=0.9, error="no fix commits found"),
        ]
        filtered = filter_ai_results(results)
        ids = [r["cve_id"] for r in filtered]
        assert "CVE-A" in ids
        assert "CVE-B" not in ids

    def test_respects_min_confidence_threshold(self):
        results = [
            _make_result(cve_id="CVE-A", ai_confidence=0.5),
            _make_result(cve_id="CVE-B", ai_confidence=0.1),
            _make_result(cve_id="CVE-C", ai_confidence=0.05),
        ]
        filtered = filter_ai_results(results, min_confidence=0.2)
        ids = [r["cve_id"] for r in filtered]
        assert "CVE-A" in ids
        assert "CVE-B" not in ids
        assert "CVE-C" not in ids

    def test_empty_input(self):
        assert filter_ai_results([]) == []


# ---------------------------------------------------------------------------
# TestParseSeverityLabel
# ---------------------------------------------------------------------------

class TestParseSeverityLabel:
    """_parse_severity_label extracts the right label from CVSS vector strings."""

    def test_critical_from_cvss_vector(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H => score ~10.0 => CRITICAL
        assert _parse_severity_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == "CRITICAL"

    def test_high_from_cvss_vector(self):
        # CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H => score ~8.8 => HIGH
        assert _parse_severity_label("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == "HIGH"

    def test_medium_from_cvss_vector(self):
        # CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N => low score => LOW or MEDIUM
        label = _parse_severity_label("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N")
        assert label in ("LOW", "MEDIUM")

    def test_empty_string_returns_unknown(self):
        assert _parse_severity_label("") == "UNKNOWN"

    def test_unknown_format_returns_unknown(self):
        assert _parse_severity_label("not-a-cvss-string") == "UNKNOWN"


# ---------------------------------------------------------------------------
# TestExtractCvssScore
# ---------------------------------------------------------------------------

class TestExtractCvssScore:
    """_extract_cvss_score computes a numeric CVSS score from a vector string."""

    def test_critical_vector(self):
        score = _extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score >= 9.0

    def test_high_vector(self):
        score = _extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        assert 7.0 <= score < 9.0

    def test_empty_returns_zero(self):
        assert _extract_cvss_score("") == 0.0

    def test_invalid_returns_zero(self):
        assert _extract_cvss_score("garbage") == 0.0


# ---------------------------------------------------------------------------
# TestBuildCveEntry
# ---------------------------------------------------------------------------

class TestBuildCveEntry:
    """build_cve_entry transforms a cached result dict into a web-friendly entry."""

    def test_builds_entry_with_ai_signals(self):
        result = _make_result()
        entry = build_cve_entry(result)

        assert entry["id"] == "CVE-2026-99999"
        assert entry["description"] == "Test vulnerability"
        assert entry["severity"] == "HIGH"
        assert entry["cwes"] == ["CWE-78"]
        assert "cursor" in entry["ai_tools"]
        assert entry["confidence"] == 0.855
        assert len(entry["bug_commits"]) == 1

        bc = entry["bug_commits"][0]
        assert bc["sha"] == "def456abc"
        assert bc["author"] == "dev"
        assert bc["date"] == "2026-01-15T02:58:20Z"
        # Only first line of commit message
        assert bc["message"] == "feat: add new endpoint"
        assert bc["ai_signals"][0]["tool"] == "cursor"
        assert bc["blamed_file"] == "src/main.py"
        assert bc["blame_confidence"] == 0.9

    def test_extracts_severity_label_from_cvss(self):
        result = _make_result(severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        entry = build_cve_entry(result)
        assert entry["severity"] == "CRITICAL"

    def test_handles_missing_fields(self):
        result = {
            "cve_id": "CVE-2026-00001",
            "description": "",
            "severity": "",
            "fix_commits": [],
            "bug_introducing_commits": [],
            "ai_signals": [],
            "references": [],
            "cwes": [],
            "error": "",
            "error_category": "",
            "ai_confidence": 0.5,
        }
        entry = build_cve_entry(result)
        assert entry["id"] == "CVE-2026-00001"
        assert entry["severity"] == "UNKNOWN"
        assert entry["cvss"] == 0.0
        assert entry["ai_tools"] == []
        assert entry["bug_commits"] == []
        assert entry["fix_commits"] == []

    def test_deduplicates_ai_tools(self):
        result = _make_result(
            ai_signals=[
                {"tool": "cursor", "signal_type": "co_author_trailer", "matched_text": "x", "confidence": 0.9},
                {"tool": "cursor", "signal_type": "commit_message", "matched_text": "y", "confidence": 0.8},
                {"tool": "copilot", "signal_type": "co_author_trailer", "matched_text": "z", "confidence": 0.7},
            ]
        )
        entry = build_cve_entry(result)
        assert sorted(entry["ai_tools"]) == ["copilot", "cursor"]

    def test_fix_commits_preserved(self):
        result = _make_result()
        entry = build_cve_entry(result)
        assert len(entry["fix_commits"]) == 1
        assert entry["fix_commits"][0]["sha"] == "abc123"
        assert entry["fix_commits"][0]["repo_url"] == "https://github.com/owner/repo"


# ---------------------------------------------------------------------------
# TestBuildStats
# ---------------------------------------------------------------------------

class TestBuildStats:
    """build_stats aggregates statistics from web entries."""

    def _make_entry(self, cve_id="CVE-1", severity="HIGH", ai_tools=None, published="2026-01"):
        return {
            "id": cve_id,
            "severity": severity,
            "ai_tools": ai_tools or ["cursor"],
            "confidence": 0.8,
            "published": published,
            "ecosystem": "",
        }

    def test_aggregates_correctly(self):
        entries = [
            self._make_entry("CVE-1", "HIGH", ["cursor"], "2026-01"),
            self._make_entry("CVE-2", "CRITICAL", ["copilot"], "2026-01"),
            self._make_entry("CVE-3", "HIGH", ["cursor", "copilot"], "2026-02"),
        ]
        stats = build_stats(entries)

        assert stats["total_cves"] == 3
        assert stats["by_tool"]["cursor"] == 2
        assert stats["by_tool"]["copilot"] == 2
        assert stats["by_severity"]["HIGH"] == 2
        assert stats["by_severity"]["CRITICAL"] == 1
        assert len(stats["by_month"]) == 2
        assert stats["generated_at"]  # should be present

    def test_handles_empty_input(self):
        stats = build_stats([])
        assert stats["total_cves"] == 0
        assert stats["by_tool"] == {}
        assert stats["by_severity"] == {}
        assert stats["by_month"] == []

    def test_by_month_sorted(self):
        entries = [
            self._make_entry("CVE-1", published="2026-03"),
            self._make_entry("CVE-2", published="2026-01"),
            self._make_entry("CVE-3", published="2026-01"),
        ]
        stats = build_stats(entries)
        months = [m["month"] for m in stats["by_month"]]
        assert months == sorted(months)


# ---------------------------------------------------------------------------
# TestLoadCachedResults
# ---------------------------------------------------------------------------

class TestLoadCachedResults:
    """load_cached_results reads JSON files from a directory."""

    def test_reads_json_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data = _make_result(cve_id="CVE-TEMP-1")
            with open(os.path.join(tmpdir, "CVE-TEMP-1.json"), "w") as f:
                json.dump(data, f)
            results = load_cached_results(tmpdir)
            assert len(results) == 1
            assert results[0]["cve_id"] == "CVE-TEMP-1"

    def test_skips_non_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "readme.txt"), "w") as f:
                f.write("not json")
            data = _make_result(cve_id="CVE-TEMP-2")
            with open(os.path.join(tmpdir, "CVE-TEMP-2.json"), "w") as f:
                json.dump(data, f)
            results = load_cached_results(tmpdir)
            assert len(results) == 1

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = load_cached_results(tmpdir)
            assert results == []
