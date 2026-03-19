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
    _file_extension_to_language,
    _determine_languages,
    _parse_severity_label,
    _recompute_ai_confidence,
    _repo_url_to_display_name,
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
            _make_result(
                cve_id="CVE-B",
                ai_confidence=0.0,
                bug_introducing_commits=[],
                ai_signals=[],
            ),
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

    def test_filters_by_verdict_not_confidence(self):
        """filter_ai_results uses verdict-based filtering: CONFIRMED passes,
        UNLIKELY/UNRELATED are excluded, no deep verify = benefit of the doubt."""
        def _bic_with_deep(verdict: str | None) -> list[dict]:
            bic = {
                "commit": {
                    "sha": "abc",
                    "author_name": "dev",
                    "author_email": "dev@example.com",
                    "committer_name": "dev",
                    "committer_email": "dev@example.com",
                    "message": "fix",
                    "authored_date": "2026-01-15T00:00:00Z",
                    "ai_signals": [
                        {"tool": "cursor", "signal_type": "co_author_trailer",
                         "matched_text": "x", "confidence": 0.9}
                    ],
                },
                "blamed_file": "main.py",
                "blamed_lines": [1],
                "blame_confidence": 0.9,
            }
            if verdict is not None:
                bic["deep_verification"] = {
                    "verdict": verdict,
                    "confidence": "high",
                    "reasoning": "test",
                    "model": "test-model",
                }
            return [bic]

        results = [
            _make_result(cve_id="CVE-CONFIRMED", bug_introducing_commits=_bic_with_deep("CONFIRMED")),
            _make_result(cve_id="CVE-UNLIKELY", bug_introducing_commits=_bic_with_deep("UNLIKELY")),
            _make_result(cve_id="CVE-UNRELATED", bug_introducing_commits=_bic_with_deep("UNRELATED")),
            _make_result(cve_id="CVE-NODEEP", bug_introducing_commits=_bic_with_deep(None)),
        ]
        filtered = filter_ai_results(results)
        ids = [r["cve_id"] for r in filtered]
        assert "CVE-CONFIRMED" in ids
        assert "CVE-UNLIKELY" not in ids
        assert "CVE-UNRELATED" not in ids
        assert "CVE-NODEEP" in ids  # benefit of the doubt

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
        """ai_tools is extracted from BIC-level signals, not top-level ai_signals."""
        bics = [
            {
                "commit": {
                    "sha": "aaa",
                    "author_name": "dev", "author_email": "dev@example.com",
                    "committer_name": "dev", "committer_email": "dev@example.com",
                    "message": "feat: add endpoint",
                    "authored_date": "2026-01-15T00:00:00Z",
                    "ai_signals": [
                        {"tool": "cursor", "signal_type": "co_author_trailer", "matched_text": "x", "confidence": 0.9},
                        {"tool": "cursor", "signal_type": "commit_message", "matched_text": "y", "confidence": 0.8},
                    ],
                },
                "fix_commit_sha": "abc123",
                "blamed_file": "src/main.py",
                "blamed_lines": [10],
                "blame_confidence": 0.9,
            },
            {
                "commit": {
                    "sha": "bbb",
                    "author_name": "dev", "author_email": "dev@example.com",
                    "committer_name": "dev", "committer_email": "dev@example.com",
                    "message": "feat: add helper",
                    "authored_date": "2026-01-16T00:00:00Z",
                    "ai_signals": [
                        {"tool": "copilot", "signal_type": "co_author_trailer", "matched_text": "z", "confidence": 0.7},
                    ],
                },
                "fix_commit_sha": "abc123",
                "blamed_file": "src/helper.py",
                "blamed_lines": [5],
                "blame_confidence": 0.8,
            },
        ]
        result = _make_result(bug_introducing_commits=bics)
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

    def _make_entry(self, cve_id="CVE-1", severity="HIGH", ai_tools=None,
                    published="2026-01", languages=None, fix_commits=None):
        return {
            "id": cve_id,
            "severity": severity,
            "ai_tools": ai_tools or ["cursor"],
            "languages": languages or [],
            "fix_commits": fix_commits or [],
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


# ---------------------------------------------------------------------------
# TestFileExtensionToLanguage
# ---------------------------------------------------------------------------

class TestFileExtensionToLanguage:
    """_file_extension_to_language maps file extensions to language names."""

    def test_python_extension(self):
        assert _file_extension_to_language("src/main.py") == "Python"

    def test_javascript_extension(self):
        assert _file_extension_to_language("index.js") == "JavaScript"

    def test_typescript_extensions(self):
        assert _file_extension_to_language("app.ts") == "TypeScript"
        assert _file_extension_to_language("component.tsx") == "TypeScript"

    def test_go_extension(self):
        assert _file_extension_to_language("main.go") == "Go"

    def test_rust_extension(self):
        assert _file_extension_to_language("lib.rs") == "Rust"

    def test_c_extensions(self):
        assert _file_extension_to_language("main.c") == "C/C++"
        assert _file_extension_to_language("header.h") == "C/C++"

    def test_cpp_extensions(self):
        assert _file_extension_to_language("main.cpp") == "C/C++"
        assert _file_extension_to_language("main.cc") == "C/C++"

    def test_unknown_extension_returns_none(self):
        assert _file_extension_to_language("data.csv") is None
        assert _file_extension_to_language("Makefile") is None

    def test_empty_string_returns_none(self):
        assert _file_extension_to_language("") is None

    def test_case_insensitive(self):
        assert _file_extension_to_language("main.PY") == "Python"
        assert _file_extension_to_language("app.JS") == "JavaScript"


# ---------------------------------------------------------------------------
# TestDetermineLanguages
# ---------------------------------------------------------------------------

class TestDetermineLanguages:
    """_determine_languages extracts sorted unique languages from bug commits."""

    def test_single_language(self):
        commits = [{"blamed_file": "src/main.py"}]
        assert _determine_languages(commits) == ["Python"]

    def test_multiple_languages(self):
        commits = [
            {"blamed_file": "src/main.py"},
            {"blamed_file": "lib/util.js"},
        ]
        assert _determine_languages(commits) == ["JavaScript", "Python"]

    def test_deduplicates(self):
        commits = [
            {"blamed_file": "src/a.py"},
            {"blamed_file": "src/b.py"},
        ]
        assert _determine_languages(commits) == ["Python"]

    def test_empty_commits(self):
        assert _determine_languages([]) == []

    def test_unknown_extensions_excluded(self):
        commits = [
            {"blamed_file": "src/main.py"},
            {"blamed_file": "data.csv"},
        ]
        assert _determine_languages(commits) == ["Python"]

    def test_missing_blamed_file(self):
        commits = [{"blamed_file": ""}]
        assert _determine_languages(commits) == []


# ---------------------------------------------------------------------------
# TestBuildCveEntryLanguages
# ---------------------------------------------------------------------------

class TestBuildCveEntryLanguages:
    """build_cve_entry includes languages derived from bug commit blamed_files."""

    def test_entry_has_languages_field(self):
        result = _make_result()
        entry = build_cve_entry(result)
        assert "languages" in entry
        assert entry["languages"] == ["Python"]

    def test_entry_multiple_languages(self):
        result = _make_result(
            bug_introducing_commits=[
                {
                    "commit": {
                        "sha": "abc123",
                        "author_name": "dev",
                        "author_email": "dev@example.com",
                        "committer_name": "dev",
                        "committer_email": "dev@example.com",
                        "message": "fix",
                        "authored_date": "2026-01-15T00:00:00Z",
                        "ai_signals": [{"tool": "cursor", "signal_type": "co_author_trailer", "matched_text": "x", "confidence": 0.9}],
                    },
                    "blamed_file": "src/main.py",
                    "blamed_lines": [1],
                    "blame_confidence": 0.9,
                },
                {
                    "commit": {
                        "sha": "def456",
                        "author_name": "dev",
                        "author_email": "dev@example.com",
                        "committer_name": "dev",
                        "committer_email": "dev@example.com",
                        "message": "fix",
                        "authored_date": "2026-01-15T00:00:00Z",
                        "ai_signals": [{"tool": "cursor", "signal_type": "co_author_trailer", "matched_text": "x", "confidence": 0.9}],
                    },
                    "blamed_file": "lib/util.js",
                    "blamed_lines": [1],
                    "blame_confidence": 0.9,
                },
            ]
        )
        entry = build_cve_entry(result)
        assert entry["languages"] == ["JavaScript", "Python"]


# ---------------------------------------------------------------------------
# TestBuildStatsLanguages
# ---------------------------------------------------------------------------

class TestBuildStatsLanguages:
    """build_stats includes by_language counts."""

    def test_by_language_counts(self):
        entries = [
            {"id": "CVE-1", "severity": "HIGH", "ai_tools": ["cursor"], "languages": ["Python"], "confidence": 0.8, "published": "2026-01", "ecosystem": ""},
            {"id": "CVE-2", "severity": "HIGH", "ai_tools": ["cursor"], "languages": ["Python", "JavaScript"], "confidence": 0.8, "published": "2026-01", "ecosystem": ""},
            {"id": "CVE-3", "severity": "HIGH", "ai_tools": ["cursor"], "languages": ["Go"], "confidence": 0.8, "published": "2026-01", "ecosystem": ""},
        ]
        stats = build_stats(entries)
        assert stats["by_language"]["Python"] == 2
        assert stats["by_language"]["JavaScript"] == 1
        assert stats["by_language"]["Go"] == 1

    def test_by_language_empty(self):
        stats = build_stats([])
        assert stats["by_language"] == {}


# ---------------------------------------------------------------------------
# TestRepoUrlToDisplayName
# ---------------------------------------------------------------------------

class TestRepoUrlToDisplayName:
    """_repo_url_to_display_name extracts owner/repo from GitHub URLs."""

    def test_github_url(self):
        assert _repo_url_to_display_name("https://github.com/Owner/Repo") == "owner/repo"

    def test_github_url_with_git_suffix(self):
        assert _repo_url_to_display_name("https://github.com/owner/repo.git") == "owner/repo"

    def test_non_github_url(self):
        assert _repo_url_to_display_name("https://gitlab.com/owner/repo") is None

    def test_empty_string(self):
        assert _repo_url_to_display_name("") is None

    def test_trailing_slash(self):
        assert _repo_url_to_display_name("https://github.com/owner/repo/") == "owner/repo"


# ---------------------------------------------------------------------------
# TestBuildStatsRepo
# ---------------------------------------------------------------------------

class TestBuildStatsRepo:
    """build_stats includes by_repo counts."""

    def test_by_repo_counts(self):
        entries = [
            {
                "id": "CVE-1", "severity": "HIGH", "ai_tools": ["cursor"],
                "languages": ["Python"], "confidence": 0.8, "published": "2026-01",
                "ecosystem": "",
                "fix_commits": [{"sha": "a", "repo_url": "https://github.com/owner/repo-a", "source": "osv"}],
            },
            {
                "id": "CVE-2", "severity": "HIGH", "ai_tools": ["cursor"],
                "languages": ["Python"], "confidence": 0.8, "published": "2026-01",
                "ecosystem": "",
                "fix_commits": [{"sha": "b", "repo_url": "https://github.com/owner/repo-a", "source": "osv"}],
            },
            {
                "id": "CVE-3", "severity": "CRITICAL", "ai_tools": ["cursor"],
                "languages": ["Go"], "confidence": 0.8, "published": "2026-01",
                "ecosystem": "",
                "fix_commits": [{"sha": "c", "repo_url": "https://github.com/other/repo-b", "source": "osv"}],
            },
        ]
        stats = build_stats(entries)
        assert stats["by_repo"]["owner/repo-a"] == 2
        assert stats["by_repo"]["other/repo-b"] == 1

    def test_by_repo_dedupes_per_cve(self):
        """A CVE with two fix commits in the same repo counts once."""
        entries = [
            {
                "id": "CVE-1", "severity": "HIGH", "ai_tools": ["cursor"],
                "languages": [], "confidence": 0.8, "published": "2026-01",
                "ecosystem": "",
                "fix_commits": [
                    {"sha": "a", "repo_url": "https://github.com/owner/repo", "source": "osv"},
                    {"sha": "b", "repo_url": "https://github.com/owner/repo", "source": "osv"},
                ],
            },
        ]
        stats = build_stats(entries)
        assert stats["by_repo"]["owner/repo"] == 1

    def test_by_repo_empty(self):
        stats = build_stats([])
        assert stats["by_repo"] == {}


# ---------------------------------------------------------------------------
# TestRecomputeAiConfidenceUnrelated
# ---------------------------------------------------------------------------


def _make_bic_dict(
    tool: str,
    signal_conf: float,
    blame_conf: float,
    verdict: str | None = None,
    sha: str = "abc123",
) -> dict:
    """Build a BIC dict with a specific tool and optional LLM verdict."""
    bic = {
        "commit": {
            "sha": sha,
            "author_name": "dev",
            "author_email": "dev@example.com",
            "committer_name": "dev",
            "committer_email": "dev@example.com",
            "message": "fix",
            "authored_date": "2026-01-15T00:00:00Z",
            "ai_signals": [
                {
                    "tool": tool,
                    "signal_type": "co_author_trailer",
                    "matched_text": f"Co-Authored-By: {tool}",
                    "confidence": signal_conf,
                }
            ],
        },
        "blamed_file": "src/main.py",
        "blamed_lines": [1],
        "blame_confidence": blame_conf,
    }
    if verdict is not None:
        # _bic_dict_is_excluded checks deep_verification (authoritative),
        # not screening_verification (advisory only).
        bic["deep_verification"] = {
            "verdict": verdict,
            "confidence": "high",
            "reasoning": "test",
            "model": "test-model",
        }
    return bic


class TestRecomputeAiConfidenceUnrelated:
    """_recompute_ai_confidence should exclude UNRELATED BICs."""

    def test_unrelated_bic_excluded_from_confidence(self):
        confirmed_bic = _make_bic_dict(
            "cursor", signal_conf=0.7, blame_conf=0.8,
            verdict="CONFIRMED", sha="aaa111",
        )
        unrelated_bic = _make_bic_dict(
            "claude_code", signal_conf=0.95, blame_conf=0.9,
            verdict="UNRELATED", sha="bbb222",
        )
        result = {
            "bug_introducing_commits": [confirmed_bic, unrelated_bic],
            "ai_signals": [
                confirmed_bic["commit"]["ai_signals"][0],
                unrelated_bic["commit"]["ai_signals"][0],
            ],
        }
        conf = _recompute_ai_confidence(result)
        # Should use CONFIRMED BIC: 0.7 * 0.8 = 0.56
        assert abs(conf - 0.56) < 0.01

    def test_all_unrelated_yields_zero(self):
        unrelated_bic = _make_bic_dict(
            "claude_code", signal_conf=0.95, blame_conf=0.9,
            verdict="UNRELATED", sha="aaa111",
        )
        result = {
            "bug_introducing_commits": [unrelated_bic],
            "ai_signals": unrelated_bic["commit"]["ai_signals"],
        }
        conf = _recompute_ai_confidence(result)
        assert conf == 0.0

    def test_no_verdict_still_included(self):
        bic = _make_bic_dict(
            "cursor", signal_conf=0.9, blame_conf=0.9,
            verdict=None, sha="aaa111",
        )
        result = {
            "bug_introducing_commits": [bic],
            "ai_signals": bic["commit"]["ai_signals"],
        }
        conf = _recompute_ai_confidence(result)
        assert abs(conf - 0.81) < 0.01

    def test_unlikely_still_included_but_penalized(self):
        """UNLIKELY BICs are included (not excluded) but receive a 0.25x
        penalty for high-confidence UNLIKELY verdicts."""
        bic = _make_bic_dict(
            "cursor", signal_conf=0.9, blame_conf=0.9,
            verdict="UNLIKELY", sha="aaa111",
        )
        result = {
            "bug_introducing_commits": [bic],
            "ai_signals": bic["commit"]["ai_signals"],
        }
        conf = _recompute_ai_confidence(result)
        # 0.9 * 0.9 * 0.25 (high-confidence UNLIKELY penalty) = 0.2025
        assert abs(conf - 0.2025) < 0.01


# ---------------------------------------------------------------------------
# TestHowIntroducedPriority
# ---------------------------------------------------------------------------

def _make_bic_with_verdicts(
    sha="def456abc",
    ai_signals=True,
    screening_verdict=None,
    screening_reasoning="",
    screening_causal_chain="",
    screening_vulnerable_pattern="",
    deep_verdict=None,
    deep_confidence="high",
    deep_reasoning="",
):
    """Build a BIC dict with optional screening and deep-verify verdicts."""
    bic = {
        "commit": {
            "sha": sha,
            "author_name": "dev",
            "author_email": "dev@example.com",
            "committer_name": "dev",
            "committer_email": "dev@example.com",
            "message": "feat: some change",
            "authored_date": "2026-01-15T00:00:00Z",
            "ai_signals": [
                {"tool": "claude_code", "signal_type": "co_author_trailer",
                 "matched_text": "Co-authored-by: Claude", "confidence": 0.95}
            ] if ai_signals else [],
        },
        "fix_commit_sha": "abc123",
        "blamed_file": "src/main.py",
        "blamed_lines": [10],
        "blame_confidence": 1.0,
    }
    if screening_verdict:
        bic["screening_verification"] = {
            "verdict": screening_verdict,
            "reasoning": screening_reasoning,
            "causal_chain": screening_causal_chain,
            "vulnerable_pattern": screening_vulnerable_pattern,
            "vuln_type": "Test Vuln",
            "vuln_description": "Test description",
            "model": "test-model",
        }
    if deep_verdict:
        bic["deep_verification"] = {
            "verdict": deep_verdict,
            "confidence": deep_confidence,
            "reasoning": deep_reasoning,
            "model": "gpt-5.4",
        }
    return bic


class TestHowIntroducedPriority:
    """how_introduced should prefer deep-verify CONFIRMED over screening CONFIRMED."""

    def test_deep_verify_confirmed_over_screening_confirmed(self):
        """When screening says CONFIRMED but deep verify says UNLIKELY on BIC 1,
        and deep verify says CONFIRMED on BIC 2, use BIC 2's reasoning."""
        bic1 = _make_bic_with_verdicts(
            sha="bic1",
            screening_verdict="CONFIRMED",
            screening_causal_chain="Screening says BIC1 caused it",
            deep_verdict="UNLIKELY",
            deep_reasoning="Deep verify says BIC1 did NOT cause it",
        )
        bic2 = _make_bic_with_verdicts(
            sha="bic2",
            screening_verdict="UNRELATED",
            deep_verdict="CONFIRMED",
            deep_reasoning="Deep verify says BIC2 introduced the path traversal",
        )
        result = _make_result(
            bug_introducing_commits=[bic1, bic2],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert "BIC2 introduced" in entry["how_introduced"]
        assert "BIC1 caused it" not in entry["how_introduced"]

    def test_screening_ignored_when_deep_says_unlikely(self):
        """A BIC with screening CONFIRMED but deep verify UNLIKELY should NOT
        provide how_introduced."""
        bic = _make_bic_with_verdicts(
            sha="overruled",
            screening_verdict="CONFIRMED",
            screening_causal_chain="Screening thinks this caused it",
            deep_verdict="UNLIKELY",
            deep_reasoning="Deep verify disagrees",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert "Screening thinks" not in entry["how_introduced"]

    def test_screening_ok_when_no_deep_verify(self):
        """If no deep verify exists, screening CONFIRMED is acceptable."""
        bic = _make_bic_with_verdicts(
            sha="no_deep",
            screening_verdict="CONFIRMED",
            screening_causal_chain="Screening explanation is fine",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert entry["how_introduced"] == "Screening explanation is fine"

    def test_deep_confirmed_reasoning_used(self):
        """Deep verify CONFIRMED reasoning should be used as how_introduced."""
        bic = _make_bic_with_verdicts(
            sha="confirmed",
            deep_verdict="CONFIRMED",
            deep_reasoning="The commit introduced processIncludes without path validation",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert "processIncludes" in entry["how_introduced"]

    def test_causal_chain_preferred_over_deep_reasoning(self):
        """When both screening causal_chain and deep verify reasoning exist
        for the same CONFIRMED BIC, prefer causal_chain (more concise)."""
        bic = _make_bic_with_verdicts(
            sha="both",
            screening_verdict="CONFIRMED",
            screening_causal_chain="Concise: commit added unsanitized input interpolation",
            deep_verdict="CONFIRMED",
            deep_reasoning="Verbose forensic analysis about the commit and its context",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert "Concise" in entry["how_introduced"]
        assert "Verbose" not in entry["how_introduced"]

    def test_deep_reasoning_fallback_when_no_causal_chain(self):
        """If screening exists but has empty causal_chain, fall back to
        deep verify reasoning."""
        bic = _make_bic_with_verdicts(
            sha="no_chain",
            screening_verdict="CONFIRMED",
            screening_causal_chain="",
            deep_verdict="CONFIRMED",
            deep_reasoning="Deep verify found path traversal in the commit",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert "path traversal" in entry["how_introduced"]

    def test_vulnerable_pattern_output_from_screening(self):
        """vulnerable_pattern from screening should appear in entry."""
        bic = _make_bic_with_verdicts(
            sha="vp_test",
            screening_verdict="CONFIRMED",
            screening_causal_chain="The commit introduced XSS",
            screening_vulnerable_pattern="Unsanitized innerHTML assignment",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert entry["vulnerable_pattern"] == "Unsanitized innerHTML assignment"

    def test_vulnerable_pattern_from_deep_confirmed_with_screening(self):
        """vulnerable_pattern should come from screening even when deep verify
        is CONFIRMED."""
        bic = _make_bic_with_verdicts(
            sha="vp_deep",
            screening_verdict="CONFIRMED",
            screening_causal_chain="causal chain text",
            screening_vulnerable_pattern="Direct SQL string concatenation",
            deep_verdict="CONFIRMED",
            deep_reasoning="The commit introduced SQL injection",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert entry["vulnerable_pattern"] == "Direct SQL string concatenation"

    def test_vulnerable_pattern_empty_when_no_screening(self):
        """vulnerable_pattern should be empty when no screening exists."""
        bic = _make_bic_with_verdicts(
            sha="no_screen",
            deep_verdict="CONFIRMED",
            deep_reasoning="Deep verify found the issue",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert entry["vulnerable_pattern"] == ""

    def test_vulnerable_pattern_from_screening_fallback(self):
        """vulnerable_pattern should be set even when only screening (no deep
        verify) provides it."""
        bic = _make_bic_with_verdicts(
            sha="screen_only",
            screening_verdict="CONFIRMED",
            screening_causal_chain="Screening explanation",
            screening_vulnerable_pattern="Unvalidated redirect target",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert entry["vulnerable_pattern"] == "Unvalidated redirect target"

    def test_vulnerable_pattern_suppressed_when_deep_says_unlikely(self):
        """vulnerable_pattern should be empty when deep verify overrules
        screening CONFIRMED with UNLIKELY."""
        bic = _make_bic_with_verdicts(
            sha="suppressed",
            screening_verdict="CONFIRMED",
            screening_causal_chain="Screening says XSS",
            screening_vulnerable_pattern="innerHTML = userInput",
            deep_verdict="UNLIKELY",
            deep_reasoning="Deep verify disagrees",
        )
        result = _make_result(
            bug_introducing_commits=[bic],
            ai_signals=[{"tool": "claude_code", "signal_type": "co_author_trailer",
                         "matched_text": "Co-authored-by: Claude", "confidence": 0.95}],
        )
        entry = build_cve_entry(result)
        assert entry["vulnerable_pattern"] == ""
