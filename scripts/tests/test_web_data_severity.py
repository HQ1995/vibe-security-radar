"""Tests for scripts/web_data/severity.py"""

from __future__ import annotations

import pytest

from web_data.severity import (
    extract_cvss_score,
    parse_severity,
    _parse_cvss_vector,
    _compute_cvss_score,
    _parse_cvss4_severity,
    _parse_severity_label,
    _infer_severity_from_description,
    _extract_cvss_score,
)


# ---------------------------------------------------------------------------
# CVSS 3.1 vector parsing
# ---------------------------------------------------------------------------

class TestParseCvssVector:
    def test_valid_v31_vector(self):
        metrics = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        assert metrics["AV"] == "N"
        assert metrics["AC"] == "L"
        assert metrics["PR"] == "L"
        assert metrics["UI"] == "N"
        assert metrics["S"] == "U"
        assert metrics["C"] == "H"
        assert metrics["I"] == "H"
        assert metrics["A"] == "H"

    def test_empty_string(self):
        assert _parse_cvss_vector("") == {}

    def test_non_cvss3_prefix(self):
        assert _parse_cvss_vector("CVSS:4.0/AV:N") == {}

    def test_v30_vector(self):
        metrics = _parse_cvss_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
        assert metrics["AV"] == "L"
        assert metrics["A"] == "H"


class TestComputeCvssScore:
    def test_critical_network_no_auth(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
        metrics = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        score = _compute_cvss_score(metrics)
        assert score == 9.8

    def test_high_score(self):
        # CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H → 8.8
        metrics = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        score = _compute_cvss_score(metrics)
        assert 7.0 <= score < 9.0

    def test_medium_score(self):
        # Network, low complexity, low auth, no UI, no confidentiality/integrity impact
        metrics = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")
        score = _compute_cvss_score(metrics)
        assert 4.0 <= score < 7.0

    def test_incomplete_metrics_returns_zero(self):
        assert _compute_cvss_score({}) == 0.0
        assert _compute_cvss_score({"AV": "N"}) == 0.0

    def test_scope_changed_vector(self):
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
        metrics = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        score = _compute_cvss_score(metrics)
        assert score == 10.0

    def test_zero_impact_returns_zero(self):
        metrics = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        score = _compute_cvss_score(metrics)
        assert score == 0.0


# ---------------------------------------------------------------------------
# CVSS 4.0 severity parsing
# ---------------------------------------------------------------------------

class TestParseCvss4Severity:
    def test_empty_returns_empty(self):
        assert _parse_cvss4_severity("") == ""

    def test_non_cvss4_returns_empty(self):
        assert _parse_cvss4_severity("CVSS:3.1/AV:N") == ""

    def test_critical_all_high_network(self):
        # AV:N, AC:L, PR:N, UI:N with all-high impact → CRITICAL
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert _parse_cvss4_severity(v) == "CRITICAL"

    def test_high_partial_impact(self):
        # Single high impact metric, network
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
        result = _parse_cvss4_severity(v)
        assert result in ("HIGH", "CRITICAL")

    def test_low_when_no_impact(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        assert _parse_cvss4_severity(v) == "LOW"

    def test_subsequent_system_impact(self):
        # No direct impact but subsequent system impact
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H"
        result = _parse_cvss4_severity(v)
        assert result in ("CRITICAL", "HIGH")


# ---------------------------------------------------------------------------
# Severity label parsing
# ---------------------------------------------------------------------------

class TestParseSeverityLabel:
    def test_plain_high(self):
        assert _parse_severity_label("HIGH") == "HIGH"

    def test_plain_critical_lowercase(self):
        assert _parse_severity_label("critical") == "CRITICAL"

    def test_moderate_maps_to_medium(self):
        assert _parse_severity_label("MODERATE") == "MEDIUM"
        assert _parse_severity_label("moderate") == "MEDIUM"

    def test_low(self):
        assert _parse_severity_label("low") == "LOW"

    def test_empty_string(self):
        assert _parse_severity_label("") == "UNKNOWN"

    def test_cvss31_critical_vector(self):
        assert _parse_severity_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "CRITICAL"

    def test_cvss31_high_vector(self):
        result = _parse_severity_label("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        assert result == "HIGH"

    def test_cvss31_medium_vector(self):
        result = _parse_severity_label("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")
        assert result == "MEDIUM"

    def test_cvss31_low_vector(self):
        # Physical access, low impact
        result = _parse_severity_label("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        assert result == "LOW"

    def test_cvss4_vector(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert _parse_severity_label(v) == "CRITICAL"

    def test_garbage_string(self):
        assert _parse_severity_label("NOTAVALIDSEVERITY") == "UNKNOWN"


# ---------------------------------------------------------------------------
# Score extraction
# ---------------------------------------------------------------------------

class TestExtractCvssScore:
    def test_v3_vector(self):
        score = _extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_v4_vector_returns_approximate(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        score = _extract_cvss_score(v)
        assert score > 0.0

    def test_empty_returns_zero(self):
        assert _extract_cvss_score("") == 0.0

    def test_plain_label_returns_zero(self):
        assert _extract_cvss_score("HIGH") == 0.0


class TestExtractCvssScorePublic:
    def test_pre_score_takes_priority(self):
        # pre_score > 0 should bypass the vector
        score = extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", pre_score=7.5)
        assert score == 7.5

    def test_no_pre_score_uses_vector(self):
        score = extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_zero_pre_score_uses_vector(self):
        score = extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", pre_score=0.0)
        assert score == 9.8


# ---------------------------------------------------------------------------
# Description-based inference
# ---------------------------------------------------------------------------

class TestInferSeverityFromDescription:
    def test_heap_buffer_overflow_is_high(self):
        assert _infer_severity_from_description("heap-buffer-overflow in foo") == "HIGH"

    def test_use_after_free_is_high(self):
        assert _infer_severity_from_description("use-after-free vulnerability") == "HIGH"

    def test_remote_code_execution_is_high(self):
        assert _infer_severity_from_description("allows remote code execution") == "HIGH"

    def test_null_dereference_is_medium(self):
        assert _infer_severity_from_description("null-dereference crash") == "MEDIUM"

    def test_denial_of_service_is_medium(self):
        assert _infer_severity_from_description("can cause denial of service") == "MEDIUM"

    def test_oom_is_low(self):
        assert _infer_severity_from_description("oom in allocator") == "LOW"

    def test_no_match_returns_empty(self):
        assert _infer_severity_from_description("some unrelated issue") == ""

    def test_vuln_type_used(self):
        assert _infer_severity_from_description("", vuln_type="heap-buffer-overflow") == "HIGH"

    def test_high_takes_priority_over_medium(self):
        # HIGH keyword appears in combined string alongside MEDIUM keyword
        desc = "heap-buffer-overflow with denial of service"
        assert _infer_severity_from_description(desc) == "HIGH"


# ---------------------------------------------------------------------------
# Unified parse_severity
# ---------------------------------------------------------------------------

class TestParseSeverity:
    def test_pre_score_derives_critical(self):
        assert parse_severity("", cvss_score=9.5) == "CRITICAL"

    def test_pre_score_derives_high(self):
        assert parse_severity("", cvss_score=7.5) == "HIGH"

    def test_pre_score_derives_medium(self):
        assert parse_severity("", cvss_score=5.0) == "MEDIUM"

    def test_pre_score_derives_low(self):
        assert parse_severity("", cvss_score=2.0) == "LOW"

    def test_pre_score_does_not_override_known_label(self):
        # Severity label from severity_str should be preserved when known
        result = parse_severity("HIGH", cvss_score=5.0)
        assert result == "HIGH"

    def test_cvss_vector_parsed(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert parse_severity(v) == "CRITICAL"

    def test_plain_label_passthrough(self):
        assert parse_severity("HIGH") == "HIGH"
        assert parse_severity("medium") == "MEDIUM"
        assert parse_severity("MODERATE") == "MEDIUM"

    def test_ghsa_fallback(self):
        assert parse_severity("", ghsa_severity="HIGH") == "HIGH"

    def test_ghsa_fallback_not_used_when_label_known(self):
        # severity_str="LOW" is known, ghsa should not override
        assert parse_severity("LOW", ghsa_severity="HIGH") == "LOW"

    def test_description_inference_fallback(self):
        result = parse_severity("", description="heap-buffer-overflow detected")
        assert result == "HIGH"

    def test_unknown_string_returns_unknown(self):
        assert parse_severity("NOTVALID") == "UNKNOWN"

    def test_empty_everything_returns_unknown(self):
        assert parse_severity("") == "UNKNOWN"

    def test_cvss4_vector(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        result = parse_severity(v)
        assert result == "CRITICAL"

    def test_full_fallback_chain(self):
        # No severity_str, no pre_score, no ghsa — falls back to description
        result = parse_severity(
            "",
            cvss_score=0.0,
            ghsa_severity="",
            description="allows remote code execution via buffer overflow",
        )
        assert result == "HIGH"
