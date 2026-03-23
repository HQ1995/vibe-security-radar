"""Tests for scripts/web_data/filters.py"""

from __future__ import annotations

import pytest

from cve_analyzer.models import (
    AiSignal,
    AiTool,
    BugIntroducingCommit,
    CommitInfo,
    CveAnalysisResult,
    LlmVerdict,
    BlameVerdict,
)
from web_data.filters import is_fallback_verdict, should_include


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_commit(sha: str = "abc123", ai_signals: list[AiSignal] | None = None) -> CommitInfo:
    return CommitInfo(
        sha=sha,
        author_name="Alice",
        author_email="alice@example.com",
        committer_name="Alice",
        committer_email="alice@example.com",
        message="some commit",
        authored_date="2025-06-01T00:00:00Z",
        ai_signals=ai_signals or [],
    )


def make_signal() -> AiSignal:
    return AiSignal(
        tool=AiTool.CLAUDE_CODE,
        signal_type="co_author_trailer",
        matched_text="Co-authored-by: Claude",
        confidence=0.95,
    )


def make_bic(
    *,
    ai_signals: list[AiSignal] | None = None,
    screening_verification: LlmVerdict | None = None,
    deep_verification: dict | None = None,
) -> BugIntroducingCommit:
    return BugIntroducingCommit(
        commit=make_commit(ai_signals=ai_signals or []),
        fix_commit_sha="fix000",
        blamed_file="src/foo.py",
        blamed_lines=[10, 11],
        screening_verification=screening_verification,
        deep_verification=deep_verification,
    )


def make_result(
    *,
    cve_id: str = "CVE-2025-9999",
    description: str = "A vulnerability.",
    error: str = "",
    ai_involved: bool | None = None,
    bics: list[BugIntroducingCommit] | None = None,
) -> CveAnalysisResult:
    return CveAnalysisResult(
        cve_id=cve_id,
        description=description,
        error=error,
        ai_involved=ai_involved,
        bug_introducing_commits=bics or [],
    )


# ---------------------------------------------------------------------------
# is_fallback_verdict
# ---------------------------------------------------------------------------

class TestIsFallbackVerdict:
    def test_is_fallback_flag_true(self):
        assert is_fallback_verdict({"is_fallback": True, "verdict": "UNLIKELY"})

    def test_is_fallback_flag_false(self):
        assert not is_fallback_verdict({"is_fallback": False, "verdict": "CONFIRMED"})

    def test_fallback_reasoning_no_evidence(self):
        dv = {"reasoning": "Fallback verdict due to timeout", "evidence": []}
        assert is_fallback_verdict(dv)

    def test_fallback_reasoning_with_evidence(self):
        # Has evidence — NOT a fallback
        dv = {"reasoning": "Fallback verdict", "evidence": ["some evidence"]}
        assert not is_fallback_verdict(dv)

    def test_normal_confirmed_verdict(self):
        dv = {"verdict": "CONFIRMED", "reasoning": "The commit introduced the bug.", "evidence": ["line 10"]}
        assert not is_fallback_verdict(dv)

    def test_empty_dict(self):
        assert not is_fallback_verdict({})

    def test_fallback_reasoning_none_evidence(self):
        dv = {"reasoning": "Fallback verdict", "evidence": None}
        assert is_fallback_verdict(dv)


# ---------------------------------------------------------------------------
# should_include — error and rejected CVEs
# ---------------------------------------------------------------------------

class TestShouldIncludeErrorAndRejected:
    def test_error_result_excluded(self):
        result = make_result(error="Repository not found")
        assert not should_include(result)

    def test_rejected_reason_excluded(self):
        result = make_result(description="** REJECTED ** Rejected reason: duplicate")
        assert not should_include(result)

    def test_rejected_id_excluded(self):
        result = make_result(description="This CVE ID has been rejected.")
        assert not should_include(result)

    def test_rejected_case_insensitive(self):
        result = make_result(description="THIS CVE ID HAS BEEN REJECTED as a duplicate")
        assert not should_include(result)

    def test_normal_description_not_excluded(self):
        # ai_involved=True to ensure inclusion
        result = make_result(description="Buffer overflow in foo.", ai_involved=True)
        assert should_include(result)


# ---------------------------------------------------------------------------
# should_include — audit overrides
# ---------------------------------------------------------------------------

class TestShouldIncludeAuditOverrides:
    def test_audit_override_forces_inclusion(self):
        # No signals, no ai_involved — would normally be excluded
        result = make_result(cve_id="CVE-2025-1234")
        assert should_include(result, audit_overrides={"CVE-2025-1234"})

    def test_audit_override_bypasses_rejection_check(self):
        # Override does NOT bypass rejection — rejection is checked first
        result = make_result(
            cve_id="CVE-2025-1234",
            description="Rejected reason: duplicate entry",
        )
        assert not should_include(result, audit_overrides={"CVE-2025-1234"})

    def test_audit_override_not_in_set(self):
        result = make_result(cve_id="CVE-2025-5678")
        assert not should_include(result, audit_overrides={"CVE-2025-1234"})

    def test_no_audit_overrides_arg(self):
        result = make_result(cve_id="CVE-2025-1234", ai_involved=True)
        assert should_include(result, audit_overrides=None)


# ---------------------------------------------------------------------------
# should_include — ai_involved flag
# ---------------------------------------------------------------------------

class TestShouldIncludeAiInvolved:
    def test_ai_involved_true_included(self):
        result = make_result(ai_involved=True)
        assert should_include(result)

    def test_ai_involved_false_excluded(self):
        result = make_result(ai_involved=False)
        assert not should_include(result)

    def test_ai_involved_none_falls_through_to_bic_logic(self):
        # No BICs, no ai_involved → no passing BICs → excluded
        result = make_result(ai_involved=None)
        assert not should_include(result)


# ---------------------------------------------------------------------------
# should_include — BIC-level logic (no ai_involved)
# ---------------------------------------------------------------------------

class TestShouldIncludeBicLogic:
    def test_bic_with_no_signals_and_no_screening_skipped(self):
        bic = make_bic()  # no signals, no screening, no deep
        result = make_result(bics=[bic])
        assert not should_include(result)

    def test_bic_with_signals_no_deep_verify_benefit_of_doubt(self):
        bic = make_bic(ai_signals=[make_signal()])
        result = make_result(bics=[bic])
        assert should_include(result)

    def test_bic_with_screening_only_benefit_of_doubt(self):
        sv = LlmVerdict(
            verdict=BlameVerdict.CONFIRMED,
            reasoning="Looks AI-generated",
            model="claude-3",
        )
        bic = make_bic(screening_verification=sv)
        result = make_result(bics=[bic])
        assert should_include(result)

    def test_confirmed_deep_verdict_included(self):
        dv = {"verdict": "CONFIRMED", "final_verdict": "CONFIRMED", "reasoning": "AI wrote this"}
        bic = make_bic(ai_signals=[make_signal()], deep_verification=dv)
        result = make_result(bics=[bic])
        assert should_include(result)

    def test_unrelated_deep_verdict_excluded(self):
        dv = {"verdict": "UNRELATED", "final_verdict": "UNRELATED", "reasoning": "Not AI"}
        bic = make_bic(ai_signals=[make_signal()], deep_verification=dv)
        result = make_result(bics=[bic])
        assert not should_include(result)

    def test_unlikely_deep_verdict_excluded(self):
        dv = {"verdict": "UNLIKELY", "final_verdict": "UNLIKELY", "reasoning": "Probably not AI"}
        bic = make_bic(ai_signals=[make_signal()], deep_verification=dv)
        result = make_result(bics=[bic])
        assert not should_include(result)

    def test_fallback_verdict_treated_as_unverified(self):
        # Fallback verdict → benefit of the doubt (treated as no deep verify)
        dv = {"is_fallback": True, "verdict": "UNLIKELY", "reasoning": "Timeout fallback"}
        bic = make_bic(ai_signals=[make_signal()], deep_verification=dv)
        result = make_result(bics=[bic])
        assert should_include(result)

    def test_fallback_reasoning_no_evidence_treated_as_unverified(self):
        dv = {"reasoning": "Fallback verdict due to tool budget exhaustion", "evidence": []}
        bic = make_bic(ai_signals=[make_signal()], deep_verification=dv)
        result = make_result(bics=[bic])
        assert should_include(result)

    def test_multiple_bics_one_confirmed(self):
        # One UNRELATED BIC, one CONFIRMED BIC — should include
        dv_unrelated = {"final_verdict": "UNRELATED", "reasoning": "Not related"}
        dv_confirmed = {"final_verdict": "CONFIRMED", "reasoning": "AI wrote this"}
        bic1 = make_bic(ai_signals=[make_signal()], deep_verification=dv_unrelated)
        bic2 = make_bic(ai_signals=[make_signal()], deep_verification=dv_confirmed)
        result = make_result(bics=[bic1, bic2])
        assert should_include(result)

    def test_multiple_bics_all_unrelated(self):
        dv = {"final_verdict": "UNRELATED", "reasoning": "Not AI"}
        bic1 = make_bic(ai_signals=[make_signal()], deep_verification=dv)
        bic2 = make_bic(ai_signals=[make_signal()], deep_verification=dv)
        result = make_result(bics=[bic1, bic2])
        assert not should_include(result)

    def test_deep_verdict_without_final_verdict_key_uses_verdict(self):
        # Some deep verdicts only have "verdict" key, not "final_verdict"
        dv = {"verdict": "CONFIRMED", "reasoning": "AI-authored"}
        bic = make_bic(ai_signals=[make_signal()], deep_verification=dv)
        result = make_result(bics=[bic])
        assert should_include(result)
