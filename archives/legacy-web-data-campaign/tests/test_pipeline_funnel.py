from __future__ import annotations

from cve_analyzer.models import (
    AiSignal,
    AiTool,
    BugIntroducingCommit,
    CommitInfo,
    CveAnalysisResult,
    CveScreeningResult,
)
from pipeline_funnel import production_funnel_counts


def _result(signal: AiSignal | None, *, confirmed: bool = False) -> dict:
    message = (
        f"fixture\n\n{signal.matched_text}"
        if signal is not None
        and signal.signal_type == "co_author_trailer"
        and "<" in signal.matched_text
        else "fixture"
    )
    bic = BugIntroducingCommit(
        commit=CommitInfo(
            sha="a" * 40,
            author_name="A",
            author_email="a@example.invalid",
            committer_name="A",
            committer_email="a@example.invalid",
            message=message,
            authored_date="2026-07-01T00:00:00Z",
            ai_signals=[signal] if signal else [],
        ),
        fix_commit_sha="b" * 40,
        blamed_file="src/a.py",
        blamed_lines=[1],
        deep_verification={"verdict": "CONFIRMED"} if confirmed else None,
    )
    result = CveAnalysisResult(
        cve_id="CVE-2026-1",
        bug_introducing_commits=[bic],
        screening=CveScreeningResult(
            worth_investigating=True,
            reasoning="fixture",
        ),
    )
    result.rebuild_signals()
    return result.to_dict()


def test_production_funnel_separates_primary_and_shadow_signals() -> None:
    primary = AiSignal(
        tool=AiTool.CLAUDE_CODE,
        signal_type="co_author_trailer",
        matched_text="Co-authored-by: Claude <noreply@anthropic.com>",
        confidence=0.99,
    )
    shadow = AiSignal(
        tool=AiTool.CLAUDE_CODE,
        signal_type="message_keyword",
        matched_text="generated with Claude",
        confidence=0.99,
    )

    counts = production_funnel_counts(
        [_result(primary, confirmed=True), _result(shadow)]
    )

    assert counts == {
        "readable": 2,
        "route_screenable": 1,
        "route_reason::explicit_ai_authorship_ready": 1,
        "source_match": 1,
        "screening_positive": 1,
        "verification_confirmed": 1,
        "route_deferred_retryable": 1,
        "route_reason::source_repository_incomplete": 1,
        "shadow_only": 1,
    }
