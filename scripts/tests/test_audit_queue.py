"""Focused regressions for audit queue scoring."""

from __future__ import annotations

import audit_queue


def _fn_candidate(repo_ai_activity: list[str]) -> dict:
    return {
        "bug_introducing_commits": [
            {
                "commit": {
                    "authored_date": "2024-01-01T00:00:00Z",
                    "author_email": "human@example.com",
                    "committer_email": "human@example.com",
                }
            }
        ],
        "fix_commits": [],
        "repo_ai_activity": repo_ai_activity,
    }


def test_incomplete_repo_ai_activity_does_not_raise_fn_score() -> None:
    score, reasons = audit_queue.score_fn_candidate(
        _fn_candidate(["incomplete:git_log_timeout", "incomplete:config_scan_failed"]),
        set(),
        set(),
    )

    assert score == 0
    assert reasons == []


def test_completed_repo_ai_activity_still_raises_fn_score() -> None:
    score, reasons = audit_queue.score_fn_candidate(
        _fn_candidate(["git_log:claude_code"]),
        set(),
        set(),
    )

    assert score == 10
    assert reasons == ["repo-ai(claude_code)"]


def test_malformed_repo_ai_activity_does_not_raise_fn_score() -> None:
    candidate = _fn_candidate([])
    candidate["repo_ai_activity"] = None

    score, reasons = audit_queue.score_fn_candidate(candidate, set(), set())

    assert score == 0
    assert reasons == []
