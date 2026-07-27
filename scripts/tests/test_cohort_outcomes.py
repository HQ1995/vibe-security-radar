"""Tests for the revert and ``Fixes:`` outcome parsers.

Every positive here is a real message shape taken from the corpus, and the
negatives are the things that would quietly inflate the outcome rate if the
parsers were loose — an inflated outcome is worse than a missed one, because it
looks like a finding.
"""

from __future__ import annotations

import pytest

from cohort.outcomes import fixes_trailer_shas, reverted_shas

SHA = "13e5afd3d773c6fc6ca2b89027befaaaa1ea7293"
OTHER = "8c9602e3a145e9596dc1a63c6ed67865814b6633"


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (f'Revert "add the thing"\n\nThis reverts commit {SHA}.', [SHA]),
        (f"Revert it\n\nThis reverts commit {SHA}", [SHA]),
        # git indents the line inside a larger body in some workflows.
        (f"subject\n\n  This reverts commit {SHA}.\n", [SHA]),
        (f"subject\n\nthis reverts commit {SHA.upper()}.", [SHA]),
        # A revert of a revert names both, in order, without duplicates.
        (
            f"subject\n\nThis reverts commit {SHA}.\nThis reverts commit {OTHER}.\n"
            f"This reverts commit {SHA}.",
            [SHA, OTHER],
        ),
    ],
)
def test_revert_messages_are_recognised(message: str, expected: list[str]) -> None:
    assert reverted_shas(message) == expected


@pytest.mark.parametrize(
    "message",
    [
        "fix: an ordinary commit",
        # Prose about reverting is not a revert.
        "We should probably revert commit 13e5afd if this breaks",
        # An abbreviated sha is not what `git revert` writes, and accepting it
        # would make the match ambiguous.
        "This reverts commit 13e5afd.",
        # Quoting someone else's revert in a discussion.
        f"subject\n\n> This reverts commit {SHA}.",
        "",
    ],
)
def test_non_reverts_are_rejected(message: str) -> None:
    assert reverted_shas(message) == []


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (f"fix: thing\n\nFixes: {SHA[:12]} (\"subsys: add the thing\")", [SHA[:12]]),
        (f"fix: thing\n\nFixes: {SHA}", [SHA]),
        (f"fix: thing\n\nfixes: {SHA[:7]}", [SHA[:7]]),
        (
            f"fix: two\n\nFixes: {SHA[:12]} (\"one\")\nFixes: {OTHER[:12]} (\"two\")",
            [SHA[:12], OTHER[:12]],
        ),
    ],
)
def test_fixes_trailers_are_recognised(message: str, expected: list[str]) -> None:
    assert fixes_trailer_shas(message) == expected


@pytest.mark.parametrize(
    "message",
    [
        # GitHub's issue-closing keyword. No colon, and #123 is an issue, not a
        # commit — treating it as one would fabricate outcome links wholesale.
        "fix: thing\n\nFixes #123",
        "fix: thing\n\nfixes #4567",
        "fix: thing\n\nFixes https://github.com/o/r/issues/12",
        # A colon but no sha.
        "fix: thing\n\nFixes: the parser was wrong",
        # Too short to be a usable abbreviation.
        "fix: thing\n\nFixes: abc12",
        "",
    ],
)
def test_non_commit_fixes_references_are_rejected(message: str) -> None:
    assert fixes_trailer_shas(message) == []


def test_issue_reference_and_commit_trailer_can_coexist() -> None:
    """A commit may close an issue and name a culprit; only the sha is a link."""

    message = f"fix: thing\n\nFixes #123\nFixes: {SHA[:12]} (\"subsys: oops\")"
    assert fixes_trailer_shas(message) == [SHA[:12]]
