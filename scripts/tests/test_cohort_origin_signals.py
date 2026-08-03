"""Tests for conservative origin-signal parsing and union rows."""

from __future__ import annotations

import re

import pytest

from cohort.origin_signals import (
    OriginSignalContractError,
    candidate_signal_row,
    deleted_line_ranges,
    history_search_tokens,
    history_token_regex_chunks,
    parse_origin_hunks,
    prioritize_candidate_rows,
)


def test_deleted_line_ranges_use_parent_coordinates() -> None:
    patch = """\
diff --git a/src/a.py b/src/a.py
--- a/src/a.py
+++ b/src/a.py
@@ -10,3 +10,2 @@
-old
+new
@@ -30,0 +29,2 @@
+added
"""

    assert deleted_line_ranges(patch) == {"src/a.py": [(10, 12)]}


def test_candidate_signal_row_keeps_file_history_only_candidate() -> None:
    row = candidate_signal_row(
        sha="1" * 40,
        in_copy_aware_szz=False,
        in_file_local_szz=False,
        in_file_history=True,
        observed_ai_unit=False,
    )

    assert row["signals"] == ["affected_file_history"]
    assert row["retained"] is True


def test_candidate_signal_row_keeps_szz_only_candidate() -> None:
    row = candidate_signal_row(
        sha="1" * 40,
        in_copy_aware_szz=True,
        in_file_local_szz=False,
        in_file_history=False,
        observed_ai_unit=True,
    )

    assert row["signals"] == ["szz_copy_aware"]
    assert row["retained"] is True


def test_candidate_signal_row_rejects_row_without_any_signal() -> None:
    with pytest.raises(OriginSignalContractError, match="at least one signal"):
        candidate_signal_row(
            sha="1" * 40,
            in_copy_aware_szz=False,
            in_file_local_szz=False,
            in_file_history=False,
            observed_ai_unit=True,
        )


def test_add_only_guard_is_a_first_class_origin_hunk() -> None:
    patch = """\
diff --git a/src/auth.py b/src/auth.py
--- a/src/auth.py
+++ b/src/auth.py
@@ -20,0 +21,3 @@
+if not request.user.can_write(project):
+    raise PermissionError("write denied")
+mutate(project)
"""

    hunks = parse_origin_hunks(patch)

    assert len(hunks) == 1
    assert hunks[0].parent_path == "src/auth.py"
    assert hunks[0].old_count == 0
    assert hunks[0].insertion_points == (20,)
    assert hunks[0].is_guard_like is True


def test_replacement_guard_keeps_deleted_and_add_check_coordinates() -> None:
    patch = """\
diff --git a/src/api.py b/src/api.py
--- a/src/api.py
+++ b/src/api.py
@@ -40,2 +40,4 @@
-return mutate(item)
-
+if not authorized(user, item):
+    raise Forbidden()
+return mutate(item)
+
"""

    hunk = parse_origin_hunks(patch)[0]

    assert hunk.deleted_span == (40, 41)
    assert hunk.insertion_points == (40, 41)
    assert hunk.is_guard_like is True


def test_history_search_tokens_keep_guarded_surface_identifiers() -> None:
    tokens = history_search_tokens(
        "if not request.user.can_write(project):\n"
        "    raise PermissionError('write denied')\n"
        "return mutate_project(project)"
    )

    assert "can_write" in tokens
    assert "mutate_project" in tokens
    assert "request" not in tokens
    assert "return" not in tokens


def test_pickaxe_regex_chunks_keep_every_extracted_token() -> None:
    tokens = ["authorize_project", "mutate_project", "PermissionError", "can_write"]

    chunks = history_token_regex_chunks(tokens, max_pattern_chars=36)

    assert len(chunks) > 1
    combined = "\n".join(chunks)
    assert all(re.escape(token) in combined for token in tokens)


def test_add_check_lane_cannot_be_crowded_out_by_szz() -> None:
    rows = [
        candidate_signal_row(
            sha=f"{index:040x}",
            in_copy_aware_szz=True,
            in_file_local_szz=False,
            in_file_history=True,
            observed_ai_unit=True,
        )
        for index in range(1, 21)
    ]
    rows.append(
        candidate_signal_row(
            sha="f" * 40,
            in_copy_aware_szz=False,
            in_file_local_szz=False,
            in_file_history=False,
            in_add_context_blame=True,
            observed_ai_unit=True,
        )
    )

    ranked = prioritize_candidate_rows(rows)
    add_check = next(row for row in ranked if row["sha"] == "f" * 40)

    assert add_check["priority_class"] == "P0_OBSERVED_AI_CAUSAL_SIGNAL"
    assert add_check["priority_rank"] <= 2
    assert add_check["primary_lane"] == "add_context_blame"


def test_ai_attribution_cannot_crowd_out_unknown_add_check() -> None:
    rows = [
        {
            "sha": f"{index:040x}",
            "signals": ["squash_pr_member_relation"],
            "observed_ai_unit": True,
            "retained": True,
        }
        for index in range(1, 21)
    ]
    rows.append(
        candidate_signal_row(
            sha="f" * 40,
            in_copy_aware_szz=False,
            in_file_local_szz=False,
            in_file_history=False,
            in_add_context_blame=True,
            observed_ai_unit=False,
        )
    )

    ranked = prioritize_candidate_rows(rows)
    add_check = next(row for row in ranked if row["sha"] == "f" * 40)

    assert len(ranked) == len(rows)
    assert add_check["priority_class"] == "P1_CAUSAL_SIGNAL"
    assert add_check["priority_rank"] == 2
    assert add_check["within_priority_class_rank"] == 1


def test_file_history_only_follows_every_direct_signal_lane() -> None:
    rows = [
        candidate_signal_row(
            sha="a" * 40,
            in_copy_aware_szz=False,
            in_file_local_szz=False,
            in_file_history=True,
            observed_ai_unit=False,
        ),
        candidate_signal_row(
            sha="b" * 40,
            in_copy_aware_szz=False,
            in_file_local_szz=False,
            in_file_history=False,
            in_cross_file_security_bridge=True,
            observed_ai_unit=False,
        ),
    ]

    ranked = prioritize_candidate_rows(rows)

    assert [row["sha"] for row in ranked] == ["b" * 40, "a" * 40]
    assert ranked[0]["priority_class"] == "P1_CAUSAL_SIGNAL"
    assert ranked[1]["priority_class"] == "P3_AFFECTED_FILE_HISTORY"
