"""Tests for merge-member causal batch witness helpers."""

from __future__ import annotations

import pytest

from cohort_coolify_merge_member_causal_batch_witness import (
    _contains_all,
    _load_case_manifest,
    _resolve_overlay_row,
    _review_index,
)


def test_contains_all_is_case_insensitive_and_conjunctive() -> None:
    text = "Preserve Restarting and restore Log::warning"

    assert _contains_all(text, ("preserve restarting", "LOG::WARNING")) is True
    assert _contains_all(text, ("preserve", "missing")) is False
    assert _contains_all(text, ()) is True


def test_resolve_overlay_row_uses_candidate_and_member_prefixes() -> None:
    rows = [
        {
            "candidate_sha": "a" * 40,
            "member_fix_sha": "b" * 40,
        },
        {
            "candidate_sha": "c" * 40,
            "member_fix_sha": "d" * 40,
        },
    ]

    assert _resolve_overlay_row(rows, "a" * 8, "b" * 8) == rows[0]
    with pytest.raises(ValueError, match="resolved to 0"):
        _resolve_overlay_row(rows, "e" * 8, "f" * 8)


def test_review_index_requires_completed_lossless_unique_results() -> None:
    result = {
        "result_status": "completed",
        "parse_error": "",
        "review": {"reviews": [{"key": "a__b", "verdict": "PROMOTE"}]},
    }

    assert _review_index([result])["a__b"]["verdict"] == "PROMOTE"
    with pytest.raises(ValueError, match="duplicate semantic review key"):
        _review_index([result, result])


def test_review_index_rejects_parse_errors_and_incomplete_results() -> None:
    with pytest.raises(ValueError, match="not completed"):
        _review_index([{"result_status": "failed"}])
    with pytest.raises(ValueError, match="parse error"):
        _review_index(
            [
                {
                    "result_status": "completed",
                    "parse_error": "truncated",
                    "review": {"reviews": []},
                }
            ]
        )


def test_load_case_manifest_preserves_source_assertions(tmp_path) -> None:
    manifest = tmp_path / "cases.json"
    manifest.write_text(
        """{
  "cases": [
    {
      "key": "example",
      "candidate_prefix": "aaaaaaaaaaaa",
      "fix_prefix": "bbbbbbbbbbbb",
      "adjudication": "CONFIRMED_TEST",
      "mechanism_group": "example",
      "claim": "candidate state is repaired",
      "causal_role": "COMPOSITIONAL_CONTRIBUTOR",
      "fix_message_fragments": ["fix example"],
      "exact_line_fragments": ["unsafe"],
      "candidate_diff_fragments": ["unsafe"],
      "fix_diff_fragments": ["safe"],
      "candidate_source_path": "helper.php",
      "candidate_source_fragments": ["oldHelper"],
      "candidate_source_forbidden_fragments": ["newHelper"],
      "fix_parent_source_path": "helper.php",
      "fix_parent_source_fragments": ["oldHelper"],
      "fix_parent_source_forbidden_fragments": ["newHelper"]
    }
  ]
}\n""",
        encoding="utf-8",
    )

    cases = _load_case_manifest(manifest)

    assert len(cases) == 1
    assert cases[0].candidate_source_path == "helper.php"
    assert cases[0].candidate_source_fragments == ("oldHelper",)
    assert cases[0].candidate_source_forbidden_fragments == ("newHelper",)
    assert cases[0].causal_role == "COMPOSITIONAL_CONTRIBUTOR"
    assert cases[0].fix_parent_source_path == "helper.php"
    assert cases[0].fix_parent_source_fragments == ("oldHelper",)
    assert cases[0].fix_parent_source_forbidden_fragments == ("newHelper",)


def test_load_case_manifest_rejects_incomplete_fix_parent_assertion(tmp_path) -> None:
    manifest = tmp_path / "cases.json"
    manifest.write_text(
        """{
  "cases": [
    {
      "key": "example",
      "candidate_prefix": "aaaaaaaaaaaa",
      "fix_prefix": "bbbbbbbbbbbb",
      "adjudication": "CONFIRMED_TEST",
      "mechanism_group": "example",
      "claim": "candidate state is repaired",
      "fix_message_fragments": ["fix example"],
      "exact_line_fragments": ["unsafe"],
      "candidate_diff_fragments": ["unsafe"],
      "fix_diff_fragments": ["safe"],
      "fix_parent_source_fragments": ["unsafe"]
    }
  ]
}\n""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="incomplete fix-parent source assertion"):
        _load_case_manifest(manifest)
