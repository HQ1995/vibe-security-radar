"""Tests for exact-delta causal batch witness helpers."""

from __future__ import annotations

import pytest

from cohort_coolify_exact_delta_causal_batch_witness import (
    _line_evidence,
    _load_case_manifest,
    _message_contains,
    _resolve_unique,
)
from cohort_coolify_preimage_exact_delta_bridge import CommitDelta, DeltaLine


def test_resolve_unique_accepts_prefixes_and_rejects_ambiguity() -> None:
    rows = [
        {"candidate_sha": "a" * 40, "fix_sha": "b" * 40},
        {"candidate_sha": "c" * 40, "fix_sha": "d" * 40},
    ]

    assert _resolve_unique(rows, "a" * 8, "b" * 8) == rows[0]
    with pytest.raises(ValueError, match="resolved to 0"):
        _resolve_unique(rows, "e" * 8, "f" * 8)


def test_message_fragment_checks_are_case_insensitive_and_conjunctive() -> None:
    message = "Fix duplicate notifications\nRemove Redundant UI dispatch"

    assert _message_contains(message, ("DUPLICATE", "redundant ui")) is True
    assert _message_contains(message, ("duplicate", "missing")) is False
    assert _message_contains(message, ()) is True


def test_load_case_manifest_validates_and_builds_cases(tmp_path) -> None:
    manifest = tmp_path / "cases.json"
    manifest.write_text(
        """{
  "cases": [
    {
      "key": "example",
      "candidate_prefix": "aaaaaaaaaaaa",
      "fix_prefix": "bbbbbbbbbbbb",
      "adjudication": "CONFIRMED_DIRECT_AI_FUNCTIONAL_REGRESSION",
      "mechanism_group": "example_regression",
      "claim": "the candidate broke behavior repaired by the fix",
      "fix_message_fragments": ["fix example"],
      "exact_line_fragments": ["brokenCall"],
      "candidate_diff_fragments": ["brokenCall"],
      "fix_diff_fragments": ["safeCall"],
      "causal_role": "COMPOSITIONAL_CONTRIBUTOR",
      "candidate_source_path": "app.php",
      "candidate_source_fragments": ["brokenCall"],
      "candidate_source_forbidden_fragments": ["safeCall"],
      "fix_parent_source_path": "app.php",
      "fix_parent_source_fragments": ["brokenCall"],
      "fix_parent_source_forbidden_fragments": ["safeCall"],
      "model_promotion_required": true
    }
  ]
}\n""",
        encoding="utf-8",
    )

    cases = _load_case_manifest(manifest)

    assert len(cases) == 1
    assert cases[0].key == "example"
    assert cases[0].exact_line_fragments == ("brokenCall",)
    assert cases[0].causal_role == "COMPOSITIONAL_CONTRIBUTOR"
    assert cases[0].candidate_diff_fragments == ("brokenCall",)
    assert cases[0].fix_parent_source_path == "app.php"
    assert cases[0].fix_parent_source_fragments == ("brokenCall",)


def test_load_case_manifest_rejects_incomplete_source_assertion(tmp_path) -> None:
    manifest = tmp_path / "cases.json"
    manifest.write_text(
        """{
  "cases": [
    {
      "key": "example",
      "candidate_prefix": "aaaaaaaaaaaa",
      "fix_prefix": "bbbbbbbbbbbb",
      "adjudication": "CONFIRMED_DIRECT_AI_FUNCTIONAL_REGRESSION",
      "mechanism_group": "example_regression",
      "claim": "the candidate broke behavior repaired by the fix",
      "fix_message_fragments": ["fix example"],
      "fix_parent_source_fragments": ["brokenCall"]
    }
  ]
}\n""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="incomplete fix-parent source assertion"):
        _load_case_manifest(manifest)


def test_line_evidence_preserves_both_exact_reversal_directions() -> None:
    parent = "1" * 40
    candidate = CommitDelta(
        sha="a" * 40,
        parents=(parent,),
        compared_parents=(parent,),
        additions=(DeltaLine(parent, "app.php", "unsafe();"),),
        removals=(DeltaLine(parent, "app.php", "guard();"),),
        binary_paths=(),
        coverage_gaps=(),
    )
    fix = CommitDelta(
        sha="b" * 40,
        parents=("2" * 40,),
        compared_parents=("2" * 40,),
        additions=(DeltaLine("2" * 40, "app.php", "guard();"),),
        removals=(DeltaLine("2" * 40, "app.php", "unsafe();"),),
        binary_paths=(),
        coverage_gaps=(),
    )

    exact, forward, restored = _line_evidence(candidate, fix)

    assert len(exact) == 2
    assert [row["content_excerpt"] for row in forward] == ["unsafe();"]
    assert [row["content_excerpt"] for row in restored] == ["guard();"]
