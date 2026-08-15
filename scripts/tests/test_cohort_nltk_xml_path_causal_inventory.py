"""Contracts for the NLTK XML-path causal inventory."""

from __future__ import annotations

from pathlib import Path

import pytest

import cohort_nltk_xml_path_causal_inventory as inventory


def test_weak_metadata_lane_catches_copilot_feedback_candidate() -> None:
    rows = inventory._weak_metadata_matches(
        {
            "author_name": "Human",
            "author_email": "human@example.com",
            "message": "copilot feedback",
        }
    )

    assert rows == [{"candidate_signal": "tool_name_token", "matched_text": "copilot"}]


def test_weak_metadata_lane_is_candidate_only() -> None:
    assert all("source" not in name for name, _pattern in inventory.WEAK_AI_PATTERNS)


def test_signal_changes_only_records_changed_semantic_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diff = """\
diff --git a/nltk/downloader.py b/nltk/downloader.py
--- a/nltk/downloader.py
+++ b/nltk/downloader.py
@@ -1 +1,2 @@
-filepath = os.path.join(download_dir, info.filename)
+filepath = pathsec.open(download_dir, info.filename)
+guard = os.path.realpath(filepath)
 context = Package.fromxml(node)
"""
    monkeypatch.setattr(inventory, "_git", lambda *_args, **_kwargs: diff)

    rows = inventory._signal_changes(Path("repo"), "a" * 40)

    assert [row["sign"] for row in rows] == ["removed", "added", "added"]
    assert "path_composition" in rows[0]["categories"]
    assert "filesystem_write_sink" in rows[1]["categories"]
    assert "path_containment_guard" in rows[2]["categories"]
    assert all("Package.fromxml" not in row["line"] for row in rows)


def test_priority_keeps_ancestry_fallback_visible() -> None:
    assert (
        inventory._priority(
            ancestor_of_affected=True,
            code_path_hit=False,
            context_path_hit=False,
            semantic_hit=False,
        )
        == "P3_AI_ANCESTRY_FALLBACK"
    )
    assert (
        inventory._priority(
            ancestor_of_affected=False,
            code_path_hit=True,
            context_path_hit=False,
            semantic_hit=True,
        )
        == "P4_NON_ANCESTOR_RETAINED"
    )


def test_known_full_ref_candidates_include_new_strict_and_weak_lanes() -> None:
    assert "3bc1214f7db0bc0d261196fac42c4dca74ce6d63" in (
        inventory.KNOWN_STRICT_AI_AFFECTED_CODE_ANCESTORS
    )
    assert inventory.KNOWN_WEAK_ONLY_AFFECTED_CODE_ANCESTORS == {
        "394eef88b0d5fd2d8571622f43cf7c3205b59355",
        "90712b608d9a8a8711016376223f9ba20bf5634d",
        "c88d8469d46b8743638dce75d07f67878bada9d1",
    }


def test_sha_inventory_digest_is_order_independent() -> None:
    assert inventory._sha_inventory_digest({"a" * 40, "b" * 40}) == (
        inventory._sha_inventory_digest({"b" * 40, "a" * 40})
    )


def test_origin_transition_requires_source_composition_and_sink() -> None:
    assert inventory.ORIGIN_REQUIRED_SNIPPETS == (
        "self.filename = os.path.join(subdir, id+ext)",
        "self.__dict__.update(kw)",
        "filepath = os.path.join(download_dir, info.filename)",
        "outfile = open(filepath, 'wb')",
    )


def test_context_paths_are_additive_not_code_paths() -> None:
    assert "nltk/test/unit/test_downloader.py" in inventory.CONTEXT_PATHS
    assert not set(inventory.CONTEXT_PATHS) & set(inventory.CODE_PATHS)
