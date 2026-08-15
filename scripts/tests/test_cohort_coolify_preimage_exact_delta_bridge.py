"""Tests for the lossless Coolify preimage exact-delta bridge."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cohort_coolify_preimage_exact_delta_bridge import (
    CommitDelta,
    DeltaBridgeError,
    DeltaLine,
    _cached_delta_matches,
    _cached_line_index,
    _delta_matches,
    _parse_unified_patch,
    _validate_declared_repositories,
    build_delta_bridge,
)


def _sha(character: str) -> str:
    return character * 40


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _delta(
    sha: str,
    *,
    additions: list[tuple[str, str]] | None = None,
    removals: list[tuple[str, str]] | None = None,
    parent: str | None = None,
    gap: str | None = None,
) -> CommitDelta:
    parent_sha = parent or _sha("f")
    return CommitDelta(
        sha=sha,
        parents=(parent_sha,),
        compared_parents=(parent_sha,),
        additions=tuple(
            DeltaLine(parent_sha, path, content)
            for path, content in additions or []
        ),
        removals=tuple(
            DeltaLine(parent_sha, path, content)
            for path, content in removals or []
        ),
        coverage_gaps=((gap,) if gap else ()),
    )


def _source_pair(
    candidate: str,
    fix: str,
    *,
    line: str,
    path: str = "app/Service.php",
    line_kind: str = "direct_preimage",
    source_rank: int = 1,
) -> dict[str, object]:
    return {
        "candidate_sha": candidate,
        "candidate_subject": "AI change",
        "candidate_authored_at": "2026-01-01T00:00:00Z",
        "fix_sha": fix,
        "fix_subject": "fix: restore guard",
        "fix_authored_at": "2026-01-02T00:00:00Z",
        "fix_review_lane": "added_check_or_guard",
        "priority_tier": 0 if line_kind == "direct_preimage" else 1,
        "priority_class": "source-priority",
        "review_priority_rank": source_rank,
        "review_priority_score": 1_000,
        "ledger_edge_status": "NEW_SOURCE_OWNER_EDGE",
        "matched_line_evidence": [
            {
                "path": path,
                "line_kind": line_kind,
                "content_sha256": _digest(line),
                "guard_like_hunk": True,
            }
        ],
        "retained": True,
    }


def test_declared_repository_union_must_match_preimage_overlay(tmp_path: Path) -> None:
    first = (tmp_path / "first").resolve()
    second = (tmp_path / "second").resolve()
    summary = {
        "configuration": {"repositories": [str(first), str(second)]}
    }

    _validate_declared_repositories(summary, [second, first])

    with pytest.raises(DeltaBridgeError, match="disagree with preimage overlay"):
        _validate_declared_repositories(summary, [first])
    with pytest.raises(DeltaBridgeError, match="duplicate --repository"):
        _validate_declared_repositories(summary, [first, first])


def test_parse_unified_patch_distinguishes_headers_from_hunk_content() -> None:
    parent = _sha("a")
    patch = """diff --git a/app/a.php b/app/a.php
--- a/app/a.php
+++ b/app/a.php
@@ -1,2 +1,2 @@
-if ($unsafe) {
---- literal content
+if ($safe) {
++++ literal content
"""

    additions, removals, binary = _parse_unified_patch(patch, parent_sha=parent)

    assert [(line.path, line.content) for line in additions] == [
        ("app/a.php", "if ($safe) {"),
        ("app/a.php", "+++ literal content"),
    ]
    assert [(line.path, line.content) for line in removals] == [
        ("app/a.php", "if ($unsafe) {"),
        ("app/a.php", "--- literal content"),
    ]
    assert binary == ()


def test_cached_delta_matcher_preserves_reference_evidence() -> None:
    parent = _sha("1")
    left = (
        DeltaLine(parent, "app/a.php", "unsafe();"),
        DeltaLine(parent, "app/b.php", "if  ($x)"),
        DeltaLine(parent, "app/c.php", "moved();"),
        DeltaLine(parent, "app/a.php", "unsafe();"),
    )
    right = (
        DeltaLine(parent, "app/a.php", "unsafe();"),
        DeltaLine(parent, "app/b.php", "if ($x)"),
        DeltaLine(parent, "app/d.php", "moved();"),
    )

    reference = _delta_matches(left, right, direction="candidate_added_fix_removed")
    cached = _cached_delta_matches(
        _cached_line_index(left),
        _cached_line_index(right),
        direction="candidate_added_fix_removed",
    )

    assert cached == reference


def test_bridge_prioritizes_bidirectional_exact_reversal_without_dropping_edges() -> None:
    candidate_a = _sha("a")
    candidate_b = _sha("b")
    candidate_c = _sha("c")
    fix_d = _sha("d")
    fix_e = _sha("e")
    fix_parent_d = _sha("1")
    fix_parent_e = _sha("2")
    unsafe = "run($userInput);"
    guard = "if (! authorized($team)) { abort(403); }"
    method = "public function deploy(): void"
    source_pairs = [
        _source_pair(candidate_a, fix_d, line=unsafe, source_rank=2),
        _source_pair(
            candidate_b,
            fix_e,
            line=method,
            line_kind="method_signature",
            source_rank=1,
        ),
        _source_pair(candidate_c, fix_e, line="unchanged();", source_rank=3),
    ]
    candidate_deltas = {
        candidate_a: _delta(
            candidate_a,
            additions=[("app/Service.php", unsafe)],
            removals=[("app/Service.php", guard)],
        ),
        candidate_b: _delta(
            candidate_b,
            additions=[("app/Service.php", method)],
        ),
        candidate_c: _delta(candidate_c, additions=[]),
    }
    fix_deltas = {
        fix_d: _delta(
            fix_d,
            additions=[("app/Service.php", guard)],
            removals=[("app/Service.php", unsafe)],
            parent=fix_parent_d,
        ),
        fix_e: _delta(
            fix_e,
            additions=[("app/Service.php", "if ($invalid) { abort(422); }")],
            parent=fix_parent_e,
            gap="binary path retained for retry",
        ),
    }
    artifacts = build_delta_bridge(
        preimage_summary={
            "repository_identity": "github.com/coollabsio/coolify",
            "strict_source_owner_pair_count": 3,
            "all_source_pairs_conserved": True,
            "hard_filter_count": 0,
            "source_direct_ancestry_pair_count": 100,
            "unprocessed_direct_ancestry_pair_count": 97,
            "source_topology_fallback_root_count": 5,
        },
        source_pairs=source_pairs,
        root_evidence=[
            {"fix_sha": fix_d, "parent_sha": fix_parent_d},
            {"fix_sha": fix_e, "parent_sha": fix_parent_e},
        ],
        ledger={
            "edge_ledger": [
                {
                    "candidate_sha": candidate_c,
                    "fix_sha": _sha("9"),
                    "status": "CONFIRMED_TRUE_POSITIVE",
                }
            ]
        },
        candidate_deltas=candidate_deltas,
        fix_deltas=fix_deltas,
        split_id="test-v1",
    )

    summary = artifacts["summary"]
    pairs = artifacts["pairs"]
    assert summary["source_owner_pair_count"] == 3
    assert summary["retained_delta_bridge_pair_count"] == 3
    assert summary["all_source_owner_pairs_conserved"] is True
    assert summary["hard_filter_count"] == 0
    assert summary["coverage_gap_commit_count"] == 1
    assert pairs[0]["candidate_sha"] == candidate_a
    assert pairs[0]["delta_bridge_class"] == "B0_BIDIRECTIONAL_EXACT_REVERSAL"
    assert pairs[0]["meaningful_exact_same_path_delta_count"] == 2
    by_candidate = {row["candidate_sha"]: row for row in pairs}
    assert (
        by_candidate[candidate_b]["delta_bridge_class"]
        == "B3_EXACT_GUARD_METHOD_INTRODUCTION"
    )
    assert (
        by_candidate[candidate_c]["delta_bridge_class"]
        == "B5_SOURCE_OWNER_ONLY_RETAINED"
    )
    assert all(row["retained"] is True for row in pairs)
    assert len(artifacts["review_queue"]) == 3
    assert len(artifacts["candidate_frontier"]) == 3


def test_bridge_keeps_generated_exact_match_but_downranks_it() -> None:
    candidate_a = _sha("a")
    candidate_b = _sha("b")
    fix_c = _sha("c")
    fix_d = _sha("d")
    parent_c = _sha("1")
    parent_d = _sha("2")
    generated_line = '"unsafe": true,'
    runtime_line = "run_unchecked($input);"
    pairs = [
        _source_pair(
            candidate_a,
            fix_c,
            line=generated_line,
            path="openapi.json",
        ),
        _source_pair(candidate_b, fix_d, line=runtime_line, source_rank=2),
    ]
    artifacts = build_delta_bridge(
        preimage_summary={
            "strict_source_owner_pair_count": 2,
            "all_source_pairs_conserved": True,
            "hard_filter_count": 0,
        },
        source_pairs=pairs,
        root_evidence=[
            {"fix_sha": fix_c, "parent_sha": parent_c},
            {"fix_sha": fix_d, "parent_sha": parent_d},
        ],
        ledger={"edge_ledger": []},
        candidate_deltas={
            candidate_a: _delta(
                candidate_a, additions=[("openapi.json", generated_line)]
            ),
            candidate_b: _delta(
                candidate_b, additions=[("app/Service.php", runtime_line)]
            ),
        },
        fix_deltas={
            fix_c: _delta(
                fix_c,
                removals=[("openapi.json", generated_line)],
                parent=parent_c,
            ),
            fix_d: _delta(
                fix_d,
                removals=[("app/Service.php", runtime_line)],
                parent=parent_d,
            ),
        },
        split_id="test-generated-v1",
    )

    by_candidate = {row["candidate_sha"]: row for row in artifacts["pairs"]}
    assert by_candidate[candidate_a]["generated_or_machine_artifact_only"] is True
    assert by_candidate[candidate_b]["generated_or_machine_artifact_only"] is False
    assert (
        by_candidate[candidate_b]["delta_bridge_score"]
        > by_candidate[candidate_a]["delta_bridge_score"]
    )
    assert artifacts["summary"]["generated_or_machine_artifact_only_pair_count"] == 1
