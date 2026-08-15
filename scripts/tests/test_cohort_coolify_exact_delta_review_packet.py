"""Tests for compact exact-delta semantic review packets."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import cohort_coolify_exact_delta_review_packet as packet
from cohort_coolify_fix_preimage_lineage import LineageEvidenceError
from cohort_coolify_exact_delta_review_packet import (
    _resolve_edges,
    _selected_patch_hunks,
)


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _sha(character: str) -> str:
    return character * 40


def _edge(candidate_sha: str, fix_sha: str) -> dict[str, object]:
    return {
        "candidate_sha": candidate_sha,
        "fix_sha": fix_sha,
        "retained": True,
        "delta_bridge_tier": 0,
        "delta_bridge_class": "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED",
        "delta_bridge_rank": 1,
        "source_priority_class": "P0_DIRECT_RUNTIME_OWNER",
        "source_pair_sha256": _sha("f"),
    }


def test_declared_repository_union_must_match_delta_bridge(tmp_path: Path) -> None:
    first = (tmp_path / "first").resolve()
    second = (tmp_path / "second").resolve()
    summary = {"configuration": {"repositories": [str(first), str(second)]}}

    packet._validate_declared_repositories(summary, [second, first])

    with pytest.raises(ValueError, match="disagree with delta bridge"):
        packet._validate_declared_repositories(summary, [first])
    with pytest.raises(ValueError, match="duplicate --repository"):
        packet._validate_declared_repositories(summary, [first, first])
    with pytest.raises(ValueError, match="legacy delta bridge"):
        packet._validate_declared_repositories({}, [first, second])


def test_commit_assignment_unions_nonnested_repositories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = (tmp_path / "first").resolve()
    second = (tmp_path / "second").resolve()
    candidate = _sha("a")
    fix = _sha("b")

    def assign(
        repositories: list[Path], sha: str, *, timeout: int
    ) -> Path:
        assert repositories == [first, second]
        assert timeout == 17
        if sha == candidate:
            return first
        if sha == fix:
            return second
        raise LineageEvidenceError(f"missing {sha}")

    monkeypatch.setattr(packet, "_repository_for_commit", assign)

    assignments, errors = packet._commit_repository_assignments_fail_open(
        [first, second], [candidate, fix, _sha("c")], timeout=17
    )

    assert assignments == {candidate: first, fix: second}
    assert errors == {_sha("c"): f"missing {_sha('c')}"}


def test_missing_commit_objects_retain_edge_as_explicit_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    candidate = _sha("a")
    fix = _sha("b")
    repositories = [(tmp_path / "first").resolve(), (tmp_path / "second").resolve()]

    def missing(
        repositories: list[Path], sha: str, *, timeout: int
    ) -> Path:
        del repositories, timeout
        raise LineageEvidenceError(f"commit {sha} missing from clone union")

    monkeypatch.setattr(packet, "_repository_for_commit", missing)

    payload = packet.build_packet(
        repositories,
        selected_rows=[_edge(candidate, fix)],
        observed_ai_shas={candidate},
        context_lines=5,
        max_paths=4,
        max_hunks=4,
        max_patch_chars=8_000,
        max_stat_chars=2_000,
        max_focal_lines=8,
        timeout=120,
    )

    assert len(payload["case_results"]) == 1
    case = payload["case_results"][0]
    assert case["candidate_sha"] == candidate
    assert case["fix_sha"] == fix
    assert case["repository_coverage"]["retry_required"] is True
    assert case["checks"]["candidate_object_available"] is False
    assert case["checks"]["fix_object_available"] is False
    assert case["passed"] is False
    assert payload["repository_coverage"]["all_requested_edges_retained"] is True
    assert (
        payload["repository_coverage"][
            "commit_objects_missing_from_all_declared_clones"
        ]
        == 2
    )
    assert payload["summary"]["retry_required_case_count"] == 1


def test_main_freezes_retry_packet_for_missing_clone_objects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    candidate = _sha("a")
    fix = _sha("b")
    repositories = [(tmp_path / "first").resolve(), (tmp_path / "second").resolve()]
    for repository in repositories:
        (repository / ".git").mkdir(parents=True)
    bridge_dir = tmp_path / "bridge"
    ai_dir = tmp_path / "ai"
    bridge_dir.mkdir()
    ai_dir.mkdir()
    pair_text = json.dumps(_edge(candidate, fix), sort_keys=True) + "\n"
    (bridge_dir / "delta_bridge_pairs.jsonl").write_text(
        pair_text, encoding="utf-8"
    )
    (bridge_dir / "summary.json").write_text(
        json.dumps(
            {
                "all_source_owner_pairs_conserved": True,
                "configuration": {
                    "repositories": [str(repository) for repository in repositories]
                },
                "output_artifacts": {
                    "delta_bridge_pairs": {
                        "sha256": hashlib.sha256(pair_text.encode("utf-8")).hexdigest()
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (ai_dir / "commits.jsonl").write_text(
        json.dumps({"sha": candidate}) + "\n", encoding="utf-8"
    )

    def missing(
        repositories: list[Path], sha: str, *, timeout: int
    ) -> Path:
        del repositories, timeout
        raise LineageEvidenceError(f"commit {sha} missing from clone union")

    monkeypatch.setattr(packet, "_repository_for_commit", missing)
    output = tmp_path / "packet.json"

    result = packet.main(
        [
            "--repository",
            str(repositories[0]),
            "--repository",
            str(repositories[1]),
            "--ai-scan-dir",
            str(ai_dir),
            "--delta-bridge-dir",
            str(bridge_dir),
            "--edge",
            f"{candidate[:8]}:{fix[:8]}",
            "--output",
            str(output),
        ]
    )

    frozen = json.loads(output.read_text(encoding="utf-8"))
    assert result == 0
    assert frozen["packet_passed"] is False
    assert len(frozen["case_results"]) == 1
    assert frozen["case_results"][0]["repository_coverage"]["retry_required"]
    assert frozen["configuration"]["repositories"] == [
        str(repository) for repository in repositories
    ]


def test_resolve_edges_preserves_requested_order_and_rejects_duplicates() -> None:
    rows = [
        {"candidate_sha": "a" * 40, "fix_sha": "c" * 40},
        {"candidate_sha": "b" * 40, "fix_sha": "d" * 40},
    ]

    selected = _resolve_edges(
        [f"{'b' * 8}:{'d' * 8}", f"{'a' * 8}:{'c' * 8}"], rows
    )

    assert [row["candidate_sha"] for row in selected] == ["b" * 40, "a" * 40]
    with pytest.raises(ValueError, match="duplicate"):
        _resolve_edges(
            [f"{'a' * 8}:{'c' * 8}", f"{'a' * 8}:{'c' * 8}"], rows
        )


def test_selected_patch_hunks_keeps_only_focal_changed_hunk() -> None:
    patch = """diff --git a/app/a.php b/app/a.php
--- a/app/a.php
+++ b/app/a.php
@@ -1 +1 @@
-unsafe();
+safe();
@@ -10 +10 @@
-old_ui();
+new_ui();
"""

    packet = _selected_patch_hunks(
        patch,
        focal_hashes={_digest("unsafe();")},
        max_hunks=4,
        max_chars=8_000,
    )

    assert packet["total_hunk_count"] == 2
    assert packet["focal_hunk_count"] == 1
    assert "unsafe();" in packet["excerpt"]
    assert "old_ui();" not in packet["excerpt"]
    assert packet["excerpt_truncated"] is False


def test_selected_patch_hunks_records_truncation_without_losing_membership() -> None:
    patch = """diff --git a/app/a.php b/app/a.php
--- a/app/a.php
+++ b/app/a.php
@@ -1 +1 @@
-unsafe();
+safe();
"""

    packet = _selected_patch_hunks(
        patch,
        focal_hashes={_digest("unsafe();")},
        max_hunks=1,
        max_chars=40,
    )

    assert packet["focal_hunk_count"] == 1
    assert packet["excerpt_truncated"] is True
    assert len(packet["excerpt"]) == 40
