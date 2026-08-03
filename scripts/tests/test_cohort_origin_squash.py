"""Tests for recall-safe expansion of landed squashes."""

from __future__ import annotations

from cohort.origin_squash import expand_squash_candidate_pairs


REPOSITORY = "github.com/example/repo"
FIX = "f" * 40
LANDED = "a" * 40
MEMBER_AI = "b" * 40
MEMBER_UNATTRIBUTED = "c" * 40


def _candidate(sha: str, rank: int, signals: list[str]) -> dict[str, object]:
    return {
        "advisory": "CVE-2099-0001",
        "repository_identity": REPOSITORY,
        "sha": sha,
        "fix_sha": FIX,
        "priority_rank": rank,
        "signals": signals,
        "materialization": "structural_signal",
        "observed_ai_unit": True,
        "merge_topology": "squash" if sha == LANDED else "direct",
        "pr_number": 7 if sha == LANDED else None,
        "tools": ["claude_code"],
        "retained": True,
    }


def _relation(origin: str, relation_id: str) -> dict[str, object]:
    return {
        "relation_id": relation_id,
        "repository_identity": REPOSITORY,
        "origin_sha": origin,
        "landed_sha": LANDED,
        "pr_number": 7,
        "relation": "pull_request_member_landed_as_squash",
        "origin_observed_in_cohort": origin == MEMBER_AI,
    }


def test_every_real_member_is_retained_even_without_member_ai_signal() -> None:
    result = expand_squash_candidate_pairs(
        [_candidate(LANDED, 1, ["affected_file_history"])],
        [
            _relation(MEMBER_AI, "relation-ai"),
            _relation(MEMBER_UNATTRIBUTED, "relation-unattributed"),
        ],
        {
            (REPOSITORY, MEMBER_AI): {
                "authored_date": "2099-01-01",
                "observed_ai_unit": True,
                "tools": ["claude_code"],
            },
            (REPOSITORY, MEMBER_UNATTRIBUTED): {
                "authored_date": "2099-01-02",
                "observed_ai_unit": False,
            },
        },
    )

    rows = {row["sha"]: row for row in result["candidates"]}
    assert set(rows) == {LANDED, MEMBER_AI, MEMBER_UNATTRIBUTED}
    assert result["all_parent_candidate_pairs_retained"] is True
    assert result["added_atomic_member_pair_count"] == 2
    assert rows[MEMBER_AI]["tools"] == ["claude_code"]
    assert rows[MEMBER_UNATTRIBUTED]["observed_ai_unit"] is False
    assert rows[MEMBER_UNATTRIBUTED]["ai_exposure_supported"] is True
    assert rows[MEMBER_UNATTRIBUTED]["ai_exposure_basis"] == (
        "ai_attributed_landed_squash"
    )
    assert rows[MEMBER_UNATTRIBUTED]["merge_topology"] == "pull_request_member"
    assert rows[MEMBER_UNATTRIBUTED]["ancestry_certificate"].startswith(
        "pull_request_member_landed_as_squash"
    )


def test_squash_lane_round_robin_does_not_bury_add_check() -> None:
    add_check = "d" * 40
    candidates = [
        _candidate(LANDED, 2, ["ai_ancestry_fallback"]),
        {
            **_candidate(add_check, 1, ["add_context_blame"]),
            "observed_ai_unit": False,
            "tools": [],
        },
    ]
    relations = [
        _relation(f"{number:040x}", f"relation-{number}") for number in range(1, 5)
    ]

    result = expand_squash_candidate_pairs(candidates, relations, {})

    rows = {row["sha"]: row for row in result["candidates"]}
    assert rows[add_check]["priority_rank"] == 2
    assert rows[add_check]["primary_lane"] == "add_context_blame"
    member_ranks = sorted(
        row["priority_rank"]
        for row in result["candidates"]
        if row["merge_topology"] == "pull_request_member"
    )
    assert member_ranks[0] == 1
    assert member_ranks[1] > rows[add_check]["priority_rank"]


def test_multiple_landed_paths_collapse_without_losing_evidence() -> None:
    other_landed = "e" * 40
    candidates = [
        _candidate(LANDED, 1, ["affected_file_history"]),
        {
            **_candidate(other_landed, 2, ["pickaxe_token_history"]),
            "merge_topology": "squash",
            "pr_number": 8,
        },
    ]
    second = {
        **_relation(MEMBER_UNATTRIBUTED, "relation-second"),
        "landed_sha": other_landed,
        "pr_number": 8,
    }

    result = expand_squash_candidate_pairs(
        candidates,
        [_relation(MEMBER_UNATTRIBUTED, "relation-first"), second],
        {},
    )

    member = next(
        row for row in result["candidates"] if row["sha"] == MEMBER_UNATTRIBUTED
    )
    assert result["attempted_atomic_member_pair_count"] == 2
    assert result["added_atomic_member_pair_count"] == 1
    assert result["collapsed_duplicate_member_pair_count"] == 1
    assert len(member["relation_evidence"]) == 2
    assert member["signals"] == ["squash_pr_member_relation"]
    assert set(member["landed_signals"]) == {
        "affected_file_history",
        "pickaxe_token_history",
    }


def test_substantive_fix_file_overlap_beats_empty_member_within_pr() -> None:
    result = expand_squash_candidate_pairs(
        [_candidate(LANDED, 1, ["affected_file_history"])],
        [
            _relation(MEMBER_AI, "relation-substantive"),
            _relation(MEMBER_UNATTRIBUTED, "relation-empty"),
        ],
        {
            (REPOSITORY, MEMBER_AI): {
                "changed_files": ["src/server.py"],
                "code_files_changed": ["src/server.py"],
                "additions": 30,
                "deletions": 2,
                "empty_commit": False,
                "observed_ai_unit": True,
            },
            (REPOSITORY, MEMBER_UNATTRIBUTED): {
                "changed_files": [],
                "code_files_changed": [],
                "additions": 0,
                "deletions": 0,
                "empty_commit": True,
                "observed_ai_unit": False,
            },
        },
        {(REPOSITORY, FIX): ["src/server.py"]},
    )

    rows = {row["sha"]: row for row in result["candidates"]}
    assert rows[MEMBER_AI]["priority_rank"] < rows[MEMBER_UNATTRIBUTED]["priority_rank"]
    assert rows[MEMBER_AI]["fix_file_overlap"] == ["src/server.py"]
    assert rows[MEMBER_UNATTRIBUTED]["empty_commit"] is True


def test_internal_fix_context_blame_beats_broad_file_overlap() -> None:
    result = expand_squash_candidate_pairs(
        [_candidate(LANDED, 1, ["affected_file_history"])],
        [
            _relation(MEMBER_AI, "relation-broad"),
            _relation(MEMBER_UNATTRIBUTED, "relation-internal"),
        ],
        {
            (REPOSITORY, MEMBER_AI): {
                "changed_files": ["src/a.py", "src/b.py", "src/c.py"],
                "code_files_changed": ["src/a.py", "src/b.py", "src/c.py"],
                "additions": 500,
                "deletions": 400,
            },
            (REPOSITORY, MEMBER_UNATTRIBUTED): {
                "changed_files": ["src/a.py"],
                "code_files_changed": ["src/a.py"],
                "additions": 5,
                "deletions": 1,
            },
        },
        {(REPOSITORY, FIX): ["src/a.py", "src/b.py", "src/c.py"]},
        {
            (REPOSITORY, LANDED, FIX, MEMBER_UNATTRIBUTED): [
                {
                    "path": "src/a.py",
                    "fix_sha": FIX,
                    "fix_parent_line": 10,
                    "pull_head_line": 8,
                    "content_sha256": "0" * 64,
                }
            ]
        },
    )

    rows = {row["sha"]: row for row in result["candidates"]}
    assert rows[MEMBER_UNATTRIBUTED]["priority_rank"] < rows[MEMBER_AI]["priority_rank"]
    assert rows[MEMBER_UNATTRIBUTED]["squash_internal_blame_line_count"] == 1
    assert "squash_internal_fix_context_blame" in rows[MEMBER_UNATTRIBUTED]["signals"]
