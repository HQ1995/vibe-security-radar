"""Tests for strict batched origin response conservation."""

from __future__ import annotations

import pytest

from cohort.origin_batch import (
    OriginBatchContractError,
    parse_batch_response,
    parse_edge_batch_response,
)
import cohort_origin_ai_batch_route as batch_route
from cohort_origin_ai_batch_route import _select_packets


def test_batch_response_requires_every_alias_exactly_once() -> None:
    parsed = parse_batch_response(
        '{"results":['
        '{"id":"C01","causality":"possible","reason":"shared policy path"},'
        '{"id":"C02","causality":"unlikely","reason":"unrelated docs"}'
        "]}",
        ["C01", "C02"],
    )

    assert [row["id"] for row in parsed] == ["C01", "C02"]
    assert parsed[0]["causality"] == "possible"


@pytest.mark.parametrize(
    "response",
    [
        '{"results":[{"id":"C01","causality":"possible","reason":"x"}]}',
        '{"results":['
        '{"id":"C01","causality":"possible","reason":"x"},'
        '{"id":"C01","causality":"unlikely","reason":"y"}'
        "]}",
        '{"results":['
        '{"id":"C01","causality":"certain","reason":"x"},'
        '{"id":"C02","causality":"unlikely","reason":"y"}'
        "]}",
    ],
)
def test_missing_duplicate_or_invalid_result_blocks_whole_batch(response: str) -> None:
    with pytest.raises(OriginBatchContractError):
        parse_batch_response(response, ["C01", "C02"])


def test_edge_batch_response_preserves_exact_candidate_fix_subset() -> None:
    parsed = parse_edge_batch_response(
        '{"results":['
        '{"id":"C01","causality":"possible","related_fixes":["F02"],'
        '"reason":"shared policy path"},'
        '{"id":"C02","causality":"unlikely","related_fixes":[],'
        '"reason":"unrelated docs"}'
        "]}",
        {"C01": ["F01", "F02"], "C02": ["F02"]},
    )

    assert parsed[0]["related_fixes"] == ["F02"]
    assert parsed[1]["related_fixes"] == []


@pytest.mark.parametrize(
    "response,match",
    [
        (
            '{"results":[{"id":"C01","causality":"likely",'
            '"related_fixes":[],"reason":"missing edge"}]}',
            "lacks a related fix",
        ),
        (
            '{"results":[{"id":"C01","causality":"unlikely",'
            '"related_fixes":["F01"],"reason":"contradictory edge"}]}',
            "unlikely candidate names a related fix",
        ),
        (
            '{"results":[{"id":"C01","causality":"possible",'
            '"related_fixes":["F99"],"reason":"unknown edge"}]}',
            "unknown related fix",
        ),
    ],
)
def test_edge_batch_response_rejects_ambiguous_edge_claims(
    response: str, match: str
) -> None:
    with pytest.raises(OriginBatchContractError, match=match):
        parse_edge_batch_response(response, {"C01": ["F01"]})


def test_packet_budget_is_applied_per_advisory_group() -> None:
    packets = [
        {
            "sequence": 1,
            "advisory": "A",
            "repository_identity": "repo/a",
        },
        {
            "sequence": 2,
            "advisory": "A",
            "repository_identity": "repo/a",
        },
        {
            "sequence": 3,
            "advisory": "B",
            "repository_identity": "repo/b",
        },
        {
            "sequence": 4,
            "advisory": "B",
            "repository_identity": "repo/b",
        },
    ]

    selected = _select_packets(packets, packets_per_group=1, max_packets=0)

    assert [row["sequence"] for row in selected] == [1, 3]


def test_candidate_sha_filter_keeps_only_requested_units_and_packets() -> None:
    sha_a = "a" * 40
    sha_b = "b" * 40
    units = [
        {"unit_id": "U1", "candidate_sha": sha_a},
        {"unit_id": "U2", "candidate_sha": sha_b},
    ]
    packets = [
        {"sequence": 1, "candidate_unit_ids": ["U1", "U2"], "candidate_count": 2},
        {"sequence": 2, "candidate_unit_ids": ["U2"], "candidate_count": 1},
    ]

    filtered = batch_route._filter_packets_by_candidate_sha(packets, units, [sha_a])

    assert filtered == [
        {"sequence": 1, "candidate_unit_ids": ["U1"], "candidate_count": 1}
    ]
    assert packets[0]["candidate_unit_ids"] == ["U1", "U2"]


def test_candidate_sha_filter_fails_closed_when_target_is_missing() -> None:
    with pytest.raises(SystemExit, match="not present"):
        batch_route._filter_packets_by_candidate_sha(
            [{"sequence": 1, "candidate_unit_ids": ["U1"]}],
            [{"unit_id": "U1", "candidate_sha": "a" * 40}],
            ["b" * 40],
        )


def test_candidate_signal_filter_keeps_only_units_with_every_signal() -> None:
    units = [
        {"unit_id": "U1", "signals": ["squash", "internal"]},
        {"unit_id": "U2", "signals": ["squash"]},
    ]
    packets = [
        {"sequence": 1, "candidate_unit_ids": ["U1", "U2"], "candidate_count": 2}
    ]

    filtered = batch_route._filter_packets_by_candidate_signal(
        packets, units, ["squash", "internal"]
    )

    assert filtered == [
        {"sequence": 1, "candidate_unit_ids": ["U1"], "candidate_count": 1}
    ]


def test_priority_overlap_paths_prefers_production_then_new_files() -> None:
    ordered = batch_route._priority_overlap_paths(
        [
            "docs/usage.md",
            "src/old.py",
            "tests/test_new.py",
            "src/new.py",
        ],
        added_paths={"tests/test_new.py", "src/new.py"},
    )

    assert ordered == [
        "src/new.py",
        "src/old.py",
        "tests/test_new.py",
        "docs/usage.md",
    ]


def test_isolate_candidate_packets_conserves_units_and_scopes_fixes() -> None:
    units = [
        {
            "unit_id": "U1",
            "candidate_sha": "a" * 40,
            "fix_edges": [{"fix_sha": "1" * 40}],
        },
        {
            "unit_id": "U2",
            "candidate_sha": "b" * 40,
            "fix_edges": [
                {"fix_sha": "1" * 40},
                {"fix_sha": "2" * 40},
            ],
        },
    ]
    packets = [
        {
            "packet_id": "P1",
            "sequence": 7,
            "candidate_unit_ids": ["U1", "U2"],
            "candidate_shas": ["a" * 40, "b" * 40],
            "candidate_count": 2,
            "fix_shas": ["1" * 40, "2" * 40],
            "fix_edge_count": 3,
        }
    ]

    isolated = batch_route._isolate_candidate_packets(packets, units)

    assert [row["candidate_unit_ids"] for row in isolated] == [["U1"], ["U2"]]
    assert [row["sequence"] for row in isolated] == [1, 2]
    assert [row["source_packet_id"] for row in isolated] == ["P1", "P1"]
    assert isolated[0]["fix_shas"] == ["1" * 40]
    assert isolated[1]["fix_shas"] == ["1" * 40, "2" * 40]
    assert [row["fix_edge_count"] for row in isolated] == [1, 2]


def test_prepare_prompts_prioritizes_shared_fix_path_before_global_diff(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    candidate_sha = "a" * 40
    fix_sha = "f" * 40
    priority_calls: dict[str, dict[str, object]] = {}

    def fake_commit_view(_repo, sha, _limit, **kwargs):
        priority_calls[sha] = kwargs
        label = str(kwargs.get("priority_label") or "global")
        return f"subject-{sha[0]}", "2026-01-01", f"# {label}\n+guard"

    def fake_run_git(_repo, arguments, **_kwargs):
        if "diff-tree" in arguments:
            return "src/security.py\n"
        return ""

    monkeypatch.setattr(batch_route, "_commit_view", fake_commit_view)
    monkeypatch.setattr(batch_route, "_run_git", fake_run_git)

    units = [
        {
            "unit_id": "U1",
            "candidate_sha": candidate_sha,
            "best_priority_rank": 1,
            "signals": ["add_context"],
            "fix_edges": [
                {
                    "fix_sha": fix_sha,
                    "landed_signals": [],
                    "squash_internal_blame_line_count": 0,
                    "squash_internal_blame_paths": [],
                }
            ],
            "additions": 1,
            "deletions": 0,
            "changed_files": ["src/security.py"],
            "empty_commit": False,
        }
    ]
    fixes = [
        {
            "advisory": "GHSA-test",
            "repository_identity": "github.com/acme/repo",
            "fix_sha": fix_sha,
            "repository_path": str(tmp_path),
            "status": "RESOLVED",
        }
    ]
    packets = [
        {
            "packet_id": "P1",
            "sequence": 1,
            "advisory": "GHSA-test",
            "repository_identity": "github.com/acme/repo",
            "candidate_unit_ids": ["U1"],
            "fix_shas": [fix_sha],
        }
    ]

    _items, prompts = batch_route._prepare_prompts(
        packets,
        units,
        fixes,
        candidate_diff_chars=500,
        fix_diff_chars=500,
    )

    assert priority_calls[fix_sha]["priority_paths"] == ["src/security.py"]
    assert (
        priority_calls[fix_sha]["priority_label"]
        == "Candidate/fix shared-path fix evidence"
    )
    assert "# Candidate/fix shared-path fix evidence\n+guard" in prompts[0][
        "user_prompt"
    ]


def test_selected_candidate_lineage_exposes_parent_child_order() -> None:
    parent = "a" * 40
    child = "b" * 40
    unrelated_parent = "c" * 40
    aliases = {parent: "C01", child: "C02"}
    parent_shas = {parent: [unrelated_parent], child: [parent]}

    assert batch_route._selected_candidate_lineage(
        parent,
        parent_shas=parent_shas,
        alias_by_sha=aliases,
    ) == (
        f"git-parents={unrelated_parent}; direct-parent-in-packet=none; "
        f"direct-children-in-packet=C02@{child}"
    )
    assert batch_route._selected_candidate_lineage(
        child,
        parent_shas=parent_shas,
        alias_by_sha=aliases,
    ) == (
        f"git-parents={parent}; direct-parent-in-packet=C01@{parent}; "
        "direct-children-in-packet=none"
    )


def test_causal_delta_prompt_requires_an_independent_runtime_delta() -> None:
    prompt = batch_route._prompt(
        packet={"repository_identity": "repo/example", "advisory": "CVE-X"},
        aliases=[{"unit_id": "U1", "id": "C01"}],
        fix_views=[
            {"sha": "f" * 40, "date": "later", "subject": "fix", "diff": "+guard"}
        ],
        candidate_views=[
            {
                "unit_id": "U1",
                "sha": "a" * 40,
                "fix_shas": ["f" * 40],
                "rank": 1,
                "signals": ["ai_ancestry_fallback"],
                "carrier_signals": [],
                "provenance": "mainline",
                "lineage": "git-parents=parent",
                "change_stats": "+1/-0",
                "date": "earlier",
                "subject": "candidate",
                "diff": "+new runtime path",
            }
        ],
        causal_delta_gate=True,
    )

    assert "parent-to-candidate delta" in prompt
    assert "new runtime-reachable path" in prompt
    assert "Mere ancestry or unchanged perpetuation is unlikely" in prompt


def test_contributor_recall_prompt_includes_activation_and_sink_preservation() -> None:
    prompt = batch_route._prompt(
        packet={"repository_identity": "repo/example", "advisory": "CVE-X"},
        aliases=[{"unit_id": "U1", "id": "C01"}],
        fix_views=[
            {"sha": "f" * 40, "date": "later", "subject": "fix", "diff": "+guard"}
        ],
        candidate_views=[
            {
                "unit_id": "U1",
                "sha": "a" * 40,
                "fix_shas": ["f" * 40],
                "rank": 1,
                "signals": ["function_history"],
                "carrier_signals": [],
                "provenance": "mainline",
                "lineage": "git-parents=parent",
                "change_stats": "+1/-0",
                "date": "earlier",
                "subject": "candidate",
                "diff": "+new caller into existing sink",
            }
        ],
        contributor_recall_gate=True,
    )

    assert "Count activation" in prompt
    assert "material sink/dataflow preservation" in prompt
    assert "independent root-cause introduction is not required" in prompt


def test_contributor_recall_gate_is_mutually_exclusive_with_causal_delta() -> None:
    common = [
        "--generated-dir",
        "generated",
        "--packet-dir",
        "packets",
        "--model",
        "model",
        "--reasoning-effort",
        "max",
        "--output-dir",
        "output",
    ]

    args = batch_route._parse_args([*common, "--contributor-recall-gate"])
    assert args.contributor_recall_gate is True
    assert args.causal_delta_gate is False

    with pytest.raises(SystemExit):
        batch_route._parse_args(
            [*common, "--causal-delta-gate", "--contributor-recall-gate"]
        )


def test_label_neutral_input_rejects_soft_known_positive_signal() -> None:
    candidate = {
        "sha": "a" * 40,
        "priority_rank": 1,
        "signals": ["guard_method_history"],
    }
    batch_route._validate_label_neutral_input(
        {"label_neutral": True}, [candidate]
    )

    candidate["signals"] = ["p5_already_confirmed_candidate_coverage"]
    with pytest.raises(SystemExit, match="leaks signals"):
        batch_route._validate_label_neutral_input(
            {"label_neutral": True}, [candidate]
        )


def test_label_neutral_prompt_rejects_adjudication_marker() -> None:
    batch_route._validate_prompt_label_neutrality(
        [{"user_prompt": "Signals: guard_surface_history"}]
    )

    with pytest.raises(SystemExit, match="adjudication markers"):
        batch_route._validate_prompt_label_neutrality(
            [{"user_prompt": "Signals: p5_already_confirmed_candidate_coverage"}]
        )


def test_edge_specific_prompt_requires_exact_fix_aliases() -> None:
    prompt = batch_route._prompt(
        packet={"repository_identity": "repo/example", "advisory": "FRONTIER"},
        aliases=[{"unit_id": "U1", "id": "C01"}],
        fix_views=[
            {
                "id": "F01",
                "sha": "f" * 40,
                "date": "later",
                "subject": "fix",
                "diff": "+guard",
            }
        ],
        candidate_views=[
            {
                "unit_id": "U1",
                "sha": "a" * 40,
                "fix_shas": ["f" * 40],
                "fix_ids": ["F01"],
                "rank": 1,
                "signals": ["ai_ancestry_fallback"],
                "carrier_signals": [],
                "provenance": "mainline",
                "lineage": "git-parents=parent",
                "change_stats": "+1/-0",
                "date": "earlier",
                "subject": "candidate",
                "diff": "+new runtime path",
            }
        ],
        edge_specific=True,
    )

    assert "Security fix F01" in prompt
    assert "Eligible fixes: F01" in prompt
    assert '"related_fixes":["F01"]' in prompt


def test_contract_failure_gets_one_exact_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter(
        [
            {"result_status": "parse_error", "reason": "missing C02"},
            {"result_status": "completed", "reason": "", "unit_results": []},
        ]
    )

    monkeypatch.setattr(
        batch_route,
        "_call_one_once",
        lambda _prompt, **_kwargs: next(responses),
    )
    result = batch_route._call_with_retries({}, transport_retries=0, contract_retries=1)

    assert result["result_status"] == "completed"
    assert result["attempt_count"] == 2
    assert result["contract_retry_count"] == 1
