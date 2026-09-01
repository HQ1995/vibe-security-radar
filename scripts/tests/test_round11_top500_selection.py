"""Unit tests for the round11 ranking functions (score_row/select_top/rank)."""
from __future__ import annotations

import importlib.util
import math
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round11-top500-20260829"
RANK_PATH = LANE / "rank.py"


def _load_rank():
    spec = importlib.util.spec_from_file_location("round11_rank", RANK_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules["round11_rank"] = module
    spec.loader.exec_module(module)
    return module


rank = _load_rank()


def _row(**overrides):
    row = {
        "class_id": "alias-aaaaaaaaaaaaaaaaaaaaaaaa",
        "status": "UNANALYZED",
        "repo": "acme/widget",
        "advisory_ids": ["CVE-2026-11111", "GHSA-aaaa-bbbb-cccc"],
        "leftover_bucket": "has_ai",
        "leftover_kind": "unreviewed",
    }
    row.update(overrides)
    return row


def test_score_row_round10_top_signal_is_211() -> None:
    """Known-TP repo with 12 published TPs plus AI scan/GHSA/2026/clone = 211."""
    score, signals = rank.score_row(
        _row(),
        scans={},
        tp_repos=Counter({"acme/widget": 12}),
        clone_ready={"acme/widget"},
    )
    assert score == 211.0
    assert "repo_ai_commit_scan" in signals
    assert "known_tp_repo:12" in signals
    assert "unreviewed_advisory" in signals
    assert "ghsa_bundle" in signals
    assert "2026" in signals
    assert "clone_ready" in signals


def test_score_row_ai_commit_density_is_log_scaled() -> None:
    score, signals = rank.score_row(
        _row(leftover_bucket=None, leftover_kind=None, advisory_ids=["GHSA-aaaa-bbbb-cccc"]),
        scans={"acme/widget": {"ai_commit_count": 15}},
        tp_repos=Counter(),
        clone_ready=set(),
    )
    expected = round(15 + min(30, 5 * math.log2(16)), 3)
    assert score == expected
    assert "ai_commits:15" in signals


def test_prior_not_ai_is_penalized() -> None:
    score, signals = rank.score_row(
        _row(
            status="PARTIALLY_ANALYZED",
            leftover_bucket=None,
            leftover_kind=None,
            advisory_ids=["GHSA-aaaa-bbbb-cccc"],
            partial_wave_verdict="NOT_AI",
        ),
        scans={},
        tp_repos=Counter(),
        clone_ready=set(),
    )
    assert score == 15 + 5 - 70
    assert "prior_not_ai" in signals


def test_exclude_round10_class_and_advisory() -> None:
    excluded_classes = {"alias-round10"}
    excluded_advisories = {"GHSA-R10A-R10A-R10A"}
    same_class = _row(class_id="alias-round10")
    same_advisory = _row(
        class_id="alias-other",
        advisory_ids=["CVE-2026-99999", "GHSA-R10A-R10A-R10A"],
    )
    open_other = _row(class_id="alias-keep")
    closed = _row(class_id="alias-closed", status="NOT_AI")
    assert not rank.is_eligible(same_class, excluded_classes, excluded_advisories)
    assert not rank.is_eligible(same_advisory, excluded_classes, excluded_advisories)
    assert not rank.is_eligible(closed, excluded_classes, excluded_advisories)
    assert rank.is_eligible(open_other, excluded_classes, excluded_advisories)


def test_select_top_enforces_repo_cap_ghsa_and_unique_ids() -> None:
    rows = []
    for idx in range(8):
        rows.append(
            (
                200 - idx,
                f"alias-{idx:024x}",
                _row(
                    class_id=f"alias-{idx:024x}",
                    repo="acme/widget",
                    advisory_ids=[f"CVE-2026-{10000+idx}", f"GHSA-aaaa-bbbb-{idx:04d}"],
                ),
                ["repo_ai_commit_scan", "ghsa_bundle"],
            )
        )
    rows.append(
        (
            10,
            "alias-noghsa0000000000000000",
            _row(
                class_id="alias-noghsa0000000000000000",
                repo="other/lib",
                leftover_bucket=None,
                advisory_ids=["CVE-2026-22222"],
            ),
            [],
        )
    )
    for idx in range(5):
        rows.append(
            (
                150 - idx,
                f"alias-b{idx:023x}",
                _row(
                    class_id=f"alias-b{idx:023x}",
                    repo="beta/tool",
                    leftover_bucket="has_ai",
                    advisory_ids=[f"CVE-2026-{20000+idx}", f"GHSA-bbbb-cccc-{idx:04d}"],
                ),
                ["repo_ai_commit_scan", "ghsa_bundle"],
            )
        )
    selected = rank.select_top(rows, target=10, max_per_repo=5)
    assert len(selected) == 10
    repos = Counter(rank.normalize_repo(item[2]["repo"]) for item in selected)
    assert repos["acme/widget"] == 5
    assert repos["beta/tool"] == 5
    assert "other/lib" not in repos
    assert len({item[1] for item in selected}) == 10


def test_rank_orders_by_score_then_class_id() -> None:
    high_b = _row(class_id="alias-bbbbbbbbbbbbbbbbbbbbbbbb", leftover_bucket="has_ai")
    high_a = _row(class_id="alias-aaaaaaaaaaaaaaaaaaaaaaaa", leftover_bucket="has_ai")
    low = _row(
        class_id="alias-cccccccccccccccccccccccc",
        leftover_bucket=None,
        leftover_kind=None,
        advisory_ids=["GHSA-cccc-cccc-cccc"],
    )
    ranked = rank.rank_open_cases(
        [low, high_b, high_a],
        scans={},
        tp_repos=Counter(),
        clone_ready=set(),
        excluded_classes=set(),
        excluded_advisories=set(),
    )
    assert [item[1] for item in ranked] == [
        "alias-aaaaaaaaaaaaaaaaaaaaaaaa",
        "alias-bbbbbbbbbbbbbbbbbbbbbbbb",
        "alias-cccccccccccccccccccccccc",
    ]

