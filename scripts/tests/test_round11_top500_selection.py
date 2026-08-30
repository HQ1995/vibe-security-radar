"""Drive the round11 ranking function — the freeze must be the real top 500."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round11-top500-20260829"
RANK_PATH = LANE / "rank.py"
ROUND10 = ROOT / "research/round10-top200-20260828/manifest.jsonl"
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"


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


def test_recompute_selection_is_500_unique_open_and_excludes_round10() -> None:
    selected = rank.recompute_selection()
    assert len(selected) == 500
    class_ids = [item[1] for item in selected]
    assert len(set(class_ids)) == 500
    statuses = {item[2]["status"] for item in selected}
    assert statuses <= {"UNANALYZED", "PARTIALLY_ANALYZED"}
    round10 = [json.loads(line) for line in ROUND10.read_text().splitlines() if line.strip()]
    excluded_classes, excluded_advisories = rank.excluded_identities(round10)
    assert not (set(class_ids) & excluded_classes)
    selected_advisories = {
        value for item in selected for value in rank.official_ids(item[2])
    }
    assert not (selected_advisories & excluded_advisories)
    assert all(rank.ghsa_ids(item[2]) for item in selected)
    per_repo = Counter(rank.normalize_repo(item[2].get("repo")) for item in selected)
    assert per_repo
    assert max(per_repo.values()) <= 5


def test_present_primary_records_pass_shipped_gates() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from audit_record_gates import check_record

    manifest = [json.loads(line) for line in (LANE / "manifest.jsonl").read_text().splitlines() if line.strip()]
    by_worker = {row["worker"]: row for row in manifest}
    paths = sorted((LANE / "primary").glob("w*.json"))
    assert paths, "workers must start writing primary records"
    problems = []
    for path in paths:
        record = json.loads(path.read_text())
        item = by_worker[path.stem]
        assert record["class_id"] == item["class_id"]
        assert record["repo"] == item["repo"]
        assert record["advisory_ids"] == item["advisory_ids"]
        problems.extend(check_record(record))
    assert problems == []


def test_clone_prep_covers_every_selected_repo() -> None:
    prep_path = LANE / "clone-prep.json"
    assert prep_path.exists()
    prep = json.loads(prep_path.read_text())
    manifest = [json.loads(line) for line in (LANE / "manifest.jsonl").read_text().splitlines() if line.strip()]
    assert len(prep) == len({row["repo"] for row in manifest})
    assert all(item.get("ok") is True for item in prep)
    assert max(Counter(row["repo"] for row in manifest).values()) <= 5


def test_frozen_manifest_is_exactly_recomputed_top500() -> None:
    selected = rank.recompute_selection()
    class_ids = [item[1] for item in selected]
    manifest_path = LANE / "manifest.jsonl"
    summary_path = LANE / "selection-summary.json"
    assert manifest_path.exists(), "freeze manifest must exist"
    assert summary_path.exists(), "selection summary must exist"
    manifest = [json.loads(line) for line in manifest_path.read_text().splitlines() if line.strip()]
    assert [row["class_id"] for row in manifest] == class_ids
    assert len(manifest) == 500
    assert {row["status_at_selection"] for row in manifest} <= {"UNANALYZED", "PARTIALLY_ANALYZED"}
    summary = json.loads(summary_path.read_text())
    assert summary["target"] == 500
    assert summary["excluded_overlap"] == 0
    assert summary["score_max"] == selected[0][0]
    assert summary["score_min"] == selected[-1][0]
    freeze_sha = summary["ledger_sha256_at_freeze"]
    assert isinstance(freeze_sha, str) and len(freeze_sha) == 64
    live_sha = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    by_id = {}
    for line in LEDGER.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        by_id[row["class_id"]] = row
    for row in manifest:
        live = by_id[row["class_id"]]
        assert live.get("round11_research") is None
        if live_sha == freeze_sha:
            assert live["status"] == row["status_at_selection"]
        else:
            assert row["class_id"] in by_id
            assert row["status_at_selection"] in {"UNANALYZED", "PARTIALLY_ANALYZED"}
