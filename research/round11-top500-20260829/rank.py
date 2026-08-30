#!/usr/bin/env python3
"""Deterministic TP-likelihood ranking for remaining open ledger cases.

Scoring matches the round9/round10 campaign: repo AI-commit scan dominates,
then known-TP repo, AI-commit density, advisory quality/recency, clone
readiness. Round10 class_ids and advisory ids are excluded. GHSA identity
is required. Max five cases per repository.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round11-top500-20260829"
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
SCAN_RESULTS = ROOT / ".ai-slop/state/funnel-ai-writer-20260826/scan-results.jsonl"
CLONE_INDEX = ROOT / ".ai-slop/state/funnel-ai-writer-20260826/existing-clone-index.json"
EXCLUDED_MANIFEST = ROOT / "research/round10-top200-20260828/manifest.jsonl"
OPEN_STATUSES = {"UNANALYZED", "PARTIALLY_ANALYZED"}
TP_STATUSES = {"AI_ROOT_CAUSE", "AI_CODE_FLAWED"}
MAX_PER_REPO = 5
TARGET = 500


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def normalize_repo(repo: str | None) -> str:
    value = (repo or "").strip().lower()
    return value.removeprefix("https://").removeprefix("http://").removeprefix("github.com/")


def official_ids(row: dict) -> set[str]:
    return {str(value).upper() for value in row.get("advisory_ids") or []}


def ghsa_ids(row: dict) -> list[str]:
    return sorted(
        str(value).upper()
        for value in row.get("advisory_ids") or []
        if str(value).upper().startswith("GHSA-")
    )


def excluded_identities(rows: list[dict]) -> tuple[set[str], set[str]]:
    classes = {row["class_id"] for row in rows}
    advisories = {
        str(value).upper()
        for row in rows
        for value in row.get("advisory_ids") or []
    }
    return classes, advisories


def is_eligible(row: dict, excluded_classes: set[str], excluded_advisories: set[str]) -> bool:
    if row.get("status") not in OPEN_STATUSES:
        return False
    if row["class_id"] in excluded_classes:
        return False
    if official_ids(row) & excluded_advisories:
        return False
    return True


def load_scans(path: Path) -> dict[str, dict]:
    scans: dict[str, dict] = {}
    for item in jsonl(path):
        repo = normalize_repo(item.get("repo"))
        if not repo:
            continue
        current = scans.get(repo)
        if current is None or int(item.get("ai_commit_count") or 0) > int(current.get("ai_commit_count") or 0):
            scans[repo] = item
    return scans


def known_tp_repos(ledger: list[dict]) -> Counter[str]:
    return Counter(
        normalize_repo(row.get("repo"))
        for row in ledger
        if row.get("status") in TP_STATUSES
    )


def clone_ready_repos(clone_index: dict[str, str]) -> set[str]:
    ready: set[str] = set()
    for repo, path in clone_index.items():
        if path and (Path(path) / ".git").exists():
            ready.add(normalize_repo(repo))
    return ready


def score_row(
    row: dict,
    *,
    scans: dict[str, dict],
    tp_repos: Counter[str],
    clone_ready: set[str],
) -> tuple[float, list[str]]:
    repo = normalize_repo(row.get("repo"))
    score = 0.0
    signals: list[str] = []
    if row.get("leftover_bucket") == "has_ai":
        score += 100
        signals.append("repo_ai_commit_scan")
    if tp_repos[repo]:
        score += 45 + min(10, tp_repos[repo] * 2)
        signals.append(f"known_tp_repo:{tp_repos[repo]}")
    ai_count = int((scans.get(repo) or {}).get("ai_commit_count") or 0)
    if ai_count:
        score += min(30, 5 * math.log2(ai_count + 1))
        signals.append(f"ai_commits:{ai_count}")
    kind = row.get("leftover_kind")
    if kind == "reviewed":
        score += 15
        signals.append("reviewed_advisory")
    elif kind == "unreviewed":
        score += 8
        signals.append("unreviewed_advisory")
    elif kind == "nvd_only":
        signals.append("nvd_only")
    ids = row.get("advisory_ids") or []
    if any(str(value).upper().startswith("GHSA-") for value in ids):
        score += 15
        signals.append("ghsa_bundle")
    if any(str(value).upper().startswith("CVE-2026-") for value in ids):
        score += 8
        signals.append("2026")
    elif any(str(value).upper().startswith("CVE-2025-") for value in ids):
        score += 3
        signals.append("2025")
    if len(ids) >= 2:
        score += 5
    if repo in clone_ready:
        score += 20
        signals.append("clone_ready")
    if row.get("status") == "PARTIALLY_ANALYZED":
        score += 5
        prior = row.get("partial_wave_verdict")
        if prior == "EVIDENCE_GAP":
            score += 8
            signals.append("prior_evidence_gap")
        elif prior == "NOT_AI":
            score -= 70
            signals.append("prior_not_ai")
        elif prior == "BLOCKED":
            score -= 80
            signals.append("prior_blocked")
    return round(score, 3), signals


def rank_open_cases(
    ledger: list[dict],
    *,
    scans: dict[str, dict],
    tp_repos: Counter[str],
    clone_ready: set[str],
    excluded_classes: set[str],
    excluded_advisories: set[str],
) -> list[tuple[float, str, dict, list[str]]]:
    ranked: list[tuple[float, str, dict, list[str]]] = []
    for row in ledger:
        if not is_eligible(row, excluded_classes, excluded_advisories):
            continue
        score, signals = score_row(
            row, scans=scans, tp_repos=tp_repos, clone_ready=clone_ready
        )
        ranked.append((score, row["class_id"], row, signals))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return ranked


def select_top(
    ranked: list[tuple[float, str, dict, list[str]]],
    *,
    target: int = TARGET,
    max_per_repo: int = MAX_PER_REPO,
) -> list[tuple[float, str, dict, list[str]]]:
    selected: list[tuple[float, str, dict, list[str]]] = []
    per_repo: Counter[str] = Counter()
    used_advisory_ids: set[str] = set()
    for score, class_id, row, signals in ranked:
        repo = normalize_repo(row.get("repo"))
        if per_repo[repo] >= max_per_repo:
            continue
        if not ghsa_ids(row):
            continue
        ids = official_ids(row)
        if ids & used_advisory_ids:
            continue
        selected.append((score, class_id, row, signals))
        per_repo[repo] += 1
        used_advisory_ids.update(ids)
        if len(selected) == target:
            break
    return selected


def load_live_inputs() -> dict:
    ledger = jsonl(LEDGER)
    excluded = jsonl(EXCLUDED_MANIFEST)
    excluded_classes, excluded_advisories = excluded_identities(excluded)
    clone_index = {
        normalize_repo(key): value
        for key, value in json.loads(CLONE_INDEX.read_text()).items()
    }
    return {
        "ledger": ledger,
        "scans": load_scans(SCAN_RESULTS),
        "tp_repos": known_tp_repos(ledger),
        "clone_ready": clone_ready_repos(clone_index),
        "clone_index": clone_index,
        "excluded_classes": excluded_classes,
        "excluded_advisories": excluded_advisories,
        "ledger_sha256": hashlib.sha256(LEDGER.read_bytes()).hexdigest(),
    }


def recompute_selection(inputs: dict | None = None) -> list[tuple[float, str, dict, list[str]]]:
    data = inputs or load_live_inputs()
    ranked = rank_open_cases(
        data["ledger"],
        scans=data["scans"],
        tp_repos=data["tp_repos"],
        clone_ready=data["clone_ready"],
        excluded_classes=data["excluded_classes"],
        excluded_advisories=data["excluded_advisories"],
    )
    selected = select_top(ranked)
    if len(selected) != TARGET:
        raise AssertionError(f"selection filled {len(selected)}/{TARGET}")
    class_ids = [item[1] for item in selected]
    if len(set(class_ids)) != TARGET:
        raise AssertionError("selection class_ids are not unique")
    selected_classes = set(class_ids)
    selected_advisories = {
        value
        for item in selected
        for value in official_ids(item[2])
    }
    if selected_classes & data["excluded_classes"]:
        raise AssertionError("selection overlaps excluded class_ids")
    if selected_advisories & data["excluded_advisories"]:
        raise AssertionError("selection overlaps excluded advisory ids")
    if not ({item[2]["status"] for item in selected} <= OPEN_STATUSES):
        raise AssertionError("selection contains a non-open status")
    return selected
