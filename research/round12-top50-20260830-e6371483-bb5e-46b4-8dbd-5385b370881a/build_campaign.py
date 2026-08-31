#!/usr/bin/env python3
"""Freeze 50 highest-signal open cases without touching the canonical ledger."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LANE = Path(__file__).resolve().parent
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
ROUND11 = ROOT / "research/round11-top500-20260829"
TARGET = 50
EXCLUSIONS = [
    ROOT / "research/round9-top200-20260828/manifest.jsonl",
    ROOT / "research/round9-top200-20260828/external-review-manifest.jsonl",
    ROOT / "research/round10-top200-20260828/manifest.jsonl",
    ROOT / "research/round11-top500-20260829/manifest.jsonl",
    ROOT / "research/gate-campaign-20260830/manifest.jsonl",
]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rank = load_module("round11_rank", ROUND11 / "rank.py")
bundle_tools = load_module("round11_bundle_tools", ROUND11 / "build_campaign.py")
bundle_tools.QUEUE = LANE
bundle_tools.CACHE_DIRS = [
    LANE / "advisory-cache",
    ROOT / ".ai-slop/state/research-queue/round11/advisory-cache",
    ROOT / ".ai-slop/state/research-queue/round10/advisory-cache",
    ROOT / ".ai-slop/state/research-queue/round9/advisory-cache",
]


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def exclusions(ledger: list[dict]) -> tuple[set[str], set[str]]:
    classes = {
        row["class_id"]
        for row in ledger
        if any(
            row.get(key)
            for key in (
                *(f"round{n}_{suffix}" for n in range(3, 9) for suffix in ("research", "research_source", "verdict")),
                "round9_resolution",
                "round9_assessment_ids",
                "round9_scan_runs",
                "causal_research",
                "partial_wave",
                "partial_wave_verdict",
                "partial_wave_reaudited",
            )
        )
    }
    advisories: set[str] = set()
    for path in EXCLUSIONS:
        if not path.exists():
            continue
        for row in jsonl(path):
            classes.add(row["class_id"])
            advisories.update(str(value).upper() for value in row.get("advisory_ids") or [])
            if row.get("case_id"):
                advisories.add(str(row["case_id"]).upper())
    by_class = {row["class_id"]: row for row in ledger}
    advisories.update(
        str(value).upper()
        for class_id in classes
        for value in (by_class.get(class_id) or {}).get("advisory_ids") or []
    )
    return classes, advisories


def clone_dir(repo: str, clone_index: dict[str, str]) -> Path:
    indexed = clone_index.get(repo)
    candidates = ([Path(indexed)] if indexed else []) + [
        ROOT / ".ai-slop/state/repos" / repo.replace("/", "_")
    ]
    return next((path for path in candidates if (path / ".git").exists()), candidates[-1])


def git_output(clone: Path, *args: str, check: bool = True) -> str:
    return subprocess.run(
        ["git", "-C", str(clone), *args],
        check=check,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> None:
    before = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    data = rank.load_live_inputs()
    excluded_classes, excluded_advisories = exclusions(data["ledger"])

    for row in data["ledger"]:
        repo = rank.normalize_repo(row.get("repo"))
        if repo and (clone_dir(repo, data["clone_index"]) / ".git").exists():
            data["clone_ready"].add(repo)

    ranked = rank.rank_open_cases(
        data["ledger"],
        scans=data["scans"],
        tp_repos=data["tp_repos"],
        clone_ready=data["clone_ready"],
        excluded_classes=excluded_classes,
        excluded_advisories=excluded_advisories,
    )
    selected = rank.select_top(ranked, target=TARGET, max_per_repo=5)
    assert len(selected) == TARGET
    assert len({item[1] for item in selected}) == TARGET

    ghsas = [
        next(value for value in rank.ghsa_ids(row))
        for _, _, row, _ in selected
    ]
    with ThreadPoolExecutor(max_workers=8) as pool:
        advisory_rows = dict(zip(ghsas, pool.map(bundle_tools.advisory, ghsas), strict=True))

    after = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    if before != after:
        raise RuntimeError(f"ledger changed during freeze: {before} -> {after}")

    site_cases = json.loads((ROOT / "web/src/generated/research-data.json").read_text())["cases"]
    revisions = bundle_tools.load_revisions()
    manifest = []
    for ordinal, (score, class_id, row, signals) in enumerate(selected):
        worker = f"w{ordinal:03d}"
        repo = rank.normalize_repo(row.get("repo"))
        ids = row.get("advisory_ids") or []
        ghsa = rank.ghsa_ids(row)[0]
        clone = clone_dir(repo, data["clone_index"])
        advisory = advisory_rows[ghsa]
        bundle = {
            "schema_version": "causal-audit-bundle/1",
            "class_id": class_id,
            "status_at_selection": row["status"],
            "repo": repo,
            "clone_dir": str(clone),
            "clone_url": bundle_tools.clone_url(repo),
            "clone_head_sha": git_output(clone, "rev-parse", "HEAD"),
            "clone_shallow": git_output(clone, "rev-parse", "--is-shallow-repository"),
            "clone_promisor": git_output(clone, "config", "--get", "remote.origin.promisor", check=False) == "true",
            "clone_partial_filter": git_output(clone, "config", "--get", "remote.origin.partialclonefilter", check=False) or None,
            "advisory_ids": ids,
            "base_ledger_revision": revisions.get(class_id, 1),
            "ledger_snapshot_sha256": before,
            "advisory": advisory,
            "same_repository_prior_hits": bundle_tools.same_repo_hits(
                repo,
                " ".join(str(advisory.get(key) or "") for key in ("summary", "description")),
                site_cases,
            ),
            "protocol": "docs/AUDIT-PROTOCOL.md",
            "context_rule": (
                "One case, one clean context. Do not read the canonical ledger, another "
                "case bundle/output, or a prior verdict. Prior hits are leads, never proof."
            ),
        }
        bundle_path = LANE / "bundles" / f"{worker}.json"
        atomic_write(bundle_path, json.dumps(bundle, ensure_ascii=False, indent=1) + "\n")
        manifest.append({
            "ordinal": ordinal,
            "worker": worker,
            "class_id": class_id,
            "status_at_selection": row["status"],
            "repo": repo,
            "advisory_ids": ids,
            "score": score,
            "signals": signals,
            "bundle": str(bundle_path.relative_to(ROOT)),
            "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
            "clone_dir": str(clone),
            "clone_head_sha": bundle["clone_head_sha"],
            "clone_shallow": bundle["clone_shallow"],
            "clone_promisor": bundle["clone_promisor"],
            "clone_partial_filter": bundle["clone_partial_filter"],
            "primary_out": str((LANE / "primary" / f"{worker}.json").relative_to(ROOT)),
        })

    used_ids = {value for row in manifest for value in map(str.upper, row["advisory_ids"])}
    assert not ({row["class_id"] for row in manifest} & excluded_classes)
    assert not (used_ids & excluded_advisories)
    assert all(row["clone_shallow"] == "false" for row in manifest)
    assert all((Path(row["clone_dir"]) / ".git").exists() for row in manifest)

    atomic_write(
        LANE / "manifest.jsonl",
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in manifest),
    )
    summary = {
        "target": TARGET,
        "selected": len(manifest),
        "selection_statuses": dict(Counter(row["status_at_selection"] for row in manifest)),
        "repositories": len({row["repo"] for row in manifest}),
        "score_max": manifest[0]["score"],
        "score_min": manifest[-1]["score"],
        "clone_ready_full_history": sum(row["clone_shallow"] == "false" for row in manifest),
        "excluded_classes": len(excluded_classes),
        "excluded_advisories": len(excluded_advisories),
        "excluded_manifests": [str(path.relative_to(ROOT)) for path in EXCLUSIONS],
        "ledger_sha256_at_freeze": before,
        "selection_rule": (
            "Round11 deterministic TP-likelihood score, refreshed local clone readiness, "
            "GHSA required, max five per repository, excluding every class/advisory in "
            "all meaningful round3-round11/causal/partial-wave coverage and the active "
            "gate-campaign manifest."
        ),
    }
    atomic_write(LANE / "selection-summary.json", json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
