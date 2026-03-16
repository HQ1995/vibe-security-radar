#!/usr/bin/env python3
"""Regression test for tag-based fix commit discovery.

Picks CVEs with known fix commits (from osv/github_advisory) where the
advisory also has a patched_version.  Runs _resolve_fix_from_version_tag()
with only the version + repo, and compares the result against the known SHA.

Usage:
    uv run python scripts/regression_tag_search.py --sample 50
    uv run python scripts/regression_tag_search.py --sample 20 --verbose
    uv run python scripts/regression_tag_search.py --sample 100 --workers 16
"""

from __future__ import annotations

import argparse
import logging
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Ensure the cve-analyzer package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cve-analyzer" / "src"))

from cve_analyzer import git_ops, ghsa_local, github_advisory, commit_scoring
from cve_analyzer.pipeline import _resolve_fix_from_version_tag, _is_non_code_commit

from regression_ground_truth import (
    RegressionStats,
    build_candidates,
    sha_matches,
)


def _load_candidates(sample_size: int, verbose: bool = False) -> list[dict]:
    """Load CVEs that have good fix commits AND advisory patched versions."""
    print("Loading GHSA local index...")
    ghsa_local.ensure_cloned()

    all_candidates, filter_stats = build_candidates()

    # Enrich with patched_version from GHSA local data
    enriched: list[dict] = []
    for cand in all_candidates:
        advisory = ghsa_local.get_advisory_local(cand["cve_id"])
        if not advisory:
            continue
        all_versions = github_advisory.extract_all_patched_versions(advisory)
        if not all_versions:
            continue
        cand["patched_version"] = all_versions[0]
        cand["all_patched_versions"] = all_versions
        enriched.append(cand)

    random.shuffle(enriched)
    candidates = enriched[:sample_size]

    if verbose or filter_stats:
        print(f"Candidate pool: {len(enriched)} with versions (from {len(all_candidates)} validated)")
        if filter_stats:
            print(f"Ground truth filtered: {filter_stats}")

    return candidates


def _run_one(cand: dict, diagnose: bool = False, llm_rerank: bool = False):
    """Run tag-based discovery for a single CVE.

    Returns (cve_id, status, got_sha, expected_shas, position, diag_info).
    diag_info is a dict with failure diagnosis when diagnose=True and status=WRONG.
    """
    cve_id = cand["cve_id"]
    expected_shas = cand["expected_shas"]
    diag: dict | None = None

    # Try patched versions (first is primary, up to 3 fallbacks)
    all_versions = cand.get("all_patched_versions", [cand["patched_version"]])[:3]
    results = None
    for version in all_versions:
        try:
            results = _resolve_fix_from_version_tag(
                repo_url=cand["repo_url"],
                patched_version=version,
                description=cand["description"],
                source="regression_test",
                cve_id=cve_id,
                llm_rerank=llm_rerank,
            )
            if results:
                break  # Found candidates with this version
        except Exception as exc:
            if version == all_versions[-1]:
                return cve_id, f"ERROR: {exc}", None, expected_shas, -1, None

    if not results:
        # Diagnose NOT_FOUND: check if tag range exists at all
        if diagnose:
            diag = _diagnose_not_found(cand)
        return cve_id, "NOT_FOUND", None, expected_shas, -1, diag

    repo_path = cand.get("repo_path")
    for i, result in enumerate(results):
        if sha_matches(result.sha, expected_shas, repo_path=repo_path):
            return cve_id, "CORRECT", result.sha, expected_shas, i, None

    # WRONG: diagnose why
    if diagnose:
        diag = _diagnose_wrong(cand, results)
    return cve_id, "WRONG", results[0].sha, expected_shas, -1, diag


def _diagnose_wrong(cand: dict, results) -> dict:
    """Diagnose a WRONG result: is expected SHA in the range? What's its score?"""
    repo_url = cand["repo_url"]
    expected_shas = cand["expected_shas"]
    local_path = git_ops.clone_repo(repo_url)
    if not local_path:
        return {"category": "clone_failed"}

    tag_range = git_ops.resolve_version_to_tag(local_path, cand["patched_version"], True)
    if not tag_range:
        return {"category": "no_tag_range"}

    prev_tag, fix_tag = tag_range
    all_commits = git_ops.list_commits_in_range(local_path, prev_tag, fix_tag, max_results=1000)
    range_shas = {sha for sha, _ in all_commits}

    expected_in_range = any(
        any(rs.startswith(es) or es.startswith(rs) for rs in range_shas)
        for es in expected_shas
    )

    if not expected_in_range:
        return {
            "category": "not_in_range",
            "range_size": len(all_commits),
            "range": f"{prev_tag}..{fix_tag}",
        }

    # Expected IS in range — scoring/filtering problem
    # Score all commits and find where expected ranks
    commits_with_files = git_ops.list_commits_with_files(
        local_path, prev_tag, fix_tag, max_results=1000,
    )
    candidates = [
        commit_scoring.ScoredCandidate(sha=sha, message=msg, changed_files=files)
        for sha, msg, files in commits_with_files
    ]
    commit_scoring.score_candidates(candidates, cand["cve_id"], cand["description"])

    # Find expected's rank and score
    expected_rank = -1
    expected_score = None
    for i, c in enumerate(candidates):
        if any(c.sha.startswith(es) or es.startswith(c.sha) for es in expected_shas):
            expected_rank = i
            expected_score = c.score
            break

    # Check if expected was filtered out by _is_non_code_commit
    expected_filtered = False
    for sha, msg, files in commits_with_files:
        if any(sha.startswith(es) or es.startswith(sha) for es in expected_shas):
            expected_filtered = _is_non_code_commit(files)
            break

    top_score = candidates[0].score if candidates else 0
    return {
        "category": "filtered_out" if expected_filtered else "outscored",
        "range_size": len(all_commits),
        "expected_rank": expected_rank,
        "expected_score": expected_score,
        "top_score": top_score,
        "score_gap": (top_score - expected_score) if expected_score is not None else None,
        "top_sha": candidates[0].sha[:12] if candidates else None,
    }


def _diagnose_not_found(cand: dict) -> dict:
    """Diagnose NOT_FOUND: tag range issue or empty range."""
    local_path = git_ops.clone_repo(cand["repo_url"])
    if not local_path:
        return {"category": "clone_failed"}
    tag_range = git_ops.resolve_version_to_tag(local_path, cand["patched_version"], True)
    if not tag_range:
        return {"category": "no_tag_range"}
    prev_tag, fix_tag = tag_range
    all_commits = git_ops.list_commits_in_range(local_path, prev_tag, fix_tag, max_results=1000)
    return {
        "category": "empty_range" if not all_commits else "all_filtered",
        "range_size": len(all_commits),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Regression test for tag-based fix commit discovery")
    parser.add_argument("--sample", type=int, default=50, help="Number of CVEs to test")
    parser.add_argument("--verbose", action="store_true", help="Show per-CVE details")
    parser.add_argument("--workers", type=int, default=8, help="Parallel workers")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--diagnose", action="store_true", help="Deep diagnosis of WRONG/NOT_FOUND cases")
    parser.add_argument("--llm-rerank", action="store_true", help="Use LLM to re-rank ambiguous top candidates")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    candidates = _load_candidates(args.sample, verbose=args.verbose)
    print(f"Regression: {args.sample} requested, {len(candidates)} with cloned repos + versions")
    print(f"Running with {args.workers} parallel workers\n")

    if not candidates:
        print("No candidates found. Check backup directory and cloned repos.")
        sys.exit(1)

    stats = RegressionStats()
    total = len(candidates)
    start = time.time()
    diag_results: list[tuple[str, str, dict]] = []  # (cve_id, status, diag)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_run_one, cand, args.diagnose, args.llm_rerank): cand for cand in candidates}

        for future in as_completed(futures):
            cve_id, status, got_sha, expected_shas, position, diag = future.result()

            if diag:
                diag_results.append((cve_id, status, diag))

            if status.startswith("ERROR"):
                stats.record_error()
                if args.verbose:
                    print(f"  [{stats.completed}/{total}] {cve_id}: {status}")
            elif status == "NOT_FOUND":
                stats.record_not_found()
                if args.verbose:
                    print(f"  [{stats.completed}/{total}] {cve_id}: NOT_FOUND (v{futures[future]['patched_version']})")
            elif status == "CORRECT":
                stats.record_correct(cve_id, got_sha, position=position)
                if args.verbose:
                    pos_label = f"@{position}" if position > 0 else ""
                    print(f"  [{stats.completed}/{total}] {cve_id}: CORRECT{pos_label} ({got_sha[:12]})")
            elif status == "WRONG":
                stats.record_wrong(cve_id, expected_shas[0][:12], got_sha[:12])
                if args.verbose:
                    print(f"  [{stats.completed}/{total}] {cve_id}: WRONG (expected {expected_shas[0][:12]}, got {got_sha[:12]})")

            if not args.verbose and stats.completed % 10 == 0:
                elapsed = time.time() - start
                print(f"  Progress: {stats.completed}/{total} ({elapsed:.0f}s)")

    elapsed = time.time() - start
    stats.print_report("Tag-based regression", elapsed)

    if diag_results:
        _print_diagnosis(diag_results)

    if not stats.check_thresholds(min_recall=0.2, min_precision=0.4):
        sys.exit(1)


def _print_diagnosis(diag_results: list[tuple[str, str, dict]]) -> None:
    """Print diagnostic breakdown of failure categories."""
    from collections import Counter, defaultdict

    categories = Counter()
    score_gaps: list[float] = []
    expected_ranks: list[int] = []
    range_sizes_by_cat: defaultdict[str, list[int]] = defaultdict(list)

    for cve_id, status, diag in diag_results:
        cat = diag.get("category", "unknown")
        categories[cat] += 1
        rs = diag.get("range_size", 0)
        range_sizes_by_cat[cat].append(rs)
        if diag.get("score_gap") is not None:
            score_gaps.append(diag["score_gap"])
        if diag.get("expected_rank", -1) >= 0:
            expected_ranks.append(diag["expected_rank"])

    total = len(diag_results)
    wrong_total = sum(1 for _, s, _ in diag_results if s == "WRONG")
    nf_total = sum(1 for _, s, _ in diag_results if s == "NOT_FOUND")

    print(f"\n{'='*60}")
    print(f"DIAGNOSTIC BREAKDOWN ({total} failures analyzed)")
    print(f"{'='*60}")

    print(f"\nWRONG ({wrong_total}):")
    for cat in ["outscored", "filtered_out", "not_in_range", "clone_failed", "no_tag_range"]:
        n = sum(1 for _, s, d in diag_results if s == "WRONG" and d.get("category") == cat)
        if n:
            pct = n * 100 / wrong_total if wrong_total else 0
            print(f"  {cat:20s}: {n:4d} ({pct:.0f}%)")
            sizes = [d.get("range_size", 0) for _, s, d in diag_results
                     if s == "WRONG" and d.get("category") == cat]
            if sizes:
                sizes.sort()
                print(f"    range size: median={sizes[len(sizes)//2]}, max={max(sizes)}")

    print(f"\nNOT_FOUND ({nf_total}):")
    for cat in ["no_tag_range", "empty_range", "all_filtered", "clone_failed"]:
        n = sum(1 for _, s, d in diag_results if s == "NOT_FOUND" and d.get("category") == cat)
        if n:
            pct = n * 100 / nf_total if nf_total else 0
            print(f"  {cat:20s}: {n:4d} ({pct:.0f}%)")

    if score_gaps:
        score_gaps.sort()
        print(f"\nScore gap (top vs expected) for outscored cases:")
        print(f"  median: {score_gaps[len(score_gaps)//2]:.1f}")
        print(f"  p25:    {score_gaps[len(score_gaps)//4]:.1f}")
        print(f"  p75:    {score_gaps[3*len(score_gaps)//4]:.1f}")
        print(f"  max:    {score_gaps[-1]:.1f}")
        # Distribution of score gaps
        buckets = Counter()
        for g in score_gaps:
            if g <= 1:
                buckets["≤1 (close)"] += 1
            elif g <= 3:
                buckets["1-3 (moderate)"] += 1
            elif g <= 5:
                buckets["3-5 (large)"] += 1
            else:
                buckets[">5 (huge)"] += 1
        print(f"  gap distribution:")
        for label in ["≤1 (close)", "1-3 (moderate)", "3-5 (large)", ">5 (huge)"]:
            if label in buckets:
                print(f"    {label}: {buckets[label]}")

    if expected_ranks:
        expected_ranks.sort()
        print(f"\nExpected commit rank (for outscored cases, N={len(expected_ranks)}):")
        print(f"  median: {expected_ranks[len(expected_ranks)//2]}")
        print(f"  p90:    {expected_ranks[9*len(expected_ranks)//10]}")
        within_8 = sum(1 for r in expected_ranks if r < 8)
        print(f"  within top 8: {within_8}/{len(expected_ranks)} ({within_8*100//len(expected_ranks)}%)")
        within_3 = sum(1 for r in expected_ranks if r < 3)
        print(f"  within top 3: {within_3}/{len(expected_ranks)} ({within_3*100//len(expected_ranks)}%)")


if __name__ == "__main__":
    main()
