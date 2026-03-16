#!/usr/bin/env python3
"""Regression test harness for description-based fix commit discovery.

Picks CVEs with known fix commits from the backup cache, runs
discover_fix_commit() with only the description (pretending no fix
commit is known), and compares the result against the known fix SHA.

Usage:
    uv run python scripts/regression_desc_search.py --sample 50 --seed 42
    uv run python scripts/regression_desc_search.py --save-fixture fixtures/desc-baseline.json --seed 42
    uv run python scripts/regression_desc_search.py --fixture fixtures/desc-baseline.json --workers 8
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Ensure the cve-analyzer package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cve-analyzer" / "src"))

from cve_analyzer.commit_scoring import score_candidates
from cve_analyzer.description_search import (
    compute_confidence_signals,
    discover_fix_commit,
    extract_search_terms,
    search_candidates,
)

from regression_ground_truth import (
    RegressionStats,
    build_candidates,
    sha_matches,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_candidates(sample_size: int, *, seed: int | None = None) -> list[dict]:
    """Load CVEs that have good fix commits and cloned repos."""
    candidates, filter_stats = build_candidates()

    if seed is not None:
        random.seed(seed)
    random.shuffle(candidates)
    selected = candidates[:sample_size]

    if filter_stats:
        print(f"Candidate pool: {len(candidates)} validated")
        print(f"Ground truth filtered: {filter_stats}")

    return selected


def _save_fixture(candidates: list[dict], path: Path) -> None:
    """Save a test fixture (CVE IDs + expected SHAs) to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fixture = [
        {
            "cve_id": c["cve_id"],
            "expected_shas": c["expected_shas"],
            "repo_url": c["repo_url"],
        }
        for c in candidates
    ]
    path.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"Saved fixture: {len(fixture)} CVEs → {path}")


def _load_fixture(path: Path) -> list[dict]:
    """Load a test fixture and resolve against current ground truth."""
    fixture = json.loads(path.read_text())
    fixture_ids = {f["cve_id"] for f in fixture}

    # Rebuild full candidates from ground truth, filtered to fixture IDs
    all_candidates, _ = build_candidates()
    by_id = {c["cve_id"]: c for c in all_candidates}

    selected = []
    missing = []
    for f in fixture:
        cve_id = f["cve_id"]
        if cve_id in by_id:
            selected.append(by_id[cve_id])
        else:
            missing.append(cve_id)

    if missing:
        print(f"Warning: {len(missing)} fixture CVEs not in current ground truth: {missing[:5]}")
    print(f"Loaded fixture: {len(selected)}/{len(fixture)} CVEs from {path}")
    return selected


def _run_one(cand: dict, model: str) -> dict:
    """Run discovery for a single CVE. Returns a result dict."""
    cve_id = cand["cve_id"]
    expected_shas = cand["expected_shas"]

    # Extract published_date from raw cached result
    raw = cand.get("raw", {})
    published_date = raw.get("published_date") or raw.get("published") or None

    try:
        results = discover_fix_commit(
            repo_path=Path(cand["repo_path"]),
            cve_id=cve_id,
            description=cand["description"],
            cwes=cand["cwes"],
            repo_url=cand["repo_url"],
            model=model,
            published_date=published_date,
        )
    except Exception as exc:
        return {"cve_id": cve_id, "status": f"ERROR: {exc}", "got_sha": None, "expected_shas": expected_shas}

    if not results:
        return {"cve_id": cve_id, "status": "NOT_FOUND", "got_sha": None, "expected_shas": expected_shas}

    got_sha = results[0].sha
    status = "CORRECT" if sha_matches(got_sha, expected_shas) else "WRONG"
    return {"cve_id": cve_id, "status": status, "got_sha": got_sha, "expected_shas": expected_shas}


def _dry_run_one(cand: dict) -> dict:
    """Score candidates for a single CVE without LLM calls."""
    cve_id = cand["cve_id"]
    repo_path = Path(cand["repo_path"])
    description = cand["description"]
    cwes = cand["cwes"]
    expected_shas = cand["expected_shas"]

    raw = cand.get("raw", {})
    published_date = raw.get("published_date") or raw.get("published") or None

    try:
        terms = extract_search_terms(description, cwes)
        if not terms:
            return {"cve_id": cve_id, "status": "NO_TERMS",
                    "top_sha": None, "expected_shas": expected_shas,
                    "candidate_count": 0}

        candidates = search_candidates(
            repo_path, terms, max_results=100,
            published_date=published_date,
        )
        if not candidates:
            return {"cve_id": cve_id, "status": "NO_CANDIDATES",
                    "top_sha": None, "expected_shas": expected_shas,
                    "candidate_count": 0}

        scored = score_candidates(
            candidates, cve_id, description,
            reference_date=published_date,
        )
        top_scored = scored[:30]
        signals = compute_confidence_signals(top_scored)

        top_sha = top_scored[0].sha if top_scored else None
        match = sha_matches(top_sha, expected_shas) if top_sha else False

        return {
            "cve_id": cve_id,
            "top_sha": top_sha, "top_score": signals.top_score if signals else 0,
            "gap_ratio": round(signals.gap_ratio, 3) if signals else 0,
            "cluster_size": signals.cluster_size if signals else 0,
            "candidate_count": len(candidates),
            "match": match, "expected_shas": expected_shas,
        }
    except Exception as exc:
        return {"cve_id": cve_id, "status": f"ERROR: {exc}",
                "top_sha": None, "expected_shas": expected_shas,
                "candidate_count": 0}


def _dry_run_signals(candidates: list[dict], workers: int = 16) -> None:
    """Compute scoring signals for all CVEs without LLM calls."""
    print(f"Dry-run signal analysis: {len(candidates)} CVEs ({workers} workers)\n")

    results = []
    completed = 0
    total = len(candidates)
    start = time.time()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_dry_run_one, cand): cand for cand in candidates}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            completed += 1
            if completed % 20 == 0:
                elapsed = time.time() - start
                print(f"  Progress: {completed}/{total} ({elapsed:.0f}s)")

    # Report stats
    match_count = sum(1 for r in results if r.get("match"))
    total_candidates = sum(r.get("candidate_count", 0) for r in results)
    results_with_candidates = [r for r in results if r.get("candidate_count", 0) > 0]
    avg_candidates = total_candidates / len(results_with_candidates) if results_with_candidates else 0

    print(f"\n{'='*50}")
    print(f"Signal analysis ({total} CVEs):")
    print(f"  Top-by-score match: {match_count}/{total} ({match_count/total*100:.1f}%)")
    print(f"  Avg candidates: {avg_candidates:.1f}")
    print(f"  Total candidates: {total_candidates}")


def _save_results(all_results: list[dict], path: Path) -> None:
    """Save per-CVE results for comparison across runs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(all_results, indent=2) + "\n")
    print(f"Results saved: {len(all_results)} CVEs → {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Regression test for description search")
    parser.add_argument("--sample", type=int, default=50, help="Number of CVEs to test")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible sampling")
    parser.add_argument("--fixture", type=str, default=None, help="Load fixed CVE set from JSON file")
    parser.add_argument("--save-fixture", type=str, default=None, help="Save selected CVEs to fixture file (no run)")
    parser.add_argument("--save-results", type=str, default=None, help="Save per-CVE results to JSON for comparison")
    parser.add_argument("--dry-run-signals", action="store_true", help="Compute scoring signals without LLM calls")
    parser.add_argument("--verbose", action="store_true", help="Show per-CVE details")
    parser.add_argument("--workers", type=int, default=16, help="Parallel workers")
    parser.add_argument("--model", default="gemini-3.1-flash-lite-preview", help="LLM model")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # Load candidates: from fixture or fresh sampling
    if args.fixture:
        candidates = _load_fixture(Path(args.fixture))
    else:
        candidates = _load_candidates(args.sample, seed=args.seed)

    # Save fixture and exit (no regression run)
    if args.save_fixture:
        _save_fixture(candidates, Path(args.save_fixture))
        return

    # Dry-run signal analysis (no LLM calls)
    if args.dry_run_signals:
        _dry_run_signals(candidates, workers=args.workers)
        return

    print(f"Regression: {len(candidates)} CVEs (seed={args.seed})")
    print(f"Running with {args.workers} parallel workers\n")

    if not candidates:
        print("No candidates found. Check backup directory and cloned repos.")
        sys.exit(1)

    stats = RegressionStats()
    all_results: list[dict] = []
    total = len(candidates)
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_run_one, cand, args.model): cand for cand in candidates}

        for future in as_completed(futures):
            r = future.result()
            all_results.append(r)
            cve_id, status = r["cve_id"], r["status"]
            got_sha, expected_shas = r["got_sha"], r["expected_shas"]

            if status.startswith("ERROR"):
                stats.record_error()
                if args.verbose:
                    print(f"  [{stats.completed}/{total}] {cve_id}: {status}")
            elif status == "NOT_FOUND":
                stats.record_not_found()
                if args.verbose:
                    print(f"  [{stats.completed}/{total}] {cve_id}: NOT_FOUND")
            elif status == "CORRECT":
                stats.record_correct(cve_id, got_sha)
                if args.verbose:
                    print(f"  [{stats.completed}/{total}] {cve_id}: CORRECT ({got_sha[:12]})")
            elif status == "WRONG":
                stats.record_wrong(cve_id, expected_shas[0][:12], got_sha[:12])
                if args.verbose:
                    print(f"  [{stats.completed}/{total}] {cve_id}: WRONG (expected {expected_shas[0][:12]}, got {got_sha[:12]})")

            if not args.verbose and stats.completed % 10 == 0:
                elapsed = time.time() - start
                print(f"  Progress: {stats.completed}/{total} ({elapsed:.0f}s)")

    elapsed = time.time() - start
    stats.print_report("Description search regression", elapsed)

    if args.save_results:
        _save_results(all_results, Path(args.save_results))

    if not stats.check_thresholds(min_recall=0.3, min_precision=0.5):
        sys.exit(1)


if __name__ == "__main__":
    main()
