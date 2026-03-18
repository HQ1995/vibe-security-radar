#!/usr/bin/env python3
"""Regression script for ref_search module.

Samples CVEs that have no fix commits but do have GitHub/GitLab refs,
runs ref_search.discover() on each, and reports the hit rate.

Usage:
    python3 scripts/regression_ref_search.py --sample 50
    python3 scripts/regression_ref_search.py --sample 20 --use-llm
    python3 scripts/regression_ref_search.py --sample 100 --workers 8
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

# Add the cve-analyzer source to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cve-analyzer" / "src"))

from cve_analyzer import nvd, ref_search


@dataclass
class _Result:
    index: int
    cve_id: str
    commits: list | None  # None = error
    error: str
    elapsed: float


def find_candidates(max_scan: int = 5000) -> list[dict]:
    """Find cached CVEs with no fix commits but with GitHub/GitLab refs."""
    cache_dir = Path.home() / ".cache" / "cve-analyzer" / "results"
    if not cache_dir.exists():
        print(f"Cache directory not found: {cache_dir}", file=sys.stderr)
        return []

    candidates: list[dict] = []
    scanned = 0

    for path in cache_dir.iterdir():
        if not path.name.endswith(".json"):
            continue
        scanned += 1
        if scanned > max_scan:
            break

        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        # Must have no fix commits
        if data.get("fix_commits"):
            continue

        # Must have references
        refs = data.get("references", [])
        if not refs:
            continue

        # Must have at least one non-junk repo URL in refs
        if ref_search.extract_repo_urls(refs):
            candidates.append(data)

    return candidates


def _run_one(index: int, data: dict, use_llm: bool) -> _Result:
    """Run ref_search.discover() for a single CVE. Thread-safe."""
    cve_id = data["cve_id"]
    refs = data.get("references", [])
    desc = data.get("description", "")
    cwes = data.get("cwes", [])
    ghsa_ids = nvd.extract_ghsa_ids(refs)

    # Clear ref-search cache for this CVE so we get fresh results
    cache_path = ref_search.CACHE_DIR / f"{cve_id}.json"
    if cache_path.exists():
        cache_path.unlink()

    start = time.monotonic()
    try:
        results = ref_search.discover(
            cve_id, refs, desc, cwes,
            ghsa_ids=ghsa_ids,
            use_llm=use_llm,
        )
        return _Result(index, cve_id, results, "", time.monotonic() - start)
    except Exception as exc:
        return _Result(index, cve_id, None, str(exc), time.monotonic() - start)


def main() -> None:
    parser = argparse.ArgumentParser(description="Regression test for ref_search")
    parser.add_argument("--sample", type=int, default=50, help="Number of CVEs to test")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--use-llm", action="store_true", help="Enable LLM desc search fallback")
    parser.add_argument("--max-scan", type=int, default=10000, help="Max cache files to scan")
    parser.add_argument("--workers", type=int, default=4, help="Parallel workers")
    args = parser.parse_args()

    random.seed(args.seed)

    print(f"Scanning cache for candidates (max {args.max_scan})...")
    candidates = find_candidates(max_scan=args.max_scan)
    print(f"Found {len(candidates)} CVEs with repo refs but no fix commits")

    if not candidates:
        print("No candidates found. Run a batch first.")
        sys.exit(1)

    sample = random.sample(candidates, min(args.sample, len(candidates)))
    total = len(sample)
    print(f"Testing {total} CVEs (seed={args.seed}, use_llm={args.use_llm}, workers={args.workers})")
    print("-" * 70)

    wall_start = time.monotonic()
    hits = 0
    errors = 0
    done = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(_run_one, i, data, args.use_llm): i
            for i, data in enumerate(sample, 1)
        }

        for future in as_completed(futures):
            r = future.result()
            done += 1

            if r.commits is None:
                errors += 1
                print(f"  [{done}/{total}] {r.cve_id}: ERROR ({r.error}) [{r.elapsed:.1f}s]")
            elif r.commits:
                hits += 1
                shas = ", ".join(c.sha[:12] for c in r.commits)
                repo = r.commits[0].repo_url
                print(f"  [{done}/{total}] {r.cve_id}: HIT ({len(r.commits)} commits: {shas}) repo={repo} [{r.elapsed:.1f}s]")
            else:
                print(f"  [{done}/{total}] {r.cve_id}: MISS [{r.elapsed:.1f}s]")

    wall_time = time.monotonic() - wall_start
    print("-" * 70)
    print(f"Results: {hits}/{total} hits ({100*hits/total:.1f}%)")
    print(f"Errors: {errors}")
    print(f"Wall time: {wall_time:.1f}s ({wall_time/total:.1f}s/CVE effective)")


if __name__ == "__main__":
    main()
