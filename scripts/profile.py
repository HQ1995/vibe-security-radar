#!/usr/bin/env python3
"""Pipeline performance profiler — single-command analysis of cached results."""

import json
import statistics
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

CACHE = Path.home() / ".cache/cve-analyzer/results"


def main() -> None:
    if not CACHE.exists() or not any(CACHE.glob("*.json")):
        print("No results to profile.")
        return

    files = sorted(CACHE.glob("*.json"), key=lambda f: f.stat().st_mtime)
    total = len(files)

    # --- Collect data ---
    first_t = files[0].stat().st_mtime
    last_t = files[-1].stat().st_mtime
    wall = last_t - first_t

    phase_times: dict[str, list[float]] = defaultdict(list)
    error_cats: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    repo_blame: dict[str, dict] = defaultdict(
        lambda: {"blame": 0.0, "cves": 0, "errors": 0}
    )
    signals = 0
    tribunal_v = 0
    buckets: dict[int, int] = defaultdict(int)

    for f in files:
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue

        # Phase timing
        for phase, dur in d.get("phase_times", {}).items():
            if isinstance(dur, (int, float)):
                phase_times[phase].append(dur)

        # Error categories
        cat = d.get("error_category") or (
            "success" if d.get("fix_commits") else "no_data"
        )
        error_cats[cat] += 1

        # Fix sources and repo hotspots
        for fc in d.get("fix_commits", []):
            sources[fc.get("source", "?")] += 1
            repo = fc.get("repo_url", "?").replace("https://github.com/", "")
            repo_blame[repo]["cves"] += 1
            repo_blame[repo]["blame"] += d.get("phase_times", {}).get(
                "Phase B (blame)", 0
            )
        if d.get("error"):
            for fc in d.get("fix_commits", []):
                repo = fc.get("repo_url", "?").replace("https://github.com/", "")
                repo_blame[repo]["errors"] += 1

        # Signals and tribunal
        if d.get("ai_signals"):
            signals += 1
        for b in d.get("bug_introducing_commits", []):
            if b.get("tribunal_verdict"):
                tribunal_v += 1

        # Timeline bucket
        m = int((f.stat().st_mtime - first_t) / 60)
        buckets[m] += 1

    # --- Print report ---
    cpu_total = sum(sum(v) for v in phase_times.values())

    print("=" * 65)
    print(f"  Pipeline Performance Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 65)
    print()

    print("=== Summary ===")
    print(f"  Results:    {total}")
    print(f"  Signals:    {signals}")
    print(f"  Tribunal:   {tribunal_v}")
    print()

    print("=== Timeline ===")
    print(f"  Wall time (first→last result): {wall:.0f}s ({wall / 60:.1f}min)")
    print(f"  CPU time (sum of all phases):  {cpu_total:.0f}s ({cpu_total / 60:.1f}min)")
    if wall > 0:
        print(f"  Parallelism factor:            {cpu_total / wall:.1f}x")
        print(f"  Throughput:                    {total / wall * 60:.1f} results/min")
    print()

    if phase_times:
        print("=== Phase Timing ===")
        header = f"{'Phase':25s} {'n':>5s} {'mean':>7s} {'p50':>7s} {'p95':>7s} {'total':>8s} {'pct':>5s}"
        print(header)
        print("-" * len(header))
        for phase in sorted(phase_times):
            t = phase_times[phase]
            n = len(t)
            s = sorted(t)
            tot = sum(s)
            mean = statistics.mean(s)
            p50 = s[n // 2]
            p95 = s[min(int(n * 0.95), n - 1)]
            pct = tot / cpu_total * 100 if cpu_total > 0 else 0
            print(
                f"  {phase:23s} {n:>5d} {mean:>6.1f}s {p50:>6.1f}s {p95:>6.1f}s {tot / 60:>7.1f}m {pct:>4.0f}%"
            )
        print()

    print("=== Error Categories ===")
    for cat, n in error_cats.most_common():
        print(f"  {cat:25s} {n:>5d} ({n * 100 // total:>2d}%)")
    print()

    print("=== Fix Sources ===")
    for src, n in sources.most_common():
        print(f"  {src:25s} {n:>5d}")
    print()

    top_repos = sorted(repo_blame.items(), key=lambda x: -x[1]["blame"])[:10]
    if top_repos and any(r[1]["blame"] > 0 for r in top_repos):
        print("=== Top Repo Hotspots (by blame time) ===")
        for repo, s in top_repos:
            if s["blame"] > 0:
                print(
                    f"  {repo:50s} {s['cves']:>3d} CVEs  {s['blame'] / 60:>5.1f}m  {s['errors']:>2d} err"
                )
        print()

    if buckets:
        print("=== Throughput Timeline (results/min) ===")
        max_min = max(buckets.keys())
        for m in range(max_min + 1):
            c = buckets.get(m, 0)
            bar = "#" * min(c, 80)
            print(f"  min {m:>2d}: {c:>4d} {bar}")
        print()

    # --- Diagnosis ---
    print("=== Diagnosis ===")
    issues = []

    if wall > 0 and cpu_total / wall > 2:
        issues.append(
            f"Good parallelism ({cpu_total / wall:.1f}x) — workers are utilized"
        )
    elif wall > 0:
        issues.append(
            f"Low parallelism ({cpu_total / wall:.1f}x) — workers mostly idle (rate-limit or setup bound)"
        )

    if "Phase B (blame)" in phase_times:
        bt = phase_times["Phase B (blame)"]
        s = sorted(bt)
        mean_b = statistics.mean(s)
        p95_b = s[min(int(len(s) * 0.95), len(s) - 1)]
        if p95_b > mean_b * 5:
            issues.append(
                f"Blame p95 ({p95_b:.1f}s) >> mean ({mean_b:.1f}s) — outlier repos dominating"
            )

    no_fix_pct = error_cats.get("no_fix_commits", 0) * 100 // max(total, 1)
    if no_fix_pct > 50:
        issues.append(f"{no_fix_pct}% of CVEs have no fix commits — consider pre-filtering")

    for i, issue in enumerate(issues, 1):
        print(f"  {i}. {issue}")
    if not issues:
        print("  No major issues detected.")
    print()


if __name__ == "__main__":
    main()
