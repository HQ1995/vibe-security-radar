#!/usr/bin/env python3
"""Pipeline performance profiler — single-command analysis of cached results."""

import json
import statistics
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
    verified_v = 0
    verdict_counts: Counter[str] = Counter()
    verdict_confidence: Counter[str] = Counter()
    verdict_models: Counter[str] = Counter()
    tool_calls_list: list[int] = []
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
        cat = d.get("error_category") or ""
        if not cat:
            cat = "success" if d.get("fix_commits") else "no_data"
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

        # Signals and deep verification
        if d.get("ai_signals"):
            signals += 1
        for b in d.get("bug_introducing_commits", []):
            vv = b.get("verification_verdict")
            tv = b.get("tribunal_verdict")
            if vv or tv:
                verified_v += 1
            if vv:
                verdict_counts[vv.get("verdict", "?")] += 1
                verdict_confidence[vv.get("confidence", "?")] += 1
                verdict_models[vv.get("model", "?")] += 1
                tc = vv.get("tool_calls_made", 0)
                if tc:
                    tool_calls_list.append(tc)
            elif tv:
                verdict_counts["tribunal:" + tv.get("verdict", "?")] += 1

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
    print(f"  Verified:   {verified_v}")
    print()

    if verdict_counts:
        print("=== Deep Verify ===")
        for v, n in verdict_counts.most_common():
            print(f"  {v:25s} {n:>5d}")
        if verdict_confidence:
            conf_str = ", ".join(
                f"{c} {n}" for c, n in verdict_confidence.most_common()
            )
            print(f"  confidence:  {conf_str}")
        if verdict_models:
            model_str = ", ".join(
                f"{m} ({n})" for m, n in verdict_models.most_common()
            )
            print(f"  models:      {model_str}")
        if tool_calls_list:
            tc_sorted = sorted(tool_calls_list)
            tc_mean = statistics.mean(tc_sorted)
            tc_p50 = tc_sorted[len(tc_sorted) // 2]
            tc_p95 = tc_sorted[min(int(len(tc_sorted) * 0.95), len(tc_sorted) - 1)]
            print(
                f"  tool calls:  mean {tc_mean:.0f}, p50 {tc_p50}, p95 {tc_p95} ({len(tool_calls_list)} BICs)"
            )
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

    if "Phase D (deep verify)" in phase_times:
        dv = phase_times["Phase D (deep verify)"]
        dv_sorted = sorted(dv)
        dv_mean = statistics.mean(dv_sorted)
        dv_total = sum(dv_sorted)
        confirmed = verdict_counts.get("CONFIRMED", 0)
        total_v = sum(verdict_counts.values())
        if total_v > 0:
            fp_rate = (1 - confirmed / total_v) * 100
            issues.append(
                f"Deep verify: {total_v} BICs checked, {confirmed} confirmed ({fp_rate:.0f}% filtered), "
                f"mean {dv_mean:.0f}s/CVE, {dv_total / 60:.0f}min total"
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
