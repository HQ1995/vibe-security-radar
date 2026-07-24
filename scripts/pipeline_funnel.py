#!/usr/bin/env python3
"""Pipeline funnel diagnostics — show where CVEs drop off at each stage."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from web_data.writer import load_published_web_data
from cve_analyzer.models import CveAnalysisResult
from cve_analyzer.screening_router import (
    ScreeningRouteStatus,
    evaluate_evidence_availability,
    route_for_screening,
)
from cve_analyzer.source_matcher import (
    bic_is_candidate,
    candidate_evidence_complete,
    match_result,
)

CACHE_DIR = Path(os.path.expanduser("~/.cache/cve-analyzer"))
RESULTS_DIR = CACHE_DIR / "results"
WEB_DATA_DIR = Path(__file__).resolve().parent.parent / "web" / "data"
DESC_SEARCH_DIR = CACHE_DIR / "desc-search"
FIX_INFERENCE_DIR = CACHE_DIR / "fix-inference"


def _pct(n: int, total: int) -> str:
    return f"{n / total * 100:.1f}%" if total else "—"


def _bar(n: int, total: int, width: int = 30) -> str:
    if not total:
        return ""
    filled = int(n / total * width)
    return f"[{'█' * filled}{'░' * (width - filled)}]"


def load_results() -> list[dict]:
    results = []
    for f in RESULTS_DIR.iterdir():
        if not f.name.endswith(".json"):
            continue
        try:
            with open(f) as fh:
                results.append(json.load(fh))
        except Exception:
            continue
    return results


def load_web_cves(data_dir: Path = WEB_DATA_DIR) -> dict[str, dict]:
    """Load one validated publication generation.

    A missing or inconsistent manifest is a diagnostic failure. Silently
    treating partial publication as an empty site would under-report funnel
    losses.
    """
    published = load_published_web_data(data_dir)
    return {entry["id"]: entry for entry in published.entries}


def production_funnel_counts(results: list[dict]) -> dict[str, int]:
    """Return the token-free production-v1 funnel over cached result JSON."""

    counts: Counter[str] = Counter()
    for payload in results:
        try:
            result = CveAnalysisResult.from_dict(payload)
        except (KeyError, TypeError, ValueError):
            counts["unreadable"] += 1
            continue
        counts["readable"] += 1
        decision = match_result(
            result, complete=candidate_evidence_complete(result)
        )
        route = route_for_screening(
            result,
            decision,
            evidence=evaluate_evidence_availability(result),
        )
        counts[f"route_{route.status.value}"] += 1
        counts[f"route_reason::{route.reason_code}"] += 1
        has_shadow = bool(result.ai_signals) or any(
            bic.all_ai_signals() for bic in result.bug_introducing_commits
        )
        if not decision.eligible:
            if has_shadow:
                counts["shadow_only"] += 1
            continue
        counts["source_match"] += 1
        if (
            route.status is ScreeningRouteStatus.SCREENABLE
            and result.screening is not None
            and result.screening.worth_investigating
        ):
            counts["screening_positive"] += 1
        if route.status is ScreeningRouteStatus.SCREENABLE and any(
            bic_is_candidate(bic)
            and isinstance(bic.deep_verification, dict)
            and str(
                bic.deep_verification.get("final_verdict")
                or bic.deep_verification.get("verdict")
                or ""
            ).upper()
            == "CONFIRMED"
            for bic in result.bug_introducing_commits
        ):
            counts["verification_confirmed"] += 1
    return dict(counts)


def analyze_funnel(results: list[dict]) -> None:
    total = len(results)
    production = production_funnel_counts(results)

    # Stage 1: Error categories (why CVEs fail early)
    error_cats: Counter[str] = Counter()
    no_error = 0
    for r in results:
        ec = r.get("error_category") or ""
        err = r.get("error") or ""
        if ec:
            error_cats[ec] += 1
        elif err:
            error_cats["other_error"] += 1
        else:
            no_error += 1

    # Stage 2: Fix commits
    has_fix = [r for r in results if r.get("fix_commits")]
    fix_sources: Counter[str] = Counter()
    for r in has_fix:
        sources = {fc.get("source", "unknown") for fc in r["fix_commits"]}
        for s in sources:
            fix_sources[s] += 1

    # Stage 3: BICs
    has_bic = [r for r in results if r.get("bug_introducing_commits")]
    bic_count = sum(len(r["bug_introducing_commits"]) for r in has_bic)
    blame_strategies: Counter[str] = Counter()
    for r in has_bic:
        for bic in r["bug_introducing_commits"]:
            blame_strategies[bic.get("blame_strategy", "unknown")] += 1

    # Stage 4: AI signals
    has_signals = [r for r in results if r.get("ai_signals")]
    signal_types: Counter[str] = Counter()
    tool_counts: Counter[str] = Counter()
    for r in has_signals:
        for s in r["ai_signals"]:
            signal_types[s.get("signal_type", "unknown")] += 1
            tool_counts[s.get("tool", "unknown")] += 1

    # Stage 5: Screening verification
    screening_verdicts: Counter[str] = Counter()
    for r in has_signals:
        for bic in r.get("bug_introducing_commits", []):
            sv = bic.get("screening_verification")
            if sv:
                screening_verdicts[sv.get("verdict", "unknown")] += 1

    # Stage 6: Deep verification
    deep_verdicts: Counter[str] = Counter()
    for r in results:
        for bic in r.get("bug_introducing_commits", []):
            dv = bic.get("deep_verification")
            if dv:
                deep_verdicts[dv.get("verdict", "unknown")] += 1

    # Stage 7: Confidence > 0
    has_confidence = [r for r in results if (r.get("ai_confidence") or 0) > 0]
    confidence_buckets: Counter[str] = Counter()
    for r in has_confidence:
        c = r["ai_confidence"]
        if c >= 0.7:
            confidence_buckets["high (≥0.7)"] += 1
        elif c >= 0.3:
            confidence_buckets["medium (0.3–0.7)"] += 1
        else:
            confidence_buckets["low (<0.3)"] += 1

    # Stage 8: Decomposition stats
    decomposed_bics = 0
    culprit_has_ai = 0
    culprit_no_ai = 0
    signals_removed = 0
    for r in results:
        for bic in r.get("bug_introducing_commits", []):
            dc = bic.get("decomposed_commits", [])
            if not dc:
                continue
            decomposed_bics += 1
            culprit_sha = bic.get("culprit_sha", "")
            if culprit_sha:
                culprit_dc = next((d for d in dc if d.get("sha") == culprit_sha), None)
                if culprit_dc and culprit_dc.get("ai_signals"):
                    culprit_has_ai += 1
                else:
                    culprit_no_ai += 1
                    # Check if squash-merge had signals that were removed
                    orig_signals = bic.get("commit", {}).get("ai_signals", [])
                    non_decomposed = [s for s in orig_signals
                                      if not s.get("signal_type", "").startswith("squash_decomposed")]
                    if not non_decomposed and any(
                        d.get("ai_signals") for d in dc if d.get("sha") != culprit_sha
                    ):
                        signals_removed += 1

    # Website
    web_cves = load_web_cves()
    web_ids = set(web_cves.keys())

    # ── Print funnel ────────────────────────────────────────────────
    print("=" * 70)
    print("PIPELINE FUNNEL DIAGNOSTICS")
    print("=" * 70)

    print(f"\n{'Stage':<45} {'Count':>7}  {'%':>6}  Visual")
    print("─" * 70)
    print(f"{'CVEs in cache':<45} {total:>7,}  {'100%':>6}  {_bar(total, total)}")
    print(f"{'  ├─ with errors':<45} {sum(error_cats.values()):>7,}  {_pct(sum(error_cats.values()), total):>6}")
    for cat, cnt in error_cats.most_common():
        print(f"{'  │    ' + cat:<45} {cnt:>7,}  {_pct(cnt, total):>6}")
    print(f"{'  └─ no errors':<45} {no_error:>7,}  {_pct(no_error, total):>6}")
    print()
    print(f"{'CVEs with fix commits':<45} {len(has_fix):>7,}  {_pct(len(has_fix), total):>6}  {_bar(len(has_fix), total)}")
    print(f"{'CVEs with BICs':<45} {len(has_bic):>7,}  {_pct(len(has_bic), total):>6}  {_bar(len(has_bic), total)}")
    print(f"{'  total BICs':<45} {bic_count:>7,}")
    print(f"{'CVEs with AI signals':<45} {len(has_signals):>7,}  {_pct(len(has_signals), total):>6}  {_bar(len(has_signals), total)}")
    print(f"{'CVEs with confidence > 0':<45} {len(has_confidence):>7,}  {_pct(len(has_confidence), total):>6}  {_bar(len(has_confidence), total)}")
    print(f"{'CVEs on website':<45} {len(web_ids):>7,}  {_pct(len(web_ids), total):>6}  {_bar(len(web_ids), total)}")

    print(f"\n{'=' * 70}")
    print("PRODUCTION V1 TOKEN-FREE FUNNEL (explicit AI authorship sources)")
    print("=" * 70)
    for label, key in (
        ("Readable cached results", "readable"),
        ("Explicit AI source matches", "source_match"),
        ("Route: screenable", "route_screenable"),
        ("Route: no screening value", "route_no_screening_value"),
        ("Route: deferred/retryable", "route_deferred_retryable"),
        ("Shadow-only signals (excluded)", "shadow_only"),
        ("Flash screening positives", "screening_positive"),
        ("Luna verification confirmed", "verification_confirmed"),
        ("Unreadable legacy results", "unreadable"),
    ):
        count = production.get(key, 0)
        print(f"  {label:<43} {count:>7,}  {_pct(count, total):>6}")
    route_reasons = Counter(
        {
            key.removeprefix("route_reason::"): count
            for key, count in production.items()
            if key.startswith("route_reason::")
        }
    )
    if route_reasons:
        print("  Route reasons:")
        for reason, count in route_reasons.most_common():
            print(f"    {reason:<41} {count:>7,}  {_pct(count, total):>6}")

    # ── Drop-off analysis ───────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print("DROP-OFF ANALYSIS (where CVEs get lost)")
    print("=" * 70)
    fix_no_bic = len(has_fix) - len(has_bic)
    bic_no_signal = len(has_bic) - len(has_signals)
    signal_no_confidence = len(has_signals) - len(has_confidence)
    confidence_not_on_web = len(has_confidence) - len(web_ids & {r["cve_id"] for r in has_confidence})

    drops = [
        ("Errors (no fix commits, clone failed, etc.)", sum(error_cats.values())),
        ("Have fix commits but no BICs from blame", fix_no_bic),
        ("Have BICs but no AI signals detected", bic_no_signal),
        ("Have AI signals but confidence = 0", signal_no_confidence),
        ("Have confidence but not on website", confidence_not_on_web),
    ]
    for label, cnt in drops:
        print(f"  {label:<50} {cnt:>7,}  {_pct(cnt, total):>6}")

    # ── Fix commit sources ──────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print("FIX COMMIT SOURCES")
    print("=" * 70)
    for src, cnt in fix_sources.most_common():
        print(f"  {src:<40} {cnt:>7,}")

    # ── Blame strategies ────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print(f"BLAME STRATEGIES ({bic_count:,} total BICs)")
    print("=" * 70)
    for strat, cnt in blame_strategies.most_common():
        print(f"  {strat:<40} {cnt:>7,}  {_pct(cnt, bic_count):>6}")

    # ── AI tools detected ───────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print("AI TOOLS DETECTED")
    print("=" * 70)
    for tool, cnt in tool_counts.most_common(15):
        print(f"  {tool:<40} {cnt:>7,}")

    # ── Signal types ────────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print("SIGNAL TYPES (top 15)")
    print("=" * 70)
    for st, cnt in signal_types.most_common(15):
        print(f"  {st:<45} {cnt:>7,}")

    # ── Screening verdicts ──────────────────────────────────────────
    if screening_verdicts:
        print(f"\n{'=' * 70}")
        print("SCREENING VERDICTS (LLM quick check)")
        print("=" * 70)
        for v, cnt in screening_verdicts.most_common():
            print(f"  {v:<40} {cnt:>7,}")

    # ── Deep verification ───────────────────────────────────────────
    if deep_verdicts:
        print(f"\n{'=' * 70}")
        print("DEEP VERIFICATION VERDICTS")
        print("=" * 70)
        for v, cnt in deep_verdicts.most_common():
            print(f"  {v:<40} {cnt:>7,}")

    # ── Decomposition ───────────────────────────────────────────────
    if decomposed_bics:
        print(f"\n{'=' * 70}")
        print("SQUASH-MERGE DECOMPOSITION")
        print("=" * 70)
        print(f"  {'BICs decomposed':<40} {decomposed_bics:>7,}")
        print(f"  {'Culprit HAS AI signal (kept)':<40} {culprit_has_ai:>7,}")
        print(f"  {'Culprit NO AI signal (FP removed)':<40} {culprit_no_ai:>7,}")
        if signals_removed:
            print(f"  {'Signals removed (AI ≠ root cause)':<40} {signals_removed:>7,}")

    # ── Confidence distribution ─────────────────────────────────────
    if confidence_buckets:
        print(f"\n{'=' * 70}")
        print("CONFIDENCE DISTRIBUTION")
        print("=" * 70)
        for bucket, cnt in sorted(confidence_buckets.items()):
            print(f"  {bucket:<40} {cnt:>7,}")

    # ── Desc-search / fix-inference stats ───────────────────────────
    print(f"\n{'=' * 70}")
    print("AUXILIARY CACHES")
    print("=" * 70)
    if DESC_SEARCH_DIR.exists():
        ds_total = sum(1 for f in DESC_SEARCH_DIR.iterdir() if f.suffix == ".json")
        ds_found = 0
        for f in DESC_SEARCH_DIR.iterdir():
            if f.suffix != ".json":
                continue
            try:
                with open(f) as fh:
                    d = json.load(fh)
                if d.get("status") == "FOUND":
                    ds_found += 1
            except Exception:
                pass
        print(f"  {'desc-search attempts':<40} {ds_total:>7,}")
        print(f"  {'desc-search FOUND':<40} {ds_found:>7,}  {_pct(ds_found, ds_total):>6}")

    if FIX_INFERENCE_DIR.exists():
        fi_total = sum(1 for f in FIX_INFERENCE_DIR.iterdir() if f.suffix == ".json")
        fi_statuses: Counter[str] = Counter()
        for f in FIX_INFERENCE_DIR.iterdir():
            if f.suffix != ".json":
                continue
            try:
                with open(f) as fh:
                    d = json.load(fh)
                fi_statuses[d.get("status", "unknown")] += 1
            except Exception:
                pass
        print(f"  {'fix-inference attempts':<40} {fi_total:>7,}")
        for st, cnt in fi_statuses.most_common():
            print(f"    {st:<38} {cnt:>7,}  {_pct(cnt, fi_total):>6}")

    # ── Website summary ─────────────────────────────────────────────
    if web_cves:
        print(f"\n{'=' * 70}")
        print(f"WEBSITE SUMMARY ({len(web_cves)} CVEs)")
        print("=" * 70)
        web_tools: Counter[str] = Counter()
        web_verdicts: Counter[str] = Counter()
        web_conf: list[float] = []
        for cve in web_cves.values():
            for t in cve.get("ai_tools", []):
                web_tools[t] += 1
            web_verdicts[cve.get("verdict", "unknown")] += 1
            web_conf.append(cve.get("confidence", 0))

        print("  Verdicts:")
        for v, cnt in web_verdicts.most_common():
            print(f"    {v:<38} {cnt:>7,}")
        print("  AI tools:")
        for t, cnt in web_tools.most_common():
            print(f"    {t:<38} {cnt:>7,}")
        if web_conf:
            print(f"  Confidence: min={min(web_conf):.2f}  median={sorted(web_conf)[len(web_conf)//2]:.2f}  max={max(web_conf):.2f}")


def _in_coverage_window(r: dict, since: str) -> bool:
    """Check if a result falls within the coverage window (>= since)."""
    cve_id = r.get("cve_id", "")
    year = int(since[:4]) if len(since) >= 4 else 0
    if cve_id.startswith("CVE-"):
        parts = cve_id.split("-")
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1]) >= year
    # GHSA, OSV, etc. — include conservatively
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Pipeline funnel diagnostics")
    parser.add_argument("--since", default="2025-05",
                        help="Coverage window start (YYYY-MM, default: 2025-05)")
    parser.add_argument("--all", action="store_true",
                        help="Include all cached results (no date filter)")
    args = parser.parse_args()

    if not RESULTS_DIR.exists():
        print(f"No results directory at {RESULTS_DIR}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading results from {RESULTS_DIR} ...")
    results = load_results()
    total_loaded = len(results)

    if not args.all:
        results = [r for r in results if _in_coverage_window(r, args.since)]
        print(f"Loaded {total_loaded:,} cached results, {len(results):,} in coverage window (>= {args.since}).\n")
    else:
        print(f"Loaded {total_loaded:,} cached results (no date filter).\n")

    analyze_funnel(results)


if __name__ == "__main__":
    main()
