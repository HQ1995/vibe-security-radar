#!/usr/bin/env python3
"""Generate web-friendly seed data from cached CVE analysis results.

Thin orchestrator that imports from the web_data package and cve_analyzer.
Reads cached results, filters, transforms, and writes:
  - web/data/cves.json   (individual CVE entries)
  - web/data/stats.json  (aggregate statistics)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# sys.path setup — make cve_analyzer and web_data importable
# ---------------------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_CVE_SRC = os.path.join(_SCRIPT_DIR, "..", "cve-analyzer", "src")
if _CVE_SRC not in sys.path:
    sys.path.insert(0, _CVE_SRC)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from web_data.constants import DEFAULT_CACHE_DIR, DEFAULT_NVD_FEEDS_DIR, DEFAULT_GHSA_DB_DIR, DEFAULT_OUTPUT_DIR  # noqa: E402
from web_data.loader import (  # noqa: E402
    load_cached_results,
    load_reviews,
    load_nvd_published_dates,
    load_ghsa_published_dates,
    load_ghsa_severities,
    load_fix_commit_dates,
    fetch_ghsa_published_dates_api,
    build_alias_map,
    load_audit_overrides,
    load_audit_override_details,
)
from web_data.filters import should_include  # noqa: E402
from web_data.entry_builder import build_entry  # noqa: E402
from web_data.stats import build_stats  # noqa: E402


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint: load, filter, transform, and write seed data."""
    parser = argparse.ArgumentParser(
        description="Generate web seed data from cached CVE analysis results."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for JSON files (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--cache-dir",
        type=str,
        default=DEFAULT_CACHE_DIR,
        help=f"Directory with cached analysis results (default: {DEFAULT_CACHE_DIR})",
    )
    parser.add_argument(
        "--since",
        type=str,
        default="2025-05",
        help="Coverage start month YYYY-MM for total_analyzed count (default: 2025-05)",
    )
    args = parser.parse_args(argv)

    # ------------------------------------------------------------------
    # 1. Load cached results (CveAnalysisResult objects)
    # ------------------------------------------------------------------
    print(f"Loading cached results from {args.cache_dir} ...")
    results = load_cached_results(args.cache_dir)
    print(f"  Found {len(results)} cached results.")

    # ------------------------------------------------------------------
    # 2. Load supplementary data sources
    # ------------------------------------------------------------------
    reviews = load_reviews()
    print(f"  Found {len(reviews)} reviews.")

    print(f"Loading NVD published dates from {DEFAULT_NVD_FEEDS_DIR} ...")
    nvd_dates = load_nvd_published_dates()
    print(f"  Indexed {len(nvd_dates)} CVE published dates.")

    print(f"Loading GHSA published dates from {DEFAULT_GHSA_DB_DIR} ...")
    ghsa_dates = load_ghsa_published_dates()
    print(f"  Indexed {len(ghsa_dates)} GHSA published dates.")

    print(f"Loading GHSA severities from {DEFAULT_GHSA_DB_DIR} ...")
    ghsa_severities = load_ghsa_severities()
    print(f"  Indexed {len(ghsa_severities)} GHSA severity entries.")

    # ------------------------------------------------------------------
    # 3. Merge date sources: NVD takes precedence, GHSA fills gaps
    # ------------------------------------------------------------------
    nvd_dates.update({k: v for k, v in ghsa_dates.items() if k not in nvd_dates})

    # ------------------------------------------------------------------
    # 4. Load audit overrides
    # ------------------------------------------------------------------
    audit_override_ids = load_audit_overrides()

    # ------------------------------------------------------------------
    # 5. Filter: should_include() per result
    # ------------------------------------------------------------------
    filtered = [r for r in results if should_include(r, audit_override_ids)]
    excluded = len(results) - len(filtered)
    print(f"  {len(filtered)} results with confirmed AI involvement.")
    if excluded:
        print(f"  ({excluded} excluded by filter)")

    # ------------------------------------------------------------------
    # 6. Fetch missing GHSA published dates via API
    # ------------------------------------------------------------------
    missing_ghsa_ids = [
        r.cve_id for r in filtered
        if r.cve_id.startswith("GHSA-") and r.cve_id not in nvd_dates
    ]
    if missing_ghsa_ids:
        print(f"Fetching {len(missing_ghsa_ids)} missing GHSA published dates via API ...")
        api_dates = fetch_ghsa_published_dates_api(missing_ghsa_ids)
        nvd_dates.update(api_dates)
        print(f"  Resolved {len(api_dates)} of {len(missing_ghsa_ids)} via API.")

    # ------------------------------------------------------------------
    # 7. Fix commit date fallback from local repos
    # ------------------------------------------------------------------
    still_missing = [r for r in filtered if r.cve_id not in nvd_dates]
    if still_missing:
        print(f"Looking up {len(still_missing)} fix commit dates from local repos ...")
        commit_dates = load_fix_commit_dates(still_missing)
        nvd_dates.update(commit_dates)
        print(f"  Resolved {len(commit_dates)} of {len(still_missing)} from git history.")

    # ------------------------------------------------------------------
    # 8. Build entries
    # ------------------------------------------------------------------
    entries = [
        e for e in (
            build_entry(r, nvd_dates, ghsa_severities, reviews, audit_override_ids)
            for r in filtered
        )
        if e is not None
    ]

    # ------------------------------------------------------------------
    # 9. Post-process: audit override tool injection
    # ------------------------------------------------------------------
    override_details = load_audit_override_details()
    for e in entries:
        if not e.get("ai_tools") and e["id"] in audit_override_ids:
            detail = override_details.get(e["id"], {})
            if "tools" in detail:
                e["ai_tools"] = detail["tools"]

    # ------------------------------------------------------------------
    # 10. Exclude entries with no ai_tools
    # ------------------------------------------------------------------
    no_tools = [
        e for e in entries
        if not e.get("ai_tools") and e["id"] not in audit_override_ids
    ]
    if no_tools:
        print(f"  Excluded {len(no_tools)} CVEs with no displayable AI tool (signals filtered by verdict or origin).")
    entries = [e for e in entries if e.get("ai_tools") or e["id"] in audit_override_ids]

    # ------------------------------------------------------------------
    # 11. Alias deduplication
    # ------------------------------------------------------------------
    alias_map = build_alias_map()
    seen_canonical: dict[str, dict] = {}
    deduped_entries: list[dict] = []
    for e in entries:
        eid = e["id"]
        canonical = min(alias_map.get(eid, {eid}))
        if canonical in seen_canonical:
            existing = seen_canonical[canonical]
            # Prefer CVE-* over GHSA-*
            if eid.startswith("CVE-") and not existing["id"].startswith("CVE-"):
                seen_canonical[canonical] = e
                deduped_entries = [x if x["id"] != existing["id"] else e for x in deduped_entries]
                print(f"  Dedup: {existing['id']} replaced by {eid} (alias)")
            else:
                print(f"  Dedup: {eid} dropped (alias of {existing['id']})")
        else:
            seen_canonical[canonical] = e
            deduped_entries.append(e)
    if len(deduped_entries) < len(entries):
        print(f"  Deduplicated {len(entries) - len(deduped_entries)} alias entries.")
    entries = deduped_entries

    # ------------------------------------------------------------------
    # 12. Sort: CONFIRMED-first, then confidence descending
    # ------------------------------------------------------------------
    entries = sorted(
        entries,
        key=lambda e: (
            any(
                (bc.get("screening_verification") or bc.get("llm_verdict") or {}).get("verdict") == "CONFIRMED"
                for bc in e.get("bug_commits", [])
            ),
            e.get("confidence", 0),
        ),
        reverse=True,
    )

    # ------------------------------------------------------------------
    # 13. Coverage stats
    # ------------------------------------------------------------------
    coverage_since = args.since
    coverage_year = int(coverage_since[:4]) if coverage_since else 0
    if coverage_since:
        total_in_range = 0
        with_fix_commits = 0
        for result in results:  # all results, not just filtered
            pub = nvd_dates.get(result.cve_id, "")
            in_range = False
            if pub:
                in_range = pub[:7] >= coverage_since
            elif result.cve_id.startswith("CVE-"):
                parts = result.cve_id.split("-")
                in_range = len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) >= coverage_year
            else:
                in_range = True  # GHSA etc — include conservatively
            if in_range:
                total_in_range += 1
                if any(fc.sha for fc in result.fix_commits):
                    with_fix_commits += 1
        print(f"  {total_in_range} of {len(results)} results within coverage window (>= {coverage_since}).")
        if total_in_range > 0:
            print(f"  {with_fix_commits} with fix commits ({100*with_fix_commits/total_in_range:.1f}%), {total_in_range - with_fix_commits} without.")
    else:
        total_in_range = len(results)
        with_fix_commits = sum(
            1 for result in results
            if any(fc.sha for fc in result.fix_commits)
        )

    # ------------------------------------------------------------------
    # 14. Build stats
    # ------------------------------------------------------------------
    stats_output = build_stats(
        entries,
        total_analyzed=total_in_range,
        with_fix_commits=with_fix_commits,
        coverage_since=coverage_since,
    )

    # ------------------------------------------------------------------
    # 15. Write output
    # ------------------------------------------------------------------
    cves_output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(entries),
        "cves": entries,
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cves_path = output_dir / "cves.json"
    with open(cves_path, "w", encoding="utf-8") as fh:
        json.dump(cves_output, fh, indent=2, ensure_ascii=False)
    print(f"  Wrote {cves_path} ({len(entries)} CVEs)")

    stats_path = output_dir / "stats.json"
    with open(stats_path, "w", encoding="utf-8") as fh:
        json.dump(stats_output, fh, indent=2, ensure_ascii=False)
    print(f"  Wrote {stats_path}")

    # ------------------------------------------------------------------
    # 16. Summary
    # ------------------------------------------------------------------
    print("\nDone!")
    for entry in entries:
        tools = ", ".join(entry["ai_tools"]) or "(none)"
        print(f"  {entry['id']}: confidence={entry['confidence']} tools=[{tools}] severity={entry['severity']}")


if __name__ == "__main__":
    main()
