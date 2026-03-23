"""Statistics aggregation for web CVE entries.

Operates on web entry dicts (output of entry_builder), not model objects.
"""

from __future__ import annotations

from datetime import datetime, timezone

from web_data.loader import _parse_github_owner_repo


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _repo_url_to_display_name(repo_url: str) -> str | None:
    """Extract 'owner/repo' from a GitHub URL, lowercased for dedup.

    Returns None for non-GitHub or unparseable URLs.
    """
    parts = _parse_github_owner_repo(repo_url)
    return f"{parts[0]}/{parts[1]}".lower() if parts else None


def _extract_month(entry: dict, published: str) -> str:
    """Extract a YYYY-MM string from the entry's published date.

    Uses the CVE publication date (from NVD or CVE ID year).
    """
    if published and len(published) >= 7:
        return published[:7]
    if published and len(published) == 4:
        return published
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_stats(
    entries: list[dict],
    *,
    total_analyzed: int = 0,
    with_fix_commits: int = 0,
    coverage_since: str = "",
) -> dict:
    """Aggregate statistics from a list of web CVE entries."""
    by_tool: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_language: dict[str, int] = {}
    by_repo: dict[str, int] = {}
    month_counts: dict[str, int] = {}
    month_tool_counts: dict[str, dict[str, int]] = {}

    for entry in entries:
        # Tools
        for tool in entry.get("ai_tools", []):
            by_tool[tool] = by_tool.get(tool, 0) + 1

        # Languages (count each CVE once per language it touches)
        for lang in entry.get("languages", []):
            by_language[lang] = by_language.get(lang, 0) + 1

        # Repos (count each CVE once per unique repo)
        seen_repos: set[str] = set()
        for fc in entry.get("fix_commits", []):
            name = _repo_url_to_display_name(fc.get("repo_url", ""))
            if name and name not in seen_repos:
                seen_repos.add(name)
                by_repo[name] = by_repo.get(name, 0) + 1

        # Severity
        sev = entry.get("severity", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        # Monthly (use published year + first bug commit month, or just year-month)
        published = entry.get("published", "")
        month_key = _extract_month(entry, published)
        if month_key:
            month_counts[month_key] = month_counts.get(month_key, 0) + 1
            if month_key not in month_tool_counts:
                month_tool_counts[month_key] = {}
            for tool in entry.get("ai_tools", []):
                month_tool_counts[month_key][tool] = (
                    month_tool_counts[month_key].get(tool, 0) + 1
                )

    by_month = [
        {"month": m, "count": c, "by_tool": month_tool_counts.get(m, {})}
        for m, c in sorted(month_counts.items())
    ]

    sorted_months = sorted(month_counts.keys())
    # Use day-level precision for coverage range
    if coverage_since:
        # Expand "2025-05" to "2025-05-01"
        coverage_from = coverage_since if len(coverage_since) > 7 else f"{coverage_since}-01"
    else:
        coverage_from = f"{sorted_months[0]}-01" if sorted_months else ""
    # Find the latest published date across all entries
    latest_date = ""
    for e in entries:
        pub = e.get("published", "")[:10]  # "YYYY-MM-DD" prefix
        if pub > latest_date:
            latest_date = pub
    coverage_to = latest_date or (f"{sorted_months[-1]}-01" if sorted_months else "")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_cves": len(entries),
        "total_analyzed": total_analyzed,
        "with_fix_commits": with_fix_commits,
        "coverage_from": coverage_from,
        "coverage_to": coverage_to,
        "by_tool": by_tool,
        "by_severity": by_severity,
        "by_language": by_language,
        "by_repo": by_repo,
        "by_month": by_month,
    }
