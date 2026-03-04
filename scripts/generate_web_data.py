#!/usr/bin/env python3
"""Generate web-friendly seed data from cached CVE analysis results.

Reads cached results from ~/.cache/cve-analyzer/results/*.json,
filters to those with AI signals, transforms them into a web-friendly
format, and writes two JSON files for the Next.js app:
  - web/data/cves.json   (individual CVE entries)
  - web/data/stats.json  (aggregate statistics)

No external dependencies required -- stdlib only.
"""

from __future__ import annotations

import argparse
import glob
import gzip
import json
import math
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CACHE_DIR = os.path.expanduser("~/.cache/cve-analyzer/results")
DEFAULT_REVIEWS_DIR = os.path.expanduser("~/.cache/cve-analyzer/reviews")
DEFAULT_NVD_FEEDS_DIR = os.path.expanduser("~/.cache/cve-analyzer/nvd-feeds")
DEFAULT_GHSA_DB_DIR = os.path.expanduser(
    "~/.cache/cve-analyzer/advisory-database/advisories"
)
DEFAULT_REPOS_DIR = os.path.expanduser("~/.cache/cve-analyzer/repos")
DEFAULT_OUTPUT_DIR = "web/data"
DEFAULT_MIN_CONFIDENCE = 0.0


# ---------------------------------------------------------------------------
# CVSS 3.1 scoring (simplified but accurate for common vectors)
# ---------------------------------------------------------------------------

# Metric value weights from the CVSS v3.1 specification
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _parse_cvss_vector(vector_str: str) -> dict[str, str]:
    """Parse a CVSS:3.x vector string into a dict of metric -> value.

    Example: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    Returns: {"AV": "N", "AC": "L", "PR": "L", ...}
    """
    metrics: dict[str, str] = {}
    if not vector_str or not vector_str.startswith("CVSS:3"):
        return metrics

    # Strip the "CVSS:3.x/" prefix
    parts = vector_str.split("/")
    for part in parts[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    return metrics


def _compute_cvss_score(metrics: dict[str, str]) -> float:
    """Compute a CVSS 3.1 base score from parsed metric values.

    Implements the official CVSS 3.1 scoring algorithm.
    Returns 0.0 if metrics are incomplete or invalid.
    """
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"

        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        pr = pr_table[metrics["PR"]]

        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError:
        return 0.0

    # Impact Sub-Score (ISS)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    # Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # Base Score
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    # Round up to one decimal (CVSS spec: "round up")
    return math.ceil(base * 10) / 10


def _extract_cvss_score(severity_str: str) -> float:
    """Extract a numeric CVSS score from a CVSS vector string.

    Handles CVSS V3 (exact) and V4 (approximate).
    Returns 0.0 for empty or unparseable strings.
    """
    if not severity_str:
        return 0.0
    # CVSS V3: exact scoring
    if severity_str.startswith("CVSS:3"):
        metrics = _parse_cvss_vector(severity_str)
        if metrics:
            return _compute_cvss_score(metrics)
    # CVSS V4: approximate from severity label
    if severity_str.startswith("CVSS:4"):
        label = _parse_cvss4_severity(severity_str)
        # Return midpoint of range as approximate score
        approx = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.5}
        return approx.get(label, 0.0)
    return 0.0


def _parse_cvss4_severity(vector_str: str) -> str:
    """Approximate severity label from a CVSS 4.0 vector string.

    CVSS 4.0 scoring is complex; we approximate using the impact metrics
    (VC/VI/VA for the vulnerable system) and exploitability (AV/AC/AT/PR/UI).

    Returns one of: CRITICAL, HIGH, MEDIUM, LOW, or empty string if unparseable.
    """
    if not vector_str or not vector_str.startswith("CVSS:4"):
        return ""

    metrics: dict[str, str] = {}
    parts = vector_str.split("/")
    for part in parts[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value

    # Vulnerable system impact: VC, VI, VA (H=High, L=Low, N=None)
    vc = metrics.get("VC", "N")
    vi = metrics.get("VI", "N")
    va = metrics.get("VA", "N")

    # Exploitability factors
    av = metrics.get("AV", "N")  # N=Network, A=Adjacent, L=Local, P=Physical
    ac = metrics.get("AC", "L")  # L=Low, H=High
    pr = metrics.get("PR", "N")  # N=None, L=Low, H=High
    ui = metrics.get("UI", "N")  # N=None, P=Passive, A=Active

    # Simple heuristic scoring
    impact_high = sum(1 for x in (vc, vi, va) if x == "H")
    impact_low = sum(1 for x in (vc, vi, va) if x == "L")
    no_impact = (vc == "N" and vi == "N" and va == "N")

    if no_impact:
        # Check subsequent system impact (SC/SI/SA)
        sc = metrics.get("SC", "N")
        si = metrics.get("SI", "N")
        sa = metrics.get("SA", "N")
        sub_high = sum(1 for x in (sc, si, sa) if x == "H")
        sub_low = sum(1 for x in (sc, si, sa) if x == "L")
        if sub_high == 0 and sub_low == 0:
            return "LOW"
        impact_high = sub_high
        impact_low = sub_low

    easy_exploit = (av == "N" and ac == "L" and pr == "N" and ui == "N")
    moderate_exploit = (av == "N" and ac == "L")

    if impact_high >= 3 and easy_exploit:
        return "CRITICAL"
    if impact_high >= 2 and moderate_exploit:
        return "CRITICAL" if easy_exploit else "HIGH"
    if impact_high >= 1:
        return "HIGH" if moderate_exploit else "MEDIUM"
    if impact_low >= 2:
        return "MEDIUM" if moderate_exploit else "LOW"
    if impact_low >= 1:
        return "LOW"
    return "LOW"


def _parse_severity_label(severity_str: str) -> str:
    """Convert a severity string to a label.

    Handles: CVSS V3 vectors, CVSS V4 vectors, plain text labels.
    Returns one of: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.
    """
    if not severity_str:
        return "UNKNOWN"

    # Plain text label (from GitHub Advisory API or GHSA database_specific)
    upper = severity_str.strip().upper()
    if upper == "MODERATE":
        upper = "MEDIUM"
    if upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return upper

    # CVSS V3 vector
    if severity_str.startswith("CVSS:3"):
        score = _extract_cvss_score(severity_str)
        if score > 0:
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"

    # CVSS V4 vector
    if severity_str.startswith("CVSS:4"):
        label = _parse_cvss4_severity(severity_str)
        if label:
            return label

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_cached_results(cache_dir: str = DEFAULT_CACHE_DIR) -> list[dict]:
    """Read all JSON files from the cache directory.

    Returns a list of parsed dicts (one per file). Skips non-JSON files
    and files that fail to parse (with a warning to stderr).
    """
    results: list[dict] = []
    pattern = os.path.join(cache_dir, "*.json")
    for filepath in sorted(glob.glob(pattern)):
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            results.append(data)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Warning: skipping {filepath}: {exc}", file=sys.stderr)
    return results


def load_reviews(reviews_dir: str = DEFAULT_REVIEWS_DIR) -> dict[str, dict]:
    """Read all review JSON files and return a dict keyed by cve_id.

    Returns an empty dict if the directory does not exist.
    """
    reviews: dict[str, dict] = {}
    if not os.path.isdir(reviews_dir):
        return reviews
    pattern = os.path.join(reviews_dir, "*.json")
    for filepath in sorted(glob.glob(pattern)):
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            cve_id = data.get("cve_id", "")
            if cve_id:
                reviews[cve_id] = data
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Warning: skipping review {filepath}: {exc}", file=sys.stderr)
    return reviews


def load_nvd_published_dates(
    nvd_feeds_dir: str = DEFAULT_NVD_FEEDS_DIR,
) -> dict[str, str]:
    """Build a {cve_id: published_date} index from NVD feed .json.gz files.

    The published_date is an ISO 8601 string like "2025-10-03T19:15:43.490".
    Returns an empty dict if the feeds directory does not exist.
    """
    index: dict[str, str] = {}
    if not os.path.isdir(nvd_feeds_dir):
        return index
    pattern = os.path.join(nvd_feeds_dir, "*.json.gz")
    for filepath in sorted(glob.glob(pattern)):
        try:
            with gzip.open(filepath, "rt", encoding="utf-8") as fh:
                feed = json.load(fh)
            for vuln in feed.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                published = cve.get("published", "")
                if cve_id and published:
                    index[cve_id] = published
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Warning: skipping NVD feed {filepath}: {exc}", file=sys.stderr)
    return index


def load_ghsa_published_dates(
    ghsa_db_dir: str = DEFAULT_GHSA_DB_DIR,
) -> dict[str, str]:
    """Build a {ghsa_id: published_date} index from the GHSA advisory DB.

    Scans github-reviewed and github-unreviewed directories.
    Returns an empty dict if the directory does not exist.
    """
    index: dict[str, str] = {}
    if not os.path.isdir(ghsa_db_dir):
        return index
    for subdir in ("github-reviewed", "github-unreviewed"):
        pattern = os.path.join(ghsa_db_dir, subdir, "**", "*.json")
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                ghsa_id = data.get("id", "")
                published = data.get("published", "")
                if ghsa_id and published:
                    index[ghsa_id] = published
            except (json.JSONDecodeError, OSError):
                pass
    return index


def _repo_url_to_dir(repo_url: str) -> str | None:
    """Convert a GitHub repo URL to a local cache directory name (owner_repo)."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/*$", repo_url.rstrip("/"))
    if m:
        return f"{m.group(1)}_{m.group(2)}"
    return None


def load_fix_commit_dates(
    results: list[dict],
    repos_dir: str = DEFAULT_REPOS_DIR,
) -> dict[str, str]:
    """Extract published dates from fix commit timestamps in local git repos.

    For each result without a published date, looks up the earliest fix commit
    date in the locally cloned repository. Returns {cve_id: date_iso}.
    """
    index: dict[str, str] = {}
    if not os.path.isdir(repos_dir):
        return index

    for result in results:
        cve_id = result.get("cve_id", "")
        fix_commits = result.get("fix_commits", [])
        if not fix_commits:
            continue

        # Find repo dir from first fix commit
        repo_url = fix_commits[0].get("repo_url", "")
        repo_dir_name = _repo_url_to_dir(repo_url)
        if not repo_dir_name:
            continue

        repo_path = os.path.join(repos_dir, repo_dir_name)
        if not os.path.isdir(repo_path):
            continue

        # Get the earliest fix commit date
        earliest_dt: datetime | None = None
        earliest_str: str | None = None
        for fc in fix_commits:
            sha = fc.get("sha", "")
            if not sha or not re.fullmatch(r"[0-9a-fA-F]+", sha):
                continue
            try:
                out = subprocess.run(
                    ["git", "log", "--format=%aI", "-1", sha],
                    cwd=repo_path, capture_output=True, text=True, timeout=5,
                )
                if out.returncode == 0 and out.stdout.strip():
                    date_str = out.stdout.strip()
                    dt = datetime.fromisoformat(date_str)
                    if earliest_dt is None or dt < earliest_dt:
                        earliest_dt = dt
                        earliest_str = date_str
            except (subprocess.TimeoutExpired, OSError, ValueError):
                pass

        if earliest_str:
            index[cve_id] = earliest_str

    return index


def fetch_ghsa_published_dates_api(
    ghsa_ids: list[str],
) -> dict[str, str]:
    """Fetch published dates for GHSA IDs via the GitHub REST API.

    Requires GITHUB_TOKEN in the environment. Returns {ghsa_id: published_iso}
    for successfully resolved entries; silently skips failures.
    """
    token = os.environ.get("GITHUB_TOKEN", "")
    index: dict[str, str] = {}
    for i, ghsa_id in enumerate(ghsa_ids):
        if i > 0:
            time.sleep(0.72)  # ~1.39 req/s, matching GitHubAdvisoryRateLimiter
        url = f"https://api.github.com/advisories/{ghsa_id}"
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            published = data.get("published_at", "")
            if published:
                index[ghsa_id] = published
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
            pass
    return index


# GHSA severity uses "MODERATE" but our website uses "MEDIUM"
_GHSA_SEV_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def load_ghsa_severities(
    ghsa_db_dir: str = DEFAULT_GHSA_DB_DIR,
) -> dict[str, str]:
    """Build a {vuln_id: severity} index from the GHSA advisory DB.

    Maps both the GHSA ID and all aliases (CVE-xxxx, PYSEC-xxxx, etc.)
    to the normalized severity label.
    """
    index: dict[str, str] = {}
    if not os.path.isdir(ghsa_db_dir):
        return index
    for subdir in ("github-reviewed", "github-unreviewed"):
        pattern = os.path.join(ghsa_db_dir, subdir, "**", "*.json")
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                raw_sev = data.get("database_specific", {}).get("severity", "")
                normalized = _GHSA_SEV_MAP.get(raw_sev.upper(), "")
                if not normalized:
                    continue
                ghsa_id = data.get("id", "")
                aliases = data.get("aliases", [])
                for vid in [ghsa_id] + aliases:
                    if vid:
                        index[vid] = normalized
            except (json.JSONDecodeError, OSError):
                pass
    return index


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def _is_all_negative_verdict(result: dict) -> bool:
    """Return True if every AI-signaled BIC has an LLM verdict of UNLIKELY or UNRELATED.

    CVEs where the LLM determined that *none* of the AI-authored commits
    actually introduced the vulnerability are false positives and should
    be excluded from the website.

    Returns False (keep) when:
    - No BICs have AI signals (shouldn't happen for AI results, but safe)
    - Any BIC with AI signals lacks an LLM verdict (benefit of the doubt)
    - Any BIC has a CONFIRMED verdict
    """
    ai_bics = [
        bic for bic in result.get("bug_introducing_commits", [])
        if bic.get("commit", {}).get("ai_signals")
    ]
    if not ai_bics:
        return False

    for bic in ai_bics:
        llm_v = bic.get("llm_verdict")
        if not llm_v or not llm_v.get("verdict"):
            # No verdict → keep (benefit of the doubt)
            return False
        if llm_v["verdict"] == "CONFIRMED":
            return False

    # All AI BICs have verdicts and none are CONFIRMED
    return True


def filter_ai_results(
    results: list[dict],
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
) -> list[dict]:
    """Keep only results whose recomputed AI confidence is above zero and meets the threshold.

    Also excludes results with errors or where LLM verification
    determined that all AI-signaled bug-introducing commits are
    UNLIKELY or UNRELATED (false positives from coarse git blame).
    """
    filtered = []
    excluded_by_verdict = 0
    for r in results:
        conf = _recompute_ai_confidence(r)
        if conf <= 0:
            continue
        if conf < min_confidence:
            continue
        if r.get("error", ""):
            continue
        if _is_all_negative_verdict(r):
            excluded_by_verdict += 1
            continue
        filtered.append(r)
    if excluded_by_verdict:
        print(f"  Excluded {excluded_by_verdict} CVEs with all-negative LLM verdicts.")
    return filtered


# ---------------------------------------------------------------------------
# Transformation
# ---------------------------------------------------------------------------

def _extract_published_year(result: dict) -> str:
    """Extract the publication year from the CVE ID or bug commit dates.

    Falls back to empty string if nothing can be determined.
    """
    cve_id = result.get("cve_id", "")
    # CVE-YYYY-NNNNN format
    if cve_id.startswith("CVE-"):
        parts = cve_id.split("-")
        if len(parts) >= 2 and parts[1].isdigit():
            return parts[1]
    return ""


def _first_line(message: str) -> str:
    """Return only the first line of a multi-line commit message."""
    if not message:
        return ""
    return message.split("\n")[0].strip()


def _build_bug_commit(bic: dict) -> dict:
    """Transform a bug_introducing_commit entry into the web format."""
    commit = bic.get("commit", {})
    llm_v = bic.get("llm_verdict")
    return {
        "sha": commit.get("sha", ""),
        "author": commit.get("author_name", ""),
        "date": commit.get("authored_date", ""),
        "message": _first_line(commit.get("message", "")),
        "ai_signals": [
            {
                "tool": sig.get("tool", ""),
                "signal_type": sig.get("signal_type", ""),
                "matched_text": sig.get("matched_text", ""),
                "confidence": sig.get("confidence", 0),
            }
            for sig in commit.get("ai_signals", [])
        ],
        "blamed_file": bic.get("blamed_file", ""),
        "blame_confidence": bic.get("blame_confidence", 0),
        "llm_verdict": {
            "verdict": llm_v.get("verdict", ""),
            "reasoning": llm_v.get("reasoning", ""),
            "model": llm_v.get("model", ""),
            "vuln_type": llm_v.get("vuln_type", ""),
            "vuln_description": llm_v.get("vuln_description", ""),
            "vulnerable_pattern": llm_v.get("vulnerable_pattern", ""),
            "causal_chain": llm_v.get("causal_chain", ""),
        } if llm_v else None,
    }


def _recompute_ai_confidence(result: dict) -> float:
    """Recompute AI confidence from raw BIC data.

    Uses best signal_confidence * blame_confidence without ratio penalty.
    LLM verification handles quality filtering instead.

    Mirrors _compute_ai_confidence() in cve_analyzer/pipeline.py.
    Keep both in sync when the scoring formula changes.
    """
    max_score = 0.0
    for bic in result.get("bug_introducing_commits", []):
        signals = bic.get("commit", {}).get("ai_signals", [])
        if not signals:
            continue
        best_signal = max(s.get("confidence", 0) for s in signals)
        score = best_signal * bic.get("blame_confidence", 0)
        if score > max_score:
            max_score = score
    return round(max_score, 4)


def build_cve_entry(
    result: dict,
    nvd_dates: dict[str, str] | None = None,
    ghsa_severities: dict[str, str] | None = None,
    reviews: dict[str, dict] | None = None,
) -> dict:
    """Transform a cached analysis result dict into a web-friendly CVE entry."""
    severity_str = result.get("severity", "")
    ai_signals = result.get("ai_signals", [])

    # Deduplicated list of AI tool names
    ai_tools = sorted(set(sig.get("tool", "") for sig in ai_signals if sig.get("tool")))

    bug_commits = [
        _build_bug_commit(bic)
        for bic in result.get("bug_introducing_commits", [])
    ]

    # Use NVD published date if available, fall back to year from CVE ID
    cve_id = result.get("cve_id", "")
    published = ""
    if nvd_dates and cve_id in nvd_dates:
        published = nvd_dates[cve_id]
    if not published:
        published = _extract_published_year(result)

    # Severity: prefer pre-computed cvss_score from CNA (cvelistV5),
    # then CVSS vector parsing, then GHSA database fallback
    pre_score = result.get("cvss_score", 0.0)
    severity = _parse_severity_label(severity_str)
    if pre_score > 0:
        cvss = pre_score
        # If severity is still UNKNOWN or came from an unparseable V4 vector,
        # derive it from the pre-computed score
        if severity == "UNKNOWN":
            if pre_score >= 9.0:
                severity = "CRITICAL"
            elif pre_score >= 7.0:
                severity = "HIGH"
            elif pre_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
    else:
        cvss = _extract_cvss_score(severity_str)
    if severity == "UNKNOWN" and ghsa_severities:
        ghsa_sev = ghsa_severities.get(cve_id, "")
        if ghsa_sev:
            severity = ghsa_sev

    # Compute verified_by from LLM verdicts and manual reviews
    models: set[str] = set()
    for bic in result.get("bug_introducing_commits", []):
        llm_v = bic.get("llm_verdict")
        if llm_v and llm_v.get("model"):
            models.add(llm_v["model"])

    verified_by = ""
    review = reviews.get(cve_id) if reviews else None
    if review and review.get("verdict") in ("confirmed", "uncertain"):
        verified_by = "Manual"
    elif models:
        verified_by = ", ".join(sorted(models))

    # Populate how_introduced from first CONFIRMED verdict's vuln_description
    how_introduced = ""
    for bic in result.get("bug_introducing_commits", []):
        llm_v = bic.get("llm_verdict")
        if llm_v and llm_v.get("verdict") == "CONFIRMED" and llm_v.get("vuln_description"):
            how_introduced = llm_v["vuln_description"]
            break

    return {
        "id": cve_id,
        "description": result.get("description", ""),
        "severity": severity,
        "cvss": cvss,
        "cwes": result.get("cwes", []),
        "ecosystem": "",
        "published": published,
        "ai_tools": ai_tools,
        "confidence": _recompute_ai_confidence(result),
        "verified_by": verified_by,
        "how_introduced": how_introduced,
        "bug_commits": bug_commits,
        "fix_commits": result.get("fix_commits", []),
        "references": result.get("references", []),
    }


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def build_stats(entries: list[dict], *, total_analyzed: int = 0) -> dict:
    """Aggregate statistics from a list of web CVE entries."""
    by_tool: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    month_counts: dict[str, int] = {}
    month_tool_counts: dict[str, dict[str, int]] = {}

    for entry in entries:
        # Tools
        for tool in entry.get("ai_tools", []):
            by_tool[tool] = by_tool.get(tool, 0) + 1

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
    coverage_from = sorted_months[0] if sorted_months else ""
    coverage_to = sorted_months[-1] if sorted_months else ""

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_cves": len(entries),
        "total_analyzed": total_analyzed,
        "coverage_from": coverage_from,
        "coverage_to": coverage_to,
        "by_tool": by_tool,
        "by_severity": by_severity,
        "by_month": by_month,
    }


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
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint: load, filter, transform, and write seed data."""
    parser = argparse.ArgumentParser(
        description="Generate web seed data from cached CVE analysis results."
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MIN_CONFIDENCE,
        help=f"Minimum AI confidence threshold (default: {DEFAULT_MIN_CONFIDENCE})",
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
    args = parser.parse_args(argv)

    # Load
    print(f"Loading cached results from {args.cache_dir} ...")
    results = load_cached_results(args.cache_dir)
    print(f"  Found {len(results)} cached results.")

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

    # Merge: NVD takes precedence, GHSA fills gaps
    nvd_dates.update({k: v for k, v in ghsa_dates.items() if k not in nvd_dates})

    # Filter
    filtered = filter_ai_results(results, min_confidence=args.min_confidence)
    print(f"  {len(filtered)} results with AI signals (confidence >= {args.min_confidence}).")

    # Identify GHSA IDs still missing published dates and fetch via API
    missing_ghsa_ids = [
        r.get("cve_id", "")
        for r in filtered
        if r.get("cve_id", "").startswith("GHSA-") and r.get("cve_id", "") not in nvd_dates
    ]
    if missing_ghsa_ids:
        print(f"Fetching {len(missing_ghsa_ids)} missing GHSA published dates via API ...")
        api_dates = fetch_ghsa_published_dates_api(missing_ghsa_ids)
        nvd_dates.update(api_dates)
        print(f"  Resolved {len(api_dates)} of {len(missing_ghsa_ids)} via API.")

    # Final fallback: use fix commit dates from local repos
    still_missing = [
        r for r in filtered
        if r.get("cve_id", "") not in nvd_dates
    ]
    if still_missing:
        print(f"Looking up {len(still_missing)} fix commit dates from local repos ...")
        commit_dates = load_fix_commit_dates(still_missing)
        nvd_dates.update(commit_dates)
        print(f"  Resolved {len(commit_dates)} of {len(still_missing)} from git history.")

    # Transform
    entries = [build_cve_entry(r, nvd_dates, ghsa_severities, reviews) for r in filtered]
    # Sort: LLM-confirmed first, then by confidence descending
    entries = sorted(
        entries,
        key=lambda e: (
            # 1. Has any CONFIRMED verdict
            any(
                (bc.get("llm_verdict") or {}).get("verdict") == "CONFIRMED"
                for bc in e.get("bug_commits", [])
            ),
            # 2. Then by confidence
            e.get("confidence", 0),
        ),
        reverse=True,
    )

    # Build output
    cves_output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(entries),
        "cves": entries,
    }
    # Count only cached (actually analyzed) advisories within the coverage window.
    # Use published date when available; for IDs without a date, use year from
    # the CVE ID prefix (e.g. CVE-2025-xxxx → 2025).  Non-CVE IDs (GHSA, JLSEC)
    # that lack a published date are included since they likely fall in range.
    coverage_from = min((e.get("published", "")[:7] for e in entries if e.get("published")), default="")
    coverage_year = int(coverage_from[:4]) if coverage_from else 0
    if coverage_from:
        total_in_range = 0
        for r in results:
            cve_id = r.get("cve_id", "")
            pub = nvd_dates.get(cve_id, "")
            if pub:
                if pub[:7] >= coverage_from:
                    total_in_range += 1
            elif cve_id.startswith("CVE-"):
                # Extract year from CVE-YYYY-nnnnn
                parts = cve_id.split("-")
                if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) >= coverage_year:
                    total_in_range += 1
            else:
                # GHSA, JLSEC, etc. — no year in ID, include conservatively
                total_in_range += 1
    else:
        total_in_range = len(results)
    stats_output = build_stats(entries, total_analyzed=total_in_range)

    # Write
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

    # Summary
    print("\nDone!")
    for entry in entries:
        tools = ", ".join(entry["ai_tools"]) or "(none)"
        print(f"  {entry['id']}: confidence={entry['confidence']} tools=[{tools}] severity={entry['severity']}")


if __name__ == "__main__":
    main()
