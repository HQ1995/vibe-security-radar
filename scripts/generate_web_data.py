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
DEFAULT_OUTPUT_DIR = str(Path(__file__).resolve().parent.parent / "web" / "data")
DEFAULT_MIN_CONFIDENCE = 0.0

# Workflow signal types — AI participated in merge/review but didn't write code.
# Keep in sync with WORKFLOW_SIGNAL_TYPES in cve_analyzer/models.py.
_WORKFLOW_SIGNAL_TYPES: frozenset[str] = frozenset({"merge_workflow", "ai_review_bot"})

# File extension → language mapping for language analytics
EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".java": "Java",
    ".kt": "Kotlin",
    ".php": "PHP",
    ".c": "C/C++",
    ".h": "C/C++",
    ".cpp": "C/C++",
    ".cc": "C/C++",
    ".cxx": "C/C++",
    ".hpp": "C/C++",
    ".hxx": "C/C++",
    ".cs": "C#",
    ".swift": "Swift",
    ".vue": "Vue",
    ".dart": "Dart",
    ".scala": "Scala",
    ".r": "R",
    ".lua": "Lua",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".zig": "Zig",
    ".nim": "Nim",
    ".pl": "Perl",
    ".pm": "Perl",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".sql": "SQL",
    ".sol": "Solidity",
    ".tf": "Terraform",
    ".hcl": "Terraform",
}

# Template/config extensions that need project-level language inference.
# These files don't have vulnerabilities on their own — the vulnerability
# is in the server-side framework that renders them.
_TEMPLATE_EXTENSIONS = frozenset({
    ".html", ".htm",          # Django/Jinja2/EJS/Handlebars templates
    ".xml", ".xsl", ".xslt",
    ".yaml", ".yml",          # config files
    ".json",                  # config/data
    ".erb",                   # Ruby ERB templates
    ".ejs",                   # Node EJS templates
    ".hbs",                   # Handlebars templates
    ".twig",                  # PHP Twig templates
    ".j2", ".jinja", ".jinja2",  # Jinja2 templates
})


def _file_extension_to_language(filepath: str) -> str | None:
    """Map a file path to a programming language via its extension.

    Returns None if the extension is not recognized.
    """
    if not filepath:
        return None
    ext = os.path.splitext(filepath)[1].lower()
    return EXTENSION_TO_LANGUAGE.get(ext)


def _fix_commit_files(fix_commits: list[dict], repos_dir: str) -> list[str]:
    """Get changed file paths from fix commits using local repo clones."""
    files: list[str] = []
    for fc in fix_commits:
        repo_url = fc.get("repo_url", "")
        sha = fc.get("sha", "")
        if not repo_url or not sha:
            continue
        # Derive local repo dir: owner_repo from URL
        parts = repo_url.rstrip("/").split("/")
        if len(parts) >= 2:
            repo_dir = os.path.join(repos_dir, f"{parts[-2]}_{parts[-1]}")
            if os.path.isdir(repo_dir):
                try:
                    out = subprocess.run(
                        ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", sha],
                        cwd=repo_dir, capture_output=True, text=True, timeout=10,
                    )
                    if out.returncode == 0:
                        files.extend(line for line in out.stdout.strip().split("\n") if line)
                except Exception:
                    pass
    return files


def _infer_language_from_template(filepath: str, fix_commits: list[dict] | None,
                                   repos_dir: str) -> str | None:
    """Infer the project language when the blamed file is a template/config.

    Template files (.html, .yaml, etc.) don't have vulnerabilities on their
    own — the bug is in the server-side framework.  Infer the framework
    language from sibling files in the fix commit diff.
    """
    fix_files = _fix_commit_files(fix_commits, repos_dir) if fix_commits else []
    # Count languages from fix commit files
    lang_counts: dict[str, int] = {}
    for f in fix_files:
        lang = _file_extension_to_language(f)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
    if lang_counts:
        return max(lang_counts, key=lang_counts.get)  # type: ignore[arg-type]
    # Heuristic from template type or path → likely framework
    ext = os.path.splitext(filepath)[1].lower()
    ext_hints = {
        ".erb": "Ruby", ".twig": "PHP", ".ejs": "JavaScript",
        ".j2": "Python", ".jinja": "Python", ".jinja2": "Python",
    }
    if ext in ext_hints:
        return ext_hints[ext]
    # Path-based hints for generic extensions like .html
    path_lower = filepath.lower()
    path_hints = [
        ("/templates/", "Python"),       # Django/Flask
        ("/views/", "PHP"),              # Laravel/PHP
        ("/resources/views/", "PHP"),    # Laravel
    ]
    for pattern, lang in path_hints:
        if pattern in path_lower:
            return lang
    return None


def _determine_languages(
    bug_commits: list[dict],
    fix_commits: list[dict] | None = None,
    repos_dir: str = DEFAULT_REPOS_DIR,
) -> list[str]:
    """Extract sorted unique languages from blamed_file extensions in bug commits.

    For template/config files (.html, .yaml, etc.), infers the project
    language from fix commit diffs since the vulnerability is in the
    framework, not the template format itself.

    Falls back to fix commit diff files when blamed_file is a placeholder
    (e.g. osv_introduced strategy).
    """
    languages: set[str] = set()
    needs_inference: list[str] = []
    for bc in bug_commits:
        filepath = bc.get("blamed_file", "")
        lang = _file_extension_to_language(filepath)
        if lang:
            languages.add(lang)
        elif filepath and os.path.splitext(filepath)[1].lower() in _TEMPLATE_EXTENSIONS:
            needs_inference.append(filepath)

    # Infer language for template files from project context
    if needs_inference and not languages:
        for filepath in needs_inference:
            lang = _infer_language_from_template(filepath, fix_commits, repos_dir)
            if lang:
                languages.add(lang)
                break

    # Fallback: infer from fix commit changed files
    if not languages and fix_commits:
        for filepath in _fix_commit_files(fix_commits, repos_dir):
            lang = _file_extension_to_language(filepath)
            if lang:
                languages.add(lang)

    return sorted(languages)


# ---------------------------------------------------------------------------
# CVSS 3.1 scoring (simplified but accurate for common vectors)
# ---------------------------------------------------------------------------

# Metric value weights from the CVSS v3.1 specification
_CONF_MAP = {"high": 0.95, "medium": 0.7, "low": 0.4}

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


# Keyword-based severity inference for OSS-Fuzz and similar advisories
_SEVERITY_KEYWORDS: list[tuple[str, list[str]]] = [
    ("HIGH", [
        "heap-buffer-overflow", "use-after-free", "stack-buffer-overflow",
        "out-of-bounds-write", "double-free", "memory-corruption",
        "buffer-overflow", "arbitrary code execution", "remote code execution",
    ]),
    ("MEDIUM", [
        "integer-overflow", "null-dereference", "out-of-bounds-read",
        "divide-by-zero", "assertion-failure", "uninitialized-value",
        "denial of service",
    ]),
    ("LOW", [
        "timeout", "oom", "out-of-memory",
    ]),
]


def _infer_severity_from_description(description: str, vuln_type: str = "") -> str:
    """Infer a severity label from description/vuln_type keywords.

    Checks HIGH keywords first, then MEDIUM, then LOW.
    Returns the highest severity found, or empty string if no match.
    """
    combined = f"{description} {vuln_type}".lower()
    for severity, keywords in _SEVERITY_KEYWORDS:
        for kw in keywords:
            if kw in combined:
                return severity
    return ""


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


def _parse_github_owner_repo(repo_url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL, or None if unparseable."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/*$", repo_url.rstrip("/"))
    return (m.group(1), m.group(2)) if m else None


def _repo_url_to_dir(repo_url: str) -> str | None:
    """Convert a GitHub repo URL to a local cache directory name (owner_repo)."""
    parts = _parse_github_owner_repo(repo_url)
    return f"{parts[0]}_{parts[1]}" if parts else None


def _repo_url_to_display_name(repo_url: str) -> str | None:
    """Extract 'owner/repo' from a GitHub URL, lowercased for dedup.

    Returns None for non-GitHub or unparseable URLs.
    """
    parts = _parse_github_owner_repo(repo_url)
    return f"{parts[0]}/{parts[1]}".lower() if parts else None


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

def _get_screening_verdict(bic: dict) -> dict | None:
    """Return the screening verification dict for a BIC, with old-name fallback."""
    return bic.get("screening_verification") or bic.get("llm_verdict")


def _is_fallback_verdict(vv: dict) -> bool:
    """Return True if the verdict is a timeout/error fallback, not a real analysis.

    Fallback verdicts are generated when the deep verifier exhausts its tool-call
    budget or encounters an error.  They should not be trusted as genuine verdicts.
    Detected via:
    - ``is_fallback`` flag (new format, set by agent_loop.py)
    - Reasoning containing "Fallback verdict" with empty evidence (legacy format)
    """
    if vv.get("is_fallback"):
        return True
    reasoning = vv.get("reasoning", "")
    evidence = vv.get("evidence", None)
    if "Fallback verdict" in reasoning and (not evidence or len(evidence) == 0):
        return True
    return False


def _get_deep_verdict(bic: dict) -> dict | None:
    """Return the best deep-verification verdict dict for a BIC.

    Prefers deep_verification (new single-model verifier) over
    tribunal_verdict (old 3-model voting) for backward compatibility.

    Returns a *copy* with ``"final_verdict"`` normalized so all downstream
    consumers can use one key (verification uses ``"verdict"``, tribunal
    uses ``"final_verdict"``).  Returns None if neither exists.

    Timeout/error fallback verdicts are ignored (returns None) so that
    downstream logic treats the BIC as unverified (benefit of the doubt).
    """
    vv = bic.get("deep_verification") or bic.get("verification_verdict")
    if vv:
        if _is_fallback_verdict(vv):
            return None
        if "final_verdict" not in vv and "verdict" in vv:
            return {**vv, "final_verdict": vv["verdict"]}
        return vv
    return bic.get("tribunal_verdict")


def _effective_verdict(bic: dict) -> str:
    """Return the best available verdict for a BIC.

    Prefers deep verification verdict over screening_verification (screening).
    Returns "" if no verdict exists.
    """
    dv = _get_deep_verdict(bic)
    if dv and dv.get("final_verdict"):
        return dv["final_verdict"].upper()
    llm_v = _get_screening_verdict(bic)
    if llm_v and llm_v.get("verdict"):
        return llm_v["verdict"].upper()
    return ""


def _has_no_confirmed_verdict(result: dict) -> bool:
    """Return True if no BIC has a CONFIRMED verdict with AI involvement.

    Deep verification is authoritative: only CONFIRMED passes.
    UNLIKELY and UNRELATED both cause exclusion — UNLIKELY means the
    verifier thinks the AI probably didn't cause the vulnerability.

    BICs with no deep verdict still pass (benefit of the doubt).
    """
    for bic in result.get("bug_introducing_commits", []):
        has_signals = bool(bic.get("commit", {}).get("ai_signals"))
        has_llm = _get_screening_verdict(bic) is not None
        if not has_signals and not has_llm:
            continue  # no AI involvement at all

        dv = _get_deep_verdict(bic)
        if dv:
            dv_verdict = (dv.get("final_verdict") or "").upper()
            # Only CONFIRMED passes; UNLIKELY and UNRELATED are excluded
            if dv_verdict == "CONFIRMED":
                return False
            continue

        # No deep verification — accept (benefit of the doubt)
        return False

    return True


def filter_ai_results(
    results: list[dict],
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
) -> list[dict]:
    """Keep results with a CONFIRMED deep-verification/LLM verdict.

    A CONFIRMED deep verdict bypasses confidence filtering — if the
    verifier confirms it's real, a mechanical formula shouldn't
    override that.  For CVEs without deep verification, fall back to
    confidence threshold.
    """
    filtered = []
    excluded_by_verdict = 0
    excluded_rejected = 0
    for r in results:
        if r.get("error", ""):
            continue
        # Skip rejected/withdrawn CVEs
        desc = (r.get("description") or "").lower()
        if "rejected reason:" in desc or "this cve id has been rejected" in desc:
            excluded_rejected += 1
            continue
        if _has_no_confirmed_verdict(r):
            excluded_by_verdict += 1
            continue
        filtered.append(r)
    if excluded_rejected:
        print(f"  Excluded {excluded_rejected} rejected/withdrawn CVEs.")
    if excluded_by_verdict:
        print(f"  Excluded {excluded_by_verdict} CVEs without CONFIRMED verdict.")
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


DEFAULT_API_RESPONSES_DIR = os.path.expanduser("~/.cache/cve-analyzer/api-responses")


def _lookup_pr_for_commit(
    repo_url: str,
    sha: str,
    api_responses_dir: str = DEFAULT_API_RESPONSES_DIR,
) -> tuple[str, str]:
    """Look up PR URL and title for a commit from the gh_commit_prs cache.

    Returns (pr_url, pr_title) or ("", "") if not found.
    """
    parts = _parse_github_owner_repo(repo_url)
    if not parts or not sha or not re.fullmatch(r"[0-9a-fA-F]{4,64}", sha):
        return ("", "")
    owner, repo = parts
    cache_path = os.path.join(
        api_responses_dir, "gh_commit_prs", owner, repo, "commits", sha, "pulls.json"
    )
    try:
        with open(cache_path, "r", encoding="utf-8") as fh:
            prs = json.load(fh)
        if prs and isinstance(prs, list):
            pr = prs[0]
            return (pr.get("html_url", ""), pr.get("title", ""))
    except (json.JSONDecodeError, OSError):
        pass
    return ("", "")


def _build_signal_entry(sig: dict) -> dict:
    """Transform a raw AI signal dict into the web format."""
    return {
        "tool": sig.get("tool", ""),
        "signal_type": sig.get("signal_type", ""),
        "matched_text": sig.get("matched_text", ""),
        "confidence": sig.get("confidence", 0),
    }


def _build_bug_commit(bic: dict, repo_url: str = "", fix_commit_source: str = "") -> dict:
    """Transform a bug_introducing_commit entry into the web format."""
    commit = bic.get("commit", {})
    llm_v = _get_screening_verdict(bic)
    tv = _get_deep_verdict(bic)
    entry: dict = {
        "sha": commit.get("sha", ""),
        "author": commit.get("author_name", ""),
        "date": commit.get("authored_date", ""),
        "message": _first_line(commit.get("message", "")),
        "ai_signals": [
            _build_signal_entry(sig) for sig in commit.get("ai_signals", [])
        ],
        "blamed_file": bic.get("blamed_file", ""),
        "blame_confidence": bic.get("blame_confidence", 0),
    }
    if fix_commit_source:
        entry["fix_commit_source"] = fix_commit_source
    entry["screening_verification"] = {
        "verdict": llm_v.get("verdict", ""),
        "reasoning": llm_v.get("reasoning", ""),
        "model": llm_v.get("model", ""),
        "vuln_type": llm_v.get("vuln_type", ""),
        "vuln_description": llm_v.get("vuln_description", ""),
        "vulnerable_pattern": llm_v.get("vulnerable_pattern", ""),
        "causal_chain": llm_v.get("causal_chain", ""),
    } if llm_v else None
    # Look up PR URL from API cache
    commit_sha = commit.get("sha", "")
    pr_url, pr_title = _lookup_pr_for_commit(repo_url, commit_sha)
    if pr_url:
        entry["pr_url"] = pr_url
        entry["pr_title"] = pr_title

    if tv:
        # Both formats are normalized via _get_deep_verdict(). Build unified web output.
        if tv.get("agent_verdicts"):
            # Old format: multi-model with agent_verdicts list
            entry["verification"] = {
                "verdict": tv.get("final_verdict", ""),
                "confidence": tv.get("confidence", ""),
                "models": [
                    av.get("model", "") for av in tv.get("agent_verdicts", [])
                ],
                "agent_verdicts": [
                    {
                        "model": av.get("model", ""),
                        "verdict": av.get("verdict", ""),
                        "reasoning": av.get("reasoning", ""),
                        "confidence": av.get("confidence", 0),
                        "tool_calls_made": av.get("tool_calls_made", 0),
                        "steps_completed": av.get("steps_completed", 0),
                        "evidence": av.get("evidence", []),
                    }
                    for av in tv["agent_verdicts"]
                ],
            }
        else:
            # New verifier format: single-model flat structure.
            # Map string confidence ("high"/"medium"/"low") to numeric
            # for web UI compatibility (formatConfidence expects 0-1).
            raw_conf = tv.get("confidence", "")
            numeric_conf = _CONF_MAP.get(str(raw_conf).lower(), raw_conf)
            entry["verification"] = {
                "verdict": tv.get("final_verdict", ""),
                "confidence": numeric_conf,
                "models": [tv["model"]] if tv.get("model") else [],
                "agent_verdicts": [
                    {
                        "model": tv.get("model", ""),
                        "verdict": tv.get("final_verdict", ""),
                        "reasoning": tv.get("reasoning", ""),
                        "confidence": numeric_conf,
                        "tool_calls_made": tv.get("tool_calls_made", 0),
                        "steps_completed": tv.get("steps_completed", 0),
                        "evidence": tv.get("evidence", []),
                    }
                ],
            }

    # Decomposed sub-commits from squash merge PRs
    decomposed = bic.get("decomposed_commits", [])
    if decomposed:
        entry["decomposed_commits"] = [
            {
                "sha": dc.get("sha", ""),
                "author_name": dc.get("author_name", ""),
                "message": _first_line(dc.get("message", "")),
                "ai_signals": [
                    _build_signal_entry(sig) for sig in dc.get("ai_signals", [])
                ],
                "touched_blamed_file": dc.get("touched_blamed_file"),
            }
            for dc in decomposed
        ]

    # Promote culprit sub-commit as the primary BIC when available.
    # If culprit_sha not set in cache, infer from decomposed commits:
    # prefer sub-commits that touched the blamed file, else keep squash merge.
    culprit_sha = bic.get("culprit_sha", "")
    if not culprit_sha and decomposed:
        touched = [dc for dc in decomposed if dc.get("ai_signals") and dc.get("touched_blamed_file") is True]
        if len(touched) == 1:
            culprit_sha = touched[0].get("sha", "")
        elif len(touched) > 1:
            # Multiple file-confirmed sub-commits — pick highest signal confidence
            best = max(touched, key=lambda dc: max((s.get("confidence", 0) for s in dc.get("ai_signals", [])), default=0))
            culprit_sha = best.get("sha", "")
        # When no sub-commit has touched_blamed_file=True, don't guess —
        # keep the squash merge as the BIC (avoids promoting empty commits).
    if culprit_sha and decomposed:
        for dc in decomposed:
            if dc.get("sha") == culprit_sha:
                entry["squash_merge_sha"] = entry["sha"]
                entry["sha"] = culprit_sha
                entry["author"] = dc.get("author_name", entry["author"])
                entry["message"] = _first_line(dc.get("message", ""))
                # Replace AI signals with culprit's own signals.
                # The squash-merge's signals are PR-level; the culprit's
                # signals reflect whether AI actually wrote the vulnerable code.
                culprit_signals = dc.get("ai_signals", [])
                entry["ai_signals"] = [_build_signal_entry(s) for s in culprit_signals]
                break

    return entry


_EXCLUSION_VERDICTS_DICT = frozenset({"UNRELATED"})


def _bic_dict_is_excluded(bic: dict) -> bool:
    """Return True if this BIC dict should be excluded from AI confidence scoring.

    Dict-based mirror of ``_bic_is_excluded()`` in pipeline.py.
    Deep verification verdict is authoritative and checked first.
    """
    dv = _get_deep_verdict(bic)
    if dv:
        dv_final = (dv.get("final_verdict") or "").upper()
        if dv_final in _EXCLUSION_VERDICTS_DICT:
            return True
        # CONFIRMED or other → not excluded, even if LLM said UNRELATED
        return False
    # Screening verdict is advisory only — never exclude based on it.
    return False


_UNLIKELY_PENALTIES_DICT: dict[str, float] = {
    "high": 0.25,
    "medium": 0.5,
    "low": 1.0,
}


def _get_unlikely_penalty_dict(bic: dict) -> float:
    """Return penalty multiplier for UNLIKELY deep_verification.

    Dict-based mirror of _get_unlikely_penalty() in pipeline.py.
    Only checks deep_verification (has confidence field).
    """
    vv = bic.get("deep_verification") or bic.get("verification_verdict")
    if not vv:
        return 1.0
    if (vv.get("verdict") or "").upper() != "UNLIKELY":
        return 1.0
    confidence = (vv.get("confidence") or "low").lower()
    return _UNLIKELY_PENALTIES_DICT.get(confidence, 1.0)


def _recompute_ai_confidence(result: dict) -> float:
    """Recompute AI confidence from raw BIC data.

    Penalties applied (in order):
    1. Indirect-only penalty (0.25x) when ALL signals on best BIC are
       ``squash_decomposed_*``.
    2. Diffuse blame penalty when total BICs > 50:
       a. Count damping: multiply by (50 / total).
       b. AI ratio damping: if AI BICs < 50% of total, multiply by
          max(ai_bic_count / total, 0.1).
    3. Confidence floor: scores < 0.05 are zeroed.

    Mirrors _compute_ai_confidence() in cve_analyzer/pipeline.py.
    Keep both in sync when the scoring formula changes.
    """
    bics = result.get("bug_introducing_commits", [])
    total = len(bics)
    max_score = 0.0
    best_bic: dict | None = None
    ai_bic_count = 0
    for bic in bics:
        signals = bic.get("commit", {}).get("ai_signals", [])
        if not signals:
            continue
        if _bic_dict_is_excluded(bic):
            continue
        # Only consider authorship signals — workflow signals don't prove
        # AI wrote the code (mirrored from pipeline.py).
        authorship = [s for s in signals if s.get("signal_type", "").removeprefix("squash_decomposed_") not in _WORKFLOW_SIGNAL_TYPES]
        if not authorship:
            continue
        ai_bic_count += 1
        best_signal = max(s.get("confidence", 0) for s in authorship)
        score = best_signal * bic.get("blame_confidence", 0)
        score *= _get_unlikely_penalty_dict(bic)
        if score > max_score:
            max_score = score
            best_bic = bic

    # Indirect-only penalty (mirrored from pipeline.py)
    if max_score > 0 and best_bic is not None:
        best_signals = best_bic.get("commit", {}).get("ai_signals", [])
        best_authorship = [s for s in best_signals if s.get("signal_type", "").removeprefix("squash_decomposed_") not in _WORKFLOW_SIGNAL_TYPES]
        if best_authorship and all(
            s.get("signal_type", "").startswith("squash_decomposed")
            for s in best_authorship
        ):
            max_score *= 0.25  # _INDIRECT_ONLY_PENALTY — keep in sync with pipeline.py

    # Diffuse blame penalty (mirrored from pipeline.py)
    if total > 50 and max_score > 0:
        max_score *= (50 / total)
        ai_ratio = ai_bic_count / total
        if ai_ratio < 0.5:
            max_score *= max(ai_ratio, 0.1)

    # Confidence floor (mirrored from pipeline.py)
    if 0 < max_score < 0.05:
        max_score = 0.0
    return round(max_score, 4)


def build_cve_entry(
    result: dict,
    nvd_dates: dict[str, str] | None = None,
    ghsa_severities: dict[str, str] | None = None,
    reviews: dict[str, dict] | None = None,
) -> dict:
    """Transform a cached analysis result dict into a web-friendly CVE entry."""
    severity_str = result.get("severity", "")

    # Deduplicated list of AI tool names — only authorship signals from BICs
    # whose effective verdict is CONFIRMED or missing (benefit of the doubt).
    # Workflow signals (merge_workflow, ai_review_bot) are excluded.
    ai_tools_set: set[str] = set()
    for bic in result.get("bug_introducing_commits", []):
        commit = bic.get("commit", {})
        signals = commit.get("ai_signals", [])
        if not signals:
            continue
        verdict = _effective_verdict(bic)
        if verdict == "UNRELATED":
            continue
        for sig in signals:
            if sig.get("signal_type", "").removeprefix("squash_decomposed_") in _WORKFLOW_SIGNAL_TYPES:
                continue
            tool = sig.get("tool", "")
            if tool:
                ai_tools_set.add(tool)
    ai_tools = sorted(ai_tools_set)

    # Only include BICs with AI signals whose effective verdict is CONFIRMED
    # or missing.  Skip commits without AI signals (plain human commits from
    # git blame) and those judged UNLIKELY/UNRELATED by deep verifier or LLM.
    raw_bics = result.get("bug_introducing_commits", [])
    # Get repo URL from first fix commit for PR lookups
    fix_repo_url = ""
    for fc in result.get("fix_commits", []):
        if fc.get("repo_url"):
            fix_repo_url = fc["repo_url"]
            break
    # Map fix commit SHA → source for downstream display
    fix_source_by_sha: dict[str, str] = {}
    for fc in result.get("fix_commits", []):
        sha = fc.get("sha", "")
        if sha:
            fix_source_by_sha[sha] = fc.get("source", "")
    bug_commits_raw = [
        _build_bug_commit(
            bic,
            repo_url=fix_repo_url,
            fix_commit_source=fix_source_by_sha.get(bic.get("fix_commit_sha", ""), ""),
        )
        for bic in raw_bics
        if bic.get("commit", {}).get("ai_signals")
        and _effective_verdict(bic) not in ("UNRELATED", "UNLIKELY")
    ]
    # Merge BICs with the same SHA (same commit blamed for multiple files).
    # Keep the first entry and append extra blamed_file values.
    seen_shas: dict[str, dict] = {}
    bug_commits: list[dict] = []
    for bc in bug_commits_raw:
        sha = bc["sha"]
        if sha in seen_shas:
            existing = seen_shas[sha]
            if bc["blamed_file"] and bc["blamed_file"] != existing["blamed_file"]:
                existing["blamed_file"] += f", {bc['blamed_file']}"
        else:
            seen_shas[sha] = bc
            bug_commits.append(bc)

    # Deduplicate BICs with different SHAs but identical verification reasoning
    # (happens when multiple commits are blamed for the same fix file and the
    # deep verifier produces the same analysis for each).
    seen_reasonings: set[str] = set()
    deduped: list[dict] = []
    for bc in bug_commits:
        reasoning = ""
        for av in bc.get("verification", {}).get("agent_verdicts", []):
            reasoning = av.get("reasoning", "")
            break
        if reasoning and reasoning in seen_reasonings:
            continue
        if reasoning:
            seen_reasonings.add(reasoning)
        deduped.append(bc)
    bug_commits = deduped

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

    # Infer severity from description keywords (e.g. OSS-Fuzz advisories)
    if severity == "UNKNOWN":
        # Extract vuln_type early from first CONFIRMED verdict for inference
        _vt = ""
        for bic in result.get("bug_introducing_commits", []):
            llm_v = _get_screening_verdict(bic)
            if llm_v and llm_v.get("verdict") == "CONFIRMED":
                _vt = llm_v.get("vuln_type", "")
                if _vt:
                    break
        inferred = _infer_severity_from_description(
            result.get("description", ""), _vt,
        )
        if inferred:
            severity = inferred

    # Compute verified_by from deep verification + LLM verdicts and manual reviews
    models: set[str] = set()
    for bic in result.get("bug_introducing_commits", []):
        dv = _get_deep_verdict(bic)
        if dv:
            # New verifier format: model at top level
            if dv.get("model"):
                models.add(dv["model"])
            # Old tribunal format: model inside agent_verdicts
            for av in dv.get("agent_verdicts", []):
                if av.get("model"):
                    models.add(av["model"])
        llm_v = _get_screening_verdict(bic)
        if llm_v and llm_v.get("model"):
            # Strip strategy prefixes like "osv+" to get the bare model name
            model = llm_v["model"]
            if "+" in model:
                model = model.split("+", 1)[1]
            models.add(model)

    verified_by = ""
    review = reviews.get(cve_id) if reviews else None
    if review and review.get("verdict") in ("confirmed", "uncertain"):
        verified_by = "Manual"
    elif models:
        verified_by = ", ".join(sorted(models))

    # Populate how_introduced (causal chain), root_cause, and vuln_type.
    # Priority: deep-verify CONFIRMED > screening CONFIRMED (no deep verify).
    # If deep verify says UNLIKELY/UNRELATED, screening CONFIRMED is ignored
    # for that BIC — the deep verifier overrules screening.
    how_introduced = ""
    root_cause = ""
    vuln_type = ""
    screening_fallback = ""
    screening_root_cause = ""
    screening_vuln_type = ""

    for bic in result.get("bug_introducing_commits", []):
        dv = _get_deep_verdict(bic)
        dv_verdict = ""
        if dv:
            dv_verdict = (dv.get("final_verdict") or dv.get("verdict") or "").upper()

        # Best source: deep verify CONFIRMED
        if dv_verdict == "CONFIRMED":
            if dv.get("reasoning"):
                how_introduced = dv["reasoning"]
            # Old format: reasoning inside agent_verdicts
            for av in dv.get("agent_verdicts", []):
                if av.get("verdict") == "CONFIRMED" and av.get("reasoning"):
                    how_introduced = av["reasoning"]
                    break
            if how_introduced:
                break

        # Screening CONFIRMED — only use if deep verify did NOT overrule it
        llm_v = _get_screening_verdict(bic)
        if llm_v and llm_v.get("verdict") == "CONFIRMED" and not dv_verdict:
            # No deep verify exists for this BIC — screening is acceptable
            candidate = llm_v.get("causal_chain", "")
            if candidate and not screening_fallback:
                screening_fallback = candidate
                screening_root_cause = llm_v.get("vuln_description", "")
                screening_vuln_type = llm_v.get("vuln_type", "")

    # Use screening only as fallback when no deep-verify CONFIRMED was found
    if not how_introduced and screening_fallback:
        how_introduced = screening_fallback
        root_cause = screening_root_cause
        vuln_type = screening_vuln_type

    # Best verdict across all BICs (for list table display).
    # UNRELATED and UNLIKELY BICs are filtered out of bug_commits above,
    # so only CONFIRMED BICs appear.
    best_verdict = ""
    for bic in result.get("bug_introducing_commits", []):
        v = _effective_verdict(bic)
        if v == "CONFIRMED":
            best_verdict = "CONFIRMED"
            break
        if v == "UNLIKELY" and best_verdict != "CONFIRMED":
            best_verdict = "UNLIKELY"

    return {
        "id": cve_id,
        "description": result.get("description", ""),
        "severity": severity,
        "cvss": cvss,
        "cwes": result.get("cwes", []),
        "ecosystem": "",
        "published": published,
        "ai_tools": ai_tools,
        "languages": _determine_languages(bug_commits, result.get("fix_commits")),
        "confidence": _recompute_ai_confidence(result),
        "verified_by": verified_by,
        "how_introduced": how_introduced,
        "root_cause": root_cause,
        "vuln_type": vuln_type,
        "verdict": best_verdict,
        "bug_commits": bug_commits,
        "fix_commits": result.get("fix_commits", []),
        "references": result.get("references", []),
    }


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def build_stats(entries: list[dict], *, total_analyzed: int = 0, with_fix_commits: int = 0, coverage_since: str = "") -> dict:
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
    parser.add_argument(
        "--since",
        type=str,
        default="2025-05",
        help="Coverage start month YYYY-MM for total_analyzed count (default: 2025-05)",
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
    print(f"  {len(filtered)} results with confirmed AI involvement.")

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
    # Drop entries with no AI tools (signals lost from cache — need re-analysis)
    no_tools = [e for e in entries if not e.get("ai_tools")]
    if no_tools:
        print(f"  Excluded {len(no_tools)} CVEs with lost AI signal data (need --no-cache re-analysis).")
    entries = [e for e in entries if e.get("ai_tools")]
    # Sort: LLM-confirmed first, then by confidence descending
    entries = sorted(
        entries,
        key=lambda e: (
            # 1. Has any CONFIRMED verdict
            any(
                (bc.get("screening_verification") or bc.get("llm_verdict") or {}).get("verdict") == "CONFIRMED"
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
    coverage_since = args.since  # e.g. "2025-05"
    coverage_year = int(coverage_since[:4]) if coverage_since else 0
    if coverage_since:
        total_in_range = 0
        with_fix_commits = 0
        for r in results:
            cve_id = r.get("cve_id", "")
            pub = nvd_dates.get(cve_id, "")
            in_range = False
            if pub:
                in_range = pub[:7] >= coverage_since
            elif cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                in_range = len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) >= coverage_year
            else:
                # GHSA, JLSEC, etc. — no year in ID, include conservatively
                in_range = True
            if in_range:
                total_in_range += 1
                fcs = r.get("fix_commits") or []
                if any(fc.get("sha") for fc in fcs):
                    with_fix_commits += 1
        print(f"  {total_in_range} of {len(results)} results within coverage window (>= {coverage_since}).")
        if total_in_range > 0:
            print(f"  {with_fix_commits} with fix commits ({100*with_fix_commits/total_in_range:.1f}%), {total_in_range - with_fix_commits} without.")
    else:
        total_in_range = len(results)
        with_fix_commits = sum(
            1 for r in results
            if any(fc.get("sha") for fc in (r.get("fix_commits") or []))
        )
    stats_output = build_stats(
        entries, total_analyzed=total_in_range,
        with_fix_commits=with_fix_commits,
        coverage_since=coverage_since,
    )

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
