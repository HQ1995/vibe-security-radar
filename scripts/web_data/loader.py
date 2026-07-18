"""Data loading functions for web data generation.

Reads cached CVE analysis results, reviews, NVD/GHSA date feeds, and
audit override files. All functions return plain Python objects; no
external dependencies beyond stdlib and cve_analyzer.
"""

from __future__ import annotations

import glob
import gzip
import json
import logging
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime

from cve_analyzer.models import CveAnalysisResult

from web_data.constants import (
    DEFAULT_CACHE_DIR,
    DEFAULT_GHSA_DB_DIR,
    DEFAULT_NVD_FEEDS_DIR,
    DEFAULT_REPOS_DIR,
    DEFAULT_REVIEWS_DIR,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GHSA severity normalisation map
# ---------------------------------------------------------------------------

_GHSA_SEV_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

_FULL_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
_YEAR_ONLY_RE = re.compile(r"^\d{4}$")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def normalize_published(value: str) -> str:
    """Normalize a published date to "YYYY-MM-DD", "YYYY" (year-only), or "".

    Sources disagree on precision (NVD uses millisecond ISO, GHSA/git use
    offset ISO, CVE-ID fallback is year-only); the web contract admits only
    the three shapes above.  Anything else is treated as unknown ("").
    """
    value = (value or "").strip()
    if _FULL_DATE_RE.match(value):
        return value[:10]
    if _YEAR_ONLY_RE.match(value):
        return value
    return ""


def _parse_github_owner_repo(repo_url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL, or None if unparseable."""
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/*$",
        repo_url.rstrip("/"),
    )
    return (m.group(1), m.group(2)) if m else None


def _repo_url_to_dir(repo_url: str) -> str | None:
    """Convert a GitHub repo URL to a local cache directory name (owner_repo)."""
    parts = _parse_github_owner_repo(repo_url)
    return f"{parts[0]}_{parts[1]}" if parts else None


# ---------------------------------------------------------------------------
# Public loaders
# ---------------------------------------------------------------------------


def load_cached_results(cache_dir: str = DEFAULT_CACHE_DIR) -> list[CveAnalysisResult]:
    """Read all JSON files from the cache directory.

    Returns a list of CveAnalysisResult objects (one per file). Skips
    non-JSON files and files that fail to parse (with a logged warning).
    Calls rebuild_signals() on each result after deserialisation.
    """
    results: list[CveAnalysisResult] = []
    for filepath in sorted(glob.glob(os.path.join(cache_dir, "*.json"))):
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            result = CveAnalysisResult.from_dict(data)
            result.rebuild_signals()
            results.append(result)
        except Exception as exc:
            logger.warning("Skipping cached result %s: %s", filepath, exc)
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
            logger.warning("Skipping review %s: %s", filepath, exc)
    return reviews


def load_nvd_published_dates(
    nvd_feeds_dir: str = DEFAULT_NVD_FEEDS_DIR,
) -> dict[str, str]:
    """Build a {cve_id: published_date} index from NVD feed .json.gz files.

    Values are normalized via normalize_published() to "YYYY-MM-DD".
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
                published = normalize_published(cve.get("published", ""))
                if cve_id and published:
                    index[cve_id] = published
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping NVD feed %s: %s", filepath, exc)
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
                published = normalize_published(data.get("published", ""))
                if ghsa_id and published:
                    index[ghsa_id] = published
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping GHSA advisory %s: %s", filepath, exc)
    return index


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
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping GHSA advisory %s: %s", filepath, exc)
    return index


def load_fix_commit_dates(
    results: list[CveAnalysisResult],
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
        cve_id = result.cve_id
        fix_commits = result.fix_commits
        if not fix_commits:
            continue

        # Find repo dir from first fix commit
        repo_url = fix_commits[0].repo_url
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
            sha = fc.sha
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
            except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
                logger.warning(
                    "Fix commit date lookup failed for %s in %s: %s",
                    sha, repo_path, exc,
                )

        if earliest_str:
            index[cve_id] = normalize_published(earliest_str)

    return index


def fetch_ghsa_published_dates_api(
    ghsa_ids: list[str],
) -> dict[str, str]:
    """Fetch published dates for GHSA IDs via the GitHub REST API.

    Requires GITHUB_TOKEN in the environment. Returns {ghsa_id: published}
    (normalized to "YYYY-MM-DD") for successfully resolved entries; logs a
    warning and skips failures.
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
            published = normalize_published(data.get("published_at", ""))
            if published:
                index[ghsa_id] = published
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as exc:
            logger.warning("GHSA API lookup failed for %s: %s", ghsa_id, exc)
    return index


def build_alias_map(ghsa_db_dir: str = DEFAULT_GHSA_DB_DIR) -> dict[str, set[str]]:
    """Build {vuln_id: set_of_all_aliases} from the GHSA advisory database."""
    alias_groups: dict[str, set[str]] = {}
    if not os.path.isdir(ghsa_db_dir):
        return alias_groups
    for subdir in ("github-reviewed", "github-unreviewed"):
        pattern = os.path.join(ghsa_db_dir, subdir, "**", "*.json")
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                ghsa_id = data.get("id", "")
                aliases = data.get("aliases", [])
                all_ids = set([ghsa_id] + [a for a in aliases if a])
                # Merge with any existing groups
                merged = set()
                for aid in all_ids:
                    if aid in alias_groups:
                        merged |= alias_groups[aid]
                merged |= all_ids
                for aid in merged:
                    alias_groups[aid] = merged
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping GHSA advisory %s: %s", filepath, exc)
    return alias_groups


def _read_audit_override_file() -> list[dict]:
    """Read scripts/audit_overrides.json, returning the raw entry list.

    Returns [] when the file is missing, malformed, or not a list — with a
    logged warning in the latter cases, since silently ignoring it would
    un-force-include audited true positives.
    """
    override_path = os.path.join(os.path.dirname(__file__), "..", "audit_overrides.json")
    if not os.path.exists(override_path):
        return []
    try:
        with open(override_path, "r", encoding="utf-8") as fh:
            entries = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load audit overrides from %s: %s", override_path, exc)
        return []
    if not isinstance(entries, list):
        logger.warning(
            "Audit overrides %s is not a list (got %s); ignoring",
            override_path, type(entries).__name__,
        )
        return []
    return [e for e in entries if isinstance(e, dict) and e.get("cve_id")]


def load_audit_overrides() -> set[str]:
    """Load CVE IDs that were independently audited as true positives.

    These bypass the normal pipeline verdict filter — the audit found
    AI involvement that the pipeline missed (blame gap, verifier error, etc.).
    File: scripts/audit_overrides.json — list of {cve_id, reason} dicts.
    """
    ids = {e["cve_id"] for e in _read_audit_override_file()}
    if ids:
        print(f"  Audit overrides: {len(ids)} CVEs force-included.")
    return ids


def load_audit_override_details() -> dict[str, dict]:
    """Load full audit override entries keyed by CVE ID."""
    return {e["cve_id"]: e for e in _read_audit_override_file()}
