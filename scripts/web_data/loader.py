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
import zipfile
from datetime import date, datetime

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

_GHSA_ADVISORY_SUBDIRS = ("github-reviewed", "unreviewed")

_DEFAULT_OSV_BULK_DIR = os.path.expanduser("~/.cache/cve-analyzer/osv-bulk")

_YEAR_ONLY_RE = re.compile(r"^\d{4}$")
_FULL_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BIC_SUBJECT_KEYS = frozenset({"fix_commit_sha", "commit_sha", "blamed_file"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def normalize_published(value: str | None) -> str:
    """Normalize a published date to "YYYY-MM-DD", "YYYY" (year-only), or "".

    Sources disagree on precision (NVD uses millisecond ISO, GHSA/git use
    offset ISO, CVE-ID fallback is year-only); the web contract admits only
    the three shapes above.  Anything else is treated as unknown ("").
    """
    value = (value or "").strip()
    if not value:
        return ""
    if _YEAR_ONLY_RE.fullmatch(value):
        return value if value != "0000" else ""
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return date.fromisoformat(value).isoformat()
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return ""


def _normalize_source_published(value: object, source: str) -> str:
    """Normalize a source date and make malformed non-empty values observable."""
    raw = value if isinstance(value, str) else ""
    normalized = normalize_published(raw)
    if value not in (None, "") and not normalized:
        logger.warning("Ignoring malformed published date from %s: %r", source, value)
    return normalized


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
                published = _normalize_source_published(
                    cve.get("published", ""),
                    f"NVD {cve_id or filepath}",
                )
                if cve_id and published:
                    index[cve_id] = published
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping NVD feed %s: %s", filepath, exc)
    return index


def load_ghsa_published_dates(
    ghsa_db_dir: str = DEFAULT_GHSA_DB_DIR,
) -> dict[str, str]:
    """Build a {ghsa_id: published_date} index from the GHSA advisory DB.

    Scans the reviewed and unreviewed directories in the upstream database.
    Returns an empty dict if the directory does not exist.
    """
    index: dict[str, str] = {}
    if not os.path.isdir(ghsa_db_dir):
        return index
    for subdir in _GHSA_ADVISORY_SUBDIRS:
        pattern = os.path.join(ghsa_db_dir, subdir, "**", "*.json")
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                ghsa_id = data.get("id", "")
                published = _normalize_source_published(
                    data.get("published", ""),
                    f"GHSA {ghsa_id or filepath}",
                )
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
    for subdir in _GHSA_ADVISORY_SUBDIRS:
        pattern = os.path.join(ghsa_db_dir, subdir, "**", "*.json")
        for filepath in glob.glob(pattern, recursive=True):
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                database_specific = data.get("database_specific")
                if not isinstance(database_specific, dict):
                    continue
                raw_sev = database_specific.get("severity", "")
                if not isinstance(raw_sev, str):
                    continue
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
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=5,
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
                    sha,
                    repo_path,
                    exc,
                )

        if earliest_str:
            normalized = _normalize_source_published(
                earliest_str,
                f"git history for {cve_id}",
            )
            if normalized:
                index[cve_id] = normalized

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
            published = _normalize_source_published(
                data.get("published_at", ""),
                f"GitHub Advisory API {ghsa_id}",
            )
            if published:
                index[ghsa_id] = published
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as exc:
            logger.warning("GHSA API lookup failed for %s: %s", ghsa_id, exc)
    return index


def _merge_alias_group(
    alias_groups: dict[str, set[str]],
    all_ids: set[str],
) -> None:
    """Merge one alias group into the transitive in-memory alias index."""
    merged = set(all_ids)
    for advisory_id in all_ids:
        merged.update(alias_groups.get(advisory_id, ()))
    for advisory_id in merged:
        alias_groups[advisory_id] = merged


def _parse_alias_group(data: object, source: str) -> set[str] | None:
    """Validate an advisory's id/aliases projection before linking IDs.

    A malformed alias field is skipped as a whole. Guessing around malformed
    data could join unrelated vulnerabilities and incorrectly suppress one at
    publication time.
    """
    if not isinstance(data, dict):
        logger.warning("Skipping alias record %s: expected an object", source)
        return None

    advisory_id = data.get("id")
    aliases = data.get("aliases", [])
    if not isinstance(advisory_id, str) or not advisory_id.strip():
        logger.warning("Skipping alias record %s: missing string id", source)
        return None
    if not isinstance(aliases, list) or any(not isinstance(alias, str) or not alias.strip() for alias in aliases):
        logger.warning("Skipping alias record %s: aliases must be strings", source)
        return None
    return {advisory_id, *aliases}


def build_alias_map(
    ghsa_db_dir: str = DEFAULT_GHSA_DB_DIR,
    osv_bulk_dir: str = _DEFAULT_OSV_BULK_DIR,
) -> dict[str, set[str]]:
    """Build ``{vuln_id: all_equivalent_ids}`` from local advisory sources.

    GHSA remains the primary source. Local OSV bulk archives supplement it
    because OSV can carry CVE/GHSA equivalences that have not landed in the
    checked-out GitHub Advisory Database. Missing directories and malformed
    archives are tolerated; malformed individual alias records are skipped
    without creating a partial equivalence.
    """
    alias_groups: dict[str, set[str]] = {}

    if os.path.isdir(ghsa_db_dir):
        for subdir in _GHSA_ADVISORY_SUBDIRS:
            pattern = os.path.join(ghsa_db_dir, subdir, "**", "*.json")
            for filepath in glob.glob(pattern, recursive=True):
                try:
                    with open(filepath, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    all_ids = _parse_alias_group(data, filepath)
                    if all_ids:
                        _merge_alias_group(alias_groups, all_ids)
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("Skipping GHSA advisory %s: %s", filepath, exc)

    if not os.path.isdir(osv_bulk_dir):
        return alias_groups

    for archive_path in sorted(glob.glob(os.path.join(osv_bulk_dir, "*.zip"))):
        try:
            with zipfile.ZipFile(archive_path) as archive:
                for member in archive.infolist():
                    if member.is_dir() or not member.filename.endswith(".json"):
                        continue
                    source = f"{archive_path}:{member.filename}"
                    try:
                        data = json.loads(archive.read(member))
                    except (
                        json.JSONDecodeError,
                        UnicodeDecodeError,
                        OSError,
                        RuntimeError,
                        zipfile.BadZipFile,
                    ) as exc:
                        logger.warning("Skipping OSV alias record %s: %s", source, exc)
                        continue
                    all_ids = _parse_alias_group(data, source)
                    # Single-ID OSV records add no equivalence and dominate the
                    # bulk corpus, so avoid retaining them in the publication map.
                    if all_ids and len(all_ids) > 1:
                        _merge_alias_group(alias_groups, all_ids)
        except (OSError, zipfile.BadZipFile) as exc:
            logger.warning("Skipping OSV bulk archive %s: %s", archive_path, exc)
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
            override_path,
            type(entries).__name__,
        )
        return []
    valid_entries = [
        entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("cve_id"), str) and entry["cve_id"].strip()
    ]
    invalid_count = len(entries) - len(valid_entries)
    if invalid_count:
        logger.warning(
            "Ignoring %d malformed audit override entries from %s",
            invalid_count,
            override_path,
        )
    return valid_entries


def _read_audit_adjudication_file() -> list[dict]:
    """Load the versioned CVE-level AI-causality adjudication corpus.

    The corpus is a release-safety input. Malformed or conflicting labels are
    fatal so a broken file cannot silently publish a known false positive.
    """
    path = os.path.join(
        os.path.dirname(__file__), "..", "publication_adjudications.json"
    )
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"Failed to load audit adjudications from {path}: {exc}") from exc

    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("Audit adjudications require schema_version 1")
    entries = payload.get("adjudications")
    if not isinstance(entries, list):
        raise ValueError("Audit adjudications must contain an adjudications array")

    allowed = {"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"}
    validated: list[dict] = []
    seen: set[str] = set()
    labels_by_subject: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Every audit adjudication must be an object")
        cve_id = entry.get("cve_id")
        label = entry.get("label")
        if not isinstance(cve_id, str) or not cve_id.strip():
            raise ValueError("Every audit adjudication requires cve_id")
        if cve_id in seen:
            raise ValueError(f"Duplicate audit adjudication for {cve_id}")
        if label not in allowed:
            raise ValueError(f"Invalid audit adjudication label for {cve_id}: {label}")
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list) or any(not isinstance(alias, str) or not alias.strip() for alias in aliases):
            raise ValueError(f"Invalid audit aliases for {cve_id}")
        if len(aliases) != len(set(aliases)) or cve_id in aliases:
            raise ValueError(f"Duplicate audit aliases for {cve_id}")
        _audit_excluded_aliases(entry)
        confidence = entry.get("confidence")
        if confidence is not None and (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            raise ValueError(f"Invalid audit confidence for {cve_id}")
        excluded_subjects = entry.get("excluded_bic_subjects")
        if excluded_subjects is not None:
            if label != "AI_CAUSAL" or not isinstance(excluded_subjects, list) or not excluded_subjects:
                raise ValueError(f"Invalid excluded BIC subjects for {cve_id}")
            seen_subjects: set[tuple[str, str, str]] = set()
            for subject in excluded_subjects:
                if not isinstance(subject, dict) or set(subject) != _BIC_SUBJECT_KEYS:
                    raise ValueError(f"Invalid excluded BIC subjects for {cve_id}")
                fix_sha = subject["fix_commit_sha"]
                commit_sha = subject["commit_sha"]
                blamed_file = subject["blamed_file"]
                if (
                    not isinstance(fix_sha, str)
                    or _FULL_GIT_SHA_RE.fullmatch(fix_sha) is None
                    or not isinstance(commit_sha, str)
                    or _FULL_GIT_SHA_RE.fullmatch(commit_sha) is None
                    or not isinstance(blamed_file, str)
                    or blamed_file != blamed_file.strip()
                    or blamed_file.startswith(("/", "\\", "("))
                    or "\\" in blamed_file
                    or "\x00" in blamed_file
                    or any(part in {"", ".", ".."} for part in blamed_file.split("/"))
                ):
                    raise ValueError(f"Invalid excluded BIC subjects for {cve_id}")
                subject_key = (fix_sha, commit_sha, blamed_file)
                if subject_key in seen_subjects:
                    raise ValueError(f"Duplicate excluded BIC subject for {cve_id}")
                seen_subjects.add(subject_key)
        for subject_id in [cve_id, *aliases]:
            existing_label = labels_by_subject.get(subject_id)
            if existing_label is not None and existing_label != label:
                raise ValueError(f"Conflicting audit adjudication for alias {subject_id}")
            labels_by_subject[subject_id] = label
        seen.add(cve_id)
        validated.append(entry)
    return validated


def _audit_subject_ids(entry: dict) -> set[str]:
    """Return the canonical advisory ID and every explicitly audited alias."""
    return {entry["cve_id"], *entry.get("aliases", [])}


def _audit_excluded_aliases(entry: dict) -> set[str]:
    """Return validated aliases that source expansion must not resurrect."""
    canonical_id = entry.get("cve_id")
    aliases = entry.get("aliases", [])
    excluded = entry.get("excluded_aliases", [])
    if not isinstance(excluded, list) or any(
        not isinstance(alias, str) or not alias.strip() for alias in excluded
    ):
        raise ValueError(f"Invalid excluded audit aliases for {canonical_id}")
    normalized = {alias.upper() for alias in excluded}
    if len(normalized) != len(excluded):
        raise ValueError(f"Duplicate excluded audit aliases for {canonical_id}")
    subjects = {
        subject.upper()
        for subject in [canonical_id, *aliases]
        if isinstance(subject, str)
    }
    if subjects & normalized:
        raise ValueError(f"Audit aliases and excluded aliases overlap for {canonical_id}")
    return normalized


def expand_audit_adjudications(
    entries: list[dict],
    alias_map: dict[str, set[str]] | None = None,
) -> list[dict]:
    """Expand audited subjects through source-known alias equivalence classes.

    Audit files intentionally remain small and reviewable, so they may name
    only one ID from a CVE/GHSA/OSV equivalence class.  Publication filtering
    must still apply that label to every source-known alias.  Any overlap
    between two adjudication rows is rejected: differing labels are unsafe,
    while duplicate same-label rows would double-count the quality sample.
    """
    source_aliases = alias_map or {}
    expanded: list[dict] = []
    subject_owner: dict[str, tuple[str, str]] = {}
    excluded_aliases = set().union(
        *(_audit_excluded_aliases(entry) for entry in entries)
    )
    explicit_subjects = {
        subject.upper()
        for entry in entries
        for subject in _audit_subject_ids(entry)
    }
    if overlap := excluded_aliases & explicit_subjects:
        raise ValueError(f"Excluded audit aliases are explicit subjects: {sorted(overlap)}")

    for entry in entries:
        canonical_id = entry["cve_id"]
        label = entry["label"]
        subjects = _audit_subject_ids(entry)
        pending = list(subjects)
        while pending:
            subject_id = pending.pop()
            for alias in source_aliases.get(subject_id, ()):
                if alias.upper() not in excluded_aliases and alias not in subjects:
                    subjects.add(alias)
                    pending.append(alias)

        for subject_id in sorted(subjects):
            owner = subject_owner.get(subject_id)
            if owner is None:
                subject_owner[subject_id] = (canonical_id, label)
                continue
            owner_id, owner_label = owner
            if owner_label != label:
                raise ValueError(
                    "Conflicting audit adjudications for source aliases "
                    f"{owner_id} ({owner_label}) and {canonical_id} ({label})"
                )
            raise ValueError(
                "Duplicate audit adjudications for source aliases "
                f"{owner_id} and {canonical_id}"
            )

        expanded.append(
            {
                **entry,
                "aliases": sorted(subjects - {canonical_id}),
            }
        )
    return expanded


def _expanded_audit_adjudications(
    alias_map: dict[str, set[str]] | None = None,
) -> list[dict]:
    return expand_audit_adjudications(_read_audit_adjudication_file(), alias_map)


def load_adjudicated_positive_ids(
    alias_map: dict[str, set[str]] | None = None,
) -> set[str]:
    """Return only independently adjudicated AI-causal vulnerability IDs."""
    ids: set[str] = set()
    for entry in _expanded_audit_adjudications(alias_map):
        if entry["label"] == "AI_CAUSAL":
            ids.update(_audit_subject_ids(entry))
    return ids


def load_audit_overrides(
    alias_map: dict[str, set[str]] | None = None,
) -> set[str]:
    """Load CVE IDs that were independently audited as true positives.

    These bypass the normal pipeline verdict filter — the audit found
    AI involvement that the pipeline missed (blame gap, verifier error, etc.).
    File: scripts/audit_overrides.json — list of {cve_id, reason} dicts.
    """
    ids = {e["cve_id"] for e in _read_audit_override_file()}
    for entry in _expanded_audit_adjudications(alias_map):
        if entry["label"] == "AI_CAUSAL":
            ids.update(_audit_subject_ids(entry))
    if ids:
        print(f"  Audit overrides: {len(ids)} CVEs force-included.")
    return ids


def load_audit_override_details(
    alias_map: dict[str, set[str]] | None = None,
) -> dict[str, dict]:
    """Load full audit override entries keyed by CVE ID."""
    details = {e["cve_id"]: e for e in _read_audit_override_file()}
    for entry in _expanded_audit_adjudications(alias_map):
        if entry["label"] == "AI_CAUSAL":
            for subject_id in _audit_subject_ids(entry):
                details[subject_id] = {
                    **details.get(subject_id, {}),
                    **entry,
                }
    return details


def load_audit_exclusions(
    alias_map: dict[str, set[str]] | None = None,
) -> set[str]:
    """Return adjudications that are unsafe to publish as AI-caused.

    ``NOT_AI_CAUSAL`` is a confirmed negative and ``INCONCLUSIVE`` lacks the
    evidence required for a positive attribution. Both labels fail closed at
    publication time; ``AI_CAUSAL`` keeps its independent force-include path.
    """
    ids: set[str] = set()
    for entry in _expanded_audit_adjudications(alias_map):
        if entry["label"] in {"NOT_AI_CAUSAL", "INCONCLUSIVE"}:
            ids.update(_audit_subject_ids(entry))
    return ids
