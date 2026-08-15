"""Shared parsing and local indexing of advisory fix-commit references."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import time
import zipfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


_CACHE_SCHEMA_VERSION = 3
_PUBLIC_ID_RE = re.compile(r"^(?:CVE-\d{4}-\d+|GHSA-[0-9A-Za-z-]+)$", re.IGNORECASE)

NATIVE_GIT_FIXED = "native_git_fixed"
CONVERTED_VERSION_BOUNDARY = "converted_version_boundary"
COMMIT_URL = "commit_url"


def _git_range_reference_kind(entry: Mapping[str, object]) -> str:
    """Distinguish native Git fixes from generated version boundaries.

    The CVE-to-OSV converter can synthesize a 40-hex ``fixed`` event by
    resolving the first version outside a CPE range to a release tag. That is
    a useful public boundary candidate, but it is not evidence that the tag
    commit itself contains the security fix.
    """

    database_specific = entry.get("database_specific")
    if not isinstance(database_specific, Mapping):
        return NATIVE_GIT_FIXED
    raw_sources = database_specific.get("source")
    if isinstance(raw_sources, str):
        sources = {raw_sources}
    elif isinstance(raw_sources, Sequence) and not isinstance(
        raw_sources, (str, bytes)
    ):
        sources = {str(value) for value in raw_sources}
    else:
        sources = set()
    if "CPE_RANGE" in sources or database_specific.get("extracted_events"):
        return CONVERTED_VERSION_BOUNDARY
    return NATIVE_GIT_FIXED


def commit_reference_rows_from_record(
    record: dict[str, Any],
) -> list[dict[str, str]]:
    """Return provenance-preserving public commit references from an advisory."""

    from cohort.commit_urls import parse_foreign_commit_url
    from cve_analyzer.git_url import parse_commit_url, parse_repo_url

    rows: list[dict[str, str]] = []
    for affected in record.get("affected") or []:
        for entry in affected.get("ranges") or []:
            if entry.get("type") != "GIT":
                continue
            parsed = parse_repo_url(str(entry.get("repo") or ""))
            if not parsed:
                continue
            identity = "/".join(str(part) for part in parsed).lower()
            reference_kind = _git_range_reference_kind(entry)
            for event in entry.get("events") or []:
                fixed = str(event.get("fixed") or "").strip().lower()
                if len(fixed) == 40 and all(
                    character in "0123456789abcdef" for character in fixed
                ):
                    rows.append(
                        {
                            "repository_identity": identity,
                            "fix_sha": fixed,
                            "reference_kind": reference_kind,
                            "reference_detail": "affected.ranges.events.fixed",
                        }
                    )
    for reference in record.get("references") or []:
        url = str(reference.get("url") or "")
        if not url:
            continue
        resolved = None
        try:
            parsed = parse_commit_url(url)
            if parsed:
                resolved = (
                    f"{parsed.host}/{parsed.owner}/{parsed.repo}".lower(),
                    parsed.sha.lower(),
                )
        except Exception:  # noqa: BLE001 - malformed public URLs are data, not fatal
            resolved = None
        if resolved is None:
            foreign = parse_foreign_commit_url(url)
            if foreign:
                resolved = (foreign[0].lower(), foreign[1].lower())
        if resolved and len(resolved[1]) >= 7:
            rows.append(
                {
                    "repository_identity": resolved[0],
                    "fix_sha": resolved[1],
                    "reference_kind": COMMIT_URL,
                    "reference_detail": "references.commit_url",
                }
            )
    return rows


def commit_refs_from_record(record: dict[str, Any]) -> list[tuple[str, str]]:
    """Return repository identity and fix reference pairs named by one advisory."""

    return [
        (row["repository_identity"], row["fix_sha"])
        for row in commit_reference_rows_from_record(record)
    ]


def introduced_reference_rows_from_record(
    record: dict[str, Any],
) -> list[dict[str, object]]:
    """Return exact OSV GIT-introduced observations with their public aliases."""

    from cve_analyzer.git_url import parse_repo_url
    from cve_analyzer.osv import extract_introduced_commits

    record_id = str(record.get("id") or "")
    public_ids = sorted(
        {
            str(value).upper()
            for value in (record_id, *(record.get("aliases") or []))
            if _PUBLIC_ID_RE.fullmatch(str(value or ""))
        }
    )
    rows: list[dict[str, object]] = []
    for introduced_sha, repo_url in extract_introduced_commits(record):
        parsed = parse_repo_url(repo_url)
        if parsed is None:
            continue
        rows.append(
            {
                "repository_identity": "/".join(str(part) for part in parsed).lower(),
                "introduced_sha": introduced_sha.lower(),
                "record_id": record_id,
                "public_ids": public_ids,
                "published": str(record.get("published") or ""),
            }
        )
    return rows


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_osv_archive_manifest(osv_dir: Path) -> list[dict[str, object]]:
    """Hash every local archive once for provenance and cache selection."""

    return [
        {
            "name": archive.name,
            "size_bytes": archive.stat().st_size,
            "sha256": _sha256_file(archive),
        }
        for archive in sorted(osv_dir.glob("*.zip"))
    ]


def _validated_manifest(
    osv_dir: Path,
    raw: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    manifest: list[dict[str, object]] = []
    for row in raw:
        name = str(row.get("name") or "")
        sha = str(row.get("sha256") or "")
        size = row.get("size_bytes")
        if not name or Path(name).name != name:
            raise ValueError("OSV archive manifest contains an unsafe name")
        if len(sha) != 64 or any(character not in "0123456789abcdef" for character in sha):
            raise ValueError("OSV archive manifest contains an invalid sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("OSV archive manifest contains an invalid size")
        archive = osv_dir / name
        if archive.is_symlink() or not archive.is_file() or archive.stat().st_size != size:
            raise ValueError(f"OSV archive manifest does not match local file: {name}")
        manifest.append({"name": name, "size_bytes": size, "sha256": sha})
    manifest.sort(key=lambda row: str(row["name"]))
    return manifest


def _scan_archive(
    archive: Path,
    *,
    cutoff: str = "",
    until: str = "",
) -> tuple[list[dict[str, str]], list[dict[str, object]], dict[str, int]]:
    fix_rows: list[dict[str, str]] = []
    introduced_rows: list[dict[str, object]] = []
    stats = Counter[str]()
    stats["archives"] = 1
    try:
        handle = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile):
        stats["unreadable_archives"] += 1
        return fix_rows, introduced_rows, dict(stats)
    with handle:
        for name in handle.namelist():
            if not name.endswith(".json"):
                continue
            try:
                record = json.loads(handle.read(name))
            except (ValueError, OSError, KeyError):
                stats["unreadable_records"] += 1
                continue
            if not isinstance(record, dict):
                stats["unreadable_records"] += 1
                continue
            stats["records"] += 1
            published = str(record.get("published") or "")
            if cutoff and (not published or published < cutoff):
                if not published:
                    stats["missing_publication_date"] += 1
                continue
            if until and (not published or published[:10] > until):
                if not published:
                    stats["missing_publication_date"] += 1
                continue
            stats["in_window"] += 1
            references = commit_reference_rows_from_record(record)
            introduced = introduced_reference_rows_from_record(record)
            if references:
                stats["with_fix_commit"] += 1
            if introduced:
                stats["with_introduced_commit"] += 1
            advisory = str(record.get("id") or "")
            fix_rows.extend(
                {
                    **reference,
                    "advisory": advisory,
                    "published": published,
                }
                for reference in references
            )
            introduced_rows.extend(introduced)
    fix_rows.sort(
        key=lambda row: (
            row["repository_identity"],
            row["advisory"],
            row["fix_sha"],
            row["published"],
        )
    )
    introduced_rows.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["introduced_sha"]),
            str(row["record_id"]),
        )
    )
    return fix_rows, introduced_rows, dict(stats)


def _cache_shard_path(cache_dir: Path, archive: Mapping[str, object]) -> Path:
    name_digest = hashlib.sha256(str(archive["name"]).encode("utf-8")).hexdigest()[:12]
    return cache_dir / f"v{_CACHE_SCHEMA_VERSION}-{archive['sha256']}-{name_digest}.json.gz"


def _cache_payload(
    archive: Mapping[str, object],
    fix_rows: list[dict[str, str]],
    introduced_rows: list[dict[str, object]],
    stats: Mapping[str, int],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": _CACHE_SCHEMA_VERSION,
        "artifact_kind": "osv_advisory_fix_index_shard",
        "archive": dict(archive),
        "fix_rows": fix_rows,
        "introduced_rows": introduced_rows,
        "stats": dict(sorted(stats.items())),
    }
    payload["payload_sha256"] = _canonical_sha256(payload)
    return payload


def _load_cache_shard(
    path: Path,
    archive: Mapping[str, object],
) -> tuple[list[dict[str, str]], list[dict[str, object]], dict[str, int]] | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, gzip.BadGzipFile):
        return None
    if not isinstance(payload, dict):
        return None
    digest = str(payload.get("payload_sha256") or "")
    unsigned = {key: value for key, value in payload.items() if key != "payload_sha256"}
    if (
        payload.get("schema_version") != _CACHE_SCHEMA_VERSION
        or payload.get("artifact_kind") != "osv_advisory_fix_index_shard"
        or payload.get("archive") != dict(archive)
        or _canonical_sha256(unsigned) != digest
    ):
        return None
    raw_rows = payload.get("fix_rows")
    raw_introduced = payload.get("introduced_rows")
    raw_stats = payload.get("stats")
    if (
        not isinstance(raw_rows, list)
        or not isinstance(raw_introduced, list)
        or not isinstance(raw_stats, dict)
    ):
        return None
    rows: list[dict[str, str]] = []
    required = {
        "repository_identity",
        "advisory",
        "fix_sha",
        "published",
        "reference_kind",
        "reference_detail",
    }
    for raw in raw_rows:
        if not isinstance(raw, dict) or set(raw) != required:
            return None
        row = {key: str(raw[key]) for key in required}
        rows.append(row)
    introduced_rows: list[dict[str, object]] = []
    introduced_required = {
        "repository_identity",
        "introduced_sha",
        "record_id",
        "public_ids",
        "published",
    }
    for raw in raw_introduced:
        if not isinstance(raw, dict) or set(raw) != introduced_required:
            return None
        public_ids = raw.get("public_ids")
        if not isinstance(public_ids, list) or any(
            not isinstance(value, str) for value in public_ids
        ):
            return None
        introduced_rows.append(
            {
                "repository_identity": str(raw["repository_identity"]),
                "introduced_sha": str(raw["introduced_sha"]),
                "record_id": str(raw["record_id"]),
                "public_ids": list(public_ids),
                "published": str(raw["published"]),
            }
        )
    stats: dict[str, int] = {}
    for key, value in raw_stats.items():
        if not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool):
            return None
        stats[key] = value
    return rows, introduced_rows, stats


def _write_cache_shard(path: Path, payload: Mapping[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with gzip.open(temporary, "wt", encoding="utf-8", compresslevel=6) as handle:
        json.dump(payload, handle, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def index_advisory_observations(
    osv_dir: Path,
    cohort_repos: set[str],
    cutoff: str = "",
    *,
    until: str = "",
    cache_dir: Path | None = None,
) -> tuple[
    dict[str, list[dict[str, str]]],
    dict[str, list[dict[str, object]]],
    dict[str, Any],
]:
    """Index public fix and introduced observations in one archive pass.

    An empty cutoff is intentional and means all locally available records.
    Recall-first callers should leave it empty. Reproduction cutoffs bypass the
    cache so legacy in-window statistics retain their exact prior meaning.
    """

    started = time.monotonic()
    manifest_started = time.monotonic()
    manifest = _validated_manifest(osv_dir, build_osv_archive_manifest(osv_dir))
    manifest_elapsed = time.monotonic() - manifest_started
    manifest_sha = _canonical_sha256(manifest)
    cache_enabled = cache_dir is not None and not cutoff and not until
    cache_error = ""
    if cache_enabled:
        assert cache_dir is not None
        try:
            if cache_dir.is_symlink() or (cache_dir.exists() and not cache_dir.is_dir()):
                raise OSError("cache path is not a real directory")
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            cache_enabled = False
            cache_error = f"cache_directory_unavailable:{type(exc).__name__}"

    aggregate = Counter[str]()
    cache_hits = 0
    cache_misses = 0
    cache_write_failures = 0
    selected_rows: list[dict[str, str]] = []
    selected_introduced: list[dict[str, object]] = []
    shard_started = time.monotonic()
    for archive_row in manifest:
        archive = osv_dir / str(archive_row["name"])
        shard: tuple[
            list[dict[str, str]], list[dict[str, object]], dict[str, int]
        ] | None = None
        shard_path: Path | None = None
        if cache_enabled:
            assert cache_dir is not None
            shard_path = _cache_shard_path(cache_dir, archive_row)
            shard = _load_cache_shard(shard_path, archive_row)
        if shard is None:
            rows, introduced_rows, archive_stats = _scan_archive(
                archive, cutoff=cutoff, until=until
            )
            if cache_enabled:
                cache_misses += 1
                assert shard_path is not None
                try:
                    _write_cache_shard(
                        shard_path,
                        _cache_payload(
                            archive_row, rows, introduced_rows, archive_stats
                        ),
                    )
                except OSError:
                    cache_write_failures += 1
        else:
            cache_hits += 1
            rows, introduced_rows, archive_stats = shard
        aggregate.update(archive_stats)
        selected_rows.extend(
            row for row in rows if row["repository_identity"] in cohort_repos
        )
        selected_introduced.extend(
            row
            for row in introduced_rows
            if row["repository_identity"] in cohort_repos
        )

    selected_rows.sort(
        key=lambda row: (
            row["repository_identity"],
            row["advisory"],
            row["fix_sha"],
            row["published"],
        )
    )
    by_repo: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in selected_rows:
        by_repo[row["repository_identity"]].append(
            {
                "advisory": row["advisory"],
                "fix_sha": row["fix_sha"],
                "published": row["published"],
                "reference_kind": row["reference_kind"],
                "reference_detail": row["reference_detail"],
            }
        )
    selected_introduced.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["introduced_sha"]),
            str(row["record_id"]),
        )
    )
    introduced_by_repo: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in selected_introduced:
        introduced_by_repo[str(row["repository_identity"])].append(
            {
                key: value
                for key, value in row.items()
                if key != "repository_identity"
            }
        )
    aggregate["landing_in_cohort"] = len(selected_rows)
    aggregate["introduced_landing_in_cohort"] = len(selected_introduced)
    if cutoff or until:
        cache_status = "bypassed_reproduction_cutoff"
    elif cache_dir is None:
        cache_status = "disabled"
    elif not cache_enabled:
        cache_status = "disabled_error"
    elif cache_misses == 0:
        cache_status = "hit"
    elif cache_hits == 0:
        cache_status = "cold_build"
    else:
        cache_status = "partial_rebuild"
    stats: dict[str, Any] = dict(aggregate)
    stats.update(
        {
            "archive_manifest": manifest,
            "archive_manifest_sha256": manifest_sha,
            "cache_schema_version": _CACHE_SCHEMA_VERSION,
            "cache_status": cache_status,
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "cache_write_failures": cache_write_failures,
            "cache_error": cache_error,
            "manifest_hash_elapsed_seconds": round(manifest_elapsed, 3),
            "shard_index_elapsed_seconds": round(
                time.monotonic() - shard_started, 3
            ),
            "index_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    )
    return dict(by_repo), dict(introduced_by_repo), stats


def index_advisory_fixes(
    osv_dir: Path,
    cohort_repos: set[str],
    cutoff: str = "",
    *,
    until: str = "",
    cache_dir: Path | None = None,
) -> tuple[dict[str, list[dict[str, str]]], dict[str, Any]]:
    """Compatibility view over :func:`index_advisory_observations`."""

    fixes, _introduced, stats = index_advisory_observations(
        osv_dir,
        cohort_repos,
        cutoff=cutoff,
        until=until,
        cache_dir=cache_dir,
    )
    return fixes, stats
