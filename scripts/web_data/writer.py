"""Publish and read the reviewable per-CVE Web data layout.

The public directory is one generation and is promoted as a unit::

    index.json       manifest with the ordered entry ids
    cves/<ID>.json   one validated entry per file
    stats.json       aggregates for the same entry generation
    inventory.json   optional, separately content-addressed detector inventory

Writers build and validate a sibling staging directory before swapping it
into place.  Readers validate the complete manifest/file/stats relationship
and fail closed on missing, corrupt, duplicated, unsafe, or inconsistent data.
"""

from __future__ import annotations

import ctypes
import errno
import json
import hashlib
import math
import os
import re
import shutil
import stat
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime
from pathlib import Path
from typing import NoReturn

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only off Unix
    fcntl = None  # type: ignore[assignment]

from web_data.schema import (
    VULNERABILITY_ID_PATTERN,
    validate_cve_entry,
    validate_index_payload,
    validate_inventory_payload,
    validate_stats_payload,
)

_LEGACY_CVES_JSON = "cves.json"
_PUBLIC_ID = re.compile(VULNERABILITY_ID_PATTERN)
_GITHUB_REPO = re.compile(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/*$")
_AT_FDCWD = -100
_RENAME_EXCHANGE = 2
_GENERATION_CONTRACT_VERSION = 1
_MAX_PUBLISHED_INDEX_BYTES = 16 * 1024 * 1024
_MAX_PUBLISHED_STATS_BYTES = 16 * 1024 * 1024
_MAX_PUBLISHED_INVENTORY_BYTES = 128 * 1024 * 1024
_MAX_PUBLISHED_ENTRY_BYTES = 8 * 1024 * 1024
_MAX_PUBLISHED_RECEIPT_BYTES = 32 * 1024 * 1024
_MAX_PUBLISHED_INPUT_BYTES = 512 * 1024 * 1024


class PublishedDataError(ValueError):
    """Raised when a published generation is unsafe or internally inconsistent."""


class PublicationWriteError(RuntimeError):
    """Raised when the atomic publication safety contract cannot be completed."""


@dataclass(frozen=True)
class PublishedWebData:
    """A fully validated published generation."""

    index: dict
    entries: list[dict]
    stats: dict
    inventory: dict | None = None
    _raw_input_bytes: int = dataclass_field(default=0, repr=False, compare=False)


@dataclass(frozen=True)
class WriteResult:
    """Summary of one generation-level publication."""

    index_path: Path
    stats_path: Path
    cves_dir: Path
    written: int
    removed_stale: int
    removed_legacy: bool
    inventory_path: Path | None = None


@dataclass(frozen=True)
class StagedWebData:
    """A validated generation waiting for an explicit promotion decision."""

    staging_dir: Path
    output_dir: Path
    generated_at: str
    written: int
    removed_stale: int
    removed_legacy: bool


@dataclass(frozen=True)
class PublicationParentLock:
    """One stable parent directory plus the grandparent lock that protects its name."""

    path: Path
    descriptor: int
    identity: tuple[int, int]
    grandparent_descriptor: int

    def assert_current(self) -> None:
        descriptor_metadata = os.fstat(self.descriptor)
        descriptor_identity = (
            descriptor_metadata.st_dev,
            descriptor_metadata.st_ino,
        )
        try:
            path_metadata = os.stat(
                self.path.name,
                dir_fd=self.grandparent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise PublicationWriteError(
                f"publication parent path changed while locked: {self.path}"
            ) from exc
        path_identity = (path_metadata.st_dev, path_metadata.st_ino)
        if (
            descriptor_identity != self.identity
            or path_identity != self.identity
            or not stat.S_ISDIR(path_metadata.st_mode)
        ):
            raise PublicationWriteError(
                f"publication parent path changed while locked: {self.path}"
            )

    def child_identity(self, name: str) -> tuple[int, int]:
        self.assert_current()
        if not name or Path(name).name != name:
            raise PublicationWriteError("publication child name is unsafe")
        metadata = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
        return metadata.st_dev, metadata.st_ino

    def child_exists(self, name: str) -> bool:
        self.assert_current()
        try:
            os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True


@dataclass(frozen=True)
class PromotionCommitToken:
    """Proof that rollback was explicitly disabled for one live candidate."""

    output_path: Path
    candidate_identity: tuple[int, int]
    publication_parent_identity: tuple[int, int]


@dataclass
class PromotionTransaction:
    """One exchanged candidate whose previous generation remains recoverable."""

    staged: StagedWebData
    candidate_identity: tuple[int, int]
    previous_identity: tuple[int, int] | None
    parent_lock: PublicationParentLock
    state: str = "open"

    def commit(self) -> PromotionCommitToken:
        """Disable rollback only after the candidate and parent are durably rechecked."""

        if self.state == "rolled_back":
            raise PublicationWriteError("cannot commit a rolled-back publication")
        if self.state == "open":
            _commit_promotion(self)
            self.state = "committed"
        return PromotionCommitToken(
            output_path=self.staged.output_dir.absolute(),
            candidate_identity=self.candidate_identity,
            publication_parent_identity=self.parent_lock.identity,
        )


def _canonical_sha256(value: object) -> str:
    """Hash JSON data with the release evaluator's canonical encoding."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PublishedDataError(
            f"publication data is not canonical JSON: {exc}"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_source_remote_cutoff(cutoff: object) -> None:
    """Validate the refresh runner's exact schema-3 remote-parity projection."""

    if not isinstance(cutoff, dict) or set(cutoff) != {
        "checked_at_utc",
        "receipt_file",
        "remote_parity",
        "receipt",
    }:
        _invalid("release receipt source_remote_cutoff must use the exact projection")
    receipt = cutoff.get("receipt")
    checked_at = cutoff.get("checked_at_utc")
    try:
        parsed_checked_at = datetime.fromisoformat(checked_at)
    except (TypeError, ValueError) as exc:
        raise PublishedDataError(
            "release receipt source_remote_cutoff checked_at_utc is invalid"
        ) from exc
    if parsed_checked_at.tzinfo is None:
        _invalid("release receipt source_remote_cutoff checked_at_utc lacks timezone")
    receipt_file = cutoff.get("receipt_file")
    if (
        cutoff.get("remote_parity") is not True
        or not isinstance(receipt_file, dict)
        or set(receipt_file) != {"name", "path", "sha256", "size_bytes"}
        or not isinstance(receipt_file.get("name"), str)
        or not receipt_file["name"]
        or not isinstance(receipt_file.get("path"), str)
        or not Path(receipt_file["path"]).is_absolute()
        or not _valid_sha256(receipt_file.get("sha256"))
        or isinstance(receipt_file.get("size_bytes"), bool)
        or not isinstance(receipt_file.get("size_bytes"), int)
        or receipt_file["size_bytes"] <= 0
        or not isinstance(receipt, dict)
        or set(receipt)
        != {
            "schema_version",
            "checked_at_utc",
            "git_sources",
            "nvd_feeds",
            "osv_ecosystem_manifest",
            "osv_archive_count",
            "osv_archives",
            "remote_parity",
        }
        or receipt.get("schema_version") != 3
        or receipt.get("checked_at_utc") != checked_at
        or receipt.get("remote_parity") is not True
    ):
        _invalid("release receipt source_remote_cutoff schema-3 proof is invalid")

    git_sources = receipt.get("git_sources")
    git_fields = {"branch", "head", "name", "origin", "path", "remote_head", "tree"}
    if not isinstance(git_sources, list) or not git_sources:
        _invalid("release receipt source_remote_cutoff Git inventory is invalid")
    git_names: set[str] = set()
    for entry in git_sources:
        if (
            not isinstance(entry, dict)
            or set(entry) != git_fields
            or not isinstance(entry.get("name"), str)
            or not entry["name"]
            or entry["name"] in git_names
            or not isinstance(entry.get("branch"), str)
            or not entry["branch"]
            or not isinstance(entry.get("origin"), str)
            or not entry["origin"]
            or not isinstance(entry.get("path"), str)
            or not Path(entry["path"]).is_absolute()
            or entry.get("head") != entry.get("remote_head")
            or not isinstance(entry.get("head"), str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", entry["head"]) is None
            or not isinstance(entry.get("tree"), str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", entry["tree"]) is None
        ):
            _invalid("release receipt source_remote_cutoff Git entry is invalid")
        git_names.add(entry["name"])

    nvd_feeds = receipt.get("nvd_feeds")
    nvd_fields = {
        "feed_path",
        "feed_sha256",
        "feed_size",
        "meta_path",
        "meta_sha256",
        "remote_etag",
        "remote_last_modified",
        "remote_meta_sha256",
        "year",
    }
    if not isinstance(nvd_feeds, list) or not nvd_feeds:
        _invalid("release receipt source_remote_cutoff NVD inventory is invalid")
    nvd_years: set[int] = set()
    for entry in nvd_feeds:
        if (
            not isinstance(entry, dict)
            or set(entry) != nvd_fields
            or isinstance(entry.get("year"), bool)
            or not isinstance(entry.get("year"), int)
            or entry["year"] in nvd_years
            or not isinstance(entry.get("feed_path"), str)
            or not Path(entry["feed_path"]).is_absolute()
            or not isinstance(entry.get("meta_path"), str)
            or not Path(entry["meta_path"]).is_absolute()
            or not _valid_sha256(entry.get("feed_sha256"))
            or not _valid_sha256(entry.get("meta_sha256"))
            or entry.get("meta_sha256") != entry.get("remote_meta_sha256")
            or isinstance(entry.get("feed_size"), bool)
            or not isinstance(entry.get("feed_size"), int)
            or entry["feed_size"] <= 0
            or not isinstance(entry.get("remote_etag"), str)
            or not entry["remote_etag"]
            or not isinstance(entry.get("remote_last_modified"), str)
            or not entry["remote_last_modified"]
        ):
            _invalid("release receipt source_remote_cutoff NVD entry is invalid")
        nvd_years.add(entry["year"])

    manifest = receipt.get("osv_ecosystem_manifest")
    manifest_fields = {
        "ecosystem_count",
        "ecosystems",
        "etag",
        "filename",
        "generation",
        "last_modified",
        "md5_base64",
        "path",
        "remote_size",
        "sha256",
        "size",
        "url",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != manifest_fields
        or manifest.get("filename") != "ecosystems.txt"
        or not isinstance(manifest.get("ecosystems"), list)
        or manifest.get("ecosystem_count") != len(manifest["ecosystems"])
        or manifest["ecosystems"] != sorted(set(manifest["ecosystems"]))
        or any(not isinstance(item, str) or not item for item in manifest["ecosystems"])
        or not isinstance(manifest.get("generation"), str)
        or not manifest["generation"].isdigit()
        or manifest.get("size") != manifest.get("remote_size")
        or isinstance(manifest.get("size"), bool)
        or not isinstance(manifest.get("size"), int)
        or manifest["size"] <= 0
        or not _valid_sha256(manifest.get("sha256"))
        or not isinstance(manifest.get("path"), str)
        or not Path(manifest["path"]).is_absolute()
        or not isinstance(manifest.get("url"), str)
        or not manifest["url"]
    ):
        _invalid("release receipt source_remote_cutoff OSV manifest is invalid")

    osv_archives = receipt.get("osv_archives")
    osv_fields = {
        "crc32c_base64",
        "etag",
        "filename",
        "generation",
        "last_modified",
        "md5_base64",
        "path",
        "remote_size",
        "sha256",
        "size",
        "url",
    }
    if (
        not isinstance(osv_archives, list)
        or not osv_archives
        or receipt.get("osv_archive_count") != len(osv_archives)
    ):
        _invalid("release receipt source_remote_cutoff OSV inventory is invalid")
    archive_names: set[str] = set()
    for entry in osv_archives:
        if (
            not isinstance(entry, dict)
            or set(entry) != osv_fields
            or not isinstance(entry.get("filename"), str)
            or not entry["filename"].endswith(".zip")
            or entry["filename"] in archive_names
            or not isinstance(entry.get("generation"), str)
            or not entry["generation"].isdigit()
            or entry.get("size") != entry.get("remote_size")
            or isinstance(entry.get("size"), bool)
            or not isinstance(entry.get("size"), int)
            or entry["size"] <= 0
            or not _valid_sha256(entry.get("sha256"))
            or not isinstance(entry.get("path"), str)
            or not Path(entry["path"]).is_absolute()
            or not isinstance(entry.get("url"), str)
            or not entry["url"]
        ):
            _invalid("release receipt source_remote_cutoff OSV entry is invalid")
        archive_names.add(entry["filename"])


def _generation_id(
    entries: list[dict],
    stats: dict,
    *,
    generated_at: str,
) -> str:
    """Bind one ID to the exact ordered entries and aggregate payload.

    ``generation_id`` is omitted from the preimage so the digest can be stored
    in every artifact. The manifest is derived from the ordered entries.
    """
    return _canonical_sha256(
        {
            "schema_version": _GENERATION_CONTRACT_VERSION,
            "generated_at": generated_at,
            "entries": entries,
            "stats": stats,
        }
    )


def _without_generation_id(payload: dict) -> dict:
    """Return a shallow copy suitable for generation-digest verification."""
    return {key: value for key, value in payload.items() if key != "generation_id"}


def _invalid(message: str) -> NoReturn:
    raise PublishedDataError(message)


def _validate_public_id(public_id: object) -> str:
    if not isinstance(public_id, str) or _PUBLIC_ID.fullmatch(public_id) is None:
        _invalid(
            "entry id must start with an ASCII letter or digit and contain only "
            f"ASCII letters, digits, dots, underscores, or hyphens; got {public_id!r}"
        )
    return public_id


def _entry_path(cves_dir: Path, public_id: str) -> Path:
    """Return a contained filename for a validated public id."""
    public_id = _validate_public_id(public_id)
    base = cves_dir.resolve(strict=False)
    candidate = (base / f"{public_id}.json").resolve(strict=False)
    if candidate.parent != base:
        _invalid(f"entry path escapes the CVE directory: {public_id!r}")
    return candidate


def _expected_aggregates(entries: list[dict]) -> dict[str, object]:
    """Recompute the entry-derived subset of ``StatsData``."""
    by_tool: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    by_language: Counter[str] = Counter()
    by_repo: Counter[str] = Counter()
    by_month: Counter[str] = Counter()
    month_tools: dict[str, Counter[str]] = {}

    latest_date = ""
    for entry in entries:
        by_tool.update(entry.get("ai_tools", []))
        by_severity[entry.get("severity", "UNKNOWN")] += 1
        by_language.update(entry.get("languages", []))

        repos: set[str] = set()
        for fix_commit in entry.get("fix_commits", []):
            match = _GITHUB_REPO.fullmatch(
                str(fix_commit.get("repo_url", "")).rstrip("/")
            )
            if match:
                repos.add(f"{match.group(1)}/{match.group(2)}".lower())
        by_repo.update(repos)

        published = entry.get("published", "")
        month = published[:7] if len(published) == 10 else ""
        if month:
            by_month[month] += 1
            month_tools.setdefault(month, Counter()).update(entry.get("ai_tools", []))
        coverage_date = f"{published}-01-01" if len(published) == 4 else published
        latest_date = max(latest_date, coverage_date)

    return {
        "total_cves": len(entries),
        "by_tool": dict(by_tool),
        "by_severity": dict(by_severity),
        "by_language": dict(by_language),
        "by_repo": dict(by_repo),
        "by_month": [
            {
                "month": month,
                "count": count,
                "by_tool": dict(month_tools.get(month, {})),
            }
            for month, count in sorted(by_month.items())
        ],
        "coverage_to": latest_date,
    }


def _validate_bundle(
    index: dict,
    entries: list[dict],
    stats: dict,
    inventory: dict | None = None,
) -> None:
    """Validate schemas plus all cross-file publication invariants."""
    validate_index_payload(index)
    validate_stats_payload(stats)
    inventory_summary = stats.get("inventory")
    if inventory is None and inventory_summary is not None:
        _invalid("stats.json references a missing inventory.json")
    if inventory is not None:
        validate_inventory_payload(inventory)
        expected_inventory_summary = {
            "path": "inventory.json",
            "inventory_id": inventory["inventory_id"],
            "source_snapshot_sha256": inventory["source_snapshot_sha256"],
            "source_alias_class_manifest_sha256": inventory[
                "source_alias_class_manifest_sha256"
            ],
            "campaign_id": inventory["campaign_id"],
            "campaign_mode": inventory["campaign_mode"],
            "complete": inventory["complete"],
            "coverage_to": inventory["coverage_to"],
            "alias_class_count": inventory["alias_class_count"],
            "detector_candidate_count": inventory["detector_candidate_count"],
            "pending_adjudication_count": inventory["pending_adjudication_count"],
            "coverage_failure_count": inventory["coverage_failure_count"],
        }
        if inventory_summary != expected_inventory_summary:
            _invalid("stats.json inventory binding does not match inventory.json")

    ids: list[str] = []
    for entry in entries:
        validate_cve_entry(entry)
        ids.append(_validate_public_id(entry.get("id")))

    if len(ids) != len(set(ids)):
        duplicates = sorted(
            public_id for public_id, count in Counter(ids).items() if count > 1
        )
        _invalid(f"duplicate entry ids: {duplicates}")

    index_ids = [_validate_public_id(public_id) for public_id in index.get("ids", [])]
    if len(index_ids) != len(set(index_ids)):
        duplicates = sorted(
            public_id for public_id, count in Counter(index_ids).items() if count > 1
        )
        _invalid(f"duplicate manifest ids: {duplicates}")
    if index.get("total") != len(index_ids):
        _invalid(
            f"manifest total {index.get('total')!r} does not match {len(index_ids)} ids"
        )
    if index_ids != ids:
        _invalid("manifest ids and entry ids differ or are in a different order")

    if stats.get("generated_at") != index.get("generated_at"):
        _invalid("index.json and stats.json must share one generated_at value")

    generation_id = index.get("generation_id")
    if stats.get("generation_id") != generation_id:
        _invalid("index.json and stats.json must share one generation_id")
    mismatched_entries = [
        entry.get("id", "<unknown>")
        for entry in entries
        if entry.get("generation_id") != generation_id
    ]
    if mismatched_entries:
        _invalid(
            f"published entries belong to a different generation: {mismatched_entries}"
        )
    expected_generation_id = _generation_id(
        [_without_generation_id(entry) for entry in entries],
        _without_generation_id(stats),
        generated_at=index.get("generated_at"),
    )
    if generation_id != expected_generation_id:
        _invalid("generation_id does not match the published bundle contents")

    expected = _expected_aggregates(entries)
    for field, expected_value in expected.items():
        if stats.get(field) != expected_value:
            _invalid(f"stats.{field} is inconsistent with the published entries")

    total_analyzed = stats.get("total_analyzed")
    with_fix_commits = stats.get("with_fix_commits")
    if total_analyzed < len(entries):
        _invalid("stats.total_analyzed cannot be smaller than stats.total_cves")
    if with_fix_commits > total_analyzed:
        _invalid("stats.with_fix_commits cannot exceed stats.total_analyzed")


def _stable_regular_bytes(path: Path, label: str, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublishedDataError(f"cannot open {label} at {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _invalid(f"{label} is missing or is not a regular file: {path}")
        if before.st_size > max_bytes:
            _invalid(f"{label} exceeds the {max_bytes}-byte size bound: {path}")
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                _invalid(f"{label} exceeds the {max_bytes}-byte size bound: {path}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except PublishedDataError:
        raise
    except OSError as exc:
        raise PublishedDataError(f"cannot read {label} at {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    signature = lambda value: (  # noqa: E731 - compact immutable stat projection
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if signature(before) != signature(after) or len(content) != after.st_size:
        _invalid(f"{label} changed while being read: {path}")
    try:
        current = path.lstat()
    except OSError as exc:
        raise PublishedDataError(f"cannot recheck {label} at {path}: {exc}") from exc
    if signature(current) != signature(after):
        _invalid(f"{label} path changed while being read: {path}")
    return content


def _read_json_object(
    path: Path,
    label: str,
    *,
    max_bytes: int,
) -> tuple[dict, int]:
    try:
        content = _stable_regular_bytes(path, label, max_bytes=max_bytes)
        value = json.loads(content)
    except PublishedDataError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PublishedDataError(f"cannot read {label} at {path}: {exc}") from exc
    if not isinstance(value, dict):
        _invalid(f"{label} must contain a JSON object")
    return value, len(content)


def _load_published_web_data_unlocked(output_dir: Path) -> PublishedWebData:
    """Read one generation while the caller holds the publication lock."""
    output_dir = Path(output_dir)
    if output_dir.is_symlink() or not output_dir.is_dir():
        _invalid(f"published data directory is missing or unsafe: {output_dir}")

    index, index_bytes = _read_json_object(
        output_dir / "index.json",
        "manifest",
        max_bytes=_MAX_PUBLISHED_INDEX_BYTES,
    )
    stats, stats_bytes = _read_json_object(
        output_dir / "stats.json",
        "statistics",
        max_bytes=_MAX_PUBLISHED_STATS_BYTES,
    )
    total_input_bytes = index_bytes + stats_bytes
    inventory: dict | None = None
    inventory_path = output_dir / "inventory.json"
    if os.path.lexists(inventory_path):
        inventory, inventory_bytes = _read_json_object(
            inventory_path,
            "detector inventory",
            max_bytes=_MAX_PUBLISHED_INVENTORY_BYTES,
        )
        total_input_bytes += inventory_bytes
    if total_input_bytes > _MAX_PUBLISHED_INPUT_BYTES:
        _invalid("published Web data exceeds the aggregate input size bound")
    validate_index_payload(index)

    index_ids = [_validate_public_id(public_id) for public_id in index.get("ids", [])]
    if len(index_ids) != len(set(index_ids)):
        _invalid("manifest contains duplicate ids")

    cves_dir = output_dir / "cves"
    if cves_dir.is_symlink() or not cves_dir.is_dir():
        _invalid(f"published CVE directory is missing or unsafe: {cves_dir}")

    expected_names = {f"{public_id}.json" for public_id in index_ids}
    actual_names: set[str] = set()
    try:
        for child in cves_dir.iterdir():
            if child.is_symlink() or not child.is_file() or child.suffix != ".json":
                _invalid(
                    f"unexpected non-entry artifact in published CVE directory: {child.name}"
                )
            actual_names.add(child.name)
    except OSError as exc:
        raise PublishedDataError(
            f"cannot enumerate published CVE directory: {exc}"
        ) from exc

    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    if missing or unexpected:
        _invalid(f"manifest/file mismatch; missing={missing}, unexpected={unexpected}")

    entries: list[dict] = []
    for public_id in index_ids:
        entry, entry_bytes = _read_json_object(
            _entry_path(cves_dir, public_id),
            f"entry {public_id}",
            max_bytes=_MAX_PUBLISHED_ENTRY_BYTES,
        )
        total_input_bytes += entry_bytes
        if total_input_bytes > _MAX_PUBLISHED_INPUT_BYTES:
            _invalid("published Web data exceeds the aggregate input size bound")
        if entry.get("id") != public_id:
            _invalid(f"entry filename/id mismatch for {public_id!r}")
        entries.append(entry)

    _validate_bundle(index, entries, stats, inventory)
    return PublishedWebData(
        index=index,
        entries=entries,
        stats=stats,
        inventory=inventory,
        _raw_input_bytes=total_input_bytes,
    )


@contextmanager
def _publication_parent_lock(
    output_dir: Path,
    *,
    exclusive: bool,
    error_type: type[PublishedDataError] | type[PublicationWriteError],
) -> Iterator[PublicationParentLock]:
    """Lock the stable grandparent and bind the publication parent by descriptor."""

    parent = Path(output_dir).absolute().parent
    grandparent = parent.parent
    if parent == grandparent:
        raise error_type("safe publication requires a non-root parent directory")
    if fcntl is None:
        raise error_type("safe publication requires Linux-compatible flock support")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        grandparent_descriptor = os.open(grandparent, flags)
    except OSError as exc:
        raise error_type(
            f"cannot open publication grandparent directory {grandparent}: {exc}"
        ) from exc
    descriptor: int | None = None
    try:
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        try:
            fcntl.flock(grandparent_descriptor, operation)
        except OSError as exc:
            raise error_type(
                f"cannot lock publication grandparent directory {grandparent}: {exc}"
            ) from exc
        try:
            descriptor = os.open(parent.name, flags, dir_fd=grandparent_descriptor)
            metadata = os.fstat(descriptor)
            path_metadata = os.stat(
                parent.name,
                dir_fd=grandparent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise error_type(
                f"cannot bind publication parent directory {parent}: {exc}"
            ) from exc
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            identity != (path_metadata.st_dev, path_metadata.st_ino)
            or not stat.S_ISDIR(metadata.st_mode)
            or not stat.S_ISDIR(path_metadata.st_mode)
        ):
            raise error_type(f"publication parent directory is unsafe: {parent}")
        binding = PublicationParentLock(
            path=parent,
            descriptor=descriptor,
            identity=identity,
            grandparent_descriptor=grandparent_descriptor,
        )
        binding.assert_current()
        yield binding
        binding.assert_current()
    except PublicationWriteError as exc:
        if error_type is PublishedDataError:
            raise PublishedDataError(str(exc)) from exc
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(grandparent_descriptor)


def load_published_web_data(output_dir: Path) -> PublishedWebData:
    """Read one complete generation under a shared publication lock."""
    output_dir = Path(output_dir)
    with _publication_parent_lock(
        output_dir,
        exclusive=False,
        error_type=PublishedDataError,
    ) as parent_lock:
        parent_lock.assert_current()
        published = _load_published_web_data_unlocked(output_dir)
        parent_lock.assert_current()
        return published


def publication_bundle_sha256(publication: PublishedWebData) -> str:
    """Return the canonical hash bound into a gated release receipt."""
    if not isinstance(publication, PublishedWebData):
        raise TypeError("publication must be a PublishedWebData instance")
    return _canonical_sha256(
        {
            "index": publication.index,
            "entries": publication.entries,
            "stats": publication.stats,
        }
    )


def staged_publication_bundle_sha256(staged: StagedWebData) -> str:
    """Hash one fully validated staged publication bundle."""
    if not isinstance(staged, StagedWebData):
        raise TypeError("staged must be a StagedWebData instance")
    return publication_bundle_sha256(load_published_web_data(staged.staging_dir))


def _write_json(path: Path, payload: dict, *, sort_keys: bool = False) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(
            payload,
            handle,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=sort_keys,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _validate_release_receipt(
    receipt: dict,
    publication: PublishedWebData,
) -> None:
    """Bind a successful formal-release receipt to one exact generation."""
    required = {
        "schema_version",
        "generation_id",
        "generated_at",
        "campaign_id",
        "campaign_result_manifest_sha256",
        "campaign_mode",
        "population_policy",
        "analyzer_contract_sha256",
        "signature_sha256",
        "alias_class_manifest_sha256",
        "source_snapshot_sha256",
        "source_remote_cutoff",
        "publication_bundle_sha256",
        "publication_manifest_sha256",
        "publication_curation_consistency_report_sha256",
        "publication_curation_inputs_sha256",
        "heldout_quality_report_sha256",
        "heldout_selection_sha256",
        "heldout_labels_sha256",
        "heldout_campaign_population_sha256",
        "heldout_campaign_proof_sha256",
        "heldout_campaign_result_manifest_sha256",
        "recall_selection_sha256",
        "recall_labels_sha256",
        "recall_report_sha256",
        "recall_inventory_id",
        "recall_selection_manifest_sha256",
        "protected_census_manifest_sha256",
        "protected_overlap_class_count",
        "protected_census_complete",
        "verifier_contract_sha256",
        "verifier_git_commit",
        "verifier_git_tree",
        "verifier_files_manifest_sha256",
        "verifier_dependency_lock_sha256",
        "recall_evaluation_status",
        "recall_evaluation_complete",
        "recall_point_estimate",
        "recall_interval",
        "targets",
        "curation_consistency_point_estimates",
        "heldout_point_estimates",
        "heldout_measurement_boundary",
        "evaluation_complete",
        "release_safe",
        "curation_consistent",
        "heldout_certified",
    }
    missing = sorted(required - receipt.keys())
    if missing:
        _invalid(f"release receipt is missing required fields: {missing}")
    if receipt.get("schema_version") != 4:
        _invalid("release receipt requires schema_version 4")
    for field in (
        "generation_id",
        "campaign_id",
        "campaign_result_manifest_sha256",
        "analyzer_contract_sha256",
        "signature_sha256",
        "alias_class_manifest_sha256",
        "source_snapshot_sha256",
        "publication_bundle_sha256",
        "publication_manifest_sha256",
        "publication_curation_consistency_report_sha256",
        "publication_curation_inputs_sha256",
        "heldout_quality_report_sha256",
        "heldout_selection_sha256",
        "heldout_labels_sha256",
        "heldout_campaign_population_sha256",
        "heldout_campaign_proof_sha256",
        "heldout_campaign_result_manifest_sha256",
        "recall_selection_sha256",
        "recall_labels_sha256",
        "recall_report_sha256",
        "recall_inventory_id",
        "recall_selection_manifest_sha256",
        "protected_census_manifest_sha256",
        "verifier_contract_sha256",
        "verifier_files_manifest_sha256",
        "verifier_dependency_lock_sha256",
    ):
        value = receipt.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            _invalid(f"release receipt {field} must be a lowercase SHA-256")
    if receipt.get("evaluation_complete") is not True:
        _invalid("release receipt evaluation_complete must be true")
    if receipt.get("release_safe") is not True:
        _invalid("release receipt release_safe must be true")
    if receipt.get("curation_consistent") is not True:
        _invalid("release receipt curation_consistent must be true")
    if receipt.get("heldout_certified") is not True:
        _invalid("release receipt heldout_certified must be true")
    protected_overlap_count = receipt.get("protected_overlap_class_count")
    if (
        receipt.get("protected_census_complete") is not True
        or isinstance(protected_overlap_count, bool)
        or not isinstance(protected_overlap_count, int)
        or protected_overlap_count < 0
    ):
        _invalid("release receipt protected census proof is invalid")
    for field in ("verifier_git_commit", "verifier_git_tree"):
        value = receipt.get(field)
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is None
        ):
            _invalid(f"release receipt {field} must be a Git object ID")
    recall_point = receipt.get("recall_point_estimate")
    recall_interval = receipt.get("recall_interval")
    if (
        receipt.get("recall_evaluation_status") != "complete_end_to_end"
        or receipt.get("recall_evaluation_complete") is not True
        or isinstance(recall_point, bool)
        or not isinstance(recall_point, (int, float))
        or not math.isfinite(float(recall_point))
        or not 0.0 <= float(recall_point) <= 1.0
        or not isinstance(recall_interval, list)
        or len(recall_interval) != 2
        or any(
            isinstance(bound, bool)
            or not isinstance(bound, (int, float))
            or not math.isfinite(float(bound))
            or not 0.0 <= float(bound) <= 1.0
            for bound in recall_interval
        )
        or float(recall_interval[0]) > float(recall_point)
        or float(recall_point) > float(recall_interval[1])
    ):
        _invalid("release receipt end-to-end recall proof is invalid")
    if (
        receipt.get("campaign_mode") != "formal"
        or receipt.get("population_policy") != "formal_full"
    ):
        _invalid("release receipt requires a formal full-population campaign")
    inventory = publication.inventory
    if inventory is None:
        _invalid("formal release detector inventory is missing")
    inventory_fields = {
        "detector_inventory_id",
        "detector_inventory_sha256",
        "detector_inventory_campaign_mode",
        "detector_inventory_complete",
        "detector_inventory_source_snapshot_sha256",
        "detector_inventory_alias_class_manifest_sha256",
        "detector_inventory_alias_class_count",
    }
    inventory_missing = sorted(inventory_fields - receipt.keys())
    if inventory_missing:
        _invalid(
            f"release receipt is missing detector inventory fields: {inventory_missing}"
        )
    if (
        receipt.get("detector_inventory_id") != inventory["inventory_id"]
        or receipt.get("detector_inventory_sha256") != _canonical_sha256(inventory)
        or receipt.get("detector_inventory_campaign_mode") != "formal"
        or receipt.get("detector_inventory_complete") is not True
        or receipt.get("detector_inventory_source_snapshot_sha256")
        != inventory["source_snapshot_sha256"]
        or receipt.get("detector_inventory_alias_class_manifest_sha256")
        != inventory["source_alias_class_manifest_sha256"]
        or receipt.get("detector_inventory_alias_class_count")
        != inventory["alias_class_count"]
        or receipt.get("recall_inventory_id") != inventory["inventory_id"]
        or inventory["campaign_mode"] != "formal"
        or inventory["complete"] is not True
    ):
        _invalid("release receipt detector inventory proof is invalid")
    targets = receipt.get("targets")
    curation_points = receipt.get("curation_consistency_point_estimates")
    heldout_points = receipt.get("heldout_point_estimates")
    if (
        not isinstance(targets, dict)
        or set(targets) != {"precision", "recall"}
        or not isinstance(curation_points, dict)
        or set(curation_points) != {"precision", "recall"}
        or not isinstance(heldout_points, dict)
        or set(heldout_points) != {"precision", "recall"}
    ):
        _invalid("release receipt quality target/point contracts are malformed")
    for metric in ("precision", "recall"):
        target = targets.get(metric)
        curation_point = curation_points.get(metric)
        heldout_point = heldout_points.get(metric)
        if (
            isinstance(target, bool)
            or not isinstance(target, (int, float))
            or not 0.95 <= float(target) <= 1.0
            or isinstance(curation_point, bool)
            or not isinstance(curation_point, (int, float))
            or not math.isfinite(float(curation_point))
            or float(curation_point) < float(target)
            or isinstance(heldout_point, bool)
            or not isinstance(heldout_point, (int, float))
            or not math.isfinite(float(heldout_point))
            or float(heldout_point) < float(target)
        ):
            _invalid(f"release receipt {metric} gate proof is invalid")
    if float(recall_point) < float(targets["recall"]) or float(
        recall_interval[0]
    ) < float(targets["recall"]):
        _invalid(
            "release receipt end-to-end recall point and interval lower bound "
            "must meet the recall target"
        )
    boundary = receipt.get("heldout_measurement_boundary")
    if (
        not isinstance(boundary, dict)
        or set(boundary) != {"precision", "recall", "excluded"}
        or any(
            not isinstance(value, str) or not value.strip()
            for value in boundary.values()
        )
        or "candidate" not in boundary["recall"].casefold()
        or "advisory discovery" not in boundary["excluded"].casefold()
        or "signature discovery" not in boundary["excluded"].casefold()
    ):
        _invalid("release receipt held-out conditional recall boundary is invalid")
    _validate_source_remote_cutoff(receipt.get("source_remote_cutoff"))
    if receipt.get("generation_id") != publication.index.get("generation_id"):
        _invalid("release receipt generation_id does not match index.json")
    if receipt.get("generated_at") != publication.index.get("generated_at"):
        _invalid("release receipt generated_at does not match index.json")
    if receipt["publication_bundle_sha256"] != publication_bundle_sha256(publication):
        _invalid(
            "release receipt publication_bundle_sha256 does not match "
            "the staged publication"
        )


def _read_release_receipt(
    staging_dir: Path,
    publication: PublishedWebData,
) -> dict:
    """Read and validate the gated-release receipt for one generation."""
    receipt, receipt_bytes = _read_json_object(
        staging_dir / "release-receipt.json",
        "release receipt",
        max_bytes=_MAX_PUBLISHED_RECEIPT_BYTES,
    )
    if publication._raw_input_bytes + receipt_bytes > _MAX_PUBLISHED_INPUT_BYTES:
        _invalid("published Web data exceeds the aggregate input size bound")
    _validate_release_receipt(receipt, publication)
    return receipt


def validate_published_release(
    output_dir: Path,
) -> tuple[PublishedWebData, dict, tuple[dict[str, object], ...]]:
    """Validate one receipted publication and return its exact raw-file manifest."""

    output_dir = Path(output_dir)
    with _publication_parent_lock(
        output_dir,
        exclusive=False,
        error_type=PublishedDataError,
    ) as parent_lock:
        parent_lock.assert_current()
        _validate_staged_inventory(output_dir, require_release_receipt=True)
        publication = _load_published_web_data_unlocked(output_dir)
        receipt = _read_release_receipt(output_dir, publication)
        paths = [output_dir / "index.json", output_dir / "stats.json"]
        if publication.inventory is not None:
            paths.append(output_dir / "inventory.json")
        paths.extend(sorted((output_dir / "cves").glob("*.json")))
        manifest_entries: list[dict[str, object]] = []
        manifest_input_bytes = 0
        for path in paths:
            if path.name == "index.json":
                max_bytes = _MAX_PUBLISHED_INDEX_BYTES
            elif path.name == "stats.json":
                max_bytes = _MAX_PUBLISHED_STATS_BYTES
            elif path.name == "inventory.json":
                max_bytes = _MAX_PUBLISHED_INVENTORY_BYTES
            else:
                max_bytes = _MAX_PUBLISHED_ENTRY_BYTES
            content = _stable_regular_bytes(
                path,
                "publication artifact",
                max_bytes=max_bytes,
            )
            manifest_input_bytes += len(content)
            if manifest_input_bytes > _MAX_PUBLISHED_INPUT_BYTES:
                _invalid("published Web data exceeds the aggregate input size bound")
            manifest_entries.append(
                {
                    "path": path.relative_to(output_dir).as_posix(),
                    "size_bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        manifest = tuple(manifest_entries)
        final_publication = _load_published_web_data_unlocked(output_dir)
        final_receipt = _read_release_receipt(output_dir, final_publication)
        if publication_bundle_sha256(publication) != publication_bundle_sha256(
            final_publication
        ) or _canonical_sha256(receipt) != _canonical_sha256(final_receipt):
            _invalid("published release changed during formal validation")
        parent_lock.assert_current()
        return final_publication, final_receipt, manifest


def _validate_staged_inventory(
    staging_dir: Path,
    *,
    require_release_receipt: bool,
) -> None:
    """Reject every artifact outside the fixed publication layout."""
    expected = {"index.json", "stats.json", "cves"}
    if os.path.lexists(staging_dir / "inventory.json"):
        expected.add("inventory.json")
    if require_release_receipt:
        expected.add("release-receipt.json")
    try:
        actual = {child.name for child in staging_dir.iterdir()}
    except OSError as exc:
        raise PublishedDataError(
            f"cannot enumerate staged publication directory: {exc}"
        ) from exc
    if actual != expected:
        _invalid(
            "staged publication inventory mismatch; "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
        )
    for file_name in expected - {"cves"}:
        path = staging_dir / file_name
        if path.is_symlink() or not path.is_file():
            _invalid(f"staged publication artifact is unsafe: {path}")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _old_layout_summary(output_dir: Path, current_names: set[str]) -> tuple[int, bool]:
    cves_dir = output_dir / "cves"
    old_names: set[str] = set()
    if cves_dir.is_dir() and not cves_dir.is_symlink():
        old_names = {
            child.name
            for child in cves_dir.iterdir()
            if child.is_file() and not child.is_symlink() and child.suffix == ".json"
        }
    return len(old_names - current_names), (output_dir / _LEGACY_CVES_JSON).exists()


def _publication_directory_mode(output_dir: Path) -> int:
    """Preserve an existing generation's mode or inherit it from the parent."""
    mode_source = output_dir if output_dir.exists() else output_dir.parent
    try:
        return stat.S_IMODE(mode_source.stat().st_mode)
    except OSError as exc:
        raise PublicationWriteError(
            f"cannot determine publication directory mode from {mode_source}"
        ) from exc


def _rename_exchange(
    first: Path,
    second: Path,
    parent_lock: PublicationParentLock | None = None,
) -> None:
    """Atomically exchange two sibling paths with Linux ``renameat2``.

    A portable two-rename fallback would make the live path disappear between
    operations and after a process kill.  Publication therefore fails closed
    when the Linux primitive is unavailable.
    """
    if not sys.platform.startswith("linux"):
        raise PublicationWriteError(
            "atomic publication requires Linux renameat2(RENAME_EXCHANGE)"
        )
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise PublicationWriteError(
            "atomic publication requires Linux renameat2(RENAME_EXCHANGE)"
        ) from exc

    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if parent_lock is None:
        first_descriptor = _AT_FDCWD
        second_descriptor = _AT_FDCWD
        first_bytes = os.fsencode(first.absolute())
        second_bytes = os.fsencode(second.absolute())
    else:
        parent_lock.assert_current()
        if (
            first.absolute().parent != parent_lock.path
            or second.absolute().parent != parent_lock.path
        ):
            raise PublicationWriteError(
                "atomic publication paths do not match the locked parent"
            )
        first_descriptor = parent_lock.descriptor
        second_descriptor = parent_lock.descriptor
        first_bytes = os.fsencode(first.name)
        second_bytes = os.fsencode(second.name)
    if (
        renameat2(
            first_descriptor,
            first_bytes,
            second_descriptor,
            second_bytes,
            _RENAME_EXCHANGE,
        )
        == 0
    ):
        return

    error_number = ctypes.get_errno()
    unavailable = {
        errno.ENOSYS,
        errno.EINVAL,
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        getattr(errno, "ENOTSUP", errno.EINVAL),
    }
    detail = os.strerror(error_number)
    if error_number in unavailable:
        detail = (
            f"{detail}; atomic publication requires a Linux filesystem with "
            "renameat2(RENAME_EXCHANGE) support"
        )
    raise PublicationWriteError(
        f"cannot atomically exchange {first} and {second}: {detail}"
    )


def _path_identity(path: Path) -> tuple[int, int]:
    """Return the filesystem identity of a path without following symlinks."""
    metadata = path.stat(follow_symlinks=False)
    return metadata.st_dev, metadata.st_ino


def _locked_path_identity(
    path: Path,
    parent_lock: PublicationParentLock,
) -> tuple[int, int]:
    if path.absolute().parent != parent_lock.path:
        raise PublicationWriteError("publication path does not match the locked parent")
    return parent_lock.child_identity(path.name)


def _locked_path_exists(path: Path, parent_lock: PublicationParentLock) -> bool:
    if path.absolute().parent != parent_lock.path:
        raise PublicationWriteError("publication path does not match the locked parent")
    return parent_lock.child_exists(path.name)


def _remove_tree_locked(path: Path, parent_lock: PublicationParentLock) -> None:
    parent_lock.assert_current()
    if path.absolute().parent != parent_lock.path:
        raise PublicationWriteError("publication path does not match the locked parent")
    shutil.rmtree(path.name, dir_fd=parent_lock.descriptor)
    _fsync_publication_parent(parent_lock)


def _fsync_publication_parent(parent_lock: PublicationParentLock) -> None:
    parent_lock.assert_current()
    os.fsync(parent_lock.descriptor)
    parent_lock.assert_current()


def _exchange_completed(
    staging_dir: Path,
    output_dir: Path,
    *,
    staged_identity: tuple[int, int],
    live_identity: tuple[int, int],
    parent_lock: PublicationParentLock,
) -> bool:
    """Distinguish the original and exchanged states after an interruption."""
    try:
        current_staged = _locked_path_identity(staging_dir, parent_lock)
        current_live = _locked_path_identity(output_dir, parent_lock)
    except OSError as exc:
        raise PublicationWriteError(
            "cannot determine atomic publication state after interruption; "
            f"inspect {output_dir} and {staging_dir}"
        ) from exc
    if (current_staged, current_live) == (staged_identity, live_identity):
        return False
    if (current_staged, current_live) == (live_identity, staged_identity):
        return True
    raise PublicationWriteError(
        "publication paths changed unexpectedly during atomic exchange; "
        f"inspect {output_dir} and {staging_dir}"
    )


def _promote_generation(
    staged: StagedWebData,
    *,
    retain_previous: bool = False,
    parent_lock: PublicationParentLock,
) -> PromotionTransaction:
    """Promote a staged directory while keeping the live path continuously visible.

    The caller must hold an exclusive parent-directory publication lock.  An
    existing live directory is exchanged atomically with the staged directory;
    after the exchange the old generation remains recoverable at
    ``staging_dir`` until the parent directory has been synced.
    """
    staging_dir = staged.staging_dir
    output_dir = staged.output_dir
    parent_lock.assert_current()
    parent = output_dir.absolute().parent
    if parent != parent_lock.path or staging_dir.absolute().parent != parent_lock.path:
        raise PublicationWriteError(
            "publication paths do not match the bound parent directory"
        )
    had_old_generation = _locked_path_exists(output_dir, parent_lock)
    if had_old_generation and (output_dir.is_symlink() or not output_dir.is_dir()):
        _invalid(f"published data directory is unsafe: {output_dir}")

    candidate_identity = _locked_path_identity(staging_dir, parent_lock)
    if not had_old_generation:
        try:
            os.rename(
                staging_dir.name,
                output_dir.name,
                src_dir_fd=parent_lock.descriptor,
                dst_dir_fd=parent_lock.descriptor,
            )
            _fsync_publication_parent(parent_lock)
        except BaseException as publish_error:
            if _locked_path_exists(output_dir, parent_lock) and not _locked_path_exists(
                staging_dir, parent_lock
            ):
                try:
                    os.rename(
                        output_dir.name,
                        staging_dir.name,
                        src_dir_fd=parent_lock.descriptor,
                        dst_dir_fd=parent_lock.descriptor,
                    )
                    _fsync_publication_parent(parent_lock)
                except BaseException as restore_error:
                    raise PublicationWriteError(
                        "first publication failed after rename; the live generation "
                        f"remains at {output_dir}"
                    ) from restore_error
            raise publish_error
        return PromotionTransaction(
            staged=staged,
            candidate_identity=candidate_identity,
            previous_identity=None,
            parent_lock=parent_lock,
        )

    staged_identity = candidate_identity
    live_identity = _locked_path_identity(output_dir, parent_lock)
    exchanged = False
    committed = False
    try:
        _rename_exchange(staging_dir, output_dir, parent_lock)
        exchanged = True
        _fsync_publication_parent(parent_lock)
        committed = True
    except BaseException as publish_error:
        if not exchanged:
            exchanged = _exchange_completed(
                staging_dir,
                output_dir,
                staged_identity=staged_identity,
                live_identity=live_identity,
                parent_lock=parent_lock,
            )
        if exchanged and not committed:
            try:
                _rename_exchange(staging_dir, output_dir, parent_lock)
            except BaseException as restore_error:
                try:
                    rollback_completed = not _exchange_completed(
                        staging_dir,
                        output_dir,
                        staged_identity=staged_identity,
                        live_identity=live_identity,
                        parent_lock=parent_lock,
                    )
                except PublicationWriteError:
                    rollback_completed = False
                if not rollback_completed:
                    raise PublicationWriteError(
                        "publication failed after atomic exchange and rollback failed; "
                        f"a live generation remains at {output_dir} and the other "
                        f"generation remains at {staging_dir}"
                    ) from restore_error
            try:
                _fsync_publication_parent(parent_lock)
            except BaseException as restore_error:
                raise PublicationWriteError(
                    "publication rollback completed, but its parent-directory sync "
                    f"failed; the prior live generation remains at {output_dir}"
                ) from restore_error
        raise publish_error

    transaction = PromotionTransaction(
        staged=staged,
        candidate_identity=staged_identity,
        previous_identity=live_identity,
        parent_lock=parent_lock,
    )
    if retain_previous:
        return transaction

    try:
        _remove_tree_locked(staging_dir, parent_lock)
    except BaseException as cleanup_error:
        raise PublicationWriteError(
            "publication committed, but the prior generation could not be removed "
            f"from {staging_dir}"
        ) from cleanup_error
    return transaction


def _rollback_promotion(transaction: PromotionTransaction) -> None:
    staging_dir = transaction.staged.staging_dir
    output_dir = transaction.staged.output_dir
    parent_lock = transaction.parent_lock
    parent_lock.assert_current()
    if _locked_path_identity(output_dir, parent_lock) != transaction.candidate_identity:
        raise PublicationWriteError("cannot rollback: live candidate inode changed")
    if transaction.previous_identity is None:
        if _locked_path_exists(staging_dir, parent_lock):
            raise PublicationWriteError("cannot rollback: staging path was recreated")
        os.rename(
            output_dir.name,
            staging_dir.name,
            src_dir_fd=parent_lock.descriptor,
            dst_dir_fd=parent_lock.descriptor,
        )
    else:
        if (
            _locked_path_identity(staging_dir, parent_lock)
            != transaction.previous_identity
        ):
            raise PublicationWriteError(
                "cannot rollback: previous generation inode changed"
            )
        _rename_exchange(staging_dir, output_dir, parent_lock)
        if (
            _locked_path_identity(output_dir, parent_lock)
            != transaction.previous_identity
            or _locked_path_identity(staging_dir, parent_lock)
            != transaction.candidate_identity
        ):
            raise PublicationWriteError("publication rollback inode proof failed")
    _fsync_publication_parent(parent_lock)
    transaction.state = "rolled_back"


def _commit_promotion(transaction: PromotionTransaction) -> None:
    staging_dir = transaction.staged.staging_dir
    output_dir = transaction.staged.output_dir
    parent_lock = transaction.parent_lock
    parent_lock.assert_current()
    if _locked_path_identity(output_dir, parent_lock) != transaction.candidate_identity:
        raise PublicationWriteError("cannot commit: live candidate inode changed")
    if transaction.previous_identity is not None:
        if (
            _locked_path_identity(staging_dir, parent_lock)
            != transaction.previous_identity
        ):
            raise PublicationWriteError(
                "cannot commit: previous generation inode changed"
            )
    _fsync_publication_parent(parent_lock)


def _cleanup_committed_promotion(transaction: PromotionTransaction) -> None:
    if transaction.previous_identity is None:
        return
    staging_dir = transaction.staged.staging_dir
    if _locked_path_identity(staging_dir, transaction.parent_lock) != (
        transaction.previous_identity
    ):
        raise PublicationWriteError(
            "cannot clean up: previous generation inode changed"
        )
    _remove_tree_locked(staging_dir, transaction.parent_lock)


def write_web_data(
    entries: list[dict],
    stats: dict,
    output_dir: Path,
    *,
    generated_at: str,
    allow_unreceipted: bool = False,
    inventory: dict | None = None,
) -> WriteResult:
    """Publish without a campaign receipt only after an explicit opt-in.

    Production callers use :func:`stage_web_data`, attach a gated release
    receipt, and call :func:`promote_staged_web_data`.  This compatibility
    helper is reserved for fixtures and local migrations where the caller has
    explicitly accepted the missing campaign provenance.
    """
    if not allow_unreceipted:
        raise PublishedDataError(
            "direct unreceipted publication is disabled; use the staged release "
            "receipt workflow or pass allow_unreceipted=True explicitly"
        )
    staged = stage_web_data(
        entries,
        stats,
        output_dir,
        generated_at=generated_at,
        inventory=inventory,
    )
    try:
        return promote_staged_web_data(
            staged,
            require_release_receipt=False,
        )
    except BaseException:
        discard_staged_web_data(staged)
        raise


def stage_web_data(
    entries: list[dict],
    stats: dict,
    output_dir: Path,
    *,
    generated_at: str,
    inventory: dict | None = None,
) -> StagedWebData:
    """Build and validate a sibling staging generation without publishing it."""
    output_dir = Path(output_dir)
    if output_dir.is_symlink():
        _invalid(f"refusing to replace symlinked output directory: {output_dir}")
    if output_dir.exists() and not output_dir.is_dir():
        _invalid(f"output path is not a directory: {output_dir}")

    # Candidate entries are generation-neutral. Add one content-derived bundle
    # identity only after the final ordered payload and aggregates are known.
    published_entries = [_without_generation_id(entry) for entry in entries]
    published_stats = _without_generation_id(stats)
    published_stats["generated_at"] = generated_at
    generation_id = _generation_id(
        published_entries,
        published_stats,
        generated_at=generated_at,
    )
    published_entries = [
        {"generation_id": generation_id, **entry} for entry in published_entries
    ]
    published_stats = {"generation_id": generation_id, **published_stats}
    index = {
        "generation_id": generation_id,
        "generated_at": generated_at,
        "total": len(published_entries),
        "ids": [entry.get("id") for entry in published_entries],
    }
    _validate_bundle(index, published_entries, published_stats, inventory)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    current_names = {f"{entry['id']}.json" for entry in published_entries}
    with _publication_parent_lock(
        output_dir,
        exclusive=False,
        error_type=PublicationWriteError,
    ):
        if output_dir.is_symlink():
            _invalid(f"refusing to replace symlinked output directory: {output_dir}")
        if output_dir.exists() and not output_dir.is_dir():
            _invalid(f"output path is not a directory: {output_dir}")
        publication_mode = _publication_directory_mode(output_dir)
        removed_stale, removed_legacy = (
            _old_layout_summary(output_dir, current_names)
            if output_dir.exists()
            else (0, False)
        )

    staging_dir = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.staging-", dir=output_dir.parent)
    )
    try:
        cves_dir = staging_dir / "cves"
        cves_dir.mkdir()
        for entry in published_entries:
            _write_json(_entry_path(cves_dir, entry["id"]), entry)
        _write_json(staging_dir / "index.json", index)
        _write_json(staging_dir / "stats.json", published_stats)
        if inventory is not None:
            # The evidence archive canonicalizes JSON object keys. Give the
            # separately content-addressed inventory one identical stable byte
            # encoding so its publication-manifest digest survives archival
            # parse/serialize replay.
            _write_json(
                staging_dir / "inventory.json",
                inventory,
                sort_keys=True,
            )
        os.chmod(staging_dir, publication_mode)
        _fsync_directory(cves_dir)
        _fsync_directory(staging_dir)

        # Re-read the exact staged bytes through the fail-closed consumer path.
        _validate_staged_inventory(
            staging_dir,
            require_release_receipt=False,
        )
        load_published_web_data(staging_dir)
    except BaseException:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    return StagedWebData(
        staging_dir=staging_dir,
        output_dir=output_dir,
        generated_at=generated_at,
        written=len(published_entries),
        removed_stale=removed_stale,
        removed_legacy=removed_legacy,
    )


def write_staged_release_receipt(
    staged: StagedWebData,
    payload: dict,
) -> Path:
    """Durably attach one validated release receipt to a staged generation."""
    if not isinstance(staged, StagedWebData):
        raise TypeError("staged must be a StagedWebData instance")
    staging_dir = staged.staging_dir
    with _publication_parent_lock(
        staged.output_dir,
        exclusive=True,
        error_type=PublicationWriteError,
    ):
        if staging_dir.is_symlink() or not staging_dir.is_dir():
            _invalid(f"staged generation is missing or unsafe: {staging_dir}")
        receipt_path = staging_dir / "release-receipt.json"
        if os.path.lexists(receipt_path):
            _invalid(f"release receipt already exists: {receipt_path}")
        _validate_staged_inventory(
            staging_dir,
            require_release_receipt=False,
        )
        publication = _load_published_web_data_unlocked(staging_dir)
        _validate_release_receipt(payload, publication)
        _write_json(receipt_path, payload)
        _read_release_receipt(staging_dir, publication)
        _validate_staged_inventory(
            staging_dir,
            require_release_receipt=True,
        )
        _fsync_directory(staging_dir)
        return receipt_path


@contextmanager
def publication_promotion_transaction(
    staged: StagedWebData,
    *,
    require_release_receipt: bool = True,
    expected_release_receipt: dict | None = None,
) -> Iterator[PromotionTransaction]:
    """Exchange a candidate and retain the prior generation until context commit."""
    if not isinstance(staged, StagedWebData):
        raise TypeError("staged must be a StagedWebData instance")
    staging_dir = staged.staging_dir
    output_dir = staged.output_dir
    if staging_dir.is_symlink() or not staging_dir.is_dir():
        _invalid(f"staged generation is missing or unsafe: {staging_dir}")
    if staging_dir.parent.resolve() != output_dir.parent.resolve():
        _invalid("staged generation and publication must share one parent directory")
    if not staging_dir.name.startswith(f".{output_dir.name}.staging-"):
        _invalid(f"unexpected staged generation path: {staging_dir}")
    with _publication_parent_lock(
        output_dir,
        exclusive=True,
        error_type=PublicationWriteError,
    ) as parent_lock:
        parent_lock.assert_current()
        if expected_release_receipt is not None:
            require_release_receipt = True
        if require_release_receipt and not os.path.lexists(
            staging_dir / "release-receipt.json"
        ):
            _invalid(f"release receipt is missing: {staging_dir}")
        _validate_staged_inventory(
            staging_dir,
            require_release_receipt=require_release_receipt,
        )
        publication = _load_published_web_data_unlocked(staging_dir)
        receipt = (
            _read_release_receipt(staging_dir, publication)
            if require_release_receipt
            else None
        )
        if receipt is not None:
            if expected_release_receipt is not None and _canonical_sha256(
                receipt
            ) != _canonical_sha256(expected_release_receipt):
                _invalid("staged release receipt changed before promotion")
        transaction = _promote_generation(
            staged,
            retain_previous=True,
            parent_lock=parent_lock,
        )
        try:
            yield transaction
        except BaseException:
            if transaction.state == "open":
                try:
                    _rollback_promotion(transaction)
                except BaseException as rollback_error:
                    raise PublicationWriteError(
                        "publication postcheck failed and atomic rollback failed; "
                        f"inspect {output_dir} and {staging_dir}"
                    ) from rollback_error
            elif transaction.state == "committed":
                # Keep the prior generation recoverable. A durable activation
                # record decides whether reconciliation finalizes this candidate
                # or atomically restores the prior publication.
                pass
            raise
        else:
            transaction.commit()
            _cleanup_committed_promotion(transaction)


def promote_staged_web_data(
    staged: StagedWebData,
    *,
    require_release_receipt: bool = True,
    expected_release_receipt: dict | None = None,
) -> WriteResult:
    """Revalidate and atomically promote one immediately committed generation."""
    with publication_promotion_transaction(
        staged,
        require_release_receipt=require_release_receipt,
        expected_release_receipt=expected_release_receipt,
    ):
        pass
    output_dir = staged.output_dir
    return WriteResult(
        index_path=output_dir / "index.json",
        stats_path=output_dir / "stats.json",
        cves_dir=output_dir / "cves",
        written=staged.written,
        removed_stale=staged.removed_stale,
        removed_legacy=staged.removed_legacy,
        inventory_path=(
            output_dir / "inventory.json"
            if (output_dir / "inventory.json").exists()
            else None
        ),
    )


def discard_staged_web_data(
    staged: StagedWebData,
    *,
    expected_candidate_identity: tuple[int, int] | None = None,
) -> bool:
    """Remove an exact unpromoted candidate and preserve exchanged recovery data."""
    if not isinstance(staged, StagedWebData):
        raise TypeError("staged must be a StagedWebData instance")
    with _publication_parent_lock(
        staged.output_dir,
        exclusive=True,
        error_type=PublicationWriteError,
    ) as parent_lock:
        if not _locked_path_exists(staged.staging_dir, parent_lock):
            return False
        if (
            expected_candidate_identity is not None
            and _locked_path_identity(staged.staging_dir, parent_lock)
            != expected_candidate_identity
        ):
            return False
        _remove_tree_locked(staged.staging_dir, parent_lock)
        return True
