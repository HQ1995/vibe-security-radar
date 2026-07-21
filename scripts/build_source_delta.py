#!/usr/bin/env python3
"""Build a reproducible, fail-closed advisory-source delta.

The preserved source-before-final directory is the immutable comparison point.
Git history, NVD records, and preserved OSV archives are compared semantically;
every current OSV archive is also validated and content-addressed.  The source
delta and the candidate union are staged, fsynced, and atomically replaced in a
fail-safe order (candidate superset first, then its delta manifest).
"""

from __future__ import annotations

import argparse
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

import analysis_contract
import data_refresh_paths

from cve_analyzer import ghsa_local, osv
from cve_analyzer.git_ops import _run_argv_bounded
from cve_analyzer.models import CveAnalysisResult
from cve_analyzer.vuln_discovery import (
    _iter_ghsa_json_files,
    extract_vuln_ids,
    has_git_range,
    is_informational,
    is_non_cve_unique,
    load_ghsa_as_vulns,
)

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_DEFAULT_STATE_ROOT = data_refresh_paths.DATA_REFRESH_STATE_RELATIVE
_DEFAULT_ADJUDICATED_CORPUS = str(
    _DEFAULT_STATE_ROOT / "adjudicated-corpus-subjects.txt"
)

SCHEMA_VERSION = 3
FORMAL_FULL_POLICY = "formal_full"
INCREMENTAL_POLICY = "incremental"
POPULATION_POLICIES = frozenset({FORMAL_FULL_POLICY, INCREMENTAL_POLICY})
OSV_ECOSYSTEMS_FILENAME = "ecosystems.txt"
DEFAULT_DISCOVERY_SINCE = "2025-05-01"
# The July 2026 source inventories produce up to 72,107,801 bytes for
# ``ls-files --debug`` and 44,736,445 bytes for ``ls-tree``.  Keep one explicit
# capture contract for the builder, refresher, and campaign runner with enough
# headroom for normal inventory growth while retaining a hard memory bound.
MAX_GIT_STDOUT_BYTES = 128 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 2 * 1024 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 180.0
GIT_FSCK_TIMEOUT_SECONDS = 4 * 60 * 60.0
MAX_GIT_METADATA_ENTRIES = 5_000_000
MAX_RECORDED_INVALID_ALIASES = 100
MAX_RECORDED_INVALID_PRIMARIES = 100
MAX_OSV_INVALID_PRIMARY_IDS = 1_000
MAX_OSV_QUARANTINE_PREVIEW_BYTES = 256
MAX_NVD_GZIP_BYTES = 1024 * 1024 * 1024
MAX_NVD_JSON_BYTES = 1024 * 1024 * 1024
NVD_VALIDATION_TIMEOUT_SECONDS = 60 * 60
NVD_READ_CHUNK_BYTES = 1024 * 1024
MAX_OSV_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_OSV_CENTRAL_DIRECTORY_BYTES = 512 * 1024 * 1024
MAX_OSV_ARCHIVE_MEMBERS = 5_000_000
MAX_OSV_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES = 16 * 1024 * 1024 * 1024
OSV_ARCHIVE_VALIDATION_TIMEOUT_SECONDS = 60 * 60
OSV_ARCHIVE_READ_CHUNK_BYTES = 1024 * 1024
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_OID = re.compile(r"[0-9a-f]{40,64}")
_OSV_ECOSYSTEM_NAME = re.compile(r"[A-Za-z0-9 ._+()\[\]-]{1,128}")
_SUBJECT_ID = re.compile(
    r"[A-Za-z][A-Za-z0-9._:+-]{0,198}-[A-Za-z0-9][A-Za-z0-9._:+-]{0,198}"
)
_GIT_PARTIAL_CONFIG_KEY = re.compile(
    r"(?:extensions\.partialclone|remote\..+\.(?:promisor|partialclonefilter))"
)
_GIT_INDEX_ENTRY = re.compile(
    r"(?P<tag>.) (?P<mode>[0-7]{6}) (?P<oid>[0-9a-f]{40,64}) "
    r"(?P<stage>[0-3])\t(?P<path>.+)",
    re.DOTALL,
)
_GIT_INDEX_DEBUG_METADATA = re.compile(
    r"  ctime: [0-9]+:[0-9]+\n"
    r"  mtime: [0-9]+:[0-9]+\n"
    r"  dev: [0-9]+\tino: [0-9]+\n"
    r"  uid: [0-9]+\tgid: [0-9]+\n"
    r"  size: [0-9]+\tflags: (?P<flags>[0-9A-Fa-f]+)(?:\n|$)"
)
_GIT_TREE_ENTRY = re.compile(
    r"(?P<mode>[0-7]{6}) (?P<type>[a-z]+) (?P<oid>[0-9a-f]{40,64})"
    r"\t(?P<path>.+)",
    re.DOTALL,
)

_CVELIST_ORIGIN = "https://github.com/CVEProject/cvelistV5.git"
_GHSA_ORIGIN = "https://github.com/github/advisory-database.git"
_GEMNASIUM_ORIGIN = "https://gitlab.com/gitlab-org/advisories-community.git"

_CURRENT_RESULT_FIELDS = frozenset(
    {
        "cve_id",
        "description",
        "severity",
        "fix_commits",
        "bug_introducing_commits",
        "ai_signals",
        "references",
        "cwes",
        "cvss_score",
        "error",
        "error_category",
        "ai_confidence",
        "repo_ai_activity",
        "phase_times",
    }
)
_TERMINAL_EARLY_RESULT_CATEGORIES = frozenset({"no_fix_commits", "skipped_advisory"})
_KNOWN_NONTERMINAL_RESULT_CATEGORIES = frozenset({"no_ai_activity"})


class SourceDeltaError(RuntimeError):
    """A source input, comparison, or publication invariant failed."""


GitFsckCacheKey = tuple[str, str, str, str]


class SuccessfulGitFsckCache:
    """Bounded process-local LRU containing only stable successful fsck keys."""

    def __init__(self, max_entries: int = 16) -> None:
        if (
            not isinstance(max_entries, int)
            or isinstance(max_entries, bool)
            or max_entries <= 0
        ):
            raise ValueError("max_entries must be a positive integer")
        self.max_entries = max_entries
        self._entries: dict[GitFsckCacheKey, None] = {}
        self._lock = threading.RLock()

    def contains(self, key: GitFsckCacheKey) -> bool:
        with self._lock:
            if key not in self._entries:
                return False
            self._entries.pop(key)
            self._entries[key] = None
            return True

    def record_success(self, key: GitFsckCacheKey) -> None:
        with self._lock:
            self._entries.pop(key, None)
            self._entries[key] = None
            while len(self._entries) > self.max_entries:
                self._entries.pop(next(iter(self._entries)))

    def rebind_resolved_path(self, old_value: str, new_value: str) -> None:
        """Transfer successful keys after an owned same-inode directory rename."""

        if not old_value or not new_value:
            raise ValueError("resolved cache paths must be non-empty")
        with self._lock:
            replacements = [
                ((new_value, head, tree, metadata), key)
                for key in self._entries
                for path, head, tree, metadata in (key,)
                if path == old_value
            ]
            for new_key, old_key in replacements:
                self._entries.pop(old_key, None)
                self._entries[new_key] = None
            while len(self._entries) > self.max_entries:
                self._entries.pop(next(iter(self._entries)))

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


@dataclass(frozen=True)
class OsvEcosystemInventory:
    """A validated manifest and its canonical per-ecosystem archive names."""

    ecosystems: tuple[str, ...]
    archive_names: tuple[str, ...]


def parse_osv_ecosystems_manifest(data: bytes) -> OsvEcosystemInventory:
    """Parse OSV's UTF-8 line manifest without splitting names on spaces."""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceDeltaError("OSV ecosystem manifest is not UTF-8") from exc
    if not text or len(data) > 64 * 1024:
        raise SourceDeltaError("OSV ecosystem manifest is empty or oversized")

    ecosystems = text.splitlines()
    if not ecosystems or len(ecosystems) > 4096:
        raise SourceDeltaError("OSV ecosystem manifest has an invalid line count")
    for ecosystem in ecosystems:
        if (
            ecosystem != ecosystem.strip()
            or ecosystem in {"", ".", ".."}
            or _OSV_ECOSYSTEM_NAME.fullmatch(ecosystem) is None
            or "/" in ecosystem
            or "\\" in ecosystem
        ):
            raise SourceDeltaError(
                f"OSV ecosystem manifest contains an unsafe name: {ecosystem!r}"
            )

    canonical = tuple(sorted(ecosystems, key=lambda name: (name.casefold(), name)))
    if len(set(canonical)) != len(canonical):
        raise SourceDeltaError("OSV ecosystem manifest contains duplicate names")
    if len({name.casefold() for name in canonical}) != len(canonical):
        raise SourceDeltaError(
            "OSV ecosystem manifest contains case-insensitive duplicate names"
        )
    archive_names = tuple(f"{ecosystem}.zip" for ecosystem in canonical)
    if len({name.casefold() for name in archive_names}) != len(archive_names):
        raise SourceDeltaError("OSV ecosystem manifest derives colliding archive names")
    return OsvEcosystemInventory(canonical, archive_names)


@dataclass(frozen=True)
class GitSource:
    """One Git mirror and the file containing its preserved baseline HEAD."""

    name: str
    directory: Path
    baseline_head_file: Path
    expected_origin: str


@dataclass(frozen=True)
class BuildPaths:
    """All inputs and outputs for one source-delta build."""

    repo_root: Path
    baseline_dir: Path
    git_sources: tuple[GitSource, ...]
    nvd_dir: Path
    osv_dir: Path
    osv_ecosystems_file: Path
    result_cache_dir: Path
    delta_output: Path
    candidate_output: Path
    adjudicated_corpus_file: Path | None
    discovery_since: str = DEFAULT_DISCOVERY_SINCE
    population_policy: str = FORMAL_FULL_POLICY

    @classmethod
    def defaults(cls, repo_root: Path = _REPO_ROOT) -> BuildPaths:
        root = repo_root.resolve()
        state = data_refresh_paths.data_refresh_state_root(root)
        baseline = state / "source-before-final"
        cache = Path.home() / ".cache" / "cve-analyzer"
        corpus = state / "adjudicated-corpus-subjects.txt"
        return cls(
            repo_root=root,
            baseline_dir=baseline,
            git_sources=(
                GitSource(
                    "cvelistV5",
                    cache / "cvelistV5",
                    baseline / "cvelistV5.head",
                    _CVELIST_ORIGIN,
                ),
                GitSource(
                    "github-advisory-database",
                    cache / "advisory-database",
                    baseline / "github-advisory-database.head",
                    _GHSA_ORIGIN,
                ),
                GitSource(
                    "gemnasium-db",
                    cache / "gemnasium-db",
                    baseline / "gemnasium-db.head",
                    _GEMNASIUM_ORIGIN,
                ),
            ),
            nvd_dir=cache / "nvd-feeds",
            osv_dir=cache / "osv-bulk",
            osv_ecosystems_file=cache / "osv-bulk" / OSV_ECOSYSTEMS_FILENAME,
            result_cache_dir=cache / "results",
            delta_output=state / "source-delta-current.json",
            candidate_output=state / "new-osv-candidates.txt",
            adjudicated_corpus_file=corpus if corpus.is_file() else None,
        )


@dataclass(frozen=True)
class BuiltArtifacts:
    """Verified output bytes plus the input snapshot they were built from."""

    delta: dict[str, Any]
    delta_bytes: bytes
    candidate_bytes: bytes
    input_guard: dict[str, Any]


@dataclass(frozen=True)
class ResultCacheSnapshot:
    """A content-addressed result-cache inventory and its valid subject IDs."""

    metadata: dict[str, Any]
    subject_ids: frozenset[str]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ids_sha256(values: Iterable[str]) -> str:
    ordered = sorted(values)
    data = ("\n".join(ordered) + "\n").encode() if ordered else b""
    return _sha256_bytes(data)


def advisory_source_snapshot_sha256(input_guard: Mapping[str, Any]) -> str:
    """Hash source evidence while excluding caches and candidate-side inputs."""

    keys = (
        "baseline",
        "git",
        "nvd",
        "osv_ecosystem_manifest",
        "osv_archive_names",
        "osv",
    )
    source_snapshot = {key: input_guard.get(key) for key in keys}
    if any(source_snapshot[key] is None for key in keys):
        raise SourceDeltaError("input guard is missing advisory source evidence")
    return _sha256_bytes(
        json.dumps(source_snapshot, sort_keys=True, separators=(",", ":")).encode()
    )


def _regular_file_bytes(path: Path, label: str) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise SourceDeltaError(
                f"{label} must be a regular non-symlink file: {path}"
            )
        return path.read_bytes()
    except SourceDeltaError:
        raise
    except OSError as exc:
        raise SourceDeltaError(f"cannot read {label} {path}: {exc}") from exc


def _sha256_file(path: Path, label: str) -> str:
    digest = hashlib.sha256()
    try:
        if path.is_symlink() or not path.is_file():
            raise SourceDeltaError(
                f"{label} must be a regular non-symlink file: {path}"
            )
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except SourceDeltaError:
        raise
    except OSError as exc:
        raise SourceDeltaError(f"cannot hash {label} {path}: {exc}") from exc
    return digest.hexdigest()


def _file_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_stable_regular_file(
    path: Path,
    label: str,
) -> tuple[BinaryIO, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise SourceDeltaError(f"cannot inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SourceDeltaError(f"{label} must be a regular non-symlink file: {path}")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SourceDeltaError(f"cannot open {label} {path}: {exc}") from exc
    try:
        handle = os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise
    try:
        opened = os.fstat(handle.fileno())
        if _file_signature(opened) != _file_signature(before):
            raise SourceDeltaError(f"{label} changed while being opened: {path}")
    except BaseException:
        handle.close()
        raise
    return handle, opened


def _verify_open_file_identity(
    path: Path,
    handle: BinaryIO,
    initial: os.stat_result,
    label: str,
    *,
    action: str,
) -> None:
    try:
        final = os.fstat(handle.fileno())
        current = path.lstat()
    except OSError as exc:
        raise SourceDeltaError(
            f"cannot verify {label} after {action}: {path}: {exc}"
        ) from exc
    if _file_signature(final) != _file_signature(initial) or _file_signature(
        current
    ) != _file_signature(final):
        raise SourceDeltaError(f"{label} changed while being {action}: {path}")


def _hash_open_file(
    handle: BinaryIO,
    *,
    deadline: Callable[[], None] | None = None,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    handle.seek(0)
    while True:
        if deadline is not None:
            deadline()
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        digest.update(chunk)
    handle.seek(0)
    return digest.hexdigest(), size


def _validate_expected_snapshot(
    expected: Mapping[str, Any] | None,
    label: str,
) -> tuple[int | None, str | None]:
    if expected is None:
        return None, None
    size = expected.get("size_bytes")
    sha256 = expected.get("sha256")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
        or not isinstance(sha256, str)
        or _HEX_SHA256.fullmatch(sha256) is None
    ):
        raise SourceDeltaError(f"invalid expected snapshot for {label}")
    return size, sha256


def _capture_regular_file_snapshot(
    path: Path,
    label: str,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    handle, initial = _open_stable_regular_file(path, label)
    try:
        if initial.st_size <= 0 or initial.st_size > max_bytes:
            raise SourceDeltaError(
                f"{label} size is outside 1..{max_bytes} bytes: {initial.st_size}"
            )
        sha256, size = _hash_open_file(handle)
        if size != initial.st_size:
            raise SourceDeltaError(f"{label} changed while being hashed: {path}")
        _verify_open_file_identity(
            path,
            handle,
            initial,
            label,
            action="hashed",
        )
        return {"size_bytes": size, "sha256": sha256}
    finally:
        handle.close()


def _real_directory(path: Path, label: str) -> Path:
    try:
        if path.is_symlink() or not path.is_dir():
            raise SourceDeltaError(f"{label} must be a real directory: {path}")
        return path.resolve(strict=True)
    except SourceDeltaError:
        raise
    except OSError as exc:
        raise SourceDeltaError(f"cannot resolve {label} {path}: {exc}") from exc


def _relative_path(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _validate_subject_id(value: str, label: str) -> str:
    normalized = value.strip()
    if (
        normalized != value
        or not _SUBJECT_ID.fullmatch(normalized)
        or "/" in normalized
        or "\\" in normalized
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in normalized)
    ):
        raise SourceDeltaError(
            f"invalid vulnerability subject ID in {label}: {value!r}"
        )
    return normalized


def _read_id_list(
    path: Path,
    label: str,
    *,
    legacy_duplicates: bool = False,
) -> tuple[list[str], dict[str, int], bytes]:
    data = _regular_file_bytes(path, label)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceDeltaError(f"{label} is not UTF-8: {path}") from exc
    raw = [line.strip() for line in text.splitlines() if line.strip()]
    if not raw:
        raise SourceDeltaError(f"{label} has no subject IDs: {path}")
    ids = [_validate_subject_id(item, label) for item in raw]
    duplicates = {item: count for item, count in Counter(ids).items() if count > 1}
    if duplicates and not legacy_duplicates:
        raise SourceDeltaError(
            f"{label} contains duplicate subject IDs: {dict(list(duplicates.items())[:10])}"
        )
    return ids, duplicates, data


def _ordered_unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _validate_generated_at(value: str | None) -> str:
    generated_at = value or _utc_now()
    try:
        parsed = datetime.fromisoformat(generated_at)
    except ValueError as exc:
        raise SourceDeltaError(
            f"generated timestamp is not ISO-8601: {generated_at!r}"
        ) from exc
    if parsed.tzinfo is None:
        raise SourceDeltaError("generated timestamp must include a timezone")
    return generated_at


def _validate_discovery_since(value: str) -> str:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise SourceDeltaError(
            f"discovery since date must be YYYY-MM-DD: {value!r}"
        ) from exc
    if parsed.strftime("%Y-%m-%d") != value:
        raise SourceDeltaError(
            f"discovery since date must be canonical YYYY-MM-DD: {value!r}"
        )
    return value


def _directory_entry_state(path: Path) -> tuple[tuple[str, int, int, int], ...]:
    """Return a bounded identity/size/mtime snapshot for direct JSON children."""

    try:
        entries = sorted(path.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise SourceDeltaError(f"cannot inventory result cache {path}: {exc}") from exc
    output: list[tuple[str, int, int, int]] = []
    for entry in entries:
        if entry.suffix != ".json":
            continue
        try:
            metadata = entry.lstat()
        except OSError as exc:
            raise SourceDeltaError(
                f"cannot stat result-cache entry {entry}: {exc}"
            ) from exc
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise SourceDeltaError(
                f"result-cache JSON must be a regular non-symlink file: {entry}"
            )
        output.append(
            (entry.name, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        )
    if len({name.casefold() for name, *_ in output}) != len(output):
        raise SourceDeltaError("result-cache JSON names collide case-insensitively")
    return tuple(output)


def _cache_coverage_ineligibility(
    payload: Mapping[str, Any], result: CveAnalysisResult
) -> str | None:
    """Return why a schema-valid result cannot suppress current discovery."""

    missing_fields = _CURRENT_RESULT_FIELDS - payload.keys()
    if missing_fields:
        return "missing_current_schema_fields"
    list_fields = (
        "fix_commits",
        "bug_introducing_commits",
        "ai_signals",
        "references",
        "cwes",
        "repo_ai_activity",
    )
    if any(not isinstance(payload[field], list) for field in list_fields):
        return "invalid_current_schema_field_type"
    if any(
        not isinstance(value, str)
        for field in ("references", "cwes", "repo_ai_activity")
        for value in payload[field]
    ):
        return "invalid_current_schema_field_type"
    if any(
        not isinstance(payload[field], str)
        for field in ("cve_id", "description", "severity", "error", "error_category")
    ):
        return "invalid_current_schema_field_type"
    if any(
        not isinstance(payload[field], (int, float))
        for field in ("cvss_score", "ai_confidence")
    ):
        return "invalid_current_schema_field_type"
    phase_times = payload["phase_times"]
    if not isinstance(phase_times, dict) or any(
        not isinstance(key, str) or not isinstance(value, (int, float))
        for key, value in phase_times.items()
    ):
        return "invalid_current_schema_field_type"
    if "Phase A (discovery)" not in phase_times:
        return "incomplete_phase_a_telemetry"
    incomplete_tier0 = [
        reason
        for reason in result.repo_ai_activity
        if isinstance(reason, str) and reason.startswith("incomplete:")
    ]
    if incomplete_tier0:
        return "incomplete_tier0_telemetry"

    category = result.error_category
    if category in _TERMINAL_EARLY_RESULT_CATEGORIES:
        return None
    if category in _KNOWN_NONTERMINAL_RESULT_CATEGORIES:
        return f"known_nonterminal_{category}"
    if category:
        return f"nonterminal_or_unsupported_{category}"
    if result.error:
        return "uncategorized_error"
    if "Phase B (blame)" not in phase_times:
        return "incomplete_tier0_or_blame_telemetry"
    return None


def _scan_result_cache(path: Path, repo_root: Path) -> ResultCacheSnapshot:
    """Load every core-compatible cache result and bind the exact inventory."""

    cache_dir = _real_directory(path, "analysis result cache")
    before = _directory_entry_state(cache_dir)
    manifest = hashlib.sha256()
    all_subject_ids: set[str] = set()
    eligible_subject_ids: set[str] = set()
    ineligible_reasons: Counter[str] = Counter()
    total_size = 0
    for name, _inode, expected_size, _mtime_ns in before:
        entry = cache_dir / name
        data = _regular_file_bytes(entry, "analysis cache result")
        if len(data) != expected_size:
            raise SourceDeltaError(
                f"result-cache entry changed while being read: {entry}"
            )
        try:
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise TypeError("JSON root is not an object")
            result = CveAnalysisResult.from_dict(payload)
        except Exception as exc:
            raise SourceDeltaError(
                f"invalid analysis cache result {entry}: {exc}"
            ) from exc
        subject = _validate_subject_id(result.cve_id, f"analysis cache result {name}")
        if entry.stem != subject:
            raise SourceDeltaError(
                f"analysis cache filename/subject mismatch: {entry.stem!r} != {subject!r}"
            )
        if subject in all_subject_ids:
            raise SourceDeltaError(f"duplicate analysis cache subject ID: {subject}")
        all_subject_ids.add(subject)
        ineligibility = _cache_coverage_ineligibility(payload, result)
        if ineligibility is None:
            eligible_subject_ids.add(subject)
        else:
            ineligible_reasons[ineligibility] += 1
        digest = _sha256_bytes(data)
        manifest.update(name.encode("utf-8"))
        manifest.update(b"\0")
        manifest.update(str(len(data)).encode("ascii"))
        manifest.update(b"\0")
        manifest.update(digest.encode("ascii"))
        manifest.update(b"\0")
        manifest.update(subject.encode("utf-8"))
        manifest.update(b"\n")
        total_size += len(data)
    after = _directory_entry_state(cache_dir)
    if after != before:
        raise SourceDeltaError("result-cache inventory changed while being scanned")

    ordered_subject_bytes = (
        ("\n".join(sorted(eligible_subject_ids)) + "\n").encode()
        if eligible_subject_ids
        else b""
    )
    required_fields_bytes = ("\n".join(sorted(_CURRENT_RESULT_FIELDS)) + "\n").encode()
    metadata = {
        "directory": _relative_path(cache_dir, repo_root),
        "json_file_count": len(before),
        "schema_valid_result_count": len(all_subject_ids),
        "coverage_eligible_result_count": len(eligible_subject_ids),
        "coverage_ineligible_result_count": len(all_subject_ids)
        - len(eligible_subject_ids),
        "coverage_ineligible_reason_counts": dict(sorted(ineligible_reasons.items())),
        "total_size_bytes": total_size,
        "inventory_manifest_sha256": manifest.hexdigest(),
        "eligible_subject_ids_sha256": _sha256_bytes(ordered_subject_bytes),
        "all_json_results_schema_valid": True,
        "coverage_policy": {
            "scope": "incremental_diagnostic_only",
            "formal_population_suppression_enabled": False,
            "formal_current_epoch_stage_receipt_required": True,
            "production_max_age_days": None,
            "current_schema_required_fields_sha256": _sha256_bytes(
                required_fields_bytes
            ),
            "terminal_early_categories": sorted(_TERMINAL_EARLY_RESULT_CATEGORIES),
            "known_nonterminal_categories": sorted(
                _KNOWN_NONTERMINAL_RESULT_CATEGORIES
            ),
            "clean_results_require_phase_a_and_phase_b": True,
            "infrastructure_and_unsupported_errors_eligible": False,
            "current_luna_max_receipt_required": False,
            "boundary": (
                "historical terminal current-schema results remain eligible; "
                "uniform Luna/max adjudication is a separate campaign proof"
            ),
        },
    }
    return ResultCacheSnapshot(metadata, frozenset(eligible_subject_ids))


def _parse_sha256_manifest(paths: BuildPaths) -> dict[str, str]:
    baseline = _real_directory(paths.baseline_dir, "preserved baseline directory")
    manifest_path = baseline / "SHA256SUMS"
    data = _regular_file_bytes(manifest_path, "baseline SHA256 manifest")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SourceDeltaError("baseline SHA256 manifest is not UTF-8") from exc

    entries: dict[str, str] = {}
    seen_paths: set[Path] = set()
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if not match:
            raise SourceDeltaError(f"malformed SHA256SUMS line {line_number}: {line!r}")
        expected, raw_name = match.groups()
        pure = PurePosixPath(raw_name)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise SourceDeltaError(f"unsafe SHA256SUMS path: {raw_name!r}")
        root_candidate = (paths.repo_root / Path(*pure.parts)).resolve()
        local_candidate = (baseline / Path(*pure.parts)).resolve()
        candidates = [
            candidate
            for candidate in (root_candidate, local_candidate)
            if candidate.is_file()
        ]
        candidates = [
            candidate
            for candidate in candidates
            if candidate == baseline or baseline in candidate.parents
        ]
        if len(set(candidates)) != 1:
            raise SourceDeltaError(
                f"SHA256SUMS entry does not resolve uniquely in baseline: {raw_name!r}"
            )
        resolved = candidates[0]
        if resolved in seen_paths:
            raise SourceDeltaError(f"duplicate SHA256SUMS path: {raw_name!r}")
        seen_paths.add(resolved)
        actual = _sha256_file(resolved, "preserved baseline input")
        if actual != expected:
            raise SourceDeltaError(
                f"preserved baseline checksum mismatch for {raw_name}: expected {expected}, got {actual}"
            )
        entries[resolved.relative_to(baseline).as_posix()] = actual

    actual_files = {
        path.resolve()
        for path in baseline.iterdir()
        if path.name != "SHA256SUMS" and path.is_file() and not path.is_symlink()
    }
    unsafe = [
        path
        for path in baseline.iterdir()
        if path.name != "SHA256SUMS" and (path.is_symlink() or not path.is_file())
    ]
    if unsafe:
        raise SourceDeltaError(
            f"baseline contains unsafe or nested entries: {unsafe[:5]}"
        )
    if actual_files != seen_paths:
        missing = sorted(path.name for path in actual_files - seen_paths)
        stale = sorted(path.name for path in seen_paths - actual_files)
        raise SourceDeltaError(
            f"SHA256SUMS must cover the exact preserved baseline: unlisted={missing}, stale={stale}"
        )
    if not entries:
        raise SourceDeltaError("baseline SHA256 manifest is empty")
    return dict(sorted(entries.items()))


def system_git_binary() -> str:
    """Return the fixed system Git executable, independent of ambient PATH."""

    candidate = shutil.which("git", path=os.defpath)
    if candidate is None:
        raise SourceDeltaError("git is absent from the system path")
    try:
        resolved = Path(candidate).resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise SourceDeltaError(
            f"cannot resolve the system Git executable: {exc}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise SourceDeltaError(f"system Git executable is unsafe: {resolved}")
    return str(resolved)


def safe_git_environment() -> dict[str, str]:
    """Build a deny-all environment for deterministic, non-interactive Git."""

    return {
        "GIT_ALLOW_PROTOCOL": "file:https",
        "GIT_ASKPASS": "/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_GRAFT_FILE": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }


def safe_git_command(directory: Path, arguments: Sequence[str]) -> list[str]:
    """Build a Git command that disables hooks, helpers, lazy fetch, and prompts."""

    return [
        system_git_binary(),
        "--no-replace-objects",
        "--literal-pathspecs",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "credential.helper=",
        "-c",
        "credential.interactive=false",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        "-c",
        "fetch.recurseSubmodules=false",
        "-c",
        "submodule.recurse=false",
        "-c",
        "extensions.worktreeConfig=false",
        "-c",
        "core.sparseCheckout=false",
        "-c",
        "core.sparseCheckoutCone=false",
        "-c",
        "index.sparse=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=always",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "http.proxy=",
        "-c",
        "http.sslVerify=true",
        "-C",
        str(directory),
        *arguments,
    ]


def _git_env() -> dict[str, str]:
    """Compatibility wrapper for internal callers and focused tests."""

    return safe_git_environment()


def _resolved_reported_git_directory(
    source_dir: Path,
    raw_value: str,
    label: str,
) -> Path:
    candidate = Path(raw_value)
    if not candidate.is_absolute():
        candidate = source_dir / candidate
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise SourceDeltaError(f"cannot resolve {label} {candidate}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise SourceDeltaError(f"{label} is not a directory: {resolved}")
    return resolved


def _local_git_config_entries(raw: str, label: str) -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    for raw_entry in raw.split("\0"):
        if not raw_entry:
            continue
        key, separator, value = raw_entry.partition("\n")
        if not separator or not key or any(ord(char) > 0x7F for char in key):
            raise SourceDeltaError(f"malformed local Git config in {label}")
        entries.append((key.casefold(), value))
    return tuple(entries)


def _external_git_config(key: str, value: str) -> bool:
    if key == "include.path" or (
        key.startswith("includeif.") and key.endswith(".path")
    ):
        return True
    if key in {
        "core.alternaterefscommand",
        "core.attributesfile",
        "core.editor",
        "core.fsmonitor",
        "core.gitproxy",
        "core.hookspath",
        "core.pager",
        "core.sshcommand",
        "core.worktree",
        "extensions.worktreeconfig",
        "core.sparsecheckout",
        "core.sparsecheckoutcone",
        "index.sparse",
        "diff.external",
        "interactive.difffilter",
        "uploadpack.packobjectshook",
    }:
        return True
    if key.startswith("pager."):
        return True
    if key.startswith("filter.") and key.rsplit(".", 1)[-1] in {
        "clean",
        "process",
        "smudge",
    }:
        return True
    if key.startswith("merge.") and key.endswith(".driver"):
        return True
    if key.startswith("diff.") and key.rsplit(".", 1)[-1] in {
        "command",
        "textconv",
    }:
        return True
    if key == "credential.helper" or (
        key.startswith("credential.") and key.endswith(".helper")
    ):
        return True
    if key.startswith("url.") and key.rsplit(".", 1)[-1] in {
        "insteadof",
        "pushinsteadof",
    }:
        return True
    if key.startswith("remote.") and key.rsplit(".", 1)[-1] in {
        "proxy",
        "receivepack",
        "uploadpack",
        "vcs",
    }:
        return True
    if key == "protocol.allow" or (
        key.startswith("protocol.") and key.endswith(".allow")
    ):
        return True
    if key.startswith("http."):
        return True
    if key.startswith(("fsck.", "receive.fsck", "fetch.fsck")):
        return True
    return key.startswith("submodule.")


def _git_metadata_signature(path: Path) -> tuple[int, int, int, int, int, int]:
    metadata = path.lstat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _update_git_metadata_digest(
    digest: Any,
    relative_path: str,
    metadata: os.stat_result,
) -> None:
    encoded_path = os.fsencode(relative_path)
    signature = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    digest.update(len(encoded_path).to_bytes(8, "big"))
    digest.update(encoded_path)
    encoded_signature = ",".join(str(value) for value in signature).encode("ascii")
    digest.update(len(encoded_signature).to_bytes(8, "big"))
    digest.update(encoded_signature)


def _validate_git_metadata_tree(git_dir: Path, label: str) -> str:
    """Validate and digest every object/ref/control metadata entry."""

    inspected = 0
    digest = hashlib.sha256()
    for storage_root in (git_dir / "objects", git_dir / "refs"):
        try:
            walker = os.fwalk(storage_root, topdown=True, follow_symlinks=False)
            for root, directories, files, root_fd in walker:
                root_path = Path(root)
                root_metadata = root_path.lstat()
                if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(
                    root_metadata.st_mode
                ):
                    raise SourceDeltaError(
                        f"{label} Git metadata contains redirected or unsupported "
                        f"directory: {root_path}"
                    )
                _update_git_metadata_digest(
                    digest,
                    root_path.relative_to(git_dir).as_posix(),
                    root_metadata,
                )
                inspected += 1
                retained: list[str] = []
                for name in sorted(directories, key=os.fsencode):
                    metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(
                        metadata.st_mode
                    ):
                        raise SourceDeltaError(
                            f"{label} Git metadata contains redirected or unsupported "
                            f"directory: {root_path / name}"
                        )
                    retained.append(name)
                directories[:] = retained
                for name in sorted(files, key=os.fsencode):
                    metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                    inspected += 1
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
                        metadata.st_mode
                    ):
                        raise SourceDeltaError(
                            f"{label} Git metadata contains redirected or unsupported "
                            f"file: {root_path / name}"
                        )
                    _update_git_metadata_digest(
                        digest,
                        (root_path / name).relative_to(git_dir).as_posix(),
                        metadata,
                    )
                if inspected > MAX_GIT_METADATA_ENTRIES:
                    raise SourceDeltaError(
                        f"{label} Git metadata exceeds the bounded entry limit"
                    )
        except SourceDeltaError:
            raise
        except OSError as exc:
            raise SourceDeltaError(
                f"cannot inspect {label} Git object/ref storage: {exc}"
            ) from exc

    controls = (
        (git_dir / "HEAD", True),
        (git_dir / "config", True),
        (git_dir / "index", True),
        (git_dir / "packed-refs", False),
        (git_dir / "objects" / "info" / "commit-graph", False),
    )
    for path, required in controls:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if required:
                raise SourceDeltaError(
                    f"required Git metadata is missing for {label}: {path}"
                )
            digest.update(b"missing\0")
            digest.update(path.relative_to(git_dir).as_posix().encode("utf-8"))
            continue
        except OSError as exc:
            raise SourceDeltaError(
                f"cannot inspect {label} Git metadata {path}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise SourceDeltaError(f"unsafe Git metadata path for {label}: {path}")
        _update_git_metadata_digest(
            digest,
            path.relative_to(git_dir).as_posix(),
            metadata,
        )
    return digest.hexdigest()


def _validate_git_index_and_worktree(
    directory: Path,
    label: str,
    git_output: Callable[[Sequence[str]], str],
) -> None:
    """Bind HEAD, index, and every visible or ignored worktree entry."""

    staged = git_output(["ls-files", "--cached", "--stage", "-v", "--sparse", "-z"])
    staged_paths: list[str] = []
    for raw_entry in staged.split("\0"):
        if not raw_entry:
            continue
        match = _GIT_INDEX_ENTRY.fullmatch(raw_entry)
        if match is None:
            raise SourceDeltaError(f"malformed Git index entry in {label}")
        path = match.group("path")
        if (
            "\ufffd" in path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
        ):
            raise SourceDeltaError(f"unsafe Git index path in {label}: {path!r}")
        if match.group("stage") != "0":
            raise SourceDeltaError(f"{label} has unmerged Git index entries")
        if match.group("tag") != "H":
            raise SourceDeltaError(
                f"{label} has forbidden Git index flags for {path!r}"
            )
        if match.group("mode") not in {"100644", "100755"}:
            entry_kind = {
                "040000": "sparse directory",
                "120000": "symlink",
                "160000": "gitlink",
            }.get(match.group("mode"), "unsupported mode")
            raise SourceDeltaError(
                f"{label} has forbidden {entry_kind} index entry for {path!r}"
            )
        staged_paths.append(path)
    if len(staged_paths) != len(set(staged_paths)):
        raise SourceDeltaError(f"{label} has duplicate or unmerged Git index entries")

    debug = git_output(["ls-files", "--cached", "--debug", "--sparse", "-z"])
    debug_paths: list[str] = []
    cursor = 0
    while cursor < len(debug):
        separator = debug.find("\0", cursor)
        if separator < 0:
            raise SourceDeltaError(f"malformed Git index debug output in {label}")
        path = debug[cursor:separator]
        metadata = _GIT_INDEX_DEBUG_METADATA.match(debug, separator + 1)
        if metadata is None:
            raise SourceDeltaError(f"malformed Git index flags in {label}")
        if int(metadata.group("flags"), 16) != 0:
            raise SourceDeltaError(
                f"{label} has forbidden Git index flags for {path!r}"
            )
        debug_paths.append(path)
        cursor = metadata.end()
    if debug_paths != staged_paths:
        raise SourceDeltaError(f"inconsistent Git index inventory in {label}")

    cached_changes = git_output(
        [
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            "--name-only",
            "-z",
            "HEAD",
            "--",
        ]
    )
    if cached_changes:
        raise SourceDeltaError(f"{label} Git index differs from the HEAD tree")
    _validate_head_worktree_snapshot(directory, label, git_output)


def _git_blob_oid(file_descriptor: int, size: int, oid_length: int) -> str:
    algorithm = {40: "sha1", 64: "sha256"}.get(oid_length)
    if algorithm is None:
        raise SourceDeltaError(f"unsupported Git object ID length: {oid_length}")
    digest = hashlib.new(algorithm)
    digest.update(f"blob {size}\0".encode("ascii"))
    while True:
        chunk = os.read(file_descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _dirty_git_worktree_error(label: str, detail: str) -> SourceDeltaError:
    subject = "Git source" if "Git source" in label else "Git mirror"
    return SourceDeltaError(
        f"{subject} is dirty: {label} worktree differs from the HEAD tree: {detail}"
    )


def _validate_head_worktree_snapshot(
    directory: Path,
    label: str,
    git_output: Callable[[Sequence[str]], str],
) -> None:
    """Prove the analyzer-visible filesystem is the exact regular-file HEAD tree."""

    raw_tree = git_output(["ls-tree", "-r", "-z", "--full-tree", "HEAD"])
    expected_files: dict[str, tuple[str, int]] = {}
    expected_directories: set[str] = set()
    oid_length: int | None = None
    for raw_entry in raw_tree.split("\0"):
        if not raw_entry:
            continue
        match = _GIT_TREE_ENTRY.fullmatch(raw_entry)
        if match is None:
            raise SourceDeltaError(f"malformed HEAD tree entry in {label}")
        path = match.group("path")
        parsed_path = PurePosixPath(path)
        if (
            "\ufffd" in path
            or parsed_path.is_absolute()
            or ".." in parsed_path.parts
            or ".git" in parsed_path.parts
        ):
            raise SourceDeltaError(f"unsafe HEAD tree path in {label}: {path!r}")
        mode = match.group("mode")
        object_type = match.group("type")
        if mode not in {"100644", "100755"} or object_type != "blob":
            entry_kind = {
                "040000": "sparse directory",
                "120000": "symlink",
                "160000": "gitlink",
            }.get(mode, f"{object_type} mode {mode}")
            raise SourceDeltaError(
                f"{label} HEAD tree contains forbidden {entry_kind}: {path!r}"
            )
        oid = match.group("oid")
        if oid_length is None:
            oid_length = len(oid)
        elif len(oid) != oid_length:
            raise SourceDeltaError(f"mixed Git object ID formats in {label}")
        if path in expected_files:
            raise SourceDeltaError(f"duplicate HEAD tree path in {label}: {path!r}")
        expected_files[path] = (oid, int(mode, 8))
        parent = parsed_path.parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent

    actual_files: set[str] = set()
    directory_signatures: dict[Path, tuple[int, int, int, int, int, int]] = {}
    try:
        for root, directories, files, root_fd in os.fwalk(
            directory,
            topdown=True,
            follow_symlinks=False,
        ):
            root_path = Path(root)
            relative_root = root_path.relative_to(directory)
            root_prefix = "" if relative_root == Path(".") else relative_root.as_posix()
            directory_signatures[root_path] = _git_metadata_signature(root_path)
            retained_directories: list[str] = []
            for name in directories:
                if name == ".git":
                    if not root_prefix:
                        continue
                    raise SourceDeltaError(
                        f"{label} worktree contains nested Git metadata: "
                        f"{root_prefix}/.git"
                    )
                metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                relative = f"{root_prefix}/{name}" if root_prefix else name
                if stat.S_ISLNK(metadata.st_mode):
                    raise SourceDeltaError(
                        f"{label} worktree contains a symlink: {relative!r}"
                    )
                if not stat.S_ISDIR(metadata.st_mode):
                    raise SourceDeltaError(
                        f"{label} worktree contains a non-directory entry: {relative!r}"
                    )
                if relative not in expected_directories:
                    raise _dirty_git_worktree_error(
                        label,
                        f"unexpected directory {relative!r}",
                    )
                retained_directories.append(name)
            directories[:] = retained_directories

            for name in files:
                relative = f"{root_prefix}/{name}" if root_prefix else name
                if name == ".git":
                    raise SourceDeltaError(
                        f"{label} worktree contains nested Git metadata: {relative!r}"
                    )
                expected = expected_files.get(relative)
                if expected is None:
                    raise _dirty_git_worktree_error(
                        label,
                        f"unexpected file {relative!r}",
                    )
                before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                    raise SourceDeltaError(
                        f"{label} worktree contains a non-regular file: {relative!r}"
                    )
                expected_oid, expected_mode = expected
                expected_executable = bool(expected_mode & 0o111)
                actual_executable = bool(before.st_mode & 0o111)
                if actual_executable != expected_executable:
                    raise SourceDeltaError(
                        f"{label} worktree mode differs from HEAD for {relative!r}"
                    )
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(name, flags, dir_fd=root_fd)
                try:
                    opened = os.fstat(descriptor)
                    if _git_metadata_signature_from_stat(opened) != (
                        _git_metadata_signature_from_stat(before)
                    ):
                        raise SourceDeltaError(
                            f"{label} worktree changed while opening {relative!r}"
                        )
                    actual_oid = _git_blob_oid(
                        descriptor,
                        opened.st_size,
                        len(expected_oid),
                    )
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                if _git_metadata_signature_from_stat(after) != (
                    _git_metadata_signature_from_stat(opened)
                ):
                    raise SourceDeltaError(
                        f"{label} worktree changed while hashing {relative!r}"
                    )
                if actual_oid != expected_oid:
                    raise _dirty_git_worktree_error(label, repr(relative))
                actual_files.add(relative)
    except OSError as exc:
        raise SourceDeltaError(f"cannot inspect {label} worktree: {exc}") from exc

    missing_files = sorted(set(expected_files) - actual_files)
    if missing_files:
        raise _dirty_git_worktree_error(
            label,
            f"missing file {missing_files[0]!r}",
        )
    for path, signature in directory_signatures.items():
        try:
            current = _git_metadata_signature(path)
        except OSError as exc:
            raise SourceDeltaError(
                f"{label} worktree changed during validation: {path}: {exc}"
            ) from exc
        if current != signature:
            raise SourceDeltaError(
                f"{label} worktree changed during validation: {path}"
            )


def _git_metadata_signature_from_stat(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def validate_git_repository_safety(
    source_dir: Path,
    label: str,
    git_output: Callable[[Sequence[str]], str],
    *,
    allow_incomplete_storage: bool = False,
    fsck_cache: SuccessfulGitFsckCache | None = None,
) -> Path:
    """Reject Git layouts/configuration that can redirect evidence or run code."""

    try:
        directory_metadata = source_dir.lstat()
    except OSError as exc:
        raise SourceDeltaError(f"cannot inspect {label} directory: {exc}") from exc
    if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(
        directory_metadata.st_mode
    ):
        raise SourceDeltaError(f"{label} must be a real directory: {source_dir}")
    directory = source_dir.resolve(strict=True)
    git_dir = directory / ".git"
    try:
        git_metadata = git_dir.lstat()
    except OSError as exc:
        raise SourceDeltaError(f"cannot inspect {label} Git directory: {exc}") from exc
    if stat.S_ISLNK(git_metadata.st_mode) or not stat.S_ISDIR(git_metadata.st_mode):
        raise SourceDeltaError(f"unsafe Git directory for {label}: {git_dir}")
    expected_git_dir = git_dir.resolve(strict=True)

    required_paths = (
        (git_dir / "HEAD", stat.S_ISREG),
        (git_dir / "config", stat.S_ISREG),
        (git_dir / "index", stat.S_ISREG),
        (git_dir / "objects", stat.S_ISDIR),
        (git_dir / "objects/info", stat.S_ISDIR),
        (git_dir / "objects/pack", stat.S_ISDIR),
        (git_dir / "refs", stat.S_ISDIR),
    )
    for path, expected_type in required_paths:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SourceDeltaError(
                f"cannot inspect {label} Git metadata {path}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not expected_type(metadata.st_mode):
            raise SourceDeltaError(f"unsafe Git metadata path for {label}: {path}")
    metadata_digest_before = _validate_git_metadata_tree(git_dir, label)

    forbidden_controls = (
        (git_dir / "config.worktree", "worktree config"),
        (git_dir / "config.worktree.lock", "worktree config lock"),
        (git_dir / "index.lock", "index lock"),
        (git_dir / "info/sparse-checkout", "sparse checkout"),
        (git_dir / "objects/info/alternates", "alternates"),
        (git_dir / "objects/info/http-alternates", "http-alternates"),
        (git_dir / "info/grafts", "grafts"),
        (git_dir / "refs/replace", "replace refs"),
    )
    for path, control in forbidden_controls:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SourceDeltaError(
                f"cannot inspect {label} {control} control: {exc}"
            ) from exc
        if allow_incomplete_storage and control in {
            "worktree config",
            "worktree config lock",
            "sparse checkout",
        }:
            continue
        raise SourceDeltaError(f"{label} uses forbidden {control}: {path}")

    metadata_paths = (directory, git_dir, *(path for path, _kind in required_paths))
    try:
        metadata_before = {
            path: _git_metadata_signature(path) for path in metadata_paths
        }
    except OSError as exc:
        raise SourceDeltaError(
            f"cannot bind {label} Git metadata before validation: {exc}"
        ) from exc

    actual_git_dir = _resolved_reported_git_directory(
        directory,
        git_output(["rev-parse", "--absolute-git-dir"]),
        f"{label} Git directory",
    )
    common_git_dir = _resolved_reported_git_directory(
        directory,
        git_output(["rev-parse", "--git-common-dir"]),
        f"{label} Git common directory",
    )
    if actual_git_dir != expected_git_dir or common_git_dir != expected_git_dir:
        raise SourceDeltaError(
            f"{label} Git metadata is redirected: git={actual_git_dir}, "
            f"common={common_git_dir}, expected={expected_git_dir}"
        )

    pack_dir = git_dir / "objects/pack"
    try:
        promisor_markers = sorted(
            path for path in pack_dir.iterdir() if path.name.endswith(".promisor")
        )
    except OSError as exc:
        raise SourceDeltaError(
            f"cannot inspect {label} Git pack directory: {exc}"
        ) from exc
    if promisor_markers:
        if not allow_incomplete_storage:
            raise SourceDeltaError(
                f"{label} uses forbidden promisor packs: {promisor_markers[:3]}"
            )

    shallow_path = git_dir / "shallow"
    try:
        shallow_metadata = shallow_path.lstat()
    except FileNotFoundError:
        shallow_metadata = None
    except OSError as exc:
        raise SourceDeltaError(
            f"cannot inspect {label} shallow history control: {exc}"
        ) from exc
    if shallow_metadata is not None:
        if stat.S_ISLNK(shallow_metadata.st_mode) or not stat.S_ISREG(
            shallow_metadata.st_mode
        ):
            raise SourceDeltaError(
                f"unsafe Git shallow history control for {label}: {shallow_path}"
            )
        if not allow_incomplete_storage:
            raise SourceDeltaError(
                f"{label} uses forbidden shallow history: {shallow_path}"
            )

    config_entries = _local_git_config_entries(
        git_output(["config", "--local", "--no-includes", "--null", "--list"]),
        label,
    )
    for key, value in config_entries:
        if key == "extensions.worktreeconfig":
            if allow_incomplete_storage:
                continue
            raise SourceDeltaError(f"{label} uses forbidden worktree config: {key}")
        if _GIT_PARTIAL_CONFIG_KEY.fullmatch(key):
            if not allow_incomplete_storage:
                raise SourceDeltaError(
                    f"{label} uses forbidden partial-clone/promisor config: {key}"
                )
            continue
        if allow_incomplete_storage and key in {
            "core.sparsecheckout",
            "core.sparsecheckoutcone",
            "index.sparse",
        }:
            continue
        if _external_git_config(key, value):
            raise SourceDeltaError(f"{label} uses forbidden external Git config: {key}")

    replace_refs = git_output(["for-each-ref", "--format=%(refname)", "refs/replace"])
    if replace_refs:
        raise SourceDeltaError(
            f"{label} uses forbidden replace refs: {replace_refs.splitlines()[0][:300]}"
        )
    top_level = _resolved_reported_git_directory(
        directory,
        git_output(["rev-parse", "--show-toplevel"]),
        f"{label} Git worktree",
    )
    if top_level != directory:
        raise SourceDeltaError(
            f"{label} Git worktree is redirected: {top_level} != {directory}"
        )
    head_before = git_output(["rev-parse", "--verify", "HEAD^{commit}"]).strip()
    tree_before = git_output(["rev-parse", "--verify", "HEAD^{tree}"]).strip()
    if not _GIT_OID.fullmatch(head_before) or not _GIT_OID.fullmatch(tree_before):
        raise SourceDeltaError(f"invalid Git HEAD or tree object ID in {label}")
    if not allow_incomplete_storage:
        _validate_git_index_and_worktree(directory, label, git_output)
        # The exact worktree proof binds bytes to HEAD OIDs, while fsck proves
        # that every object reachable from HEAD/history is actually present
        # and internally valid.  Partial legacy caches skip this only in the
        # disposable migration preflight and are never accepted as sources.
        fsck_key: GitFsckCacheKey = (
            str(directory),
            head_before,
            tree_before,
            metadata_digest_before,
        )
        fsck_cached = fsck_cache is not None and fsck_cache.contains(fsck_key)
        if not fsck_cached:
            git_output(["fsck", "--full", "--strict", "--no-dangling", "--no-progress"])
        metadata_digest_after = _validate_git_metadata_tree(git_dir, label)
        if metadata_digest_after != metadata_digest_before:
            raise SourceDeltaError(
                f"{label} Git object/ref metadata changed during validation"
            )
        if not fsck_cached and fsck_cache is not None:
            fsck_cache.record_success(fsck_key)
    head_after = git_output(["rev-parse", "--verify", "HEAD^{commit}"]).strip()
    tree_after = git_output(["rev-parse", "--verify", "HEAD^{tree}"]).strip()
    if (head_after, tree_after) != (head_before, tree_before):
        raise SourceDeltaError(f"{label} HEAD changed during validation")
    try:
        metadata_after = {
            path: _git_metadata_signature(path) for path in metadata_paths
        }
    except OSError as exc:
        raise SourceDeltaError(
            f"cannot bind {label} Git metadata after validation: {exc}"
        ) from exc
    changed_metadata = [
        str(path)
        for path in metadata_paths
        if metadata_after[path] != metadata_before[path]
    ]
    if changed_metadata:
        raise SourceDeltaError(
            f"{label} Git metadata changed during validation: {changed_metadata[0]}"
        )
    return directory


def _run_git(
    source: GitSource,
    arguments: Sequence[str],
) -> bytes:
    command = safe_git_command(source.directory, arguments)
    timeout_seconds = (
        GIT_FSCK_TIMEOUT_SECONDS
        if arguments and arguments[0] == "fsck"
        else GIT_COMMAND_TIMEOUT_SECONDS
    )
    try:
        completed = _run_argv_bounded(
            command,
            timeout=timeout_seconds,
            max_stdout_bytes=MAX_GIT_STDOUT_BYTES,
            max_stderr_bytes=MAX_GIT_STDERR_BYTES,
            capture_output=True,
            text=False,
            stdin=subprocess.DEVNULL,
            check=False,
            env=_git_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceDeltaError(f"Git command failed for {source.name}: {exc}") from exc
    if any(
        getattr(completed, attribute, False)
        for attribute in (
            "stdout_limit_exceeded",
            "stderr_limit_exceeded",
            "stdout_drain_incomplete",
            "stderr_drain_incomplete",
        )
    ):
        raise SourceDeltaError(
            f"Git command output was incomplete or exceeded the bounded limit "
            f"for {source.name}"
        )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", "replace")[:2000]
        raise SourceDeltaError(
            f"Git command failed for {source.name} with exit {completed.returncode}: {error}"
        )
    return completed.stdout


def _normalize_origin(value: str) -> str:
    return value.strip().rstrip("/").removesuffix(".git")


def _read_baseline_head(source: GitSource) -> str:
    data = _regular_file_bytes(
        source.baseline_head_file, f"{source.name} baseline HEAD"
    )
    try:
        value = data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise SourceDeltaError(f"{source.name} baseline HEAD is not ASCII") from exc
    if not _GIT_OID.fullmatch(value):
        raise SourceDeltaError(f"invalid {source.name} baseline HEAD: {value!r}")
    return value


def _decode_git_text(source: GitSource, arguments: Sequence[str]) -> str:
    try:
        return _run_git(source, arguments).decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SourceDeltaError(
            f"non-UTF-8 Git output for {source.name}: {' '.join(arguments)}"
        ) from exc


def _git_state(
    source: GitSource,
    *,
    fsck_cache: SuccessfulGitFsckCache | None = None,
) -> dict[str, Any]:
    _real_directory(source.directory, f"{source.name} Git mirror")
    validate_git_repository_safety(
        source.directory,
        f"{source.name} Git mirror",
        lambda arguments: _decode_git_text(source, arguments).strip(),
        fsck_cache=fsck_cache,
    )
    head = (
        _run_git(source, ["rev-parse", "--verify", "HEAD^{commit}"])
        .decode("ascii")
        .strip()
    )
    tree = (
        _run_git(source, ["rev-parse", "--verify", "HEAD^{tree}"])
        .decode("ascii")
        .strip()
    )
    origin = _run_git(source, ["remote", "get-url", "origin"]).decode("utf-8").strip()
    dirty = _run_git(source, ["status", "--porcelain=v1", "--untracked-files=all"])
    if not _GIT_OID.fullmatch(head) or not _GIT_OID.fullmatch(tree):
        raise SourceDeltaError(f"invalid Git object ID in {source.name}")
    if dirty:
        raise SourceDeltaError(f"Git mirror is dirty: {source.name}")
    if _normalize_origin(origin) != _normalize_origin(source.expected_origin):
        raise SourceDeltaError(
            f"wrong Git origin for {source.name}: expected {source.expected_origin}, got {origin}"
        )
    return {"head": head, "tree": tree, "origin": origin, "clean": True}


def _subject_candidate(value: Any, label: str) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if stripped != value or not _SUBJECT_ID.fullmatch(stripped):
        return None
    if stripped.upper().startswith("CWE-"):
        return None
    return _validate_subject_id(stripped, label)


def _extract_json_subject_ids(
    data: bytes, label: str, *, allow_non_object: bool = False
) -> list[str]:
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceDeltaError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(payload, dict):
        if allow_non_object:
            return []
        raise SourceDeltaError(f"JSON root must be an object in {label}")

    output: list[str] = []
    key_names = {"id", "cveid", "cve_id", "ghsa_id", "identifier"}
    list_names = {"aliases", "identifiers"}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = key.lower()
                if normalized_key in key_names:
                    candidate = _subject_candidate(item, label)
                    if candidate:
                        output.append(candidate)
                elif normalized_key in list_names:
                    if item is None:
                        continue
                    if not isinstance(item, list):
                        raise SourceDeltaError(f"{key} must be an array in {label}")
                    list_candidates: list[str] = []
                    for alias in item:
                        if isinstance(alias, dict):
                            candidate = _subject_candidate(alias.get("value"), label)
                        else:
                            candidate = _subject_candidate(alias, label)
                        if candidate:
                            list_candidates.append(candidate)
                    duplicates = {
                        subject: count
                        for subject, count in Counter(list_candidates).items()
                        if count > 1
                    }
                    if duplicates:
                        raise SourceDeltaError(
                            f"duplicate vulnerability aliases in {label}: "
                            f"{dict(list(duplicates.items())[:10])}"
                        )
                    output.extend(list_candidates)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(payload)
    return _ordered_unique(output)


def _yaml_scalar(value: str, label: str) -> str:
    raw = value.split(" #", 1)[0].strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
        raw = raw[1:-1]
    candidate = _subject_candidate(raw, label)
    if candidate is None:
        raise SourceDeltaError(
            f"invalid YAML advisory identifier in {label}: {value!r}"
        )
    return candidate


def _extract_yaml_subject_ids(data: bytes, label: str) -> list[str]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SourceDeltaError(f"invalid UTF-8 YAML in {label}") from exc
    output: list[str] = []
    in_identifiers = False
    identifiers_indent = 0
    for line in lines:
        if not line.strip() or line.lstrip().startswith(("#", "---")):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0 and stripped.startswith("identifier:"):
            output.append(_yaml_scalar(stripped.split(":", 1)[1], label))
            in_identifiers = False
            continue
        if indent == 0 and stripped == "identifiers:":
            in_identifiers = True
            identifiers_indent = indent
            continue
        if in_identifiers:
            if stripped.startswith("-") and indent >= identifiers_indent:
                output.append(_yaml_scalar(stripped[1:], label))
                continue
            if indent <= identifiers_indent:
                in_identifiers = False
    if not output:
        raise SourceDeltaError(f"Gemnasium YAML has no identifier fields: {label}")
    duplicates = [item for item, count in Counter(output).items() if count > 1]
    if duplicates:
        # Gemnasium routinely repeats the primary ID in identifiers.  It is a
        # schema-level alias repetition, so canonicalize it while preserving a
        # duplicate-free emitted subject list.
        output = _ordered_unique(output)
    return output


def _extract_advisory_subject_ids(data: bytes, path: str, label: str) -> list[str]:
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return _extract_json_subject_ids(data, label, allow_non_object=True)
    if suffix in {".yml", ".yaml"}:
        return _extract_yaml_subject_ids(data, label)
    return []


def _git_blob_or_none(source: GitSource, revision: str, path: str) -> bytes | None:
    listing = _run_git(source, ["ls-tree", "-z", revision, "--", path])
    if not listing:
        return None
    entries = [entry for entry in listing.split(b"\0") if entry]
    if len(entries) != 1 or not entries[0].endswith(b"\t" + path.encode("utf-8")):
        raise SourceDeltaError(
            f"ambiguous Git tree entry for {source.name}:{revision}:{path}"
        )
    return _run_git(source, ["show", f"{revision}:{path}"])


def _git_is_ancestor(source: GitSource, before: str, after: str) -> bool:
    command = safe_git_command(
        source.directory,
        ["merge-base", "--is-ancestor", before, after],
    )
    try:
        completed = _run_argv_bounded(
            command,
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
            max_stdout_bytes=64 * 1024,
            max_stderr_bytes=MAX_GIT_STDERR_BYTES,
            capture_output=True,
            text=False,
            stdin=subprocess.DEVNULL,
            check=False,
            env=_git_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceDeltaError(
            f"Git ancestry check failed for {source.name}: {exc}"
        ) from exc
    if any(
        getattr(completed, attribute, False)
        for attribute in (
            "stdout_limit_exceeded",
            "stderr_limit_exceeded",
            "stdout_drain_incomplete",
            "stderr_drain_incomplete",
        )
    ):
        raise SourceDeltaError(
            f"Git ancestry output was incomplete or exceeded the bounded limit "
            f"for {source.name}"
        )
    if completed.returncode not in {0, 1, 128}:
        error = completed.stderr.decode("utf-8", "replace")[:2000]
        raise SourceDeltaError(
            f"Git ancestry check failed for {source.name} with exit "
            f"{completed.returncode}: {error}"
        )
    return completed.returncode == 0


def _compare_git(source: GitSource, initial_state: Mapping[str, Any]) -> dict[str, Any]:
    before = _read_baseline_head(source)
    after = str(initial_state["head"])
    if not _git_is_ancestor(source, before, after):
        raise SourceDeltaError(
            f"preserved HEAD is absent from or not an ancestor of current {source.name}: {before} -> {after}"
        )
    raw_paths = _run_git(
        source,
        [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "--no-renames",
            "-z",
            before,
            after,
            "--",
        ],
    )
    try:
        decoded = raw_paths.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceDeltaError(f"non-UTF-8 changed path in {source.name}") from exc
    changed_files = sorted(item for item in decoded.split("\0") if item)
    if len(changed_files) != len(set(changed_files)):
        raise SourceDeltaError(
            f"duplicate changed paths reported by Git for {source.name}"
        )
    if any(
        PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
        for path in changed_files
    ):
        raise SourceDeltaError(f"unsafe changed path reported by Git for {source.name}")

    subject_ids: set[str] = set()
    parsed_files: list[str] = []
    for path in changed_files:
        if Path(path).suffix.lower() not in {".json", ".yml", ".yaml"}:
            continue
        for revision, side in ((before, "before"), (after, "after")):
            blob = _git_blob_or_none(source, revision, path)
            if blob is None:
                continue
            extracted = _extract_advisory_subject_ids(
                blob,
                path,
                f"{source.name}:{revision}:{path} ({side})",
            )
            subject_ids.update(extracted)
        parsed_files.append(path)
    return {
        "before": before,
        "after": after,
        "after_tree": initial_state["tree"],
        "origin": initial_state["origin"],
        "changed_file_count": len(changed_files),
        "changed_files": changed_files,
        "parsed_advisory_file_count": len(parsed_files),
        "parsed_advisory_files": parsed_files,
        "subject_id_count": len(subject_ids),
        "subject_ids": sorted(subject_ids),
    }


def _check_nvd_deadline(started_at: float, label: str) -> None:
    if time.monotonic() - started_at > NVD_VALIDATION_TIMEOUT_SECONDS:
        raise SourceDeltaError(
            f"{label} validation exceeded {NVD_VALIDATION_TIMEOUT_SECONDS} seconds"
        )


def _load_nvd(
    path: Path,
    label: str,
    *,
    expected_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, tuple[str, bytes]]:
    started = time.monotonic()
    expected_size, expected_sha256 = _validate_expected_snapshot(
        expected_snapshot,
        label,
    )
    try:
        raw_handle, opened = _open_stable_regular_file(path, label)
        try:
            if opened.st_size > MAX_NVD_GZIP_BYTES:
                raise SourceDeltaError(
                    f"{label} compressed size exceeds {MAX_NVD_GZIP_BYTES} bytes: "
                    f"{opened.st_size}"
                )
            if expected_size is not None and opened.st_size != expected_size:
                raise SourceDeltaError(
                    f"{label} does not match expected snapshot size: "
                    f"{opened.st_size} != {expected_size}"
                )
            compressed = bytearray()
            digest = hashlib.sha256()
            while True:
                _check_nvd_deadline(started, label)
                chunk = raw_handle.read(
                    min(
                        NVD_READ_CHUNK_BYTES,
                        MAX_NVD_GZIP_BYTES - len(compressed) + 1,
                    )
                )
                if not chunk:
                    break
                compressed.extend(chunk)
                digest.update(chunk)
                if len(compressed) > MAX_NVD_GZIP_BYTES:
                    raise SourceDeltaError(
                        f"{label} compressed read exceeds {MAX_NVD_GZIP_BYTES} bytes"
                    )
            if len(compressed) != opened.st_size:
                raise SourceDeltaError(f"{label} changed while being read: {path}")
            actual_sha256 = digest.hexdigest()
            if expected_sha256 is not None and actual_sha256 != expected_sha256:
                raise SourceDeltaError(
                    f"{label} does not match expected snapshot sha256: "
                    f"{actual_sha256} != {expected_sha256}"
                )
            _verify_open_file_identity(
                path,
                raw_handle,
                opened,
                label,
                action="read",
            )
        finally:
            raw_handle.close()

        data = bytearray()
        compressed_stream = io.BytesIO(compressed)
        del compressed
        with compressed_stream:
            with gzip.GzipFile(fileobj=compressed_stream, mode="rb") as handle:
                while True:
                    _check_nvd_deadline(started, label)
                    chunk = handle.read(
                        min(
                            NVD_READ_CHUNK_BYTES,
                            MAX_NVD_JSON_BYTES - len(data) + 1,
                        )
                    )
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > MAX_NVD_JSON_BYTES:
                        raise SourceDeltaError(
                            f"{label} decompressed JSON exceeds "
                            f"{MAX_NVD_JSON_BYTES} bytes"
                        )
        _check_nvd_deadline(started, label)
        payload = json.loads(data)
        del data
        _check_nvd_deadline(started, label)
    except SourceDeltaError:
        raise
    except (OSError, EOFError, UnicodeError, json.JSONDecodeError) as exc:
        raise SourceDeltaError(f"invalid {label} {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(
        payload.get("vulnerabilities"), list
    ):
        raise SourceDeltaError(f"{label} has no vulnerabilities array: {path}")
    records: dict[str, tuple[str, bytes]] = {}
    for index, wrapper in enumerate(payload["vulnerabilities"]):
        _check_nvd_deadline(started, label)
        if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
            raise SourceDeltaError(f"malformed {label} record at index {index}")
        record = wrapper["cve"]
        identifier = record.get("id")
        if not isinstance(identifier, str):
            raise SourceDeltaError(f"NVD record at index {index} has no string id")
        identifier = _validate_subject_id(identifier, label)
        if identifier in records:
            raise SourceDeltaError(f"duplicate NVD subject ID in {label}: {identifier}")
        canonical = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        records[identifier] = (_sha256_bytes(canonical), canonical)
        _check_nvd_deadline(started, label)
    if not records:
        raise SourceDeltaError(f"{label} contains no CVE records")
    del payload
    _check_nvd_deadline(started, label)
    return records


def _compare_nvd(
    paths: BuildPaths,
    current_snapshot: Mapping[str, Any],
    baseline_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    baseline_names = sorted(
        path.name for path in paths.baseline_dir.glob("nvdcve-2.0-*.json.gz")
    )
    current_names = sorted(
        path.name for path in paths.nvd_dir.glob("nvdcve-2.0-*.json.gz")
    )
    if baseline_names != current_names or baseline_names != [
        "nvdcve-2.0-2025.json.gz",
        "nvdcve-2.0-2026.json.gz",
    ]:
        raise SourceDeltaError(
            f"NVD baseline/current inventory mismatch: baseline={baseline_names}, current={current_names}"
        )
    output: dict[str, Any] = {}
    for name in baseline_names:
        year_match = re.fullmatch(r"nvdcve-2\.0-([0-9]{4})\.json\.gz", name)
        assert year_match is not None
        year = year_match.group(1)
        before_path = paths.baseline_dir / name
        after_path = paths.nvd_dir / name
        before = _load_nvd(
            before_path,
            f"NVD {year} baseline",
            expected_snapshot={
                "size_bytes": before_path.stat().st_size,
                "sha256": baseline_snapshot[name],
            },
        )
        after = _load_nvd(
            after_path,
            f"NVD {year} current",
            expected_snapshot=current_snapshot[name],
        )
        before_ids = set(before)
        after_ids = set(after)
        added = sorted(after_ids - before_ids)
        removed = sorted(before_ids - after_ids)
        changed = sorted(
            identifier
            for identifier in before_ids & after_ids
            if before[identifier][0] != after[identifier][0]
        )
        subjects: set[str] = set(added) | set(removed) | set(changed)
        for identifier in changed + removed:
            subjects.update(
                _extract_json_subject_ids(
                    before[identifier][1], f"NVD {year} baseline {identifier}"
                )
            )
        for identifier in changed + added:
            subjects.update(
                _extract_json_subject_ids(
                    after[identifier][1], f"NVD {year} current {identifier}"
                )
            )
        output[year] = {
            "baseline_file": _relative_path(before_path, paths.repo_root),
            "current_file": _relative_path(after_path, paths.repo_root),
            "baseline_sha256": baseline_snapshot[name],
            "current_sha256": current_snapshot[name]["sha256"],
            "baseline_record_count": len(before),
            "current_record_count": len(after),
            "added_count": len(added),
            "changed_count": len(changed),
            "removed_count": len(removed),
            "added": added,
            "changed": changed,
            "removed": removed,
            "subject_id_count": len(subjects),
            "subject_ids": sorted(subjects),
        }
    return output


def _inspect_open_zip_physical_bounds(
    handle: BinaryIO,
    archive_size: int,
    path: Path,
    label: str,
    *,
    max_archive_bytes: int | None = None,
    max_central_directory_bytes: int | None = None,
    max_members: int | None = None,
) -> tuple[int, int, int]:
    """Inspect the bounded EOCD before ``ZipFile`` loads the central directory."""

    archive_limit = (
        MAX_OSV_ARCHIVE_BYTES if max_archive_bytes is None else max_archive_bytes
    )
    central_limit = (
        MAX_OSV_CENTRAL_DIRECTORY_BYTES
        if max_central_directory_bytes is None
        else max_central_directory_bytes
    )
    member_limit = MAX_OSV_ARCHIVE_MEMBERS if max_members is None else max_members
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (archive_limit, central_limit, member_limit)
    ):
        raise SourceDeltaError("ZIP physical limits must be positive integers")

    if archive_size <= 0 or archive_size > archive_limit:
        raise SourceDeltaError(
            f"{label} archive size is outside 1..{archive_limit} bytes: {archive_size}"
        )

    try:
        handle.seek(0)
        # This private stdlib helper reads at most the EOCD search window and
        # ZIP64 trailer. It runs on the same descriptor later given to ZipFile.
        end_record = zipfile._EndRecData(handle)  # noqa: SLF001
        handle.seek(0)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise SourceDeltaError(f"invalid {label} {path}: {exc}") from exc
    if end_record is None:
        raise SourceDeltaError(f"invalid {label} {path}: missing ZIP end record")

    values = {
        "disk": end_record[zipfile._ECD_DISK_NUMBER],  # noqa: SLF001
        "start_disk": end_record[zipfile._ECD_DISK_START],  # noqa: SLF001
        "entries_this_disk": end_record[zipfile._ECD_ENTRIES_THIS_DISK],  # noqa: SLF001
        "entries": end_record[zipfile._ECD_ENTRIES_TOTAL],  # noqa: SLF001
        "central_size": end_record[zipfile._ECD_SIZE],  # noqa: SLF001
        "central_offset": end_record[zipfile._ECD_OFFSET],  # noqa: SLF001
        "end_location": end_record[zipfile._ECD_LOCATION],  # noqa: SLF001
    }
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in values.values()
    ):
        raise SourceDeltaError(f"invalid {label} {path}: malformed ZIP end record")
    if (
        values["disk"] != 0
        or values["start_disk"] != 0
        or values["entries_this_disk"] != values["entries"]
    ):
        raise SourceDeltaError(f"invalid {label} {path}: multi-disk ZIP is unsupported")
    if values["entries"] == 0 or values["entries"] > member_limit:
        raise SourceDeltaError(
            f"{label} member count is outside 1..{member_limit}: {values['entries']}"
        )
    if values["central_size"] > central_limit:
        raise SourceDeltaError(
            f"{label} central directory exceeds {central_limit} bytes: "
            f"{values['central_size']}"
        )
    concat = values["end_location"] - values["central_size"] - values["central_offset"]
    central_start = values["central_offset"] + concat
    central_end = central_start + values["central_size"]
    if (
        concat < 0
        or central_start < 0
        or central_end != values["end_location"]
        or central_end > archive_size
    ):
        raise SourceDeltaError(
            f"invalid {label} {path}: unsafe central directory bounds"
        )
    return archive_size, values["central_size"], values["entries"]


def _inspect_zip_physical_bounds(
    path: Path,
    label: str,
    *,
    max_archive_bytes: int | None = None,
    max_central_directory_bytes: int | None = None,
    max_members: int | None = None,
) -> tuple[int, int, int]:
    """Inspect a no-follow descriptor and prove the path still names it."""

    handle, initial = _open_stable_regular_file(path, label)
    try:
        result = _inspect_open_zip_physical_bounds(
            handle,
            initial.st_size,
            path,
            label,
            max_archive_bytes=max_archive_bytes,
            max_central_directory_bytes=max_central_directory_bytes,
            max_members=max_members,
        )
        _verify_open_file_identity(
            path,
            handle,
            initial,
            label,
            action="inspected",
        )
        return result
    finally:
        handle.close()


def _check_osv_archive_deadline(started_at: float, label: str) -> None:
    if time.monotonic() - started_at > OSV_ARCHIVE_VALIDATION_TIMEOUT_SECONDS:
        raise SourceDeltaError(
            f"{label} validation exceeded "
            f"{OSV_ARCHIVE_VALIDATION_TIMEOUT_SECONDS} seconds"
        )


class _StableZipArchive:
    """Own one source descriptor across ZIP preflight, scanning, and close guard."""

    def __init__(
        self,
        archive: zipfile.ZipFile,
        source_handle: BinaryIO,
        path: Path,
        label: str,
        initial: os.stat_result,
        sha256: str,
    ) -> None:
        self._archive = archive
        self._source_handle = source_handle
        self._path = path
        self._label = label
        self._initial = initial
        self._sha256 = sha256
        self._closed = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._archive, name)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._archive.close()
            sha256, size = _hash_open_file(self._source_handle)
            _verify_open_file_identity(
                self._path,
                self._source_handle,
                self._initial,
                self._label,
                action="scanned",
            )
            if size != self._initial.st_size or sha256 != self._sha256:
                raise SourceDeltaError(
                    f"{self._label} changed while being scanned: {self._path}"
                )
        finally:
            self._source_handle.close()
            self._closed = True


def _safe_zip_members(
    path: Path,
    label: str,
    *,
    started_at: float | None = None,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> tuple[_StableZipArchive, dict[str, zipfile.ZipInfo]]:
    started = time.monotonic() if started_at is None else started_at
    if (
        expected_size is not None
        and (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size <= 0
        )
    ) or (
        expected_sha256 is not None
        and (
            not isinstance(expected_sha256, str)
            or _HEX_SHA256.fullmatch(expected_sha256) is None
        )
    ):
        raise SourceDeltaError(f"invalid expected snapshot for {label}")
    handle, initial = _open_stable_regular_file(path, label)
    try:
        if expected_size is not None and initial.st_size != expected_size:
            raise SourceDeltaError(
                f"{label} does not match expected snapshot size: "
                f"{initial.st_size} != {expected_size}"
            )
        sha256, hashed_size = _hash_open_file(
            handle,
            deadline=lambda: _check_osv_archive_deadline(started, label),
        )
        if hashed_size != initial.st_size or (
            expected_sha256 is not None and sha256 != expected_sha256
        ):
            raise SourceDeltaError(f"{label} does not match expected snapshot sha256")
        _verify_open_file_identity(
            path,
            handle,
            initial,
            label,
            action="hashed",
        )
        _archive_size, _central_size, declared_members = (
            _inspect_open_zip_physical_bounds(
                handle,
                initial.st_size,
                path,
                label,
            )
        )
        _check_osv_archive_deadline(started, label)
        archive = _StableZipArchive(
            zipfile.ZipFile(handle),
            handle,
            path,
            label,
            initial,
            sha256,
        )
        infos = archive.infolist()
    except SourceDeltaError:
        handle.close()
        raise
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        handle.close()
        raise SourceDeltaError(f"invalid {label} {path}: {exc}") from exc
    except BaseException:
        handle.close()
        raise
    members: dict[str, zipfile.ZipInfo] = {}
    try:
        if len(infos) != declared_members or len(infos) > MAX_OSV_ARCHIVE_MEMBERS:
            raise SourceDeltaError(
                f"{label} central-directory member count is inconsistent"
            )
        uncompressed_bytes = 0
        for info in infos:
            _check_osv_archive_deadline(started, label)
            pure = PurePosixPath(info.filename)
            file_type = stat.S_IFMT(info.external_attr >> 16)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or "\\" in info.filename
                or info.flag_bits & 0x1
                or file_type == stat.S_IFLNK
            ):
                raise SourceDeltaError(
                    f"unsafe ZIP member in {label}: {info.filename!r}"
                )
            if info.file_size > MAX_OSV_ARCHIVE_MEMBER_BYTES:
                raise SourceDeltaError(
                    f"ZIP member exceeds {MAX_OSV_ARCHIVE_MEMBER_BYTES} bytes in "
                    f"{label}: {info.filename!r}"
                )
            uncompressed_bytes += info.file_size
            if uncompressed_bytes > MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES:
                raise SourceDeltaError(
                    f"{label} uncompressed content exceeds "
                    f"{MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES} bytes"
                )
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            if info.filename in members:
                raise SourceDeltaError(
                    f"duplicate ZIP member in {label}: {info.filename!r}"
                )
            members[info.filename] = info
        if not members:
            raise SourceDeltaError(f"{label} contains no JSON members")
    except BaseException:
        archive.close()
        raise
    return archive, members


def _zip_member_fingerprint(info: zipfile.ZipInfo) -> tuple[int, int]:
    return info.CRC, info.file_size


def _extract_osv_subject_ids(
    data: bytes | bytearray,
    label: str,
) -> tuple[list[str], list[str], str | None, str]:
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceDeltaError(f"invalid OSV JSON in {label}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SourceDeltaError(f"OSV record root must be an object in {label}")
    primary = payload.get("id")
    if not isinstance(primary, str):
        raise SourceDeltaError(f"OSV record has no string primary ID in {label}")
    primary_subject = _subject_candidate(primary, label)
    identifiers = [primary_subject] if primary_subject is not None else []
    invalid_aliases: list[str] = []
    aliases = payload.get("aliases")
    if aliases is not None:
        if not isinstance(aliases, list):
            raise SourceDeltaError(f"OSV aliases must be an array in {label}")
        for alias in aliases:
            if not isinstance(alias, str):
                raise SourceDeltaError(f"OSV alias must be a string in {label}")
            candidate = _subject_candidate(alias, label)
            if candidate is None:
                invalid_aliases.append(alias)
            else:
                identifiers.append(candidate)
    duplicates = {
        identifier: count
        for identifier, count in Counter(identifiers).items()
        if count > 1
    }
    if duplicates:
        raise SourceDeltaError(f"duplicate OSV subject IDs in {label}: {duplicates}")
    return identifiers, invalid_aliases, primary_subject, primary


def _quarantine_value(value: str, label: str) -> dict[str, str | int]:
    """Return a bounded, content-addressed description of one invalid ID."""

    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise SourceDeltaError(
            f"invalid OSV identifier is not strict UTF-8 in {label}"
        ) from exc
    preview = encoded[:MAX_OSV_QUARANTINE_PREVIEW_BYTES].decode(
        "utf-8",
        errors="ignore",
    )
    return {
        "preview": preview,
        "sha256": _sha256_bytes(encoded),
        "value_length": len(value),
    }


def _scan_osv_records(
    archive: _StableZipArchive,
    members: Mapping[str, zipfile.ZipInfo],
    label: str,
    *,
    started_at: float | None = None,
) -> dict[str, Any]:
    started = time.monotonic() if started_at is None else started_at
    output: dict[str, tuple[str, ...]] = {}
    primary_owners: dict[str, str] = {}
    invalid_alias_count = 0
    invalid_aliases: list[dict[str, str | int]] = []
    invalid_primary_count = 0
    invalid_primaries: list[dict[str, str | int]] = []
    for name in sorted(members):
        _check_osv_archive_deadline(started, label)
        info = members[name]
        data = bytearray()
        try:
            with archive.open(info) as member:
                while True:
                    _check_osv_archive_deadline(started, label)
                    chunk = member.read(
                        min(
                            OSV_ARCHIVE_READ_CHUNK_BYTES,
                            MAX_OSV_ARCHIVE_MEMBER_BYTES - len(data) + 1,
                        )
                    )
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > MAX_OSV_ARCHIVE_MEMBER_BYTES:
                        raise SourceDeltaError(
                            f"expanded ZIP member exceeds "
                            f"{MAX_OSV_ARCHIVE_MEMBER_BYTES} bytes in {label}: {name!r}"
                        )
        except SourceDeltaError:
            raise
        except (EOFError, KeyError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise SourceDeltaError(f"cannot read {label} member {name}: {exc}") from exc
        if len(data) != info.file_size:
            raise SourceDeltaError(
                f"expanded ZIP member size mismatch in {label}: {name!r}"
            )
        extracted, invalid, primary, raw_primary = _extract_osv_subject_ids(
            data,
            f"{label}:{name}",
        )
        invalid_alias_count += len(invalid)
        for alias in invalid:
            if len(invalid_aliases) < MAX_RECORDED_INVALID_ALIASES:
                invalid_aliases.append(
                    {
                        "member": name,
                        **_quarantine_value(alias, f"{label}:{name}"),
                    }
                )
        if primary is None:
            invalid_primary_count += 1
            if invalid_primary_count > MAX_OSV_INVALID_PRIMARY_IDS:
                raise SourceDeltaError(
                    f"{label} invalid primary-ID quarantine exceeds "
                    f"{MAX_OSV_INVALID_PRIMARY_IDS} records"
                )
            if len(invalid_primaries) < MAX_RECORDED_INVALID_PRIMARIES:
                invalid_primaries.append(
                    {
                        "member": name,
                        **_quarantine_value(raw_primary, f"{label}:{name}"),
                    }
                )
        else:
            previous = primary_owners.get(primary)
            if previous is not None:
                raise SourceDeltaError(
                    f"duplicate OSV primary ID {primary} in {label}: {previous}, {name}"
                )
            primary_owners[primary] = name
        output[name] = tuple(extracted)
        _check_osv_archive_deadline(started, label)
    _check_osv_archive_deadline(started, label)
    return {
        "records": output,
        "invalid_alias_count": invalid_alias_count,
        "invalid_aliases": invalid_aliases,
        "invalid_primary_count": invalid_primary_count,
        "invalid_primaries": invalid_primaries,
    }


def _subjects_for_members(
    records: Mapping[str, tuple[str, ...]], names: Iterable[str]
) -> set[str]:
    return {identifier for name in names for identifier in records[name]}


def _osv_ecosystem_inventory(paths: BuildPaths) -> OsvEcosystemInventory:
    data = _regular_file_bytes(paths.osv_ecosystems_file, "OSV ecosystem manifest")
    return parse_osv_ecosystems_manifest(data)


def _expected_osv_archive_paths(paths: BuildPaths) -> tuple[Path, ...]:
    """Resolve the exact archive inventory derived from the bound manifest."""

    directory = _real_directory(paths.osv_dir, "current OSV archive directory")
    expected = _osv_ecosystem_inventory(paths).archive_names

    current_paths = tuple(
        sorted(
            directory.glob("*.zip"),
            key=lambda path: (path.name.casefold(), path.name),
        )
    )
    current_names = tuple(path.name for path in current_paths)
    if len({name.casefold() for name in current_names}) != len(current_names):
        raise SourceDeltaError("current OSV ZIP names collide case-insensitively")
    if current_names != expected:
        missing = sorted(set(expected) - set(current_names))
        unexpected = sorted(set(current_names) - set(expected))
        raise SourceDeltaError(
            "current OSV ZIP inventory does not match the ecosystem manifest: "
            f"missing={missing}, unexpected={unexpected}"
        )
    return current_paths


def _compare_osv(
    paths: BuildPaths,
    current_snapshot: Mapping[str, Any],
    baseline_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    current_paths = _expected_osv_archive_paths(paths)
    current_names = {path.name for path in current_paths}
    if set(current_snapshot) != current_names:
        raise SourceDeltaError(
            "current OSV snapshot inventory changed before comparison"
        )
    baseline_paths = {
        path.name: path
        for path in paths.baseline_dir.glob("*.zip")
        if path.is_file() and not path.is_symlink()
    }
    unknown_baselines = sorted(
        set(baseline_paths) - {path.name for path in current_paths}
    )
    if unknown_baselines:
        raise SourceDeltaError(
            f"preserved OSV ZIPs are absent from current inventory: {unknown_baselines}"
        )

    output: dict[str, Any] = {}
    for current_path in current_paths:
        name = current_path.name
        expected_current = current_snapshot[name]
        expected_size, current_sha = _validate_expected_snapshot(
            expected_current,
            f"current OSV archive {name}",
        )
        assert expected_size is not None and current_sha is not None
        current_started = time.monotonic()
        current_archive, current_members = _safe_zip_members(
            current_path,
            f"current OSV archive {name}",
            started_at=current_started,
            expected_size=expected_size,
            expected_sha256=current_sha,
        )
        baseline_path = baseline_paths.get(name)
        try:
            current_records = _scan_osv_records(
                current_archive,
                current_members,
                f"current OSV archive {name}",
                started_at=current_started,
            )
            if baseline_path is None:
                output[current_path.stem] = {
                    "comparison": "baseline_not_preserved",
                    "baseline_file": None,
                    "baseline_sha256": None,
                    "current_file": _relative_path(current_path, paths.repo_root),
                    "current_sha256": current_sha,
                    "current_member_count": len(current_members),
                    "current_invalid_alias_count": current_records[
                        "invalid_alias_count"
                    ],
                    "current_invalid_aliases": current_records["invalid_aliases"],
                    "current_invalid_primary_count": current_records[
                        "invalid_primary_count"
                    ],
                    "current_invalid_primaries": current_records["invalid_primaries"],
                    "added_member_count": 0,
                    "changed_member_count": 0,
                    "removed_member_count": 0,
                    "added_members": [],
                    "changed_members": [],
                    "removed_members": [],
                    "subject_id_count": 0,
                    "subject_ids": [],
                }
                continue
            baseline_sha = baseline_snapshot.get(name)
            if not isinstance(baseline_sha, str):
                raise SourceDeltaError(f"baseline snapshot omits OSV archive {name}")
            baseline_started = time.monotonic()
            baseline_archive, baseline_members = _safe_zip_members(
                baseline_path,
                f"baseline OSV archive {name}",
                started_at=baseline_started,
                expected_size=baseline_path.stat().st_size,
                expected_sha256=baseline_sha,
            )
            try:
                baseline_records = _scan_osv_records(
                    baseline_archive,
                    baseline_members,
                    f"baseline OSV archive {name}",
                    started_at=baseline_started,
                )
                before_names = set(baseline_members)
                after_names = set(current_members)
                added = sorted(after_names - before_names)
                removed = sorted(before_names - after_names)
                changed = sorted(
                    member
                    for member in before_names & after_names
                    if _zip_member_fingerprint(baseline_members[member])
                    != _zip_member_fingerprint(current_members[member])
                )
                subjects = _subjects_for_members(
                    current_records["records"],
                    added + changed,
                )
                subjects.update(
                    _subjects_for_members(
                        baseline_records["records"],
                        changed + removed,
                    )
                )
            finally:
                baseline_archive.close()
            output[current_path.stem] = {
                "comparison": "member_diff",
                "baseline_file": _relative_path(baseline_path, paths.repo_root),
                "baseline_sha256": baseline_sha,
                "current_file": _relative_path(current_path, paths.repo_root),
                "current_sha256": current_sha,
                "baseline_member_count": len(baseline_members),
                "current_member_count": len(current_members),
                "baseline_invalid_alias_count": baseline_records["invalid_alias_count"],
                "baseline_invalid_aliases": baseline_records["invalid_aliases"],
                "baseline_invalid_primary_count": baseline_records[
                    "invalid_primary_count"
                ],
                "baseline_invalid_primaries": baseline_records["invalid_primaries"],
                "current_invalid_alias_count": current_records["invalid_alias_count"],
                "current_invalid_aliases": current_records["invalid_aliases"],
                "current_invalid_primary_count": current_records[
                    "invalid_primary_count"
                ],
                "current_invalid_primaries": current_records["invalid_primaries"],
                "added_member_count": len(added),
                "changed_member_count": len(changed),
                "removed_member_count": len(removed),
                "added_members": added,
                "changed_members": changed,
                "removed_members": removed,
                "subject_id_count": len(subjects),
                "subject_ids": sorted(subjects),
            }
        finally:
            current_archive.close()
    return output


def _ghsa_source(paths: BuildPaths) -> GitSource:
    matches = [
        source
        for source in paths.git_sources
        if source.name == "github-advisory-database"
    ]
    if len(matches) != 1:
        raise SourceDeltaError(
            "exactly one github-advisory-database Git source is required"
        )
    return matches[0]


@contextmanager
def _frozen_discovery_sources(paths: BuildPaths):
    """Point the production discovery loaders at this verified local snapshot."""

    ghsa_directory = _ghsa_source(paths).directory
    previous_ghsa_dir = ghsa_local.GHSA_DIR
    previous_osv_dir = osv._OSV_CACHE_DIR
    previous_frozen = os.environ.get(osv.FROZEN_LOCAL_SOURCES_ENV)
    with osv._ecosystem_lock:
        previous_ecosystem_cache = osv._ecosystem_cache
        osv._ecosystem_cache = {}
    ghsa_local.GHSA_DIR = ghsa_directory
    osv._OSV_CACHE_DIR = paths.osv_dir
    os.environ[osv.FROZEN_LOCAL_SOURCES_ENV] = "1"
    try:
        yield
    finally:
        ghsa_local.GHSA_DIR = previous_ghsa_dir
        osv._OSV_CACHE_DIR = previous_osv_dir
        if previous_frozen is None:
            os.environ.pop(osv.FROZEN_LOCAL_SOURCES_ENV, None)
        else:
            os.environ[osv.FROZEN_LOCAL_SOURCES_ENV] = previous_frozen
        with osv._ecosystem_lock:
            osv._ecosystem_cache = previous_ecosystem_cache


def _validate_ghsa_discovery_inventory(
    ghsa_directory: Path,
    *,
    since: str,
    loaded_count: int,
) -> dict[str, Any]:
    """Reject GHSA loader omissions and bind the eligible local file inventory."""

    advisory_root = _real_directory(
        ghsa_directory / "advisories", "GHSA advisory directory"
    )
    eligible_count = 0
    total_file_count = 0
    inventory = hashlib.sha256()
    for subdir_name in ghsa_local.GHSA_SUBDIRS:
        subdir = advisory_root / subdir_name
        if not subdir.exists():
            continue
        _real_directory(subdir, f"GHSA {subdir_name} directory")
        files = sorted(
            _iter_ghsa_json_files(subdir, since),
            key=lambda item: item.as_posix(),
        )
        for path in files:
            data = _regular_file_bytes(path, "GHSA advisory")
            try:
                payload = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceDeltaError(f"invalid GHSA advisory {path}: {exc}") from exc
            if not isinstance(payload, dict):
                raise SourceDeltaError(f"GHSA advisory root must be an object: {path}")
            identifier = payload.get("id")
            _validate_subject_id(identifier, f"GHSA advisory {path}")
            aliases = payload.get("aliases", [])
            if not isinstance(aliases, list) or any(
                not isinstance(alias, str) for alias in aliases
            ):
                raise SourceDeltaError(f"GHSA aliases must be strings: {path}")
            published = payload.get("published", "")
            if not isinstance(published, str):
                raise SourceDeltaError(f"GHSA published must be a string: {path}")
            relative = path.relative_to(advisory_root).as_posix()
            inventory.update(relative.encode("utf-8"))
            inventory.update(b"\0")
            inventory.update(str(len(data)).encode("ascii"))
            inventory.update(b"\0")
            inventory.update(_sha256_bytes(data).encode("ascii"))
            inventory.update(b"\n")
            total_file_count += 1
            if not published or published >= since:
                eligible_count += 1
    if loaded_count != eligible_count:
        raise SourceDeltaError(
            "GHSA production loader omitted eligible local advisories: "
            f"validated={eligible_count}, loaded={loaded_count}"
        )
    return {
        "scanned_json_file_count": total_file_count,
        "since_eligible_file_count": eligible_count,
        "inventory_manifest_sha256": inventory.hexdigest(),
        "all_json_records_valid": True,
    }


def _extract_discovery_alias_groups(
    records: Sequence[dict[str, Any]],
    *,
    label: str,
) -> tuple[list[str], dict[str, frozenset[str]]]:
    """Use production canonicalization and retain each chosen ID's aliases."""

    discovered = extract_vuln_ids(
        list(records),
        include_ghsa=True,
        limit=sys.maxsize,
    )
    if len(discovered) != len(set(discovered)):
        raise SourceDeltaError(f"{label} discovery emitted duplicate chosen IDs")

    expected = iter(discovered)
    seen: set[str] = set()
    groups: dict[str, frozenset[str]] = {}
    for index, record in enumerate(records):
        identifier = record.get("id", "")
        aliases = record.get("aliases", [])
        if (
            not isinstance(identifier, str)
            or not isinstance(aliases, list)
            or any(not isinstance(alias, str) for alias in aliases)
        ):
            raise SourceDeltaError(f"malformed {label} discovery record {index}")
        raw_ids = [identifier, *aliases]
        if any(subject in seen for subject in raw_ids):
            continue

        chosen = next(
            (subject for subject in raw_ids if subject.startswith("CVE-")),
            None,
        )
        if chosen is None:
            chosen = next(
                (subject for subject in raw_ids if subject.startswith("GHSA-")),
                None,
            )
        if chosen is None:
            chosen = identifier
        if not chosen:
            continue

        try:
            production_chosen = next(expected)
        except StopIteration as exc:
            raise SourceDeltaError(
                f"{label} alias reconstruction exceeded production discovery"
            ) from exc
        if chosen != production_chosen:
            raise SourceDeltaError(
                f"{label} alias reconstruction drift: {chosen!r} != "
                f"{production_chosen!r}"
            )
        chosen = _validate_subject_id(chosen, f"{label} chosen discovery ID")
        valid_aliases = {
            candidate
            for subject in raw_ids
            if (candidate := _subject_candidate(subject, label)) is not None
        }
        valid_aliases.add(chosen)
        groups[chosen] = frozenset(valid_aliases)
        seen.update(raw_ids)
    try:
        trailing = next(expected)
    except StopIteration:
        trailing = None
    if trailing is not None or set(groups) != set(discovered):
        raise SourceDeltaError(f"{label} alias reconstruction was incomplete")
    return discovered, groups


def _alias_components(
    records: Sequence[dict[str, Any]],
    *,
    label: str,
) -> tuple[dict[str, frozenset[str]], dict[str, Any]]:
    """Build transitive alias components over every valid discovery record ID."""

    parent: dict[str, str] = {}

    def find(subject: str) -> str:
        root = subject
        while parent[root] != root:
            root = parent[root]
        while parent[subject] != subject:
            next_subject = parent[subject]
            parent[subject] = root
            subject = next_subject
        return root

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            parent[right_root] = left_root
        else:
            parent[left_root] = right_root

    for index, record in enumerate(records):
        identifier = record.get("id", "")
        aliases = record.get("aliases", [])
        if (
            not isinstance(identifier, str)
            or not isinstance(aliases, list)
            or any(not isinstance(alias, str) for alias in aliases)
        ):
            raise SourceDeltaError(f"malformed {label} alias record {index}")
        valid = _ordered_unique(
            candidate
            for subject in [identifier, *aliases]
            if (candidate := _subject_candidate(subject, label)) is not None
        )
        for subject in valid:
            parent.setdefault(subject, subject)
        for subject in valid[1:]:
            union(valid[0], subject)

    members: dict[str, set[str]] = {}
    for subject in sorted(parent):
        members.setdefault(find(subject), set()).add(subject)
    by_subject: dict[str, frozenset[str]] = {}
    manifest = hashlib.sha256()
    for component in sorted(
        (tuple(sorted(values)) for values in members.values()),
        key=lambda values: values,
    ):
        manifest.update("\0".join(component).encode("utf-8"))
        manifest.update(b"\n")
        frozen = frozenset(component)
        for subject in component:
            by_subject[subject] = frozen
    metadata = {
        "subject_id_count": len(parent),
        "component_count": len(members),
        "component_manifest_sha256": manifest.hexdigest(),
        "transitive": True,
    }
    return by_subject, metadata


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _record_analysis_evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the source evidence that must survive alias-class deduplication."""

    git_ranges: list[dict[str, Any]] = []
    fixed_events: list[dict[str, str]] = []
    affected = record.get("affected", [])
    if isinstance(affected, list):
        for affected_item in affected:
            if not isinstance(affected_item, dict):
                continue
            ranges = affected_item.get("ranges", [])
            if not isinstance(ranges, list):
                continue
            for range_item in ranges:
                if not isinstance(range_item, dict) or range_item.get("type") != "GIT":
                    continue
                normalized = json.loads(_canonical_json_bytes(range_item))
                if normalized not in git_ranges:
                    git_ranges.append(normalized)
                events = range_item.get("events", [])
                if isinstance(events, list):
                    for event in events:
                        if not isinstance(event, dict):
                            continue
                        for kind in ("fixed", "last_affected", "limit"):
                            value = event.get(kind)
                            if isinstance(value, str) and value:
                                item = {"kind": kind, "value": value}
                                if item not in fixed_events:
                                    fixed_events.append(item)

    reference_urls: list[str] = []
    references = record.get("references", [])
    if isinstance(references, list):
        for reference in references:
            if isinstance(reference, str) and reference:
                reference_urls.append(reference)
            elif isinstance(reference, dict):
                url = reference.get("url")
                if isinstance(url, str) and url:
                    reference_urls.append(url)
    return {
        "git_ranges": sorted(git_ranges, key=lambda item: _canonical_json_bytes(item)),
        "fixed_events": sorted(
            fixed_events, key=lambda item: (item["kind"], item["value"])
        ),
        "reference_urls": sorted(set(reference_urls)),
    }


def _build_alias_class_manifest(
    records: Sequence[tuple[str, Mapping[str, Any]]],
    *,
    production_ids: Sequence[str],
    source_snapshot_sha256: str,
) -> dict[str, Any]:
    """Persist one complete evidence-preserving record per current alias class."""

    plain_records = [dict(record) for _source, record in records]
    by_subject, _metadata = _alias_components(
        plain_records,
        label="alias-class source inventory",
    )
    production_set = set(production_ids)
    components = sorted(
        {
            tuple(sorted(by_subject[subject]))
            for subject in production_ids
            if subject in by_subject
        }
    )
    missing = sorted(production_set - set(by_subject))
    components.extend((subject,) for subject in missing)

    records_by_component: dict[
        tuple[str, ...], list[tuple[str, Mapping[str, Any]]]
    ] = {}
    for source, record in records:
        raw_aliases = record.get("aliases", [])
        aliases = raw_aliases if isinstance(raw_aliases, list) else []
        tokens = [record.get("id"), *aliases]
        component = next(
            (
                tuple(sorted(by_subject[token]))
                for token in tokens
                if isinstance(token, str) and token in by_subject
            ),
            None,
        )
        if component is not None:
            records_by_component.setdefault(component, []).append((source, record))

    class_records: list[dict[str, Any]] = []
    all_eligible: set[str] = set()
    for members in sorted(set(components)):
        member_set = set(members)
        eligible = sorted(member_set & production_set)
        if not eligible:
            continue
        component_sha256 = _sha256_bytes(("\n".join(members) + "\n").encode())
        source_entries: list[dict[str, Any]] = []
        merged_git_ranges: list[dict[str, Any]] = []
        merged_fixed_events: list[dict[str, str]] = []
        merged_references: set[str] = set()
        for source, record in records_by_component.get(members, []):
            record_bytes = _canonical_json_bytes(record)
            record_digest = _sha256_bytes(record_bytes)
            identifier = record.get("id")
            source_entries.append(
                {
                    "source": source,
                    "record_id": identifier if isinstance(identifier, str) else "",
                    "record_sha256": record_digest,
                    "reference": f"{source}:{identifier or record_digest[:16]}",
                }
            )
            evidence = _record_analysis_evidence(record)
            for git_range in evidence["git_ranges"]:
                if git_range not in merged_git_ranges:
                    merged_git_ranges.append(git_range)
            for event in evidence["fixed_events"]:
                if event not in merged_fixed_events:
                    merged_fixed_events.append(event)
            merged_references.update(evidence["reference_urls"])

        source_entries.sort(
            key=lambda item: (
                item["source"],
                item["record_id"],
                item["record_sha256"],
            )
        )
        analysis_input = {
            "member_ids": list(members),
            "git_ranges": sorted(
                merged_git_ranges, key=lambda item: _canonical_json_bytes(item)
            ),
            "fixed_events": sorted(
                merged_fixed_events, key=lambda item: (item["kind"], item["value"])
            ),
            "reference_urls": sorted(merged_references),
        }
        source_evidence_payload = {
            "records": source_entries,
            "analysis_input": analysis_input,
        }
        analysis_subject = next(
            (subject for subject in eligible if subject.startswith("CVE-")),
            next(
                (subject for subject in eligible if subject.startswith("GHSA-")),
                eligible[0],
            ),
        )
        class_records.append(
            {
                "class_id": f"alias-{component_sha256[:24]}",
                "component_sha256": component_sha256,
                "all_member_ids": list(members),
                "eligible_seed_ids": eligible,
                "source_record_references": source_entries,
                "merged_source_evidence_sha256": _sha256_bytes(
                    _canonical_json_bytes(source_evidence_payload)
                ),
                "analysis_subject": analysis_subject,
                "analysis_input": analysis_input,
                "source_snapshot_sha256": source_snapshot_sha256,
            }
        )
        all_eligible.update(eligible)

    class_records.sort(key=lambda item: item["class_id"])
    if all_eligible != production_set:
        raise SourceDeltaError("alias-class manifest does not exactly cover production IDs")
    member_counts = Counter(
        subject
        for class_record in class_records
        for subject in class_record["eligible_seed_ids"]
    )
    if any(count != 1 for count in member_counts.values()):
        raise SourceDeltaError("production IDs overlap alias classes")
    return {
        "schema_version": 1,
        "source_snapshot_sha256": source_snapshot_sha256,
        "class_count": len(class_records),
        "eligible_seed_id_count": len(all_eligible),
        "all_eligible_seed_ids_exactly_once": True,
        "classes_sha256": _sha256_bytes(_canonical_json_bytes(class_records)),
        "classes": class_records,
    }


def _schedule_alias_classes(
    manifest: Mapping[str, Any],
    raw_candidate_ids: Sequence[str],
) -> tuple[dict[str, Any], list[str]]:
    """Project a raw candidate union onto exactly one analysis subject per class."""

    raw_classes = manifest.get("classes")
    if not isinstance(raw_classes, list):
        raise SourceDeltaError("alias-class manifest classes are malformed")
    classes = [dict(item) for item in raw_classes if isinstance(item, dict)]
    if len(classes) != len(raw_classes):
        raise SourceDeltaError("alias-class manifest contains a malformed class")
    member_to_index: dict[str, int] = {}
    for index, class_record in enumerate(classes):
        members = class_record.get("all_member_ids")
        eligible = class_record.get("eligible_seed_ids")
        if (
            not isinstance(members, list)
            or any(not isinstance(item, str) for item in members)
            or not isinstance(eligible, list)
            or any(not isinstance(item, str) for item in eligible)
            or not set(eligible).issubset(members)
        ):
            raise SourceDeltaError("alias-class members are malformed")
        for member in members:
            previous = member_to_index.setdefault(member, index)
            if previous != index:
                raise SourceDeltaError(f"alias member occurs in multiple classes: {member}")

    for subject in raw_candidate_ids:
        if subject in member_to_index:
            continue
        component_sha256 = _sha256_bytes(f"{subject}\n".encode())
        analysis_input = {
            "member_ids": [subject],
            "git_ranges": [],
            "fixed_events": [],
            "reference_urls": [],
        }
        member_to_index[subject] = len(classes)
        classes.append(
            {
                "class_id": f"alias-{component_sha256[:24]}",
                "component_sha256": component_sha256,
                "all_member_ids": [subject],
                "eligible_seed_ids": [subject],
                "source_record_references": [],
                "merged_source_evidence_sha256": _sha256_bytes(
                    _canonical_json_bytes(
                        {"records": [], "analysis_input": analysis_input}
                    )
                ),
                "analysis_subject": subject,
                "analysis_input": analysis_input,
                "source_snapshot_sha256": manifest["source_snapshot_sha256"],
                "supplemental_candidate": True,
            }
        )

    scheduled_by_class: dict[int, list[str]] = {}
    scheduled_class_order: list[int] = []
    for raw_subject in raw_candidate_ids:
        class_index = member_to_index[raw_subject]
        scheduled = scheduled_by_class.setdefault(class_index, [])
        scheduled.append(raw_subject)
        if len(scheduled) == 1:
            scheduled_class_order.append(class_index)

    for index, class_record in enumerate(classes):
        scheduled_seeds = sorted(set(scheduled_by_class.get(index, [])))
        eligible_seeds = sorted(
            set(class_record["eligible_seed_ids"]) | set(scheduled_seeds)
        )
        if not eligible_seeds:
            raise SourceDeltaError("alias class has no eligible analysis subject")
        class_record["eligible_seed_ids"] = eligible_seeds
        class_record["analysis_subject"] = next(
            (subject for subject in eligible_seeds if subject.startswith("CVE-")),
            next(
                (subject for subject in eligible_seeds if subject.startswith("GHSA-")),
                eligible_seeds[0],
            ),
        )
        class_record["scheduled_seed_ids"] = scheduled_seeds
    scheduled_subjects = [
        classes[class_index]["analysis_subject"]
        for class_index in scheduled_class_order
    ]
    classes.sort(key=lambda item: item["class_id"])
    eligible_counts = Counter(
        subject
        for class_record in classes
        for subject in class_record["eligible_seed_ids"]
    )
    eligible_exactly_once = all(count == 1 for count in eligible_counts.values())
    scheduled_class_count = sum(bool(item["scheduled_seed_ids"]) for item in classes)
    scheduled_manifest = {
        **{key: value for key, value in manifest.items() if key != "classes"},
        "class_count": len(classes),
        "eligible_seed_id_count": len(eligible_counts),
        "all_eligible_seed_ids_exactly_once": eligible_exactly_once,
        "scheduled_class_count": scheduled_class_count,
        "scheduled_analysis_subject_count": len(scheduled_subjects),
        "scheduled_classes_exactly_once": len(scheduled_subjects)
        == scheduled_class_count
        == len(set(scheduled_subjects)),
        "classes": classes,
    }
    scheduled_manifest["classes_sha256"] = _sha256_bytes(
        _canonical_json_bytes(classes)
    )
    if scheduled_manifest["scheduled_classes_exactly_once"] is not True:
        raise SourceDeltaError("alias-class analysis subjects are not an exact partition")
    if scheduled_manifest["all_eligible_seed_ids_exactly_once"] is not True:
        raise SourceDeltaError("alias-class eligible subjects are not an exact partition")
    return scheduled_manifest, scheduled_subjects


def _build_production_discovery(
    paths: BuildPaths,
    *,
    valid_cache_ids: frozenset[str],
    source_snapshot_sha256: str,
) -> tuple[list[str], dict[str, Any]]:
    """Return every alias-aware uncached ID emitted by local batch discovery."""

    since = _validate_discovery_since(paths.discovery_since)
    with _frozen_discovery_sources(paths):
        try:
            all_osv_inventory = osv.load_all_ecosystems(since=None)
        except Exception as exc:
            raise SourceDeltaError(
                f"frozen local OSV production discovery failed: {exc}"
            ) from exc
        all_osv = [
            record
            for record in all_osv_inventory
            if not record.get("published", "") or record.get("published", "") >= since
        ]
        blameable = [
            record
            for record in all_osv
            if not record.get("id", "").startswith("MAL-")
            and not is_informational(record)
            and (has_git_range(record) or is_non_cve_unique(record))
        ]
        osv_ids, osv_groups = _extract_discovery_alias_groups(
            blameable, label="OSV blameable"
        )
        try:
            ghsa_records = load_ghsa_as_vulns(since=since)
        except Exception as exc:
            raise SourceDeltaError(
                f"frozen local GHSA production discovery failed: {exc}"
            ) from exc
        ghsa_inventory = _validate_ghsa_discovery_inventory(
            _ghsa_source(paths).directory,
            since=since,
            loaded_count=len(ghsa_records),
        )
        ghsa_ids, ghsa_groups = _extract_discovery_alias_groups(
            ghsa_records, label="GHSA supplement"
        )

    existing = set(osv_ids)
    ghsa_supplement = [subject for subject in ghsa_ids if subject not in existing]
    production_ids = [*osv_ids, *ghsa_supplement]
    if len(production_ids) != len(set(production_ids)):
        raise SourceDeltaError("combined production discovery contains duplicate IDs")

    groups = {**osv_groups, **{item: ghsa_groups[item] for item in ghsa_supplement}}
    alias_components, alias_metadata = _alias_components(
        [*all_osv_inventory, *ghsa_records],
        label="combined current OSV and GHSA alias inventory",
    )
    groups = {
        subject: alias_components.get(subject, direct_aliases)
        for subject, direct_aliases in groups.items()
    }
    covered = [
        subject for subject in production_ids if groups[subject] & valid_cache_ids
    ]
    covered_set = set(covered)
    uncached = [subject for subject in production_ids if subject not in covered_set]
    ghsa_supplement_set = set(ghsa_supplement)
    uncached_ghsa = [subject for subject in uncached if subject in ghsa_supplement_set]
    uncached_osv = [subject for subject in uncached if subject in existing]
    alias_class_manifest = _build_alias_class_manifest(
        [
            *(("osv", record) for record in all_osv_inventory),
            *(("ghsa", record) for record in ghsa_records),
        ],
        production_ids=production_ids,
        source_snapshot_sha256=source_snapshot_sha256,
    )

    def ids_sha256(values: Iterable[str]) -> str:
        ordered = sorted(values)
        data = ("\n".join(ordered) + "\n").encode() if ordered else b""
        return _sha256_bytes(data)

    metadata = {
        "scope": "local OSV blameable records plus local GHSA supplement",
        "since": since,
        "include_ghsa": True,
        "repo_filter": None,
        "limit": None,
        "frozen_local_sources": True,
        "network_advisory_api_included": False,
        "osv_alias_inventory_record_count": len(all_osv_inventory),
        "osv_loaded_record_count": len(all_osv),
        "osv_blameable_record_count": len(blameable),
        "osv_discovered_id_count": len(osv_ids),
        "ghsa_loaded_record_count": len(ghsa_records),
        "ghsa_discovered_id_count": len(ghsa_ids),
        "ghsa_supplement_id_count": len(ghsa_supplement),
        "production_discovered_id_count": len(production_ids),
        "production_discovered_ids_sha256": ids_sha256(production_ids),
        "production_discovered_ids": sorted(production_ids),
        "cache_covered_discovered_id_count": len(covered),
        "cache_covered_discovered_ids_sha256": ids_sha256(covered),
        "cache_covered_discovered_ids": sorted(covered),
        "uncached_discovered_id_count": len(uncached),
        "uncached_discovered_ids_sha256": ids_sha256(uncached),
        "uncached_discovered_ids": sorted(uncached),
        "uncached_osv_id_count": len(uncached_osv),
        "uncached_osv_ids_sha256": ids_sha256(uncached_osv),
        "uncached_osv_ids": sorted(uncached_osv),
        "uncached_ghsa_supplement_id_count": len(uncached_ghsa),
        "uncached_ghsa_supplement_ids_sha256": ids_sha256(uncached_ghsa),
        "uncached_ghsa_supplement_ids": sorted(uncached_ghsa),
        "alias_aware_cache_coverage": True,
        "alias_components": alias_metadata,
        "alias_class_manifest": alias_class_manifest,
        "ghsa_inventory": ghsa_inventory,
    }
    return sorted(uncached), metadata


def _capture_input_guard(
    paths: BuildPaths,
    *,
    fsck_cache: SuccessfulGitFsckCache | None = None,
) -> dict[str, Any]:
    manifest = _parse_sha256_manifest(paths)
    baseline = {
        "manifest_sha256": _sha256_file(
            paths.baseline_dir / "SHA256SUMS", "baseline SHA256 manifest"
        ),
        "files": manifest,
    }
    git = {
        source.name: _git_state(source, fsck_cache=fsck_cache)
        for source in paths.git_sources
    }
    nvd = {
        path.name: _capture_regular_file_snapshot(
            path,
            "current NVD feed",
            max_bytes=MAX_NVD_GZIP_BYTES,
        )
        for path in sorted(paths.nvd_dir.glob("*.json.gz"), key=lambda item: item.name)
    }
    osv_inventory = _osv_ecosystem_inventory(paths)
    osv_manifest_data = _regular_file_bytes(
        paths.osv_ecosystems_file, "OSV ecosystem manifest"
    )
    osv = {
        path.name: _capture_regular_file_snapshot(
            path,
            "current OSV archive",
            max_bytes=MAX_OSV_ARCHIVE_BYTES,
        )
        for path in _expected_osv_archive_paths(paths)
    }
    corpus: dict[str, Any] | None = None
    if paths.adjudicated_corpus_file is not None:
        data = _regular_file_bytes(paths.adjudicated_corpus_file, "adjudicated corpus")
        corpus = {
            "path": _relative_path(paths.adjudicated_corpus_file, paths.repo_root),
            "sha256": _sha256_bytes(data),
        }
    result_cache = _scan_result_cache(paths.result_cache_dir, paths.repo_root).metadata
    guard = {
        "baseline": baseline,
        "git": git,
        "nvd": nvd,
        "osv_ecosystem_manifest": {
            "path": _relative_path(paths.osv_ecosystems_file, paths.repo_root),
            "sha256": _sha256_bytes(osv_manifest_data),
            "size_bytes": len(osv_manifest_data),
            "ecosystem_count": len(osv_inventory.ecosystems),
            "ecosystems": list(osv_inventory.ecosystems),
        },
        "osv_archive_names": list(osv_inventory.archive_names),
        "osv": osv,
        "result_cache": result_cache,
        "adjudicated_corpus": corpus,
    }
    guard["sha256"] = _sha256_bytes(
        json.dumps(guard, sort_keys=True, separators=(",", ":")).encode()
    )
    return guard


def scan_result_cache(paths: BuildPaths) -> ResultCacheSnapshot:
    """Public runner hook: recompute the schema-3 cache inventory and coverage."""

    return _scan_result_cache(paths.result_cache_dir, paths.repo_root)


def capture_input_guard(
    paths: BuildPaths,
    *,
    fsck_cache: SuccessfulGitFsckCache | None = None,
) -> dict[str, Any]:
    """Public runner hook: recompute every schema-3 content-addressed input."""

    return _capture_input_guard(paths, fsck_cache=fsck_cache)


def _validate_paths(paths: BuildPaths) -> None:
    root = _real_directory(paths.repo_root, "repository root")
    baseline = _real_directory(paths.baseline_dir, "preserved baseline directory")
    try:
        baseline.relative_to(root)
    except ValueError as exc:
        raise SourceDeltaError(
            "preserved baseline directory must be inside the repository root"
        ) from exc
    _real_directory(paths.nvd_dir, "current NVD directory")
    _real_directory(paths.osv_dir, "current OSV directory")
    _osv_ecosystem_inventory(paths)
    result_cache = _real_directory(paths.result_cache_dir, "analysis result cache")
    _validate_discovery_since(paths.discovery_since)
    if paths.population_policy not in POPULATION_POLICIES:
        raise SourceDeltaError(
            f"population policy must be one of {sorted(POPULATION_POLICIES)}"
        )
    if (
        len(paths.git_sources) != 3
        or len({source.name for source in paths.git_sources}) != 3
    ):
        raise SourceDeltaError("exactly three uniquely named Git sources are required")
    # The exact archive inventory is re-derived from the content-addressed OSV
    # manifest whenever an input guard is captured.
    if (
        paths.delta_output == paths.candidate_output
        or paths.delta_output.parent != paths.candidate_output.parent
    ):
        raise SourceDeltaError(
            "delta and candidate outputs must be distinct files in one directory"
        )
    for label, output in (
        ("delta output", paths.delta_output),
        ("candidate output", paths.candidate_output),
    ):
        try:
            output.resolve().relative_to(root)
        except ValueError as exc:
            raise SourceDeltaError(
                f"{label} must be inside the repository root"
            ) from exc
        if output.resolve() == baseline or baseline in output.resolve().parents:
            raise SourceDeltaError(f"{label} cannot be inside the preserved baseline")
    if paths.adjudicated_corpus_file is not None:
        corpus = paths.adjudicated_corpus_file.resolve()
        try:
            corpus.relative_to(root)
        except ValueError as exc:
            raise SourceDeltaError(
                "adjudicated corpus must be inside the repository root"
            ) from exc
        if corpus in {paths.delta_output.resolve(), paths.candidate_output.resolve()}:
            raise SourceDeltaError("adjudicated corpus cannot alias an output")
    if result_cache in {
        paths.delta_output.resolve(),
        paths.candidate_output.resolve(),
    }:
        raise SourceDeltaError("analysis result cache cannot alias an output")


def build_artifacts(
    paths: BuildPaths,
    *,
    generated_at_utc: str | None = None,
    fsck_cache: SuccessfulGitFsckCache | None = None,
) -> BuiltArtifacts:
    """Read all inputs, prove one coherent snapshot, and build output bytes."""

    _validate_paths(paths)
    generated_at = _validate_generated_at(generated_at_utc)
    operation_fsck_cache = (
        fsck_cache if fsck_cache is not None else SuccessfulGitFsckCache()
    )
    try:
        analyzer_contract = analysis_contract.analysis_contract_epoch(paths.repo_root)
    except analysis_contract.AnalysisContractError as exc:
        raise SourceDeltaError(f"cannot capture analyzer contract epoch: {exc}") from exc
    initial_guard = _capture_input_guard(paths, fsck_cache=operation_fsck_cache)
    cache_snapshot = _scan_result_cache(paths.result_cache_dir, paths.repo_root)
    if cache_snapshot.metadata != initial_guard["result_cache"]:
        raise SourceDeltaError(
            "result-cache inventory changed before production discovery"
        )

    baseline_candidate = paths.baseline_dir / "new-osv-candidates.txt"
    baseline_ids, baseline_duplicates, baseline_candidate_data = _read_id_list(
        baseline_candidate,
        "preserved baseline candidate",
        legacy_duplicates=True,
    )
    corpus_ids: list[str] = []
    corpus_data: bytes | None = None
    if paths.adjudicated_corpus_file is not None:
        corpus_ids, _, corpus_data = _read_id_list(
            paths.adjudicated_corpus_file, "adjudicated corpus"
        )

    git_output: dict[str, Any] = {}
    for source in paths.git_sources:
        git_output[source.name] = _compare_git(
            source, initial_guard["git"][source.name]
        )
    nvd_output = _compare_nvd(
        paths,
        initial_guard["nvd"],
        initial_guard["baseline"]["files"],
    )
    osv_output = _compare_osv(
        paths,
        initial_guard["osv"],
        initial_guard["baseline"]["files"],
    )
    uncached_discovery_ids, discovery_metadata = _build_production_discovery(
        paths,
        valid_cache_ids=cache_snapshot.subject_ids,
        source_snapshot_sha256=advisory_source_snapshot_sha256(initial_guard),
    )

    all_delta_ids: set[str] = set()
    for source in git_output.values():
        all_delta_ids.update(source["subject_ids"])
    for source in nvd_output.values():
        all_delta_ids.update(source["subject_ids"])
    for source in osv_output.values():
        all_delta_ids.update(source["subject_ids"])
    sorted_delta_ids = sorted(
        _validate_subject_id(item, "computed source delta") for item in all_delta_ids
    )
    if len(sorted_delta_ids) != len(set(sorted_delta_ids)):
        raise SourceDeltaError("computed source delta contains duplicate IDs")

    discovery_candidate_ids = (
        discovery_metadata["production_discovered_ids"]
        if paths.population_policy == FORMAL_FULL_POLICY
        else uncached_discovery_ids
    )
    raw_candidate_ids = _ordered_unique(
        [
            *baseline_ids,
            *sorted_delta_ids,
            *corpus_ids,
            *discovery_candidate_ids,
        ]
    )
    alias_class_manifest, candidate_ids = _schedule_alias_classes(
        discovery_metadata["alias_class_manifest"],
        raw_candidate_ids,
    )
    discovery_metadata["alias_class_manifest"] = alias_class_manifest
    if len(candidate_ids) != len(set(candidate_ids)):
        raise SourceDeltaError("candidate union contains duplicate IDs")
    candidate_bytes = ("\n".join(candidate_ids) + "\n").encode()

    sparse_archives = sorted(
        name
        for name, source in osv_output.items()
        if source["comparison"] == "baseline_not_preserved"
    )
    baseline_unique = _ordered_unique(baseline_ids)
    candidate_metadata: dict[str, Any] = {
        "baseline_file": _relative_path(baseline_candidate, paths.repo_root),
        "baseline_sha256": _sha256_bytes(baseline_candidate_data),
        "baseline_line_count": len(baseline_ids),
        "baseline_unique_id_count": len(baseline_unique),
        "baseline_duplicate_line_count": len(baseline_ids) - len(baseline_unique),
        "baseline_duplicates": baseline_duplicates,
        "delta_id_count": len(sorted_delta_ids),
        "adjudicated_corpus_file": (
            _relative_path(paths.adjudicated_corpus_file, paths.repo_root)
            if paths.adjudicated_corpus_file is not None
            else None
        ),
        "adjudicated_corpus_sha256": _sha256_bytes(corpus_data)
        if corpus_data is not None
        else None,
        "adjudicated_corpus_id_count": len(corpus_ids),
        "adjudicated_corpus_forced_regardless_of_cache": True,
        "population_policy": paths.population_policy,
        "formal_release_eligible": paths.population_policy == FORMAL_FULL_POLICY,
        "historical_cache_suppresses_current_classes": paths.population_policy
        == INCREMENTAL_POLICY,
        "raw_union_id_count": len(raw_candidate_ids),
        "raw_union_sha256": _ids_sha256(raw_candidate_ids),
        "uncached_production_discovery_id_count": len(uncached_discovery_ids),
        "uncached_production_discovery_added_id_count": len(
            set(uncached_discovery_ids)
            - set(baseline_ids)
            - set(sorted_delta_ids)
            - set(corpus_ids)
        ),
        "output_file": _relative_path(paths.candidate_output, paths.repo_root),
        "output_id_count": len(candidate_ids),
        "output_sha256": _sha256_bytes(candidate_bytes),
        "output_duplicate_id_count": len(candidate_ids) - len(set(candidate_ids)),
        "output_analysis_class_count": len(candidate_ids),
        "alias_class_manifest_sha256": alias_class_manifest["classes_sha256"],
    }
    candidate_metadata["union_exact"] = (
        alias_class_manifest["scheduled_classes_exactly_once"] is True
        and set(candidate_ids)
        == {
            class_record["analysis_subject"]
            for class_record in alias_class_manifest["classes"]
            if class_record["scheduled_seed_ids"]
        }
    )
    delta: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated_at,
        "source_snapshot_time": generated_at,
        "purpose": (
            "formal full alias-class advisory population"
            if paths.population_policy == FORMAL_FULL_POLICY
            else "incremental advisory source delta from the preserved pre-refresh baseline"
        ),
        "population_policy": paths.population_policy,
        "analyzer_contract": analyzer_contract,
        "input_snapshot_sha256": initial_guard["sha256"],
        "input_snapshot": initial_guard,
        "baseline": {
            "directory": _relative_path(paths.baseline_dir, paths.repo_root),
            "sha256_manifest": initial_guard["baseline"],
        },
        "coverage": {
            "git_mirror_count": len(git_output),
            "nvd_feed_count": len(nvd_output),
            "current_osv_archive_count": len(osv_output),
            "member_diff_osv_archive_count": len(osv_output) - len(sparse_archives),
            "sparse_baseline_osv_archive_count": len(sparse_archives),
            "sparse_baseline_osv_archives": sparse_archives,
            "sparse_baseline_semantics": (
                "archives absent from the preserved baseline are validated and hashed, but contribute no inferred member delta"
            ),
        },
        "git": git_output,
        "nvd": nvd_output,
        "osv": osv_output,
        "production_discovery": discovery_metadata,
        "result_cache": cache_snapshot.metadata,
        "all_id_count": len(sorted_delta_ids),
        "all_ids": sorted_delta_ids,
        "candidate": candidate_metadata,
    }
    delta_bytes = (json.dumps(delta, indent=2, sort_keys=False) + "\n").encode()
    delta["integrity_payload_sha256"] = _sha256_bytes(delta_bytes)
    # Include an integrity digest without making it self-referential: it hashes
    # the complete artifact before this single field is appended.
    delta_bytes = (json.dumps(delta, indent=2, sort_keys=False) + "\n").encode()

    final_guard = _capture_input_guard(paths, fsck_cache=operation_fsck_cache)
    if final_guard != initial_guard:
        raise SourceDeltaError("source inputs changed while the delta was being built")
    try:
        final_analyzer_contract = analysis_contract.analysis_contract_epoch(paths.repo_root)
    except analysis_contract.AnalysisContractError as exc:
        raise SourceDeltaError(f"cannot recapture analyzer contract epoch: {exc}") from exc
    if final_analyzer_contract != analyzer_contract:
        raise SourceDeltaError("analyzer contract changed while the delta was being built")
    return BuiltArtifacts(delta, delta_bytes, candidate_bytes, initial_guard)


def _write_temp(parent: Path, prefix: str, data: bytes) -> Path:
    descriptor, raw_path = tempfile.mkstemp(prefix=prefix, dir=parent)
    path = Path(raw_path)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _locked_directory(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _validate_replaceable_file(path: Path, label: str) -> bool:
    if not os.path.lexists(path):
        return False
    if path.is_symlink() or not path.is_file():
        raise SourceDeltaError(
            f"{label} must be absent or a regular non-symlink file: {path}"
        )
    return True


def _restore_output(path: Path, backup: Path | None) -> None:
    if backup is None:
        path.unlink(missing_ok=True)
    else:
        os.replace(backup, path)


def publish_artifacts(
    paths: BuildPaths,
    artifacts: BuiltArtifacts,
    *,
    fsck_cache: SuccessfulGitFsckCache | None = None,
) -> None:
    """Atomically replace each output after a final source-drift proof."""

    operation_fsck_cache = (
        fsck_cache if fsck_cache is not None else SuccessfulGitFsckCache()
    )
    if (
        _capture_input_guard(paths, fsck_cache=operation_fsck_cache)
        != artifacts.input_guard
    ):
        raise SourceDeltaError("source inputs changed before publication")
    parent = paths.delta_output.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SourceDeltaError(
            f"cannot create output directory {parent}: {exc}"
        ) from exc
    if parent.is_symlink() or not parent.is_dir():
        raise SourceDeltaError(f"output parent must be a real directory: {parent}")

    candidate_temp = _write_temp(
        parent, ".source-candidates.staging-", artifacts.candidate_bytes
    )
    delta_temp = _write_temp(parent, ".source-delta.staging-", artifacts.delta_bytes)
    candidate_backup: Path | None = None
    delta_backup: Path | None = None
    try:
        with _locked_directory(parent):
            candidate_exists = _validate_replaceable_file(
                paths.candidate_output, "existing candidate output"
            )
            delta_exists = _validate_replaceable_file(
                paths.delta_output, "existing delta output"
            )
            if candidate_exists:
                candidate_backup = _write_temp(
                    parent,
                    ".source-candidates.backup-",
                    paths.candidate_output.read_bytes(),
                )
            if delta_exists:
                delta_backup = _write_temp(
                    parent, ".source-delta.backup-", paths.delta_output.read_bytes()
                )
            try:
                # Publishing the candidate superset first keeps every observable
                # intermediate state safe for the downstream batch builder.
                os.replace(candidate_temp, paths.candidate_output)
                os.replace(delta_temp, paths.delta_output)
                if (
                    _capture_input_guard(paths, fsck_cache=operation_fsck_cache)
                    != artifacts.input_guard
                ):
                    raise SourceDeltaError(
                        "source inputs changed during output publication"
                    )
                _fsync_directory(parent)
            except (OSError, SourceDeltaError) as exc:
                _restore_output(paths.candidate_output, candidate_backup)
                candidate_backup = None
                _restore_output(paths.delta_output, delta_backup)
                delta_backup = None
                _fsync_directory(parent)
                if isinstance(exc, SourceDeltaError):
                    raise
                raise SourceDeltaError(
                    f"cannot publish source-delta outputs: {exc}"
                ) from exc
    finally:
        candidate_temp.unlink(missing_ok=True)
        delta_temp.unlink(missing_ok=True)
        if candidate_backup is not None:
            candidate_backup.unlink(missing_ok=True)
        if delta_backup is not None:
            delta_backup.unlink(missing_ok=True)


def build_source_delta(
    paths: BuildPaths, *, generated_at_utc: str | None = None
) -> dict[str, Any]:
    """Build and publish a coherent source delta and candidate union."""

    fsck_cache = SuccessfulGitFsckCache()
    artifacts = build_artifacts(
        paths,
        generated_at_utc=generated_at_utc,
        fsck_cache=fsck_cache,
    )
    publish_artifacts(paths, artifacts, fsck_cache=fsck_cache)
    return artifacts.delta


def _resolve_from_root(value: str, root: Path) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    parser.add_argument(
        "--baseline-dir", default=str(_DEFAULT_STATE_ROOT / "source-before-final")
    )
    parser.add_argument(
        "--cvelist-dir", default=str(Path.home() / ".cache/cve-analyzer/cvelistV5")
    )
    parser.add_argument(
        "--ghsa-dir", default=str(Path.home() / ".cache/cve-analyzer/advisory-database")
    )
    parser.add_argument(
        "--gemnasium-dir", default=str(Path.home() / ".cache/cve-analyzer/gemnasium-db")
    )
    parser.add_argument(
        "--nvd-dir", default=str(Path.home() / ".cache/cve-analyzer/nvd-feeds")
    )
    parser.add_argument(
        "--osv-dir", default=str(Path.home() / ".cache/cve-analyzer/osv-bulk")
    )
    parser.add_argument(
        "--osv-ecosystems-file",
        help="OSV ecosystems.txt (defaults to <osv-dir>/ecosystems.txt)",
    )
    parser.add_argument(
        "--result-cache-dir",
        default=str(Path.home() / ".cache/cve-analyzer/results"),
    )
    parser.add_argument(
        "--delta-output", default=str(_DEFAULT_STATE_ROOT / "source-delta-current.json")
    )
    parser.add_argument(
        "--candidate-output", default=str(_DEFAULT_STATE_ROOT / "new-osv-candidates.txt")
    )
    parser.add_argument(
        "--adjudicated-corpus-file",
        default=_DEFAULT_ADJUDICATED_CORPUS,
    )
    parser.add_argument("--no-adjudicated-corpus", action="store_true")
    parser.add_argument(
        "--discovery-since",
        default=DEFAULT_DISCOVERY_SINCE,
        help="production discovery lower bound (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--population-policy",
        choices=sorted(POPULATION_POLICIES),
        default=FORMAL_FULL_POLICY,
        help="formal_full schedules every current alias class; incremental permits historical cache suppression",
    )
    parser.add_argument(
        "--generated-at-utc", help="explicit timezone-aware ISO-8601 timestamp"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = Path(args.repo_root).expanduser().resolve()
    baseline = _resolve_from_root(args.baseline_dir, root)
    corpus_path = _resolve_from_root(args.adjudicated_corpus_file, root)
    osv_dir = _resolve_from_root(args.osv_dir, root)
    osv_ecosystems_file = (
        _resolve_from_root(args.osv_ecosystems_file, root)
        if args.osv_ecosystems_file
        else osv_dir / OSV_ECOSYSTEMS_FILENAME
    )
    corpus: Path | None = None
    if not args.no_adjudicated_corpus:
        if corpus_path.is_file():
            corpus = corpus_path
        elif args.adjudicated_corpus_file != _DEFAULT_ADJUDICATED_CORPUS:
            print(
                f"error: adjudicated corpus is missing: {corpus_path}", file=sys.stderr
            )
            return 2
    paths = BuildPaths(
        repo_root=root,
        baseline_dir=baseline,
        git_sources=(
            GitSource(
                "cvelistV5",
                _resolve_from_root(args.cvelist_dir, root),
                baseline / "cvelistV5.head",
                _CVELIST_ORIGIN,
            ),
            GitSource(
                "github-advisory-database",
                _resolve_from_root(args.ghsa_dir, root),
                baseline / "github-advisory-database.head",
                _GHSA_ORIGIN,
            ),
            GitSource(
                "gemnasium-db",
                _resolve_from_root(args.gemnasium_dir, root),
                baseline / "gemnasium-db.head",
                _GEMNASIUM_ORIGIN,
            ),
        ),
        nvd_dir=_resolve_from_root(args.nvd_dir, root),
        osv_dir=osv_dir,
        osv_ecosystems_file=osv_ecosystems_file,
        result_cache_dir=_resolve_from_root(args.result_cache_dir, root),
        delta_output=_resolve_from_root(args.delta_output, root),
        candidate_output=_resolve_from_root(args.candidate_output, root),
        adjudicated_corpus_file=corpus,
        discovery_since=args.discovery_since,
        population_policy=args.population_policy,
    )
    try:
        delta = build_source_delta(paths, generated_at_utc=args.generated_at_utc)
    except SourceDeltaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "schema_version": delta["schema_version"],
                "source_snapshot_time": delta["source_snapshot_time"],
                "input_snapshot_sha256": delta["input_snapshot_sha256"],
                "population_policy": delta["population_policy"],
                "analyzer_contract_sha256": delta["analyzer_contract"]["sha256"],
                "alias_class_count": delta["production_discovery"][
                    "alias_class_manifest"
                ]["class_count"],
                "delta_id_count": delta["all_id_count"],
                "candidate_id_count": delta["candidate"]["output_id_count"],
                "production_discovered_id_count": delta["production_discovery"][
                    "production_discovered_id_count"
                ],
                "uncached_discovered_id_count": delta["production_discovery"][
                    "uncached_discovered_id_count"
                ],
                "uncached_ghsa_supplement_id_count": delta["production_discovery"][
                    "uncached_ghsa_supplement_id_count"
                ],
                "current_osv_archive_count": delta["coverage"][
                    "current_osv_archive_count"
                ],
                "member_diff_osv_archive_count": delta["coverage"][
                    "member_diff_osv_archive_count"
                ],
                "delta_output": str(paths.delta_output),
                "candidate_output": str(paths.candidate_output),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
