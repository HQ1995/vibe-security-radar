#!/usr/bin/env python3
"""Build deterministic, repository-affinity data-refresh batches.

Candidate IDs connected by an OSV alias or normalized GIT repository stay in
the same batch. The builder writes a fully verified staging directory and then
publishes it with an atomic directory exchange when the platform supports it;
the portable fallback keeps a rollback copy until publication succeeds.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import urlsplit

import data_refresh_paths

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_DEFAULT_STATE_ROOT = data_refresh_paths.DATA_REFRESH_STATE_RELATIVE
_DEFAULT_QUALITY_CORPUS = str(
    _DEFAULT_STATE_ROOT / "adjudicated-corpus-subjects.txt"
)

SCHEMA_VERSION = 3
MAX_IDS_PER_BATCH = 500
MAX_REPOS_PER_BATCH = 100
MAX_RECORDED_PARSE_FAILURES = 100
MAX_OSV_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_OSV_CENTRAL_DIRECTORY_BYTES = 512 * 1024 * 1024
MAX_OSV_ARCHIVE_MEMBERS = 5_000_000
MAX_OSV_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES = 16 * 1024 * 1024 * 1024
OSV_ARCHIVE_VALIDATION_TIMEOUT_SECONDS = 60 * 60
OSV_ARCHIVE_READ_CHUNK_BYTES = 1024 * 1024
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")


class BatchBuildError(RuntimeError):
    """A fail-closed batch-build validation or publication error."""


@dataclass(frozen=True)
class BuildPaths:
    """Inputs and output for one reproducible batch build."""

    repo_root: Path
    candidate_file: Path
    excluded_file: Path
    delta_file: Path
    quality_corpus_file: Path | None
    osv_archive_dir: Path
    output_dir: Path

    @classmethod
    def defaults(cls, repo_root: Path = _REPO_ROOT) -> BuildPaths:
        root = repo_root.resolve()
        refresh_state = data_refresh_paths.data_refresh_state_root(root)
        quality_corpus = refresh_state / "adjudicated-corpus-subjects.txt"
        return cls(
            repo_root=root,
            candidate_file=refresh_state / "new-osv-candidates.txt",
            excluded_file=refresh_state / "batches-v1" / "batch-001.txt",
            delta_file=refresh_state / "source-delta-current.json",
            quality_corpus_file=quality_corpus if quality_corpus.is_file() else None,
            osv_archive_dir=Path.home() / ".cache" / "cve-analyzer" / "osv-bulk",
            output_dir=refresh_state / "grouped-batches-v1",
        )


class UnionFind:
    """Deterministic disjoint sets for alias and repository connectivity."""

    def __init__(self, values: Sequence[str]) -> None:
        self._parent = {value: value for value in values}
        self._size = {value: 1 for value in values}

    def find(self, value: str) -> str:
        parent = self._parent[value]
        if parent != value:
            self._parent[value] = self.find(parent)
        return self._parent[value]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self._size[left_root] < self._size[right_root]:
            left_root, right_root = right_root, left_root
        self._parent[right_root] = left_root
        self._size[left_root] += self._size[right_root]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        if not path.is_file():
            raise BatchBuildError(f"{label} is missing or is not a file: {path}")
        return path.read_bytes()
    except BatchBuildError:
        raise
    except OSError as exc:
        raise BatchBuildError(f"cannot read {label} {path}: {exc}") from exc


def _read_nonempty_lines(data: bytes, path: Path, label: str) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BatchBuildError(f"{label} is not UTF-8: {path}") from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise BatchBuildError(f"{label} has no non-empty IDs: {path}")
    return lines


def _ordered_unique(items: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
        raise BatchBuildError(f"cannot inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise BatchBuildError(f"{label} must be a regular non-symlink file: {path}")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise BatchBuildError(f"cannot open {label} {path}: {exc}") from exc
    try:
        handle = os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise
    try:
        opened = os.fstat(handle.fileno())
        if _file_signature(opened) != _file_signature(before):
            raise BatchBuildError(f"{label} changed while being opened: {path}")
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
        raise BatchBuildError(
            f"cannot verify {label} after {action}: {path}: {exc}"
        ) from exc
    if _file_signature(final) != _file_signature(initial) or _file_signature(
        current
    ) != _file_signature(final):
        raise BatchBuildError(f"{label} changed while being {action}: {path}")


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


def _manifest_path(path: Path, repo_root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def normalize_repo(value: str) -> str | None:
    """Normalize URL and SCP-style repository identifiers for grouping."""

    raw = value.strip()
    if not raw:
        return None
    scp_match = re.fullmatch(r"(?:[^@/\s]+@)?([^:/\s]+):(.+)", raw)
    if scp_match and "://" not in raw:
        host, path = scp_match.groups()
        raw = f"https://{host}/{path}"
    if "://" in raw:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        path = parts.path.strip("/").rstrip("/")
        if path.lower().endswith(".git"):
            path = path[:-4]
        if host and path:
            return f"{host}/{path}".lower()
        lowered = raw.lower().rstrip("/")
        return lowered.removesuffix(".git")
    return (
        raw.lower().split("?", 1)[0].split("#", 1)[0].rstrip("/").removesuffix(".git")
    )


def _load_delta_metadata(
    data: bytes,
    path: Path,
    candidate_ids: set[str],
) -> tuple[int, str, dict[str, dict[str, Any]], dict[str, Any]]:
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BatchBuildError(f"invalid source delta JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise BatchBuildError(f"source delta must be a JSON object: {path}")
    raw_ids = payload.get("all_ids")
    if not isinstance(raw_ids, list) or any(
        not isinstance(item, str) or not item.strip() for item in raw_ids
    ):
        raise BatchBuildError(
            "source delta all_ids must be an array of non-empty strings"
        )
    delta_ids = [item.strip() for item in raw_ids]
    if len(delta_ids) != len(set(delta_ids)):
        raise BatchBuildError("source delta all_ids contains duplicate subject IDs")
    population_policy = payload.get("population_policy", "incremental")
    if population_policy not in {"formal_full", "incremental"}:
        raise BatchBuildError("source delta population policy is invalid")
    if population_policy == "incremental":
        missing = sorted(set(delta_ids) - candidate_ids)
        if missing:
            raise BatchBuildError(
                f"candidate file omits {len(missing)} source-delta IDs: {missing[:10]}"
            )
    input_snapshot = payload.get("input_snapshot")
    if not isinstance(input_snapshot, dict):
        raise BatchBuildError("source delta input_snapshot must be an object")
    archive_names = input_snapshot.get("osv_archive_names")
    osv_snapshot = input_snapshot.get("osv")
    if (
        not isinstance(archive_names, list)
        or not archive_names
        or any(
            not isinstance(name, str)
            or Path(name).name != name
            or not name.endswith(".zip")
            for name in archive_names
        )
        or len(archive_names) != len(set(archive_names))
        or len({name.casefold() for name in archive_names}) != len(archive_names)
        or archive_names
        != sorted(archive_names, key=lambda name: (name.casefold(), name))
        or not isinstance(osv_snapshot, dict)
        or set(osv_snapshot) != set(archive_names)
    ):
        raise BatchBuildError("source delta OSV input snapshot is malformed")
    expected_archives: dict[str, dict[str, Any]] = {}
    for name in archive_names:
        metadata = osv_snapshot[name]
        if not isinstance(metadata, dict):
            raise BatchBuildError(f"source delta OSV snapshot is malformed: {name}")
        size = metadata.get("size_bytes")
        sha256 = metadata.get("sha256")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or not isinstance(sha256, str)
            or _HEX_SHA256.fullmatch(sha256) is None
        ):
            raise BatchBuildError(f"source delta OSV snapshot is malformed: {name}")
        expected_archives[name] = {"size_bytes": size, "sha256": sha256}
    formal_contract: dict[str, Any] = {"population_policy": population_policy}
    if population_policy == "formal_full":
        production = payload.get("production_discovery")
        alias_manifest = (
            production.get("alias_class_manifest")
            if isinstance(production, dict)
            else None
        )
        analyzer_contract = payload.get("analyzer_contract")
        if not isinstance(alias_manifest, dict) or not isinstance(
            analyzer_contract, dict
        ):
            raise BatchBuildError(
                "formal source delta requires alias-class and analyzer contracts"
            )
        classes = alias_manifest.get("classes")
        if not isinstance(classes, list) or not classes:
            raise BatchBuildError("formal alias-class manifest has no classes")
        if alias_manifest.get("classes_sha256") != _sha256_bytes(
            json.dumps(classes, sort_keys=True, separators=(",", ":")).encode()
        ):
            raise BatchBuildError("formal alias-class manifest digest is invalid")
        scheduled_subjects: list[str] = []
        class_ids: list[str] = []
        covered_member_ids: set[str] = set()
        for class_record in classes:
            if not isinstance(class_record, dict):
                raise BatchBuildError("formal alias-class record is malformed")
            class_id = class_record.get("class_id")
            subject = class_record.get("analysis_subject")
            scheduled = class_record.get("scheduled_seed_ids")
            all_member_ids = class_record.get("all_member_ids")
            if (
                not isinstance(class_id, str)
                or not class_id
                or not isinstance(subject, str)
                or not subject
                or not isinstance(scheduled, list)
                or any(not isinstance(item, str) for item in scheduled)
                or not isinstance(all_member_ids, list)
                or not all_member_ids
                or any(
                    not isinstance(item, str) or not item.strip()
                    for item in all_member_ids
                )
                or subject not in all_member_ids
            ):
                raise BatchBuildError("formal alias-class record is malformed")
            class_ids.append(class_id)
            covered_member_ids.update(item.strip() for item in all_member_ids)
            if scheduled:
                scheduled_subjects.append(subject)
        if len(class_ids) != len(set(class_ids)):
            raise BatchBuildError("formal alias-class IDs are not unique")
        if len(scheduled_subjects) != len(set(scheduled_subjects)):
            raise BatchBuildError("formal analysis subjects are not unique")
        if set(scheduled_subjects) != candidate_ids:
            raise BatchBuildError(
                "formal candidate file is not the exact scheduled alias-class population"
            )
        uncovered_delta_ids = sorted(set(delta_ids) - covered_member_ids)
        if uncovered_delta_ids:
            raise BatchBuildError(
                "formal alias-class manifest omits "
                f"{len(uncovered_delta_ids)} source-delta IDs: "
                f"{uncovered_delta_ids[:10]}"
            )
        if (
            alias_manifest.get("scheduled_classes_exactly_once") is not True
            or alias_manifest.get("scheduled_analysis_subject_count")
            != len(scheduled_subjects)
            or not isinstance(analyzer_contract.get("sha256"), str)
            or not isinstance(analyzer_contract.get("signature_sha256"), str)
        ):
            raise BatchBuildError("formal source-delta proof is incomplete")
        formal_contract.update(
            {
                "alias_class_manifest": alias_manifest,
                "analyzer_contract": analyzer_contract,
            }
        )
    return len(delta_ids), _sha256_bytes(data), expected_archives, formal_contract


def _load_quality_corpus_metadata(
    path: Path | None,
    candidate_ids: set[str],
    repo_root: Path,
    *,
    alias_class_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if path is None:
        return {}
    data = _read_bytes(path, "quality corpus file")
    subject_ids = _read_nonempty_lines(data, path, "quality corpus file")
    if len(subject_ids) != len(set(subject_ids)):
        raise BatchBuildError("quality corpus contains duplicate subject IDs")
    subject_to_analysis_subject: dict[str, str] = {}
    if alias_class_manifest is not None:
        member_to_analysis_subject: dict[str, str] = {}
        for item in alias_class_manifest.get("classes", []):
            analysis_subject = item.get("analysis_subject")
            members = item.get("all_member_ids")
            if not isinstance(analysis_subject, str) or not isinstance(members, list):
                raise BatchBuildError(
                    "formal alias-class manifest has invalid quality-corpus mapping data"
                )
            for member in members:
                if not isinstance(member, str):
                    raise BatchBuildError(
                        "formal alias-class manifest has a non-string member ID"
                    )
                previous = member_to_analysis_subject.setdefault(
                    member, analysis_subject
                )
                if previous != analysis_subject:
                    raise BatchBuildError(
                        f"alias member {member!r} maps to multiple analysis subjects"
                    )
        subject_to_analysis_subject = {
            subject: member_to_analysis_subject.get(subject, subject)
            for subject in subject_ids
        }
    else:
        subject_to_analysis_subject = {subject: subject for subject in subject_ids}

    missing = sorted(
        subject
        for subject, analysis_subject in subject_to_analysis_subject.items()
        if analysis_subject not in candidate_ids
    )
    if missing:
        raise BatchBuildError(
            f"candidate file omits {len(missing)} quality-corpus IDs: {missing[:10]}"
        )
    metadata: dict[str, Any] = {
        "quality_corpus_file": _manifest_path(path, repo_root),
        "quality_corpus_subject_id_count": len(subject_ids),
        "quality_corpus_sha256": _sha256_bytes(data),
    }
    if alias_class_manifest is not None:
        mapping_json = json.dumps(
            subject_to_analysis_subject,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        metadata.update(
            {
                "quality_corpus_analysis_subject_id_count": len(
                    set(subject_to_analysis_subject.values())
                ),
                "quality_corpus_alias_mapped_subject_id_count": sum(
                    subject != analysis_subject
                    for subject, analysis_subject in subject_to_analysis_subject.items()
                ),
                "quality_corpus_subject_to_analysis_subject": (
                    subject_to_analysis_subject
                ),
                "quality_corpus_subject_mapping_sha256": hashlib.sha256(
                    mapping_json
                ).hexdigest(),
            }
        )
    return metadata


def _archive_content_mtime(infos: Sequence[zipfile.ZipInfo]) -> str | None:
    """Return a stable timestamp encoded inside the archive, never filesystem mtime."""

    if not infos:
        return None
    newest = max(info.date_time for info in infos)
    return datetime(*newest, tzinfo=UTC).isoformat()


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
    """Reject oversized ZIP metadata before ZipFile materializes ZipInfo entries."""

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
        raise BatchBuildError("ZIP physical limits must be positive integers")

    if archive_size <= 0 or archive_size > archive_limit:
        raise BatchBuildError(
            f"{label} archive size is outside 1..{archive_limit} bytes: {archive_size}"
        )

    try:
        handle.seek(0)
        end_record = zipfile._EndRecData(handle)  # noqa: SLF001
        handle.seek(0)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise BatchBuildError(f"invalid {label} {path}: {exc}") from exc
    if end_record is None:
        raise BatchBuildError(f"invalid {label} {path}: missing ZIP end record")

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
        raise BatchBuildError(f"invalid {label} {path}: malformed ZIP end record")
    if (
        values["disk"] != 0
        or values["start_disk"] != 0
        or values["entries_this_disk"] != values["entries"]
    ):
        raise BatchBuildError(f"invalid {label} {path}: multi-disk ZIP is unsupported")
    if values["entries"] == 0 or values["entries"] > member_limit:
        raise BatchBuildError(
            f"{label} member count is outside 1..{member_limit}: {values['entries']}"
        )
    if values["central_size"] > central_limit:
        raise BatchBuildError(
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
        raise BatchBuildError(
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
        raise BatchBuildError(
            f"{label} validation exceeded "
            f"{OSV_ARCHIVE_VALIDATION_TIMEOUT_SECONDS} seconds"
        )


class _StableZipArchive:
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
                raise BatchBuildError(
                    f"{self._label} changed while being scanned: {self._path}"
                )
        finally:
            self._source_handle.close()
            self._closed = True


def _safe_zip_members(
    path: Path,
    label: str,
    *,
    started_at: float,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> tuple[_StableZipArchive, list[zipfile.ZipInfo], int]:
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
        raise BatchBuildError(f"invalid expected snapshot for {label}")
    handle, initial = _open_stable_regular_file(path, label)
    try:
        if expected_size is not None and initial.st_size != expected_size:
            raise BatchBuildError(
                f"{label} does not match expected snapshot size: "
                f"{initial.st_size} != {expected_size}"
            )
        sha256, hashed_size = _hash_open_file(
            handle,
            deadline=lambda: _check_osv_archive_deadline(started_at, label),
        )
        if hashed_size != initial.st_size or (
            expected_sha256 is not None and sha256 != expected_sha256
        ):
            raise BatchBuildError(f"{label} does not match expected snapshot sha256")
        _verify_open_file_identity(
            path,
            handle,
            initial,
            label,
            action="hashed",
        )
        archive_size, _central_size, declared_members = (
            _inspect_open_zip_physical_bounds(
                handle,
                initial.st_size,
                path,
                label,
            )
        )
        _check_osv_archive_deadline(started_at, label)
        archive = _StableZipArchive(
            zipfile.ZipFile(handle),
            handle,
            path,
            label,
            initial,
            sha256,
        )
        infos = archive.infolist()
    except BatchBuildError:
        handle.close()
        raise
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        handle.close()
        raise BatchBuildError(f"invalid {label} {path}: {exc}") from exc
    except BaseException:
        handle.close()
        raise
    try:
        if len(infos) != declared_members or len(infos) > MAX_OSV_ARCHIVE_MEMBERS:
            raise BatchBuildError(
                f"{label} central-directory member count is inconsistent"
            )
        total_uncompressed = 0
        names: set[str] = set()
        for info in infos:
            _check_osv_archive_deadline(started_at, label)
            pure = PurePosixPath(info.filename)
            file_type = stat.S_IFMT(info.external_attr >> 16)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or "\\" in info.filename
                or info.flag_bits & 0x1
                or file_type == stat.S_IFLNK
            ):
                raise BatchBuildError(
                    f"unsafe ZIP member in {label}: {info.filename!r}"
                )
            if info.file_size > MAX_OSV_ARCHIVE_MEMBER_BYTES:
                raise BatchBuildError(
                    f"ZIP member exceeds {MAX_OSV_ARCHIVE_MEMBER_BYTES} bytes in "
                    f"{label}: {info.filename!r}"
                )
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES:
                raise BatchBuildError(
                    f"{label} uncompressed content exceeds "
                    f"{MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES} bytes"
                )
            if info.filename in names:
                raise BatchBuildError(
                    f"duplicate ZIP member in {label}: {info.filename!r}"
                )
            names.add(info.filename)
    except BaseException:
        archive.close()
        raise
    return archive, infos, archive_size


def _read_zip_member(
    archive: _StableZipArchive,
    info: zipfile.ZipInfo,
    label: str,
    *,
    started_at: float,
) -> bytearray:
    data = bytearray()
    try:
        with archive.open(info) as member:
            while True:
                _check_osv_archive_deadline(started_at, label)
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
                    raise BatchBuildError(
                        f"expanded ZIP member exceeds "
                        f"{MAX_OSV_ARCHIVE_MEMBER_BYTES} bytes in {label}: "
                        f"{info.filename!r}"
                    )
    except BatchBuildError:
        raise
    except (EOFError, KeyError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise BatchBuildError(
            f"cannot read {label} member {info.filename}: {exc}"
        ) from exc
    if len(data) != info.file_size:
        raise BatchBuildError(
            f"expanded ZIP member size mismatch in {label}: {info.filename!r}"
        )
    return data


def _record_tokens(record: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    primary = record.get("id")
    if isinstance(primary, str) and primary:
        tokens.add(primary)
    aliases = record.get("aliases") or []
    if isinstance(aliases, list):
        tokens.update(alias for alias in aliases if isinstance(alias, str) and alias)
    return tokens


def _record_repositories(record: dict[str, Any]) -> set[str]:
    repositories: set[str] = set()
    affected = record.get("affected") or []
    if not isinstance(affected, list):
        return repositories
    for affected_item in affected:
        if not isinstance(affected_item, dict):
            continue
        ranges = affected_item.get("ranges") or []
        if not isinstance(ranges, list):
            continue
        for range_item in ranges:
            if not isinstance(range_item, dict) or range_item.get("type") != "GIT":
                continue
            raw_repo = range_item.get("repo")
            if isinstance(raw_repo, str) and raw_repo.strip():
                repositories.add(raw_repo.strip())
    return repositories


def _scan_archives(
    archive_dir: Path,
    remaining: set[str],
    order_index: dict[str, int],
    union_find: UnionFind,
    expected_archives: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    try:
        archive_paths = sorted(
            (
                path
                for path in archive_dir.iterdir()
                if path.is_file() and path.suffix.lower() == ".zip"
            ),
            key=lambda path: (path.name.casefold(), path.name),
        )
    except OSError as exc:
        raise BatchBuildError(
            f"cannot list OSV archive directory {archive_dir}: {exc}"
        ) from exc
    if not archive_paths:
        raise BatchBuildError(
            f"OSV archive directory contains no ZIP files: {archive_dir}"
        )
    if len({path.name.casefold() for path in archive_paths}) != len(archive_paths):
        raise BatchBuildError(
            "OSV archive names collide under case-insensitive ordering"
        )
    actual_names = [path.name for path in archive_paths]
    if actual_names != list(expected_archives):
        raise BatchBuildError(
            "OSV archive inventory differs from source delta snapshot: "
            f"expected={list(expected_archives)}, actual={actual_names}"
        )

    candidate_repos: dict[str, set[str]] = defaultdict(set)
    repo_first_id: dict[str, str] = {}
    repo_variants: dict[str, set[str]] = defaultdict(set)
    matched_record_ids: set[str] = set()
    matched_records = 0
    records_scanned = 0
    parse_failures: list[dict[str, str]] = []
    archive_stats: list[dict[str, Any]] = []

    for archive_path in archive_paths:
        label = f"OSV archive {archive_path.name}"
        expected = expected_archives[archive_path.name]
        started = time.monotonic()
        archive, infos, archive_size = _safe_zip_members(
            archive_path,
            label,
            started_at=started,
            expected_size=expected["size_bytes"],
            expected_sha256=expected["sha256"],
        )
        archive_records = 0
        archive_matched = 0
        archive_failures = 0
        expanded_read_total = 0
        try:
            for member in infos:
                _check_osv_archive_deadline(started, label)
                if member.is_dir() or not member.filename.endswith(".json"):
                    continue
                records_scanned += 1
                archive_records += 1
                try:
                    data = _read_zip_member(
                        archive,
                        member,
                        label,
                        started_at=started,
                    )
                    expanded_read_total += len(data)
                    if expanded_read_total > MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES:
                        raise BatchBuildError(
                            f"{label} expanded content exceeds "
                            f"{MAX_OSV_ARCHIVE_UNCOMPRESSED_BYTES} bytes"
                        )
                    payload = json.loads(data)
                    del data
                    if not isinstance(payload, dict):
                        raise ValueError("OSV record root is not an object")
                except BatchBuildError:
                    raise
                except (
                    OSError,
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    ValueError,
                ) as exc:
                    archive_failures += 1
                    if len(parse_failures) < MAX_RECORDED_PARSE_FAILURES:
                        parse_failures.append(
                            {
                                "archive": archive_path.name,
                                "member": member.filename,
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )
                    _check_osv_archive_deadline(started, label)
                    continue

                hits = sorted(
                    _record_tokens(payload) & remaining, key=order_index.__getitem__
                )
                if not hits:
                    _check_osv_archive_deadline(started, label)
                    continue
                archive_matched += 1
                matched_records += 1
                matched_record_ids.update(hits)

                raw_repos = _record_repositories(payload)
                repos: set[str] = set()
                for raw_repo in sorted(raw_repos):
                    canonical = normalize_repo(raw_repo)
                    if canonical:
                        repos.add(canonical)
                        repo_variants[canonical].add(raw_repo)

                anchor = hits[0]
                for other in hits[1:]:
                    union_find.union(anchor, other)
                for hit in hits:
                    candidate_repos[hit].update(repos)
                for repo in sorted(repos):
                    previous = repo_first_id.get(repo)
                    if previous is None:
                        repo_first_id[repo] = anchor
                    else:
                        union_find.union(anchor, previous)
                _check_osv_archive_deadline(started, label)

            _check_osv_archive_deadline(started, label)
            archive_timestamp = _archive_content_mtime(infos)
        finally:
            archive.close()

        archive_stats.append(
            {
                "name": archive_path.name,
                "size_bytes": archive_size,
                "mtime_utc": archive_timestamp,
                "sha256": expected["sha256"],
                "json_records": archive_records,
                "matched_records": archive_matched,
                "parse_failures": archive_failures,
            }
        )

    if parse_failures:
        total = sum(int(item["parse_failures"]) for item in archive_stats)
        raise BatchBuildError(
            f"OSV archives contain {total} unreadable JSON records; first failures: {parse_failures[:3]}"
        )
    return {
        "candidate_repos": candidate_repos,
        "repo_first_id": repo_first_id,
        "repo_variants": repo_variants,
        "matched_record_ids": matched_record_ids,
        "matched_records": matched_records,
        "records_scanned": records_scanned,
        "parse_failures": parse_failures,
        "archive_stats": archive_stats,
    }


def _build_batch_specs(
    remaining_order: list[str],
    union_find: UnionFind,
    candidate_repos: dict[str, set[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    order_index = {item: index for index, item in enumerate(remaining_order)}
    component_ids: dict[str, list[str]] = defaultdict(list)
    for item in remaining_order:
        component_ids[union_find.find(item)].append(item)

    mapped_components: list[dict[str, Any]] = []
    unmapped_ids: list[str] = []
    for ids in component_ids.values():
        repos: set[str] = set()
        for item in ids:
            repos.update(candidate_repos.get(item, set()))
        ids.sort(key=order_index.__getitem__)
        if repos:
            mapped_components.append({"ids": ids, "repos": sorted(repos)})
        else:
            unmapped_ids.extend(ids)

    mapped_components.sort(
        key=lambda component: (
            -len(component["repos"]),
            -len(component["ids"]),
            component["ids"][0],
        )
    )
    large_components = [
        component
        for component in mapped_components
        if len(component["repos"]) > MAX_REPOS_PER_BATCH
        or len(component["ids"]) > MAX_IDS_PER_BATCH
    ]
    small_components = [
        component
        for component in mapped_components
        if len(component["repos"]) <= MAX_REPOS_PER_BATCH
        and len(component["ids"]) <= MAX_IDS_PER_BATCH
    ]

    batch_specs: list[dict[str, Any]] = [
        {
            "kind": "large_component",
            "components": [component],
            "ids": list(component["ids"]),
            "repos": list(component["repos"]),
        }
        for component in large_components
    ]
    packed: list[dict[str, Any]] = []
    for component in small_components:
        for batch in packed:
            if (
                len(batch["ids"]) + len(component["ids"]) <= MAX_IDS_PER_BATCH
                and len(batch["repos"]) + len(component["repos"]) <= MAX_REPOS_PER_BATCH
            ):
                batch["components"].append(component)
                batch["ids"].extend(component["ids"])
                batch["repos"].extend(component["repos"])
                break
        else:
            packed.append(
                {
                    "kind": "repo_affinity",
                    "components": [component],
                    "ids": list(component["ids"]),
                    "repos": list(component["repos"]),
                }
            )
    batch_specs.extend(packed)

    unmapped_ids.sort(key=order_index.__getitem__)
    for offset in range(0, len(unmapped_ids), MAX_IDS_PER_BATCH):
        batch_specs.append(
            {
                "kind": "unmapped",
                "components": [],
                "ids": unmapped_ids[offset : offset + MAX_IDS_PER_BATCH],
                "repos": [],
            }
        )

    for batch in batch_specs:
        batch["ids"].sort(key=order_index.__getitem__)
        batch["repos"] = sorted(set(batch["repos"]))
    return batch_specs, mapped_components, unmapped_ids


def _formal_class_mapping(
    alias_manifest: Mapping[str, Any],
    candidate_ids: Sequence[str],
) -> tuple[dict[str, set[str]], dict[str, str]]:
    """Load scheduling affinity only from the persisted alias-class manifest."""

    candidate_set = set(candidate_ids)
    candidate_repos: dict[str, set[str]] = defaultdict(set)
    class_ids: dict[str, str] = {}
    classes = alias_manifest.get("classes")
    assert isinstance(classes, list)
    for class_record in classes:
        assert isinstance(class_record, dict)
        subject = class_record.get("analysis_subject")
        scheduled = class_record.get("scheduled_seed_ids")
        if not isinstance(subject, str) or subject not in candidate_set or not scheduled:
            continue
        class_id = class_record.get("class_id")
        analysis_input = class_record.get("analysis_input")
        if not isinstance(class_id, str) or not isinstance(analysis_input, dict):
            raise BatchBuildError("formal alias-class scheduling record is malformed")
        if subject in class_ids:
            raise BatchBuildError(f"formal analysis subject is repeated: {subject}")
        class_ids[subject] = class_id
        git_ranges = analysis_input.get("git_ranges", [])
        if not isinstance(git_ranges, list):
            raise BatchBuildError("formal alias-class git_ranges are malformed")
        for range_item in git_ranges:
            if not isinstance(range_item, dict):
                raise BatchBuildError("formal alias-class GIT range is malformed")
            raw_repo = range_item.get("repo")
            if isinstance(raw_repo, str) and raw_repo.strip():
                normalized = normalize_repo(raw_repo)
                if normalized:
                    candidate_repos[subject].add(normalized)
    if set(class_ids) != candidate_set:
        raise BatchBuildError("formal class mapping does not cover every candidate")
    return candidate_repos, class_ids


def _verify_batches(
    batch_specs: list[dict[str, Any]],
    remaining: set[str],
    candidate_repos: dict[str, set[str]],
    *,
    allow_shared_repos: bool = False,
) -> dict[str, Any]:
    all_output_ids = [item for batch in batch_specs for item in batch["ids"]]
    output_counts = Counter(all_output_ids)
    duplicate_outputs = sorted(
        item for item, count in output_counts.items() if count != 1
    )
    missing_outputs = sorted(remaining - set(all_output_ids))
    unexpected_outputs = sorted(set(all_output_ids) - remaining)

    repo_batch_owners: dict[str, int] = {}
    cross_batch_repos: dict[str, list[int]] = defaultdict(list)
    for batch_number, batch in enumerate(batch_specs, 1):
        batch_repos = set(batch["repos"])
        if batch["kind"] != "large_component" and (
            len(batch["repos"]) > MAX_REPOS_PER_BATCH
            or len(batch["ids"]) > MAX_IDS_PER_BATCH
        ):
            raise BatchBuildError(
                f"normal batch {batch_number} exceeds packing targets"
            )
        if batch["kind"] == "large_component" and len(batch["components"]) != 1:
            raise BatchBuildError(
                f"large batch {batch_number} does not contain exactly one component"
            )
        for item in batch["ids"]:
            if not candidate_repos.get(item, set()).issubset(batch_repos):
                raise BatchBuildError(
                    f"batch {batch_number} omits a repository mapped to {item}"
                )
        for repo in batch["repos"]:
            previous = repo_batch_owners.get(repo)
            if previous is None:
                repo_batch_owners[repo] = batch_number
            elif previous != batch_number:
                cross_batch_repos[repo] = sorted({previous, batch_number})

    exact_once = (
        len(all_output_ids) == len(remaining)
        and not missing_outputs
        and not unexpected_outputs
        and not duplicate_outputs
    )
    if not exact_once:
        raise BatchBuildError(
            "output IDs failed exact partition proof: "
            f"missing={missing_outputs[:10]}, unexpected={unexpected_outputs[:10]}, "
            f"duplicates={duplicate_outputs[:10]}"
        )
    if cross_batch_repos and not allow_shared_repos:
        raise BatchBuildError(
            f"repositories cross batch boundaries: {dict(list(cross_batch_repos.items())[:10])}"
        )
    return {
        "expected_remaining_unique_ids": len(remaining),
        "output_id_lines": len(all_output_ids),
        "output_unique_ids": len(set(all_output_ids)),
        "missing_ids": missing_outputs,
        "unexpected_ids": unexpected_outputs,
        "duplicate_or_nonunit_output_ids": duplicate_outputs,
        "cross_batch_repos": dict(cross_batch_repos),
        "all_remaining_ids_exactly_once": exact_once,
        "each_repo_owned_by_one_batch": not cross_batch_repos,
        "shared_repositories_are_scheduling_affinity": allow_shared_repos,
        "normal_batches_within_targets": all(
            batch["kind"] == "large_component"
            or (
                len(batch["ids"]) <= MAX_IDS_PER_BATCH
                and len(batch["repos"]) <= MAX_REPOS_PER_BATCH
            )
            for batch in batch_specs
        ),
    }


def build_manifest(
    paths: BuildPaths, *, generated_at_utc: str | None = None
) -> dict[str, Any]:
    """Read, group, and verify all inputs without changing the output directory."""

    generated_at = generated_at_utc or _utc_now()
    try:
        parsed_generated_at = datetime.fromisoformat(generated_at)
    except ValueError as exc:
        raise BatchBuildError(
            f"generated timestamp is not ISO-8601: {generated_at!r}"
        ) from exc
    if parsed_generated_at.tzinfo is None:
        raise BatchBuildError("generated timestamp must include a timezone")

    candidate_data = _read_bytes(paths.candidate_file, "candidate file")
    candidate_lines = _read_nonempty_lines(
        candidate_data, paths.candidate_file, "candidate file"
    )
    candidate_ids = _ordered_unique(candidate_lines)
    candidate_set = set(candidate_ids)

    excluded_data = _read_bytes(paths.excluded_file, "excluded batch file")
    excluded_lines = _read_nonempty_lines(
        excluded_data, paths.excluded_file, "excluded batch file"
    )
    excluded_ids = set(excluded_lines)

    delta_data = _read_bytes(paths.delta_file, "source delta file")
    delta_count, delta_sha256, expected_archives, delta_contract = _load_delta_metadata(
        delta_data, paths.delta_file, candidate_set
    )
    formal_full = delta_contract["population_policy"] == "formal_full"
    remaining_order = (
        list(candidate_ids)
        if formal_full
        else [item for item in candidate_ids if item not in excluded_ids]
    )
    if not remaining_order:
        raise BatchBuildError(
            "no candidate IDs remain after applying the population policy"
        )
    remaining = set(remaining_order)
    order_index = {item: index for index, item in enumerate(remaining_order)}
    quality_metadata = _load_quality_corpus_metadata(
        paths.quality_corpus_file,
        candidate_set,
        paths.repo_root,
        alias_class_manifest=delta_contract.get("alias_class_manifest")
        if formal_full
        else None,
    )

    union_find = UnionFind(remaining_order)
    class_ids: dict[str, str] = {}
    if formal_full:
        candidate_repos, class_ids = _formal_class_mapping(
            delta_contract["alias_class_manifest"],
            remaining_order,
        )
        archive_stats = [
            {
                "name": name,
                "size_bytes": metadata["size_bytes"],
                "sha256": metadata["sha256"],
            }
            for name, metadata in expected_archives.items()
        ]
        scan = {
            "candidate_repos": candidate_repos,
            "repo_first_id": {
                repo: next(
                    subject
                    for subject in remaining_order
                    if repo in candidate_repos.get(subject, set())
                )
                for repo in sorted(
                    {repo for repos in candidate_repos.values() for repo in repos}
                )
            },
            "repo_variants": {},
            "matched_record_ids": set(remaining_order),
            "matched_records": len(remaining_order),
            "records_scanned": 0,
            "parse_failures": [],
            "archive_stats": archive_stats,
        }
    else:
        scan = _scan_archives(
            paths.osv_archive_dir,
            remaining,
            order_index,
            union_find,
            expected_archives,
        )
        candidate_repos = scan["candidate_repos"]
    batch_specs, components, unmapped_ids = _build_batch_specs(
        remaining_order,
        union_find,
        candidate_repos,
    )
    verification = _verify_batches(
        batch_specs,
        remaining,
        candidate_repos,
        allow_shared_repos=formal_full,
    )
    if formal_full:
        output_classes = [class_ids[item] for batch in batch_specs for item in batch["ids"]]
        verification.update(
            {
                "expected_alias_class_count": len(class_ids),
                "output_alias_class_count": len(output_classes),
                "alias_classes_exactly_once": len(output_classes)
                == len(set(output_classes))
                == len(class_ids),
            }
        )
        if verification["alias_classes_exactly_once"] is not True:
            raise BatchBuildError("formal alias classes failed exact-once partition proof")

    candidate_duplicate_counts = {
        item: count for item, count in Counter(candidate_lines).items() if count > 1
    }
    excluded_duplicate_counts = {
        item: count for item, count in Counter(excluded_lines).items() if count > 1
    }
    mapped_ids = [item for item in remaining_order if candidate_repos.get(item)]
    unmatched_record_ids = [
        item for item in remaining_order if item not in scan["matched_record_ids"]
    ]
    large_components = [
        component
        for component in components
        if len(component["repos"]) > MAX_REPOS_PER_BATCH
        or len(component["ids"]) > MAX_IDS_PER_BATCH
    ]

    manifest_batches: list[dict[str, Any]] = []
    for index, batch in enumerate(batch_specs, 1):
        manifest_batches.append(
            {
                "batch": index,
                "file": f"batch-{index:03d}.txt",
                "kind": batch["kind"],
                "id_count": len(batch["ids"]),
                "repo_count": len(batch["repos"]),
                "component_count": len(batch["components"]),
                "ids": batch["ids"],
                "class_ids": [class_ids[item] for item in batch["ids"]]
                if formal_full
                else [],
                "repos": batch["repos"],
                "within_target_limits": (
                    len(batch["ids"]) <= MAX_IDS_PER_BATCH
                    and len(batch["repos"]) <= MAX_REPOS_PER_BATCH
                ),
            }
        )

    inputs: dict[str, Any] = {
        "candidate_file": _manifest_path(paths.candidate_file, paths.repo_root),
        "candidate_line_count": len(candidate_lines),
        "candidate_unique_id_count": len(candidate_ids),
        "candidate_duplicate_line_count": len(candidate_lines) - len(candidate_ids),
        "candidate_duplicate_id_count": len(candidate_duplicate_counts),
        "candidate_duplicates": candidate_duplicate_counts,
        "excluded_file": _manifest_path(paths.excluded_file, paths.repo_root),
        "excluded_sha256": _sha256_bytes(excluded_data),
        "excluded_line_count": len(excluded_lines),
        "excluded_unique_id_count": len(excluded_ids),
        "excluded_duplicate_line_count": len(excluded_lines) - len(excluded_ids),
        "excluded_duplicates": excluded_duplicate_counts,
        "excluded_ids_present_in_candidates": len(excluded_ids & candidate_set),
        "remaining_unique_id_count": len(remaining),
        "population_policy": delta_contract["population_policy"],
        "formal_release_eligible": formal_full,
        "osv_archive_dir": _manifest_path(paths.osv_archive_dir, paths.repo_root),
        "archive_count": len(scan["archive_stats"]),
        "archives": scan["archive_stats"],
        "records_scanned": scan["records_scanned"],
        "parse_failure_count": 0,
        "parse_failures": scan["parse_failures"],
        "delta_file": _manifest_path(paths.delta_file, paths.repo_root),
        "delta_subject_id_count": delta_count,
        **quality_metadata,
        "candidate_sha256": _sha256_bytes(candidate_data),
        "delta_sha256": delta_sha256,
    }
    if formal_full:
        inputs.update(
            {
                "alias_class_manifest_sha256": delta_contract[
                    "alias_class_manifest"
                ]["classes_sha256"],
                "analyzer_contract_sha256": delta_contract["analyzer_contract"][
                    "sha256"
                ],
                "signature_sha256": delta_contract["analyzer_contract"][
                    "signature_sha256"
                ],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": generated_at,
        "purpose": (
            "formal full alias-class analysis batches"
            if formal_full
            else "repo-affinity multi-source incremental analysis batches"
        ),
        "inputs": inputs,
        "mapping": {
            "ids_matched_by_primary_or_alias": len(scan["matched_record_ids"]),
            "ids_not_matched_by_any_record": len(unmatched_record_ids),
            "ids_not_matched": unmatched_record_ids,
            "ids_with_git_repo": len(mapped_ids),
            "ids_without_git_repo": len(unmapped_ids),
            "unique_normalized_repos": len(scan["repo_first_id"]),
            "matched_osv_records": scan["matched_records"],
            "mapped_components": len(components),
            "large_components": len(large_components),
            "largest_component_id_count": max(
                (len(component["ids"]) for component in components),
                default=0,
            ),
            "largest_component_repo_count": max(
                (len(component["repos"]) for component in components),
                default=0,
            ),
            "repo_normalization_variant_count": sum(
                max(0, len(variants) - 1) for variants in scan["repo_variants"].values()
            ),
            "repo_variants": {
                repo: sorted(variants)
                for repo, variants in sorted(scan["repo_variants"].items())
                if len(variants) > 1
            },
        },
        "packing": {
            "batch_count": len(batch_specs),
            "repo_affinity_batch_count": sum(
                batch["kind"] == "repo_affinity" for batch in batch_specs
            ),
            "large_component_batch_count": sum(
                batch["kind"] == "large_component" for batch in batch_specs
            ),
            "unmapped_batch_count": sum(
                batch["kind"] == "unmapped" for batch in batch_specs
            ),
            "target_max_unique_repos_per_batch": MAX_REPOS_PER_BATCH,
            "preferred_max_ids_per_batch": MAX_IDS_PER_BATCH,
            "batches_over_repo_target": sum(
                len(batch["repos"]) > MAX_REPOS_PER_BATCH for batch in batch_specs
            ),
            "batches_over_id_preference": sum(
                len(batch["ids"]) > MAX_IDS_PER_BATCH for batch in batch_specs
            ),
        },
        "verification": verification,
        "batches": manifest_batches,
    }


def _write_durable(path: Path, content: str) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


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


def _try_atomic_exchange(left: Path, right: Path) -> bool:
    """Atomically exchange two directories with Linux renameat2 when available."""

    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if renameat2 is None:
        return False
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(left),
        -100,
        os.fsencode(right),
        2,
    )
    if result == 0:
        return True
    error = ctypes.get_errno()
    if error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.EXDEV}:
        return False
    raise OSError(error, os.strerror(error), f"{left} <-> {right}")


def _is_path_present(path: Path) -> bool:
    return os.path.lexists(path)


def _validate_replaceable_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise BatchBuildError(f"{label} must be a real directory: {path}")


def _publish_staged_directory(staged: Path, output_dir: Path) -> None:
    parent = output_dir.parent
    backup = parent / f".{output_dir.name}.previous"
    with _locked_directory(parent):
        if _is_path_present(backup):
            _validate_replaceable_directory(backup, "stale output backup")
            if _is_path_present(output_dir):
                _validate_replaceable_directory(output_dir, "existing output")
                shutil.rmtree(backup)
            else:
                os.replace(backup, output_dir)
                _fsync_directory(parent)

        if not _is_path_present(output_dir):
            os.replace(staged, output_dir)
            _fsync_directory(parent)
            return
        _validate_replaceable_directory(output_dir, "existing output")

        try:
            exchanged = _try_atomic_exchange(staged, output_dir)
        except OSError as exc:
            raise BatchBuildError(
                f"cannot atomically exchange output directory: {exc}"
            ) from exc
        if exchanged:
            _fsync_directory(parent)
            shutil.rmtree(staged)
            _fsync_directory(parent)
            return

        os.replace(output_dir, backup)
        try:
            os.replace(staged, output_dir)
            _fsync_directory(parent)
        except OSError as exc:
            if not _is_path_present(output_dir) and _is_path_present(backup):
                os.replace(backup, output_dir)
                _fsync_directory(parent)
            raise BatchBuildError(f"cannot publish output directory: {exc}") from exc
        shutil.rmtree(backup)
        _fsync_directory(parent)


def write_output(manifest: dict[str, Any], output_dir: Path) -> None:
    """Write a complete staging tree and safely replace the current output."""

    parent = output_dir.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BatchBuildError(f"cannot create output parent {parent}: {exc}") from exc
    if parent.is_symlink() or not parent.is_dir():
        raise BatchBuildError(f"output parent must be a real directory: {parent}")

    staged = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.staging-", dir=parent))
    try:
        for batch in manifest["batches"]:
            ids = batch["ids"]
            _write_durable(staged / batch["file"], "\n".join(ids) + "\n")
        _write_durable(
            staged / "manifest.json",
            json.dumps(manifest, indent=2, sort_keys=False) + "\n",
        )
        _fsync_directory(staged)
        _publish_staged_directory(staged, output_dir)
    except BatchBuildError:
        if staged.exists():
            shutil.rmtree(staged)
        raise
    except OSError as exc:
        if staged.exists():
            shutil.rmtree(staged)
        raise BatchBuildError(f"cannot write batch output {output_dir}: {exc}") from exc


def build_batches(
    paths: BuildPaths, *, generated_at_utc: str | None = None
) -> dict[str, Any]:
    """Build, verify, and publish one complete grouped-batch directory."""

    output_resolved = paths.output_dir.resolve()
    for label, input_path in (
        ("candidate file", paths.candidate_file),
        ("excluded file", paths.excluded_file),
        ("delta file", paths.delta_file),
        ("OSV archive directory", paths.osv_archive_dir),
    ):
        try:
            input_path.resolve().relative_to(output_resolved)
        except ValueError:
            continue
        raise BatchBuildError(
            f"{label} cannot be inside the generated output directory"
        )
    if paths.quality_corpus_file is not None:
        try:
            paths.quality_corpus_file.resolve().relative_to(output_resolved)
        except ValueError:
            pass
        else:
            raise BatchBuildError(
                "quality corpus file cannot be inside the generated output directory"
            )

    manifest = build_manifest(paths, generated_at_utc=generated_at_utc)
    write_output(manifest, paths.output_dir)
    return manifest


def _resolve_from_root(value: str, repo_root: Path) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (repo_root / path).resolve()


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    parser.add_argument(
        "--candidate-file",
        default=str(_DEFAULT_STATE_ROOT / "new-osv-candidates.txt"),
    )
    parser.add_argument(
        "--excluded-file",
        default=str(_DEFAULT_STATE_ROOT / "batches-v1" / "batch-001.txt"),
    )
    parser.add_argument(
        "--delta-file",
        default=str(_DEFAULT_STATE_ROOT / "source-delta-current.json"),
    )
    parser.add_argument(
        "--quality-corpus-file",
        default=_DEFAULT_QUALITY_CORPUS,
        help="optional fixed quality-corpus list; omitted from metadata when the default file is absent",
    )
    parser.add_argument(
        "--no-quality-corpus",
        action="store_true",
        help="omit optional quality-corpus metadata",
    )
    parser.add_argument(
        "--osv-archive-dir",
        default=str(Path.home() / ".cache" / "cve-analyzer" / "osv-bulk"),
    )
    parser.add_argument(
        "--output-dir",
        default=str(_DEFAULT_STATE_ROOT / "grouped-batches-v1"),
    )
    parser.add_argument(
        "--generated-at-utc",
        help="explicit timezone-aware ISO-8601 generation timestamp",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    repo_root = Path(args.repo_root).expanduser().resolve()
    candidate_file = _resolve_from_root(args.candidate_file, repo_root)
    excluded_file = _resolve_from_root(args.excluded_file, repo_root)
    delta_file = _resolve_from_root(args.delta_file, repo_root)
    quality_path = _resolve_from_root(args.quality_corpus_file, repo_root)
    quality_corpus_file = None
    if not args.no_quality_corpus:
        if quality_path.is_file():
            quality_corpus_file = quality_path
        elif args.quality_corpus_file != _DEFAULT_QUALITY_CORPUS:
            print(
                f"error: quality corpus file is missing: {quality_path}",
                file=sys.stderr,
            )
            return 2

    paths = BuildPaths(
        repo_root=repo_root,
        candidate_file=candidate_file,
        excluded_file=excluded_file,
        delta_file=delta_file,
        quality_corpus_file=quality_corpus_file,
        osv_archive_dir=_resolve_from_root(args.osv_archive_dir, repo_root),
        output_dir=_resolve_from_root(args.output_dir, repo_root),
    )
    try:
        manifest = build_batches(paths, generated_at_utc=args.generated_at_utc)
    except BatchBuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    mapping = manifest["mapping"]
    packing = manifest["packing"]
    verification = manifest["verification"]
    print(
        json.dumps(
            {
                "remaining_unique_ids": verification["expected_remaining_unique_ids"],
                "mapped_ids": mapping["ids_with_git_repo"],
                "unmapped_ids": mapping["ids_without_git_repo"],
                "matched_primary_or_alias": mapping["ids_matched_by_primary_or_alias"],
                "unique_repos": mapping["unique_normalized_repos"],
                "mapped_components": mapping["mapped_components"],
                "large_components": mapping["large_components"],
                "batches": packing["batch_count"],
                "repo_batches": packing["repo_affinity_batch_count"],
                "large_batches": packing["large_component_batch_count"],
                "unmapped_batches": packing["unmapped_batch_count"],
                "all_exactly_once": verification["all_remaining_ids_exactly_once"],
                "repo_single_owner": verification["each_repo_owned_by_one_batch"],
                "population_policy": manifest["inputs"]["population_policy"],
                "alias_classes_exactly_once": verification.get(
                    "alias_classes_exactly_once"
                ),
                "shared_repositories_are_scheduling_affinity": verification[
                    "shared_repositories_are_scheduling_affinity"
                ],
                "output_dir": str(paths.output_dir),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
