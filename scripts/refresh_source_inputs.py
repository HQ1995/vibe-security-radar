#!/usr/bin/env python3
"""Refresh every advisory input and emit the campaign's remote-cutoff receipt.

The write path captures each source at an independently verified immutable
version, stages and validates all HTTP inputs before changing a source, and
rolls local changes back when any later validation fails. The resulting
rolling-cutoff receipt is validated through :mod:`run_data_refresh` before and
after its atomic install; it never requires unrelated upstreams to stay frozen
for the duration of a full-clone fsck.

``--check`` performs sequential live remote discovery and local validation
without fetching Git objects, downloading bulk bodies, creating locks, or
writing files. It reports rolling-receipt validity separately from current
remote freshness.
"""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Protocol, Self
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

import build_source_delta
import data_refresh_paths
import run_data_refresh as campaign_contract
from cve_analyzer import nvd_feed
from cve_analyzer.git_ops import _run_argv_bounded

SCHEMA_VERSION = 3
CHECK_SCHEMA_VERSION = 1
NVD_YEARS = (2025, 2026)
NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
OSV_BASE_URL = "https://storage.googleapis.com/osv-vulnerabilities"
OSV_ECOSYSTEMS_URL = f"{OSV_BASE_URL}/{build_source_delta.OSV_ECOSYSTEMS_FILENAME}"

GIT_TIMEOUT_SECONDS = build_source_delta.GIT_COMMAND_TIMEOUT_SECONDS
GIT_CLONE_TIMEOUT_SECONDS = 4 * 60 * 60.0
HTTP_TIMEOUT_SECONDS = 600.0
MAX_GIT_STDOUT_BYTES = build_source_delta.MAX_GIT_STDOUT_BYTES
MAX_GIT_STDERR_BYTES = build_source_delta.MAX_GIT_STDERR_BYTES
MAX_GIT_CLONE_STDOUT_BYTES = 8 * 1024 * 1024
MIN_GIT_MIGRATION_FREE_BYTES = campaign_contract.MIN_FREE_BYTES + 16 * 1024**3
MAX_META_BYTES = 64 * 1024
MAX_NVD_GZIP_BYTES = 1024 * 1024 * 1024
MAX_OSV_ARCHIVE_BYTES = 1024 * 1024 * 1024
HTTP_CHUNK_BYTES = 1024 * 1024

_GIT_OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_GCS_ETAG = re.compile(r'"([0-9a-f]{32})"')
_NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, max-age=0",
    "Pragma": "no-cache",
    "User-Agent": "ai-slop-source-refresh/2",
}


class SourceRefreshError(RuntimeError):
    """A local invariant, remote proof, or transactional update failed."""


@dataclass(frozen=True)
class GitMirror:
    """One configured, independently validated advisory mirror."""

    name: str
    directory: Path
    expected_origin: str


@dataclass(frozen=True)
class RefreshPaths:
    """All mutable source paths and the durable remote-cutoff receipt."""

    repo_root: Path
    git_mirrors: tuple[GitMirror, ...]
    nvd_dir: Path
    osv_dir: Path
    osv_ecosystems_file: Path
    receipt_path: Path
    runner_state_dir: Path

    @classmethod
    def defaults(cls, repo_root: Path | None = None) -> Self:
        root = (
            Path(__file__).resolve().parent.parent
            if repo_root is None
            else repo_root.resolve()
        )
        delta_paths = build_source_delta.BuildPaths.defaults(root)
        state_root = data_refresh_paths.data_refresh_state_root(root)
        mirrors = tuple(
            GitMirror(source.name, source.directory, source.expected_origin)
            for source in delta_paths.git_sources
        )
        return cls(
            repo_root=root,
            git_mirrors=mirrors,
            nvd_dir=delta_paths.nvd_dir,
            osv_dir=delta_paths.osv_dir,
            osv_ecosystems_file=delta_paths.osv_ecosystems_file,
            receipt_path=state_root / "source-remote-check-now.json",
            runner_state_dir=state_root / "refresh-runner-v1",
        )


@dataclass(frozen=True)
class HttpResult:
    """Bounded HTTP response metadata plus an optional in-memory body."""

    status: int
    final_url: str
    headers: dict[str, str]
    size: int
    body: bytes | None


class HttpTransport(Protocol):
    """The small injectable network surface used by the refresher."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        max_bytes: int,
        allowed_hosts: frozenset[str],
        destination: Path | None = None,
        timeout_seconds: float = HTTP_TIMEOUT_SECONDS,
    ) -> HttpResult: ...


class UrllibTransport:
    """A dependency-free HTTPS transport with byte and wall-clock limits."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        max_bytes: int,
        allowed_hosts: frozenset[str],
        destination: Path | None = None,
        timeout_seconds: float = HTTP_TIMEOUT_SECONDS,
    ) -> HttpResult:
        if method not in {"GET", "HEAD"}:
            raise SourceRefreshError(f"unsupported HTTP method: {method!r}")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes <= 0
        ):
            raise SourceRefreshError("HTTP max_bytes must be a positive integer")
        _validate_https_url(url, allowed_hosts)
        request = Request(url, method=method, headers=dict(headers))
        started = time.monotonic()
        body = bytearray() if destination is None and method == "GET" else None
        output: BinaryIO | None = None
        try:
            if destination is not None:
                output = destination.open("wb")
            with urlopen(  # noqa: S310 - fixed HTTPS origins are validated twice
                request,
                timeout=min(timeout_seconds, 30.0),
            ) as response:
                status = int(response.status)
                if status != 200:
                    raise SourceRefreshError(f"HTTP {status} for {url}")
                final_url = response.geturl()
                _validate_https_url(final_url, allowed_hosts)
                response_headers = _normalized_response_headers(response.headers)
                declared_size = _optional_content_length(response_headers, url)
                if (
                    method == "GET"
                    and declared_size is not None
                    and declared_size > max_bytes
                ):
                    raise SourceRefreshError(
                        f"HTTP body exceeds {max_bytes} bytes for {url}: {declared_size}"
                    )

                size = 0
                if method == "GET":
                    while True:
                        if time.monotonic() - started > timeout_seconds:
                            raise SourceRefreshError(
                                f"HTTP request exceeded {timeout_seconds:g}s: {url}"
                            )
                        chunk = response.read(
                            min(HTTP_CHUNK_BYTES, max_bytes - size + 1)
                        )
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > max_bytes:
                            raise SourceRefreshError(
                                f"HTTP body exceeds {max_bytes} bytes for {url}"
                            )
                        if output is not None:
                            output.write(chunk)
                        else:
                            assert body is not None
                            body.extend(chunk)
                    if declared_size is not None and size != declared_size:
                        raise SourceRefreshError(
                            f"HTTP Content-Length mismatch for {url}: "
                            f"declared={declared_size}, read={size}"
                        )
                if output is not None:
                    output.flush()
                    os.fsync(output.fileno())
                return HttpResult(
                    status=status,
                    final_url=final_url,
                    headers=response_headers,
                    size=size,
                    body=bytes(body) if body is not None else None,
                )
        except SourceRefreshError:
            raise
        except HTTPError as exc:
            raise SourceRefreshError(f"HTTP {exc.code} for {url}") from exc
        except (OSError, TimeoutError, URLError) as exc:
            raise SourceRefreshError(f"HTTP request failed for {url}: {exc}") from exc
        finally:
            if output is not None:
                output.close()


@dataclass(frozen=True)
class GitState:
    branch: str
    head: str
    tree: str
    origin: str


@dataclass(frozen=True)
class RemoteGitState:
    branch: str
    head: str


@dataclass(frozen=True)
class NvdRemoteProof:
    year: int
    metadata_bytes: bytes
    metadata_etag: str
    metadata_last_modified: str
    entry: dict[str, object]
    staged_files: tuple[tuple[Path, Path], ...]


@dataclass(frozen=True)
class OsvRemoteProof:
    filename: str
    url: str
    generation: str
    etag: str
    md5_base64: str
    crc32c_base64: str
    last_modified: str
    remote_size: int
    entry: dict[str, object]
    staged_file: tuple[Path, Path] | None


@dataclass(frozen=True)
class OsvManifestRemoteProof:
    url: str
    generation: str
    etag: str
    md5_base64: str
    last_modified: str
    remote_size: int
    sha256: str
    inventory: build_source_delta.OsvEcosystemInventory
    entry: dict[str, object]
    staged_file: tuple[Path, Path] | None


@dataclass
class _InstalledFile:
    destination: Path
    backup: Path | None
    existed: bool


class _FileTransaction:
    """Install staged regular files atomically and retain rollback links."""

    def __init__(self) -> None:
        self._installed: list[_InstalledFile] = []
        self._staged: set[Path] = set()

    def track(self, staged: Path) -> None:
        self._staged.add(staged)

    def install(self, staged: Path, destination: Path) -> None:
        self.track(staged)
        _require_regular_file(staged, "staged source")
        _require_real_directory(destination.parent, "source destination")
        if any(item.destination == destination for item in self._installed):
            raise SourceRefreshError(
                f"duplicate transactional destination: {destination}"
            )

        try:
            current = destination.lstat()
        except FileNotFoundError:
            existed = False
            backup = None
        except OSError as exc:
            raise SourceRefreshError(
                f"cannot inspect destination {destination}: {exc}"
            ) from exc
        else:
            if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
                raise SourceRefreshError(
                    f"refusing to replace unsafe source file: {destination}"
                )
            existed = True
            if _same_file_content(staged, destination):
                staged.unlink()
                self._staged.discard(staged)
                return
            backup = _reserve_backup_path(destination)
            try:
                os.link(destination, backup)
            except OSError as exc:
                backup.unlink(missing_ok=True)
                raise SourceRefreshError(
                    f"cannot stage rollback link for {destination}: {exc}"
                ) from exc

        installed = _InstalledFile(destination, backup, existed)
        self._installed.append(installed)
        try:
            os.replace(staged, destination)
            self._staged.discard(staged)
            _fsync_directory(destination.parent)
        except OSError as exc:
            raise SourceRefreshError(
                f"cannot install source file {destination}: {exc}"
            ) from exc

    def remove(self, destination: Path) -> None:
        """Remove one obsolete regular file with a rollback hard link."""

        _require_real_directory(destination.parent, "source destination")
        _require_regular_file(destination, "obsolete source")
        if any(item.destination == destination for item in self._installed):
            raise SourceRefreshError(
                f"duplicate transactional destination: {destination}"
            )
        backup = _reserve_backup_path(destination)
        try:
            os.link(destination, backup)
        except OSError as exc:
            backup.unlink(missing_ok=True)
            raise SourceRefreshError(
                f"cannot stage obsolete source removal {destination}: {exc}"
            ) from exc
        # Record the rollback link before the destructive unlink.  An async
        # TERM/HUP after unlink therefore always finds a complete ledger entry.
        self._installed.append(_InstalledFile(destination, backup, True))
        try:
            destination.unlink()
            _fsync_directory(destination.parent)
        except OSError as exc:
            raise SourceRefreshError(
                f"cannot transactionally remove obsolete source {destination}: {exc}"
            ) from exc

    def rollback(self) -> None:
        errors: list[str] = []
        for installed in reversed(self._installed):
            try:
                if installed.existed:
                    if installed.backup is None:
                        raise OSError("rollback link is missing")
                    os.replace(installed.backup, installed.destination)
                    installed.backup = None
                else:
                    installed.destination.unlink(missing_ok=True)
                _fsync_directory(installed.destination.parent)
            except OSError as exc:
                errors.append(f"{installed.destination}: {exc}")
        self._cleanup_staged()
        if errors:
            raise SourceRefreshError(
                "source-file rollback failed: " + "; ".join(errors)
            )

    def commit(self) -> None:
        cleanup_errors: list[str] = []
        for installed in self._installed:
            if installed.backup is None:
                continue
            try:
                installed.backup.unlink(missing_ok=True)
            except OSError as exc:
                cleanup_errors.append(f"{installed.backup}: {exc}")
        self._cleanup_staged()
        if cleanup_errors:
            print(
                "warning: committed sources but could not remove rollback links: "
                + "; ".join(cleanup_errors),
                file=sys.stderr,
            )

    def _cleanup_staged(self) -> None:
        for staged in self._staged:
            try:
                staged.unlink(missing_ok=True)
            except OSError:
                pass
        self._staged.clear()


class _GitTransaction:
    """Apply verified fast-forwards and restore original commits on failure."""

    def __init__(
        self,
        fsck_cache: build_source_delta.SuccessfulGitFsckCache,
    ) -> None:
        self._updates: list[tuple[GitMirror, GitState, RemoteGitState]] = []
        self._fsck_cache = fsck_cache

    def fast_forward(
        self,
        mirror: GitMirror,
        original: GitState,
        remote: RemoteGitState,
    ) -> GitState:
        current = _git_state(mirror, fsck_cache=self._fsck_cache)
        if current != original:
            raise SourceRefreshError(f"Git mirror changed before update: {mirror.name}")
        if original.branch != remote.branch:
            raise SourceRefreshError(
                f"{mirror.name} is on {original.branch!r}; remote default is "
                f"{remote.branch!r}"
            )
        self._updates.append((mirror, original, remote))
        if original.head != remote.head:
            _run_git(mirror, ["merge", "--ff-only", remote.head])
        updated = _git_state(mirror, fsck_cache=self._fsck_cache)
        if updated.head != remote.head or updated.branch != remote.branch:
            raise SourceRefreshError(
                f"Git mirror did not reach exact remote head: {mirror.name}"
            )
        return updated

    def rollback(self) -> None:
        errors: list[str] = []
        for mirror, original, remote in reversed(self._updates):
            try:
                current = _git_state(mirror, fsck_cache=self._fsck_cache)
                if current.head not in {original.head, remote.head}:
                    raise SourceRefreshError(
                        f"refusing to overwrite concurrent Git change {current.head}"
                    )
                if current.head != original.head:
                    _run_git(mirror, ["reset", "--hard", original.head])
                restored = _git_state(mirror, fsck_cache=self._fsck_cache)
                if restored != original:
                    raise SourceRefreshError("restored state does not match original")
            except (OSError, SourceRefreshError) as exc:
                errors.append(f"{mirror.name}: {exc}")
        if errors:
            raise SourceRefreshError("Git rollback failed: " + "; ".join(errors))


@dataclass(frozen=True)
class _StagedGitMigration:
    mirror: GitMirror
    original: GitState
    remote: RemoteGitState
    staged_path: Path
    staged_state: GitState


def _git_migration_paths(mirror: GitMirror) -> tuple[Path, Path, Path]:
    parent = mirror.directory.parent
    base = mirror.directory.name
    return (
        parent / f".{base}.source-refresh-stage",
        parent / f".{base}.source-refresh-backup",
        parent / f".{base}.source-refresh-garbage",
    )


def _remove_migration_tree(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SourceRefreshError(f"cannot inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SourceRefreshError(f"refusing to remove unsafe {label}: {path}")
    try:
        shutil.rmtree(path)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise SourceRefreshError(f"cannot remove {label} {path}: {exc}") from exc


def _recover_git_migration(mirror: GitMirror) -> None:
    """Roll back a prior interrupted directory exchange before new writes."""

    stage, backup, garbage = _git_migration_paths(mirror)
    _require_real_directory(mirror.directory.parent, f"{mirror.name} Git parent")
    backup_exists = backup.exists() or backup.is_symlink()
    destination_exists = mirror.directory.exists() or mirror.directory.is_symlink()
    if backup_exists:
        _remove_migration_tree(stage, f"stale {mirror.name} migration stage")
        if destination_exists:
            try:
                destination_metadata = mirror.directory.lstat()
            except OSError as exc:
                raise SourceRefreshError(
                    f"cannot inspect interrupted {mirror.name} destination: {exc}"
                ) from exc
            if stat.S_ISLNK(destination_metadata.st_mode) or not stat.S_ISDIR(
                destination_metadata.st_mode
            ):
                raise SourceRefreshError(
                    f"unsafe interrupted Git destination: {mirror.directory}"
                )
            os.replace(mirror.directory, stage)
            _fsync_directory(mirror.directory.parent)
        try:
            backup_metadata = backup.lstat()
            if stat.S_ISLNK(backup_metadata.st_mode) or not stat.S_ISDIR(
                backup_metadata.st_mode
            ):
                raise SourceRefreshError(
                    f"unsafe interrupted Git backup for {mirror.name}: {backup}"
                )
            os.replace(backup, mirror.directory)
            _fsync_directory(mirror.directory.parent)
        except OSError as exc:
            raise SourceRefreshError(
                f"cannot recover interrupted Git migration for {mirror.name}: {exc}"
            ) from exc
        _remove_migration_tree(stage, f"rolled-back {mirror.name} migration")
    elif not destination_exists:
        raise SourceRefreshError(f"Git mirror is missing: {mirror.directory}")
    else:
        _remove_migration_tree(stage, f"stale {mirror.name} migration stage")
    _remove_migration_tree(garbage, f"committed {mirror.name} migration garbage")


class _GitMigrationTransaction:
    """Atomically install full clones while retaining interruption rollback."""

    def __init__(
        self,
        fsck_cache: build_source_delta.SuccessfulGitFsckCache,
    ) -> None:
        self._installed: list[_StagedGitMigration] = []
        self._tracked: list[_StagedGitMigration] = []
        self._fsck_cache = fsck_cache

    def track(self, migration: _StagedGitMigration) -> None:
        self._tracked.append(migration)

    def install(self, migration: _StagedGitMigration) -> GitState:
        mirror = migration.mirror
        stage, backup, garbage = _git_migration_paths(mirror)
        if stage != migration.staged_path:
            raise SourceRefreshError(f"unexpected migration stage for {mirror.name}")
        for reserved in (backup, garbage):
            if reserved.exists() or reserved.is_symlink():
                raise SourceRefreshError(
                    f"stale Git migration control path for {mirror.name}: {reserved}"
                )
        current = _git_state(mirror, allow_incomplete_storage=True)
        if current != migration.original:
            raise SourceRefreshError(
                f"Git mirror changed before full-clone migration: {mirror.name}"
            )
        staged_mirror = GitMirror(mirror.name, stage, mirror.expected_origin)
        stage_resolved = str(stage.resolve(strict=True))
        stage_metadata = stage.lstat()
        if (
            _git_state(
                staged_mirror,
                fsck_cache=self._fsck_cache,
            )
            != migration.staged_state
        ):
            raise SourceRefreshError(
                f"staged full clone changed before installation: {mirror.name}"
            )

        self._installed.append(migration)
        try:
            os.replace(mirror.directory, backup)
            _fsync_directory(mirror.directory.parent)
            os.replace(stage, mirror.directory)
            _fsync_directory(mirror.directory.parent)
        except OSError as exc:
            raise SourceRefreshError(
                f"cannot install full Git clone for {mirror.name}: {exc}"
            ) from exc
        installed_metadata = mirror.directory.lstat()
        if (
            installed_metadata.st_dev == stage_metadata.st_dev
            and installed_metadata.st_ino == stage_metadata.st_ino
            and installed_metadata.st_mode == stage_metadata.st_mode
        ):
            self._fsck_cache.rebind_resolved_path(
                stage_resolved,
                str(mirror.directory.resolve(strict=True)),
            )
        installed = _git_state(mirror, fsck_cache=self._fsck_cache)
        if installed != migration.staged_state:
            raise SourceRefreshError(
                f"installed full clone differs from staged proof: {mirror.name}"
            )
        return installed

    def rollback(self) -> None:
        errors: list[str] = []
        for migration in reversed(self._installed):
            mirror = migration.mirror
            stage, backup, _garbage = _git_migration_paths(mirror)
            try:
                if backup.exists() or backup.is_symlink():
                    _remove_migration_tree(
                        stage,
                        f"rollback {mirror.name} migration stage",
                    )
                    if mirror.directory.exists() or mirror.directory.is_symlink():
                        os.replace(mirror.directory, stage)
                        _fsync_directory(mirror.directory.parent)
                    os.replace(backup, mirror.directory)
                    _fsync_directory(mirror.directory.parent)
                    _remove_migration_tree(
                        stage,
                        f"rolled-back {mirror.name} full clone",
                    )
                restored = _git_state(mirror, allow_incomplete_storage=True)
                if restored != migration.original:
                    raise SourceRefreshError("restored incomplete mirror changed")
            except (OSError, SourceRefreshError) as exc:
                errors.append(f"{mirror.name}: {exc}")
        if errors:
            raise SourceRefreshError(
                "Git migration rollback failed: " + "; ".join(errors)
            )
        for migration in self._tracked:
            try:
                _remove_migration_tree(
                    migration.staged_path,
                    f"unused {migration.mirror.name} migration stage",
                )
            except SourceRefreshError as exc:
                errors.append(f"{migration.mirror.name}: {exc}")
        if errors:
            raise SourceRefreshError(
                "Git migration rollback failed: " + "; ".join(errors)
            )

    def commit(self) -> None:
        cleanup_errors: list[str] = []
        for migration in self._installed:
            mirror = migration.mirror
            _stage, backup, garbage = _git_migration_paths(mirror)
            try:
                if backup.exists() or backup.is_symlink():
                    os.replace(backup, garbage)
                    _fsync_directory(mirror.directory.parent)
                _remove_migration_tree(
                    garbage,
                    f"committed {mirror.name} incomplete mirror",
                )
            except (OSError, SourceRefreshError) as exc:
                cleanup_errors.append(f"{mirror.name}: {exc}")
        for migration in self._tracked:
            try:
                _remove_migration_tree(
                    migration.staged_path,
                    f"unused {migration.mirror.name} migration stage",
                )
            except SourceRefreshError as exc:
                cleanup_errors.append(f"{migration.mirror.name}: {exc}")
        if cleanup_errors:
            print(
                "warning: committed Git migrations but could not remove old mirrors: "
                + "; ".join(cleanup_errors),
                file=sys.stderr,
            )


class SourceRefresher:
    """Reproducibly check or refresh the complete source-input contract."""

    def __init__(
        self,
        paths: RefreshPaths,
        *,
        http: HttpTransport | None = None,
    ) -> None:
        self.paths = paths
        self.http = http or UrllibTransport()
        if len(paths.git_mirrors) != 3:
            raise SourceRefreshError("exactly three Git mirrors are required")
        if paths.osv_ecosystems_file.parent.resolve() != paths.osv_dir.resolve():
            raise SourceRefreshError(
                "OSV ecosystem manifest must live in the OSV source directory"
            )

    def check(self) -> dict[str, object]:
        """Report sequential live drift and local rolling-receipt validity."""
        drift: list[dict[str, str]] = []
        git_entries: list[dict[str, object]] = []
        nvd_entries: list[dict[str, object]] = []
        osv_entries: list[dict[str, object]] = []
        osv_manifest_entry: dict[str, object] | None = None
        checked_at = _utc_now()
        operation_fsck_cache = build_source_delta.SuccessfulGitFsckCache()

        with _read_only_campaign_lock(self.paths.runner_state_dir):
            for mirror in sorted(self.paths.git_mirrors, key=lambda item: item.name):
                try:
                    local = _git_state(
                        mirror,
                        fsck_cache=operation_fsck_cache,
                    )
                except SourceRefreshError as exc:
                    drift.append({"source": f"git:{mirror.name}", "reason": str(exc)})
                    continue
                remote = _remote_default(mirror)
                if local.branch != remote.branch or local.head != remote.head:
                    drift.append(
                        {
                            "source": f"git:{mirror.name}",
                            "reason": (
                                f"local {local.branch}@{local.head} differs from "
                                f"remote {remote.branch}@{remote.head}"
                            ),
                        }
                    )
                    continue
                git_entries.append(_git_receipt_entry(mirror, local, remote))

            _require_real_directory(self.paths.nvd_dir, "NVD source")
            nvd_inventory_error = _http_inventory_error(self.paths, source="nvd")
            if nvd_inventory_error is not None:
                drift.append({"source": "nvd:inventory", "reason": nvd_inventory_error})
            for year in NVD_YEARS:
                proof, reason = self._check_nvd(year)
                if reason is not None:
                    drift.append({"source": f"nvd:{year}", "reason": reason})
                elif proof is not None:
                    nvd_entries.append(proof.entry)

            _require_real_directory(self.paths.osv_dir, "OSV source")
            osv_inventory_error = _http_inventory_error(self.paths, source="osv")
            if osv_inventory_error is not None:
                drift.append({"source": "osv:inventory", "reason": osv_inventory_error})
            manifest_proof, manifest_reason = self._check_osv_manifest()
            if manifest_reason is not None:
                drift.append(
                    {"source": "osv:ecosystems.txt", "reason": manifest_reason}
                )
            else:
                osv_manifest_entry = manifest_proof.entry
            expected_archive_names = manifest_proof.inventory.archive_names
            local_names = tuple(
                path.name
                for path in sorted(
                    self.paths.osv_dir.glob("*.zip"),
                    key=lambda path: (path.name.casefold(), path.name),
                )
            )
            if local_names != expected_archive_names:
                drift.append(
                    {
                        "source": "osv:inventory",
                        "reason": (
                            f"expected={list(expected_archive_names)!r}, "
                            f"actual={list(local_names)!r}"
                        ),
                    }
                )
            for filename in expected_archive_names:
                proof, reason = self._check_osv(filename)
                if reason is not None:
                    drift.append({"source": f"osv:{filename}", "reason": reason})
                elif proof is not None:
                    osv_entries.append(proof.entry)

            source_parity = not drift
            receipt_valid = False
            try:
                _validate_campaign_contract(
                    self.paths,
                    receipt_path=self.paths.receipt_path,
                    fsck_cache=operation_fsck_cache,
                )
            except SourceRefreshError:
                pass
            else:
                receipt_valid = True
            receipt_current = False
            if source_parity and osv_manifest_entry is not None:
                receipt = _build_receipt(
                    checked_at,
                    git_entries=git_entries,
                    nvd_entries=nvd_entries,
                    osv_manifest_entry=osv_manifest_entry,
                    osv_entries=osv_entries,
                )
                receipt_current = receipt_valid and _receipt_matches(
                    self.paths.receipt_path,
                    receipt,
                )
                if not receipt_current:
                    drift.append(
                        {
                            "source": "receipt",
                            "reason": "remote-cutoff receipt is absent, unsafe, or stale",
                        }
                    )
            elif not receipt_valid:
                drift.append(
                    {
                        "source": "receipt",
                        "reason": "remote-cutoff receipt is absent, unsafe, or stale",
                    }
                )

        drift.sort(key=lambda item: (item["source"].casefold(), item["reason"]))
        return {
            "schema_version": CHECK_SCHEMA_VERSION,
            "checked_at_utc": checked_at,
            "freshness_semantics": "sequential-live-check-v1",
            "mode": "check",
            "remote_parity": source_parity and receipt_current,
            "source_remote_parity": source_parity,
            "receipt_valid": receipt_valid,
            "receipt_current": receipt_current,
            "drift": drift,
        }

    def refresh(self) -> dict[str, object]:
        """Stage, verify, transactionally install, and formally bind all inputs."""
        file_transaction = _FileTransaction()
        operation_fsck_cache = build_source_delta.SuccessfulGitFsckCache()
        git_transaction = _GitTransaction(operation_fsck_cache)
        migration_transaction = _GitMigrationTransaction(operation_fsck_cache)
        initial_git: dict[str, GitState] = {}
        remote_git: dict[str, RemoteGitState] = {}
        migrations: dict[str, _StagedGitMigration] = {}
        nvd_proofs: list[NvdRemoteProof] = []
        osv_proofs: list[OsvRemoteProof] = []
        osv_manifest_proof: OsvManifestRemoteProof | None = None

        with campaign_contract.batch_singleton_lock(
            self.paths.runner_state_dir,
            campaign_contract.CAMPAIGN_LOCK_KEY,
        ):
            try:
                _prepare_writable_directories(self.paths)
                _validate_existing_http_inventory(self.paths)
                for mirror in self.paths.git_mirrors:
                    _recover_git_migration(mirror)
                    try:
                        initial = _git_state(
                            mirror,
                            fsck_cache=operation_fsck_cache,
                        )
                    except SourceRefreshError as strict_error:
                        try:
                            initial = _git_state(
                                mirror,
                                allow_incomplete_storage=True,
                            )
                        except SourceRefreshError as migration_error:
                            raise SourceRefreshError(
                                f"unsafe Git repository for {mirror.name}; "
                                f"strict validation failed ({strict_error}); "
                                f"migration preflight failed ({migration_error})"
                            ) from migration_error
                        migration = _stage_full_git_mirror(
                            mirror,
                            initial,
                            fsck_cache=operation_fsck_cache,
                        )
                        migration_transaction.track(migration)
                        migrations[mirror.name] = migration
                        remote_git[mirror.name] = migration.remote
                    else:
                        remote_git[mirror.name] = _remote_default(
                            mirror,
                            validate_safety=False,
                        )
                    initial_git[mirror.name] = initial

                for year in NVD_YEARS:
                    proof = self._stage_nvd(year)
                    nvd_proofs.append(proof)
                    for staged, _destination in proof.staged_files:
                        file_transaction.track(staged)

                osv_manifest_proof = self._stage_osv_manifest()
                if osv_manifest_proof.staged_file is None:
                    raise SourceRefreshError("OSV ecosystem manifest was not staged")
                file_transaction.track(osv_manifest_proof.staged_file[0])
                for filename in osv_manifest_proof.inventory.archive_names:
                    proof = self._stage_osv(filename)
                    osv_proofs.append(proof)
                    if proof.staged_file is not None:
                        file_transaction.track(proof.staged_file[0])

                for mirror in self.paths.git_mirrors:
                    if mirror.name in migrations:
                        continue
                    remote = _fetch_exact_remote_commit(
                        mirror,
                        initial_git[mirror.name],
                        remote_git[mirror.name],
                        validate_safety=False,
                    )
                    remote_git[mirror.name] = remote

                updated_git: dict[str, GitState] = {}
                for mirror in self.paths.git_mirrors:
                    migration = migrations.get(mirror.name)
                    if migration is not None:
                        updated_git[mirror.name] = migration_transaction.install(
                            migration
                        )
                    else:
                        updated_git[mirror.name] = git_transaction.fast_forward(
                            mirror,
                            initial_git[mirror.name],
                            remote_git[mirror.name],
                        )

                for proof in nvd_proofs:
                    for staged, destination in proof.staged_files:
                        file_transaction.install(staged, destination)
                file_transaction.install(*osv_manifest_proof.staged_file)
                for proof in osv_proofs:
                    if proof.staged_file is not None:
                        file_transaction.install(*proof.staged_file)

                expected_names = set(osv_manifest_proof.inventory.archive_names)
                obsolete_archives = sorted(
                    (
                        path
                        for path in self.paths.osv_dir.glob("*.zip")
                        if path.name not in expected_names
                    ),
                    key=lambda path: (path.name.casefold(), path.name),
                )
                for path in obsolete_archives:
                    file_transaction.remove(path)

                checked_at = _utc_now()
                receipt = _build_receipt(
                    checked_at,
                    git_entries=[
                        _git_receipt_entry(
                            mirror,
                            updated_git[mirror.name],
                            remote_git[mirror.name],
                        )
                        for mirror in self.paths.git_mirrors
                    ],
                    nvd_entries=[proof.entry for proof in nvd_proofs],
                    osv_manifest_entry=osv_manifest_proof.entry,
                    osv_entries=[proof.entry for proof in osv_proofs],
                )
                staged_receipt = _stage_json(self.paths.receipt_path, receipt)
                file_transaction.track(staged_receipt)
                _validate_campaign_contract(
                    self.paths,
                    receipt_path=staged_receipt,
                    fsck_cache=operation_fsck_cache,
                )
                file_transaction.install(staged_receipt, self.paths.receipt_path)
                snapshot = _validate_campaign_contract(
                    self.paths,
                    receipt_path=self.paths.receipt_path,
                    fsck_cache=operation_fsck_cache,
                )
            except BaseException as exc:
                rollback_errors: list[str] = []
                try:
                    file_transaction.rollback()
                except SourceRefreshError as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
                try:
                    migration_transaction.rollback()
                except SourceRefreshError as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
                try:
                    git_transaction.rollback()
                except SourceRefreshError as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
                if rollback_errors:
                    raise SourceRefreshError(
                        f"refresh failed ({exc}); rollback failures: "
                        + "; ".join(rollback_errors)
                    ) from exc
                raise
            else:
                migration_transaction.commit()
                file_transaction.commit()

        return {
            "schema_version": SCHEMA_VERSION,
            "checked_at_utc": checked_at,
            "cutoff_semantics": "rolling-source-capture-v1",
            "remote_parity": True,
            "receipt_path": str(self.paths.receipt_path.resolve()),
            "source_snapshot_sha256": snapshot.sha256,
            "git_source_count": len(initial_git),
            "nvd_feed_count": len(nvd_proofs),
            "osv_archive_count": len(osv_proofs),
        }

    def _stage_nvd(self, year: int) -> NvdRemoteProof:
        feed_url = f"{NVD_BASE_URL}/nvdcve-2.0-{year}.json.gz"
        meta_url = f"{NVD_BASE_URL}/nvdcve-2.0-{year}.meta"
        meta_before = self._small_get(meta_url, frozenset({"nvd.nist.gov"}))
        metadata = _parse_nvd_metadata(meta_before.body, year)
        feed_destination = self.paths.nvd_dir / f"nvdcve-2.0-{year}.json.gz"
        meta_destination = self.paths.nvd_dir / f"nvdcve-2.0-{year}.meta"
        staged_feed = _new_stage_path(feed_destination, "download")
        staged_meta: Path | None = None
        try:
            feed_response = self.http.request(
                "GET",
                feed_url,
                headers=_NO_CACHE_HEADERS,
                max_bytes=min(metadata.gzip_size, MAX_NVD_GZIP_BYTES),
                allowed_hosts=frozenset({"nvd.nist.gov"}),
                destination=staged_feed,
            )
            if feed_response.final_url != feed_url:
                raise SourceRefreshError(
                    f"NVD {year} feed redirected unexpectedly: "
                    f"{feed_response.final_url!r}"
                )
            if feed_response.size != metadata.gzip_size:
                raise SourceRefreshError(
                    f"NVD {year} gzip size mismatch: metadata={metadata.gzip_size}, "
                    f"download={feed_response.size}"
                )
            meta_after = self._small_get(meta_url, frozenset({"nvd.nist.gov"}))
            _require_same_http_proof(meta_before, meta_after, f"NVD {year} metadata")
            feed_sha = _verify_nvd_feed(staged_feed, metadata, year)
            staged_meta = _stage_bytes(
                meta_destination, meta_before.body or b"", "download"
            )
            entry = _nvd_receipt_entry(
                year,
                feed_destination,
                staged_feed,
                meta_destination,
                staged_meta,
                meta_before,
                feed_sha,
            )
            return NvdRemoteProof(
                year=year,
                metadata_bytes=meta_before.body or b"",
                metadata_etag=_required_header(
                    meta_before, "etag", f"NVD {year} metadata"
                ),
                metadata_last_modified=_required_header(
                    meta_before,
                    "last-modified",
                    f"NVD {year} metadata",
                ),
                entry=entry,
                staged_files=(
                    (staged_feed, feed_destination),
                    (staged_meta, meta_destination),
                ),
            )
        except BaseException:
            staged_feed.unlink(missing_ok=True)
            if staged_meta is not None:
                staged_meta.unlink(missing_ok=True)
            raise

    def _check_nvd(self, year: int) -> tuple[NvdRemoteProof | None, str | None]:
        meta_url = f"{NVD_BASE_URL}/nvdcve-2.0-{year}.meta"
        meta_before = self._small_get(meta_url, frozenset({"nvd.nist.gov"}))
        metadata = _parse_nvd_metadata(meta_before.body, year)
        feed_path = self.paths.nvd_dir / f"nvdcve-2.0-{year}.json.gz"
        meta_path = self.paths.nvd_dir / f"nvdcve-2.0-{year}.meta"
        reason: str | None = None
        entry: dict[str, object] | None = None
        try:
            local_meta = _read_regular_file(
                meta_path, f"NVD {year} metadata", MAX_META_BYTES
            )
            if local_meta != meta_before.body:
                raise SourceRefreshError(
                    "local metadata bytes differ from the remote metadata"
                )
            feed_sha = _verify_nvd_feed(feed_path, metadata, year)
            entry = _nvd_receipt_entry(
                year,
                feed_path,
                feed_path,
                meta_path,
                meta_path,
                meta_before,
                feed_sha,
            )
        except SourceRefreshError as exc:
            reason = str(exc)
        meta_after = self._small_get(meta_url, frozenset({"nvd.nist.gov"}))
        _require_same_http_proof(meta_before, meta_after, f"NVD {year} metadata")
        if reason is not None or entry is None:
            return None, reason
        return (
            NvdRemoteProof(
                year=year,
                metadata_bytes=meta_before.body or b"",
                metadata_etag=_required_header(
                    meta_before, "etag", f"NVD {year} metadata"
                ),
                metadata_last_modified=_required_header(
                    meta_before,
                    "last-modified",
                    f"NVD {year} metadata",
                ),
                entry=entry,
                staged_files=(),
            ),
            None,
        )

    def _stage_osv_manifest(self) -> OsvManifestRemoteProof:
        proof, body = self._fetch_osv_manifest()
        staged = _stage_bytes(
            self.paths.osv_ecosystems_file,
            body,
            "download",
        )
        entry = _osv_manifest_receipt_entry(
            proof,
            self.paths.osv_ecosystems_file,
        )
        return replace(
            proof,
            entry=entry,
            staged_file=(staged, self.paths.osv_ecosystems_file),
        )

    def _check_osv_manifest(
        self,
    ) -> tuple[OsvManifestRemoteProof, str | None]:
        proof, body = self._fetch_osv_manifest()
        try:
            local = _read_regular_file(
                self.paths.osv_ecosystems_file,
                "OSV ecosystem manifest",
                MAX_META_BYTES,
            )
            if local != body:
                raise SourceRefreshError(
                    "local OSV ecosystem manifest differs from the remote manifest"
                )
        except SourceRefreshError as exc:
            reason = str(exc)
        else:
            reason = None
        entry = _osv_manifest_receipt_entry(
            proof,
            self.paths.osv_ecosystems_file,
        )
        return replace(proof, entry=entry), reason

    def _fetch_osv_manifest(self) -> tuple[OsvManifestRemoteProof, bytes]:
        before = self._osv_manifest_head()
        response = self.http.request(
            "GET",
            OSV_ECOSYSTEMS_URL,
            headers={**_NO_CACHE_HEADERS, "If-Match": before.etag},
            max_bytes=MAX_META_BYTES,
            allowed_hosts=frozenset({"storage.googleapis.com"}),
        )
        if response.final_url != OSV_ECOSYSTEMS_URL:
            raise SourceRefreshError(
                "OSV ecosystem manifest redirected unexpectedly: "
                f"{response.final_url!r}"
            )
        body = response.body
        if body is None or not body:
            raise SourceRefreshError("OSV ecosystem manifest response is empty")
        _require_osv_manifest_response_matches(response, before)
        inventory = build_source_delta.parse_osv_ecosystems_manifest(body)
        after = self._osv_manifest_head()
        _require_same_osv_manifest_proof(before, after)
        sha256 = hashlib.sha256(body).hexdigest()
        proof = replace(
            after,
            sha256=sha256,
            inventory=inventory,
        )
        return proof, body

    def _osv_manifest_head(self) -> OsvManifestRemoteProof:
        result = self.http.request(
            "HEAD",
            OSV_ECOSYSTEMS_URL,
            headers=_NO_CACHE_HEADERS,
            max_bytes=1,
            allowed_hosts=frozenset({"storage.googleapis.com"}),
        )
        if result.final_url != OSV_ECOSYSTEMS_URL:
            raise SourceRefreshError(
                f"OSV ecosystem manifest redirected unexpectedly: {result.final_url!r}"
            )
        label = build_source_delta.OSV_ECOSYSTEMS_FILENAME
        generation = _required_header(result, "x-goog-generation", label)
        etag = _required_header(result, "etag", label)
        hashes = _parse_gcs_hashes(
            _required_header(result, "x-goog-hash", label),
            label,
            require_crc32c=False,
        )
        last_modified = _required_header(result, "last-modified", label)
        remote_size = _required_content_length(result.headers, label)
        if not generation.isdigit():
            raise SourceRefreshError(
                f"invalid GCS generation for {label}: {generation!r}"
            )
        if not _GCS_ETAG.fullmatch(etag):
            raise SourceRefreshError(f"invalid GCS ETag for {label}: {etag!r}")
        if remote_size > MAX_META_BYTES:
            raise SourceRefreshError(
                f"OSV ecosystem manifest exceeds {MAX_META_BYTES} bytes"
            )
        return OsvManifestRemoteProof(
            url=OSV_ECOSYSTEMS_URL,
            generation=generation,
            etag=etag,
            md5_base64=hashes["md5"],
            last_modified=last_modified,
            remote_size=remote_size,
            sha256="",
            inventory=build_source_delta.OsvEcosystemInventory((), ()),
            entry={},
            staged_file=None,
        )

    def _stage_osv(self, filename: str) -> OsvRemoteProof:
        url = _osv_url(filename)
        before = self._osv_head(url, filename)
        destination = self.paths.osv_dir / filename
        staged = _new_stage_path(destination, "download")
        try:
            response = self.http.request(
                "GET",
                url,
                headers={**_NO_CACHE_HEADERS, "If-Match": before.etag},
                max_bytes=min(before.remote_size, MAX_OSV_ARCHIVE_BYTES),
                allowed_hosts=frozenset({"storage.googleapis.com"}),
                destination=staged,
            )
            if response.final_url != url:
                raise SourceRefreshError(
                    f"OSV object redirected unexpectedly for {filename}: "
                    f"{response.final_url!r}"
                )
            _require_osv_response_matches(response, before, filename)
            sha256 = _verify_osv_archive(staged, before, filename)
            after = self._osv_head(url, filename)
            _require_same_osv_proof(before, after)
            entry = _osv_receipt_entry(after, destination, sha256)
            return OsvRemoteProof(
                filename=filename,
                url=url,
                generation=after.generation,
                etag=after.etag,
                md5_base64=after.md5_base64,
                crc32c_base64=after.crc32c_base64,
                last_modified=after.last_modified,
                remote_size=after.remote_size,
                entry=entry,
                staged_file=(staged, destination),
            )
        except BaseException:
            staged.unlink(missing_ok=True)
            raise

    def _check_osv(self, filename: str) -> tuple[OsvRemoteProof | None, str | None]:
        url = _osv_url(filename)
        before = self._osv_head(url, filename)
        path = self.paths.osv_dir / filename
        try:
            sha256 = _verify_osv_archive(path, before, filename)
            entry = _osv_receipt_entry(before, path, sha256)
        except SourceRefreshError as exc:
            reason = str(exc)
        else:
            reason = None
        after = self._osv_head(url, filename)
        _require_same_osv_proof(before, after)
        if reason is not None:
            return None, reason
        return replace(before, entry=entry, staged_file=None), None

    def _osv_head(self, url: str, filename: str) -> OsvRemoteProof:
        result = self.http.request(
            "HEAD",
            url,
            headers=_NO_CACHE_HEADERS,
            max_bytes=1,
            allowed_hosts=frozenset({"storage.googleapis.com"}),
        )
        if result.final_url != url:
            raise SourceRefreshError(
                f"OSV object redirected unexpectedly for {filename}: "
                f"{result.final_url!r}"
            )
        generation = _required_header(result, "x-goog-generation", filename)
        etag = _required_header(result, "etag", filename)
        hashes = _parse_gcs_hashes(
            _required_header(result, "x-goog-hash", filename),
            filename,
        )
        last_modified = _required_header(result, "last-modified", filename)
        if not generation.isdigit():
            raise SourceRefreshError(
                f"invalid GCS generation for {filename}: {generation!r}"
            )
        if not _GCS_ETAG.fullmatch(etag):
            raise SourceRefreshError(f"invalid GCS ETag for {filename}: {etag!r}")
        remote_size = _required_content_length(result.headers, filename)
        if remote_size > MAX_OSV_ARCHIVE_BYTES:
            raise SourceRefreshError(
                f"OSV archive exceeds {MAX_OSV_ARCHIVE_BYTES} bytes: {filename}"
            )
        return OsvRemoteProof(
            filename=filename,
            url=url,
            generation=generation,
            etag=etag,
            md5_base64=hashes["md5"],
            crc32c_base64=hashes["crc32c"],
            last_modified=last_modified,
            remote_size=remote_size,
            entry={},
            staged_file=None,
        )

    def _small_get(self, url: str, allowed_hosts: frozenset[str]) -> HttpResult:
        result = self.http.request(
            "GET",
            url,
            headers=_NO_CACHE_HEADERS,
            max_bytes=MAX_META_BYTES,
            allowed_hosts=allowed_hosts,
        )
        if result.final_url != url:
            raise SourceRefreshError(
                f"HTTP metadata redirected unexpectedly: {url!r} -> "
                f"{result.final_url!r}"
            )
        if result.body is None or not result.body:
            raise SourceRefreshError(f"empty HTTP metadata response: {url}")
        return result


def _validate_https_url(url: str, allowed_hosts: frozenset[str]) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
    ):
        raise SourceRefreshError(f"unexpected HTTP origin: {url!r}")


def _normalized_response_headers(headers: object) -> dict[str, str]:
    """Normalize HTTPMessage headers while preserving repeated GCS hashes."""
    keys = getattr(headers, "keys", None)
    get_all = getattr(headers, "get_all", None)
    if not callable(keys) or not callable(get_all):
        raise SourceRefreshError("HTTP response exposed malformed headers")
    normalized: dict[str, str] = {}
    for raw_name in keys():
        name = str(raw_name).lower()
        if name in normalized:
            continue
        raw_values = get_all(raw_name) or []
        values = [str(value).strip() for value in raw_values]
        if not values or any(not value for value in values):
            raise SourceRefreshError(f"HTTP response has an empty {name} header")
        if name == "x-goog-hash":
            normalized[name] = ",".join(values)
        elif (
            name in {"content-length", "etag", "last-modified", "x-goog-generation"}
            and len(set(values)) != 1
        ):
            raise SourceRefreshError(
                f"HTTP response has conflicting duplicate {name} headers"
            )
        else:
            normalized[name] = values[0] if len(set(values)) == 1 else ", ".join(values)
    return normalized


def _optional_content_length(headers: Mapping[str, str], label: str) -> int | None:
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise SourceRefreshError(
            f"invalid Content-Length for {label}: {raw!r}"
        ) from exc
    if value < 0:
        raise SourceRefreshError(f"negative Content-Length for {label}: {value}")
    return value


def _required_content_length(headers: Mapping[str, str], label: str) -> int:
    value = _optional_content_length(headers, label)
    if value is None or value <= 0:
        raise SourceRefreshError(f"missing positive Content-Length for {label}")
    return value


def _required_header(result: HttpResult, name: str, label: str) -> str:
    value = result.headers.get(name)
    if not isinstance(value, str) or not value.strip():
        raise SourceRefreshError(f"missing HTTP {name} for {label}")
    return value.strip()


def _parse_gcs_hashes(
    value: str,
    label: str,
    *,
    require_crc32c: bool = True,
) -> dict[str, str]:
    """Parse and validate the public object's GCS MD5 and CRC32C proof."""
    hashes: dict[str, str] = {}
    for component in value.split(","):
        name, separator, encoded = component.strip().partition("=")
        if not separator or name not in {"md5", "crc32c"} or name in hashes:
            raise SourceRefreshError(f"invalid x-goog-hash for {label}: {value!r}")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise SourceRefreshError(
                f"invalid x-goog-hash encoding for {label}: {value!r}"
            ) from exc
        expected_size = 16 if name == "md5" else 4
        if len(decoded) != expected_size:
            raise SourceRefreshError(
                f"invalid GCS {name} digest size for {label}: {len(decoded)}"
            )
        hashes[name] = encoded
    required = {"md5", "crc32c"} if require_crc32c else {"md5"}
    if not required.issubset(hashes) or set(hashes) - {"md5", "crc32c"}:
        raise SourceRefreshError(
            f"x-goog-hash lacks required digest metadata for {label}: {value!r}"
        )
    return hashes


def _require_same_http_proof(first: HttpResult, second: HttpResult, label: str) -> None:
    if (
        first.body != second.body
        or _required_header(first, "etag", label)
        != _required_header(second, "etag", label)
        or _required_header(first, "last-modified", label)
        != _required_header(second, "last-modified", label)
    ):
        raise SourceRefreshError(f"{label} changed during verification")


def _parse_nvd_metadata(body: bytes | None, year: int) -> nvd_feed._FeedMetadata:
    if body is None:
        raise SourceRefreshError(f"missing NVD {year} metadata body")
    try:
        metadata = nvd_feed._parse_metadata(body)
    except ValueError as exc:
        raise SourceRefreshError(f"invalid NVD {year} metadata: {exc}") from exc
    if metadata.gzip_size > MAX_NVD_GZIP_BYTES:
        raise SourceRefreshError(
            f"NVD {year} feed exceeds {MAX_NVD_GZIP_BYTES} gzip bytes"
        )
    if metadata.json_size > campaign_contract.MAX_NVD_JSON_BYTES:
        raise SourceRefreshError(
            f"NVD {year} feed exceeds {campaign_contract.MAX_NVD_JSON_BYTES} "
            "decompressed JSON bytes"
        )
    return metadata


def _verify_nvd_feed(
    path: Path,
    metadata: nvd_feed._FeedMetadata,
    year: int,
) -> str:
    _require_regular_file(path, f"NVD {year} feed")
    gzip_size = metadata.gzip_size
    json_size = metadata.json_size
    json_sha256 = metadata.json_sha256
    if path.stat().st_size != gzip_size:
        raise SourceRefreshError(
            f"NVD {year} gzip size mismatch: metadata={gzip_size}, local={path.stat().st_size}"
        )
    digest = hashlib.sha256()
    decompressed_size = 0
    try:
        with gzip.open(path, "rb") as handle:
            while chunk := handle.read(HTTP_CHUNK_BYTES):
                decompressed_size += len(chunk)
                if decompressed_size > json_size:
                    raise SourceRefreshError(
                        f"NVD {year} decompressed size exceeds metadata size"
                    )
                digest.update(chunk)
    except (EOFError, OSError) as exc:
        raise SourceRefreshError(f"invalid NVD {year} gzip feed: {exc}") from exc
    if decompressed_size != json_size or digest.hexdigest() != json_sha256:
        raise SourceRefreshError(
            f"NVD {year} decompressed content differs from official metadata"
        )
    compressed_sha = campaign_contract.file_sha256(path)
    try:
        campaign_contract._validate_nvd_feed(str(path.resolve()), compressed_sha)
    except campaign_contract.RunnerError as exc:
        raise SourceRefreshError(str(exc)) from exc
    return compressed_sha


def _nvd_receipt_entry(
    year: int,
    feed_destination: Path,
    feed_source: Path,
    meta_destination: Path,
    meta_source: Path,
    response: HttpResult,
    feed_sha: str,
) -> dict[str, object]:
    return {
        "feed_path": str(feed_destination.resolve()),
        "feed_sha256": feed_sha,
        "feed_size": feed_source.stat().st_size,
        "meta_path": str(meta_destination.resolve()),
        "meta_sha256": campaign_contract.file_sha256(meta_source),
        "remote_etag": _required_header(response, "etag", f"NVD {year} metadata"),
        "remote_last_modified": _required_header(
            response,
            "last-modified",
            f"NVD {year} metadata",
        ),
        "remote_meta_sha256": campaign_contract.file_sha256(meta_source),
        "year": year,
    }


def _osv_url(filename: str) -> str:
    if Path(filename).name != filename or not filename.endswith(".zip"):
        raise SourceRefreshError(f"unsafe OSV filename: {filename!r}")
    ecosystem = filename.removesuffix(".zip")
    return f"{OSV_BASE_URL}/{quote(ecosystem, safe='')}/all.zip"


def _require_osv_manifest_response_matches(
    response: HttpResult,
    proof: OsvManifestRemoteProof,
) -> None:
    label = build_source_delta.OSV_ECOSYSTEMS_FILENAME
    hashes = _parse_gcs_hashes(
        _required_header(response, "x-goog-hash", label),
        label,
        require_crc32c=False,
    )
    if (
        response.size != proof.remote_size
        or _required_content_length(response.headers, label) != proof.remote_size
        or _required_header(response, "x-goog-generation", label) != proof.generation
        or _required_header(response, "etag", label) != proof.etag
        or hashes["md5"] != proof.md5_base64
        or _required_header(response, "last-modified", label) != proof.last_modified
    ):
        raise SourceRefreshError(
            "OSV ecosystem manifest metadata changed during download"
        )
    assert response.body is not None
    md5 = hashlib.md5(response.body, usedforsecurity=False)
    etag_match = _GCS_ETAG.fullmatch(proof.etag)
    assert etag_match is not None
    if (
        md5.hexdigest() != etag_match.group(1)
        or base64.b64encode(md5.digest()).decode("ascii") != proof.md5_base64
    ):
        raise SourceRefreshError(
            "OSV ecosystem manifest MD5 proof does not match its content"
        )


def _require_same_osv_manifest_proof(
    first: OsvManifestRemoteProof,
    second: OsvManifestRemoteProof,
) -> None:
    if (
        first.url != second.url
        or first.generation != second.generation
        or first.etag != second.etag
        or first.md5_base64 != second.md5_base64
        or first.last_modified != second.last_modified
        or first.remote_size != second.remote_size
    ):
        raise SourceRefreshError("OSV ecosystem manifest changed during verification")


def _require_osv_response_matches(
    response: HttpResult,
    proof: OsvRemoteProof,
    label: str,
) -> None:
    hashes = _parse_gcs_hashes(
        _required_header(response, "x-goog-hash", label),
        label,
    )
    if (
        response.size != proof.remote_size
        or _required_content_length(response.headers, label) != proof.remote_size
        or _required_header(response, "x-goog-generation", label) != proof.generation
        or _required_header(response, "etag", label) != proof.etag
        or hashes["md5"] != proof.md5_base64
        or hashes["crc32c"] != proof.crc32c_base64
        or _required_header(response, "last-modified", label) != proof.last_modified
    ):
        raise SourceRefreshError(f"OSV GCS metadata mismatch during download: {label}")


def _require_same_osv_proof(first: OsvRemoteProof, second: OsvRemoteProof) -> None:
    if (
        first.filename != second.filename
        or first.url != second.url
        or first.generation != second.generation
        or first.etag != second.etag
        or first.md5_base64 != second.md5_base64
        or first.crc32c_base64 != second.crc32c_base64
        or first.last_modified != second.last_modified
        or first.remote_size != second.remote_size
    ):
        raise SourceRefreshError(
            f"OSV GCS object changed during verification: {first.filename}"
        )


def _verify_osv_archive(path: Path, proof: OsvRemoteProof, label: str) -> str:
    details = _require_regular_file(path, f"OSV archive {label}")
    if details.st_size != proof.remote_size:
        raise SourceRefreshError(
            f"OSV size mismatch for {label}: remote={proof.remote_size}, local={details.st_size}"
        )
    etag_match = _GCS_ETAG.fullmatch(proof.etag)
    assert etag_match is not None
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(HTTP_CHUNK_BYTES):
            md5.update(chunk)
            sha256.update(chunk)
    if md5.hexdigest() != etag_match.group(1):
        raise SourceRefreshError(f"OSV ETag/content mismatch for {label}")
    md5_base64 = base64.b64encode(md5.digest()).decode("ascii")
    if md5_base64 != proof.md5_base64:
        raise SourceRefreshError(f"OSV GCS MD5/content mismatch for {label}")
    digest = sha256.hexdigest()
    try:
        campaign_contract._validate_osv_archive(str(path.resolve()), digest)
    except campaign_contract.RunnerError as exc:
        raise SourceRefreshError(str(exc)) from exc
    return digest


def _osv_receipt_entry(
    proof: OsvRemoteProof,
    destination: Path,
    sha256: str,
) -> dict[str, object]:
    return {
        "crc32c_base64": proof.crc32c_base64,
        "etag": proof.etag,
        "filename": proof.filename,
        "generation": proof.generation,
        "last_modified": proof.last_modified,
        "md5_base64": proof.md5_base64,
        "path": str(destination.resolve()),
        "remote_size": proof.remote_size,
        "sha256": sha256,
        "size": proof.remote_size,
        "url": proof.url,
    }


def _osv_manifest_receipt_entry(
    proof: OsvManifestRemoteProof,
    destination: Path,
) -> dict[str, object]:
    return {
        "ecosystem_count": len(proof.inventory.ecosystems),
        "ecosystems": list(proof.inventory.ecosystems),
        "etag": proof.etag,
        "filename": build_source_delta.OSV_ECOSYSTEMS_FILENAME,
        "generation": proof.generation,
        "last_modified": proof.last_modified,
        "md5_base64": proof.md5_base64,
        "path": str(destination.resolve()),
        "remote_size": proof.remote_size,
        "sha256": proof.sha256,
        "size": proof.remote_size,
        "url": proof.url,
    }


def _git_env() -> dict[str, str]:
    return build_source_delta.safe_git_environment()


def _run_git(
    mirror: GitMirror,
    arguments: Sequence[str],
    *,
    allowed_returncodes: frozenset[int] = frozenset({0}),
    max_stdout_bytes: int = MAX_GIT_STDOUT_BYTES,
    timeout_seconds: float = GIT_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    command = build_source_delta.safe_git_command(mirror.directory, arguments)
    try:
        completed = _run_argv_bounded(
            command,
            timeout=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=MAX_GIT_STDERR_BYTES,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            env=_git_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceRefreshError(
            f"Git command failed for {mirror.name}: {' '.join(arguments)}: {exc}"
        ) from exc
    if (
        getattr(completed, "stdout_limit_exceeded", False)
        or getattr(completed, "stderr_limit_exceeded", False)
        or getattr(completed, "stdout_drain_incomplete", False)
        or getattr(completed, "stderr_drain_incomplete", False)
    ):
        raise SourceRefreshError(f"Git output was incomplete for {mirror.name}")
    if completed.returncode not in allowed_returncodes:
        stderr = completed.stderr.strip()[:1000]
        raise SourceRefreshError(
            f"Git command failed for {mirror.name} with exit {completed.returncode}: "
            f"{' '.join(arguments)}" + (f": {stderr}" if stderr else "")
        )
    return completed


def _assert_git_mirror_safety(
    mirror: GitMirror,
    *,
    allow_incomplete_storage: bool = False,
    fsck_cache: build_source_delta.SuccessfulGitFsckCache | None = None,
) -> Path:
    directory = _require_real_directory(mirror.directory, f"{mirror.name} Git mirror")
    try:
        return build_source_delta.validate_git_repository_safety(
            directory,
            f"{mirror.name} Git mirror",
            lambda arguments: _run_git(
                mirror,
                arguments,
                max_stdout_bytes=MAX_GIT_STDOUT_BYTES,
                timeout_seconds=(
                    build_source_delta.GIT_FSCK_TIMEOUT_SECONDS
                    if arguments and arguments[0] == "fsck"
                    else GIT_TIMEOUT_SECONDS
                ),
            ).stdout.strip(),
            allow_incomplete_storage=allow_incomplete_storage,
            fsck_cache=fsck_cache,
        )
    except build_source_delta.SourceDeltaError as exc:
        raise SourceRefreshError(
            f"unsafe Git repository for {mirror.name}: {exc}"
        ) from exc


def _git_origins(mirror: GitMirror) -> list[str]:
    origins = [
        line
        for line in _run_git(
            mirror,
            [
                "config",
                "--local",
                "--no-includes",
                "--get-all",
                "remote.origin.url",
            ],
            max_stdout_bytes=8192,
        ).stdout.splitlines()
        if line
    ]
    if origins != [mirror.expected_origin]:
        raise SourceRefreshError(
            f"wrong Git origin for {mirror.name}: expected "
            f"{mirror.expected_origin!r}, got {origins!r}"
        )
    return origins


def _git_materialization_markers(mirror: GitMirror) -> tuple[str, ...]:
    """Return the bounded, explicit reasons a mirror needs a full clone."""

    git_dir = mirror.directory / ".git"
    markers: list[str] = []
    shallow = git_dir / "shallow"
    try:
        shallow_metadata = shallow.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise SourceRefreshError(
            f"cannot inspect shallow marker for {mirror.name}: {exc}"
        ) from exc
    else:
        if stat.S_ISLNK(shallow_metadata.st_mode) or not stat.S_ISREG(
            shallow_metadata.st_mode
        ):
            raise SourceRefreshError(
                f"unsafe shallow marker for {mirror.name}: {shallow}"
            )
        markers.append("shallow history")

    pack_dir = git_dir / "objects" / "pack"
    try:
        promisor = sorted(
            path.name for path in pack_dir.iterdir() if path.name.endswith(".promisor")
        )
    except OSError as exc:
        raise SourceRefreshError(
            f"cannot inspect promisor packs for {mirror.name}: {exc}"
        ) from exc
    if promisor:
        markers.append("promisor packs")

    config = _run_git(
        mirror,
        ["config", "--local", "--no-includes", "--null", "--list"],
        max_stdout_bytes=2 * 1024 * 1024,
    ).stdout
    try:
        entries = build_source_delta._local_git_config_entries(  # noqa: SLF001
            config,
            f"{mirror.name} Git mirror",
        )
    except build_source_delta.SourceDeltaError as exc:
        raise SourceRefreshError(str(exc)) from exc
    partial_keys = sorted(
        key
        for key, _value in entries
        if build_source_delta._GIT_PARTIAL_CONFIG_KEY.fullmatch(key)  # noqa: SLF001
    )
    if partial_keys:
        markers.append("partial-clone/promisor config")
    sparse_keys = sorted(
        key
        for key, _value in entries
        if key
        in {
            "core.sparsecheckout",
            "core.sparsecheckoutcone",
            "index.sparse",
        }
    )
    if sparse_keys:
        markers.append("sparse checkout config")
    if any(key == "extensions.worktreeconfig" for key, _value in entries):
        markers.append("worktree config extension")
    for filename in ("config.worktree", "config.worktree.lock"):
        try:
            (git_dir / filename).lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SourceRefreshError(
                f"cannot inspect {filename} for {mirror.name}: {exc}"
            ) from exc
        markers.append(filename)
    sparse_checkout = git_dir / "info" / "sparse-checkout"
    try:
        sparse_checkout.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise SourceRefreshError(
            f"cannot inspect sparse checkout for {mirror.name}: {exc}"
        ) from exc
    else:
        markers.append("sparse checkout file")
    return tuple(markers)


def _git_state(
    mirror: GitMirror,
    *,
    allow_incomplete_storage: bool = False,
    fsck_cache: build_source_delta.SuccessfulGitFsckCache | None = None,
) -> GitState:
    _assert_git_mirror_safety(
        mirror,
        allow_incomplete_storage=allow_incomplete_storage,
        fsck_cache=fsck_cache,
    )
    if allow_incomplete_storage and not _git_materialization_markers(mirror):
        raise SourceRefreshError(
            f"Git mirror is unsafe for a reason other than incomplete storage: "
            f"{mirror.name}"
        )
    origins = _git_origins(mirror)
    branch = _run_git(
        mirror,
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        max_stdout_bytes=4096,
    ).stdout.strip()
    if not branch or branch.startswith("-") or ".." in branch:
        raise SourceRefreshError(f"unsafe current branch for {mirror.name}: {branch!r}")
    valid_branch = _run_git(
        mirror,
        ["check-ref-format", f"refs/heads/{branch}"],
        allowed_returncodes=frozenset({0, 1}),
        max_stdout_bytes=4096,
    )
    if valid_branch.returncode != 0:
        raise SourceRefreshError(
            f"invalid current branch for {mirror.name}: {branch!r}"
        )
    head = _run_git(
        mirror,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        max_stdout_bytes=4096,
    ).stdout.strip()
    tree = _run_git(
        mirror,
        ["rev-parse", "--verify", "HEAD^{tree}"],
        max_stdout_bytes=4096,
    ).stdout.strip()
    if not _GIT_OID.fullmatch(head) or not _GIT_OID.fullmatch(tree):
        raise SourceRefreshError(f"invalid Git object ID for {mirror.name}")
    if not allow_incomplete_storage:
        status_output = _run_git(
            mirror,
            ["status", "--porcelain=v1", "--untracked-files=all"],
            max_stdout_bytes=4 * 1024 * 1024,
        ).stdout
        if status_output:
            raise SourceRefreshError(
                f"Git mirror is dirty: {mirror.name}: "
                f"{status_output.splitlines()[0][:300]}"
            )
        _assert_git_tree_has_no_symlinks(mirror, head)
    return GitState(branch=branch, head=head, tree=tree, origin=origins[0])


def _assert_git_tree_has_no_symlinks(mirror: GitMirror, revision: str) -> None:
    listing = _run_git(
        mirror,
        ["ls-tree", "-r", "-z", revision],
        max_stdout_bytes=MAX_GIT_STDOUT_BYTES,
    ).stdout
    for raw_entry in listing.split("\0"):
        if not raw_entry:
            continue
        metadata, separator, _path = raw_entry.partition("\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise SourceRefreshError(f"malformed Git tree entry for {mirror.name}")
        if fields[0] == "120000":
            raise SourceRefreshError(
                f"Git tree contains a symlink for {mirror.name}: {_path!r}"
            )
        if fields[0] == "160000":
            raise SourceRefreshError(
                f"Git tree contains a gitlink for {mirror.name}: {_path!r}"
            )
        if fields[0] not in {"100644", "100755"} or fields[1] != "blob":
            raise SourceRefreshError(
                f"Git tree contains an unsupported entry for {mirror.name}: "
                f"{fields[0]} {fields[1]} {_path!r}"
            )


def _remote_default(
    mirror: GitMirror,
    *,
    validate_safety: bool = True,
) -> RemoteGitState:
    if validate_safety:
        _assert_git_mirror_safety(mirror)
    _git_origins(mirror)
    output = _run_git(
        mirror,
        ["ls-remote", "--symref", "origin", "HEAD"],
        max_stdout_bytes=64 * 1024,
    ).stdout
    branch: str | None = None
    head: str | None = None
    for line in output.splitlines():
        if line.startswith("ref: "):
            fields = line.split("\t")
            if len(fields) == 2 and fields[1] == "HEAD":
                ref = fields[0].removeprefix("ref: ")
                prefix = "refs/heads/"
                if ref.startswith(prefix):
                    candidate = ref.removeprefix(prefix)
                    if branch is not None:
                        raise SourceRefreshError(
                            f"ambiguous remote default branch for {mirror.name}"
                        )
                    branch = candidate
        else:
            fields = line.split("\t")
            if (
                len(fields) == 2
                and fields[1] == "HEAD"
                and _GIT_OID.fullmatch(fields[0])
            ):
                if head is not None:
                    raise SourceRefreshError(
                        f"ambiguous remote default head for {mirror.name}"
                    )
                head = fields[0]
    if (
        branch is None
        or head is None
        or not branch
        or branch.startswith("-")
        or ".." in branch
    ):
        raise SourceRefreshError(f"malformed remote default ref for {mirror.name}")
    valid_ref = _run_git(
        mirror,
        ["check-ref-format", f"refs/heads/{branch}"],
        allowed_returncodes=frozenset({0, 1}),
        max_stdout_bytes=4096,
    )
    if valid_ref.returncode != 0:
        raise SourceRefreshError(
            f"invalid remote default branch for {mirror.name}: {branch!r}"
        )
    return RemoteGitState(branch=branch, head=head)


def _cloned_remote_default(
    mirror: GitMirror,
    state: GitState,
) -> RemoteGitState:
    """Bind a full clone to the exact default tip its fetch installed."""

    remote_head_ref = _run_git(
        mirror,
        ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
        max_stdout_bytes=4096,
    ).stdout.strip()
    expected_ref = f"refs/remotes/origin/{state.branch}"
    if remote_head_ref != expected_ref:
        raise SourceRefreshError(
            f"full clone default tracking ref mismatch for {mirror.name}: "
            f"expected {expected_ref!r}, got {remote_head_ref!r}"
        )
    tracking_head = _run_git(
        mirror,
        ["rev-parse", "--verify", f"{expected_ref}^{{commit}}"],
        max_stdout_bytes=4096,
    ).stdout.strip()
    if tracking_head != state.head:
        raise SourceRefreshError(
            f"full clone checkout differs from fetched default tip for {mirror.name}"
        )
    return RemoteGitState(branch=state.branch, head=tracking_head)


def _stage_full_git_mirror(
    mirror: GitMirror,
    original: GitState,
    *,
    fsck_cache: build_source_delta.SuccessfulGitFsckCache,
) -> _StagedGitMigration:
    """Clone a complete trusted replacement without using old Git objects."""

    stage, backup, garbage = _git_migration_paths(mirror)
    parent = _require_real_directory(
        mirror.directory.parent,
        f"{mirror.name} Git migration parent",
    )
    for reserved in (stage, backup, garbage):
        if reserved.exists() or reserved.is_symlink():
            raise SourceRefreshError(
                f"stale Git migration control path for {mirror.name}: {reserved}"
            )
    try:
        free_bytes = shutil.disk_usage(parent).free
    except OSError as exc:
        raise SourceRefreshError(
            f"cannot inspect free space for {mirror.name} migration: {exc}"
        ) from exc
    if free_bytes < MIN_GIT_MIGRATION_FREE_BYTES:
        raise SourceRefreshError(
            f"insufficient free space for {mirror.name} full-clone migration: "
            f"free={free_bytes}, required={MIN_GIT_MIGRATION_FREE_BYTES}"
        )

    bootstrap = GitMirror(
        f"{mirror.name} full-clone bootstrap", parent, mirror.expected_origin
    )
    try:
        _run_git(
            bootstrap,
            [
                "clone",
                "--no-local",
                "--no-recurse-submodules",
                "--origin",
                "origin",
                "--",
                mirror.expected_origin,
                stage.name,
            ],
            max_stdout_bytes=MAX_GIT_CLONE_STDOUT_BYTES,
            timeout_seconds=GIT_CLONE_TIMEOUT_SECONDS,
        )
        staged_mirror = GitMirror(mirror.name, stage, mirror.expected_origin)
        staged_state = _git_state(staged_mirror, fsck_cache=fsck_cache)
        remote = _cloned_remote_default(staged_mirror, staged_state)
        if (
            _git_state(staged_mirror, fsck_cache=fsck_cache) != staged_state
            or _cloned_remote_default(staged_mirror, staged_state) != remote
        ):
            raise SourceRefreshError(
                f"full clone changed while binding its fetched tip: {mirror.name}"
            )
        if original.branch != remote.branch:
            raise SourceRefreshError(
                f"{mirror.name} is on {original.branch!r}; remote default is "
                f"{remote.branch!r}"
            )
        old_commit = _run_git(
            staged_mirror,
            ["cat-file", "-e", f"{original.head}^{{commit}}"],
            max_stdout_bytes=4096,
        )
        del old_commit
        ancestry = _run_git(
            staged_mirror,
            ["merge-base", "--is-ancestor", original.head, remote.head],
            allowed_returncodes=frozenset({0, 1}),
            max_stdout_bytes=4096,
        )
        if ancestry.returncode != 0:
            raise SourceRefreshError(
                f"Git update is not a fast-forward for {mirror.name}: "
                f"{original.head} -> {remote.head}"
            )
        return _StagedGitMigration(
            mirror=mirror,
            original=original,
            remote=remote,
            staged_path=stage,
            staged_state=staged_state,
        )
    except BaseException:
        _remove_migration_tree(stage, f"failed {mirror.name} full clone")
        raise


def _fetch_exact_remote_commit(
    mirror: GitMirror,
    local: GitState,
    expected: RemoteGitState,
    *,
    validate_safety: bool = True,
) -> RemoteGitState:
    if validate_safety:
        _assert_git_mirror_safety(mirror)
    _git_origins(mirror)
    if local.branch != expected.branch:
        raise SourceRefreshError(
            f"{mirror.name} is on {local.branch!r}; remote default is {expected.branch!r}"
        )
    _run_git(
        mirror,
        [
            "-c",
            "fetch.fsckObjects=true",
            "-c",
            "transfer.fsckObjects=true",
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-auto-maintenance",
            "--force",
            "origin",
            f"refs/heads/{expected.branch}",
        ],
        max_stdout_bytes=8 * 1024 * 1024,
    )
    fetched_head = _run_git(
        mirror,
        ["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
        max_stdout_bytes=4096,
    ).stdout.strip()
    if not _GIT_OID.fullmatch(fetched_head):
        raise SourceRefreshError(
            f"invalid fetched Git head for {mirror.name}: {fetched_head!r}"
        )
    _run_git(
        mirror,
        ["cat-file", "-e", f"{expected.head}^{{commit}}"],
        max_stdout_bytes=4096,
    )
    _run_git(
        mirror,
        ["cat-file", "-e", f"{fetched_head}^{{commit}}"],
        max_stdout_bytes=4096,
    )
    advertised_ancestry = _run_git(
        mirror,
        ["merge-base", "--is-ancestor", expected.head, fetched_head],
        allowed_returncodes=frozenset({0, 1}),
        max_stdout_bytes=4096,
    )
    if advertised_ancestry.returncode != 0:
        raise SourceRefreshError(
            f"Git remote was not a fast-forward after advertisement for "
            f"{mirror.name}: {expected.head} -> {fetched_head}"
        )
    ancestry = _run_git(
        mirror,
        ["merge-base", "--is-ancestor", local.head, fetched_head],
        allowed_returncodes=frozenset({0, 1}),
        max_stdout_bytes=4096,
    )
    if ancestry.returncode != 0:
        raise SourceRefreshError(
            f"Git update is not a fast-forward for {mirror.name}: "
            f"{local.head} -> {fetched_head}"
        )
    _assert_git_tree_has_no_symlinks(mirror, fetched_head)
    return RemoteGitState(branch=expected.branch, head=fetched_head)


def _git_receipt_entry(
    mirror: GitMirror,
    local: GitState,
    remote: RemoteGitState,
) -> dict[str, object]:
    return {
        "branch": remote.branch,
        "head": local.head,
        "name": mirror.name,
        "origin": local.origin,
        "path": str(mirror.directory.resolve()),
        "remote_head": remote.head,
        "tree": local.tree,
    }


def _build_receipt(
    checked_at: str,
    *,
    git_entries: Sequence[dict[str, object]],
    nvd_entries: Sequence[dict[str, object]],
    osv_manifest_entry: dict[str, object],
    osv_entries: Sequence[dict[str, object]],
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "checked_at_utc": checked_at,
        "git_sources": sorted(git_entries, key=lambda entry: str(entry["name"])),
        "nvd_feeds": sorted(nvd_entries, key=lambda entry: int(entry["year"])),
        "osv_ecosystem_manifest": osv_manifest_entry,
        "osv_archive_count": len(osv_entries),
        "osv_archives": sorted(
            osv_entries,
            key=lambda entry: (
                str(entry["filename"]).casefold(),
                str(entry["filename"]),
            ),
        ),
        "remote_parity": True,
    }


def _validate_campaign_contract(
    paths: RefreshPaths,
    *,
    receipt_path: Path,
    fsck_cache: build_source_delta.SuccessfulGitFsckCache | None = None,
) -> campaign_contract.SourceSnapshot:
    runner_paths = replace(
        campaign_contract.RunnerPaths.defaults(paths.repo_root),
        cvelist_dir=_mirror_path(paths, "cvelistV5"),
        ghsa_dir=_mirror_path(paths, "github-advisory-database"),
        gemnasium_dir=_mirror_path(paths, "gemnasium-db"),
        nvd_feeds_dir=paths.nvd_dir,
        osv_bulk_dir=paths.osv_dir,
        osv_ecosystems_file=paths.osv_ecosystems_file,
        source_remote_receipt=receipt_path,
    )
    try:
        return campaign_contract.capture_source_snapshot(
            runner_paths,
            fsck_cache=fsck_cache,
        )
    except campaign_contract.RunnerError as exc:
        raise SourceRefreshError(
            f"remote-cutoff receipt failed campaign validation: {exc}"
        ) from exc


def _mirror_path(paths: RefreshPaths, name: str) -> Path:
    matches = [mirror.directory for mirror in paths.git_mirrors if mirror.name == name]
    if len(matches) != 1:
        raise SourceRefreshError(f"missing or duplicate Git mirror: {name}")
    return matches[0]


def _receipt_matches(path: Path, expected: dict[str, object]) -> bool:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return False
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    payload = dict(payload)
    expected = dict(expected)
    payload.pop("checked_at_utc", None)
    expected.pop("checked_at_utc", None)
    return payload == expected


def _prepare_writable_directories(paths: RefreshPaths) -> None:
    for directory, label in (
        (paths.nvd_dir, "NVD source"),
        (paths.osv_dir, "OSV source"),
        (paths.receipt_path.parent, "receipt"),
    ):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SourceRefreshError(
                f"cannot create {label} directory {directory}: {exc}"
            ) from exc
        _require_real_directory(directory, label)


def _http_inventory_error(paths: RefreshPaths, *, source: str) -> str | None:
    if source == "nvd":
        expected = {
            *(f"nvdcve-2.0-{year}.json.gz" for year in NVD_YEARS),
            *(f"nvdcve-2.0-{year}.meta" for year in NVD_YEARS),
        }
        actual = {
            path.name
            for path in paths.nvd_dir.iterdir()
            if path.name.endswith((".json.gz", ".meta"))
        }
    elif source == "osv":
        unexpected: list[str] = []
        for path in paths.osv_dir.iterdir():
            if path.name == build_source_delta.OSV_ECOSYSTEMS_FILENAME:
                allowed = True
            elif path.name.endswith(".zip") and Path(path.name).name == path.name:
                try:
                    build_source_delta.parse_osv_ecosystems_manifest(
                        (path.name.removesuffix(".zip") + "\n").encode("utf-8")
                    )
                except (UnicodeEncodeError, build_source_delta.SourceDeltaError):
                    allowed = False
                else:
                    allowed = True
            else:
                allowed = False
            try:
                metadata = path.lstat()
            except OSError:
                unexpected.append(path.name)
                continue
            if (
                not allowed
                or stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size <= 0
            ):
                unexpected.append(path.name)
        return (
            "unsafe or unexpected source files: "
            f"{sorted(unexpected, key=lambda name: (name.casefold(), name))!r}"
            if unexpected
            else None
        )
    else:  # pragma: no cover - internal call contract
        raise SourceRefreshError(f"unknown source inventory: {source}")
    unexpected = sorted(actual - expected, key=lambda name: (name.casefold(), name))
    return f"unexpected source files: {unexpected!r}" if unexpected else None


def _validate_existing_http_inventory(paths: RefreshPaths) -> None:
    for source in ("nvd", "osv"):
        error = _http_inventory_error(paths, source=source)
        if error is not None:
            raise SourceRefreshError(f"{source.upper()} inventory is unsafe: {error}")


@contextmanager
def _read_only_campaign_lock(state_dir: Path) -> Iterator[None]:
    """Share an existing campaign lock without creating or rewriting it."""
    lock_path = state_dir / "locks" / f"{campaign_contract.CAMPAIGN_LOCK_KEY}.lock"
    lock_directory_fd: int | None = None
    descriptor: int | None = None
    try:
        lock_directory_fd = campaign_contract._open_directory_chain(  # noqa: SLF001
            lock_path.parent,
            label="read-only campaign lock directory",
            create=False,
            missing_ok=True,
        )
        if lock_directory_fd is None:
            yield
            return
        descriptor = campaign_contract._open_lock_file_at(  # noqa: SLF001
            lock_directory_fd,
            lock_path.name,
            label=f"read-only campaign lock {lock_path}",
            writable=False,
            create=False,
            missing_ok=True,
        )
        if descriptor is None:
            yield
            return
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise SourceRefreshError(
                    "a data-refresh campaign is currently active"
                ) from exc
            raise SourceRefreshError(
                f"cannot acquire read-only campaign lock {lock_path}: {exc}"
            ) from exc
        campaign_contract._revalidate_lock_file_at(  # noqa: SLF001
            lock_directory_fd,
            lock_path.name,
            descriptor,
            label=f"read-only campaign lock {lock_path}",
        )
        yield
    except campaign_contract.RunnerError as exc:
        raise SourceRefreshError(str(exc)) from exc
    finally:
        if descriptor is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        if lock_directory_fd is not None:
            os.close(lock_directory_fd)


def _require_real_directory(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SourceRefreshError(
            f"cannot inspect {label} directory {path}: {exc}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SourceRefreshError(f"{label} path is not a real directory: {path}")
    return path.resolve()


def _require_regular_file(path: Path, label: str) -> os.stat_result:
    try:
        before = path.lstat()
    except OSError as exc:
        raise SourceRefreshError(f"cannot inspect {label} {path}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
    ):
        raise SourceRefreshError(
            f"{label} is missing, empty, symlinked, or non-regular: {path}"
        )
    return before


def _read_regular_file(path: Path, label: str, max_bytes: int) -> bytes:
    metadata = _require_regular_file(path, label)
    if metadata.st_size > max_bytes:
        raise SourceRefreshError(f"{label} exceeds {max_bytes} bytes: {path}")
    try:
        body = path.read_bytes()
    except OSError as exc:
        raise SourceRefreshError(f"cannot read {label} {path}: {exc}") from exc
    after = path.lstat()
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ):
        raise SourceRefreshError(f"{label} changed while being read: {path}")
    return body


def _new_stage_path(destination: Path, purpose: str) -> Path:
    _require_real_directory(destination.parent, f"{purpose} staging")
    try:
        descriptor, name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.{purpose}.",
            suffix=".tmp",
        )
        os.close(descriptor)
        return Path(name)
    except OSError as exc:
        raise SourceRefreshError(f"cannot stage {destination}: {exc}") from exc


def _stage_bytes(destination: Path, body: bytes, purpose: str) -> Path:
    staged = _new_stage_path(destination, purpose)
    try:
        with staged.open("wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        return staged
    except OSError:
        staged.unlink(missing_ok=True)
        raise


def _stage_json(destination: Path, payload: Mapping[str, object]) -> Path:
    body = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    return _stage_bytes(destination, body, "receipt")


def _reserve_backup_path(destination: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.rollback.",
        suffix=".tmp",
    )
    os.close(descriptor)
    path = Path(name)
    path.unlink()
    return path


def _same_file_content(first: Path, second: Path) -> bool:
    first_stat = _require_regular_file(first, "staged source")
    second_stat = _require_regular_file(second, "existing source")
    return first_stat.st_size == second_stat.st_size and campaign_contract.file_sha256(
        first
    ) == campaign_contract.file_sha256(second)


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Refresh and remotely bind every frozen advisory source input."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report remote drift without mutating local sources or state",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        with campaign_contract._campaign_signal_handlers():
            refresher = SourceRefresher(RefreshPaths.defaults())
            result = refresher.check() if args.check else refresher.refresh()
    except campaign_contract.CampaignSignalInterrupt as exc:
        print(
            f"source refresh interrupted by {exc.signal_name}; transaction rolled back",
            file=sys.stderr,
        )
        return 128 + exc.signum
    except (SourceRefreshError, campaign_contract.RunnerError) as exc:
        print(f"source refresh failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.check and result.get("remote_parity") is not True:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
