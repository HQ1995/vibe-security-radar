#!/usr/bin/env python3
"""Atomically migrate validated ambiguous legacy Git caches to v2 paths."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import data_refresh_paths

from cve_analyzer.git_ops import _cache_matches_origin, run_git, url_to_cache_dir
from cve_analyzer.git_url import normalize_repo_identity


class MigrationError(RuntimeError):
    """Raised when a cache cannot be migrated without losing provenance."""


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_STATE_ROOT = data_refresh_paths.DATA_REFRESH_STATE_RELATIVE
_V2_NAME = re.compile(
    r"v2_[a-z0-9._-]+_[a-z0-9._-]+_[0-9a-f]{64}(?:\.recovery-[1-9][0-9]*)?"
)


def _git_revision(path: Path, expression: str) -> str:
    completed = run_git(
        ["git", "-C", str(path), "rev-parse", expression],
        capture_output=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
    )
    value = completed.stdout.strip() if completed.returncode == 0 else ""
    if re.fullmatch(r"[0-9a-f]{40,64}", value) is None:
        raise MigrationError(f"cannot attest {expression} for {path}")
    return value


def _load_inventory(path: Path) -> tuple[tuple[str, Path, Path], ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise MigrationError(f"cannot read collision inventory {path}: {exc}") from exc
    records: dict[str, tuple[str, Path, Path]] = {}
    for line_number, line in enumerate(lines, 1):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 3 or not fields[2].startswith("legacy-origin-collision:"):
            raise MigrationError(f"malformed collision line {line_number}")
        request_url = fields[0]
        expected = Path(fields[1])
        legacy = Path(fields[2].split(":", 1)[1])
        if not expected.is_absolute() or not legacy.is_absolute():
            raise MigrationError(f"collision line {line_number} has relative paths")
        previous = records.get(request_url)
        record = (request_url, expected, legacy)
        if previous is not None and previous[1] != expected:
            raise MigrationError(
                f"collision identity has multiple v2 targets: {request_url}"
            )
        # One identity may collide through multiple legacy naming generations.
        # Prefer the legacy path that actually exists; otherwise retain the
        # lexicographically first path for deterministic reporting.
        if previous is None or (legacy.exists() and not previous[2].exists()) or (
            legacy.exists() == previous[2].exists() and str(legacy) < str(previous[2])
        ):
            records[request_url] = record
    return tuple(records[key] for key in sorted(records))


def migrate_inventory(path: Path) -> dict[str, Any]:
    migrations: list[dict[str, Any]] = []
    already_v2: list[str] = []
    absent: list[str] = []
    for request_url, expected, legacy in _load_inventory(path):
        identity = normalize_repo_identity(request_url)
        if identity is None:
            raise MigrationError(f"cannot normalize collision URL: {request_url}")
        if (
            expected.parent != legacy.parent
            or _V2_NAME.fullmatch(expected.name) is None
            or legacy == expected
        ):
            raise MigrationError(f"unsafe collision migration paths: {request_url}")
        if expected.exists():
            if expected.is_symlink() or not _cache_matches_origin(expected, identity):
                raise MigrationError(f"existing v2 cache is invalid: {expected}")
            already_v2.append(request_url)
            continue
        resolved = Path(url_to_cache_dir(request_url)).absolute()
        if (
            resolved != expected
            and resolved.parent == expected.parent
            and resolved.exists()
            and _V2_NAME.fullmatch(resolved.name) is None
        ):
            legacy = resolved
        if not legacy.exists():
            absent.append(request_url)
            continue
        if (
            legacy.is_symlink()
            or not legacy.is_dir()
            or not _cache_matches_origin(legacy, identity)
        ):
            # A shared legacy path belonging to the other collision identity is
            # intentionally left untouched.
            absent.append(request_url)
            continue
        head = _git_revision(legacy, "HEAD")
        tree = _git_revision(legacy, "HEAD^{tree}")
        try:
            os.rename(legacy, expected)
            if (
                not _cache_matches_origin(expected, identity)
                or _git_revision(expected, "HEAD") != head
                or _git_revision(expected, "HEAD^{tree}") != tree
            ):
                raise MigrationError(f"post-migration attestation failed: {expected}")
        except BaseException:
            if expected.exists() and not legacy.exists():
                os.rename(expected, legacy)
            raise
        directory_fd = os.open(expected.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        migrations.append(
            {
                "request_url": request_url,
                "legacy_path": str(legacy),
                "v2_path": str(expected),
                "head": head,
                "tree": tree,
            }
        )
    return {
        "schema_version": 1,
        "inventory_path": str(path),
        "migrated_count": len(migrations),
        "already_v2_count": len(already_v2),
        "absent_or_other_identity_count": len(absent),
        "migrations": migrations,
        "already_v2": already_v2,
        "absent_or_other_identity": absent,
    }


def _merge_receipts(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(previous, dict) or previous.get("schema_version") not in {1, 2}:
        return current
    combined: dict[str, dict[str, Any]] = {}
    for receipt in (previous, current):
        for migration in receipt.get("migrations", []):
            if not isinstance(migration, dict) or not isinstance(
                migration.get("request_url"), str
            ):
                raise MigrationError("existing migration receipt is malformed")
            request_url = migration["request_url"]
            old = combined.get(request_url)
            if old is not None and old != migration:
                raise MigrationError(
                    f"migration receipt changed for {request_url}"
                )
            combined[request_url] = migration
    migrated = set(combined)
    already = sorted(
        (
            set(previous.get("already_v2", []))
            | set(current.get("already_v2", []))
        )
        - migrated
    )
    absent = sorted(set(current.get("absent_or_other_identity", [])) - migrated)
    return {
        **current,
        "schema_version": 2,
        "migrations": [combined[key] for key in sorted(combined)],
        "migrated_count": len(combined),
        "already_v2": already,
        "already_v2_count": len(already),
        "absent_or_other_identity": absent,
        "absent_or_other_identity_count": len(absent),
    }


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    parser.add_argument(
        "--inventory",
        default=str(_STATE_ROOT / "missing-required-repos.txt"),
    )
    parser.add_argument(
        "--receipt",
        default=str(_STATE_ROOT / "legacy-cache-migration-v2.json"),
    )
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).expanduser().resolve()

    def resolve(value: str) -> Path:
        candidate = Path(value).expanduser()
        return candidate.resolve() if candidate.is_absolute() else (repo_root / candidate).resolve()

    try:
        receipt_path = resolve(args.receipt)
        previous = None
        if receipt_path.is_file() and not receipt_path.is_symlink():
            previous = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt = _merge_receipts(
            previous,
            migrate_inventory(resolve(args.inventory)),
        )
        _atomic_write_json(receipt_path, receipt)
    except (MigrationError, OSError) as exc:
        print(f"error: {exc}")
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
