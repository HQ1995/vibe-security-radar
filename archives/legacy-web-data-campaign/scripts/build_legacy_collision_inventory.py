#!/usr/bin/env python3
"""Build the deterministic legacy repository-cache collision inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import data_refresh_paths

from cve_analyzer.git_ops import CACHE_DIR, _canonical_cache_dir


class InventoryError(RuntimeError):
    """Raised when the formal batch manifest cannot prove the inventory."""


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_STATE_ROOT = data_refresh_paths.DATA_REFRESH_STATE_RELATIVE


def _read_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
        payload = json.loads(data)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot read grouped batch manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise InventoryError("grouped batch manifest must be an object")
    verification = payload.get("verification")
    if (
        payload.get("schema_version") != 3
        or payload.get("inputs", {}).get("population_policy") != "formal_full"
        or not isinstance(verification, Mapping)
        or verification.get("all_remaining_ids_exactly_once") is not True
        or verification.get("alias_classes_exactly_once") is not True
        or not isinstance(payload.get("batches"), list)
    ):
        raise InventoryError("grouped batch manifest lacks formal exact-once proofs")
    return payload, data


def _normalized_repositories(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    repositories: set[str] = set()
    for batch in manifest["batches"]:
        if not isinstance(batch, Mapping) or not isinstance(batch.get("repos"), list):
            raise InventoryError("grouped batch has malformed repository metadata")
        for repository in batch["repos"]:
            if not isinstance(repository, str) or not repository:
                raise InventoryError("grouped batch has an invalid repository identity")
            if (
                "/" not in repository
                or repository != repository.casefold()
                or any(character.isspace() for character in repository)
            ):
                raise InventoryError(
                    f"grouped batch repository is not canonical: {repository!r}"
                )
            host, repo_path = repository.split("/", 1)
            if not host or not repo_path or any(not part for part in repo_path.split("/")):
                raise InventoryError(
                    f"grouped batch repository is not canonical: {repository!r}"
                )
            repositories.add(repository)
    expected = manifest.get("mapping", {}).get("unique_normalized_repos")
    if expected != len(repositories):
        raise InventoryError(
            "grouped batch repository count does not match its manifest proof"
        )
    return tuple(sorted(repositories))


def _legacy_paths(repository: str, cache_root: Path) -> tuple[Path, ...]:
    host, repo_path = repository.split("/", 1)
    parts = repo_path.split("/")
    cache_host = host.replace(":", "_")
    return tuple(
        dict.fromkeys(
            (
                cache_root / f"{cache_host}_{'_'.join(parts)}",
                cache_root / f"{cache_host}_{'_'.join(parts[-2:])}",
                cache_root / "_".join(parts[-2:]),
            )
        )
    )


def build_inventory(
    manifest_path: Path,
    *,
    cache_root: Path = CACHE_DIR,
) -> tuple[bytes, dict[str, Any]]:
    """Return inventory bytes and a deterministic provenance summary."""

    manifest, manifest_bytes = _read_manifest(manifest_path)
    repositories = _normalized_repositories(manifest)
    path_owners: dict[Path, set[str]] = defaultdict(set)
    for repository in repositories:
        for legacy_path in _legacy_paths(repository, cache_root):
            path_owners[legacy_path].add(repository)

    collision_paths = {
        path: owners for path, owners in path_owners.items() if len(owners) > 1
    }
    lines: list[str] = []
    for legacy_path, owners in sorted(
        collision_paths.items(), key=lambda item: str(item[0])
    ):
        for repository in sorted(owners):
            host, repo_path = repository.split("/", 1)
            identity = (host, repo_path)
            expected = _canonical_cache_dir(identity)
            if expected.parent != cache_root:
                expected = cache_root / expected.name
            lines.append(
                f"https://{repository}\t{expected}\t"
                f"legacy-origin-collision:{legacy_path}"
            )
    inventory = (("\n".join(lines) + "\n") if lines else "").encode("utf-8")
    return inventory, {
        "schema_version": 1,
        "formal_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "repository_count": len(repositories),
        "collision_path_count": len(collision_paths),
        "collision_repository_count": len(
            {repository for owners in collision_paths.values() for repository in owners}
        ),
        "inventory_line_count": len(lines),
        "inventory_sha256": hashlib.sha256(inventory).hexdigest(),
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    parser.add_argument(
        "--manifest",
        default=str(_STATE_ROOT / "grouped-batches-v1" / "manifest.json"),
    )
    parser.add_argument(
        "--output",
        default=str(_STATE_ROOT / "missing-required-repos.txt"),
    )
    parser.add_argument("--cache-root", default=str(CACHE_DIR))
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).expanduser().resolve()

    def resolve(value: str) -> Path:
        path = Path(value).expanduser()
        return path.resolve() if path.is_absolute() else (repo_root / path).resolve()

    try:
        inventory, summary = build_inventory(
            resolve(args.manifest), cache_root=resolve(args.cache_root)
        )
        _atomic_write(resolve(args.output), inventory)
    except (InventoryError, OSError) as exc:
        print(f"error: {exc}")
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
