"""Locating and identifying the repository clones the cohort study runs over.

Two caches hold clones: the durable project-local one the campaign wrote to,
and the older home-directory one.  Both are keyed by a hashed path, so the
only trustworthy way to name a clone is to ask the clone itself for its
origin and canonicalise that.
"""

from __future__ import annotations

import os
from pathlib import Path

CLONE_DIR_PREFIX = "v2_"


def cache_roots(repo_root: Path) -> list[tuple[str, Path]]:
    """Return (label, path) for every repository cache root, preferred first."""

    import data_refresh_paths
    from cve_analyzer.git_ops import CACHE_DIR

    return [
        ("project", data_refresh_paths.shared_analyzer_cache_root(repo_root) / "repos"),
        ("home", CACHE_DIR),
    ]


def clone_identity(repo_dir: Path) -> str:
    """Return the canonical identity from the clone's own origin, or ``""``."""

    from cve_analyzer.git_ops import run_git
    from cve_analyzer.models import canonical_repository_identity

    try:
        completed = run_git(
            ["git", "-C", str(repo_dir), "config", "--get", "remote.origin.url"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    return canonical_repository_identity(completed.stdout.strip())


def discover_local_clones(repo_root: Path) -> tuple[dict[str, Path], list[dict[str, str]]]:
    """Map canonical identity -> clone path, preferring the project-local cache.

    Returns the mapping plus the cache directories whose origin could not be
    canonicalised, so callers can report them instead of silently dropping them.
    """

    resolved: dict[str, Path] = {}
    unresolved: list[dict[str, str]] = []
    for root_name, root in cache_roots(repo_root):
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if not entry.name.startswith(CLONE_DIR_PREFIX) or not entry.is_dir():
                continue
            identity = clone_identity(entry)
            if not identity:
                unresolved.append({"path": str(entry), "root": root_name})
                continue
            resolved.setdefault(identity, entry)
    return resolved, unresolved


def clone_url(identity: str) -> str:
    """Rebuild an HTTPS clone URL from a canonical ``host/path`` identity."""

    return f"https://{identity}.git"


def directory_size_mb(path: Path) -> float:
    """Return the on-disk size of a directory in MiB (0.0 when unreadable)."""

    total = 0
    for dirpath, dirnames, filenames in os.walk(path, onerror=lambda _e: None):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total / (1024 * 1024)
