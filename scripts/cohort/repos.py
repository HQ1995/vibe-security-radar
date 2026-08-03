"""Locating and identifying the repository clones the cohort study runs over.

Two caches hold clones: the durable project-local one the campaign wrote to,
and the older home-directory one.  Both are keyed by a hashed path, so the
only trustworthy way to name a clone is to ask the clone itself for its
origin and canonicalise that.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


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


def discover_local_clone_groups(
    repo_root: Path,
) -> tuple[dict[str, tuple[Path, ...]], list[dict[str, str]]]:
    """Map canonical identity to every locally available clone path.

    The home cache holds two generations of naming: 121 clones under the
    hashed ``v2_*`` scheme and ~5,900 older clones named directly after their
    repository (``torvalds_linux``, ``libreoffice_core``, ...). Both are real,
    readable git checkouts — restricting discovery to ``v2_*`` made 808 GB of
    already-cloned repositories invisible, which would have re-cloned them.
    Every directory containing a ``.git`` is checked, regardless of name.

    Duplicate clones are intentionally retained.  Their ref sets need not be
    nested: a project-local clone can carry pulled PR refs while an older home
    clone carries remote topic branches.  A recall-first inventory must union
    both rather than silently choosing either one.

    Returns the groups plus cache directories whose origin could not be
    canonicalised, so callers can report them instead of silently dropping
    them.  Paths preserve cache-root preference and lexical order.
    """

    resolved: dict[str, list[Path]] = {}
    unresolved: list[dict[str, str]] = []
    for root_name, root in cache_roots(repo_root):
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if not entry.is_dir() or not (entry / ".git").exists():
                continue
            identity = clone_identity(entry)
            if not identity:
                unresolved.append({"path": str(entry), "root": root_name})
                continue
            paths = resolved.setdefault(identity, [])
            if entry not in paths:
                paths.append(entry)
    return {
        identity: tuple(paths)
        for identity, paths in resolved.items()
    }, unresolved


def discover_local_clones(repo_root: Path) -> tuple[dict[str, Path], list[dict[str, str]]]:
    """Map canonical identity to one preferred clone for single-checkout jobs.

    Consumers that enumerate repository history must use
    :func:`discover_local_clone_groups` and union all clones.  This compatibility
    view remains for jobs that require exactly one worktree to execute Git
    operations; it preserves the historical project-cache-first choice.
    """

    groups, unresolved = discover_local_clone_groups(repo_root)
    return {
        identity: paths[0]
        for identity, paths in groups.items()
        if paths
    }, unresolved


def clone_url(identity: str) -> str:
    """Rebuild an HTTPS clone URL from a canonical ``host/path`` identity."""

    return f"https://{identity}.git"


def directory_size_mb(path: Path) -> float:
    """Return the on-disk size of a directory in MiB (0.0 when unreadable).

    Shells out to ``du`` rather than walking with ``os.walk`` + per-file
    ``lstat``: measured against the cohort's largest clone (66 GB, likely
    millions of loose objects before a gc), the pure-Python walk made the
    frame planner's per-repo size pass effectively unbounded, while ``du``'s
    own C-level walk finishes in a fraction of the time.
    """

    try:
        completed = subprocess.run(
            ["du", "-sk", str(path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return 0.0
    if completed.returncode != 0 or not completed.stdout:
        return 0.0
    try:
        kib = int(completed.stdout.split()[0])
    except (ValueError, IndexError):
        return 0.0
    return kib / 1024
