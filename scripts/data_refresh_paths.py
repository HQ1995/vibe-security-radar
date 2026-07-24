"""Canonical project-owned paths for data-refresh runtime artifacts."""

from __future__ import annotations

from pathlib import Path


PROJECT_RUNTIME_DIRECTORY = ".ai-slop"
DATA_REFRESH_STATE_RELATIVE = (
    Path(PROJECT_RUNTIME_DIRECTORY) / "state" / "data-refresh"
)
DATA_REFRESH_LOG_RELATIVE = Path(PROJECT_RUNTIME_DIRECTORY) / "logs" / "data-refresh"
SHARED_ANALYZER_CACHE_RELATIVE = (
    Path(PROJECT_RUNTIME_DIRECTORY) / "cache" / "cve-analyzer"
)


def data_refresh_state_root(repo_root: Path) -> Path:
    """Return the repository-local durable state root."""

    return repo_root.resolve() / DATA_REFRESH_STATE_RELATIVE


def data_refresh_log_root(repo_root: Path) -> Path:
    """Return the repository-local append-only log root."""

    return repo_root.resolve() / DATA_REFRESH_LOG_RELATIVE


def shared_analyzer_cache_root(repo_root: Path) -> Path:
    """Return the durable project-local cache shared across campaign epochs."""

    return repo_root.resolve() / SHARED_ANALYZER_CACHE_RELATIVE
