"""Mixed clone-path policy for this lane only.

Existing active objects stay under EXISTING_ACTIVE_ROOT.
NEW clones and large objects go under NEW_CLONE_ROOT.
Do not move a path that already exists.
"""

from __future__ import annotations

from pathlib import Path

EXISTING_ACTIVE_ROOT = Path("/tmp/ghsa200-worker-clones/delta-even")
NEW_CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones/delta-even")


def existing_path(*parts: str) -> Path:
    return EXISTING_ACTIVE_ROOT.joinpath(*parts)


def new_clone_path(*parts: str) -> Path:
    NEW_CLONE_ROOT.mkdir(parents=True, exist_ok=True)
    return NEW_CLONE_ROOT.joinpath(*parts)


def resolve_existing_or_new(*parts: str) -> Path:
    """Reuse an existing active tree; otherwise return the new-clone destination."""
    current = existing_path(*parts)
    if current.exists():
        return current
    return new_clone_path(*parts)
