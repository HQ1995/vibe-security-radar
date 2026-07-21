#!/usr/bin/env python3
"""Content-address the analyzer semantics that make campaign results reusable.

The epoch deliberately excludes advisory snapshots, generated plans, campaign
receipts, and publication code.  Those inputs have their own independent
digests and including them here would create a circular cache key.
"""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any


class AnalysisContractError(RuntimeError):
    """The analyzer contract could not be captured safely and completely."""


def _regular_file_bytes(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AnalysisContractError(f"missing analysis contract input {label}: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AnalysisContractError(
            f"analysis contract input must be a regular non-symlink file: {path}"
        )
    try:
        data = path.read_bytes()
        current = path.lstat()
    except OSError as exc:
        raise AnalysisContractError(f"cannot read analysis contract input {path}: {exc}") from exc
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    current_identity = (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )
    if current_identity != identity or len(data) != metadata.st_size:
        raise AnalysisContractError(f"analysis contract input changed while read: {path}")
    return data


def _contract_paths(repo_root: Path) -> tuple[tuple[str, Path], ...]:
    root = repo_root.resolve()
    analyzer = root / "cve-analyzer"
    source = analyzer / "src"
    if source.is_symlink() or not source.is_dir():
        raise AnalysisContractError(f"analyzer source tree is missing or unsafe: {source}")

    paths = [
        ("cve-analyzer/pyproject.toml", analyzer / "pyproject.toml"),
        ("cve-analyzer/uv.lock", analyzer / "uv.lock"),
    ]
    source_paths = sorted(
        path
        for path in source.rglob("*.py")
        if "__pycache__" not in path.parts
    )
    if not source_paths:
        raise AnalysisContractError(f"analyzer source tree contains no Python files: {source}")
    for path in source_paths:
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except ValueError as exc:
            raise AnalysisContractError(f"analysis contract input escapes repository: {path}") from exc
        paths.append((relative, path))
    labels = [label for label, _path in paths]
    if len(labels) != len(set(labels)):
        raise AnalysisContractError("analysis contract contains duplicate path labels")
    return tuple(sorted(paths))


def analysis_contract_epoch(repo_root: Path) -> dict[str, Any]:
    """Return the stable analyzer epoch and its complete input manifest."""

    digest = hashlib.sha256()
    inputs: list[dict[str, Any]] = []
    signature_sha256: str | None = None
    for label, path in _contract_paths(repo_root):
        data = _regular_file_bytes(path, label)
        content_sha256 = hashlib.sha256(data).hexdigest()
        label_bytes = label.encode("utf-8")
        digest.update(len(label_bytes).to_bytes(8, "big"))
        digest.update(label_bytes)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        inputs.append(
            {
                "path": label,
                "size_bytes": len(data),
                "sha256": content_sha256,
            }
        )
        if label == "cve-analyzer/src/cve_analyzer/ai_signatures.py":
            signature_sha256 = content_sha256
    if signature_sha256 is None:
        raise AnalysisContractError("AI signature registry is absent from analyzer source")
    return {
        "schema_version": 1,
        "sha256": digest.hexdigest(),
        "signature_sha256": signature_sha256,
        "input_count": len(inputs),
        "inputs": inputs,
        "excluded_input_classes": [
            "advisory_source_snapshots",
            "campaign_plans",
            "campaign_receipts",
            "publication_artifacts",
        ],
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        epoch = analysis_contract_epoch(args.repo_root)
    except AnalysisContractError as exc:
        parser.error(str(exc))
    print(json.dumps(epoch, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
