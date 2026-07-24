#!/usr/bin/env python3
"""Build the deterministic source-inclusion corpus from frozen adjudications."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

import data_refresh_paths


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_DEFAULT_INPUT = _SCRIPT_DIR / "audit_adjudications.json"
_ALLOWED_LABELS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"})


class CorpusBuildError(RuntimeError):
    """The adjudication source cannot produce a safe deterministic corpus."""


def build_corpus(payload: Any) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise CorpusBuildError("adjudications require schema_version 1")
    entries = payload.get("adjudications")
    if not isinstance(entries, list) or not entries:
        raise CorpusBuildError("adjudications must contain a non-empty array")
    ids: list[str] = []
    labels: Counter[str] = Counter()
    for entry in entries:
        if not isinstance(entry, dict):
            raise CorpusBuildError("every adjudication must be an object")
        subject_id = entry.get("cve_id")
        label = entry.get("label")
        if (
            not isinstance(subject_id, str)
            or not subject_id
            or subject_id != subject_id.strip()
            or any(character.isspace() for character in subject_id)
        ):
            raise CorpusBuildError("every adjudication requires a path-safe cve_id")
        if label not in _ALLOWED_LABELS:
            raise CorpusBuildError(f"invalid adjudication label for {subject_id}")
        ids.append(subject_id)
        labels[str(label)] += 1
    if len(ids) != len(set(ids)):
        raise CorpusBuildError("adjudication cve_id values must be unique")
    encoded = ("\n".join(sorted(ids)) + "\n").encode("utf-8")
    return encoded, {
        "schema_version": 1,
        "subject_count": len(ids),
        "conclusive_count": labels["AI_CAUSAL"] + labels["NOT_AI_CAUSAL"],
        "labels": dict(sorted(labels.items())),
        "output_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=_REPO_ROOT)
    parser.add_argument("--input", type=Path, default=_DEFAULT_INPUT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = args.repo_root.expanduser().resolve()
    source = args.input.expanduser().resolve()
    output = (
        args.output.expanduser().resolve()
        if args.output is not None
        else data_refresh_paths.data_refresh_state_root(repo_root)
        / "adjudicated-corpus-subjects.txt"
    )
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        content, report = build_corpus(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, CorpusBuildError) as exc:
        print(f"adjudicated corpus failed closed: {exc}")
        return 2
    if args.check:
        try:
            current = output.read_bytes()
        except OSError:
            current = b""
        if current != content:
            print(json.dumps({**report, "status": "stale", "path": str(output)}))
            return 2
        print(json.dumps({**report, "status": "current", "path": str(output)}))
        return 0
    _atomic_write(output, content)
    print(json.dumps({**report, "status": "written", "path": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
