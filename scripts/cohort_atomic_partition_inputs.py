#!/usr/bin/env python3
"""Partition global atomic-candidate inputs by repository in one pass."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path


_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repositories", type=Path, required=True)
    parser.add_argument("--ai-commits", type=Path, required=True)
    parser.add_argument("--expanded-candidates", type=Path, required=True)
    parser.add_argument("--fix-roots", type=Path, required=True)
    parser.add_argument("--fix-source-observations", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _repositories(path: Path) -> list[dict[str, str]]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or not rows:
        raise SystemExit("repositories must be a non-empty JSON array")
    required = {"repository_identity", "repository_path"}
    normalized: list[dict[str, str]] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict) or not required <= set(row) <= required | {"slug"}:
            raise SystemExit("repository rows have invalid keys")
        value = {key: str(row[key]) for key in required}
        value["slug"] = str(row.get("slug") or f"repo-{index}")
        if (
            not value["repository_identity"]
            or not value["repository_path"]
            or not _SLUG_RE.fullmatch(value["slug"])
        ):
            raise SystemExit("repository row has invalid values")
        normalized.append(value)
    if len({row["slug"] for row in normalized}) != len(normalized) or len(
        {row["repository_identity"] for row in normalized}
    ) != len(normalized):
        raise SystemExit("repository slugs and identities must be unique")
    return normalized


def partition_inputs(
    repositories: list[dict[str, str]],
    sources: dict[str, Path],
    output_dir: Path,
) -> dict[str, object]:
    if output_dir.exists():
        raise SystemExit(f"output directory already exists: {output_dir}")
    by_identity = {row["repository_identity"]: row["slug"] for row in repositories}
    counts = {row["slug"]: {name: 0 for name in sources} for row in repositories}
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{output_dir.name}.", dir=output_dir.parent
    ) as temporary:
        temporary_path = Path(temporary)
        for row in repositories:
            (temporary_path / row["slug"]).mkdir()
        for name, source in sources.items():
            with ExitStack() as stack:
                handles = {
                    row["slug"]: stack.enter_context(
                        (temporary_path / row["slug"] / f"{name}.jsonl").open(
                            "w", encoding="utf-8"
                        )
                    )
                    for row in repositories
                }
                with source.open(encoding="utf-8") as source_handle:
                    for line_number, line in enumerate(source_handle, start=1):
                        if not line.strip():
                            continue
                        value = json.loads(line)
                        if not isinstance(value, dict):
                            raise SystemExit(f"{source}:{line_number} is not an object")
                        slug = by_identity.get(str(value.get("repository_identity") or ""))
                        if slug is not None:
                            handles[slug].write(line if line.endswith("\n") else line + "\n")
                            counts[slug][name] += 1
        summary = {
            "schema_version": 1,
            "artifact_kind": "repository_partitioned_atomic_candidate_inputs",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "repositories": repositories,
            "row_counts": counts,
            "partitions": {
                row["slug"]: {
                    name: hashlib.sha256(
                        (temporary_path / row["slug"] / f"{name}.jsonl").read_bytes()
                    ).hexdigest()
                    for name in sources
                }
                for row in repositories
            },
            "claim_boundary": "lossless repository partition only; no causal labels",
        }
        (temporary_path / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary_path, output_dir)
    return summary


def main() -> int:
    args = _parse_args()
    repositories = _repositories(args.repositories)
    summary = partition_inputs(
        repositories,
        {
            "ai-commits": args.ai_commits,
            "expanded-candidates": args.expanded_candidates,
            "fix-roots": args.fix_roots,
            "fix-source-observations": args.fix_source_observations,
        },
        args.output_dir,
    )
    print(json.dumps(summary["row_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
