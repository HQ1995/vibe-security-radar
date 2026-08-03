#!/usr/bin/env python3
"""Freeze a deterministic prospective batch from a strict pre-history pool."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cohort.prospective_intake import (
    ProspectiveIntakeContractError,
    SOURCE_CLASSES,
    build_prospective_intake,
    canonical_sha256,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", type=Path, required=True)
    parser.add_argument("--exclusions", type=Path, required=True)
    parser.add_argument(
        "--split-id", default="prospective-all-commit-20260801-v1"
    )
    parser.add_argument("--per-stratum", type=int, default=6)
    parser.add_argument(
        "--source-class",
        action="append",
        choices=sorted(SOURCE_CLASSES),
        dest="source_classes",
    )
    parser.add_argument("--minimum-ai-units", type=int, default=8)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _jsonl_text(rows: list[dict[str, object]]) -> str:
    return "".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    pool = _load_jsonl(args.pool)
    exclusions = _load_json(args.exclusions)
    if not isinstance(exclusions, dict):
        raise SystemExit("exclusion projection is not an object")
    try:
        result = build_prospective_intake(
            pool,
            exclusions,
            split_id=args.split_id,
            per_stratum=args.per_stratum,
            minimum_ai_units=args.minimum_ai_units,
            source_classes=args.source_classes,
        )
    except ProspectiveIntakeContractError as exc:
        raise SystemExit(f"prospective intake contract failed: {exc}") from exc

    frozen_at = datetime.now(timezone.utc).isoformat()
    payload = {
        **{key: value for key, value in result.items() if key != "census"},
        "frozen_at": frozen_at,
        "input_provenance": {
            "pool_path": str(args.pool.resolve()),
            "pool_file_sha256": _sha256_file(args.pool),
            "pool_rows_sha256": canonical_sha256(pool),
            "exclusions_path": str(args.exclusions.resolve()),
            "exclusions_file_sha256": _sha256_file(args.exclusions),
            "exclusions_sha256": canonical_sha256(exclusions),
        },
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
    }
    payload["artifact_sha256"] = canonical_sha256(payload)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_write(args.output_dir / "intake.json", _json_text(payload))
    _atomic_write(
        args.output_dir / "selected.jsonl",
        _jsonl_text([dict(row) for row in result["selected"]]),
    )
    _atomic_write(
        args.output_dir / "census.jsonl",
        _jsonl_text([dict(row) for row in result["census"]]),
    )
    print("prospective intake frozen")
    print(f"  selected repositories : {result['selected_repository_count']}")
    print(f"  source classes        : {result['selected_source_class_counts']}")
    print(f"  gate                  : {result['gate_status']}")
    print("  model calls           : 0")
    print(f"  output                : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
