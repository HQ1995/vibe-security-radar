#!/usr/bin/env python3
"""Gate model use on frozen positive-control relation recall."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from cohort.positive_controls import evaluate_positive_controls
from cohort.relations import normalize_repository_aliases


_SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONTROLS = _SCRIPT_DIR / "cohort_positive_controls.json"
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--relation-dir", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--controls", type=Path, default=DEFAULT_CONTROLS)
    parser.add_argument("--repository-aliases", type=Path, default=DEFAULT_ALIASES)
    parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        handle = path.open(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    with handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise SystemExit(f"malformed {path}:{line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_number} is not an object")
            rows.append(row)
    return rows


def _atomic_write_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    controls_payload = _load_json(args.controls)
    alias_payload = _load_json(args.repository_aliases)
    controls = controls_payload.get("controls")
    alias_rows = alias_payload.get("aliases")
    if controls_payload.get("schema_version") != 1 or not isinstance(controls, list):
        raise SystemExit("positive controls must use schema_version 1")
    if alias_payload.get("schema_version") != 1 or not isinstance(alias_rows, list):
        raise SystemExit("repository aliases must use schema_version 1")
    aliases = normalize_repository_aliases(alias_rows)
    result = evaluate_positive_controls(
        controls,
        _load_jsonl(args.relation_dir / "candidates_expanded.jsonl"),
        _load_jsonl(args.candidate_dir / "public_fix_references.jsonl"),
        aliases,
    )
    output = args.output or (args.relation_dir / "control_recall.json")
    _atomic_write_json(output, result)

    print("\nPositive-control recall gate")
    print(
        f"  relation engine : {result['relation_engine_pass_count']}/"
        f"{result['control_count']}"
    )
    print(
        f"  public exact fix: {result['public_exact_fix_pass_count']}/"
        f"{result['control_count']}"
    )
    print(f"  model/API cost  : ${result['model_cost_usd']:.2f}")
    print(f"  gate            : {'PASS' if result['relation_gate_passed'] else 'FAIL'}")
    print(f"  output          : {output}")
    return 0 if result["relation_gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
