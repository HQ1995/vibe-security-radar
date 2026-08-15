#!/usr/bin/env python3
"""Evaluate recall-first fix sources against a sealed fix-only manifest."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from cohort.fix_manifest import FixManifestContractError, normalize_fix_manifest
from cohort.fix_sources import FixSourceContractError, evaluate_fix_source_recall
from cohort.relations import normalize_repository_aliases


_SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--fix-manifest", type=Path, required=True)
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
    aliases_payload = _load_json(args.repository_aliases)
    alias_rows = aliases_payload.get("aliases")
    if aliases_payload.get("schema_version") != 1 or not isinstance(alias_rows, list):
        raise SystemExit("repository aliases must use schema_version 1")
    try:
        aliases = normalize_repository_aliases(alias_rows)
        manifest = normalize_fix_manifest(_load_json(args.fix_manifest), aliases)
        result = evaluate_fix_source_recall(
            manifest["fixes"],
            _load_jsonl(args.candidate_dir / "fix_source_observations.jsonl"),
            _load_jsonl(
                args.candidate_dir / "repository_fallback_candidates.jsonl"
            ),
        )
    except (FixManifestContractError, FixSourceContractError, ValueError) as exc:
        raise SystemExit(f"invalid fix-source recall input: {exc}") from exc

    output = args.output or (args.candidate_dir / "fix_source_recall.json")
    _atomic_write_json(output, result)
    print("\nFix-source recall gate")
    print(
        f"  public exact      : {result['public_exact_pass_count']}/"
        f"{result['fix_obligation_count']}"
    )
    print(
        f"  + enriched select : {result['enriched_selected_union_pass_count']}/"
        f"{result['fix_obligation_count']}"
    )
    print(
        f"  + all carriers    : {result['source_candidate_pass_count']}/"
        f"{result['fix_obligation_count']}"
    )
    print(
        f"  repo fallback     : {result['repository_fallback_pass_count']}/"
        f"{result['fix_obligation_count']}"
    )
    print("  model/API cost   : $0.00")
    print(f"  output           : {output}")
    passed = bool(
        result["source_candidate_gate_passed"]
        and result["repository_fallback_gate_passed"]
    )
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
