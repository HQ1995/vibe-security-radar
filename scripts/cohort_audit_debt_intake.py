#!/usr/bin/env python3
"""Freeze a repository-disjoint queue for repairing known-positive audit debt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cohort.audit_debt_intake import (
    AuditDebtIntakeContractError,
    build_audit_debt_intake,
    canonical_sha256,
)
from cohort.relations import normalize_repository_aliases


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"
DEFAULT_CONTROL_PATHS = (
    _SCRIPT_DIR / "cohort_positive_controls.json",
    _SCRIPT_DIR / "cohort_heldout_controls.json",
    _SCRIPT_DIR / "cohort_expansion_controls.json",
    _SCRIPT_DIR / "cohort_complex_controls.json",
    _SCRIPT_DIR / "cohort_complex_heldout_controls.json",
)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census", type=Path, required=True)
    parser.add_argument(
        "--existing-controls",
        action="append",
        type=Path,
        help="prior control JSON; repeatable (defaults to every frozen split)",
    )
    parser.add_argument("--repository-aliases", type=Path, default=DEFAULT_ALIASES)
    parser.add_argument("--minimum-new-repositories", type=int, default=5)
    parser.add_argument(
        "--split-id", default="audit-debt-contract-recovery-20260801-v1"
    )
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
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise SystemExit(f"{path}:{line_number}: row is not an object")
            rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(_REPO_ROOT))
    except ValueError:
        return str(resolved)


def _atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
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
    census_rows = _load_jsonl(args.census)
    control_paths = args.existing_controls or list(DEFAULT_CONTROL_PATHS)
    control_payloads: list[dict[str, object]] = []
    for path in control_paths:
        value = _load_json(path)
        if not isinstance(value, dict):
            raise SystemExit(f"control payload is not an object: {path}")
        control_payloads.append(value)
    alias_payload = _load_json(args.repository_aliases)
    if not isinstance(alias_payload, dict) or alias_payload.get("schema_version") != 1:
        raise SystemExit("repository aliases must use schema_version 1")
    alias_rows = alias_payload.get("aliases")
    if not isinstance(alias_rows, list) or any(
        not isinstance(row, dict) for row in alias_rows
    ):
        raise SystemExit("repository aliases are malformed")
    try:
        aliases = normalize_repository_aliases(alias_rows)
        result = build_audit_debt_intake(
            census_rows,
            control_payloads=control_payloads,
            aliases=aliases,
            minimum_new_repositories=args.minimum_new_repositories,
        )
    except (AuditDebtIntakeContractError, ValueError) as exc:
        raise SystemExit(f"audit-debt intake contract failed: {exc}") from exc

    frozen_at = datetime.now(timezone.utc).isoformat()
    payload = {
        **result,
        "split_id": args.split_id,
        "frozen_at": frozen_at,
        "input_provenance": {
            "census_path": _display_path(args.census),
            "census_file_sha256": _sha256_file(args.census),
            "census_rows_sha256": canonical_sha256(census_rows),
            "repository_aliases_path": _display_path(args.repository_aliases),
            "repository_aliases_sha256": _sha256_file(args.repository_aliases),
            "prior_control_paths": [_display_path(path) for path in control_paths],
            "prior_control_sha256": {
                _display_path(path): _sha256_file(path) for path in control_paths
            },
        },
    }
    payload["artifact_sha256"] = canonical_sha256(payload)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_write(args.output_dir / "intake.json", _json_text(payload))
    _atomic_write(
        args.output_dir / "audit_queue.jsonl",
        _jsonl_text([dict(row) for row in payload["selected"]]),
    )
    _atomic_write(
        args.output_dir / "census.jsonl",
        _jsonl_text([dict(row) for row in payload["census"]]),
    )
    print("audit-debt intake frozen")
    print(
        "  debt accounted       : "
        f"{payload['population']['audit_contract_missing_count']}"
    )
    print(f"  new repositories     : {payload['selected_repository_count']}")
    print(f"  gate                  : {payload['gate_status']}")
    print("  model calls           : 0")
    print(f"  output                : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
