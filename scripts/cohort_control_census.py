#!/usr/bin/env python3
"""Freeze a fail-closed census of audited AI-causal control candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cohort.control_census import (
    ControlCensusContractError,
    build_control_candidate_census,
)
from cohort.relations import normalize_repository_aliases


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_ADJUDICATIONS = _SCRIPT_DIR / "audit_adjudications.json"
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"
DEFAULT_EXISTING_CONTROLS = (
    _SCRIPT_DIR / "cohort_positive_controls.json",
    _SCRIPT_DIR / "cohort_heldout_controls.json",
)
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "cve-analyzer" / "results"
_SAFE_ADVISORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--adjudications", type=Path, default=DEFAULT_ADJUDICATIONS)
    parser.add_argument("--audit-root", type=Path, default=_REPO_ROOT)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--repository-aliases", type=Path, default=DEFAULT_ALIASES)
    parser.add_argument(
        "--existing-controls",
        type=Path,
        action="append",
        default=[],
        help="repeatable; defaults to the development and first held-out ledgers",
    )
    parser.add_argument("--minimum-confidence", type=float, default=0.98)
    parser.add_argument("--split-id", default="recall-first-heldout-expansion-v1")
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"input is missing or unsafe: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read JSON input {path}: {exc}") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _atomic_write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False)
                + "\n"
            )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _load_aliases(path: Path) -> dict[str, str]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise SystemExit("repository aliases must use schema_version 1")
    rows = payload.get("aliases")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise SystemExit("repository aliases must contain object rows")
    try:
        return normalize_repository_aliases(rows)
    except ValueError as exc:
        raise SystemExit(f"invalid repository aliases: {exc}") from exc


def _load_existing_controls(paths: list[Path]) -> list[dict[str, object]]:
    controls: list[dict[str, object]] = []
    for path in paths:
        payload = _load_json(path)
        rows = payload.get("controls") if isinstance(payload, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise SystemExit(f"existing controls are malformed: {path}")
        controls.extend(rows)
    return controls


def _source_path(audit_root: Path, source: str) -> Path | None:
    relative = Path(source)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    root = audit_root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None
    return path


def _repository_source(advisory: str) -> str:
    relative = Path("web") / "data" / "cves" / f"{advisory}.json"
    path = _REPO_ROOT / relative
    return str(relative) if path.is_file() and not path.is_symlink() else ""


def _main(args: argparse.Namespace) -> int:
    ledger = _load_json(args.adjudications)
    adjudications = ledger.get("adjudications") if isinstance(ledger, dict) else None
    if not isinstance(adjudications, list) or any(
        not isinstance(row, dict) for row in adjudications
    ):
        raise SystemExit("adjudication ledger is malformed")
    aliases = _load_aliases(args.repository_aliases)
    existing_paths = args.existing_controls or list(DEFAULT_EXISTING_CONTROLS)
    existing_controls = _load_existing_controls(existing_paths)

    audits: dict[str, object] = {}
    audit_hashes: dict[str, str] = {}
    cached: dict[str, dict[str, object]] = {}
    cache_hashes: dict[str, str] = {}
    for row in adjudications:
        if row.get("label") != "AI_CAUSAL":
            continue
        advisory = str(row.get("cve_id") or "")
        source = str(row.get("source") or "")
        source_path = _source_path(args.audit_root, source)
        if source_path is not None and source_path.is_file() and not source_path.is_symlink():
            audits[source] = _load_json(source_path)
            audit_hashes[source] = _sha256_file(source_path)
        if _SAFE_ADVISORY_RE.fullmatch(advisory):
            cache_path = args.cache_dir / f"{advisory}.json"
            if cache_path.is_file() and not cache_path.is_symlink():
                raw = _load_json(cache_path)
                if isinstance(raw, dict):
                    cached[advisory] = raw
                    cache_hashes[advisory] = _sha256_file(cache_path)

    try:
        result = build_control_candidate_census(
            adjudications,
            audits,
            cached,
            existing_controls=existing_controls,
            aliases=aliases,
            minimum_confidence=args.minimum_confidence,
        )
    except ControlCensusContractError as exc:
        raise SystemExit(f"control census contract failed: {exc}") from exc

    selected_controls = [dict(row) for row in result["selected_controls"]]
    for control in selected_controls:
        repository_source = _repository_source(str(control["advisory"]))
        if repository_source:
            control["repository_source"] = repository_source
    selected_payload = {
        "schema_version": 1,
        "split_id": args.split_id,
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "minimum_confidence": args.minimum_confidence,
        "selection_rule": (
            "From every independently adjudicated AI_CAUSAL row, select at most one"
            " lexicographically first advisory per repository after excluding all"
            " development and prior-heldout advisories/repositories; require the"
            " current TRUE_POSITIVE audit contract, explicit AI authorship, one"
            " structured atomic origin, one exact fix, at most one audited landed"
            " squash, and no cross-repository origin. All other rows remain in the"
            " census with an explicit non-selected disposition."
        ),
        "controls": selected_controls,
    }
    summary = {
        **{key: value for key, value in result.items() if key != "census"},
        "selected_controls": selected_controls,
        "frozen_at": selected_payload["frozen_at"],
        "split_id": args.split_id,
        "input_provenance": {
            "adjudications_path": str(args.adjudications),
            "adjudications_sha256": _sha256_file(args.adjudications),
            "repository_aliases_path": str(args.repository_aliases),
            "repository_aliases_sha256": _sha256_file(args.repository_aliases),
            "existing_control_paths": [str(path) for path in existing_paths],
            "existing_control_sha256": {
                str(path): _sha256_file(path) for path in existing_paths
            },
            "audit_source_sha256": dict(sorted(audit_hashes.items())),
            "cached_result_sha256": dict(sorted(cache_hashes.items())),
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_write_jsonl(args.output_dir / "census.jsonl", result["census"])
    _atomic_write_json(args.output_dir / "selected_controls.json", selected_payload)
    _atomic_write_json(args.output_dir / "summary.json", summary)
    print("AI-causal control census frozen")
    print(f"  AI_CAUSAL accounted : {result['accounted_count']}/{result['ai_causal_count']}")
    print(f"  atomic selected     : {result['selected_count']}")
    print(f"  edge status         : {result['edge_status_counts']}")
    print(f"  selection status    : {result['selection_status_counts']}")
    print(f"  output              : {args.output_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return _main(_parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
