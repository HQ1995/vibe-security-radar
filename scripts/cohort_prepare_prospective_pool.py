#!/usr/bin/env python3
"""Project rich local evidence into a strict prospective pre-history pool."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cohort.prospective_intake import (
    ProspectiveIntakeContractError,
    aggregate_ai_exposure,
    build_pre_history_pool,
    build_prior_exclusion_projection,
    canonical_sha256,
    description_associations,
    public_exact_pairs,
)
from cohort.relations import normalize_repository_aliases


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_OUTCOMES = (
    _REPO_ROOT
    / ".ai-slop/state/cohort-v1/outcomes-20260727T032754Z/outcomes.jsonl"
)
DEFAULT_DESCRIPTION_SEARCH = Path.home() / ".cache/cve-analyzer/desc-search"
DEFAULT_PUBLIC_REFERENCES = (
    _REPO_ROOT
    / ".ai-slop/state/cohort-v1/advisory-candidates-controls-20260731-v1"
    / "public_fix_references.jsonl"
)
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"
DEFAULT_ADJUDICATIONS = _SCRIPT_DIR / "audit_adjudications.json"
DEFAULT_VERIFIED_GROUND_TRUTH = _SCRIPT_DIR / "fixtures/verified-ground-truth.json"
DEFAULT_AUDIT_DIRS = (
    _SCRIPT_DIR / "audit_results",
    _SCRIPT_DIR / "audit_recovery_results",
)
DEFAULT_CONTROL_PATHS = tuple(sorted(_SCRIPT_DIR.glob("cohort_*controls.json")))
DEFAULT_RESULT_CACHE = Path.home() / ".cache/cve-analyzer/results"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outcomes", type=Path, default=DEFAULT_OUTCOMES)
    parser.add_argument(
        "--description-search-dir", type=Path, default=DEFAULT_DESCRIPTION_SEARCH
    )
    parser.add_argument(
        "--public-references", type=Path, default=DEFAULT_PUBLIC_REFERENCES
    )
    parser.add_argument("--repository-aliases", type=Path, default=DEFAULT_ALIASES)
    parser.add_argument("--adjudications", type=Path, default=DEFAULT_ADJUDICATIONS)
    parser.add_argument(
        "--verified-ground-truth",
        type=Path,
        default=DEFAULT_VERIFIED_GROUND_TRUTH,
    )
    parser.add_argument("--audit-dir", action="append", type=Path, default=[])
    parser.add_argument("--existing-controls", action="append", type=Path, default=[])
    parser.add_argument("--result-cache-dir", type=Path, default=DEFAULT_RESULT_CACHE)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> Any:
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
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _directory_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


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


def _aliases(path: Path) -> dict[str, str]:
    payload = _load_json(path)
    rows = payload.get("aliases") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or not isinstance(rows, list)
    ):
        raise SystemExit("repository aliases are malformed")
    try:
        return normalize_repository_aliases(rows)
    except ValueError as exc:
        raise SystemExit(f"repository aliases are malformed: {exc}") from exc


def _ground_truth_controls(path: Path) -> dict[str, object]:
    rows = _load_json(path)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise SystemExit("verified ground truth is malformed")
    controls: list[dict[str, str]] = []
    for row in rows:
        advisory = str(row.get("cve_id") or "").strip()
        repository = str(row.get("repo_url") or "").strip()
        if not advisory or not repository:
            raise SystemExit("verified ground truth has an incomplete identity")
        controls.append(
            {"advisory": advisory, "repository_identity": repository}
        )
    return {"controls": controls}


def _audit_inputs(
    directories: list[Path], cache_dir: Path, adjudications_path: Path
) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]], set[str]]:
    audits: dict[str, dict[str, object]] = {}
    for directory in directories:
        for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
            value = _load_json(path)
            if isinstance(value, dict):
                audits[path.stem] = value
    adjudicated: set[str] = set()
    ledger = _load_json(adjudications_path)
    rows = ledger.get("adjudications") if isinstance(ledger, dict) else None
    if not isinstance(rows, list):
        raise SystemExit("adjudication ledger is malformed")
    for row in rows:
        if not isinstance(row, dict):
            raise SystemExit("adjudication ledger contains a non-object row")
        advisory = str(row.get("cve_id") or "").strip()
        if advisory:
            adjudicated.add(advisory)
    all_advisories = set(audits) | adjudicated
    cached: dict[str, dict[str, object]] = {}
    for advisory in sorted(all_advisories):
        path = cache_dir / f"{advisory}.json"
        if not path.is_file() or path.is_symlink():
            continue
        value = _load_json(path)
        if isinstance(value, dict):
            cached[advisory] = value
    return audits, cached, adjudicated


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    aliases = _aliases(args.repository_aliases)
    outcome_rows = _load_jsonl(args.outcomes)
    public_rows = _load_jsonl(args.public_references)
    description_paths = sorted(args.description_search_dir.glob("*.json"))
    description_payloads: list[dict[str, object]] = []
    unreadable_description_count = 0
    for path in description_paths:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            unreadable_description_count += 1
            continue
        if isinstance(value, dict):
            description_payloads.append(value)
        else:
            unreadable_description_count += 1

    control_paths = args.existing_controls or list(DEFAULT_CONTROL_PATHS)
    controls: list[dict[str, object]] = []
    for path in control_paths:
        value = _load_json(path)
        if not isinstance(value, dict):
            raise SystemExit(f"control payload is not an object: {path}")
        controls.append(value)
    controls.append(_ground_truth_controls(args.verified_ground_truth))
    audit_dirs = args.audit_dir or list(DEFAULT_AUDIT_DIRS)
    audits, cached, adjudicated = _audit_inputs(
        audit_dirs, args.result_cache_dir, args.adjudications
    )
    try:
        exposure = aggregate_ai_exposure(outcome_rows, aliases)
        associations, association_stats = description_associations(
            description_payloads, aliases
        )
        exact_pairs = public_exact_pairs(public_rows, aliases)
        pool, pool_stats = build_pre_history_pool(
            associations, exposure, exact_pairs
        )
        exclusions = build_prior_exclusion_projection(
            control_payloads=controls,
            audit_records_by_advisory=audits,
            cached_results_by_advisory=cached,
            adjudicated_advisories=adjudicated,
            aliases=aliases,
        )
    except ProspectiveIntakeContractError as exc:
        raise SystemExit(f"prospective projection contract failed: {exc}") from exc

    args.output_dir.mkdir(parents=True, exist_ok=False)
    pool_path = args.output_dir / "pool.jsonl"
    exclusions_path = args.output_dir / "exclusions.json"
    _atomic_write(pool_path, _jsonl_text(pool))
    _atomic_write(exclusions_path, _json_text(exclusions))
    summary = {
        "schema_version": 1,
        "artifact_kind": "prospective_pre_history_pool_projection",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "projection_contract": (
            "pool.jsonl contains only repository/advisory identity, aggregate AI "
            "exposure, source-class presence, and a deterministic candidate ID. "
            "No commit SHA, message, description, search result, SZZ output, or audit "
            "judgment crosses into selection."
        ),
        "claim_boundary": (
            "The legacy outcome file is used only as an AI-exposure inventory; this "
            "artifact does not inherit its maturity window as an outcome population."
        ),
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
        "counts": {
            **pool_stats,
            "ai_repository_count": len(exposure),
            "public_exact_pair_count": len(exact_pairs),
            "description_files_seen": len(description_paths),
            "description_files_unreadable": unreadable_description_count,
            "excluded_advisory_count": len(exclusions["advisories"]),
            "excluded_repository_count": len(exclusions["repositories"]),
        },
        "description_association_stats": association_stats,
        "pool_rows_sha256": canonical_sha256(pool),
        "exclusions_sha256": canonical_sha256(exclusions),
        "input_provenance": {
            "outcomes_path": str(args.outcomes.resolve()),
            "outcomes_sha256": _sha256_file(args.outcomes),
            "public_references_path": str(args.public_references.resolve()),
            "public_references_sha256": _sha256_file(args.public_references),
            "description_search_dir": str(args.description_search_dir.resolve()),
            "description_search_file_count": len(description_paths),
            "description_search_manifest_sha256": _directory_digest(description_paths),
            "repository_aliases_path": str(args.repository_aliases.resolve()),
            "repository_aliases_sha256": _sha256_file(args.repository_aliases),
            "adjudications_path": str(args.adjudications.resolve()),
            "adjudications_sha256": _sha256_file(args.adjudications),
            "verified_ground_truth_path": str(
                args.verified_ground_truth.resolve()
            ),
            "verified_ground_truth_sha256": _sha256_file(
                args.verified_ground_truth
            ),
            "control_paths": [str(path.resolve()) for path in control_paths],
            "control_sha256": {
                str(path.resolve()): _sha256_file(path) for path in control_paths
            },
            "audit_directories": [str(path.resolve()) for path in audit_dirs],
            "audit_record_count": len(audits),
            "cached_audit_result_count": len(cached),
        },
    }
    _atomic_write(args.output_dir / "summary.json", _json_text(summary))
    print("prospective pre-history pool projected")
    print(f"  strict pool rows      : {len(pool):,}")
    print(f"  AI repositories       : {len(exposure):,}")
    print(f"  prior repositories    : {len(exclusions['repositories']):,}")
    print("  model calls           : 0")
    print(f"  output                : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
