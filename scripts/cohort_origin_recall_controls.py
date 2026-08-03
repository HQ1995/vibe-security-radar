#!/usr/bin/env python3
"""Generate blind origin queues from fix-only inputs, then score recall separately."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

from cohort.fix_manifest import normalize_fix_manifest
from cohort.origin_controls import flatten_origin_controls
from cohort.origin_signals import candidate_signal_row, prioritize_candidate_rows
from cohort.relations import (
    canonical_repository_identity,
    normalize_repository_aliases,
)
from cohort.repos import clone_identity, discover_local_clones
from cohort.root_adjudication import canonical_sha256
from cohort_origin_signal_pilot import collect_origin_signals


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"
_BUDGETS = (1, 5, 10, 25, 50, 100)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate")
    generate.add_argument("--fix-manifest", type=Path, required=True)
    generate.add_argument("--aliases", type=Path, default=DEFAULT_ALIASES)
    generate.add_argument(
        "--repository-path",
        action="append",
        default=[],
        metavar="IDENTITY=PATH",
    )
    generate.add_argument("--repository-identity")
    generate.add_argument("--repo-timeout", type=int, default=120)
    generate.add_argument("--output-dir", type=Path, required=True)

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--generated-dir", type=Path, required=True)
    evaluate.add_argument("--controls", type=Path, required=True)
    evaluate.add_argument("--repository-identity")
    evaluate.add_argument("--output", type=Path, required=True)
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


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _aliases(path: Path) -> dict[str, str]:
    payload = _load_json(path)
    if not isinstance(payload, Mapping) or not isinstance(payload.get("aliases"), list):
        raise SystemExit("repository aliases are malformed")
    return normalize_repository_aliases(payload["aliases"])


def _explicit_repositories(
    specifications: list[str], aliases: Mapping[str, str]
) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for specification in specifications:
        identity_text, separator, path_text = specification.partition("=")
        if not separator:
            raise SystemExit("repository-path must use IDENTITY=PATH")
        identity = canonical_repository_identity(identity_text, aliases)
        path = Path(path_text).resolve()
        if not path.is_dir() or not (path / ".git").exists():
            raise SystemExit(f"repository path is not a Git checkout: {path}")
        observed_identity = canonical_repository_identity(clone_identity(path), aliases)
        if observed_identity != identity:
            raise SystemExit(
                f"repository path identity mismatch: expected {identity}, got {observed_identity}"
            )
        if identity in result and result[identity] != path:
            raise SystemExit(f"duplicate repository path for {identity}")
        result[identity] = path
    return result


def _signal_set(collected: Mapping[str, object], name: str) -> set[str]:
    value = collected.get(name)
    if not isinstance(value, set):
        raise SystemExit(f"collector returned malformed {name}")
    return value


def _rank_collected(collected: Mapping[str, object]) -> list[dict[str, object]]:
    copy_aware = _signal_set(collected, "copy_aware")
    file_local = _signal_set(collected, "file_local")
    add_context = _signal_set(collected, "add_context")
    function_history = _signal_set(collected, "function_history")
    pickaxe_history = _signal_set(collected, "pickaxe_history")
    file_history = _signal_set(collected, "file_history")
    cross_file_surface = _signal_set(collected, "cross_file_surface")
    cross_file_bridge = _signal_set(collected, "cross_file_bridge")
    materialized = (
        copy_aware
        | file_local
        | add_context
        | function_history
        | pickaxe_history
        | file_history
        | cross_file_surface
        | cross_file_bridge
    )
    rows = [
        candidate_signal_row(
            sha=sha,
            in_copy_aware_szz=sha in copy_aware,
            in_file_local_szz=sha in file_local,
            in_file_history=sha in file_history,
            observed_ai_unit=False,
            in_add_context_blame=sha in add_context,
            in_function_history=sha in function_history,
            in_pickaxe_history=sha in pickaxe_history,
            in_cross_file_security_bridge=sha in cross_file_bridge,
            in_cross_file_surface_history=sha in cross_file_surface,
        )
        for sha in sorted(materialized)
    ]
    return prioritize_candidate_rows(rows)


def _generate(args: argparse.Namespace) -> int:
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.repo_timeout < 1:
        raise SystemExit("repo-timeout must be positive")
    aliases = _aliases(args.aliases)
    manifest_payload = _load_json(args.fix_manifest)
    if not isinstance(manifest_payload, Mapping):
        raise SystemExit("fix manifest is malformed")
    manifest = normalize_fix_manifest(manifest_payload, aliases)
    requested_identity = (
        canonical_repository_identity(args.repository_identity, aliases)
        if args.repository_identity
        else ""
    )
    fixes = manifest["fixes"]
    assert isinstance(fixes, list)
    selected_fixes = [
        row
        for row in fixes
        if not requested_identity or row["repository_identity"] == requested_identity
    ]
    if not selected_fixes:
        raise SystemExit("no fix rows match the requested repository")

    repositories = _explicit_repositories(args.repository_path, aliases)
    unresolved_clones: list[dict[str, str]] = []
    if not repositories:
        repositories, unresolved_clones = discover_local_clones(_REPO_ROOT)

    candidate_rows: list[dict[str, object]] = []
    fix_rows: list[dict[str, object]] = []
    bridge_rows: list[dict[str, object]] = []
    for fix in selected_fixes:
        assert isinstance(fix, Mapping)
        advisory = str(fix["advisory"])
        identity = str(fix["repository_identity"])
        fix_sha = str(fix["fix_sha"])
        repo = repositories.get(identity)
        if repo is None:
            fix_rows.append(
                {
                    "advisory": advisory,
                    "repository_identity": identity,
                    "fix_sha": fix_sha,
                    "status": "BLOCKED",
                    "reason": "local_repository_unavailable",
                }
            )
            continue
        global_arguments = ["--shallow-file", ""] if (repo / ".git" / "shallow").exists() else []
        try:
            collected = collect_origin_signals(
                repo,
                global_arguments,
                fix_sha,
                {},
                timeout=args.repo_timeout,
            )
        except SystemExit as exc:
            fix_rows.append(
                {
                    "advisory": advisory,
                    "repository_identity": identity,
                    "fix_sha": fix_sha,
                    "repository_path": str(repo),
                    "status": "BLOCKED",
                    "reason": str(exc),
                }
            )
            continue
        ranked = _rank_collected(collected)
        for row in ranked:
            row.update(
                {
                    "advisory": advisory,
                    "repository_identity": identity,
                    "fix_sha": fix_sha,
                    "ai_priority_not_evaluated": True,
                }
            )
            candidate_rows.append(row)
        evidence = collected.get("bridge_evidence")
        assert isinstance(evidence, list)
        for row in evidence:
            assert isinstance(row, dict)
            bridge_rows.append(
                {
                    **row,
                    "advisory": advisory,
                    "repository_identity": identity,
                    "fix_sha": fix_sha,
                }
            )
        gaps = collected.get("coverage_gaps")
        assert isinstance(gaps, list)
        ancestors = _signal_set(collected, "ancestors")
        fix_rows.append(
            {
                "advisory": advisory,
                "repository_identity": identity,
                "fix_sha": fix_sha,
                "repository_path": str(repo),
                "status": "RESOLVED" if not gaps else "BLOCKED",
                "reason": "" if not gaps else "origin_signal_coverage_gap",
                "coverage_gaps": gaps,
                "ancestor_fallback_candidate_count": len(ancestors),
                "materialized_candidate_count": len(ranked),
                "add_only_hunk_count": collected["add_only_hunk_count"],
                "guard_like_hunk_count": collected["guard_like_hunk_count"],
                "fix_has_global_guard": collected["fix_has_global_guard"],
                "pickaxe_token_count": collected["pickaxe_token_count"],
                "pickaxe_query_count": collected["pickaxe_query_count"],
            }
        )

    candidate_rows.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]),
            str(row["fix_sha"]),
            int(row["priority_rank"]),
        )
    )
    fix_rows.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]),
            str(row["fix_sha"]),
        )
    )
    bridge_rows.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]),
            str(row["fix_sha"]),
            str(row["sha"]),
        )
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_jsonl(args.output_dir / "candidates.jsonl", candidate_rows)
    _atomic_jsonl(args.output_dir / "fixes.jsonl", fix_rows)
    _atomic_jsonl(args.output_dir / "cross_file_bridge.jsonl", bridge_rows)
    summary = {
        "schema_version": 1,
        "artifact_kind": "blind_origin_recall_control_generation",
        "gate_status": (
            "READY_FOR_SEPARATE_EVALUATION"
            if fix_rows and all(row["status"] == "RESOLVED" for row in fix_rows)
            else "BLOCKED"
        ),
        "split_id": manifest["split_id"],
        "requested_repository_identity": requested_identity,
        "generation_process_boundary": "sealed_fix_only_no_golden_ledger_read",
        "ai_priority_mode": "disabled_for_structural_signal_recall",
        "fix_manifest_sha256": canonical_sha256(manifest),
        "fix_count": len(fix_rows),
        "resolved_fix_count": sum(row["status"] == "RESOLVED" for row in fix_rows),
        "blocked_fix_count": sum(row["status"] == "BLOCKED" for row in fix_rows),
        "candidate_count": len(candidate_rows),
        "unresolved_clone_count": len(unresolved_clones),
        "candidate_rows_sha256": canonical_sha256(candidate_rows),
        "fix_rows_sha256": canonical_sha256(fix_rows),
        "bridge_rows_sha256": canonical_sha256(bridge_rows),
        "claim_boundary": (
            "Generation reads fix-only rows and local Git history. It deliberately "
            "does not read origins, expected relations, or AI-attribution labels."
        ),
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print("blind origin control generation frozen")
    print(f"  fixes      : {len(fix_rows)}")
    print(f"  resolved   : {summary['resolved_fix_count']}")
    print(f"  candidates : {len(candidate_rows)}")
    print(f"  gate        : {summary['gate_status']}")
    print(f"  output      : {args.output_dir}")
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    generated_summary = _load_json(args.generated_dir / "summary.json")
    if not isinstance(generated_summary, Mapping):
        raise SystemExit("generated summary is malformed")
    candidates = _load_jsonl(args.generated_dir / "candidates.jsonl")
    fixes = _load_jsonl(args.generated_dir / "fixes.jsonl")
    if canonical_sha256(candidates) != generated_summary.get("candidate_rows_sha256"):
        raise SystemExit("generated candidate digest mismatch")
    if canonical_sha256(fixes) != generated_summary.get("fix_rows_sha256"):
        raise SystemExit("generated fix digest mismatch")
    controls_payload = _load_json(args.controls)
    if not isinstance(controls_payload, Mapping):
        raise SystemExit("control ledger is malformed")
    requested_identity = str(args.repository_identity or "").strip().lower()
    controls = [
        row
        for row in flatten_origin_controls(controls_payload)
        if not requested_identity or row.get("repository_identity") == requested_identity
    ]
    if not controls:
        raise SystemExit("no controls match evaluation scope")

    candidate_index = {
        (
            str(row.get("advisory") or ""),
            str(row.get("repository_identity") or ""),
            str(row.get("fix_sha") or ""),
            str(row.get("sha") or ""),
        ): row
        for row in candidates
    }
    fix_index = {
        (
            str(row.get("advisory") or ""),
            str(row.get("repository_identity") or ""),
            str(row.get("fix_sha") or ""),
        ): row
        for row in fixes
    }
    result_rows: list[dict[str, object]] = []
    for control in controls:
        advisory = str(control.get("advisory") or "")
        identity = str(control.get("repository_identity") or "")
        fix_sha = str(control.get("fix_sha") or "")
        origin_sha = str(
            control.get("expected_landed_sha")
            or control.get("atomic_origin_sha")
            or ""
        )
        fix_row = fix_index.get((advisory, identity, fix_sha))
        candidate = candidate_index.get((advisory, identity, fix_sha, origin_sha))
        signals = candidate.get("signals", []) if candidate else []
        assert isinstance(signals, list)
        rank = int(candidate["priority_rank"]) if candidate else None
        result_rows.append(
            {
                "advisory": advisory,
                "repository_identity": identity,
                "fix_sha": fix_sha,
                "atomic_origin_sha": str(control.get("atomic_origin_sha") or ""),
                "evaluation_sha": origin_sha,
                "expected_relation": str(control.get("expected_relation") or ""),
                "generation_status": str(fix_row.get("status") if fix_row else "MISSING"),
                "materialized": candidate is not None,
                "priority_rank": rank,
                "signals": signals,
                "szz_hit": bool({"szz_copy_aware", "szz_file_local"} & set(signals)),
                "add_check_hit": bool(
                    {
                        "add_context_blame",
                        "enclosing_function_history",
                        "pickaxe_token_history",
                    }
                    & set(signals)
                ),
                "cross_file_hit": bool(
                    {
                        "cross_file_security_bridge",
                        "cross_file_surface_history",
                    }
                    & set(signals)
                ),
                "fallback_retained_by_contract": bool(
                    fix_row and fix_row.get("status") == "RESOLVED"
                ),
            }
        )

    evaluated = [row for row in result_rows if row["generation_status"] != "MISSING"]
    denominator = len(evaluated)
    recall_at_budget = {
        str(budget): (
            sum(
                isinstance(row["priority_rank"], int)
                and int(row["priority_rank"]) <= budget
                for row in evaluated
            )
            / denominator
            if denominator
            else 0.0
        )
        for budget in _BUDGETS
    }
    summary = {
        "schema_version": 1,
        "artifact_kind": "origin_recall_control_evaluation",
        "gate_status": (
            "PILOT_PASS"
            if denominator
            and denominator == len(result_rows)
            and all(row["generation_status"] == "RESOLVED" for row in evaluated)
            and recall_at_budget["25"] == 1.0
            else "REVISE"
        ),
        "split_id": controls_payload.get("split_id"),
        "requested_repository_identity": requested_identity,
        "generation_summary_sha256": canonical_sha256(generated_summary),
        "control_count": len(result_rows),
        "evaluated_control_count": denominator,
        "missing_generation_count": len(result_rows) - denominator,
        "materialized_recall": (
            sum(row["materialized"] is True for row in evaluated) / denominator
            if denominator
            else 0.0
        ),
        "szz_recall": (
            sum(row["szz_hit"] is True for row in evaluated) / denominator
            if denominator
            else 0.0
        ),
        "add_check_recall": (
            sum(row["add_check_hit"] is True for row in evaluated) / denominator
            if denominator
            else 0.0
        ),
        "cross_file_recall": (
            sum(row["cross_file_hit"] is True for row in evaluated) / denominator
            if denominator
            else 0.0
        ),
        "recall_at_candidate_budget": recall_at_budget,
        "rows": result_rows,
        "claim_boundary": (
            "This is structural recall on selected known-positive controls, not "
            "population recall, precision, or AI-attribution recall. Gold origins "
            "are joined only after the fix-only generation artifact is frozen."
        ),
    }
    _atomic_json(args.output, summary)
    print("origin recall control evaluation frozen")
    print(f"  controls       : {len(result_rows)}")
    print(f"  materialized   : {summary['materialized_recall']:.3f}")
    print(f"  SZZ recall     : {summary['szz_recall']:.3f}")
    print(f"  add-check      : {summary['add_check_recall']:.3f}")
    print(f"  recall@25      : {recall_at_budget['25']:.3f}")
    print(f"  gate           : {summary['gate_status']}")
    print(f"  output         : {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "generate":
        return _generate(args)
    return _evaluate(args)


if __name__ == "__main__":
    raise SystemExit(main())
