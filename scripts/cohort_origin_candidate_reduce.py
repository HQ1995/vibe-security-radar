#!/usr/bin/env python3
"""Reduce pre-fix history to a proof-carrying, finite origin inventory."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

from cohort.fix_manifest import normalize_fix_manifest
from cohort.origin_controls import flatten_origin_controls
from cohort.origin_reduction import reduce_origin_candidates
from cohort.relations import (
    canonical_repository_identity,
    normalize_repository_aliases,
)
from cohort.repos import clone_identity
from cohort.root_adjudication import canonical_sha256
from cve_analyzer.git_ops import run_git


_SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BUDGETS = (1, 5, 10, 25, 50, 100)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate")
    generate.add_argument("--fix-manifest", type=Path, required=True)
    generate.add_argument("--structural-dir", type=Path, action="append", required=True)
    generate.add_argument("--ai-scan-dir", type=Path, action="append", required=True)
    generate.add_argument(
        "--repository-path",
        action="append",
        default=[],
        metavar="IDENTITY=PATH",
    )
    generate.add_argument("--aliases", type=Path, default=DEFAULT_ALIASES)
    generate.add_argument("--repo-timeout", type=int, default=120)
    generate.add_argument("--output-dir", type=Path, required=True)

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--generated-dir", type=Path, required=True)
    evaluate.add_argument("--controls", type=Path, action="append", required=True)
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


def _full_sha(value: object, label: str) -> str:
    sha = str(value or "").strip().lower()
    if not _FULL_SHA_RE.fullmatch(sha):
        raise SystemExit(f"{label} must be a full Git SHA")
    return sha


def _fix_key(row: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        str(row.get("advisory") or ""),
        str(row.get("repository_identity") or "").lower(),
        _full_sha(row.get("fix_sha"), "fix sha"),
    )


def _candidate_key(row: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (*_fix_key(row), _full_sha(row.get("sha"), "candidate sha"))


def _aliases(path: Path) -> dict[str, str]:
    payload = _load_json(path)
    if not isinstance(payload, Mapping) or not isinstance(payload.get("aliases"), list):
        raise SystemExit("repository aliases are malformed")
    return normalize_repository_aliases(payload["aliases"])


def _repository_paths(
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
                f"repository path identity mismatch: expected {identity}, "
                f"got {observed_identity}"
            )
        result[identity] = path
    return result


def _load_structural_inputs(
    directories: list[Path],
) -> tuple[
    dict[tuple[str, str, str], dict[str, object]],
    dict[tuple[str, str, str], list[dict[str, object]]],
    list[dict[str, object]],
]:
    fix_rows: dict[tuple[str, str, str], dict[str, object]] = {}
    candidates: defaultdict[
        tuple[str, str, str], list[dict[str, object]]
    ] = defaultdict(list)
    provenance: list[dict[str, object]] = []
    for raw_directory in directories:
        directory = raw_directory.resolve()
        summary = _load_json(directory / "summary.json")
        rows = _load_jsonl(directory / "candidates.jsonl")
        fixes = _load_jsonl(directory / "fixes.jsonl")
        if not isinstance(summary, Mapping):
            raise SystemExit(f"structural summary is malformed: {directory}")
        if summary.get("generation_process_boundary") != (
            "sealed_fix_only_no_golden_ledger_read"
        ):
            raise SystemExit(f"structural input crossed the gold boundary: {directory}")
        if summary.get("gate_status") != "READY_FOR_SEPARATE_EVALUATION":
            raise SystemExit(
                f"structural input is not ready: {directory}: "
                f"{summary.get('gate_status')!r}"
            )
        if canonical_sha256(rows) != summary.get("candidate_rows_sha256"):
            raise SystemExit(f"structural candidate digest mismatch: {directory}")
        if canonical_sha256(fixes) != summary.get("fix_rows_sha256"):
            raise SystemExit(f"structural fix digest mismatch: {directory}")
        local_keys: set[tuple[str, str, str]] = set()
        for row in fixes:
            key = _fix_key(row)
            if key in fix_rows:
                raise SystemExit(f"duplicate structural fix: {key}")
            fix_rows[key] = row
            local_keys.add(key)
        for row in rows:
            key = _fix_key(row)
            if key not in local_keys:
                raise SystemExit(f"structural candidate has no local fix row: {key}")
            candidates[key].append(row)
        provenance.append(
            {
                "directory": str(directory),
                "summary_sha256": canonical_sha256(summary),
                "candidate_rows_sha256": canonical_sha256(rows),
                "fix_rows_sha256": canonical_sha256(fixes),
            }
        )
    for key, rows in candidates.items():
        shas = [_full_sha(row.get("sha"), "structural candidate sha") for row in rows]
        if len(shas) != len(set(shas)):
            raise SystemExit(f"duplicate structural candidate: {key}")
    return fix_rows, dict(candidates), provenance


def _load_ai_scans(
    directories: list[Path],
) -> tuple[
    dict[str, list[dict[str, object]]],
    set[str],
    list[dict[str, object]],
]:
    by_repository: defaultdict[str, dict[str, dict[str, object]]] = defaultdict(dict)
    complete_repositories: set[str] = set()
    provenance: list[dict[str, object]] = []
    for raw_directory in directories:
        directory = raw_directory.resolve()
        summary = _load_json(directory / "summary.json")
        rows = _load_jsonl(directory / "commits.jsonl")
        if not isinstance(summary, Mapping) or summary.get("artifact_kind") != (
            "cohort_ai_commit_scan"
        ):
            raise SystemExit(f"AI scan summary is malformed: {directory}")
        if summary.get("ai_commit_count") != len(rows):
            raise SystemExit(f"AI scan row count mismatch: {directory}")
        raw_complete = summary.get("complete_repository_identities")
        if not isinstance(raw_complete, list) or any(
            not isinstance(value, str) for value in raw_complete
        ):
            raise SystemExit(f"AI scan coverage is malformed: {directory}")
        complete_repositories.update(value.lower() for value in raw_complete)
        for raw in rows:
            identity = str(raw.get("repository_identity") or "").lower()
            sha = _full_sha(raw.get("sha"), "AI observation sha")
            row = dict(raw)
            prior = by_repository[identity].get(sha)
            if prior is not None and prior != row:
                raise SystemExit(f"conflicting AI observation: {identity}@{sha}")
            by_repository[identity][sha] = row
        provenance.append(
            {
                "directory": str(directory),
                "summary_sha256": canonical_sha256(summary),
                "commit_rows_sha256": canonical_sha256(rows),
                "since": summary.get("since"),
                "complete_repository_identities": sorted(
                    value.lower() for value in raw_complete
                ),
            }
        )
    return (
        {
            identity: [rows[sha] for sha in sorted(rows)]
            for identity, rows in by_repository.items()
        },
        complete_repositories,
        provenance,
    )


def _git_lines(repo: Path, arguments: list[str], *, timeout: int) -> list[str]:
    # The cohort cache can retain a shallow marker after the missing objects
    # have been hydrated.  Treating that stale marker as a real history
    # boundary silently drops reachable pre-fix ancestors.  Other history
    # enumerators in this pipeline use the complete local object graph under
    # the same condition, so keep the reducer on that recall-preserving view.
    global_arguments = (
        ["--shallow-file", ""] if (repo / ".git" / "shallow").exists() else []
    )
    completed = run_git(
        ["git", "-C", str(repo), *global_arguments, *arguments],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        no_lazy_fetch=True,
    )
    if completed.returncode != 0:
        detail = str(completed.stderr or "").strip().replace("\n", " ")[:300]
        raise SystemExit(f"git {arguments[0]} failed in {repo}: {detail}")
    return [line.strip() for line in str(completed.stdout or "").splitlines() if line.strip()]


def _pre_fix_ancestry(repo: Path, fix_sha: str, *, timeout: int) -> tuple[list[str], set[str]]:
    parent_record = _git_lines(
        repo, ["rev-list", "--parents", "-n", "1", fix_sha], timeout=timeout
    )
    if len(parent_record) != 1:
        raise SystemExit(f"fix cannot be resolved exactly once: {fix_sha}")
    fields = parent_record[0].split()
    if not fields or fields[0].lower() != fix_sha or len(fields) < 2:
        raise SystemExit(f"fix has no pre-fix parent state: {fix_sha}")
    parents = [_full_sha(value, "fix parent") for value in fields[1:]]
    ancestors = {
        _full_sha(value, "ancestor")
        for value in _git_lines(repo, ["rev-list", *parents], timeout=timeout)
    }
    if not ancestors:
        raise SystemExit(f"fix has an empty ancestry closure: {fix_sha}")
    return parents, ancestors


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
    manifest_fixes = manifest["fixes"]
    assert isinstance(manifest_fixes, list)
    manifest_index = {_fix_key(row): row for row in manifest_fixes}
    if len(manifest_index) != len(manifest_fixes):
        raise SystemExit("fix manifest contains duplicate rows")

    structural_fixes, structural_candidates, structural_provenance = (
        _load_structural_inputs(args.structural_dir)
    )
    if set(structural_fixes) != set(manifest_index):
        missing = sorted(set(manifest_index) - set(structural_fixes))
        extra = sorted(set(structural_fixes) - set(manifest_index))
        raise SystemExit(
            f"structural/fix manifest mismatch: missing={missing[:3]} extra={extra[:3]}"
        )
    ai_rows, complete_repositories, ai_provenance = _load_ai_scans(args.ai_scan_dir)
    overrides = _repository_paths(args.repository_path, aliases)

    candidates: list[dict[str, object]] = []
    certificates: list[dict[str, object]] = []
    scope_gaps: list[dict[str, object]] = []
    fix_results: list[dict[str, object]] = []
    for key in sorted(manifest_index):
        advisory, identity, fix_sha = key
        structural_fix = structural_fixes[key]
        repo = overrides.get(identity)
        if repo is None:
            recorded_path = Path(str(structural_fix.get("repository_path") or ""))
            if recorded_path.is_dir() and (recorded_path / ".git").exists():
                repo = recorded_path.resolve()
        if repo is None:
            raise SystemExit(f"local repository unavailable for {identity}")
        parents, ancestors = _pre_fix_ancestry(
            repo, fix_sha, timeout=args.repo_timeout
        )
        recorded_ancestor_count = structural_fix.get("ancestor_fallback_candidate_count")
        if (
            isinstance(recorded_ancestor_count, int)
            and recorded_ancestor_count != len(ancestors)
        ):
            raise SystemExit(f"ancestor count drift for {key}")
        observation_complete = identity in complete_repositories
        reduction = reduce_origin_candidates(
            ancestors,
            ai_rows.get(identity, []),
            structural_candidates.get(key, []),
            observation_complete=observation_complete,
        )
        reduced_rows = reduction["candidates"]
        assert isinstance(reduced_rows, list)
        for raw in reduced_rows:
            assert isinstance(raw, dict)
            candidates.append(
                {
                    "advisory": advisory,
                    "repository_identity": identity,
                    "fix_sha": fix_sha,
                    **raw,
                }
            )
        non_ancestors = reduction["certified_non_ancestor_shas"]
        assert isinstance(non_ancestors, list)
        for candidate_sha in non_ancestors:
            certificates.append(
                {
                    "advisory": advisory,
                    "repository_identity": identity,
                    "fix_sha": fix_sha,
                    "candidate_sha": candidate_sha,
                    "certificate_kind": "git_non_ancestor_of_pre_fix_state",
                    "pre_fix_parents": parents,
                    "excluded_from_candidate_inventory": True,
                }
            )
        scope_gaps.append(
            {
                "advisory": advisory,
                "repository_identity": identity,
                "fix_sha": fix_sha,
                "scope_kind": "attribution_unobserved_but_retained",
                "not_a_negative_result": True,
                "unobserved_ancestor_count": reduction["unobserved_ancestor_count"],
                "unobserved_ancestor_shas_sha256": reduction[
                    "unobserved_ancestor_shas_sha256"
                ],
                "disposition": (
                    "RETAINED_LOW_PRIORITY"
                    if observation_complete
                    else "RETAINED_FAIL_OPEN"
                ),
            }
        )
        fix_results.append(
            {
                "advisory": advisory,
                "repository_identity": identity,
                "fix_sha": fix_sha,
                "repository_path": str(repo),
                "history_view": (
                    "complete_local_object_graph_ignoring_shallow_marker"
                    if (repo / ".git" / "shallow").exists()
                    else "declared_repository_graph"
                ),
                "pre_fix_parents": parents,
                "status": reduction["status"],
                "observation_complete": observation_complete,
                "ancestor_count": reduction["ancestor_count"],
                "ancestor_shas_sha256": reduction["ancestor_shas_sha256"],
                "observed_ai_count": reduction["observed_ai_count"],
                "observed_ai_ancestor_count": reduction[
                    "observed_ai_ancestor_count"
                ],
                "certified_non_ancestor_count": reduction[
                    "certified_non_ancestor_count"
                ],
                "unobserved_ancestor_count": reduction[
                    "unobserved_ancestor_count"
                ],
                "retained_candidate_count": reduction[
                    "retained_candidate_count"
                ],
                "fail_open_candidate_count": reduction["fail_open_candidate_count"],
                "candidate_shas_sha256": reduction["candidate_shas_sha256"],
            }
        )

    candidates.sort(key=lambda row: (*_fix_key(row), int(row["priority_rank"])))
    certificates.sort(
        key=lambda row: (*_fix_key(row), str(row["candidate_sha"]))
    )
    scope_gaps.sort(key=_fix_key)
    fix_results.sort(key=_fix_key)
    candidate_keys = [_candidate_key(row) for row in candidates]
    if len(candidate_keys) != len(set(candidate_keys)):
        raise SystemExit("reduced candidate inventory contains duplicates")
    total_ancestors = sum(int(row["ancestor_count"]) for row in fix_results)
    total_candidates = len(candidates)
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "proof_carrying_origin_candidate_reduction",
        "split_id": manifest["split_id"],
        "generation_process_boundary": (
            "sealed_fix_plus_frozen_ai_observation_no_golden_origin_read"
        ),
        "claim_boundary": (
            "Every commit in the frozen local pre-fix ancestry is retained. AI "
            "attribution and structural signals only rank candidates. This does "
            "not cover missing/private history, cross-repository copies, or exact "
            "atomic members hidden behind an unexpanded squash carrier."
        ),
        "candidate_membership_policy": "all_pre_fix_ancestors",
        "ai_attribution_disposition": "rank_only_no_deletion",
        "fix_manifest_sha256": canonical_sha256(manifest_payload),
        "structural_inputs": structural_provenance,
        "ai_scan_inputs": ai_provenance,
        "fix_count": len(fix_results),
        "resolved_fix_count": sum(row["status"] == "RESOLVED" for row in fix_results),
        "blocked_fix_count": sum(row["status"] != "RESOLVED" for row in fix_results),
        "ancestor_pair_count": total_ancestors,
        "candidate_count": total_candidates,
        "certified_non_ancestor_count": len(certificates),
        "unobserved_ancestor_pair_count": sum(
            int(row["unobserved_ancestor_count"]) for row in fix_results
        ),
        "reduction_fraction": (
            1.0 - (total_candidates / total_ancestors) if total_ancestors else 0.0
        ),
        "all_ancestor_pairs_retained": total_candidates == total_ancestors,
        "all_candidates_retained": all(
            row.get("retained") is True for row in candidates
        ),
        "candidate_rows_sha256": canonical_sha256(candidates),
        "certificate_rows_sha256": canonical_sha256(certificates),
        "scope_gap_rows_sha256": canonical_sha256(scope_gaps),
        "fix_rows_sha256": canonical_sha256(fix_results),
        "gate_status": (
            "READY_FOR_SEPARATE_EVALUATION"
            if all(row["status"] == "RESOLVED" for row in fix_results)
            else "BLOCKED_OBSERVATION_COVERAGE"
        ),
    }
    args.output_dir.mkdir(parents=True)
    _atomic_jsonl(args.output_dir / "candidates.jsonl", candidates)
    _atomic_jsonl(
        args.output_dir / "exclusion_certificates.jsonl", certificates
    )
    _atomic_jsonl(args.output_dir / "scope_gaps.jsonl", scope_gaps)
    _atomic_jsonl(args.output_dir / "fixes.jsonl", fix_results)
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _recall_at_budget(ranks: list[int | None]) -> dict[str, float]:
    return {
        str(budget): (
            sum(rank is not None and rank <= budget for rank in ranks) / len(ranks)
            if ranks
            else 0.0
        )
        for budget in _BUDGETS
    }


def _evaluate(args: argparse.Namespace) -> int:
    summary = _load_json(args.generated_dir / "summary.json")
    candidates = _load_jsonl(args.generated_dir / "candidates.jsonl")
    fixes = _load_jsonl(args.generated_dir / "fixes.jsonl")
    certificates = _load_jsonl(
        args.generated_dir / "exclusion_certificates.jsonl"
    )
    scope_gaps = _load_jsonl(args.generated_dir / "scope_gaps.jsonl")
    if not isinstance(summary, Mapping):
        raise SystemExit("reduction summary is malformed")
    for rows, field, label in (
        (candidates, "candidate_rows_sha256", "candidate"),
        (fixes, "fix_rows_sha256", "fix"),
        (certificates, "certificate_rows_sha256", "certificate"),
        (scope_gaps, "scope_gap_rows_sha256", "scope gap"),
    ):
        if canonical_sha256(rows) != summary.get(field):
            raise SystemExit(f"reduction {label} digest mismatch")
    candidate_index = {_candidate_key(row): row for row in candidates}
    if len(candidate_index) != len(candidates):
        raise SystemExit("reduction candidate inventory contains duplicates")
    fix_index = {_fix_key(row): row for row in fixes}

    controls: list[dict[str, object]] = []
    for path in args.controls:
        payload = _load_json(path)
        if not isinstance(payload, Mapping):
            raise SystemExit(f"control ledger is malformed: {path}")
        controls.extend(flatten_origin_controls(payload))
    selected_controls = [row for row in controls if _fix_key(row) in fix_index]
    if not selected_controls:
        raise SystemExit("no controls match the generated fix inventory")
    control_keys: set[tuple[str, str, str, str]] = set()
    evaluation_rows: list[dict[str, object]] = []
    ranks: list[int | None] = []
    for control in selected_controls:
        origin_sha = _full_sha(
            control.get("expected_landed_sha")
            or control.get("atomic_origin_sha"),
            "gold origin sha",
        )
        key = (*_fix_key(control), origin_sha)
        if key in control_keys:
            raise SystemExit(f"duplicate control edge: {key}")
        control_keys.add(key)
        candidate = candidate_index.get(key)
        rank = int(candidate["priority_rank"]) if candidate is not None else None
        ranks.append(rank)
        fix = fix_index[_fix_key(control)]
        evaluation_rows.append(
            {
                "advisory": key[0],
                "repository_identity": key[1],
                "fix_sha": key[2],
                "origin_sha": origin_sha,
                "retained": candidate is not None,
                "rank": rank,
                "signals": candidate.get("signals", []) if candidate else [],
                "materialization": (
                    candidate.get("materialization") if candidate else "MISSING"
                ),
                "candidate_count_for_fix": fix["retained_candidate_count"],
                "ancestor_count_for_fix": fix["ancestor_count"],
            }
        )
    retained_count = sum(row["retained"] is True for row in evaluation_rows)
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "origin_candidate_reduction_control_evaluation",
        "generated_summary_sha256": canonical_sha256(summary),
        "control_count": len(evaluation_rows),
        "retained_control_count": retained_count,
        "missed_control_count": len(evaluation_rows) - retained_count,
        "observed_scope_recall": retained_count / len(evaluation_rows),
        "recall_at_budget": _recall_at_budget(ranks),
        "ancestor_pair_count": summary.get("ancestor_pair_count"),
        "candidate_count": summary.get("candidate_count"),
        "reduction_fraction": summary.get("reduction_fraction"),
        "claim_boundary": summary.get("claim_boundary"),
        "gate_status": (
            "PASS_ZERO_CONTROL_MISSES"
            if retained_count == len(evaluation_rows)
            else "FAIL_CONTROL_MISS"
        ),
        "rows": evaluation_rows,
    }
    _atomic_json(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "generate":
        return _generate(args)
    return _evaluate(args)


if __name__ == "__main__":
    raise SystemExit(main())
