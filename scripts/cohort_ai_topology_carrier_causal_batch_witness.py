#!/usr/bin/env python3
"""Freeze claim-grade witnesses for AI changes landed through exact carriers."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cohort_ai_topology_patch_id_relations import _inspect_patch_ids
from cohort_coolify_exact_delta_review_packet import _git, _load_json
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _is_ancestor,
)


@dataclass(frozen=True)
class CausalCase:
    key: str
    candidate_prefix: str
    fix_prefix: str
    adjudication: str
    mechanism_group: str
    claim: str


CASES = (
    CausalCase(
        "docker_flags_branch_a",
        "f8e3bb54a3cb",
        "37c3cd9f4e88",
        "CONFIRMED_CARRIER_AI_INCOMPLETE_DOCKER_COMPOSE_FLAG_REPAIR",
        "docker_compose_custom_command_flag_injection",
        "the landed AI patch used a literal build-only --env-file replacement; the repair centralizes robust -f and --env-file injection for build and start commands",
    ),
    CausalCase(
        "docker_flags_branch_b",
        "1094ab7a4645",
        "274c37e33380",
        "CONFIRMED_CARRIER_AI_INCOMPLETE_DOCKER_COMPOSE_FLAG_REPAIR",
        "docker_compose_custom_command_flag_injection",
        "the equivalent branch copy used the same literal build-only --env-file replacement and was repaired by the same helper-based flag injection",
    ),
    CausalCase(
        "traefik_restart_versions_branch_a",
        "c7fc0a271cbc",
        "329708791e24",
        "CONFIRMED_CARRIER_AI_MISSING_REQUIRED_JOB_ARGUMENT",
        "traefik_restart_job_missing_versions_argument",
        "the landed AI patch dispatched a job without its required versions array; the repair supplies get_traefik_versions()",
    ),
    CausalCase(
        "traefik_restart_versions_branch_b",
        "d3e7d979f6d6",
        "49ab9b2278a0",
        "CONFIRMED_CARRIER_AI_MISSING_REQUIRED_JOB_ARGUMENT",
        "traefik_restart_job_missing_versions_argument",
        "the equivalent branch copy dispatched the same job without its required versions array and received the same repair",
    ),
    CausalCase(
        "buildpack_cleanup_scope_branch_a",
        "0540b2eae567",
        "171732dbcfea",
        "CONFIRMED_CARRIER_AI_UNSCOPED_RELATION_DELETE",
        "application_env_cleanup_unscoped_or_where",
        "the landed AI lifecycle hook used an ungrouped OR on a scoped morphMany delete; the repair groups both key predicates inside the relation scope",
    ),
    CausalCase(
        "buildpack_cleanup_scope_branch_b",
        "36d2c0249805",
        "171732dbcfea",
        "CONFIRMED_CARRIER_AI_UNSCOPED_RELATION_DELETE",
        "application_env_cleanup_unscoped_or_where",
        "an equivalent AI branch copy used the same ungrouped scoped-relation delete and is covered by the grouping repair",
    ),
    CausalCase(
        "buildpack_cleanup_scope_branch_c",
        "36f8a58c281e",
        "59e9d1619041",
        "CONFIRMED_CARRIER_AI_UNSCOPED_RELATION_DELETE",
        "application_env_cleanup_unscoped_or_where",
        "an equivalent AI branch copy used the same ungrouped scoped-relation delete and received an equivalent grouping repair",
    ),
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--mechanism-packet", type=Path, required=True)
    parser.add_argument("--semantic-review-result", type=Path, action="append", required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--repo-timeout", type=int, default=120)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"{path}:{line_number} is not an object")
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {path}: {exc}") from exc
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_case(
    rows: Sequence[Mapping[str, object]], case: CausalCase
) -> Mapping[str, object]:
    matches = [
        row
        for row in rows
        if str(row.get("candidate_sha") or "").startswith(case.candidate_prefix)
        and str(row.get("fix_sha") or "").startswith(case.fix_prefix)
    ]
    if len(matches) != 1:
        raise ValueError(f"{case.key} resolved to {len(matches)} packet rows")
    return matches[0]


def _ledger_statuses(ledger: Mapping[str, object]) -> dict[tuple[str, str], str]:
    raw_rows = ledger.get("edge_ledger")
    if not isinstance(raw_rows, list):
        raise ValueError("ledger edge_ledger is malformed")
    return {
        (str(row.get("candidate_sha") or ""), str(row.get("fix_sha") or "")): str(
            row.get("status") or ""
        )
        for row in raw_rows
        if isinstance(row, Mapping)
    }


def _model_reviews(
    payloads: Sequence[Mapping[str, object]],
) -> dict[str, list[dict[str, object]]]:
    reviews: dict[str, list[dict[str, object]]] = {}
    for payload in payloads:
        if payload.get("result_status") != "completed":
            raise ValueError("semantic review result is incomplete")
        review = payload.get("review")
        raw_rows = review.get("reviews") if isinstance(review, Mapping) else None
        if not isinstance(raw_rows, list):
            raise ValueError("semantic review rows are malformed")
        for raw_row in raw_rows:
            if not isinstance(raw_row, Mapping):
                raise ValueError("semantic review row is malformed")
            key = str(raw_row.get("key") or "")
            reviews.setdefault(key, []).append(dict(raw_row))
    return reviews


def _diffs(
    repository: Path,
    packet_case: Mapping[str, object],
    *,
    timeout: int,
) -> tuple[str, str, str]:
    candidate_sha = str(packet_case["candidate_sha"])
    fix_sha = str(packet_case["fix_sha"])
    raw_paths = packet_case.get("path_packets")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise ValueError("mechanism packet has no path packets")
    candidate_parts: list[str] = []
    carrier_parts: list[str] = []
    fix_parts: list[str] = []
    for raw_path in raw_paths:
        if not isinstance(raw_path, Mapping):
            raise ValueError("mechanism path packet is malformed")
        candidate_parts.append(
            _git(
                repository,
                [
                    "diff",
                    "--no-color",
                    "--no-ext-diff",
                    str(raw_path["candidate_parent_sha"]),
                    candidate_sha,
                    "--",
                    str(raw_path["candidate_path"]),
                ],
                timeout=timeout,
            )
        )
        carrier_parts.append(
            _git(
                repository,
                [
                    "diff",
                    "--no-color",
                    "--no-ext-diff",
                    str(raw_path["carrier_parent_sha"]),
                    str(raw_path["carrier_sha"]),
                    "--",
                    str(raw_path["carrier_path"]),
                ],
                timeout=timeout,
            )
        )
        fix_parts.append(
            _git(
                repository,
                [
                    "diff",
                    "--no-color",
                    "--no-ext-diff",
                    str(raw_path["fix_parent_sha"]),
                    fix_sha,
                    "--",
                    str(raw_path["fix_path"]),
                ],
                timeout=timeout,
            )
        )
    return "\n".join(candidate_parts), "\n".join(carrier_parts), "\n".join(fix_parts)


def _contains_all(text: str, fragments: Sequence[str]) -> bool:
    return all(fragment in text for fragment in fragments)


def _semantic_checks(
    mechanism_group: str,
    *,
    candidate_diff: str,
    carrier_diff: str,
    fix_diff: str,
    carrier_state: str,
) -> dict[str, bool]:
    if mechanism_group == "docker_compose_custom_command_flag_injection":
        focal = (
            "if (! str_contains($build_command, '--env-file'))",
            "'docker compose --env-file /artifacts/build-time.env'",
        )
        return {
            "candidate_and_carrier_share_focal_patch_behavior": _contains_all(
                candidate_diff, focal
            )
            and _contains_all(carrier_diff, focal),
            "candidate_added_literal_env_only_guard": _contains_all(candidate_diff, focal),
            "fix_removes_literal_env_only_guard": _contains_all(
                fix_diff,
                (
                    "-            if (! str_contains($build_command, '--env-file'))",
                    "'docker compose --env-file /artifacts/build-time.env'",
                ),
            ),
            "fix_adds_shared_flag_injector": _contains_all(
                fix_diff,
                (
                    "injectDockerComposeFlags(",
                    "{$this->workdir}{$this->docker_compose_location}",
                    "BUILD_TIME_ENV_PATH",
                ),
            ),
        }
    if mechanism_group == "traefik_restart_job_missing_versions_argument":
        focal = "CheckTraefikVersionForServerJob::dispatch($this->server);"
        return {
            "candidate_and_carrier_share_focal_patch_behavior": focal
            in candidate_diff
            and focal in carrier_diff,
            "candidate_dispatches_without_versions": (
                "+                CheckTraefikVersionForServerJob::dispatch($this->server);"
                in candidate_diff
            ),
            "carrier_job_constructor_requires_versions_array": _contains_all(
                carrier_state,
                (
                    "public function __construct(",
                    "public Server $server,",
                    "public array $traefikVersions",
                ),
            ),
            "fix_supplies_required_versions": _contains_all(
                fix_diff,
                (
                    "-                CheckTraefikVersionForServerJob::dispatch($this->server);",
                    "+                CheckTraefikVersionForServerJob::dispatch($this->server, get_traefik_versions());",
                ),
            ),
        }
    if mechanism_group == "application_env_cleanup_unscoped_or_where":
        focal = (
            "$application->environment_variables()",
            "->where('key', 'LIKE', 'SERVICE_FQDN_%')",
            "->orWhere('key', 'LIKE', 'SERVICE_URL_%')",
            "->delete();",
        )
        return {
            "candidate_and_carrier_share_focal_patch_behavior": _contains_all(
                candidate_diff, focal
            )
            and _contains_all(carrier_diff, focal),
            "candidate_adds_ungrouped_relation_or_delete": _contains_all(candidate_diff, focal),
            "carrier_relationship_has_preexisting_scope": _contains_all(
                carrier_state,
                (
                    "morphMany(EnvironmentVariable::class, 'resourceable')",
                    "->where('is_preview', false)",
                    "->where('is_preview', true)",
                ),
            ),
            "fix_groups_or_predicates_inside_relation_scope": (
                fix_diff.count("+                        ->where(function ($q)") >= 2
                and "+                                ->orWhere('key', 'LIKE', 'SERVICE_URL_%');"
                in fix_diff
            ),
        }
    raise ValueError(f"unknown mechanism group: {mechanism_group}")


def _carrier_state(
    repository: Path,
    mechanism_group: str,
    carrier_sha: str,
    *,
    timeout: int,
) -> str:
    if mechanism_group == "traefik_restart_job_missing_versions_argument":
        source_path = "app/Jobs/CheckTraefikVersionForServerJob.php"
    elif mechanism_group == "application_env_cleanup_unscoped_or_where":
        source_path = "app/Models/Application.php"
    else:
        return "not_required"
    return _git(repository, ["show", f"{carrier_sha}:{source_path}"], timeout=timeout)


def build_witness(
    repository: Path,
    *,
    mechanism_packet: Mapping[str, object],
    observed_ai_shas: set[str],
    semantic_results: Sequence[Mapping[str, object]],
    ledger: Mapping[str, object],
    timeout: int,
) -> dict[str, object]:
    if mechanism_packet.get("packet_passed") is not True:
        raise ValueError("mechanism packet did not pass")
    raw_cases = mechanism_packet.get("case_results")
    if not isinstance(raw_cases, list):
        raise ValueError("mechanism packet cases are malformed")
    packet_cases = [row for row in raw_cases if isinstance(row, Mapping)]
    if len(packet_cases) != len(raw_cases):
        raise ValueError("mechanism packet contains a non-object case")
    reviews = _model_reviews(semantic_results)
    prior_statuses = _ledger_statuses(ledger)
    representative_promotions: dict[str, list[dict[str, object]]] = {}
    for case in CASES:
        packet_case = _resolve_case(packet_cases, case)
        key = str(packet_case.get("key") or "")
        promoted = [
            row for row in reviews.get(key, []) if row.get("verdict") == "PROMOTE"
        ]
        if promoted:
            representative_promotions.setdefault(case.mechanism_group, []).extend(
                promoted
            )
    results: list[dict[str, object]] = []
    for case in CASES:
        packet_case = _resolve_case(packet_cases, case)
        candidate_sha = str(packet_case["candidate_sha"])
        carrier_sha = str(packet_case["carrier_sha"])
        fix_sha = str(packet_case["fix_sha"])
        candidate_diff, carrier_diff, fix_diff = _diffs(
            repository, packet_case, timeout=timeout
        )
        raw_chains = packet_case.get("carrier_chains")
        if not isinstance(raw_chains, list) or not raw_chains:
            raise ValueError(f"{case.key} has no carrier chains")
        patch_ids = {
            str(chain.get("patch_id") or "")
            for chain in raw_chains
            if isinstance(chain, Mapping)
        }
        candidate_patch_ids = _inspect_patch_ids(
            repository, candidate_sha, timeout=timeout
        )
        carrier_patch_ids = _inspect_patch_ids(
            repository, carrier_sha, timeout=timeout
        )
        semantic_checks = _semantic_checks(
            case.mechanism_group,
            candidate_diff=candidate_diff,
            carrier_diff=carrier_diff,
            fix_diff=fix_diff,
            carrier_state=_carrier_state(
                repository,
                case.mechanism_group,
                carrier_sha,
                timeout=timeout,
            ),
        )
        edge = (candidate_sha, fix_sha)
        common_checks = {
            "candidate_is_observed_ai": candidate_sha in observed_ai_shas,
            "mechanical_packet_case_passed": packet_case.get("passed") is True,
            "candidate_and_fix_are_graph_incomparable": not _is_ancestor(
                repository, candidate_sha, fix_sha
            )
            and not _is_ancestor(repository, fix_sha, candidate_sha),
            "carrier_strictly_precedes_fix": carrier_sha != fix_sha
            and _is_ancestor(repository, carrier_sha, fix_sha),
            "stable_patch_id_recomputed": bool(patch_ids)
            and patch_ids <= candidate_patch_ids.patch_ids
            and patch_ids <= carrier_patch_ids.patch_ids,
            "patch_id_inspection_complete": not candidate_patch_ids.coverage_gaps
            and not carrier_patch_ids.coverage_gaps,
            "mechanism_has_independent_model_promotion": bool(
                representative_promotions.get(case.mechanism_group)
            ),
            "edge_not_previously_adjudicated": prior_statuses.get(edge, "NEW_EDGE")
            not in {"CONFIRMED_TRUE_POSITIVE", "REJECTED_NONCAUSAL"},
        }
        checks = {**common_checks, **semantic_checks}
        results.append(
            {
                "key": case.key,
                "candidate_sha": candidate_sha,
                "carrier_sha": carrier_sha,
                "fix_sha": fix_sha,
                "adjudication": case.adjudication,
                "mechanism_group": case.mechanism_group,
                "claim": case.claim,
                "candidate_metadata": _commit_metadata(repository, candidate_sha),
                "carrier_metadata": _commit_metadata(repository, carrier_sha),
                "fix_metadata": _commit_metadata(repository, fix_sha),
                "stable_patch_ids": sorted(patch_ids),
                "representative_model_promotions": representative_promotions.get(
                    case.mechanism_group, []
                ),
                "checks": checks,
                "passed": all(checks.values()),
            }
        )
    edges = {(row["candidate_sha"], row["fix_sha"]) for row in results}
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_topology_carrier_causal_batch_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "confirmed_edges": [
            {
                "candidate_sha": row["candidate_sha"],
                "fix_sha": row["fix_sha"],
                "adjudication": row["adjudication"],
                "mechanism_group": row["mechanism_group"],
            }
            for row in results
        ],
        "case_results": results,
        "summary": {
            "confirmed_edge_count": len(results),
            "unique_candidate_commit_count": len(
                {row["candidate_sha"] for row in results}
            ),
            "unique_fix_commit_count": len({row["fix_sha"] for row in results}),
            "mechanism_group_count": len(
                {row["mechanism_group"] for row in results}
            ),
            "exact_patch_copy_overcount": len(results)
            - len({row["mechanism_group"] for row in results}),
            "failed_case_count": sum(row["passed"] is not True for row in results),
        },
        "witness_passed": len(edges) == len(results)
        and bool(results)
        and all(row["passed"] is True for row in results),
        "claim_boundary": (
            "Confirmed edges are distinct observed-AI commit occurrences. Exact "
            "branch copies are intentionally collapsed into mechanism_group for "
            "scientific counting: seven causal edges represent three mechanisms. "
            "Every case requires candidate-to-carrier patch identity, carrier ancestry, "
            "specific runtime defect and repair fragments, and at least one independent "
            "model promotion for the mechanism. Model labels alone are never sufficient."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.repo_timeout < 1:
        raise SystemExit("--repo-timeout must be positive")
    repository = args.repository.resolve()
    packet_path = args.mechanism_packet.resolve()
    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    ledger_path = args.ledger.resolve()
    review_paths = [path.resolve() for path in args.semantic_review_result]
    try:
        payload = build_witness(
            repository,
            mechanism_packet=_load_json(packet_path),
            observed_ai_shas={
                str(row.get("sha") or "") for row in _load_jsonl(ai_path)
            },
            semantic_results=[_load_json(path) for path in review_paths],
            ledger=_load_json(ledger_path),
            timeout=args.repo_timeout,
        )
    except ValueError as exc:
        raise SystemExit(f"topology carrier causal witness failed: {exc}") from exc
    payload["source_artifacts"] = {
        "ai_commits": {"path": str(ai_path), "sha256": _sha256(ai_path)},
        "mechanism_packet": {
            "path": str(packet_path),
            "sha256": _sha256(packet_path),
        },
        "semantic_review_results": [
            {"path": str(path), "sha256": _sha256(path)} for path in review_paths
        ],
        "prior_ledger": {"path": str(ledger_path), "sha256": _sha256(ledger_path)},
    }
    if payload["witness_passed"] is not True:
        failed = [row["key"] for row in payload["case_results"] if not row["passed"]]
        raise SystemExit(f"topology carrier causal witness failed checks: {failed}")
    _atomic_json(args.output.resolve(), payload)
    print("Coolify topology-carrier causal batch witness frozen")
    print(f"  confirmed edges : {payload['summary']['confirmed_edge_count']}")
    print(f"  unique AI       : {payload['summary']['unique_candidate_commit_count']}")
    print(f"  mechanisms      : {payload['summary']['mechanism_group_count']}")
    print(f"  output          : {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
