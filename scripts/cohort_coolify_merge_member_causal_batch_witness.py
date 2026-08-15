#!/usr/bin/env python3
"""Freeze claim-grade causal witnesses from direct merge-member reversals.

The merge-member overlay is a recall surface, not a labeler.  This witness only
promotes an edge after re-reading the commits and proving a mechanism-specific
candidate -> repair transition.  Semantic model output is retained as a lead;
it is never sufficient on its own and negative output cannot delete a pair.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cohort_coolify_exact_delta_causal_batch_witness import _line_evidence
from cohort_coolify_exact_delta_review_packet import _git
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _is_ancestor,
)
from cohort_coolify_preimage_exact_delta_bridge import _inspect_commit_delta


@dataclass(frozen=True)
class CausalCase:
    key: str
    candidate_prefix: str
    fix_prefix: str
    adjudication: str
    mechanism_group: str
    claim: str
    fix_message_fragments: tuple[str, ...]
    exact_line_fragments: tuple[str, ...]
    candidate_diff_fragments: tuple[str, ...]
    fix_diff_fragments: tuple[str, ...]
    causal_role: str = "DIRECT_CAUSAL_MEMBER"
    parent_source_path: str | None = None
    parent_source_fragments: tuple[str, ...] = ()
    candidate_source_path: str | None = None
    candidate_source_fragments: tuple[str, ...] = ()
    candidate_source_forbidden_fragments: tuple[str, ...] = ()
    fix_parent_source_path: str | None = None
    fix_parent_source_fragments: tuple[str, ...] = ()
    fix_parent_source_forbidden_fragments: tuple[str, ...] = ()


CASES = (
    CausalCase(
        key="docker_27_stop_timeout_compatibility",
        candidate_prefix="8d280b4aac3f",
        fix_prefix="5b79844a3a11",
        adjudication="CONFIRMED_DIRECT_AI_DOCKER_VERSION_COMPATIBILITY_REGRESSION",
        mechanism_group="docker_27_stop_timeout_flag_compatibility",
        claim=(
            "the AI candidate introduced docker stop --timeout while the checked-in "
            "installer still selected Docker 27.0; the follow-up restored --time on "
            "every affected database stop path"
        ),
        fix_message_fragments=("use --time instead of --timeout",),
        exact_line_fragments=("docker stop --timeout=10",),
        candidate_diff_fragments=("docker stop --timeout=10",),
        fix_diff_fragments=("docker stop --time=10",),
        parent_source_path="scripts/install.sh",
        parent_source_fragments=('DOCKER_VERSION="27.0"',),
    ),
    CausalCase(
        key="subresource_restarting_status_preservation",
        candidate_prefix="c65ad2e65580",
        fix_prefix="66e81d6d9654",
        adjudication="CONFIRMED_DIRECT_AI_STATUS_SEMANTICS_REGRESSION",
        mechanism_group="subresource_restarting_status_preservation",
        claim=(
            "the AI status-priority change collapsed restarting sub-resources into "
            "degraded:unhealthy; the follow-up restores restarting:unknown at the "
            "application and sub-resource call sites"
        ),
        fix_message_fragments=(
            'preserve "Restarting" for applications and sub-resources',
        ),
        exact_line_fragments=(
            "Priority 2: Restarting containers (degraded state)",
            "return 'degraded:unhealthy';",
        ),
        candidate_diff_fragments=(
            "Priority 2: Restarting containers (degraded state)",
            "return 'degraded:unhealthy';",
        ),
        fix_diff_fragments=(
            "preserveRestarting: true",
            "return $preserveRestarting ? 'restarting:unknown' : "
            "'degraded:unhealthy';",
        ),
    ),
    CausalCase(
        key="docker_compose_raw_user_input_preservation",
        candidate_prefix="a956e11b3e40",
        fix_prefix="5b9146d8df7a",
        adjudication="CONFIRMED_DIRECT_AI_RAW_CONFIGURATION_MUTATION_REGRESSION",
        mechanism_group="docker_compose_raw_user_input_preservation",
        claim=(
            "the AI candidate stored the fully processed compose document in the raw "
            "user-input field; the follow-up preserves the original YAML and strips "
            "only generated volume metadata"
        ),
        fix_message_fragments=(
            "incorrectly set docker_compose_raw",
            "broke the separation between user input",
        ),
        exact_line_fragments=(
            "$resource->docker_compose_raw = $cleanedCompose;",
        ),
        candidate_diff_fragments=(
            "$resource->docker_compose_raw = $cleanedCompose;",
        ),
        fix_diff_fragments=(
            "$originalYaml = Yaml::parse($originalCompose);",
            "$resource->docker_compose_raw = Yaml::dump($originalYaml, 10, 2);",
            "docker_compose_raw should not contain Traefik labels",
            "docker_compose_raw should contain original user labels",
        ),
    ),
    CausalCase(
        key="backup_failure_observability",
        candidate_prefix="c25272de8d4f",
        fix_prefix="d27d697b3786",
        adjudication="CONFIRMED_DIRECT_AI_FAILURE_OBSERVABILITY_REGRESSION",
        mechanism_group="name_cleanup_backup_failure_observability",
        claim=(
            "the AI logging cleanup swallowed backup exceptions with a silent catch; "
            "the focused follow-up restores a structured warning while continuing"
        ),
        fix_message_fragments=("log warning on backup failure",),
        exact_line_fragments=("// Silently continue",),
        candidate_diff_fragments=("// Silently continue",),
        fix_diff_fragments=(
            "Log::warning('Name cleanup backup failed'",
            "backup is optional safeguard",
        ),
    ),
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--topology-overlay-dir", type=Path, required=True)
    parser.add_argument(
        "--semantic-review-result",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument(
        "--case-manifest",
        type=Path,
        help="optional frozen JSON case manifest; built-in batch is used when omitted",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo-timeout", type=int, default=120)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


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


def _contains_all(text: str, fragments: Sequence[str]) -> bool:
    folded = text.casefold()
    return all(fragment.casefold() in folded for fragment in fragments)


def _case_from_mapping(row: Mapping[str, object], *, index: int) -> CausalCase:
    required_strings = (
        "key",
        "candidate_prefix",
        "fix_prefix",
        "adjudication",
        "mechanism_group",
        "claim",
    )
    values: dict[str, str] = {}
    for field in required_strings:
        value = row.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"case manifest row {index} has invalid {field}")
        values[field] = value.strip()
    causal_role = row.get("causal_role", "DIRECT_CAUSAL_MEMBER")
    if not isinstance(causal_role, str) or not causal_role.strip():
        raise ValueError(f"case manifest row {index} has invalid causal_role")

    required_lists = (
        "fix_message_fragments",
        "exact_line_fragments",
        "candidate_diff_fragments",
        "fix_diff_fragments",
    )
    lists: dict[str, tuple[str, ...]] = {}
    for field in required_lists:
        raw = row.get(field)
        if (
            not isinstance(raw, list)
            or not raw
            or not all(isinstance(value, str) and value for value in raw)
        ):
            raise ValueError(f"case manifest row {index} has invalid {field}")
        lists[field] = tuple(raw)

    optional_lists = (
        "parent_source_fragments",
        "candidate_source_fragments",
        "candidate_source_forbidden_fragments",
        "fix_parent_source_fragments",
        "fix_parent_source_forbidden_fragments",
    )
    for field in optional_lists:
        raw = row.get(field, [])
        if not isinstance(raw, list) or not all(
            isinstance(value, str) and value for value in raw
        ):
            raise ValueError(f"case manifest row {index} has invalid {field}")
        lists[field] = tuple(raw)

    optional_paths: dict[str, str | None] = {}
    for field in (
        "parent_source_path",
        "candidate_source_path",
        "fix_parent_source_path",
    ):
        raw = row.get(field)
        if raw is not None and (not isinstance(raw, str) or not raw.strip()):
            raise ValueError(f"case manifest row {index} has invalid {field}")
        optional_paths[field] = raw.strip() if isinstance(raw, str) else None
    if bool(optional_paths["parent_source_path"]) != bool(
        lists["parent_source_fragments"]
    ):
        raise ValueError(
            f"case manifest row {index} has incomplete parent source assertion"
        )
    if bool(optional_paths["candidate_source_path"]) != bool(
        lists["candidate_source_fragments"]
        or lists["candidate_source_forbidden_fragments"]
    ):
        raise ValueError(
            f"case manifest row {index} has incomplete candidate source assertion"
        )
    if bool(optional_paths["fix_parent_source_path"]) != bool(
        lists["fix_parent_source_fragments"]
        or lists["fix_parent_source_forbidden_fragments"]
    ):
        raise ValueError(
            f"case manifest row {index} has incomplete fix-parent source assertion"
        )
    return CausalCase(
        key=values["key"],
        candidate_prefix=values["candidate_prefix"],
        fix_prefix=values["fix_prefix"],
        adjudication=values["adjudication"],
        mechanism_group=values["mechanism_group"],
        claim=values["claim"],
        fix_message_fragments=lists["fix_message_fragments"],
        exact_line_fragments=lists["exact_line_fragments"],
        candidate_diff_fragments=lists["candidate_diff_fragments"],
        fix_diff_fragments=lists["fix_diff_fragments"],
        causal_role=causal_role.strip(),
        parent_source_path=optional_paths["parent_source_path"],
        parent_source_fragments=lists["parent_source_fragments"],
        candidate_source_path=optional_paths["candidate_source_path"],
        candidate_source_fragments=lists["candidate_source_fragments"],
        candidate_source_forbidden_fragments=lists[
            "candidate_source_forbidden_fragments"
        ],
        fix_parent_source_path=optional_paths["fix_parent_source_path"],
        fix_parent_source_fragments=lists["fix_parent_source_fragments"],
        fix_parent_source_forbidden_fragments=lists[
            "fix_parent_source_forbidden_fragments"
        ],
    )


def _load_case_manifest(path: Path) -> tuple[CausalCase, ...]:
    payload = _load_json(path)
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("case manifest has no cases")
    cases = tuple(
        _case_from_mapping(row, index=index)
        for index, row in enumerate(raw_cases, start=1)
        if isinstance(row, Mapping)
    )
    if len(cases) != len(raw_cases):
        raise ValueError("case manifest contains a non-object row")
    if len({case.key for case in cases}) != len(cases):
        raise ValueError("case manifest contains duplicate keys")
    edges = {(case.candidate_prefix, case.fix_prefix) for case in cases}
    if len(edges) != len(cases):
        raise ValueError("case manifest contains duplicate edges")
    return cases


def _resolve_overlay_row(
    rows: Sequence[Mapping[str, object]],
    candidate_prefix: str,
    fix_prefix: str,
) -> Mapping[str, object]:
    matches = [
        row
        for row in rows
        if str(row.get("candidate_sha") or "").startswith(candidate_prefix)
        and str(row.get("member_fix_sha") or "").startswith(fix_prefix)
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{candidate_prefix}:{fix_prefix} resolved to {len(matches)} overlay rows"
        )
    return matches[0]


def _review_index(
    results: Sequence[Mapping[str, object]],
) -> dict[str, Mapping[str, object]]:
    reviews: dict[str, Mapping[str, object]] = {}
    for result_index, result in enumerate(results, start=1):
        if result.get("result_status") != "completed":
            raise ValueError(f"semantic result {result_index} is not completed")
        if str(result.get("parse_error") or ""):
            raise ValueError(f"semantic result {result_index} has a parse error")
        raw_review = result.get("review")
        raw_rows = raw_review.get("reviews") if isinstance(raw_review, Mapping) else None
        if not isinstance(raw_rows, list):
            raise ValueError(f"semantic result {result_index} has malformed reviews")
        for row in raw_rows:
            if not isinstance(row, Mapping):
                raise ValueError(f"semantic result {result_index} has a non-object review")
            key = str(row.get("key") or "")
            if not key:
                raise ValueError(f"semantic result {result_index} has a keyless review")
            if key in reviews:
                raise ValueError(f"duplicate semantic review key: {key}")
            reviews[key] = row
    return reviews


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


def _exact_evidence_text(exact: Sequence[Mapping[str, object]]) -> str:
    return "\n".join(str(row.get("content_excerpt") or "") for row in exact)


def _case_proof(
    repository: Path,
    case: CausalCase,
    *,
    overlay_row: Mapping[str, object],
    review_row: Mapping[str, object],
    observed_ai_shas: set[str],
    prior_statuses: Mapping[tuple[str, str], str],
    timeout: int,
) -> dict[str, object]:
    candidate_sha = str(overlay_row["candidate_sha"])
    fix_sha = str(overlay_row["member_fix_sha"])
    candidate_delta = _inspect_commit_delta(
        repository, candidate_sha, compare_all_parents=True, timeout=timeout
    )
    fix_delta = _inspect_commit_delta(
        repository, fix_sha, compare_all_parents=False, timeout=timeout
    )
    exact, forward, restored = _line_evidence(candidate_delta, fix_delta)
    candidate_diff = _git(
        repository,
        ["show", "--format=", "--find-renames", candidate_sha],
        timeout=timeout,
    )
    fix_diff = _git(
        repository,
        ["show", "--format=", "--find-renames", fix_sha],
        timeout=timeout,
    )
    candidate_metadata = _commit_metadata(repository, candidate_sha)
    fix_metadata = _commit_metadata(repository, fix_sha)
    fix_message = str(fix_metadata.get("message") or "")
    parent_source = ""
    if case.parent_source_path:
        if len(candidate_delta.parents) != 1:
            raise ValueError(
                f"{case.key} needs a singular candidate parent for its source assertion"
            )
        parent_source = _git(
            repository,
            ["show", f"{candidate_delta.parents[0]}:{case.parent_source_path}"],
            timeout=timeout,
        )
    candidate_source = ""
    if case.candidate_source_path:
        candidate_source = _git(
            repository,
            ["show", f"{candidate_sha}:{case.candidate_source_path}"],
            timeout=timeout,
        )
    fix_parent_source = ""
    if case.fix_parent_source_path:
        if not fix_delta.parents:
            raise ValueError(
                f"{case.key} has no fix parent for its source assertion"
            )
        fix_parent_source = _git(
            repository,
            ["show", f"{fix_delta.parents[0]}:{case.fix_parent_source_path}"],
            timeout=timeout,
        )
    edge = (candidate_sha, fix_sha)
    prior_status = prior_statuses.get(edge, "NEW_EDGE")
    review_key = f"{candidate_sha[:12]}__{fix_sha[:12]}"
    overlay_exact_count = int(overlay_row.get("exact_reversal_line_count", -1))
    checks = {
        "candidate_is_observed_ai": candidate_sha in observed_ai_shas,
        "candidate_strictly_precedes_fix": candidate_sha != fix_sha
        and _is_ancestor(repository, candidate_sha, fix_sha),
        "overlay_pair_retained": overlay_row.get("retained") is True,
        "overlay_pair_is_direct_member": overlay_row.get("member_topology_class")
        == "T0_DIRECT_MEMBER_AFTER_CANDIDATE",
        "fix_member_is_atomic_or_root": overlay_row.get("member_kind")
        == "atomic_or_root",
        "candidate_delta_inspection_complete": not candidate_delta.coverage_gaps,
        "fix_delta_inspection_complete": not fix_delta.coverage_gaps,
        "meaningful_exact_same_path_reversal_present": bool(exact),
        "local_exact_reversal_is_covered_by_overlay_count": overlay_exact_count
        >= len(exact)
        > 0,
        "required_exact_line_fragments_present": _contains_all(
            _exact_evidence_text(exact), case.exact_line_fragments
        ),
        "candidate_diff_encodes_faulty_mechanism": _contains_all(
            candidate_diff, case.candidate_diff_fragments
        ),
        "fix_diff_encodes_repaired_mechanism": _contains_all(
            fix_diff, case.fix_diff_fragments
        ),
        "fix_message_matches_mechanism": _contains_all(
            fix_message, case.fix_message_fragments
        ),
        "candidate_parent_contract_matches": _contains_all(
            parent_source, case.parent_source_fragments
        ),
        "candidate_source_contract_matches": _contains_all(
            candidate_source, case.candidate_source_fragments
        ),
        "candidate_source_forbidden_fragments_absent": not any(
            fragment.casefold() in candidate_source.casefold()
            for fragment in case.candidate_source_forbidden_fragments
        ),
        "faulty_contract_survives_to_fix_parent": _contains_all(
            fix_parent_source, case.fix_parent_source_fragments
        ),
        "fix_parent_repair_fragments_absent": not any(
            fragment.casefold() in fix_parent_source.casefold()
            for fragment in case.fix_parent_source_forbidden_fragments
        ),
        "semantic_review_key_matches_edge": str(review_row.get("key") or "")
        == review_key,
        "semantic_model_promoted_as_lead": review_row.get("verdict") == "PROMOTE",
        "edge_not_previously_adjudicated": prior_status
        not in {"CONFIRMED_TRUE_POSITIVE", "REJECTED_NONCAUSAL"},
    }
    return {
        "key": case.key,
        "candidate_sha": candidate_sha,
        "fix_sha": fix_sha,
        "adjudication": case.adjudication,
        "causal_role": case.causal_role,
        "mechanism_group": case.mechanism_group,
        "claim": case.claim,
        "adjudication_basis": (
            "lossless_merge_member_exact_reversal_plus_mechanism_specific_source_"
            "state_surviving_to_fix_parent_plus_fix_rationale; model_is_lead_only"
        ),
        "candidate_metadata": candidate_metadata,
        "fix_metadata": fix_metadata,
        "merge_member_provenance": {
            "member_topology_class": overlay_row.get("member_topology_class"),
            "member_kind": overlay_row.get("member_kind"),
            "merge_carrier_shas": overlay_row.get("merge_carrier_shas"),
            "source_merge_edge_count": overlay_row.get("source_merge_edge_count"),
            "semantic_lanes": overlay_row.get("semantic_lanes"),
            "topology_review_rank": overlay_row.get("topology_review_rank"),
            "overlay_exact_reversal_line_count": overlay_exact_count,
        },
        "prior_ledger_status": prior_status,
        "semantic_review": dict(review_row),
        "exact_same_path_reversal_count": len(exact),
        "candidate_added_fix_removed_count": len(forward),
        "candidate_removed_fix_added_count": len(restored),
        "exact_reversal_evidence": exact[:32],
        "exact_reversal_evidence_truncated": len(exact) > 32,
        "mechanism_assertions": {
            "candidate_diff_fragments": list(case.candidate_diff_fragments),
            "fix_diff_fragments": list(case.fix_diff_fragments),
            "fix_message_fragments": list(case.fix_message_fragments),
            "candidate_parent_source_path": case.parent_source_path,
            "candidate_parent_source_fragments": list(case.parent_source_fragments),
            "candidate_source_path": case.candidate_source_path,
            "candidate_source_fragments": list(case.candidate_source_fragments),
            "candidate_source_forbidden_fragments": list(
                case.candidate_source_forbidden_fragments
            ),
        },
        "checks": checks,
        "passed": all(checks.values()),
    }


def build_witness(
    repository: Path,
    *,
    overlay_summary: Mapping[str, object],
    overlay_rows: Sequence[Mapping[str, object]],
    semantic_results: Sequence[Mapping[str, object]],
    observed_ai_shas: set[str],
    ledger: Mapping[str, object],
    cases: Sequence[CausalCase] = CASES,
    timeout: int = 120,
) -> dict[str, object]:
    if overlay_summary.get("all_exact_pairs_conserved") is not True:
        raise ValueError("merge-member topology overlay is not lossless")
    if int(overlay_summary.get("hard_filter_count", -1)) != 0:
        raise ValueError("merge-member topology overlay used a hard filter")
    if int(overlay_summary.get("model_labels_used_for_membership_or_rank", -1)) != 0:
        raise ValueError("model labels affected merge-member membership or rank")
    if int(overlay_summary.get("input_exact_pair_count", -1)) != int(
        overlay_summary.get("retained_exact_pair_count", -2)
    ):
        raise ValueError("merge-member exact-pair counts do not conserve")
    reviews = _review_index(semantic_results)
    prior_statuses = _ledger_statuses(ledger)
    results: list[dict[str, object]] = []
    for case in cases:
        overlay_row = _resolve_overlay_row(
            overlay_rows, case.candidate_prefix, case.fix_prefix
        )
        candidate_sha = str(overlay_row["candidate_sha"])
        fix_sha = str(overlay_row["member_fix_sha"])
        review_key = f"{candidate_sha[:12]}__{fix_sha[:12]}"
        review_row = reviews.get(review_key)
        if review_row is None:
            raise ValueError(f"missing semantic review: {review_key}")
        results.append(
            _case_proof(
                repository,
                case,
                overlay_row=overlay_row,
                review_row=review_row,
                observed_ai_shas=observed_ai_shas,
                prior_statuses=prior_statuses,
                timeout=timeout,
            )
        )
    edges = {(row["candidate_sha"], row["fix_sha"]) for row in results}
    if len(edges) != len(results):
        raise ValueError("causal batch contains duplicate edges")
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_merge_member_causal_batch_witness",
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
            "unique_candidate_count": len({row["candidate_sha"] for row in results}),
            "unique_fix_count": len({row["fix_sha"] for row in results}),
            "mechanism_group_count": len(
                {row["mechanism_group"] for row in results}
            ),
            "causal_role_counts": dict(
                sorted(Counter(row["causal_role"] for row in results).items())
            ),
            "failed_case_count": sum(row["passed"] is not True for row in results),
            "source_exact_pair_count_conserved": int(
                overlay_summary["retained_exact_pair_count"]
            ),
        },
        "witness_passed": bool(results) and all(row["passed"] is True for row in results),
        "claim_boundary": (
            "The 8,864 exact merge-member pairs remain a lossless scheduling universe. "
            "Each confirmed edge additionally requires observed-AI membership, direct "
            "strict ancestry, complete local deltas, an atomic fix member, exact same-path "
            "reversal, mechanism-specific source assertions, and a matching fix rationale. "
            "Manifested fix-parent assertions prove that the attributed faulty contract "
            "survived intervening history, while causal_role separates direct origins from "
            "compositional contributors. Model PROMOTE is supporting triage only. DEFER "
            "and REJECT never delete pairs."
        ),
    }


def _validate_linked_packet(result: Mapping[str, object]) -> dict[str, str]:
    raw_path = result.get("packet_path")
    expected = str(result.get("packet_sha256") or "")
    if not isinstance(raw_path, str) or not raw_path or not expected:
        raise ValueError("semantic result lacks linked packet provenance")
    packet_path = Path(raw_path).resolve()
    actual = _sha256(packet_path)
    if actual != expected:
        raise ValueError(f"semantic result packet checksum drift: {packet_path}")
    return {"path": str(packet_path), "sha256": actual}


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.repo_timeout < 1:
        raise SystemExit("--repo-timeout must be positive")
    repository = args.repository.resolve()
    overlay_dir = args.topology_overlay_dir.resolve()
    summary_path = overlay_dir / "summary.json"
    queue_path = overlay_dir / "exact_member_topology_queue.jsonl"
    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    ledger_path = args.ledger.resolve()
    review_paths = [value.resolve() for value in args.semantic_review_result]
    overlay_summary = _load_json(summary_path)
    overlay_rows = _load_jsonl(queue_path)
    semantic_results = [_load_json(value) for value in review_paths]
    ai_rows = _load_jsonl(ai_path)
    ledger = _load_json(ledger_path)
    case_manifest_path = args.case_manifest.resolve() if args.case_manifest else None
    try:
        cases = _load_case_manifest(case_manifest_path) if case_manifest_path else CASES
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    output_artifacts = overlay_summary.get("output_artifacts")
    queue_record = (
        output_artifacts.get("exact_member_topology_queue")
        if isinstance(output_artifacts, Mapping)
        else None
    )
    expected_queue_digest = (
        str(queue_record.get("sha256") or "")
        if isinstance(queue_record, Mapping)
        else ""
    )
    if not expected_queue_digest or expected_queue_digest != _sha256(queue_path):
        raise SystemExit("merge-member topology overlay queue checksum drift")
    try:
        payload = build_witness(
            repository,
            overlay_summary=overlay_summary,
            overlay_rows=overlay_rows,
            semantic_results=semantic_results,
            observed_ai_shas={str(row.get("sha") or "") for row in ai_rows},
            ledger=ledger,
            cases=cases,
            timeout=args.repo_timeout,
        )
        linked_packets = [_validate_linked_packet(result) for result in semantic_results]
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    payload["source_artifacts"] = {
        "ai_commits": {"path": str(ai_path), "sha256": _sha256(ai_path)},
        "topology_overlay_summary": {
            "path": str(summary_path),
            "sha256": _sha256(summary_path),
        },
        "topology_overlay_queue": {
            "path": str(queue_path),
            "sha256": _sha256(queue_path),
        },
        "semantic_review_results": [
            {"path": str(path), "sha256": _sha256(path)} for path in review_paths
        ],
        "semantic_review_packets": linked_packets,
        "prior_ledger": {
            "path": str(ledger_path),
            "sha256": _sha256(ledger_path),
        },
    }
    if case_manifest_path is not None:
        payload["source_artifacts"]["case_manifest"] = {
            "path": str(case_manifest_path),
            "sha256": _sha256(case_manifest_path),
        }
    if payload["witness_passed"] is not True:
        failed = {
            str(row["key"]): [
                key for key, value in row["checks"].items() if value is not True
            ]
            for row in payload["case_results"]
            if not row["passed"]
        }
        raise SystemExit(f"merge-member causal witness failed: {failed}")
    _atomic_json(args.output.resolve(), payload)
    print("Coolify merge-member causal batch witness frozen")
    print(f"  confirmed edges : {payload['summary']['confirmed_edge_count']}")
    print(f"  unique AI       : {payload['summary']['unique_candidate_count']}")
    print(f"  mechanisms      : {payload['summary']['mechanism_group_count']}")
    print(f"  output          : {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
