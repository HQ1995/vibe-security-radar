#!/usr/bin/env python3
"""Freeze claim-grade causal witnesses from the Coolify exact-delta frontier."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cohort_coolify_exact_delta_review_packet import _git
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _is_ancestor,
)
from cohort_coolify_preimage_exact_delta_bridge import (
    CommitDelta,
    _delta_matches,
    _inspect_commit_delta,
    _meaningful,
)


@dataclass(frozen=True)
class CausalCase:
    key: str
    candidate_prefix: str
    fix_prefix: str
    adjudication: str
    mechanism_group: str
    claim: str
    fix_message_fragments: tuple[str, ...]
    model_promotion_required: bool = True
    exact_line_fragments: tuple[str, ...] = ()
    candidate_diff_fragments: tuple[str, ...] = ()
    fix_diff_fragments: tuple[str, ...] = ()
    causal_role: str = "DIRECT_ORIGIN"
    parent_source_path: str | None = None
    parent_source_fragments: tuple[str, ...] = ()
    parent_source_forbidden_fragments: tuple[str, ...] = ()
    candidate_source_path: str | None = None
    candidate_source_fragments: tuple[str, ...] = ()
    candidate_source_forbidden_fragments: tuple[str, ...] = ()
    fix_parent_source_path: str | None = None
    fix_parent_source_fragments: tuple[str, ...] = ()
    fix_parent_source_forbidden_fragments: tuple[str, ...] = ()


CASES = (
    CausalCase(
        "excluded_container_default_status",
        "f81640e316f3",
        "498b189286c0",
        "CONFIRMED_DIRECT_AI_INCOMPLETE_STATUS_REPAIR",
        "excluded_container_default_status",
        "the AI fix hard-coded exited:healthy for fully excluded services; the follow-up computes real excluded-container status",
        ("correct status for services with all containers excluded",),
    ),
    CausalCase(
        "unknown_container_health_preservation",
        "498b189286c0",
        "e3746a4b8874",
        "CONFIRMED_DIRECT_AI_INCOMPLETE_STATUS_REPAIR",
        "unknown_container_health_preservation",
        "the AI repair treated nullable health through a truthiness guard; the follow-up explicitly preserves unknown health",
        ("preserve unknown health state",),
    ),
    CausalCase(
        "manual_webhook_repository_casefold",
        "c1518ba1c0be",
        "809d9b21fa96",
        "CONFIRMED_DIRECT_AI_CASE_SENSITIVITY_REGRESSION",
        "manual_webhook_repository_casefold",
        "the AI exact-match repair used case-sensitive repository comparison; the follow-up normalizes Git host casing",
        ("case-insensitively",),
        exact_line_fragments=("hash_equals",),
    ),
    CausalCase(
        "image_retention_runtime_images",
        "4ed7a4238a50",
        "6ea563c6ac75",
        "CONFIRMED_DIRECT_AI_INCOMPLETE_IMAGE_RETENTION",
        "image_retention_runtime_images",
        "the AI image-retention feature omitted active helper and realtime images; the fix protects both from pruning",
        ("Prevent coolify-helper and coolify-realtime images from being pruned",),
    ),
    CausalCase(
        "service_name_last_separator",
        "4706bc23aa86",
        "8c40cc607afa",
        "CONFIRMED_DIRECT_AI_SERVICE_NAME_PARSING_REGRESSION",
        "service_name_last_separator",
        "the AI prerequisite helper split service names at the first hyphen; the fix uses the final separator for hyphenated names",
        ("Fragile service name parsing",),
    ),
    CausalCase(
        "duplicate_proxy_restart_notifications",
        "e4810a28d28b",
        "b00d8902f4a7",
        "CONFIRMED_DIRECT_AI_DUPLICATE_NOTIFICATION_REGRESSION",
        "duplicate_proxy_restart_notifications",
        "the AI background restart job dispatched a UI event already emitted by the completion listener; the fix removes the redundant dispatch",
        (
            "Fix duplicate proxy restart notifications",
            "Remove redundant ProxyStatusChangedUI dispatch",
        ),
        model_promotion_required=False,
        exact_line_fragments=(
            "ProxyStatusChangedUI::dispatch($teamId, $this->activity_id)",
        ),
    ),
    CausalCase(
        "null_versions_cache_assignment",
        "5d73b76a4419",
        "cb0f2301f520",
        "CONFIRMED_DIRECT_AI_NULL_VERSION_CACHE_REGRESSION",
        "null_versions_cache_assignment",
        "the AI cache refactor assigned nullable versions data before validation; the fix caches only a successful load",
        ("handle null versions",),
        exact_line_fragments=("cachedVersionsFile",),
    ),
    CausalCase(
        "running_version_downgrade_guard",
        "d9774d296849",
        "cd10796612bd",
        "CONFIRMED_DIRECT_AI_INCOMPLETE_DOWNGRADE_PREVENTION",
        "running_version_downgrade_guard",
        "the AI downgrade prevention left cache and running-version paths insufficiently validated; the follow-up adds both guards",
        ("validate cache and add running version checks",),
    ),
    CausalCase(
        "deployment_technical_detail_disclosure",
        "97550f40669f",
        "b602fef4dbce",
        "CONFIRMED_DIRECT_AI_TECHNICAL_DETAIL_DISCLOSURE",
        "deployment_technical_detail_disclosure",
        "the AI deployment logging emitted detailed exception and trace material; the repair hides technical details while retaining useful error types",
        ("hidden technical details",),
    ),
    CausalCase(
        "hetzner_pending_ip_retention",
        "706923671405",
        "e01b8a057e64",
        "CONFIRMED_DIRECT_AI_PROVISIONING_STATE_REGRESSION",
        "hetzner_pending_ip_retention",
        "the AI IPv4/IPv6 feature threw when a fresh cloud instance had no immediate public IP; the fix retains it for later polling",
        ("retain cloud instances awaiting IPs",),
        exact_line_fragments=("No public IP address available",),
    ),
    CausalCase(
        "proxy_restart_debounce_guard",
        "c42fb8134704",
        "2fc870c6eb08",
        "CONFIRMED_DIRECT_AI_INEFFECTIVE_DEBOUNCE_GUARD",
        "proxy_restart_debounce_guard",
        "the AI restart guard reset immediately after dispatch and could not debounce duplicates; the fix keeps the guard set on success",
        ("ineffective restartInitiated guard",),
        exact_line_fragments=("restartInitiated = false",),
    ),
    CausalCase(
        "garage_rpc_secret_length",
        "0f54c194d7a3",
        "b5416859e5b5",
        "CONFIRMED_DIRECT_AI_INVALID_SECRET_CONFIGURATION",
        "garage_rpc_secret_length",
        "the AI Garage template wired a 32-hex RPC secret where Garage requires 64; the fix changes the generated secret source",
        ("generate valid Garage RPC secret",),
        exact_line_fragments=("SERVICE_HEX_32_RPCSECRET",),
    ),
    CausalCase(
        "user_team_null_context",
        "2cf915aed813",
        "2743229cc49c",
        "CONFIRMED_DIRECT_AI_TEAM_CONTEXT_NULL_REGRESSION",
        "user_team_null_context",
        "the AI User-model refactor assumed a current session team; the follow-up makes non-web and missing-team contexts safe",
        ("complete User model fixes for non-web contexts",),
    ),
    CausalCase(
        "sudo_keyword_prefix_collision",
        "01635e8b80ae",
        "246e3cd8a286",
        "CONFIRMED_DIRECT_AI_SUDO_PREFIX_CLASSIFICATION_REGRESSION",
        "sudo_keyword_prefix_collision",
        "the AI keyword list used prefix matching so do also matched docker; the fix uses word-boundary control-keyword detection",
        ("sudo prefix bug",),
    ),
    CausalCase(
        "ray_parser_debug_hooks",
        "5b9146d8df7a",
        "9b060958aad7",
        "CONFIRMED_DIRECT_AI_RUNTIME_DEBUG_INSTRUMENTATION",
        "ray_parser_debug_hooks",
        "the AI parser repair added runtime Ray diagnostics; the cleanup fix removes those hooks",
        ("remove Ray debug hooks from runtime",),
        exact_line_fragments=("ray(",),
    ),
    CausalCase(
        "ray_webhook_debug_hooks",
        "dc15bee980ed",
        "9b060958aad7",
        "CONFIRMED_DIRECT_AI_RUNTIME_DEBUG_INSTRUMENTATION",
        "ray_webhook_debug_hooks",
        "the AI webhook feature added request and response Ray diagnostics on runtime paths; the cleanup fix removes them",
        ("remove Ray debug hooks from runtime",),
        exact_line_fragments=("ray(",),
    ),
    CausalCase(
        "sentinel_status_debug_logging",
        "d2d9c1b2bcac",
        "14bba8ba86a2",
        "CONFIRMED_DIRECT_AI_RUNTIME_DEBUG_INSTRUMENTATION",
        "sentinel_status_debug_logging",
        "the AI debug commit instrumented runtime Sentinel status paths with detailed identifiers and states; the fix removes the logging",
        ("remove debug logging",),
        exact_line_fragments=("Log::debug",),
    ),
    CausalCase(
        "exited_container_health_suffix",
        "70fb4c6869ed",
        "ac9eca3c051e",
        "CONFIRMED_DIRECT_AI_EXITED_HEALTH_STATUS_REGRESSION",
        "exited_container_health_suffix",
        "the AI status-aggregation refactor emitted an unhealthy suffix for exited containers; the fix returns the exited status without health",
        ("don't show health status for exited containers",),
        exact_line_fragments=("exited:unhealthy:excluded",),
    ),
    CausalCase(
        "finished_deployment_terminal_state",
        "42f916dce235",
        "a2e5b2d67d8c",
        "CONFIRMED_DIRECT_AI_INCOMPLETE_TERMINAL_STATE_GUARD",
        "finished_deployment_terminal_state",
        "the AI transition refactor treated only failed and cancelled deployments as terminal; the fix also protects finished deployments",
        ("healthy container completes rolling update",),
    ),
    CausalCase(
        "webhook_settings_migration_order",
        "53d1ad48cddb",
        "a3df33a4e06c",
        "CONFIRMED_DIRECT_AI_MIGRATION_ORDER_REGRESSION",
        "webhook_settings_migration_order",
        "the AI population migration ran before the table-creation migration; the fix deletes and reorders the migration set",
        ("correct webhook notification settings migration",),
        exact_line_fragments=("webhook_notification_settings",),
    ),
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--delta-bridge-dir", type=Path, required=True)
    parser.add_argument("--semantic-review-aggregate", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument(
        "--case-manifest",
        type=Path,
        help=(
            "optional frozen JSON case manifest; the built-in first batch is "
            "used when omitted"
        ),
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
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} is not an object")
            rows.append(value)
    return rows


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
    raw_fragments = row.get("fix_message_fragments")
    if (
        not isinstance(raw_fragments, list)
        or not raw_fragments
        or not all(isinstance(value, str) and value for value in raw_fragments)
    ):
        raise ValueError(
            f"case manifest row {index} has invalid fix_message_fragments"
        )
    raw_exact_fragments = row.get("exact_line_fragments", [])
    if not isinstance(raw_exact_fragments, list) or not all(
        isinstance(value, str) and value for value in raw_exact_fragments
    ):
        raise ValueError(
            f"case manifest row {index} has invalid exact_line_fragments"
        )
    model_required = row.get("model_promotion_required", True)
    if not isinstance(model_required, bool):
        raise ValueError(
            f"case manifest row {index} has invalid model_promotion_required"
        )
    causal_role = row.get("causal_role", "DIRECT_ORIGIN")
    if not isinstance(causal_role, str) or not causal_role.strip():
        raise ValueError(f"case manifest row {index} has invalid causal_role")
    optional_lists = (
        "candidate_diff_fragments",
        "fix_diff_fragments",
        "parent_source_fragments",
        "parent_source_forbidden_fragments",
        "candidate_source_fragments",
        "candidate_source_forbidden_fragments",
        "fix_parent_source_fragments",
        "fix_parent_source_forbidden_fragments",
    )
    lists: dict[str, tuple[str, ...]] = {}
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
    source_assertions = (
        (
            "parent",
            optional_paths["parent_source_path"],
            lists["parent_source_fragments"],
            lists["parent_source_forbidden_fragments"],
        ),
        (
            "candidate",
            optional_paths["candidate_source_path"],
            lists["candidate_source_fragments"],
            lists["candidate_source_forbidden_fragments"],
        ),
        (
            "fix-parent",
            optional_paths["fix_parent_source_path"],
            lists["fix_parent_source_fragments"],
            lists["fix_parent_source_forbidden_fragments"],
        ),
    )
    for label, path, required, forbidden in source_assertions:
        if bool(path) != bool(required or forbidden):
            raise ValueError(
                f"case manifest row {index} has incomplete {label} source assertion"
            )
    return CausalCase(
        key=values["key"],
        candidate_prefix=values["candidate_prefix"],
        fix_prefix=values["fix_prefix"],
        adjudication=values["adjudication"],
        mechanism_group=values["mechanism_group"],
        claim=values["claim"],
        fix_message_fragments=tuple(raw_fragments),
        model_promotion_required=model_required,
        exact_line_fragments=tuple(raw_exact_fragments),
        candidate_diff_fragments=lists["candidate_diff_fragments"],
        fix_diff_fragments=lists["fix_diff_fragments"],
        causal_role=causal_role.strip(),
        parent_source_path=optional_paths["parent_source_path"],
        parent_source_fragments=lists["parent_source_fragments"],
        parent_source_forbidden_fragments=lists[
            "parent_source_forbidden_fragments"
        ],
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
    keys = [case.key for case in cases]
    edges = [(case.candidate_prefix, case.fix_prefix) for case in cases]
    if len(set(keys)) != len(keys):
        raise ValueError("case manifest contains duplicate keys")
    if len(set(edges)) != len(edges):
        raise ValueError("case manifest contains duplicate edges")
    return cases


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_unique(
    rows: Sequence[Mapping[str, object]],
    candidate_prefix: str,
    fix_prefix: str,
) -> Mapping[str, object]:
    matches = [
        row
        for row in rows
        if str(row.get("candidate_sha") or "").startswith(candidate_prefix)
        and str(row.get("fix_sha") or "").startswith(fix_prefix)
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{candidate_prefix}:{fix_prefix} resolved to {len(matches)} rows"
        )
    return matches[0]


def _message_contains(message: str, fragments: Sequence[str]) -> bool:
    lowered = message.casefold()
    return all(fragment.casefold() in lowered for fragment in fragments)


def _line_evidence(
    candidate_delta: CommitDelta, fix_delta: CommitDelta
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    all_matches = [
        *_delta_matches(
            candidate_delta.additions,
            fix_delta.removals,
            direction="candidate_added_fix_removed",
        ),
        *_delta_matches(
            candidate_delta.removals,
            fix_delta.additions,
            direction="candidate_removed_fix_added",
        ),
    ]
    exact = [
        row
        for row in all_matches
        if row.get("match_kind") == "exact_same_path"
        and row.get("meaningful") is True
    ]
    forward = [
        row
        for row in exact
        if row.get("direction") == "candidate_added_fix_removed"
    ]
    restored = [
        row
        for row in exact
        if row.get("direction") == "candidate_removed_fix_added"
    ]
    return exact, forward, restored


def _fix_addition_sample(
    fix_delta: CommitDelta, focal_paths: set[str]
) -> list[dict[str, str]]:
    rows: dict[tuple[str, str], dict[str, str]] = {}
    for line in fix_delta.additions:
        if line.path not in focal_paths or not _meaningful(line.content):
            continue
        normalized = " ".join(line.content.strip().split())
        key = (line.path, line.content_sha256)
        rows[key] = {
            "path": line.path,
            "content_sha256": line.content_sha256,
            "content_excerpt": (
                normalized[:179] + "…" if len(normalized) > 180 else normalized
            ),
        }
    return [rows[key] for key in sorted(rows)][:32]


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


def _case_proof(
    repository: Path,
    case: CausalCase,
    *,
    bridge_row: Mapping[str, object],
    review_row: Mapping[str, object],
    observed_ai_shas: set[str],
    prior_statuses: Mapping[tuple[str, str], str],
    timeout: int,
) -> dict[str, object]:
    candidate_sha = str(bridge_row["candidate_sha"])
    fix_sha = str(bridge_row["fix_sha"])
    candidate_delta = _inspect_commit_delta(
        repository, candidate_sha, compare_all_parents=True, timeout=timeout
    )
    fix_delta = _inspect_commit_delta(
        repository, fix_sha, compare_all_parents=False, timeout=timeout
    )
    exact, forward, restored = _line_evidence(candidate_delta, fix_delta)
    candidate_metadata = _commit_metadata(repository, candidate_sha)
    fix_metadata = _commit_metadata(repository, fix_sha)
    fix_message = str(fix_metadata.get("message") or "")
    candidate_diff = ""
    if case.candidate_diff_fragments:
        candidate_diff = _git(
            repository,
            ["show", "--format=", "--find-renames", candidate_sha],
            timeout=timeout,
        )
    fix_diff = ""
    if case.fix_diff_fragments:
        fix_diff = _git(
            repository,
            ["show", "--format=", "--find-renames", fix_sha],
            timeout=timeout,
        )
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
    evidence_text = "\n".join(
        str(row.get("content_excerpt") or "") for row in [*forward, *restored]
    )
    review_promoted = review_row.get("model_union_promoted") is True
    edge = (candidate_sha, fix_sha)
    prior_status = prior_statuses.get(edge, "NEW_EDGE")
    checks = {
        "candidate_is_observed_ai": candidate_sha in observed_ai_shas,
        "candidate_is_ancestor_of_fix": _is_ancestor(
            repository, candidate_sha, fix_sha
        ),
        "source_owner_edge_retained": bridge_row.get("retained") is True,
        "exact_delta_tier_zero": int(bridge_row.get("delta_bridge_tier", -1)) == 0,
        "candidate_delta_inspection_complete": not candidate_delta.coverage_gaps,
        "fix_delta_inspection_complete": not fix_delta.coverage_gaps,
        "candidate_delta_is_exactly_reversed_by_fix": bool(forward or restored),
        "fix_message_matches_adjudicated_mechanism": _message_contains(
            fix_message, case.fix_message_fragments
        ),
        "required_exact_line_fragments_present": _message_contains(
            evidence_text, case.exact_line_fragments
        ),
        "candidate_diff_encodes_faulty_mechanism": _message_contains(
            candidate_diff, case.candidate_diff_fragments
        ),
        "fix_diff_encodes_repaired_mechanism": _message_contains(
            fix_diff, case.fix_diff_fragments
        ),
        "candidate_parent_contract_matches": _message_contains(
            parent_source, case.parent_source_fragments
        ),
        "candidate_parent_forbidden_fragments_absent": not any(
            fragment.casefold() in parent_source.casefold()
            for fragment in case.parent_source_forbidden_fragments
        ),
        "candidate_source_contract_matches": _message_contains(
            candidate_source, case.candidate_source_fragments
        ),
        "candidate_source_forbidden_fragments_absent": not any(
            fragment.casefold() in candidate_source.casefold()
            for fragment in case.candidate_source_forbidden_fragments
        ),
        "faulty_contract_survives_to_fix_parent": _message_contains(
            fix_parent_source, case.fix_parent_source_fragments
        ),
        "fix_parent_repair_fragments_absent": not any(
            fragment.casefold() in fix_parent_source.casefold()
            for fragment in case.fix_parent_source_forbidden_fragments
        ),
        "semantic_basis_satisfied": (
            review_promoted
            if case.model_promotion_required
            else _message_contains(fix_message, case.fix_message_fragments)
        ),
        "edge_not_previously_adjudicated": prior_status
        not in {"CONFIRMED_TRUE_POSITIVE", "REJECTED_NONCAUSAL"},
    }
    focal_paths = {
        str(row["candidate_path"]) for row in [*forward, *restored]
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
            "exact_delta_plus_fix_rationale_plus_model_semantic_lead"
            if case.model_promotion_required
            else "exact_delta_plus_explicit_fix_commit_rationale"
        ),
        "candidate_metadata": candidate_metadata,
        "fix_metadata": fix_metadata,
        "bridge_rank": bridge_row.get("delta_bridge_rank"),
        "bridge_class": bridge_row.get("delta_bridge_class"),
        "source_pair_sha256": bridge_row.get("source_pair_sha256"),
        "prior_ledger_status": prior_status,
        "semantic_review": {
            "model_union_promoted": review_promoted,
            "review_count": review_row.get("review_count"),
            "models": review_row.get("models"),
            "verdicts": review_row.get("verdicts"),
            "claim_grade_status_before_witness": review_row.get(
                "claim_grade_status"
            ),
        },
        "exact_same_path_reversal_count": len(exact),
        "candidate_added_fix_removed_count": len(forward),
        "exact_reversal_evidence": forward[:24],
        "exact_reversal_evidence_truncated": len(forward) > 24,
        "candidate_removed_fix_added_count": len(restored),
        "restored_exact_reversal_evidence": restored[:24],
        "restored_exact_reversal_evidence_truncated": len(restored) > 24,
        "fix_addition_evidence": _fix_addition_sample(fix_delta, focal_paths),
        "checks": checks,
        "passed": all(checks.values()),
    }


def build_witness(
    repository: Path,
    *,
    bridge_summary: Mapping[str, object],
    bridge_rows: list[dict[str, object]],
    semantic_aggregate: Mapping[str, object],
    observed_ai_shas: set[str],
    ledger: Mapping[str, object],
    cases: Sequence[CausalCase] = CASES,
    timeout: int = 120,
) -> dict[str, object]:
    if bridge_summary.get("all_source_owner_pairs_conserved") is not True:
        raise ValueError("delta bridge is not lossless")
    conservation = semantic_aggregate.get("conservation")
    if not isinstance(conservation, Mapping) or conservation.get("passed") is not True:
        raise ValueError("semantic review aggregate is not lossless")
    if int(semantic_aggregate.get("claim_grade_positive_edge_count", -1)) != 0:
        raise ValueError("semantic review improperly claims positives")
    review_rows = semantic_aggregate.get("edge_records")
    if not isinstance(review_rows, list):
        raise ValueError("semantic review edge records are malformed")
    prior_statuses = _ledger_statuses(ledger)
    results: list[dict[str, object]] = []
    for case in cases:
        bridge_row = _resolve_unique(
            bridge_rows, case.candidate_prefix, case.fix_prefix
        )
        review_row = _resolve_unique(
            [row for row in review_rows if isinstance(row, Mapping)],
            case.candidate_prefix,
            case.fix_prefix,
        )
        results.append(
            _case_proof(
                repository,
                case,
                bridge_row=bridge_row,
                review_row=review_row,
                observed_ai_shas=observed_ai_shas,
                prior_statuses=prior_statuses,
                timeout=timeout,
            )
        )
    edges = {
        (str(row["candidate_sha"]), str(row["fix_sha"])) for row in results
    }
    if len(edges) != len(results):
        raise ValueError("causal batch contains duplicate edges")
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_exact_delta_causal_batch_witness",
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
            "unique_candidate_count": len(
                {str(row["candidate_sha"]) for row in results}
            ),
            "unique_fix_count": len({str(row["fix_sha"]) for row in results}),
            "mechanism_group_count": len(
                {str(row["mechanism_group"]) for row in results}
            ),
            "model_led_edge_count": sum(case.model_promotion_required for case in cases),
            "explicit_fix_rationale_edge_count": sum(
                not case.model_promotion_required for case in cases
            ),
            "failed_case_count": sum(row["passed"] is not True for row in results),
            "causal_role_counts": dict(
                sorted(Counter(str(row["causal_role"]) for row in results).items())
            ),
        },
        "witness_passed": bool(results) and all(row["passed"] is True for row in results),
        "claim_boundary": (
            "Each confirmed edge requires observed-AI membership, strict ancestry, "
            "retained source ownership, a meaningful candidate-added line exactly "
            "removed by the fix or a meaningful candidate-removed line exactly restored "
            "by the fix, a mechanism-specific fix rationale, and either a semantic "
            "model lead or an explicit fix-body admission. When manifested, source-state "
            "assertions also prove that the faulty contract survived to the fix parent "
            "and distinguish direct origins from compositional contributors. Mechanism "
            "groups are causal commit/fix transitions and may not be distinct vulnerabilities."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.repo_timeout < 1:
        raise SystemExit("--repo-timeout must be positive")
    repository = args.repository.resolve()
    bridge_dir = args.delta_bridge_dir.resolve()
    bridge_summary_path = bridge_dir / "summary.json"
    bridge_pairs_path = bridge_dir / "delta_bridge_pairs.jsonl"
    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    semantic_path = args.semantic_review_aggregate.resolve()
    ledger_path = args.ledger.resolve()
    bridge_summary = _load_json(bridge_summary_path)
    bridge_rows = _load_jsonl(bridge_pairs_path)
    semantic_aggregate = _load_json(semantic_path)
    ai_rows = _load_jsonl(ai_path)
    ledger = _load_json(ledger_path)
    case_manifest_path = args.case_manifest.resolve() if args.case_manifest else None
    cases = _load_case_manifest(case_manifest_path) if case_manifest_path else CASES
    payload = build_witness(
        repository,
        bridge_summary=bridge_summary,
        bridge_rows=bridge_rows,
        semantic_aggregate=semantic_aggregate,
        observed_ai_shas={str(row.get("sha") or "") for row in ai_rows},
        ledger=ledger,
        cases=cases,
        timeout=args.repo_timeout,
    )
    payload["source_artifacts"] = {
        "ai_commits": {"path": str(ai_path), "sha256": _sha256(ai_path)},
        "delta_bridge_summary": {
            "path": str(bridge_summary_path),
            "sha256": _sha256(bridge_summary_path),
        },
        "delta_bridge_pairs": {
            "path": str(bridge_pairs_path),
            "sha256": _sha256(bridge_pairs_path),
        },
        "semantic_review_aggregate": {
            "path": str(semantic_path),
            "sha256": _sha256(semantic_path),
        },
        "prior_ledger": {"path": str(ledger_path), "sha256": _sha256(ledger_path)},
    }
    if case_manifest_path is not None:
        payload["source_artifacts"]["case_manifest"] = {
            "path": str(case_manifest_path),
            "sha256": _sha256(case_manifest_path),
    }
    if payload["witness_passed"] is not True:
        failed = {
            str(row["key"]): sorted(
                str(check)
                for check, passed in dict(row["checks"]).items()
                if passed is not True
            )
            for row in payload["case_results"]
            if row["passed"] is not True
        }
        raise SystemExit(f"exact-delta causal witness failed: {failed}")
    _atomic_json(args.output.resolve(), payload)
    print("Coolify exact-delta causal batch witness frozen")
    print(f"  confirmed edges : {payload['summary']['confirmed_edge_count']}")
    print(f"  unique AI       : {payload['summary']['unique_candidate_count']}")
    print(f"  mechanisms      : {payload['summary']['mechanism_group_count']}")
    print(f"  output          : {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
