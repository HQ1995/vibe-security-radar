#!/usr/bin/env python3
"""Prepare or execute a cost-capped, recall-safe AI candidate-routing pilot."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import subprocess
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from cohort.complex_controls import (
    ComplexControlContractError,
    normalize_complex_controls,
    routing_target_controls,
)
from cohort.relations import canonical_repository_identity, normalize_repository_aliases
from cohort.repos import discover_local_clones
from cohort.routing_pilot import (
    RoutingPilotContractError,
    build_budget_contract,
    evaluate_pilot_results,
    select_blind_pilot_edges,
)
from cohort.security_bridge import cross_file_security_bridge
from cve_analyzer.llm_client import extract_response_text, resolve_litellm_config


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_CONTROLS = _SCRIPT_DIR / "cohort_positive_controls.json"
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"
DEFAULT_MODEL = "gpt-5.6-luna"
DEFAULT_REASONING_EFFORT = "low"
DEFAULT_COMPARATORS = 3
DEFAULT_DIFF_CHARS = 8000
DEFAULT_MAX_OUTPUT_TOKENS = 2000
DEFAULT_INPUT_PRICE = "0.20"
DEFAULT_OUTPUT_PRICE = "1.20"
DEFAULT_MAX_COST_USD = "0.25"
DEFAULT_SECURITY_BRIDGE_CHARS = 4000
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SUPPORTED_BACKENDS = {"litellm", "cliproxyapi"}
CLIPROXY_REASONING_ALIAS = "backend-alias"
CLIPROXY_EXPLICIT_REASONING_EFFORTS = {"low", "medium", "high"}

SYSTEM_PROMPT = """\
You rank candidate software commits for security-causality review. This is a
recall-first queue: false positives are acceptable and your answer will never
delete a candidate. Do not require SZZ line overlap. A later fix can repair the
same defect through a caller, guard, validation layer, dataflow boundary, or
refactor. Judge only the supplied candidate and fix evidence.

Return JSON only with exactly these keys:
{"causality":"likely|possible|unlikely|insufficient","reason":"max 40 words"}

Use possible when a causal mechanism is plausible but not fully proved. Use
insufficient only when the supplied evidence is unreadable or genuinely lacks
enough code to assess.
"""

USER_TEMPLATE = """\
Repository: {repository_identity}
Candidate-to-fix relation: {relation}
Advisories attached to this fix: {advisories}

## Earlier candidate commit
SHA: {candidate_sha}
Date: {candidate_date}
Subject: {candidate_subject}
```diff
{candidate_diff}
```

## Later security-fix commit
SHA: {fix_sha}
Date: {fix_date}
Subject: {fix_subject}
```diff
{fix_diff}
```

Does the later fix likely or possibly repair a defect introduced by the earlier
candidate? Prefer possible over unlikely when a concrete cross-file or indirect
mechanism remains plausible.
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--relation-dir", type=Path, required=True)
    prepare.add_argument(
        "--backend",
        choices=sorted(SUPPORTED_BACKENDS),
        default="litellm",
    )
    prepare.add_argument("--controls", type=Path, default=DEFAULT_CONTROLS)
    prepare.add_argument(
        "--control-format",
        choices=("atomic", "complex-target"),
        default="atomic",
        help="complex-target flattens every same-repository target obligation",
    )
    prepare.add_argument(
        "--control-id",
        action="append",
        default=[],
        help="diagnostic scope over exact control advisory/obligation IDs",
    )
    prepare.add_argument("--repository-aliases", type=Path, default=DEFAULT_ALIASES)
    prepare.add_argument("--comparators-per-control", type=int, default=DEFAULT_COMPARATORS)
    prepare.add_argument(
        "--allow-fewer-comparators",
        action="store_true",
        help=(
            "keep sparse positive controls even when fewer same-fix comparators exist;"
            " actual per-control counts are frozen in the pilot spec"
        ),
    )
    prepare.add_argument("--diff-chars", type=int, default=DEFAULT_DIFF_CHARS)
    prepare.add_argument(
        "--materialize-missing",
        action="store_true",
        help="explicitly allow partial clones to fetch missing commit blobs",
    )
    prepare.add_argument("--model", default=DEFAULT_MODEL)
    prepare.add_argument(
        "--reasoning-effort",
        default=DEFAULT_REASONING_EFFORT,
        help=(
            "explicit low/medium/high request parameter, or backend-alias only"
            " when the CLIProxyAPI model ID itself ends in an effort suffix"
        ),
    )
    prepare.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    prepare.add_argument("--input-usd-per-million", default=None)
    prepare.add_argument("--output-usd-per-million", default=None)
    prepare.add_argument("--max-cost-usd", default=DEFAULT_MAX_COST_USD)
    prepare.add_argument("--output-dir", type=Path, required=True)

    execute = subparsers.add_parser("execute")
    execute.add_argument("--pilot-dir", type=Path, required=True)
    execute.add_argument("--max-cost-usd", required=True)
    execute.add_argument("--timeout", type=float, default=180.0)
    execute.add_argument(
        "--allow-non-loopback-cliproxyapi",
        action="store_true",
        help=(
            "explicitly acknowledge that frozen repository evidence will be sent"
            " to a non-loopback CLIProxyAPI endpoint"
        ),
    )
    return parser.parse_args(argv)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _budget_prices(
    backend: str,
    input_usd_per_million: str | None,
    output_usd_per_million: str | None,
) -> tuple[str, str]:
    """Resolve explicit proxy assumptions separately from live provider prices."""

    if backend == "cliproxyapi" and (
        input_usd_per_million is None or output_usd_per_million is None
    ):
        raise RoutingPilotContractError(
            "CLIProxyAPI exposes no price contract; provide both"
            " --input-usd-per-million and --output-usd-per-million"
        )
    return (
        input_usd_per_million or DEFAULT_INPUT_PRICE,
        output_usd_per_million or DEFAULT_OUTPUT_PRICE,
    )


def _is_loopback_api_base(api_base: str) -> bool:
    """Require an explicit opt-in before sending evidence off the host."""

    hostname = urlsplit(api_base).hostname
    if not hostname:
        return False
    if hostname.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


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


def _atomic_write_json(path: Path, value: Mapping[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_write_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _aliases(path: Path) -> dict[str, str]:
    payload = _load_json(path)
    rows = payload.get("aliases")
    if payload.get("schema_version") != 1 or not isinstance(rows, list):
        raise SystemExit("repository aliases must use schema_version 1")
    return normalize_repository_aliases(rows)


def _canonical_clone_paths(
    aliases: Mapping[str, str],
) -> dict[str, Path]:
    repositories, _unresolved = discover_local_clones(_REPO_ROOT)
    resolved: dict[str, tuple[bool, Path]] = {}
    for observed, path in sorted(repositories.items()):
        identity = canonical_repository_identity(observed, aliases)
        candidate = (observed.strip().lower() == identity, path)
        if identity not in resolved or candidate[0] > resolved[identity][0]:
            resolved[identity] = candidate
    return {identity: value[1] for identity, value in resolved.items()}


def _run_git(
    repo: Path,
    arguments: list[str],
    *,
    timeout: int = 120,
    allow_lazy_fetch: bool = False,
) -> str:
    environment = dict(os.environ)
    if allow_lazy_fetch:
        environment.pop("GIT_NO_LAZY_FETCH", None)
    else:
        environment["GIT_NO_LAZY_FETCH"] = "1"
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _commit_view(
    repo: Path,
    sha: str,
    limit: int,
    *,
    allow_lazy_fetch: bool = False,
    priority_paths: Sequence[str] = (),
    priority_label: str = "Candidate-path-priority fix evidence",
    priority_evidence: Sequence[tuple[str, str]] = (),
) -> tuple[str, str, str]:
    header = _run_git(
        repo,
        ["show", "--no-patch", "--format=%s%x1f%aI", sha],
        allow_lazy_fetch=allow_lazy_fetch,
    )
    subject, separator, authored = header.strip().partition("\x1f")
    if not separator:
        return "", "", ""
    full_diff = _run_git(
        repo,
        [
            "show",
            "--first-parent",
            "--find-renames",
            "--find-copies",
            "--unified=5",
            "--no-color",
            "--format=",
            sha,
        ],
        allow_lazy_fetch=allow_lazy_fetch,
    ).strip()
    priority_chunks: list[str] = []
    seen_priority_chunks: set[str] = set()
    for path in priority_paths:
        chunk = _path_patch(
            repo,
            sha,
            path,
            allow_lazy_fetch=allow_lazy_fetch,
        ).strip()
        if chunk and chunk not in seen_priority_chunks:
            priority_chunks.append(chunk)
            seen_priority_chunks.add(chunk)
    priority_diff = "\n".join(priority_chunks)
    sections = [
        f"# {label}\n{evidence.strip()}"
        for label, evidence in priority_evidence
        if label.strip() and evidence.strip()
    ]
    if priority_diff:
        sections.append(f"# {priority_label}\n{priority_diff}")
    if sections and full_diff:
        sections.append(f"# Global fix evidence\n{full_diff}")
    diff = "\n".join(sections) if sections else full_diff
    if len(diff) > limit:
        marker = "\n...[truncated by frozen pilot contract]"
        diff = diff[: max(0, limit - len(marker))] + marker
    return subject.strip(), authored.strip(), diff


def _changed_paths(
    repo: Path,
    sha: str,
    *,
    allow_lazy_fetch: bool = False,
) -> list[str]:
    output = _run_git(
        repo,
        [
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "-r",
            sha,
        ],
        allow_lazy_fetch=allow_lazy_fetch,
    )
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def _path_patch(
    repo: Path,
    sha: str,
    path: str,
    *,
    allow_lazy_fetch: bool = False,
) -> str:
    return _run_git(
        repo,
        [
            "show",
            "--first-parent",
            "--find-renames",
            "--find-copies",
            "--unified=5",
            "--no-color",
            "--format=",
            sha,
            "--",
            path,
        ],
        allow_lazy_fetch=allow_lazy_fetch,
    ).strip()


def _cross_file_security_bridge(
    repo: Path,
    candidate_sha: str,
    fix_sha: str,
    candidate_paths: Sequence[str],
    fix_paths: Sequence[str],
    *,
    limit: int,
    allow_lazy_fetch: bool = False,
) -> dict[str, object]:
    return cross_file_security_bridge(
        repo,
        candidate_sha,
        fix_sha,
        candidate_paths,
        fix_paths,
        path_patch=_path_patch,
        limit=limit,
        allow_lazy_fetch=allow_lazy_fetch,
    )


def _prepare(args: argparse.Namespace) -> int:
    if args.diff_chars < 100 or args.max_output_tokens < 1:
        raise SystemExit("diff-chars and max-output-tokens must be positive")
    try:
        reasoning_transport = _reasoning_transport(
            backend=args.backend,
            model=args.model,
            reasoning_effort=args.reasoning_effort,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    aliases = _aliases(args.repository_aliases)
    control_payload = _load_json(args.controls)
    controls = control_payload.get("controls")
    if control_payload.get("schema_version") != 1 or not isinstance(controls, list):
        raise SystemExit("controls must use schema_version 1")
    normalized_controls: list[dict[str, object]]
    if args.control_format == "complex-target":
        try:
            normalized_controls = routing_target_controls(
                normalize_complex_controls(controls, aliases)
            )
        except ComplexControlContractError as exc:
            raise SystemExit(f"invalid complex controls: {exc}") from exc
    else:
        normalized_controls = []
        for raw in controls:
            if not isinstance(raw, dict):
                raise SystemExit("positive control row is malformed")
            row = dict(raw)
            row["repository_identity"] = canonical_repository_identity(
                str(raw.get("repository_identity") or ""), aliases
            )
            normalized_controls.append(row)
    requested_control_ids = {
        str(value).strip() for value in args.control_id if str(value).strip()
    }
    if requested_control_ids:
        available_control_ids = {
            str(control.get("advisory") or "") for control in normalized_controls
        }
        missing_control_ids = sorted(requested_control_ids - available_control_ids)
        if missing_control_ids:
            raise SystemExit(
                "unknown control-id values: " + ", ".join(missing_control_ids)
            )
        normalized_controls = [
            control
            for control in normalized_controls
            if str(control.get("advisory") or "") in requested_control_ids
        ]

    expanded_path = args.relation_dir / "candidates_expanded.jsonl"
    comparison_pool_per_control = max(
        args.comparators_per_control,
        args.comparators_per_control * 8,
    )
    item_pool = select_blind_pilot_edges(
        _load_jsonl(expanded_path),
        normalized_controls,
        comparators_per_control=comparison_pool_per_control,
        require_full_comparators=not args.allow_fewer_comparators,
    )
    repositories = _canonical_clone_paths(aliases)
    items: list[dict[str, object]] = []
    prompts: list[dict[str, object]] = []
    selection_blocked: list[dict[str, object]] = []
    materialized_evidence: list[dict[str, str]] = []
    evidence_routing: list[dict[str, object]] = []
    comparator_counts: dict[str, int] = {}
    for item in item_pool:
        role = str(item["evaluation_role"])
        matched_control = str(
            item.get("control_advisory")
            or item.get("matched_control_advisory")
            or ""
        )
        if (
            role == "unlabeled_comparator"
            and comparator_counts.get(matched_control, 0)
            >= args.comparators_per_control
        ):
            continue
        edge = item["edge"]
        assert isinstance(edge, Mapping)
        identity = str(edge["repository_identity"])
        repo = repositories.get(identity)
        if repo is None:
            raise SystemExit(f"no local clone for pilot item repository: {identity}")
        candidate_sha = str(edge["candidate_sha"])
        fix_sha = str(edge["fix_sha"])
        candidate_paths = _changed_paths(repo, candidate_sha)
        fix_paths = _changed_paths(repo, fix_sha)
        shared_paths = sorted(set(candidate_paths) & set(fix_paths))
        bridge_limit = max(
            100,
            min(DEFAULT_SECURITY_BRIDGE_CHARS, args.diff_chars // 2),
        )
        bridge = _cross_file_security_bridge(
            repo,
            candidate_sha,
            fix_sha,
            candidate_paths,
            fix_paths,
            limit=bridge_limit,
        )
        candidate_priority_evidence: list[tuple[str, str]] = []
        fix_priority_evidence: list[tuple[str, str]] = []
        if bridge["applied"]:
            candidate_priority_evidence.append(
                (
                    "Cross-file security-surface candidate evidence",
                    str(bridge["candidate_evidence"]),
                )
            )
            fix_priority_evidence.append(
                (
                    "Cross-file global-guard fix evidence",
                    str(bridge["fix_evidence"]),
                )
            )
        candidate_subject, candidate_date, candidate_diff = _commit_view(
            repo,
            candidate_sha,
            args.diff_chars,
            priority_paths=shared_paths,
            priority_label="Candidate/fix shared-path candidate evidence",
            priority_evidence=candidate_priority_evidence,
        )
        fix_subject, fix_date, fix_diff = _commit_view(
            repo,
            fix_sha,
            args.diff_chars,
            priority_paths=shared_paths,
            priority_label="Candidate/fix shared-path fix evidence",
            priority_evidence=fix_priority_evidence,
        )
        candidate_was_missing = not candidate_subject or not candidate_diff
        fix_was_missing = not fix_subject or not fix_diff
        if args.materialize_missing and (candidate_was_missing or fix_was_missing):
            candidate_paths = _changed_paths(
                repo,
                candidate_sha,
                allow_lazy_fetch=True,
            )
            fix_paths = _changed_paths(
                repo,
                fix_sha,
                allow_lazy_fetch=True,
            )
            shared_paths = sorted(set(candidate_paths) & set(fix_paths))
            bridge = _cross_file_security_bridge(
                repo,
                candidate_sha,
                fix_sha,
                candidate_paths,
                fix_paths,
                limit=bridge_limit,
                allow_lazy_fetch=True,
            )
            candidate_priority_evidence = []
            fix_priority_evidence = []
            if bridge["applied"]:
                candidate_priority_evidence.append(
                    (
                        "Cross-file security-surface candidate evidence",
                        str(bridge["candidate_evidence"]),
                    )
                )
                fix_priority_evidence.append(
                    (
                        "Cross-file global-guard fix evidence",
                        str(bridge["fix_evidence"]),
                    )
                )
            candidate_subject, candidate_date, candidate_diff = _commit_view(
                repo,
                candidate_sha,
                args.diff_chars,
                allow_lazy_fetch=True,
                priority_paths=shared_paths,
                priority_label="Candidate/fix shared-path candidate evidence",
                priority_evidence=candidate_priority_evidence,
            )
            fix_subject, fix_date, fix_diff = _commit_view(
                repo,
                fix_sha,
                args.diff_chars,
                allow_lazy_fetch=True,
                priority_paths=shared_paths,
                priority_label="Candidate/fix shared-path fix evidence",
                priority_evidence=fix_priority_evidence,
            )
            if candidate_was_missing and candidate_subject and candidate_diff:
                materialized_evidence.append(
                    {
                        "repository_identity": identity,
                        "sha": candidate_sha,
                        "role": "candidate",
                    }
                )
            if fix_was_missing and fix_subject and fix_diff:
                materialized_evidence.append(
                    {
                        "repository_identity": identity,
                        "sha": fix_sha,
                        "role": "fix",
                    }
                )
        if not candidate_subject or not fix_subject or not candidate_diff or not fix_diff:
            if role == "control":
                raise SystemExit(
                    "positive-control pilot evidence unavailable without lazy fetch: "
                    f"{identity}@{candidate_sha}->{fix_sha}"
                )
            selection_blocked.append(
                {
                    "pilot_item_id": item["pilot_item_id"],
                    "edge_id": edge.get("edge_id", ""),
                    "repository_identity": identity,
                    "candidate_sha": candidate_sha,
                    "fix_sha": fix_sha,
                    "matched_control_advisory": matched_control,
                    "status": "BLOCKED",
                    "reason": "diff_unavailable_without_lazy_fetch",
                }
            )
            continue
        advisories = edge.get("advisories", [])
        advisory_ids = ", ".join(
            sorted(
                str(advisory.get("id") or "")
                for advisory in advisories
                if isinstance(advisory, Mapping)
            )
        )
        user_prompt = USER_TEMPLATE.format(
            repository_identity=identity,
            relation=edge.get("relation", ""),
            advisories=advisory_ids,
            candidate_sha=candidate_sha,
            candidate_date=candidate_date,
            candidate_subject=candidate_subject,
            candidate_diff=candidate_diff,
            fix_sha=fix_sha,
            fix_date=fix_date,
            fix_subject=fix_subject,
            fix_diff=fix_diff,
        )
        prompts.append(
            {
                "pilot_item_id": item["pilot_item_id"],
                "system_prompt": SYSTEM_PROMPT,
                "user_prompt": user_prompt,
                "request_sha256": _sha256_json(
                    {"system": SYSTEM_PROMPT, "user": user_prompt}
                ),
            }
        )
        evidence_routing.append(
            {
                "pilot_item_id": item["pilot_item_id"],
                "shared_paths": shared_paths,
                "cross_file_security_bridge_applied": bool(bridge["applied"]),
                "cross_file_candidate_paths": bridge["candidate_paths"],
                "cross_file_fix_paths": bridge["fix_paths"],
            }
        )
        items.append(item)
        if role == "unlabeled_comparator":
            comparator_counts[matched_control] = comparator_counts.get(matched_control, 0) + 1
    expected_controls = {
        str(control.get("advisory") or "") for control in normalized_controls
    }
    incomplete = sorted(
        advisory
        for advisory in expected_controls
        if comparator_counts.get(advisory, 0) != args.comparators_per_control
    )
    if incomplete and not args.allow_fewer_comparators:
        raise SystemExit(
            "not enough renderable same-fix comparators for: " + ", ".join(incomplete)
        )
    paired = sorted(
        zip(items, prompts, strict=True),
        key=lambda pair: str(pair[0]["pilot_item_id"]),
    )
    items = [pair[0] for pair in paired]
    prompts = [pair[1] for pair in paired]
    evidence_by_item = {
        str(row["pilot_item_id"]): row for row in evidence_routing
    }
    evidence_routing = [
        evidence_by_item[str(item["pilot_item_id"])] for item in items
    ]
    input_price, output_price = _budget_prices(
        args.backend,
        args.input_usd_per_million,
        args.output_usd_per_million,
    )
    budget = build_budget_contract(
        prompts,
        input_usd_per_million=input_price,
        output_usd_per_million=output_price,
        max_output_tokens=args.max_output_tokens,
        max_cost_usd=args.max_cost_usd,
    )
    spec: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "recall_safe_ai_routing_pilot",
        "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
        "backend": args.backend,
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "reasoning_effort_transport": reasoning_transport,
        "relation_dir": str(args.relation_dir),
        "expanded_candidates_sha256": _sha256_file(expanded_path),
        "controls_path": str(args.controls),
        "controls_sha256": _sha256_file(args.controls),
        "control_format": args.control_format,
        "selected_control_ids": sorted(requested_control_ids),
        "control_scope_complete": not requested_control_ids,
        "repository_aliases_path": str(args.repository_aliases),
        "repository_aliases_sha256": _sha256_file(args.repository_aliases),
        "comparators_per_control": args.comparators_per_control,
        "allow_fewer_comparators": args.allow_fewer_comparators,
        "comparator_counts_by_control": dict(sorted(comparator_counts.items())),
        "comparison_pool_per_control": comparison_pool_per_control,
        "selection_blocked_count": len(selection_blocked),
        "selection_blocked_sha256": _sha256_json(selection_blocked),
        "materialize_missing_enabled": args.materialize_missing,
        "materialized_evidence_count": len(materialized_evidence),
        "materialized_evidence_sha256": _sha256_json(materialized_evidence),
        "diff_chars_per_commit": args.diff_chars,
        "diff_evidence_strategy": (
            "cross_file_security_surface_then_shared_paths_then_global_prefix_"
            "first_parent_merges_v4"
        ),
        "cross_file_security_bridge_count": sum(
            bool(row["cross_file_security_bridge_applied"])
            for row in evidence_routing
        ),
        "evidence_routing_sha256": _sha256_json(evidence_routing),
        "item_count": len(items),
        "control_count": sum(item["evaluation_role"] == "control" for item in items),
        "unlabeled_comparator_count": sum(
            item["evaluation_role"] == "unlabeled_comparator" for item in items
        ),
        "items_sha256": _sha256_json(items),
        "prompts_sha256": _sha256_json(prompts),
        "budget": budget,
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
        "claim_boundary": (
            "controls and unlabeled same-fix comparators are frozen before model use;"
            " sparse controls are retained even without a full comparator stratum;"
            " evaluation roles are not included in requests; model scores route only"
            " and never remove candidate edges; complex-target mode evaluates only"
            " same-repository target obligations, not upstream import causality;"
            " cross-file security-surface heuristics add evidence only and never"
            " filter or relabel an edge"
        ),
    }
    spec["spec_sha256"] = _sha256_json(spec)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_write_jsonl(args.output_dir / "items.jsonl", items)
    _atomic_write_jsonl(args.output_dir / "prompts.jsonl", prompts)
    _atomic_write_jsonl(
        args.output_dir / "selection_blocked.jsonl",
        selection_blocked,
    )
    _atomic_write_jsonl(
        args.output_dir / "materialized_evidence.jsonl",
        materialized_evidence,
    )
    _atomic_write_jsonl(
        args.output_dir / "evidence_routing.jsonl",
        evidence_routing,
    )
    _atomic_write_json(args.output_dir / "pilot_spec.json", spec)
    print("\nRecall-safe AI routing pilot prepared")
    print(f"  backend            : {args.backend}")
    print(f"  items              : {len(items)}")
    print(f"  controls           : {spec['control_count']}")
    print(f"  comparators        : {spec['unlabeled_comparator_count']}")
    print(
        "  worst-case cost    : $"
        f"{Decimal(budget['worst_case_reservation_microusd']) / Decimal(1_000_000):.6f}"
    )
    print(f"  hard cap           : ${Decimal(budget['max_cost_microusd']) / Decimal(1_000_000):.2f}")
    print("  model/API cost now : $0.00")
    print(f"  output              : {args.output_dir}")
    return 0


def _parse_model_json(text: str) -> tuple[str, str, str]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        payload = json.loads(stripped)
    except ValueError:
        return "parse_error", "", text[:500]
    if not isinstance(payload, dict):
        return "parse_error", "", text[:500]
    causality = str(payload.get("causality") or "").strip().lower()
    reason = str(payload.get("reason") or "").strip()[:500]
    if causality not in {"likely", "possible", "unlikely", "insufficient"}:
        return "parse_error", "", reason or text[:500]
    return "completed", causality, reason


def _live_model_contract(
    client: httpx.Client,
    api_base: str,
    headers: Mapping[str, str],
    model: str,
    *,
    timeout: float,
) -> dict[str, object]:
    response = client.get(f"{api_base}/model/info", headers=headers, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    data = payload.get("data") if isinstance(payload, dict) else None
    matches = [
        row
        for row in data or []
        if isinstance(row, dict) and row.get("model_name") == model
    ]
    if len(matches) != 1:
        raise SystemExit(f"live model-info must contain exactly one {model!r} contract")
    row = matches[0]
    info = row.get("model_info")
    if not isinstance(info, dict):
        raise SystemExit("live model-info contract is malformed")
    try:
        return {
            "model": model,
            "litellm_model": str(row.get("litellm_params", {}).get("model") or ""),
            "input_cost_per_token": Decimal(str(info["input_cost_per_token"])),
            "output_cost_per_token": Decimal(str(info["output_cost_per_token"])),
            "max_input_tokens": int(info["max_input_tokens"]),
            "max_output_tokens": int(
                info.get("max_output_tokens", info.get("max_tokens"))
            ),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit("live model-info pricing is malformed") from exc


def _live_cliproxy_contract(
    client: httpx.Client,
    api_base: str,
    headers: Mapping[str, str],
    model: str,
    *,
    timeout: float,
) -> dict[str, object]:
    """Freeze the local proxy's exposed request alias without inventing prices."""

    response = client.get(f"{api_base}/models", headers=headers, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        raise SystemExit("CLIProxyAPI model list is malformed")
    model_ids = sorted(
        str(row.get("id") or "")
        for row in data
        if isinstance(row, dict) and str(row.get("id") or "")
    )
    if model_ids.count(model) != 1:
        raise SystemExit(
            f"CLIProxyAPI model list must expose {model!r} exactly once"
        )
    return {
        "backend": "cliproxyapi",
        "model": model,
        "exposed_model_count": len(model_ids),
        "model_ids_sha256": _sha256_json(model_ids),
        "pricing_available": False,
        "input_cost_per_token": Decimal(0),
        "output_cost_per_token": Decimal(0),
    }


def _reasoning_transport(
    *,
    backend: str,
    model: str,
    reasoning_effort: str,
) -> str:
    if backend == "litellm":
        if reasoning_effort == CLIPROXY_REASONING_ALIAS:
            raise ValueError("backend-alias reasoning effort requires CLIProxyAPI")
        return "request_parameter"
    if backend != "cliproxyapi":
        raise ValueError(f"unsupported model backend: {backend}")
    if reasoning_effort == CLIPROXY_REASONING_ALIAS:
        if not model.endswith(("-extra-low", "-low", "-medium", "-high")):
            raise ValueError(
                "backend-alias reasoning effort requires an explicit effort suffix"
                " in the CLIProxyAPI model ID"
            )
        return "model_alias"
    if reasoning_effort not in CLIPROXY_EXPLICIT_REASONING_EFFORTS:
        raise ValueError(
            f"unsupported CLIProxyAPI reasoning effort: {reasoning_effort!r}"
        )
    return "request_parameter"


def _request_contract(
    *,
    backend: str,
    api_base: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_output_tokens: int,
    reasoning_effort: str,
) -> tuple[str, dict[str, object]]:
    reasoning_transport = _reasoning_transport(
        backend=backend,
        model=model,
        reasoning_effort=reasoning_effort,
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    if backend == "litellm":
        return f"{api_base}/responses", {
            "model": model,
            "input": messages,
            "max_output_tokens": max_output_tokens,
            "reasoning": {"effort": reasoning_effort},
        }
    if backend == "cliproxyapi":
        body: dict[str, object] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_output_tokens,
        }
        if reasoning_transport == "request_parameter":
            body["reasoning_effort"] = reasoning_effort
        return f"{api_base}/chat/completions", body
    raise ValueError(f"unsupported model backend: {backend}")


def _validate_response_provenance(
    raw: Mapping[str, object],
    *,
    backend: str,
    requested_model: str,
) -> tuple[bool, str, str]:
    observed_model = str(raw.get("model") or "")
    if backend == "litellm":
        valid = raw.get("status") == "completed" and observed_model == requested_model
        reason = "" if valid else f"status={raw.get('status')!r},model={observed_model!r}"
        return valid, reason, observed_model
    if backend == "cliproxyapi":
        choices = raw.get("choices")
        valid = (
            bool(observed_model)
            and isinstance(choices, list)
            and bool(choices)
            and isinstance(choices[0], Mapping)
            and isinstance(choices[0].get("message"), Mapping)
        )
        reason = "" if valid else f"choices_or_model_missing:model={observed_model!r}"
        # CLIProxyAPI may report a provider-side model name (for example
        # gemini-default) rather than the exposed request alias.  The request
        # alias is verified independently against /models and both are stored.
        return valid, reason, observed_model
    raise ValueError(f"unsupported model backend: {backend}")


def _usage_counts(usage: Mapping[str, object]) -> tuple[int, int]:
    input_value = usage.get("input_tokens", usage.get("prompt_tokens", 0))
    output_value = usage.get("output_tokens", usage.get("completion_tokens", 0))
    try:
        input_tokens = int(input_value or 0)
        reported_output_tokens = int(output_value or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("response usage token counts are malformed") from exc
    if input_tokens < 0 or reported_output_tokens < 0:
        raise ValueError("response usage token counts are malformed")

    # OpenAI-compatible providers disagree on whether completion_tokens already
    # includes hidden reasoning.  Reconcile against total_tokens when present:
    # Terra includes reasoning in completion_tokens, while Gemini currently
    # exposes it only through total_tokens and completion_tokens_details.
    total_value = usage.get("total_tokens")
    if total_value is not None:
        try:
            total_tokens = int(total_value)
        except (TypeError, ValueError) as exc:
            raise ValueError("response usage token counts are malformed") from exc
        if total_tokens < input_tokens:
            raise ValueError("response usage token counts are malformed")
        return input_tokens, max(reported_output_tokens, total_tokens - input_tokens)

    details = usage.get("completion_tokens_details")
    if isinstance(details, Mapping):
        reasoning_value = details.get("reasoning_tokens", 0)
        try:
            reasoning_tokens = int(reasoning_value or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("response usage token counts are malformed") from exc
        if reasoning_tokens < 0:
            raise ValueError("response usage token counts are malformed")
        # With no aggregate total there is no reliable way to distinguish
        # inclusive and exclusive provider conventions.  Conservatively count
        # the separately reported reasoning so the budget cannot undercount.
        reported_output_tokens += reasoning_tokens
    return input_tokens, reported_output_tokens


def _usage_cost(
    input_tokens: int,
    output_tokens: int,
    input_cost_per_token: Decimal,
    output_cost_per_token: Decimal,
) -> Decimal:
    if min(
        input_tokens,
        output_tokens,
        input_cost_per_token,
        output_cost_per_token,
    ) < 0:
        raise ValueError("usage and token prices must be non-negative")
    return (
        Decimal(input_tokens) * input_cost_per_token
        + Decimal(output_tokens) * output_cost_per_token
    )


def _execute(args: argparse.Namespace) -> int:
    pilot_dir = args.pilot_dir
    if (pilot_dir / "execution_summary.json").exists() or (pilot_dir / "results.jsonl").exists():
        raise SystemExit("pilot already has execution artifacts; refusing duplicate spend")
    spec = _load_json(pilot_dir / "pilot_spec.json")
    items = _load_jsonl(pilot_dir / "items.jsonl")
    prompts = _load_jsonl(pilot_dir / "prompts.jsonl")
    if spec.get("schema_version") != 1 or spec.get("artifact_kind") != "recall_safe_ai_routing_pilot":
        raise SystemExit("pilot spec contract is invalid")
    if spec.get("items_sha256") != _sha256_json(items) or spec.get(
        "prompts_sha256"
    ) != _sha256_json(prompts):
        raise SystemExit("frozen pilot items or prompts changed after preparation")
    budget = spec.get("budget")
    if not isinstance(budget, dict):
        raise SystemExit("pilot budget contract is missing")
    operator_cap_microusd = int(Decimal(args.max_cost_usd) * Decimal(1_000_000))
    reservation = int(budget.get("worst_case_reservation_microusd", -1))
    prepared_cap = int(budget.get("max_cost_microusd", -1))
    if operator_cap_microusd <= 0 or reservation < 0:
        raise SystemExit("operator cost cap is invalid")
    if reservation > min(operator_cap_microusd, prepared_cap):
        raise SystemExit("worst-case reservation exceeds prepared or operator cap")

    backend = str(spec.get("backend") or "litellm")
    if backend not in SUPPORTED_BACKENDS:
        raise SystemExit(f"unsupported pilot backend: {backend}")
    config = resolve_litellm_config()
    if config is None:
        raise SystemExit("OpenAI-compatible transport is not configured")
    endpoint_is_loopback = _is_loopback_api_base(config.api_base)
    if (
        backend == "cliproxyapi"
        and not endpoint_is_loopback
        and not args.allow_non_loopback_cliproxyapi
    ):
        raise SystemExit(
            "CLIProxyAPI endpoint is not loopback; rerun only with explicit"
            " --allow-non-loopback-cliproxyapi authorization"
        )
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }
    model = str(spec.get("model") or "")
    prepared_input = Decimal(str(budget["input_usd_per_million_tokens"])) / Decimal(
        1_000_000
    )
    prepared_output = Decimal(str(budget["output_usd_per_million_tokens"])) / Decimal(
        1_000_000
    )
    max_output_tokens = int(budget["max_output_tokens_per_request"])
    results: list[dict[str, object]] = []
    physical_calls = 0
    input_tokens = 0
    output_tokens = 0
    actual_cost = Decimal(0)
    budget_estimated_cost = Decimal(0)
    with httpx.Client() as client:
        if backend == "litellm":
            live = _live_model_contract(
                client,
                config.api_base,
                headers,
                model,
                timeout=min(args.timeout, 30.0),
            )
        else:
            live = _live_cliproxy_contract(
                client,
                config.api_base,
                headers,
                model,
                timeout=min(args.timeout, 30.0),
            )
        live_input = live["input_cost_per_token"]
        live_output = live["output_cost_per_token"]
        assert isinstance(live_input, Decimal) and isinstance(live_output, Decimal)
        if live_input > prepared_input or live_output > prepared_output:
            raise SystemExit("live LiteLLM prices exceed the frozen budget contract")
        if "max_output_tokens" in live and int(live["max_output_tokens"]) < max_output_tokens:
            raise SystemExit("prepared output bound exceeds live model contract")

        responses_dir = pilot_dir / "responses"
        responses_dir.mkdir(mode=0o700)

        for index, prompt in enumerate(prompts, start=1):
            item_id = str(prompt["pilot_item_id"])
            endpoint, body = _request_contract(
                backend=backend,
                api_base=config.api_base,
                model=model,
                system_prompt=str(prompt["system_prompt"]),
                user_prompt=str(prompt["user_prompt"]),
                max_output_tokens=max_output_tokens,
                reasoning_effort=str(spec["reasoning_effort"]),
            )
            physical_calls += 1
            result: dict[str, object] = {
                "pilot_item_id": item_id,
                "sequence": index,
                "model": model,
                "result_status": "transport_error",
                "causality": "",
                "reason": "",
                "observed_model": "",
                "usage": {},
            }
            try:
                response = client.post(
                    endpoint,
                    headers=headers,
                    json=body,
                    timeout=args.timeout,
                )
                response.raise_for_status()
                if len(response.content) > MAX_RESPONSE_BYTES:
                    raise ValueError("response_too_large")
                raw = response.json()
                if not isinstance(raw, dict):
                    raise ValueError("response_not_object")
                response_path = responses_dir / f"{index:02d}-{item_id}.json"
                _atomic_write_json(response_path, raw)
                valid_provenance, provenance_reason, observed_model = (
                    _validate_response_provenance(
                        raw,
                        backend=backend,
                        requested_model=model,
                    )
                )
                result["observed_model"] = observed_model
                if not valid_provenance:
                    result["result_status"] = "provenance_error"
                    result["reason"] = provenance_reason
                else:
                    text = extract_response_text(raw)
                    status, causality, reason = _parse_model_json(text)
                    result["result_status"] = status
                    result["causality"] = causality
                    result["reason"] = reason
                usage = raw.get("usage")
                if isinstance(usage, dict):
                    current_input, current_output = _usage_counts(usage)
                    input_tokens += current_input
                    output_tokens += current_output
                    current_cost = _usage_cost(
                        current_input,
                        current_output,
                        live_input,
                        live_output,
                    )
                    current_budget_estimate = _usage_cost(
                        current_input,
                        current_output,
                        prepared_input,
                        prepared_output,
                    )
                    actual_cost += current_cost
                    budget_estimated_cost += current_budget_estimate
                    result["usage"] = {
                        "input_tokens": current_input,
                        "output_tokens": current_output,
                        "known_cost_usd": format(current_cost, "f"),
                        "budget_estimated_cost_usd": format(
                            current_budget_estimate,
                            "f",
                        ),
                    }
            except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
                result["reason"] = type(exc).__name__
            results.append(result)
            _atomic_write_jsonl(pilot_dir / "results.jsonl", results)
            if max(actual_cost, budget_estimated_cost) * Decimal(1_000_000) > min(
                operator_cap_microusd, prepared_cap
            ):
                raise SystemExit(
                    "known or frozen-price estimated spend breached the hard cap"
                )
            print(
                f"  [{index}/{len(prompts)}] {item_id[-8:]} "
                f"{result['result_status']} {result['causality']}",
                flush=True,
            )

    evaluation = evaluate_pilot_results(items, results)
    _atomic_write_jsonl(pilot_dir / "pilot_routing.jsonl", evaluation["routes"])
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "recall_safe_ai_routing_pilot_execution",
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "parent_spec_sha256": spec["spec_sha256"],
        "backend": backend,
        "model": model,
        "reasoning_effort": spec["reasoning_effort"],
        "reasoning_effort_transport": spec.get(
            "reasoning_effort_transport",
            "legacy_unspecified",
        ),
        "physical_model_calls": physical_calls,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "output_token_accounting": (
            "max(reported_output_tokens,total_tokens-input_tokens);"
            " add separately reported reasoning conservatively when total is absent"
        ),
        "known_model_cost_usd": format(actual_cost, "f"),
        "budget_estimated_model_cost_usd": format(budget_estimated_cost, "f"),
        "budget_estimate_price_source": "frozen_operator_assumption",
        "operator_max_cost_usd": args.max_cost_usd,
        "api_endpoint_scope": "loopback" if endpoint_is_loopback else "non_loopback",
        "non_loopback_cliproxyapi_explicitly_allowed": bool(
            args.allow_non_loopback_cliproxyapi
        ),
        "api_base_sha256": hashlib.sha256(config.api_base.encode("utf-8")).hexdigest(),
        "live_model_contract": {
            **live,
            "input_cost_per_token": format(live_input, "f"),
            "output_cost_per_token": format(live_output, "f"),
        },
        "evaluation": evaluation,
        "results_sha256": _sha256_json(results),
        "claim_boundary": (
            "all model outcomes are routing dispositions only; DEFER is not a"
            " negative label and BLOCKED is not a miss; comparator items are unlabeled;"
            " CLIProxyAPI reports zero known cost because it exposes no per-token price"
            " contract, which is not a claim about upstream provider billing; the"
            " separate budget estimate uses frozen operator price assumptions"
        ),
    }
    summary["summary_sha256"] = _sha256_json(summary)
    _atomic_write_json(pilot_dir / "execution_summary.json", summary)
    print("\nRecall-safe AI routing pilot executed")
    print(f"  backend          : {backend}")
    print(
        f"  control promoted : {evaluation['control_promoted_count']}/"
        f"{evaluation['control_count']}"
    )
    print(
        f"  comparators up   : {evaluation['unlabeled_comparator_promoted_count']}/"
        f"{evaluation['unlabeled_comparator_count']}"
    )
    print(f"  tokens           : {input_tokens:,} in / {output_tokens:,} out")
    print(f"  known cost       : ${actual_cost:.6f}")
    print(f"  budget estimate  : ${budget_estimated_cost:.6f}")
    print(f"  scale gate       : {'PASS' if evaluation['scale_gate_passed'] else 'FAIL'}")
    return 0 if evaluation["scale_gate_passed"] else 2


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        return _prepare(args) if args.command == "prepare" else _execute(args)
    except RoutingPilotContractError as exc:
        raise SystemExit(f"routing pilot contract failed: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
