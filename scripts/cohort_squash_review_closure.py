#!/usr/bin/env python3
"""Certify review and adjudication closure over a frozen squash-member inventory."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from cohort.root_adjudication import canonical_sha256


REPO_ROOT = Path(__file__).resolve().parents[1]
FULL_SHA = re.compile(r"[0-9a-f]{40}")
MEMBER_SIGNAL = "squash_pr_member_relation"
REVIEWED_CAUSALITIES = frozenset(
    {"likely", "possible", "unlikely", "insufficient"}
)
CandidateKey = tuple[str, str, str, str]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--adjudications", type=Path, required=True)
    parser.add_argument(
        "--route",
        action="append",
        default=[],
        metavar="NAME=DIRECTORY",
        help="completed, lossless batch-route artifact; repeat for every lane",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
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
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _write_new_json(path: Path, value: object) -> None:
    """Atomically publish a new JSON file without overwriting prior evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise SystemExit(f"output already exists: {path}") from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _parse_route_arguments(values: list[str]) -> list[tuple[str, Path]]:
    parsed: list[tuple[str, Path]] = []
    names: set[str] = set()
    for value in values:
        name, separator, directory = value.partition("=")
        if not separator or not name.strip() or not directory.strip():
            raise SystemExit(f"--route must be NAME=DIRECTORY: {value!r}")
        name = name.strip()
        if name in names:
            raise SystemExit(f"duplicate route name: {name}")
        names.add(name)
        parsed.append((name, Path(directory)))
    if not parsed:
        raise SystemExit("at least one --route is required")
    return parsed


def _key(row: dict[str, object], *, sha_field: str) -> CandidateKey:
    values = (
        str(row.get("advisory", "")),
        str(row.get("repository_identity", "")),
        str(row.get("fix_sha", "")).lower(),
        str(row.get(sha_field, "")).lower(),
    )
    if not values[0] or not values[1]:
        raise SystemExit(f"candidate identity is incomplete: {values}")
    if not FULL_SHA.fullmatch(values[2]) or not FULL_SHA.fullmatch(values[3]):
        raise SystemExit(f"candidate identity has malformed SHA: {values}")
    return values


def _unique_rows(
    rows: list[dict[str, object]], *, sha_field: str, label: str
) -> dict[CandidateKey, dict[str, object]]:
    indexed: dict[CandidateKey, dict[str, object]] = {}
    for row in rows:
        key = _key(row, sha_field=sha_field)
        if key in indexed:
            raise SystemExit(f"duplicate {label} identity: {key}")
        indexed[key] = row
    return indexed


def _has_member_signal(row: dict[str, object]) -> bool:
    signals = row.get("signals")
    if not isinstance(signals, list) or any(
        not isinstance(signal, str) for signal in signals
    ):
        raise SystemExit("candidate signals are malformed")
    return MEMBER_SIGNAL in signals


def _is_zero_content(row: dict[str, object]) -> bool:
    return row.get("empty_commit") is True


def _validate_zero_content(row: dict[str, object]) -> None:
    if row.get("additions") != 0 or row.get("deletions") != 0:
        raise SystemExit(f"empty member has a non-zero diff: {row.get('sha')}")
    for field in ("changed_files", "code_files_changed"):
        value = row.get(field)
        if not isinstance(value, list) or value:
            raise SystemExit(
                f"empty member has malformed or non-empty {field}: {row.get('sha')}"
            )


def _expand_adjudications(
    payload: dict[str, object],
) -> tuple[dict[CandidateKey, dict[str, object]], dict[CandidateKey, dict[str, object]]]:
    if payload.get("schema_version") != 1 or payload.get("artifact_kind") != (
        "squash_promoted_candidate_adjudications"
    ):
        raise SystemExit("unsupported promoted-adjudication artifact")
    raw_confirmed = payload.get("confirmed")
    raw_groups = payload.get("rejected_groups")
    if not isinstance(raw_confirmed, list) or not isinstance(raw_groups, list):
        raise SystemExit("promoted-adjudication rows are malformed")

    confirmed = _unique_rows(raw_confirmed, sha_field="candidate_sha", label="confirmed")
    rejected_rows: list[dict[str, object]] = []
    for group in raw_groups:
        if not isinstance(group, dict):
            raise SystemExit("rejected adjudication group is not an object")
        candidate_shas = group.get("candidate_shas")
        if not isinstance(candidate_shas, list) or not candidate_shas:
            raise SystemExit("rejected adjudication group has no candidate SHAs")
        for candidate_sha in candidate_shas:
            row = dict(group)
            row.pop("candidate_shas", None)
            row["candidate_sha"] = candidate_sha
            rejected_rows.append(row)
    rejected = _unique_rows(rejected_rows, sha_field="candidate_sha", label="rejected")
    overlap = set(confirmed) & set(rejected)
    if overlap:
        raise SystemExit(f"candidate is both confirmed and rejected: {sorted(overlap)}")
    return confirmed, rejected


def _validate_evidence(confirmed: dict[CandidateKey, dict[str, object]]) -> None:
    for key, row in confirmed.items():
        evidence = row.get("evidence")
        if not isinstance(evidence, str) or not evidence:
            raise SystemExit(f"confirmed candidate lacks evidence: {key}")
        if not (REPO_ROOT / evidence).is_file():
            raise SystemExit(f"confirmed evidence does not exist: {evidence}")


def _key_rows(values: Iterable[CandidateKey]) -> list[dict[str, str]]:
    return [
        {
            "advisory": key[0],
            "repository_identity": key[1],
            "fix_sha": key[2],
            "candidate_sha": key[3],
        }
        for key in sorted(values)
    ]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    route_arguments = _parse_route_arguments(args.route)

    summary = _load_json(args.generated_dir / "summary.json")
    candidates = _load_jsonl(args.generated_dir / "candidates.jsonl")
    candidate_digest = canonical_sha256(candidates)
    if candidate_digest != summary.get("candidate_rows_sha256"):
        raise SystemExit("generated candidate digest mismatch")
    if summary.get("gate_status") != "READY":
        raise SystemExit("generated candidate inventory is not READY")
    candidate_rows = _unique_rows(candidates, sha_field="sha", label="candidate")
    if len(candidate_rows) != summary.get("candidate_count"):
        raise SystemExit("generated candidate count mismatch")
    if not all(row.get("retained") is True for row in candidates):
        raise SystemExit("generated inventory contains a non-retained candidate")

    member_rows = {
        key: row for key, row in candidate_rows.items() if _has_member_signal(row)
    }
    zero_content = {
        key: row for key, row in member_rows.items() if _is_zero_content(row)
    }
    nonempty_members = set(member_rows) - set(zero_content)
    for row in zero_content.values():
        _validate_zero_content(row)

    reviewed_by: dict[CandidateKey, set[str]] = {}
    promoted: set[CandidateKey] = set()
    route_reports: list[dict[str, object]] = []
    parent_generation_digests: set[str] = set()
    all_route_inventories_conserved = True
    all_route_candidates_retained = True
    all_route_results_completed = True

    for name, directory in route_arguments:
        spec = _load_json(directory / "spec.json")
        execution = _load_json(directory / "execution.json")
        results = _load_jsonl(directory / "results.jsonl")
        routes = _load_jsonl(directory / "routes.jsonl")
        if spec.get("artifact_kind") != "recall_safe_origin_ai_batch_route":
            raise SystemExit(f"{name}: unsupported route spec")
        if execution.get("artifact_kind") != (
            "recall_safe_origin_ai_batch_route_execution"
        ):
            raise SystemExit(f"{name}: unsupported route execution")
        if spec.get("candidate_inventory_sha256") != candidate_digest:
            raise SystemExit(f"{name}: candidate inventory digest mismatch")
        if canonical_sha256(results) != execution.get("results_sha256"):
            raise SystemExit(f"{name}: result digest mismatch")
        if canonical_sha256(routes) != execution.get("routes_sha256"):
            raise SystemExit(f"{name}: route digest mismatch")

        route_rows = _unique_rows(routes, sha_field="candidate_sha", label=name)
        inventory_conserved = set(route_rows) == set(candidate_rows)
        candidates_retained = all(row.get("retained") is True for row in routes)
        blocked_count = sum(row.get("disposition") == "BLOCKED" for row in routes)
        reviewed = {
            key
            for key, row in route_rows.items()
            if row.get("causality") in REVIEWED_CAUSALITIES
        }
        lane_promoted = {
            key for key, row in route_rows.items() if row.get("disposition") == "PROMOTE"
        }
        if not reviewed <= set(member_rows):
            raise SystemExit(f"{name}: route reviewed a non-squash candidate")
        if not lane_promoted <= reviewed:
            raise SystemExit(f"{name}: unreviewed candidate was promoted")
        if len(reviewed) != spec.get("selected_candidate_unit_count"):
            raise SystemExit(f"{name}: selected-unit/reviewed-row count mismatch")
        if len(lane_promoted) != execution.get("promoted_count"):
            raise SystemExit(f"{name}: promoted count mismatch")
        if blocked_count != execution.get("blocked_count"):
            raise SystemExit(f"{name}: blocked count mismatch")
        if len(routes) != execution.get("inventory_count"):
            raise SystemExit(f"{name}: route inventory count mismatch")
        if candidates_retained != execution.get("all_candidates_retained"):
            raise SystemExit(f"{name}: retained flag mismatch")

        completed = (
            blocked_count == 0
            and execution.get("transport_or_parse_blocked_count") == 0
        )
        all_route_inventories_conserved &= inventory_conserved
        all_route_candidates_retained &= candidates_retained
        all_route_results_completed &= completed
        parent_generation_digests.add(str(spec.get("parent_generation_sha256", "")))
        for key in reviewed:
            reviewed_by.setdefault(key, set()).add(name)
        promoted.update(lane_promoted)
        route_reports.append(
            {
                "name": name,
                "directory": str(directory),
                "model": execution.get("model"),
                "reasoning_effort": execution.get("reasoning_effort"),
                "reviewed_member_count": len(reviewed),
                "promoted_member_count": len(lane_promoted),
                "blocked_count": blocked_count,
                "inventory_conserved": inventory_conserved,
                "all_candidates_retained": candidates_retained,
                "results_completed": completed,
                "routes_sha256": execution.get("routes_sha256"),
            }
        )

    reviewed = set(reviewed_by)
    reviewed_nonempty = reviewed & nonempty_members
    reviewed_zero_content = reviewed & set(zero_content)
    unreviewed_nonempty = nonempty_members - reviewed
    unreviewed_zero_content = set(zero_content) - reviewed
    multiply_reviewed = {
        key: sorted(names) for key, names in reviewed_by.items() if len(names) > 1
    }

    adjudications = _load_json(args.adjudications)
    confirmed, rejected = _expand_adjudications(adjudications)
    _validate_evidence(confirmed)
    adjudicated = set(confirmed) | set(rejected)
    unadjudicated_promotions = promoted - adjudicated
    adjudications_without_promotion = adjudicated - promoted
    if not adjudicated <= set(member_rows):
        raise SystemExit("adjudication ledger contains a non-squash candidate")

    role_counts = Counter(str(row.get("causal_role", "")) for row in confirmed.values())
    direct_member_ai_count = sum(
        row.get("member_ai_authorship_claim") is True for row in confirmed.values()
    )
    gates = {
        "generated_inventory_ready": summary.get("gate_status") == "READY",
        "all_route_inventories_conserved": all_route_inventories_conserved,
        "all_route_candidates_retained": all_route_candidates_retained,
        "all_route_results_completed": all_route_results_completed,
        "all_nonempty_members_reviewed": not unreviewed_nonempty,
        "all_unreviewed_members_are_zero_content": not (
            set(member_rows) - reviewed - set(zero_content)
        ),
        "zero_content_members_have_empty_tree_certificates": len(zero_content)
        == sum(_is_zero_content(row) for row in member_rows.values()),
        "review_lanes_are_disjoint": not multiply_reviewed,
        "all_promotions_adjudicated": not unadjudicated_promotions,
        "adjudication_ledger_matches_promotion_union": not (
            unadjudicated_promotions or adjudications_without_promotion
        ),
        "single_packet_generation_parent": len(parent_generation_digests) == 1,
    }
    gate_status = "READY" if all(gates.values()) else "BLOCKED"
    output = {
        "schema_version": 1,
        "artifact_kind": "squash_member_review_adjudication_closure",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "gate_status": gate_status,
        "generated_inventory": {
            "directory": str(args.generated_dir),
            "candidate_count": len(candidate_rows),
            "candidate_rows_sha256": candidate_digest,
            "squash_member_count": len(member_rows),
            "nonempty_member_count": len(nonempty_members),
            "zero_content_member_count": len(zero_content),
            "zero_content_member_keys_sha256": canonical_sha256(
                _key_rows(zero_content)
            ),
        },
        "review_closure": {
            "model_reviewed_member_count": len(reviewed),
            "reviewed_nonempty_member_count": len(reviewed_nonempty),
            "reviewed_zero_content_member_count": len(reviewed_zero_content),
            "unreviewed_nonempty_member_count": len(unreviewed_nonempty),
            "unreviewed_zero_content_member_count": len(unreviewed_zero_content),
            "multiply_reviewed_member_count": len(multiply_reviewed),
            "unreviewed_nonempty_members": _key_rows(unreviewed_nonempty),
        },
        "promotion_adjudication": {
            "promoted_member_count": len(promoted),
            "confirmed_causal_count": len(confirmed),
            "rejected_independent_causal_claim_count": len(rejected),
            "unadjudicated_promotion_count": len(unadjudicated_promotions),
            "adjudications_without_promotion_count": len(
                adjudications_without_promotion
            ),
            "direct_member_ai_authorship_confirmed_count": direct_member_ai_count,
            "carrier_context_only_confirmed_count": len(confirmed)
            - direct_member_ai_count,
            "causal_role_counts": dict(sorted(role_counts.items())),
            "promoted_member_keys_sha256": canonical_sha256(_key_rows(promoted)),
            "adjudication_ledger_sha256": canonical_sha256(adjudications),
            "unadjudicated_promotions": _key_rows(unadjudicated_promotions),
            "adjudications_without_promotion": _key_rows(
                adjudications_without_promotion
            ),
        },
        "routes": route_reports,
        "gates": gates,
        "claim_boundary": (
            "READY proves zero unreviewed non-empty members and zero "
            "unadjudicated model promotions only inside the frozen squash-member "
            "inventory. Model negatives never delete candidates. Confirmed causal "
            "members require patch or witness evidence; carrier-level AI context "
            "does not establish member-level AI authorship. This artifact does not "
            "prove completeness outside the frozen fix, attribution, and PR-relation "
            "population."
        ),
    }
    _write_new_json(args.output, output)
    print("squash member review closure frozen")
    print(f"  gate       : {gate_status}")
    print(f"  members    : {len(member_rows)}")
    print(f"  reviewed   : {len(reviewed)}")
    print(f"  zero-only  : {len(unreviewed_zero_content)}")
    print(f"  promoted   : {len(promoted)}")
    print(f"  confirmed  : {len(confirmed)}")
    print(f"  output     : {args.output}")
    return 0 if gate_status == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
