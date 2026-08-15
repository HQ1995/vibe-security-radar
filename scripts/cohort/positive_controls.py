"""Separate relation-engine recall from public advisory-source recall."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

from cohort.relations import canonical_repository_identity


class PositiveControlContractError(ValueError):
    """A golden control or evaluated artifact is malformed."""


def _sha256_json(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _full_sha(value: object, *, field: str) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise PositiveControlContractError(f"{field} must be a full 40-hex SHA")
    return sha


def evaluate_positive_controls(
    controls: Sequence[Mapping[str, object]],
    expanded_edges: Sequence[Mapping[str, object]],
    public_fix_references: Sequence[Mapping[str, object]],
    aliases: Mapping[str, str],
) -> dict[str, object]:
    """Evaluate exact golden relations without confusing them with source coverage."""

    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in controls:
        identity = canonical_repository_identity(
            str(raw.get("repository_identity") or ""), aliases
        )
        advisory = str(raw.get("advisory") or "").strip()
        origin_sha = _full_sha(raw.get("atomic_origin_sha"), field="atomic origin")
        fix_sha = _full_sha(raw.get("fix_sha"), field="fix")
        relation = str(raw.get("expected_relation") or "").strip()
        if not advisory or not relation:
            raise PositiveControlContractError(
                "positive controls require advisory and expected_relation"
            )
        key = (identity, origin_sha, fix_sha)
        if key in seen:
            raise PositiveControlContractError("duplicate positive control")
        seen.add(key)

        expected_landed = str(raw.get("expected_landed_sha") or "").strip().lower()
        if expected_landed:
            expected_landed = _full_sha(expected_landed, field="expected landed")
        matching_edges = [
            edge
            for edge in expanded_edges
            if str(edge.get("repository_identity") or "").strip().lower() == identity
            and str(edge.get("candidate_sha") or "").strip().lower() == origin_sha
            and str(edge.get("fix_sha") or "").strip().lower() == fix_sha
            and str(edge.get("relation") or "") == relation
            and (
                not expected_landed
                or str(edge.get("landed_sha") or "").strip().lower()
                == expected_landed
            )
        ]
        public_matches = [
            reference
            for reference in public_fix_references
            if canonical_repository_identity(
                str(reference.get("repository_identity") or ""), aliases
            )
            == identity
            and str(reference.get("advisory") or "").strip() == advisory
            and str(reference.get("fix_sha") or "").strip().lower() == fix_sha
        ]
        row: dict[str, object] = {
            "advisory": advisory,
            "repository_identity": identity,
            "atomic_origin_sha": origin_sha,
            "fix_sha": fix_sha,
            "expected_relation": relation,
            "relation_engine_status": "PASS" if matching_edges else "MISS",
            "matching_edge_ids": sorted(
                str(edge.get("edge_id") or "") for edge in matching_edges
            ),
            "public_exact_fix_status": "PASS" if public_matches else "MISS",
            "public_matching_reference_count": len(public_matches),
        }
        if expected_landed:
            row["expected_landed_sha"] = expected_landed
        rows.append(row)

    rows.sort(key=lambda row: (str(row["repository_identity"]), str(row["advisory"])))
    relation_passes = sum(row["relation_engine_status"] == "PASS" for row in rows)
    public_passes = sum(row["public_exact_fix_status"] == "PASS" for row in rows)
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "forward_cohort_positive_control_recall",
        "control_count": len(rows),
        "relation_engine_pass_count": relation_passes,
        "relation_engine_recall": relation_passes / len(rows) if rows else 0.0,
        "relation_gate_passed": bool(rows) and relation_passes == len(rows),
        "public_exact_fix_pass_count": public_passes,
        "public_exact_fix_recall": public_passes / len(rows) if rows else 0.0,
        "controls": rows,
        "controls_sha256": _sha256_json(rows),
        "claim_boundary": (
            "relation recall is measured with exact audited fix roots supplied as an"
            " evaluation overlay; public exact-fix recall uses only parsed public"
            " advisory references and is reported separately"
        ),
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
    }
    result["result_sha256"] = _sha256_json(result)
    return result
