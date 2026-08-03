"""Fail-closed evaluation for multi-edge and cross-repository controls."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence

from cohort.relations import canonical_repository_identity


DIRECT_RELATION = "reachable_ancestor"
COMPOSITE_RELATION = (
    "pull_request_member_landed_as_squash_then_reachable_ancestor"
)
DECLARED_IMPORT_RELATION = "declared_cross_repository_import"
ALLOWED_DIMENSIONS = frozenset(
    {"MULTI_ORIGIN", "MULTI_FIX", "CROSS_REPOSITORY_ORIGIN"}
)


class ComplexControlContractError(ValueError):
    """A complex control ledger or evaluated artifact is malformed."""


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


def _full_sha(value: object, *, field: str) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise ComplexControlContractError(f"{field} must be a full 40-hex SHA")
    return sha


def _content_sha(value: object, *, field: str) -> str:
    digest = str(value or "").strip().lower()
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ComplexControlContractError(f"{field} must be a 64-hex SHA-256")
    return digest


def _identity(
    value: object,
    aliases: Mapping[str, str],
    *,
    field: str,
) -> str:
    try:
        identity = canonical_repository_identity(str(value or ""), aliases)
    except ValueError as exc:
        raise ComplexControlContractError(f"invalid {field}") from exc
    if not identity or "/" not in identity:
        raise ComplexControlContractError(f"invalid {field}")
    return identity


def normalize_complex_controls(
    controls: Sequence[Mapping[str, object]],
    aliases: Mapping[str, str],
) -> list[dict[str, object]]:
    """Validate and canonicalize every complex control obligation."""

    normalized: list[dict[str, object]] = []
    seen_advisories: set[str] = set()
    for raw in controls:
        if not isinstance(raw, Mapping):
            raise ComplexControlContractError("complex control must be an object")
        advisory = str(raw.get("advisory") or "").strip()
        source = str(raw.get("source") or "").strip()
        if not advisory or advisory in seen_advisories:
            raise ComplexControlContractError("complex controls require unique advisories")
        if not source:
            raise ComplexControlContractError(f"{advisory} requires an audit source")
        seen_advisories.add(advisory)
        source_sha256 = _content_sha(
            raw.get("source_sha256"), field=f"{advisory} source_sha256"
        )
        raw_topology_sources = raw.get("topology_sources", [])
        if not isinstance(raw_topology_sources, list):
            raise ComplexControlContractError(
                f"{advisory} topology_sources must be a list"
            )
        topology_sources: list[dict[str, str]] = []
        for raw_source in raw_topology_sources:
            if not isinstance(raw_source, Mapping):
                raise ComplexControlContractError(
                    f"{advisory} topology source is malformed"
                )
            topology_path = str(raw_source.get("path") or "").strip()
            if not topology_path:
                raise ComplexControlContractError(
                    f"{advisory} topology source requires a path"
                )
            topology_sources.append(
                {
                    "path": topology_path,
                    "sha256": _content_sha(
                        raw_source.get("sha256"),
                        field=f"{advisory} topology source sha256",
                    ),
                }
            )
        topology_sources.sort(key=lambda row: row["path"])
        target_identity = _identity(
            raw.get("target_repository_identity"),
            aliases,
            field=f"{advisory} target repository",
        )
        raw_dimensions = raw.get("dimensions")
        if not isinstance(raw_dimensions, list) or not raw_dimensions:
            raise ComplexControlContractError(f"{advisory} requires dimensions")
        dimensions = sorted({str(value or "").strip() for value in raw_dimensions})
        if not set(dimensions) <= ALLOWED_DIMENSIONS:
            raise ComplexControlContractError(f"{advisory} has unsupported dimensions")

        raw_edges = raw.get("target_edges")
        if not isinstance(raw_edges, list) or not raw_edges:
            raise ComplexControlContractError(f"{advisory} requires target edges")
        target_edges: list[dict[str, str]] = []
        seen_edges: set[tuple[str, str, str, str]] = set()
        for raw_edge in raw_edges:
            if not isinstance(raw_edge, Mapping):
                raise ComplexControlContractError(f"{advisory} target edge is malformed")
            candidate_sha = _full_sha(
                raw_edge.get("candidate_sha"), field=f"{advisory} candidate"
            )
            fix_sha = _full_sha(raw_edge.get("fix_sha"), field=f"{advisory} fix")
            relation = str(raw_edge.get("expected_relation") or "").strip()
            if relation not in {DIRECT_RELATION, COMPOSITE_RELATION}:
                raise ComplexControlContractError(
                    f"{advisory} has unsupported target relation"
                )
            landed_sha = str(raw_edge.get("expected_landed_sha") or "").strip()
            if relation == COMPOSITE_RELATION:
                landed_sha = _full_sha(
                    landed_sha, field=f"{advisory} expected landed"
                )
            elif landed_sha:
                raise ComplexControlContractError(
                    f"{advisory} direct edge cannot require a landed SHA"
                )
            key = (candidate_sha, fix_sha, relation, landed_sha)
            if key in seen_edges:
                raise ComplexControlContractError(f"{advisory} has duplicate target edge")
            seen_edges.add(key)
            edge = {
                "candidate_sha": candidate_sha,
                "fix_sha": fix_sha,
                "expected_relation": relation,
            }
            if landed_sha:
                edge["expected_landed_sha"] = landed_sha
            target_edges.append(edge)
        target_edges.sort(
            key=lambda row: (
                row["candidate_sha"],
                row["fix_sha"],
                row["expected_relation"],
                row.get("expected_landed_sha", ""),
            )
        )

        raw_upstream = raw.get("upstream_imports")
        if not isinstance(raw_upstream, list):
            raise ComplexControlContractError(f"{advisory} upstream_imports must be a list")
        upstream_imports: list[dict[str, str]] = []
        seen_upstream: set[tuple[str, str, str]] = set()
        target_candidates = {edge["candidate_sha"] for edge in target_edges}
        for raw_relation in raw_upstream:
            if not isinstance(raw_relation, Mapping):
                raise ComplexControlContractError(
                    f"{advisory} upstream import is malformed"
                )
            origin_identity = _identity(
                raw_relation.get("origin_repository_identity"),
                aliases,
                field=f"{advisory} origin repository",
            )
            if origin_identity == target_identity:
                raise ComplexControlContractError(
                    f"{advisory} cross-repository origin equals target"
                )
            origin_sha = _full_sha(
                raw_relation.get("origin_sha"), field=f"{advisory} upstream origin"
            )
            import_sha = _full_sha(
                raw_relation.get("import_sha"), field=f"{advisory} import"
            )
            relation = str(raw_relation.get("expected_relation") or "").strip()
            if relation != DECLARED_IMPORT_RELATION:
                raise ComplexControlContractError(
                    f"{advisory} has unsupported upstream relation"
                )
            if import_sha not in target_candidates:
                raise ComplexControlContractError(
                    f"{advisory} upstream import is not a target candidate"
                )
            key = (origin_identity, origin_sha, import_sha)
            if key in seen_upstream:
                raise ComplexControlContractError(
                    f"{advisory} has duplicate upstream import"
                )
            seen_upstream.add(key)
            upstream_imports.append(
                {
                    "origin_repository_identity": origin_identity,
                    "origin_sha": origin_sha,
                    "import_sha": import_sha,
                    "expected_relation": relation,
                }
            )
        upstream_imports.sort(
            key=lambda row: (
                row["origin_repository_identity"],
                row["origin_sha"],
                row["import_sha"],
            )
        )
        has_cross_dimension = "CROSS_REPOSITORY_ORIGIN" in dimensions
        if has_cross_dimension != bool(upstream_imports):
            raise ComplexControlContractError(
                f"{advisory} cross-repository dimension and obligations disagree"
            )

        raw_public = raw.get("public_fixes")
        if not isinstance(raw_public, list) or not raw_public:
            raise ComplexControlContractError(f"{advisory} requires public fixes")
        public_fixes = sorted(
            {_full_sha(value, field=f"{advisory} public fix") for value in raw_public}
        )
        target_fixes = {edge["fix_sha"] for edge in target_edges}
        if not set(public_fixes) <= target_fixes:
            raise ComplexControlContractError(
                f"{advisory} public fix is not a target edge root"
            )
        if "MULTI_FIX" in dimensions and len(target_fixes) < 2:
            raise ComplexControlContractError(
                f"{advisory} MULTI_FIX requires multiple target fixes"
            )
        origin_population = (
            {row["origin_sha"] for row in upstream_imports}
            if has_cross_dimension
            else {row["candidate_sha"] for row in target_edges}
        )
        if "MULTI_ORIGIN" in dimensions and len(origin_population) < 2:
            raise ComplexControlContractError(
                f"{advisory} MULTI_ORIGIN requires multiple origins"
            )

        normalized.append(
            {
                "advisory": advisory,
                "dimensions": dimensions,
                "source": source,
                "source_sha256": source_sha256,
                "topology_sources": topology_sources,
                "target_repository_identity": target_identity,
                "target_edges": target_edges,
                "upstream_imports": upstream_imports,
                "public_fixes": public_fixes,
            }
        )
    normalized.sort(key=lambda row: str(row["advisory"]))
    return normalized


def generation_fix_overlay(
    controls: Sequence[Mapping[str, object]],
) -> dict[str, list[dict[str, str]]]:
    """Expose only unique fix roots; all golden relation fields stay hidden."""

    rows: dict[str, dict[tuple[str, str], dict[str, str]]] = {}
    for control in controls:
        identity = str(control["target_repository_identity"])
        advisory = str(control["advisory"])
        source = str(control["source"])
        by_key = rows.setdefault(identity, {})
        for edge in control["target_edges"]:
            assert isinstance(edge, Mapping)
            fix_sha = str(edge["fix_sha"])
            by_key[(advisory, fix_sha)] = {
                "advisory": advisory,
                "fix_sha": fix_sha,
                "published": "",
                "source": f"complex_control:{source}",
            }
    return {
        identity: sorted(
            values.values(),
            key=lambda row: (row["advisory"], row["fix_sha"]),
        )
        for identity, values in sorted(rows.items())
    }


def routing_target_controls(
    controls: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Flatten target obligations for model-routing evaluation, not generation."""

    rows: list[dict[str, object]] = []
    for control in controls:
        advisory = str(control["advisory"])
        identity = str(control["target_repository_identity"])
        for index, edge in enumerate(control["target_edges"], start=1):
            assert isinstance(edge, Mapping)
            row: dict[str, object] = {
                "advisory": f"{advisory}:target-obligation-{index:02d}",
                "base_advisory": advisory,
                "repository_identity": identity,
                "atomic_origin_sha": str(edge["candidate_sha"]),
                "fix_sha": str(edge["fix_sha"]),
                "expected_relation": str(edge["expected_relation"]),
                "source": str(control["source"]),
            }
            if edge.get("expected_landed_sha"):
                row["expected_landed_sha"] = str(edge["expected_landed_sha"])
            rows.append(row)
    rows.sort(key=lambda row: str(row["advisory"]))
    return rows


def _normalized_edge_identity(
    row: Mapping[str, object], aliases: Mapping[str, str]
) -> str:
    try:
        return canonical_repository_identity(
            str(row.get("repository_identity") or ""), aliases
        )
    except ValueError:
        return ""


def evaluate_complex_controls(
    controls: Sequence[Mapping[str, object]],
    expanded_edges: Sequence[Mapping[str, object]],
    cross_repository_relations: Sequence[Mapping[str, object]],
    public_fix_references: Sequence[Mapping[str, object]],
    aliases: Mapping[str, str],
) -> dict[str, object]:
    """Require every edge in every complex control; one hit cannot mask another."""

    normalized = normalize_complex_controls(controls, aliases)
    control_rows: list[dict[str, object]] = []
    relation_obligation_count = 0
    relation_obligation_passes = 0
    target_obligation_count = 0
    target_obligation_passes = 0
    upstream_obligation_count = 0
    upstream_obligation_passes = 0
    public_rows: list[dict[str, object]] = []
    for control in normalized:
        advisory = str(control["advisory"])
        target_identity = str(control["target_repository_identity"])
        target_rows: list[dict[str, object]] = []
        for expected in control["target_edges"]:
            assert isinstance(expected, Mapping)
            relation_obligation_count += 1
            target_obligation_count += 1
            matches = [
                edge
                for edge in expanded_edges
                if _normalized_edge_identity(edge, aliases) == target_identity
                and str(edge.get("candidate_sha") or "").strip().lower()
                == expected["candidate_sha"]
                and str(edge.get("fix_sha") or "").strip().lower()
                == expected["fix_sha"]
                and str(edge.get("relation") or "") == expected["expected_relation"]
                and (
                    not expected.get("expected_landed_sha")
                    or str(edge.get("landed_sha") or "").strip().lower()
                    == expected["expected_landed_sha"]
                )
            ]
            passed = bool(matches)
            relation_obligation_passes += int(passed)
            target_obligation_passes += int(passed)
            row: dict[str, object] = {
                **dict(expected),
                "status": "PASS" if passed else "MISS",
                "matching_edge_ids": sorted(
                    str(edge.get("edge_id") or "") for edge in matches
                ),
            }
            target_rows.append(row)

        upstream_rows: list[dict[str, object]] = []
        for expected in control["upstream_imports"]:
            assert isinstance(expected, Mapping)
            relation_obligation_count += 1
            upstream_obligation_count += 1
            matches = [
                relation
                for relation in cross_repository_relations
                if str(
                    relation.get("origin_repository_identity") or ""
                ).strip().lower()
                == expected["origin_repository_identity"]
                and str(relation.get("origin_sha") or "").strip().lower()
                == expected["origin_sha"]
                and str(
                    relation.get("target_repository_identity") or ""
                ).strip().lower()
                == target_identity
                and str(relation.get("import_sha") or "").strip().lower()
                == expected["import_sha"]
                and str(relation.get("relation") or "")
                == expected["expected_relation"]
            ]
            passed = bool(matches)
            relation_obligation_passes += int(passed)
            upstream_obligation_passes += int(passed)
            upstream_rows.append(
                {
                    **dict(expected),
                    "status": "PASS" if passed else "MISS",
                    "matching_relation_ids": sorted(
                        str(relation.get("relation_id") or "")
                        for relation in matches
                    ),
                }
            )

        control_passed = all(row["status"] == "PASS" for row in target_rows) and all(
            row["status"] == "PASS" for row in upstream_rows
        )
        control_rows.append(
            {
                "advisory": advisory,
                "dimensions": list(control["dimensions"]),
                "target_repository_identity": target_identity,
                "target_edges": target_rows,
                "upstream_imports": upstream_rows,
                "relation_status": "PASS" if control_passed else "MISS",
            }
        )

        for fix_sha in control["public_fixes"]:
            matches = [
                reference
                for reference in public_fix_references
                if _normalized_edge_identity(reference, aliases) == target_identity
                and str(reference.get("advisory") or "").strip() == advisory
                and str(reference.get("fix_sha") or "").strip().lower() == fix_sha
            ]
            public_rows.append(
                {
                    "advisory": advisory,
                    "repository_identity": target_identity,
                    "fix_sha": fix_sha,
                    "status": "PASS" if matches else "MISS",
                    "matching_reference_count": len(matches),
                }
            )

    control_passes = sum(row["relation_status"] == "PASS" for row in control_rows)
    public_passes = sum(row["status"] == "PASS" for row in public_rows)
    dimension_counts: Counter[str] = Counter()
    dimension_passes: Counter[str] = Counter()
    for row in control_rows:
        for dimension in row["dimensions"]:
            dimension_counts[str(dimension)] += 1
            if row["relation_status"] == "PASS":
                dimension_passes[str(dimension)] += 1
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "complex_ai_causal_recall_evaluation",
        "control_count": len(control_rows),
        "control_pass_count": control_passes,
        "relation_obligation_count": relation_obligation_count,
        "relation_obligation_pass_count": relation_obligation_passes,
        "relation_obligation_recall": (
            relation_obligation_passes / relation_obligation_count
            if relation_obligation_count
            else 0.0
        ),
        "relation_gate_passed": bool(control_rows)
        and control_passes == len(control_rows),
        "target_obligation_count": target_obligation_count,
        "target_obligation_pass_count": target_obligation_passes,
        "upstream_obligation_count": upstream_obligation_count,
        "upstream_obligation_pass_count": upstream_obligation_passes,
        "public_exact_fix_count": len(public_rows),
        "public_exact_fix_pass_count": public_passes,
        "public_exact_fix_recall": public_passes / len(public_rows) if public_rows else 0.0,
        "dimension_counts": {
            dimension: {
                "control_count": dimension_counts[dimension],
                "control_pass_count": dimension_passes[dimension],
            }
            for dimension in sorted(dimension_counts)
        },
        "controls": control_rows,
        "public_fixes": public_rows,
        "controls_sha256": _sha256_json(control_rows),
        "claim_boundary": (
            "all frozen target and upstream obligations must pass; public exact-fix"
            " source recall is separate; the ledger supplies fix roots only during"
            " candidate generation and never supplies origin relations"
        ),
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
    }
    result["result_sha256"] = _sha256_json(result)
    return result
