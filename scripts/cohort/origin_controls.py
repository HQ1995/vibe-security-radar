"""Normalize atomic and multi-edge origin controls into evaluation rows."""

from __future__ import annotations

from collections.abc import Mapping

from cohort.complex_controls import normalize_complex_controls


class OriginControlContractError(ValueError):
    """An origin-control ledger cannot be flattened safely."""


def flatten_origin_controls(
    payload: Mapping[str, object],
) -> list[dict[str, object]]:
    """Return one target-repository row per gold origin/fix edge."""

    raw_controls = payload.get("controls")
    if not isinstance(raw_controls, list) or not raw_controls:
        raise OriginControlContractError("control ledger requires controls")
    has_complex = [
        isinstance(row, Mapping) and "target_edges" in row for row in raw_controls
    ]
    if any(has_complex) and not all(has_complex):
        raise OriginControlContractError("control ledger mixes atomic and complex rows")
    if all(has_complex):
        try:
            controls = normalize_complex_controls(raw_controls, {})
        except ValueError as exc:
            raise OriginControlContractError(str(exc)) from exc
        flattened: list[dict[str, object]] = []
        for control in controls:
            identity = str(control["target_repository_identity"])
            for edge in control["target_edges"]:
                assert isinstance(edge, Mapping)
                row: dict[str, object] = {
                    "advisory": control["advisory"],
                    "repository_identity": identity,
                    "fix_sha": edge["fix_sha"],
                    "atomic_origin_sha": edge["candidate_sha"],
                    "expected_relation": edge["expected_relation"],
                }
                if edge.get("expected_landed_sha"):
                    row["expected_landed_sha"] = edge["expected_landed_sha"]
                flattened.append(row)
        return flattened

    flattened = []
    for raw in raw_controls:
        if not isinstance(raw, Mapping):
            raise OriginControlContractError("atomic control must be an object")
        required = {
            "advisory",
            "repository_identity",
            "fix_sha",
        }
        if not required <= raw.keys() or not (
            raw.get("expected_landed_sha") or raw.get("atomic_origin_sha")
        ):
            raise OriginControlContractError("atomic control lacks an origin edge")
        flattened.append(dict(raw))
    return flattened
