#!/usr/bin/env python3
"""Freeze and evaluate a lossless candidate-unit review schedule."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from cohort.root_adjudication import canonical_sha256


DEFAULT_BUDGETS = (1, 5, 10, 25, 50, 100)
CONFIRMED_STATUS = "CONFIRMED_TRUE_POSITIVE"
UNLEDGERED_STATUS = "NOT_EXPLICITLY_LEDGERED"
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ATOMIC_BUDGET_UNIT = "atomic"
CARRIER_BUDGET_UNIT = "carrier"
_BUDGET_UNITS = (ATOMIC_BUDGET_UNIT, CARRIER_BUDGET_UNIT)
_CANDIDATE_SURFACE_FIELDS = (
    "candidate_surface_uncovered_count",
    "candidate_surface_coverage_complete",
    "carrier_only_squash_relation_root_count",
    "atomic_provenance_gap_count",
)

UnitKey = tuple[str, str, str]
FixKey = tuple[str, str, str]
EdgeKey = tuple[str, str, str, str]
MembershipKey = tuple[str, str, str, str]


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate")
    generate.add_argument("--packets-dir", type=Path, required=True)
    generate.add_argument("--output-dir", type=Path, required=True)
    generate.add_argument("--budget", type=int, action="append", default=[])
    generate.add_argument(
        "--budget-unit",
        choices=_BUDGET_UNITS,
        default=ATOMIC_BUDGET_UNIT,
        help=(
            "atomic keeps one candidate SHA per budget slot; carrier folds "
            "connected squash/landed-PR evidence into one slot while retaining "
            "exact atomic ranks"
        ),
    )

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--generated-dir", type=Path, required=True)
    evaluate.add_argument("--ledger", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


def _read_jsonl(path: Path) -> list[dict[str, object]]:
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
    if not rows:
        raise SystemExit(f"empty JSONL artifact: {path}")
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


def _atomic_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
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


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _full_sha(value: object, label: str) -> str:
    sha = str(value or "").strip().lower()
    if not _FULL_SHA_RE.fullmatch(sha):
        raise SystemExit(f"{label} must be a full lowercase Git SHA")
    return sha


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise SystemExit(f"{label} must be a positive integer")
    return value


def _unit_key(row: Mapping[str, object]) -> UnitKey:
    identity = str(row.get("repository_identity") or "").strip().lower()
    advisory = str(row.get("advisory") or "").strip()
    candidate_sha = _full_sha(row.get("candidate_sha"), "candidate_sha")
    if not identity or not advisory:
        raise SystemExit("candidate unit has an incomplete repository/advisory key")
    return identity, advisory, candidate_sha


def _edge_key(row: Mapping[str, object], edge: Mapping[str, object]) -> EdgeKey:
    identity, advisory, candidate_sha = _unit_key(row)
    return identity, advisory, candidate_sha, _full_sha(edge.get("fix_sha"), "fix_sha")


def _normalize_budgets(values: Sequence[int]) -> list[int]:
    budgets = sorted(set(values or DEFAULT_BUDGETS))
    if not budgets or any(
        not isinstance(value, int) or isinstance(value, bool) or value < 1
        for value in budgets
    ):
        raise SystemExit("budgets must be positive integers")
    return budgets


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SystemExit(f"{label} must be a non-negative integer")
    return value


def _packet_surface_counts(
    packet_summary: Mapping[str, object], budget_unit: str
) -> tuple[int, int, int, int, bool]:
    blocked_roots = _nonnegative_int(
        packet_summary.get("blocked_squash_relation_root_count"),
        "packet summary blocked_squash_relation_root_count",
    )
    has_new_surface = any(
        field in packet_summary for field in _CANDIDATE_SURFACE_FIELDS
    )
    if budget_unit == CARRIER_BUDGET_UNIT:
        candidate_uncovered = _nonnegative_int(
            packet_summary.get("candidate_surface_uncovered_count"),
            "packet summary candidate_surface_uncovered_count",
        )
        carrier_only_roots = _nonnegative_int(
            packet_summary.get("carrier_only_squash_relation_root_count"),
            "packet summary carrier_only_squash_relation_root_count",
        )
        atomic_gaps = _nonnegative_int(
            packet_summary.get("atomic_provenance_gap_count"),
            "packet summary atomic_provenance_gap_count",
        )
        if packet_summary.get("squash_relation_closure_applied") is not True:
            raise SystemExit("carrier schedule requires squash relation closure")
        has_new_surface = True
    elif has_new_surface:
        candidate_uncovered = _nonnegative_int(
            packet_summary.get("candidate_surface_uncovered_count"),
            "packet summary candidate_surface_uncovered_count",
        )
        carrier_only_roots = (
            _nonnegative_int(
                packet_summary.get("carrier_only_squash_relation_root_count"),
                "packet summary carrier_only_squash_relation_root_count",
            )
            if "carrier_only_squash_relation_root_count" in packet_summary
            else 0
        )
        atomic_gaps = (
            _nonnegative_int(
                packet_summary.get("atomic_provenance_gap_count"),
                "packet summary atomic_provenance_gap_count",
            )
            if "atomic_provenance_gap_count" in packet_summary
            else 0
        )
    else:
        candidate_uncovered = blocked_roots
        carrier_only_roots = 0
        atomic_gaps = 0

    if has_new_surface:
        expected_complete = candidate_uncovered == 0
        if (
            packet_summary.get("candidate_surface_coverage_complete")
            is not expected_complete
        ):
            raise SystemExit(
                "packet summary candidate_surface_coverage_complete contradicts "
                "candidate_surface_uncovered_count"
            )
    if has_new_surface and atomic_gaps != carrier_only_roots + blocked_roots:
        raise SystemExit(
            "packet summary atomic_provenance_gap_count must equal "
            "carrier_only_squash_relation_root_count plus "
            "blocked_squash_relation_root_count"
        )
    if has_new_surface and candidate_uncovered != blocked_roots:
        raise SystemExit(
            "packet summary candidate_surface_uncovered_count must equal "
            "blocked_squash_relation_root_count"
        )
    return (
        blocked_roots,
        candidate_uncovered,
        carrier_only_roots,
        atomic_gaps,
        has_new_surface,
    )


def _schedule_budget_unit(summary: Mapping[str, object]) -> str:
    schema_version = summary.get("schema_version")
    explicit = summary.get("budget_unit")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise SystemExit("unsupported or ambiguous frozen schedule schema")
    if schema_version == 1 and explicit is None:
        return ATOMIC_BUDGET_UNIT
    if schema_version == 2 and explicit == CARRIER_BUDGET_UNIT:
        return CARRIER_BUDGET_UNIT
    raise SystemExit("unsupported or ambiguous frozen schedule schema")


def _normalize_units(
    raw_units: Sequence[Mapping[str, object]],
    *,
    preserve_carrier_metadata: bool = False,
) -> list[dict[str, object]]:
    units: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_keys: set[UnitKey] = set()
    for raw in raw_units:
        identity, advisory, candidate_sha = _unit_key(raw)
        unit_id = str(raw.get("unit_id") or "").strip()
        if not unit_id or unit_id in seen_ids:
            raise SystemExit(
                f"candidate unit has a missing or duplicate unit_id: {unit_id!r}"
            )
        key = (identity, advisory, candidate_sha)
        if key in seen_keys:
            raise SystemExit(f"duplicate candidate unit key: {key}")
        if raw.get("retained") is not True:
            raise SystemExit(f"candidate unit is not retained: {unit_id}")
        raw_edges = raw.get("fix_edges")
        if not isinstance(raw_edges, list) or not raw_edges:
            raise SystemExit(f"candidate unit has no fix edges: {unit_id}")
        edges: list[dict[str, object]] = []
        seen_fixes: set[str] = set()
        for raw_edge in raw_edges:
            if not isinstance(raw_edge, Mapping):
                raise SystemExit(f"candidate unit has a malformed fix edge: {unit_id}")
            fix_sha = _full_sha(raw_edge.get("fix_sha"), "fix_sha")
            if fix_sha in seen_fixes:
                raise SystemExit(
                    f"candidate unit repeats a fix edge: {unit_id}@{fix_sha}"
                )
            seen_fixes.add(fix_sha)
            edges.append(
                {
                    "fix_sha": fix_sha,
                    "source_priority_rank": _positive_int(
                        raw_edge.get("priority_rank"), "fix edge priority_rank"
                    ),
                }
            )
        edges.sort(key=lambda edge: str(edge["fix_sha"]))
        if raw.get("fix_edge_count") != len(edges):
            raise SystemExit(f"candidate unit fix_edge_count mismatch: {unit_id}")
        best_priority_rank = _positive_int(
            raw.get("best_priority_rank"), "best_priority_rank"
        )
        if best_priority_rank != min(
            int(edge["source_priority_rank"]) for edge in edges
        ):
            raise SystemExit(f"candidate unit best_priority_rank mismatch: {unit_id}")
        unit = {
            "unit_id": unit_id,
            "repository_identity": identity,
            "advisory": advisory,
            "candidate_sha": candidate_sha,
            "best_priority_rank": best_priority_rank,
            "fix_edges": edges,
            "fix_edge_count": len(edges),
        }
        if preserve_carrier_metadata:
            raw_group_ids = raw.get("squash_group_ids", [])
            if not isinstance(raw_group_ids, list) or any(
                not isinstance(value, str) for value in raw_group_ids
            ):
                raise SystemExit(
                    f"candidate unit has malformed squash_group_ids: {unit_id}"
                )
            unit["squash_group_ids"] = sorted(
                {_full_sha(value, "squash_group_id") for value in raw_group_ids}
            )
            raw_pr_number = raw.get("pr_number")
            unit["carrier_squash_pr_number_connector"] = (
                raw_pr_number
                if str(raw.get("merge_topology") or "").strip().lower() == "squash"
                and isinstance(raw_pr_number, int)
                and not isinstance(raw_pr_number, bool)
                and raw_pr_number > 0
                else None
            )
        units.append(unit)
        seen_ids.add(unit_id)
        seen_keys.add(key)
    return units


def _assign_carrier_groups(
    units: Sequence[dict[str, object]],
) -> None:
    by_case: defaultdict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for unit in units:
        case_key = (str(unit["repository_identity"]), str(unit["advisory"]))
        by_case[case_key].append(unit)

    for (identity, advisory), case_units in sorted(by_case.items()):
        by_id = {str(unit["unit_id"]): unit for unit in case_units}
        parent = {unit_id: unit_id for unit_id in by_id}
        owner_by_connector: dict[tuple[str, object], str] = {}

        def root(unit_id: str) -> str:
            while parent[unit_id] != unit_id:
                parent[unit_id] = parent[parent[unit_id]]
                unit_id = parent[unit_id]
            return unit_id

        for unit in sorted(case_units, key=lambda row: str(row["unit_id"])):
            unit_id = str(unit["unit_id"])
            raw_group_ids = unit.get("squash_group_ids", [])
            assert isinstance(raw_group_ids, list)
            connectors: list[tuple[str, object]] = [
                ("sha", str(unit["candidate_sha"])),
                *(("sha", group_id) for group_id in raw_group_ids),
            ]
            pr_number = unit.get("carrier_squash_pr_number_connector")
            if isinstance(pr_number, int):
                connectors.append(("squash_pr", pr_number))
            for connector in connectors:
                owner = owner_by_connector.setdefault(connector, unit_id)
                parent[root(unit_id)] = root(owner)

        components: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
        for unit_id, unit in by_id.items():
            components[root(unit_id)].append(unit)
        for component in components.values():
            member_shas = sorted(str(unit["candidate_sha"]) for unit in component)
            digest = hashlib.sha256(
                "\0".join((identity, advisory, *member_shas)).encode()
            ).hexdigest()
            group_id = f"carrier-group-{digest}"
            for unit in component:
                unit["carrier_group_id"] = group_id


def _unit_order(row: Mapping[str, object]) -> tuple[int, str, str]:
    return (
        int(row["best_priority_rank"]),
        str(row["candidate_sha"]),
        str(row["unit_id"]),
    )


def _atomic_fix_positions(
    units: Sequence[Mapping[str, object]],
) -> dict[tuple[str, str], int]:
    fix_members: defaultdict[FixKey, list[tuple[int, str, str]]] = defaultdict(list)
    for unit in units:
        identity, advisory, candidate_sha = _unit_key(unit)
        unit_id = str(unit["unit_id"])
        for edge in unit["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(edge, Mapping)
            fix_sha = _full_sha(edge.get("fix_sha"), "fix_sha")
            fix_members[(identity, advisory, fix_sha)].append(
                (int(edge["source_priority_rank"]), candidate_sha, unit_id)
            )
    positions: dict[tuple[str, str], int] = {}
    for fix_key, members in fix_members.items():
        for position, (_, _, unit_id) in enumerate(sorted(members), start=1):
            positions[(unit_id, fix_key[2])] = position
    return positions


def _freeze_schedule(units: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    ordered = sorted(
        units,
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]),
            *_unit_order(row),
        ),
    )
    fix_positions = _atomic_fix_positions(ordered)

    case_positions: Counter[tuple[str, str]] = Counter()
    schedule: list[dict[str, object]] = []
    for schedule_position, unit in enumerate(ordered, start=1):
        case_key = (
            str(unit["repository_identity"]),
            str(unit["advisory"]),
        )
        case_positions[case_key] += 1
        frozen_edges: list[dict[str, object]] = []
        for edge in unit["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(edge, Mapping)
            fix_sha = str(edge["fix_sha"])
            frozen_edges.append(
                {
                    "fix_sha": fix_sha,
                    "source_priority_rank": int(edge["source_priority_rank"]),
                    "frozen_fix_position": fix_positions[
                        (str(unit["unit_id"]), fix_sha)
                    ],
                }
            )
        schedule.append(
            {
                "schedule_position": schedule_position,
                "case_schedule_position": case_positions[case_key],
                "unit_id": str(unit["unit_id"]),
                "repository_identity": case_key[0],
                "advisory": case_key[1],
                "candidate_sha": str(unit["candidate_sha"]),
                "best_priority_rank": int(unit["best_priority_rank"]),
                "fix_edges": frozen_edges,
                "fix_edge_count": len(frozen_edges),
            }
        )
    return schedule


def _carrier_fix_positions(
    schedule: Sequence[Mapping[str, object]], group_ids: Mapping[str, str]
) -> dict[tuple[FixKey, str], int]:
    group_ranks: defaultdict[FixKey, dict[str, int]] = defaultdict(dict)
    for row in schedule:
        identity, advisory, _ = _unit_key(row)
        group_id = group_ids[str(row["unit_id"])]
        for edge in row["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(edge, Mapping)
            fix_key = (
                identity,
                advisory,
                _full_sha(edge.get("fix_sha"), "fix_sha"),
            )
            rank = int(edge["source_priority_rank"])
            group_ranks[fix_key][group_id] = min(
                rank, group_ranks[fix_key].get(group_id, rank)
            )
    return {
        (fix_key, group_id): position
        for fix_key, ranks in group_ranks.items()
        for position, group_id in enumerate(
            sorted(ranks, key=lambda value: (ranks[value], value)), start=1
        )
    }


def _add_carrier_schedule(
    schedule: Sequence[dict[str, object]],
    units: Sequence[Mapping[str, object]],
) -> None:
    units_by_id = {str(unit["unit_id"]): unit for unit in units}
    group_ids = {
        unit_id: str(unit["carrier_group_id"]) for unit_id, unit in units_by_id.items()
    }
    positions = _carrier_fix_positions(schedule, group_ids)
    for row in schedule:
        unit = units_by_id[str(row["unit_id"])]
        group_id = group_ids[str(row["unit_id"])]
        provenance = {"squash_group_ids": list(unit["squash_group_ids"])}
        pr_number = unit.get("carrier_squash_pr_number_connector")
        if isinstance(pr_number, int):
            provenance["squash_pr_number"] = pr_number
        row.update(
            carrier_group_id=group_id,
            carrier_connector_provenance=provenance,
        )
        for edge in row["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(edge, dict)
            fix_key = (
                str(row["repository_identity"]),
                str(row["advisory"]),
                str(edge["fix_sha"]),
            )
            edge["frozen_carrier_fix_position"] = positions[(fix_key, group_id)]


def _rebuild_schedule(
    raw_units: Sequence[Mapping[str, object]], budget_unit: str
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    carrier_mode = budget_unit == CARRIER_BUDGET_UNIT
    if budget_unit not in _BUDGET_UNITS:
        raise SystemExit("unknown schedule budget unit")
    units = _normalize_units(
        raw_units,
        preserve_carrier_metadata=carrier_mode,
    )
    if carrier_mode:
        _assign_carrier_groups(units)
    schedule = _freeze_schedule(units)
    if carrier_mode:
        _add_carrier_schedule(schedule, units)
    return units, schedule


def _index_schedule(
    schedule: Sequence[Mapping[str, object]],
) -> tuple[dict[str, dict[str, object]], set[EdgeKey], set[FixKey]]:
    units: dict[str, dict[str, object]] = {}
    unit_keys: set[UnitKey] = set()
    edge_keys: set[EdgeKey] = set()
    fix_positions: defaultdict[FixKey, list[int]] = defaultdict(list)
    for expected_position, raw in enumerate(schedule, start=1):
        row = dict(raw)
        if row.get("schedule_position") != expected_position:
            raise SystemExit("frozen schedule positions are not contiguous")
        unit_id = str(row.get("unit_id") or "")
        if not unit_id or unit_id in units:
            raise SystemExit(f"frozen schedule repeats unit_id: {unit_id!r}")
        key = _unit_key(row)
        if key in unit_keys:
            raise SystemExit(f"frozen schedule repeats candidate unit key: {key}")
        _positive_int(row.get("best_priority_rank"), "best_priority_rank")
        _positive_int(row.get("case_schedule_position"), "case_schedule_position")
        raw_edges = row.get("fix_edges")
        if not isinstance(raw_edges, list) or not raw_edges:
            raise SystemExit(f"frozen schedule unit has no fix edges: {unit_id}")
        if row.get("fix_edge_count") != len(raw_edges):
            raise SystemExit(f"frozen schedule fix_edge_count mismatch: {unit_id}")
        for raw_edge in raw_edges:
            if not isinstance(raw_edge, Mapping):
                raise SystemExit(f"frozen schedule has malformed fix edge: {unit_id}")
            edge_key = _edge_key(row, raw_edge)
            if edge_key in edge_keys:
                raise SystemExit(f"frozen schedule repeats edge: {edge_key}")
            _positive_int(raw_edge.get("source_priority_rank"), "source_priority_rank")
            position = _positive_int(
                raw_edge.get("frozen_fix_position"), "frozen_fix_position"
            )
            fix_key = (edge_key[0], edge_key[1], edge_key[3])
            fix_positions[fix_key].append(position)
            edge_keys.add(edge_key)
        units[unit_id] = row
        unit_keys.add(key)
    for fix_key, positions in fix_positions.items():
        if sorted(positions) != list(range(1, len(positions) + 1)):
            raise SystemExit(f"frozen fix positions are not contiguous: {fix_key}")
    return units, edge_keys, set(fix_positions)


def _validate_schedule_mode(
    schedule: Sequence[Mapping[str, object]], budget_unit: str
) -> None:
    expected_atomic_positions = _atomic_fix_positions(schedule)
    for row in schedule:
        edges = row["fix_edges"]  # type: ignore[assignment]
        assert isinstance(edges, list)
        for edge in edges:
            assert isinstance(edge, Mapping)
            expected_position = expected_atomic_positions[
                (str(row["unit_id"]), _full_sha(edge.get("fix_sha"), "fix_sha"))
            ]
            if edge.get("frozen_fix_position") != expected_position:
                raise SystemExit("frozen atomic fix position mismatch")

    if budget_unit == ATOMIC_BUDGET_UNIT:
        if any(
            any(
                field in row
                for field in ("carrier_group_id", "carrier_connector_provenance")
            )
            or any(
                "frozen_carrier_fix_position" in edge
                for edge in row["fix_edges"]  # type: ignore[union-attr]
            )
            for row in schedule
        ):
            raise SystemExit("atomic schedule contains carrier metadata")
        return
    if budget_unit != CARRIER_BUDGET_UNIT:
        raise SystemExit("unknown schedule budget unit")

    reconstructed_units: list[dict[str, object]] = []
    for row in schedule:
        edges = row["fix_edges"]  # type: ignore[assignment]
        assert isinstance(edges, list)
        group_id = row.get("carrier_group_id")
        provenance = row.get("carrier_connector_provenance")
        if (
            not isinstance(group_id, str)
            or not group_id
            or not isinstance(provenance, Mapping)
        ):
            raise SystemExit("frozen schedule budget-unit schema mismatch")
        if set(provenance) - {"squash_group_ids", "squash_pr_number"}:
            raise SystemExit("frozen schedule carrier provenance is malformed")
        raw_group_ids = provenance.get("squash_group_ids")
        if not isinstance(raw_group_ids, list) or any(
            not isinstance(value, str) for value in raw_group_ids
        ):
            raise SystemExit("frozen schedule carrier provenance is malformed")
        squash_group_ids = sorted(
            {_full_sha(value, "squash_group_id") for value in raw_group_ids}
        )
        pr_number = provenance.get("squash_pr_number")
        if "squash_pr_number" in provenance:
            pr_number = _positive_int(pr_number, "squash_pr_number")
        if any(
            not isinstance(edge, Mapping)
            or not isinstance(edge.get("frozen_carrier_fix_position"), int)
            or isinstance(edge.get("frozen_carrier_fix_position"), bool)
            or int(edge["frozen_carrier_fix_position"]) < 1
            for edge in edges
        ):
            raise SystemExit("frozen schedule budget-unit schema mismatch")
        identity, advisory, candidate_sha = _unit_key(row)
        reconstructed_units.append(
            {
                "unit_id": str(row["unit_id"]),
                "repository_identity": identity,
                "advisory": advisory,
                "candidate_sha": candidate_sha,
                "squash_group_ids": squash_group_ids,
                "carrier_squash_pr_number_connector": pr_number,
            }
        )

    _assign_carrier_groups(reconstructed_units)
    expected_group_ids = {
        str(unit["unit_id"]): str(unit["carrier_group_id"])
        for unit in reconstructed_units
    }
    for row in schedule:
        if row["carrier_group_id"] != expected_group_ids[str(row["unit_id"])]:
            raise SystemExit("frozen carrier group id mismatch")
    expected_carrier_positions = _carrier_fix_positions(schedule, expected_group_ids)
    for row in schedule:
        group_id = expected_group_ids[str(row["unit_id"])]
        identity, advisory, _ = _unit_key(row)
        for edge in row["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(edge, Mapping)
            fix_key = (
                identity,
                advisory,
                _full_sha(edge.get("fix_sha"), "fix_sha"),
            )
            if (
                edge["frozen_carrier_fix_position"]
                != expected_carrier_positions[(fix_key, group_id)]
            ):
                raise SystemExit("frozen carrier fix position mismatch")


def _budget_selection(
    units: Mapping[str, Mapping[str, object]],
    budget: int,
    budget_unit: str,
) -> tuple[set[MembershipKey], set[str], set[EdgeKey], set[EdgeKey]]:
    position_field = (
        "frozen_fix_position"
        if budget_unit == ATOMIC_BUDGET_UNIT
        else "frozen_carrier_fix_position"
    )
    memberships: set[MembershipKey] = set()
    entity_by_unit: dict[str, tuple[str, str, str]] = {}
    for unit_id, row in units.items():
        identity, advisory, _ = _unit_key(row)
        entity = (
            unit_id
            if budget_unit == ATOMIC_BUDGET_UNIT
            else str(row["carrier_group_id"])
        )
        scoped_entity = (
            identity,
            advisory,
            entity,
        )
        entity_by_unit[unit_id] = scoped_entity
        for edge in row["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(edge, Mapping)
            if int(edge[position_field]) <= budget:
                memberships.add(
                    (*scoped_entity, _full_sha(edge.get("fix_sha"), "fix_sha"))
                )
    selected_entities = {membership[:3] for membership in memberships}
    selected_units = {
        unit_id
        for unit_id, entity in entity_by_unit.items()
        if entity in selected_entities
    }
    same_fix_edges: set[EdgeKey] = set()
    global_edges: set[EdgeKey] = set()
    for unit_id, row in units.items():
        for edge in row["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(edge, Mapping)
            edge_key = _edge_key(row, edge)
            if (*entity_by_unit[unit_id], edge_key[3]) in memberships:
                same_fix_edges.add(edge_key)
            if unit_id in selected_units:
                global_edges.add(edge_key)
    return memberships, selected_units, same_fix_edges, global_edges


def _aggregate_slots(
    schedule: Sequence[Mapping[str, object]],
    budgets: Sequence[int],
    *,
    budget_unit: str = ATOMIC_BUDGET_UNIT,
) -> list[dict[str, object]]:
    units, _, fix_keys = _index_schedule(schedule)
    _validate_schedule_mode(schedule, budget_unit)
    result: list[dict[str, object]] = []
    for budget in budgets:
        memberships, selected_units, _, global_edges = _budget_selection(
            units, budget, budget_unit
        )
        if budget_unit == CARRIER_BUDGET_UNIT:
            result.append(
                {
                    "budget_per_fix": budget,
                    "budget_unit": CARRIER_BUDGET_UNIT,
                    "triggered_carrier_fix_membership_count": len(memberships),
                    "triggered_unique_carrier_group_count": len(
                        {
                            (repository, advisory, group_id)
                            for repository, advisory, group_id, _ in memberships
                        }
                    ),
                    "expanded_atomic_unit_count": len(selected_units),
                }
            )
            continue
        result.append(
            {
                "budget_per_fix": budget,
                "fix_scope_count": len(fix_keys),
                "aggregate_per_fix_slot_capacity": budget * len(fix_keys),
                "aggregate_fix_prefix_membership_slots": len(memberships),
                "aggregate_unique_unit_review_slots": len(selected_units),
                "folded_duplicate_membership_slots": len(memberships)
                - len(selected_units),
                "selected_units_carried_edge_count": len(global_edges),
            }
        )
    return result


def _generate(args: argparse.Namespace) -> int:
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    packet_summary = _read_json(args.packets_dir / "summary.json")
    raw_units = _read_jsonl(args.packets_dir / "candidate_units.jsonl")
    if packet_summary.get("artifact_kind") != "lossless_origin_candidate_packets":
        raise SystemExit("candidate-unit scheduling requires lossless origin packets")
    if canonical_sha256(raw_units) != packet_summary.get("candidate_units_sha256"):
        raise SystemExit("candidate unit digest mismatch")
    if packet_summary.get("candidate_unit_count") != len(raw_units):
        raise SystemExit("candidate unit count mismatch")
    if packet_summary.get("all_fix_edges_conserved") is not True:
        raise SystemExit("packet artifact did not conserve fix edges")
    if packet_summary.get("all_candidate_units_assigned_once") is not True:
        raise SystemExit("packet artifact did not assign every candidate unit once")

    budget_unit = str(args.budget_unit)
    carrier_mode = budget_unit == CARRIER_BUDGET_UNIT
    _packet_surface_counts(packet_summary, budget_unit)
    units, schedule = _rebuild_schedule(raw_units, budget_unit)
    edge_count = sum(int(unit["fix_edge_count"]) for unit in units)
    if packet_summary.get("candidate_fix_pair_count") != edge_count:
        raise SystemExit("candidate fix-edge count mismatch")
    budgets = _normalize_budgets(args.budget)
    _, edge_keys, fix_keys = _index_schedule(schedule)
    aggregates = _aggregate_slots(schedule, budgets, budget_unit=budget_unit)
    case_count = len(
        {(str(row["repository_identity"]), str(row["advisory"])) for row in schedule}
    )

    args.output_dir.mkdir(parents=True, exist_ok=False)
    schedule_path = args.output_dir / "schedule.jsonl"
    _atomic_jsonl(schedule_path, schedule)
    summary = {
        "schema_version": 2 if carrier_mode else 1,
        "artifact_kind": "frozen_candidate_unit_schedule",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "generation_process_boundary": (
            "frozen_candidate_units_no_label_or_adjudication_ledger_read"
        ),
        "schedule_order_policy": (
            "Within each fix scope: that edge's source_priority_rank, candidate_sha, "
            "unit_id. Global schedule_position uses the unit's best edge rank for "
            "stable serialization only and is never interpreted as a review budget."
        ),
        "budget_semantics": (
            "B is applied independently to every fix scope. Aggregate unit-review "
            "slots are the union of those per-fix prefixes, so a multi-fix unit is "
            "reviewed once while every exact fix edge remains attached."
        ),
        "budgets_per_fix": budgets,
        "source_artifacts": {
            "packet_summary": {
                "path": str(args.packets_dir / "summary.json"),
                "sha256": _file_sha256(args.packets_dir / "summary.json"),
                "canonical_sha256": canonical_sha256(packet_summary),
            },
            "candidate_units": {
                "path": str(args.packets_dir / "candidate_units.jsonl"),
                "sha256": _file_sha256(args.packets_dir / "candidate_units.jsonl"),
                "canonical_sha256": canonical_sha256(raw_units),
            },
        },
        "case_count": case_count,
        "fix_scope_count": len(fix_keys),
        "candidate_unit_count": len(schedule),
        "candidate_fix_edge_count": len(edge_keys),
        "schedule_rows_sha256": canonical_sha256(schedule),
        "schedule_file_sha256": _file_sha256(schedule_path),
        "aggregate_review_slots": aggregates,
        "conservation": {
            "all_candidate_units_scheduled_once": len(schedule) == len(units),
            "all_fix_edges_preserved": len(edge_keys) == edge_count,
            "hard_filter_count": 0,
            "passed": len(schedule) == len(units) and len(edge_keys) == edge_count,
        },
    }
    if carrier_mode:
        summary.update(
            {
                "budget_unit": CARRIER_BUDGET_UNIT,
                "schedule_order_policy": (
                    "Per-fix carrier order: minimum source_priority_rank, then group id; "
                    "frozen_fix_position stays atomic."
                ),
                "budget_semantics": (
                    "B carrier groups/fix; carry same-fix atomic edges; cost is expanded "
                    "units; transport/token cost is unknown."
                ),
                "carrier_group_policy": (
                    "Repo+advisory components over SHA/group IDs plus positive PR only "
                    "for squash; budget-only, not atomic provenance; unconnected direct "
                    "is singleton."
                ),
            }
        )
    _atomic_json(args.output_dir / "summary.json", summary)
    print("Candidate-unit schedule frozen")
    print(f"  units : {len(schedule)}")
    print(f"  edges : {len(edge_keys)}")
    print(f"  fixes : {len(fix_keys)}")
    print(f"  output: {args.output_dir}")
    return 0


def _ledger_state(
    ledger: Mapping[str, object], schedule_edges: set[EdgeKey]
) -> dict[EdgeKey, str]:
    conservation = ledger.get("conservation")
    if not isinstance(conservation, Mapping):
        raise SystemExit("label ledger conservation is missing")
    if conservation.get("passed") is not True:
        raise SystemExit("label ledger conservation did not pass")
    if conservation.get("hard_delete_count") != 0:
        raise SystemExit("label ledger contains hard deletions")
    raw_rows = ledger.get("edge_ledger")
    if not isinstance(raw_rows, list):
        raise SystemExit("label ledger edge_ledger is malformed")
    statuses: dict[EdgeKey, str] = {}
    for raw in raw_rows:
        if not isinstance(raw, Mapping):
            raise SystemExit("label ledger contains a non-object edge row")
        identity = str(raw.get("repository_identity") or "").strip().lower()
        advisory = str(raw.get("advisory") or "").strip()
        key = (
            identity,
            advisory,
            _full_sha(raw.get("candidate_sha"), "ledger candidate_sha"),
            _full_sha(raw.get("fix_sha"), "ledger fix_sha"),
        )
        status = str(raw.get("status") or "").strip()
        if not identity or not advisory or not status:
            raise SystemExit("label ledger contains an incomplete edge row")
        if key in statuses:
            raise SystemExit(f"label ledger repeats edge: {key}")
        if key not in schedule_edges:
            raise SystemExit(f"label ledger edge is outside frozen schedule: {key}")
        statuses[key] = status
    return statuses


def _evaluate_budget(
    slot: Mapping[str, object],
    units: Mapping[str, Mapping[str, object]],
    statuses: Mapping[EdgeKey, str],
) -> dict[str, object]:
    budget = int(slot["budget_per_fix"])
    trigger_edges: set[EdgeKey] = set()
    selected_units: set[str] = set()
    all_unit_edges: dict[str, set[EdgeKey]] = {}
    for unit_id, row in units.items():
        unit_edges: set[EdgeKey] = set()
        for edge in row["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(edge, Mapping)
            key = _edge_key(row, edge)
            unit_edges.add(key)
            if int(edge["frozen_fix_position"]) <= budget:
                trigger_edges.add(key)
                selected_units.add(unit_id)
        all_unit_edges[unit_id] = unit_edges
    carried_edges = {
        edge for unit_id in selected_units for edge in all_unit_edges[unit_id]
    }
    confirmed_edges = {
        key for key, value in statuses.items() if value == CONFIRMED_STATUS
    }
    confirmed_units = {
        unit_id for unit_id, edges in all_unit_edges.items() if edges & confirmed_edges
    }
    selected_confirmed_units = selected_units & confirmed_units
    confirmed_prefix_edges = trigger_edges & confirmed_edges
    confirmed_carried_edges = carried_edges & confirmed_edges
    labeled_selected_units = {
        unit_id for unit_id in selected_units if all_unit_edges[unit_id] & set(statuses)
    }
    status_counts = Counter(
        statuses.get(edge, UNLEDGERED_STATUS) for edge in carried_edges
    )
    return {
        **dict(slot),
        "labeled_unique_unit_count": len(labeled_selected_units),
        "labeled_carried_edge_count": len(carried_edges & set(statuses)),
        "confirmed_unique_unit_count": len(selected_confirmed_units),
        "confirmed_fix_prefix_edge_count": len(confirmed_prefix_edges),
        "confirmed_carried_edge_count": len(confirmed_carried_edges),
        "edge_status_counts_in_reviewed_units": dict(sorted(status_counts.items())),
        "known_confirmed_unit_recall_within_schedule": (
            len(selected_confirmed_units) / len(confirmed_units)
            if confirmed_units
            else None
        ),
        "known_confirmed_edge_recall_by_fix_prefix": (
            len(confirmed_prefix_edges) / len(confirmed_edges)
            if confirmed_edges
            else None
        ),
        "known_confirmed_edge_recall_via_unit_reviews": (
            len(confirmed_carried_edges) / len(confirmed_edges)
            if confirmed_edges
            else None
        ),
    }


def _evaluate(args: argparse.Namespace) -> int:
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    summary_path = args.generated_dir / "summary.json"
    schedule_path = args.generated_dir / "schedule.jsonl"
    summary = _read_json(summary_path)
    schedule = _read_jsonl(schedule_path)
    if summary.get("artifact_kind") != "frozen_candidate_unit_schedule":
        raise SystemExit("evaluation requires a frozen candidate-unit schedule")
    if _schedule_budget_unit(summary) != ATOMIC_BUDGET_UNIT:
        raise SystemExit("label-ledger evaluation supports atomic schedules only")
    if summary.get("generation_process_boundary") != (
        "frozen_candidate_units_no_label_or_adjudication_ledger_read"
    ):
        raise SystemExit("frozen schedule crossed the label boundary")
    if canonical_sha256(schedule) != summary.get("schedule_rows_sha256"):
        raise SystemExit("frozen schedule canonical digest mismatch")
    if _file_sha256(schedule_path) != summary.get("schedule_file_sha256"):
        raise SystemExit("frozen schedule file digest mismatch")
    units, schedule_edges, fix_keys = _index_schedule(schedule)
    if summary.get("candidate_unit_count") != len(units):
        raise SystemExit("frozen schedule unit count mismatch")
    if summary.get("candidate_fix_edge_count") != len(schedule_edges):
        raise SystemExit("frozen schedule edge count mismatch")
    budgets = _normalize_budgets(summary.get("budgets_per_fix", []))  # type: ignore[arg-type]
    slots = _aggregate_slots(schedule, budgets)
    if slots != summary.get("aggregate_review_slots"):
        raise SystemExit("frozen aggregate review slots mismatch")

    ledger = _read_json(args.ledger)
    if ledger.get("artifact_kind") != "candidate_unit_edge_label_ledger":
        raise SystemExit("label ledger artifact kind is invalid")
    statuses = _ledger_state(ledger, schedule_edges)
    confirmed_edges = {
        key for key, value in statuses.items() if value == CONFIRMED_STATUS
    }
    confirmed_units = {
        unit_id
        for unit_id, row in units.items()
        if any(_edge_key(row, edge) in confirmed_edges for edge in row["fix_edges"])  # type: ignore[union-attr]
    }
    unit_evaluations: list[dict[str, object]] = []
    for unit_id, row in units.items():
        edge_evaluations: list[dict[str, object]] = []
        for edge in row["fix_edges"]:  # type: ignore[union-attr]
            assert isinstance(edge, Mapping)
            key = _edge_key(row, edge)
            edge_evaluations.append(
                {
                    "fix_sha": key[3],
                    "source_priority_rank": int(edge["source_priority_rank"]),
                    "frozen_fix_position": int(edge["frozen_fix_position"]),
                    "status": statuses.get(key, UNLEDGERED_STATUS),
                }
            )
        unit_evaluations.append(
            {
                "schedule_position": int(row["schedule_position"]),
                "unit_id": unit_id,
                "repository_identity": str(row["repository_identity"]),
                "advisory": str(row["advisory"]),
                "candidate_sha": str(row["candidate_sha"]),
                "fix_edge_count": len(edge_evaluations),
                "labeled_edge_count": sum(
                    edge["status"] != UNLEDGERED_STATUS for edge in edge_evaluations
                ),
                "has_confirmed_edge": unit_id in confirmed_units,
                "edge_evaluations": edge_evaluations,
            }
        )
    status_counts = Counter(statuses.values())
    artifact = {
        "schema_version": 1,
        "artifact_kind": "candidate_unit_frozen_schedule_scorecard",
        "source_artifacts": {
            "frozen_schedule_summary": {
                "path": str(summary_path),
                "sha256": _file_sha256(summary_path),
            },
            "frozen_schedule": {
                "path": str(schedule_path),
                "sha256": _file_sha256(schedule_path),
            },
            "label_ledger": {
                "path": str(args.ledger),
                "sha256": _file_sha256(args.ledger),
            },
        },
        "frozen_schedule_rows_sha256": summary["schedule_rows_sha256"],
        "summary": {
            "frozen_candidate_unit_count": len(units),
            "frozen_candidate_fix_edge_count": len(schedule_edges),
            "fix_scope_count": len(fix_keys),
            "ledgered_edge_count": len(statuses),
            "unledgered_edge_count": len(schedule_edges) - len(statuses),
            "known_confirmed_edge_count": len(confirmed_edges),
            "known_confirmed_unit_count": len(confirmed_units),
            "edge_status_counts": dict(sorted(status_counts.items())),
        },
        "aggregate_review_slots": [
            _evaluate_budget(slot, units, statuses) for slot in slots
        ],
        "unit_evaluations": unit_evaluations,
        "conservation": {
            "schedule_order_recomputed": False,
            "schedule_digest_preserved": True,
            "all_units_retained": len(unit_evaluations) == len(units),
            "all_fix_edges_retained": sum(
                int(row["fix_edge_count"]) for row in unit_evaluations
            )
            == len(schedule_edges),
            "hard_filter_count": 0,
            "passed": True,
        },
        "claim_boundary": (
            "Labels are attached to exact repository/advisory/candidate/fix edges "
            "after the unit schedule is frozen. Budgets are top-B per fix, while "
            "aggregate review cost counts the union of candidate units. This is "
            "known-label recall inside the frozen schedule, not population recall."
        ),
    }
    _atomic_json(args.output, artifact)
    print("Candidate-unit scorecard written")
    print(f"  units : {len(units)}")
    print(f"  edges : {len(schedule_edges)}")
    print(f"  labels: {len(statuses)}")
    print(f"  output: {args.output}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "generate":
        return _generate(args)
    return _evaluate(args)


if __name__ == "__main__":
    raise SystemExit(main())
