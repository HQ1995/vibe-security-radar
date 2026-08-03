"""Tests for the label-free candidate-unit schedule and edge scorecard."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cohort.root_adjudication import canonical_sha256
from cohort_candidate_unit_scorecard import (
    CARRIER_BUDGET_UNIT,
    _schedule_budget_unit,
    _validate_schedule_mode,
    main,
)


def _sha(character: str) -> str:
    return character * 40


def _json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def _unit(
    *,
    unit_id: str,
    repository: str,
    advisory: str,
    candidate: str,
    edges: list[tuple[str, int]],
    squash_group_ids: list[str] | None = None,
    merge_topology: str | None = None,
    pr_number: int | None = None,
) -> dict[str, object]:
    unit: dict[str, object] = {
        "unit_id": unit_id,
        "repository_identity": repository,
        "advisory": advisory,
        "candidate_sha": candidate,
        "fix_edges": [
            {"fix_sha": fix_sha, "priority_rank": rank, "signals": ["signal"]}
            for fix_sha, rank in edges
        ],
        "fix_edge_count": len(edges),
        "best_priority_rank": min(rank for _, rank in edges),
        "signals": ["signal"],
        "retained": True,
    }
    if squash_group_ids is not None:
        unit["squash_group_ids"] = squash_group_ids
    if merge_topology is not None:
        unit["merge_topology"] = merge_topology
    if pr_number is not None:
        unit["pr_number"] = pr_number
    return unit


def _write_packet_artifact(
    packet_dir: Path,
    units: list[dict[str, object]],
    *,
    packet_size: int = 25,
) -> list[dict[str, object]]:
    packets = [
        {
            "packet_id": f"packet-{offset // packet_size + 1}",
            "candidate_unit_ids": [
                str(unit["unit_id"]) for unit in units[offset : offset + packet_size]
            ],
            "candidate_count": len(units[offset : offset + packet_size]),
        }
        for offset in range(0, len(units), packet_size)
    ]
    _jsonl(packet_dir / "candidate_units.jsonl", units)
    _jsonl(packet_dir / "packets.jsonl", packets)
    _json(
        packet_dir / "summary.json",
        {
            "schema_version": 1,
            "artifact_kind": "lossless_origin_candidate_packets",
            "candidate_fix_pair_count": sum(
                int(unit["fix_edge_count"]) for unit in units
            ),
            "candidate_unit_count": len(units),
            "packet_count": len(packets),
            "candidate_units_sha256": canonical_sha256(units),
            "packets_sha256": canonical_sha256(packets),
            "all_fix_edges_conserved": True,
            "all_candidate_units_assigned_once": True,
            "blocked_squash_relation_root_count": 0,
            "carrier_only_squash_relation_root_count": 0,
            "atomic_provenance_gap_count": 0,
            "candidate_surface_uncovered_count": 0,
            "candidate_surface_coverage_complete": True,
            "squash_relation_closure_applied": True,
        },
    )
    return packets


def _packet_artifact(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    repo = "github.com/example/repo"
    other_repo = "github.com/example/other"
    advisory = "CVE-2099-0001"
    other_advisory = "CVE-2099-0002"
    fixes = {"one": _sha("1"), "two": _sha("2"), "three": _sha("3")}
    units = [
        _unit(
            unit_id="unit-c",
            repository=repo,
            advisory=advisory,
            candidate=_sha("c"),
            edges=[(fixes["two"], 2)],
        ),
        # Candidate SHAs are repository-scoped, not globally unique.
        _unit(
            unit_id="unit-other-a",
            repository=other_repo,
            advisory=other_advisory,
            candidate=_sha("a"),
            edges=[(fixes["three"], 1)],
        ),
        _unit(
            unit_id="unit-b",
            repository=repo,
            advisory=advisory,
            candidate=_sha("b"),
            edges=[(fixes["one"], 2)],
        ),
        _unit(
            unit_id="unit-a",
            repository=repo,
            advisory=advisory,
            candidate=_sha("a"),
            edges=[(fixes["one"], 1), (fixes["two"], 3)],
        ),
    ]
    packet_dir = tmp_path / "packets"
    _jsonl(packet_dir / "candidate_units.jsonl", units)
    _json(
        packet_dir / "summary.json",
        {
            "schema_version": 1,
            "artifact_kind": "lossless_origin_candidate_packets",
            "candidate_fix_pair_count": 5,
            "candidate_unit_count": 4,
            "candidate_units_sha256": canonical_sha256(units),
            "all_fix_edges_conserved": True,
            "all_candidate_units_assigned_once": True,
            "blocked_squash_relation_root_count": 0,
        },
    )
    return packet_dir, {
        "repo": repo,
        "other_repo": other_repo,
        "advisory": advisory,
        "other_advisory": other_advisory,
        **fixes,
    }


def _ledger(
    path: Path,
    statuses: list[tuple[str, str, str, str, str]],
) -> None:
    _json(
        path,
        {
            "schema_version": 1,
            "artifact_kind": "candidate_unit_edge_label_ledger",
            "edge_ledger": [
                {
                    "repository_identity": repository,
                    "advisory": advisory,
                    "candidate_sha": candidate,
                    "fix_sha": fix_sha,
                    "status": status,
                }
                for repository, advisory, candidate, fix_sha, status in statuses
            ],
            "conservation": {"passed": True, "hard_delete_count": 0},
        },
    )


def test_labels_do_not_change_schedule_and_multifix_units_stay_folded(
    tmp_path: Path,
) -> None:
    packet_dir, keys = _packet_artifact(tmp_path)
    generated_dir = tmp_path / "generated"
    assert (
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(generated_dir),
                "--budget",
                "1",
                "--budget",
                "2",
            ]
        )
        == 0
    )
    generated = json.loads((generated_dir / "summary.json").read_text(encoding="utf-8"))
    frozen_digest = generated["schedule_rows_sha256"]
    frozen_schedule = (generated_dir / "schedule.jsonl").read_bytes()
    schedule_rows = [
        json.loads(line)
        for line in frozen_schedule.decode("utf-8").splitlines()
        if line
    ]
    assert [row["unit_id"] for row in schedule_rows] == [
        "unit-other-a",
        "unit-a",
        "unit-b",
        "unit-c",
    ]
    top_one = generated["aggregate_review_slots"][0]
    assert top_one == {
        "budget_per_fix": 1,
        "fix_scope_count": 3,
        "aggregate_per_fix_slot_capacity": 3,
        "aggregate_fix_prefix_membership_slots": 3,
        "aggregate_unique_unit_review_slots": 3,
        "folded_duplicate_membership_slots": 0,
        "selected_units_carried_edge_count": 4,
    }
    unit_a = next(row for row in schedule_rows if row["unit_id"] == "unit-a")
    assert [edge["frozen_fix_position"] for edge in unit_a["fix_edges"]] == [1, 2]

    first_ledger = tmp_path / "labels-one.json"
    _ledger(
        first_ledger,
        [
            (
                keys["repo"],
                keys["advisory"],
                _sha("a"),
                keys["one"],
                "CONFIRMED_TRUE_POSITIVE",
            ),
            (
                keys["repo"],
                keys["advisory"],
                _sha("a"),
                keys["two"],
                "REJECTED_NONCAUSAL",
            ),
        ],
    )
    second_ledger = tmp_path / "labels-two.json"
    _ledger(
        second_ledger,
        [
            (
                keys["repo"],
                keys["advisory"],
                _sha("a"),
                keys["one"],
                "REJECTED_NONCAUSAL",
            ),
            (
                keys["repo"],
                keys["advisory"],
                _sha("a"),
                keys["two"],
                "CONFIRMED_TRUE_POSITIVE",
            ),
        ],
    )

    first_output = tmp_path / "scorecard-one.json"
    second_output = tmp_path / "scorecard-two.json"
    for ledger, output in (
        (first_ledger, first_output),
        (second_ledger, second_output),
    ):
        assert (
            main(
                [
                    "evaluate",
                    "--generated-dir",
                    str(generated_dir),
                    "--ledger",
                    str(ledger),
                    "--output",
                    str(output),
                ]
            )
            == 0
        )

    first = json.loads(first_output.read_text(encoding="utf-8"))
    second = json.loads(second_output.read_text(encoding="utf-8"))
    assert first["frozen_schedule_rows_sha256"] == frozen_digest
    assert second["frozen_schedule_rows_sha256"] == frozen_digest
    assert (generated_dir / "schedule.jsonl").read_bytes() == frozen_schedule

    first_unit = next(
        row for row in first["unit_evaluations"] if row["unit_id"] == "unit-a"
    )
    second_unit = next(
        row for row in second["unit_evaluations"] if row["unit_id"] == "unit-a"
    )
    assert first_unit["fix_edge_count"] == 2
    assert first_unit["labeled_edge_count"] == 2
    assert [edge["status"] for edge in first_unit["edge_evaluations"]] == [
        "CONFIRMED_TRUE_POSITIVE",
        "REJECTED_NONCAUSAL",
    ]
    assert [edge["status"] for edge in second_unit["edge_evaluations"]] == [
        "REJECTED_NONCAUSAL",
        "CONFIRMED_TRUE_POSITIVE",
    ]
    assert first["aggregate_review_slots"][0]["aggregate_unique_unit_review_slots"] == 3
    assert (
        first["aggregate_review_slots"][0]["aggregate_fix_prefix_membership_slots"] == 3
    )
    assert first["aggregate_review_slots"][0]["confirmed_carried_edge_count"] == 1


def test_evaluate_rejects_labels_outside_frozen_edge_inventory(
    tmp_path: Path,
) -> None:
    packet_dir, keys = _packet_artifact(tmp_path)
    generated_dir = tmp_path / "generated"
    assert (
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(generated_dir),
                "--budget",
                "1",
            ]
        )
        == 0
    )
    ledger = tmp_path / "outside.json"
    _ledger(
        ledger,
        [
            (
                keys["repo"],
                keys["advisory"],
                _sha("f"),
                keys["one"],
                "CONFIRMED_TRUE_POSITIVE",
            )
        ],
    )

    with pytest.raises(SystemExit, match="outside frozen schedule"):
        main(
            [
                "evaluate",
                "--generated-dir",
                str(generated_dir),
                "--ledger",
                str(ledger),
                "--output",
                str(tmp_path / "scorecard.json"),
            ]
        )


def test_carrier_budget_carries_101st_member_and_reports_real_costs(
    tmp_path: Path,
) -> None:
    repository = "github.com/example/repo"
    advisory = "CVE-2099-0101"
    main_fix = _sha("e")
    target_fix = _sha("f")
    candidates = [f"{index:040x}" for index in range(1, 102)]
    units: list[dict[str, object]] = []
    for index, candidate in enumerate(candidates):
        group_ids = (
            [] if index == 0 else [candidates[0] if index != 2 else candidates[1]]
        )
        edges = [(main_fix, index + 1)]
        if index == 0:
            edges.append((target_fix, 2))
        units.append(
            _unit(
                unit_id=f"carrier-member-{index + 1}",
                repository=repository,
                advisory=advisory,
                candidate=candidate,
                edges=edges,
                squash_group_ids=group_ids,
            )
        )
    direct_candidate = f"{1000:040x}"
    units.append(
        _unit(
            unit_id="direct-singleton",
            repository=repository,
            advisory=advisory,
            candidate=direct_candidate,
            edges=[(target_fix, 1)],
        )
    )
    packet_dir = tmp_path / "carrier-packets"
    _write_packet_artifact(packet_dir, units)

    generated_dir = tmp_path / "carrier-schedule"
    assert (
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(generated_dir),
                "--budget-unit",
                "carrier",
                "--budget",
                "1",
                "--budget",
                "2",
            ]
        )
        == 0
    )

    summary = json.loads((generated_dir / "summary.json").read_text())
    rows = [
        json.loads(line)
        for line in (generated_dir / "schedule.jsonl").read_text().splitlines()
    ]
    by_id = {row["unit_id"]: row for row in rows}
    first = by_id["carrier-member-1"]
    second = by_id["carrier-member-2"]
    nested = by_id["carrier-member-3"]
    last = by_id["carrier-member-101"]
    direct = by_id["direct-singleton"]

    incomplete = json.loads(json.dumps(rows))
    incomplete[0].pop("carrier_group_id")
    with pytest.raises(SystemExit, match="budget-unit schema mismatch"):
        _validate_schedule_mode(incomplete, CARRIER_BUDGET_UNIT)

    fake_group = json.loads(json.dumps(rows))
    original_group = first["carrier_group_id"]
    for row in fake_group:
        if row["carrier_group_id"] == original_group:
            row["carrier_group_id"] = f"carrier-group-{'0' * 64}"
    with pytest.raises(SystemExit, match="carrier group id mismatch"):
        _validate_schedule_mode(fake_group, CARRIER_BUDGET_UNIT)

    swapped_atomic = json.loads(json.dumps(rows))
    swapped_by_id = {row["unit_id"]: row for row in swapped_atomic}
    first_main = next(
        edge
        for edge in swapped_by_id["carrier-member-1"]["fix_edges"]
        if edge["fix_sha"] == main_fix
    )
    second_main = swapped_by_id["carrier-member-2"]["fix_edges"][0]
    first_main["frozen_fix_position"], second_main["frozen_fix_position"] = (
        second_main["frozen_fix_position"],
        first_main["frozen_fix_position"],
    )
    with pytest.raises(SystemExit, match="frozen atomic fix position mismatch"):
        _validate_schedule_mode(swapped_atomic, CARRIER_BUDGET_UNIT)

    swapped_carrier = json.loads(json.dumps(rows))
    swapped_by_id = {row["unit_id"]: row for row in swapped_carrier}
    first_target = next(
        edge
        for edge in swapped_by_id["carrier-member-1"]["fix_edges"]
        if edge["fix_sha"] == target_fix
    )
    direct_target = swapped_by_id["direct-singleton"]["fix_edges"][0]
    (
        first_target["frozen_carrier_fix_position"],
        direct_target["frozen_carrier_fix_position"],
    ) = (
        direct_target["frozen_carrier_fix_position"],
        first_target["frozen_carrier_fix_position"],
    )
    with pytest.raises(SystemExit, match="frozen carrier fix position mismatch"):
        _validate_schedule_mode(swapped_carrier, CARRIER_BUDGET_UNIT)

    assert summary["schema_version"] == 2
    assert summary["budget_unit"] == "carrier"
    assert first["carrier_group_id"] == second["carrier_group_id"]
    assert second["carrier_group_id"] == nested["carrier_group_id"]
    assert (
        sum(row["carrier_group_id"] == first["carrier_group_id"] for row in rows) == 101
    )
    assert direct["carrier_group_id"] != first["carrier_group_id"]
    assert second["carrier_connector_provenance"]["squash_group_ids"] == [candidates[0]]
    assert nested["carrier_connector_provenance"]["squash_group_ids"] == [candidates[1]]

    last_main_edge = next(
        edge for edge in last["fix_edges"] if edge["fix_sha"] == main_fix
    )
    first_target_edge = next(
        edge for edge in first["fix_edges"] if edge["fix_sha"] == target_fix
    )
    direct_target_edge = direct["fix_edges"][0]
    assert last_main_edge["frozen_fix_position"] == 101
    assert last_main_edge["frozen_carrier_fix_position"] == 1
    assert first_target_edge["frozen_carrier_fix_position"] == 2
    assert direct_target_edge["frozen_carrier_fix_position"] == 1
    assert summary["aggregate_review_slots"][0] == {
        "budget_per_fix": 1,
        "budget_unit": "carrier",
        "triggered_carrier_fix_membership_count": 2,
        "triggered_unique_carrier_group_count": 2,
        "expanded_atomic_unit_count": 102,
    }


def test_carrier_pr_connector_is_conservative_and_scope_isolated(
    tmp_path: Path,
) -> None:
    repository = "github.com/example/repo"
    other_repository = "github.com/example/other"
    advisory = "CVE-2099-0039"
    other_advisory = "CVE-2099-0040"
    fix_sha = _sha("f")
    units = [
        _unit(
            unit_id="landed-variant-a",
            repository=repository,
            advisory=advisory,
            candidate=_sha("a"),
            edges=[(fix_sha, 1)],
            merge_topology="squash",
            pr_number=39,
        ),
        _unit(
            unit_id="landed-variant-b",
            repository=repository,
            advisory=advisory,
            candidate=_sha("b"),
            edges=[(fix_sha, 2)],
            merge_topology="squash",
            pr_number=39,
        ),
        _unit(
            unit_id="ordinary-direct",
            repository=repository,
            advisory=advisory,
            candidate=_sha("c"),
            edges=[(fix_sha, 3)],
            merge_topology="direct",
            pr_number=39,
        ),
        _unit(
            unit_id="other-advisory",
            repository=repository,
            advisory=other_advisory,
            candidate=_sha("d"),
            edges=[(fix_sha, 1)],
            merge_topology="squash",
            pr_number=39,
        ),
        _unit(
            unit_id="other-repository",
            repository=other_repository,
            advisory=advisory,
            candidate=_sha("e"),
            edges=[(fix_sha, 1)],
            merge_topology="squash",
            pr_number=39,
        ),
    ]
    packet_dir = tmp_path / "pr-packets"
    _write_packet_artifact(packet_dir, units)
    generated_dir = tmp_path / "pr-schedule"
    assert (
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(generated_dir),
                "--budget-unit",
                "carrier",
                "--budget",
                "1",
            ]
        )
        == 0
    )

    rows = [
        json.loads(line)
        for line in (generated_dir / "schedule.jsonl").read_text().splitlines()
    ]
    by_id = {row["unit_id"]: row for row in rows}
    first = by_id["landed-variant-a"]
    second = by_id["landed-variant-b"]
    assert first["carrier_group_id"] == second["carrier_group_id"]
    assert first["carrier_connector_provenance"]["squash_pr_number"] == 39
    assert second["carrier_connector_provenance"]["squash_pr_number"] == 39
    assert (
        "squash_pr_number"
        not in by_id["ordinary-direct"]["carrier_connector_provenance"]
    )
    assert (
        len(
            {
                by_id[unit_id]["carrier_group_id"]
                for unit_id in (
                    "landed-variant-a",
                    "ordinary-direct",
                    "other-advisory",
                    "other-repository",
                )
            }
        )
        == 4
    )
    summary = json.loads((generated_dir / "summary.json").read_text())
    assert "budget-only, not atomic provenance" in summary["carrier_group_policy"]


@pytest.mark.parametrize(
    "summary",
    [
        {"schema_version": True},
        {"schema_version": 1.0},
        {"schema_version": 2.0, "budget_unit": "carrier"},
    ],
)
def test_schedule_schema_version_rejects_bool_and_float(
    summary: dict[str, object],
) -> None:
    with pytest.raises(SystemExit, match="unsupported or ambiguous"):
        _schedule_budget_unit(summary)


def test_generate_requires_closed_consistent_surface(tmp_path: Path) -> None:
    packet_dir = tmp_path / "packets"
    _write_packet_artifact(
        packet_dir,
        [
            _unit(
                unit_id="unit",
                repository="github.com/example/repo",
                advisory="CVE-2099-0041",
                candidate=_sha("a"),
                edges=[(_sha("f"), 1)],
            )
        ],
    )
    packet_summary_path = packet_dir / "summary.json"
    packet_summary = json.loads(packet_summary_path.read_text())
    packet_summary["blocked_squash_relation_root_count"] = 1
    packet_summary["atomic_provenance_gap_count"] = 1
    _json(packet_summary_path, packet_summary)
    with pytest.raises(
        SystemExit,
        match="candidate_surface_uncovered_count must equal",
    ):
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(tmp_path / "forged-atomic-complete-surface"),
            ]
        )

    packet_summary["blocked_squash_relation_root_count"] = 0
    packet_summary["atomic_provenance_gap_count"] = 1
    _json(packet_summary_path, packet_summary)
    with pytest.raises(SystemExit, match="atomic_provenance_gap_count must equal"):
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(tmp_path / "inconsistent-atomic-provenance"),
            ]
        )

    packet_summary["atomic_provenance_gap_count"] = 0
    packet_summary["squash_relation_closure_applied"] = False
    _json(packet_summary_path, packet_summary)
    with pytest.raises(SystemExit, match="requires squash relation closure"):
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(tmp_path / "no-closure"),
                "--budget-unit",
                "carrier",
            ]
        )

    packet_summary["squash_relation_closure_applied"] = True
    packet_summary["atomic_provenance_gap_count"] = 1
    _json(packet_summary_path, packet_summary)
    with pytest.raises(SystemExit, match="must equal"):
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(tmp_path / "inconsistent-surface"),
                "--budget-unit",
                "carrier",
            ]
        )

    packet_summary["blocked_squash_relation_root_count"] = 1
    packet_summary["atomic_provenance_gap_count"] = 1
    _json(packet_summary_path, packet_summary)
    with pytest.raises(
        SystemExit,
        match="candidate_surface_uncovered_count must equal",
    ):
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(tmp_path / "forged-complete-surface"),
                "--budget-unit",
                "carrier",
            ]
        )

    for field in (
        "candidate_surface_uncovered_count",
        "candidate_surface_coverage_complete",
        "carrier_only_squash_relation_root_count",
        "atomic_provenance_gap_count",
    ):
        packet_summary.pop(field)
    _json(packet_summary_path, packet_summary)
    with pytest.raises(
        SystemExit,
        match="candidate_surface_uncovered_count must be a non-negative integer",
    ):
        main(
            [
                "generate",
                "--packets-dir",
                str(packet_dir),
                "--output-dir",
                str(tmp_path / "missing-surface"),
                "--budget-unit",
                "carrier",
            ]
        )
