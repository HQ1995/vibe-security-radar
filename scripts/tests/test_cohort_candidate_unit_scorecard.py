"""Tests for the label-free candidate-unit schedule and edge scorecard."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cohort.root_adjudication import canonical_sha256
from cohort_candidate_unit_scorecard import main


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
) -> dict[str, object]:
    return {
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
