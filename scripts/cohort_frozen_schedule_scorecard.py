#!/usr/bin/env python3
"""Score a frozen candidate schedule against two causal ledgers.

The schedule order is never regenerated from the evaluation ledger.  This
prevents adjudication-aware penalties or frontier removal from leaking future
labels into a retrospective recall-at-budget comparison.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path


class FrozenScheduleError(RuntimeError):
    """Raised when a scorecard input violates the frozen-evaluation contract."""


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FrozenScheduleError(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise FrozenScheduleError(f"expected JSON object at {path}:{line_number}")
        rows.append(value)
    if not rows:
        raise FrozenScheduleError(f"empty frozen schedule: {path}")
    return rows


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ledger_state(
    ledger: Mapping[str, object],
) -> tuple[dict[tuple[str, str], str], set[str]]:
    raw_rows = ledger.get("edge_ledger")
    if not isinstance(raw_rows, list):
        raise FrozenScheduleError("ledger edge_ledger is malformed")
    status_by_edge: dict[tuple[str, str], str] = {}
    confirmed_candidates: set[str] = set()
    for row in raw_rows:
        if not isinstance(row, Mapping):
            raise FrozenScheduleError("ledger contains a non-object edge row")
        edge = (
            str(row.get("candidate_sha") or ""),
            str(row.get("fix_sha") or ""),
        )
        status = str(row.get("status") or "")
        if not all(edge) or not status:
            raise FrozenScheduleError("ledger contains an incomplete edge row")
        if edge in status_by_edge:
            raise FrozenScheduleError(f"duplicate ledger edge: {edge}")
        status_by_edge[edge] = status
        if status == "CONFIRMED_TRUE_POSITIVE":
            confirmed_candidates.add(edge[0])
    return status_by_edge, confirmed_candidates


def _validate_ledger_conservation(ledger: Mapping[str, object], *, label: str) -> None:
    conservation = ledger.get("conservation")
    if not isinstance(conservation, Mapping):
        raise FrozenScheduleError(f"{label} ledger conservation is missing")
    if conservation.get("passed") is not True:
        raise FrozenScheduleError(f"{label} ledger conservation did not pass")
    if conservation.get("hard_delete_count") != 0:
        raise FrozenScheduleError(f"{label} ledger contains hard deletions")


def _frozen_rows(
    schedule: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    frozen: list[dict[str, object]] = []
    seen_candidates: set[str] = set()
    previous_rank = 0
    for position, row in enumerate(schedule, start=1):
        candidate_sha = str(row.get("candidate_sha") or "")
        fix_sha = str(row.get("fix_sha") or "")
        rank = row.get("delta_bridge_rank")
        if not candidate_sha or not fix_sha:
            raise FrozenScheduleError(f"schedule row {position} has an incomplete edge")
        if candidate_sha in seen_candidates:
            raise FrozenScheduleError(f"schedule repeats candidate {candidate_sha}")
        if not isinstance(rank, int) or rank <= previous_rank:
            raise FrozenScheduleError(
                "schedule delta_bridge_rank must be strictly increasing"
            )
        seen_candidates.add(candidate_sha)
        previous_rank = rank
        frozen.append(
            {
                "schedule_position": position,
                "candidate_sha": candidate_sha,
                "fix_sha": fix_sha,
                "frozen_delta_bridge_rank": rank,
                "delta_bridge_class": row.get("delta_bridge_class"),
                "source_review_priority_rank": row.get("source_review_priority_rank"),
            }
        )
    return frozen


def _is_adjudicated(status: str) -> bool:
    return status in {
        "CONFIRMED_TRUE_POSITIVE",
        "REJECTED_NONCAUSAL",
        "PATCH_EQUIVALENT_ALIAS",
    }


def build_scorecard(
    *,
    schedule: Sequence[Mapping[str, object]],
    baseline_ledger: Mapping[str, object],
    evaluation_ledger: Mapping[str, object],
    budgets: Sequence[int],
) -> dict[str, object]:
    """Evaluate later labels on the original schedule order."""

    _validate_ledger_conservation(baseline_ledger, label="baseline")
    _validate_ledger_conservation(evaluation_ledger, label="evaluation")
    rows = _frozen_rows(schedule)
    baseline_status, baseline_confirmed = _ledger_state(baseline_ledger)
    evaluation_status, evaluation_confirmed = _ledger_state(evaluation_ledger)
    if not baseline_confirmed <= evaluation_confirmed:
        raise FrozenScheduleError("evaluation ledger regressed a confirmed candidate")

    immutable_statuses = {
        "CONFIRMED_TRUE_POSITIVE",
        "REJECTED_NONCAUSAL",
        "PATCH_EQUIVALENT_ALIAS",
    }
    for edge, status in baseline_status.items():
        if status in immutable_statuses and evaluation_status.get(edge) != status:
            raise FrozenScheduleError(
                f"evaluation ledger regressed adjudicated edge {edge}"
            )

    transitions: list[dict[str, object]] = []
    for row in rows:
        edge = (str(row["candidate_sha"]), str(row["fix_sha"]))
        baseline_edge_status = baseline_status.get(edge, "NOT_EXPLICITLY_LEDGERED")
        evaluation_edge_status = evaluation_status.get(edge, "NOT_EXPLICITLY_LEDGERED")
        row.update(
            {
                "baseline_edge_status": baseline_edge_status,
                "evaluation_edge_status": evaluation_edge_status,
                "baseline_candidate_confirmed": edge[0] in baseline_confirmed,
                "evaluation_candidate_confirmed": edge[0] in evaluation_confirmed,
            }
        )
        if baseline_edge_status != evaluation_edge_status:
            transitions.append(dict(row))

    schedule_candidates = {str(row["candidate_sha"]) for row in rows}
    baseline_present = schedule_candidates & baseline_confirmed
    evaluation_present = schedule_candidates & evaluation_confirmed
    newly_confirmed_present = evaluation_present - baseline_present
    normalized_budgets = list(
        dict.fromkeys(
            min(value, len(rows)) for value in [*budgets, len(rows)] if value > 0
        )
    )
    if not normalized_budgets:
        raise FrozenScheduleError("at least one positive budget is required")

    budget_rows: list[dict[str, object]] = []
    for budget in normalized_budgets:
        prefix = rows[:budget]
        prefix_candidates = {str(row["candidate_sha"]) for row in prefix}
        recovered_baseline = prefix_candidates & baseline_present
        recovered_evaluation = prefix_candidates & evaluation_present
        recovered_new = prefix_candidates & newly_confirmed_present
        newly_confirmed_edges = sum(
            row["baseline_edge_status"] != "CONFIRMED_TRUE_POSITIVE"
            and row["evaluation_edge_status"] == "CONFIRMED_TRUE_POSITIVE"
            for row in prefix
        )
        newly_rejected_edges = sum(
            row["baseline_edge_status"] != "REJECTED_NONCAUSAL"
            and row["evaluation_edge_status"] == "REJECTED_NONCAUSAL"
            for row in prefix
        )
        budget_rows.append(
            {
                "budget": budget,
                "scheduled_unique_candidate_count": len(prefix),
                "baseline_known_confirmed_candidate_count": len(recovered_baseline),
                "evaluation_known_confirmed_candidate_count": len(recovered_evaluation),
                "newly_confirmed_candidate_count": len(recovered_new),
                "newly_confirmed_edge_count": newly_confirmed_edges,
                "newly_rejected_edge_count": newly_rejected_edges,
                "newly_adjudicated_edge_count": (
                    newly_confirmed_edges + newly_rejected_edges
                ),
                "evaluation_known_recall_within_frozen_schedule": (
                    len(recovered_evaluation) / len(evaluation_present)
                    if evaluation_present
                    else None
                ),
                "evaluation_known_recall_against_global_ledger": (
                    len(recovered_evaluation) / len(evaluation_confirmed)
                    if evaluation_confirmed
                    else None
                ),
                "new_confirmed_candidate_capture": (
                    len(recovered_new) / len(newly_confirmed_present)
                    if newly_confirmed_present
                    else None
                ),
            }
        )

    new_confirmed_edge_count = sum(
        row["baseline_edge_status"] != "CONFIRMED_TRUE_POSITIVE"
        and row["evaluation_edge_status"] == "CONFIRMED_TRUE_POSITIVE"
        for row in rows
    )
    new_rejected_edge_count = sum(
        row["baseline_edge_status"] != "REJECTED_NONCAUSAL"
        and row["evaluation_edge_status"] == "REJECTED_NONCAUSAL"
        for row in rows
    )
    new_adjudicated_edge_count = new_confirmed_edge_count + new_rejected_edge_count
    transition_counts = Counter(
        f"{row['baseline_edge_status']}->{row['evaluation_edge_status']}"
        for row in transitions
    )
    return {
        "summary": {
            "frozen_schedule_candidate_count": len(rows),
            "baseline_global_confirmed_candidate_count": len(baseline_confirmed),
            "evaluation_global_confirmed_candidate_count": len(evaluation_confirmed),
            "baseline_confirmed_candidate_in_schedule_count": len(baseline_present),
            "evaluation_confirmed_candidate_in_schedule_count": len(evaluation_present),
            "newly_confirmed_candidate_in_schedule_count": len(newly_confirmed_present),
            "newly_confirmed_edge_count": new_confirmed_edge_count,
            "newly_rejected_edge_count": new_rejected_edge_count,
            "newly_adjudicated_edge_count": new_adjudicated_edge_count,
            "new_edge_true_positive_yield": (
                new_confirmed_edge_count / new_adjudicated_edge_count
                if new_adjudicated_edge_count
                else None
            ),
            "transition_counts": dict(sorted(transition_counts.items())),
        },
        "recall_at_budget": budget_rows,
        "changed_edge_transitions": transitions,
        "conservation": {
            "schedule_order_recomputed": False,
            "schedule_row_count": len(rows),
            "unique_candidate_count": len(schedule_candidates),
            "hard_filter_count": 0,
            "baseline_confirmed_labels_preserved": True,
            "passed": len(rows) == len(schedule_candidates),
        },
    }


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schedule", type=Path, required=True)
    parser.add_argument("--baseline-ledger", type=Path, required=True)
    parser.add_argument("--evaluation-ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--budget", type=int, action="append", default=[])
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    baseline = _read_json(args.baseline_ledger)
    evaluation = _read_json(args.evaluation_ledger)
    scorecard = build_scorecard(
        schedule=_read_jsonl(args.schedule),
        baseline_ledger=baseline,
        evaluation_ledger=evaluation,
        budgets=args.budget or [10, 25, 50, 100, 200],
    )
    artifact = {
        "schema_version": 1,
        "artifact_kind": "causal_ledger_frozen_schedule_scorecard",
        "source_artifacts": {
            "frozen_schedule": {
                "path": str(args.schedule),
                "sha256": _sha256(args.schedule),
            },
            "baseline_ledger": {
                "path": str(args.baseline_ledger),
                "sha256": _sha256(args.baseline_ledger),
            },
            "evaluation_ledger": {
                "path": str(args.evaluation_ledger),
                "sha256": _sha256(args.evaluation_ledger),
            },
        },
        **scorecard,
        "claim_boundary": (
            "This is retrospective known-label recall on an immutable schedule, "
            "not proof of recall over unknown true positives. The evaluation "
            "ledger may add labels but cannot reorder or remove schedule rows. "
            "Edge yield counts causal candidate/fix memberships, not distinct "
            "vulnerabilities."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=False)
    args.output.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("Frozen schedule scorecard written")
    print(
        f"  schedule rows : {scorecard['summary']['frozen_schedule_candidate_count']}"
    )
    print(f"  new confirmed : {scorecard['summary']['newly_confirmed_edge_count']}")
    print(f"  new rejected  : {scorecard['summary']['newly_rejected_edge_count']}")
    print(f"  output        : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
