#!/usr/bin/env python3
"""Aggregate exact Transformers packet coverage without giving failures authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

from cohort_transformers_zeroday_packet_ai_review import (
    EXPECTED_PRIORITY_COUNT,
    EXPECTED_SOURCE_COUNT,
    EXPECTED_STRUCTURAL_COUNT,
    PROMOTED_VERDICTS,
    _candidate_rows,
)


EXPECTED_MEMBER_COUNT = 179


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--reviews-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain one JSON object")
    return value


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _usage(value: object, *, path: Path) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ValueError(f"review usage is malformed: {path}")
    return {
        key: int(value.get(key, 0))
        for key in ("input_tokens", "output_tokens", "total_tokens")
    }


def _sum_usage(rows: list[dict[str, int]]) -> dict[str, int]:
    return {
        key: sum(row[key] for row in rows)
        for key in ("input_tokens", "output_tokens", "total_tokens")
    }


def _packet_key(result: Mapping[str, object], *, path: Path) -> tuple[str, int]:
    packet = result.get("packet")
    if not isinstance(packet, Mapping):
        raise ValueError(f"review packet is malformed: {path}")
    lane = str(packet.get("lane", ""))
    if lane not in {"source_attributed", "structural_path_partner_no_ai_signal"}:
        raise ValueError(f"unexpected review lane {lane!r}: {path}")
    try:
        packet_index = int(packet.get("packet_index", -1))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"review packet index is malformed: {path}") from exc
    if packet_index < 0:
        raise ValueError(f"review packet index is malformed: {path}")
    return lane, packet_index


def _aggregate(
    closure: Mapping[str, object],
    results: list[tuple[Path, Mapping[str, object]]],
    *,
    closure_sha256: str,
) -> dict[str, object]:
    if closure.get("artifact_kind") != "transformers_zeroday_squash_member_closure":
        raise ValueError("unexpected closure artifact")
    conservation = closure.get("conservation")
    if not isinstance(conservation, Mapping):
        raise ValueError("closure conservation block is malformed")
    if (
        conservation.get("hard_filter_count") != 0
        or conservation.get("squash_members_retained") != EXPECTED_MEMBER_COUNT
    ):
        raise ValueError("closure does not preserve the frozen 179-member inventory")

    source, structural = _candidate_rows(closure)
    expected_by_lane = {
        "source_attributed": {str(row["sha"]) for row in source},
        "structural_path_partner_no_ai_signal": {
            str(row["sha"]) for row in structural
        },
    }
    expected = set().union(*expected_by_lane.values())
    if len(expected) != EXPECTED_PRIORITY_COUNT:
        raise ValueError("priority inventory count is not frozen")

    attempts_by_packet: dict[
        tuple[str, int], list[tuple[Path, Mapping[str, object]]]
    ] = defaultdict(list)
    attempted_usage_rows: list[dict[str, int]] = []
    incomplete_attempts: list[dict[str, object]] = []
    for path, result in results:
        if result.get("artifact_kind") != "transformers_zeroday_packet_ai_review":
            raise ValueError(f"unexpected review artifact: {path}")
        if result.get("closure_sha256") != closure_sha256:
            raise ValueError(f"review closure digest mismatch: {path}")
        key = _packet_key(result, path=path)
        attempts_by_packet[key].append((path, result))
        usage = _usage(result.get("usage"), path=path)
        attempted_usage_rows.append(usage)
        if result.get("result_status") != "completed":
            incomplete_attempts.append(
                {
                    "lane": key[0],
                    "packet_index": key[1],
                    "result_path": str(path),
                    "result_status": result.get("result_status"),
                    "model": result.get("model"),
                    "reasoning_effort": result.get("reasoning_effort"),
                    "finish_reason": result.get("finish_reason"),
                    "parse_error": result.get("parse_error"),
                    "usage": usage,
                    "negative_authority": False,
                }
            )

    completed: list[tuple[Path, Mapping[str, object]]] = []
    for key, attempts in sorted(attempts_by_packet.items()):
        accepted = [row for row in attempts if row[1].get("result_status") == "completed"]
        if len(accepted) > 1:
            raise ValueError(f"duplicate completed review packet: {key}")
        if accepted:
            completed.append(accepted[0])

    assessments: list[dict[str, object]] = []
    packet_rows: list[dict[str, object]] = []
    accepted_usage_rows: list[dict[str, int]] = []
    models: set[str] = set()
    efforts: set[str] = set()
    for path, result in completed:
        packet = result["packet"]
        assert isinstance(packet, Mapping)
        lane, packet_index = _packet_key(result, path=path)
        review = result.get("review")
        if not isinstance(review, Mapping):
            raise ValueError(f"completed review body is malformed: {path}")
        raw_assessments = review.get("candidate_assessments")
        if not isinstance(raw_assessments, list) or not all(
            isinstance(row, dict) for row in raw_assessments
        ):
            raise ValueError(f"review assessments are malformed: {path}")
        packet_shas = [str(sha) for sha in packet.get("candidate_shas", [])]
        assessed_shas = [str(row.get("sha", "")) for row in raw_assessments]
        if (
            len(packet_shas) != len(set(packet_shas))
            or len(assessed_shas) != len(set(assessed_shas))
            or set(assessed_shas) != set(packet_shas)
            or not set(packet_shas) <= expected_by_lane[lane]
        ):
            raise ValueError(f"review packet coverage is not exact: {path}")
        declared_count = (
            EXPECTED_SOURCE_COUNT
            if lane == "source_attributed"
            else EXPECTED_STRUCTURAL_COUNT
        )
        if int(packet.get("lane_candidate_count", -1)) != declared_count:
            raise ValueError(f"review lane count is not frozen: {path}")
        for row in raw_assessments:
            assessments.append(
                {**row, "lane": lane, "packet_index": packet_index}
            )
        usage = _usage(result.get("usage"), path=path)
        accepted_usage_rows.append(usage)
        packet_rows.append(
            {
                "lane": lane,
                "packet_index": packet_index,
                "packet_count": packet.get("packet_count"),
                "candidate_shas": packet_shas,
                "result_path": str(path),
                "model": result.get("model"),
                "reasoning_effort": result.get("reasoning_effort"),
                "usage": usage,
            }
        )
        models.add(str(result.get("model")))
        efforts.add(str(result.get("reasoning_effort")))

    assessed = [str(row["sha"]) for row in assessments]
    if len(assessed) != len(set(assessed)) or set(assessed) != expected:
        missing = sorted(expected - set(assessed))
        extras = sorted(set(assessed) - expected)
        raise ValueError(
            f"global review coverage failed: missing={missing}, extras={extras}"
        )

    packet_count_by_lane = Counter(str(row["lane"]) for row in packet_rows)
    for lane, count in packet_count_by_lane.items():
        indexes = sorted(
            int(row["packet_index"]) for row in packet_rows if row["lane"] == lane
        )
        declared = {
            int(row["packet_count"]) for row in packet_rows if row["lane"] == lane
        }
        if declared != {count} or indexes != list(range(count)):
            raise ValueError(f"packet index coverage failed for {lane}")

    verdict_counts = Counter(str(row.get("verdict")) for row in assessments)
    promoted = sorted(
        str(row["sha"])
        for row in assessments
        if row.get("verdict") in PROMOTED_VERDICTS
    )
    return {
        "schema_version": 1,
        "artifact_kind": "transformers_zeroday_packet_ai_review_aggregate",
        "closure_sha256": closure_sha256,
        "models": sorted(models),
        "reasoning_efforts": sorted(efforts),
        "completed_packet_count": len(packet_rows),
        "packet_count_by_lane": dict(sorted(packet_count_by_lane.items())),
        "completed_packets": sorted(
            packet_rows, key=lambda row: (str(row["lane"]), int(row["packet_index"]))
        ),
        "attempt_count": len(results),
        "incomplete_attempt_count": len(incomplete_attempts),
        "incomplete_attempts": sorted(
            incomplete_attempts,
            key=lambda row: (
                str(row["lane"]),
                int(row["packet_index"]),
                str(row["result_path"]),
            ),
        ),
        "candidate_input_count": len(expected),
        "candidate_assessment_count": len(assessments),
        "unique_candidate_assessment_count": len(set(assessed)),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "model_promoted_candidate_shas": promoted,
        "model_promoted_count": len(promoted),
        "claim_grade_positive_shas": [],
        "claim_grade_positive_count": 0,
        "promotion_disposition": "FOLLOWUP_REQUIRED_NOT_TP",
        "candidate_assessments": sorted(assessments, key=lambda row: str(row["sha"])),
        "usage": {
            "accepted_completed_attempts": _sum_usage(accepted_usage_rows),
            "all_attempts_including_incomplete": _sum_usage(attempted_usage_rows),
        },
        "conservation": {
            "expected_priority_candidate_count": len(expected),
            "assessed_candidate_count": len(assessments),
            "unique_assessed_candidate_count": len(set(assessed)),
            "exact_squash_member_inventory_retained": EXPECTED_MEMBER_COUNT,
            "hard_filter_count": 0,
            "incomplete_attempt_negative_authority_count": 0,
            "passed": True,
        },
        "claim_boundary": (
            "Completed model reviews only rank the finite follow-up queue. "
            "Incomplete attempts have no negative authority, model promotions are "
            "not true positives without an exact causal edge, and no candidate is "
            "deleted by a model verdict."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    closure_bytes = args.closure.read_bytes()
    closure = _load_json(args.closure)
    paths = sorted(args.reviews_dir.glob("*/result.json"))
    if not paths:
        raise SystemExit(f"no packet results found under {args.reviews_dir}")
    results = [(path, _load_json(path)) for path in paths]
    try:
        aggregate = _aggregate(
            closure,
            results,
            closure_sha256=hashlib.sha256(closure_bytes).hexdigest(),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    _atomic_json(args.output, aggregate)
    print("Transformers packet reviews aggregated")
    print(f"  completed packets : {aggregate['completed_packet_count']}")
    print(f"  incomplete tries  : {aggregate['incomplete_attempt_count']}")
    print(f"  candidates        : {aggregate['candidate_assessment_count']}")
    print(f"  model leads       : {aggregate['model_promoted_count']}")
    print(f"  claim-grade TP    : {aggregate['claim_grade_positive_count']}")
    print(f"  output            : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
