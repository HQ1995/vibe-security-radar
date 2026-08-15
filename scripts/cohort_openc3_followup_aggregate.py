#!/usr/bin/env python3
"""Freeze OpenC3 follow-up coverage without treating truncated reviews as negatives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

from cohort_openc3_promoted_followup import EXPECTED_LEADS
from cohort_openc3_weak_password_chronology import EXPECTED_OBSERVED_AI_UNITS


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--followup", type=Path, action="append", required=True)
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _aggregate(
    certificate: Mapping[str, object],
    recall_aggregate: Mapping[str, object],
    followups: list[tuple[Path, Mapping[str, object]]],
    *,
    certificate_sha256: str,
    aggregate_sha256: str,
) -> dict[str, object]:
    conservation = certificate.get("conservation")
    if not isinstance(conservation, Mapping):
        raise ValueError("certificate conservation is malformed")
    retained = int(conservation.get("retained_candidate_count", -1))
    if (
        retained != EXPECTED_OBSERVED_AI_UNITS
        or conservation.get("hard_filter_count") != 0
        or conservation.get("passed") is not True
    ):
        raise ValueError("certificate candidate conservation did not pass")
    if recall_aggregate.get("artifact_kind") != "openc3_weak_password_ai_review_aggregate":
        raise ValueError("unexpected recall aggregate")
    if recall_aggregate.get("certificate_sha256") != certificate_sha256:
        raise ValueError("recall aggregate certificate digest mismatch")
    promoted = recall_aggregate.get("model_promoted_candidate_shas")
    if not isinstance(promoted, list) or {str(sha) for sha in promoted} != EXPECTED_LEADS:
        raise ValueError("recall lead queue drifted")

    completed: list[dict[str, object]] = []
    incomplete: list[dict[str, object]] = []
    claim_grade: set[str] = set()
    completed_assessments: dict[str, list[dict[str, object]]] = {
        sha: [] for sha in sorted(EXPECTED_LEADS)
    }
    total_usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    seen_runs: set[tuple[str, str, str]] = set()
    for path, result in followups:
        if result.get("artifact_kind") != "openc3_weak_password_promoted_followup":
            raise ValueError(f"unexpected follow-up artifact: {path}")
        if result.get("certificate_sha256") != certificate_sha256:
            raise ValueError(f"follow-up certificate digest mismatch: {path}")
        if result.get("aggregate_sha256") != aggregate_sha256:
            raise ValueError(f"follow-up aggregate digest mismatch: {path}")
        candidate_shas = result.get("candidate_shas")
        if (
            not isinstance(candidate_shas, list)
            or {str(sha) for sha in candidate_shas} != EXPECTED_LEADS
            or len(candidate_shas) != len(EXPECTED_LEADS)
        ):
            raise ValueError(f"follow-up candidate coverage declaration drifted: {path}")
        model = str(result.get("observed_model") or result.get("model") or "")
        effort = str(result.get("reasoning_effort") or "")
        prompt_digest = str(result.get("prompt_sha256") or "")
        run_key = (model, effort, prompt_digest)
        if run_key in seen_runs:
            raise ValueError(f"duplicate follow-up run: {run_key}")
        seen_runs.add(run_key)
        usage = result.get("usage")
        if not isinstance(usage, Mapping):
            raise ValueError(f"follow-up usage is malformed: {path}")
        for key in total_usage:
            total_usage[key] += int(usage.get(key, 0))
        common = {
            "path": str(path),
            "model": model,
            "reasoning_effort": effort,
            "finish_reason": str(result.get("finish_reason") or ""),
            "result_status": str(result.get("result_status") or ""),
            "usage": dict(usage),
        }
        if result.get("result_status") != "completed":
            incomplete.append(
                {
                    **common,
                    "parse_error": str(result.get("parse_error") or ""),
                    "disposition": "INCOMPLETE_NOT_INTERPRETED_AS_NEGATIVE",
                }
            )
            continue
        review = result.get("review")
        if not isinstance(review, Mapping):
            raise ValueError(f"completed follow-up review is malformed: {path}")
        assessments = review.get("candidate_assessments")
        if not isinstance(assessments, list) or not all(
            isinstance(row, Mapping) for row in assessments
        ):
            raise ValueError(f"completed follow-up assessments are malformed: {path}")
        assessed = [str(row.get("sha")) for row in assessments]
        if len(assessed) != len(set(assessed)) or set(assessed) != EXPECTED_LEADS:
            raise ValueError(f"completed follow-up coverage is not exact: {path}")
        declared = result.get("claim_grade_shas")
        if not isinstance(declared, list) or not {str(sha) for sha in declared} <= EXPECTED_LEADS:
            raise ValueError(f"completed follow-up claim-grade declaration is invalid: {path}")
        claim_grade.update(str(sha) for sha in declared)
        for row in assessments:
            completed_assessments[str(row["sha"])].append(
                {"model": model, **dict(row)}
            )
        completed.append({**common, "claim_grade_shas": sorted(str(sha) for sha in declared)})

    if not completed:
        raise ValueError("no complete strict follow-up covers the full lead queue")
    return {
        "schema_version": 1,
        "artifact_kind": "openc3_weak_password_final_adjudication",
        "certificate_sha256": certificate_sha256,
        "recall_aggregate_sha256": aggregate_sha256,
        "candidate_inventory_count": retained,
        "candidate_retained_count": retained,
        "hard_filter_count": 0,
        "model_lead_count": len(EXPECTED_LEADS),
        "model_lead_shas": sorted(EXPECTED_LEADS),
        "strict_complete_run_count": len(completed),
        "strict_incomplete_run_count": len(incomplete),
        "strict_complete_runs": completed,
        "strict_incomplete_runs": incomplete,
        "candidate_assessments": completed_assessments,
        "claim_grade_positive_shas": sorted(claim_grade),
        "claim_grade_positive_count": len(claim_grade),
        "usage": total_usage,
        "conservation": {
            "input_candidate_count": retained,
            "retained_candidate_count": retained,
            "lead_queue_count": len(EXPECTED_LEADS),
            "strictly_assessed_lead_count": len(completed_assessments),
            "hard_filter_count": 0,
            "passed": True,
        },
        "claim_boundary": (
            "All 55 candidates remain retained. A completed strict review must cover "
            "all five recall-first leads; truncated or unparsable runs contribute no "
            "negative evidence. Claim-grade positives are the union declared by "
            "complete strict runs, not by the upstream recall model."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    certificate = _load_json(args.certificate)
    recall_aggregate = _load_json(args.aggregate)
    followups = [(path, _load_json(path)) for path in args.followup]
    try:
        result = _aggregate(
            certificate,
            recall_aggregate,
            followups,
            certificate_sha256=_sha256(args.certificate),
            aggregate_sha256=_sha256(args.aggregate),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    _atomic_json(args.output, result)
    print("OpenC3 strict follow-ups aggregated")
    print(f"  retained      : {result['candidate_retained_count']}")
    print(f"  strict runs   : {result['strict_complete_run_count']} complete")
    print(f"  incomplete    : {result['strict_incomplete_run_count']}")
    print(f"  claim-grade TP: {result['claim_grade_positive_count']}")
    print(f"  output        : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
