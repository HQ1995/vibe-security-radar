#!/usr/bin/env python3
"""Aggregate exact OpenC3 packet coverage without upgrading model leads to TPs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from cohort_openc3_weak_password_chronology import EXPECTED_OBSERVED_AI_UNITS


PROMOTED_VERDICTS = {
    "promote_compositional_contributor",
    "promote_regression_or_path_extension",
    "retain_possible",
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
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


def _aggregate(
    certificate: Mapping[str, object],
    results: list[tuple[Path, Mapping[str, object]]],
    *,
    certificate_sha256: str,
) -> dict[str, object]:
    candidates = certificate.get("observed_ai_candidates")
    if not isinstance(candidates, list):
        raise ValueError("certificate candidate inventory is malformed")
    expected = {
        str(row["sha"])
        for row in candidates
        if isinstance(row, Mapping) and isinstance(row.get("sha"), str)
    }
    if len(expected) != EXPECTED_OBSERVED_AI_UNITS:
        raise ValueError("certificate candidate count is not frozen")

    assessments: list[dict[str, object]] = []
    packet_rows: list[dict[str, object]] = []
    seen_packets: set[tuple[str, int]] = set()
    input_tokens = output_tokens = total_tokens = 0
    models: set[str] = set()
    efforts: set[str] = set()
    for path, result in results:
        if result.get("artifact_kind") != "openc3_weak_password_packet_ai_review":
            raise ValueError(f"unexpected review artifact: {path}")
        if result.get("result_status") != "completed":
            raise ValueError(f"review is incomplete: {path}")
        if result.get("certificate_sha256") != certificate_sha256:
            raise ValueError(f"review certificate digest mismatch: {path}")
        packet = result.get("packet")
        review = result.get("review")
        usage = result.get("usage")
        if not isinstance(packet, Mapping) or not isinstance(review, Mapping):
            raise ValueError(f"review packet is malformed: {path}")
        if not isinstance(usage, Mapping):
            raise ValueError(f"review usage is malformed: {path}")
        bucket = str(packet.get("bucket"))
        packet_index = int(packet.get("packet_index", -1))
        packet_key = (bucket, packet_index)
        if packet_key in seen_packets:
            raise ValueError(f"duplicate review packet: {packet_key}")
        seen_packets.add(packet_key)
        raw_assessments = review.get("candidate_assessments")
        if not isinstance(raw_assessments, list) or not all(
            isinstance(row, dict) for row in raw_assessments
        ):
            raise ValueError(f"review assessments are malformed: {path}")
        packet_shas = [str(sha) for sha in packet.get("candidate_shas", [])]
        assessed_shas = [str(row["sha"]) for row in raw_assessments]
        if len(assessed_shas) != len(set(assessed_shas)) or set(assessed_shas) != set(
            packet_shas
        ):
            raise ValueError(f"review packet coverage is not exact: {path}")
        for row in raw_assessments:
            assessments.append({**row, "bucket": bucket, "packet_index": packet_index})
        packet_rows.append(
            {
                "bucket": bucket,
                "packet_index": packet_index,
                "packet_count": packet.get("packet_count"),
                "candidate_shas": packet_shas,
                "result_path": str(path),
                "usage": dict(usage),
            }
        )
        input_tokens += int(usage.get("input_tokens", 0))
        output_tokens += int(usage.get("output_tokens", 0))
        total_tokens += int(usage.get("total_tokens", 0))
        models.add(str(result.get("model")))
        efforts.add(str(result.get("reasoning_effort")))

    assessed = [str(row["sha"]) for row in assessments]
    if len(assessed) != len(set(assessed)) or set(assessed) != expected:
        missing = sorted(expected - set(assessed))
        extras = sorted(set(assessed) - expected)
        raise ValueError(
            f"global review coverage failed: missing={missing}, extras={extras}"
        )

    packet_count_by_bucket = Counter(row["bucket"] for row in packet_rows)
    for bucket, count in packet_count_by_bucket.items():
        indexes = sorted(
            int(row["packet_index"]) for row in packet_rows if row["bucket"] == bucket
        )
        declared = {
            int(row["packet_count"]) for row in packet_rows if row["bucket"] == bucket
        }
        if declared != {count} or indexes != list(range(count)):
            raise ValueError(f"packet index coverage failed for {bucket}")

    verdict_counts = Counter(str(row["verdict"]) for row in assessments)
    promoted = sorted(
        str(row["sha"])
        for row in assessments
        if row.get("verdict") in PROMOTED_VERDICTS
    )
    return {
        "schema_version": 1,
        "artifact_kind": "openc3_weak_password_ai_review_aggregate",
        "certificate_sha256": certificate_sha256,
        "models": sorted(models),
        "reasoning_efforts": sorted(efforts),
        "packet_count": len(packet_rows),
        "packet_count_by_bucket": dict(sorted(packet_count_by_bucket.items())),
        "packets": sorted(
            packet_rows, key=lambda row: (str(row["bucket"]), int(row["packet_index"]))
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
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
        },
        "conservation": {
            "expected_candidate_count": len(expected),
            "assessed_candidate_count": len(assessments),
            "unique_assessed_candidate_count": len(set(assessed)),
            "hard_filter_count": 0,
            "passed": True,
        },
        "claim_boundary": (
            "Model promotions create a finite follow-up queue only. They are not "
            "true positives until an exact causal edge and counterfactual are "
            "independently established. Negative model verdicts do not delete any "
            "candidate."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    certificate_bytes = args.certificate.read_bytes()
    certificate = _load_json(args.certificate)
    paths = sorted(args.reviews_dir.glob("*/result.json"))
    if not paths:
        raise SystemExit(f"no packet results found under {args.reviews_dir}")
    results = [(path, _load_json(path)) for path in paths]
    try:
        aggregate = _aggregate(
            certificate,
            results,
            certificate_sha256=hashlib.sha256(certificate_bytes).hexdigest(),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    _atomic_json(args.output, aggregate)
    print("OpenC3 packet reviews aggregated")
    print(f"  packets       : {aggregate['packet_count']}")
    print(f"  candidates    : {aggregate['candidate_assessment_count']}")
    print(f"  model leads   : {aggregate['model_promoted_count']}")
    print(f"  claim-grade TP: {aggregate['claim_grade_positive_count']}")
    print(f"  usage         : {aggregate['usage']}")
    print(f"  output        : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
