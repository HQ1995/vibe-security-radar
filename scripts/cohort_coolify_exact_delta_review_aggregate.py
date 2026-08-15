#!/usr/bin/env python3
"""Aggregate complete and partial Coolify exact-delta model reviews losslessly."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort_coolify_exact_delta_ai_review import VERDICTS
from cohort_coolify_postgresql_query_idor_path_extension_witness import _atomic_json


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-dir", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _response_content(response: Mapping[str, object]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("response has no choices")
    choice = choices[0]
    if not isinstance(choice, Mapping):
        raise ValueError("response choice is malformed")
    message = choice.get("message")
    if not isinstance(message, Mapping) or not isinstance(message.get("content"), str):
        raise ValueError("response has no message content")
    return str(message["content"])


def _parse_partial_review(
    text: str, expected_keys: set[str]
) -> tuple[dict[str, object], set[str]]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(f"response is not JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("reviews"), list):
        raise ValueError("response has no reviews array")
    seen: set[str] = set()
    for row in value["reviews"]:
        if not isinstance(row, dict):
            raise ValueError("review row is not an object")
        key = str(row.get("key") or "")
        if key not in expected_keys or key in seen:
            raise ValueError(f"unexpected or duplicate key: {key}")
        seen.add(key)
        if row.get("verdict") not in VERDICTS:
            raise ValueError(f"invalid verdict for {key}")
        try:
            confidence = float(row.get("confidence"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid confidence for {key}") from exc
        if not 0 <= confidence <= 1:
            raise ValueError(f"confidence out of range for {key}")
        for field in ("defect_type", "causal_chain"):
            if not isinstance(row.get(field), str):
                raise ValueError(f"missing {field} for {key}")
        for field in ("decisive_evidence", "missing_evidence", "possible_overlap"):
            if not isinstance(row.get(field), list):
                raise ValueError(f"missing {field} list for {key}")
    if not seen:
        raise ValueError("response contains no usable reviews")
    return value, seen


def _usage(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {key: 0 for key in ("input_tokens", "output_tokens", "total_tokens")}
    return {
        key: int(value.get(key, 0) or 0)
        for key in ("input_tokens", "output_tokens", "total_tokens")
    }


def _sum_usage(rows: Sequence[Mapping[str, int]]) -> dict[str, int]:
    return {
        key: sum(int(row.get(key, 0)) for row in rows)
        for key in ("input_tokens", "output_tokens", "total_tokens")
    }


def _packet_cases(packet: Mapping[str, object]) -> dict[str, dict[str, str]]:
    raw_cases = packet.get("case_results")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("packet has no case_results")
    result: dict[str, dict[str, str]] = {}
    for row in raw_cases:
        if not isinstance(row, Mapping) or row.get("passed") is not True:
            raise ValueError("packet contains a failed case")
        key = str(row.get("key") or "")
        candidate = str(row.get("candidate_sha") or "")
        fix = str(row.get("fix_sha") or "")
        if not key or key in result or len(candidate) != 40 or len(fix) != 40:
            raise ValueError("packet case identity is malformed")
        result[key] = {"candidate_sha": candidate, "fix_sha": fix}
    return result


def build_aggregate(review_dirs: Sequence[Path]) -> dict[str, object]:
    attempts: list[dict[str, object]] = []
    reviews_by_key: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    identities: dict[str, dict[str, str]] = {}
    usage_rows: list[dict[str, int]] = []
    packet_records: dict[str, dict[str, object]] = {}
    for raw_directory in review_dirs:
        directory = raw_directory.resolve()
        spec_path = directory / "spec.json"
        if not spec_path.exists():
            raise ValueError(f"review directory has no spec.json: {directory}")
        spec = _load_json(spec_path)
        if spec.get("artifact_kind") != "coolify_exact_delta_semantic_ai_review":
            raise ValueError(f"unexpected review spec: {directory}")
        packet_path = Path(str(spec.get("packet_path") or ""))
        if not packet_path.is_absolute():
            packet_path = packet_path.resolve()
        if not packet_path.exists() or _sha256(packet_path) != spec.get("packet_sha256"):
            raise ValueError(f"packet checksum drift: {directory}")
        packet = _load_json(packet_path)
        packet_cases = _packet_cases(packet)
        for key, identity in packet_cases.items():
            if key in identities and identities[key] != identity:
                raise ValueError(f"case identity drift for {key}")
            identities[key] = identity
        packet_records[str(packet_path)] = {
            "path": str(packet_path),
            "sha256": _sha256(packet_path),
            "case_count": len(packet_cases),
        }
        response_path = directory / "response.json"
        result_path = directory / "result.json"
        attempt: dict[str, object] = {
            "review_dir": str(directory),
            "model": spec.get("model"),
            "reasoning_effort": spec.get("reasoning_effort"),
            "packet_path": str(packet_path),
            "packet_sha256": spec.get("packet_sha256"),
            "expected_case_count": len(packet_cases),
            "reviewed_case_count": 0,
            "missing_keys": sorted(packet_cases),
            "status": "transport_or_response_missing",
            "negative_authority": False,
            "usage": _usage(None),
        }
        if not response_path.exists():
            attempts.append(attempt)
            continue
        response = _load_json(response_path)
        usage = _usage(response.get("usage"))
        if result_path.exists():
            result_payload = _load_json(result_path)
            usage = _usage(result_payload.get("usage"))
        usage_rows.append(usage)
        attempt["usage"] = usage
        attempt["response_path"] = str(response_path)
        attempt["response_sha256"] = _sha256(response_path)
        try:
            review, seen = _parse_partial_review(
                _response_content(response), set(packet_cases)
            )
        except ValueError as exc:
            attempt["status"] = "parse_error"
            attempt["parse_error"] = str(exc)
            attempts.append(attempt)
            continue
        missing = set(packet_cases) - seen
        attempt["status"] = "completed" if not missing else "partial"
        attempt["reviewed_case_count"] = len(seen)
        attempt["missing_keys"] = sorted(missing)
        for raw_review in review["reviews"]:
            key = str(raw_review["key"])
            reviews_by_key[key].append(
                {
                    **raw_review,
                    **packet_cases[key],
                    "model": spec.get("model"),
                    "reasoning_effort": spec.get("reasoning_effort"),
                    "review_dir": str(directory),
                    "response_sha256": _sha256(response_path),
                    "negative_authority": False,
                }
            )
        attempts.append(attempt)

    duplicate_model_keys = [
        key
        for key, reviews in reviews_by_key.items()
        if len({str(row["model"]) for row in reviews}) != len(reviews)
    ]
    if duplicate_model_keys:
        raise ValueError(f"duplicate model reviews for keys: {duplicate_model_keys}")
    reviewed_keys = set(reviews_by_key)
    expected_keys = set(identities)
    missing_global = sorted(expected_keys - reviewed_keys)
    edge_records: list[dict[str, object]] = []
    for key in sorted(expected_keys):
        reviews = sorted(
            reviews_by_key.get(key, []), key=lambda row: str(row["model"])
        )
        verdicts = {str(row["verdict"]) for row in reviews}
        promoted = any(row["verdict"] == "PROMOTE" for row in reviews)
        edge_records.append(
            {
                "key": key,
                **identities[key],
                "review_count": len(reviews),
                "models": sorted({str(row["model"]) for row in reviews}),
                "verdicts": sorted(verdicts),
                "model_union_promoted": promoted,
                "multi_model_consensus_promoted": (
                    len(reviews) >= 2 and verdicts == {"PROMOTE"}
                ),
                "model_verdict_conflict": len(verdicts) > 1,
                "reviews": reviews,
                "candidate_retained": True,
                "claim_grade_status": "FOLLOWUP_REQUIRED_NOT_TP",
            }
        )
    verdict_counts = Counter(
        str(review["verdict"])
        for reviews in reviews_by_key.values()
        for review in reviews
    )
    union_promoted = [row for row in edge_records if row["model_union_promoted"]]
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_exact_delta_semantic_review_aggregate",
        "repository_identity": "github.com/coollabsio/coolify",
        "attempt_count": len(attempts),
        "attempt_status_counts": dict(
            sorted(Counter(str(row["status"]) for row in attempts).items())
        ),
        "attempts": attempts,
        "packet_artifacts": sorted(packet_records.values(), key=lambda row: row["path"]),
        "selected_edge_count": len(expected_keys),
        "reviewed_edge_count": len(reviewed_keys),
        "unreviewed_edge_count": len(missing_global),
        "unreviewed_keys": missing_global,
        "individual_model_verdict_counts": dict(sorted(verdict_counts.items())),
        "model_union_promoted_edge_count": len(union_promoted),
        "model_union_promoted_unique_candidate_count": len(
            {str(row["candidate_sha"]) for row in union_promoted}
        ),
        "multi_model_reviewed_edge_count": sum(
            int(row["review_count"]) >= 2 for row in edge_records
        ),
        "model_verdict_conflict_edge_count": sum(
            row["model_verdict_conflict"] is True for row in edge_records
        ),
        "claim_grade_positive_edge_count": 0,
        "edge_records": edge_records,
        "usage": _sum_usage(usage_rows),
        "conservation": {
            "selected_edge_count": len(expected_keys),
            "retained_edge_count": len(edge_records),
            "hard_filter_count": 0,
            "incomplete_attempt_negative_authority_count": 0,
            "passed": len(edge_records) == len(expected_keys),
        },
        "claim_boundary": (
            "Complete and partial model responses only propose follow-up edges. "
            "Omitted keys, parse failures, and transport failures have no negative "
            "authority; REJECT also does not remove an edge from the source universe. "
            "A model-union promotion is not a claim-grade true positive until an "
            "exact causal witness is independently frozen."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    try:
        aggregate = build_aggregate(args.review_dir)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if aggregate["unreviewed_edge_count"]:
        raise SystemExit(f"aggregate has unreviewed keys: {aggregate['unreviewed_keys']}")
    _atomic_json(args.output.resolve(), aggregate)
    print("Coolify exact-delta semantic reviews aggregated")
    print(f"  selected edges : {aggregate['selected_edge_count']}")
    print(f"  reviewed edges : {aggregate['reviewed_edge_count']}")
    print(f"  model leads    : {aggregate['model_union_promoted_edge_count']}")
    print(f"  transport/parse: {aggregate['attempt_status_counts']}")
    print(f"  usage          : {aggregate['usage']}")
    print(f"  output         : {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
