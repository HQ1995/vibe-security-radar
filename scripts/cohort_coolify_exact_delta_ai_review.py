#!/usr/bin/env python3
"""Challenge Coolify exact-delta packets with a local semantic reviewer."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from cohort_churchcrm_compositional_ai_review import (
    DEFAULT_API_BASE,
    DEFAULT_API_CONFIG,
    _api_key,
    _atomic_json,
    _loopback,
    _request_json,
    _require_model,
    _response_text,
    _usage,
)


SYSTEM_PROMPT = """\
You are an independent software provenance reviewer. Determine whether each
observed-AI candidate commit actually contributed a defect that the later fix
repairs. The packet mechanically proves ancestry and exact reverse patch lines,
but exact overlap can still be incidental in broad refactors, generated files,
tests, UI restyling, or product-decision reverts.

PROMOTE only when the shown candidate and fix hunks establish a concrete causal
state transition: a functional regression, vulnerable behavior, incomplete
repair, invalid configuration, leaked diagnostics, or another specific defect.
DEFER when causality is plausible but runtime semantics, chronology, or omitted
hunks are needed. Because false negatives are costly, use REJECT only when the
shown evidence affirmatively indicates incidental overlap or a non-defect
change. A pure feature rollback without evidence of a defect is DEFER, not an
automatic promotion. Never use your verdict to delete a candidate and return
only the requested JSON object.
"""
VERDICTS = frozenset({"PROMOTE", "DEFER", "REJECT"})


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--reasoning-effort", choices=("low", "medium", "high"), required=True
    )
    parser.add_argument("--max-output-tokens", type=int, default=12_000)
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--api-key-env", default="CLIPROXY_API_KEY")
    parser.add_argument("--api-key-config", type=Path, default=DEFAULT_API_CONFIG)
    parser.add_argument("--timeout", type=float, default=420.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


def _metadata_subject(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    subject = value.get("subject")
    if isinstance(subject, str) and subject:
        return subject
    message = value.get("message")
    if isinstance(message, str) and message:
        return message.splitlines()[0]
    return None


def _build_prompt(packet: Mapping[str, object]) -> str:
    raw_cases = packet.get("case_results")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("packet has no cases")
    cases: list[dict[str, object]] = []
    for row in raw_cases:
        if not isinstance(row, Mapping) or row.get("passed") is not True:
            raise ValueError("packet has a failed or malformed case")
        path_packets = row.get("path_packets")
        if not isinstance(path_packets, list) or not path_packets:
            raise ValueError("packet case has no focal patch hunks")
        cases.append(
            {
                "key": row.get("key"),
                "candidate_sha": row.get("candidate_sha"),
                "candidate_subject": _metadata_subject(
                    row.get("candidate_metadata")
                ),
                "candidate_diff_stat": row.get("candidate_diff_stat"),
                "fix_sha": row.get("fix_sha"),
                "fix_subject": _metadata_subject(row.get("fix_metadata")),
                "fix_diff_stat": row.get("fix_diff_stat"),
                "bridge_class": row.get("bridge_class"),
                "exact_reversal_counts": row.get("exact_reversal_counts"),
                "focal_exact_delta_sample": row.get("focal_exact_delta_sample"),
                "omitted_focal_path_count": row.get("omitted_focal_path_count"),
                "path_packets": path_packets,
                "mechanical_checks": row.get("checks"),
            }
        )
    schema = {
        "reviews": [
            {
                "key": "exact supplied key",
                "verdict": "PROMOTE|DEFER|REJECT",
                "confidence": "number from 0 through 1",
                "defect_type": (
                    "concise category such as FUNCTIONAL_REGRESSION, "
                    "INCOMPLETE_REPAIR, SECURITY_REGRESSION, DEBUG_LEAKAGE, "
                    "INVALID_CONFIGURATION, INCIDENTAL_OVERLAP, or UNKNOWN"
                ),
                "causal_chain": (
                    "one concise sentence connecting candidate state to fix state"
                ),
                "decisive_evidence": ["zero or more exact packet facts"],
                "missing_evidence": ["zero or more concrete missing facts"],
                "possible_overlap": ["zero or more supplied case keys"],
            }
        ],
        "batch_notes": ["zero or more cross-case observations"],
    }
    return (
        "Review every case exactly once. Treat candidate and fix subjects as hints, "
        "not proof. Read both sides of every focal hunk: a line deleted later may "
        "have been moved or superseded rather than repaired. A candidate that was "
        "itself a fix can still be a true positive if the later commit corrects an "
        "incomplete or newly broken behavior. Distinguish multiple commits in the "
        "same defect chain using possible_overlap. Do not infer unseen code.\n\n"
        f"CASES:\n{json.dumps(cases, indent=2, sort_keys=True)}\n\n"
        f"RETURN_SCHEMA:\n{json.dumps(schema, indent=2, sort_keys=True)}"
    )


def _parse_review(text: str, expected_keys: set[str]) -> dict[str, object]:
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
        raise ValueError(f"model response is not JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("reviews"), list):
        raise ValueError("model response has no reviews array")
    seen: set[str] = set()
    for row in value["reviews"]:
        if not isinstance(row, dict):
            raise ValueError("review row is not an object")
        key = str(row.get("key") or "")
        if key not in expected_keys or key in seen:
            raise ValueError(f"unexpected or duplicate review key: {key}")
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
    if seen != expected_keys:
        raise ValueError(f"model omitted case keys: {sorted(expected_keys - seen)}")
    if not isinstance(value.get("batch_notes", []), list):
        raise ValueError("batch_notes is not a list")
    return value


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.max_output_tokens < 1 or args.timeout <= 0:
        raise SystemExit("output-token and timeout bounds must be positive")
    if not _loopback(args.api_base):
        raise SystemExit("exact-delta review requires loopback CLIProxyAPI")
    packet_path = args.packet.resolve()
    packet = _load_json(packet_path)
    if packet.get("artifact_kind") != "coolify_exact_delta_semantic_review_packet":
        raise SystemExit("unexpected packet artifact kind")
    if packet.get("packet_passed") is not True:
        raise SystemExit("mechanical packet did not pass")
    raw_cases = packet.get("case_results")
    assert isinstance(raw_cases, list)
    expected_keys = {
        str(row.get("key")) for row in raw_cases if isinstance(row, Mapping)
    }
    prompt = _build_prompt(packet)
    api_key = _api_key(args.api_key_env, args.api_key_config)
    _require_model(args.api_base, api_key, args.model, args.timeout)
    spec = {
        "schema_version": 1,
        "artifact_kind": "coolify_exact_delta_semantic_ai_review",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "max_output_tokens": args.max_output_tokens,
        "packet_path": str(packet_path),
        "packet_sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "prompt_chars": len(SYSTEM_PROMPT) + len(prompt),
        "estimated_input_tokens_chars_div_4": (
            len(SYSTEM_PROMPT) + len(prompt) + 3
        )
        // 4,
        "negative_disposition": "RETAIN_FOR_HUMAN_REVIEW_NOT_DELETE",
    }
    args.output_dir.mkdir(parents=True)
    _atomic_json(args.output_dir / "spec.json", spec)
    _atomic_json(
        args.output_dir / "prompt.json",
        {"system_prompt": SYSTEM_PROMPT, "user_prompt": prompt},
    )
    response = _request_json(
        f"{args.api_base.rstrip('/')}/chat/completions",
        api_key,
        method="POST",
        body={
            "model": args.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "reasoning_effort": args.reasoning_effort,
            "max_tokens": args.max_output_tokens,
        },
        timeout=args.timeout,
    )
    _atomic_json(args.output_dir / "response.json", response)
    result: dict[str, object] = {
        **spec,
        "observed_model": str(response.get("model") or ""),
        "finish_reason": "",
        "usage": _usage(response),
        "result_status": "parse_error",
        "review": {},
        "parse_error": "",
    }
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], Mapping):
        result["finish_reason"] = str(choices[0].get("finish_reason") or "")
    try:
        result["review"] = _parse_review(_response_text(response), expected_keys)
    except ValueError as exc:
        result["parse_error"] = str(exc)
    else:
        result["result_status"] = "completed"
    _atomic_json(args.output_dir / "result.json", result)
    print("Coolify exact-delta semantic AI review complete")
    print(f"  model        : {args.model}")
    print(f"  effort       : {args.reasoning_effort}")
    print(f"  prompt chars : {spec['prompt_chars']}")
    print(f"  status       : {result['result_status']}")
    print(f"  usage        : {result['usage']}")
    print(f"  output       : {args.output_dir}")
    return 0 if result["result_status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
