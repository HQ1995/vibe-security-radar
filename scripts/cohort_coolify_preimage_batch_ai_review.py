#!/usr/bin/env python3
"""Ask a local model to challenge the exact preimage-recovery batch witness."""

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
You are an independent software provenance and security reviewer. The supplied
Git checks are mechanically true, but you must challenge whether each claimed
repair is actually causal rather than an incidental refactor. False negatives
are costly, so use DEFER when more evidence could plausibly establish causality.
Use REJECT only when the supplied state transition affirmatively shows no causal
defect contribution. PROMOTE means the exact AI-added state and later repair are
already sufficient for human confirmation. Never treat your verdict as ground
truth and return only the requested JSON object.
"""
VERDICTS = {"PROMOTE", "DEFER", "REJECT"}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witness", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--reasoning-effort", choices=("low", "medium", "high"), required=True
    )
    parser.add_argument("--max-output-tokens", type=int, default=8000)
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--api-key-env", default="CLIPROXY_API_KEY")
    parser.add_argument("--api-key-config", type=Path, default=DEFAULT_API_CONFIG)
    parser.add_argument("--timeout", type=float, default=300.0)
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


def _build_prompt(witness: Mapping[str, object]) -> str:
    raw_cases = witness.get("case_results")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("witness has no case_results")
    cases: list[dict[str, object]] = []
    for row in raw_cases:
        if not isinstance(row, Mapping) or row.get("passed") is not True:
            raise ValueError("witness has a failed or malformed case")
        candidate_metadata = row.get("candidate_metadata")
        fix_metadata = row.get("fix_metadata")
        cases.append(
            {
                "key": row.get("key"),
                "candidate_sha": row.get("candidate_sha"),
                "candidate_subject": (
                    candidate_metadata.get("subject")
                    if isinstance(candidate_metadata, Mapping)
                    else None
                ),
                "fix_sha": row.get("fix_sha"),
                "fix_subject": (
                    fix_metadata.get("subject")
                    if isinstance(fix_metadata, Mapping)
                    else None
                ),
                "path": row.get("path"),
                "claim": row.get("claim"),
                "proposed_adjudication": row.get("adjudication"),
                "proposed_mechanism_group": row.get("mechanism_group"),
                "focal_fragments": row.get("focal_fragments"),
                "mechanical_checks": row.get("checks"),
            }
        )
    schema = {
        "reviews": [
            {
                "key": "exact supplied key",
                "verdict": "PROMOTE|DEFER|REJECT",
                "confidence": "number from 0 through 1",
                "causal_delta": "one concise evidence-grounded sentence",
                "missing_evidence": ["zero or more concrete missing facts"],
                "possible_overlap": ["keys that may be the same mechanism"],
            }
        ],
        "batch_notes": ["zero or more concise cross-case observations"],
    }
    return (
        "Review every case exactly once. Distinguish a new vulnerable sink, an "
        "incomplete hardening, a functional regression, and an incidental touched "
        "line. Exact source ownership alone is not enough. For an add-check repair, "
        "the vulnerable line may remain while the new guard establishes causality. "
        "Do not invent repository facts beyond this packet.\n\n"
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
    reviews = value["reviews"]
    seen: set[str] = set()
    for row in reviews:
        if not isinstance(row, dict):
            raise ValueError("review row is not an object")
        key = str(row.get("key") or "")
        if key in seen or key not in expected_keys:
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
        if not isinstance(row.get("causal_delta"), str):
            raise ValueError(f"missing causal_delta for {key}")
        if not isinstance(row.get("missing_evidence"), list):
            raise ValueError(f"missing_evidence is not a list for {key}")
        if not isinstance(row.get("possible_overlap"), list):
            raise ValueError(f"possible_overlap is not a list for {key}")
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
        raise SystemExit("preimage batch review requires loopback CLIProxyAPI")
    witness_path = args.witness.resolve()
    witness = _load_json(witness_path)
    if witness.get("artifact_kind") != (
        "coolify_preimage_recovery_exact_causal_batch_witness"
    ):
        raise SystemExit("unexpected witness artifact kind")
    if witness.get("witness_passed") is not True:
        raise SystemExit("mechanical witness did not pass")
    raw_cases = witness.get("case_results")
    assert isinstance(raw_cases, list)
    expected_keys = {
        str(row.get("key")) for row in raw_cases if isinstance(row, Mapping)
    }
    prompt = _build_prompt(witness)
    api_key = _api_key(args.api_key_env, args.api_key_config)
    _require_model(args.api_base, api_key, args.model, args.timeout)
    spec = {
        "schema_version": 1,
        "artifact_kind": "coolify_preimage_recovery_batch_ai_review",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "max_output_tokens": args.max_output_tokens,
        "witness_path": str(witness_path),
        "witness_sha256": hashlib.sha256(witness_path.read_bytes()).hexdigest(),
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
        result["review"] = _parse_review(
            _response_text(response), expected_keys
        )
    except ValueError as exc:
        result["parse_error"] = str(exc)
    else:
        result["result_status"] = "completed"
    _atomic_json(args.output_dir / "result.json", result)
    print("Coolify preimage batch AI review complete")
    print(f"  model        : {args.model}")
    print(f"  effort       : {args.reasoning_effort}")
    print(f"  prompt chars : {spec['prompt_chars']}")
    print(f"  status       : {result['result_status']}")
    print(f"  usage        : {result['usage']}")
    print(f"  output       : {args.output_dir}")
    return 0 if result["result_status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
