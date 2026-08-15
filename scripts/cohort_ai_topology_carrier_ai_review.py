#!/usr/bin/env python3
"""Review topology-carrier packets with a local semantic model."""

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
from cohort_coolify_exact_delta_ai_review import _metadata_subject, _parse_review


SYSTEM_PROMPT = """\
You are an independent software provenance reviewer. Each case mechanically
proves a three-stage chain: an observed-AI candidate parent-diff is stable-patch-
id equivalent to a landed carrier parent-diff; that carrier is a strict Git
ancestor of a later commit; and the later parent-diff exactly reverses one or
more same-path candidate lines. The original candidate and later commit are
graph-incomparable, so reason through the shown carrier rather than assuming
direct ancestry.

PROMOTE only when the supplied three-way hunks establish a concrete defect in
the candidate/carrier state that the later commit repairs: a functional or
security regression, incomplete repair, invalid behavior/configuration, or a
similarly specific fault. Stable patch identity and reverse lines alone are not
semantic causality. Version bumps, common syntax, merge churn, independent
changes, harmless cleanup, and product-choice rewrites are not promotions.

DEFER when causality is plausible but the packet omits runtime semantics or a
decisive hunk. Because false negatives are costly, REJECT only when the supplied
evidence affirmatively shows incidental overlap or a non-defect transition.
Never use a model verdict to remove a candidate. Return only the requested JSON
object.
"""


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


def _excerpt(value: object) -> object:
    if isinstance(value, Mapping):
        return value.get("excerpt")
    return value


def _compact_path_packet(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("path packet is malformed")
    raw_focal = value.get("focal_exact_delta_sample")
    if not isinstance(raw_focal, list):
        raw_focal = []
    focal_lines = [
        {
            "direction": row.get("direction"),
            "content_excerpt": row.get("content_excerpt"),
        }
        for row in raw_focal
        if isinstance(row, Mapping)
    ]
    candidate_patch = value.get("candidate_patch")
    carrier_patch = value.get("carrier_patch")
    fix_patch = value.get("fix_patch")
    return {
        "candidate_path": value.get("candidate_path"),
        "carrier_path": value.get("carrier_path"),
        "fix_path": value.get("fix_path"),
        "direction": value.get("direction"),
        "candidate_parent_sha": value.get("candidate_parent_sha"),
        "carrier_parent_sha": value.get("carrier_parent_sha"),
        "fix_parent_sha": value.get("fix_parent_sha"),
        "stable_patch_id": value.get("stable_patch_id"),
        "focal_lines": focal_lines,
        "candidate_patch_excerpt": _excerpt(candidate_patch),
        "candidate_patch_truncated": candidate_patch.get("excerpt_truncated")
        if isinstance(candidate_patch, Mapping)
        else None,
        "carrier_patch_omitted_as_stable_patch_id_equivalent": bool(carrier_patch),
        "fix_patch_excerpt": _excerpt(fix_patch),
        "fix_patch_truncated": fix_patch.get("excerpt_truncated")
        if isinstance(fix_patch, Mapping)
        else None,
    }


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
            raise ValueError("packet case has no three-way focal hunks")
        cases.append(
            {
                "key": row.get("key"),
                "candidate_sha": row.get("candidate_sha"),
                "candidate_subject": _metadata_subject(row.get("candidate_metadata")),
                "candidate_diff_stat": _excerpt(row.get("candidate_diff_stat")),
                "carrier_sha": row.get("carrier_sha"),
                "carrier_subject": _metadata_subject(row.get("carrier_metadata")),
                "carrier_diff_stat": _excerpt(row.get("carrier_diff_stat")),
                "fix_sha": row.get("fix_sha"),
                "fix_subject": _metadata_subject(row.get("fix_metadata")),
                "fix_diff_stat": _excerpt(row.get("fix_diff_stat")),
                "carrier_chains": row.get("carrier_chains"),
                "bridge_class": row.get("bridge_class"),
                "source_delta_class": row.get("source_delta_class"),
                "omitted_focal_context_count": row.get(
                    "omitted_focal_context_count"
                ),
                "path_packets": [
                    _compact_path_packet(value) for value in path_packets
                ],
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
                    "INCOMPLETE_REPAIR, SECURITY_REGRESSION, "
                    "INVALID_CONFIGURATION, INCIDENTAL_OVERLAP, or UNKNOWN"
                ),
                "causal_chain": (
                    "one concise sentence connecting landed candidate state to fix"
                ),
                "decisive_evidence": ["zero or more exact packet facts"],
                "missing_evidence": ["zero or more concrete missing facts"],
                "possible_overlap": ["zero or more supplied case keys"],
            }
        ],
        "batch_notes": ["zero or more cross-case observations"],
    }
    return (
        "Review every case exactly once. Treat subjects as hints, not proof. Read "
        "candidate, equivalent carrier, and later fix hunks as one compositional "
        "chain. A candidate that was itself labeled fix can still be a true positive "
        "when the later change corrects an incomplete or newly broken behavior. Do "
        "not infer omitted code. Mark equivalent mechanisms in possible_overlap.\n\n"
        f"CASES:\n{json.dumps(cases, indent=2, sort_keys=True)}\n\n"
        f"RETURN_SCHEMA:\n{json.dumps(schema, indent=2, sort_keys=True)}"
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.max_output_tokens < 1 or args.timeout <= 0:
        raise SystemExit("output-token and timeout bounds must be positive")
    if not _loopback(args.api_base):
        raise SystemExit("topology-carrier review requires loopback CLIProxyAPI")
    packet_path = args.packet.resolve()
    packet = _load_json(packet_path)
    if packet.get("artifact_kind") != (
        "coolify_topology_carrier_semantic_review_packet"
    ):
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
        "artifact_kind": "coolify_topology_carrier_semantic_ai_review",
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
        text = _response_text(response)
        result["review"] = _parse_review(text, expected_keys)
        result["result_status"] = "completed"
    except ValueError as exc:
        result["parse_error"] = str(exc)
    _atomic_json(args.output_dir / "result.json", result)
    usage = result["usage"]
    assert isinstance(usage, Mapping)
    print("Coolify topology-carrier semantic AI review frozen")
    print(f"  status       : {result['result_status']}")
    print(f"  cases        : {len(expected_keys)}")
    print(f"  prompt chars : {spec['prompt_chars']}")
    print(f"  total tokens : {usage.get('total_tokens', 0)}")
    print(f"  output       : {args.output_dir.resolve()}")
    return 0 if result["result_status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
