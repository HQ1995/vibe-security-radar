#!/usr/bin/env python3
"""Review one deterministic packet from the OpenC3 carrier-aware inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
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
from cohort_openc3_weak_password_chronology import (
    ADVISORY_ID,
    AFFECTED_SHA,
    AUTH_MODEL_PATH,
    EXPECTED_GRAPH_BUCKET_COUNTS,
    EXPECTED_OBSERVED_AI_UNITS,
)


BUCKETS = tuple(
    bucket for bucket, count in EXPECTED_GRAPH_BUCKET_COUNTS.items() if count
)
VERDICTS = {
    "promote_compositional_contributor",
    "promote_regression_or_path_extension",
    "retain_possible",
    "retain_insufficient",
    "retain_unrelated",
}
PROMOTED_VERDICTS = {
    "promote_compositional_contributor",
    "promote_regression_or_path_extension",
    "retain_possible",
}
FAMILY_VERDICTS = {"supported", "possible", "not_supported", "insufficient"}
HYPOTHESIS_STATUSES = {"supported", "possible", "insufficient"}
REVIEW_KEYS = {
    "candidate_assessments",
    "family_assessment",
    "cross_file_hypotheses",
    "missing_evidence",
    "summary",
}
CANDIDATE_KEYS = {
    "sha",
    "verdict",
    "causal_role",
    "mechanism_relation",
    "evidence",
    "missing_evidence",
}
FAMILY_KEYS = {
    "cve",
    "ai_involvement",
    "candidate_shas",
    "reasoning",
    "missing_evidence",
}
HYPOTHESIS_KEYS = {
    "candidate_shas",
    "status",
    "hypothesis",
    "evidence_needed",
}
MAX_PROMPT_CHARS = 500_000

SYSTEM_PROMPT = """\
You are an independent software-security and commit-provenance reviewer. False
negatives are costly. Look for direct, cross-file, latent-primitive, activation,
regression, vulnerable-path-extension, fix-conflict, and carrier-composition
roles. The affected v6.0.0 snapshot predates every supplied AI candidate, which
rules out only original introduction into that snapshot. It does not rule out
later causal roles. Review every supplied SHA exactly once. Negative judgments
have no deletion authority; prefer retain_insufficient when a concrete
dependency cannot be resolved. Return only the requested JSON object.
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--bucket", choices=BUCKETS, required=True)
    parser.add_argument("--packet-index", type=int, required=True)
    parser.add_argument("--max-packet-diff-bytes", type=int, default=180_000)
    parser.add_argument("--max-candidates", type=int, default=6)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--reasoning-effort", choices=("low", "medium", "high"), required=True
    )
    parser.add_argument("--max-output-tokens", type=int, default=7000)
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--api-key-env", default="CLIPROXY_API_KEY")
    parser.add_argument("--api-key-config", type=Path, default=DEFAULT_API_CONFIG)
    parser.add_argument("--timeout", type=float, default=360.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain one JSON object")
    return value


def _git(repository: Path, arguments: list[str], *, timeout: int = 120) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git {' '.join(arguments)} failed: {exc}") from exc
    if completed.returncode != 0:
        raise SystemExit(f"git {' '.join(arguments)} failed: {completed.stderr[:500]}")
    return completed.stdout


def _commit_diff(repository: Path, sha: str) -> str:
    return _git(
        repository,
        [
            "show",
            "--format=commit %H%nsubject: %s%nauthor: %an <%ae>%nauthored: %aI%nbody:%n%B",
            "--no-ext-diff",
            "--no-renames",
            "--unified=8",
            sha,
        ],
    ).strip()


def _carrier_auth_diff(repository: Path, sha: str, paths: list[str]) -> str:
    return _git(
        repository,
        [
            "diff",
            "--no-ext-diff",
            "--no-renames",
            "--unified=8",
            f"{sha}^1",
            sha,
            "--",
            *paths,
        ],
    ).strip()


def _candidate_rows(certificate: Mapping[str, object]) -> list[dict[str, object]]:
    rows = certificate.get("observed_ai_candidates")
    conservation = certificate.get("conservation")
    priority = certificate.get("priority_review_shas")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise SystemExit("certificate candidate inventory is malformed")
    if not isinstance(conservation, Mapping) or conservation.get("passed") is not True:
        raise SystemExit("certificate candidate conservation did not pass")
    if conservation.get("hard_filter_count") != 0:
        raise SystemExit("certificate used a hard candidate filter")
    if len(rows) != EXPECTED_OBSERVED_AI_UNITS or not isinstance(priority, list):
        raise SystemExit("certificate candidate count is not frozen")
    shas = [str(row.get("sha")) for row in rows]
    if len(shas) != len(set(shas)) or set(shas) != {str(sha) for sha in priority}:
        raise SystemExit("certificate priority coverage is not exact")
    return rows


def _bucket_rows(
    certificate: Mapping[str, object], bucket: str
) -> list[dict[str, object]]:
    rows = []
    for row in _candidate_rows(certificate):
        membership = row.get("graph_membership")
        if isinstance(membership, Mapping) and membership.get("bucket") == bucket:
            rows.append(row)
    expected = EXPECTED_GRAPH_BUCKET_COUNTS[bucket]
    if len(rows) != expected:
        raise SystemExit(f"bucket {bucket} count drifted: {len(rows)} != {expected}")
    return sorted(rows, key=lambda row: str(row["sha"]))


def _packetize(
    rows: list[dict[str, object]], *, max_diff_bytes: int, max_candidates: int
) -> list[list[dict[str, object]]]:
    if max_diff_bytes < 1 or max_candidates < 1:
        raise ValueError("packet bounds must be positive")
    packets: list[list[dict[str, object]]] = []
    current: list[dict[str, object]] = []
    current_bytes = 0
    for row in rows:
        size = int(row.get("exact_diff_bytes", 0))
        if size < 0:
            raise ValueError("candidate diff size must not be negative")
        if current and (
            current_bytes + size > max_diff_bytes or len(current) >= max_candidates
        ):
            packets.append(current)
            current = []
            current_bytes = 0
        current.append(row)
        current_bytes += size
    if current:
        packets.append(current)
    flattened = [str(row["sha"]) for packet in packets for row in packet]
    expected = [str(row["sha"]) for row in rows]
    if flattened != expected or len(flattened) != len(set(flattened)):
        raise ValueError("packet candidate conservation failed")
    return packets


def _neutral_context(
    certificate: Mapping[str, object], selected: list[dict[str, object]]
) -> dict[str, object]:
    affected = certificate.get("affected_release")
    carriers = certificate.get("mitigation_carriers")
    mitigations = certificate.get("mitigation_chronology")
    adjudication = certificate.get("adjudication")
    if not isinstance(affected, Mapping) or not isinstance(carriers, list):
        raise SystemExit("certificate affected release or carriers are malformed")
    if not isinstance(mitigations, list) or not isinstance(adjudication, Mapping):
        raise SystemExit("certificate mitigation chronology is malformed")
    carrier_summary = []
    for row in carriers:
        if not isinstance(row, Mapping):
            raise SystemExit("certificate carrier row is malformed")
        carrier_summary.append(
            {
                "label": row.get("label"),
                "sha": row.get("sha"),
                "parents": row.get("parents"),
                "pr_number": row.get("pr_number"),
                "member_count": row.get("member_count"),
                "observed_ai_member_shas": row.get("observed_ai_member_shas"),
            }
        )
    selected_rows = []
    for row in selected:
        selected_rows.append(
            {
                key: row.get(key)
                for key in (
                    "sha",
                    "subject",
                    "authored_at",
                    "committed_at",
                    "ai_routes",
                    "ai_tools",
                    "changed_files",
                    "auth_surface_hits",
                    "graph_membership",
                    "priority_lane",
                    "exact_diff_bytes",
                )
            }
        )
    return {
        "advisory": certificate.get("advisory"),
        "public_mechanism_boundary": (
            "The public assessment reports accepted clear-text passwords, an eight-"
            "character minimum, and faster brute force; it recommends removing "
            "clear-text password use. The source probe proves direct password "
            "verification and an unsalted SHA-2 representation, not plaintext "
            "database storage."
        ),
        "affected_release": {
            "tag": affected.get("tag"),
            "resolved_commit": affected.get("resolved_commit"),
            "metadata": affected.get("metadata"),
            "source_probe": affected.get("source_probe"),
            "line_origins": affected.get("line_origins"),
        },
        "graph_windows": certificate.get("graph_windows"),
        "mitigation_chronology": mitigations,
        "mitigation_carriers": carrier_summary,
        "auth_ui_exact_delta": certificate.get("auth_ui_exact_delta"),
        "selected_candidates": selected_rows,
        "adjudication_boundaries": adjudication,
        "conservation": certificate.get("conservation"),
    }


def _build_prompt(
    repository: Path,
    certificate: Mapping[str, object],
    *,
    bucket: str,
    packet_index: int,
    max_diff_bytes: int,
    max_candidates: int,
) -> tuple[str, list[str], dict[str, object]]:
    rows = _bucket_rows(certificate, bucket)
    packets = _packetize(
        rows, max_diff_bytes=max_diff_bytes, max_candidates=max_candidates
    )
    if packet_index < 0 or packet_index >= len(packets):
        raise SystemExit(
            f"packet index {packet_index} is out of range for {bucket}: 0..{len(packets) - 1}"
        )
    selected = packets[packet_index]
    candidate_shas = [str(row["sha"]) for row in selected]
    context = _neutral_context(certificate, selected)
    candidate_diffs = {sha: _commit_diff(repository, sha) for sha in candidate_shas}

    auth_paths = sorted(
        {
            str(path)
            for row in certificate.get("mitigation_chronology", [])
            if isinstance(row, Mapping)
            for path in row.get("auth_surface_hits", [])
        }
    )
    carrier_diffs = {
        str(row["label"]): {
            "sha": row["sha"],
            "auth_surface_diff_against_first_parent": _carrier_auth_diff(
                repository, str(row["sha"]), auth_paths
            ),
        }
        for row in certificate.get("mitigation_carriers", [])
        if isinstance(row, Mapping)
        and row.get("label")
        in {"release_v7_to_main", "rate_limit_pr_2884", "redis_rate_limit_pr_2921"}
    }
    affected_source = _git(repository, ["show", f"{AFFECTED_SHA}:{AUTH_MODEL_PATH}"])
    packet_metadata = {
        "bucket": bucket,
        "packet_index": packet_index,
        "packet_count": len(packets),
        "bucket_candidate_count": len(rows),
        "packet_candidate_count": len(selected),
        "packet_exact_diff_bytes": sum(
            int(row["exact_diff_bytes"]) for row in selected
        ),
        "max_packet_diff_bytes": max_diff_bytes,
        "max_candidates": max_candidates,
        "candidate_shas": candidate_shas,
        "all_packet_shas": [[str(row["sha"]) for row in packet] for packet in packets],
    }
    prompt = f"""\
Review packet {packet_index + 1}/{len(packets)} from graph bucket `{bucket}` for
{ADVISORY_ID}. Assess every supplied SHA exactly once. Seek recoverable causal
roles, including interactions outside explicitly named auth files. A retain
verdict never deletes a candidate.

## Carrier-aware evidence and selected candidate metadata
```json
{json.dumps(context, indent=2, sort_keys=True, ensure_ascii=False)}
```

## Complete exact diffs for every selected AI candidate
```text
{json.dumps(candidate_diffs, indent=2, sort_keys=True, ensure_ascii=False)}
```

## Auth-surface deltas of the three main landing carriers
```text
{json.dumps(carrier_diffs, indent=2, sort_keys=True, ensure_ascii=False)}
```

## Complete affected v6.0.0 authentication model
```ruby
{affected_source}
```

Return exactly this JSON schema:
{{
  "candidate_assessments": [
    {{
      "sha": "one supplied SHA; every supplied SHA exactly once",
      "verdict": "promote_compositional_contributor" | "promote_regression_or_path_extension" | "retain_possible" | "retain_insufficient" | "retain_unrelated",
      "causal_role": "one concise sentence",
      "mechanism_relation": "specific relation to password acceptance, brute force, hashing, rate limiting, auth UI, dependency loading, or fix carriers",
      "evidence": ["zero or more exact evidence facts"],
      "missing_evidence": ["zero or more concrete missing facts"]
    }}
  ],
  "family_assessment": {{
    "cve": "{ADVISORY_ID}",
    "ai_involvement": "supported" | "possible" | "not_supported" | "insufficient",
    "candidate_shas": ["zero or more supplied SHAs"],
    "reasoning": "concise evidence-grounded packet conclusion",
    "missing_evidence": ["zero or more concrete missing facts"]
  }},
  "cross_file_hypotheses": [
    {{
      "candidate_shas": ["one or more supplied SHAs"],
      "status": "supported" | "possible" | "insufficient",
      "hypothesis": "the dependency, activation, regression, extension, or carrier chain",
      "evidence_needed": ["zero or more concrete checks"]
    }}
  ],
  "missing_evidence": ["global packet evidence gaps"],
  "summary": "overall recall-oriented packet conclusion"
}}
"""
    if len(prompt) + len(SYSTEM_PROMPT) > MAX_PROMPT_CHARS:
        raise SystemExit("review prompt exceeds the fail-closed size bound")
    return prompt, candidate_shas, packet_metadata


def _strip_fence(text: str) -> str:
    value = text.strip()
    if value.startswith("```"):
        lines = value.splitlines()
        value = "\n".join(line for line in lines if not line.startswith("```")).strip()
    return value


def _string_list(value: object, *, field: str, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{field} must be a string list")
    if not allow_empty and not value:
        raise ValueError(f"{field} must not be empty")
    return value


def _parse_review(text: str, candidate_shas: list[str]) -> dict[str, object]:
    try:
        value = json.loads(_strip_fence(text))
    except json.JSONDecodeError as exc:
        raise ValueError(f"review response is not JSON: {exc}") from exc
    if not isinstance(value, dict) or set(value) != REVIEW_KEYS:
        raise ValueError("review response keys are invalid")
    expected = set(candidate_shas)

    assessments = value["candidate_assessments"]
    if not isinstance(assessments, list):
        raise ValueError("candidate_assessments must be a list")
    observed: list[str] = []
    for row in assessments:
        if not isinstance(row, dict) or set(row) != CANDIDATE_KEYS:
            raise ValueError("candidate assessment keys are invalid")
        sha = str(row["sha"])
        observed.append(sha)
        if sha not in expected or row["verdict"] not in VERDICTS:
            raise ValueError(f"candidate assessment is invalid: {sha}")
        if not isinstance(row["causal_role"], str) or not row["causal_role"].strip():
            raise ValueError(f"candidate causal_role is invalid: {sha}")
        if (
            not isinstance(row["mechanism_relation"], str)
            or not row["mechanism_relation"].strip()
        ):
            raise ValueError(f"candidate mechanism_relation is invalid: {sha}")
        _string_list(row["evidence"], field="evidence")
        _string_list(row["missing_evidence"], field="missing_evidence")
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ValueError("candidate assessment coverage is not exact")

    family = value["family_assessment"]
    if not isinstance(family, dict) or set(family) != FAMILY_KEYS:
        raise ValueError("family assessment keys are invalid")
    if family["cve"] != ADVISORY_ID or family["ai_involvement"] not in FAMILY_VERDICTS:
        raise ValueError("family assessment identity or verdict is invalid")
    family_shas = _string_list(family["candidate_shas"], field="candidate_shas")
    if not set(family_shas) <= expected:
        raise ValueError("family assessment contains an unknown SHA")
    if not isinstance(family["reasoning"], str) or not family["reasoning"].strip():
        raise ValueError("family reasoning is invalid")
    _string_list(family["missing_evidence"], field="missing_evidence")

    hypotheses = value["cross_file_hypotheses"]
    if not isinstance(hypotheses, list):
        raise ValueError("cross_file_hypotheses must be a list")
    for row in hypotheses:
        if not isinstance(row, dict) or set(row) != HYPOTHESIS_KEYS:
            raise ValueError("cross-file hypothesis keys are invalid")
        shas = _string_list(
            row["candidate_shas"], field="candidate_shas", allow_empty=False
        )
        if not set(shas) <= expected or row["status"] not in HYPOTHESIS_STATUSES:
            raise ValueError("cross-file hypothesis identity or status is invalid")
        if not isinstance(row["hypothesis"], str) or not row["hypothesis"].strip():
            raise ValueError("cross-file hypothesis text is invalid")
        _string_list(row["evidence_needed"], field="evidence_needed")
    _string_list(value["missing_evidence"], field="missing_evidence")
    if not isinstance(value["summary"], str) or not value["summary"].strip():
        raise ValueError("review summary is invalid")
    return value


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.max_output_tokens < 1 or args.timeout <= 0:
        raise SystemExit("output-token and timeout bounds must be positive")
    if not _loopback(args.api_base):
        raise SystemExit("OpenC3 review requires a loopback CLIProxyAPI endpoint")
    repository = args.repository.resolve()
    certificate = _load_json(args.certificate)
    if (
        certificate.get("artifact_kind")
        != "openc3_weak_password_carrier_chronology_certificate"
    ):
        raise SystemExit("unexpected certificate artifact kind")

    prompt, candidate_shas, packet = _build_prompt(
        repository,
        certificate,
        bucket=args.bucket,
        packet_index=args.packet_index,
        max_diff_bytes=args.max_packet_diff_bytes,
        max_candidates=args.max_candidates,
    )
    api_key = _api_key(args.api_key_env, args.api_key_config)
    _require_model(args.api_base, api_key, args.model, args.timeout)
    certificate_bytes = args.certificate.read_bytes()
    spec = {
        "schema_version": 2,
        "artifact_kind": "openc3_weak_password_packet_ai_review",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "max_output_tokens": args.max_output_tokens,
        "certificate_sha256": hashlib.sha256(certificate_bytes).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "prompt_chars": len(prompt) + len(SYSTEM_PROMPT),
        "estimated_input_tokens_chars_div_4": (len(prompt) + len(SYSTEM_PROMPT) + 3)
        // 4,
        "packet": packet,
        "negative_disposition": "RETAIN_NOT_DELETE",
        "unreviewed_candidate_disposition": "RETAIN_NOT_DELETE",
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
        "result_status": "parse_error",
        "usage": _usage(response),
        "review": {},
        "promoted_candidate_shas": [],
        "parse_error": "",
    }
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], Mapping):
        result["finish_reason"] = str(choices[0].get("finish_reason") or "")
    try:
        review = _parse_review(_response_text(response), candidate_shas)
    except ValueError as exc:
        result["parse_error"] = str(exc)
    else:
        assessments = review["candidate_assessments"]
        assert isinstance(assessments, list)
        result["review"] = review
        result["promoted_candidate_shas"] = sorted(
            str(row["sha"])
            for row in assessments
            if isinstance(row, Mapping) and row.get("verdict") in PROMOTED_VERDICTS
        )
        result["result_status"] = "completed"
    _atomic_json(args.output_dir / "result.json", result)

    print("OpenC3 packet AI review complete")
    print(f"  model        : {args.model}")
    print(f"  effort       : {args.reasoning_effort}")
    print(f"  bucket       : {args.bucket}")
    print(f"  packet       : {args.packet_index + 1}/{packet['packet_count']}")
    print(f"  prompt chars : {spec['prompt_chars']}")
    print(f"  candidates   : {len(candidate_shas)}")
    print(f"  status       : {result['result_status']}")
    print(f"  usage        : {result['usage']}")
    print(f"  promoted     : {len(result['promoted_candidate_shas'])}")
    if result["result_status"] != "completed":
        print(f"  parse error  : {result['parse_error']}")
    print(f"  output       : {args.output_dir}")
    return 0 if result["result_status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
