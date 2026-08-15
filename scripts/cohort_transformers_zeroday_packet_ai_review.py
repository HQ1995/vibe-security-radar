#!/usr/bin/env python3
"""Review Transformers 0-day candidates in small, add-only, exact-cover packets."""

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
from cohort_transformers_zeroday_ai_review import (
    PROBE_SPECS,
    _candidate_packet,
    _load_json,
    _neutral_advisories,
    _probe,
)


LANES = {"source_attributed", "structural_path_partner_no_ai_signal"}
VERDICTS = {
    "promote_direct_introducer",
    "promote_compositional_contributor",
    "promote_path_extension",
    "retain_possible",
    "retain_insufficient",
    "retain_unrelated",
}
PROMOTED_VERDICTS = {
    "promote_direct_introducer",
    "promote_compositional_contributor",
    "promote_path_extension",
    "retain_possible",
}
HYPOTHESIS_STATUSES = {"supported", "possible", "insufficient"}
REVIEW_KEYS = {
    "candidate_assessments",
    "cross_file_hypotheses",
    "missing_evidence",
    "summary",
}
CANDIDATE_KEYS = {
    "sha",
    "verdict",
    "related_cves",
    "causal_role",
    "reasoning",
    "missing_evidence",
}
HYPOTHESIS_KEYS = {
    "candidate_shas",
    "cves",
    "status",
    "hypothesis",
    "evidence_needed",
}
EXPECTED_SOURCE_COUNT = 26
EXPECTED_STRUCTURAL_COUNT = 6
EXPECTED_PRIORITY_COUNT = EXPECTED_SOURCE_COUNT + EXPECTED_STRUCTURAL_COUNT
MAX_PROMPT_CHARS = 180_000

SYSTEM_PROMPT = """\
You are an independent software-security and commit-provenance reviewer. False
negatives are costly, so surface direct, compositional, activation, and
path-extension leads even when evidence is incomplete. Only candidates marked
source_attributed have direct AI evidence. A structural partner can support a
composition hypothesis but cannot become an AI-authored root. Every supplied
candidate must receive one assessment. A negative or insufficient verdict has
no deletion authority. Return only the requested JSON object.
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--lane", choices=sorted(LANES), required=True)
    parser.add_argument("--packet-index", type=int, required=True)
    parser.add_argument("--packet-size", type=int, default=4)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--reasoning-effort", choices=("low", "medium", "high"), required=True
    )
    parser.add_argument("--max-output-tokens", type=int, default=6500)
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--api-key-env", default="CLIPROXY_API_KEY")
    parser.add_argument("--api-key-config", type=Path, default=DEFAULT_API_CONFIG)
    parser.add_argument("--timeout", type=float, default=360.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _candidate_rows(
    closure: Mapping[str, object],
) -> tuple[list[Mapping[str, object]], list[Mapping[str, object]]]:
    members = closure.get("member_candidates")
    noncarriers = closure.get("noncarrier_observed_ai_candidates")
    if not isinstance(members, list) or not isinstance(noncarriers, list):
        raise ValueError("closure candidate rows are malformed")
    all_rows = [row for row in [*members, *noncarriers] if isinstance(row, Mapping)]
    source = sorted(
        (row for row in all_rows if row.get("source_v3_ai_evidence") is True),
        key=lambda row: str(row.get("sha")),
    )
    structural = sorted(
        (
            row
            for row in members
            if isinstance(row, Mapping)
            and row.get("source_v3_ai_evidence") is not True
            and bool(row.get("advisory_model_path_hits"))
        ),
        key=lambda row: str(row.get("sha")),
    )
    source_shas = [str(row.get("sha")) for row in source]
    structural_shas = [str(row.get("sha")) for row in structural]
    if len(source_shas) != len(set(source_shas)) or len(structural_shas) != len(
        set(structural_shas)
    ):
        raise ValueError("priority lane contains duplicate candidate identities")
    if set(source_shas) & set(structural_shas):
        raise ValueError("source and structural lanes overlap")
    if len(source) != EXPECTED_SOURCE_COUNT or len(structural) != EXPECTED_STRUCTURAL_COUNT:
        raise ValueError(
            f"unexpected lane sizes: source={len(source)}, structural={len(structural)}"
        )
    return source, structural


def _candidate_index(
    source: list[Mapping[str, object]], structural: list[Mapping[str, object]]
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for lane, candidates in (
        ("source_attributed", source),
        ("structural_path_partner_no_ai_signal", structural),
    ):
        for row in candidates:
            rows.append(
                {
                    "sha": row.get("sha"),
                    "lane": lane,
                    "source_attributed": lane == "source_attributed",
                    "pr_number": row.get("pr_number"),
                    "subject": row.get("subject"),
                    "changed_files": row.get("changed_files", []),
                    "advisory_model_path_hits": row.get(
                        "advisory_model_path_hits", []
                    ),
                }
            )
    return sorted(rows, key=lambda row: str(row["sha"]))


def _packet_bounds(total: int, packet_size: int, packet_index: int) -> tuple[int, int, int]:
    if packet_size < 1:
        raise ValueError("packet size must be positive")
    packet_count = (total + packet_size - 1) // packet_size
    if packet_index < 0 or packet_index >= packet_count:
        raise ValueError(
            f"packet index {packet_index} is outside [0, {packet_count})"
        )
    start = packet_index * packet_size
    return start, min(start + packet_size, total), packet_count


def _build_prompt(
    repository: Path,
    closure: Mapping[str, object],
    *,
    lane: str,
    packet_index: int,
    packet_size: int,
) -> tuple[str, dict[str, object], list[str], list[str], set[str]]:
    source, structural = _candidate_rows(closure)
    lane_rows = source if lane == "source_attributed" else structural
    start, end, packet_count = _packet_bounds(len(lane_rows), packet_size, packet_index)
    selected = lane_rows[start:end]
    advisories = _neutral_advisories(repository, closure)
    cves = sorted(str(row["cve"]) for row in advisories)
    prefixes_by_cve = {
        str(row["cve"]): [str(path) for path in row["model_path_prefixes"]]
        for row in advisories
        if isinstance(row.get("model_path_prefixes"), list)
    }
    source_shas = {str(row["sha"]) for row in source}
    global_index = _candidate_index(source, structural)
    global_shas = {str(row["sha"]) for row in global_index}
    candidates = []
    for row in selected:
        diff_paths = None
        if lane == "structural_path_partner_no_ai_signal":
            diff_paths = sorted(
                {
                    prefix
                    for cve in row.get("advisory_model_path_hits", [])
                    for prefix in prefixes_by_cve.get(str(cve), [])
                }
            )
        candidates.append(
            _candidate_packet(
                repository,
                row,
                lane=lane,
                diff_paths=diff_paths,
            )
        )
    probes = [_probe(repository, spec, source_shas) for spec in PROBE_SPECS]
    probes.append(
        {
            "cve": "CVE-2025-14930",
            "status": "NO_EXACT_LOCAL_MECHANISM_ANCHOR_SELECTED",
            "reason": (
                "The public description says GLM4 weight parsing, but the resolved "
                "v4.57.1 model-family paths contain no pickle.load or torch.load "
                "anchor. Treat mapping as insufficient, not negative."
            ),
        }
    )
    packet = {
        "lane": lane,
        "packet_index": packet_index,
        "packet_count": packet_count,
        "packet_size": packet_size,
        "lane_candidate_count": len(lane_rows),
        "candidate_shas": [str(row["sha"]) for row in candidates],
    }
    evidence = {
        "packet": packet,
        "advisories": advisories,
        "mechanism_probes": probes,
        "review_candidates_with_exact_diffs": candidates,
        "global_32_candidate_index_without_diffs": global_index,
        "inventory_boundary": {
            "frozen_observed_ai_units": EXPECTED_SOURCE_COUNT,
            "exact_squash_ancestry_members_retained": 179,
            "priority_candidate_count": EXPECTED_PRIORITY_COUNT,
            "hard_filter_count": 0,
        },
        "release_squash_boundary": (
            "PR 41310 is a genuine v4.57.0 release aggregation: its exact base is "
            "an ancestor of its head and all 167 commits form the linear base..head "
            "range. Only one has direct AI attribution; the others remain possible "
            "structural or activation partners, never AI roots by association."
        ),
    }
    prompt = f"""\
Review this exact packet from the 32-candidate Transformers priority inventory
against all eight advisory families. Assess each packet SHA exactly once. Use
the global index to notice cross-packet composition, but do not claim an unseen
exact delta as proven. Put plausible dependencies in cross_file_hypotheses so
they enter the add-only follow-up queue. Public reports omit some exact lines;
prefer retain_insufficient or retain_possible over an unsupported exclusion.

## Frozen packet and evidence
```json
{json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False)}
```

Return exactly this JSON schema:
{{
  "candidate_assessments": [
    {{
      "sha": "every packet SHA exactly once",
      "verdict": "promote_direct_introducer" | "promote_compositional_contributor" | "promote_path_extension" | "retain_possible" | "retain_insufficient" | "retain_unrelated",
      "related_cves": ["zero or more supplied CVEs"],
      "causal_role": "one concise sentence",
      "reasoning": "evidence-grounded explanation",
      "missing_evidence": ["zero or more concrete missing facts"]
    }}
  ],
  "cross_file_hypotheses": [
    {{
      "candidate_shas": ["one or more SHAs from the global 32-candidate index, including at least one packet SHA"],
      "cves": ["one or more supplied CVEs"],
      "status": "supported" | "possible" | "insufficient",
      "hypothesis": "specific dependency or activation chain",
      "evidence_needed": ["zero or more exact checks"]
    }}
  ],
  "missing_evidence": ["global evidence gaps"],
  "summary": "packet-level recall-oriented conclusion"
}}
"""
    if len(prompt) + len(SYSTEM_PROMPT) > MAX_PROMPT_CHARS:
        raise ValueError(
            f"packet prompt exceeds fail-closed bound: {len(prompt) + len(SYSTEM_PROMPT)}"
        )
    return (
        prompt,
        packet,
        [str(row["sha"]) for row in candidates],
        cves,
        global_shas,
    )


def _strip_fence(text: str) -> str:
    value = text.strip()
    if value.startswith("```"):
        value = "\n".join(
            line for line in value.splitlines() if not line.startswith("```")
        ).strip()
    return value


def _string_list(value: object, *, field: str, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{field} must be a string list")
    if not allow_empty and not value:
        raise ValueError(f"{field} must not be empty")
    return value


def _parse_review(
    text: str,
    candidate_shas: list[str],
    cves: list[str],
    global_shas: set[str],
    *,
    structural_lane: bool,
) -> dict[str, object]:
    try:
        value = json.loads(_strip_fence(text))
    except json.JSONDecodeError as exc:
        raise ValueError(f"review response is not JSON: {exc}") from exc
    if not isinstance(value, dict) or set(value) != REVIEW_KEYS:
        raise ValueError("review response keys are invalid")
    expected = set(candidate_shas)
    expected_cves = set(cves)
    assessments = value["candidate_assessments"]
    if not isinstance(assessments, list):
        raise ValueError("candidate_assessments must be a list")
    observed: list[str] = []
    for row in assessments:
        if not isinstance(row, dict) or set(row) != CANDIDATE_KEYS:
            raise ValueError("candidate assessment keys are invalid")
        sha = str(row["sha"])
        observed.append(sha)
        verdict = str(row["verdict"])
        if sha not in expected or verdict not in VERDICTS:
            raise ValueError(f"candidate assessment is invalid: {sha}")
        if structural_lane and verdict == "promote_direct_introducer":
            raise ValueError(f"structural candidate cannot be a direct AI root: {sha}")
        related = _string_list(row["related_cves"], field="related_cves")
        if not set(related) <= expected_cves:
            raise ValueError(f"candidate has an unknown CVE: {sha}")
        for field in ("causal_role", "reasoning"):
            if not isinstance(row[field], str) or not row[field].strip():
                raise ValueError(f"candidate {field} is invalid: {sha}")
        _string_list(row["missing_evidence"], field="missing_evidence")
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ValueError("candidate assessment coverage is not exact")

    hypotheses = value["cross_file_hypotheses"]
    if not isinstance(hypotheses, list):
        raise ValueError("cross_file_hypotheses must be a list")
    for row in hypotheses:
        if not isinstance(row, dict) or set(row) != HYPOTHESIS_KEYS:
            raise ValueError("cross-file hypothesis keys are invalid")
        shas = _string_list(
            row["candidate_shas"], field="candidate_shas", allow_empty=False
        )
        related = _string_list(row["cves"], field="cves", allow_empty=False)
        if not set(shas) <= global_shas or not set(shas) & expected:
            raise ValueError("cross-file hypothesis candidate scope is invalid")
        if not set(related) <= expected_cves:
            raise ValueError("cross-file hypothesis CVE scope is invalid")
        if row["status"] not in HYPOTHESIS_STATUSES:
            raise ValueError("cross-file hypothesis status is invalid")
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
    if args.packet_size < 1 or args.max_output_tokens < 1 or args.timeout <= 0:
        raise SystemExit("packet, token, and timeout bounds must be positive")
    if not _loopback(args.api_base):
        raise SystemExit("Transformers packet review requires a loopback endpoint")
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    closure = _load_json(args.closure)
    if closure.get("artifact_kind") != "transformers_zeroday_squash_member_closure":
        raise SystemExit("unexpected closure artifact kind")
    try:
        prompt, packet, candidate_shas, cves, global_shas = _build_prompt(
            repository,
            closure,
            lane=args.lane,
            packet_index=args.packet_index,
            packet_size=args.packet_size,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    api_key = _api_key(args.api_key_env, args.api_key_config)
    _require_model(args.api_base, api_key, args.model, args.timeout)
    spec = {
        "schema_version": 1,
        "artifact_kind": "transformers_zeroday_packet_ai_review",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "max_output_tokens": args.max_output_tokens,
        "closure_sha256": hashlib.sha256(args.closure.read_bytes()).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "prompt_chars": len(prompt) + len(SYSTEM_PROMPT),
        "estimated_input_tokens_chars_div_4": (
            len(prompt) + len(SYSTEM_PROMPT) + 3
        )
        // 4,
        "packet": packet,
        "candidate_shas": candidate_shas,
        "advisories": cves,
        "global_priority_candidate_count": len(global_shas),
        "negative_disposition": "RETAIN_NOT_DELETE",
        "unscreened_member_disposition": "RETAIN_NOT_DELETE",
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
        "cross_file_lead_shas": [],
        "parse_error": "",
    }
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], Mapping):
        result["finish_reason"] = str(choices[0].get("finish_reason") or "")
    try:
        review = _parse_review(
            _response_text(response),
            candidate_shas,
            cves,
            global_shas,
            structural_lane=args.lane == "structural_path_partner_no_ai_signal",
        )
    except ValueError as exc:
        result["parse_error"] = str(exc)
    else:
        assessments = review["candidate_assessments"]
        hypotheses = review["cross_file_hypotheses"]
        assert isinstance(assessments, list) and isinstance(hypotheses, list)
        result["review"] = review
        result["promoted_candidate_shas"] = sorted(
            str(row["sha"])
            for row in assessments
            if isinstance(row, Mapping) and row.get("verdict") in PROMOTED_VERDICTS
        )
        result["cross_file_lead_shas"] = sorted(
            {
                str(sha)
                for row in hypotheses
                if isinstance(row, Mapping)
                and row.get("status") in {"supported", "possible"}
                for sha in row.get("candidate_shas", [])
            }
        )
        result["result_status"] = "completed"
    _atomic_json(args.output_dir / "result.json", result)
    print("Transformers packet AI review complete")
    print(f"  lane         : {args.lane}")
    print(
        f"  packet       : {args.packet_index + 1}/{packet['packet_count']} "
        f"({len(candidate_shas)} candidates)"
    )
    print(f"  model        : {args.model}")
    print(f"  effort       : {args.reasoning_effort}")
    print(f"  prompt chars : {spec['prompt_chars']}")
    print(f"  status       : {result['result_status']}")
    print(f"  usage        : {result['usage']}")
    print(f"  promoted     : {len(result['promoted_candidate_shas'])}")
    print(f"  output       : {args.output_dir}")
    return 0 if result["result_status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
