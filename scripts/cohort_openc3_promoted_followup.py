#!/usr/bin/env python3
"""Counterfactual review of the five Grok-promoted OpenC3 leads."""

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
    AUTH_UI_AI_SHA,
    LOGIN_PATH,
    RATE_MAIN_LANDING_SHA,
    USER_MENU_PATH,
)


EXPECTED_LEADS = frozenset(
    {
        "09ca75b894593da721948979c2406b93572c64f1",
        "1e5f85448c2d91f608dfc72218c4f5c0b225c2a4",
        "2fc46a6806b5d78e6f9e10b8c41e7c23debbf719",
        "91a313c31747920a90def4f8d120899ee73ac01f",
        AUTH_UI_AI_SHA,
    }
)
AUTH_RUNTIME_PATHS = (
    "openc3-cosmos-cmd-tlm-api/app/controllers/auth_controller.rb",
    "openc3/lib/openc3/models/auth_model.rb",
    "openc3/lib/openc3/utilities/authentication.rb",
    "openc3/lib/openc3/utilities/authorization.rb",
    LOGIN_PATH,
)
SYMBOL_PROBES = {
    "1e5f85448c2d91f608dfc72218c4f5c0b225c2a4": (
        "item_within_buffer_bounds|ALLOW_SHORT"
    ),
    "2fc46a6806b5d78e6f9e10b8c41e7c23debbf719": (
        "check_limits|apply_format_string_and_units|PolynomialConversion|"
        "SegmentedPolynomialConversion"
    ),
    "91a313c31747920a90def4f8d120899ee73ac01f": (
        "RESERVED_ITEM_NAMES|given_raw|write_item|command_decom"
    ),
}
VERDICTS = {
    "claim_grade_compositional_contributor",
    "claim_grade_path_extension",
    "possible_needs_evidence",
    "not_causal_from_exact_delta",
    "insufficient",
}
TERNARY = {"yes", "no", "insufficient"}
REVIEW_KEYS = {
    "candidate_assessments",
    "claim_grade_shas",
    "missing_evidence",
    "summary",
}
CANDIDATE_KEYS = {
    "sha",
    "verdict",
    "changed_vulnerability_mechanism",
    "necessary_or_path_extending",
    "exact_causal_edge",
    "counterfactual",
    "evidence",
    "missing_evidence",
}
MAX_PROMPT_CHARS = 300_000

SYSTEM_PROMPT = """\
You are the strict counterfactual adjudicator after a recall-first model pass.
False positives were allowed upstream; claim-grade causal labels are not. Mere
same-branch ancestry, documentation about security, file-name proximity, or a
hypothetical dependency without a call/data/config edge is insufficient. A
compositional contributor must change a primitive, value, control edge, config,
or reachability used by the vulnerability. A path extension must actually
extend or regress the vulnerable path. Review every supplied lead exactly once.
Candidates remain retained regardless of verdict. Return only the requested
JSON object.
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
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


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain one JSON object")
    return value


def _git(
    repository: Path, arguments: list[str], *, allow_no_match: bool = False
) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git {' '.join(arguments)} failed: {exc}") from exc
    allowed = {0, 1} if allow_no_match else {0}
    if completed.returncode not in allowed:
        raise SystemExit(f"git {' '.join(arguments)} failed: {completed.stderr[:500]}")
    return completed.stdout


def _commit_diff(repository: Path, sha: str, *, paths: tuple[str, ...] = ()) -> str:
    arguments = [
        "show",
        "--format=commit %H%nsubject: %s%nauthor: %an <%ae>%nauthored: %aI%nbody:%n%B",
        "--no-ext-diff",
        "--no-renames",
        "--unified=8",
        sha,
    ]
    if paths:
        arguments.extend(["--", *paths])
    return _git(repository, arguments).strip()


def _lead_rows(
    certificate: Mapping[str, object], aggregate: Mapping[str, object]
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    promoted = aggregate.get("model_promoted_candidate_shas")
    assessments = aggregate.get("candidate_assessments")
    candidates = certificate.get("observed_ai_candidates")
    if (
        not isinstance(promoted, list)
        or {str(sha) for sha in promoted} != EXPECTED_LEADS
    ):
        raise SystemExit("aggregate promoted lead identities drifted")
    if not isinstance(assessments, list) or not isinstance(candidates, list):
        raise SystemExit("aggregate or certificate candidate rows are malformed")
    candidate_by_sha = {
        str(row["sha"]): row
        for row in candidates
        if isinstance(row, dict) and isinstance(row.get("sha"), str)
    }
    assessment_by_sha = {
        str(row["sha"]): row
        for row in assessments
        if isinstance(row, dict) and str(row.get("sha")) in EXPECTED_LEADS
    }
    if set(assessment_by_sha) != EXPECTED_LEADS or not EXPECTED_LEADS <= set(
        candidate_by_sha
    ):
        raise SystemExit("follow-up lead coverage is not exact")
    return (
        [candidate_by_sha[sha] for sha in sorted(EXPECTED_LEADS)],
        [assessment_by_sha[sha] for sha in sorted(EXPECTED_LEADS)],
    )


def _static_probes(
    repository: Path, certificate: Mapping[str, object]
) -> dict[str, object]:
    symbol_results = {}
    for sha, pattern in SYMBOL_PROBES.items():
        matches = _git(
            repository,
            [
                "grep",
                "-n",
                "-E",
                pattern,
                RATE_MAIN_LANDING_SHA,
                "--",
                *AUTH_RUNTIME_PATHS,
            ],
            allow_no_match=True,
        ).splitlines()
        symbol_results[sha] = {
            "pattern": pattern,
            "auth_runtime_matches_at_rate_landing": matches,
            "match_count": len(matches),
        }
    auth_delta = certificate.get("auth_ui_exact_delta")
    if (
        not isinstance(auth_delta, Mapping)
        or auth_delta.get("login_script_block_unchanged") is not True
    ):
        raise SystemExit("auth UI exact-delta probe is unavailable")
    return {
        "docs_candidate": {
            "sha": "09ca75b894593da721948979c2406b93572c64f1",
            "runtime_file_delta_count": 0,
            "changed_paths_are_documentation_only": True,
        },
        "auth_ui_candidate": dict(auth_delta),
        "packet_symbol_reachability": symbol_results,
        "carrier_boundary": (
            "The exact PR member lists for the plaintext, Argon2, rate-limit, and "
            "Redis carriers contain no observed AI member. Being in a carrier's "
            "ancestry is not itself a causal edge."
        ),
    }


def _build_prompt(
    repository: Path,
    certificate: Mapping[str, object],
    aggregate: Mapping[str, object],
) -> tuple[str, list[str]]:
    candidates, upstream = _lead_rows(certificate, aggregate)
    candidate_shas = sorted(EXPECTED_LEADS)
    diffs = {}
    for sha in candidate_shas:
        paths = (LOGIN_PATH, USER_MENU_PATH) if sha == AUTH_UI_AI_SHA else ()
        diffs[sha] = _commit_diff(repository, sha, paths=paths)
    evidence = {
        "advisory": certificate.get("advisory"),
        "graph_windows": certificate.get("graph_windows"),
        "mitigation_carriers": certificate.get("mitigation_carriers"),
        "lead_candidate_metadata": candidates,
        "upstream_recall_first_assessments": upstream,
        "static_counterfactual_probes": _static_probes(repository, certificate),
        "claim_boundary": aggregate.get("claim_boundary"),
    }
    prompt = f"""\
Strictly adjudicate the five recall-first leads for {ADVISORY_ID}. For each SHA,
identify an exact code, data, config, or reachability edge and state the
counterfactual without that delta. If the only relation is documentation,
same-carrier ancestry, unrelated packet processing, or a byte-identical auth
script block, do not assign a claim-grade causal role. Retain every candidate.

## Frozen evidence and static counterfactual probes
```json
{json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False)}
```

## Exact diffs (auth-path scoped only for the large ESLint candidate)
```text
{json.dumps(diffs, indent=2, sort_keys=True, ensure_ascii=False)}
```

Return exactly this JSON schema:
{{
  "candidate_assessments": [
    {{
      "sha": "every supplied SHA exactly once",
      "verdict": "claim_grade_compositional_contributor" | "claim_grade_path_extension" | "possible_needs_evidence" | "not_causal_from_exact_delta" | "insufficient",
      "changed_vulnerability_mechanism": "yes" | "no" | "insufficient",
      "necessary_or_path_extending": "yes" | "no" | "insufficient",
      "exact_causal_edge": "specific edge, or state that none is evidenced",
      "counterfactual": "what changes in the vulnerable path without this exact delta",
      "evidence": ["exact facts"],
      "missing_evidence": ["facts needed for a stronger claim"]
    }}
  ],
  "claim_grade_shas": ["only supplied SHAs that meet a claim-grade verdict"],
  "missing_evidence": ["global gaps"],
  "summary": "strict aggregate conclusion"
}}
"""
    if len(prompt) + len(SYSTEM_PROMPT) > MAX_PROMPT_CHARS:
        raise SystemExit("follow-up prompt exceeds the fail-closed size bound")
    return prompt, candidate_shas


def _strip_fence(text: str) -> str:
    value = text.strip()
    if value.startswith("```"):
        value = "\n".join(
            line for line in value.splitlines() if not line.startswith("```")
        ).strip()
    return value


def _string_list(value: object, *, field: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{field} must be a string list")
    return value


def _parse_review(text: str, candidate_shas: list[str]) -> dict[str, object]:
    try:
        value = json.loads(_strip_fence(text))
    except json.JSONDecodeError as exc:
        raise ValueError(f"review response is not JSON: {exc}") from exc
    if not isinstance(value, dict) or set(value) != REVIEW_KEYS:
        raise ValueError("review response keys are invalid")
    assessments = value["candidate_assessments"]
    if not isinstance(assessments, list):
        raise ValueError("candidate_assessments must be a list")
    expected = set(candidate_shas)
    observed = []
    claim_grade = set()
    for row in assessments:
        if not isinstance(row, dict) or set(row) != CANDIDATE_KEYS:
            raise ValueError("candidate assessment keys are invalid")
        sha = str(row["sha"])
        observed.append(sha)
        if sha not in expected or row["verdict"] not in VERDICTS:
            raise ValueError(f"candidate assessment is invalid: {sha}")
        if row["changed_vulnerability_mechanism"] not in TERNARY:
            raise ValueError(f"candidate mechanism ternary is invalid: {sha}")
        if row["necessary_or_path_extending"] not in TERNARY:
            raise ValueError(f"candidate counterfactual ternary is invalid: {sha}")
        for field in ("exact_causal_edge", "counterfactual"):
            if not isinstance(row[field], str) or not row[field].strip():
                raise ValueError(f"candidate {field} is invalid: {sha}")
        _string_list(row["evidence"], field="evidence")
        _string_list(row["missing_evidence"], field="missing_evidence")
        if str(row["verdict"]).startswith("claim_grade_"):
            claim_grade.add(sha)
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ValueError("candidate assessment coverage is not exact")
    declared = set(_string_list(value["claim_grade_shas"], field="claim_grade_shas"))
    if declared != claim_grade or not declared <= expected:
        raise ValueError("claim-grade SHA declaration is inconsistent")
    _string_list(value["missing_evidence"], field="missing_evidence")
    if not isinstance(value["summary"], str) or not value["summary"].strip():
        raise ValueError("review summary is invalid")
    return value


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if not _loopback(args.api_base):
        raise SystemExit("OpenC3 follow-up requires a loopback CLIProxyAPI endpoint")
    certificate = _load_json(args.certificate)
    aggregate = _load_json(args.aggregate)
    prompt, candidate_shas = _build_prompt(
        args.repository.resolve(), certificate, aggregate
    )
    api_key = _api_key(args.api_key_env, args.api_key_config)
    _require_model(args.api_base, api_key, args.model, args.timeout)
    spec = {
        "schema_version": 1,
        "artifact_kind": "openc3_weak_password_promoted_followup",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "max_output_tokens": args.max_output_tokens,
        "certificate_sha256": hashlib.sha256(args.certificate.read_bytes()).hexdigest(),
        "aggregate_sha256": hashlib.sha256(args.aggregate.read_bytes()).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "prompt_chars": len(prompt) + len(SYSTEM_PROMPT),
        "estimated_input_tokens_chars_div_4": (len(prompt) + len(SYSTEM_PROMPT) + 3)
        // 4,
        "candidate_shas": candidate_shas,
        "negative_disposition": "RETAIN_NOT_DELETE",
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
        "claim_grade_shas": [],
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
        result["review"] = review
        result["claim_grade_shas"] = review["claim_grade_shas"]
        result["result_status"] = "completed"
    _atomic_json(args.output_dir / "result.json", result)
    print("OpenC3 promoted-lead follow-up complete")
    print(f"  model        : {args.model}")
    print(f"  effort       : {args.reasoning_effort}")
    print(f"  prompt chars : {spec['prompt_chars']}")
    print(f"  status       : {result['result_status']}")
    print(f"  usage        : {result['usage']}")
    print(f"  claim-grade  : {len(result['claim_grade_shas'])}")
    print(f"  output       : {args.output_dir}")
    return 0 if result["result_status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
