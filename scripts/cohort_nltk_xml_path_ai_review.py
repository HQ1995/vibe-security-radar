#!/usr/bin/env python3
"""Route every affected-state AI candidate in the frozen NLTK inventory.

This is an add-only review stage.  Every AI-attributed or broad-regex candidate
that is an exact Git ancestor of the affected state is covered once.  Model
negatives remain retained and never change the finite inventory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from cohort_nltk_xml_path_causal_inventory import (
    AFFECTED_SHA,
    ADVISORY,
    FIX_MEMBER_SHA,
    REPOSITORY_IDENTITY,
    _git,
)


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
ASSESSMENT_KEYS = {
    "sha",
    "verdict",
    "causal_role",
    "reasoning",
    "missing_evidence",
}
REVIEW_KEYS = {"candidate_assessments", "cross_file_hypotheses", "summary"}
HYPOTHESIS_KEYS = {
    "candidate_shas",
    "status",
    "hypothesis",
    "evidence_needed",
}
HYPOTHESIS_STATUSES = {"supported", "possible", "insufficient"}
PRIORITY_ORDER = {
    "P0_AI_CAUSAL_SEMANTIC_CODE": 0,
    "P1_AI_AFFECTED_CODE_HISTORY": 1,
    "P2_AI_AFFECTED_CONTEXT_HISTORY": 2,
    "P3_AI_ANCESTRY_FALLBACK": 3,
}
EXPECTED_SELECTED_COUNT = 48
MAX_PROMPT_CHARS = 160_000

SYSTEM_PROMPT = """\
You are a recall-first software-security history reviewer. False negatives are
expensive. Assess the candidate's own parent-to-child delta, including direct
introduction, a latent compositional primitive, a newly reachable source/sink,
an insecure default, a caller or route activation, a path extension, or removal
of a guard. Mere ancestry, unchanged perpetuation, tests, documentation, and an
unrelated security hardening are not causal deltas. Weak metadata-regex evidence
means only that the commit is a candidate for AI use; do not upgrade it to
publication-grade attribution. Every candidate remains retained regardless of
your answer. Return only the exact JSON object requested.
"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--reasoning-effort", choices=("low", "medium", "high"), required=True
    )
    parser.add_argument("--packet-size", type=int, default=6)
    parser.add_argument("--candidate-diff-chars", type=int, default=8_000)
    parser.add_argument("--max-output-tokens", type=int, default=5_000)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--contract-retries", type=int, default=1)
    parser.add_argument(
        "--candidate-sha",
        action="append",
        default=[],
        help="review only this affected-state candidate; repeat for a subset",
    )
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
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _selected_candidates(
    inventory: Mapping[str, object],
) -> list[Mapping[str, object]]:
    if inventory.get("artifact_kind") != "nltk_xml_path_traversal_recall_inventory":
        raise ValueError("unexpected NLTK inventory artifact")
    if inventory.get("repository_identity") != REPOSITORY_IDENTITY:
        raise ValueError("repository identity changed")
    if inventory.get("advisory") != ADVISORY:
        raise ValueError("advisory identity changed")
    conservation = inventory.get("conservation")
    if (
        not isinstance(conservation, Mapping)
        or conservation.get("passed") is not True
        or conservation.get("hard_filter_count") != 0
    ):
        raise ValueError("parent inventory is not recall-conserving")
    rows = inventory.get("ai_candidates")
    if not isinstance(rows, list):
        raise ValueError("AI candidate inventory is malformed")
    selected = [
        row
        for row in rows
        if isinstance(row, Mapping) and row.get("ancestor_of_affected_state") is True
    ]
    selected.sort(
        key=lambda row: (
            PRIORITY_ORDER.get(str(row.get("priority")), 99),
            str(row.get("sha")),
        )
    )
    shas = [str(row.get("sha")) for row in selected]
    if len(shas) != EXPECTED_SELECTED_COUNT or len(shas) != len(set(shas)):
        raise ValueError(f"expected {EXPECTED_SELECTED_COUNT} unique candidates")
    return selected


def _packetize(
    candidates: list[Mapping[str, object]], packet_size: int
) -> list[list[Mapping[str, object]]]:
    if packet_size < 1:
        raise ValueError("packet size must be positive")
    return [
        candidates[offset : offset + packet_size]
        for offset in range(0, len(candidates), packet_size)
    ]


def _filter_candidates(
    candidates: list[Mapping[str, object]], requested_shas: list[str]
) -> list[Mapping[str, object]]:
    if not requested_shas:
        return candidates
    requested = {value.lower() for value in requested_shas}
    malformed = sorted(value for value in requested if len(value) != 40)
    available = {str(row["sha"]): row for row in candidates}
    missing = sorted(requested - set(available))
    if malformed or missing:
        raise ValueError(
            f"candidate filter is invalid: malformed={malformed} missing={missing}"
        )
    return [row for row in candidates if str(row["sha"]) in requested]


def _bounded_diff(repository: Path, sha: str, limit: int) -> dict[str, object]:
    diff = _git(
        repository,
        [
            "show",
            "--format=commit %H%nparents: %P%nsubject: %s%nauthor: %an <%ae>%nbody:%n%B",
            "--no-ext-diff",
            "--no-renames",
            "--unified=5",
            sha,
        ],
    )
    truncated = len(diff) > limit
    return {
        "text": diff[:limit],
        "original_chars": len(diff),
        "truncated": truncated,
    }


def _global_index(candidates: list[Mapping[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "sha": row.get("sha"),
            "priority": row.get("priority"),
            "subject": row.get("subject"),
            "changed_files": row.get("changed_files", []),
            "evidence_contracts": row.get("evidence_contracts", []),
            "code_path_hits": row.get("code_path_hits", []),
            "context_path_hits": row.get("context_path_hits", []),
            "semantic_signal_hit": row.get("semantic_signal_hit"),
        }
        for row in candidates
    ]


def _build_prompt(
    repository: Path,
    inventory: Mapping[str, object],
    candidates: list[Mapping[str, object]],
    packet: list[Mapping[str, object]],
    *,
    packet_index: int,
    packet_count: int,
    review_selected_count: int,
    candidate_diff_chars: int,
) -> tuple[str, list[str]]:
    candidate_shas = [str(row["sha"]) for row in packet]
    evidence = {
        "advisory": ADVISORY,
        "affected_state": AFFECTED_SHA,
        "public_fix_member": FIX_MEMBER_SHA,
        "mechanism": (
            "A remote XML index supplied Package.subdir and Package.id. Those "
            "attributes formed Package.filename; _download_package joined it "
            "under download_dir and opened the result for writing without "
            "validating the XML components or enforcing containment."
        ),
        "fix": (
            "The fix rejects absolute/parent-traversing subdir and separator-bearing "
            "id values, then realpath-checks the final filepath before writing."
        ),
        "exact_transitions": inventory.get("exact_local_transitions", []),
        "packet": {
            "index": packet_index,
            "count": packet_count,
            "candidate_shas": candidate_shas,
        },
        "review_candidates": [
            {
                "sha": row["sha"],
                "priority": row.get("priority"),
                "subject": row.get("subject"),
                "changed_files": row.get("changed_files", []),
                "evidence_contracts": row.get("evidence_contracts", []),
                "exact_parent_to_candidate_diff": _bounded_diff(
                    repository, str(row["sha"]), candidate_diff_chars
                ),
            }
            for row in packet
        ],
        "global_affected_ai_candidate_index_without_diffs": _global_index(candidates),
        "inventory_boundary": {
            "global_affected_ai_candidate_count": len(candidates),
            "review_selected_candidate_count": review_selected_count,
            "finite_retained_commit_count": inventory.get("finite_inventory", {}).get(
                "retained_union_commit_count"
            )
            if isinstance(inventory.get("finite_inventory"), Mapping)
            else None,
            "hard_filter_count": 0,
            "negative_disposition": "RETAIN_NOT_DELETE",
        },
    }
    prompt = f"""\
Review every SHA in this packet exactly once for a causal contribution to the
specified XML-index arbitrary-file-write mechanism. A candidate outside
nltk/downloader.py can still be causal if its own delta activates the downloader,
changes the default remote index or download destination, adds a new runtime
caller/source/sink, removes a cross-file guard, or extends the vulnerable path.
Do not promote unrelated security work merely because it is security-sensitive.
When a diff is truncated and the missing part could settle causality, use
retain_insufficient. Put concrete multi-commit activation hypotheses in the
cross-file list. Model negatives have no exclusion authority.

## Frozen evidence
```json
{json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False)}
```

Return exactly this JSON schema:
{{
  "candidate_assessments": [
    {{
      "sha": "every packet SHA exactly once",
      "verdict": "promote_direct_introducer" | "promote_compositional_contributor" | "promote_path_extension" | "retain_possible" | "retain_insufficient" | "retain_unrelated",
      "causal_role": "one concise sentence",
      "reasoning": "tie the candidate's own changed lines to or away from the mechanism",
      "missing_evidence": ["zero or more concrete missing facts"]
    }}
  ],
  "cross_file_hypotheses": [
    {{
      "candidate_shas": ["one or more SHAs from the global 48-candidate index, including at least one packet SHA"],
      "status": "supported" | "possible" | "insufficient",
      "hypothesis": "specific activation or dependency chain",
      "evidence_needed": ["zero or more exact checks"]
    }}
  ],
  "summary": "packet-level recall-oriented conclusion"
}}
"""
    if len(SYSTEM_PROMPT) + len(prompt) > MAX_PROMPT_CHARS:
        raise ValueError("packet prompt exceeds the fail-closed character bound")
    return prompt, candidate_shas


def _strip_fence(text: str) -> str:
    value = text.strip()
    if value.startswith("```"):
        lines = value.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        value = "\n".join(lines).strip()
    return value


def _string_list(value: object, *, field: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{field} must be a string list")
    return value


def _parse_review(
    text: str,
    candidate_shas: list[str],
    global_shas: set[str],
) -> dict[str, object]:
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
    observed: list[str] = []
    for row in assessments:
        if not isinstance(row, dict) or set(row) != ASSESSMENT_KEYS:
            raise ValueError("candidate assessment keys are invalid")
        sha = str(row["sha"])
        verdict = str(row["verdict"])
        observed.append(sha)
        if sha not in expected or verdict not in VERDICTS:
            raise ValueError(f"candidate assessment is invalid: {sha}")
        if not isinstance(row["causal_role"], str) or not row["causal_role"].strip():
            raise ValueError(f"candidate causal_role is invalid: {sha}")
        if not isinstance(row["reasoning"], str) or not row["reasoning"].strip():
            raise ValueError(f"candidate reasoning is invalid: {sha}")
        _string_list(row["missing_evidence"], field="missing_evidence")
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ValueError("candidate assessment coverage is not exact")

    hypotheses = value["cross_file_hypotheses"]
    if not isinstance(hypotheses, list):
        raise ValueError("cross_file_hypotheses must be a list")
    for row in hypotheses:
        if not isinstance(row, dict) or set(row) != HYPOTHESIS_KEYS:
            raise ValueError("cross-file hypothesis keys are invalid")
        shas = _string_list(row["candidate_shas"], field="candidate_shas")
        if not shas or not set(shas) <= global_shas or not set(shas) & expected:
            raise ValueError("cross-file hypothesis candidate scope is invalid")
        if row["status"] not in HYPOTHESIS_STATUSES:
            raise ValueError("cross-file hypothesis status is invalid")
        if not isinstance(row["hypothesis"], str) or not row["hypothesis"].strip():
            raise ValueError("cross-file hypothesis text is invalid")
        _string_list(row["evidence_needed"], field="evidence_needed")
    if not isinstance(value["summary"], str) or not value["summary"].strip():
        raise ValueError("review summary is invalid")
    return value


def _review_packet(
    *,
    packet_index: int,
    prompt: str,
    candidate_shas: list[str],
    global_shas: set[str],
    api_base: str,
    api_key: str,
    model: str,
    reasoning_effort: str,
    max_output_tokens: int,
    timeout: float,
    contract_retries: int,
) -> dict[str, object]:
    attempts: list[dict[str, object]] = []
    for attempt_index in range(contract_retries + 1):
        try:
            response = _request_json(
                f"{api_base.rstrip('/')}/chat/completions",
                api_key,
                method="POST",
                body={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "reasoning_effort": reasoning_effort,
                    "max_tokens": max_output_tokens,
                },
                timeout=timeout,
            )
        except SystemExit as exc:
            attempts.append(
                {
                    "attempt_index": attempt_index,
                    "status": "transport_error",
                    "error": str(exc),
                }
            )
            continue
        attempt: dict[str, object] = {
            "attempt_index": attempt_index,
            "status": "parse_error",
            "observed_model": str(response.get("model") or ""),
            "usage": _usage(response),
            "response": response,
            "error": "",
        }
        try:
            review = _parse_review(
                _response_text(response), candidate_shas, global_shas
            )
        except ValueError as exc:
            attempt["error"] = str(exc)
            attempts.append(attempt)
            continue
        attempt["status"] = "completed"
        attempt["review"] = review
        attempts.append(attempt)
        return {
            "packet_index": packet_index,
            "candidate_shas": candidate_shas,
            "status": "completed",
            "attempts": attempts,
            "accepted_attempt_index": attempt_index,
            "review": review,
            "usage": attempt["usage"],
            "observed_model": attempt["observed_model"],
        }
    return {
        "packet_index": packet_index,
        "candidate_shas": candidate_shas,
        "status": "blocked",
        "attempts": attempts,
        "accepted_attempt_index": None,
        "review": {},
        "usage": {"input_tokens": 0, "output_tokens": 0},
        "observed_model": "",
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if (
        min(
            args.packet_size,
            args.candidate_diff_chars,
            args.max_output_tokens,
            args.workers,
        )
        < 1
    ):
        raise SystemExit("packet, diff, token, and worker bounds must be positive")
    if args.contract_retries < 0 or args.timeout <= 0:
        raise SystemExit("retry and timeout bounds are invalid")
    if not _loopback(args.api_base):
        raise SystemExit("NLTK AI review requires a loopback endpoint")
    repository = args.repository.resolve()
    if not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    try:
        inventory = _load_json(args.inventory)
        all_candidates = _selected_candidates(inventory)
        candidates = _filter_candidates(all_candidates, args.candidate_sha)
        packets = _packetize(candidates, args.packet_size)
        built = [
            _build_prompt(
                repository,
                inventory,
                all_candidates,
                packet,
                packet_index=index,
                packet_count=len(packets),
                review_selected_count=len(candidates),
                candidate_diff_chars=args.candidate_diff_chars,
            )
            for index, packet in enumerate(packets)
        ]
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    api_key = _api_key(args.api_key_env, args.api_key_config)
    _require_model(args.api_base, api_key, args.model, args.timeout)
    global_shas = {str(row["sha"]) for row in all_candidates}
    review_shas = {str(row["sha"]) for row in candidates}
    spec = {
        "schema_version": 1,
        "artifact_kind": "nltk_xml_path_ai_review",
        "inventory_sha256": hashlib.sha256(args.inventory.read_bytes()).hexdigest(),
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "packet_size": args.packet_size,
        "packet_count": len(packets),
        "global_affected_ai_candidate_count": len(all_candidates),
        "selected_candidate_count": len(candidates),
        "candidate_shas": sorted(review_shas),
        "candidate_sha_filter": sorted({value.lower() for value in args.candidate_sha}),
        "candidate_diff_chars": args.candidate_diff_chars,
        "max_output_tokens": args.max_output_tokens,
        "workers": args.workers,
        "contract_retries": args.contract_retries,
        "prompt_sha256s": [
            hashlib.sha256(prompt.encode()).hexdigest() for prompt, _shas in built
        ],
        "estimated_input_tokens_chars_div_4": sum(
            (len(SYSTEM_PROMPT) + len(prompt) + 3) // 4 for prompt, _shas in built
        ),
        "negative_disposition": "RETAIN_NOT_DELETE",
        "hard_filter_count": 0,
    }
    args.output_dir.mkdir(parents=True)
    _atomic_json(args.output_dir / "spec.json", spec)
    _atomic_json(
        args.output_dir / "prompts.json",
        [
            {
                "packet_index": index,
                "candidate_shas": candidate_shas,
                "system_prompt": SYSTEM_PROMPT,
                "user_prompt": prompt,
            }
            for index, (prompt, candidate_shas) in enumerate(built)
        ],
    )

    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                _review_packet,
                packet_index=index,
                prompt=prompt,
                candidate_shas=candidate_shas,
                global_shas=global_shas,
                api_base=args.api_base,
                api_key=api_key,
                model=args.model,
                reasoning_effort=args.reasoning_effort,
                max_output_tokens=args.max_output_tokens,
                timeout=args.timeout,
                contract_retries=args.contract_retries,
            ): index
            for index, (prompt, candidate_shas) in enumerate(built)
        }
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda row: int(row["packet_index"]))

    accepted_assessments: list[Mapping[str, object]] = []
    hypotheses: list[Mapping[str, object]] = []
    for result in results:
        review = result.get("review")
        if not isinstance(review, Mapping):
            continue
        rows = review.get("candidate_assessments")
        packet_hypotheses = review.get("cross_file_hypotheses")
        if isinstance(rows, list):
            accepted_assessments.extend(row for row in rows if isinstance(row, Mapping))
        if isinstance(packet_hypotheses, list):
            hypotheses.extend(
                row for row in packet_hypotheses if isinstance(row, Mapping)
            )
    accepted_shas = [str(row["sha"]) for row in accepted_assessments]
    blocked_shas = sorted(review_shas - set(accepted_shas))
    verdict_counts = Counter(str(row["verdict"]) for row in accepted_assessments)
    promoted_shas = sorted(
        str(row["sha"])
        for row in accepted_assessments
        if row.get("verdict") in PROMOTED_VERDICTS
    )
    usage = {
        key: sum(
            int(result.get("usage", {}).get(key, 0))
            for result in results
            if isinstance(result.get("usage"), Mapping)
        )
        for key in ("input_tokens", "output_tokens")
    }
    exact_coverage = (
        len(accepted_shas) == len(set(accepted_shas)) == len(review_shas)
        and set(accepted_shas) == review_shas
    )
    aggregate = {
        **spec,
        "result_status": "completed" if exact_coverage else "blocked",
        "completed_packet_count": sum(
            result.get("status") == "completed" for result in results
        ),
        "blocked_packet_count": sum(
            result.get("status") != "completed" for result in results
        ),
        "accepted_candidate_count": len(accepted_assessments),
        "blocked_candidate_shas": blocked_shas,
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "promoted_candidate_shas": promoted_shas,
        "cross_file_hypotheses": hypotheses,
        "usage": usage,
        "conservation": {
            "exact_candidate_coverage": exact_coverage,
            "all_candidates_retained": True,
            "negative_has_deletion_authority": False,
            "blocked_candidates_retained": True,
            "hard_filter_count": 0,
            "passed": exact_coverage,
        },
    }
    _atomic_json(args.output_dir / "packet_results.json", results)
    _atomic_json(args.output_dir / "aggregate.json", aggregate)
    print("NLTK affected-ancestor AI review complete")
    print(f"  model         : {args.model}")
    print(f"  effort        : {args.reasoning_effort}")
    print(f"  packets       : {len(packets)}")
    print(f"  exact coverage: {len(accepted_assessments)}/{len(candidates)}")
    print(f"  promoted      : {len(promoted_shas)}")
    print(f"  blocked       : {len(blocked_shas)}")
    print(f"  usage         : {usage}")
    print(f"  output        : {args.output_dir}")
    return 0 if exact_coverage else 2


if __name__ == "__main__":
    raise SystemExit(main())
