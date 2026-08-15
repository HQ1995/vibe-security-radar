#!/usr/bin/env python3
"""Blindly route a frozen origin queue with one local CLIProxyAPI model."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx

from cohort.root_adjudication import canonical_sha256
from cohort_ai_routing_pilot import (
    SYSTEM_PROMPT,
    _changed_paths,
    _commit_view,
    _cross_file_security_bridge,
    _is_loopback_api_base,
    _parse_model_json,
    _usage_counts,
    _validate_response_provenance,
)
from cve_analyzer.llm_client import extract_response_text


DEFAULT_API_BASE = "http://127.0.0.1:8317/v1"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--reasoning-effort",
        choices=("low", "medium", "high", "model-controlled"),
        required=True,
    )
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--api-key-env", default="CLIPROXY_API_KEY")
    parser.add_argument("--max-candidates", type=int, default=100)
    parser.add_argument("--diff-chars", type=int, default=6000)
    parser.add_argument("--max-output-tokens", type=int, default=600)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _item_id(identity: str, fix_sha: str, candidate_sha: str) -> str:
    digest = hashlib.sha256(
        f"{identity}\0{fix_sha}\0{candidate_sha}".encode("utf-8")
    ).hexdigest()
    return f"origin-route-{digest}"


def _prompt(
    *,
    identity: str,
    advisory: str,
    candidate: Mapping[str, object],
    candidate_subject: str,
    candidate_date: str,
    candidate_diff: str,
    fix_subject: str,
    fix_date: str,
    fix_diff: str,
) -> str:
    return f"""\
Repository: {identity}
Advisory: {advisory}
Candidate priority rank: {candidate['priority_rank']}
Candidate structural signals: {', '.join(str(value) for value in candidate['signals'])}

## Earlier candidate commit
SHA: {candidate['sha']}
Date: {candidate_date}
Subject: {candidate_subject}
```diff
{candidate_diff}
```

## Later security-fix commit
SHA: {candidate['fix_sha']}
Date: {fix_date}
Subject: {fix_subject}
```diff
{fix_diff}
```

Does the later fix likely or possibly repair a defect introduced by the earlier
candidate? Treat added checks, caller-to-callee guards, middleware, validation,
and refactors as valid indirect mechanisms. Return JSON only with exactly:
{{"causality":"likely|possible|unlikely|insufficient","reason":"max 40 words"}}
"""


def _prepare_items(
    candidates: list[dict[str, object]],
    fixes: list[dict[str, object]],
    *,
    max_candidates: int,
    diff_chars: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    fix_index = {
        (
            str(row.get("advisory") or ""),
            str(row.get("repository_identity") or ""),
            str(row.get("fix_sha") or ""),
        ): row
        for row in fixes
    }
    selected = candidates[:max_candidates]
    items: list[dict[str, object]] = []
    prompts: list[dict[str, object]] = []
    fix_view_cache: dict[tuple[str, str], tuple[str, str, str, list[str]]] = {}
    for sequence, candidate in enumerate(selected, start=1):
        advisory = str(candidate.get("advisory") or "")
        identity = str(candidate.get("repository_identity") or "")
        fix_sha = str(candidate.get("fix_sha") or "")
        candidate_sha = str(candidate.get("sha") or "")
        fix_row = fix_index.get((advisory, identity, fix_sha))
        if fix_row is None or fix_row.get("status") != "RESOLVED":
            raise SystemExit("selected candidate has no resolved fix artifact")
        repo = Path(str(fix_row.get("repository_path") or ""))
        if not repo.is_dir():
            raise SystemExit(f"repository path unavailable for {identity}")
        cache_key = (str(repo), fix_sha)
        if cache_key not in fix_view_cache:
            fix_paths = _changed_paths(repo, fix_sha)
            fix_subject, fix_date, fix_diff = _commit_view(
                repo,
                fix_sha,
                diff_chars,
            )
            fix_view_cache[cache_key] = (
                fix_subject,
                fix_date,
                fix_diff,
                fix_paths,
            )
        fix_subject, fix_date, fix_diff, fix_paths = fix_view_cache[cache_key]
        candidate_paths = _changed_paths(repo, candidate_sha)
        shared_paths = sorted(set(candidate_paths) & set(fix_paths))
        bridge = _cross_file_security_bridge(
            repo,
            candidate_sha,
            fix_sha,
            candidate_paths,
            fix_paths,
            limit=max(100, min(3000, diff_chars // 2)),
        )
        candidate_priority_evidence: list[tuple[str, str]] = []
        fix_priority_evidence: list[tuple[str, str]] = []
        if bridge["applied"]:
            candidate_priority_evidence.append(
                ("Cross-file candidate evidence", str(bridge["candidate_evidence"]))
            )
            fix_priority_evidence.append(
                ("Cross-file fix evidence", str(bridge["fix_evidence"]))
            )
        candidate_subject, candidate_date, candidate_diff = _commit_view(
            repo,
            candidate_sha,
            diff_chars,
            priority_paths=shared_paths,
            priority_label="Candidate/fix shared-path candidate evidence",
            priority_evidence=candidate_priority_evidence,
        )
        if fix_priority_evidence or shared_paths:
            fix_subject, fix_date, fix_diff = _commit_view(
                repo,
                fix_sha,
                diff_chars,
                priority_paths=shared_paths,
                priority_label="Candidate/fix shared-path fix evidence",
                priority_evidence=fix_priority_evidence,
            )
        item_id = _item_id(identity, fix_sha, candidate_sha)
        item = {
            "item_id": item_id,
            "sequence": sequence,
            "advisory": advisory,
            "repository_identity": identity,
            "fix_sha": fix_sha,
            "candidate_sha": candidate_sha,
            "input_priority_rank": candidate["priority_rank"],
            "signals": candidate["signals"],
            "cross_file_security_bridge_applied": bridge["applied"],
        }
        items.append(item)
        prompts.append(
            {
                "item_id": item_id,
                "sequence": sequence,
                "system_prompt": SYSTEM_PROMPT,
                "user_prompt": _prompt(
                    identity=identity,
                    advisory=advisory,
                    candidate=candidate,
                    candidate_subject=candidate_subject,
                    candidate_date=candidate_date,
                    candidate_diff=candidate_diff,
                    fix_subject=fix_subject,
                    fix_date=fix_date,
                    fix_diff=fix_diff,
                ),
            }
        )
    return items, prompts


def _call_one(
    prompt: Mapping[str, object],
    *,
    api_base: str,
    api_key: str,
    model: str,
    reasoning_effort: str,
    max_output_tokens: int,
    timeout: float,
    responses_dir: Path,
) -> dict[str, object]:
    body: dict[str, object] = {
        "model": model,
        "messages": [
            {"role": "system", "content": str(prompt["system_prompt"])},
            {"role": "user", "content": str(prompt["user_prompt"])},
        ],
        "max_tokens": max_output_tokens,
    }
    if reasoning_effort != "model-controlled":
        body["reasoning_effort"] = reasoning_effort
    result: dict[str, object] = {
        "item_id": prompt["item_id"],
        "sequence": prompt["sequence"],
        "requested_model": model,
        "observed_model": "",
        "result_status": "transport_error",
        "causality": "",
        "reason": "",
        "finish_reason": "",
        "usage": {},
    }
    try:
        response = httpx.post(
            f"{api_base.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=timeout,
        )
        response.raise_for_status()
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise ValueError("response_too_large")
        raw = response.json()
        if not isinstance(raw, dict):
            raise ValueError("response_not_object")
        _atomic_json(responses_dir / f"{int(prompt['sequence']):03d}.json", raw)
        valid, reason, observed_model = _validate_response_provenance(
            raw,
            backend="cliproxyapi",
            requested_model=model,
        )
        result["observed_model"] = observed_model
        choices = raw.get("choices")
        if (
            isinstance(choices, list)
            and choices
            and isinstance(choices[0], Mapping)
        ):
            result["finish_reason"] = str(choices[0].get("finish_reason") or "")
        if not valid:
            result["result_status"] = "provenance_error"
            result["reason"] = reason
        else:
            status, causality, parsed_reason = _parse_model_json(
                extract_response_text(raw)
            )
            if status != "completed" and not parsed_reason:
                parsed_reason = (
                    "model_json_parse_failed:finish_reason="
                    f"{result['finish_reason'] or 'unknown'}"
                )
            result["result_status"] = status
            result["causality"] = causality
            result["reason"] = parsed_reason
        usage = raw.get("usage")
        if isinstance(usage, Mapping):
            input_tokens, output_tokens = _usage_counts(usage)
            result["usage"] = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reported_cost": str(raw.get("cost") or ""),
            }
    except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
        result["reason"] = f"{type(exc).__name__}:{str(exc)[:200]}"
    return result


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if min(
        args.max_candidates,
        args.diff_chars,
        args.max_output_tokens,
        args.workers,
    ) < 1:
        raise SystemExit("candidate, evidence, output, and worker bounds must be positive")
    if not _is_loopback_api_base(args.api_base):
        raise SystemExit("origin routing requires a loopback CLIProxyAPI endpoint")
    api_key = os.environ.get(args.api_key_env, "")
    if not api_key:
        raise SystemExit(f"API key environment is empty: {args.api_key_env}")
    summary = _load_json(args.generated_dir / "summary.json")
    candidates = _load_jsonl(args.generated_dir / "candidates.jsonl")
    fixes = _load_jsonl(args.generated_dir / "fixes.jsonl")
    if canonical_sha256(candidates) != summary.get("candidate_rows_sha256"):
        raise SystemExit("generated candidate digest mismatch")
    if canonical_sha256(fixes) != summary.get("fix_rows_sha256"):
        raise SystemExit("generated fix digest mismatch")
    candidates.sort(
        key=lambda row: (
            str(row.get("repository_identity") or ""),
            str(row.get("advisory") or ""),
            str(row.get("fix_sha") or ""),
            int(row.get("priority_rank") or 0),
        )
    )
    selected_count = min(args.max_candidates, len(candidates))
    items, prompts = _prepare_items(
        candidates,
        fixes,
        max_candidates=selected_count,
        diff_chars=args.diff_chars,
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    responses_dir = args.output_dir / "responses"
    responses_dir.mkdir(mode=0o700)
    _atomic_jsonl(args.output_dir / "items.jsonl", items)
    _atomic_jsonl(args.output_dir / "prompts.jsonl", prompts)
    spec = {
        "schema_version": 1,
        "artifact_kind": "recall_safe_origin_ai_route",
        "parent_generation_sha256": canonical_sha256(summary),
        "candidate_inventory_sha256": canonical_sha256(candidates),
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "api_endpoint_scope": "loopback",
        "max_candidates": args.max_candidates,
        "selected_candidate_count": selected_count,
        "total_candidate_count": len(candidates),
        "diff_chars": args.diff_chars,
        "max_output_tokens": args.max_output_tokens,
        "workers": args.workers,
        "items_sha256": canonical_sha256(items),
        "prompts_sha256": canonical_sha256(prompts),
        "negative_disposition": "DEFER_not_delete",
    }
    _atomic_json(args.output_dir / "spec.json", spec)

    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                _call_one,
                prompt,
                api_base=args.api_base,
                api_key=api_key,
                model=args.model,
                reasoning_effort=args.reasoning_effort,
                max_output_tokens=args.max_output_tokens,
                timeout=args.timeout,
                responses_dir=responses_dir,
            ): prompt
            for prompt in prompts
        }
        completed_count = 0
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed_count += 1
            print(
                f"  [{completed_count}/{len(prompts)}] "
                f"{result['result_status']} {result['causality']}",
                flush=True,
            )
    results.sort(key=lambda row: int(row["sequence"]))
    _atomic_jsonl(args.output_dir / "results.jsonl", results)
    result_index = {str(row["item_id"]): row for row in results}
    item_index = {str(row["item_id"]): row for row in items}
    routes: list[dict[str, object]] = []
    for candidate in candidates:
        item_id = _item_id(
            str(candidate["repository_identity"]),
            str(candidate["fix_sha"]),
            str(candidate["sha"]),
        )
        item = item_index.get(item_id)
        result = result_index.get(item_id)
        if item is None or result is None:
            disposition = "DEFER"
            reason = "outside_model_routing_budget"
            causality = ""
        elif result["result_status"] != "completed":
            disposition = "BLOCKED"
            reason = str(result["reason"])
            causality = str(result["causality"])
        else:
            causality = str(result["causality"])
            disposition = "PROMOTE" if causality in {"likely", "possible"} else "DEFER"
            reason = str(result["reason"])
        routes.append(
            {
                "repository_identity": candidate["repository_identity"],
                "advisory": candidate["advisory"],
                "fix_sha": candidate["fix_sha"],
                "candidate_sha": candidate["sha"],
                "input_priority_rank": candidate["priority_rank"],
                "model": args.model,
                "disposition": disposition,
                "causality": causality,
                "reason": reason,
                "retained": True,
            }
        )
    _atomic_jsonl(args.output_dir / "routes.jsonl", routes)
    input_tokens = sum(
        int(row.get("usage", {}).get("input_tokens", 0))
        for row in results
        if isinstance(row.get("usage"), Mapping)
    )
    output_tokens = sum(
        int(row.get("usage", {}).get("output_tokens", 0))
        for row in results
        if isinstance(row.get("usage"), Mapping)
    )
    execution = {
        "schema_version": 1,
        "artifact_kind": "recall_safe_origin_ai_route_execution",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "physical_model_calls": len(results),
        "parsed_count": sum(row["result_status"] == "completed" for row in results),
        "transport_or_parse_blocked_count": sum(
            row["result_status"] != "completed" for row in results
        ),
        "promoted_count": sum(row["disposition"] == "PROMOTE" for row in routes),
        "deferred_count": sum(row["disposition"] == "DEFER" for row in routes),
        "blocked_count": sum(row["disposition"] == "BLOCKED" for row in routes),
        "inventory_count": len(routes),
        "all_candidates_retained": all(row["retained"] is True for row in routes),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "known_marginal_cost_usd": "0",
        "cost_claim_boundary": (
            "CLIProxyAPI reported quota-backed local proxy usage; zero known "
            "marginal cost is not an upstream provider price claim."
        ),
        "results_sha256": canonical_sha256(results),
        "routes_sha256": canonical_sha256(routes),
    }
    _atomic_json(args.output_dir / "execution.json", execution)
    print("origin AI route frozen")
    print(f"  model      : {args.model}")
    print(f"  calls      : {len(results)}")
    print(f"  parsed     : {execution['parsed_count']}")
    print(f"  promoted   : {execution['promoted_count']}")
    print(f"  tokens     : {input_tokens:,} in / {output_tokens:,} out")
    print(f"  retained   : {execution['all_candidates_retained']}")
    print(f"  output     : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
