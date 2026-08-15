#!/usr/bin/env python3
"""Run an add-only independent review of the Transformers 0-day candidate lanes."""

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
FAMILY_VERDICTS = {"supported", "possible", "not_supported", "insufficient"}
HYPOTHESIS_STATUSES = {"supported", "possible", "insufficient"}
REVIEW_KEYS = {
    "candidate_assessments",
    "family_assessments",
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
FAMILY_KEYS = {"cve", "ai_involvement", "candidate_shas", "reasoning", "missing_evidence"}
HYPOTHESIS_KEYS = {"candidate_shas", "cves", "status", "hypothesis", "evidence_needed"}
MAX_PROMPT_CHARS = 1_500_000

SYSTEM_PROMPT = """\
You are an independent software-security and commit-provenance reviewer. False
negatives are costly. Review every supplied candidate and be alert to direct,
compositional, activation, and path-extension roles across files and commits.
Do not attribute an entire squash merge to AI merely because one member has an
AI trailer: direct AI authorship applies only to candidates explicitly marked
source_attributed. A candidate without direct AI signal can still be a human
activation/path partner, but not an AI-authored root. Negative judgments have
no deletion authority: use retain_unrelated or retain_insufficient and leave the
candidate retained. Public 0-day descriptions may omit exact causal lines, so
prefer insufficient over an unsupported confident negative. Return only the
requested JSON object.
"""

PROBE_SPECS: tuple[dict[str, str], ...] = (
    {
        "cve": "CVE-2025-14920",
        "revision": "9c8bd3fc1befe54f3efb9f385561eef49f060a70",
        "path": "src/transformers/models/perceiver/convert_perceiver_haiku_to_pytorch.py",
        "marker": "checkpoint = pickle.loads(f.read())",
        "relation": "unsafe_deserialization_anchor_at_cna_affected_commit",
    },
    {
        "cve": "CVE-2025-14921",
        "revision": "9c8bd3fc1befe54f3efb9f385561eef49f060a70",
        "path": (
            "src/transformers/models/deprecated/transfo_xl/"
            "convert_transfo_xl_original_tf_checkpoint_to_pytorch.py"
        ),
        "marker": 'corpus = pickle.load(fp, encoding="latin1")',
        "relation": "unsafe_deserialization_anchor_at_cna_affected_commit",
    },
    {
        "cve": "CVE-2025-14924",
        "revision": "95faabf0a6cd845f4c5548697e288a79e424b096",
        "path": "src/transformers/models/megatron_gpt2/convert_megatron_gpt2_checkpoint.py",
        "marker": (
            "input_state_dict = torch.load(args.path_to_checkpoint, "
            'map_location="cpu", weights_only=False)'
        ),
        "relation": "unsafe_deserialization_anchor_at_cna_affected_commit",
    },
    {
        "cve": "CVE-2025-14926",
        "revision": "2ccc6cae21faaf11631efa5fb9054687ae5dc931",
        "path": "src/transformers/models/sew/convert_sew_original_pytorch_checkpoint_to_pytorch.py",
        "marker": "conv_layers = eval(fs_config.conv_feature_layers)",
        "relation": (
            "unsafe_eval_anchor_at_v4.57.0_branch_squash; resolved v4.57.0 "
            "tag lacks this converter, so exact CNA mapping remains blocked"
        ),
    },
    {
        "cve": "CVE-2025-14927",
        "revision": "2ccc6cae21faaf11631efa5fb9054687ae5dc931",
        "path": "src/transformers/models/sew_d/convert_sew_d_original_pytorch_checkpoint_to_pytorch.py",
        "marker": "conv_layers = eval(fs_config.conv_feature_layers)",
        "relation": (
            "unsafe_eval_anchor_at_v4.57.0_branch_squash; resolved v4.57.0 "
            "tag lacks this converter, so exact CNA mapping remains blocked"
        ),
    },
    {
        "cve": "CVE-2025-14928",
        "revision": "2ccc6cae21faaf11631efa5fb9054687ae5dc931",
        "path": (
            "src/transformers/models/hubert/"
            "convert_distilhubert_original_s3prl_checkpoint_to_pytorch.py"
        ),
        "marker": "conv_layers = eval(fs_config.extractor_conv_feature_layers)",
        "relation": (
            "unsafe_eval_anchor_at_v4.57.0_branch_squash; resolved v4.57.0 "
            "tag lacks this converter, so exact CNA mapping remains blocked"
        ),
    },
    {
        "cve": "CVE-2025-14929",
        "revision": "d1c6310d6a02481d48d81607cba7840be04580d1",
        "path": "src/transformers/models/x_clip/convert_x_clip_original_pytorch_to_hf.py",
        "marker": (
            'state_dict = torch.load(output, map_location="cpu", '
            'weights_only=True)["model"]'
        ),
        "relation": (
            "safe_weights_only_anchor_observed_at_cna_affected_commit; it is "
            "not asserted to be the undisclosed public flaw"
        ),
    },
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--reasoning-effort", choices=("low", "medium", "high"), required=True)
    parser.add_argument("--max-output-tokens", type=int, default=12_000)
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
            timeout=timeout,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git {' '.join(arguments)} failed: {exc}") from exc
    if completed.returncode != 0:
        raise SystemExit(f"git {' '.join(arguments)} failed: {completed.stderr[:500]}")
    return completed.stdout


def _commit_diff(repository: Path, sha: str, *, paths: list[str] | None = None) -> str:
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


def _commit_date(repository: Path, sha: str) -> str:
    return _git(repository, ["show", "-s", "--format=%aI", sha]).strip()


def _probe(repository: Path, spec: Mapping[str, str], source_shas: set[str]) -> dict[str, object]:
    source = _git(repository, ["show", f"{spec['revision']}:{spec['path']}"])
    lines = source.splitlines()
    matches = [index for index, line in enumerate(lines, start=1) if spec["marker"] in line]
    if len(matches) != 1:
        raise SystemExit(
            f"{spec['cve']}: expected one mechanism marker, observed {matches}"
        )
    line_number = matches[0]
    start = max(1, line_number - 5)
    end = min(len(lines), line_number + 5)
    excerpt = "\n".join(
        f"{number:04d}: {lines[number - 1]}" for number in range(start, end + 1)
    )
    blame = _git(
        repository,
        [
            "blame",
            "--line-porcelain",
            "-L",
            f"{line_number},{line_number}",
            spec["revision"],
            "--",
            spec["path"],
        ],
    )
    blame_lines = blame.splitlines()
    origin_sha = blame_lines[0].split()[0].lstrip("^")
    details: dict[str, str] = {}
    for line in blame_lines[1:]:
        key, separator, value = line.partition(" ")
        if separator and key in {"author", "author-mail", "author-time", "summary"}:
            details[key] = value
    return {
        **dict(spec),
        "line": line_number,
        "excerpt": excerpt,
        "line_origin_sha": origin_sha,
        "line_origin": details,
        "line_origin_is_source_attributed_candidate": origin_sha in source_shas,
    }


def _candidate_packet(
    repository: Path,
    row: Mapping[str, object],
    *,
    lane: str,
    diff_paths: list[str] | None = None,
) -> dict[str, object]:
    return {
        "sha": row.get("sha"),
        "lane": lane,
        "source_attributed": lane == "source_attributed",
        "source_matches": row.get("source_matches", []),
        "pr_number": row.get("pr_number"),
        "authored_at": row.get("authored_at"),
        "subject": row.get("subject"),
        "changed_files": row.get("changed_files"),
        "advisory_model_path_hits": row.get("advisory_model_path_hits", []),
        "diff_scope": diff_paths or ["ALL_CHANGED_PATHS"],
        "exact_diff": _commit_diff(repository, str(row["sha"]), paths=diff_paths),
    }


def _neutral_advisories(repository: Path, closure: Mapping[str, object]) -> list[dict[str, object]]:
    raw = closure.get("advisories")
    if not isinstance(raw, list):
        raise SystemExit("closure advisories are malformed")
    rows: list[dict[str, object]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise SystemExit("closure advisory row is malformed")
        resolved = str(item.get("resolved_affected_commit", ""))
        rows.append(
            {
                "cve": item.get("cve"),
                "title": item.get("title"),
                "description": item.get("description"),
                "affected_revision": item.get("affected_revision"),
                "resolved_affected_commit": resolved,
                "affected_commit_authored_at": _commit_date(repository, resolved),
                "model_path_prefixes": item.get("model_path_prefixes"),
                "model_path_presence_at_affected_revision": item.get(
                    "model_path_presence_at_affected_revision"
                ),
                "references": item.get("references"),
            }
        )
    return rows


def _build_prompt(
    repository: Path, closure: Mapping[str, object]
) -> tuple[str, list[str], list[str]]:
    member_rows = closure.get("member_candidates")
    noncarrier_rows = closure.get("noncarrier_observed_ai_candidates")
    if not isinstance(member_rows, list) or not isinstance(noncarrier_rows, list):
        raise SystemExit("closure candidate rows are malformed")
    source_rows = [
        row
        for row in [*member_rows, *noncarrier_rows]
        if isinstance(row, Mapping) and row.get("source_v3_ai_evidence") is True
    ]
    structural_rows = [
        row
        for row in member_rows
        if isinstance(row, Mapping)
        and row.get("source_v3_ai_evidence") is not True
        and bool(row.get("advisory_model_path_hits"))
    ]
    source_shas = {str(row["sha"]) for row in source_rows}
    structural_shas = {str(row["sha"]) for row in structural_rows}
    if source_shas & structural_shas:
        raise SystemExit("source and structural review lanes overlap")
    if len(source_shas) != 26 or len(structural_shas) != 6:
        raise SystemExit(
            f"unexpected review lane sizes: source={len(source_shas)} "
            f"structural={len(structural_shas)}"
        )
    advisories = _neutral_advisories(repository, closure)
    cves = sorted(str(row["cve"]) for row in advisories)
    prefixes_by_cve = {
        str(row["cve"]): [str(path) for path in row["model_path_prefixes"]]
        for row in advisories
        if isinstance(row.get("model_path_prefixes"), list)
    }
    candidates = [
        *(
            _candidate_packet(repository, row, lane="source_attributed")
            for row in sorted(source_rows, key=lambda item: str(item["sha"]))
        ),
        *(
            _candidate_packet(
                repository,
                row,
                lane="structural_path_partner_no_ai_signal",
                diff_paths=sorted(
                    {
                        prefix
                        for cve in row.get("advisory_model_path_hits", [])
                        for prefix in prefixes_by_cve.get(str(cve), [])
                    }
                ),
            )
            for row in sorted(structural_rows, key=lambda item: str(item["sha"]))
        ),
    ]
    probes = [_probe(repository, spec, source_shas) for spec in PROBE_SPECS]
    probes.append(
        {
            "cve": "CVE-2025-14930",
            "status": "NO_EXACT_LOCAL_MECHANISM_ANCHOR_SELECTED",
            "reason": (
                "The public description says GLM4 weight parsing, but the resolved "
                "v4.57.1 model-family paths contain no pickle.load or torch.load "
                "anchor. Treat causal mapping as insufficient, not negative."
            ),
        }
    )
    evidence = {
        "advisories": advisories,
        "mechanism_probes": probes,
        "review_candidates": candidates,
        "inventory_boundary": {
            "frozen_observed_ai_units": 26,
            "exact_squash_members_retained": 179,
            "source_attributed_atomic_candidates_reviewed": len(source_shas),
            "structural_path_partners_reviewed": len(structural_shas),
            "other_squash_members_still_retained_but_not_in_this_priority_packet": (
                179 - 7 - len(structural_shas)
            ),
            "hard_filter_count": 0,
        },
        "authorship_boundary": (
            "Only source_attributed candidates have direct AI evidence. Structural "
            "path partners have no direct AI signal and cannot become AI-authored "
            "roots merely because they shared a squash PR with one attributed member."
        ),
    }
    prompt = f"""\
Review the complete 32-item priority packet against all eight advisory families.
Assess every SHA exactly once. Look for direct introduction, compositional
dependencies, later activation, and vulnerable path extension. The mechanism
probes are local observations, not a claim that every probe is the exact
undisclosed 0-day line. A verdict beginning with retain never deletes a
candidate. If exact public mechanism evidence is missing, retain_insufficient is
preferred over a confident exclusion.

## Neutral evidence packet
```json
{json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False)}
```

Return exactly this JSON schema:
{{
  "candidate_assessments": [
    {{
      "sha": "one supplied SHA; every supplied SHA exactly once",
      "verdict": "promote_direct_introducer" | "promote_compositional_contributor" | "promote_path_extension" | "retain_possible" | "retain_insufficient" | "retain_unrelated",
      "related_cves": ["zero or more of the eight supplied CVEs"],
      "causal_role": "one concise sentence",
      "reasoning": "evidence-grounded explanation",
      "missing_evidence": ["zero or more concrete missing facts"]
    }}
  ],
  "family_assessments": [
    {{
      "cve": "each supplied CVE exactly once",
      "ai_involvement": "supported" | "possible" | "not_supported" | "insufficient",
      "candidate_shas": ["zero or more supplied SHAs"],
      "reasoning": "concise explanation",
      "missing_evidence": ["zero or more concrete missing facts"]
    }}
  ],
  "cross_file_hypotheses": [
    {{
      "candidate_shas": ["one or more supplied SHAs"],
      "cves": ["one or more supplied CVEs"],
      "status": "supported" | "possible" | "insufficient",
      "hypothesis": "the dependency or activation chain",
      "evidence_needed": ["zero or more concrete checks"]
    }}
  ],
  "missing_evidence": ["global evidence gaps"],
  "summary": "overall recall-oriented conclusion"
}}
"""
    if len(prompt) + len(SYSTEM_PROMPT) > MAX_PROMPT_CHARS:
        raise SystemExit("review prompt exceeds the fail-closed size bound")
    return prompt, sorted(source_shas | structural_shas), cves


def _strip_fence(text: str) -> str:
    value = text.strip()
    if value.startswith("```"):
        lines = value.splitlines()
        value = "\n".join(line for line in lines if not line.startswith("```")).strip()
    return value


def _string_list(value: object, *, field: str, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{field} must be a string list")
    if not allow_empty and not value:
        raise ValueError(f"{field} must not be empty")
    return value


def _parse_review(text: str, candidate_shas: list[str], cves: list[str]) -> dict[str, object]:
    try:
        value = json.loads(_strip_fence(text))
    except json.JSONDecodeError as exc:
        raise ValueError(f"review response is not JSON: {exc}") from exc
    if not isinstance(value, dict) or set(value) != REVIEW_KEYS:
        raise ValueError("review response keys are invalid")
    expected_shas = set(candidate_shas)
    expected_cves = set(cves)

    assessments = value["candidate_assessments"]
    if not isinstance(assessments, list):
        raise ValueError("candidate_assessments must be a list")
    observed_shas: list[str] = []
    for row in assessments:
        if not isinstance(row, dict) or set(row) != CANDIDATE_KEYS:
            raise ValueError("candidate assessment keys are invalid")
        sha = str(row["sha"])
        observed_shas.append(sha)
        if sha not in expected_shas or row["verdict"] not in VERDICTS:
            raise ValueError(f"candidate assessment is invalid: {sha}")
        related = _string_list(row["related_cves"], field="related_cves")
        if not set(related) <= expected_cves:
            raise ValueError(f"candidate has an unknown CVE: {sha}")
        if not isinstance(row["causal_role"], str) or not row["causal_role"].strip():
            raise ValueError(f"candidate causal_role is invalid: {sha}")
        if not isinstance(row["reasoning"], str) or not row["reasoning"].strip():
            raise ValueError(f"candidate reasoning is invalid: {sha}")
        _string_list(row["missing_evidence"], field="missing_evidence")
    if len(observed_shas) != len(set(observed_shas)) or set(observed_shas) != expected_shas:
        raise ValueError("candidate assessment coverage is not exact")

    families = value["family_assessments"]
    if not isinstance(families, list):
        raise ValueError("family_assessments must be a list")
    observed_cves: list[str] = []
    for row in families:
        if not isinstance(row, dict) or set(row) != FAMILY_KEYS:
            raise ValueError("family assessment keys are invalid")
        cve = str(row["cve"])
        observed_cves.append(cve)
        if cve not in expected_cves or row["ai_involvement"] not in FAMILY_VERDICTS:
            raise ValueError(f"family assessment is invalid: {cve}")
        shas = _string_list(row["candidate_shas"], field="candidate_shas")
        if not set(shas) <= expected_shas:
            raise ValueError(f"family assessment has an unknown SHA: {cve}")
        if not isinstance(row["reasoning"], str) or not row["reasoning"].strip():
            raise ValueError(f"family reasoning is invalid: {cve}")
        _string_list(row["missing_evidence"], field="missing_evidence")
    if len(observed_cves) != len(set(observed_cves)) or set(observed_cves) != expected_cves:
        raise ValueError("family assessment coverage is not exact")

    hypotheses = value["cross_file_hypotheses"]
    if not isinstance(hypotheses, list):
        raise ValueError("cross_file_hypotheses must be a list")
    for row in hypotheses:
        if not isinstance(row, dict) or set(row) != HYPOTHESIS_KEYS:
            raise ValueError("cross-file hypothesis keys are invalid")
        shas = _string_list(row["candidate_shas"], field="candidate_shas", allow_empty=False)
        related = _string_list(row["cves"], field="cves", allow_empty=False)
        if not set(shas) <= expected_shas or not set(related) <= expected_cves:
            raise ValueError("cross-file hypothesis contains an unknown identity")
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
    if args.max_output_tokens < 1 or args.timeout <= 0:
        raise SystemExit("output-token and timeout bounds must be positive")
    if not _loopback(args.api_base):
        raise SystemExit("Transformers review requires a loopback CLIProxyAPI endpoint")
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    closure = _load_json(args.closure)
    if closure.get("artifact_kind") != "transformers_zeroday_squash_member_closure":
        raise SystemExit("unexpected closure artifact kind")
    squash = closure.get("squash_closure")
    conservation = closure.get("conservation")
    if not isinstance(squash, Mapping) or squash.get("status") != "RESOLVED":
        raise SystemExit("squash-member closure is not resolved")
    if not isinstance(conservation, Mapping) or conservation.get("hard_filter_count") != 0:
        raise SystemExit("candidate conservation did not pass")

    prompt, candidate_shas, cves = _build_prompt(repository, closure)
    api_key = _api_key(args.api_key_env, args.api_key_config)
    _require_model(args.api_base, api_key, args.model, args.timeout)
    closure_bytes = args.closure.read_bytes()
    spec = {
        "schema_version": 1,
        "artifact_kind": "transformers_zeroday_add_only_ai_review",
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "max_output_tokens": args.max_output_tokens,
        "closure_sha256": hashlib.sha256(closure_bytes).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "prompt_chars": len(prompt) + len(SYSTEM_PROMPT),
        "estimated_input_tokens_chars_div_4": (len(prompt) + len(SYSTEM_PROMPT) + 3) // 4,
        "candidate_count": len(candidate_shas),
        "advisory_count": len(cves),
        "candidate_shas": candidate_shas,
        "advisories": cves,
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
        "parse_error": "",
    }
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], Mapping):
        result["finish_reason"] = str(choices[0].get("finish_reason") or "")
    try:
        review = _parse_review(_response_text(response), candidate_shas, cves)
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

    print("Transformers add-only AI review complete")
    print(f"  model        : {args.model}")
    print(f"  effort       : {args.reasoning_effort}")
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
