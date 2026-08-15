#!/usr/bin/env python3
"""Deterministically repair schema-only gaps in a Transformers model review."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from cohort_churchcrm_compositional_ai_review import _atomic_json, _response_text
from cohort_transformers_zeroday_ai_review import (
    PROMOTED_VERDICTS,
    _parse_review,
    _strip_fence,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--review-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain one JSON object")
    return value


def _patch_id(repository: Path, sha: str) -> str:
    try:
        shown = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "show",
                "--format=",
                "--full-index",
                "--binary",
                sha,
            ],
            capture_output=True,
            check=False,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
            timeout=120,
        )
        patched = subprocess.run(
            ["git", "patch-id", "--stable"],
            input=shown.stdout,
            capture_output=True,
            check=False,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"cannot compute patch-id for {sha}: {exc}") from exc
    fields = patched.stdout.decode("utf-8", errors="strict").split()
    if shown.returncode != 0 or patched.returncode != 0 or not fields:
        return ""
    return fields[0]


def _repair_payload(
    raw: Mapping[str, object],
    *,
    candidate_shas: list[str],
    cves: list[str],
    patch_ids: Mapping[str, str],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    value = copy.deepcopy(dict(raw))
    assessments = value.get("candidate_assessments")
    if not isinstance(assessments, list) or not all(
        isinstance(row, dict) for row in assessments
    ):
        raise ValueError("candidate assessments are malformed")
    actions: list[dict[str, object]] = []
    observed: dict[str, dict[str, object]] = {}
    for row in assessments:
        assert isinstance(row, dict)
        sha = str(row.get("sha", ""))
        if sha in observed:
            raise ValueError(f"duplicate observed candidate: {sha}")
        observed[sha] = row
        if not str(row.get("causal_role", "")).strip():
            row["causal_role"] = (
                "No supported causal role in the supplied evidence; candidate remains retained."
            )
            actions.append(
                {
                    "action": "fill_empty_causal_role_from_existing_verdict",
                    "sha": sha,
                }
            )

    expected = set(candidate_shas)
    if not set(observed) <= expected:
        raise ValueError("review contains an unknown candidate")
    for missing_sha in sorted(expected - set(observed)):
        patch_id = patch_ids.get(missing_sha, "")
        if not patch_id:
            raise ValueError(f"missing candidate has no non-empty patch-id: {missing_sha}")
        equivalents = [
            row
            for sha, row in observed.items()
            if patch_ids.get(sha, "") == patch_id
        ]
        if len(equivalents) != 1:
            raise ValueError(
                f"missing candidate does not have one assessed patch equivalent: {missing_sha}"
            )
        source = equivalents[0]
        clone = copy.deepcopy(source)
        source_sha = str(source["sha"])
        clone["sha"] = missing_sha
        clone["reasoning"] = (
            f"Patch-equivalent to assessed candidate {source_sha}. "
            f"{source['reasoning']}"
        )
        assessments.append(clone)
        observed[missing_sha] = clone
        actions.append(
            {
                "action": "propagate_assessment_across_exact_stable_patch_id",
                "sha": missing_sha,
                "source_sha": source_sha,
                "patch_id": patch_id,
            }
        )

    assessments.sort(key=lambda row: str(row["sha"]))
    repaired = _parse_review(json.dumps(value), candidate_shas, cves)
    return repaired, actions


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    spec_path = args.review_dir / "spec.json"
    response_path = args.review_dir / "response.json"
    spec = _load_json(spec_path)
    response = _load_json(response_path)
    candidate_shas = spec.get("candidate_shas")
    cves = spec.get("advisories")
    if not isinstance(candidate_shas, list) or not all(
        isinstance(sha, str) for sha in candidate_shas
    ):
        raise SystemExit("review spec candidate list is malformed")
    if not isinstance(cves, list) or not all(isinstance(cve, str) for cve in cves):
        raise SystemExit("review spec advisory list is malformed")
    try:
        raw = json.loads(_strip_fence(_response_text(response)))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"model response has no repairable JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise SystemExit("model review is not an object")
    patch_ids = {sha: _patch_id(repository, sha) for sha in candidate_shas}
    try:
        review, actions = _repair_payload(
            raw,
            candidate_shas=candidate_shas,
            cves=cves,
            patch_ids=patch_ids,
        )
    except ValueError as exc:
        raise SystemExit(f"model review is not deterministically repairable: {exc}") from exc
    assessments = review["candidate_assessments"]
    assert isinstance(assessments, list)
    promoted = sorted(
        str(row["sha"])
        for row in assessments
        if isinstance(row, Mapping) and row.get("verdict") in PROMOTED_VERDICTS
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "transformers_zeroday_review_deterministic_repair",
        "source_spec_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
        "source_response_sha256": hashlib.sha256(response_path.read_bytes()).hexdigest(),
        "model": spec.get("model"),
        "reasoning_effort": spec.get("reasoning_effort"),
        "repair_actions": actions,
        "repair_action_count": len(actions),
        "exact_candidate_coverage": len(assessments),
        "verdict_counts": dict(
            sorted(Counter(str(row["verdict"]) for row in assessments).items())
        ),
        "promoted_candidate_shas": promoted,
        "negative_disposition": "RETAIN_NOT_DELETE",
        "review": review,
    }
    _atomic_json(args.output, payload)
    print("Transformers model review deterministically repaired")
    print(f"  actions       : {len(actions)}")
    print(f"  coverage      : {len(assessments)}/{len(candidate_shas)}")
    print(f"  promoted      : {len(promoted)}")
    print(f"  output        : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
