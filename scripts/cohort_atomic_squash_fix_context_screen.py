#!/usr/bin/env python3
"""Route same-file squash candidates with fix-context blame to real PR members."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import defaultdict
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from cohort.pull_refs import COHORT_PULL_NAMESPACE
from cohort.root_adjudication import canonical_sha256
from cohort_atomic_same_file_screen import _atomic_json, _atomic_jsonl, _jsonl
from cohort_origin_squash_expand import _squash_internal_fix_context


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--repositories", type=Path, required=True)
    parser.add_argument("--repo-timeout", type=int, default=120)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _repository_paths(path: Path) -> dict[str, Path]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise SystemExit("repositories must be a JSON array")
    result: dict[str, Path] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise SystemExit("repository row is malformed")
        identity = str(row.get("repository_identity") or "")
        repo = Path(str(row.get("repository_path") or ""))
        if not identity or not (repo / ".git").exists() or identity in result:
            raise SystemExit(f"invalid repository row: {identity}")
        result[identity] = repo
    return result


def _group_rows(
    rows: Iterable[Mapping[str, object]],
) -> dict[tuple[str, int, str], list[dict[str, object]]]:
    groups: defaultdict[tuple[str, int, str], list[dict[str, object]]] = defaultdict(list)
    for raw in rows:
        row = dict(raw)
        identity = str(row.get("repository_identity") or "")
        fix_sha = str(row.get("fix_sha") or "").lower()
        pr_number = row.get("relation_pr_number")
        candidate_sha = str(row.get("candidate_sha") or "").lower()
        if not identity or not fix_sha or not candidate_sha or not isinstance(pr_number, int):
            raise SystemExit("candidate row lacks repository, PR, candidate, or fix")
        groups[(identity, pr_number, fix_sha)].append(row)
    return dict(groups)


def _missing_objects(
    repo: Path, specs: set[str], *, timeout: int
) -> tuple[set[str], str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "--batch-check"],
            input="".join(f"{spec}\n" for spec in sorted(specs)),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return set(specs), f"{type(exc).__name__}:{exc}"
    if completed.returncode != 0:
        reason = str(completed.stderr or "git cat-file failed").strip()[:300]
        return set(specs), reason
    missing = {
        line.rsplit(" ", 1)[0]
        for line in completed.stdout.splitlines()
        if line.endswith(" missing")
    }
    return missing, ""


def _rows_with_evidence(
    rows: Iterable[Mapping[str, object]],
    evidence_by_sha: Mapping[str, list[dict[str, object]]],
) -> list[dict[str, object]]:
    matched: list[dict[str, object]] = []
    for raw in rows:
        row = dict(raw)
        evidence = evidence_by_sha.get(str(row["candidate_sha"]).lower(), [])
        if not evidence:
            continue
        qualities = sorted({str(item["match_quality"]) for item in evidence})
        row.update(
            {
                "squash_internal_fix_context": evidence,
                "fix_context_line_count": len(evidence),
                "fix_context_match_qualities": qualities,
                "exact_unambiguous_line_count": sum(
                    item["match_quality"] == "exact_line"
                    and int(item["match_ambiguity"]) == 1
                    for item in evidence
                ),
                "claim_boundary": (
                    "fix-context blame maps public-fix parent lines to this directly "
                    "AI-attributed PR member; mechanism review is still required"
                ),
            }
        )
        matched.append(row)
    return matched


def _refine_repository(
    identity: str,
    repo: Path,
    groups: list[tuple[tuple[str, int, str], list[dict[str, object]]]],
    *,
    timeout: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    specs = {
        spec
        for (_, pr_number, fix_sha), _ in groups
        for spec in (
            f"{fix_sha}^{{commit}}",
            f"{COHORT_PULL_NAMESPACE}/{pr_number}^{{commit}}",
        )
    }
    missing, reason = _missing_objects(repo, specs, timeout=timeout)
    matches: list[dict[str, object]] = []
    blocked: list[dict[str, object]] = []
    patch_cache: dict[str, str] = {}
    file_cache: dict[tuple[str, str], list[str]] = {}
    blame_cache: dict[tuple[int, str], list[dict[str, object]]] = {}
    for (_, pr_number, fix_sha), rows in groups:
        required = {
            f"{fix_sha}^{{commit}}",
            f"{COHORT_PULL_NAMESPACE}/{pr_number}^{{commit}}",
        }
        absent = sorted(required & missing)
        if absent:
            blocked.append(
                {
                    "repository_identity": identity,
                    "relation_pr_number": pr_number,
                    "fix_sha": fix_sha,
                    "candidate_row_count": len(rows),
                    "missing_objects": absent,
                    "reason": reason or "required git object is missing",
                }
            )
            continue
        mapped = _squash_internal_fix_context(
            repo,
            pr_number=pr_number,
            fix_sha=fix_sha,
            member_shas={str(row["candidate_sha"]).lower() for row in rows},
            timeout=timeout,
            patch_cache=patch_cache,
            file_cache=file_cache,
            blame_cache=blame_cache,
        )
        matches.extend(_rows_with_evidence(rows, mapped))
    return matches, blocked


def main() -> int:
    args = _parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if min(args.workers, args.repo_timeout) < 1:
        raise SystemExit("workers and repo-timeout must be positive")
    candidates = list(_jsonl(args.candidates))
    repositories = _repository_paths(args.repositories)
    grouped = _group_rows(candidates)
    by_repo: defaultdict[
        str, list[tuple[tuple[str, int, str], list[dict[str, object]]]]
    ] = defaultdict(list)
    for key, rows in grouped.items():
        by_repo[key[0]].append((key, rows))
    missing_repositories = sorted(set(by_repo) - set(repositories))
    if missing_repositories:
        raise SystemExit(f"candidate repositories are missing: {missing_repositories}")

    args.output_dir.mkdir(parents=True)
    matches: list[dict[str, object]] = []
    blocked: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                _refine_repository,
                identity,
                repositories[identity],
                groups,
                timeout=args.repo_timeout,
            ): identity
            for identity, groups in by_repo.items()
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            repo_matches, repo_blocked = future.result()
            matches.extend(repo_matches)
            blocked.extend(repo_blocked)
            print(
                f"[{completed}/{len(futures)}] {futures[future]} "
                f"matches={len(repo_matches)} blocked={len(repo_blocked)}",
                flush=True,
            )

    matches.sort(
        key=lambda row: (
            str(row["class_id"]),
            str(row["fix_sha"]),
            str(row["candidate_sha"]),
        )
    )
    blocked.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            int(row["relation_pr_number"]),
            str(row["fix_sha"]),
        )
    )
    _atomic_jsonl(args.output_dir / "matches.jsonl", matches)
    _atomic_jsonl(args.output_dir / "blocked.jsonl", blocked)
    summary = {
        "schema_version": 1,
        "artifact_kind": "atomic_squash_fix_context_member_screen",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "claim_boundary": (
            "positive routing evidence only; unmatched rows remain UNKNOWN and token-signature "
            "matches are not claim-grade without manual mechanism review"
        ),
        "input_candidate_count": len(candidates),
        "input_group_count": len(grouped),
        "repository_count": len(by_repo),
        "matched_candidate_count": len(matches),
        "matched_alias_class_count": len({str(row["class_id"]) for row in matches}),
        "exact_unambiguous_candidate_count": sum(
            int(row["exact_unambiguous_line_count"]) > 0 for row in matches
        ),
        "token_signature_only_candidate_count": sum(
            row["fix_context_match_qualities"] == ["token_signature_fail_open"]
            for row in matches
        ),
        "unmatched_candidate_count": len(candidates) - len(matches),
        "blocked_group_count": len(blocked),
        "candidates_sha256": canonical_sha256(candidates),
        "matches_sha256": canonical_sha256(matches),
        "blocked_sha256": canonical_sha256(blocked),
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
