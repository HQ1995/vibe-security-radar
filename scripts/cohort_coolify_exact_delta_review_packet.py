#!/usr/bin/env python3
"""Freeze compact review packets for selected Coolify exact-delta edges.

Each packet proves only deterministic provenance and patch facts.  It samples
the exact candidate/fix hunks that contain reverse-delta lines so a semantic
reviewer can decide whether the transition is causal or incidental.  Packet
membership never changes the lossless source-owner universe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort_ai_descendant_preimage_overlay import (
    _assignment_counts,
    _repository_for_commit,
)
from cohort_coolify_fix_preimage_lineage import LineageEvidenceError
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _is_ancestor,
)
from cohort_coolify_preimage_exact_delta_bridge import (
    CommitDelta,
    _delta_matches,
    _inspect_commit_delta,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        action="append",
        required=True,
        help=(
            "Git checkout containing part or all of the frozen commit universe; "
            "repeat for non-nested clones"
        ),
    )
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--delta-bridge-dir", type=Path, required=True)
    parser.add_argument(
        "--edge",
        action="append",
        required=True,
        help="candidate-prefix:fix-prefix; repeat to preserve review order",
    )
    parser.add_argument("--context-lines", type=int, default=5)
    parser.add_argument("--max-paths", type=int, default=4)
    parser.add_argument("--max-hunks-per-patch", type=int, default=4)
    parser.add_argument("--max-patch-chars", type=int, default=8_000)
    parser.add_argument("--max-stat-chars", type=int, default=2_000)
    parser.add_argument("--max-focal-lines", type=int, default=8)
    parser.add_argument("--repo-timeout", type=int, default=120)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot load {path}: {exc}") from exc
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
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"row {line_number} is not an object")
                rows.append(value)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"cannot load {path}: {exc}") from exc
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_declared_repositories(
    bridge_summary: Mapping[str, object], repositories: Sequence[Path]
) -> None:
    """Require the packet to use the clone union frozen by the delta bridge."""

    declared = set(repositories)
    if len(declared) != len(repositories):
        raise ValueError("duplicate --repository clone")
    raw_configuration = bridge_summary.get("configuration")
    if raw_configuration is None:
        if len(repositories) != 1:
            raise ValueError(
                "legacy delta bridge has no frozen repository union; "
                "declare exactly one --repository"
            )
        return
    if not isinstance(raw_configuration, Mapping):
        raise ValueError("delta bridge configuration is malformed")
    raw_repositories = raw_configuration.get("repositories")
    if raw_repositories is None:
        if len(repositories) != 1:
            raise ValueError(
                "legacy delta bridge has no frozen repository union; "
                "declare exactly one --repository"
            )
        return
    if not isinstance(raw_repositories, list) or not all(
        isinstance(value, str) and value for value in raw_repositories
    ):
        raise ValueError("delta bridge repository union is malformed")
    expected = {Path(value).resolve() for value in raw_repositories}
    if len(expected) != len(raw_repositories):
        raise ValueError("delta bridge repository union contains duplicates")
    if declared != expected:
        missing = sorted(str(path) for path in expected - declared)
        extra = sorted(str(path) for path in declared - expected)
        raise ValueError(
            "declared repository clones disagree with delta bridge: "
            f"missing={missing}, extra={extra}"
        )


def _commit_repository_assignments_fail_open(
    repositories: Sequence[Path], shas: Sequence[str], *, timeout: int
) -> tuple[dict[str, Path], dict[str, str]]:
    """Assign every available commit and retain missing objects as retry evidence."""

    repository_by_sha: dict[str, Path] = {}
    errors: dict[str, str] = {}
    for sha in sorted(set(shas)):
        try:
            repository_by_sha[sha] = _repository_for_commit(
                repositories, sha, timeout=timeout
            )
        except LineageEvidenceError as exc:
            errors[sha] = str(exc)
    return repository_by_sha, errors


def _repository_for_pair(
    repositories: Sequence[Path], candidate_sha: str, fix_sha: str, *, timeout: int
) -> Path:
    """Return a clone containing both edge endpoints for the ancestry check."""

    errors: list[str] = []
    for repository in repositories:
        try:
            _git(
                repository,
                ["cat-file", "-e", f"{candidate_sha}^{{commit}}"],
                timeout=timeout,
            )
            _git(
                repository,
                ["cat-file", "-e", f"{fix_sha}^{{commit}}"],
                timeout=timeout,
            )
        except ValueError as exc:
            errors.append(f"{repository}: {exc}")
            continue
        return repository
    raise ValueError(
        "no declared clone contains both edge endpoints: " + "; ".join(errors)
    )


def _empty_delta(sha: str, error: str) -> CommitDelta:
    return CommitDelta(
        sha=sha,
        parents=(),
        compared_parents=(),
        additions=(),
        removals=(),
        coverage_gaps=(error,),
    )


def _git(repository: Path, arguments: Sequence[str], *, timeout: int) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"git {arguments[0]} failed: {exc}") from exc
    if completed.returncode != 0:
        reason = completed.stderr.strip().replace("\n", " ")
        raise ValueError(f"git {arguments[0]} failed: {reason[:500]}")
    return completed.stdout


def _parent(repository: Path, sha: str, *, timeout: int) -> str:
    return _git(repository, ["rev-parse", f"{sha}^1"], timeout=timeout).strip()


def _diff(
    repository: Path,
    parent: str,
    child: str,
    source_path: str,
    *,
    context_lines: int,
    timeout: int,
) -> str:
    return _git(
        repository,
        [
            "diff",
            f"--unified={context_lines}",
            "--no-color",
            "--no-ext-diff",
            parent,
            child,
            "--",
            source_path,
        ],
        timeout=timeout,
    )


def _diff_stat(
    repository: Path, parent: str, child: str, *, timeout: int
) -> str:
    return _git(
        repository,
        ["diff", "--stat", "--no-color", parent, child, "--"],
        timeout=timeout,
    ).strip()


def _bounded_text(value: str, *, max_chars: int) -> dict[str, object]:
    truncated = len(value) > max_chars
    excerpt = value[: max_chars - 1] + "…" if truncated else value
    return {
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "original_chars": len(value),
        "excerpt_truncated": truncated,
        "excerpt": excerpt,
    }


def _changed_line_hash(raw_line: str) -> str | None:
    if raw_line.startswith(("+++", "---")):
        return None
    if not raw_line.startswith(("+", "-")):
        return None
    return hashlib.sha256(raw_line[1:].encode("utf-8")).hexdigest()


def _selected_patch_hunks(
    patch: str,
    *,
    focal_hashes: set[str],
    max_hunks: int,
    max_chars: int,
) -> dict[str, object]:
    header: list[str] = []
    hunks: list[list[str]] = []
    current: list[str] | None = None
    for line in patch.splitlines():
        if line.startswith("@@"):
            current = [line]
            hunks.append(current)
        elif current is None:
            header.append(line)
        else:
            current.append(line)
    matched = [
        hunk
        for hunk in hunks
        if any(
            (digest := _changed_line_hash(line)) is not None
            and digest in focal_hashes
            for line in hunk
        )
    ]
    selected = matched[:max_hunks]
    text = "\n".join([*header, *(line for hunk in selected for line in hunk)])
    original_chars = len(text)
    truncated = len(matched) > len(selected) or original_chars > max_chars
    if original_chars > max_chars:
        text = text[: max_chars - 1] + "…"
    return {
        "patch_sha256": hashlib.sha256(patch.encode("utf-8")).hexdigest(),
        "total_hunk_count": len(hunks),
        "focal_hunk_count": len(matched),
        "included_focal_hunk_count": len(selected),
        "excerpt_truncated": truncated,
        "excerpt": text,
    }


def _resolve_edges(
    specifications: Sequence[str], rows: Sequence[Mapping[str, object]]
) -> list[Mapping[str, object]]:
    selected: list[Mapping[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for specification in specifications:
        if specification.count(":") != 1:
            raise ValueError(f"malformed --edge: {specification}")
        candidate_prefix, fix_prefix = specification.split(":", 1)
        if len(candidate_prefix) < 7 or len(fix_prefix) < 7:
            raise ValueError("edge prefixes must contain at least seven characters")
        matches = [
            row
            for row in rows
            if str(row.get("candidate_sha") or "").startswith(candidate_prefix)
            and str(row.get("fix_sha") or "").startswith(fix_prefix)
        ]
        if len(matches) != 1:
            raise ValueError(
                f"--edge {specification} resolved to {len(matches)} bridge rows"
            )
        row = matches[0]
        edge = (str(row["candidate_sha"]), str(row["fix_sha"]))
        if edge in seen:
            raise ValueError(f"duplicate --edge: {specification}")
        seen.add(edge)
        selected.append(row)
    return selected


def _path_order(matches: Sequence[Mapping[str, object]]) -> list[str]:
    counts: Counter[str] = Counter()
    control: set[str] = set()
    for row in matches:
        source_path = str(row.get("candidate_path") or "")
        if not source_path:
            continue
        counts[source_path] += 1
        if row.get("control_like") is True:
            control.add(source_path)
    return sorted(counts, key=lambda value: (value not in control, -counts[value], value))


def _case_packet(
    repositories: Sequence[Path],
    row: Mapping[str, object],
    *,
    repository_by_sha: Mapping[str, Path],
    repository_errors: Mapping[str, str],
    observed_ai_shas: set[str],
    context_lines: int,
    max_paths: int,
    max_hunks: int,
    max_patch_chars: int,
    max_stat_chars: int,
    max_focal_lines: int,
    timeout: int,
) -> dict[str, object]:
    candidate_sha = str(row["candidate_sha"])
    fix_sha = str(row["fix_sha"])
    candidate_repository = repository_by_sha.get(candidate_sha)
    fix_repository = repository_by_sha.get(fix_sha)
    inspection_errors: list[str] = []
    if candidate_repository is None:
        candidate_error = repository_errors.get(
            candidate_sha, "candidate commit has no repository assignment"
        )
        candidate_delta = _empty_delta(candidate_sha, candidate_error)
    else:
        candidate_delta = _inspect_commit_delta(
            candidate_repository,
            candidate_sha,
            compare_all_parents=True,
            timeout=timeout,
        )
    if fix_repository is None:
        fix_error = repository_errors.get(
            fix_sha, "fix commit has no repository assignment"
        )
        fix_delta = _empty_delta(fix_sha, fix_error)
    else:
        fix_delta = _inspect_commit_delta(
            fix_repository,
            fix_sha,
            compare_all_parents=False,
            timeout=timeout,
        )
    inspection_errors.extend(
        f"candidate delta: {error}" for error in candidate_delta.coverage_gaps
    )
    inspection_errors.extend(
        f"fix delta: {error}" for error in fix_delta.coverage_gaps
    )
    matches = [
        *_delta_matches(
            candidate_delta.additions,
            fix_delta.removals,
            direction="candidate_added_fix_removed",
        ),
        *_delta_matches(
            candidate_delta.removals,
            fix_delta.additions,
            direction="candidate_removed_fix_added",
        ),
    ]
    focal = [
        value
        for value in matches
        if value.get("match_kind") == "exact_same_path"
        and value.get("meaningful") is True
    ]
    candidate_parent = (
        candidate_delta.compared_parents[0]
        if candidate_delta.compared_parents
        else None
    )
    fix_parent = fix_delta.compared_parents[0] if fix_delta.compared_parents else None
    ordered_paths = _path_order(focal)
    selected_paths = ordered_paths[:max_paths]
    focal_hashes_by_path: dict[str, set[str]] = {
        source_path: {
            str(value["content_sha256"])
            for value in focal
            if value.get("candidate_path") == source_path
        }
        for source_path in selected_paths
    }
    path_packets: list[dict[str, object]] = []
    for source_path in selected_paths:
        if candidate_repository is None or candidate_parent is None:
            inspection_errors.append(
                f"candidate patch unavailable for {source_path}: missing object or parent"
            )
            continue
        if fix_repository is None or fix_parent is None:
            inspection_errors.append(
                f"fix patch unavailable for {source_path}: missing object or parent"
            )
            continue
        try:
            candidate_patch = _diff(
                candidate_repository,
                candidate_parent,
                candidate_sha,
                source_path,
                context_lines=context_lines,
                timeout=timeout,
            )
            fix_patch = _diff(
                fix_repository,
                fix_parent,
                fix_sha,
                source_path,
                context_lines=context_lines,
                timeout=timeout,
            )
        except ValueError as exc:
            inspection_errors.append(f"patch inspection failed for {source_path}: {exc}")
            continue
        focal_hashes = focal_hashes_by_path[source_path]
        path_packets.append(
            {
                "path": source_path,
                "focal_exact_line_count": len(focal_hashes),
                "candidate_patch": _selected_patch_hunks(
                    candidate_patch,
                    focal_hashes=focal_hashes,
                    max_hunks=max_hunks,
                    max_chars=max_patch_chars,
                ),
                "fix_patch": _selected_patch_hunks(
                    fix_patch,
                    focal_hashes=focal_hashes,
                    max_hunks=max_hunks,
                    max_chars=max_patch_chars,
                ),
            }
        )
    forward_count = sum(
        value.get("direction") == "candidate_added_fix_removed" for value in focal
    )
    reverse_count = sum(
        value.get("direction") == "candidate_removed_fix_added" for value in focal
    )

    ancestry_repository: Path | None = None
    candidate_is_ancestor = False
    if candidate_repository is not None and fix_repository is not None:
        try:
            ancestry_repository = _repository_for_pair(
                repositories, candidate_sha, fix_sha, timeout=timeout
            )
            candidate_is_ancestor = _is_ancestor(
                ancestry_repository, candidate_sha, fix_sha
            )
        except (ValueError, SystemExit) as exc:
            inspection_errors.append(f"ancestry inspection failed: {exc}")

    def metadata(
        repository: Path | None, sha: str, *, role: str
    ) -> dict[str, object] | None:
        if repository is None:
            return None
        try:
            return _commit_metadata(repository, sha)
        except (ValueError, SystemExit) as exc:
            inspection_errors.append(f"{role} metadata inspection failed: {exc}")
            return None

    def diff_stat(
        repository: Path | None,
        parent: str | None,
        sha: str,
        *,
        role: str,
    ) -> dict[str, object] | None:
        if repository is None or parent is None:
            return None
        try:
            return _bounded_text(
                _diff_stat(repository, parent, sha, timeout=timeout),
                max_chars=max_stat_chars,
            )
        except ValueError as exc:
            inspection_errors.append(f"{role} diff stat inspection failed: {exc}")
            return None

    candidate_metadata = metadata(
        candidate_repository, candidate_sha, role="candidate"
    )
    fix_metadata = metadata(fix_repository, fix_sha, role="fix")
    candidate_diff_stat = diff_stat(
        candidate_repository,
        candidate_parent,
        candidate_sha,
        role="candidate",
    )
    fix_diff_stat = diff_stat(
        fix_repository,
        fix_parent,
        fix_sha,
        role="fix",
    )
    checks = {
        "candidate_is_observed_ai": candidate_sha in observed_ai_shas,
        "bridge_edge_retained": row.get("retained") is True,
        "bridge_is_exact_same_path_tier": int(row.get("delta_bridge_tier", -1))
        == 0,
        "candidate_object_available": candidate_repository is not None,
        "fix_object_available": fix_repository is not None,
        "shared_ancestry_repository_available": ancestry_repository is not None,
        "candidate_is_ancestor_of_fix": candidate_is_ancestor,
        "candidate_delta_inspection_complete": not candidate_delta.coverage_gaps,
        "fix_delta_inspection_complete": not fix_delta.coverage_gaps,
        "case_artifact_inspection_complete": not inspection_errors,
        "meaningful_exact_same_path_reversal_present": bool(focal),
        "selected_patch_hunks_cover_focal_delta": bool(selected_paths)
        and len(path_packets) == len(selected_paths)
        and all(
            int(packet["candidate_patch"]["focal_hunk_count"]) > 0
            and int(packet["fix_patch"]["focal_hunk_count"]) > 0
            for packet in path_packets
        ),
    }
    focal_sample = sorted(
        focal,
        key=lambda value: (
            value.get("control_like") is not True,
            str(value.get("candidate_path") or ""),
            str(value.get("content_sha256") or ""),
        ),
    )[:max_focal_lines]
    return {
        "key": f"{candidate_sha[:12]}__{fix_sha[:12]}",
        "candidate_sha": candidate_sha,
        "fix_sha": fix_sha,
        "repository_coverage": {
            "candidate_repository": (
                str(candidate_repository) if candidate_repository is not None else None
            ),
            "fix_repository": str(fix_repository) if fix_repository is not None else None,
            "ancestry_repository": (
                str(ancestry_repository) if ancestry_repository is not None else None
            ),
            "inspection_errors": list(dict.fromkeys(inspection_errors)),
            "retry_required": bool(inspection_errors),
        },
        "candidate_metadata": candidate_metadata,
        "fix_metadata": fix_metadata,
        "candidate_parent_sha": candidate_parent,
        "fix_parent_sha": fix_parent,
        "candidate_diff_stat": candidate_diff_stat,
        "fix_diff_stat": fix_diff_stat,
        "bridge_class": row.get("delta_bridge_class"),
        "bridge_rank": row.get("delta_bridge_rank"),
        "source_priority_class": row.get("source_priority_class"),
        "source_pair_sha256": row.get("source_pair_sha256"),
        "exact_reversal_counts": {
            "candidate_added_fix_removed": forward_count,
            "candidate_removed_fix_added": reverse_count,
            "total": len(focal),
        },
        "focal_exact_delta_sample": focal_sample,
        "focal_exact_delta_sample_truncated": len(focal) > len(focal_sample),
        "path_packets": path_packets,
        "selected_path_count": len(selected_paths),
        "omitted_focal_path_count": len(ordered_paths) - len(selected_paths),
        "checks": checks,
        "passed": all(checks.values()),
    }


def build_packet(
    repository: Path | Sequence[Path],
    *,
    selected_rows: Sequence[Mapping[str, object]],
    observed_ai_shas: set[str],
    context_lines: int,
    max_paths: int,
    max_hunks: int,
    max_patch_chars: int,
    max_stat_chars: int,
    max_focal_lines: int,
    timeout: int,
) -> dict[str, object]:
    repositories = [repository] if isinstance(repository, Path) else list(repository)
    if not repositories:
        raise ValueError("at least one repository is required")
    candidate_shas = [str(row["candidate_sha"]) for row in selected_rows]
    fix_shas = [str(row["fix_sha"]) for row in selected_rows]
    repository_by_sha, repository_errors = (
        _commit_repository_assignments_fail_open(
            repositories,
            [*candidate_shas, *fix_shas],
            timeout=timeout,
        )
    )
    cases = [
        _case_packet(
            repositories,
            row,
            repository_by_sha=repository_by_sha,
            repository_errors=repository_errors,
            observed_ai_shas=observed_ai_shas,
            context_lines=context_lines,
            max_paths=max_paths,
            max_hunks=max_hunks,
            max_patch_chars=max_patch_chars,
            max_stat_chars=max_stat_chars,
            max_focal_lines=max_focal_lines,
            timeout=timeout,
        )
        for row in selected_rows
    ]
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_exact_delta_semantic_review_packet",
        "repository_identity": "github.com/coollabsio/coolify",
        "case_results": cases,
        "repository_coverage": {
            "declared_repositories": [str(path) for path in repositories],
            "candidate_repository_assignment_counts": _assignment_counts(
                {
                    sha: repository_by_sha[sha]
                    for sha in candidate_shas
                    if sha in repository_by_sha
                }
            ),
            "fix_repository_assignment_counts": _assignment_counts(
                {
                    sha: repository_by_sha[sha]
                    for sha in fix_shas
                    if sha in repository_by_sha
                }
            ),
            "commit_objects_missing_from_all_declared_clones": len(
                repository_errors
            ),
            "missing_commit_objects": [
                {"sha": sha, "error": repository_errors[sha]}
                for sha in sorted(repository_errors)
            ],
            "all_requested_edges_retained": len(cases) == len(selected_rows),
        },
        "summary": {
            "case_count": len(cases),
            "unique_candidate_count": len(
                {str(row["candidate_sha"]) for row in cases}
            ),
            "unique_fix_count": len({str(row["fix_sha"]) for row in cases}),
            "failed_case_count": sum(row["passed"] is not True for row in cases),
            "retry_required_case_count": sum(
                bool(row["repository_coverage"]["retry_required"])
                for row in cases
            ),
            "forward_exact_reversal_count": sum(
                int(row["exact_reversal_counts"]["candidate_added_fix_removed"])
                for row in cases
            ),
            "reverse_exact_reversal_count": sum(
                int(row["exact_reversal_counts"]["candidate_removed_fix_added"])
                for row in cases
            ),
        },
        "packet_passed": bool(cases) and all(row["passed"] is True for row in cases),
        "claim_boundary": (
            "The packet proves observed-AI membership, ancestry, retained bridge "
            "membership, and exact same-path reverse patch lines. It does not label "
            "causality: broad reverts, shared syntax, generated changes, and later "
            "refactors can still be incidental. Every negative model disposition "
            "must remain in the lossless review universe."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if min(
        args.context_lines,
        args.max_paths,
        args.max_hunks_per_patch,
        args.max_patch_chars,
        args.max_stat_chars,
        args.max_focal_lines,
        args.repo_timeout,
    ) < 1:
        raise SystemExit("packet limits must be positive")
    repositories = [path.resolve() for path in args.repository]
    for repository in repositories:
        if not repository.is_dir() or not (repository / ".git").exists():
            raise SystemExit(f"repository is not a Git checkout: {repository}")
    bridge_dir = args.delta_bridge_dir.resolve()
    bridge_summary_path = bridge_dir / "summary.json"
    bridge_pairs_path = bridge_dir / "delta_bridge_pairs.jsonl"
    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    bridge_summary = _load_json(bridge_summary_path)
    bridge_rows = _load_jsonl(bridge_pairs_path)
    ai_rows = _load_jsonl(ai_path)
    try:
        _validate_declared_repositories(bridge_summary, repositories)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if bridge_summary.get("all_source_owner_pairs_conserved") is not True:
        raise SystemExit("delta bridge is not lossless")
    expected_digest = (
        bridge_summary.get("output_artifacts", {})
        .get("delta_bridge_pairs", {})
        .get("sha256")
        if isinstance(bridge_summary.get("output_artifacts"), Mapping)
        else None
    )
    if expected_digest != _sha256(bridge_pairs_path):
        raise SystemExit("delta bridge pair checksum drift")
    try:
        selected_rows = _resolve_edges(args.edge, bridge_rows)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    observed_ai_shas = {str(row.get("sha") or "") for row in ai_rows}
    payload = build_packet(
        repositories,
        selected_rows=selected_rows,
        observed_ai_shas=observed_ai_shas,
        context_lines=args.context_lines,
        max_paths=args.max_paths,
        max_hunks=args.max_hunks_per_patch,
        max_patch_chars=args.max_patch_chars,
        max_stat_chars=args.max_stat_chars,
        max_focal_lines=args.max_focal_lines,
        timeout=args.repo_timeout,
    )
    payload["configuration"] = {
        "requested_edges": list(args.edge),
        "repositories": [str(repository) for repository in repositories],
        "candidate_repository_assignment_counts": payload[
            "repository_coverage"
        ]["candidate_repository_assignment_counts"],
        "fix_repository_assignment_counts": payload["repository_coverage"][
            "fix_repository_assignment_counts"
        ],
        "commit_objects_missing_from_all_declared_clones": payload[
            "repository_coverage"
        ]["commit_objects_missing_from_all_declared_clones"],
        "context_lines": args.context_lines,
        "max_paths": args.max_paths,
        "max_hunks_per_patch": args.max_hunks_per_patch,
        "max_patch_chars": args.max_patch_chars,
        "max_stat_chars": args.max_stat_chars,
        "max_focal_lines": args.max_focal_lines,
        "repo_timeout_seconds": args.repo_timeout,
    }
    payload["source_artifacts"] = {
        "ai_commits": {"path": str(ai_path), "sha256": _sha256(ai_path)},
        "delta_bridge_summary": {
            "path": str(bridge_summary_path),
            "sha256": _sha256(bridge_summary_path),
        },
        "delta_bridge_pairs": {
            "path": str(bridge_pairs_path),
            "sha256": _sha256(bridge_pairs_path),
        },
    }
    _atomic_json(args.output.resolve(), payload)
    print("Coolify exact-delta semantic review packet frozen")
    print(f"  cases          : {payload['summary']['case_count']}")
    print(f"  unique AI      : {payload['summary']['unique_candidate_count']}")
    print(f"  exact reversals: {payload['summary']['forward_exact_reversal_count']}")
    print(f"  retry required : {payload['summary']['retry_required_case_count']}")
    print(f"  output         : {args.output.resolve()}")
    if payload["packet_passed"] is not True:
        failed = [row["key"] for row in payload["case_results"] if not row["passed"]]
        print(f"  mechanical gaps: {failed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
