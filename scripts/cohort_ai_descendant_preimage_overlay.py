#!/usr/bin/env python3
"""Recover observed-AI source owners for every scheduled repair root.

The all-graph census remains the recall floor.  This overlay inspects the
pre-fix state of selected direct-ancestry roots and promotes observed AI
commits that own deleted/replaced lines, enclosing method declarations, or
nearby insertion context.  It never treats missing blame evidence as a
negative label and never removes a source census pair.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

from cohort_coolify_fix_preimage_lineage import (
    FixEvidence,
    LineageEvidenceError,
    _excerpt,
    _fix_evidence,
    _git_text,
    _path_kind,
)


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_ADJUDICATED_STATUSES = frozenset(
    {
        "CONFIRMED_TRUE_POSITIVE",
        "PATCH_EQUIVALENT_ALIAS",
        "REJECTED_NONCAUSAL",
    }
)
_TIER_NAMES = {
    0: "P0_DIRECT_RUNTIME_PREIMAGE_OWNER",
    1: "P1_GUARD_ENCLOSING_METHOD_OWNER",
    2: "P2_GUARD_NEARBY_CONTEXT_OWNER",
    3: "P3_RUNTIME_METHOD_OWNER",
    4: "P4_RUNTIME_NEARBY_CONTEXT_OWNER",
    5: "P5_NON_RUNTIME_SOURCE_OWNER",
}
_TIER_BONUS = {0: 1_200, 1: 950, 2: 700, 3: 500, 4: 260, 5: 80}


class PreimageOverlayError(ValueError):
    """The source census or preimage overlay contract is malformed."""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument(
        "--repository",
        type=Path,
        action="append",
        required=True,
        help=(
            "local clone participating in the census graph; repeat for every "
            "declared nonnested clone"
        ),
    )
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--root-lane",
        action="append",
        dest="root_lanes",
        help=(
            "process only this direct-root lane; repeat for multiple lanes "
            "(the default processes every direct root)"
        ),
    )
    parser.add_argument("--context-radius", type=int, default=12)
    parser.add_argument("--repo-timeout", type=int, default=120)
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="parallel read-only Git evidence workers (default: 1)",
    )
    parser.add_argument("--copy-aware", action="store_true")
    parser.add_argument(
        "--ignore-whitespace",
        action="store_true",
        help=(
            "run the much slower git blame -w mode; ordinary blame is the broad "
            "first-pass default and all unmatched pairs remain retained"
        ),
    )
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PreimageOverlayError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PreimageOverlayError(f"{path} must contain an object")
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
                    raise PreimageOverlayError(
                        f"{path}:{line_number} is not an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise PreimageOverlayError(f"cannot load {path}: {exc}") from exc
    return rows


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: object) -> None:
    _atomic_jsonl(path, [value], pretty=True)


def _atomic_jsonl(
    path: Path, rows: Iterable[object], *, pretty: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise PreimageOverlayError(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if pretty:
                materialized = list(rows)
                if len(materialized) != 1:
                    raise PreimageOverlayError("pretty output requires one value")
                json.dump(
                    materialized[0],
                    handle,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
                handle.write("\n")
            else:
                for row in rows:
                    handle.write(
                        json.dumps(
                            row,
                            sort_keys=True,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                    )
                    handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _decode_ancestors(
    root: Mapping[str, object], ai_shas: Sequence[str], bitset_width: int
) -> set[str]:
    encoded = str(root.get("ai_ancestor_bitset_hex") or "")
    if len(encoded) != bitset_width:
        raise PreimageOverlayError(
            f"root {root.get('sha')} has malformed ancestor bitset"
        )
    try:
        bits = int(encoded, 16)
    except ValueError as exc:
        raise PreimageOverlayError(
            f"root {root.get('sha')} has non-hex ancestor bitset"
        ) from exc
    expected = int(root.get("strict_ai_ancestor_count") or 0)
    if bits.bit_count() != expected:
        raise PreimageOverlayError(
            f"root {root.get('sha')} ancestor bit count mismatch"
        )
    result: set[str] = set()
    while bits:
        low_bit = bits & -bits
        index = low_bit.bit_length() - 1
        bits ^= low_bit
        if index >= len(ai_shas):
            raise PreimageOverlayError("ancestor bitset exceeds AI index")
        result.add(ai_shas[index])
    return result


def _ledger_state(
    ledger: Mapping[str, object],
) -> tuple[dict[tuple[str, str], str], set[str]]:
    raw_rows = ledger.get("edge_ledger")
    if not isinstance(raw_rows, list):
        raise PreimageOverlayError("ledger edge_ledger is malformed")
    status_by_edge: dict[tuple[str, str], str] = {}
    confirmed_candidates: set[str] = set()
    for row in raw_rows:
        if not isinstance(row, Mapping):
            raise PreimageOverlayError("ledger has non-object edge row")
        candidate = str(row.get("candidate_sha") or "")
        fix = str(row.get("fix_sha") or "")
        status = str(row.get("status") or "")
        status_by_edge[(candidate, fix)] = status
        if status == "CONFIRMED_TRUE_POSITIVE":
            confirmed_candidates.add(candidate)
    return status_by_edge, confirmed_candidates


def _repository_for_commit(
    repositories: Sequence[Path], sha: str, *, timeout: int
) -> Path:
    """Return the first declared clone containing an immutable commit object."""

    errors: list[str] = []
    for repository in repositories:
        try:
            _git_text(
                repository,
                ["cat-file", "-e", f"{sha}^{{commit}}"],
                timeout=timeout,
            )
        except LineageEvidenceError as exc:
            errors.append(f"{repository}: {exc}")
            continue
        return repository
    detail = "; ".join(errors)
    raise LineageEvidenceError(
        f"commit {sha} is missing from every declared clone: {detail}"
    )


def _commit_repository_assignments(
    repositories: Sequence[Path], shas: Sequence[str], *, timeout: int
) -> dict[str, Path]:
    return {
        sha: _repository_for_commit(repositories, sha, timeout=timeout)
        for sha in shas
    }


def _observed_ai_blame_cutoff(
    repository_by_sha: Mapping[str, Path], *, timeout: int
) -> str:
    """Return a boundary strictly older than every observed AI Git timestamp."""

    shas_by_repository: defaultdict[Path, list[str]] = defaultdict(list)
    for sha, repository in repository_by_sha.items():
        shas_by_repository[repository].append(sha)
    seen: set[str] = set()
    timestamps: list[datetime] = []
    for repository, shas in shas_by_repository.items():
        output = _git_text(
            repository,
            [
                "show",
                "--no-patch",
                "--no-walk=unsorted",
                "--format=%H%x09%aI%x09%cI",
                *shas,
            ],
            timeout=timeout,
        )
        for line in output.splitlines():
            if not line.strip():
                continue
            fields = line.split("\t")
            if len(fields) != 3 or not _FULL_SHA_RE.fullmatch(fields[0]):
                raise PreimageOverlayError("cannot parse observed-AI Git timestamps")
            seen.add(fields[0])
            try:
                timestamps.extend(
                    (datetime.fromisoformat(fields[1]), datetime.fromisoformat(fields[2]))
                )
            except ValueError as exc:
                raise PreimageOverlayError(
                    f"cannot parse Git timestamp for {fields[0]}"
                ) from exc
    if seen != set(repository_by_sha) or not timestamps:
        raise PreimageOverlayError("Git timestamp census disagrees with AI index")
    return (min(timestamps) - timedelta(days=1)).isoformat()


def _validate_declared_repositories(
    census_summary: Mapping[str, object], repositories: Sequence[Path]
) -> None:
    raw_coverage = census_summary.get("repository_clone_coverage")
    if raw_coverage is None:
        return
    if not isinstance(raw_coverage, list):
        raise PreimageOverlayError("repository_clone_coverage is malformed")
    expected: set[Path] = set()
    for row in raw_coverage:
        if not isinstance(row, Mapping) or not row.get("repository_path"):
            raise PreimageOverlayError("repository clone coverage row is malformed")
        expected.add(Path(str(row["repository_path"])).resolve())
    declared = set(repositories)
    if len(declared) != len(repositories):
        raise PreimageOverlayError("duplicate --repository clone")
    if declared != expected:
        missing = sorted(str(path) for path in expected - declared)
        extra = sorted(str(path) for path in declared - expected)
        raise PreimageOverlayError(
            f"declared repository clones disagree with census: "
            f"missing={missing}, extra={extra}"
        )


def _assignment_counts(repository_by_sha: Mapping[str, Path]) -> dict[str, int]:
    return dict(
        sorted(Counter(str(path) for path in repository_by_sha.values()).items())
    )


def _source_lines(
    evidence: FixEvidence,
    *,
    observed_ai_shas: set[str],
    strict_ancestor_shas: set[str],
) -> list[dict[str, object]]:
    """Return every observed-AI-owned evidence line, including anomalies."""

    rows: list[dict[str, object]] = []
    seen: set[tuple[str, int, str, int, str]] = set()
    for context in evidence.hunks:
        source_path = context.hunk.parent_path
        if source_path is None:
            continue
        line_groups = (
            ("direct_preimage", context.direct_lines),
            ("method_signature", context.method_signature_lines),
            ("nearby_context", context.nearby_lines),
        )
        for line_kind, line_numbers in line_groups:
            for blame_mode, blame_by_path in (
                ("file_local", evidence.local_blame),
                ("copy_aware", evidence.copy_blame),
            ):
                blame = blame_by_path.get(source_path, {})
                for line_number in line_numbers:
                    blamed = blame.get(line_number)
                    if blamed is None or blamed.sha not in observed_ai_shas:
                        continue
                    key = (
                        blamed.sha,
                        context.index,
                        line_kind,
                        line_number,
                        blame_mode,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append(
                        {
                            "candidate_sha": blamed.sha,
                            "source_relation": (
                                "strict_ai_ancestor"
                                if blamed.sha in strict_ancestor_shas
                                else "observed_ai_blame_outside_strict_ancestry"
                            ),
                            "hunk_index": context.index,
                            "path": source_path,
                            "path_kind": _path_kind(source_path),
                            "line": line_number,
                            "line_kind": line_kind,
                            "blame_mode": blame_mode,
                            "guard_like_hunk": context.hunk.is_guard_like,
                            "add_only_hunk": context.hunk.old_count == 0,
                            "content_sha256": hashlib.sha256(
                                blamed.content.encode("utf-8")
                            ).hexdigest(),
                            "content_excerpt": _excerpt(blamed.content),
                        }
                    )
    rows.sort(
        key=lambda row: (
            str(row["candidate_sha"]),
            int(row["hunk_index"]),
            str(row["line_kind"]),
            int(row["line"]),
            str(row["blame_mode"]),
        )
    )
    return rows


def _priority(evidence_rows: Sequence[Mapping[str, object]]) -> tuple[int, str]:
    runtime = [row for row in evidence_rows if row["path_kind"] == "runtime"]
    if any(row["line_kind"] == "direct_preimage" for row in runtime):
        tier = 0
    elif any(
        row["line_kind"] == "method_signature"
        and row["guard_like_hunk"] is True
        for row in runtime
    ):
        tier = 1
    elif any(
        row["line_kind"] == "nearby_context"
        and row["guard_like_hunk"] is True
        for row in runtime
    ):
        tier = 2
    elif any(row["line_kind"] == "method_signature" for row in runtime):
        tier = 3
    elif runtime:
        tier = 4
    else:
        tier = 5
    return tier, _TIER_NAMES[tier]


def _aggregate_pair(
    *,
    root: Mapping[str, object],
    candidate: Mapping[str, object],
    line_rows: list[dict[str, object]],
    source_relation: str,
    edge_status: str,
    candidate_already_confirmed: bool,
) -> dict[str, object]:
    tier, priority_class = _priority(line_rows)
    signal_counts = Counter(
        f"{row['line_kind']}_{row['blame_mode']}" for row in line_rows
    )
    score = int(root.get("review_score") or 0) + _TIER_BONUS[tier]
    score += min(len(line_rows), 20) * 4
    if not candidate_already_confirmed:
        score += 100
    if edge_status == "CONFIRMED_TRUE_POSITIVE":
        score -= 10_000
    elif edge_status == "REJECTED_NONCAUSAL":
        score -= 5_000
    candidate_subject = str(candidate.get("message") or "").split("\n", 1)[0]
    return {
        "candidate_sha": str(candidate.get("sha") or ""),
        "candidate_authored_at": candidate.get("authored_date"),
        "candidate_subject": candidate_subject,
        "fix_sha": str(root.get("sha") or ""),
        "fix_authored_at": root.get("authored_at"),
        "fix_subject": root.get("subject"),
        "fix_review_lane": root.get("review_lane"),
        "fix_review_signals": root.get("review_signals", []),
        "fix_strict_ai_ancestor_count": root.get("strict_ai_ancestor_count"),
        "source_relation": source_relation,
        "priority_tier": tier,
        "priority_class": priority_class,
        "review_priority_score": score,
        "lineage_signal_counts": dict(sorted(signal_counts.items())),
        "matched_line_evidence": line_rows,
        "ledger_edge_status": edge_status or "NEW_SOURCE_OWNER_EDGE",
        "candidate_already_confirmed_elsewhere": candidate_already_confirmed,
        "retained": True,
        "review_priority_rank": None,
    }


def build_preimage_overlay(
    *,
    census_summary: Mapping[str, object],
    ancestor_index: Mapping[str, object],
    commit_rows: list[dict[str, object]],
    ai_rows: list[dict[str, object]],
    ledger: Mapping[str, object],
    evidence_by_fix: Mapping[str, FixEvidence],
    evidence_errors: Mapping[str, str],
    selected_lanes: set[str] | None,
    split_id: str,
) -> dict[str, object]:
    raw_ai_shas = ancestor_index.get("ai_shas")
    if not isinstance(raw_ai_shas, list):
        raise PreimageOverlayError("AI ancestor index has no ai_shas")
    ai_shas = [str(value) for value in raw_ai_shas]
    ai_by_sha = {str(row.get("sha") or ""): row for row in ai_rows}
    if ai_shas != sorted(ai_by_sha):
        raise PreimageOverlayError("AI scan and ancestor index disagree")
    if any(not _FULL_SHA_RE.fullmatch(sha) for sha in ai_shas):
        raise PreimageOverlayError("AI index contains malformed SHA")
    bitset_width = int(ancestor_index.get("bitset_hex_width") or 0)
    if bitset_width != (len(ai_shas) + 3) // 4:
        raise PreimageOverlayError("AI ancestor bitset width is invalid")

    direct_roots = [
        row for row in commit_rows if row.get("route") == "direct_ai_ancestry"
    ]
    available_lanes = {str(row.get("review_lane") or "") for row in direct_roots}
    if selected_lanes is not None and not selected_lanes <= available_lanes:
        unknown = sorted(selected_lanes - available_lanes)
        raise PreimageOverlayError(f"unknown direct-root lanes: {unknown}")
    selected_roots = [
        row
        for row in direct_roots
        if selected_lanes is None
        or str(row.get("review_lane") or "") in selected_lanes
    ]
    selected_root_shas = {str(row.get("sha") or "") for row in selected_roots}
    provided_root_shas = set(evidence_by_fix) | set(evidence_errors)
    if provided_root_shas != selected_root_shas:
        raise PreimageOverlayError(
            "source evidence roots do not exactly match selected census roots"
        )

    status_by_edge, confirmed_candidates = _ledger_state(ledger)
    observed_ai_shas = set(ai_shas)
    direct_pair_count = 0
    selected_pair_count = 0
    source_pairs: list[dict[str, object]] = []
    anomaly_pairs: list[dict[str, object]] = []
    root_evidence: list[dict[str, object]] = []
    roots_with_strict_owner: set[str] = set()
    for root in direct_roots:
        ancestors = _decode_ancestors(root, ai_shas, bitset_width)
        direct_pair_count += len(ancestors)
        fix_sha = str(root.get("sha") or "")
        if fix_sha not in selected_root_shas:
            continue
        selected_pair_count += len(ancestors)
        if fix_sha in evidence_errors:
            root_evidence.append(
                {
                    "fix_sha": fix_sha,
                    "fix_review_lane": root.get("review_lane"),
                    "strict_ai_ancestor_count": len(ancestors),
                    "attribution_complete": False,
                    "coverage_gaps": [
                        {
                            "operation": "fix_preimage_evidence",
                            "reason": evidence_errors[fix_sha],
                        }
                    ],
                    "strict_source_owner_count": 0,
                    "outside_ancestry_owner_count": 0,
                    "retained_for_retry": True,
                }
            )
            continue

        evidence = evidence_by_fix[fix_sha]
        line_rows = _source_lines(
            evidence,
            observed_ai_shas=observed_ai_shas,
            strict_ancestor_shas=ancestors,
        )
        grouped: defaultdict[tuple[str, str], list[dict[str, object]]] = defaultdict(
            list
        )
        for line_row in line_rows:
            grouped[
                (str(line_row["candidate_sha"]), str(line_row["source_relation"]))
            ].append(line_row)
        strict_owner_count = 0
        outside_owner_count = 0
        for (candidate_sha, source_relation), matched_rows in grouped.items():
            pair = _aggregate_pair(
                root=root,
                candidate=ai_by_sha[candidate_sha],
                line_rows=matched_rows,
                source_relation=source_relation,
                edge_status=status_by_edge.get((candidate_sha, fix_sha), ""),
                candidate_already_confirmed=candidate_sha in confirmed_candidates,
            )
            if source_relation == "strict_ai_ancestor":
                source_pairs.append(pair)
                roots_with_strict_owner.add(fix_sha)
                strict_owner_count += 1
            else:
                anomaly_pairs.append(pair)
                outside_owner_count += 1
        root_evidence.append(
            {
                "fix_sha": fix_sha,
                "fix_review_lane": root.get("review_lane"),
                "strict_ai_ancestor_count": len(ancestors),
                "parent_sha": evidence.parent_sha,
                "hunk_count": len(evidence.hunks),
                "attribution_complete": not evidence.coverage_gaps,
                "coverage_gaps": list(evidence.coverage_gaps),
                "skipped_parent_entries": list(evidence.skipped_parent_entries),
                "strict_source_owner_count": strict_owner_count,
                "outside_ancestry_owner_count": outside_owner_count,
                "retained_for_retry": bool(evidence.coverage_gaps),
            }
        )

    expected_pair_count = int(census_summary.get("direct_ancestry_pair_count") or -1)
    if direct_pair_count != expected_pair_count:
        raise PreimageOverlayError(
            f"direct pair mismatch: {direct_pair_count} != {expected_pair_count}"
        )
    source_pairs.sort(
        key=lambda row: (
            -int(row["review_priority_score"]),
            str(row["fix_sha"]),
            str(row["candidate_sha"]),
        )
    )
    anomaly_pairs.sort(
        key=lambda row: (str(row["fix_sha"]), str(row["candidate_sha"]))
    )
    for rank, row in enumerate(source_pairs, start=1):
        row["review_priority_rank"] = rank

    unadjudicated = [
        row
        for row in source_pairs
        if str(row["ledger_edge_status"]) not in _ADJUDICATED_STATUSES
    ]
    best_by_candidate: dict[str, dict[str, object]] = {}
    for row in unadjudicated:
        best_by_candidate.setdefault(str(row["candidate_sha"]), row)
    candidate_frontier = [
        {**row, "frontier_kind": "best_source_owner_edge_per_ai_candidate"}
        for row in best_by_candidate.values()
    ]

    unique_source_pair_count = len(
        {(str(row["candidate_sha"]), str(row["fix_sha"])) for row in source_pairs}
    )
    if unique_source_pair_count != len(source_pairs):
        raise PreimageOverlayError("duplicate strict source-owner pair")
    processed_without_owner = selected_pair_count - unique_source_pair_count
    unprocessed_pair_count = direct_pair_count - selected_pair_count
    conservation_passed = (
        unique_source_pair_count
        + processed_without_owner
        + unprocessed_pair_count
        == direct_pair_count
        and processed_without_owner >= 0
        and unprocessed_pair_count >= 0
    )
    priority_counts = Counter(str(row["priority_class"]) for row in source_pairs)
    route_counts = census_summary.get("all_commit_route_counts", {})
    topology_fallback_count = (
        int(route_counts.get("nonancestral_topology_fallback", 0))
        if isinstance(route_counts, Mapping)
        else 0
    )
    summary = {
        "schema_version": 1,
        "artifact_kind": "ai_descendant_fix_preimage_source_owner_overlay",
        "split_id": split_id,
        "repository_identity": census_summary.get("repository_identity"),
        "selected_root_lanes": (
            sorted(selected_lanes) if selected_lanes is not None else ["ALL"]
        ),
        "source_direct_root_count": len(direct_roots),
        "processed_direct_root_count": len(selected_roots),
        "unprocessed_direct_root_count": len(direct_roots) - len(selected_roots),
        "source_direct_ancestry_pair_count": direct_pair_count,
        "processed_direct_ancestry_pair_count": selected_pair_count,
        "strict_source_owner_pair_count": unique_source_pair_count,
        "processed_pairs_without_source_owner_count": processed_without_owner,
        "unprocessed_direct_ancestry_pair_count": unprocessed_pair_count,
        "source_topology_fallback_root_count": topology_fallback_count,
        "roots_with_strict_source_owner_count": len(roots_with_strict_owner),
        "candidate_frontier_count": len(candidate_frontier),
        "unadjudicated_source_owner_edge_count": len(unadjudicated),
        "outside_strict_ancestry_source_owner_pair_count": len(anomaly_pairs),
        "priority_class_counts": dict(sorted(priority_counts.items())),
        "fixes_with_coverage_gaps": sum(
            not bool(row["attribution_complete"]) for row in root_evidence
        ),
        "all_source_pairs_conserved": conservation_passed,
        "hard_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "claim_boundary": (
            "Source ownership is deterministic scheduling evidence, not causal "
            "ground truth. Direct deleted-line ownership can be incidental, and "
            "method or nearby ownership is weaker. A missing owner never rejects "
            "an ancestor pair: processed residual pairs, unprocessed direct pairs, "
            "coverage-gap retries, and non-ancestral topology roots remain explicit."
        ),
    }
    if not conservation_passed:
        raise PreimageOverlayError("source-pair conservation failed")
    return {
        "summary": summary,
        "root_evidence": sorted(root_evidence, key=lambda row: str(row["fix_sha"])),
        "source_owner_pairs": source_pairs,
        "topology_anomalies": anomaly_pairs,
        "candidate_frontier": candidate_frontier,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.context_radius < 1 or args.workers < 1:
        raise SystemExit("--context-radius and --workers must be positive")
    repositories = [path.resolve() for path in args.repository]
    for repository in repositories:
        if not repository.is_dir() or not (repository / ".git").exists():
            raise SystemExit(f"repository is not a Git checkout: {repository}")
    census_dir = args.census_dir.resolve()
    ai_scan_dir = args.ai_scan_dir.resolve()
    summary_path = census_dir / "summary.json"
    index_path = census_dir / "ancestor_index.json"
    commits_path = census_dir / "all_commits.jsonl"
    ai_path = ai_scan_dir / "commits.jsonl"
    ledger_path = args.ledger.resolve()
    census_summary = _load_json(summary_path)
    ancestor_index = _load_json(index_path)
    commit_rows = _load_jsonl(commits_path)
    ai_rows = _load_jsonl(ai_path)
    ledger = _load_json(ledger_path)
    _validate_declared_repositories(census_summary, repositories)
    raw_ai_shas = ancestor_index.get("ai_shas")
    if not isinstance(raw_ai_shas, list):
        raise SystemExit("AI ancestor index has no ai_shas")
    ai_repository_by_sha = _commit_repository_assignments(
        repositories,
        [str(value) for value in raw_ai_shas],
        timeout=args.repo_timeout,
    )
    blame_since = _observed_ai_blame_cutoff(
        ai_repository_by_sha,
        timeout=args.repo_timeout,
    )
    selected_lanes = set(args.root_lanes) if args.root_lanes else None
    selected_roots = [
        row
        for row in commit_rows
        if row.get("route") == "direct_ai_ancestry"
        and (
            selected_lanes is None
            or str(row.get("review_lane") or "") in selected_lanes
        )
    ]
    if not selected_roots:
        raise SystemExit("no direct roots match --root-lane")

    root_repository_by_sha: dict[str, Path] = {}
    root_repository_errors: dict[str, str] = {}
    for root in selected_roots:
        fix_sha = str(root.get("sha") or "")
        try:
            root_repository_by_sha[fix_sha] = _repository_for_commit(
                repositories, fix_sha, timeout=args.repo_timeout
            )
        except LineageEvidenceError as exc:
            root_repository_errors[fix_sha] = str(exc)

    def inspect_root(root: Mapping[str, object]) -> tuple[str, FixEvidence | None, str]:
        fix_sha = str(root.get("sha") or "")
        if fix_sha in root_repository_errors:
            return fix_sha, None, root_repository_errors[fix_sha]
        repository = root_repository_by_sha[fix_sha]
        try:
            return (
                fix_sha,
                _fix_evidence(
                    repository,
                    fix_sha,
                    context_radius=args.context_radius,
                    copy_aware_enabled=args.copy_aware,
                    ignore_whitespace=args.ignore_whitespace,
                    blame_since=blame_since,
                    timeout=args.repo_timeout,
                ),
                "",
            )
        except LineageEvidenceError as exc:
            return fix_sha, None, str(exc)

    evidence_by_fix: dict[str, FixEvidence] = {}
    evidence_errors: dict[str, str] = {}
    total = len(selected_roots)
    if args.workers == 1:
        completed_results = map(inspect_root, selected_roots)
    else:
        executor = ThreadPoolExecutor(max_workers=args.workers)
        futures = [executor.submit(inspect_root, root) for root in selected_roots]
        completed_results = (future.result() for future in as_completed(futures))
    for index, (fix_sha, evidence, error) in enumerate(completed_results, start=1):
        if evidence is not None:
            evidence_by_fix[fix_sha] = evidence
        else:
            evidence_errors[fix_sha] = error
        if index % 25 == 0 or index == total:
            print(f"preimage roots inspected: {index}/{total}", flush=True)
    if args.workers > 1:
        executor.shutdown(wait=True)

    artifacts = build_preimage_overlay(
        census_summary=census_summary,
        ancestor_index=ancestor_index,
        commit_rows=commit_rows,
        ai_rows=ai_rows,
        ledger=ledger,
        evidence_by_fix=evidence_by_fix,
        evidence_errors=evidence_errors,
        selected_lanes=selected_lanes,
        split_id=args.split_id,
    )
    output_dir = args.output_dir.resolve()
    root_path = output_dir / "root_evidence.jsonl"
    pairs_path = output_dir / "source_owner_pairs.jsonl"
    anomaly_path = output_dir / "topology_anomalies.jsonl"
    frontier_path = output_dir / "candidate_frontier.jsonl"
    summary_output = output_dir / "summary.json"
    _atomic_jsonl(root_path, artifacts["root_evidence"])
    _atomic_jsonl(pairs_path, artifacts["source_owner_pairs"])
    _atomic_jsonl(anomaly_path, artifacts["topology_anomalies"])
    _atomic_jsonl(frontier_path, artifacts["candidate_frontier"])
    summary = dict(artifacts["summary"])
    summary["configuration"] = {
        "context_radius": args.context_radius,
        "copy_aware": args.copy_aware,
        "ignore_whitespace": args.ignore_whitespace,
        "workers": args.workers,
        "repositories": [str(repository) for repository in repositories],
        "observed_ai_repository_assignment_counts": _assignment_counts(
            ai_repository_by_sha
        ),
        "selected_root_repository_assignment_counts": _assignment_counts(
            root_repository_by_sha
        ),
        "selected_roots_missing_from_all_declared_clones": len(
            root_repository_errors
        ),
        "blame_since": blame_since,
        "blame_since_is_before_all_observed_ai_git_timestamps": True,
        "whitespace_transparent_retry_retained": not args.ignore_whitespace,
        "repository_timeout_seconds": args.repo_timeout,
    }
    summary["source_artifacts"] = {
        "census_summary": {"path": str(summary_path), "sha256": _sha256(summary_path)},
        "ancestor_index": {"path": str(index_path), "sha256": _sha256(index_path)},
        "all_commits": {"path": str(commits_path), "sha256": _sha256(commits_path)},
        "ai_commits": {"path": str(ai_path), "sha256": _sha256(ai_path)},
        "ledger": {"path": str(ledger_path), "sha256": _sha256(ledger_path)},
    }
    summary["output_artifacts"] = {
        "root_evidence": {"path": str(root_path), "sha256": _sha256(root_path)},
        "source_owner_pairs": {
            "path": str(pairs_path),
            "sha256": _sha256(pairs_path),
        },
        "topology_anomalies": {
            "path": str(anomaly_path),
            "sha256": _sha256(anomaly_path),
        },
        "candidate_frontier": {
            "path": str(frontier_path),
            "sha256": _sha256(frontier_path),
        },
    }
    _atomic_json(summary_output, summary)
    print("AI-descendant preimage source-owner overlay frozen")
    print(f"  processed roots : {summary['processed_direct_root_count']}")
    print(f"  source owners   : {summary['strict_source_owner_pair_count']}")
    print(f"  new review edges: {summary['unadjudicated_source_owner_edge_count']}")
    print(f"  coverage gaps   : {summary['fixes_with_coverage_gaps']}")
    print(f"  output          : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
