#!/usr/bin/env python3
"""Add all-parent exact-delta evidence to every topology-residual pair.

Every graph-incomparable pair remains retained.  Exact reverse deltas rank
candidate/fix transitions, while same-direction matches expose likely squash,
cherry-pick, or copy carriers without mislabeling them as repairs.  Git failures
are explicit retry evidence and never negative labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from cohort_coolify_preimage_exact_delta_bridge import (
    CommitDelta,
    DeltaLine,
    _control_like,
    _generated_path,
    _inspect_commit_delta,
    _meaningful,
)


_CLASS_BONUS = {
    "D0_BIDIRECTIONAL_EXACT_REVERSAL": 6_000,
    "D0_CANDIDATE_REMOVAL_EXACTLY_RESTORED": 5_300,
    "D0_CANDIDATE_ADDITION_EXACTLY_REMOVED": 5_000,
    "D1_WHITESPACE_NORMALIZED_REVERSAL": 3_200,
    "D2_EXACT_CROSS_PATH_REVERSAL": 2_200,
    "D3_SAME_DIRECTION_CARRIER_RELATION": 1_500,
    "D4_PATH_OVERLAP_ONLY_RETAINED": 400,
    "D5_TOPOLOGY_ONLY_RETAINED": 0,
}


class TopologyDeltaError(ValueError):
    """The topology residual or exact-delta conservation contract failed."""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--residual-overlap-dir", type=Path, required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--repo-timeout", type=int, default=120)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TopologyDeltaError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TopologyDeltaError(f"{path} must contain an object")
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
                    raise TopologyDeltaError(
                        f"{path}:{line_number} must contain an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise TopologyDeltaError(f"cannot load {path}: {exc}") from exc
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class _LineFact:
    parent_sha: str
    path: str
    content_sha256: str
    normalized_sha256: str
    normalized: str
    generated: bool


@dataclass(frozen=True)
class _LineIndex:
    exact: Mapping[tuple[str, str], _LineFact]
    normalized: Mapping[tuple[str, str], Mapping[str, _LineFact]]
    by_digest: Mapping[str, Mapping[str, _LineFact]]


@dataclass(frozen=True)
class _DeltaIndex:
    additions: _LineIndex
    removals: _LineIndex
    meaningful_keys: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class _MatchSummary:
    counts: Mapping[str, int]
    sample: tuple[Mapping[str, object], ...]
    sample_truncated: bool
    matched_left_keys: frozenset[tuple[str, str]]
    generated_count: int

    @property
    def total_count(self) -> int:
        return sum(self.counts.values())


def _index_lines(lines: Sequence[DeltaLine]) -> _LineIndex:
    exact: dict[tuple[str, str], _LineFact] = {}
    normalized: defaultdict[tuple[str, str], dict[str, _LineFact]] = defaultdict(
        dict
    )
    by_digest: defaultdict[str, dict[str, _LineFact]] = defaultdict(dict)
    for line in lines:
        if not _meaningful(line.content):
            continue
        content_sha256 = hashlib.sha256(line.content.encode("utf-8")).hexdigest()
        normalized_text = " ".join(line.content.strip().split())
        normalized_sha256 = hashlib.sha256(
            normalized_text.encode("utf-8")
        ).hexdigest()
        fact = _LineFact(
            parent_sha=line.parent_sha,
            path=line.path,
            content_sha256=content_sha256,
            normalized_sha256=normalized_sha256,
            normalized=normalized_text,
            generated=_generated_path(line.path),
        )
        exact.setdefault((line.path, content_sha256), fact)
        normalized[(line.path, normalized_sha256)].setdefault(content_sha256, fact)
        by_digest[content_sha256].setdefault(line.path, fact)
    return _LineIndex(
        exact=exact,
        normalized={key: dict(value) for key, value in normalized.items()},
        by_digest={key: dict(value) for key, value in by_digest.items()},
    )


def _index_delta(delta: CommitDelta) -> _DeltaIndex:
    additions = _index_lines(delta.additions)
    removals = _index_lines(delta.removals)
    return _DeltaIndex(
        additions=additions,
        removals=removals,
        meaningful_keys=frozenset(additions.exact) | frozenset(removals.exact),
    )


def _match_row(
    left: _LineFact,
    right: _LineFact,
    *,
    direction: str,
    match_kind: str,
) -> dict[str, object]:
    return {
        "direction": direction,
        "match_kind": match_kind,
        "candidate_parent_sha": left.parent_sha,
        "fix_parent_sha": right.parent_sha,
        "candidate_path": left.path,
        "fix_path": right.path,
        "content_sha256": left.content_sha256,
        "normalized_sha256": left.normalized_sha256,
        "content_excerpt": (
            left.normalized[:179] + "…"
            if len(left.normalized) > 180
            else left.normalized
        ),
        "meaningful": True,
        "control_like": _control_like(left.normalized),
        "generated_or_machine_artifact": left.generated or right.generated,
    }


def _match_indexes(
    left: _LineIndex,
    right: _LineIndex,
    *,
    direction: str,
    sample_limit: int = 12,
) -> _MatchSummary:
    counts: Counter[str] = Counter()
    sample: list[Mapping[str, object]] = []
    matched_left: set[tuple[str, str]] = set()
    generated_count = 0

    def record(left_fact: _LineFact, right_fact: _LineFact, kind: str) -> None:
        nonlocal generated_count
        counts[kind] += 1
        matched_left.add((left_fact.path, left_fact.content_sha256))
        if left_fact.generated or right_fact.generated:
            generated_count += 1
        if len(sample) < sample_limit:
            sample.append(
                _match_row(
                    left_fact,
                    right_fact,
                    direction=direction,
                    match_kind=kind,
                )
            )

    exact_keys = set(left.exact) & set(right.exact)
    for key in sorted(exact_keys):
        record(left.exact[key], right.exact[key], "exact_same_path")

    normalized_matched: set[tuple[str, str]] = set()
    normalized_keys = set(left.normalized) & set(right.normalized)
    for key in sorted(normalized_keys):
        left_by_digest = left.normalized[key]
        right_by_digest = right.normalized[key]
        unmatched_left = sorted(set(left_by_digest) - set(right_by_digest))
        if not unmatched_left:
            continue
        left_digest = unmatched_left[0]
        right_digest = next(
            (
                digest
                for digest in sorted(right_by_digest)
                if digest != left_digest
            ),
            "",
        )
        if not right_digest:
            continue
        left_fact = left_by_digest[left_digest]
        right_fact = right_by_digest[right_digest]
        record(left_fact, right_fact, "normalized_same_path")
        normalized_matched.add((left_fact.path, left_fact.content_sha256))

    common_digests = set(left.by_digest) & set(right.by_digest)
    for digest in sorted(common_digests):
        left_by_path = left.by_digest[digest]
        right_by_path = right.by_digest[digest]
        for left_path in sorted(set(left_by_path) - set(right_by_path)):
            left_fact = left_by_path[left_path]
            left_key = (left_path, digest)
            if left_key in normalized_matched:
                continue
            right_path = next(
                (path for path in sorted(right_by_path) if path != left_path), ""
            )
            if right_path:
                record(
                    left_fact,
                    right_by_path[right_path],
                    "exact_cross_path",
                )
    return _MatchSummary(
        counts=dict(counts),
        sample=tuple(sample),
        sample_truncated=sum(counts.values()) > len(sample),
        matched_left_keys=frozenset(matched_left),
        generated_count=generated_count,
    )


def _classify(
    *,
    forward: _MatchSummary,
    reverse: _MatchSummary,
    same_add: _MatchSummary,
    same_remove: _MatchSummary,
    path_overlap_count: int,
) -> str:
    forward_counts = forward.counts
    reverse_counts = reverse.counts
    exact_forward = forward_counts.get("exact_same_path", 0)
    exact_reverse = reverse_counts.get("exact_same_path", 0)
    if exact_forward and exact_reverse:
        return "D0_BIDIRECTIONAL_EXACT_REVERSAL"
    if exact_reverse:
        return "D0_CANDIDATE_REMOVAL_EXACTLY_RESTORED"
    if exact_forward:
        return "D0_CANDIDATE_ADDITION_EXACTLY_REMOVED"
    if (
        forward_counts.get("normalized_same_path", 0)
        or reverse_counts.get("normalized_same_path", 0)
    ):
        return "D1_WHITESPACE_NORMALIZED_REVERSAL"
    if (
        forward_counts.get("exact_cross_path", 0)
        or reverse_counts.get("exact_cross_path", 0)
    ):
        return "D2_EXACT_CROSS_PATH_REVERSAL"
    if (
        same_add.counts.get("exact_same_path", 0)
        or same_remove.counts.get("exact_same_path", 0)
        or same_add.counts.get("exact_cross_path", 0)
        or same_remove.counts.get("exact_cross_path", 0)
    ):
        return "D3_SAME_DIRECTION_CARRIER_RELATION"
    if path_overlap_count:
        return "D4_PATH_OVERLAP_ONLY_RETAINED"
    return "D5_TOPOLOGY_ONLY_RETAINED"


def _delta_summary(delta: CommitDelta) -> dict[str, object]:
    paths = {
        line.path for line in (*delta.additions, *delta.removals)
    } | set(delta.binary_paths)
    return {
        "parent_count": len(delta.parents),
        "compared_parent_count": len(delta.compared_parents),
        "changed_path_count": len(paths),
        "added_line_count": len(delta.additions),
        "removed_line_count": len(delta.removals),
        "binary_path_count": len(delta.binary_paths),
        "coverage_gaps": list(delta.coverage_gaps),
        "inspection_complete": not delta.coverage_gaps,
    }


def _pair_with_delta(
    pair: Mapping[str, object],
    *,
    candidate_delta: CommitDelta,
    fix_delta: CommitDelta,
    candidate_index: _DeltaIndex,
    fix_index: _DeltaIndex,
    candidate_summary: Mapping[str, object],
    fix_summary: Mapping[str, object],
) -> dict[str, object]:
    forward = _match_indexes(
        candidate_index.additions,
        fix_index.removals,
        direction="candidate_added_fix_removed",
    )
    reverse = _match_indexes(
        candidate_index.removals,
        fix_index.additions,
        direction="candidate_removed_fix_added",
    )
    same_add = _match_indexes(
        candidate_index.additions,
        fix_index.additions,
        direction="candidate_added_fix_added",
    )
    same_remove = _match_indexes(
        candidate_index.removals,
        fix_index.removals,
        direction="candidate_removed_fix_removed",
    )
    path_overlap_count = int(pair.get("exact_path_overlap_count") or 0)
    delta_class = _classify(
        forward=forward,
        reverse=reverse,
        same_add=same_add,
        same_remove=same_remove,
        path_overlap_count=path_overlap_count,
    )
    reversal_sample = [*forward.sample, *reverse.sample][:12]
    reversal_count = forward.total_count + reverse.total_count
    reversal_truncated = reversal_count > len(reversal_sample)
    carrier_sample = [*same_add.sample, *same_remove.sample][:12]
    carrier_count = same_add.total_count + same_remove.total_count
    carrier_truncated = carrier_count > len(carrier_sample)
    carrier_candidate_keys = (
        set(same_add.matched_left_keys) | set(same_remove.matched_left_keys)
    )
    carrier_coverage = (
        len(carrier_candidate_keys & candidate_index.meaningful_keys)
        / len(candidate_index.meaningful_keys)
        if candidate_index.meaningful_keys
        else 0.0
    )
    meaningful_reversal_count = reversal_count
    coverage_gaps = [
        *(f"candidate: {gap}" for gap in candidate_delta.coverage_gaps),
        *(f"fix: {gap}" for gap in fix_delta.coverage_gaps),
    ]
    score = int(pair.get("review_priority_score") or 0) + _CLASS_BONUS[delta_class]
    score += min(meaningful_reversal_count, 20) * 25
    score += min(len(carrier_candidate_keys), 20) * 8
    if coverage_gaps:
        score += 50
    return {
        **dict(pair),
        "delta_class": delta_class,
        "delta_review_priority_score": score,
        "meaningful_reversal_match_count": meaningful_reversal_count,
        "exact_same_path_reversal_match_count": (
            forward.counts.get("exact_same_path", 0)
            + reverse.counts.get("exact_same_path", 0)
        ),
        "normalized_same_path_reversal_match_count": (
            forward.counts.get("normalized_same_path", 0)
            + reverse.counts.get("normalized_same_path", 0)
        ),
        "exact_cross_path_reversal_match_count": (
            forward.counts.get("exact_cross_path", 0)
            + reverse.counts.get("exact_cross_path", 0)
        ),
        "reversal_match_sample": reversal_sample,
        "reversal_match_sample_truncated": reversal_truncated,
        "same_direction_carrier_match_count": carrier_count,
        "same_direction_candidate_change_coverage": carrier_coverage,
        "carrier_match_sample": carrier_sample,
        "carrier_match_sample_truncated": carrier_truncated,
        "generated_only_reversal": bool(meaningful_reversal_count)
        and forward.generated_count + reverse.generated_count
        == meaningful_reversal_count,
        "candidate_delta": dict(candidate_summary),
        "fix_delta": dict(fix_summary),
        "delta_coverage_gaps": coverage_gaps,
        "delta_inspection_complete": not coverage_gaps,
        "retained": True,
        "delta_review_priority_rank": None,
    }


def build_delta_overlay(
    *,
    overlap_summary: Mapping[str, object],
    pair_rows: Sequence[Mapping[str, object]],
    deltas: Mapping[str, CommitDelta],
    split_id: str,
) -> dict[str, object]:
    if overlap_summary.get("all_residual_pairs_conserved") is not True:
        raise TopologyDeltaError("residual overlap source is not conservative")
    if overlap_summary.get("hard_filter_count") != 0:
        raise TopologyDeltaError("residual overlap source filtered pairs")
    expected = int(overlap_summary.get("retained_residual_pair_count") or -1)
    if len(pair_rows) != expected:
        raise TopologyDeltaError("residual pair count drift")
    keys: set[tuple[str, str]] = set()
    output_rows: list[dict[str, object]] = []
    delta_indexes = {sha: _index_delta(delta) for sha, delta in deltas.items()}
    delta_summaries = {sha: _delta_summary(delta) for sha, delta in deltas.items()}
    for pair_index, pair in enumerate(pair_rows, start=1):
        candidate_sha = str(pair.get("candidate_sha") or "")
        fix_sha = str(pair.get("fix_sha") or "")
        key = (candidate_sha, fix_sha)
        if key in keys or candidate_sha not in deltas or fix_sha not in deltas:
            raise TopologyDeltaError("duplicate pair or missing delta evidence")
        keys.add(key)
        output_rows.append(
            _pair_with_delta(
                pair,
                candidate_delta=deltas[candidate_sha],
                fix_delta=deltas[fix_sha],
                candidate_index=delta_indexes[candidate_sha],
                fix_index=delta_indexes[fix_sha],
                candidate_summary=delta_summaries[candidate_sha],
                fix_summary=delta_summaries[fix_sha],
            )
        )
        if pair_index % 5_000 == 0 or pair_index == len(pair_rows):
            print(
                f"topology residual pairs matched: {pair_index}/{len(pair_rows)}",
                flush=True,
            )
    output_rows.sort(
        key=lambda row: (
            -int(row["delta_review_priority_score"]),
            str(row["fix_sha"]),
            str(row["candidate_sha"]),
        )
    )
    for rank, row in enumerate(output_rows, start=1):
        row["delta_review_priority_rank"] = rank
    exact_queue = [
        row
        for row in output_rows
        if str(row["delta_class"]).startswith(("D0_", "D1_", "D2_"))
    ]
    carrier_queue = [
        row
        for row in output_rows
        if row["delta_class"] == "D3_SAME_DIRECTION_CARRIER_RELATION"
    ]
    best_by_candidate: dict[str, dict[str, object]] = {}
    for row in output_rows:
        best_by_candidate.setdefault(str(row["candidate_sha"]), row)
    frontier = [
        {**row, "frontier_kind": "best_topology_delta_edge_per_ai_candidate"}
        for row in best_by_candidate.values()
    ]
    class_counts = Counter(str(row["delta_class"]) for row in output_rows)
    gap_commits = sorted(
        sha for sha, delta in deltas.items() if delta.coverage_gaps
    )
    summary = {
        "schema_version": 1,
        "artifact_kind": "observed_ai_topology_residual_exact_delta_overlay",
        "split_id": split_id,
        "repository_identity": overlap_summary.get("repository_identity"),
        "source_residual_pair_count": expected,
        "retained_residual_pair_count": len(output_rows),
        "unique_commit_delta_count": len(deltas),
        "delta_coverage_gap_commit_count": len(gap_commits),
        "delta_coverage_gap_commits": gap_commits,
        "exact_or_normalized_reversal_pair_count": len(exact_queue),
        "same_direction_carrier_relation_pair_count": len(carrier_queue),
        "candidate_frontier_count": len(frontier),
        "delta_class_counts": dict(sorted(class_counts.items())),
        "all_residual_pairs_conserved": len(output_rows) == expected,
        "hard_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "claim_boundary": (
            "Exact and normalized delta matches are deterministic scheduling "
            "evidence, not automatic causal labels. Same-direction matches denote "
            "possible squash, cherry-pick, or copy carriers and are not called fixes. "
            "Every residual pair and every Git inspection gap remains retained."
        ),
    }
    return {
        "summary": summary,
        "delta_pairs": output_rows,
        "exact_reversal_queue": exact_queue,
        "carrier_relation_queue": carrier_queue,
        "candidate_frontier": frontier,
    }


def _atomic_jsonl(
    path: Path, rows: Iterable[object], *, pretty: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise TopologyDeltaError(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if pretty:
                materialized = list(rows)
                if len(materialized) != 1:
                    raise TopologyDeltaError("pretty output requires one value")
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


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.workers < 1 or args.repo_timeout < 1:
        raise SystemExit("workers and repo-timeout must be positive")
    repository = args.repository.resolve()
    overlap_dir = args.residual_overlap_dir.resolve()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SystemExit(f"output directory already exists: {output_dir}")
    summary_path = overlap_dir / "summary.json"
    pairs_path = overlap_dir / "residual_pairs.jsonl"
    try:
        overlap_summary = _load_json(summary_path)
        pair_rows = _load_jsonl(pairs_path)
        unique_shas = sorted(
            {str(row.get("candidate_sha") or "") for row in pair_rows}
            | {str(row.get("fix_sha") or "") for row in pair_rows}
        )

        def inspect(sha: str) -> tuple[str, CommitDelta]:
            return sha, _inspect_commit_delta(
                repository,
                sha,
                compare_all_parents=True,
                timeout=args.repo_timeout,
            )

        deltas: dict[str, CommitDelta] = {}
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(inspect, sha) for sha in unique_shas]
            for index, future in enumerate(as_completed(futures), start=1):
                sha, delta = future.result()
                deltas[sha] = delta
                if index % 100 == 0 or index == len(unique_shas):
                    print(
                        f"topology delta commits inspected: {index}/{len(unique_shas)}",
                        flush=True,
                    )
        artifacts = build_delta_overlay(
            overlap_summary=overlap_summary,
            pair_rows=pair_rows,
            deltas=deltas,
            split_id=args.split_id,
        )
        delta_path = output_dir / "delta_pairs.jsonl"
        exact_path = output_dir / "exact_reversal_queue.jsonl"
        carrier_path = output_dir / "carrier_relation_queue.jsonl"
        frontier_path = output_dir / "candidate_frontier.jsonl"
        output_summary_path = output_dir / "summary.json"
        _atomic_jsonl(delta_path, artifacts["delta_pairs"])
        _atomic_jsonl(exact_path, artifacts["exact_reversal_queue"])
        _atomic_jsonl(carrier_path, artifacts["carrier_relation_queue"])
        _atomic_jsonl(frontier_path, artifacts["candidate_frontier"])
        summary = dict(artifacts["summary"])
        summary["configuration"] = {
            "candidate_parent_policy": "all_parents_union",
            "fix_parent_policy": "all_parents_union",
            "workers": args.workers,
            "repository_timeout_seconds": args.repo_timeout,
        }
        summary["source_artifacts"] = {
            "residual_overlap_summary": {
                "path": str(summary_path),
                "sha256": _sha256(summary_path),
            },
            "residual_pairs": {
                "path": str(pairs_path),
                "sha256": _sha256(pairs_path),
            },
        }
        summary["output_artifacts"] = {
            "delta_pairs": {"path": str(delta_path), "sha256": _sha256(delta_path)},
            "exact_reversal_queue": {
                "path": str(exact_path),
                "sha256": _sha256(exact_path),
            },
            "carrier_relation_queue": {
                "path": str(carrier_path),
                "sha256": _sha256(carrier_path),
            },
            "candidate_frontier": {
                "path": str(frontier_path),
                "sha256": _sha256(frontier_path),
            },
        }
        _atomic_jsonl(output_summary_path, [summary], pretty=True)
    except TopologyDeltaError as exc:
        raise SystemExit(f"topology exact delta failed: {exc}") from exc
    print("Observed-AI topology residual exact-delta overlay frozen")
    print(f"  retained pairs : {summary['retained_residual_pair_count']}")
    print(f"  reverse deltas : {summary['exact_or_normalized_reversal_pair_count']}")
    print(f"  carrier links  : {summary['same_direction_carrier_relation_pair_count']}")
    print(f"  coverage gaps  : {summary['delta_coverage_gap_commit_count']}")
    print(f"  output         : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
