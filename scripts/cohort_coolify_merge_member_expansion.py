#!/usr/bin/env python3
"""Expand merge-carrier repair roots to a lossless member-level universe.

For every retained candidate->merge source edge, every commit reachable from
the merge's second parent but not its first parent is retained in a compressed
candidate/member Cartesian closure. Exact reverse lines are then attributed to
atomic members when possible; unmatched exact reversals remain explicit merge-
resolution leads. No member or source edge is removed by a heuristic or model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from cohort_coolify_fix_preimage_lineage import LineageEvidenceError, _git_text
from cohort_coolify_preimage_exact_delta_bridge import (
    CommitDelta,
    DeltaLine,
    _EMPTY_TREE_SHA,
    _atomic_json,
    _atomic_jsonl,
    _control_like,
    _generated_path,
    _inspect_commit_delta,
    _load_json,
    _load_jsonl,
    _meaningful,
    _parse_unified_patch,
    _revision_parents,
    _sha256,
)
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _commit_metadata,
)


class MergeMemberError(ValueError):
    """Merge-member expansion failed a provenance or conservation check."""


@dataclass(frozen=True)
class ExactLineFact:
    path: str
    content_sha256: str
    normalized: str
    control_like: bool
    generated: bool


@dataclass(frozen=True)
class ExactDeltaIndex:
    additions: Mapping[tuple[str, str], ExactLineFact]
    removals: Mapping[tuple[str, str], ExactLineFact]
    parent_count: int
    coverage_gaps: tuple[str, ...] = ()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--merge-bridge-dir", type=Path, required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--repo-timeout", type=int, default=180)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _fact(line: DeltaLine) -> ExactLineFact:
    return ExactLineFact(
        path=line.path,
        content_sha256=line.content_sha256,
        normalized=line.normalized,
        control_like=_control_like(line.content),
        generated=_generated_path(line.path),
    )


def _exact_index(delta: CommitDelta) -> ExactDeltaIndex:
    additions = {
        (line.path, line.content_sha256): _fact(line)
        for line in delta.additions
        if _meaningful(line.content)
    }
    removals = {
        (line.path, line.content_sha256): _fact(line)
        for line in delta.removals
        if _meaningful(line.content)
    }
    return ExactDeltaIndex(
        additions=additions,
        removals=removals,
        parent_count=len(delta.parents),
        coverage_gaps=delta.coverage_gaps,
    )


def _merge_members(
    repository: Path, merge_sha: str, *, timeout: int
) -> dict[str, object]:
    try:
        parents = _revision_parents(repository, merge_sha, timeout=timeout)
        if len(parents) != 2:
            raise LineageEvidenceError(
                f"expected two merge parents, observed {len(parents)}"
            )
        output = _git_text(
            repository,
            [
                "rev-list",
                "--reverse",
                "--topo-order",
                parents[1],
                f"^{parents[0]}",
            ],
            timeout=timeout,
        )
        members = [line.strip() for line in output.splitlines() if line.strip()]
        if len(set(members)) != len(members) or any(
            len(member) != 40 for member in members
        ):
            raise LineageEvidenceError("merge member range is malformed")
        return {
            "merge_sha": merge_sha,
            "first_parent_sha": parents[0],
            "second_parent_sha": parents[1],
            "member_shas": members,
            "member_count": len(members),
            "coverage_gaps": [],
            "range_complete": True,
        }
    except LineageEvidenceError as exc:
        return {
            "merge_sha": merge_sha,
            "first_parent_sha": None,
            "second_parent_sha": None,
            "member_shas": [],
            "member_count": 0,
            "coverage_gaps": [str(exc)],
            "range_complete": False,
        }


def _inspect_member_paths(
    repository: Path,
    sha: str,
    paths: Sequence[str],
    *,
    timeout: int,
) -> ExactDeltaIndex:
    try:
        parents = _revision_parents(repository, sha, timeout=timeout)
    except LineageEvidenceError as exc:
        return ExactDeltaIndex({}, {}, 0, (str(exc),))
    parent = parents[0] if parents else _EMPTY_TREE_SHA
    try:
        patch = _git_text(
            repository,
            [
                "-c",
                "core.quotePath=false",
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--find-renames",
                "--find-copies",
                parent,
                sha,
                "--",
                *paths,
            ],
            timeout=timeout,
        )
    except LineageEvidenceError as exc:
        return ExactDeltaIndex({}, {}, len(parents), (str(exc),))
    additions, removals, _ = _parse_unified_patch(patch, parent_sha=parent)
    return _exact_index(
        CommitDelta(
            sha=sha,
            parents=parents,
            compared_parents=(parent,),
            additions=additions,
            removals=removals,
        )
    )


def _exact_reversals(
    candidate: ExactDeltaIndex, merge_fix: ExactDeltaIndex
) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    return (
        set(candidate.additions) & set(merge_fix.removals),
        set(candidate.removals) & set(merge_fix.additions),
    )


def _line_sample(
    keys: set[tuple[str, str]], facts: Mapping[tuple[str, str], ExactLineFact]
) -> list[dict[str, object]]:
    return [
        {
            "path": key[0],
            "content_sha256": key[1],
            "content_excerpt": (
                facts[key].normalized[:179] + "…"
                if len(facts[key].normalized) > 180
                else facts[key].normalized
            ),
            "control_like": facts[key].control_like,
            "generated_or_machine_artifact": facts[key].generated,
        }
        for key in sorted(keys)[:24]
    ]


def build_merge_member_expansion(
    *,
    bridge_summary: Mapping[str, object],
    source_pairs: Sequence[Mapping[str, object]],
    member_inventory: Sequence[Mapping[str, object]],
    candidate_indexes: Mapping[str, ExactDeltaIndex],
    fix_indexes: Mapping[str, ExactDeltaIndex],
    member_indexes: Mapping[str, ExactDeltaIndex],
    member_metadata: Mapping[str, Mapping[str, object]],
    split_id: str,
) -> dict[str, object]:
    if bridge_summary.get("all_source_owner_pairs_conserved") is not True:
        raise MergeMemberError("merge bridge input is not lossless")
    if bridge_summary.get("hard_filter_count") != 0:
        raise MergeMemberError("merge bridge input used a hard filter")
    expected = int(bridge_summary.get("retained_delta_bridge_pair_count") or -1)
    if len(source_pairs) != expected:
        raise MergeMemberError("merge bridge pair count drift")
    inventory_by_merge = {
        str(row.get("merge_sha") or ""): row for row in member_inventory
    }
    expected_merges = {str(row.get("fix_sha") or "") for row in source_pairs}
    if set(inventory_by_merge) != expected_merges:
        raise MergeMemberError("member inventory does not cover every merge root")
    expected_candidates = {str(row.get("candidate_sha") or "") for row in source_pairs}
    if set(candidate_indexes) != expected_candidates or set(fix_indexes) != expected_merges:
        raise MergeMemberError("candidate/fix delta indexes are incomplete")

    ai_shas = sorted(expected_candidates)
    ai_index = {sha: index for index, sha in enumerate(ai_shas)}
    candidate_subjects: dict[str, object] = {}
    for row in source_pairs:
        candidate = str(row["candidate_sha"])
        subject = row.get("candidate_subject")
        if subject and candidate not in candidate_subjects:
            candidate_subjects[candidate] = subject
    width = (len(ai_shas) + 3) // 4
    member_candidate_bits: defaultdict[str, int] = defaultdict(int)
    member_carriers: defaultdict[str, set[str]] = defaultdict(set)
    member_incidence_count = 0
    for source_pair in source_pairs:
        candidate = str(source_pair["candidate_sha"])
        merge_sha = str(source_pair["fix_sha"])
        raw_members = inventory_by_merge[merge_sha].get("member_shas")
        if not isinstance(raw_members, list):
            raise MergeMemberError("member inventory row is malformed")
        bit = 1 << ai_index[candidate]
        member_incidence_count += len(raw_members)
        for raw_member in raw_members:
            member = str(raw_member)
            member_candidate_bits[member] |= bit
            member_carriers[member].add(merge_sha)

    edge_rows: list[dict[str, object]] = []
    exact_states: dict[tuple[str, str], dict[str, object]] = {}
    resolution_only_count = 0
    nonexact_count = 0
    for source_pair in source_pairs:
        candidate = str(source_pair["candidate_sha"])
        merge_sha = str(source_pair["fix_sha"])
        candidate_index = candidate_indexes[candidate]
        fix_index = fix_indexes[merge_sha]
        forward, restored = _exact_reversals(candidate_index, fix_index)
        raw_members = inventory_by_merge[merge_sha]["member_shas"]
        assert isinstance(raw_members, list)
        member_hits: list[dict[str, object]] = []
        for raw_member in raw_members:
            member = str(raw_member)
            member_index = member_indexes.get(member)
            if member_index is None:
                continue
            member_forward = forward & set(member_index.removals)
            member_restored = restored & set(member_index.additions)
            if not member_forward and not member_restored:
                continue
            member_hits.append(
                {
                    "member_sha": member,
                    "member_parent_count": member_index.parent_count,
                    "candidate_added_member_removed_count": len(member_forward),
                    "candidate_removed_member_restored_count": len(member_restored),
                    "exact_reversal_line_count": len(member_forward)
                    + len(member_restored),
                }
            )
            state = exact_states.setdefault(
                (candidate, member),
                {
                    "candidate_sha": candidate,
                    "member_sha": member,
                    "member_parent_count": member_index.parent_count,
                    "merge_carriers": set(),
                    "source_merge_edges": 0,
                    "forward_keys": set(),
                    "restored_keys": set(),
                    "best_source_score": 0,
                },
            )
            state["merge_carriers"].add(merge_sha)
            state["source_merge_edges"] = int(state["source_merge_edges"]) + 1
            state["forward_keys"].update(member_forward)
            state["restored_keys"].update(member_restored)
            state["best_source_score"] = max(
                int(state["best_source_score"]),
                int(source_pair.get("delta_bridge_score") or 0),
            )
        exact_count = len(forward) + len(restored)
        if member_hits:
            attribution_class = "M0_ATOMIC_MEMBER_EXACT_REVERSAL"
            if all(int(row["member_parent_count"]) > 1 for row in member_hits):
                attribution_class = "M1_NESTED_MERGE_MEMBER_EXACT_REVERSAL"
        elif exact_count:
            attribution_class = "M2_MERGE_RESOLUTION_EXACT_REVERSAL"
            resolution_only_count += 1
        else:
            attribution_class = "M3_NO_EXACT_MEMBER_SIGNAL_RETAINED"
            nonexact_count += 1
        edge_rows.append(
            {
                "candidate_sha": candidate,
                "candidate_subject": source_pair.get("candidate_subject"),
                "merge_carrier_sha": merge_sha,
                "merge_carrier_subject": source_pair.get("fix_subject"),
                "source_delta_bridge_rank": source_pair.get("delta_bridge_rank"),
                "source_delta_bridge_class": source_pair.get("delta_bridge_class"),
                "candidate_added_merge_removed_count": len(forward),
                "candidate_removed_merge_restored_count": len(restored),
                "exact_merge_reversal_line_count": exact_count,
                "matching_member_count": len(member_hits),
                "matching_members": sorted(
                    member_hits,
                    key=lambda row: (
                        int(row["member_parent_count"]) > 1,
                        -int(row["exact_reversal_line_count"]),
                        str(row["member_sha"]),
                    ),
                ),
                "member_attribution_class": attribution_class,
                "retained": True,
            }
        )

    exact_queue: list[dict[str, object]] = []
    for state in exact_states.values():
        candidate = str(state["candidate_sha"])
        member = str(state["member_sha"])
        candidate_index = candidate_indexes[candidate]
        forward = set(state["forward_keys"])
        restored = set(state["restored_keys"])
        parent_count = int(state["member_parent_count"])
        score = int(state["best_source_score"]) + (4_000 if parent_count <= 1 else 1_000)
        score += min(len(forward) + len(restored), 12) * 70
        metadata = member_metadata.get(member, {})
        member_subject = metadata.get("subject")
        if not member_subject:
            message = metadata.get("message")
            if isinstance(message, str) and message.strip():
                member_subject = message.splitlines()[0]
        exact_queue.append(
            {
                "candidate_sha": candidate,
                "candidate_subject": candidate_subjects.get(candidate),
                "member_fix_sha": member,
                "member_fix_subject": member_subject,
                "member_fix_authored_at": metadata.get("authored_at"),
                "member_parent_count": parent_count,
                "member_kind": "atomic_or_root" if parent_count <= 1 else "nested_merge",
                "merge_carrier_shas": sorted(state["merge_carriers"]),
                "merge_carrier_count": len(state["merge_carriers"]),
                "source_merge_edge_count": state["source_merge_edges"],
                "candidate_added_member_removed_count": len(forward),
                "candidate_removed_member_restored_count": len(restored),
                "exact_reversal_line_count": len(forward) + len(restored),
                "exact_reversal_sample": [
                    *(
                        {
                            **row,
                            "direction": "candidate_added_member_removed",
                        }
                        for row in _line_sample(forward, candidate_index.additions)
                    ),
                    *(
                        {
                            **row,
                            "direction": "candidate_removed_member_restored",
                        }
                        for row in _line_sample(restored, candidate_index.removals)
                    ),
                ][:24],
                "exact_reversal_sample_truncated": len(forward) + len(restored) > 24,
                "review_priority_score": score,
                "review_priority_rank": None,
                "retained": True,
            }
        )
    exact_queue.sort(
        key=lambda row: (
            str(row["member_kind"]) != "atomic_or_root",
            -int(row["review_priority_score"]),
            str(row["member_fix_sha"]),
            str(row["candidate_sha"]),
        )
    )
    for rank, row in enumerate(exact_queue, start=1):
        row["review_priority_rank"] = rank
    edge_rows.sort(
        key=lambda row: (
            str(row["member_attribution_class"]),
            int(row["source_delta_bridge_rank"] or 10**9),
            str(row["merge_carrier_sha"]),
            str(row["candidate_sha"]),
        )
    )
    bitset_rows = [
        {
            "member_sha": member,
            "candidate_bitset_hex": format(bits, f"0{width}x"),
            "candidate_count": bits.bit_count(),
            "merge_carrier_shas": sorted(member_carriers[member]),
            "merge_carrier_count": len(member_carriers[member]),
        }
        for member, bits in sorted(member_candidate_bits.items())
    ]
    range_gaps = [
        str(row.get("merge_sha") or "")
        for row in member_inventory
        if row.get("range_complete") is not True
    ]
    delta_gaps = sorted(
        sha for sha, index in member_indexes.items() if index.coverage_gaps
    )
    class_counts = Counter(str(row["member_attribution_class"]) for row in edge_rows)
    summary = {
        "schema_version": 1,
        "artifact_kind": "coolify_merge_member_repair_expansion",
        "split_id": split_id,
        "repository_identity": bridge_summary.get("repository_identity"),
        "source_merge_edge_count": len(source_pairs),
        "retained_source_merge_edge_count": len(edge_rows),
        "merge_root_count": len(member_inventory),
        "merge_member_incidence_count": sum(
            int(row.get("member_count") or 0) for row in member_inventory
        ),
        "source_edge_member_incidence_count": member_incidence_count,
        "unique_merge_member_count": len(member_candidate_bits),
        "compressed_unique_candidate_member_pair_count": sum(
            bits.bit_count() for bits in member_candidate_bits.values()
        ),
        "exact_attributed_candidate_member_pair_count": len(exact_queue),
        "exact_resolution_only_source_edge_count": resolution_only_count,
        "nonexact_source_edge_retained_count": nonexact_count,
        "member_attribution_class_counts": dict(sorted(class_counts.items())),
        "merge_range_coverage_gap_count": len(range_gaps),
        "merge_range_coverage_gap_roots": range_gaps,
        "member_delta_coverage_gap_count": len(delta_gaps),
        "member_delta_coverage_gap_commits": delta_gaps,
        "all_source_merge_edges_conserved": len(edge_rows) == len(source_pairs),
        "all_recoverable_member_pairs_compressed": True,
        "hard_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "claim_boundary": (
            "The compressed member bitsets retain every recoverable candidate/member "
            "combination implied by each merge's second-parent range. Exact member "
            "reversals rank a finite semantic queue but do not prove a defect. Exact "
            "merge reversals without a member match remain resolution-only leads, and "
            "range or delta gaps are retries rather than negative labels."
        ),
    }
    return {
        "summary": summary,
        "edge_rows": edge_rows,
        "exact_queue": exact_queue,
        "bitset_rows": bitset_rows,
        "ai_index": {
            "schema_version": 1,
            "artifact_kind": "coolify_merge_member_candidate_bitset_index",
            "ai_shas": ai_shas,
            "ai_shas_sha256": hashlib.sha256(
                json.dumps(
                    ai_shas,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "bit_order": "least_significant_bit_is_ai_shas_index_zero",
            "bitset_hex_width": width,
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.workers < 1 or args.repo_timeout < 1:
        raise SystemExit("--workers and --repo-timeout must be positive")
    repository = args.repository.resolve()
    bridge_dir = args.merge_bridge_dir.resolve()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SystemExit(f"output directory already exists: {output_dir}")
    summary_path = bridge_dir / "summary.json"
    pairs_path = bridge_dir / "delta_bridge_pairs.jsonl"
    bridge_summary = _load_json(summary_path)
    source_pairs = _load_jsonl(pairs_path)
    artifacts = bridge_summary.get("output_artifacts")
    expected_pairs_digest = (
        artifacts.get("delta_bridge_pairs", {}).get("sha256")
        if isinstance(artifacts, Mapping)
        else None
    )
    if expected_pairs_digest != _sha256(pairs_path):
        raise SystemExit("merge bridge pair checksum drift")
    merge_shas = sorted({str(row.get("fix_sha") or "") for row in source_pairs})
    member_inventory: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                _merge_members,
                repository,
                sha,
                timeout=args.repo_timeout,
            ): sha
            for sha in merge_shas
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            member_inventory.append(future.result())
            if completed % 50 == 0 or completed == len(futures):
                print(f"merge member ranges inspected: {completed}/{len(futures)}")
    member_inventory.sort(key=lambda row: str(row["merge_sha"]))

    candidate_shas = sorted(
        {str(row.get("candidate_sha") or "") for row in source_pairs}
    )
    tasks = [("candidate", sha, True) for sha in candidate_shas] + [
        ("fix", sha, False) for sha in merge_shas
    ]
    candidate_indexes: dict[str, ExactDeltaIndex] = {}
    fix_indexes: dict[str, ExactDeltaIndex] = {}

    def inspect_delta(task: tuple[str, str, bool]) -> tuple[str, str, ExactDeltaIndex]:
        kind, sha, all_parents = task
        delta = _inspect_commit_delta(
            repository,
            sha,
            compare_all_parents=all_parents,
            timeout=args.repo_timeout,
        )
        return kind, sha, _exact_index(delta)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(inspect_delta, task): task for task in tasks}
        for completed, future in enumerate(as_completed(futures), start=1):
            kind, sha, index = future.result()
            (candidate_indexes if kind == "candidate" else fix_indexes)[sha] = index
            if completed % 100 == 0 or completed == len(futures):
                print(f"candidate/fix deltas inspected: {completed}/{len(futures)}")

    inventory_by_merge = {
        str(row["merge_sha"]): row for row in member_inventory
    }
    required_paths_by_merge: defaultdict[str, set[str]] = defaultdict(set)
    for source_pair in source_pairs:
        candidate = str(source_pair["candidate_sha"])
        merge_sha = str(source_pair["fix_sha"])
        forward, restored = _exact_reversals(
            candidate_indexes[candidate], fix_indexes[merge_sha]
        )
        required_paths_by_merge[merge_sha].update(key[0] for key in forward | restored)
    member_paths: defaultdict[str, set[str]] = defaultdict(set)
    for merge_sha, paths in required_paths_by_merge.items():
        raw_members = inventory_by_merge[merge_sha]["member_shas"]
        assert isinstance(raw_members, list)
        for member in raw_members:
            member_paths[str(member)].update(paths)
    member_indexes: dict[str, ExactDeltaIndex] = {}
    inspectable = sorted((sha, sorted(paths)) for sha, paths in member_paths.items())
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                _inspect_member_paths,
                repository,
                sha,
                paths,
                timeout=args.repo_timeout,
            ): sha
            for sha, paths in inspectable
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            sha = futures[future]
            member_indexes[sha] = future.result()
            if completed % 100 == 0 or completed == len(futures):
                print(f"targeted member deltas inspected: {completed}/{len(futures)}")
    preliminary = build_merge_member_expansion(
        bridge_summary=bridge_summary,
        source_pairs=source_pairs,
        member_inventory=member_inventory,
        candidate_indexes=candidate_indexes,
        fix_indexes=fix_indexes,
        member_indexes=member_indexes,
        member_metadata={},
        split_id=args.split_id,
    )
    exact_members = sorted(
        {str(row["member_fix_sha"]) for row in preliminary["exact_queue"]}
    )
    member_metadata: dict[str, Mapping[str, object]] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(_commit_metadata, repository, sha): sha
            for sha in exact_members
        }
        for future in as_completed(futures):
            member_metadata[futures[future]] = future.result()
    payload = build_merge_member_expansion(
        bridge_summary=bridge_summary,
        source_pairs=source_pairs,
        member_inventory=member_inventory,
        candidate_indexes=candidate_indexes,
        fix_indexes=fix_indexes,
        member_indexes=member_indexes,
        member_metadata=member_metadata,
        split_id=args.split_id,
    )
    inventory_path = output_dir / "merge_member_inventory.jsonl"
    edges_path = output_dir / "merge_edge_attribution.jsonl"
    queue_path = output_dir / "exact_member_review_queue.jsonl"
    bitsets_path = output_dir / "candidate_member_bitsets.jsonl"
    index_path = output_dir / "ai_index.json"
    output_summary_path = output_dir / "summary.json"
    _atomic_jsonl(inventory_path, member_inventory)
    _atomic_jsonl(edges_path, payload["edge_rows"])
    _atomic_jsonl(queue_path, payload["exact_queue"])
    _atomic_jsonl(bitsets_path, payload["bitset_rows"])
    _atomic_json(index_path, payload["ai_index"])
    summary = dict(payload["summary"])
    summary["source_artifacts"] = {
        "merge_bridge_summary": {
            "path": str(summary_path),
            "sha256": _sha256(summary_path),
        },
        "merge_bridge_pairs": {
            "path": str(pairs_path),
            "sha256": _sha256(pairs_path),
        },
    }
    summary["output_artifacts"] = {
        "merge_member_inventory": {
            "path": str(inventory_path),
            "sha256": _sha256(inventory_path),
        },
        "merge_edge_attribution": {
            "path": str(edges_path),
            "sha256": _sha256(edges_path),
        },
        "exact_member_review_queue": {
            "path": str(queue_path),
            "sha256": _sha256(queue_path),
        },
        "candidate_member_bitsets": {
            "path": str(bitsets_path),
            "sha256": _sha256(bitsets_path),
        },
        "ai_index": {"path": str(index_path), "sha256": _sha256(index_path)},
    }
    _atomic_json(output_summary_path, summary)
    print("Coolify merge-member expansion frozen")
    print(f"  source edges      : {summary['retained_source_merge_edge_count']}")
    print(f"  member pair union : {summary['compressed_unique_candidate_member_pair_count']}")
    print(f"  exact member queue: {summary['exact_attributed_candidate_member_pair_count']}")
    print(f"  resolution-only   : {summary['exact_resolution_only_source_edge_count']}")
    print(f"  coverage gaps     : {summary['merge_range_coverage_gap_count'] + summary['member_delta_coverage_gap_count']}")
    print(f"  output            : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
