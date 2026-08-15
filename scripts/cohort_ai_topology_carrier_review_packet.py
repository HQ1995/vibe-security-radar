#!/usr/bin/env python3
"""Freeze semantic-review packets for incomparable AI commits landed by carriers.

Each case binds one exact same-path reverse line to the same candidate-parent
patch that has a stable-patch-id-equivalent carrier.  The carrier must strictly
precede the alleged fix.  This proves compositional provenance, not a defect;
semantic review is still required and no source pair is removed.
"""

from __future__ import annotations

import argparse
import hashlib
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort_ai_topology_patch_id_relations import _inspect_patch_ids
from cohort_coolify_exact_delta_review_packet import (
    _bounded_text,
    _diff,
    _diff_stat,
    _load_json,
    _load_jsonl,
    _resolve_edges,
    _selected_patch_hunks,
    _sha256,
)
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _is_ancestor,
)
from cohort_coolify_preimage_exact_delta_bridge import _inspect_commit_delta


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--carrier-bridge-dir", type=Path, required=True)
    parser.add_argument(
        "--edge",
        action="append",
        required=True,
        help="candidate-prefix:fix-prefix; repeat to preserve review order",
    )
    parser.add_argument("--context-lines", type=int, default=6)
    parser.add_argument("--max-paths", type=int, default=4)
    parser.add_argument("--max-hunks-per-patch", type=int, default=4)
    parser.add_argument("--max-patch-chars", type=int, default=10_000)
    parser.add_argument("--max-stat-chars", type=int, default=2_000)
    parser.add_argument("--max-focal-lines", type=int, default=10)
    parser.add_argument("--repo-timeout", type=int, default=120)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _string_lists(value: object, *, field: str) -> dict[str, list[str]]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} is malformed")
    result: dict[str, list[str]] = {}
    for raw_key, raw_values in value.items():
        if not isinstance(raw_values, list):
            raise ValueError(f"{field} is malformed")
        result[str(raw_key)] = [str(item) for item in raw_values]
    return result


def _carrier_chain(
    row: Mapping[str, object], sample: Mapping[str, object]
) -> dict[str, str]:
    candidate_parent = str(sample.get("candidate_parent_sha") or "")
    raw_matching = sample.get("matching_strict_ancestor_carriers")
    raw_relations = row.get("strict_ancestor_carriers")
    if not isinstance(raw_matching, list) or not isinstance(raw_relations, list):
        raise ValueError("carrier-linked sample is malformed")
    matching = {str(value) for value in raw_matching}
    for raw_relation in sorted(
        raw_relations,
        key=lambda value: str(value.get("carrier_sha") or "")
        if isinstance(value, Mapping)
        else "",
    ):
        if not isinstance(raw_relation, Mapping):
            raise ValueError("carrier relation is malformed")
        carrier_sha = str(raw_relation.get("carrier_sha") or "")
        if carrier_sha not in matching:
            continue
        candidate_parents = _string_lists(
            raw_relation.get("candidate_parent_evidence"),
            field="candidate_parent_evidence",
        )
        carrier_parents = _string_lists(
            raw_relation.get("carrier_parent_evidence"),
            field="carrier_parent_evidence",
        )
        shared = raw_relation.get("shared_patch_ids")
        if not isinstance(shared, list):
            raise ValueError("shared patch IDs are malformed")
        for patch_id in sorted(str(value) for value in shared):
            if candidate_parent not in candidate_parents.get(patch_id, []):
                continue
            possible_carrier_parents = sorted(carrier_parents.get(patch_id, []))
            if possible_carrier_parents:
                return {
                    "patch_id": patch_id,
                    "candidate_parent_sha": candidate_parent,
                    "carrier_sha": carrier_sha,
                    "carrier_parent_sha": possible_carrier_parents[0],
                }
    raise ValueError("no carrier relation is linked to the focal candidate parent")


def _carrier_path(
    repository: Path,
    *,
    carrier_sha: str,
    carrier_parent_sha: str,
    direction: str,
    content_sha256: str,
    timeout: int,
) -> str:
    delta = _inspect_commit_delta(
        repository,
        carrier_sha,
        compare_all_parents=True,
        timeout=timeout,
    )
    lines = (
        delta.additions
        if direction == "candidate_added_fix_removed"
        else delta.removals
    )
    paths = sorted(
        {
            line.path
            for line in lines
            if line.parent_sha == carrier_parent_sha
            and _digest(line.content) == content_sha256
        }
    )
    if not paths:
        raise ValueError("focal line is absent from equivalent carrier parent-diff")
    return paths[0]


def _strong_samples(row: Mapping[str, object]) -> list[Mapping[str, object]]:
    raw_samples = row.get("carrier_linked_same_path_reversal_sample")
    if not isinstance(raw_samples, list):
        raise ValueError("carrier-linked reversal sample is malformed")
    samples: list[Mapping[str, object]] = []
    for sample in raw_samples:
        if not isinstance(sample, Mapping):
            raise ValueError("carrier-linked reversal sample is malformed")
        if (
            sample.get("match_kind") == "exact_same_path"
            and sample.get("meaningful") is True
            and sample.get("generated_or_machine_artifact") is not True
        ):
            samples.append(sample)
    if not samples:
        raise ValueError("case has no strong carrier-linked reverse line")
    return samples


def _case_packet(
    repository: Path,
    row: Mapping[str, object],
    *,
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
    samples = _strong_samples(row)
    grouped: defaultdict[tuple[str, str, str, str], list[Mapping[str, object]]]
    grouped = defaultdict(list)
    for sample in samples:
        key = (
            str(sample.get("candidate_parent_sha") or ""),
            str(sample.get("fix_parent_sha") or ""),
            str(sample.get("candidate_path") or ""),
            str(sample.get("direction") or ""),
        )
        grouped[key].append(sample)
    ordered = sorted(
        grouped,
        key=lambda key: (
            not any(value.get("control_like") is True for value in grouped[key]),
            -len(grouped[key]),
            key,
        ),
    )
    selected = ordered[:max_paths]
    path_packets: list[dict[str, object]] = []
    carrier_chains: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for key in selected:
        candidate_parent, fix_parent, candidate_path, direction = key
        focal_rows = grouped[key]
        chain = _carrier_chain(row, focal_rows[0])
        focal_hashes = {str(value["content_sha256"]) for value in focal_rows}
        carrier_path = _carrier_path(
            repository,
            carrier_sha=chain["carrier_sha"],
            carrier_parent_sha=chain["carrier_parent_sha"],
            direction=direction,
            content_sha256=sorted(focal_hashes)[0],
            timeout=timeout,
        )
        candidate_patch = _selected_patch_hunks(
            _diff(
                repository,
                candidate_parent,
                candidate_sha,
                candidate_path,
                context_lines=context_lines,
                timeout=timeout,
            ),
            focal_hashes=focal_hashes,
            max_hunks=max_hunks,
            max_chars=max_patch_chars,
        )
        carrier_patch = _selected_patch_hunks(
            _diff(
                repository,
                chain["carrier_parent_sha"],
                chain["carrier_sha"],
                carrier_path,
                context_lines=context_lines,
                timeout=timeout,
            ),
            focal_hashes=focal_hashes,
            max_hunks=max_hunks,
            max_chars=max_patch_chars,
        )
        fix_patch = _selected_patch_hunks(
            _diff(
                repository,
                fix_parent,
                fix_sha,
                candidate_path,
                context_lines=context_lines,
                timeout=timeout,
            ),
            focal_hashes=focal_hashes,
            max_hunks=max_hunks,
            max_chars=max_patch_chars,
        )
        carrier_chains[tuple(chain.values())] = chain
        path_packets.append(
            {
                "candidate_path": candidate_path,
                "carrier_path": carrier_path,
                "fix_path": candidate_path,
                "direction": direction,
                "candidate_parent_sha": candidate_parent,
                "carrier_parent_sha": chain["carrier_parent_sha"],
                "fix_parent_sha": fix_parent,
                "stable_patch_id": chain["patch_id"],
                "carrier_sha": chain["carrier_sha"],
                "focal_exact_line_count": len(focal_hashes),
                "focal_exact_delta_sample": [
                    dict(value) for value in focal_rows[:max_focal_lines]
                ],
                "focal_exact_delta_sample_truncated": len(focal_rows)
                > max_focal_lines,
                "candidate_patch": candidate_patch,
                "carrier_patch": carrier_patch,
                "fix_patch": fix_patch,
            }
        )
    chains = sorted(carrier_chains.values(), key=lambda value: tuple(value.values()))
    first = chains[0]
    candidate_patch_ids = _inspect_patch_ids(
        repository, candidate_sha, timeout=timeout
    )
    carrier_patch_ids = _inspect_patch_ids(
        repository, first["carrier_sha"], timeout=timeout
    )
    checks = {
        "candidate_is_observed_ai": candidate_sha in observed_ai_shas,
        "source_edge_retained": row.get("retained") is True,
        "source_bridge_is_strong_tier": int(row.get("carrier_bridge_tier", -1)) == 0,
        "candidate_and_fix_are_graph_incomparable": not _is_ancestor(
            repository, candidate_sha, fix_sha
        )
        and not _is_ancestor(repository, fix_sha, candidate_sha),
        "carrier_strictly_precedes_fix": all(
            _is_ancestor(repository, chain["carrier_sha"], fix_sha)
            and chain["carrier_sha"] != fix_sha
            for chain in chains
        ),
        "stable_patch_id_recomputed": all(
            chain["patch_id"] in candidate_patch_ids.patch_ids
            and chain["patch_id"]
            in _inspect_patch_ids(
                repository, chain["carrier_sha"], timeout=timeout
            ).patch_ids
            for chain in chains
        ),
        "patch_id_inspection_complete": not candidate_patch_ids.coverage_gaps
        and not carrier_patch_ids.coverage_gaps,
        "selected_three_way_hunks_cover_focal_lines": bool(path_packets)
        and all(
            int(packet[side]["focal_hunk_count"]) > 0
            for packet in path_packets
            for side in ("candidate_patch", "carrier_patch", "fix_patch")
        ),
    }
    return {
        "key": f"{candidate_sha[:12]}__{fix_sha[:12]}",
        "candidate_sha": candidate_sha,
        "carrier_sha": first["carrier_sha"],
        "fix_sha": fix_sha,
        "candidate_metadata": _commit_metadata(repository, candidate_sha),
        "carrier_metadata": _commit_metadata(repository, first["carrier_sha"]),
        "fix_metadata": _commit_metadata(repository, fix_sha),
        "candidate_diff_stat": _bounded_text(
            _diff_stat(
                repository,
                first["candidate_parent_sha"],
                candidate_sha,
                timeout=timeout,
            ),
            max_chars=max_stat_chars,
        ),
        "carrier_diff_stat": _bounded_text(
            _diff_stat(
                repository,
                first["carrier_parent_sha"],
                first["carrier_sha"],
                timeout=timeout,
            ),
            max_chars=max_stat_chars,
        ),
        "fix_diff_stat": _bounded_text(
            _diff_stat(
                repository,
                str(path_packets[0]["fix_parent_sha"]),
                fix_sha,
                timeout=timeout,
            ),
            max_chars=max_stat_chars,
        ),
        "carrier_chains": chains,
        "bridge_class": row.get("carrier_bridge_class"),
        "bridge_rank": row.get("carrier_bridge_rank"),
        "source_delta_class": row.get("delta_class"),
        "path_packets": path_packets,
        "selected_path_context_count": len(path_packets),
        "omitted_focal_context_count": len(ordered) - len(selected),
        "checks": checks,
        "passed": all(checks.values()),
    }


def build_packet(
    repository: Path,
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
    cases = [
        _case_packet(
            repository,
            row,
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
        "artifact_kind": "coolify_topology_carrier_semantic_review_packet",
        "repository_identity": "github.com/coollabsio/coolify",
        "case_results": cases,
        "summary": {
            "case_count": len(cases),
            "unique_candidate_count": len({row["candidate_sha"] for row in cases}),
            "unique_carrier_count": len({row["carrier_sha"] for row in cases}),
            "unique_fix_count": len({row["fix_sha"] for row in cases}),
            "failed_case_count": sum(row["passed"] is not True for row in cases),
        },
        "packet_passed": bool(cases) and all(row["passed"] is True for row in cases),
        "claim_boundary": (
            "Each case proves observed-AI membership, graph incomparability, exact "
            "candidate-to-carrier patch equivalence on the focal parent, strict "
            "carrier ancestry to the fix, and a later exact same-path reverse line. "
            "It does not prove that the transition repairs a defect. Negative model "
            "labels remain retained in the complete candidate universe."
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
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    bridge_dir = args.carrier_bridge_dir.resolve()
    summary_path = bridge_dir / "summary.json"
    rows_path = bridge_dir / "bridge_rows.jsonl"
    ai_path = args.ai_scan_dir.resolve() / "commits.jsonl"
    summary = _load_json(summary_path)
    rows = _load_jsonl(rows_path)
    ai_rows = _load_jsonl(ai_path)
    if summary.get("all_exact_reversal_pairs_conserved") is not True:
        raise SystemExit("carrier bridge is not lossless")
    expected = summary.get("output_artifacts", {})
    expected_digest = (
        expected.get("bridge_rows", {}).get("sha256")
        if isinstance(expected, Mapping)
        else None
    )
    if expected_digest != _sha256(rows_path):
        raise SystemExit("carrier bridge row checksum drift")
    try:
        selected_rows = _resolve_edges(args.edge, rows)
        if any(int(row.get("carrier_bridge_tier", -1)) != 0 for row in selected_rows):
            raise ValueError("topology semantic packet currently requires C0 edges")
        payload = build_packet(
            repository,
            selected_rows=selected_rows,
            observed_ai_shas={str(row.get("sha") or "") for row in ai_rows},
            context_lines=args.context_lines,
            max_paths=args.max_paths,
            max_hunks=args.max_hunks_per_patch,
            max_patch_chars=args.max_patch_chars,
            max_stat_chars=args.max_stat_chars,
            max_focal_lines=args.max_focal_lines,
            timeout=args.repo_timeout,
        )
    except ValueError as exc:
        raise SystemExit(f"topology carrier packet failed: {exc}") from exc
    payload["configuration"] = {
        "requested_edges": list(args.edge),
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
        "carrier_bridge_summary": {
            "path": str(summary_path),
            "sha256": _sha256(summary_path),
        },
        "carrier_bridge_rows": {
            "path": str(rows_path),
            "sha256": _sha256(rows_path),
        },
    }
    if payload["packet_passed"] is not True:
        failed = [row["key"] for row in payload["case_results"] if not row["passed"]]
        raise SystemExit(f"topology carrier packet failed checks: {failed}")
    _atomic_json(args.output.resolve(), payload)
    print("Coolify topology-carrier semantic review packet frozen")
    print(f"  cases     : {payload['summary']['case_count']}")
    print(f"  unique AI : {payload['summary']['unique_candidate_count']}")
    print(f"  output    : {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
