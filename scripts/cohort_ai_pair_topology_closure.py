#!/usr/bin/env python3
"""Freeze the complete observed-AI-by-commit Git-topology partition.

The direct ancestry census represents only pairs where an observed-AI commit
is a strict ancestor of a later commit.  That is exact but not exhaustive for
squashes, cherry-picks, copied code, and cross-branch landings.  This closure
partitions the full finite Cartesian product into four disjoint sets:

* strict AI ancestor pairs already represented by the direct census;
* commits that strictly precede the AI commit and therefore cannot be its fix;
* identity pairs; and
* incomparable residual pairs that must remain available for topology rescue.

Every set is stored as a bitset.  Signals and model labels never affect pair
membership.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from cohort.root_adjudication import canonical_sha256


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class TopologyClosureError(ValueError):
    """The census cannot be partitioned without losing or duplicating a pair."""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TopologyClosureError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TopologyClosureError(f"{path} must contain an object")
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
                    raise TopologyClosureError(
                        f"{path}:{line_number} must contain an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise TopologyClosureError(f"cannot load {path}: {exc}") from exc
    return rows


def _full_sha(value: object, label: str) -> str:
    sha = str(value or "").strip().lower()
    if not _FULL_SHA_RE.fullmatch(sha):
        raise TopologyClosureError(f"{label} must be a full Git SHA")
    return sha


def _bitset_hex(bits: int, width: int) -> str:
    return format(bits, f"0{width}x")


def build_topology_closure(
    *,
    census_summary: Mapping[str, object],
    ancestor_index: Mapping[str, object],
    commit_rows: Sequence[Mapping[str, object]],
    split_id: str,
) -> dict[str, object]:
    if not split_id.strip():
        raise TopologyClosureError("split_id is required")
    raw_ai_shas = ancestor_index.get("ai_shas")
    if not isinstance(raw_ai_shas, list) or not raw_ai_shas:
        raise TopologyClosureError("ancestor index has no AI SHAs")
    ai_shas = [_full_sha(value, "AI SHA") for value in raw_ai_shas]
    if ai_shas != sorted(set(ai_shas)):
        raise TopologyClosureError("AI SHAs must be unique and sorted")
    ai_index = {sha: index for index, sha in enumerate(ai_shas)}
    width = (len(ai_shas) + 3) // 4
    if int(ancestor_index.get("bitset_hex_width") or 0) != width:
        raise TopologyClosureError("ancestor index bitset width mismatch")

    ordered_rows: list[dict[str, object]] = []
    row_by_sha: dict[str, dict[str, object]] = {}
    complete_ai_ancestor_bits: dict[str, int] = {}
    for expected_order, raw in enumerate(commit_rows, start=1):
        row = dict(raw)
        sha = _full_sha(row.get("sha"), "commit SHA")
        if sha in row_by_sha:
            raise TopologyClosureError(f"duplicate commit row: {sha}")
        if int(row.get("graph_order") or 0) != expected_order:
            raise TopologyClosureError("commit rows are not in frozen graph order")
        raw_parents = row.get("parents")
        if not isinstance(raw_parents, list):
            raise TopologyClosureError(f"commit {sha} has malformed parents")
        parents = [_full_sha(parent, "parent SHA") for parent in raw_parents]
        missing = [parent for parent in parents if parent not in row_by_sha]
        if missing:
            raise TopologyClosureError(
                f"commit rows are not parent-before-child at {sha}: {missing}"
            )
        strict_bits = 0
        for parent in parents:
            strict_bits |= complete_ai_ancestor_bits[parent]
        declared_count = int(row.get("strict_ai_ancestor_count") or 0)
        if strict_bits.bit_count() != declared_count:
            raise TopologyClosureError(
                f"strict AI ancestor drift at {sha}: "
                f"{strict_bits.bit_count()} != {declared_count}"
            )
        if strict_bits:
            encoded = str(row.get("ai_ancestor_bitset_hex") or "")
            if len(encoded) != width or int(encoded, 16) != strict_bits:
                raise TopologyClosureError(f"ancestor bitset drift at {sha}")
        complete_bits = strict_bits
        if sha in ai_index:
            complete_bits |= 1 << ai_index[sha]
        complete_ai_ancestor_bits[sha] = complete_bits
        row["parents"] = parents
        row["_strict_bits"] = strict_bits
        ordered_rows.append(row)
        row_by_sha[sha] = row

    if set(ai_shas) - set(row_by_sha):
        raise TopologyClosureError("AI index contains commits outside the graph")
    expected_commits = int(census_summary.get("all_ref_commit_count") or -1)
    if expected_commits != len(ordered_rows):
        raise TopologyClosureError("all-ref commit count drift")
    expected_direct = int(census_summary.get("direct_ancestry_pair_count") or -1)

    inclusive_ai_descendant_bits = {
        sha: (1 << ai_index[sha]) if sha in ai_index else 0 for sha in row_by_sha
    }
    for row in reversed(ordered_rows):
        sha = str(row["sha"])
        child_bits = inclusive_ai_descendant_bits[sha]
        for parent in row["parents"]:
            inclusive_ai_descendant_bits[str(parent)] |= child_bits

    all_ai_bits = (1 << len(ai_shas)) - 1
    partition_rows: list[dict[str, object]] = []
    total_direct = 0
    total_fix_before = 0
    total_identity = 0
    total_residual = 0
    residual_by_route: Counter[str] = Counter()
    residual_roots_by_route: Counter[str] = Counter()
    for row in ordered_rows:
        sha = str(row["sha"])
        strict_bits = int(row.pop("_strict_bits"))
        identity_bits = (1 << ai_index[sha]) if sha in ai_index else 0
        fix_before_bits = inclusive_ai_descendant_bits[sha] & ~identity_bits
        if strict_bits & (fix_before_bits | identity_bits):
            raise TopologyClosureError(f"cyclic pair partition at {sha}")
        residual_bits = all_ai_bits & ~(
            strict_bits | fix_before_bits | identity_bits
        )
        if (
            strict_bits | fix_before_bits | identity_bits | residual_bits
        ) != all_ai_bits:
            raise TopologyClosureError(f"incomplete pair partition at {sha}")
        route = str(row.get("route") or "")
        residual_count = residual_bits.bit_count()
        total_direct += strict_bits.bit_count()
        total_fix_before += fix_before_bits.bit_count()
        total_identity += identity_bits.bit_count()
        total_residual += residual_count
        residual_by_route[route] += residual_count
        if residual_count:
            residual_roots_by_route[route] += 1
        partition_rows.append(
            {
                "repository_identity": row.get("repository_identity"),
                "sha": sha,
                "graph_order": row.get("graph_order"),
                "route": route,
                "topology_kind": row.get("topology_kind"),
                "subject": row.get("subject"),
                "strict_ai_ancestor_count": strict_bits.bit_count(),
                "strict_ai_ancestor_bitset_hex": _bitset_hex(strict_bits, width),
                "fix_precedes_ai_count": fix_before_bits.bit_count(),
                "fix_precedes_ai_bitset_hex": _bitset_hex(fix_before_bits, width),
                "identity_pair_count": identity_bits.bit_count(),
                "identity_bitset_hex": _bitset_hex(identity_bits, width),
                "incomparable_residual_count": residual_count,
                "incomparable_residual_bitset_hex": _bitset_hex(
                    residual_bits, width
                ),
                "residual_retained": residual_count > 0,
            }
        )

    if total_direct != expected_direct:
        raise TopologyClosureError(
            f"direct pair drift: {total_direct} != {expected_direct}"
        )
    full_pair_count = len(ordered_rows) * len(ai_shas)
    partition_sum = total_direct + total_fix_before + total_identity + total_residual
    if partition_sum != full_pair_count or total_identity != len(ai_shas):
        raise TopologyClosureError("global Cartesian partition is not conservative")

    summary = {
        "schema_version": 1,
        "artifact_kind": "observed_ai_full_topology_pair_closure",
        "split_id": split_id,
        "repository_identity": census_summary.get("repository_identity"),
        "all_ref_commit_count": len(ordered_rows),
        "observed_ai_commit_count": len(ai_shas),
        "full_cartesian_pair_count": full_pair_count,
        "strict_ai_ancestor_pair_count": total_direct,
        "fix_strictly_precedes_ai_pair_count": total_fix_before,
        "identity_pair_count": total_identity,
        "incomparable_residual_pair_count": total_residual,
        "incomparable_residual_root_count": sum(
            residual_count > 0
            for residual_count in (
                int(row["incomparable_residual_count"]) for row in partition_rows
            )
        ),
        "incomparable_residual_pair_counts_by_original_route": dict(
            sorted(residual_by_route.items())
        ),
        "incomparable_residual_root_counts_by_original_route": dict(
            sorted(residual_roots_by_route.items())
        ),
        "pair_partition_conserved": partition_sum == full_pair_count,
        "direct_pair_count_matches_census": total_direct == expected_direct,
        "hard_heuristic_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "proof_excluded_pair_count": total_fix_before + total_identity,
        "residual_disposition": "RETAIN_FOR_TOPOLOGY_RESCUE",
        "claim_boundary": (
            "The complete observed-AI-by-commit Cartesian product is represented. "
            "Only strict Git direction and identity separate pairs that cannot be a "
            "later fix for that exact AI commit. Every graph-incomparable pair remains "
            "explicit for squash, cherry-pick, copy, and cross-branch rescue. This is "
            "candidate-source completeness, not a causal or vulnerability label."
        ),
    }
    return {
        "summary": summary,
        "index": {
            "schema_version": 1,
            "artifact_kind": "observed_ai_topology_pair_bitset_index",
            "repository_identity": census_summary.get("repository_identity"),
            "bit_order": "least_significant_bit_is_ai_shas_index_zero",
            "bitset_hex_width": width,
            "ai_shas": ai_shas,
            "ai_shas_sha256": canonical_sha256(ai_shas),
        },
        "partition_rows": partition_rows,
    }


def _atomic_jsonl(
    path: Path, rows: Iterable[object], *, pretty: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise TopologyClosureError(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if pretty:
                materialized = list(rows)
                if len(materialized) != 1:
                    raise TopologyClosureError("pretty output requires one value")
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    census_dir = args.census_dir.resolve()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SystemExit(f"output directory already exists: {output_dir}")
    summary_path = census_dir / "summary.json"
    index_path = census_dir / "ancestor_index.json"
    commits_path = census_dir / "all_commits.jsonl"
    try:
        census_summary = _load_json(summary_path)
        ancestor_index = _load_json(index_path)
        commit_rows = _load_jsonl(commits_path)
        if canonical_sha256(commit_rows) != census_summary.get(
            "all_commit_rows_sha256"
        ):
            raise TopologyClosureError("all-commit census digest mismatch")
        if canonical_sha256(ancestor_index) != census_summary.get(
            "ancestor_index_sha256"
        ):
            raise TopologyClosureError("ancestor-index digest mismatch")
        artifacts = build_topology_closure(
            census_summary=census_summary,
            ancestor_index=ancestor_index,
            commit_rows=commit_rows,
            split_id=args.split_id,
        )
        partition_path = output_dir / "pair_partition.jsonl"
        output_index_path = output_dir / "ai_index.json"
        output_summary_path = output_dir / "summary.json"
        _atomic_jsonl(partition_path, artifacts["partition_rows"])
        _atomic_jsonl(output_index_path, [artifacts["index"]], pretty=True)
        summary = dict(artifacts["summary"])
        summary["source_artifacts"] = {
            "census_summary": {
                "path": str(summary_path),
                "sha256": _sha256(summary_path),
            },
            "ancestor_index": {
                "path": str(index_path),
                "sha256": _sha256(index_path),
            },
            "all_commits": {
                "path": str(commits_path),
                "sha256": _sha256(commits_path),
            },
        }
        summary["output_artifacts"] = {
            "pair_partition": {
                "path": str(partition_path),
                "sha256": _sha256(partition_path),
            },
            "ai_index": {
                "path": str(output_index_path),
                "sha256": _sha256(output_index_path),
            },
        }
        _atomic_jsonl(output_summary_path, [summary], pretty=True)
    except TopologyClosureError as exc:
        raise SystemExit(f"topology closure failed: {exc}") from exc
    print("Observed-AI full topology pair closure frozen")
    print(f"  full Cartesian pairs : {summary['full_cartesian_pair_count']}")
    print(f"  direct ancestry      : {summary['strict_ai_ancestor_pair_count']}")
    print(f"  incomparable residual: {summary['incomparable_residual_pair_count']}")
    print(f"  proof excluded       : {summary['proof_excluded_pair_count']}")
    print(f"  output               : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
