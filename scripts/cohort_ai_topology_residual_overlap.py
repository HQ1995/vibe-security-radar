#!/usr/bin/env python3
"""Materialize and rank every graph-incomparable observed-AI pair.

The topology closure is the membership authority.  This overlay adds cheap,
deterministic scheduling evidence such as exact path overlap, basename overlap,
and equivalent subjects.  It emits every residual pair exactly once; a missing
overlap is never a negative label.
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
from datetime import datetime
from pathlib import Path

from cohort.root_adjudication import canonical_sha256
from cohort_coolify_fix_preimage_lineage import _path_kind


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PR_SUFFIX_RE = re.compile(r"\s*\(#(\d+)\)\s*$")
_TIER_NAMES = {
    0: "T0_EQUIVALENT_SUBJECT_OR_PR_RELATION",
    1: "T1_EXACT_RUNTIME_PATH_OVERLAP",
    2: "T2_EXACT_NON_RUNTIME_PATH_OVERLAP",
    3: "T3_BASENAME_RENAME_OR_COPY_OVERLAP",
    4: "T4_TOPOLOGY_ONLY_RETAINED",
}
_TIER_BONUS = {0: 4_000, 1: 2_500, 2: 1_200, 3: 600, 4: 0}


class TopologyOverlapError(ValueError):
    """The residual pair universe or its overlap evidence is malformed."""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology-closure-dir", type=Path, required=True)
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TopologyOverlapError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TopologyOverlapError(f"{path} must contain an object")
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
                    raise TopologyOverlapError(
                        f"{path}:{line_number} must contain an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise TopologyOverlapError(f"cannot load {path}: {exc}") from exc
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _full_sha(value: object, label: str) -> str:
    sha = str(value or "").strip().lower()
    if not _FULL_SHA_RE.fullmatch(sha):
        raise TopologyOverlapError(f"{label} must be a full Git SHA")
    return sha


def _decode_bits(encoded: object, *, width: int, count: int) -> int:
    text = str(encoded or "")
    if len(text) != width:
        raise TopologyOverlapError("residual bitset width mismatch")
    try:
        bits = int(text, 16)
    except ValueError as exc:
        raise TopologyOverlapError("residual bitset is not hexadecimal") from exc
    if bits.bit_count() != count:
        raise TopologyOverlapError("residual bitset count mismatch")
    return bits


def _subject_key(subject: str) -> str:
    without_pr = _PR_SUFFIX_RE.sub("", subject)
    return " ".join(without_pr.casefold().split())


def _pr_number(subject: str) -> str:
    match = _PR_SUFFIX_RE.search(subject)
    return match.group(1) if match else ""


def _timestamp_order(candidate_value: object, fix_value: object) -> str:
    try:
        candidate = datetime.fromisoformat(str(candidate_value))
        fix = datetime.fromisoformat(str(fix_value))
    except ValueError:
        return "UNKNOWN"
    return "CANDIDATE_NOT_AFTER_FIX" if candidate <= fix else "TIMESTAMP_REVERSED"


def _pair_row(
    *,
    candidate: Mapping[str, object],
    fix: Mapping[str, object],
) -> dict[str, object]:
    candidate_sha = _full_sha(candidate.get("sha"), "candidate SHA")
    fix_sha = _full_sha(fix.get("sha"), "fix SHA")
    raw_candidate_paths = candidate.get("changed_files")
    raw_fix_paths = fix.get("changed_paths")
    if not isinstance(raw_candidate_paths, list) or not isinstance(raw_fix_paths, list):
        raise TopologyOverlapError("candidate or fix path inventory is malformed")
    candidate_paths = {str(value) for value in raw_candidate_paths if str(value)}
    fix_paths = {str(value) for value in raw_fix_paths if str(value)}
    exact_paths = sorted(candidate_paths & fix_paths)
    runtime_exact_paths = [path for path in exact_paths if _path_kind(path) == "runtime"]
    candidate_basenames = {path.rsplit("/", 1)[-1] for path in candidate_paths}
    fix_basenames = {path.rsplit("/", 1)[-1] for path in fix_paths}
    basename_overlap = sorted(candidate_basenames & fix_basenames)
    candidate_subject = str(candidate.get("message") or "").split("\n", 1)[0]
    fix_subject = str(fix.get("subject") or "")
    candidate_pr = _pr_number(candidate_subject)
    fix_pr = _pr_number(fix_subject)
    equivalent_subject = bool(
        _subject_key(candidate_subject)
        and _subject_key(candidate_subject) == _subject_key(fix_subject)
    )
    same_pr = bool(candidate_pr and candidate_pr == fix_pr)
    if equivalent_subject or same_pr:
        tier = 0
    elif runtime_exact_paths:
        tier = 1
    elif exact_paths:
        tier = 2
    elif basename_overlap:
        tier = 3
    else:
        tier = 4
    score = _TIER_BONUS[tier]
    score += min(len(runtime_exact_paths), 20) * 30
    score += min(len(exact_paths), 20) * 15
    score += min(len(basename_overlap), 20) * 5
    if _timestamp_order(candidate.get("authored_date"), fix.get("authored_at")) == (
        "CANDIDATE_NOT_AFTER_FIX"
    ):
        score += 20
    if fix.get("route") == "sealed_parent_root_without_direct_ancestry":
        score += 1_000
    exact_sample = exact_paths[:12]
    basename_sample = basename_overlap[:12]
    return {
        "candidate_sha": candidate_sha,
        "candidate_authored_at": candidate.get("authored_date"),
        "candidate_subject": candidate_subject,
        "fix_sha": fix_sha,
        "fix_authored_at": fix.get("authored_at"),
        "fix_subject": fix_subject,
        "fix_original_route": fix.get("route"),
        "fix_topology_kind": fix.get("topology_kind"),
        "topology_relation": "git_graph_incomparable",
        "timestamp_order": _timestamp_order(
            candidate.get("authored_date"), fix.get("authored_at")
        ),
        "equivalent_subject_without_pr_suffix": equivalent_subject,
        "same_pr_number": same_pr,
        "exact_path_overlap_count": len(exact_paths),
        "runtime_exact_path_overlap_count": len(runtime_exact_paths),
        "exact_path_overlap_sample": exact_sample,
        "exact_path_overlap_sample_truncated": len(exact_paths) > len(exact_sample),
        "basename_overlap_count": len(basename_overlap),
        "basename_overlap_sample": basename_sample,
        "basename_overlap_sample_truncated": (
            len(basename_overlap) > len(basename_sample)
        ),
        "candidate_changed_path_count": len(candidate_paths),
        "fix_changed_path_count": len(fix_paths),
        "priority_tier": tier,
        "priority_class": _TIER_NAMES[tier],
        "review_priority_score": score,
        "retained": True,
        "review_priority_rank": None,
    }


def build_overlap_overlay(
    *,
    closure_summary: Mapping[str, object],
    closure_index: Mapping[str, object],
    partition_rows: Sequence[Mapping[str, object]],
    census_summary: Mapping[str, object],
    commit_rows: Sequence[Mapping[str, object]],
    ai_scan_summary: Mapping[str, object],
    ai_rows: Sequence[Mapping[str, object]],
    split_id: str,
) -> dict[str, object]:
    if closure_summary.get("pair_partition_conserved") is not True:
        raise TopologyOverlapError("topology closure is not conservative")
    if closure_summary.get("model_labels_used_for_membership") != 0:
        raise TopologyOverlapError("model labels affected topology membership")
    if closure_summary.get("hard_heuristic_filter_count") != 0:
        raise TopologyOverlapError("topology closure applied a heuristic filter")
    if canonical_sha256(commit_rows) != census_summary.get(
        "all_commit_rows_sha256"
    ):
        raise TopologyOverlapError("all-commit census digest mismatch")
    raw_ai_shas = closure_index.get("ai_shas")
    if not isinstance(raw_ai_shas, list):
        raise TopologyOverlapError("closure AI index is malformed")
    ai_shas = [_full_sha(value, "AI SHA") for value in raw_ai_shas]
    width = int(closure_index.get("bitset_hex_width") or 0)
    if width != (len(ai_shas) + 3) // 4:
        raise TopologyOverlapError("closure AI bitset width mismatch")
    ai_by_sha = {_full_sha(row.get("sha"), "AI row SHA"): row for row in ai_rows}
    if ai_shas != sorted(ai_by_sha):
        raise TopologyOverlapError("AI scan and closure index disagree")
    if int(ai_scan_summary.get("ai_commit_count") or -1) != len(ai_rows):
        raise TopologyOverlapError("AI scan count mismatch")
    commit_by_sha = {
        _full_sha(row.get("sha"), "commit row SHA"): row for row in commit_rows
    }
    if len(commit_by_sha) != len(commit_rows) or len(partition_rows) != len(commit_rows):
        raise TopologyOverlapError("closure and census commit counts disagree")

    pairs: list[dict[str, object]] = []
    for partition in partition_rows:
        fix_sha = _full_sha(partition.get("sha"), "partition fix SHA")
        count = int(partition.get("incomparable_residual_count") or 0)
        bits = _decode_bits(
            partition.get("incomparable_residual_bitset_hex"),
            width=width,
            count=count,
        )
        while bits:
            low_bit = bits & -bits
            index = low_bit.bit_length() - 1
            bits ^= low_bit
            if index >= len(ai_shas):
                raise TopologyOverlapError("residual bitset exceeds AI index")
            pairs.append(
                _pair_row(
                    candidate=ai_by_sha[ai_shas[index]],
                    fix=commit_by_sha[fix_sha],
                )
            )
    expected = int(closure_summary.get("incomparable_residual_pair_count") or -1)
    keys = {(str(row["candidate_sha"]), str(row["fix_sha"])) for row in pairs}
    if len(pairs) != expected or len(keys) != len(pairs):
        raise TopologyOverlapError("residual pair materialization is not conservative")
    pairs.sort(
        key=lambda row: (
            int(row["priority_tier"]),
            -int(row["review_priority_score"]),
            str(row["fix_sha"]),
            str(row["candidate_sha"]),
        )
    )
    for rank, row in enumerate(pairs, start=1):
        row["review_priority_rank"] = rank
    best_by_candidate: dict[str, dict[str, object]] = {}
    for row in pairs:
        best_by_candidate.setdefault(str(row["candidate_sha"]), row)
    frontier = [
        {**row, "frontier_kind": "best_topology_residual_edge_per_ai_candidate"}
        for row in best_by_candidate.values()
    ]
    priority_counts = Counter(str(row["priority_class"]) for row in pairs)
    summary = {
        "schema_version": 1,
        "artifact_kind": "observed_ai_topology_residual_overlap_overlay",
        "split_id": split_id,
        "repository_identity": closure_summary.get("repository_identity"),
        "source_residual_pair_count": expected,
        "retained_residual_pair_count": len(pairs),
        "unique_candidate_count": len({str(row["candidate_sha"]) for row in pairs}),
        "unique_fix_count": len({str(row["fix_sha"]) for row in pairs}),
        "candidate_frontier_count": len(frontier),
        "exact_path_overlap_pair_count": sum(
            int(row["exact_path_overlap_count"]) > 0 for row in pairs
        ),
        "runtime_exact_path_overlap_pair_count": sum(
            int(row["runtime_exact_path_overlap_count"]) > 0 for row in pairs
        ),
        "basename_only_overlap_pair_count": sum(
            int(row["exact_path_overlap_count"]) == 0
            and int(row["basename_overlap_count"]) > 0
            for row in pairs
        ),
        "equivalent_subject_or_pr_pair_count": sum(
            row["equivalent_subject_without_pr_suffix"] is True
            or row["same_pr_number"] is True
            for row in pairs
        ),
        "topology_only_retained_pair_count": sum(
            row["priority_class"] == "T4_TOPOLOGY_ONLY_RETAINED" for row in pairs
        ),
        "priority_class_counts": dict(sorted(priority_counts.items())),
        "all_residual_pairs_conserved": len(pairs) == expected,
        "hard_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "claim_boundary": (
            "Path, basename, subject, PR, and timestamp fields only change review "
            "order. Every Git-incomparable pair from the full topology closure is "
            "retained, including no-overlap and reversed-timestamp pairs. These are "
            "scheduling signals, not causal or vulnerability labels."
        ),
    }
    return {"summary": summary, "pairs": pairs, "candidate_frontier": frontier}


def _atomic_jsonl(
    path: Path, rows: Iterable[object], *, pretty: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise TopologyOverlapError(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if pretty:
                materialized = list(rows)
                if len(materialized) != 1:
                    raise TopologyOverlapError("pretty output requires one value")
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
    closure_dir = args.topology_closure_dir.resolve()
    census_dir = args.census_dir.resolve()
    ai_scan_dir = args.ai_scan_dir.resolve()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SystemExit(f"output directory already exists: {output_dir}")
    closure_summary_path = closure_dir / "summary.json"
    closure_index_path = closure_dir / "ai_index.json"
    partition_path = closure_dir / "pair_partition.jsonl"
    census_summary_path = census_dir / "summary.json"
    commits_path = census_dir / "all_commits.jsonl"
    ai_summary_path = ai_scan_dir / "summary.json"
    ai_rows_path = ai_scan_dir / "commits.jsonl"
    try:
        artifacts = build_overlap_overlay(
            closure_summary=_load_json(closure_summary_path),
            closure_index=_load_json(closure_index_path),
            partition_rows=_load_jsonl(partition_path),
            census_summary=_load_json(census_summary_path),
            commit_rows=_load_jsonl(commits_path),
            ai_scan_summary=_load_json(ai_summary_path),
            ai_rows=_load_jsonl(ai_rows_path),
            split_id=args.split_id,
        )
        pairs_path = output_dir / "residual_pairs.jsonl"
        frontier_path = output_dir / "candidate_frontier.jsonl"
        summary_path = output_dir / "summary.json"
        _atomic_jsonl(pairs_path, artifacts["pairs"])
        _atomic_jsonl(frontier_path, artifacts["candidate_frontier"])
        summary = dict(artifacts["summary"])
        summary["source_artifacts"] = {
            "topology_closure_summary": {
                "path": str(closure_summary_path),
                "sha256": _sha256(closure_summary_path),
            },
            "topology_pair_partition": {
                "path": str(partition_path),
                "sha256": _sha256(partition_path),
            },
            "all_commits": {
                "path": str(commits_path),
                "sha256": _sha256(commits_path),
            },
            "ai_commits": {
                "path": str(ai_rows_path),
                "sha256": _sha256(ai_rows_path),
            },
        }
        summary["output_artifacts"] = {
            "residual_pairs": {
                "path": str(pairs_path),
                "sha256": _sha256(pairs_path),
            },
            "candidate_frontier": {
                "path": str(frontier_path),
                "sha256": _sha256(frontier_path),
            },
        }
        _atomic_jsonl(summary_path, [summary], pretty=True)
    except TopologyOverlapError as exc:
        raise SystemExit(f"topology overlap failed: {exc}") from exc
    print("Observed-AI topology residual overlap overlay frozen")
    print(f"  retained pairs : {summary['retained_residual_pair_count']}")
    print(f"  exact paths    : {summary['exact_path_overlap_pair_count']}")
    print(f"  topology only  : {summary['topology_only_retained_pair_count']}")
    print(f"  candidate lane : {summary['candidate_frontier_count']}")
    print(f"  output         : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
