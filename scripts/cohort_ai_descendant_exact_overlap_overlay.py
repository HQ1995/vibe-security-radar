#!/usr/bin/env python3
"""Materialize exact-path review overlays over a lossless AI-descendant census.

The source census remains the candidate universe.  This overlay expands only
pairs with at least one exact changed path so reviewers can work efficiently;
all cross-file pairs remain represented by the source bitsets and are counted
explicitly in the conservation summary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path


_SECURITY_RE = re.compile(
    r"(?:security|vulnerab|injection|authoriz|permission|access|escape|"
    r"validate|sanitize|harden|prevent|restrict|secret|token|path traversal)",
    re.IGNORECASE,
)
_REPAIR_RE = re.compile(
    r"(?:^fix(?:\(|:|\b)|\b(?:fix|repair|prevent|enforce|reject|block)\b)",
    re.IGNORECASE,
)
_PRODUCTION_PREFIXES = (
    "app/",
    "api/",
    "bootstrap/",
    "config/",
    "database/migrations/",
    "packages/",
    "resources/js/",
    "resources/views/",
    "routes/",
    "src/",
)
_LANE_BONUS = {
    "sealed_existing_root": 120,
    "explicit_security_or_regression": 110,
    "added_check_or_guard": 95,
    "repair_action_subject": 70,
    "merge_carrier_with_repair_signal": 55,
    "test_change_fallback": 45,
    "direct_ancestry_fallback": 20,
    "merge_carrier_fallback": 0,
}


class ExactOverlapOverlayError(ValueError):
    """The source census or overlay contract is malformed."""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExactOverlapOverlayError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExactOverlapOverlayError(f"{path} must contain an object")
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
                    raise ExactOverlapOverlayError(
                        f"{path}:{line_number} is not an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise ExactOverlapOverlayError(f"cannot load {path}: {exc}") from exc
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
        raise ExactOverlapOverlayError(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if pretty:
                materialized = list(rows)
                if len(materialized) != 1:
                    raise ExactOverlapOverlayError("pretty output requires one value")
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


def _path_class(source_path: str) -> str:
    lowered = source_path.casefold()
    if lowered.startswith("tests/") or "/tests/" in f"/{lowered}":
        return "test"
    if lowered.startswith(_PRODUCTION_PREFIXES):
        return "production"
    return "nonproduction"


def _confirmed_sets(
    ledger: Mapping[str, object],
) -> tuple[set[tuple[str, str]], set[str]]:
    rows = ledger.get("edge_ledger")
    if not isinstance(rows, list):
        raise ExactOverlapOverlayError("ledger edge_ledger is malformed")
    edges: set[tuple[str, str]] = set()
    candidates: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("status") != "CONFIRMED_TRUE_POSITIVE":
            continue
        candidate = str(row.get("candidate_sha") or "")
        fix = str(row.get("fix_sha") or "")
        edges.add((candidate, fix))
        candidates.add(candidate)
    return edges, candidates


def _review_priority(
    *,
    root: Mapping[str, object],
    candidate: Mapping[str, object],
    production_paths: list[str],
    test_paths: list[str],
    nonproduction_paths: list[str],
    confirmed_edge: bool,
    confirmed_candidate: bool,
) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = int(root.get("review_score") or 0)
    lane = str(root.get("review_lane") or "")
    score += _LANE_BONUS.get(lane, 0)
    reasons.append(f"root_lane:{lane or 'unknown'}")
    topology_kind = str(root.get("topology_kind") or "")
    if topology_kind == "merge_carrier":
        score -= 260
        reasons.append("merge_carrier_penalty:260")
    root_parents = {str(value) for value in root.get("parents", [])}
    candidate_is_direct_parent = str(candidate.get("sha") or "") in root_parents
    if candidate_is_direct_parent:
        score -= 700
        reasons.append("candidate_is_direct_parent_penalty:700")
    ancestor_count = int(root.get("strict_ai_ancestor_count") or 0)
    fanout_penalty = round(math.log2(max(ancestor_count, 1)) * 32)
    score -= fanout_penalty
    reasons.append(f"root_fanout_penalty:{fanout_penalty}")
    root_paths = {str(value) for value in root.get("changed_paths", [])}
    root_breadth_penalty = min(len(root_paths) * 2, 180)
    score -= root_breadth_penalty
    reasons.append(f"root_path_breadth_penalty:{root_breadth_penalty}")
    if production_paths:
        score += 90 + min(len(production_paths), 6) * 18
        reasons.append("exact_production_path_overlap")
    elif test_paths:
        score += 35 + min(len(test_paths), 4) * 8
        reasons.append("exact_test_path_overlap_only")
    else:
        score += 10 + min(len(nonproduction_paths), 4) * 3
        reasons.append("exact_nonproduction_path_overlap_only")
    message = str(candidate.get("message") or "")
    if _SECURITY_RE.search(message):
        score += 45
        reasons.append("candidate_security_language")
    if _REPAIR_RE.search(message):
        score += 20
        reasons.append("candidate_repair_language")
    candidate_paths = [str(value) for value in candidate.get("changed_files", [])]
    shared_count = len(production_paths) + len(test_paths) + len(nonproduction_paths)
    smaller_patch_size = max(min(len(candidate_paths), len(root_paths)), 1)
    union_size = max(len(set(candidate_paths) | root_paths), 1)
    specificity_bonus = round(
        150 * shared_count / smaller_patch_size + 80 * shared_count / union_size
    )
    score += specificity_bonus
    reasons.append(f"path_specificity_bonus:{specificity_bonus}")
    try:
        candidate_date = datetime.fromisoformat(str(candidate.get("authored_date")))
        fix_date = datetime.fromisoformat(str(root.get("authored_at")))
        gap_days = max((fix_date - candidate_date).days, 0)
    except ValueError:
        gap_days = None
    if gap_days is not None:
        if gap_days <= 7:
            gap_bonus = 100
        elif gap_days <= 30:
            gap_bonus = 75
        elif gap_days <= 90:
            gap_bonus = 45
        elif gap_days <= 180:
            gap_bonus = 20
        elif gap_days <= 365:
            gap_bonus = 0
        else:
            gap_bonus = -40
        score += gap_bonus
        reasons.append(f"temporal_gap_days:{gap_days}")
        reasons.append(f"temporal_gap_bonus:{gap_bonus}")
    if any(_path_class(path) == "test" for path in candidate_paths):
        score += 12
        reasons.append("candidate_changes_tests")
    if not confirmed_candidate:
        score += 80
        reasons.append("new_unique_candidate_opportunity")
    if confirmed_edge:
        score -= 10_000
        reasons.append("already_confirmed_edge")
    return score, reasons


def build_exact_overlap_overlay(
    *,
    census_summary: Mapping[str, object],
    ancestor_index: Mapping[str, object],
    commit_rows: list[dict[str, object]],
    ai_rows: list[dict[str, object]],
    ledger: Mapping[str, object],
    split_id: str,
) -> dict[str, object]:
    ai_shas_raw = ancestor_index.get("ai_shas")
    if not isinstance(ai_shas_raw, list):
        raise ExactOverlapOverlayError("AI ancestor index has no ai_shas")
    ai_shas = [str(value) for value in ai_shas_raw]
    ai_by_sha = {str(row.get("sha") or ""): row for row in ai_rows}
    if ai_shas != sorted(ai_by_sha):
        raise ExactOverlapOverlayError("AI scan and ancestor index disagree")
    bitset_width = int(ancestor_index.get("bitset_hex_width") or 0)
    expected_width = (len(ai_shas) + 3) // 4
    if bitset_width != expected_width:
        raise ExactOverlapOverlayError("AI ancestor bitset width is invalid")
    confirmed_edges, confirmed_candidates = _confirmed_sets(ledger)

    direct_pair_count = 0
    pair_rows: list[dict[str, object]] = []
    class_counts: Counter[str] = Counter()
    roots_with_overlap: set[str] = set()
    for root in commit_rows:
        strict_count = int(root.get("strict_ai_ancestor_count") or 0)
        if root.get("route") != "direct_ai_ancestry":
            if strict_count:
                raise ExactOverlapOverlayError("non-direct root has strict ancestors")
            continue
        encoded = str(root.get("ai_ancestor_bitset_hex") or "")
        if len(encoded) != bitset_width:
            raise ExactOverlapOverlayError("direct root has malformed ancestor bitset")
        bits = int(encoded, 16)
        if bits.bit_count() != strict_count:
            raise ExactOverlapOverlayError("direct root bit count mismatch")
        direct_pair_count += strict_count
        fix_paths = {str(value) for value in root.get("changed_paths", [])}
        fix_sha = str(root.get("sha") or "")
        while bits:
            low_bit = bits & -bits
            index = low_bit.bit_length() - 1
            bits ^= low_bit
            candidate_sha = ai_shas[index]
            candidate = ai_by_sha[candidate_sha]
            candidate_paths = {
                str(value) for value in candidate.get("changed_files", [])
            }
            shared = sorted(fix_paths & candidate_paths)
            if not shared:
                continue
            roots_with_overlap.add(fix_sha)
            production_paths = [
                path for path in shared if _path_class(path) == "production"
            ]
            test_paths = [path for path in shared if _path_class(path) == "test"]
            nonproduction_paths = [
                path for path in shared if _path_class(path) == "nonproduction"
            ]
            pair_class = (
                "exact_production_overlap"
                if production_paths
                else "exact_test_only_overlap"
                if test_paths
                else "exact_nonproduction_only_overlap"
            )
            class_counts[pair_class] += 1
            edge = (candidate_sha, fix_sha)
            score, reasons = _review_priority(
                root=root,
                candidate=candidate,
                production_paths=production_paths,
                test_paths=test_paths,
                nonproduction_paths=nonproduction_paths,
                confirmed_edge=edge in confirmed_edges,
                confirmed_candidate=candidate_sha in confirmed_candidates,
            )
            pair_rows.append(
                {
                    "candidate_sha": candidate_sha,
                    "candidate_authored_at": candidate.get("authored_date"),
                    "candidate_subject": str(candidate.get("message") or "").split(
                        "\n", 1
                    )[0],
                    "candidate_changed_path_count": len(candidate_paths),
                    "fix_sha": fix_sha,
                    "fix_authored_at": root.get("authored_at"),
                    "fix_subject": root.get("subject"),
                    "fix_topology_kind": root.get("topology_kind"),
                    "fix_parent_count": len(root.get("parents", [])),
                    "fix_review_lane": root.get("review_lane"),
                    "fix_review_tier": root.get("review_tier"),
                    "fix_review_signals": root.get("review_signals", []),
                    "fix_strict_ai_ancestor_count": strict_count,
                    "fix_changed_path_count": len(fix_paths),
                    "pair_class": pair_class,
                    "shared_production_paths": production_paths,
                    "shared_test_paths": test_paths,
                    "shared_nonproduction_paths": nonproduction_paths,
                    "review_priority_score": score,
                    "review_priority_reasons": reasons,
                    "already_confirmed_edge": edge in confirmed_edges,
                    "candidate_already_confirmed_elsewhere": (
                        candidate_sha in confirmed_candidates
                    ),
                    "candidate_is_direct_parent_of_fix": (
                        candidate_sha
                        in {str(value) for value in root.get("parents", [])}
                    ),
                    "retained": True,
                }
            )

    expected_pairs = int(census_summary.get("direct_ancestry_pair_count") or -1)
    if direct_pair_count != expected_pairs:
        raise ExactOverlapOverlayError(
            f"direct pair mismatch: {direct_pair_count} != {expected_pairs}"
        )
    pair_rows.sort(
        key=lambda row: (
            -int(row["review_priority_score"]),
            str(row["fix_sha"]),
            str(row["candidate_sha"]),
        )
    )
    for rank, row in enumerate(pair_rows, start=1):
        row["review_priority_rank"] = rank

    best_by_candidate: dict[str, dict[str, object]] = {}
    for row in pair_rows:
        if row["already_confirmed_edge"]:
            continue
        best_by_candidate.setdefault(str(row["candidate_sha"]), row)
    candidate_frontier = [
        {
            **row,
            "frontier_kind": "best_exact_overlap_per_ai_candidate",
        }
        for row in best_by_candidate.values()
    ]
    materialized_count = len(pair_rows)
    compressed_cross_file_count = direct_pair_count - materialized_count
    summary = {
        "schema_version": 1,
        "artifact_kind": "ai_descendant_exact_path_overlap_overlay",
        "split_id": split_id,
        "repository_identity": census_summary.get("repository_identity"),
        "source_direct_ancestry_pair_count": direct_pair_count,
        "materialized_exact_path_pair_count": materialized_count,
        "compressed_cross_file_pair_count": compressed_cross_file_count,
        "pair_class_counts": dict(sorted(class_counts.items())),
        "roots_with_exact_overlap_count": len(roots_with_overlap),
        "candidate_frontier_count": len(candidate_frontier),
        "already_confirmed_exact_edge_count": sum(
            bool(row["already_confirmed_edge"]) for row in pair_rows
        ),
        "all_source_pairs_conserved": (
            materialized_count + compressed_cross_file_count == direct_pair_count
        ),
        "hard_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "claim_boundary": (
            "Exact changed-path overlap changes review order only. Pairs without "
            "an exact shared path remain losslessly represented by the source "
            "ancestor bitsets and are counted as the compressed cross-file lane. "
            "Neither overlap nor priority is a causal or vulnerability label."
        ),
    }
    return {
        "summary": summary,
        "pairs": pair_rows,
        "candidate_frontier": candidate_frontier,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    census_dir = args.census_dir.resolve()
    ai_scan_dir = args.ai_scan_dir.resolve()
    summary_path = census_dir / "summary.json"
    index_path = census_dir / "ancestor_index.json"
    commits_path = census_dir / "all_commits.jsonl"
    ai_path = ai_scan_dir / "commits.jsonl"
    artifacts = build_exact_overlap_overlay(
        census_summary=_load_json(summary_path),
        ancestor_index=_load_json(index_path),
        commit_rows=_load_jsonl(commits_path),
        ai_rows=_load_jsonl(ai_path),
        ledger=_load_json(args.ledger.resolve()),
        split_id=args.split_id,
    )
    output_dir = args.output_dir.resolve()
    pairs_path = output_dir / "exact_overlap_pairs.jsonl"
    frontier_path = output_dir / "candidate_frontier.jsonl"
    summary_output = output_dir / "summary.json"
    _atomic_jsonl(pairs_path, artifacts["pairs"])
    _atomic_jsonl(frontier_path, artifacts["candidate_frontier"])
    summary = dict(artifacts["summary"])
    summary["source_artifacts"] = {
        "census_summary": {"path": str(summary_path), "sha256": _sha256(summary_path)},
        "ancestor_index": {"path": str(index_path), "sha256": _sha256(index_path)},
        "all_commits": {"path": str(commits_path), "sha256": _sha256(commits_path)},
        "ai_commits": {"path": str(ai_path), "sha256": _sha256(ai_path)},
        "ledger": {
            "path": str(args.ledger.resolve()),
            "sha256": _sha256(args.ledger.resolve()),
        },
    }
    summary["output_artifacts"] = {
        "exact_overlap_pairs": {
            "path": str(pairs_path),
            "sha256": _sha256(pairs_path),
        },
        "candidate_frontier": {
            "path": str(frontier_path),
            "sha256": _sha256(frontier_path),
        },
    }
    _atomic_json(summary_output, summary)
    print("AI-descendant exact-overlap overlay frozen")
    print(
        "  materialized : "
        f"{summary['materialized_exact_path_pair_count']}"
    )
    print(f"  cross-file   : {summary['compressed_cross_file_pair_count']}")
    print(f"  frontier     : {summary['candidate_frontier_count']}")
    print(f"  output       : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
