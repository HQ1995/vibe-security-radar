#!/usr/bin/env python3
"""Validate prospective intake, all-commit universes, and source replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intake-dir", type=Path, required=True)
    parser.add_argument("--universe-dir", type=Path, required=True)
    parser.add_argument("--source-replay-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _unique_pairs(rows: list[dict[str, object]], label: str) -> set[tuple[str, str]]:
    pairs = [
        (
            str(row.get("repository_identity") or "").strip().lower(),
            str(row.get("advisory") or "").strip(),
        )
        for row in rows
    ]
    if any(not repository or not advisory for repository, advisory in pairs):
        raise SystemExit(f"{label} contains an empty repository/advisory pair")
    if len(pairs) != len(set(pairs)):
        raise SystemExit(f"{label} contains duplicate repository/advisory pairs")
    return set(pairs)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    selected = _load_jsonl(args.intake_dir / "selected.jsonl")
    selected_pairs = _unique_pairs(selected, "selected intake")
    selected_repositories = {repository for repository, _advisory in selected_pairs}
    if len(selected_pairs) != len(selected_repositories):
        raise SystemExit("selected intake is not repository-disjoint")

    universe_summaries = _load_jsonl(
        args.universe_dir / "repository_universes.jsonl"
    )
    summary_by_repository = {
        str(row["repository_identity"]): row for row in universe_summaries
    }
    if set(summary_by_repository) != selected_repositories:
        raise SystemExit("repository universes do not conserve selected repositories")
    if len(summary_by_repository) != len(universe_summaries):
        raise SystemExit("duplicate repository universe summary")

    commit_rows = _load_jsonl(args.universe_dir / "commit_universe.jsonl")
    commits_by_repository: Counter[str] = Counter()
    ai_by_repository: Counter[str] = Counter()
    commit_keys: set[tuple[str, str]] = set()
    for row in commit_rows:
        repository = str(row.get("repository_identity") or "")
        sha = str(row.get("sha") or "")
        key = (repository, sha)
        if repository not in selected_repositories or key in commit_keys:
            raise SystemExit("commit universe has an outside or duplicate commit")
        commit_keys.add(key)
        commits_by_repository[repository] += 1
        ai_by_repository[repository] += row.get("observed_ai_unit") is True
    for repository, summary in summary_by_repository.items():
        if commits_by_repository[repository] != summary["visible_commit_count"]:
            raise SystemExit(f"visible commit count mismatch: {repository}")
        if ai_by_repository[repository] != summary["observed_ai_unit_count"]:
            raise SystemExit(f"AI overlay count mismatch: {repository}")

    fallbacks = _load_jsonl(args.universe_dir / "repository_fallbacks.jsonl")
    if _unique_pairs(fallbacks, "repository fallbacks") != selected_pairs:
        raise SystemExit("repository fallbacks do not conserve selected pairs")
    associations = _load_jsonl(
        args.source_replay_dir / "repository_advisory_associations.jsonl"
    )
    if _unique_pairs(associations, "source associations") != selected_pairs:
        raise SystemExit("source associations do not conserve selected pairs")

    observations = _load_jsonl(
        args.source_replay_dir / "fix_source_observations.jsonl"
    )
    observation_ids: set[str] = set()
    observation_statuses: Counter[str] = Counter()
    for row in observations:
        identifier = str(row.get("observation_id") or "")
        pair = (
            str(row.get("repository_identity") or ""),
            str(row.get("advisory") or ""),
        )
        status = str(row.get("resolution_status") or "")
        if not identifier or identifier in observation_ids or pair not in selected_pairs:
            raise SystemExit("source observation identity or pair is invalid")
        if status not in {"RESOLVED", "BLOCKED"}:
            raise SystemExit("source observation status is invalid")
        observation_ids.add(identifier)
        observation_statuses[status] += 1

    roots = _load_jsonl(args.source_replay_dir / "source_roots.jsonl")
    root_bits: dict[str, set[int]] = defaultdict(set)
    root_statuses: Counter[str] = Counter()
    rooted_pairs: set[tuple[str, str]] = set()
    for row in roots:
        repository = str(row.get("repository_identity") or "")
        bit = row.get("bit_index")
        if repository not in selected_repositories or not isinstance(bit, int):
            raise SystemExit("source root repository or bit is invalid")
        if bit in root_bits[repository]:
            raise SystemExit("duplicate source root bit")
        root_bits[repository].add(bit)
        status = str(row.get("status") or "")
        if status not in {"RESOLVED", "BLOCKED"}:
            raise SystemExit("source root status is invalid")
        root_statuses[status] += 1
        for advisory in row.get("advisories", []):
            pair = (repository, str(advisory))
            if pair not in selected_pairs:
                raise SystemExit("source root points outside selected pairs")
            rooted_pairs.add(pair)

    memberships = _load_jsonl(args.source_replay_dir / "root_membership.jsonl")
    membership_keys: set[tuple[str, str]] = set()
    for row in memberships:
        repository = str(row.get("repository_identity") or "")
        sha = str(row.get("sha") or "")
        key = (repository, sha)
        try:
            mask = int(str(row.get("root_mask_hex") or ""), 16)
        except ValueError as exc:
            raise SystemExit("root membership mask is malformed") from exc
        if key not in commit_keys or key in membership_keys or mask <= 0:
            raise SystemExit("root membership is outside or duplicates commit universe")
        if mask.bit_length() > len(root_bits[repository]):
            raise SystemExit("root membership references an undefined bit")
        membership_keys.add(key)

    replay_summary = _load_json(args.source_replay_dir / "summary.json")
    if not isinstance(replay_summary, dict):
        raise SystemExit("source replay summary is malformed")
    expected_metrics = {
        "selected_pair_count": len(selected_pairs),
        "association_count": len(associations),
        "source_observation_count": len(observations),
        "resolved_root_hint_count": len(roots),
        "root_membership_row_count": len(memberships),
        "fallback_count": len(fallbacks),
    }
    for field, expected in expected_metrics.items():
        if replay_summary.get(field) != expected:
            raise SystemExit(f"source replay summary mismatch: {field}")

    result = {
        "schema_version": 1,
        "artifact_kind": "prospective_replay_conservation_validation",
        "gate_status": "PASS",
        "selected_pair_count": len(selected_pairs),
        "selected_repository_count": len(selected_repositories),
        "commit_universe_count": len(commit_rows),
        "ai_overlay_commit_count": sum(ai_by_repository.values()),
        "unlabeled_commit_count": len(commit_rows) - sum(ai_by_repository.values()),
        "fallback_count": len(fallbacks),
        "source_observation_count": len(observations),
        "source_observation_status_counts": dict(sorted(observation_statuses.items())),
        "root_hint_count": len(roots),
        "root_status_counts": dict(sorted(root_statuses.items())),
        "rooted_pair_count": len(rooted_pairs),
        "membership_row_count": len(memberships),
        "checks": {
            "selected_repositories_disjoint": True,
            "commit_rows_unique": True,
            "AI_overlays_conserved": True,
            "fallback_pairs_conserved": True,
            "source_associations_conserved": True,
            "source_observations_conserved": True,
            "root_bits_valid": True,
            "membership_subset_of_all_commit_universe": True,
            "summary_metrics_recomputed": True,
        },
        "input_sha256": {
            "selected": _sha256_file(args.intake_dir / "selected.jsonl"),
            "repository_universes": _sha256_file(
                args.universe_dir / "repository_universes.jsonl"
            ),
            "commit_universe": _sha256_file(
                args.universe_dir / "commit_universe.jsonl"
            ),
            "repository_fallbacks": _sha256_file(
                args.universe_dir / "repository_fallbacks.jsonl"
            ),
            "source_observations": _sha256_file(
                args.source_replay_dir / "fix_source_observations.jsonl"
            ),
            "source_roots": _sha256_file(
                args.source_replay_dir / "source_roots.jsonl"
            ),
            "root_membership": _sha256_file(
                args.source_replay_dir / "root_membership.jsonl"
            ),
        },
    }
    _atomic_write(args.output, result)
    print("prospective replay conservation validation: PASS")
    print(f"  selected pairs        : {len(selected_pairs)}")
    print(f"  all commits           : {len(commit_rows):,}")
    print(f"  unlabeled commits     : {result['unlabeled_commit_count']:,}")
    print(f"  source observations   : {len(observations)}")
    print(f"  root hints            : {len(roots)}")
    print(f"  fallback pairs        : {len(fallbacks)}")
    print(f"  output                : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
