#!/usr/bin/env python3
"""Recover exact patch-equivalent carriers for topology-residual AI pairs.

Stable patch-id equality is add-only relation evidence for cherry-picks,
duplicated branch commits, and one-commit squash landings.  It never labels the
equivalent carrier as a repair and never removes pairs without an equality.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from cohort_coolify_fix_preimage_lineage import LineageEvidenceError, _git_text
from cohort_coolify_preimage_exact_delta_bridge import (
    _EMPTY_TREE_SHA,
    _revision_parents,
)


_PATCH_ID_RE = re.compile(r"^([0-9a-f]{40})\s+[0-9a-f]{40}$")


class PatchRelationError(ValueError):
    """Patch-equivalence evidence could not be conserved."""


@dataclass(frozen=True)
class PatchIdEvidence:
    sha: str
    parent_patch_ids: tuple[tuple[str, str], ...]
    coverage_gaps: tuple[str, ...] = ()

    @property
    def patch_ids(self) -> frozenset[str]:
        return frozenset(patch_id for _, patch_id in self.parent_patch_ids)


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
        raise PatchRelationError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PatchRelationError(f"{path} must contain an object")
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
                    raise PatchRelationError(
                        f"{path}:{line_number} must contain an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchRelationError(f"cannot load {path}: {exc}") from exc
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stable_patch_id(patch: str, *, timeout: int) -> str:
    try:
        completed = subprocess.run(
            ["git", "patch-id", "--stable"],
            input=patch,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LineageEvidenceError(f"git patch-id failed: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().replace("\n", " ")[:500]
        raise LineageEvidenceError(
            f"git patch-id exited {completed.returncode}: {detail}"
        )
    output = completed.stdout.strip()
    if not output:
        return ""
    lines = output.splitlines()
    if len(lines) != 1:
        raise LineageEvidenceError("git patch-id returned multiple records")
    match = _PATCH_ID_RE.fullmatch(lines[0])
    if not match:
        raise LineageEvidenceError("git patch-id returned a malformed record")
    return match.group(1)


def _inspect_patch_ids(
    repository: Path, sha: str, *, timeout: int
) -> PatchIdEvidence:
    try:
        parents = _revision_parents(repository, sha, timeout=timeout)
    except LineageEvidenceError as exc:
        return PatchIdEvidence(sha, (), (str(exc),))
    compared = parents or (_EMPTY_TREE_SHA,)
    records: list[tuple[str, str]] = []
    gaps: list[str] = []
    for parent in compared:
        try:
            patch = _git_text(
                repository,
                [
                    "-c",
                    "core.quotePath=false",
                    "diff",
                    "--no-color",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--binary",
                    parent,
                    sha,
                    "--",
                ],
                timeout=timeout,
            )
            patch_id = _stable_patch_id(patch, timeout=timeout)
            if patch_id:
                records.append((parent, patch_id))
        except LineageEvidenceError as exc:
            gaps.append(f"parent {parent}: {exc}")
    return PatchIdEvidence(
        sha=sha,
        parent_patch_ids=tuple(sorted(set(records))),
        coverage_gaps=tuple(gaps),
    )


def build_patch_relations(
    *,
    overlap_summary: Mapping[str, object],
    pair_rows: Sequence[Mapping[str, object]],
    evidence_by_sha: Mapping[str, PatchIdEvidence],
    split_id: str,
) -> dict[str, object]:
    if overlap_summary.get("all_residual_pairs_conserved") is not True:
        raise PatchRelationError("residual overlap source is not conservative")
    expected = int(overlap_summary.get("retained_residual_pair_count") or -1)
    if len(pair_rows) != expected:
        raise PatchRelationError("residual pair count drift")
    relation_rows: list[dict[str, object]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for pair in pair_rows:
        candidate_sha = str(pair.get("candidate_sha") or "")
        carrier_sha = str(pair.get("fix_sha") or "")
        key = (candidate_sha, carrier_sha)
        if key in seen_pairs:
            raise PatchRelationError("duplicate residual pair")
        seen_pairs.add(key)
        candidate_evidence = evidence_by_sha.get(candidate_sha)
        carrier_evidence = evidence_by_sha.get(carrier_sha)
        if candidate_evidence is None or carrier_evidence is None:
            raise PatchRelationError("patch-id evidence omitted a residual commit")
        shared = sorted(candidate_evidence.patch_ids & carrier_evidence.patch_ids)
        if not shared:
            continue
        candidate_parents: defaultdict[str, list[str]] = defaultdict(list)
        carrier_parents: defaultdict[str, list[str]] = defaultdict(list)
        for parent, patch_id in candidate_evidence.parent_patch_ids:
            if patch_id in shared:
                candidate_parents[patch_id].append(parent)
        for parent, patch_id in carrier_evidence.parent_patch_ids:
            if patch_id in shared:
                carrier_parents[patch_id].append(parent)
        relation_rows.append(
            {
                "candidate_sha": candidate_sha,
                "carrier_sha": carrier_sha,
                "relation": "stable_patch_id_equivalent",
                "shared_patch_ids": shared,
                "candidate_parent_evidence": dict(sorted(candidate_parents.items())),
                "carrier_parent_evidence": dict(sorted(carrier_parents.items())),
                "candidate_subject": pair.get("candidate_subject"),
                "carrier_subject": pair.get("fix_subject"),
                "carrier_original_route": pair.get("fix_original_route"),
                "topology_relation": pair.get("topology_relation"),
                "relation_is_not_fix_label": True,
                "retained_source_pair": pair.get("retained") is True,
            }
        )
    relation_rows.sort(
        key=lambda row: (str(row["carrier_sha"]), str(row["candidate_sha"]))
    )
    gaps = {
        sha: list(evidence.coverage_gaps)
        for sha, evidence in evidence_by_sha.items()
        if evidence.coverage_gaps
    }
    patch_clusters: defaultdict[str, set[str]] = defaultdict(set)
    for evidence in evidence_by_sha.values():
        for patch_id in evidence.patch_ids:
            patch_clusters[patch_id].add(evidence.sha)
    duplicate_clusters = {
        patch_id: sorted(shas)
        for patch_id, shas in patch_clusters.items()
        if len(shas) > 1
    }
    summary = {
        "schema_version": 1,
        "artifact_kind": "observed_ai_topology_stable_patch_id_relations",
        "split_id": split_id,
        "repository_identity": overlap_summary.get("repository_identity"),
        "source_residual_pair_count": expected,
        "inspected_unique_commit_count": len(evidence_by_sha),
        "patch_id_coverage_gap_commit_count": len(gaps),
        "patch_id_coverage_gaps": gaps,
        "duplicate_patch_id_cluster_count": len(duplicate_clusters),
        "exact_patch_equivalent_relation_count": len(relation_rows),
        "unique_ai_candidate_count": len(
            {str(row["candidate_sha"]) for row in relation_rows}
        ),
        "unique_carrier_count": len({str(row["carrier_sha"]) for row in relation_rows}),
        "source_pair_membership_unchanged": True,
        "hard_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "claim_boundary": (
            "Stable patch-id equality proves patch equivalence under Git's patch-id "
            "semantics. It is carrier relation evidence, not a repair or causality "
            "label. Pairs without equality and inspection gaps remain in the source "
            "topology residual universe."
        ),
    }
    return {"summary": summary, "relations": relation_rows}


def _atomic_jsonl(
    path: Path, rows: Iterable[object], *, pretty: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise PatchRelationError(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if pretty:
                materialized = list(rows)
                if len(materialized) != 1:
                    raise PatchRelationError("pretty output requires one value")
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
        evidence_by_sha: dict[str, PatchIdEvidence] = {}
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    _inspect_patch_ids,
                    repository,
                    sha,
                    timeout=args.repo_timeout,
                ): sha
                for sha in unique_shas
            }
            for index, future in enumerate(as_completed(futures), start=1):
                evidence = future.result()
                evidence_by_sha[evidence.sha] = evidence
                if index % 100 == 0 or index == len(unique_shas):
                    print(
                        f"topology patch-id commits inspected: {index}/{len(unique_shas)}",
                        flush=True,
                    )
        artifacts = build_patch_relations(
            overlap_summary=overlap_summary,
            pair_rows=pair_rows,
            evidence_by_sha=evidence_by_sha,
            split_id=args.split_id,
        )
        relations_path = output_dir / "relations.jsonl"
        output_summary_path = output_dir / "summary.json"
        _atomic_jsonl(relations_path, artifacts["relations"])
        summary = dict(artifacts["summary"])
        summary["configuration"] = {
            "patch_id_mode": "stable",
            "parent_policy": "all_parents_union",
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
            "relations": {
                "path": str(relations_path),
                "sha256": _sha256(relations_path),
            }
        }
        _atomic_jsonl(output_summary_path, [summary], pretty=True)
    except PatchRelationError as exc:
        raise SystemExit(f"topology patch-id relation failed: {exc}") from exc
    print("Observed-AI topology patch-id relations frozen")
    print(f"  source pairs   : {summary['source_residual_pair_count']}")
    print(f"  exact relations: {summary['exact_patch_equivalent_relation_count']}")
    print(f"  coverage gaps  : {summary['patch_id_coverage_gap_commit_count']}")
    print(f"  output         : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
