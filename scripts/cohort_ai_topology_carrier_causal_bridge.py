#!/usr/bin/env python3
"""Join exact patch carriers to later topology-residual reverse deltas.

A graph-incomparable observed-AI commit can enter mainline through an equivalent
cherry-pick or squash carrier.  This bridge promotes review priority only when
that stable-patch-id carrier is a strict Git ancestor of the later reverse-delta
commit.  Carrier equality with the alleged fix is kept separate as a same-change
landing, not mislabeled as a repair.  Every reverse-delta lead remains retained.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path


_BRIDGE_CLASSES = {
    0: "C0_EXACT_CARRIER_ANCESTOR_WITH_SAME_PATH_REVERSAL",
    1: "C1_EXACT_CARRIER_ANCESTOR_WITH_WEAKER_REVERSAL",
    2: "C2_FIX_IS_EQUIVALENT_CARRIER_NOT_REPAIR",
    3: "C3_REVERSE_DELTA_WITHOUT_EXACT_CARRIER_RETAINED",
}
_CLASS_BONUS = {0: 8_000, 1: 4_000, 2: 500, 3: 0}


class CarrierBridgeError(ValueError):
    """Carrier relation and topology-delta evidence failed conservation."""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patch-relation-dir", type=Path, required=True)
    parser.add_argument("--topology-delta-dir", type=Path, required=True)
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CarrierBridgeError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CarrierBridgeError(f"{path} must contain an object")
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
                    raise CarrierBridgeError(
                        f"{path}:{line_number} must contain an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise CarrierBridgeError(f"cannot load {path}: {exc}") from exc
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _carrier_ancestor_bits(
    commit_rows: Sequence[Mapping[str, object]], carrier_shas: Sequence[str]
) -> tuple[dict[str, int], dict[str, int]]:
    carrier_index = {sha: index for index, sha in enumerate(sorted(carrier_shas))}
    complete_bits: dict[str, int] = {}
    strict_bits: dict[str, int] = {}
    for expected_order, row in enumerate(commit_rows, start=1):
        sha = str(row.get("sha") or "")
        if len(sha) != 40 or sha in complete_bits:
            raise CarrierBridgeError("census contains duplicate or malformed commit")
        if int(row.get("graph_order") or 0) != expected_order:
            raise CarrierBridgeError("census is not in frozen graph order")
        raw_parents = row.get("parents")
        if not isinstance(raw_parents, list):
            raise CarrierBridgeError(f"census parents are malformed at {sha}")
        inherited = 0
        for parent_value in raw_parents:
            parent = str(parent_value)
            if parent not in complete_bits:
                raise CarrierBridgeError(f"census is not parent-before-child at {sha}")
            inherited |= complete_bits[parent]
        strict_bits[sha] = inherited
        if sha in carrier_index:
            inherited |= 1 << carrier_index[sha]
        complete_bits[sha] = inherited
    if set(carrier_index) - set(complete_bits):
        raise CarrierBridgeError("patch relation carrier is outside the census graph")
    return carrier_index, strict_bits


def _candidate_patch_parents(relation: Mapping[str, object]) -> set[str]:
    raw_evidence = relation.get("candidate_parent_evidence")
    if not isinstance(raw_evidence, Mapping):
        raise CarrierBridgeError("patch relation candidate-parent evidence is malformed")
    parents: set[str] = set()
    for raw_parents in raw_evidence.values():
        if not isinstance(raw_parents, list):
            raise CarrierBridgeError(
                "patch relation candidate-parent evidence is malformed"
            )
        parents.update(str(parent) for parent in raw_parents)
    if not parents:
        raise CarrierBridgeError("patch relation has no candidate patch parent")
    return parents


def _linked_same_path_samples(
    delta: Mapping[str, object], ancestor_carriers: Sequence[Mapping[str, object]]
) -> list[dict[str, object]]:
    raw_samples = delta.get("reversal_match_sample")
    if not isinstance(raw_samples, list):
        raise CarrierBridgeError("topology delta reversal sample is malformed")
    linked: list[dict[str, object]] = []
    for raw_sample in raw_samples:
        if not isinstance(raw_sample, Mapping):
            raise CarrierBridgeError("topology delta reversal sample is malformed")
        if (
            raw_sample.get("match_kind") != "exact_same_path"
            or raw_sample.get("meaningful") is not True
            or raw_sample.get("generated_or_machine_artifact") is True
        ):
            continue
        candidate_parent = str(raw_sample.get("candidate_parent_sha") or "")
        matching_carriers = sorted(
            str(carrier["carrier_sha"])
            for carrier in ancestor_carriers
            if candidate_parent in _candidate_patch_parents(carrier)
        )
        if matching_carriers:
            linked.append(
                {
                    **dict(raw_sample),
                    "matching_strict_ancestor_carriers": matching_carriers,
                }
            )
    return linked


def build_carrier_bridge(
    *,
    patch_summary: Mapping[str, object],
    relation_rows: Sequence[Mapping[str, object]],
    delta_summary: Mapping[str, object],
    exact_delta_rows: Sequence[Mapping[str, object]],
    commit_rows: Sequence[Mapping[str, object]],
    split_id: str,
) -> dict[str, object]:
    if patch_summary.get("source_pair_membership_unchanged") is not True:
        raise CarrierBridgeError("patch relation source changed pair membership")
    if patch_summary.get("hard_filter_count") != 0:
        raise CarrierBridgeError("patch relation source filtered pairs")
    if delta_summary.get("all_residual_pairs_conserved") is not True:
        raise CarrierBridgeError("topology delta source is not conservative")
    if delta_summary.get("hard_filter_count") != 0:
        raise CarrierBridgeError("topology delta source filtered pairs")
    expected_relations = int(
        patch_summary.get("exact_patch_equivalent_relation_count") or -1
    )
    expected_exact = int(
        delta_summary.get("exact_or_normalized_reversal_pair_count") or -1
    )
    if len(relation_rows) != expected_relations or len(exact_delta_rows) != expected_exact:
        raise CarrierBridgeError("source relation or exact-delta count drift")

    relations_by_candidate: defaultdict[str, list[Mapping[str, object]]] = defaultdict(
        list
    )
    carrier_shas: set[str] = set()
    relation_keys: set[tuple[str, str]] = set()
    for relation in relation_rows:
        candidate = str(relation.get("candidate_sha") or "")
        carrier = str(relation.get("carrier_sha") or "")
        key = (candidate, carrier)
        if key in relation_keys or relation.get("relation") != (
            "stable_patch_id_equivalent"
        ):
            raise CarrierBridgeError("duplicate or malformed patch relation")
        relation_keys.add(key)
        relations_by_candidate[candidate].append(relation)
        carrier_shas.add(carrier)
    carrier_index, strict_bits_by_fix = _carrier_ancestor_bits(
        commit_rows, sorted(carrier_shas)
    )

    output_rows: list[dict[str, object]] = []
    seen_edges: set[tuple[str, str]] = set()
    for delta in exact_delta_rows:
        candidate = str(delta.get("candidate_sha") or "")
        fix = str(delta.get("fix_sha") or "")
        edge = (candidate, fix)
        if edge in seen_edges or fix not in strict_bits_by_fix:
            raise CarrierBridgeError("duplicate exact edge or fix outside census")
        seen_edges.add(edge)
        carrier_is_fix: list[dict[str, object]] = []
        ancestor_carriers: list[dict[str, object]] = []
        fix_strict_bits = strict_bits_by_fix[fix]
        for relation in relations_by_candidate.get(candidate, []):
            carrier = str(relation["carrier_sha"])
            evidence = {
                "carrier_sha": carrier,
                "shared_patch_ids": relation.get("shared_patch_ids", []),
                "candidate_parent_evidence": relation.get(
                    "candidate_parent_evidence", {}
                ),
                "carrier_parent_evidence": relation.get(
                    "carrier_parent_evidence", {}
                ),
            }
            if carrier == fix:
                carrier_is_fix.append(evidence)
            elif fix_strict_bits & (1 << carrier_index[carrier]):
                ancestor_carriers.append(evidence)
        carrier_linked_samples = _linked_same_path_samples(delta, ancestor_carriers)
        if ancestor_carriers and carrier_linked_samples:
            tier = 0
        elif ancestor_carriers:
            tier = 1
        elif carrier_is_fix:
            tier = 2
        else:
            tier = 3
        output_rows.append(
            {
                **dict(delta),
                "carrier_bridge_tier": tier,
                "carrier_bridge_class": _BRIDGE_CLASSES[tier],
                "carrier_bridge_score": int(
                    delta.get("delta_review_priority_score") or 0
                )
                + _CLASS_BONUS[tier],
                "strict_ancestor_carriers": ancestor_carriers,
                "carrier_linked_same_path_reversal_sample": carrier_linked_samples,
                "carrier_linked_same_path_reversal_sample_count": len(
                    carrier_linked_samples
                ),
                "equivalent_fix_carriers": carrier_is_fix,
                "compositional_carrier_path_present": bool(ancestor_carriers),
                "equivalent_fix_is_not_called_repair": bool(carrier_is_fix),
                "retained": True,
                "carrier_bridge_rank": None,
            }
        )
    if len(output_rows) != expected_exact:
        raise CarrierBridgeError("exact-delta leads were not conserved")
    output_rows.sort(
        key=lambda row: (
            int(row["carrier_bridge_tier"]),
            -int(row["carrier_bridge_score"]),
            str(row["fix_sha"]),
            str(row["candidate_sha"]),
        )
    )
    for rank, row in enumerate(output_rows, start=1):
        row["carrier_bridge_rank"] = rank
    compositional_queue = [
        row for row in output_rows if row["compositional_carrier_path_present"] is True
    ]
    class_counts = Counter(str(row["carrier_bridge_class"]) for row in output_rows)
    summary = {
        "schema_version": 1,
        "artifact_kind": "observed_ai_topology_compositional_carrier_causal_bridge",
        "split_id": split_id,
        "repository_identity": delta_summary.get("repository_identity"),
        "source_exact_reversal_pair_count": expected_exact,
        "retained_exact_reversal_pair_count": len(output_rows),
        "source_patch_equivalent_relation_count": expected_relations,
        "compositional_carrier_ancestor_pair_count": len(compositional_queue),
        "strong_same_path_compositional_pair_count": sum(
            row["carrier_bridge_tier"] == 0 for row in output_rows
        ),
        "fix_is_equivalent_carrier_pair_count": sum(
            row["carrier_bridge_tier"] == 2 for row in output_rows
        ),
        "carrier_bridge_class_counts": dict(sorted(class_counts.items())),
        "all_exact_reversal_pairs_conserved": len(output_rows) == expected_exact,
        "hard_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "claim_boundary": (
            "A compositional row proves stable patch equivalence from the observed-AI "
            "commit to a carrier, strict carrier ancestry to the later commit, and a "
            "reverse-delta scheduling signal. It still requires semantic adjudication "
            "to establish a concrete defect. Equivalent-fix rows are same-change "
            "landings, not repair labels. Every source lead remains retained."
        ),
    }
    return {
        "summary": summary,
        "bridge_rows": output_rows,
        "compositional_queue": compositional_queue,
    }


def _atomic_jsonl(
    path: Path, rows: Iterable[object], *, pretty: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise CarrierBridgeError(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if pretty:
                materialized = list(rows)
                if len(materialized) != 1:
                    raise CarrierBridgeError("pretty output requires one value")
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
    patch_dir = args.patch_relation_dir.resolve()
    delta_dir = args.topology_delta_dir.resolve()
    census_dir = args.census_dir.resolve()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SystemExit(f"output directory already exists: {output_dir}")
    patch_summary_path = patch_dir / "summary.json"
    relations_path = patch_dir / "relations.jsonl"
    delta_summary_path = delta_dir / "summary.json"
    exact_path = delta_dir / "exact_reversal_queue.jsonl"
    commits_path = census_dir / "all_commits.jsonl"
    try:
        artifacts = build_carrier_bridge(
            patch_summary=_load_json(patch_summary_path),
            relation_rows=_load_jsonl(relations_path),
            delta_summary=_load_json(delta_summary_path),
            exact_delta_rows=_load_jsonl(exact_path),
            commit_rows=_load_jsonl(commits_path),
            split_id=args.split_id,
        )
        bridge_path = output_dir / "bridge_rows.jsonl"
        queue_path = output_dir / "compositional_queue.jsonl"
        summary_path = output_dir / "summary.json"
        _atomic_jsonl(bridge_path, artifacts["bridge_rows"])
        _atomic_jsonl(queue_path, artifacts["compositional_queue"])
        summary = dict(artifacts["summary"])
        summary["source_artifacts"] = {
            "patch_relation_summary": {
                "path": str(patch_summary_path),
                "sha256": _sha256(patch_summary_path),
            },
            "patch_relations": {
                "path": str(relations_path),
                "sha256": _sha256(relations_path),
            },
            "topology_delta_summary": {
                "path": str(delta_summary_path),
                "sha256": _sha256(delta_summary_path),
            },
            "exact_reversal_queue": {
                "path": str(exact_path),
                "sha256": _sha256(exact_path),
            },
            "all_commits": {
                "path": str(commits_path),
                "sha256": _sha256(commits_path),
            },
        }
        summary["output_artifacts"] = {
            "bridge_rows": {
                "path": str(bridge_path),
                "sha256": _sha256(bridge_path),
            },
            "compositional_queue": {
                "path": str(queue_path),
                "sha256": _sha256(queue_path),
            },
        }
        _atomic_jsonl(summary_path, [summary], pretty=True)
    except CarrierBridgeError as exc:
        raise SystemExit(f"topology carrier bridge failed: {exc}") from exc
    print("Observed-AI topology compositional carrier bridge frozen")
    print(f"  exact leads        : {summary['retained_exact_reversal_pair_count']}")
    print(f"  carrier paths      : {summary['compositional_carrier_ancestor_pair_count']}")
    print(f"  strong same-path   : {summary['strong_same_path_compositional_pair_count']}")
    print(f"  carrier-only fixes : {summary['fix_is_equivalent_carrier_pair_count']}")
    print(f"  output             : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
