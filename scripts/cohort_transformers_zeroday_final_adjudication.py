#!/usr/bin/env python3
"""Close the Transformers 0-day search without confusing rank leads with TPs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

from cohort_transformers_zeroday_semantic_inventory import _signal_changes


EXPECTED_MODEL_LEADS = {
    "89d53495c8ba71f355517b24935f8847cf6eb923",
    "9d67585e8de33640fc9b2e88638c8de338e3d0f6",
}
EXPECTED_SEMANTIC_SOURCE = {
    "2ccc6cae21faaf11631efa5fb9054687ae5dc931",
    "9ba8e8585bbf6ed4c10455ef59c51c0da5f0b85f",
    "fa6c8308e22dade298c10c72d44937e41b962353",
}
DIRECT_DANGER_CATEGORIES = {
    "pickle_deserialization",
    "torch_deserialization",
    "unsafe_weights_only",
    "code_execution_eval",
    "explicit_trust_guard",
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--packet-aggregate", type=Path, required=True)
    parser.add_argument("--semantic-inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain one JSON object")
    return value


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _categories(row: Mapping[str, object]) -> set[str]:
    changes = row.get("signal_changes")
    if not isinstance(changes, list):
        raise ValueError("semantic signal changes are malformed")
    return {
        category
        for change in changes
        if isinstance(change, Mapping)
        for category in str(change.get("categories", "")).split(",")
        if category
    }


def _adjudicate(
    repository: Path,
    closure: Mapping[str, object],
    packet: Mapping[str, object],
    semantic: Mapping[str, object],
    *,
    closure_sha256: str,
    packet_sha256: str,
    semantic_sha256: str,
) -> dict[str, object]:
    if packet.get("artifact_kind") != "transformers_zeroday_packet_ai_review_aggregate":
        raise ValueError("unexpected packet aggregate artifact")
    if semantic.get("artifact_kind") != "transformers_zeroday_semantic_recall_inventory":
        raise ValueError("unexpected semantic inventory artifact")
    if packet.get("closure_sha256") != closure_sha256:
        raise ValueError("packet aggregate closure digest mismatch")
    semantic_inputs = semantic.get("inputs")
    if not isinstance(semantic_inputs, Mapping) or semantic_inputs.get(
        "closure_sha256"
    ) != closure_sha256:
        raise ValueError("semantic inventory closure digest mismatch")
    if closure.get("artifact_kind") != "transformers_zeroday_squash_member_closure":
        raise ValueError("unexpected closure artifact")

    model_leads = {str(value) for value in packet.get("model_promoted_candidate_shas", [])}
    if model_leads != EXPECTED_MODEL_LEADS:
        raise ValueError("model lead inventory changed")
    if packet.get("candidate_assessment_count") != 32:
        raise ValueError("packet candidate coverage changed")
    packet_conservation = packet.get("conservation")
    if not isinstance(packet_conservation, Mapping) or packet_conservation.get(
        "passed"
    ) is not True:
        raise ValueError("packet review does not conserve its candidate inventory")

    semantic_rows = semantic.get("semantic_candidates")
    source_path_rows = semantic.get("source_path_candidates")
    transitions = semantic.get("exact_local_transitions")
    finite = semantic.get("finite_inventory")
    lanes = semantic.get("priority_lanes")
    conservation = semantic.get("conservation")
    if not all(
        isinstance(value, list) for value in (semantic_rows, source_path_rows, transitions)
    ) or not all(isinstance(value, Mapping) for value in (finite, lanes, conservation)):
        raise ValueError("semantic inventory is malformed")
    if conservation.get("passed") is not True or conservation.get("hard_filter_count") != 0:
        raise ValueError("semantic inventory is not recall-conserving")

    semantic_by_sha = {
        str(row["sha"]): row for row in semantic_rows if isinstance(row, Mapping)
    }
    source_path_by_sha = {
        str(row["sha"]): row for row in source_path_rows if isinstance(row, Mapping)
    }
    semantic_source = {
        str(value) for value in lanes.get("semantic_and_source_v3_shas", [])
    }
    if semantic_source != EXPECTED_SEMANTIC_SOURCE:
        raise ValueError("semantic/source intersection changed")

    lead_rows = []
    for sha in sorted(model_leads):
        signals = _signal_changes(repository, sha)
        if signals:
            raise ValueError(f"model lead gained a direct semantic signal: {sha}")
        lead_rows.append(
            {
                "sha": sha,
                "model_disposition": "REJECT_NOT_CAUSAL_NOT_AI_ATTRIBUTED",
                "direct_semantic_signal_changes": [],
                "reason": (
                    "The exact full diff is a mechanical style refactor, contains "
                    "none of the dangerous sink/guard transitions, and has no "
                    "Source-v3 AI evidence."
                ),
                "candidate_retained": True,
            }
        )

    semantic_source_rows = []
    for sha in sorted(semantic_source):
        row = semantic_by_sha[sha]
        categories = _categories(row)
        path_row = source_path_by_sha[sha]
        if sha == "2ccc6cae21faaf11631efa5fb9054687ae5dc931":
            if (
                path_row.get("attribution_scope")
                != "SQUASH_CARRIER_REQUIRES_MEMBER_DECOMPOSITION"
                or path_row.get("carrier_source_members_with_semantic_signals") != []
                or categories & DIRECT_DANGER_CATEGORIES
            ):
                raise ValueError("release carrier decomposition no longer closes")
            disposition = "REJECT_CARRIER_ATTRIBUTION_DOES_NOT_REACH_SEMANTIC_MEMBER"
            reason = (
                "The carrier aggregates 167 members. Its one Source-v3 member "
                "changes Trainer device placement and has no semantic sink/guard "
                "signal; carrier-level AI attribution cannot transfer to other members."
            )
        else:
            if path_row.get("ancestor_of_affected_cves") != []:
                raise ValueError(f"post-advisory candidate became an affected ancestor: {sha}")
            if categories & DIRECT_DANGER_CATEGORIES:
                raise ValueError(f"post-advisory candidate gained a direct danger signal: {sha}")
            disposition = "REJECT_POST_AFFECTED_NON_CAUSAL_REFACTOR"
            reason = (
                "The commit is not an ancestor of any affected snapshot and its "
                "matched lines are only loader/safe-serialization comments or refactors."
            )
        semantic_source_rows.append(
            {
                "sha": sha,
                "disposition": disposition,
                "signal_categories": sorted(categories),
                "ancestor_of_affected_cves": path_row.get(
                    "ancestor_of_affected_cves", []
                ),
                "reason": reason,
                "candidate_retained": True,
            }
        )

    transition_rows = []
    for row in transitions:
        assert isinstance(row, Mapping)
        if row.get("ai_evidence_observed") is not False:
            raise ValueError("exact local transition gained AI evidence")
        transition_rows.append(
            {
                "sha": row.get("sha"),
                "kind": row.get("kind"),
                "cves": row.get("cves"),
                "ai_evidence_observed": False,
                "security_relevance": "LOCAL_TRANSITION_PROVED",
                "ai_tp_disposition": "NOT_AI_ATTRIBUTED_UNDER_FROZEN_CONTRACT",
            }
        )

    return {
        "schema_version": 1,
        "artifact_kind": "transformers_zeroday_final_ai_adjudication",
        "inputs": {
            "closure_sha256": closure_sha256,
            "packet_aggregate_sha256": packet_sha256,
            "semantic_inventory_sha256": semantic_sha256,
        },
        "finite_funnel": {
            "retained_commit_union": finite.get("retained_union_commit_count"),
            "risk_path_candidates": finite.get("risk_path_history_count"),
            "semantic_candidates": finite.get("semantic_history_count"),
            "source_v3_candidates": finite.get("source_v3_count"),
            "semantic_source_intersection": len(semantic_source),
            "semantic_source_after_carrier_and_chronology": 0,
            "packet_priority_candidates": packet.get("candidate_assessment_count"),
            "packet_model_leads": len(model_leads),
        },
        "model_lead_adjudications": lead_rows,
        "semantic_source_adjudications": semantic_source_rows,
        "exact_local_transition_adjudications": transition_rows,
        "claim_grade_ai_true_positive_shas": [],
        "claim_grade_ai_true_positive_count": 0,
        "blocked_ai_candidate_shas": [],
        "blocked_ai_candidate_count": 0,
        "verdict": "NO_AI_CAUSAL_ROOT_RECOVERED_UNDER_FROZEN_SOURCE_CONTRACT",
        "conservation": {
            "retained_commit_union": finite.get("retained_union_commit_count"),
            "model_negative_deletion_count": 0,
            "semantic_negative_deletion_count": 0,
            "hard_filter_count": 0,
            "passed": True,
        },
        "claim_boundary": (
            "This is a complete adjudication of candidates observable under the "
            "frozen all-ref/frozen-history union and Source-v3 explicit-attribution "
            "contract. It cannot prove that commits without observable AI provenance "
            "were written without AI assistance."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    closure_raw = args.closure.read_bytes()
    packet_raw = args.packet_aggregate.read_bytes()
    semantic_raw = args.semantic_inventory.read_bytes()
    try:
        value = _adjudicate(
            args.repository.resolve(),
            _load_json(args.closure),
            _load_json(args.packet_aggregate),
            _load_json(args.semantic_inventory),
            closure_sha256=hashlib.sha256(closure_raw).hexdigest(),
            packet_sha256=hashlib.sha256(packet_raw).hexdigest(),
            semantic_sha256=hashlib.sha256(semantic_raw).hexdigest(),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    _atomic_json(args.output, value)
    print("Transformers 0-day AI adjudication complete")
    print(f"  retained commits : {value['finite_funnel']['retained_commit_union']}")
    print(f"  model leads      : {value['finite_funnel']['packet_model_leads']}")
    print(f"  claim-grade AI TP: {value['claim_grade_ai_true_positive_count']}")
    print(f"  hard filters     : {value['conservation']['hard_filter_count']}")
    print(f"  output           : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
