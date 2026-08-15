"""Contracts for post-generation squash atomic-member refinements."""

from __future__ import annotations

import json
import re
from pathlib import Path

import cohort_tinyobjloader_path_extension_witness as tiny_witness
import cohort_graphiti_default_backend_path_extension_witness as graphiti_witness
from cohort.origin_controls import flatten_origin_controls


REPO_ROOT = Path(__file__).resolve().parents[2]
REFINEMENT_PATH = (
    REPO_ROOT / "scripts" / "cohort_squash_atomic_refinement_controls.json"
)
PATH_EXTENSION_PATH = (
    REPO_ROOT / "scripts" / "cohort_squash_causal_path_extension_controls.json"
)
PROMOTED_ADJUDICATION_PATH = (
    REPO_ROOT / "scripts" / "cohort_squash_promoted_adjudications.json"
)
ATOMIC_PATH = REPO_ROOT / "scripts" / "cohort_audit_debt_atomic_controls.json"
COMPLEX_PATH = REPO_ROOT / "scripts" / "cohort_complex_heldout_controls.json"
FULL_SHA = re.compile(r"[0-9a-f]{40}")


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _prior_carrier_edges() -> set[tuple[str, str, str, str]]:
    atomic = _load(ATOMIC_PATH)["controls"]
    complex_controls = _load(COMPLEX_PATH)["controls"]
    assert isinstance(atomic, list)
    assert isinstance(complex_controls, list)
    edges = {
        (
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["atomic_origin_sha"]),
            str(row["fix_sha"]),
        )
        for row in atomic
    }
    for control in complex_controls:
        assert isinstance(control, dict)
        for edge in control["target_edges"]:
            edges.add(
                (
                    str(control["advisory"]),
                    str(control["target_repository_identity"]),
                    str(edge["candidate_sha"]),
                    str(edge["fix_sha"]),
                )
            )
    return edges


def test_refinements_are_add_only_children_of_prior_carrier_controls() -> None:
    payload = _load(REFINEMENT_PATH)
    controls = payload["controls"]
    assert payload["schema_version"] == 1
    assert payload["artifact_kind"] == "squash_atomic_origin_refinement_controls"
    assert payload["split_id"] == "squash-atomic-refinement-20260801-v1"
    assert isinstance(controls, list)
    assert len(controls) == 4

    prior_edges = _prior_carrier_edges()
    observed: set[tuple[str, str, str, str]] = set()
    for row in controls:
        assert isinstance(row, dict)
        carrier_edge = (
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["landed_squash_sha"]),
            str(row["fix_sha"]),
        )
        assert carrier_edge in prior_edges
        assert row["landed_squash_sha"] != row["atomic_origin_sha"]
        assert row["expected_relation"] == (
            "pull_request_member_landed_as_squash_then_reachable_ancestor"
        )
        assert row["causal_adjudication"] == "CONFIRMED_ATOMIC_MEMBER"
        for field in ("landed_squash_sha", "atomic_origin_sha", "fix_sha"):
            assert FULL_SHA.fullmatch(str(row[field]))
        key = (
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["atomic_origin_sha"]),
            str(row["fix_sha"]),
        )
        assert key not in observed
        observed.add(key)
        assert (REPO_ROOT / str(row["prior_control_source"])).is_file()
        assert (REPO_ROOT / str(row["audit_source"])).is_file()
        assert row["evidence_paths"]
        assert row["mechanism"]

    assert len(flatten_origin_controls(payload)) == 4


def test_member_ai_authorship_scope_is_not_inherited_silently() -> None:
    controls = _load(REFINEMENT_PATH)["controls"]
    assert isinstance(controls, list)
    direct = [row for row in controls if row["member_ai_authorship_claim"] is True]
    carrier_only = [
        row for row in controls if row["member_ai_authorship_claim"] is False
    ]
    assert len(direct) == 3
    assert all(row["member_ai_attribution"] == "direct_member_signal" for row in direct)
    assert len(carrier_only) == 1
    assert carrier_only[0]["atomic_origin_sha"] == (
        "96891d071da59ec7f178fc036aa20086af18d69f"
    )
    assert carrier_only[0]["member_ai_attribution"] == ("landed_squash_context_only")


def test_path_extension_is_separate_from_earliest_root_controls() -> None:
    payload = _load(PATH_EXTENSION_PATH)
    controls = payload["controls"]
    assert payload["artifact_kind"] == "squash_causal_path_extension_controls"
    assert isinstance(controls, list)
    assert payload["split_id"] == "squash-causal-path-extension-20260801-v2"
    assert len(controls) == 3
    tiny_controls = [
        row for row in controls if row["repository_identity"] == "github.com/tinyobjloader/tinyobjloader"
    ]
    assert {row["witness_case"] for row in tiny_controls} == set(tiny_witness.WITNESS_CASES)
    for row in tiny_controls:
        case = tiny_witness.WITNESS_CASES[str(row["witness_case"])]
        assert row["causal_role"] == "vulnerable_path_extension"
        assert row["earliest_root_origin_sha"] != row["atomic_origin_sha"]
        assert row["parent_sha"] == case.parent_sha
        assert row["atomic_origin_sha"] == case.candidate_sha
        assert row["fix_sha"] == case.fix_sha
        assert str(row["mechanism"]).find(case.trigger) >= 0
    graphiti = next(
        row
        for row in controls
        if row["repository_identity"] == "github.com/getzep/graphiti"
    )
    assert graphiti["causal_role"] == "vulnerable_default_path_activation"
    assert graphiti["parent_sha"] == graphiti_witness.PARENT_SHA
    assert graphiti["atomic_origin_sha"] == graphiti_witness.CANDIDATE_SHA
    assert graphiti["fix_sha"] == graphiti_witness.FIX_SHA
    assert graphiti_witness.TRIGGER_GROUP_ID in str(graphiti["mechanism"])
    assert graphiti["member_ai_attribution"] == "landed_squash_context_only"
    assert graphiti["member_ai_authorship_claim"] is False
    assert len(flatten_origin_controls(payload)) == 3


def test_every_promoted_squash_member_has_one_bounded_adjudication() -> None:
    payload = _load(PROMOTED_ADJUDICATION_PATH)
    assert payload["schema_version"] == 1
    assert payload["artifact_kind"] == "squash_promoted_candidate_adjudications"
    confirmed = payload["confirmed"]
    rejected_groups = payload["rejected_groups"]
    assert isinstance(confirmed, list)
    assert isinstance(rejected_groups, list)
    rejected = [
        candidate_sha
        for group in rejected_groups
        for candidate_sha in group["candidate_shas"]
    ]
    confirmed_shas = [row["candidate_sha"] for row in confirmed]
    assert len(confirmed) == 7
    assert len(rejected) == 54
    assert len(set(confirmed_shas)) == 7
    assert len(set(rejected)) == 54
    assert set(confirmed_shas).isdisjoint(rejected)
    assert len(set(confirmed_shas) | set(rejected)) == 61
    assert all(FULL_SHA.fullmatch(sha) for sha in confirmed_shas + rejected)
    assert sum(row["causal_role"] == "earliest_root" for row in confirmed) == 4
    assert sum(row["causal_role"] != "earliest_root" for row in confirmed) == 3
    assert sum(row["member_ai_authorship_claim"] is True for row in confirmed) == 5
    assert all((REPO_ROOT / row["evidence"]).is_file() for row in confirmed)
