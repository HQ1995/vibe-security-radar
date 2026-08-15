"""Contracts for mixed-origin compositional causal-contributor controls."""

from __future__ import annotations

import json
import re
from pathlib import Path

import cohort_churchcrm_setup_password_compositional_witness as churchcrm


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_PATH = REPO_ROOT / "scripts" / "cohort_compositional_causal_contributor_controls.json"
FULL_SHA = re.compile(r"[0-9a-f]{40}")


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_compositional_control_keeps_ai_contribution_distinct_from_ai_root() -> None:
    payload = _load(CONTROL_PATH)
    controls = payload["controls"]

    assert payload["schema_version"] == 1
    assert payload["artifact_kind"] == "compositional_causal_contributor_controls"
    assert payload["split_id"] == "compositional-causal-contributor-20260801-v1"
    assert "evaluation-only" in str(payload["generation_boundary"])
    assert isinstance(controls, list) and len(controls) == 1
    control = controls[0]
    assert control["advisory"] == "CVE-2025-11938"
    assert control["repository_identity"] == "github.com/churchcrm/crm"
    assert control["latent_ai_origin_sha"] == churchcrm.LATENT_AI_SHA
    assert control["pre_activation_ai_refactor_sha"] == churchcrm.PRE_ACTIVATION_AI_SHA
    assert control["human_activation_sha"] == churchcrm.ACTIVATION_SHA
    assert control["landed_merge_sha"] == churchcrm.LANDED_MERGE_SHA
    assert control["member_ai_authorship_claim"] is True
    assert control["independent_ai_root_claim"] is False
    assert control["causal_adjudication"] == "CONFIRMED_COMPOSITIONAL_AI_CONTRIBUTOR"
    for field in (
        "landed_merge_sha",
        "latent_ai_origin_sha",
        "pre_activation_ai_refactor_sha",
        "raw_source_sha",
        "human_activation_sha",
        "template_sink_sha",
    ):
        assert FULL_SHA.fullmatch(str(control[field]))


def test_compositional_control_is_bound_to_passing_mechanical_witness() -> None:
    control = _load(CONTROL_PATH)["controls"][0]
    witness_path = REPO_ROOT / str(control["witness_artifact"])
    witness = _load(witness_path)

    assert witness["witness_passed"] is True
    assert witness["direct_ai_root_claim"] is False
    assert witness["causal_adjudication"] == control["causal_adjudication"]
    assert witness["line_origins_at_activation"]["permissive_helper_definition"][
        "origin_sha"
    ] == control["latent_ai_origin_sha"]
    assert witness["line_origins_at_activation"]["runtime_validator_selection"][
        "origin_sha"
    ] == control["human_activation_sha"]


def test_independent_models_confirm_same_bounded_role() -> None:
    control = _load(CONTROL_PATH)["controls"][0]
    review_paths = [REPO_ROOT / str(path) for path in control["independent_review_artifacts"]]
    reviews = [_load(path) for path in review_paths]

    assert len({row["model"] for row in reviews}) == 2
    assert {row["reasoning_effort"] for row in reviews} == {"high", "medium"}
    for row in reviews:
        assert row["result_status"] == "completed"
        assert row["review"]["verdict"] == "confirmed_compositional_contributor"
        assert row["review"]["independent_ai_root"] == "no"
        assert row["review"]["latent_ai_primitive"] == "yes"
        assert row["review"]["human_activation_required"] == "yes"
