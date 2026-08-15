"""Contracts for the Coolify add-only repair-chain expansion."""

from __future__ import annotations

import json
from pathlib import Path

import cohort_coolify_hetzner_cloud_token_authorization_witness as hetzner
import cohort_coolify_onboarding_url_idor_path_extension_witness as onboarding
from cohort.origin_controls import flatten_origin_controls
from cohort.fix_manifest import normalize_fix_manifest


REPO_ROOT = Path(__file__).resolve().parents[2]
OLD_MANIFEST = REPO_ROOT / "scripts" / "cohort_coolify_repair_frontier_folded_fix_manifest.json"
MANIFEST = REPO_ROOT / "scripts" / "cohort_coolify_repair_chain_fix_manifest.json"
CONTROLS = REPO_ROOT / "scripts" / "cohort_coolify_repair_chain_controls.json"


def _load(source_path: Path) -> dict[str, object]:
    value = json.loads(source_path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _fix_shas(payload: dict[str, object]) -> set[str]:
    fixes = payload["fixes"]
    assert isinstance(fixes, list)
    return {str(row["fix_sha"]) for row in fixes}


def test_repair_chain_is_add_only_and_recovers_ghsa_labeled_repair() -> None:
    old_shas = _fix_shas(_load(OLD_MANIFEST))
    payload = _load(MANIFEST)
    new_shas = _fix_shas(payload)

    assert payload["schema_version"] == 1
    assert payload["artifact_kind"] == "sealed_fix_manifest"
    assert payload["split_id"] == "coolify-repair-chain-20260801-v1"
    normalized = normalize_fix_manifest(payload, {})
    assert len(normalized["fixes"]) == 8
    assert old_shas < new_shas
    assert new_shas - old_shas == {onboarding.SECURITY_REPAIR_SHA}


def test_new_controls_are_witness_bound_and_generation_blind() -> None:
    payload = _load(CONTROLS)
    controls = payload["controls"]
    assert isinstance(controls, list)
    rows = flatten_origin_controls(payload)
    edges = {
        (str(row["atomic_origin_sha"]), str(row["fix_sha"])) for row in rows
    }

    assert payload["artifact_kind"] == "coolify_repair_chain_origin_controls"
    assert "Evaluation-only" in str(payload["generation_boundary"])
    assert len(rows) == len(edges) == 7
    assert (hetzner.AI_ORIGIN_SHA, hetzner.SECURITY_REPAIR_SHA) in edges
    assert (
        onboarding.AI_PATH_EXTENSION_SHA,
        onboarding.SECURITY_REPAIR_SHA,
    ) in edges
    assert {str(row["fix_sha"]) for row in rows} <= _fix_shas(_load(MANIFEST))
