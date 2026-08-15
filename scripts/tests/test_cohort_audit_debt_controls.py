"""Frozen contracts for the complete repository-disjoint audit-debt batch."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cohort.audit_debt_intake import prior_control_inventory
from cohort.complex_controls import normalize_complex_controls
from cohort.fix_manifest import normalize_fix_manifest
from cohort.relations import normalize_repository_aliases


REPO_ROOT = Path(__file__).resolve().parents[2]
ATOMIC_PATH = REPO_ROOT / "scripts" / "cohort_audit_debt_atomic_controls.json"
COMPLEX_PATH = REPO_ROOT / "scripts" / "cohort_audit_debt_complex_controls.json"
FIX_PATH = REPO_ROOT / "scripts" / "cohort_audit_debt_fix_manifest.json"
PRIOR_CONTROL_PATHS = (
    REPO_ROOT / "scripts" / "cohort_positive_controls.json",
    REPO_ROOT / "scripts" / "cohort_heldout_controls.json",
    REPO_ROOT / "scripts" / "cohort_expansion_controls.json",
    REPO_ROOT / "scripts" / "cohort_complex_controls.json",
    REPO_ROOT / "scripts" / "cohort_complex_heldout_controls.json",
)
EXPECTED_REPOSITORIES = {
    "github.com/anthropics/claude-code",
    "github.com/franklioxygen/mytube",
    "github.com/maziggy/bambuddy",
    "github.com/safedep/vet",
    "github.com/tinyobjloader/tinyobjloader",
    "github.com/zie619/n8n-workflows",
}


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _aliases() -> dict[str, str]:
    payload = _load(REPO_ROOT / "scripts" / "cohort_repository_aliases.json")
    return normalize_repository_aliases(payload["aliases"])


def _contains(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return value.casefold() == expected.casefold()
    if isinstance(value, list):
        return any(_contains(item, expected) for item in value)
    if isinstance(value, dict):
        return any(_contains(item, expected) for item in value.values())
    return False


def test_recovery_batch_is_complete_and_disjoint_from_every_prior_split() -> None:
    atomic = _load(ATOMIC_PATH)["controls"]
    complex_controls = normalize_complex_controls(
        _load(COMPLEX_PATH)["controls"], _aliases()
    )
    observed = {str(row["repository_identity"]) for row in atomic}
    observed.update(str(row["target_repository_identity"]) for row in complex_controls)
    assert len(atomic) == 4
    assert len(complex_controls) == 2
    assert observed == EXPECTED_REPOSITORIES

    prior = prior_control_inventory(
        [_load(path) for path in PRIOR_CONTROL_PATHS], _aliases()
    )
    assert observed.isdisjoint(prior["repositories"])
    assert all(
        _load(path)["split_id"] == "audit-debt-contract-recovery-20260801-v1"
        for path in (ATOMIC_PATH, COMPLEX_PATH, FIX_PATH)
    )


def test_every_control_is_bound_to_a_recovered_audit_contract() -> None:
    atomic = _load(ATOMIC_PATH)["controls"]
    complex_controls = normalize_complex_controls(
        _load(COMPLEX_PATH)["controls"], _aliases()
    )
    for control in atomic:
        audit = _load(REPO_ROOT / str(control["source"]))
        assert audit["audit_verdict"] == "TRUE_POSITIVE"
        assert audit["ai_authored_vulnerability"] is True
        assert audit["confidence"] >= 0.99
        assert _contains(audit, str(control["atomic_origin_sha"]))
        assert _contains(audit, str(control["fix_sha"]))
    for control in complex_controls:
        source = REPO_ROOT / str(control["source"])
        assert hashlib.sha256(source.read_bytes()).hexdigest() == (
            control["source_sha256"]
        )
        audit = _load(source)
        assert audit["audit_verdict"] == "TRUE_POSITIVE"
        assert audit["ai_authored_vulnerability"] is True
        for edge in control["target_edges"]:
            assert _contains(audit, str(edge["candidate_sha"]))
            assert _contains(audit, str(edge["fix_sha"]))
        for topology in control["topology_sources"]:
            path = REPO_ROOT / str(topology["path"])
            assert hashlib.sha256(path.read_bytes()).hexdigest() == topology["sha256"]


def test_fix_only_manifest_exactly_covers_all_eight_edges_without_gold() -> None:
    manifest = normalize_fix_manifest(_load(FIX_PATH), _aliases())
    atomic = _load(ATOMIC_PATH)["controls"]
    complex_controls = normalize_complex_controls(
        _load(COMPLEX_PATH)["controls"], _aliases()
    )
    expected = {
        (
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["fix_sha"]),
        )
        for row in atomic
    }
    expected.update(
        (
            str(control["advisory"]),
            str(control["target_repository_identity"]),
            str(edge["fix_sha"]),
        )
        for control in complex_controls
        for edge in control["target_edges"]
    )
    observed = {
        (row["advisory"], row["repository_identity"], row["fix_sha"])
        for row in manifest["fixes"]
    }
    assert len(expected) == 8
    assert observed == expected
    rendered = json.dumps(manifest, sort_keys=True)
    for forbidden in (
        "AI_CAUSAL",
        "atomic_origin_sha",
        "candidate_sha",
        "expected_relation",
        "audit_verdict",
    ):
        assert forbidden not in rendered
