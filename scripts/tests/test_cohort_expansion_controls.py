"""Contract for the census-derived, repository-disjoint expansion split."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXPANSION_PATH = REPO_ROOT / "scripts" / "cohort_expansion_controls.json"
EARLIER_CONTROL_PATHS = (
    REPO_ROOT / "scripts" / "cohort_positive_controls.json",
    REPO_ROOT / "scripts" / "cohort_heldout_controls.json",
)


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _contains_string(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return value.lower() == expected.lower()
    if isinstance(value, list):
        return any(_contains_string(item, expected) for item in value)
    if isinstance(value, dict):
        return any(_contains_string(item, expected) for item in value.values())
    return False


def test_expansion_split_is_frozen_and_disjoint_from_all_earlier_controls() -> None:
    expansion = _load(EXPANSION_PATH)
    controls = expansion["controls"]
    assert expansion["schema_version"] == 1
    assert expansion["split_id"] == "recall-first-heldout-expansion-v2"
    assert expansion["frozen_at"]
    assert expansion["minimum_confidence"] == 0.98
    assert expansion["accounted_ai_causal_count"] == 36
    assert isinstance(controls, list) and len(controls) == 3

    earlier_controls = [
        control
        for path in EARLIER_CONTROL_PATHS
        for control in _load(path)["controls"]
    ]
    advisories = {control["advisory"] for control in controls}
    repositories = {control["repository_identity"] for control in controls}
    assert len(advisories) == len(controls)
    assert len(repositories) == len(controls)
    assert advisories.isdisjoint(
        control["advisory"] for control in earlier_controls
    )
    assert repositories.isdisjoint(
        control["repository_identity"] for control in earlier_controls
    )


def test_expansion_split_fails_if_any_selection_input_drifts() -> None:
    expansion = _load(EXPANSION_PATH)
    input_hashes = expansion["input_sha256"]
    assert isinstance(input_hashes, dict)
    for relative_path, expected_hash in input_hashes.items():
        assert _sha256(REPO_ROOT / relative_path) == expected_hash


def test_every_expansion_control_is_bound_to_current_audit_and_repo_evidence() -> None:
    controls = _load(EXPANSION_PATH)["controls"]
    assert isinstance(controls, list)
    for control in controls:
        audit = _load(REPO_ROOT / control["source"])
        assert audit["audit_verdict"] == "TRUE_POSITIVE"
        assert audit["ai_authored_vulnerability"] is True
        assert audit["cve_id"] == control["advisory"]
        assert _contains_string(audit, control["atomic_origin_sha"])
        assert _contains_string(audit, control["fix_sha"])
        if "expected_landed_sha" in control:
            assert _contains_string(audit, control["expected_landed_sha"])

        source_path = control.get("source") or control["repository_source"]
        repository_text = (REPO_ROOT / source_path).read_text(
            encoding="utf-8"
        )
        repository_suffix = control["repository_identity"].removeprefix("github.com/")
        assert repository_suffix in repository_text.lower()
