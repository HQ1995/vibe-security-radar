"""Frozen repository-disjoint complex held-out split contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cohort.complex_controls import normalize_complex_controls
from cohort.fix_manifest import normalize_fix_manifest


REPO_ROOT = Path(__file__).resolve().parents[2]
DEVELOPMENT_CONTROL_PATH = REPO_ROOT / "scripts" / "cohort_complex_controls.json"
DEVELOPMENT_FIX_PATH = REPO_ROOT / "scripts" / "cohort_complex_fix_manifest.json"
HELDOUT_CONTROL_PATH = REPO_ROOT / "scripts" / "cohort_complex_heldout_controls.json"
HELDOUT_FIX_PATH = REPO_ROOT / "scripts" / "cohort_complex_heldout_fix_manifest.json"


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _contains_string(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return value.casefold() == expected.casefold()
    if isinstance(value, list):
        return any(_contains_string(item, expected) for item in value)
    if isinstance(value, dict):
        return any(_contains_string(item, expected) for item in value.values())
    return False


def _control_fix_rows(controls: list[dict[str, object]]) -> set[tuple[str, str, str]]:
    rows: set[tuple[str, str, str]] = set()
    for control in controls:
        identity = str(control["target_repository_identity"])
        advisory = str(control["advisory"])
        for edge in control["target_edges"]:
            assert isinstance(edge, dict)
            rows.add((advisory, identity, str(edge["fix_sha"])))
    return rows


def _manifest_fix_rows(manifest: dict[str, object]) -> set[tuple[str, str, str]]:
    return {
        (
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["fix_sha"]),
        )
        for row in manifest["fixes"]
    }


def test_heldout_is_frozen_repository_disjoint_and_audit_bound() -> None:
    development_payload = _load(DEVELOPMENT_CONTROL_PATH)
    heldout_payload = _load(HELDOUT_CONTROL_PATH)
    development = normalize_complex_controls(development_payload["controls"], {})
    heldout = normalize_complex_controls(heldout_payload["controls"], {})

    assert heldout_payload["split_id"] == (
        "recall-first-complex-repository-disjoint-heldout-v1"
    )
    assert heldout_payload["frozen_at"]
    assert len(heldout) == 2
    assert sum(len(row["target_edges"]) for row in heldout) == 5
    assert sum(len(row["upstream_imports"]) for row in heldout) == 0
    assert {row["advisory"] for row in heldout} == {
        "CVE-2026-32247",
        "CVE-2026-34218",
    }
    development_repositories = {
        str(row["target_repository_identity"]) for row in development
    }
    heldout_repositories = {str(row["target_repository_identity"]) for row in heldout}
    assert development_repositories.isdisjoint(heldout_repositories)
    assert set(heldout_payload["excluded_development_repositories"]) == (
        development_repositories
    )

    for control in heldout:
        source = REPO_ROOT / str(control["source"])
        assert hashlib.sha256(source.read_bytes()).hexdigest() == control["source_sha256"]
        audit = _load(source)
        assert audit["cve_id"] == control["advisory"]
        assert audit["audit_verdict"] == "TRUE_POSITIVE"
        assert audit["ai_authored_vulnerability"] is True
        assert audit["confidence"] >= 0.99
        topology_evidence: list[dict[str, object]] = []
        for source_row in control["topology_sources"]:
            topology_path = REPO_ROOT / str(source_row["path"])
            assert hashlib.sha256(topology_path.read_bytes()).hexdigest() == (
                source_row["sha256"]
            )
            topology_evidence.append(_load(topology_path))
        for edge in control["target_edges"]:
            assert _contains_string(audit, str(edge["candidate_sha"]))
            assert _contains_string(audit, str(edge["fix_sha"]))
            assert any(
                _contains_string(evidence, str(edge["fix_sha"]))
                for evidence in topology_evidence
            )


def test_fix_only_manifests_exactly_match_unique_gold_fix_roots() -> None:
    for control_path, manifest_path in (
        (DEVELOPMENT_CONTROL_PATH, DEVELOPMENT_FIX_PATH),
        (HELDOUT_CONTROL_PATH, HELDOUT_FIX_PATH),
    ):
        controls = normalize_complex_controls(_load(control_path)["controls"], {})
        manifest = normalize_fix_manifest(_load(manifest_path), {})

        assert manifest["split_id"] == _load(control_path)["split_id"]
        assert _manifest_fix_rows(manifest) == _control_fix_rows(controls)
        rendered = json.dumps(manifest, sort_keys=True)
        for forbidden in (
            "candidate_sha",
            "atomic_origin_sha",
            "expected_relation",
            "expected_landed_sha",
            "upstream_imports",
        ):
            assert forbidden not in rendered
