"""Contracts for the frozen complex-causality recall obligations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cohort.complex_controls import (
    evaluate_complex_controls,
    generation_fix_overlay,
    normalize_complex_controls,
    routing_target_controls,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_PATH = REPO_ROOT / "scripts" / "cohort_complex_controls.json"
TARGET = "github.com/example/target"
UPSTREAM = "github.com/example/upstream"
ORIGIN_A = "1" * 40
ORIGIN_B = "2" * 40
IMPORT = "3" * 40
FIX_A = "4" * 40
FIX_B = "5" * 40


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


def test_complex_control_ledger_is_frozen_complete_and_audit_bound() -> None:
    payload = _load(CONTROL_PATH)
    controls = normalize_complex_controls(payload["controls"], {})

    assert payload["schema_version"] == 1
    assert payload["split_id"] == "recall-first-complex-obligations-v1"
    assert payload["frozen_at"]
    assert len(controls) == 9
    assert sum(len(row["target_edges"]) for row in controls) == 20
    assert sum(len(row["upstream_imports"]) for row in controls) == 4
    assert sum(len(row["public_fixes"]) for row in controls) == 9
    assert {row["advisory"] for row in controls} == {
        "CVE-2026-1979",
        "CVE-2026-22171",
        "CVE-2026-2376",
        "CVE-2026-27203",
        "CVE-2026-27695",
        "CVE-2026-28451",
        "CVE-2026-32021",
        "GHSA-5wp8-q9mx-8jx8",
        "GHSA-c6hr-w26q-c636",
    }

    for control in controls:
        source = REPO_ROOT / control["source"]
        assert hashlib.sha256(source.read_bytes()).hexdigest() == control["source_sha256"]
        audit = _load(source)
        assert audit["cve_id"] == control["advisory"]
        assert audit["audit_verdict"] == "TRUE_POSITIVE"
        assert audit["ai_authored_vulnerability"] is True
        topology_evidence: list[dict[str, object]] = []
        for source_row in control["topology_sources"]:
            topology_path = REPO_ROOT / source_row["path"]
            assert (
                hashlib.sha256(topology_path.read_bytes()).hexdigest()
                == source_row["sha256"]
            )
            topology_evidence.append(_load(topology_path))
        for edge in control["target_edges"]:
            assert _contains_string(audit, edge["candidate_sha"])
            assert _contains_string(audit, edge["fix_sha"])
            if edge.get("expected_landed_sha"):
                assert _contains_string(
                    audit, edge["expected_landed_sha"]
                ) or any(
                    _contains_string(evidence, edge["expected_landed_sha"])
                    for evidence in topology_evidence
                )
        for relation in control["upstream_imports"]:
            assert _contains_string(audit, relation["origin_sha"])
            assert _contains_string(audit, relation["import_sha"])


def _complex_controls() -> list[dict[str, object]]:
    return [
        {
            "advisory": "CVE-TEST-MULTI",
            "dimensions": ["MULTI_ORIGIN", "MULTI_FIX"],
            "source": "audit/multi.json",
            "source_sha256": "a" * 64,
            "target_repository_identity": TARGET,
            "target_edges": [
                {
                    "candidate_sha": ORIGIN_A,
                    "fix_sha": FIX_A,
                    "expected_relation": "reachable_ancestor",
                },
                {
                    "candidate_sha": ORIGIN_B,
                    "fix_sha": FIX_A,
                    "expected_relation": "reachable_ancestor",
                },
                {
                    "candidate_sha": ORIGIN_A,
                    "fix_sha": FIX_B,
                    "expected_relation": "reachable_ancestor",
                },
            ],
            "upstream_imports": [],
            "public_fixes": [FIX_A],
        },
        {
            "advisory": "CVE-TEST-CROSS",
            "dimensions": ["CROSS_REPOSITORY_ORIGIN"],
            "source": "audit/cross.json",
            "source_sha256": "b" * 64,
            "target_repository_identity": TARGET,
            "target_edges": [
                {
                    "candidate_sha": IMPORT,
                    "fix_sha": FIX_B,
                    "expected_relation": "reachable_ancestor",
                }
            ],
            "upstream_imports": [
                {
                    "origin_repository_identity": UPSTREAM,
                    "origin_sha": ORIGIN_B,
                    "import_sha": IMPORT,
                    "expected_relation": "declared_cross_repository_import",
                }
            ],
            "public_fixes": [FIX_B],
        },
    ]


def test_generation_overlay_exposes_only_unique_fix_roots() -> None:
    controls = normalize_complex_controls(_complex_controls(), {})

    overlay = generation_fix_overlay(controls)

    assert overlay == {
        TARGET: [
            {
                "advisory": "CVE-TEST-CROSS",
                "fix_sha": FIX_B,
                "published": "",
                "source": "complex_control:audit/cross.json",
            },
            {
                "advisory": "CVE-TEST-MULTI",
                "fix_sha": FIX_A,
                "published": "",
                "source": "complex_control:audit/multi.json",
            },
            {
                "advisory": "CVE-TEST-MULTI",
                "fix_sha": FIX_B,
                "published": "",
                "source": "complex_control:audit/multi.json",
            },
        ]
    }
    rendered = json.dumps(overlay, sort_keys=True)
    assert ORIGIN_A not in rendered
    assert ORIGIN_B not in rendered
    assert IMPORT not in rendered


def test_routing_controls_flatten_every_target_obligation_with_unique_ids() -> None:
    controls = normalize_complex_controls(_complex_controls(), {})

    routing = routing_target_controls(controls)

    assert len(routing) == 4
    assert len({row["advisory"] for row in routing}) == 4
    assert {row["base_advisory"] for row in routing} == {
        "CVE-TEST-CROSS",
        "CVE-TEST-MULTI",
    }
    assert all("origin_repository_identity" not in row for row in routing)


def test_complex_gate_requires_every_target_and_upstream_obligation() -> None:
    controls = normalize_complex_controls(_complex_controls(), {})
    expanded = [
        {
            "edge_id": f"edge-{index}",
            "repository_identity": TARGET,
            "candidate_sha": edge["candidate_sha"],
            "fix_sha": edge["fix_sha"],
            "relation": edge["expected_relation"],
        }
        for index, control in enumerate(controls)
        for edge in control["target_edges"]
    ]
    cross = [
        {
            "relation_id": "cross-1",
            "origin_repository_identity": UPSTREAM,
            "origin_sha": ORIGIN_B,
            "target_repository_identity": TARGET,
            "import_sha": IMPORT,
            "relation": "declared_cross_repository_import",
        }
    ]
    public = [
        {
            "repository_identity": TARGET,
            "advisory": "CVE-TEST-MULTI",
            "fix_sha": FIX_A,
        },
        {
            "repository_identity": TARGET,
            "advisory": "CVE-TEST-CROSS",
            "fix_sha": FIX_B,
        },
    ]

    passed = evaluate_complex_controls(controls, expanded, cross, public, {})
    missed = evaluate_complex_controls(controls, expanded[:-1], cross, public, {})

    assert passed["control_count"] == 2
    assert passed["relation_obligation_count"] == 5
    assert passed["relation_obligation_pass_count"] == 5
    assert passed["target_obligation_count"] == 4
    assert passed["target_obligation_pass_count"] == 4
    assert passed["upstream_obligation_count"] == 1
    assert passed["upstream_obligation_pass_count"] == 1
    assert passed["relation_gate_passed"] is True
    assert passed["public_exact_fix_pass_count"] == 2
    assert missed["relation_obligation_pass_count"] == 4
    assert missed["control_pass_count"] == 1
    assert missed["relation_gate_passed"] is False
