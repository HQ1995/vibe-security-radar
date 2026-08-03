"""Fail-closed tests for the sealed fix-only generation boundary."""

from __future__ import annotations

import json

import pytest

from cohort.fix_manifest import (
    FixManifestContractError,
    generation_fix_overlay,
    normalize_fix_manifest,
)


REPOSITORY = "github.com/example/project"
FIX = "4" * 40
ORIGIN = "1" * 40


def _manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "artifact_kind": "sealed_fix_manifest",
        "split_id": "heldout-v1",
        "frozen_at": "2026-07-31T00:00:00Z",
        "fixes": [
            {
                "advisory": "CVE-2026-1000",
                "repository_identity": REPOSITORY,
                "fix_sha": FIX,
            }
        ],
    }


def test_fix_manifest_exposes_only_fix_roots() -> None:
    manifest = normalize_fix_manifest(_manifest(), {})

    overlay = generation_fix_overlay(manifest)

    assert overlay == {
        REPOSITORY: [
            {
                "advisory": "CVE-2026-1000",
                "fix_sha": FIX,
                "published": "",
                "source": "sealed_fix_manifest:heldout-v1",
            }
        ]
    }
    rendered = json.dumps(manifest, sort_keys=True)
    assert "candidate_sha" not in rendered
    assert "expected_relation" not in rendered
    assert ORIGIN not in rendered


@pytest.mark.parametrize(
    ("container", "field"),
    [
        ("top", "controls"),
        ("row", "candidate_sha"),
        ("row", "atomic_origin_sha"),
        ("row", "expected_relation"),
        ("row", "landed_sha"),
    ],
)
def test_fix_manifest_rejects_every_golden_field(container: str, field: str) -> None:
    payload = _manifest()
    if container == "top":
        payload[field] = []
    else:
        fixes = payload["fixes"]
        assert isinstance(fixes, list)
        fixes[0][field] = ORIGIN

    with pytest.raises(FixManifestContractError, match="keys must be exact"):
        normalize_fix_manifest(payload, {})
