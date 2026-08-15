"""Tests for the OpenC3 CVE-2025-28389 chronology certificate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cohort_openc3_weak_password_chronology as chronology


def test_auth_surface_matching_is_broad_but_boundary_aware() -> None:
    assert chronology._is_auth_surface_path("app/controllers/auth_controller.rb")
    assert chronology._is_auth_surface_path("src/tools/base/Login.vue")
    assert chronology._is_auth_surface_path("src/tools/base/UserMenu.vue")
    assert chronology._is_auth_surface_path("docs/password-reset.md")
    assert chronology._is_auth_surface_path("lib/session/store.rb")
    assert not chronology._is_auth_surface_path("models/tokenizer/model.py")
    assert not chronology._is_auth_surface_path("src/author/profile.vue")


def test_graph_membership_uses_carrier_ancestry_not_timestamps(monkeypatch) -> None:
    candidate = "f" * 40

    def fake_ancestor(_repository: Path, ancestor: str, descendant: str) -> bool:
        return (
            ancestor == candidate
            and descendant == f"{chronology.AUTH_MAIN_LANDING_SHA}^1"
        )

    monkeypatch.setattr(chronology, "_is_ancestor", fake_ancestor)

    membership = chronology._graph_membership(Path("/unused"), candidate)

    assert membership["bucket"] == "main_before_auth_hardening_landing"


def test_priority_lanes_put_direct_auth_and_carriers_first() -> None:
    assert chronology._priority_lane("other_retained_ref", ["Login.vue"]) == (
        "P0_direct_auth_surface"
    )
    assert (
        chronology._priority_lane("release_branch_containing_auth_hardening", [])
        == "P1_auth_hardening_carrier_composition"
    )


def test_source_probe_preserves_cleartext_claim_boundary() -> None:
    source = """
MIN_TOKEN_LENGTH = 8
token_hash = hash(token)
return true if @@token_cache == token_hash
service_password = ENV['OPENC3_SERVICE_PASSWORD']
return true if service_password and service_password == token
raise "token must be at least 8 characters" if token.length < MIN_TOKEN_LENGTH
Digest::SHA2.hexdigest token
"""

    probe = chronology._source_probe(source)

    assert probe["interpretation"]["minimum_password_length"] == 8
    assert probe["interpretation"][
        "application_accepts_password_for_direct_verification"
    ]
    assert probe["interpretation"]["stored_direct_password_representation"] == (
        "unsalted_sha2_digest"
    )
    assert probe["interpretation"]["database_plaintext_storage_claimed"] is False


def test_load_cve_requires_exact_identity_description_and_reference(
    tmp_path: Path,
) -> None:
    record = {
        "cveMetadata": {
            "cveId": chronology.ADVISORY_ID,
            "datePublished": "2025-06-13T00:00:00Z",
        },
        "containers": {
            "cna": {
                "descriptions": [
                    {"lang": "en", "value": chronology.EXPECTED_DESCRIPTION}
                ],
                "references": [{"url": chronology.DISCLOSURE_URL}],
            }
        },
    }
    path = tmp_path / "cve.json"
    path.write_text(json.dumps(record))

    parsed, digest = chronology._load_cve(path)

    assert parsed["cve"] == chronology.ADVISORY_ID
    assert parsed["description"] == chronology.EXPECTED_DESCRIPTION
    assert len(digest) == 64


def test_load_commit_universe_rejects_duplicate_identity(tmp_path: Path) -> None:
    row = {
        "repository_identity": chronology.REPOSITORY_IDENTITY,
        "sha": "a" * 40,
        "observed_ai_unit": True,
    }
    path = tmp_path / "universe.jsonl"
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n")

    with pytest.raises(SystemExit, match="duplicate commit identity"):
        chronology._load_commit_universe(path)


def test_script_block_extraction_ignores_template_only_changes() -> None:
    before = b"<template>old</template>\n<script>const value = 1</script>"
    after = b"<template>new</template>\n<script>const value = 1</script>"

    assert chronology._script_block(before) == chronology._script_block(after)


def test_frozen_carrier_inventory_conserves_all_observed_ai_units() -> None:
    assert sum(chronology.EXPECTED_GRAPH_BUCKET_COUNTS.values()) == 55
    assert len(chronology.MITIGATION_SPECS) == 5
    assert len(chronology.CARRIER_SPECS) == 5
    assert (
        sum(int(spec.get("member_count", 0)) for spec in chronology.CARRIER_SPECS) == 42
    )
    assert chronology.AUTH_UI_AI_SHA not in {
        str(spec["sha"]) for spec in chronology.MITIGATION_SPECS
    }
