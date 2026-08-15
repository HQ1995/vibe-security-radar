"""Tests for the all-OSV introduced-SHA to AI-commit join."""

from cohort_osv_introduced_ai_join import join_matches


SHA = "a" * 40


def test_join_is_exact_deduplicated_and_keeps_squash_boundary() -> None:
    rows, scanned = join_matches(
        {
            "github.com/old/project": [
                {
                    "introduced_sha": SHA,
                    "record_id": "GHSA-aaaa-bbbb-cccc",
                    "public_ids": ["CVE-2026-1000", "GHSA-aaaa-bbbb-cccc"],
                    "published": "2026-01-01T00:00:00Z",
                },
                {
                    "introduced_sha": SHA,
                    "record_id": "GHSA-aaaa-bbbb-cccc",
                    "public_ids": ["CVE-2026-1000", "GHSA-aaaa-bbbb-cccc"],
                    "published": "2026-01-01T00:00:00Z",
                },
            ]
        },
        [
            {
                "repository_identity": "github.com/new/project",
                "sha": SHA,
                "merge_topology": "squash",
                "signal_types": ["co_author_trailer"],
            },
            {
                "repository_identity": "github.com/new/project",
                "sha": "b" * 40,
                "merge_topology": "direct",
                "signal_types": ["co_author_trailer"],
            },
        ],
        aliases={"github.com/old/project": "github.com/new/project"},
        alias_by_public_id={
            "CVE-2026-1000": {
                "class_id": "alias-test",
                "states": ["ACTIVE"],
            },
            "GHSA-AAAA-BBBB-CCCC": {
                "class_id": "alias-test",
                "states": ["ACTIVE"],
            },
        },
    )

    assert scanned == 2
    assert len(rows) == 1
    assert rows[0]["active_class_ids"] == ["alias-test"]
    assert len(rows[0]["introduction_observations"]) == 1
    assert rows[0]["atomicity_status"] == "SQUASH_CARRIER_REQUIRES_MEMBER_RESOLUTION"
