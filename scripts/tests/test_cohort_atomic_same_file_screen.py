from cohort_atomic_same_file_screen import build_same_file_rows


def test_same_file_screen_rejects_squash_carriers_and_requires_resolved_members() -> None:
    aliases = {"CVE-2026-1": "alias-1"}
    alias_rows = {
        "alias-1": {
            "analysis_subject": "CVE-2026-1",
            "member_ids": ["CVE-2026-1", "GHSA-1111-2222-3333"],
        }
    }
    ai_units = {
        "a" * 40: {
            "merge_topology": "direct",
            "changed_files": ["src/auth.ts"],
            "signal_types": ["co_author_trailer"],
            "tools": ["claude_code"],
        },
        "b" * 40: {
            "merge_topology": "squash",
            "changed_files": ["src/auth.ts"],
            "signal_types": ["co_author_trailer"],
            "tools": ["claude_code"],
        },
        "c" * 40: {
            "merge_topology": "direct",
            "changed_files": ["src/auth.ts"],
            "signal_types": ["co_author_trailer"],
            "tools": ["claude_code"],
        },
    }
    relations = {
        "relation-1": {
            "origin_sha": "c" * 40,
            "landed_sha": "b" * 40,
            "origin_observed_in_cohort": True,
        }
    }
    common = {
        "repository_identity": "github.com/example/project",
        "fix_sha": "f" * 40,
        "advisories": [{"id": "CVE-2026-1"}],
    }
    edges = [
        {**common, "edge_id": "direct", "candidate_sha": "a" * 40, "relation": "reachable_ancestor"},
        {**common, "edge_id": "carrier", "candidate_sha": "b" * 40, "relation": "reachable_ancestor"},
        {
            **common,
            "edge_id": "member",
            "candidate_sha": "c" * 40,
            "relation": "pull_request_member_landed_as_squash_then_reachable_ancestor",
            "origin_relation_id": "relation-1",
            "relation_pr_number": 7,
        },
    ]

    rows = build_same_file_rows(
        edges,
        repository_identity="github.com/example/project",
        aliases_by_id=aliases,
        alias_rows=alias_rows,
        ai_units=ai_units,
        relations_by_id=relations,
        fix_files={"f" * 40: ("src/auth.ts",)},
        allowed_class_fixes={("alias-1", "f" * 40)},
    )

    assert [row["candidate_sha"] for row in rows] == ["a" * 40, "c" * 40]
    assert rows[1]["landed_squash_sha"] == "b" * 40
