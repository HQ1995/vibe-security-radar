from cohort_atomic_squash_seed import select_rows


def test_select_rows_requires_multi_member_public_exact_and_unreviewed_class() -> None:
    base = {
        "route": "assistant_squash",
        "merge_topology": "squash",
        "tier": "B_decomposed",
        "root_coverage_status": "RESOLVED",
        "squash_attribution_only": False,
        "n_members": 2,
        "repository_identity": "github.com/example/repo",
        "candidate_sha": "a" * 40,
        "fix_sha": "f" * 40,
        "advisories": [{"id": "CVE-2026-1"}, {"id": "GHSA-AAAA-BBBB-CCCC"}],
    }

    rows = select_rows(
        [base, {**base, "n_members": 1}],
        aliases_by_id={"CVE-2026-1": "alias-new", "GHSA-AAAA-BBBB-CCCC": "alias-new"},
        public_exact={("github.com/example/repo", "GHSA-AAAA-BBBB-CCCC", "f" * 40)},
        excluded_class_ids=set(),
        excluded_public_ids=set(),
        member_scope="multi",
    )
    excluded = select_rows(
        [base],
        aliases_by_id={"CVE-2026-1": "alias-old", "GHSA-AAAA-BBBB-CCCC": "alias-old"},
        public_exact={("github.com/example/repo", "GHSA-AAAA-BBBB-CCCC", "f" * 40)},
        excluded_class_ids={"alias-old"},
        excluded_public_ids=set(),
        member_scope="multi",
    )

    assert len(rows) == 1
    assert [item["id"] for item in rows[0]["advisories"]] == [
        "CVE-2026-1",
        "GHSA-AAAA-BBBB-CCCC",
    ]
    assert excluded == []
