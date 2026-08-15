from cohort_atomic_cross_file_packets import rank_cross_file_rows


def test_cross_file_ranking_keeps_direct_bridge_and_excludes_squash_and_overlap() -> (
    None
):
    direct = "a" * 40
    squash = "b" * 40
    overlap = "c" * 40
    fix = "f" * 40
    common = {
        "repository_identity": "github.com/example/repo",
        "relation": "reachable_ancestor",
        "fix_sha": fix,
        "advisories": [{"id": "CVE-2026-1"}],
    }
    units = {
        direct: {
            "merge_topology": "direct",
            "signal_types": ["co_author_trailer"],
            "changed_files": ["src/auth/new_route.py"],
            "message": "feat: add auth route",
            "authored_date": "2026-01-01T00:00:00Z",
        },
        squash: {
            "merge_topology": "squash",
            "signal_types": ["co_author_trailer"],
            "changed_files": ["src/auth/other.py"],
            "message": "feat: add auth route",
        },
        overlap: {
            "merge_topology": "direct",
            "signal_types": ["co_author_trailer"],
            "changed_files": ["src/auth/guard.py"],
            "message": "feat: edit guard",
        },
    }
    rows = rank_cross_file_rows(
        [
            {**common, "candidate_sha": direct},
            {**common, "candidate_sha": squash},
            {**common, "candidate_sha": overlap},
        ],
        repository_identity="github.com/example/repo",
        aliases_by_id={"CVE-2026-1": "alias-1"},
        allowed_class_fixes={("alias-1", fix)},
        units=units,
        fix_files={fix: ("src/auth/guard.py",)},
        fix_subjects={fix: "fix auth authorization guard"},
        max_per_class=2,
    )

    assert [row["sha"] for row in rows] == [direct]
    assert rows[0]["signals"] == [
        "observed_ai_reachable_ancestor",
        "feature_introduction",
        "cross_file_path_token_bridge",
        "cross_file_subject_bridge",
    ]
    assert rows[0]["priority_rank"] == 1
