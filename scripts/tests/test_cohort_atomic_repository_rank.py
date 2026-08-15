from cohort_atomic_repository_rank import rank_repositories


def test_rank_repositories_requires_direct_explicit_ai_and_deduplicates_classes() -> (
    None
):
    aliases = [
        {"class_id": "alias-a", "member_ids": ["CVE-2026-1", "GHSA-a"]},
        {"class_id": "alias-b", "member_ids": ["OSV-2026-2"]},
    ]
    ai_commits = [
        {
            "repository_identity": "github.com/acme/repo",
            "sha": "a" * 40,
            "merge_topology": "direct",
            "signal_types": ["co_author_trailer"],
            "observed_in_clone_paths": ["/tmp/repo"],
        },
        {
            "repository_identity": "github.com/acme/repo",
            "sha": "b" * 40,
            "merge_topology": "squash",
            "signal_types": ["co_author_trailer"],
        },
    ]
    candidates = [
        {
            "repository_identity": "github.com/acme/repo",
            "candidate_sha": "a" * 40,
            "fix_sha": "f" * 40,
            "relation": "reachable_ancestor",
            "advisories": [{"id": "CVE-2026-1"}, {"id": "GHSA-a"}],
        },
        {
            "repository_identity": "github.com/acme/repo",
            "candidate_sha": "b" * 40,
            "fix_sha": "f" * 40,
            "relation": "reachable_ancestor",
            "advisories": [{"id": "CVE-2026-1"}],
        },
    ]

    fix_observations = [
        {
            "repository_identity": "github.com/acme/repo",
            "advisory": "GHSA-a",
            "fix_sha": "f" * 40,
            "resolution_status": "RESOLVED",
            "evidence_kind": "public_exact",
        }
    ]

    assert rank_repositories(
        aliases,
        ai_commits,
        candidates,
        fix_observations,
        excluded=set(),
    ) == [
        {
            "repository_identity": "github.com/acme/repo",
            "repository_paths": ["/tmp/repo"],
            "alias_class_count": 1,
            "direct_ai_candidate_count": 1,
            "fix_count": 1,
            "source_edge_count": 1,
            "rank": 1,
        }
    ]
