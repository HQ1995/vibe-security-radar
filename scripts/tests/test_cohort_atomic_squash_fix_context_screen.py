from cohort_atomic_squash_fix_context_screen import _group_rows, _rows_with_evidence
from cohort_origin_squash_expand import _squash_internal_fix_context


def test_fix_context_screen_routes_only_mapped_member() -> None:
    rows = [
        {
            "repository_identity": "github.com/example/repo",
            "relation_pr_number": 7,
            "fix_sha": "f" * 40,
            "candidate_sha": candidate,
            "class_id": f"alias-{candidate[0]}",
        }
        for candidate in ("a" * 40, "b" * 40)
    ]
    groups = _group_rows(rows)
    matched = _rows_with_evidence(
        rows,
        {
            "a" * 40: [
                {
                    "match_quality": "exact_line",
                    "match_ambiguity": 1,
                    "path": "src/a.py",
                }
            ]
        },
    )

    assert len(groups) == 1
    assert [row["candidate_sha"] for row in matched] == ["a" * 40]
    assert matched[0]["exact_unambiguous_line_count"] == 1


def test_fix_context_reuses_index_without_changing_match_semantics(monkeypatch) -> None:
    member = "a" * 40
    context = {
        "path": "src/a.py",
        "fix_hunk_old_start": 4,
        "fix_hunk_old_count": 1,
        "fix_parent_line": 4,
        "content": "dangerous(value)",
        "tokens": frozenset({"dangerous", "value"}),
    }
    monkeypatch.setattr(
        "cohort_origin_squash_expand._fix_context_lines",
        lambda *args, **kwargs: [context],
    )
    blame_cache = {
        (7, "src/a.py"): [
            {"sha": member, "line": 9, "content": "dangerous(value)"}
        ]
    }
    match_index_cache = {}

    result = _squash_internal_fix_context(
        None,
        pr_number=7,
        fix_sha="f" * 40,
        member_shas={member},
        timeout=1,
        patch_cache={},
        file_cache={},
        blame_cache=blame_cache,
        match_index_cache=match_index_cache,
    )

    assert result[member][0]["match_quality"] == "exact_line"
    assert result[member][0]["match_ambiguity"] == 1
    assert (7, "src/a.py") in match_index_cache
