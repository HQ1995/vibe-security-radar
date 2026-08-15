from cohort.relations import COMPOSITE_RELATION
from cohort_atomic_squash_member_screen import carrier_same_file_rows, screen_rows


def test_screen_requires_single_member_direct_signal_and_same_file() -> None:
    candidate = "a" * 40
    landed = "b" * 40
    fix = "f" * 40
    relation_id = "cohort-relation-1"
    identity = "github.com/example/repo"
    rows, excluded = screen_rows(
        [
            {
                "relation": COMPOSITE_RELATION,
                "repository_identity": identity,
                "candidate_sha": candidate,
                "fix_sha": fix,
                "landed_sha": landed,
                "origin_relation_id": relation_id,
                "advisories": [{"id": "CVE-2026-12345"}],
            }
        ],
        relations={
            relation_id: {
                "repository_identity": identity,
                "origin_sha": candidate,
                "landed_sha": landed,
                "pr_number": 7,
            }
        },
        roots={(identity, landed): {"status": "RESOLVED", "eligible_origin_count": 1}},
        aliases_by_id={"CVE-2026-12345": "alias-1"},
        alias_rows={
            "alias-1": {
                "analysis_subject": "CVE-2026-12345",
                "member_ids": ["CVE-2026-12345"],
            }
        },
        public_exact={(identity, "alias-1", fix)},
        member_metadata={
            (identity, candidate): {
                "observed_ai_unit": True,
                "signal_types": ["co_author_trailer"],
                "tools": ["claude_code"],
            }
        },
        diff_metadata={
            (identity, candidate): {"changed_files": ["src/a.py"]},
            (identity, fix): {"changed_files": ["src/a.py"]},
        },
    )

    assert excluded == {}
    assert rows[0]["candidate_sha"] == candidate
    assert rows[0]["landed_squash_sha"] == landed
    assert rows[0]["overlapping_files"] == ["src/a.py"]


def test_screen_can_select_multi_member_roots_only() -> None:
    candidate = "a" * 40
    landed = "b" * 40
    fix = "f" * 40
    identity = "github.com/example/repo"
    relation_id = "cohort-relation-1"
    kwargs = {
        "relations": {
            relation_id: {
                "repository_identity": identity,
                "origin_sha": candidate,
                "landed_sha": landed,
            }
        },
        "roots": {
            (identity, landed): {"status": "RESOLVED", "eligible_origin_count": 2}
        },
        "aliases_by_id": {"CVE-2026-12345": "alias-1"},
        "alias_rows": {
            "alias-1": {
                "analysis_subject": "CVE-2026-12345",
                "member_ids": ["CVE-2026-12345"],
            }
        },
        "public_exact": {(identity, "alias-1", fix)},
        "member_metadata": {
            (identity, candidate): {"observed_ai_unit": True, "signal_types": [], "tools": []}
        },
        "diff_metadata": {
            (identity, candidate): {"changed_files": ["src/a.py"]},
            (identity, fix): {"changed_files": ["src/a.py"]},
        },
    }
    candidates = [{
        "relation": COMPOSITE_RELATION,
        "repository_identity": identity,
        "candidate_sha": candidate,
        "fix_sha": fix,
        "landed_sha": landed,
        "origin_relation_id": relation_id,
        "advisories": [{"id": "CVE-2026-12345"}],
    }]

    rows, _ = screen_rows(candidates, multi_member_only=True, **kwargs)
    single_rows, _ = screen_rows(candidates, **kwargs)

    assert [row["candidate_sha"] for row in rows] == [candidate]
    assert single_rows == []


def test_carrier_same_file_prefilter_is_fail_closed() -> None:
    identity = "github.com/example/repo"
    base = {
        "relation": COMPOSITE_RELATION,
        "repository_identity": identity,
        "landed_sha": "a" * 40,
    }
    rows, excluded, blocked = carrier_same_file_rows(
        [
            {**base, "fix_sha": "b" * 40},
            {**base, "fix_sha": "c" * 40},
            {**base, "fix_sha": "d" * 40},
        ],
        {
            (identity, "a" * 40): {"changed_files": ["src/a.py"]},
            (identity, "b" * 40): {"changed_files": ["src/a.py"]},
            (identity, "c" * 40): {"changed_files": ["src/c.py"]},
        },
    )

    assert [row["fix_sha"] for row in rows] == ["b" * 40]
    assert excluded == {
        "carrier_has_no_same_file_overlap": 1,
        "carrier_or_fix_diff_metadata_missing": 1,
    }
    assert blocked[0]["fix_sha"] == "d" * 40
