"""Tests for fail-closed expansion of audited AI-causal controls."""

from __future__ import annotations

from cohort.control_census import build_control_candidate_census


ORIGIN_A = "1" * 40
ORIGIN_B = "2" * 40
LANDED = "3" * 40
FIX = "4" * 40


def _adjudication(advisory: str, source: str, confidence: float = 0.99) -> dict[str, object]:
    return {
        "cve_id": advisory,
        "label": "AI_CAUSAL",
        "source": source,
        "confidence": confidence,
    }


def _audit(advisory: str, evidence: dict[str, object]) -> dict[str, object]:
    return {
        "cve_id": advisory,
        "audit_verdict": "TRUE_POSITIVE",
        "ai_authored_vulnerability": True,
        "confidence": 0.99,
        "evidence": evidence,
    }


def _cache(repo_url: str) -> dict[str, object]:
    return {"fix_commits": [{"sha": FIX, "repo_url": repo_url}]}


def test_census_selects_one_atomic_control_per_new_repository() -> None:
    adjudications = [
        _adjudication("CVE-NEW-2", "audit/new-2.json"),
        _adjudication("CVE-NEW-1", "audit/new-1.json"),
        _adjudication("CVE-USED", "audit/used.json"),
    ]
    audits = {
        "audit/new-1.json": _audit(
            "CVE-NEW-1",
            {
                "atomic_origin_commit": ORIGIN_A,
                "atomic_ai_signal": "bot",
                "landed_squash_commit": LANDED,
                "fix_commit": FIX,
            },
        ),
        "audit/new-2.json": _audit(
            "CVE-NEW-2",
            {
                "atomic_origin_commit": ORIGIN_B,
                "atomic_ai_signal": "bot",
                "fix_commit": FIX,
            },
        ),
        "audit/used.json": _audit(
            "CVE-USED",
            {
                "atomic_origin_commit": ORIGIN_A,
                "atomic_ai_signal": "bot",
                "fix_commit": FIX,
            },
        ),
    }
    cached = {
        "CVE-NEW-1": _cache("https://github.com/Acme/Repo"),
        "CVE-NEW-2": _cache("https://github.com/acme/repo.git"),
        "CVE-USED": _cache("https://github.com/used/repo"),
    }

    result = build_control_candidate_census(
        adjudications,
        audits,
        cached,
        existing_controls=[
            {
                "advisory": "CVE-OLD",
                "repository_identity": "github.com/used/repo",
            }
        ],
        aliases={},
    )

    assert result["ai_causal_count"] == 3
    assert result["selected_count"] == 1
    assert result["selected_controls"] == [
        {
            "advisory": "CVE-NEW-1",
            "atomic_origin_sha": ORIGIN_A,
            "expected_landed_sha": LANDED,
            "expected_relation": (
                "pull_request_member_landed_as_squash_then_reachable_ancestor"
            ),
            "fix_sha": FIX,
            "repository_identity": "github.com/acme/repo",
            "source": "audit/new-1.json",
        }
    ]
    statuses = {row["advisory"]: row["selection_status"] for row in result["census"]}
    assert statuses == {
        "CVE-NEW-1": "SELECTED",
        "CVE-NEW-2": "DEFER_REPOSITORY_DEDUP",
        "CVE-USED": "ALREADY_USED_REPOSITORY",
    }


def test_census_accounts_for_complex_and_weak_audit_rows_without_selecting_them() -> None:
    adjudications = [
        _adjudication("CVE-CROSS", "audit/cross.json"),
        _adjudication("CVE-LEGACY", "audit/legacy.json"),
        _adjudication("CVE-LOW", "audit/low.json", confidence=0.90),
        _adjudication("CVE-MULTI", "audit/multi.json"),
        {"cve_id": "CVE-NEG", "label": "NOT_AI_CAUSAL", "source": "audit/neg.json"},
    ]
    audits = {
        "audit/cross.json": _audit(
            "CVE-CROSS",
            {
                "upstream_atomic_ai_origin": ORIGIN_A,
                "atomic_ai_signal": "bot",
                "fix_commit": FIX,
            },
        ),
        "audit/legacy.json": {"cve_id": "CVE-LEGACY", "verdict": "DISAGREE_FN"},
        "audit/low.json": _audit(
            "CVE-LOW",
            {
                "atomic_origin_commit": ORIGIN_A,
                "atomic_ai_signal": "bot",
                "fix_commit": FIX,
            },
        ),
        "audit/multi.json": _audit(
            "CVE-MULTI",
            {
                "trigger_origin_commit": ORIGIN_A,
                "unsafe_optimizer_commit": ORIGIN_B,
                "atomic_ai_signal": "bot",
                "fix_commit": FIX,
            },
        ),
    }
    cached = {
        advisory: _cache(f"https://github.com/example/{advisory.lower()}")
        for advisory in ("CVE-CROSS", "CVE-LEGACY", "CVE-LOW", "CVE-MULTI")
    }

    result = build_control_candidate_census(
        adjudications,
        audits,
        cached,
        existing_controls=[],
        aliases={},
        minimum_confidence=0.98,
    )

    assert result["ai_causal_count"] == 4
    assert result["selected_count"] == 0
    assert len(result["census"]) == 4
    edge_statuses = {row["advisory"]: row["edge_status"] for row in result["census"]}
    assert edge_statuses == {
        "CVE-CROSS": "CROSS_REPOSITORY_ORIGIN",
        "CVE-LEGACY": "AUDIT_CONTRACT_MISSING",
        "CVE-LOW": "LOW_CONFIDENCE",
        "CVE-MULTI": "MULTI_ORIGIN",
    }
    assert all(
        str(row["selection_status"]).startswith("BLOCKED_")
        for row in result["census"]
    )


def test_census_accepts_explicit_ai_binding_without_treating_origin_as_signal() -> None:
    advisory = "CVE-BINDING"
    source = "audit/binding.json"
    audit = _audit(
        advisory,
        {
            "atomic_ai_origin": ORIGIN_A,
            "ai_binding": "The atomic commit was authored by a named AI bot.",
            "fix_commit": FIX,
        },
    )

    result = build_control_candidate_census(
        [_adjudication(advisory, source)],
        {source: audit},
        {advisory: _cache("https://github.com/example/binding")},
        existing_controls=[],
        aliases={},
    )

    assert result["selected_count"] == 1
    assert result["census"][0]["edge_status"] == "ATOMIC"
