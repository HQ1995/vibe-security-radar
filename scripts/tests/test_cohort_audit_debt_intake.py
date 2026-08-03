"""Tests for the repository-disjoint audit-debt intake contract."""

from __future__ import annotations

import pytest

from cohort.audit_debt_intake import (
    AuditDebtIntakeContractError,
    build_audit_debt_intake,
)


def _row(advisory: str, repository: str) -> dict[str, object]:
    return {
        "advisory": advisory,
        "audit_source": f"audits/{advisory}.json",
        "edge_status": "AUDIT_CONTRACT_MISSING",
        "repository_identity": repository,
    }


def test_intake_accounts_for_every_debt_row_and_excludes_all_prior_splits() -> None:
    census = [
        _row("ADV-new-b", "github.com/new/b"),
        _row("ADV-old-id", "github.com/unused/repo"),
        _row("ADV-old-repo", "github.com/old/atomic"),
        _row("ADV-old-upstream", "github.com/old/upstream"),
        _row("ADV-new-a2", "github.com/new/a"),
        _row("ADV-new-a1", "github.com/new/a"),
        {
            **_row("ADV-not-debt", "github.com/new/ignored"),
            "edge_status": "MULTI_ORIGIN",
        },
    ]
    prior = [
        {
            "controls": [
                {
                    "advisory": "ADV-old-id",
                    "repository_identity": "github.com/old/atomic",
                },
                {
                    "advisory": "ADV-complex",
                    "target_repository_identity": "github.com/old/complex",
                    "upstream_imports": [
                        {
                            "origin_repository_identity": "github.com/old/upstream",
                        }
                    ],
                },
            ]
        }
    ]

    result = build_audit_debt_intake(
        census,
        control_payloads=prior,
        aliases={},
        minimum_new_repositories=2,
    )

    assert result["population"]["audit_contract_missing_count"] == 6
    assert result["selected_repository_count"] == 2
    assert result["gate_status"] == "READY_FOR_HISTORY_AUDIT"
    assert [row["advisory"] for row in result["selected"]] == [
        "ADV-new-a1",
        "ADV-new-b",
    ]
    statuses = {row["advisory"]: row["intake_status"] for row in result["census"]}
    assert statuses == {
        "ADV-new-a1": "SELECTED_FOR_HISTORY_AUDIT",
        "ADV-new-a2": "DEFERRED_REPOSITORY_DEDUP",
        "ADV-new-b": "SELECTED_FOR_HISTORY_AUDIT",
        "ADV-old-id": "EXCLUDED_PRIOR_CONTROL_ADVISORY",
        "ADV-old-repo": "EXCLUDED_PRIOR_CONTROL_REPOSITORY",
        "ADV-old-upstream": "EXCLUDED_PRIOR_CONTROL_REPOSITORY",
    }
    assert "not a blinded" in str(result["claim_boundary"])


def test_intake_fails_closed_on_duplicate_debt_advisory() -> None:
    with pytest.raises(AuditDebtIntakeContractError, match="duplicate"):
        build_audit_debt_intake(
            [_row("ADV-1", "github.com/new/a"), _row("ADV-1", "github.com/new/b")],
            control_payloads=[{"controls": []}],
            aliases={},
        )


def test_intake_keeps_unresolved_repository_visible_and_blocks_gate() -> None:
    result = build_audit_debt_intake(
        [_row("ADV-1", "")],
        control_payloads=[{"controls": []}],
        aliases={},
        minimum_new_repositories=1,
    )
    assert result["selected"] == []
    assert result["gate_status"] == "INSUFFICIENT_NEW_REPOSITORIES"
    assert result["census"][0]["intake_status"] == (
        "BLOCKED_REPOSITORY_UNRESOLVED"
    )
