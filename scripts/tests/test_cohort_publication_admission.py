"""Publication-gate regressions distilled from the fp211 adjudications."""

from __future__ import annotations

from copy import deepcopy

import pytest

from cohort.publication_admission import GATE_FIELDS, evaluate_publication_admission


PASS_GATES = {field: "PASS" for field in GATE_FIELDS}


def _row(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "ordinal": 2,
        "row_key": "strict-200-v3:alias-043e2fc26bdd6275f9cae512",
        "verdict": "CONFIRM",
        "confidence": "HIGH",
        "false_positive_class": None,
        **PASS_GATES,
        "candidate_set": ["d2b27f6f1edb83634730f93dc8f19721d877bd07"],
        "public_ids_keep": ["CVE-2026-6830", "GHSA-VVFR-G83F-8QCV"],
        "public_ids_remove": [],
        "duplicate_of": None,
    }
    row.update(changes)
    return row


def test_strict_confirm_is_admitted_and_candidate_is_retained_by_value() -> None:
    row = _row()
    result = evaluate_publication_admission(
        row,
        source_public_ids={"CVE-2026-6830", "GHSA-VVFR-G83F-8QCV"},
        source_tier="STRICT_RELEASED",
    )

    assert result["admission"] == "ADMIT"
    assert result["may_publish"] is result["released_publication_admitted"] is True
    assert result["strict_confirmed"] is True
    assert result["released_publication_reason"] == result["reason"]
    assert result["causal_valid"] is True
    assert result["public_ids_conserved"] is True
    assert result["errors"] == []
    assert result["recall_candidate"] == row
    assert result["recall_candidate"] is not row
    result["recall_candidate"]["candidate_set"].append("changed")
    assert row["candidate_set"] == ["d2b27f6f1edb83634730f93dc8f19721d877bd07"]


def test_real_narrow_scope_is_causal_valid_but_not_publishable() -> None:
    # fp211 ordinal 1: the AI squash member blob differs from the released carrier.
    row = _row(
        ordinal=1,
        row_key="strict-200-v3:alias-02fb7aeb21b9f4e1ab18fbce",
        verdict="NARROW",
        topology_gate="NARROW",
        candidate_set=["aae7acba91dc21fc897ef6b78989b1f548c4083e"],
        public_ids_keep=["CVE-2026-32111", "GHSA-FMFG-9G7C-3VQ7"],
    )

    result = evaluate_publication_admission(row)

    assert result["admission"] == "HOLD"
    assert result["reason"] == "narrowed_causal_scope_requires_review"
    assert result["may_publish"] is result["strict_confirmed"] is False
    assert result["causal_valid"] is True


@pytest.mark.parametrize(
    ("ordinal", "false_positive_class", "gates"),
    [
        (4, "wrong_edge", ("FAIL", "PASS", "PASS", "FAIL", "FAIL", "NARROW", "PASS")),
        (
            11,
            "old_bug_preserving_refactor",
            ("PASS", "PASS", "PASS", "FAIL", "NARROW", "FAIL", "PASS"),
        ),
        (
            168,
            "HUMAN_WEAKENED_AI_PREDICATE",
            ("PASS", "FAIL", "PASS", "FAIL", "NARROW", "UNKNOWN", "PASS"),
        ),
        (16, "wrong_edge", ("PASS", "PASS", "PASS", "FAIL", "FAIL", "PASS", "PASS")),
        (
            7,
            "unreleased_commit_only",
            ("NARROW", "PASS", "PASS", "PASS", "PASS", "FAIL", "PASS"),
        ),
        (
            68,
            "identity_mismatch",
            ("FAIL", "UNKNOWN", "PASS", "FAIL", "NARROW", "PASS", "PASS"),
        ),
    ],
)
def test_fp211_negative_lessons_are_excluded(
    ordinal: int, false_positive_class: str, gates: tuple[str, ...]
) -> None:
    row = _row(
        ordinal=ordinal,
        verdict="FALSE_POSITIVE",
        false_positive_class=false_positive_class,
        **dict(zip(GATE_FIELDS, gates, strict=True)),
    )

    result = evaluate_publication_admission(row)

    assert result["admission"] == "EXCLUDE"
    assert result["may_publish"] is result["causal_valid"] is False
    assert result["errors"] == []
    assert result["recall_candidate"] == row


def test_same_mechanism_duplicate_requires_bidirectional_uniqueness_binding() -> None:
    duplicate = _row(
        ordinal=67,
        row_key="strict-200-v3:alias-c45218004b47b9754c596ca1",
        verdict="FALSE_POSITIVE",
        false_positive_class="same_mechanism_duplicate",
        identity_gate="NARROW",
        release_gate="NARROW",
        uniqueness_gate="FAIL",
        duplicate_of="strict-200-v3:alias-b52bedc69eca463aef477f74",
    )
    assert evaluate_publication_admission(duplicate)["admission"] == "EXCLUDE"

    for mutation in (
        {"duplicate_of": None},
        {"uniqueness_gate": "PASS"},
        {"duplicate_of": duplicate["row_key"]},
    ):
        broken = {**duplicate, **mutation}
        result = evaluate_publication_admission(broken)
        assert result["admission"] == "HOLD"
        assert result["errors"]


@pytest.mark.parametrize("gate", GATE_FIELDS)
def test_any_unclosed_gate_blocks_a_claim_still_marked_confirm(gate: str) -> None:
    result = evaluate_publication_admission(_row(**{gate: "NARROW"}))

    assert result["may_publish"] is False
    assert result["causal_valid"] is False
    assert "CONFIRM requires all seven gates" in result["errors"][0]


def test_commit_only_can_be_strict_but_cannot_enter_released_publication() -> None:
    commit_only = evaluate_publication_admission(
        _row(release_gate="NA", source_tier="STRICT_COMMIT_ONLY")
    )
    assert commit_only["strict_confirmed"] is True
    assert commit_only["may_publish"] is False
    assert commit_only["admission"] == "HOLD"
    assert commit_only["reason"] == "commit_only_not_released"

    missing_tier = evaluate_publication_admission(_row())
    assert missing_tier["strict_confirmed"] is True
    assert missing_tier["may_publish"] is False
    assert missing_tier["reason"] == "released_source_tier_required"

    no_release_proof = evaluate_publication_admission(
        _row(release_gate="NA"), source_tier="STRICT_RELEASED"
    )
    assert no_release_proof["strict_confirmed"] is True
    assert no_release_proof["may_publish"] is False
    assert no_release_proof["reason"] == "release_gate_must_pass"

    medium = evaluate_publication_admission(
        _row(confidence="MEDIUM"), source_tier="STRICT_RELEASED"
    )
    assert medium["admission"] == "HOLD"
    assert medium["strict_confirmed"] is False
    assert medium["causal_valid"] is True


def test_released_publication_requires_every_gate_pass() -> None:
    held = evaluate_publication_admission(
        _row(identity_gate="NA"), source_tier="STRICT_RELEASED"
    )

    assert held["admission"] == "HOLD"
    assert held["reason"] == "all_gates_must_pass"
    assert held["may_publish"] is held["released_publication_admitted"] is False
    assert held["strict_confirmed"] is True
    assert held["causal_valid"] is True
    assert held["errors"] == []

    admitted = evaluate_publication_admission(_row(), source_tier="STRICT_RELEASED")
    assert admitted["admission"] == "ADMIT"
    assert (
        admitted["may_publish"] is admitted["released_publication_admitted"] is True
    )


@pytest.mark.parametrize(
    ("verdict", "gate_value"), [("UNKNOWN", "UNKNOWN"), ("BLOCKED", "BLOCKED")]
)
def test_unresolved_verdicts_are_held(verdict: str, gate_value: str) -> None:
    result = evaluate_publication_admission(
        _row(verdict=verdict, ai_hunk_gate=gate_value)
    )

    assert result["admission"] == "HOLD"
    assert result["may_publish"] is result["causal_valid"] is False


def test_narrow_requires_an_explicit_narrow_gate_but_allows_release_unknown() -> None:
    implicit = evaluate_publication_admission(_row(verdict="NARROW"))
    assert implicit["causal_valid"] is False
    assert "explicitly NARROW" in implicit["errors"][0]

    explicit = evaluate_publication_admission(
        _row(verdict="NARROW", topology_gate="NARROW", release_gate="UNKNOWN")
    )
    assert explicit["causal_valid"] is True
    assert explicit["may_publish"] is False


def test_false_positive_without_a_fail_and_public_id_loss_fail_closed() -> None:
    no_failure = evaluate_publication_admission(
        _row(verdict="FALSE_POSITIVE", false_positive_class="wrong_edge")
    )
    assert no_failure["admission"] == "HOLD"
    assert "fatal FAIL" in no_failure["errors"][-1]

    lost_id = evaluate_publication_admission(
        _row(),
        source_public_ids={
            "CVE-2026-6830",
            "GHSA-VVFR-G83F-8QCV",
            "GHSA-MISSING-FROM-DISPOSITION",
        },
    )
    assert lost_id["public_ids_conserved"] is False
    assert lost_id["may_publish"] is False
    assert lost_id["reason"] == "invalid_adjudication"

    topology_only = evaluate_publication_admission(
        _row(
            verdict="FALSE_POSITIVE",
            false_positive_class="carrier_only",
            topology_gate="FAIL",
        )
    )
    assert topology_only["admission"] == "EXCLUDE"
    assert topology_only["errors"] == []


def test_public_id_keep_remove_overlap_fails_closed() -> None:
    row = _row(public_ids_remove=["CVE-2026-6830"])
    original = deepcopy(row)
    result = evaluate_publication_admission(row)

    assert result["may_publish"] is False
    assert any("must be disjoint" in error for error in result["errors"])
    assert row == original


def test_malformed_unhashable_values_fail_closed_without_raising() -> None:
    result = evaluate_publication_admission(
        _row(verdict=[], identity_gate=[], source_tier=[])
    )

    assert result["admission"] == "HOLD"
    assert result["may_publish"] is result["causal_valid"] is False
    assert {"verdict is invalid", "identity_gate is invalid"} <= set(result["errors"])
