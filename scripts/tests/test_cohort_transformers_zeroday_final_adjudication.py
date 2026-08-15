"""Contracts for final Transformers candidate adjudication."""

from __future__ import annotations

from pathlib import Path

import pytest

import cohort_transformers_zeroday_final_adjudication as final


def test_categories_splits_multi_category_signals() -> None:
    value = final._categories(
        {
            "signal_changes": [
                {"categories": "torch_deserialization,unsafe_weights_only"},
                {"categories": "loader_api"},
            ]
        }
    )

    assert value == {
        "torch_deserialization",
        "unsafe_weights_only",
        "loader_api",
    }


def test_direct_danger_categories_exclude_rank_only_loader_terms() -> None:
    assert "loader_api" not in final.DIRECT_DANGER_CATEGORIES
    assert "safe_serialization" not in final.DIRECT_DANGER_CATEGORIES
    assert "unsafe_weights_only" in final.DIRECT_DANGER_CATEGORIES
    assert "explicit_trust_guard" in final.DIRECT_DANGER_CATEGORIES


def test_expected_model_leads_are_exact() -> None:
    assert final.EXPECTED_MODEL_LEADS == {
        "89d53495c8ba71f355517b24935f8847cf6eb923",
        "9d67585e8de33640fc9b2e88638c8de338e3d0f6",
    }


def test_categories_rejects_malformed_signal_rows() -> None:
    with pytest.raises(ValueError, match="malformed"):
        final._categories({"signal_changes": None})


def test_signal_followup_is_repository_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[Path, str]] = []

    def fake(repository: Path, sha: str) -> list[dict[str, str]]:
        seen.append((repository, sha))
        return []

    monkeypatch.setattr(final, "_signal_changes", fake)
    assert final._signal_changes(Path("repo"), "a" * 40) == []
    assert seen == [(Path("repo"), "a" * 40)]
