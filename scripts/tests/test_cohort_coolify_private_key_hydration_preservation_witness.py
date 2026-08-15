"""Tests for the Coolify private-key hydration preservation witness."""

from __future__ import annotations

from cohort_coolify_private_key_hydration_preservation_witness import (
    _evaluate_versions,
)


def _source(*, explicit: bool, authorized: bool) -> str:
    property_line = "public string $privateKeyValue;" if explicit else ""
    hydration = (
        "$this->privateKeyValue = $this->private_key->private_key;"
        if explicit
        else ""
    )
    authorization = (
        "$this->authorize('view', $this->private_key);" if authorized else ""
    )
    team_id = "'team_id'" if authorized else ""
    sync_call = "$this->syncData(false);" if explicit else ""
    return f"""
public PrivateKey $private_key;
{property_line}
private function syncData(bool $toModel = false) {{
    {hydration}
}}
public function mount() {{
    $fields = [{team_id}];
    {authorization}
    {sync_call}
}}
"""


def _view(*, explicit: bool) -> str:
    if explicit:
        return '<input id="privateKeyValue"><textarea id="privateKeyValue">'
    return (
        '<input id="private_key.private_key">'
        '<textarea id="private_key.private_key">'
    )


def test_private_key_hydration_requires_rewrite_and_later_authorization() -> None:
    result = _evaluate_versions(
        _source(explicit=False, authorized=False),
        _view(explicit=False),
        _source(explicit=True, authorized=False),
        _view(explicit=True),
        _source(explicit=True, authorized=True),
        _view(explicit=True),
    )

    assert all(result.values())


def test_private_key_hydration_rejects_missing_candidate_rewrite() -> None:
    baseline = _source(explicit=False, authorized=False)
    baseline_view = _view(explicit=False)
    result = _evaluate_versions(
        baseline,
        baseline_view,
        baseline,
        baseline_view,
        _source(explicit=True, authorized=True),
        _view(explicit=True),
    )

    assert result["candidate_reauthors_secret_into_public_scalar"] is False
    assert result["candidate_view_binds_reauthored_secret_scalar"] is False


def test_private_key_hydration_requires_guard_before_hydration() -> None:
    repair = _source(explicit=True, authorized=True).replace(
        "$this->authorize('view', $this->private_key);\n    $this->syncData(false);",
        "$this->syncData(false);\n    $this->authorize('view', $this->private_key);",
    )
    result = _evaluate_versions(
        _source(explicit=False, authorized=False),
        _view(explicit=False),
        _source(explicit=True, authorized=False),
        _view(explicit=True),
        repair,
        _view(explicit=True),
    )

    assert result["repair_adds_effective_view_authorization_before_hydration"] is False
