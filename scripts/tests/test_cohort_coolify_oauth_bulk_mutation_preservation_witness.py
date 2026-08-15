"""Tests for the Coolify OAuth bulk-mutation preservation witness."""

from __future__ import annotations

from cohort_coolify_oauth_bulk_mutation_preservation_witness import (
    _evaluate_versions,
)


def _source(*, bulk_reauthored: bool, authorized: bool) -> str:
    authorization = (
        "$this->authorize('update', instanceSettings());" if authorized else ""
    )
    bulk_sink = (
        """
        $errors = [];
        $oauth->fill(['enabled' => $settingData['enabled']]);
        if ($oauth->couldBeEnabled()) {}
        $oauth->save();
        $this->oauth_settings_map[$oauth->provider] = [];
"""
        if bulk_reauthored
        else "$oauth->update(['enabled' => $settingData['enabled']]);"
    )
    return f"""
private function updateOauthSettings(?string $provider = null) {{
    if ($provider) {{
        $oauth->save();
    }} else {{
        {bulk_sink}
    }}
}}
public function instantSave(string $provider) {{
    {authorization}
    $this->updateOauthSettings($provider);
}}
public function submit() {{
    {authorization}
    $this->updateOauthSettings();
}}
"""


def test_oauth_bulk_mutation_preservation_requires_rewrite_and_later_guards() -> None:
    result = _evaluate_versions(
        _source(bulk_reauthored=False, authorized=False),
        _source(bulk_reauthored=True, authorized=False),
        "wire:submit='submit' "
        "instantSave=\"instantSave('{{ $oauth_setting['provider'] }}')\"",
        _source(bulk_reauthored=True, authorized=True),
    )

    assert all(result.values())


def test_oauth_bulk_mutation_preservation_fails_without_candidate_rewrite() -> None:
    unchanged = _source(bulk_reauthored=False, authorized=False)
    result = _evaluate_versions(
        unchanged,
        unchanged,
        "wire:submit='submit' "
        "instantSave=\"instantSave('{{ $oauth_setting['provider'] }}')\"",
        _source(bulk_reauthored=True, authorized=True),
    )

    assert result["candidate_reauthors_bulk_mutation_sink"] is False
    assert result["candidate_removes_old_bulk_update_sink"] is False
