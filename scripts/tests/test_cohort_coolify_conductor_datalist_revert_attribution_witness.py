"""Tests for the deterministic Coolify datalist revert attribution witness."""

from __future__ import annotations

from collections import Counter

import pytest

import cohort_coolify_conductor_datalist_revert_attribution_witness as witness


def test_patch_lines_ignores_headers_and_preserves_multiplicity() -> None:
    diff = "+++ b/file\n+same\n+same\n--- a/file\n-old\n context"

    assert witness._patch_lines(diff, "+") == Counter({"same": 2})
    assert witness._patch_lines(diff, "-") == Counter({"old": 1})


def test_patch_lines_rejects_unknown_prefix() -> None:
    with pytest.raises(ValueError, match="prefix"):
        witness._patch_lines(" context", " ")


def test_exact_line_delta_is_fail_closed_on_extra_line() -> None:
    exact = "--- a/file\n+++ b/file\n-old\n+new"
    extra = f"{exact}\n+unrelated"

    assert witness._exact_line_delta(exact, added={"new": 1}, removed={"old": 1})
    assert not witness._exact_line_delta(extra, added={"new": 1}, removed={"old": 1})


def test_bridge_edge_requires_one_exact_pair() -> None:
    rows = [{"candidate_sha": "a" * 40, "fix_sha": "b" * 40}]

    assert witness._bridge_edge(rows, "a" * 40, "b" * 40) == rows[0]
    with pytest.raises(ValueError, match="resolved to 0"):
        witness._bridge_edge(rows, "c" * 40, "d" * 40)


def test_component_contract_requires_non_null_option_materialization() -> None:
    source = """
options: [],
filteredOptions: [],
if (!Array.isArray(this.selected)) {
    this.selected = [];
}
this.options = Array.from(this.$refs.datalist.querySelectorAll('option')).map(opt => {
    value: value,
    text: opt.textContent.trim()
});
this.filteredOptions = this.options;
options: [],
filteredOptions: [],
this.options = Array.from(this.$refs.datalist.querySelectorAll('option')).map(opt => {
    if (opt.disabled) {
        return null;
    }
    value: value,
    text: opt.textContent.trim()
}).filter(opt => opt !== null);
this.filteredOptions = this.options;
"""

    assert all(witness._component_contract(source).values())
    assert (
        witness._component_contract(
            source.replace("}).filter(opt => opt !== null);", "});")
        )["single_mode_filters_disabled_null_entries"]
        is False
    )


def test_consumer_contract_requires_ids_uuids_and_disabled_default() -> None:
    hetzner = """
<x-forms.datalist :multiple="true">
<option value="{{ $sshKey['id'] }}">key</option>
</x-forms.datalist>
"""
    terminal = """
<x-forms.datalist>
<option disabled value="default">choose</option>
<option value="{{ $server->uuid }}">server</option>
<option value="{{ $container['uuid'] }}">container</option>
</x-forms.datalist>
"""

    assert all(witness._consumer_contract(hetzner, terminal).values())
    result = witness._consumer_contract(
        hetzner.replace(
            "</x-forms.datalist>",
            '<option value="0">zero</option></x-forms.datalist>',
        ),
        terminal,
    )
    assert result["no_concrete_enabled_literal_zero_or_empty_fixture"] is False


def test_consumer_contract_ignores_falsy_options_outside_datalist() -> None:
    hetzner = """
<option value="">unrelated select</option>
<x-forms.datalist :multiple="true">
<option value="{{ $sshKey['id'] }}">key</option>
</x-forms.datalist>
"""
    terminal = """
<x-forms.datalist>
<option disabled value="default">choose</option>
<option value="{{ $server->uuid }}">server</option>
<option value="{{ $container['uuid'] }}">container</option>
</x-forms.datalist>
"""

    assert (
        witness._consumer_contract(hetzner, terminal)[
            "no_concrete_enabled_literal_zero_or_empty_fixture"
        ]
        is True
    )


def test_consumer_contract_detects_spaced_single_quoted_falsy_literal() -> None:
    hetzner = """
<x-forms.datalist :multiple="true">
<option class="key" value = '0'>zero</option>
<option value="{{ $sshKey['id'] }}">key</option>
</x-forms.datalist>
"""
    terminal = """
<x-forms.datalist>
<option disabled value="default">choose</option>
<option value="{{ $server->uuid }}">server</option>
<option value="{{ $container['uuid'] }}">container</option>
</x-forms.datalist>
"""

    assert (
        witness._consumer_contract(hetzner, terminal)[
            "no_concrete_enabled_literal_zero_or_empty_fixture"
        ]
        is False
    )
