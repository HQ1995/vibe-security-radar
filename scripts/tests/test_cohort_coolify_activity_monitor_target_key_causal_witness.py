"""Tests for the Coolify activity-monitor target/key causal witness."""

from __future__ import annotations

from cohort_coolify_activity_monitor_target_key_causal_witness import (
    _evaluate_candidate,
    _evaluate_fix,
    _evaluate_later_root_cause,
    _evaluate_parent,
    _static_delivery_matrix,
)


PARENT_SOURCE = """
$this->dispatch('activityMonitor', $restore->id);
$this->dispatch('activityMonitor', $download->id);
$this->dispatch('activityMonitor', $import->id);
"""
CANDIDATE_SOURCE = """
$this->dispatch('activityMonitor', $restore->id)->to('database-restore-monitor');
$this->dispatch('activityMonitor', $download->id)->to('s3-download-monitor');
$this->dispatch('activityMonitor', $import->id)->to('database-restore-monitor');
"""
PARENT_VIEW = """
<livewire:activity-monitor header="S3" />
<livewire:activity-monitor header="Database" />
"""
CANDIDATE_VIEW = """
<livewire:activity-monitor key="s3-download-monitor" header="S3" />
<livewire:activity-monitor key="database-restore-monitor" header="Database" />
"""
MONITOR = """
class ActivityMonitor extends Component
{
    protected $listeners = ['activityMonitor' => 'newMonitorActivity'];
}
"""
LATER_VIEW = """
@if ($s3DownloadInProgress)
<livewire:activity-monitor wire:key="s3-download-{{ $resource->uuid }}" />
@endif
@if ($importRunning)
<livewire:activity-monitor wire:key="database-restore-{{ $resource->uuid }}" />
@endif
"""
LATER_MESSAGE = """
Original approach was correct: use dispatch + event listeners
Use @if conditionals to render only one monitor at a time
unique wire:key per monitor
"""


def test_parent_has_broadcast_dispatch_and_two_unkeyed_monitors() -> None:
    assert all(_evaluate_parent(PARENT_SOURCE, PARENT_VIEW).values())


def test_candidate_mistakes_instance_keys_for_component_targets() -> None:
    assert all(_evaluate_candidate(CANDIDATE_SOURCE, CANDIDATE_VIEW, MONITOR).values())
    assert all(
        row["matching_rendered_component_name_count"] == 0
        for row in _static_delivery_matrix(CANDIDATE_SOURCE, CANDIDATE_VIEW)
    )


def test_fix_exactly_restores_parent_state() -> None:
    assert all(
        _evaluate_fix(
            PARENT_SOURCE,
            PARENT_VIEW,
            PARENT_SOURCE,
            PARENT_VIEW,
        ).values()
    )


def test_later_root_cause_uses_broadcast_plus_wire_keys() -> None:
    assert all(
        _evaluate_later_root_cause(
            LATER_MESSAGE,
            PARENT_SOURCE,
            LATER_VIEW,
        ).values()
    )


def test_component_name_target_is_not_misclassified_as_key_alias() -> None:
    source = "\n".join(
        [
            "$this->dispatch('activityMonitor', $a->id)->to('activity-monitor');",
            "$this->dispatch('activityMonitor', $b->id)->to('activity-monitor');",
            "$this->dispatch('activityMonitor', $c->id)->to('activity-monitor');",
        ]
    )
    checks = _evaluate_candidate(source, CANDIDATE_VIEW, MONITOR)

    assert checks["candidate_targets_are_exactly_instance_keys"] is False
    assert checks["instance_keys_do_not_name_rendered_component"] is False
    assert checks["static_target_resolution_finds_no_component_name"] is False
