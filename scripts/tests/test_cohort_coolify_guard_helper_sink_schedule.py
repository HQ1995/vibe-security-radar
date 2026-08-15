"""Tests for the guard-to-helper surviving-sink schedule."""

from __future__ import annotations

from cohort_coolify_guard_helper_sink_schedule import (
    _candidate_owned_method_lines,
    _closure_methods,
    _parse_blame_porcelain,
    _priority,
    _surviving_novel_sink_lines,
)


def test_closure_includes_only_defined_one_hop_this_helpers() -> None:
    source = """
public function submit() {
    $this->authorize('update', $this->settings);
    $this->mutate();
    $this->missing();
}
private function mutate() {
    $this->settings->save();
}
"""

    assert _closure_methods(source, "submit") == {"submit": 0, "mutate": 1}


def test_blame_parser_and_candidate_owned_method_lines_are_exact() -> None:
    candidate = "a" * 40
    other = "b" * 40
    blame = _parse_blame_porcelain(
        f"{other} 1 1 1\nauthor A\n\tpublic function mutate() {{\n"
        f"{candidate} 2 2 1\nauthor B\n\t$this->model->save();\n"
        f"{other} 3 3 1\nauthor A\n\t}}\n"
    )

    assert _candidate_owned_method_lines(
        blame=blame, method_range=(1, 3), candidate_sha=candidate
    ) == ["$this->model->save();"]


def test_surviving_novel_sink_gets_highest_priority() -> None:
    surviving = ["$this->model->save();", "$errors = [];"]
    delta = {"candidate_novel_sink_lines": ["$this->model->save();"]}

    assert _surviving_novel_sink_lines(surviving, delta) == [
        "$this->model->save();"
    ]
    assert _priority(
        surviving_novel_sink_count=1,
        surviving_sink_count=1,
        surviving_security_line_count=0,
        closure_depth=1,
    ) == (0, "P0_SURVIVING_NOVEL_SINK")
