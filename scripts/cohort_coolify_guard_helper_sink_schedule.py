#!/usr/bin/env python3
"""Build a label-neutral guard-to-helper surviving-sink review lane for Coolify."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

from cohort.origin_signals import parse_origin_hunks
from cohort_coolify_guard_method_history_schedule import (
    REPOSITORY_IDENTITY,
    _REMOVED_CONTROL_RE,
    _SINK_RE,
    _git,
    _method_at_line,
    _method_delta,
    _method_or_none,
    _method_ranges,
    _revision_parents,
)
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
)


_THIS_CALL_RE = re.compile(r"\$this->([A-Za-z_]\w*)\s*\(")
_SECURITY_LINE_RE = re.compile(
    r"(?:"
    r"authoriz|validat|escap|saniti|ownedBy|whereTeamId|find_destination"
    r"|\#\[Locked\]|isValid|canAccess|permission|policy|guard"
    r")",
    re.IGNORECASE,
)
_BLAME_HEADER_RE = re.compile(r"^([0-9a-f]{40})\s+\d+\s+(\d+)(?:\s+\d+)?$")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--source-queue", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(source: Path) -> dict[str, object]:
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object: {source}")
    return value


def _sha256(source: Path) -> str:
    return hashlib.sha256(source.read_bytes()).hexdigest()


def _method_range(source: str, method: str) -> tuple[int, int] | None:
    matches = [
        (start, end)
        for start, end, candidate_method in _method_ranges(source)
        if candidate_method == method
    ]
    if len(matches) > 1:
        raise ValueError(f"duplicate PHP method {method}")
    return matches[0] if matches else None


def _this_callees(method_source: str) -> set[str]:
    return set(_THIS_CALL_RE.findall(method_source))


def _closure_methods(source: str, guarded_method: str) -> dict[str, int]:
    guarded_source = _method_or_none(source, guarded_method)
    if guarded_source is None:
        return {}
    closure = {guarded_method: 0}
    for callee in sorted(_this_callees(guarded_source)):
        if callee != guarded_method and _method_or_none(source, callee) is not None:
            closure[callee] = 1
    return closure


def _parse_blame_porcelain(output: str) -> dict[int, tuple[str, str]]:
    records: dict[int, tuple[str, str]] = {}
    origin_sha: str | None = None
    final_line: int | None = None
    for raw_line in output.splitlines():
        header = _BLAME_HEADER_RE.match(raw_line)
        if header is not None:
            origin_sha = header.group(1)
            final_line = int(header.group(2))
            continue
        if raw_line.startswith("\t"):
            if origin_sha is None or final_line is None:
                raise ValueError("blame content appeared without a header")
            records[final_line] = (origin_sha, raw_line[1:])
            origin_sha = None
            final_line = None
    if not records and output:
        raise ValueError("could not parse blame porcelain output")
    return records


def _candidate_owned_method_lines(
    *,
    blame: Mapping[int, tuple[str, str]],
    method_range: tuple[int, int],
    candidate_sha: str,
) -> list[str]:
    start, end = method_range
    result: list[str] = []
    for line_number in range(start, end + 1):
        record = blame.get(line_number)
        if record is None or record[0] != candidate_sha:
            continue
        line = record[1].strip()
        if line and line not in {"{", "}"} and not line.startswith("//"):
            result.append(line)
    return result


def _surviving_novel_sink_lines(
    surviving_lines: list[str], delta: Mapping[str, object]
) -> list[str]:
    novel = {
        str(line).strip()
        for line in delta.get("candidate_novel_sink_lines", [])
        if str(line).strip()
    }
    return [line for line in surviving_lines if line in novel]


def _priority(
    *,
    surviving_novel_sink_count: int,
    surviving_sink_count: int,
    surviving_security_line_count: int,
    closure_depth: int,
) -> tuple[int, str]:
    if surviving_novel_sink_count:
        return 0, "P0_SURVIVING_NOVEL_SINK"
    if surviving_sink_count:
        return 1, "P1_SURVIVING_SINK"
    if surviving_security_line_count:
        return 2, "P2_SURVIVING_SECURITY_BOUNDARY"
    if closure_depth == 1:
        return 3, "P3_ONE_HOP_HELPER_DELTA"
    return 4, "P4_DIRECT_GUARDED_METHOD_DELTA"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    source_queue = _load_json(args.source_queue)
    if source_queue.get("repository_identity") != REPOSITORY_IDENTITY:
        raise SystemExit("source queue repository identity mismatch")
    if source_queue.get("conservation", {}).get("passed") is not True:
        raise SystemExit("source queue is not conservation-passing")
    neutral_rows = source_queue.get("route_neutral_rows")
    post_rows = source_queue.get("post_route_rows")
    if not isinstance(neutral_rows, list) or not isinstance(post_rows, list):
        raise SystemExit("source queue rows are missing")
    if len(neutral_rows) != len(post_rows):
        raise SystemExit("source queue neutral/post row count mismatch")

    def edge_of(row: Mapping[str, object]) -> tuple[str, str]:
        return str(row.get("candidate_sha") or ""), str(row.get("fix_sha") or "")

    neutral_by_edge: dict[tuple[str, str], Mapping[str, object]] = {}
    for raw_row in neutral_rows:
        if not isinstance(raw_row, Mapping):
            raise SystemExit("source queue neutral row is not an object")
        edge = edge_of(raw_row)
        if len(edge[0]) != 40 or len(edge[1]) != 40 or edge in neutral_by_edge:
            raise SystemExit(f"malformed or duplicate neutral edge: {edge}")
        neutral_by_edge[edge] = raw_row
    post_by_edge = {
        edge_of(row): row for row in post_rows if isinstance(row, Mapping)
    }
    if set(neutral_by_edge) != set(post_by_edge):
        raise SystemExit("source queue neutral/post edge universes differ")

    edges_by_fix: defaultdict[str, list[str]] = defaultdict(list)
    for candidate_sha, fix_sha in neutral_by_edge:
        edges_by_fix[fix_sha].append(candidate_sha)

    blob_cache: dict[tuple[str, str], str | None] = {}
    blame_cache: dict[
        tuple[str, str, int, int], dict[int, tuple[str, str]]
    ] = {}
    parent_cache: dict[str, list[str]] = {}

    def blob(revision: str, source_path: str) -> str | None:
        key = (revision, source_path)
        if key not in blob_cache:
            blob_cache[key] = _git(
                repository, ["show", f"{revision}:{source_path}"], optional=True
            )
        return blob_cache[key]

    def parents(revision: str) -> list[str]:
        if revision not in parent_cache:
            line = _git(repository, ["rev-list", "--parents", "-n", "1", revision])
            assert line is not None
            parent_cache[revision] = _revision_parents(line.strip(), revision)
        return parent_cache[revision]

    def blame(
        revision: str, source_path: str, method_range: tuple[int, int]
    ) -> dict[int, tuple[str, str]]:
        start, end = method_range
        key = (revision, source_path, start, end)
        if key not in blame_cache:
            output = _git(
                repository,
                [
                    "blame",
                    "--line-porcelain",
                    "-L",
                    f"{start},{end}",
                    revision,
                    "--",
                    source_path,
                ],
            )
            assert output is not None
            blame_cache[key] = _parse_blame_porcelain(output)
        return blame_cache[key]

    controls: defaultdict[
        tuple[str, str, str], dict[str, object]
    ] = defaultdict(lambda: {"hunk_count": 0, "added_lines": []})
    fix_parents: dict[str, str] = {}
    guard_hunk_count = 0
    for fix_sha in sorted(edges_by_fix):
        fix_parent_list = parents(fix_sha)
        if not fix_parent_list:
            continue
        fix_parent = fix_parent_list[0]
        fix_parents[fix_sha] = fix_parent
        patch = _git(
            repository,
            [
                "diff",
                "--unified=0",
                "--no-color",
                "--find-renames",
                fix_parent,
                fix_sha,
            ],
        )
        assert patch is not None
        for hunk in parse_origin_hunks(patch):
            source_path = hunk.parent_path
            if (
                source_path is None
                or not source_path.endswith(".php")
                or source_path.startswith(("test/", "tests/", "vendor/"))
                or not hunk.is_guard_like
            ):
                continue
            parent_source = blob(fix_parent, source_path)
            if parent_source is None:
                continue
            method = _method_at_line(parent_source, hunk.old_start)
            if method is None:
                continue
            guard_hunk_count += 1
            control = controls[(fix_sha, source_path, method)]
            control["hunk_count"] = int(control["hunk_count"]) + 1
            added_lines = control["added_lines"]
            assert isinstance(added_lines, list)
            added_lines.extend(line.strip() for line in hunk.added_lines if line.strip())

    neutral_rows_by_key: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for (fix_sha, source_path, guarded_method), control in sorted(controls.items()):
        fix_parent = fix_parents[fix_sha]
        fix_parent_source = blob(fix_parent, source_path)
        assert fix_parent_source is not None
        closure = _closure_methods(fix_parent_source, guarded_method)
        for candidate_sha in sorted(edges_by_fix[fix_sha]):
            candidate_source = blob(candidate_sha, source_path)
            if candidate_source is None:
                continue
            candidate_parents = parents(candidate_sha)
            parent_sources = [blob(parent, source_path) for parent in candidate_parents]
            for candidate_method, closure_depth in closure.items():
                delta = _method_delta(
                    parent_sources=parent_sources,
                    candidate_source=candidate_source,
                    method=candidate_method,
                )
                if delta is None:
                    continue
                method_range = _method_range(fix_parent_source, candidate_method)
                if method_range is None:
                    continue
                method_blame = blame(fix_parent, source_path, method_range)
                surviving = _candidate_owned_method_lines(
                    blame=method_blame,
                    method_range=method_range,
                    candidate_sha=candidate_sha,
                )
                if not surviving:
                    continue
                surviving_sinks = [line for line in surviving if _SINK_RE.search(line)]
                surviving_novel_sinks = _surviving_novel_sink_lines(surviving, delta)
                surviving_security = [
                    line
                    for line in surviving
                    if _REMOVED_CONTROL_RE.search(line)
                    or _SECURITY_LINE_RE.search(line)
                ]
                priority_tier, priority_class = _priority(
                    surviving_novel_sink_count=len(surviving_novel_sinks),
                    surviving_sink_count=len(surviving_sinks),
                    surviving_security_line_count=len(surviving_security),
                    closure_depth=closure_depth,
                )
                key = (candidate_sha, fix_sha, source_path, candidate_method)
                row = neutral_rows_by_key.setdefault(
                    key,
                    {
                        "repository_identity": REPOSITORY_IDENTITY,
                        "candidate_sha": candidate_sha,
                        "fix_sha": fix_sha,
                        "path": source_path,
                        "candidate_method": candidate_method,
                        "closure_depth": closure_depth,
                        "guarded_callers": [],
                        "repair_added_lines": [],
                        "repair_guard_hunk_count": 0,
                        "candidate_subject": neutral_by_edge[(candidate_sha, fix_sha)].get(
                            "candidate_subject"
                        ),
                        "candidate_parents": candidate_parents,
                        "surviving_candidate_lines": surviving[:80],
                        "surviving_candidate_line_count": len(surviving),
                        "surviving_sink_lines": surviving_sinks[:40],
                        "surviving_sink_line_count": len(surviving_sinks),
                        "surviving_novel_sink_lines": surviving_novel_sinks[:40],
                        "surviving_novel_sink_line_count": len(
                            surviving_novel_sinks
                        ),
                        "surviving_security_lines": surviving_security[:40],
                        "surviving_security_line_count": len(surviving_security),
                        "priority_tier": priority_tier,
                        "priority_class": priority_class,
                        "retained_for_review": True,
                        **delta,
                    },
                )
                callers = row["guarded_callers"]
                assert isinstance(callers, list)
                if guarded_method not in callers:
                    callers.append(guarded_method)
                repair_lines = row["repair_added_lines"]
                assert isinstance(repair_lines, list)
                for line in control["added_lines"]:
                    if line not in repair_lines:
                        repair_lines.append(line)
                row["repair_guard_hunk_count"] = int(
                    row["repair_guard_hunk_count"]
                ) + int(control["hunk_count"])
                row["closure_depth"] = min(int(row["closure_depth"]), closure_depth)
                current_priority = int(row["priority_tier"])
                if priority_tier < current_priority:
                    row["priority_tier"] = priority_tier
                    row["priority_class"] = priority_class

    ordered_neutral = sorted(
        neutral_rows_by_key.values(),
        key=lambda row: (
            int(row["priority_tier"]),
            int(row["closure_depth"]),
            str(row["fix_sha"]),
            str(row["path"]),
            str(row["candidate_method"]),
            str(row["candidate_sha"]),
        ),
    )
    rows: list[dict[str, object]] = []
    for rank, row in enumerate(ordered_neutral, start=1):
        edge = (str(row["candidate_sha"]), str(row["fix_sha"]))
        post = post_by_edge[edge]
        rows.append(
            {
                **row,
                "label_neutral_rank": rank,
                "ledger_status": post.get("ledger_status"),
                "ledger_adjudication": post.get("ledger_adjudication"),
                "candidate_confirmed_anywhere": post.get(
                    "candidate_confirmed_anywhere"
                ),
            }
        )

    priority_counts = Counter(str(row["priority_class"]) for row in rows)
    status_counts = Counter(str(row["ledger_status"]) for row in rows)
    scheduled_edges = {
        (str(row["candidate_sha"]), str(row["fix_sha"])) for row in rows
    }
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_guard_to_helper_surviving_sink_schedule",
        "repository_identity": REPOSITORY_IDENTITY,
        "inputs": {
            "source_queue": str(args.source_queue.resolve()),
            "source_queue_sha256": _sha256(args.source_queue),
        },
        "summary": {
            "finite_source_edge_count": len(neutral_by_edge),
            "guard_hunk_count": guard_hunk_count,
            "guarded_method_count": len(controls),
            "scheduled_row_count": len(rows),
            "scheduled_edge_count": len(scheduled_edges),
            "scheduled_candidate_count": len(
                {str(row["candidate_sha"]) for row in rows}
            ),
            "one_hop_helper_row_count": sum(
                int(row["closure_depth"]) == 1 for row in rows
            ),
            "priority_class_counts": dict(sorted(priority_counts.items())),
            "post_join_status_counts": dict(sorted(status_counts.items())),
        },
        "rows": rows,
        "conservation": {
            "source_edge_count": len(neutral_by_edge),
            "source_edges_retained_upstream": all(
                row.get("retained_for_source_review") is True
                for row in neutral_by_edge.values()
            ),
            "schedule_is_additive": True,
            "schedule_has_deletion_authority": False,
            "model_negative_as_ground_truth_count": 0,
            "label_fields_used_for_ordering": False,
            "passed": True,
        },
        "claim_boundary": (
            "This additive lane follows guard-like repair hunks to their enclosing "
            "method and one same-file $this helper call, then requires an exact AI "
            "method delta with lines still blamed to that candidate at the repair "
            "parent. It is a label-neutral source-review schedule, not a causal label. "
            "Unscheduled source edges remain in the upstream lossless queue, and "
            "DEFER or BLOCKED model states never authorize deletion."
        ),
    }
    _atomic_json(args.output, payload)
    print("Coolify guard-to-helper surviving-sink schedule frozen")
    print(f"  source edges : {len(neutral_by_edge)}")
    print(f"  scheduled    : {len(scheduled_edges)} edges / {len(rows)} rows")
    print(f"  helper rows  : {payload['summary']['one_hop_helper_row_count']}")
    print(f"  output       : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
