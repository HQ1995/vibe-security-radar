#!/usr/bin/env python3
"""Build a finite AI method-history schedule behind Coolify guard fixes."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

from cohort.origin_signals import parse_origin_hunks
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
)


REPOSITORY_IDENTITY = "github.com/coollabsio/coolify"
_METHOD_RE = re.compile(
    r"^\s*(?:public|protected|private)(?:\s+static)?\s+function\s+(\w+)\s*\("
)
_SINK_RE = re.compile(
    r"(?:"
    r"->(?:save|update|delete|create|attach|detach)\s*\("
    r"|::(?:create|update|destroy)\s*\("
    r"|(?:instant_)?remote_process\s*\("
    r"|(?:dispatch|dispatchSync)\s*\("
    r"|queue_\w+\s*\("
    r")",
    re.IGNORECASE,
)
_STATE_ASSIGNMENT_RE = re.compile(
    r"\$this->(?:[A-Za-z_]\w*->)+([A-Za-z_]\w*)\s*="
)
_CARRIER_SUBJECT_RE = re.compile(
    r"(?:\bmerge\b|\bsetup\b.*\bskeleton\b|\bcore skeleton\b)", re.IGNORECASE
)
_REMOVED_CONTROL_RE = re.compile(
    r"(?:"
    r"authorize\s*\("
    r"|(?:->|\b)can\s*\("
    r"|\bis(?:Instance)?Admin\s*\("
    r"|\bisMember\s*\("
    r"|ownedByCurrentTeam"
    r"|abort(?:_if|_unless)?\s*\("
    r"|isDownForMaintenance\s*\("
    r"|middleware\s*\("
    r"|throttle"
    r"|rate.?limit"
    r"|validate\s*\("
    r"|\bthrow\b"
    r")",
    re.IGNORECASE,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(source: Path) -> dict[str, object]:
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object: {source}")
    return value


def _load_jsonl(source: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(
        source.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise SystemExit(f"expected object at {source}:{line_number}")
        rows.append(value)
    return rows


def _sha256(source: Path) -> str:
    return hashlib.sha256(source.read_bytes()).hexdigest()


def _git(repository: Path, arguments: list[str], *, optional: bool = False) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    if completed.returncode == 0:
        return completed.stdout
    if optional:
        return None
    raise SystemExit(
        f"git {' '.join(arguments)} failed: {completed.stderr.strip()[:300]}"
    )


def _method_ranges(source: str) -> list[tuple[int, int, str]]:
    lines = source.splitlines()
    starts = [
        (line_number, match.group(1))
        for line_number, line in enumerate(lines, start=1)
        if (match := _METHOD_RE.search(line)) is not None
    ]
    return [
        (
            start,
            starts[index + 1][0] - 1 if index + 1 < len(starts) else len(lines),
            method,
        )
        for index, (start, method) in enumerate(starts)
    ]


def _method_at_line(source: str, line_number: int) -> str | None:
    point = max(1, line_number)
    for start, end, method in _method_ranges(source):
        if start <= point <= end:
            return method
    return None


def _method_or_none(source: str | None, method: str) -> str | None:
    if source is None:
        return None
    lines = source.splitlines()
    for start, end, candidate_method in _method_ranges(source):
        if candidate_method == method:
            return "\n".join(lines[start - 1 : end])
    return None


def _added_lines(before: str, after: str) -> list[str]:
    return [
        line[1:].strip()
        for line in difflib.unified_diff(
            before.splitlines(), after.splitlines(), n=0
        )
        if line.startswith("+") and not line.startswith("+++") and line[1:].strip()
    ]


def _removed_lines(before: str, after: str) -> list[str]:
    return [
        line[1:].strip()
        for line in difflib.unified_diff(
            before.splitlines(), after.splitlines(), n=0
        )
        if line.startswith("-") and not line.startswith("---") and line[1:].strip()
    ]


def _sink_fingerprint(line: str) -> str | None:
    assignment = _STATE_ASSIGNMENT_RE.search(line)
    if assignment is not None:
        return f"state_assignment:{assignment.group(1)}"
    static = re.search(
        r"([A-Za-z_\\][A-Za-z0-9_\\]*)::"
        r"(create|update|destroy|dispatch|dispatchSync)\s*\(",
        line,
    )
    if static is not None:
        # A refactor may replace a fully-qualified PHP class with an imported
        # short name without changing the call site.  Scheduling that alias
        # rewrite as a newly introduced sensitive sink wastes the P1 lane.
        class_name = static.group(1).rsplit("\\", 1)[-1]
        return f"static:{class_name}::{static.group(2)}"
    method = re.search(
        r"->(save|update|delete|create|attach|detach)\s*\(", line
    )
    if method is not None:
        return f"method:{method.group(1)}"
    function = re.search(
        r"\b((?:instant_)?remote_process|queue_[A-Za-z_]\w*)\s*\(", line
    )
    if function is not None:
        return f"function:{function.group(1)}"
    return None


def _novel_sink_lines(added: list[str], removed: list[str]) -> list[str]:
    removed_counts = Counter(
        fingerprint
        for line in removed
        if (fingerprint := _sink_fingerprint(line)) is not None
    )
    result: list[str] = []
    for line in added:
        fingerprint = _sink_fingerprint(line)
        if fingerprint is None:
            continue
        if removed_counts[fingerprint] > 0:
            removed_counts[fingerprint] -= 1
            continue
        result.append(line)
    return result


def _removed_control_lines(removed: list[str]) -> tuple[list[str], bool]:
    """Keep broad, source-derived guard removals for a recall-first lane."""
    direct = [line for line in removed if _REMOVED_CONTROL_RE.search(line)]
    removed_conditionals = [
        line for line in removed if re.match(r"^(?:}\s*)?(?:else\s+)?if\s*\(", line)
    ]
    removed_returns = [
        line for line in removed if re.match(r"^return(?:\s+[^;]+)?;", line)
    ]
    reachability_gate = bool(removed_conditionals and removed_returns)
    result = list(dict.fromkeys(direct))
    if reachability_gate:
        result.extend(
            line
            for line in (*removed_conditionals, *removed_returns)
            if line not in result
        )
    return result, reachability_gate


def _method_delta(
    *,
    parent_sources: list[str | None],
    candidate_source: str,
    method: str,
) -> dict[str, object] | None:
    candidate_method = _method_or_none(candidate_source, method)
    if candidate_method is None:
        return None
    parent_methods = [
        value
        for source in parent_sources
        if (value := _method_or_none(source, method)) is not None
    ]
    if parent_methods and any(value == candidate_method for value in parent_methods):
        return None

    file_existed_in_parent = any(source is not None for source in parent_sources)
    if parent_methods:
        delta_kind = "MODIFY_EXISTING_METHOD"
        baseline_method = parent_methods[0]
    elif file_existed_in_parent:
        delta_kind = "ADD_METHOD_TO_EXISTING_FILE"
        baseline_method = ""
    else:
        delta_kind = "ADD_METHOD_WITH_FILE"
        baseline_method = ""
    additions = _added_lines(baseline_method, candidate_method)
    removals = _removed_lines(baseline_method, candidate_method)
    sink_lines = [
        line
        for line in additions
        if _SINK_RE.search(line) or _STATE_ASSIGNMENT_RE.search(line)
    ]
    removed_sink_lines = [
        line
        for line in removals
        if _SINK_RE.search(line) or _STATE_ASSIGNMENT_RE.search(line)
    ]
    novel_sink_lines = _novel_sink_lines(additions, removals)
    removed_control_lines, removed_reachability_gate = _removed_control_lines(
        removals
    )
    return {
        "delta_kind": delta_kind,
        "candidate_method_sha256": hashlib.sha256(
            candidate_method.encode("utf-8")
        ).hexdigest(),
        "candidate_added_lines": additions[:80],
        "candidate_added_line_count": len(additions),
        "candidate_removed_lines": removals[:80],
        "candidate_removed_line_count": len(removals),
        "candidate_added_sink_lines": sink_lines[:40],
        "candidate_added_sink_line_count": len(sink_lines),
        "candidate_removed_sink_lines": removed_sink_lines[:40],
        "candidate_removed_sink_line_count": len(removed_sink_lines),
        "candidate_novel_sink_lines": novel_sink_lines[:40],
        "candidate_novel_sink_line_count": len(novel_sink_lines),
        "candidate_removed_control_lines": removed_control_lines[:40],
        "candidate_removed_control_line_count": len(removed_control_lines),
        "candidate_removed_reachability_gate": removed_reachability_gate,
    }


def _revision_parents(revision_line: str, expected_sha: str) -> list[str]:
    fields = revision_line.split()
    if not fields or fields[0] != expected_sha:
        raise ValueError(f"unexpected revision line for {expected_sha}: {revision_line!r}")
    return fields[1:]


def _priority(
    *,
    delta_kind: str,
    sink_count: int,
    removed_control_count: int,
    carrier_risk: bool,
    confirmed_anywhere: bool,
) -> tuple[int, str]:
    if removed_control_count:
        return 0, "P0_REMOVED_CONTROL_OR_REACHABILITY_GATE"
    if delta_kind == "ADD_METHOD_TO_EXISTING_FILE":
        return 0, "P0_NEW_METHOD_IN_EXISTING_RUNTIME_FILE"
    if delta_kind == "MODIFY_EXISTING_METHOD" and sink_count:
        return 1, "P1_EXISTING_METHOD_NEW_SINK_DELTA"
    if delta_kind == "ADD_METHOD_WITH_FILE":
        return 2, "P2_NEW_RUNTIME_FILE_METHOD"
    if carrier_risk:
        return 4, "P4_WHOLE_FILE_OR_LARGE_CARRIER_REVIEW"
    if confirmed_anywhere:
        return 5, "P5_ALREADY_CONFIRMED_CANDIDATE_COVERAGE"
    return 3, "P3_EXISTING_METHOD_OTHER_DELTA"


def _subject(metadata: Mapping[str, object]) -> str:
    return str(metadata.get("message") or "").splitlines()[0]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    ledger_payload = _load_json(args.ledger)
    ledger_rows = ledger_payload.get("edge_ledger")
    if not isinstance(ledger_rows, list):
        raise SystemExit("ledger has no edge_ledger array")
    if ledger_payload.get("repository_identity") != REPOSITORY_IDENTITY:
        raise SystemExit("ledger repository identity mismatch")
    if not all(
        isinstance(row, Mapping) and row.get("candidate_retained") is True
        for row in ledger_rows
    ):
        raise SystemExit("input ledger is not lossless")

    ai_rows = _load_jsonl(args.ai_scan)
    ai_by_sha = {str(row.get("sha") or ""): row for row in ai_rows}
    confirmed_candidates = {
        str(row["candidate_sha"])
        for row in ledger_rows
        if isinstance(row, Mapping) and row.get("status") == "CONFIRMED_TRUE_POSITIVE"
    }
    edges_by_fix: defaultdict[str, list[Mapping[str, object]]] = defaultdict(list)
    for raw_row in ledger_rows:
        if not isinstance(raw_row, Mapping):
            raise SystemExit("ledger row is not an object")
        edges_by_fix[str(raw_row["fix_sha"])].append(raw_row)

    blob_cache: dict[tuple[str, str], str | None] = {}

    def blob(revision: str, source_path: str) -> str | None:
        key = (revision, source_path)
        if key not in blob_cache:
            blob_cache[key] = _git(
                repository, ["show", f"{revision}:{source_path}"], optional=True
            )
        return blob_cache[key]

    fix_subjects: dict[str, str] = {}
    method_controls: defaultdict[
        tuple[str, str, str], dict[str, object]
    ] = defaultdict(lambda: {"hunk_count": 0, "added_lines": []})
    fix_count = 0
    guard_hunk_count = 0
    guard_hunks_without_method = 0
    for fix_sha in sorted(edges_by_fix):
        revision_line = _git(
            repository, ["rev-list", "--parents", "-n", "1", fix_sha]
        )
        assert revision_line is not None
        fields = revision_line.split()
        if len(fields) < 2:
            continue
        fix_count += 1
        parent_sha = fields[1]
        fix_subject = _git(repository, ["show", "-s", "--format=%s", fix_sha])
        fix_subjects[fix_sha] = str(fix_subject or "").strip()
        patch = _git(
            repository,
            [
                "diff",
                "--unified=0",
                "--no-color",
                "--find-renames",
                parent_sha,
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
            guard_hunk_count += 1
            parent_source = blob(parent_sha, source_path)
            method = (
                _method_at_line(parent_source, hunk.old_start)
                if parent_source is not None
                else None
            )
            if method is None:
                guard_hunks_without_method += 1
                continue
            control = method_controls[(fix_sha, source_path, method)]
            control["hunk_count"] = int(control["hunk_count"]) + 1
            added = control["added_lines"]
            assert isinstance(added, list)
            added.extend(line.strip() for line in hunk.added_lines if line.strip())

    rows_by_key: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for (fix_sha, source_path, method), control in sorted(method_controls.items()):
        for edge in edges_by_fix[fix_sha]:
            candidate_sha = str(edge["candidate_sha"])
            metadata = ai_by_sha.get(candidate_sha)
            if metadata is None or source_path not in metadata.get("changed_files", []):
                continue
            candidate_source = blob(candidate_sha, source_path)
            if candidate_source is None:
                continue
            candidate_revision_line = _git(
                repository,
                ["rev-list", "--parents", "-n", "1", candidate_sha],
            )
            assert candidate_revision_line is not None
            parents = _revision_parents(
                candidate_revision_line.strip(), candidate_sha
            )
            parent_sources = [blob(parent, source_path) for parent in parents]
            delta = _method_delta(
                parent_sources=parent_sources,
                candidate_source=candidate_source,
                method=method,
            )
            if delta is None:
                continue
            changed_file_count = len(metadata.get("changed_files", []))
            whole_file_addition = not any(source is not None for source in parent_sources)
            subject = _subject(metadata)
            carrier_risk = bool(
                (whole_file_addition and changed_file_count >= 25)
                or _CARRIER_SUBJECT_RE.search(subject)
            )
            priority_tier, priority_class = _priority(
                delta_kind=str(delta["delta_kind"]),
                sink_count=int(delta["candidate_novel_sink_line_count"]),
                removed_control_count=int(
                    delta["candidate_removed_control_line_count"]
                ),
                carrier_risk=carrier_risk,
                confirmed_anywhere=candidate_sha in confirmed_candidates,
            )
            repair_added_lines = list(dict.fromkeys(control["added_lines"]))
            row = {
                "repository_identity": REPOSITORY_IDENTITY,
                "candidate_sha": candidate_sha,
                "fix_sha": fix_sha,
                "path": source_path,
                "method": method,
                "candidate_subject": subject,
                "fix_subject": fix_subjects[fix_sha],
                "candidate_authored_date": metadata.get("authored_date"),
                "candidate_merge_topology": metadata.get("merge_topology"),
                "candidate_parents": parents,
                "candidate_changed_file_count": changed_file_count,
                "candidate_explicit_ai_signal": True,
                "candidate_confirmed_anywhere": candidate_sha in confirmed_candidates,
                "input_edge_status": edge.get("status"),
                "input_edge_adjudication": edge.get("adjudication"),
                "repair_guard_hunk_count": int(control["hunk_count"]),
                "repair_added_lines": repair_added_lines[:80],
                "repair_added_line_count": len(repair_added_lines),
                "whole_file_addition": whole_file_addition,
                "carrier_risk": carrier_risk,
                "priority_tier": priority_tier,
                "priority_class": priority_class,
                "retained_for_review": True,
                **delta,
            }
            rows_by_key[(candidate_sha, fix_sha, source_path, method)] = row

    rows = sorted(
        rows_by_key.values(),
        key=lambda row: (
            int(row["priority_tier"]),
            str(row["fix_sha"]),
            str(row["path"]),
            str(row["method"]),
            str(row["candidate_sha"]),
        ),
    )
    priority_counts = Counter(str(row["priority_class"]) for row in rows)
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_guard_method_history_review_schedule",
        "repository_identity": REPOSITORY_IDENTITY,
        "inputs": {
            "ledger": str(args.ledger.resolve()),
            "ledger_sha256": _sha256(args.ledger),
            "ai_scan": str(args.ai_scan.resolve()),
            "ai_scan_sha256": _sha256(args.ai_scan),
        },
        "summary": {
            "fix_count": fix_count,
            "parent_finite_edge_count": len(ledger_rows),
            "guard_hunk_count": guard_hunk_count,
            "guard_hunks_without_enclosing_method": guard_hunks_without_method,
            "guard_method_count": len(method_controls),
            "scheduled_method_edge_count": len(rows),
            "scheduled_unique_candidate_count": len(
                {str(row["candidate_sha"]) for row in rows}
            ),
            "scheduled_unconfirmed_candidate_count": len(
                {
                    str(row["candidate_sha"])
                    for row in rows
                    if row["candidate_confirmed_anywhere"] is False
                }
            ),
            "priority_class_counts": dict(sorted(priority_counts.items())),
        },
        "conservation": {
            "schedule_is_additive": True,
            "schedule_has_deletion_authority": False,
            "negative_model_verdict_can_delete": False,
            "all_scheduled_rows_retained": all(
                row["retained_for_review"] is True for row in rows
            ),
        },
        "claim_boundary": (
            "This artifact is a recall-oriented review schedule, not a causal "
            "label set. It intersects guard-like fix hunks with exact earlier AI "
            "deltas in the same enclosing PHP method. Same-method history, whole-file "
            "carriers, added sinks, and removed control or early-return blocks remain "
            "hypotheses until an independent source "
            "witness proves the candidate-to-fix mechanism. No parent ledger edge is "
            "removed or downgraded."
        ),
        "rows": rows,
    }
    _atomic_json(args.output, payload)
    print("Coolify guard method-history schedule frozen")
    print(f"  fixes       : {fix_count}")
    print(f"  guard methods: {len(method_controls)}")
    print(f"  scheduled   : {len(rows)}")
    print(
        "  new candidates: "
        f"{payload['summary']['scheduled_unconfirmed_candidate_count']}"
    )
    print(f"  output      : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
