#!/usr/bin/env python3
"""Build a finite AI file-surface schedule behind non-method Coolify guards."""

from __future__ import annotations

import argparse
import hashlib
import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

from cohort.origin_signals import parse_origin_hunks
from cohort_coolify_guard_method_history_schedule import (
    REPOSITORY_IDENTITY,
    _added_lines,
    _git,
    _load_json,
    _load_jsonl,
    _method_at_line,
    _removed_lines,
    _revision_parents,
    _sha256,
    _subject,
)
from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
)


_CARRIER_SUBJECT_RE = re.compile(
    r"(?:\bmerge\b|\bsetup\b.*\bskeleton\b|\bcore skeleton\b)", re.IGNORECASE
)
_EXPLICIT_REPAIR_CONTROL_RE = re.compile(
    r"(?:"
    r"#\[Locked\]"
    r"|AuthorizesRequests"
    r"|isInstanceAdmin\s*\("
    r"|->middleware\s*\("
    r"|middleware\s*=>"
    r"|\$hidden\s*="
    r"|['\"]encrypted(?::[^'\"]+)?['\"]"
    r"|Policy::class"
    r")",
    re.IGNORECASE,
)
_CANDIDATE_EXPOSURE_RE = re.compile(
    r"(?:"
    r"\bpublic\s+(?:readonly\s+)?(?:[?\\A-Za-z_][\\A-Za-z0-9_|?]*\s+)?\$"
    r"|Route::(?:get|post|put|patch|delete|any|match)\s*\("
    r"|\$casts\s*="
    r"|\$hidden\s*="
    r"|\$fillable\s*="
    r"|\$guarded\s*="
    r"|middleware\s*\("
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


def _file_delta(
    *, parent_sources: list[str | None], candidate_source: str
) -> dict[str, object] | None:
    existing_parents = [source for source in parent_sources if source is not None]
    if existing_parents and any(source == candidate_source for source in existing_parents):
        return None
    baseline = existing_parents[0] if existing_parents else ""
    additions = _added_lines(baseline, candidate_source)
    removals = _removed_lines(baseline, candidate_source)
    if not additions and not removals:
        return None
    exposure_lines = [line for line in additions if _CANDIDATE_EXPOSURE_RE.search(line)]
    return {
        "delta_kind": (
            "MODIFY_EXISTING_RUNTIME_FILE"
            if existing_parents
            else "ADD_RUNTIME_FILE"
        ),
        "candidate_file_sha256": hashlib.sha256(
            candidate_source.encode("utf-8")
        ).hexdigest(),
        "candidate_added_lines": additions[:120],
        "candidate_added_line_count": len(additions),
        "candidate_removed_lines": removals[:120],
        "candidate_removed_line_count": len(removals),
        "candidate_exposure_lines": exposure_lines[:60],
        "candidate_exposure_line_count": len(exposure_lines),
    }


def _priority(
    *,
    delta_kind: str,
    repair_lines: list[str],
    exposure_count: int,
    carrier_risk: bool,
    confirmed_anywhere: bool,
) -> tuple[int, str]:
    if confirmed_anywhere:
        return 5, "P5_ALREADY_CONFIRMED_CANDIDATE_COVERAGE"
    explicit_control = any(
        _EXPLICIT_REPAIR_CONTROL_RE.search(line) for line in repair_lines
    )
    if explicit_control and exposure_count:
        return 0, "P0_EXPOSURE_DELTA_BEFORE_EXPLICIT_SURFACE_CONTROL"
    if explicit_control:
        return 1, "P1_EXPLICIT_SURFACE_CONTROL_FILE_HISTORY"
    if carrier_risk:
        return 4, "P4_LARGE_OR_MERGE_CARRIER_REVIEW"
    if delta_kind == "ADD_RUNTIME_FILE":
        return 2, "P2_NEW_RUNTIME_FILE_SURFACE"
    if exposure_count:
        return 2, "P2_RUNTIME_EXPOSURE_SURFACE_DELTA"
    return 3, "P3_OTHER_GUARD_SURFACE_FILE_DELTA"


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
    surface_controls: defaultdict[
        tuple[str, str], dict[str, object]
    ] = defaultdict(lambda: {"hunk_count": 0, "added_lines": [], "anchors": []})
    fix_count = 0
    guard_hunk_count = 0
    method_guard_hunk_count = 0
    new_file_guard_hunk_count = 0
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
            source_path = hunk.parent_path or hunk.path
            if (
                not source_path.endswith(".php")
                or source_path.startswith(("test/", "tests/", "vendor/"))
                or not hunk.is_guard_like
            ):
                continue
            guard_hunk_count += 1
            if hunk.parent_path is None:
                new_file_guard_hunk_count += 1
            parent_source = blob(parent_sha, source_path)
            method = (
                _method_at_line(parent_source, hunk.old_start)
                if parent_source is not None
                else None
            )
            if method is not None:
                method_guard_hunk_count += 1
                continue
            control = surface_controls[(fix_sha, source_path)]
            control["hunk_count"] = int(control["hunk_count"]) + 1
            added = control["added_lines"]
            anchors = control["anchors"]
            assert isinstance(added, list)
            assert isinstance(anchors, list)
            added.extend(line.strip() for line in hunk.added_lines if line.strip())
            anchors.append(
                {
                    "old_start": hunk.old_start,
                    "old_count": hunk.old_count,
                    "new_start": hunk.new_start,
                    "new_count": hunk.new_count,
                }
            )

    rows_by_key: dict[tuple[str, str, str], dict[str, object]] = {}
    for (fix_sha, source_path), control in sorted(surface_controls.items()):
        repair_added_lines = list(dict.fromkeys(control["added_lines"]))
        for edge in edges_by_fix[fix_sha]:
            candidate_sha = str(edge["candidate_sha"])
            metadata = ai_by_sha.get(candidate_sha)
            if metadata is None or source_path not in metadata.get("changed_files", []):
                continue
            candidate_source = blob(candidate_sha, source_path)
            if candidate_source is None:
                continue
            revision_line = _git(
                repository, ["rev-list", "--parents", "-n", "1", candidate_sha]
            )
            assert revision_line is not None
            parents = _revision_parents(revision_line.strip(), candidate_sha)
            parent_sources = [blob(parent, source_path) for parent in parents]
            delta = _file_delta(
                parent_sources=parent_sources, candidate_source=candidate_source
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
                repair_lines=repair_added_lines,
                exposure_count=int(delta["candidate_exposure_line_count"]),
                carrier_risk=carrier_risk,
                confirmed_anywhere=candidate_sha in confirmed_candidates,
            )
            row = {
                "repository_identity": REPOSITORY_IDENTITY,
                "candidate_sha": candidate_sha,
                "fix_sha": fix_sha,
                "path": source_path,
                "surface_kind": "NON_METHOD_FILE_SURFACE",
                "candidate_subject": subject,
                "fix_subject": fix_subjects[fix_sha],
                "candidate_authored_date": metadata.get("authored_date"),
                "candidate_merge_topology": metadata.get("merge_topology"),
                "candidate_parents": parents,
                "candidate_changed_file_count": changed_file_count,
                "candidate_explicit_ai_signal": True,
                "candidate_confirmed_anywhere": (
                    candidate_sha in confirmed_candidates
                ),
                "input_edge_status": edge.get("status"),
                "input_edge_adjudication": edge.get("adjudication"),
                "repair_guard_hunk_count": int(control["hunk_count"]),
                "repair_hunk_anchors": list(control["anchors"])[:60],
                "repair_added_lines": repair_added_lines[:120],
                "repair_added_line_count": len(repair_added_lines),
                "repair_has_explicit_surface_control": any(
                    _EXPLICIT_REPAIR_CONTROL_RE.search(line)
                    for line in repair_added_lines
                ),
                "whole_file_addition": whole_file_addition,
                "carrier_risk": carrier_risk,
                "priority_tier": priority_tier,
                "priority_class": priority_class,
                "retained_for_review": True,
                **delta,
            }
            rows_by_key[(candidate_sha, fix_sha, source_path)] = row

    rows = sorted(
        rows_by_key.values(),
        key=lambda row: (
            int(row["priority_tier"]),
            str(row["fix_sha"]),
            str(row["path"]),
            str(row["candidate_sha"]),
        ),
    )
    priority_counts = Counter(str(row["priority_class"]) for row in rows)
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_guard_surface_history_review_schedule",
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
            "method_guard_hunk_count": method_guard_hunk_count,
            "non_method_guard_hunk_count": (
                guard_hunk_count - method_guard_hunk_count
            ),
            "new_file_guard_hunk_count": new_file_guard_hunk_count,
            "guard_surface_count": len(surface_controls),
            "scheduled_surface_edge_count": len(rows),
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
            "This artifact complements the method-history schedule with guard-like "
            "fix hunks outside an enclosing PHP method, including class properties, "
            "attributes, imports, routes, middleware, model serialization surfaces, "
            "and global helpers. Same-file history is only a review hypothesis; an "
            "independent source witness is still required for a causal label. The "
            "schedule is additive and cannot delete or downgrade ledger edges."
        ),
        "rows": rows,
    }
    _atomic_json(args.output, payload)
    print("Coolify guard file-surface history schedule frozen")
    print(f"  fixes            : {fix_count}")
    print(f"  non-method hunks : {payload['summary']['non_method_guard_hunk_count']}")
    print(f"  surfaces         : {len(surface_controls)}")
    print(f"  scheduled        : {len(rows)}")
    print(f"  new candidates   : {payload['summary']['scheduled_unconfirmed_candidate_count']}")
    print(f"  output           : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
