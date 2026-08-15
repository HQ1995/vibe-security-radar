#!/usr/bin/env python3
"""Rank every Coolify causal edge by deterministic fix-preimage lineage.

This is a scheduling artifact, not a causal classifier.  It keeps every input
edge and adds direct-line, enclosing-method, nearby-context, and coverage-gap
signals derived from ``fix^``.  In particular, add-only security checks can be
scheduled through method ownership without requiring an SZZ deletion.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cohort.origin_signals import OriginHunk, parse_origin_hunks


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BLAME_HEADER_RE = re.compile(r"^\^?([0-9a-f]{40}) (\d+) (\d+)(?: (\d+))?$")
_METHOD_PATTERNS = (
    re.compile(
        r"^\s*(?:(?:public|protected|private|static|final|abstract|readonly)\s+)*"
        r"function\s+([A-Za-z_$][\w$]*)\s*\("
    ),
    re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\("),
    re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*\("),
    re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),
    re.compile(
        r"^\s*(?:(?:export|default|declare)\s+)*(?:async\s+)?"
        r"function\s+([A-Za-z_$][\w$]*)\s*\("
    ),
    re.compile(
        r"^\s*(?:(?:export|declare)\s+)*(?:const|let|var)\s+"
        r"([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
    ),
)
_STATUS_TIE_BREAK = {
    "MODEL_PROMOTED_REVIEW_REQUIRED": 0,
    "TRANSPORT_OR_PARSE_RETRY_REQUIRED": 1,
    "DEFERRED_REVIEW_BACKLOG": 2,
}
_ADJUDICATED_STATUSES = frozenset(
    {
        "CONFIRMED_TRUE_POSITIVE",
        "PATCH_EQUIVALENT_ALIAS",
        "REJECTED_NONCAUSAL",
    }
)


class LineageEvidenceError(RuntimeError):
    """A Git evidence operation could not be completed."""


@dataclass(frozen=True)
class BlameLine:
    sha: str
    line: int
    content: str


@dataclass(frozen=True)
class HunkContext:
    index: int
    hunk: OriginHunk
    direct_lines: tuple[int, ...]
    method_signature_lines: tuple[int, ...]
    nearby_lines: tuple[int, ...]


@dataclass(frozen=True)
class FixEvidence:
    fix_sha: str
    parent_sha: str
    hunks: tuple[HunkContext, ...]
    local_blame: Mapping[str, Mapping[int, BlameLine]]
    copy_blame: Mapping[str, Mapping[int, BlameLine]]
    coverage_gaps: tuple[Mapping[str, str], ...]
    skipped_parent_entries: tuple[Mapping[str, str], ...] = ()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--context-radius", type=int, default=12)
    parser.add_argument("--repo-timeout", type=int, default=120)
    parser.add_argument(
        "--copy-aware",
        action="store_true",
        help=(
            "also run expensive -M -C -C blame; file-local ownership remains the "
            "default because upstream origin generation already preserves copy-aware SZZ"
        ),
    )
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object in {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _git_text(repository: Path, arguments: Sequence[str], *, timeout: int) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LineageEvidenceError(f"git {arguments[0]} failed: {exc}") from exc
    if completed.returncode != 0:
        stderr = completed.stderr.strip().replace("\n", " ")
        raise LineageEvidenceError(
            f"git {arguments[0]} exited {completed.returncode}: {stderr[:500]}"
        )
    return completed.stdout


def _method_signature_lines(lines: Sequence[str], points: Iterable[int]) -> tuple[int, ...]:
    """Return the nearest enclosing declaration for each parent-coordinate point.

    Coolify is predominantly PHP.  The additional patterns keep the artifact
    useful for mixed-language files, while deliberately avoiding a claim that
    this lightweight parser is a complete language frontend.
    """

    declarations: list[int] = []
    for line_number, content in enumerate(lines, start=1):
        if any(pattern.search(content) for pattern in _METHOD_PATTERNS):
            declarations.append(line_number)
    if not declarations:
        return ()

    result: set[int] = set()
    for point in points:
        prior = [line for line in declarations if line <= point]
        if not prior:
            continue
        signature = prior[-1]
        next_declaration = next(
            (line for line in declarations if line > signature), len(lines) + 1
        )
        if point < next_declaration:
            result.add(signature)
    return tuple(sorted(result))


def _parse_blame(text: str) -> dict[int, BlameLine]:
    result: dict[int, BlameLine] = {}
    current_sha = ""
    current_line = 0
    for line in text.splitlines():
        header = _BLAME_HEADER_RE.fullmatch(line)
        if header:
            current_sha = header.group(1)
            current_line = int(header.group(3))
            continue
        if current_sha and line.startswith("\t"):
            result[current_line] = BlameLine(
                sha=current_sha,
                line=current_line,
                content=line[1:],
            )
            current_sha = ""
            current_line = 0
    return result


def _blame_file(
    repository: Path,
    revision: str,
    source_path: str,
    line_numbers: Iterable[int],
    *,
    copy_aware: bool,
    ignore_whitespace: bool = True,
    blame_since: str | None = None,
    timeout: int,
) -> dict[int, BlameLine]:
    arguments = ["blame", "--line-porcelain"]
    if ignore_whitespace:
        arguments.append("-w")
    if blame_since is not None:
        arguments.append(f"--since={blame_since}")
    if copy_aware:
        arguments.extend(["-M", "-C", "-C"])
    ordered = sorted(set(line_numbers))
    if not ordered:
        return {}
    ranges: list[tuple[int, int]] = []
    start = previous = ordered[0]
    for line_number in ordered[1:]:
        if line_number == previous + 1:
            previous = line_number
            continue
        ranges.append((start, previous))
        start = previous = line_number
    ranges.append((start, previous))
    for start, end in ranges:
        arguments.extend(["-L", f"{start},{end}"])
    arguments.extend([revision, "--", source_path])
    return _parse_blame(_git_text(repository, arguments, timeout=timeout))


def _parent_tree_entry(
    repository: Path,
    revision: str,
    source_path: str,
    *,
    timeout: int,
) -> tuple[str, str, str] | None:
    """Return ``(mode, type, object)`` for an exact parent-tree path.

    ``git diff`` can emit hunks for gitlinks.  Their tree entry has type
    ``commit`` and must not be passed to blob readers or ``git blame``.  The
    NUL-delimited form also avoids confusing quoted or unusual path names.
    """

    output = _git_text(
        repository,
        ["ls-tree", "-z", revision, "--", source_path],
        timeout=timeout,
    )
    for record in output.split("\0"):
        if not record:
            continue
        metadata, separator, entry_path = record.partition("\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise LineageEvidenceError(
                f"git ls-tree returned malformed entry for {source_path}"
            )
        if entry_path == source_path:
            mode, object_type, object_sha = fields
            return mode, object_type, object_sha
    return None


def _hunk_context(
    index: int,
    hunk: OriginHunk,
    lines: Sequence[str],
    *,
    context_radius: int,
) -> HunkContext:
    if not lines or hunk.parent_path is None:
        return HunkContext(index, hunk, (), (), ())
    if hunk.old_count > 0:
        direct_start = min(max(1, hunk.old_start), len(lines))
        direct_end = min(len(lines), hunk.old_start + hunk.old_count - 1)
        direct_lines = tuple(range(direct_start, direct_end + 1))
        anchor_points = direct_lines
    else:
        anchor = min(max(1, hunk.old_start), len(lines))
        direct_lines = ()
        anchor_points = (anchor,)
    low = max(1, min(anchor_points) - context_radius)
    high = min(len(lines), max(anchor_points) + context_radius)
    signatures = _method_signature_lines(lines, anchor_points)
    excluded = set(direct_lines) | set(signatures)
    nearby = tuple(line for line in range(low, high + 1) if line not in excluded)
    return HunkContext(index, hunk, direct_lines, signatures, nearby)


def _fix_evidence(
    repository: Path,
    fix_sha: str,
    *,
    context_radius: int,
    copy_aware_enabled: bool,
    ignore_whitespace: bool = True,
    blame_since: str | None = None,
    timeout: int,
) -> FixEvidence:
    parent_sha = _git_text(
        repository, ["rev-parse", f"{fix_sha}^1"], timeout=timeout
    ).strip()
    if not _FULL_SHA_RE.fullmatch(parent_sha):
        raise LineageEvidenceError(f"malformed parent for {fix_sha}: {parent_sha}")
    patch = _git_text(
        repository,
        [
            "diff",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            "--find-renames",
            "--find-copies",
            parent_sha,
            fix_sha,
            "--",
        ],
        timeout=timeout,
    )
    hunks = parse_origin_hunks(patch)
    parent_paths = sorted(
        {hunk.parent_path for hunk in hunks if hunk.parent_path is not None}
    )
    file_lines: dict[str, list[str]] = {}
    coverage_gaps: list[dict[str, str]] = []
    skipped_parent_entries: list[dict[str, str]] = []
    for source_path in parent_paths:
        try:
            tree_entry = _parent_tree_entry(
                repository,
                parent_sha,
                source_path,
                timeout=timeout,
            )
        except LineageEvidenceError as exc:
            coverage_gaps.append(
                {
                    "path": source_path,
                    "operation": "parent_tree_entry",
                    "reason": str(exc),
                }
            )
            continue
        if tree_entry is None:
            skipped_parent_entries.append(
                {
                    "path": source_path,
                    "reason": "parent_path_absent",
                }
            )
            continue
        mode, object_type, object_sha = tree_entry
        if object_type != "blob":
            skipped_parent_entries.append(
                {
                    "path": source_path,
                    "reason": "non_blob_parent_entry",
                    "mode": mode,
                    "object_type": object_type,
                    "object_sha": object_sha,
                }
            )
            continue
        try:
            file_lines[source_path] = _git_text(
                repository,
                ["show", f"{parent_sha}:{source_path}"],
                timeout=timeout,
            ).splitlines()
        except LineageEvidenceError as exc:
            coverage_gaps.append(
                {"path": source_path, "operation": "parent_blob", "reason": str(exc)}
            )
            continue

    contexts = tuple(
        _hunk_context(
            index,
            hunk,
            file_lines.get(hunk.parent_path or "", []),
            context_radius=context_radius,
        )
        for index, hunk in enumerate(hunks)
    )
    relevant_lines: defaultdict[str, set[int]] = defaultdict(set)
    for context in contexts:
        source_path = context.hunk.parent_path
        if source_path is None:
            continue
        relevant_lines[source_path].update(context.direct_lines)
        relevant_lines[source_path].update(context.method_signature_lines)
        relevant_lines[source_path].update(context.nearby_lines)

    local_blame: dict[str, Mapping[int, BlameLine]] = {}
    copy_blame: dict[str, Mapping[int, BlameLine]] = {}
    for source_path in parent_paths:
        if source_path not in file_lines:
            continue
        modes = [(False, local_blame, "file_local_blame")]
        if copy_aware_enabled:
            modes.append((True, copy_blame, "copy_aware_blame"))
        for copy_aware, destination, operation in modes:
            try:
                destination[source_path] = _blame_file(
                    repository,
                    parent_sha,
                    source_path,
                    relevant_lines[source_path],
                    copy_aware=copy_aware,
                    ignore_whitespace=ignore_whitespace,
                    blame_since=blame_since,
                    timeout=timeout,
                )
            except LineageEvidenceError as exc:
                coverage_gaps.append(
                    {"path": source_path, "operation": operation, "reason": str(exc)}
                )

    return FixEvidence(
        fix_sha=fix_sha,
        parent_sha=parent_sha,
        hunks=contexts,
        local_blame=local_blame,
        copy_blame=copy_blame,
        coverage_gaps=tuple(coverage_gaps),
        skipped_parent_entries=tuple(skipped_parent_entries),
    )


def _excerpt(content: str, *, limit: int = 180) -> str:
    normalized = " ".join(content.strip().split())
    return normalized if len(normalized) <= limit else normalized[: limit - 1] + "…"


def _path_kind(source_path: str) -> str:
    normalized = source_path.casefold().lstrip("./")
    segments = normalized.split("/")
    if segments[0] in {"test", "tests", "spec", "specs"} or any(
        segment in {"__tests__", "fixtures", "snapshots"} for segment in segments
    ):
        return "test"
    if segments[0] in {"doc", "docs"} or normalized.endswith(
        (".md", ".mdx", ".rst", ".txt")
    ):
        return "documentation"
    if segments[0] in {"vendor", "node_modules"}:
        return "dependency"
    return "runtime"


def _matching_rows(
    candidate_sha: str,
    evidence: FixEvidence,
) -> tuple[list[dict[str, object]], Counter[str]]:
    rows: list[dict[str, object]] = []
    counts: Counter[str] = Counter()
    seen: set[tuple[int, str, int, str]] = set()
    for context in evidence.hunks:
        source_path = context.hunk.parent_path
        if source_path is None:
            continue
        for line_kind, line_numbers in (
            ("direct_preimage", context.direct_lines),
            ("method_signature", context.method_signature_lines),
            ("nearby_context", context.nearby_lines),
        ):
            for blame_mode, blame_by_path in (
                ("file_local", evidence.local_blame),
                ("copy_aware", evidence.copy_blame),
            ):
                blame = blame_by_path.get(source_path, {})
                for line_number in line_numbers:
                    blamed = blame.get(line_number)
                    if blamed is None or blamed.sha != candidate_sha:
                        continue
                    key = (context.index, line_kind, line_number, blame_mode)
                    if key in seen:
                        continue
                    seen.add(key)
                    count_key = f"{line_kind}_{blame_mode}"
                    counts[count_key] += 1
                    rows.append(
                        {
                            "hunk_index": context.index,
                            "path": source_path,
                            "path_kind": _path_kind(source_path),
                            "line": line_number,
                            "line_kind": line_kind,
                            "blame_mode": blame_mode,
                            "guard_like_hunk": context.hunk.is_guard_like,
                            "add_only_hunk": context.hunk.old_count == 0,
                            "content_sha256": hashlib.sha256(
                                blamed.content.encode("utf-8")
                            ).hexdigest(),
                            "content_excerpt": _excerpt(blamed.content),
                        }
                    )
    rows.sort(
        key=lambda row: (
            int(row["hunk_index"]),
            str(row["line_kind"]),
            int(row["line"]),
            str(row["blame_mode"]),
        )
    )
    return rows, counts


def _priority(
    *,
    evidence_rows: Sequence[Mapping[str, object]],
    coverage_incomplete: bool,
) -> tuple[int, str]:
    runtime_rows = [row for row in evidence_rows if row["path_kind"] == "runtime"]
    direct = sum(row["line_kind"] == "direct_preimage" for row in runtime_rows)
    method = sum(row["line_kind"] == "method_signature" for row in runtime_rows)
    nearby = sum(row["line_kind"] == "nearby_context" for row in runtime_rows)
    guard_method = any(
        row["line_kind"] == "method_signature" and row["guard_like_hunk"] is True
        for row in runtime_rows
    )
    guard_nearby = any(
        row["line_kind"] == "nearby_context" and row["guard_like_hunk"] is True
        for row in runtime_rows
    )
    if direct:
        return 0, "P0_DIRECT_FIX_PREIMAGE_OWNER"
    if guard_method:
        return 1, "P1_ADD_CHECK_ENCLOSING_METHOD_OWNER"
    if guard_nearby:
        return 2, "P2_ADD_CHECK_NEARBY_CONTEXT_OWNER"
    if method:
        return 3, "P3_ENCLOSING_METHOD_OWNER"
    if coverage_incomplete:
        return 4, "P4_ATTRIBUTION_INCOMPLETE_FAIL_OPEN_RETRY"
    if nearby:
        return 5, "P5_NEARBY_CONTEXT_OWNER"
    if evidence_rows:
        return 6, "P6_NON_RUNTIME_LINEAGE_ONLY"
    return 7, "P7_COMPOSITIONAL_REVIEW_NO_DIRECT_LINEAGE"


def _edge_row(
    source: Mapping[str, object],
    evidence: FixEvidence,
) -> dict[str, object]:
    candidate_sha = str(source.get("candidate_sha", ""))
    fix_sha = str(source.get("fix_sha", ""))
    if not _FULL_SHA_RE.fullmatch(candidate_sha) or fix_sha != evidence.fix_sha:
        raise SystemExit("ledger contains malformed or mismatched edge")
    if source.get("candidate_retained") is not True:
        raise SystemExit(f"input ledger dropped candidate {candidate_sha}..{fix_sha}")
    matched, counts = _matching_rows(candidate_sha, evidence)
    tier, priority_class = _priority(
        evidence_rows=matched,
        coverage_incomplete=bool(evidence.coverage_gaps),
    )
    signals = sorted(
        key for key, value in counts.items() if value > 0
    )
    return {
        "repository_identity": source.get("repository_identity"),
        "candidate_sha": candidate_sha,
        "fix_sha": fix_sha,
        "input_status": source.get("status"),
        "input_adjudication": source.get("adjudication"),
        "candidate_retained": True,
        "lineage_signals": signals,
        "lineage_signal_counts": dict(sorted(counts.items())),
        "matched_line_evidence": matched,
        "fix_attribution_complete": not evidence.coverage_gaps,
        "priority_tier": tier,
        "priority_class": priority_class,
        "model_promoted_tie_break": (
            source.get("status") == "MODEL_PROMOTED_REVIEW_REQUIRED"
        ),
        "within_fix_signal_rank": None,
        "review_priority_rank": None,
    }


def _rank_review_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_fix: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if row["input_status"] in _ADJUDICATED_STATUSES:
            continue
        by_fix[str(row["fix_sha"])].append(row)
    for fix_rows in by_fix.values():
        fix_rows.sort(
            key=lambda row: (
                int(row["priority_tier"]),
                _STATUS_TIE_BREAK.get(str(row["input_status"]), 9),
                -sum(int(value) for value in row["lineage_signal_counts"].values()),
                str(row["candidate_sha"]),
            )
        )
        for rank, row in enumerate(fix_rows, start=1):
            row["within_fix_signal_rank"] = rank

    schedule = sorted(
        (row for fix_rows in by_fix.values() for row in fix_rows),
        key=lambda row: (
            int(row["priority_tier"]),
            int(row["within_fix_signal_rank"]),
            str(row["fix_sha"]),
            str(row["candidate_sha"]),
        ),
    )
    for rank, row in enumerate(schedule, start=1):
        row["review_priority_rank"] = rank
    return schedule


def _fix_summary(evidence: FixEvidence) -> dict[str, object]:
    paths = sorted(
        {
            context.hunk.parent_path
            for context in evidence.hunks
            if context.hunk.parent_path is not None
        }
    )
    return {
        "fix_sha": evidence.fix_sha,
        "parent_sha": evidence.parent_sha,
        "hunk_count": len(evidence.hunks),
        "add_only_hunk_count": sum(
            context.hunk.old_count == 0 for context in evidence.hunks
        ),
        "guard_like_hunk_count": sum(
            context.hunk.is_guard_like for context in evidence.hunks
        ),
        "parent_path_count": len(paths),
        "parent_paths": paths,
        "coverage_gaps": list(evidence.coverage_gaps),
        "skipped_parent_entries": list(evidence.skipped_parent_entries),
        "attribution_complete": not evidence.coverage_gaps,
    }


def _build_payload(
    *,
    ledger_path: Path,
    input_payload: Mapping[str, object],
    rows: list[dict[str, object]],
    schedule: Sequence[Mapping[str, object]],
    evidence_by_fix: Mapping[str, FixEvidence],
    context_radius: int,
    copy_aware_enabled: bool,
) -> dict[str, object]:
    priority_counts = Counter(str(row["priority_class"]) for row in rows)
    review_priority_counts = Counter(
        str(row["priority_class"])
        for row in rows
        if row["input_status"] not in _ADJUDICATED_STATUSES
    )
    input_edge_count = int(
        Mapping.get(input_payload.get("summary", {}), "finite_edge_count", -1)  # type: ignore[arg-type]
    )
    output_keys = {
        (str(row["candidate_sha"]), str(row["fix_sha"])) for row in rows
    }
    input_rows = input_payload.get("edge_ledger", [])
    if not isinstance(input_rows, list):
        raise SystemExit("input ledger edge_ledger must be a list")
    input_keys = {
        (str(row.get("candidate_sha")), str(row.get("fix_sha")))
        for row in input_rows
        if isinstance(row, Mapping)
    }
    conservation_passed = bool(
        len(rows) == input_edge_count == len(output_keys) == len(input_keys)
        and output_keys == input_keys
        and all(row["candidate_retained"] is True for row in rows)
    )
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_lossless_fix_preimage_lineage_schedule",
        "repository_identity": input_payload.get("repository_identity"),
        "input": {
            "ledger_path": str(ledger_path),
            "ledger_sha256": _sha256(ledger_path),
            "ledger_artifact_kind": input_payload.get("artifact_kind"),
            "finite_edge_count": input_edge_count,
        },
        "configuration": {
            "context_radius": context_radius,
            "blame_modes": (
                ["file_local", "copy_aware"]
                if copy_aware_enabled
                else ["file_local"]
            ),
            "copy_aware_deep_audit_enabled": copy_aware_enabled,
            "copy_aware_recall_floor": (
                "preserved_by_upstream_candidate_inventory"
                if not copy_aware_enabled
                else "recomputed_in_this_artifact"
            ),
            "add_only_fix_handling": "enclosing_method_and_nearby_context_blame",
            "ranking_is_not_adjudication": True,
        },
        "summary": {
            "finite_edge_count": len(rows),
            "review_edge_count": len(schedule),
            "fix_count": len(evidence_by_fix),
            "priority_class_counts": dict(sorted(priority_counts.items())),
            "review_priority_class_counts": dict(
                sorted(review_priority_counts.items())
            ),
            "edges_with_direct_preimage_owner": sum(
                row["priority_tier"] == 0 for row in rows
            ),
            "edges_with_add_check_method_owner": sum(
                row["priority_tier"] == 1 for row in rows
            ),
            "edges_with_add_check_nearby_owner": sum(
                row["priority_tier"] == 2 for row in rows
            ),
            "fixes_with_coverage_gaps": sum(
                bool(evidence.coverage_gaps) for evidence in evidence_by_fix.values()
            ),
        },
        "fix_evidence": [
            _fix_summary(evidence_by_fix[fix_sha])
            for fix_sha in sorted(evidence_by_fix)
        ],
        "edge_lineage": sorted(
            rows, key=lambda row: (str(row["fix_sha"]), str(row["candidate_sha"]))
        ),
        "review_schedule": [
            {
                "review_priority_rank": row["review_priority_rank"],
                "within_fix_signal_rank": row["within_fix_signal_rank"],
                "priority_class": row["priority_class"],
                "candidate_sha": row["candidate_sha"],
                "fix_sha": row["fix_sha"],
                "input_status": row["input_status"],
            }
            for row in schedule
        ],
        "conservation": {
            "input_edge_count": input_edge_count,
            "output_edge_count": len(rows),
            "unique_input_edge_count": len(input_keys),
            "unique_output_edge_count": len(output_keys),
            "hard_delete_count": len(input_keys - output_keys),
            "invented_edge_count": len(output_keys - input_keys),
            "candidate_retained_count": sum(
                row["candidate_retained"] is True for row in rows
            ),
            "passed": conservation_passed,
        },
        "claim_boundary": (
            "Lineage signals are deterministic scheduling evidence, not causal ground "
            "truth. Direct preimage ownership can still be incidental; lack of direct "
            "lineage does not reject an edge because path extensions, preserved sinks, "
            "cross-file wiring, and squash members can be compositional. Every input "
            "edge is retained, add-only guards are explicitly scheduled through "
            "enclosing-method and nearby-context ownership, and test or documentation "
            "lineage cannot receive a production-code P0/P1 rank."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.context_radius < 1:
        raise SystemExit("--context-radius must be positive")
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    ledger_path = args.ledger.resolve()
    input_payload = _load_json(ledger_path)
    input_rows = input_payload.get("edge_ledger")
    if not isinstance(input_rows, list) or not input_rows:
        raise SystemExit("input ledger has no edge_ledger rows")

    fix_shas = sorted(
        {str(row.get("fix_sha", "")) for row in input_rows if isinstance(row, Mapping)}
    )
    if any(not _FULL_SHA_RE.fullmatch(fix_sha) for fix_sha in fix_shas):
        raise SystemExit("input ledger contains malformed fix SHA")
    evidence_by_fix = {
        fix_sha: _fix_evidence(
            repository,
            fix_sha,
            context_radius=args.context_radius,
            copy_aware_enabled=args.copy_aware,
            timeout=args.repo_timeout,
        )
        for fix_sha in fix_shas
    }
    rows = [
        _edge_row(row, evidence_by_fix[str(row["fix_sha"])])
        for row in input_rows
        if isinstance(row, Mapping)
    ]
    if len(rows) != len(input_rows):
        raise SystemExit("input ledger contains non-object edge rows")
    schedule = _rank_review_rows(rows)
    payload = _build_payload(
        ledger_path=ledger_path,
        input_payload=input_payload,
        rows=rows,
        schedule=schedule,
        evidence_by_fix=evidence_by_fix,
        context_radius=args.context_radius,
        copy_aware_enabled=args.copy_aware,
    )
    if payload["conservation"]["passed"] is not True:
        raise SystemExit("fix-preimage lineage conservation failed")
    _atomic_json(args.output, payload)
    summary = payload["summary"]
    print("Coolify fix-preimage lineage schedule frozen")
    print(f"  finite edges       : {summary['finite_edge_count']}")
    print(f"  direct owners      : {summary['edges_with_direct_preimage_owner']}")
    print(f"  add-check methods  : {summary['edges_with_add_check_method_owner']}")
    print(f"  add-check context  : {summary['edges_with_add_check_nearby_owner']}")
    print(f"  coverage-gap fixes : {summary['fixes_with_coverage_gaps']}")
    print(f"  output             : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
