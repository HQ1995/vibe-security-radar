#!/usr/bin/env python3
"""Build a lane-fair, recall-first origin queue under immutable fallbacks."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

from cohort.origin_signals import (
    OriginHunk,
    candidate_signal_row,
    history_search_tokens,
    history_token_regex_chunks,
    parse_origin_hunks,
    prioritize_candidate_rows,
)
from cohort.root_adjudication import canonical_sha256
from cohort.security_bridge import (
    cross_file_security_bridge,
    is_security_surface_path,
    patch_has_global_guard,
)
from cve_analyzer.git_ops import run_git


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HISTORY_RECORD_PREFIX = "@@AI_SLOP_COMMIT@@"
_CONTEXT_LINES = 3
_BLAME_SPAN_BATCH = 64
_BRIDGE_EVIDENCE_LIMIT = 4000


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "--fix-sha",
        help=(
            "select one source-qualified fix when the target has multiple "
            "high-confidence roots"
        ),
    )
    parser.add_argument("--score", type=Path, required=True)
    parser.add_argument("--universe-dir", type=Path, required=True)
    parser.add_argument("--queue-dir", type=Path, required=True)
    parser.add_argument("--repo-timeout", type=int, default=120)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _atomic_json(path: Path, value: object) -> None:
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


def _atomic_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _git_text(
    repo: Path,
    global_arguments: list[str],
    arguments: list[str],
    *,
    timeout: int,
) -> str:
    try:
        completed = run_git(
            ["git", "-C", str(repo), *global_arguments, *arguments],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            no_lazy_fetch=True,
        )
    except Exception as exc:  # noqa: BLE001 - caller converts gaps to BLOCKED
        raise SystemExit(
            f"git {arguments[0]} failed: {type(exc).__name__}"
        ) from exc
    if completed.returncode != 0:
        error = str(completed.stderr or "").strip().replace("\n", " ")
        suffix = f": {error[:300]}" if error else ""
        raise SystemExit(
            f"git {arguments[0]} returned {completed.returncode}{suffix}"
        )
    return str(completed.stdout or "")


def _optional_git_text(
    repo: Path,
    global_arguments: list[str],
    arguments: list[str],
    *,
    timeout: int,
    lane: str,
    coverage_gaps: list[dict[str, str]],
) -> str:
    try:
        return _git_text(
            repo,
            global_arguments,
            arguments,
            timeout=timeout,
        )
    except SystemExit as exc:
        coverage_gaps.append(
            {
                "lane": lane,
                "operation": arguments[0] if arguments else "git",
                "reason": str(exc),
            }
        )
        return ""


def _extract_shas(text: str) -> set[str]:
    return {
        line.strip().lower()
        for line in text.splitlines()
        if _FULL_SHA_RE.fullmatch(line.strip().lower())
    }


def _blame(
    repo: Path,
    global_arguments: list[str],
    revision: str,
    path: str,
    spans: list[tuple[int, int]],
    *,
    copy_aware: bool,
    timeout: int,
) -> set[str]:
    result: set[str] = set()
    # Git accepts multiple -L ranges but very large argument vectors are fragile.
    # Batch execution is exhaustive: unlike the old cap, every span is visited.
    for offset in range(0, len(spans), _BLAME_SPAN_BATCH):
        arguments = ["blame", "--line-porcelain", "-w"]
        if copy_aware:
            arguments.extend(["-M", "-C", "-C"])
        for start, end in spans[offset : offset + _BLAME_SPAN_BATCH]:
            arguments.extend(["-L", f"{start},{end}"])
        arguments.extend([revision, "--", path])
        output = _git_text(repo, global_arguments, arguments, timeout=timeout)
        for line in output.splitlines():
            fields = line.split(maxsplit=1)
            if fields and _FULL_SHA_RE.fullmatch(fields[0].lower()):
                result.add(fields[0].lower())
    return result


def _optional_blame(
    repo: Path,
    global_arguments: list[str],
    revision: str,
    path: str,
    spans: list[tuple[int, int]],
    *,
    copy_aware: bool,
    timeout: int,
    lane: str,
    coverage_gaps: list[dict[str, str]],
) -> set[str]:
    if not spans:
        return set()
    try:
        return _blame(
            repo,
            global_arguments,
            revision,
            path,
            spans,
            copy_aware=copy_aware,
            timeout=timeout,
        )
    except SystemExit as exc:
        coverage_gaps.append(
            {
                "lane": lane,
                "operation": "blame",
                "reason": str(exc),
            }
        )
        return set()


def _parse_commit_paths(text: str) -> dict[str, set[str]]:
    result: defaultdict[str, set[str]] = defaultdict(set)
    current = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(_HISTORY_RECORD_PREFIX):
            candidate = line.removeprefix(_HISTORY_RECORD_PREFIX).lower()
            current = candidate if _FULL_SHA_RE.fullmatch(candidate) else ""
        elif current and line:
            result[current].add(line)
    return dict(result)


def _deduplicate_gaps(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, str]] = []
    for row in rows:
        key = (row["lane"], row["operation"], row["reason"])
        if key not in seen:
            seen.add(key)
            result.append(row)
    return result


def _root_eligibility(
    score: Mapping[str, object],
    scored: Mapping[str, object],
    selected_candidate: Mapping[str, object] | None = None,
    *,
    explicit_public_control_root: bool = False,
) -> str:
    """Return the evidence gate that authorizes a target-level origin pilot."""
    if score.get("gate_status") == "CONTINUE":
        return "global_root_adjudication_gate"

    # A frozen public-exact source is an independent root observation.  The
    # model may rank another candidate first, but it must not veto this lane.
    if explicit_public_control_root:
        if selected_candidate is not None and selected_candidate.get("public_exact") is True:
            return "target_frozen_public_exact_reference"
        raise SystemExit("explicit public control root is not public-exact")

    selected = scored.get("selected_candidates")
    qualified = selected_candidate
    if qualified is None and isinstance(selected, list) and len(selected) == 1:
        raw_qualified = selected[0]
        qualified = raw_qualified if isinstance(raw_qualified, Mapping) else None
    decision = scored.get("decision")
    if (
        isinstance(decision, Mapping)
        and decision.get("decision") == "select"
        and decision.get("confidence") == "high"
        and isinstance(selected, list)
        and qualified is not None
        and any(
            isinstance(candidate, Mapping) and candidate == qualified
            for candidate in selected
        )
    ):
        return "target_model_selected_root_hypothesis"
    raise SystemExit("target root is not eligible for an origin pilot")


def _explicit_public_exact_priority_matches(
    rows: list[dict[str, object]],
    *,
    repository: str,
    fix_sha: str,
) -> list[dict[str, object]]:
    """Return frozen public-exact roots regardless of their ranking class."""
    return [
        row
        for row in rows
        if row.get("repository_identity") == repository
        and str(row.get("root_sha") or "").strip().lower() == fix_sha
        and row.get("retained") is True
        and row.get("root_coverage_status") == "RESOLVED"
        and "public_exact" in (row.get("evidence_kinds") or [])
    ]


def collect_origin_signals(
    repo: Path,
    global_arguments: list[str],
    fix_sha: str,
    commits: Mapping[str, Mapping[str, object]],
    *,
    timeout: int,
) -> dict[str, object]:
    """Collect additive signal lanes without giving any lane deletion authority."""

    parent_fields = _git_text(
        repo,
        global_arguments,
        ["rev-list", "--parents", "-n", "1", fix_sha],
        timeout=timeout,
    ).split()
    if not parent_fields or parent_fields[0].lower() != fix_sha:
        raise SystemExit("cannot resolve selected fix parents")
    parents = [sha.lower() for sha in parent_fields[1:] if _FULL_SHA_RE.fullmatch(sha.lower())]
    if not parents:
        raise SystemExit("selected fix is a root commit with no origin history")
    analysis_parent = parents[0]
    alternate_parent_delta_paths = {
        parent: sorted(
            {
                line.strip()
                for line in _git_text(
                    repo,
                    global_arguments,
                    ["diff", "--name-only", parent, fix_sha],
                    timeout=timeout,
                ).splitlines()
                if line.strip()
            }
        )
        for parent in parents[1:]
    }

    coverage_gaps: list[dict[str, str]] = []
    patches: dict[str, str] = {}
    parent_hunks: dict[str, list[OriginHunk]] = {}
    changed_paths: set[str] = set()
    deleted_range_file_count = 0
    add_only_hunk_count = 0
    guard_like_hunk_count = 0

    copy_aware: set[str] = set()
    file_local: set[str] = set()
    add_context: set[str] = set()
    function_history: set[str] = set()
    pickaxe_history: set[str] = set()
    file_history: set[str] = set()
    searched_tokens: set[tuple[str, str, str]] = set()
    pickaxe_query_count = 0
    parent_file_cache: dict[tuple[str, str], list[str] | None] = {}

    def parent_file_lines(parent: str, path: str) -> list[str] | None:
        key = (parent, path)
        if key not in parent_file_cache:
            before_gap_count = len(coverage_gaps)
            text = _optional_git_text(
                repo,
                global_arguments,
                ["show", f"{parent}:{path}"],
                timeout=min(timeout, 30),
                lane="add_context_blame",
                coverage_gaps=coverage_gaps,
            )
            parent_file_cache[key] = (
                None if len(coverage_gaps) > before_gap_count else text.splitlines()
            )
        return parent_file_cache[key]

    # For a merge, only the first-parent delta is newly landed on the target
    # branch.  Diffing against every parent imports unrelated target-branch
    # history from the other side of the merge.  Alternate parents remain in
    # the immutable repository fallback and are recorded below.
    for parent in (analysis_parent,):
        patch = _git_text(
            repo,
            global_arguments,
            [
                "diff",
                "--unified=0",
                "--no-color",
                "--find-renames",
                "--find-copies",
                parent,
                fix_sha,
            ],
            timeout=timeout,
        )
        patches[parent] = patch
        hunks = parse_origin_hunks(patch)
        parent_hunks[parent] = hunks
        parent_changed_paths = {
            line.strip()
            for line in _git_text(
                repo,
                global_arguments,
                ["diff", "--name-only", parent, fix_sha],
                timeout=timeout,
            ).splitlines()
            if line.strip()
        }
        changed_paths.update(parent_changed_paths)

        deleted_by_path: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
        context_by_path: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
        history_points: defaultdict[str, set[int]] = defaultdict(set)
        token_text: defaultdict[str, list[str]] = defaultdict(list)
        history_paths: set[str] = set(parent_changed_paths)
        for hunk in hunks:
            changed_paths.add(hunk.path)
            if hunk.parent_path is None:
                continue
            history_paths.add(hunk.parent_path)
            if hunk.deleted_span is not None:
                deleted_by_path[hunk.parent_path].append(hunk.deleted_span)
            if not hunk.needs_add_check_history:
                continue
            if hunk.old_count == 0:
                add_only_hunk_count += 1
            if hunk.is_guard_like:
                guard_like_hunk_count += 1
            lines = parent_file_lines(parent, hunk.parent_path)
            if lines is None or not lines:
                continue
            for raw_point in hunk.insertion_points:
                point = min(max(1, raw_point), len(lines))
                low = max(1, point - _CONTEXT_LINES)
                high = min(len(lines), point + _CONTEXT_LINES)
                context_by_path[hunk.parent_path].append((low, high))
                history_points[hunk.parent_path].add(point)
                token_text[hunk.parent_path].extend(lines[low - 1 : high])
            token_text[hunk.parent_path].extend(hunk.added_lines)

        deleted_range_file_count += len(deleted_by_path)
        for path, spans in deleted_by_path.items():
            copy_aware.update(
                _optional_blame(
                    repo,
                    global_arguments,
                    parent,
                    path,
                    spans,
                    copy_aware=True,
                    timeout=timeout,
                    lane="szz_copy_aware",
                    coverage_gaps=coverage_gaps,
                )
            )
            file_local.update(
                _optional_blame(
                    repo,
                    global_arguments,
                    parent,
                    path,
                    spans,
                    copy_aware=False,
                    timeout=timeout,
                    lane="szz_file_local",
                    coverage_gaps=coverage_gaps,
                )
            )

        for path, spans in context_by_path.items():
            add_context.update(
                _optional_blame(
                    repo,
                    global_arguments,
                    parent,
                    path,
                    spans,
                    copy_aware=True,
                    timeout=timeout,
                    lane="add_context_blame",
                    coverage_gaps=coverage_gaps,
                )
            )
            add_context.update(
                _optional_blame(
                    repo,
                    global_arguments,
                    parent,
                    path,
                    spans,
                    copy_aware=False,
                    timeout=timeout,
                    lane="add_context_blame",
                    coverage_gaps=coverage_gaps,
                )
            )

        for path, points in history_points.items():
            arguments = ["log", "--no-patch"]
            arguments.extend(
                f"-L{point},{point}:{path}" for point in sorted(points)
            )
            arguments.extend(["--format=%H", parent, "--"])
            output = _optional_git_text(
                repo,
                global_arguments,
                arguments,
                timeout=timeout,
                lane="enclosing_function_history",
                coverage_gaps=coverage_gaps,
            )
            function_history.update(_extract_shas(output))

        for path, text_lines in token_text.items():
            tokens = history_search_tokens("\n".join(text_lines))
            for token in tokens:
                searched_tokens.add((parent, path, token.casefold()))
            for pattern in history_token_regex_chunks(tokens):
                for arguments in (
                    [
                        "log",
                        "--format=%H",
                        "--pickaxe-regex",
                        f"-S{pattern}",
                        parent,
                        "--",
                        path,
                    ],
                    [
                        "log",
                        "--format=%H",
                        f"-G{pattern}",
                        parent,
                        "--",
                        path,
                    ],
                ):
                    pickaxe_query_count += 1
                    output = _optional_git_text(
                        repo,
                        global_arguments,
                        arguments,
                        timeout=min(timeout, 30),
                        lane="pickaxe_token_history",
                        coverage_gaps=coverage_gaps,
                    )
                    pickaxe_history.update(_extract_shas(output))

        for path in sorted(history_paths):
            output = _optional_git_text(
                repo,
                global_arguments,
                ["log", "--follow", "--format=%H", parent, "--", path],
                timeout=timeout,
                lane="affected_file_history",
                coverage_gaps=coverage_gaps,
            )
            file_history.update(_extract_shas(output))

    fix_has_global_guard = any(
        patch_has_global_guard(patch) for patch in patches.values()
    )
    ancestors: set[str] = set()
    commit_paths: defaultdict[str, set[str]] = defaultdict(set)
    for parent in parents:
        ancestors.update(
            _extract_shas(
                _git_text(
                    repo,
                    global_arguments,
                    ["rev-list", parent],
                    timeout=timeout,
                )
            )
        )
        if parent == analysis_parent and fix_has_global_guard:
            history_output = _optional_git_text(
                repo,
                global_arguments,
                [
                    "log",
                    f"--format={_HISTORY_RECORD_PREFIX}%H",
                    "--name-only",
                    "--diff-filter=ACMR",
                    parent,
                ],
                timeout=timeout,
                lane="cross_file_surface_history",
                coverage_gaps=coverage_gaps,
            )
            for sha, paths in _parse_commit_paths(history_output).items():
                commit_paths[sha].update(paths)

    if not ancestors:
        raise SystemExit("selected fix has no materialized ancestor fallback")

    cross_file_surface: set[str] = set()
    cross_file_bridge: set[str] = set()
    bridge_evidence: list[dict[str, object]] = []
    if fix_has_global_guard:
        cross_file_surface = {
            sha
            for sha, paths in commit_paths.items()
            if sha in ancestors and any(is_security_surface_path(path) for path in paths)
        }
        observed_ai_ancestors = {
            sha
            for sha in ancestors
            if commits.get(sha, {}).get("observed_ai_unit") is True
        }
        bridge_candidates = cross_file_surface | observed_ai_ancestors
        patch_cache: dict[tuple[str, str], str] = {}

        def path_patch(
            _repo: Path,
            sha: str,
            path: str,
            *,
            allow_lazy_fetch: bool = False,
        ) -> str:
            del allow_lazy_fetch
            key = (sha, path)
            if key not in patch_cache:
                patch_cache[key] = _optional_git_text(
                    repo,
                    global_arguments,
                    [
                        "show",
                        "--first-parent",
                        "--find-renames",
                        "--find-copies",
                        "--unified=5",
                        "--no-color",
                        "--format=",
                        sha,
                        "--",
                        path,
                    ],
                    timeout=min(timeout, 30),
                    lane="cross_file_security_bridge",
                    coverage_gaps=coverage_gaps,
                ).strip()
            return patch_cache[key]

        for candidate_sha in sorted(bridge_candidates):
            candidate_paths = sorted(commit_paths.get(candidate_sha, set()))
            if not candidate_paths:
                continue
            bridge = cross_file_security_bridge(
                repo,
                candidate_sha,
                fix_sha,
                candidate_paths,
                sorted(changed_paths),
                path_patch=path_patch,
                limit=_BRIDGE_EVIDENCE_LIMIT,
            )
            if bridge["applied"]:
                cross_file_bridge.add(candidate_sha)
                bridge_evidence.append(
                    {
                        "sha": candidate_sha,
                        "candidate_paths": bridge["candidate_paths"],
                        "fix_paths": bridge["fix_paths"],
                        "candidate_evidence": bridge["candidate_evidence"],
                        "fix_evidence": bridge["fix_evidence"],
                    }
                )

    signal_sets = {
        "copy_aware": copy_aware,
        "file_local": file_local,
        "add_context": add_context,
        "function_history": function_history,
        "pickaxe_history": pickaxe_history,
        "file_history": file_history,
        "cross_file_surface": cross_file_surface,
        "cross_file_bridge": cross_file_bridge,
    }
    for name, values in signal_sets.items():
        outside = values - ancestors
        if outside:
            raise SystemExit(
                f"origin signal containment failed for {name}: {sorted(outside)[:3]}"
            )

    return {
        "parents": parents,
        "analysis_parent": analysis_parent,
        "alternate_parent_delta_paths": alternate_parent_delta_paths,
        "changed_paths": sorted(changed_paths),
        "hunks": parent_hunks[analysis_parent],
        "deleted_range_file_count": deleted_range_file_count,
        "add_only_hunk_count": add_only_hunk_count,
        "guard_like_hunk_count": guard_like_hunk_count,
        "copy_aware": copy_aware,
        "file_local": file_local,
        "add_context": add_context,
        "function_history": function_history,
        "pickaxe_history": pickaxe_history,
        "file_history": file_history,
        "cross_file_surface": cross_file_surface,
        "cross_file_bridge": cross_file_bridge,
        "ancestors": ancestors,
        "fix_has_global_guard": fix_has_global_guard,
        "pickaxe_token_count": len(searched_tokens),
        "pickaxe_query_count": pickaxe_query_count,
        "bridge_evidence": bridge_evidence,
        "coverage_gaps": _deduplicate_gaps(coverage_gaps),
    }


def _priority_prefix_summary(
    rows: list[dict[str, object]],
    budgets: tuple[int, ...] = (10, 25, 50, 100),
) -> list[dict[str, int]]:
    result: list[dict[str, int]] = []
    for budget in budgets:
        prefix = rows[:budget]
        result.append(
            {
                "candidate_budget": budget,
                "materialized_count": len(prefix),
                "causal_signal_count": sum(
                    str(row.get("priority_class") or "").endswith("CAUSAL_SIGNAL")
                    for row in prefix
                ),
                "observed_ai_unit_count": sum(
                    row.get("observed_ai_unit") is True for row in prefix
                ),
            }
        )
    return result


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.repo_timeout < 1:
        raise SystemExit("repo-timeout must be positive")
    score = _load_json(args.score)
    if not isinstance(score, dict):
        raise SystemExit("root score is malformed")
    score_rows = score.get("rows")
    if not isinstance(score_rows, list):
        raise SystemExit("root score rows are malformed")
    matches = [
        row
        for row in score_rows
        if isinstance(row, dict) and row.get("repository_identity") == args.repository
    ]
    if len(matches) != 1:
        raise SystemExit("repository must identify exactly one scored pair")
    scored = matches[0]
    decision = scored.get("decision")
    selected = scored.get("selected_candidates")
    if not isinstance(selected, list) or any(
        not isinstance(candidate, dict) for candidate in selected
    ):
        raise SystemExit("root score selected candidates are malformed")
    high_confidence_selection = (
        isinstance(decision, dict)
        and decision.get("decision") == "select"
        and decision.get("confidence") == "high"
        and bool(selected)
    )
    root_priorities = _load_jsonl(args.queue_dir / "root_priorities.jsonl")
    explicit_public_control_root = False
    if args.fix_sha:
        requested_fix = args.fix_sha.strip().lower()
        if not _FULL_SHA_RE.fullmatch(requested_fix):
            raise SystemExit("--fix-sha must be a full 40-hex SHA")
        selected_matches = [
            candidate
            for candidate in selected
            if str(candidate.get("sha") or "").strip().lower() == requested_fix
        ]
        exact_matches = _explicit_public_exact_priority_matches(
            root_priorities,
            repository=args.repository,
            fix_sha=requested_fix,
        )
        if len(selected_matches) > 1 or len(exact_matches) > 1:
            raise SystemExit("--fix-sha resolves ambiguously")
        if selected_matches:
            selected_candidate = selected_matches[0]
            explicit_public_control_root = bool(exact_matches)
        elif exact_matches:
            exact = exact_matches[0]
            selected_candidate = {
                "sha": requested_fix,
                "public_exact": True,
                "evidence_kinds": exact.get("evidence_kinds", []),
                "root_coverage_status": exact.get("root_coverage_status"),
                "selection_basis": "explicit_public_control_root",
            }
            explicit_public_control_root = True
        else:
            raise SystemExit(
                "--fix-sha must name a selected root or frozen public-exact root"
            )
    elif high_confidence_selection and len(selected) == 1:
        selected_candidate = selected[0]
    elif not high_confidence_selection:
        raise SystemExit("origin pilot requires a high-confidence selected root or --fix-sha")
    else:
        raise SystemExit("multiple selected roots require --fix-sha")
    root_eligibility = _root_eligibility(
        score,
        scored,
        selected_candidate,
        explicit_public_control_root=explicit_public_control_root,
    )
    fix_sha = str(selected_candidate.get("sha") or "").lower()
    if not _FULL_SHA_RE.fullmatch(fix_sha):
        raise SystemExit("selected root SHA is malformed")

    universe_summary = _load_json(args.universe_dir / "summary.json")
    if not isinstance(universe_summary, dict):
        raise SystemExit("universe summary is malformed")
    provenance = universe_summary.get("repository_provenance")
    if not isinstance(provenance, list):
        raise SystemExit("universe repository provenance is malformed")
    repo_rows = [
        row
        for row in provenance
        if isinstance(row, dict) and row.get("repository_identity") == args.repository
    ]
    if len(repo_rows) != 1:
        raise SystemExit("repository provenance is unavailable")
    repo = Path(str(repo_rows[0].get("repository_path") or ""))
    global_arguments = (
        ["--shallow-file", ""]
        if repo_rows[0].get("history_view")
        == "complete_local_object_graph_ignoring_shallow_marker"
        else []
    )
    if not repo.is_dir():
        raise SystemExit("repository path is unavailable")

    priority_matches = [
        row
        for row in root_priorities
        if row.get("repository_identity") == args.repository
        and row.get("root_sha") == fix_sha
        and (
            row.get("priority_class") == "R0_MODEL_OR_EXPLICIT_CONTROL"
            or "public_exact" in (row.get("evidence_kinds") or [])
        )
    ]
    if len(priority_matches) != 1:
        raise SystemExit("selected fix root is not in the frozen priority overlay")

    commits: dict[str, dict[str, object]] = {}
    repository_commit_count = 0
    with (args.universe_dir / "commit_universe.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("repository_identity") != args.repository:
                continue
            repository_commit_count += 1
            commits[str(row["sha"]).lower()] = row
    if fix_sha not in commits:
        raise SystemExit("selected fix root is absent from commit universe")

    collected = collect_origin_signals(
        repo,
        global_arguments,
        fix_sha,
        commits,
        timeout=args.repo_timeout,
    )
    signal_names = (
        "copy_aware",
        "file_local",
        "add_context",
        "function_history",
        "pickaxe_history",
        "file_history",
        "cross_file_surface",
        "cross_file_bridge",
        "ancestors",
    )
    signal_sets: dict[str, set[str]] = {}
    for name in signal_names:
        value = collected[name]
        if not isinstance(value, set):
            raise SystemExit(f"internal origin signal {name} is malformed")
        signal_sets[name] = value
    copy_aware = signal_sets["copy_aware"]
    file_local = signal_sets["file_local"]
    add_context = signal_sets["add_context"]
    function_history = signal_sets["function_history"]
    pickaxe_history = signal_sets["pickaxe_history"]
    file_history = signal_sets["file_history"]
    cross_file_surface = signal_sets["cross_file_surface"]
    cross_file_bridge_candidates = signal_sets["cross_file_bridge"]
    ancestors = signal_sets["ancestors"]
    szz_union = copy_aware | file_local
    add_check_union = add_context | function_history | pickaxe_history
    direct_signal_union = (
        szz_union
        | add_check_union
        | cross_file_surface
        | cross_file_bridge_candidates
    )
    materialized = file_history | direct_signal_union

    candidate_rows: list[dict[str, object]] = []
    for sha in sorted(materialized):
        universe_row = commits.get(sha)
        if universe_row is None:
            raise SystemExit("origin signal candidate is outside commit universe")
        row = candidate_signal_row(
            sha=sha,
            in_copy_aware_szz=sha in copy_aware,
            in_file_local_szz=sha in file_local,
            in_file_history=sha in file_history,
            observed_ai_unit=universe_row.get("observed_ai_unit") is True,
            in_add_context_blame=sha in add_context,
            in_function_history=sha in function_history,
            in_pickaxe_history=sha in pickaxe_history,
            in_cross_file_security_bridge=sha in cross_file_bridge_candidates,
            in_cross_file_surface_history=sha in cross_file_surface,
        )
        coverage_gaps = collected["coverage_gaps"]
        if not isinstance(coverage_gaps, list):
            raise SystemExit("internal coverage gap list is malformed")
        metadata = _optional_git_text(
            repo,
            global_arguments,
            ["show", "--no-patch", "--format=%aI%x00%s", sha],
            timeout=args.repo_timeout,
            lane="candidate_metadata",
            coverage_gaps=coverage_gaps,
        ).rstrip("\n").split("\x00", 1)
        row.update(
            {
                "authored_date": metadata[0] if metadata else "",
                "subject": metadata[1] if len(metadata) == 2 else "",
                "ai_routes": universe_row.get("ai_routes", []),
                "ai_tools": universe_row.get("ai_tools", []),
            }
        )
        candidate_rows.append(row)
    candidate_rows = prioritize_candidate_rows(candidate_rows)

    signal_counts = Counter(
        signal for row in candidate_rows for signal in row["signals"]
    )
    priority_counts = Counter(str(row["priority_class"]) for row in candidate_rows)
    coverage_gaps = _deduplicate_gaps(coverage_gaps)
    bridge_evidence = collected["bridge_evidence"]
    if not isinstance(bridge_evidence, list):
        raise SystemExit("internal bridge evidence is malformed")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_jsonl(args.output_dir / "candidates.jsonl", candidate_rows)
    _atomic_jsonl(args.output_dir / "cross_file_bridge.jsonl", bridge_evidence)
    summary = {
        "schema_version": 2,
        "artifact_kind": "recall_first_origin_signal_pilot",
        "gate_status": (
            "READY_FOR_RECALL_EVALUATION" if not coverage_gaps else "BLOCKED"
        ),
        "repository_identity": args.repository,
        "advisory": scored["advisory"],
        "fix_sha": fix_sha,
        "fix_root_role": (
            (
                "source_exact_semantically_corroborated_fix_candidate"
                if scored.get("public_control_closure_hit") is True
                else "source_exact_reference_unvalidated_candidate"
            )
            if explicit_public_control_root
            else "model_selected_fix_candidate_not_ground_truth"
        ),
        "fix_root_is_causal_ground_truth": False,
        "root_eligibility": root_eligibility,
        "parent_shas": collected["parents"],
        "analysis_parent_sha": collected["analysis_parent"],
        "alternate_parent_shas": collected["parents"][1:],
        "alternate_parent_delta_paths": collected["alternate_parent_delta_paths"],
        "alternate_parent_deltas_retained_by_repository_fallback": True,
        "changed_paths": collected["changed_paths"],
        "deleted_range_file_count": collected["deleted_range_file_count"],
        "add_only_hunk_count": collected["add_only_hunk_count"],
        "guard_like_hunk_count": collected["guard_like_hunk_count"],
        "szz_copy_aware_candidate_count": len(copy_aware),
        "szz_file_local_candidate_count": len(file_local),
        "szz_union_candidate_count": len(szz_union),
        "add_context_candidate_count": len(add_context),
        "function_history_candidate_count": len(function_history),
        "pickaxe_history_candidate_count": len(pickaxe_history),
        "add_check_union_candidate_count": len(add_check_union),
        "pickaxe_token_count": collected["pickaxe_token_count"],
        "pickaxe_query_count": collected["pickaxe_query_count"],
        "fix_has_global_guard": collected["fix_has_global_guard"],
        "cross_file_surface_history_candidate_count": len(cross_file_surface),
        "cross_file_security_bridge_candidate_count": len(
            cross_file_bridge_candidates
        ),
        "affected_file_history_candidate_count": len(file_history),
        "materialized_signal_union_candidate_count": len(materialized),
        "direct_signal_union_candidate_count": len(direct_signal_union),
        "file_history_only_candidate_count": len(
            file_history - direct_signal_union
        ),
        "szz_only_candidate_count": len(szz_union - file_history),
        "ancestor_fallback_candidate_count": len(ancestors),
        "repository_fallback_candidate_count": repository_commit_count,
        "observed_ai_file_history_candidate_count": sum(
            row["observed_ai_unit"] is True
            and "affected_file_history" in row["signals"]
            for row in candidate_rows
        ),
        "observed_ai_materialized_candidate_count": sum(
            row["observed_ai_unit"] is True for row in candidate_rows
        ),
        "signal_counts": dict(sorted(signal_counts.items())),
        "priority_counts": dict(sorted(priority_counts.items())),
        "priority_prefixes": _priority_prefix_summary(candidate_rows),
        "ranking_contract": {
            "direct_lanes_are_coequal": True,
            "within_class_scheduler": "deterministic_round_robin_by_signal_lane",
            "observed_ai_is_priority_only": True,
            "ranking_never_deletes_candidates": True,
        },
        "coverage_status": "COMPLETE" if not coverage_gaps else "BLOCKED",
        "coverage_gaps": coverage_gaps,
        "all_file_history_candidates_retained": True,
        "ancestor_fallback_retained_by_reference": True,
        "repository_fallback_retained_by_reference": True,
        "hard_filter_count": 0,
        "claim_boundary": (
            "SZZ, insertion context, function history, pickaxe, and cross-file "
            "bridges are additive ranking evidence, not ground truth. Prefix "
            "coverage is not recall until a separately sealed origin ledger is "
            "joined during evaluation. Ancestor and repository fallbacks remain "
            "available and no model decision can delete them."
        ),
        "candidate_rows_sha256": canonical_sha256(candidate_rows),
        "cross_file_bridge_rows_sha256": canonical_sha256(bridge_evidence),
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print("recall-first origin signal pilot frozen")
    print(f"  SZZ union              : {len(szz_union)}")
    print(f"  add-check union        : {len(add_check_union)}")
    print(f"  cross-file bridge      : {len(cross_file_bridge_candidates)}")
    print(f"  cross-file broad lane  : {len(cross_file_surface)}")
    print(f"  affected-file history  : {len(file_history)}")
    print(f"  materialized union     : {len(materialized)}")
    print(f"  file-history only      : {len(file_history - direct_signal_union)}")
    print(f"  ancestor fallback      : {len(ancestors):,}")
    print(f"  repository fallback    : {repository_commit_count:,}")
    print(f"  observed AI materialized: {summary['observed_ai_materialized_candidate_count']}")
    print(f"  coverage               : {summary['coverage_status']}")
    print("  hard filters           : 0")
    print(f"  output                 : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
