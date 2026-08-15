#!/usr/bin/env python3
"""Intersect fix-hunk blame with atomic AI candidates, preserving squash gaps."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from cohort.origin_signals import parse_origin_hunks
from cohort.root_adjudication import canonical_sha256
from cohort_coolify_fix_preimage_lineage import _method_signature_lines
from cve_analyzer.git_ops import run_git


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_CONTEXT = 3
_SPAN_BATCH = 64


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--same-file-candidates", type=Path, required=True)
    parser.add_argument("--input-fix-blame", type=Path)
    parser.add_argument("--repository-path", type=Path, required=True)
    parser.add_argument("--repo-timeout", type=int, default=30)
    parser.add_argument("--allow-lazy-fetch", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _jsonl(path: Path) -> Iterable[dict[str, object]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_number} is not an object")
            yield row


def _git(
    repo: Path,
    arguments: list[str],
    *,
    timeout: int,
    allow_lazy_fetch: bool,
) -> str:
    try:
        completed = run_git(
            ["git", "-C", str(repo), *arguments],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            no_lazy_fetch=not allow_lazy_fetch,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"git {arguments[0]} failed: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        reason = str(completed.stderr or "").strip().replace("\n", " ")[:300]
        raise ValueError(f"git {arguments[0]} failed: {reason}")
    return str(completed.stdout or "")


def _blame(
    repo: Path,
    revision: str,
    path: str,
    spans: list[tuple[int, int]],
    *,
    timeout: int,
    allow_lazy_fetch: bool,
) -> set[str]:
    result: set[str] = set()
    for offset in range(0, len(spans), _SPAN_BATCH):
        arguments = ["blame", "--line-porcelain", "-w", "-M", "-C", "-C"]
        for start, end in spans[offset : offset + _SPAN_BATCH]:
            arguments.extend(["-L", f"{start},{end}"])
        arguments.extend([revision, "--", path])
        for line in _git(
            repo,
            arguments,
            timeout=timeout,
            allow_lazy_fetch=allow_lazy_fetch,
        ).splitlines():
            fields = line.split(maxsplit=1)
            if fields and _SHA_RE.fullmatch(fields[0].lower()):
                result.add(fields[0].lower())
    return result


def collect_fix_blame(
    repo: Path,
    fix_sha: str,
    *,
    timeout: int,
    allow_lazy_fetch: bool = False,
) -> dict[str, object]:
    parent_fields = _git(
        repo,
        ["rev-list", "--parents", "-n", "1", fix_sha],
        timeout=timeout,
        allow_lazy_fetch=allow_lazy_fetch,
    ).split()
    if len(parent_fields) < 2 or parent_fields[0].lower() != fix_sha:
        raise ValueError("cannot resolve fix parent")
    parent = parent_fields[1].lower()
    patch = _git(
        repo,
        ["diff", "--unified=0", "--no-color", "--find-renames", parent, fix_sha],
        timeout=timeout,
        allow_lazy_fetch=allow_lazy_fetch,
    )
    deleted: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
    context: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
    method_points: defaultdict[str, set[int]] = defaultdict(set)
    parent_lines: dict[str, list[str]] = {}
    for hunk in parse_origin_hunks(patch):
        if hunk.parent_path is None:
            continue
        if hunk.parent_path not in parent_lines:
            parent_lines[hunk.parent_path] = _git(
                repo,
                ["show", f"{parent}:{hunk.parent_path}"],
                timeout=timeout,
                allow_lazy_fetch=allow_lazy_fetch,
            ).splitlines()
        line_count = len(parent_lines[hunk.parent_path])
        if line_count:
            method_points[hunk.parent_path].add(min(max(1, hunk.old_start), line_count))
        if hunk.deleted_span is not None:
            deleted[hunk.parent_path].append(hunk.deleted_span)
        if not hunk.needs_add_check_history:
            continue
        for raw_point in hunk.insertion_points:
            if line_count < 1:
                continue
            point = min(max(1, raw_point), line_count)
            context[hunk.parent_path].append(
                (max(1, point - _CONTEXT), min(line_count, point + _CONTEXT))
            )

    methods = {
        path: [
            (line, line) for line in _method_signature_lines(parent_lines[path], points)
        ]
        for path, points in method_points.items()
    }

    evidence: defaultdict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"signals": set(), "paths": set()}
    )
    for signal, spans_by_path in (
        ("deleted_line_blame", deleted),
        ("guard_context_blame", context),
        ("method_signature_blame", methods),
    ):
        for path, spans in spans_by_path.items():
            for sha in _blame(
                repo,
                parent,
                path,
                spans,
                timeout=timeout,
                allow_lazy_fetch=allow_lazy_fetch,
            ):
                evidence[sha]["signals"].add(signal)
                evidence[sha]["paths"].add(path)
    return {
        "fix_sha": fix_sha,
        "parent_sha": parent,
        "status": "RESOLVED",
        "deleted_path_count": len(deleted),
        "guard_context_path_count": len(context),
        "method_signature_path_count": sum(bool(spans) for spans in methods.values()),
        "origins": {
            sha: {
                "signals": sorted(value["signals"]),
                "paths": sorted(value["paths"]),
            }
            for sha, value in sorted(evidence.items())
        },
    }


def match_candidates(
    candidates: Iterable[Mapping[str, object]],
    blame_by_fix: Mapping[str, Mapping[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Split exact direct blame from carrier blame that still needs atomization."""

    direct: dict[tuple[str, str, str], dict[str, object]] = {}
    carrier: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for candidate in candidates:
        fix_sha = str(candidate.get("fix_sha") or "")
        result = blame_by_fix.get(fix_sha)
        if result is None or result.get("status") != "RESOLVED":
            continue
        origins = result.get("origins", {})
        if not isinstance(origins, Mapping):
            continue
        relation = str(candidate.get("relation") or "")
        candidate_sha = str(candidate.get("candidate_sha") or "")
        if relation == "reachable_ancestor" and candidate_sha in origins:
            evidence = origins[candidate_sha]
            assert isinstance(evidence, Mapping)
            key = (str(candidate["class_id"]), fix_sha, candidate_sha)
            direct[key] = {
                **candidate,
                "blame_signals": evidence["signals"],
                "blamed_paths": evidence["paths"],
                "fix_parent_sha": result["parent_sha"],
                "claim_boundary": "exact fix-hunk blame plus AI attribution; mechanism review still required",
            }
            continue
        landed_sha = str(candidate.get("landed_squash_sha") or "")
        if relation.startswith("pull_request_member_") and landed_sha in origins:
            evidence = origins[landed_sha]
            assert isinstance(evidence, Mapping)
            key = (str(candidate["class_id"]), fix_sha, candidate_sha, landed_sha)
            carrier[key] = {
                **candidate,
                "carrier_blame_signals": evidence["signals"],
                "carrier_blamed_paths": evidence["paths"],
                "fix_parent_sha": result["parent_sha"],
                "claim_boundary": (
                    "the landed squash is blamed, but this AI member is not yet tied to the "
                    "blamed line; member-level refinement is mandatory"
                ),
            }
    return (
        [direct[key] for key in sorted(direct)],
        [carrier[key] for key in sorted(carrier)],
    )


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


def _atomic_jsonl(path: Path, rows: Iterable[Mapping[str, object]]) -> None:
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


def main() -> int:
    args = _parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.repo_timeout < 1 or not (args.repository_path / ".git").is_dir():
        raise SystemExit("invalid repository path or timeout")
    candidates = list(_jsonl(args.same_file_candidates))
    fixes = sorted({str(row["fix_sha"]) for row in candidates})
    blame_by_fix: dict[str, dict[str, object]] = {}
    if args.input_fix_blame:
        available = {str(row["fix_sha"]): row for row in _jsonl(args.input_fix_blame)}
        missing = sorted(set(fixes) - set(available))
        if missing:
            raise SystemExit(f"input fix-blame is missing {missing[0]}")
        blame_by_fix = {fix_sha: available[fix_sha] for fix_sha in fixes}
    else:
        blame_by_fix = _collect_all_fix_blame(
            args.repository_path,
            fixes,
            timeout=args.repo_timeout,
            allow_lazy_fetch=args.allow_lazy_fetch,
        )

    direct, carrier = match_candidates(candidates, blame_by_fix)
    fix_rows = [blame_by_fix[sha] for sha in sorted(blame_by_fix)]
    args.output_dir.mkdir(parents=True)
    _atomic_jsonl(args.output_dir / "fix-blame.jsonl", fix_rows)
    _atomic_jsonl(args.output_dir / "exact-direct-candidates.jsonl", direct)
    _atomic_jsonl(args.output_dir / "squash-carrier-candidates.jsonl", carrier)
    summary = {
        "schema_version": 1,
        "artifact_kind": "atomic_ai_fix_hunk_blame_screen",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_candidate_count": len(candidates),
        "reused_fix_blame": args.input_fix_blame is not None,
        "lazy_fetch_enabled": args.allow_lazy_fetch,
        "fix_count": len(fix_rows),
        "resolved_fix_count": sum(row["status"] == "RESOLVED" for row in fix_rows),
        "blocked_fix_count": sum(row["status"] == "BLOCKED" for row in fix_rows),
        "exact_direct_candidate_count": len(direct),
        "exact_direct_alias_class_count": len({row["class_id"] for row in direct}),
        "deleted_line_direct_alias_class_count": len(
            {
                row["class_id"]
                for row in direct
                if "deleted_line_blame" in row["blame_signals"]
            }
        ),
        "context_only_direct_alias_class_count": len(
            {
                row["class_id"]
                for row in direct
                if row["blame_signals"] == ["guard_context_blame"]
            }
        ),
        "squash_carrier_candidate_count": len(carrier),
        "squash_carrier_alias_class_count": len({row["class_id"] for row in carrier}),
        "fix_blame_sha256": canonical_sha256(fix_rows),
        "exact_direct_candidates_sha256": canonical_sha256(direct),
        "squash_carrier_candidates_sha256": canonical_sha256(carrier),
        "claim_boundary": (
            "Exact direct hits remain routing evidence until mechanism review. A blamed squash "
            "carrier never attributes its line to every member; carrier rows require a second "
            "member-level blame/refinement step."
        ),
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


def _collect_all_fix_blame(
    repo: Path,
    fixes: list[str],
    *,
    timeout: int,
    allow_lazy_fetch: bool,
) -> dict[str, dict[str, object]]:
    if not fixes:
        return {}
    blame_by_fix: dict[str, dict[str, object]] = {}
    workers = 1 if allow_lazy_fetch else min(8, len(fixes))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                collect_fix_blame,
                repo,
                fix_sha,
                timeout=timeout,
                allow_lazy_fetch=allow_lazy_fetch,
            ): fix_sha
            for fix_sha in fixes
        }
        for index, future in enumerate(as_completed(futures), start=1):
            fix_sha = futures[future]
            try:
                blame_by_fix[fix_sha] = future.result()
            except (OSError, ValueError) as exc:
                blame_by_fix[fix_sha] = {
                    "fix_sha": fix_sha,
                    "status": "BLOCKED",
                    "reason": str(exc),
                }
            if index % 50 == 0:
                print(f"processed {index}/{len(fixes)} fixes", flush=True)
    return blame_by_fix


if __name__ == "__main__":
    raise SystemExit(main())
