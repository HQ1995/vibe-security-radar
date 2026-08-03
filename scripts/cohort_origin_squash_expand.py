#!/usr/bin/env python3
"""Expand proof-reduced landed squashes to every recoverable real PR member."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from cohort.origin_squash import expand_squash_candidate_pairs
from cohort.origin_signals import history_search_tokens, parse_origin_hunks
from cohort.pull_refs import (
    COHORT_PULL_NAMESPACE,
    MAX_PR_MEMBERS,
    fetch_pull_refs,
    pull_members,
)
from cohort.relations import build_pull_relation_inventory
from cohort.root_adjudication import canonical_sha256
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import matches_for_commit


DEFAULT_FETCH_BATCH = 50
DEFAULT_REPO_TIMEOUT = 300
DEFAULT_MAX_SQUASH_DEPTH = 3
_RECORD_SEP = "\x1e"
_FIELD_SEP = "\x1f"
_INTERNAL_CONTEXT_RADIUS = 8
_BLAME_HEADER_RE = re.compile(r"^\^?([0-9a-f]{40}) (\d+) (\d+)(?: (\d+))?$")
_PR_NUMBER_RE = re.compile(r"\(#(\d+)\)\s*$", re.MULTILINE)
_INCOMPLETE_OBJECT_RE = re.compile(
    r"(?:could not read|unable to parse commit|bad object|missing (?:blob|tree|commit)|"
    r"invalid object|not a valid object name)",
    re.IGNORECASE,
)
_OBSERVATION_FIELDS = (
    "agent_kinds",
    "authored_date",
    "merge_topology",
    "pr_number",
    "signal_types",
    "source_modules",
    "squash_attribution_only",
    "tools",
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--generated-dir", type=Path)
    source.add_argument("--signal-dir", type=Path)
    parser.add_argument("--universe-dir", type=Path)
    parser.add_argument("--no-fetch", action="store_true")
    parser.add_argument("--fetch-batch", type=int, default=DEFAULT_FETCH_BATCH)
    parser.add_argument("--repo-timeout", type=int, default=DEFAULT_REPO_TIMEOUT)
    parser.add_argument(
        "--max-squash-depth",
        type=int,
        default=DEFAULT_MAX_SQUASH_DEPTH,
        help=(
            "recursively expand recovered members whose subject ends in (#PR); "
            "deeper unresolved squashes are retained as explicit scope gaps"
        ),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


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


def _prospective_signal_inventory(
    signal_dir: Path,
    universe_dir: Path,
) -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    """Adapt a conserved prospective signal queue to the squash relation contract."""

    parent_summary = _load_json(signal_dir / "summary.json")
    parent_candidates = _load_jsonl(signal_dir / "candidates.jsonl")
    if parent_summary.get("artifact_kind") != "recall_first_origin_signal_pilot":
        raise SystemExit("signal expansion requires a recall-first origin signal pilot")
    if canonical_sha256(parent_candidates) != parent_summary.get(
        "candidate_rows_sha256"
    ):
        raise SystemExit("signal parent candidate digest mismatch")

    identity = str(parent_summary.get("repository_identity") or "").strip().lower()
    advisory = str(parent_summary.get("advisory") or "").strip()
    fix_sha = str(parent_summary.get("fix_sha") or "").strip().lower()
    if not identity or "/" not in identity or not advisory:
        raise SystemExit("signal parent target identity is malformed")
    if not re.fullmatch(r"[0-9a-f]{40}", fix_sha):
        raise SystemExit("signal parent fix SHA is malformed")

    universe_summary = _load_json(universe_dir / "summary.json")
    if universe_summary.get("artifact_kind") != "prospective_all_commit_universe_campaign":
        raise SystemExit("signal expansion requires a prospective all-commit universe")
    raw_provenance = universe_summary.get("repository_provenance")
    if not isinstance(raw_provenance, list):
        raise SystemExit("universe repository provenance is malformed")
    provenance = [
        dict(row)
        for row in raw_provenance
        if isinstance(row, Mapping)
        and str(row.get("repository_identity") or "").strip().lower() == identity
    ]
    if len(provenance) != 1:
        raise SystemExit("signal target has no unique universe repository provenance")
    repository_path = Path(str(provenance[0].get("repository_path") or ""))
    if not repository_path.is_dir() or not (repository_path / ".git").exists():
        raise SystemExit("signal target repository path is unavailable")

    universe_rows = [
        row
        for row in _load_jsonl(universe_dir / "commit_universe.jsonl")
        if str(row.get("repository_identity") or "").strip().lower() == identity
    ]
    commits = {str(row.get("sha") or "").strip().lower(): row for row in universe_rows}
    if len(commits) != len(universe_rows):
        raise SystemExit("signal target universe contains duplicate commit SHAs")
    if fix_sha not in commits:
        raise SystemExit("signal target fix is absent from the all-commit universe")

    candidates: list[dict[str, object]] = []
    for raw in parent_candidates:
        row = dict(raw)
        sha = str(row.get("sha") or "").strip().lower()
        universe_row = commits.get(sha)
        if universe_row is None:
            raise SystemExit(f"signal candidate is outside target universe: {sha}")
        subject = str(row.get("subject") or "")
        pr_match = _PR_NUMBER_RE.search(subject)
        parents = universe_row.get("parents")
        if not isinstance(parents, list) or any(
            not isinstance(parent, str) for parent in parents
        ):
            raise SystemExit(f"signal candidate parent list is malformed: {sha}")
        if len(parents) > 1:
            topology = "merge"
        elif pr_match is not None:
            # GitHub squash merges have one parent. A trailing PR number is a
            # deliberately broad carrier signal: a false carrier only expands
            # the queue and never removes the landed commit.
            topology = "squash"
        else:
            topology = "direct"
        row.update(
            {
                "advisory": advisory,
                "repository_identity": identity,
                "fix_sha": fix_sha,
                "materialization": "prospective_structural_signal",
                "merge_topology": topology,
                "pr_number": int(pr_match.group(1)) if pr_match else None,
                "retained": True,
            }
        )
        ai_tools = row.get("ai_tools")
        if isinstance(ai_tools, list) and ai_tools:
            row["tools"] = sorted({str(tool) for tool in ai_tools if tool})
        candidates.append(row)

    fixes = [
        {
            "advisory": advisory,
            "repository_identity": identity,
            "fix_sha": fix_sha,
            "repository_path": str(repository_path.resolve()),
            "status": "RESOLVED",
            "fix_root_role": parent_summary.get("fix_root_role"),
            "root_eligibility": parent_summary.get("root_eligibility"),
        }
    ]
    return parent_summary, parent_candidates, candidates, fixes


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _atomic_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256(prefix.encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return f"{prefix}-{digest.hexdigest()}"


def _scan_observations(
    summary: Mapping[str, object],
) -> dict[tuple[str, str], dict[str, object]]:
    raw_inputs = summary.get("ai_scan_inputs")
    if not isinstance(raw_inputs, list):
        raise SystemExit("parent reduction has no verifiable AI scan inputs")
    observations: dict[tuple[str, str], dict[str, object]] = {}
    for raw in raw_inputs:
        if not isinstance(raw, Mapping):
            raise SystemExit("parent AI scan provenance is malformed")
        directory = Path(str(raw.get("directory") or ""))
        rows = _load_jsonl(directory / "commits.jsonl")
        if canonical_sha256(rows) != raw.get("commit_rows_sha256"):
            raise SystemExit(f"AI scan commit digest mismatch: {directory}")
        for row in rows:
            identity = str(row.get("repository_identity") or "").strip().lower()
            sha = str(row.get("sha") or "").strip().lower()
            key = (identity, sha)
            prior = observations.get(key)
            if prior is not None and prior != row:
                raise SystemExit(f"conflicting AI scan observation: {identity}@{sha}")
            observations[key] = row
    return observations


def _hydrate_candidate_metadata(
    rows: Sequence[Mapping[str, object]],
    observations: Mapping[tuple[str, str], Mapping[str, object]],
) -> list[dict[str, object]]:
    hydrated: list[dict[str, object]] = []
    for raw in rows:
        row = dict(raw)
        key = (
            str(row.get("repository_identity") or "").strip().lower(),
            str(row.get("sha") or "").strip().lower(),
        )
        observation = observations.get(key)
        if observation is not None:
            for field in _OBSERVATION_FIELDS:
                if field not in observation:
                    continue
                observed = observation[field]
                if field in row and row[field] not in (None, observed):
                    raise SystemExit(
                        f"candidate/scan metadata conflict: {key[0]}@{key[1]}:{field}"
                    )
                row[field] = observed
        hydrated.append(row)
    return hydrated


def _repository_paths(
    fixes: Sequence[Mapping[str, object]],
) -> dict[str, Path | None]:
    raw_paths: defaultdict[str, set[Path]] = defaultdict(set)
    for row in fixes:
        identity = str(row.get("repository_identity") or "").strip().lower()
        text = str(row.get("repository_path") or "").strip()
        if text:
            raw_paths[identity].add(Path(text).resolve())
    result: dict[str, Path | None] = {}
    for identity, paths in raw_paths.items():
        if len(paths) > 1:
            raise SystemExit(f"fix rows disagree on repository path: {identity}")
        candidate = next(iter(paths))
        result[identity] = (
            candidate if candidate.is_dir() and (candidate / ".git").exists() else None
        )
    return result


def _commit_records(
    repo: Path, shas: Sequence[str], *, timeout: int
) -> dict[str, CommitInfo]:
    records: dict[str, CommitInfo] = {}
    fmt = (
        f"{_RECORD_SEP}%H{_FIELD_SEP}%an{_FIELD_SEP}%ae"
        f"{_FIELD_SEP}%cn{_FIELD_SEP}%ce{_FIELD_SEP}%aI{_FIELD_SEP}%B"
    )
    ordered = sorted(set(shas))
    for start in range(0, len(ordered), 200):
        chunk = ordered[start : start + 200]
        output = _git_output(
            repo,
            ["show", "--no-patch", f"--format={fmt}", *chunk],
            timeout=timeout,
        )
        outputs = [output] if output else [
            single
            for sha in chunk
            if (
                single := _git_output(
                    repo,
                    ["show", "--no-patch", f"--format={fmt}", sha],
                    timeout=timeout,
                )
            )
        ]
        for raw_output in outputs:
            for record in raw_output.split(_RECORD_SEP):
                if not record.strip():
                    continue
                fields = record.split(_FIELD_SEP, 6)
                if len(fields) != 7:
                    continue
                (
                    sha,
                    author_name,
                    author_email,
                    committer_name,
                    committer_email,
                    authored,
                    message,
                ) = fields
                normalized_sha = sha.strip().lower()
                records[normalized_sha] = CommitInfo(
                    sha=normalized_sha,
                    author_name=author_name,
                    author_email=author_email,
                    committer_name=committer_name,
                    committer_email=committer_email,
                    message=message,
                    authored_date=authored.strip(),
                )
    return records


def _is_code_path(path: str) -> bool:
    normalized = path.casefold()
    parts = tuple(part for part in normalized.split("/") if part)
    name = parts[-1] if parts else normalized
    if any(part in {"doc", "docs", "test", "tests", ".github"} for part in parts):
        return False
    if name.startswith(("readme", "changelog", "license")):
        return False
    if name.endswith((".md", ".rst", ".txt")):
        return False
    return True


def _git_output_or_none(
    repo: Path, arguments: Sequence[str], *, timeout: int
) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    # Several Git walkers (notably blame in a partial clone) can emit a
    # plausible prefix and still return zero after failing to read an older
    # object. Accepting that prefix turns the oldest available PR member into
    # the apparent owner of unchanged baseline lines. Evidence is optional and
    # ranking-only, so discard incomplete output instead of manufacturing a
    # causal signal.
    if completed.returncode != 0 or _INCOMPLETE_OBJECT_RE.search(
        str(completed.stderr or "")
    ):
        return None
    return completed.stdout


def _git_output(repo: Path, arguments: Sequence[str], *, timeout: int) -> str:
    return _git_output_or_none(repo, arguments, timeout=timeout) or ""


def _materialize_member_parents(
    repo: Path, shas: Sequence[str], *, timeout: int
) -> set[str]:
    """Force every PR member's direct parent commit into a partial clone.

    GitHub PR-head fetches into a blob-filtered or formerly shallow cache may
    leave the PR base commit promised but absent. `git blame` then treats the
    oldest available member as a boundary and can falsely assign every
    unchanged line to it. `cat-file -e` deliberately permits Git's promisor
    remote to hydrate the parent before any diff or blame is trusted.
    """

    failures: set[str] = set()
    for sha in sorted(set(shas)):
        try:
            completed = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "cat-file",
                    "-e",
                    f"{sha}^1^{{commit}}",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            failures.add(sha)
            continue
        if completed.returncode != 0:
            failures.add(sha)
    return failures


def _blame_lines(
    repo: Path,
    revision: str,
    path: str,
    *,
    timeout: int,
) -> list[dict[str, object]]:
    output = _git_output(
        repo,
        ["blame", "--line-porcelain", revision, "--", path],
        timeout=timeout,
    )
    rows: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in output.splitlines():
        match = _BLAME_HEADER_RE.fullmatch(line)
        if match:
            current = {
                "sha": match.group(1),
                "line": int(match.group(3)),
            }
            continue
        if current is not None and line.startswith("\t"):
            rows.append({**current, "content": line[1:]})
            current = None
    return rows


def _line_tokens(content: str) -> frozenset[str]:
    return frozenset(token.casefold() for token in history_search_tokens(content))


def _fix_context_lines(
    repo: Path,
    fix_sha: str,
    *,
    timeout: int,
    patch_cache: dict[str, str],
    file_cache: dict[tuple[str, str], list[str]],
) -> list[dict[str, object]]:
    patch = patch_cache.get(fix_sha)
    if patch is None:
        patch = _git_output(
            repo,
            [
                "diff",
                "--no-ext-diff",
                "--no-color",
                "--unified=0",
                f"{fix_sha}^",
                fix_sha,
                "--",
            ],
            timeout=timeout,
        )
        patch_cache[fix_sha] = patch
    contexts: list[dict[str, object]] = []
    for hunk in parse_origin_hunks(patch):
        if hunk.parent_path is None:
            continue
        file_key = (fix_sha, hunk.parent_path)
        lines = file_cache.get(file_key)
        if lines is None:
            content = _git_output(
                repo,
                ["show", f"{fix_sha}^:{hunk.parent_path}"],
                timeout=timeout,
            )
            lines = content.splitlines()
            file_cache[file_key] = lines
        if not lines:
            continue
        direct_start = max(1, hunk.old_start)
        direct_end = hunk.old_start + hunk.old_count - 1
        window_start = max(1, hunk.old_start - _INTERNAL_CONTEXT_RADIUS)
        window_end = min(
            len(lines),
            hunk.old_start + max(hunk.old_count, 1) - 1 + _INTERNAL_CONTEXT_RADIUS,
        )
        added_tokens = _line_tokens("\n".join(hunk.added_lines))
        for line_number in range(window_start, window_end + 1):
            content = lines[line_number - 1]
            tokens = _line_tokens(content)
            if not tokens:
                continue
            in_direct_span = (
                hunk.old_count > 0 and direct_start <= line_number <= direct_end
            )
            if not in_direct_span and not (tokens & added_tokens):
                continue
            contexts.append(
                {
                    "path": hunk.parent_path,
                    "fix_hunk_old_start": hunk.old_start,
                    "fix_hunk_old_count": hunk.old_count,
                    "fix_parent_line": line_number,
                    "content": content,
                    "tokens": tokens,
                }
            )
    return contexts


def _squash_internal_fix_context(
    repo: Path,
    *,
    pr_number: int,
    fix_sha: str,
    member_shas: set[str],
    timeout: int,
    patch_cache: dict[str, str],
    file_cache: dict[tuple[str, str], list[str]],
    blame_cache: dict[tuple[int, str], list[dict[str, object]]],
) -> dict[str, list[dict[str, object]]]:
    """Map pre-fix hunk context back to the real member that owns it on the PR head."""
    evidence: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for context in _fix_context_lines(
        repo,
        fix_sha,
        timeout=timeout,
        patch_cache=patch_cache,
        file_cache=file_cache,
    ):
        path = str(context["path"])
        blame_key = (pr_number, path)
        pull_rows = blame_cache.get(blame_key)
        if pull_rows is None:
            pull_rows = _blame_lines(
                repo,
                f"{COHORT_PULL_NAMESPACE}/{pr_number}",
                path,
                timeout=timeout,
            )
            blame_cache[blame_key] = pull_rows
        if not pull_rows:
            continue

        content = str(context["content"])
        tokens = context["tokens"]
        assert isinstance(tokens, frozenset)
        exact = [row for row in pull_rows if row["content"] == content]
        if exact:
            matches = exact
            quality = "exact_line"
        else:
            stripped = [
                row
                for row in pull_rows
                if str(row["content"]).strip() == content.strip()
            ]
            if stripped:
                matches = stripped
                quality = "whitespace_normalized_line"
            else:
                matches = [
                    row
                    for row in pull_rows
                    if _line_tokens(str(row["content"])) == tokens
                ]
                quality = "token_signature_fail_open"
        ambiguity = len(matches)
        for row in matches:
            origin_sha = str(row["sha"])
            if origin_sha not in member_shas:
                continue
            evidence[origin_sha].append(
                {
                    "path": path,
                    "fix_sha": fix_sha,
                    "fix_hunk_old_start": context["fix_hunk_old_start"],
                    "fix_hunk_old_count": context["fix_hunk_old_count"],
                    "fix_parent_line": context["fix_parent_line"],
                    "pull_head_line": row["line"],
                    "match_quality": quality,
                    "match_ambiguity": ambiguity,
                    "content_sha256": hashlib.sha256(
                        content.encode("utf-8")
                    ).hexdigest(),
                }
            )
    quality_rank = {
        "exact_line": 0,
        "whitespace_normalized_line": 1,
        "token_signature_fail_open": 2,
    }
    deduplicated: dict[str, list[dict[str, object]]] = {}
    for origin_sha, rows in evidence.items():
        unique: dict[tuple[str, int, str], dict[str, object]] = {}
        for row in rows:
            key = (
                str(row["path"]),
                int(row["pull_head_line"]),
                str(row["content_sha256"]),
            )
            prior = unique.get(key)
            if prior is None:
                normalized = dict(row)
                normalized["fix_parent_lines"] = [int(row["fix_parent_line"])]
                normalized["fix_hunk_old_starts"] = [int(row["fix_hunk_old_start"])]
                normalized["fix_context_match_count"] = 1
                normalized.pop("fix_parent_line", None)
                normalized.pop("fix_hunk_old_start", None)
                normalized.pop("fix_hunk_old_count", None)
                unique[key] = normalized
                continue
            prior["fix_parent_lines"] = sorted(
                {
                    *(int(value) for value in prior["fix_parent_lines"]),
                    int(row["fix_parent_line"]),
                }
            )
            prior["fix_hunk_old_starts"] = sorted(
                {
                    *(int(value) for value in prior["fix_hunk_old_starts"]),
                    int(row["fix_hunk_old_start"]),
                }
            )
            prior["fix_context_match_count"] = int(prior["fix_context_match_count"]) + 1
            if (
                quality_rank[str(row["match_quality"])]
                < quality_rank[str(prior["match_quality"])]
            ):
                prior["match_quality"] = row["match_quality"]
            prior["match_ambiguity"] = min(
                int(prior["match_ambiguity"]), int(row["match_ambiguity"])
            )
        deduplicated[origin_sha] = sorted(
            unique.values(),
            key=lambda row: (
                str(row["path"]),
                int(row["pull_head_line"]),
                str(row["content_sha256"]),
            ),
        )
    return deduplicated


def _path_metadata(changed_files: Sequence[str]) -> dict[str, object]:
    unique_files = sorted(set(changed_files))
    return {
        "changed_files": unique_files,
        "code_files_changed": [path for path in unique_files if _is_code_path(path)],
        "empty_commit": not unique_files,
    }


def _numstat_metadata(lines: Sequence[str]) -> dict[str, object]:
    changed_files: list[str] = []
    additions = 0
    deletions = 0
    for line in lines:
        fields = line.split("\t", 2)
        if len(fields) != 3:
            continue
        raw_additions, raw_deletions, path = fields
        changed_files.append(path)
        if raw_additions.isdigit():
            additions += int(raw_additions)
        if raw_deletions.isdigit():
            deletions += int(raw_deletions)
    metadata = _path_metadata(changed_files)
    metadata.update({"additions": additions, "deletions": deletions})
    return metadata


def _single_diff_metadata(
    repo: Path, sha: str, *, timeout: int
) -> dict[str, object] | None:
    base = [
        "diff-tree",
        "--no-commit-id",
        "--no-renames",
        "-r",
        f"{sha}^1",
        sha,
        "--",
    ]
    numstat = _git_output_or_none(
        repo, [*base[:3], "--numstat", *base[3:]], timeout=timeout
    )
    if numstat is not None:
        return _numstat_metadata(numstat.splitlines())
    names = _git_output_or_none(
        repo, [*base[:3], "--name-only", *base[3:]], timeout=timeout
    )
    return _path_metadata(names.splitlines()) if names is not None else None


def _diff_metadata(
    repo: Path, shas: Sequence[str], *, timeout: int
) -> dict[str, dict[str, object]]:
    """Read first-parent numstat in bounded batches, with per-SHA fallback."""

    metadata: dict[str, dict[str, object]] = {}
    unique_shas = sorted(set(shas))
    for start in range(0, len(unique_shas), 128):
        chunk = unique_shas[start : start + 128]
        try:
            completed = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "show",
                    "--no-renames",
                    "--numstat",
                    "--first-parent",
                    f"--format={_RECORD_SEP}%H{_FIELD_SEP}",
                    *chunk,
                    "--",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            completed = None

        seen: set[str] = set()
        if (
            completed is not None
            and completed.returncode == 0
            and not _INCOMPLETE_OBJECT_RE.search(str(completed.stderr or ""))
        ):
            for raw_record in completed.stdout.split(_RECORD_SEP):
                if not raw_record.strip() or _FIELD_SEP not in raw_record:
                    continue
                raw_sha, raw_numstat = raw_record.split(_FIELD_SEP, 1)
                sha = raw_sha.strip().lower()
                if sha not in chunk:
                    continue
                metadata[sha] = _numstat_metadata(raw_numstat.splitlines())
                seen.add(sha)

        # A malformed or partially hydrated batch must not erase every other
        # usable commit in that batch.  Retry only missing records one by one.
        for sha in chunk:
            if sha in seen:
                continue
            single = _single_diff_metadata(repo, sha, timeout=timeout)
            if single is not None:
                metadata[sha] = single
    return metadata


def _member_metadata(record: CommitInfo) -> dict[str, object]:
    matches = matches_for_commit(record)
    metadata: dict[str, object] = {
        "authored_date": record.authored_date,
        "commit_subject": record.message.splitlines()[0] if record.message else "",
        "merge_topology": "pull_request_member",
        "observed_ai_unit": bool(matches),
        "ai_exposure_supported": True,
        "ai_exposure_basis": (
            "member_commit_signal" if matches else "ai_attributed_landed_squash"
        ),
    }
    if matches:
        metadata.update(
            {
                "agent_kinds": sorted(
                    {match.agent_kind for match in matches if match.agent_kind}
                ),
                "signal_types": sorted({match.signal_type for match in matches}),
                "source_modules": sorted({match.source_module for match in matches}),
                "tools": sorted({match.tool for match in matches}),
            }
        )
    return metadata


def _candidate_units(
    identity: str,
    candidates: Sequence[Mapping[str, object]],
    matched_members: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    units: dict[str, dict[str, object]] = {}
    for candidate in candidates:
        if str(candidate.get("repository_identity") or "").lower() != identity:
            continue
        sha = str(candidate.get("sha") or "").lower()
        unit = {
            "repository_identity": identity,
            "sha": sha,
            **{
                field: candidate[field]
                for field in _OBSERVATION_FIELDS
                if field in candidate
            },
        }
        prior = units.get(sha)
        if prior is not None and prior != unit:
            raise SystemExit(
                f"candidate metadata varies across fixes: {identity}@{sha}"
            )
        units[sha] = unit
    for sha, metadata in matched_members.items():
        units.setdefault(
            sha,
            {
                "repository_identity": identity,
                "sha": sha,
                **dict(metadata),
            },
        )
    return [units[sha] for sha in sorted(units)]


def _missing_pr_root(identity: str, landed_sha: str) -> dict[str, object]:
    return {
        "root_id": _stable_id("pull-root", identity, "missing", landed_sha),
        "repository_identity": identity,
        "pr_number": None,
        "landed_sha": landed_sha,
        "status": "BLOCKED",
        "reason": "missing_pr_number",
        "member_count": 0,
        "eligible_origin_count": 0,
        "eligible_origins_sha256": canonical_sha256([]),
        "observed_origin_count": 0,
        "unobserved_origin_count": 0,
        "member_ai_signal_count": 0,
        "squash_attribution_only": True,
    }


def _nested_squash_targets(
    candidates: Sequence[Mapping[str, object]],
    seen: set[tuple[str, str]],
) -> list[dict[str, object]]:
    """Return unexpanded member commits that look like landed GitHub squashes."""

    targets: list[dict[str, object]] = []
    emitted: set[tuple[str, str, str]] = set()
    for raw in candidates:
        if raw.get("merge_topology") != "pull_request_member":
            continue
        identity = str(raw.get("repository_identity") or "").strip().lower()
        sha = str(raw.get("sha") or "").strip().lower()
        if (identity, sha) in seen:
            continue
        match = _PR_NUMBER_RE.search(str(raw.get("commit_subject") or ""))
        if match is None:
            continue
        key = (str(raw.get("advisory") or ""), identity, sha)
        if key in emitted:
            continue
        row = dict(raw)
        row["merge_topology"] = "squash"
        row["pr_number"] = int(match.group(1))
        targets.append(row)
        emitted.add(key)
    return sorted(
        targets,
        key=lambda row: (
            str(row.get("advisory") or ""),
            str(row.get("repository_identity") or ""),
            str(row.get("fix_sha") or ""),
            str(row.get("sha") or ""),
        ),
    )


def _depth_limit_scope_gaps(
    targets: Sequence[Mapping[str, object]], max_depth: int
) -> list[dict[str, object]]:
    gaps: list[dict[str, object]] = []
    for row in targets:
        identity = str(row.get("repository_identity") or "").strip().lower()
        sha = str(row.get("sha") or "").strip().lower()
        advisory = str(row.get("advisory") or "")
        fix_sha = str(row.get("fix_sha") or "").strip().lower()
        gaps.append(
            {
                "gap_id": _stable_id(
                    "nested-squash-depth-gap",
                    advisory,
                    identity,
                    fix_sha,
                    sha,
                    str(max_depth),
                ),
                "gap_type": "nested_squash_depth_limit",
                "advisory": advisory,
                "repository_identity": identity,
                "fix_sha": fix_sha,
                "candidate_sha": sha,
                "pr_number": row.get("pr_number"),
                "max_squash_depth": max_depth,
                "status": "BLOCKED",
                "disposition": "RETAIN_nested_squash",
            }
        )
    return gaps


def _build_relations(
    candidates: Sequence[Mapping[str, object]],
    fixes: Sequence[Mapping[str, object]],
    *,
    fetch: bool,
    fetch_batch: int,
    timeout: int,
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    dict[tuple[str, str], dict[str, object]],
    dict[tuple[str, str], list[str]],
    dict[tuple[str, str, str, str], list[dict[str, object]]],
    list[dict[str, object]],
]:
    targets: defaultdict[str, dict[str, int | None]] = defaultdict(dict)
    for row in candidates:
        if row.get("merge_topology") != "squash":
            continue
        identity = str(row.get("repository_identity") or "").strip().lower()
        landed_sha = str(row.get("sha") or "").strip().lower()
        raw_pr = row.get("pr_number")
        pr_number = (
            raw_pr
            if isinstance(raw_pr, int) and not isinstance(raw_pr, bool) and raw_pr > 0
            else None
        )
        prior = targets[identity].get(landed_sha)
        if landed_sha in targets[identity] and prior != pr_number:
            raise SystemExit(f"conflicting squash PR mapping: {identity}@{landed_sha}")
        targets[identity][landed_sha] = pr_number

    repositories = _repository_paths(fixes)
    relations: list[dict[str, object]] = []
    roots: list[dict[str, object]] = []
    all_member_metadata: dict[tuple[str, str], dict[str, object]] = {}
    all_fix_changed_files: dict[tuple[str, str], list[str]] = {}
    all_internal_blame_evidence: defaultdict[
        tuple[str, str, str, str], list[dict[str, object]]
    ] = defaultdict(list)
    fetch_stats: list[dict[str, object]] = []
    for identity in sorted(targets):
        valid_targets = {
            sha: number
            for sha, number in targets[identity].items()
            if number is not None
        }
        roots.extend(
            _missing_pr_root(identity, sha)
            for sha, number in sorted(targets[identity].items())
            if number is None
        )
        if not valid_targets:
            continue
        pr_numbers = sorted({int(number) for number in valid_targets.values()})
        repo = repositories.get(identity)
        fetched, fetch_error = 0, ""
        if repo is None:
            fetch_error = "no_local_clone"
        elif fetch:
            fetched, fetch_error = fetch_pull_refs(
                repo, pr_numbers, batch=fetch_batch, timeout=timeout
            )
        pull_results: dict[int, dict[str, object]] = {}
        members_by_pr: dict[int, list[str]] = {}
        if repo is None:
            for number in pr_numbers:
                pull_results[number] = {
                    "status": "BLOCKED",
                    "members": [],
                    "reason": "no_local_clone",
                }
        else:
            # A PR may have more than one landed incarnation (for example a
            # backport or re-landing).  Union every base cut and fan the
            # recoverable member set out to every landed SHA.  This can add
            # false-positive relation paths but cannot erase a real member.
            landed_for_pr: defaultdict[int, list[str]] = defaultdict(list)
            for landed_sha, number in valid_targets.items():
                landed_for_pr[int(number)].append(landed_sha)
            for number in pr_numbers:
                member_union: set[str] = set()
                failed_base_cuts = 0
                oversized = False
                for landed_sha in sorted(landed_for_pr[number]):
                    members = pull_members(
                        repo, landed_sha, number, timeout=timeout
                    )
                    if members is None:
                        failed_base_cuts += 1
                        continue
                    if len(members) > MAX_PR_MEMBERS:
                        oversized = True
                    member_union.update(members)
                if not member_union:
                    pull_results[number] = {
                        "status": "BLOCKED",
                        "members": [],
                        "reason": "no_pr_ref",
                    }
                elif oversized or len(member_union) > MAX_PR_MEMBERS:
                    pull_results[number] = {
                        "status": "BLOCKED",
                        "members": sorted(member_union),
                        "reason": "integration_branch",
                    }
                else:
                    members = sorted(member_union)
                    members_by_pr[number] = members
                    pull_results[number] = {
                        "status": "RESOLVED",
                        "members": members,
                        "reason": (
                            "partial_base_cut_fail_open"
                            if failed_base_cuts
                            else ""
                        ),
                    }

            member_shas = sorted(
                {sha for members in members_by_pr.values() for sha in members}
            )
            missing_parent_members = _materialize_member_parents(
                repo, member_shas, timeout=timeout
            )
            fix_shas = sorted(
                {
                    str(row.get("fix_sha") or "").lower()
                    for row in fixes
                    if str(row.get("repository_identity") or "").lower() == identity
                }
            )
            records = _commit_records(
                repo,
                member_shas,
                timeout=timeout,
            )
            diff_metadata = _diff_metadata(
                repo, [*member_shas, *fix_shas], timeout=timeout
            )
            for number, members in members_by_pr.items():
                if pull_results[number].get("status") != "RESOLVED":
                    continue
                gap_shas = {
                    "member_parent_metadata_gap_shas": sorted(
                        sha for sha in members if sha in missing_parent_members
                    ),
                    "member_record_metadata_gap_shas": sorted(
                        sha for sha in members if sha not in records
                    ),
                    "member_diff_metadata_gap_shas": sorted(
                        sha for sha in members if sha not in diff_metadata
                    ),
                }
                pull_results[number].update(
                    {field: shas for field, shas in gap_shas.items() if shas}
                )
                gap_reasons = [
                    str(pull_results[number].get("reason") or ""),
                    *(
                        ["member_parent_metadata_incomplete_fail_open"]
                        if gap_shas["member_parent_metadata_gap_shas"]
                        else []
                    ),
                    *(
                        ["member_read_metadata_incomplete_fail_open"]
                        if gap_shas["member_record_metadata_gap_shas"]
                        else []
                    ),
                    *(
                        ["member_diff_metadata_incomplete_fail_open"]
                        if gap_shas["member_diff_metadata_gap_shas"]
                        else []
                    ),
                ]
                pull_results[number]["reason"] = ";".join(
                    reason for reason in gap_reasons if reason
                )
            missing_fix_metadata = [sha for sha in fix_shas if sha not in diff_metadata]
            if missing_fix_metadata:
                raise SystemExit(
                    f"cannot read fix diff metadata: {identity}@{missing_fix_metadata[0]}"
                )
            for sha in fix_shas:
                all_fix_changed_files[(identity, sha)] = list(
                    diff_metadata[sha]["changed_files"]
                )
            local_metadata: dict[str, dict[str, object]] = {}
            for sha in member_shas:
                record = records.get(sha)
                metadata = _member_metadata(record) if record is not None else {}
                metadata.update(
                    {
                        "member_parent_metadata_complete": (
                            sha not in missing_parent_members
                        ),
                        "member_record_metadata_complete": record is not None,
                        "member_diff_metadata_complete": sha in diff_metadata,
                    }
                )
                metadata.update(diff_metadata.get(sha, {}))
                local_metadata[sha] = metadata
            for sha, metadata in local_metadata.items():
                all_member_metadata[(identity, sha)] = metadata
            patch_cache: dict[str, str] = {}
            file_cache: dict[tuple[str, str], list[str]] = {}
            blame_cache: dict[tuple[int, str], list[dict[str, object]]] = {}
            for candidate in candidates:
                if candidate.get("merge_topology") != "squash":
                    continue
                if str(candidate.get("repository_identity") or "").lower() != identity:
                    continue
                landed_sha = str(candidate.get("sha") or "").lower()
                if landed_sha not in valid_targets:
                    continue
                pr_number = int(valid_targets[landed_sha])
                if pull_results[pr_number].get("status") != "RESOLVED":
                    continue
                fix_sha = str(candidate.get("fix_sha") or "").lower()
                if fix_sha not in diff_metadata:
                    continue
                mapped = _squash_internal_fix_context(
                    repo,
                    pr_number=pr_number,
                    fix_sha=fix_sha,
                    member_shas=set(members_by_pr[pr_number]),
                    timeout=timeout,
                    patch_cache=patch_cache,
                    file_cache=file_cache,
                    blame_cache=blame_cache,
                )
                for origin_sha, evidence_rows in mapped.items():
                    all_internal_blame_evidence[
                        (identity, landed_sha, fix_sha, origin_sha)
                    ].extend(evidence_rows)
            matched_members = {
                sha: metadata
                for sha, metadata in local_metadata.items()
                if metadata.get("observed_ai_unit") is True
            }
            inventory = build_pull_relation_inventory(
                identity,
                _candidate_units(identity, candidates, matched_members),
                pull_results,
                landed_candidate_shas=valid_targets,
            )
            local_relations = [dict(row) for row in inventory["relations"]]
            local_roots = [dict(row) for row in inventory["pull_roots"]]
            member_signal_by_landed = Counter(
                str(row["landed_sha"])
                for row in local_relations
                if local_metadata.get(str(row["origin_sha"]), {}).get(
                    "observed_ai_unit"
                )
                is True
            )
            for root in local_roots:
                signal_count = member_signal_by_landed[str(root["landed_sha"])]
                root["member_ai_signal_count"] = signal_count
                root["squash_attribution_only"] = bool(
                    root.get("status") == "RESOLVED" and signal_count == 0
                )
            relations.extend(local_relations)
            roots.extend(local_roots)
        fetch_stats.append(
            {
                "repository_identity": identity,
                "requested_pr_ref_count": len(pr_numbers),
                "refs_fetched": fetched,
                "fetch_error": fetch_error,
            }
        )

    relations.sort(key=lambda row: str(row["relation_id"]))
    roots.sort(key=lambda row: str(row["root_id"]))
    expected_roots = sum(len(rows) for rows in targets.values())
    if len(roots) != expected_roots:
        raise SystemExit(
            f"squash root conservation failed: expected {expected_roots}, got {len(roots)}"
        )
    return (
        relations,
        roots,
        all_member_metadata,
        all_fix_changed_files,
        dict(all_internal_blame_evidence),
        fetch_stats,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if (
        args.fetch_batch < 1
        or args.repo_timeout < 1
        or args.max_squash_depth < 1
    ):
        raise SystemExit(
            "fetch-batch, repo-timeout, and max-squash-depth must be positive"
        )

    if args.signal_dir is not None:
        if args.universe_dir is None:
            raise SystemExit("--signal-dir requires --universe-dir")
        source_dir = args.signal_dir
        (
            parent_summary,
            parent_candidates,
            hydrated,
            fixes,
        ) = _prospective_signal_inventory(args.signal_dir, args.universe_dir)
        generation_process_boundary = (
            "frozen_prospective_signal_inventory_plus_frozen_all_commit_universe_"
            "plus_public_pull_refs_no_golden_origin_read"
        )
    else:
        if args.universe_dir is not None:
            raise SystemExit("--universe-dir is only valid with --signal-dir")
        assert args.generated_dir is not None
        source_dir = args.generated_dir
        parent_summary = _load_json(args.generated_dir / "summary.json")
        parent_candidates = _load_jsonl(args.generated_dir / "candidates.jsonl")
        fixes = _load_jsonl(args.generated_dir / "fixes.jsonl")
        if (
            parent_summary.get("artifact_kind")
            != "proof_carrying_origin_candidate_reduction"
        ):
            raise SystemExit("squash expansion requires a proof-carrying reduction")
        if canonical_sha256(parent_candidates) != parent_summary.get(
            "candidate_rows_sha256"
        ):
            raise SystemExit("parent candidate digest mismatch")
        if canonical_sha256(fixes) != parent_summary.get("fix_rows_sha256"):
            raise SystemExit("parent fix digest mismatch")
        observations = _scan_observations(parent_summary)
        hydrated = _hydrate_candidate_metadata(parent_candidates, observations)
        generation_process_boundary = (
            "sealed_fix_plus_frozen_ai_observation_plus_public_pull_refs_"
            "no_golden_origin_read"
        )
    expanded = [dict(row) for row in hydrated]
    targets = [dict(row) for row in hydrated]
    seen_squashes: set[tuple[str, str]] = set()
    relations: list[dict[str, object]] = []
    roots: list[dict[str, object]] = []
    member_metadata: dict[tuple[str, str], dict[str, object]] = {}
    fix_changed_files: dict[tuple[str, str], list[str]] = {}
    internal_blame_evidence: defaultdict[
        tuple[str, str, str, str], list[dict[str, object]]
    ] = defaultdict(list)
    fetch_stats: list[dict[str, object]] = []
    depth_summaries: list[dict[str, object]] = []
    attempted_member_pairs = 0
    all_parent_candidates_retained = True
    depth_limit_targets: list[dict[str, object]] = []

    for depth in range(1, args.max_squash_depth + 1):
        active_targets = [
            row for row in targets if row.get("merge_topology") == "squash"
        ]
        if not active_targets:
            break
        active_keys = {
            (
                str(row.get("repository_identity") or "").strip().lower(),
                str(row.get("sha") or "").strip().lower(),
            )
            for row in active_targets
        }
        seen_squashes.update(active_keys)
        (
            depth_relations,
            depth_roots,
            depth_member_metadata,
            depth_fix_changed_files,
            depth_internal_blame,
            depth_fetch_stats,
        ) = _build_relations(
            active_targets,
            fixes,
            fetch=not args.no_fetch,
            fetch_batch=args.fetch_batch,
            timeout=args.repo_timeout,
        )
        for row in depth_relations:
            row["squash_depth"] = depth
        for row in depth_roots:
            row["squash_depth"] = depth
        for row in depth_fetch_stats:
            row["squash_depth"] = depth
        relations.extend(depth_relations)
        roots.extend(depth_roots)
        fetch_stats.extend(depth_fetch_stats)

        for key, metadata in depth_member_metadata.items():
            prior = member_metadata.get(key)
            if prior is not None and prior != metadata:
                raise SystemExit(
                    f"member metadata varies across squash depths: {key[0]}@{key[1]}"
                )
            member_metadata[key] = metadata
        for key, files in depth_fix_changed_files.items():
            prior = fix_changed_files.get(key)
            if prior is not None and prior != files:
                raise SystemExit(
                    f"fix metadata varies across squash depths: {key[0]}@{key[1]}"
                )
            fix_changed_files[key] = files
        for key, evidence_rows in depth_internal_blame.items():
            internal_blame_evidence[key].extend(evidence_rows)

        expansion = expand_squash_candidate_pairs(
            expanded,
            depth_relations,
            depth_member_metadata,
            depth_fix_changed_files,
            depth_internal_blame,
        )
        next_expanded = expansion["candidates"]
        assert isinstance(next_expanded, list)
        attempted_member_pairs += int(
            expansion["attempted_atomic_member_pair_count"]
        )
        all_parent_candidates_retained = bool(
            all_parent_candidates_retained
            and expansion["all_parent_candidate_pairs_retained"]
        )
        expanded = next_expanded
        next_targets = _nested_squash_targets(expanded, seen_squashes)
        depth_summaries.append(
            {
                "squash_depth": depth,
                "target_root_count": len(active_keys),
                "resolved_root_count": sum(
                    row.get("status") == "RESOLVED" for row in depth_roots
                ),
                "blocked_root_count": sum(
                    row.get("status") == "BLOCKED" for row in depth_roots
                ),
                "relation_count": len(depth_relations),
                "added_candidate_pair_count": int(
                    expansion["added_atomic_member_pair_count"]
                ),
                "next_nested_squash_pair_count": len(next_targets),
                "next_nested_squash_root_count": len(
                    {
                        (
                            str(row.get("repository_identity") or ""),
                            str(row.get("sha") or ""),
                        )
                        for row in next_targets
                    }
                ),
            }
        )
        if depth == args.max_squash_depth:
            depth_limit_targets = next_targets
            break
        targets = next_targets

    relations.sort(key=lambda row: str(row["relation_id"]))
    roots.sort(key=lambda row: str(row["root_id"]))
    fetch_stats.sort(
        key=lambda row: (
            int(row.get("squash_depth") or 0),
            str(row.get("repository_identity") or ""),
        )
    )
    recursive_scope_gaps = _depth_limit_scope_gaps(
        depth_limit_targets, args.max_squash_depth
    )

    blocked_reasons = Counter(
        str(root.get("reason") or "unspecified")
        for root in roots
        if root.get("status") == "BLOCKED"
    )
    resolved_count = sum(root.get("status") == "RESOLVED" for root in roots)
    blocked_count = sum(root.get("status") == "BLOCKED" for root in roots)
    relation_member_shas = {
        (str(row["repository_identity"]), str(row["origin_sha"])) for row in relations
    }
    member_signal_count = sum(
        member_metadata.get(key, {}).get("observed_ai_unit") is True
        for key in relation_member_shas
    )
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "proof_carrying_origin_squash_relation_closure",
        "split_id": parent_summary.get("split_id")
        or f"prospective-{parent_summary.get('advisory')}",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "generation_process_boundary": (
            generation_process_boundary
            + "_plus_bounded_recursive_public_pull_ref_closure"
        ),
        "parent_artifact_kind": parent_summary.get("artifact_kind"),
        "claim_boundary": (
            "Every parent candidate remains retained. Every real PR member recoverable "
            "from a public pull ref is added through an explicit landed-squash relation. "
            "A member is not claimed to be a mainline ancestor or individually AI-authored "
            "without member-level evidence. Exact pre-fix hunk context mapped to PR-head "
            "blame is ranking evidence, not by itself a causality verdict. Recovered "
            "members that are themselves landed squashes are recursively expanded up "
            "to the declared bound. Blocked roots and depth-limit gaps retain their "
            "landed squash as fail-open candidates."
        ),
        "parent_generation_sha256": canonical_sha256(parent_summary),
        "parent_candidate_inventory_sha256": canonical_sha256(parent_candidates),
        "hydrated_parent_candidate_inventory_sha256": canonical_sha256(hydrated),
        "fix_rows_sha256": canonical_sha256(fixes),
        "direct_candidate_pair_count": len(hydrated),
        "candidate_count": len(expanded),
        "added_atomic_member_pair_count": len(expanded) - len(hydrated),
        "attempted_atomic_member_pair_count": attempted_member_pairs,
        "collapsed_duplicate_member_pair_count": (
            attempted_member_pairs - (len(expanded) - len(hydrated))
        ),
        "max_squash_depth": args.max_squash_depth,
        "expanded_squash_depth_count": len(depth_summaries),
        "squash_depth_summaries": depth_summaries,
        "nested_squash_depth_limit_gap_count": len(recursive_scope_gaps),
        "squash_relation_root_count": len(roots),
        "resolved_squash_relation_root_count": resolved_count,
        "blocked_squash_relation_root_count": blocked_count,
        "recovered_atomic_member_count": len(relation_member_shas),
        "member_level_ai_signal_count": member_signal_count,
        "empty_atomic_member_count": sum(
            member_metadata.get(key, {}).get("empty_commit") is True
            for key in relation_member_shas
        ),
        "atomic_members_with_exact_fix_file_overlap": sum(
            row.get("merge_topology") == "pull_request_member"
            and int(row.get("fix_file_overlap_count") or 0) > 0
            for row in expanded
        ),
        "atomic_member_pairs_with_internal_fix_context_blame": sum(
            row.get("merge_topology") == "pull_request_member"
            and int(row.get("squash_internal_blame_line_count") or 0) > 0
            for row in expanded
        ),
        "internal_fix_context_blame_evidence_count": sum(
            int(row.get("squash_internal_blame_line_count") or 0)
            for row in expanded
            if row.get("merge_topology") == "pull_request_member"
        ),
        "squash_attribution_only_root_count": sum(
            root.get("squash_attribution_only") is True for root in roots
        ),
        "relation_count": len(relations),
        "blocked_relation_root_reasons": dict(sorted(blocked_reasons.items())),
        "fetch_enabled": not args.no_fetch,
        "fetch_stats": fetch_stats,
        "all_parent_candidates_retained": all_parent_candidates_retained,
        "all_relation_roots_conserved": len(roots) == resolved_count + blocked_count,
        "candidate_rows_sha256": canonical_sha256(expanded),
        "relations_sha256": canonical_sha256(relations),
        "relation_roots_sha256": canonical_sha256(roots),
        "gate_status": (
            "READY"
            if blocked_count == 0 and not recursive_scope_gaps
            else "READY_WITH_BLOCKED_SQUASH_FALLBACKS"
        ),
        "negative_disposition": "DEFER_not_delete",
        "blocked_disposition": "RETAIN_landed_squash",
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
    }
    if (
        not summary["all_parent_candidates_retained"]
        or not summary["all_relation_roots_conserved"]
    ):
        raise SystemExit("squash expansion conservation failed")

    certificates_path = source_dir / "exclusion_certificates.jsonl"
    scope_gaps_path = source_dir / "scope_gaps.jsonl"
    certificates = _load_jsonl(certificates_path) if certificates_path.is_file() else []
    scope_gaps = _load_jsonl(scope_gaps_path) if scope_gaps_path.is_file() else []
    scope_gaps.extend(recursive_scope_gaps)
    scope_gaps.sort(
        key=lambda row: (
            str(row.get("advisory") or ""),
            str(row.get("repository_identity") or ""),
            str(row.get("fix_sha") or ""),
            str(row.get("candidate_sha") or row.get("sha") or ""),
            str(row.get("gap_id") or ""),
        )
    )
    args.output_dir.mkdir(parents=True)
    _atomic_jsonl(args.output_dir / "candidates.jsonl", expanded)
    _atomic_jsonl(args.output_dir / "fixes.jsonl", fixes)
    _atomic_jsonl(args.output_dir / "relations.jsonl", relations)
    _atomic_jsonl(args.output_dir / "relation_roots.jsonl", roots)
    _atomic_jsonl(args.output_dir / "exclusion_certificates.jsonl", certificates)
    _atomic_jsonl(args.output_dir / "scope_gaps.jsonl", scope_gaps)
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
