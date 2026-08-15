#!/usr/bin/env python3
"""Bridge Coolify source ownership to exact candidate/fix delta reversals.

The preimage overlay proves that an observed-AI commit owns state immediately
before a later repair.  Ownership alone is intentionally broad: generated
files, copied lines, and incidental edits can all receive blame.  This overlay
adds two stronger, deterministic scheduling signals without filtering anything:

* a candidate-added line is later removed by the fix; and
* a candidate-removed line is later restored by the fix.

Whitespace-normalized and cross-path matches remain visible as weaker rescue
lanes.  Every source-owner edge is emitted exactly once, and Git inspection
failures remain explicit retry evidence rather than negative labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from cohort_coolify_fix_preimage_lineage import (
    LineageEvidenceError,
    _git_text,
)
from cohort_ai_descendant_preimage_overlay import (
    _assignment_counts,
    _repository_for_commit,
)


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_ADJUDICATED_STATUSES = frozenset(
    {
        "CONFIRMED_TRUE_POSITIVE",
        "PATCH_EQUIVALENT_ALIAS",
        "REJECTED_NONCAUSAL",
    }
)
_CONTROL_RE = re.compile(
    r"(?:\b(?:if|unless|throw|abort|deny|reject|validate|authorize|forbid|"
    r"permission|policy|guard|sanitize|escape|filter|where|tenant|team|auth|"
    r"csrf|token|secret|status)\b|\?\.|===|!==|>=|<=|&&|\|\|)",
    re.IGNORECASE,
)
_GENERATED_BASENAMES = frozenset(
    {
        "composer.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
        "cargo.lock",
        "poetry.lock",
        "uv.lock",
    }
)
_BRIDGE_BONUS = {
    "B0_BIDIRECTIONAL_EXACT_REVERSAL": 5_500,
    "B0_CANDIDATE_REMOVAL_EXACTLY_RESTORED": 4_700,
    "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED": 4_400,
    "B1_WHITESPACE_NORMALIZED_REVERSAL": 2_900,
    "B2_EXACT_ADDED_PREIMAGE_PERSISTENCE": 2_100,
    "B3_EXACT_GUARD_METHOD_INTRODUCTION": 1_350,
    "B4_EXACT_CROSS_PATH_RESCUE": 750,
    "B5_SOURCE_OWNER_ONLY_RETAINED": 0,
}


class DeltaBridgeError(ValueError):
    """The source overlay or exact-delta conservation contract is malformed."""


@dataclass(frozen=True)
class DeltaLine:
    parent_sha: str
    path: str
    content: str

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def normalized(self) -> str:
        return " ".join(self.content.strip().split())

    @property
    def normalized_sha256(self) -> str:
        return hashlib.sha256(self.normalized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CommitDelta:
    sha: str
    parents: tuple[str, ...]
    compared_parents: tuple[str, ...]
    additions: tuple[DeltaLine, ...]
    removals: tuple[DeltaLine, ...]
    binary_paths: tuple[str, ...] = ()
    coverage_gaps: tuple[str, ...] = ()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        action="append",
        required=True,
        help=(
            "Git checkout containing part or all of the frozen commit universe; "
            "repeat for non-nested clones"
        ),
    )
    parser.add_argument("--preimage-overlay-dir", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--repo-timeout", type=int, default=120)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeltaBridgeError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DeltaBridgeError(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise DeltaBridgeError(
                        f"{path}:{line_number} must contain an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise DeltaBridgeError(f"cannot load {path}: {exc}") from exc
    return rows


def _validate_declared_repositories(
    preimage_summary: Mapping[str, object], repositories: Sequence[Path]
) -> None:
    """Require the bridge to use the same clone union frozen by the overlay."""

    declared = set(repositories)
    if len(declared) != len(repositories):
        raise DeltaBridgeError("duplicate --repository clone")
    raw_configuration = preimage_summary.get("configuration")
    if raw_configuration is None:
        return
    if not isinstance(raw_configuration, Mapping):
        raise DeltaBridgeError("preimage configuration is malformed")
    raw_repositories = raw_configuration.get("repositories")
    if raw_repositories is None:
        return
    if not isinstance(raw_repositories, list) or not all(
        isinstance(value, str) and value for value in raw_repositories
    ):
        raise DeltaBridgeError("preimage repository union is malformed")
    expected = {Path(value).resolve() for value in raw_repositories}
    if len(expected) != len(raw_repositories):
        raise DeltaBridgeError("preimage repository union contains duplicates")
    if declared != expected:
        missing = sorted(str(path) for path in expected - declared)
        extra = sorted(str(path) for path in declared - expected)
        raise DeltaBridgeError(
            "declared repository clones disagree with preimage overlay: "
            f"missing={missing}, extra={extra}"
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: object) -> None:
    _atomic_jsonl(path, [value], pretty=True)


def _atomic_jsonl(
    path: Path, rows: Iterable[object], *, pretty: bool = False
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise DeltaBridgeError(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if pretty:
                materialized = list(rows)
                if len(materialized) != 1:
                    raise DeltaBridgeError("pretty output requires exactly one value")
                json.dump(
                    materialized[0],
                    handle,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
                handle.write("\n")
            else:
                for row in rows:
                    handle.write(
                        json.dumps(
                            row,
                            sort_keys=True,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                    )
                    handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _unquote_diff_path(raw: str) -> str | None:
    value = raw.strip()
    if value == "/dev/null":
        return None
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = value[1:-1]
        value = str(decoded)
    if value.startswith(("a/", "b/")):
        value = value[2:]
    return value


def _parse_unified_patch(
    patch: str, *, parent_sha: str
) -> tuple[tuple[DeltaLine, ...], tuple[DeltaLine, ...], tuple[str, ...]]:
    additions: list[DeltaLine] = []
    removals: list[DeltaLine] = []
    binary_paths: set[str] = set()
    current_path: str | None = None
    header_path: str | None = None
    in_hunk = False
    for raw_line in patch.splitlines():
        if raw_line.startswith("diff --git "):
            current_path = None
            header_path = None
            in_hunk = False
            continue
        if not in_hunk and raw_line.startswith("+++ "):
            current_path = _unquote_diff_path(raw_line[4:])
            continue
        if not in_hunk and raw_line.startswith("--- "):
            header_path = _unquote_diff_path(raw_line[4:])
            continue
        if not in_hunk and raw_line.startswith("Binary files "):
            binary_path = current_path or header_path
            if binary_path:
                binary_paths.add(binary_path)
            continue
        if raw_line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk or raw_line.startswith("\\ No newline at end of file"):
            continue
        if raw_line.startswith("+") and current_path is not None:
            additions.append(DeltaLine(parent_sha, current_path, raw_line[1:]))
        elif raw_line.startswith("-") and header_path is not None:
            removals.append(DeltaLine(parent_sha, header_path, raw_line[1:]))
    return tuple(additions), tuple(removals), tuple(sorted(binary_paths))


def _revision_parents(repository: Path, sha: str, *, timeout: int) -> tuple[str, ...]:
    line = _git_text(
        repository, ["rev-list", "--parents", "-n", "1", sha], timeout=timeout
    ).strip()
    fields = line.split()
    if not fields or fields[0] != sha or any(
        not _FULL_SHA_RE.fullmatch(value) for value in fields
    ):
        raise LineageEvidenceError(f"malformed revision ancestry for {sha}")
    return tuple(fields[1:])


def _inspect_commit_delta(
    repository: Path,
    sha: str,
    *,
    compare_all_parents: bool,
    timeout: int,
) -> CommitDelta:
    try:
        parents = _revision_parents(repository, sha, timeout=timeout)
    except LineageEvidenceError as exc:
        return CommitDelta(sha, (), (), (), (), coverage_gaps=(str(exc),))
    compared = parents if compare_all_parents else parents[:1]
    if not compared:
        compared = (_EMPTY_TREE_SHA,)
    additions: list[DeltaLine] = []
    removals: list[DeltaLine] = []
    binary_paths: set[str] = set()
    gaps: list[str] = []
    for parent in compared:
        try:
            patch = _git_text(
                repository,
                [
                    "-c",
                    "core.quotePath=false",
                    "diff",
                    "--unified=0",
                    "--no-color",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--find-renames",
                    "--find-copies",
                    parent,
                    sha,
                    "--",
                ],
                timeout=timeout,
            )
        except LineageEvidenceError as exc:
            gaps.append(f"parent {parent}: {exc}")
            continue
        added, removed, binary = _parse_unified_patch(patch, parent_sha=parent)
        additions.extend(added)
        removals.extend(removed)
        binary_paths.update(binary)
    return CommitDelta(
        sha=sha,
        parents=parents,
        compared_parents=compared,
        additions=tuple(additions),
        removals=tuple(removals),
        binary_paths=tuple(sorted(binary_paths)),
        coverage_gaps=tuple(gaps),
    )


def _meaningful(content: str) -> bool:
    stripped = content.strip()
    if not stripped:
        return False
    return re.fullmatch(r"[{}\[\](),;:.<>/?'\"`+-]+", stripped) is None


def _control_like(content: str) -> bool:
    return bool(_CONTROL_RE.search(content))


def _generated_path(source_path: str) -> bool:
    normalized = source_path.casefold().lstrip("./")
    basename = normalized.rsplit("/", 1)[-1]
    return (
        basename in _GENERATED_BASENAMES
        or basename in {"openapi.json", "openapi.yaml", "openapi.yml"}
        or normalized.startswith(("dist/", "build/", "public/build/"))
        or "/generated/" in f"/{normalized}/"
        or "/snapshots/" in f"/{normalized}/"
        or basename.endswith((".min.js", ".min.css"))
    )


def _line_key(line: DeltaLine, *, normalized: bool) -> tuple[str, str]:
    digest = line.normalized_sha256 if normalized else line.content_sha256
    return line.path, digest


def _line_index(
    lines: Iterable[DeltaLine], *, normalized: bool
) -> tuple[dict[tuple[str, str], list[DeltaLine]], dict[str, list[DeltaLine]]]:
    by_path: defaultdict[tuple[str, str], list[DeltaLine]] = defaultdict(list)
    by_digest: defaultdict[str, list[DeltaLine]] = defaultdict(list)
    for line in lines:
        digest = line.normalized_sha256 if normalized else line.content_sha256
        by_path[(line.path, digest)].append(line)
        by_digest[digest].append(line)
    return dict(by_path), dict(by_digest)


@dataclass(frozen=True)
class _CachedLineIndex:
    exact_by_path: Mapping[tuple[str, str], tuple[DeltaLine, ...]]
    normalized_by_path: Mapping[tuple[str, str], tuple[DeltaLine, ...]]
    exact_by_digest: Mapping[str, tuple[DeltaLine, ...]]
    positions: Mapping[int, int]


def _cached_line_index(lines: Sequence[DeltaLine]) -> _CachedLineIndex:
    exact_by_path: defaultdict[tuple[str, str], list[DeltaLine]] = defaultdict(list)
    normalized_by_path: defaultdict[tuple[str, str], list[DeltaLine]] = defaultdict(
        list
    )
    exact_by_digest: defaultdict[str, list[DeltaLine]] = defaultdict(list)
    positions: dict[int, int] = {}
    for position, line in enumerate(lines):
        exact_by_path[(line.path, line.content_sha256)].append(line)
        normalized_by_path[(line.path, line.normalized_sha256)].append(line)
        exact_by_digest[line.content_sha256].append(line)
        positions[id(line)] = position
    return _CachedLineIndex(
        exact_by_path={key: tuple(value) for key, value in exact_by_path.items()},
        normalized_by_path={
            key: tuple(value) for key, value in normalized_by_path.items()
        },
        exact_by_digest={key: tuple(value) for key, value in exact_by_digest.items()},
        positions=positions,
    )


def _delta_match_row(
    left_line: DeltaLine,
    right_line: DeltaLine,
    *,
    direction: str,
    match_kind: str,
) -> dict[str, object]:
    return {
        "direction": direction,
        "match_kind": match_kind,
        "candidate_path": left_line.path,
        "fix_path": right_line.path,
        "content_sha256": left_line.content_sha256,
        "normalized_sha256": left_line.normalized_sha256,
        "content_excerpt": (
            left_line.normalized[:179] + "…"
            if len(left_line.normalized) > 180
            else left_line.normalized
        ),
        "meaningful": _meaningful(left_line.content),
        "control_like": _control_like(left_line.content),
        "generated_or_machine_artifact": (
            _generated_path(left_line.path) or _generated_path(right_line.path)
        ),
    }


def _cached_delta_matches(
    left: _CachedLineIndex,
    right: _CachedLineIndex,
    *,
    direction: str,
) -> list[dict[str, object]]:
    """Match two prebuilt indexes without rescanning broad commit deltas."""

    matches: dict[tuple[object, ...], dict[str, object]] = {}

    def record(left_line: DeltaLine, right_line: DeltaLine, kind: str) -> None:
        key = (
            direction,
            kind,
            left_line.path,
            right_line.path,
            left_line.normalized_sha256,
        )
        matches[key] = _delta_match_row(
            left_line,
            right_line,
            direction=direction,
            match_kind=kind,
        )

    exact_keys = set(left.exact_by_path) & set(right.exact_by_path)
    exact_records = [
        (left.exact_by_path[key][-1], right.exact_by_path[key][0])
        for key in exact_keys
    ]
    for left_line, right_line in sorted(
        exact_records, key=lambda value: left.positions[id(value[0])]
    ):
        record(left_line, right_line, "exact_same_path")

    normalized_keys = set(left.normalized_by_path) & set(
        right.normalized_by_path
    )
    normalized_left_ids: set[int] = set()
    normalized_records: list[tuple[DeltaLine, DeltaLine]] = []
    for key in normalized_keys:
        right_lines = right.normalized_by_path[key]
        eligible: list[tuple[DeltaLine, DeltaLine]] = []
        for left_line in left.normalized_by_path[key]:
            if (left_line.path, left_line.content_sha256) in right.exact_by_path:
                continue
            right_line = next(
                (
                    value
                    for value in right_lines
                    if value.content_sha256 != left_line.content_sha256
                ),
                None,
            )
            if right_line is not None and left_line.normalized:
                eligible.append((left_line, right_line))
        if eligible:
            selected = max(eligible, key=lambda value: left.positions[id(value[0])])
            normalized_records.append(selected)
            normalized_left_ids.add(id(selected[0]))
    for left_line, right_line in sorted(
        normalized_records, key=lambda value: left.positions[id(value[0])]
    ):
        record(left_line, right_line, "normalized_same_path")

    common_digests = set(left.exact_by_digest) & set(right.exact_by_digest)
    cross_records: list[tuple[DeltaLine, DeltaLine]] = []
    for digest in common_digests:
        right_lines = right.exact_by_digest[digest]
        for left_line in left.exact_by_digest[digest]:
            if (left_line.path, digest) in right.exact_by_path:
                continue
            norm_key = (left_line.path, left_line.normalized_sha256)
            normalized_same = [
                value
                for value in right.normalized_by_path.get(norm_key, ())
                if value.content_sha256 != left_line.content_sha256
            ]
            if normalized_same and left_line.normalized:
                continue
            right_line = next(
                (value for value in right_lines if value.path != left_line.path),
                None,
            )
            if right_line is not None and id(left_line) not in normalized_left_ids:
                cross_records.append((left_line, right_line))
    for left_line, right_line in sorted(
        cross_records, key=lambda value: left.positions[id(value[0])]
    ):
        record(left_line, right_line, "exact_cross_path")

    return sorted(
        matches.values(),
        key=lambda row: (
            str(row["match_kind"]),
            str(row["candidate_path"]),
            str(row["fix_path"]),
            str(row["content_sha256"]),
        ),
    )


def _cached_source_addition_matches(
    evidence_rows: Sequence[Mapping[str, object]],
    candidate_additions: _CachedLineIndex,
) -> list[dict[str, object]]:
    matches: dict[tuple[object, ...], dict[str, object]] = {}
    for evidence in evidence_rows:
        digest = str(evidence.get("content_sha256") or "")
        source_path = str(evidence.get("path") or "")
        line_kind = str(evidence.get("line_kind") or "")
        if not digest or not source_path:
            continue
        additions = candidate_additions.exact_by_path.get((source_path, digest), ())
        match_kind = "exact_same_path"
        if not additions:
            additions = tuple(
                line
                for line in candidate_additions.exact_by_digest.get(digest, ())
                if line.path != source_path
            )
            match_kind = "exact_cross_path"
        if not additions:
            continue
        addition = additions[0]
        key = (line_kind, match_kind, source_path, addition.path, digest)
        matches[key] = {
            "line_kind": line_kind,
            "match_kind": match_kind,
            "source_path": source_path,
            "candidate_added_path": addition.path,
            "content_sha256": digest,
            "content_excerpt": (
                addition.normalized[:179] + "…"
                if len(addition.normalized) > 180
                else addition.normalized
            ),
            "meaningful": _meaningful(addition.content),
            "guard_like_hunk": evidence.get("guard_like_hunk") is True,
            "generated_or_machine_artifact": (
                _generated_path(source_path) or _generated_path(addition.path)
            ),
        }
    return sorted(
        matches.values(),
        key=lambda row: (
            str(row["line_kind"]),
            str(row["match_kind"]),
            str(row["source_path"]),
            str(row["content_sha256"]),
        ),
    )


def _delta_matches(
    left: Sequence[DeltaLine],
    right: Sequence[DeltaLine],
    *,
    direction: str,
) -> list[dict[str, object]]:
    right_exact_path, right_exact_any = _line_index(right, normalized=False)
    right_norm_path, _ = _line_index(right, normalized=True)
    matches: dict[tuple[object, ...], dict[str, object]] = {}
    for left_line in left:
        exact_same = right_exact_path.get(_line_key(left_line, normalized=False), [])
        if exact_same:
            match_kind = "exact_same_path"
            right_line = exact_same[0]
        else:
            normalized_same = right_norm_path.get(
                _line_key(left_line, normalized=True), []
            )
            normalized_same = [
                line
                for line in normalized_same
                if line.content_sha256 != left_line.content_sha256
            ]
            if normalized_same and left_line.normalized:
                match_kind = "normalized_same_path"
                right_line = normalized_same[0]
            else:
                cross = [
                    line
                    for line in right_exact_any.get(left_line.content_sha256, [])
                    if line.path != left_line.path
                ]
                if not cross:
                    continue
                match_kind = "exact_cross_path"
                right_line = cross[0]
        key = (
            direction,
            match_kind,
            left_line.path,
            right_line.path,
            left_line.normalized_sha256,
        )
        matches[key] = {
            "direction": direction,
            "match_kind": match_kind,
            "candidate_path": left_line.path,
            "fix_path": right_line.path,
            "content_sha256": left_line.content_sha256,
            "normalized_sha256": left_line.normalized_sha256,
            "content_excerpt": (
                left_line.normalized[:179] + "…"
                if len(left_line.normalized) > 180
                else left_line.normalized
            ),
            "meaningful": _meaningful(left_line.content),
            "control_like": _control_like(left_line.content),
            "generated_or_machine_artifact": (
                _generated_path(left_line.path) or _generated_path(right_line.path)
            ),
        }
    return sorted(
        matches.values(),
        key=lambda row: (
            str(row["match_kind"]),
            str(row["candidate_path"]),
            str(row["fix_path"]),
            str(row["content_sha256"]),
        ),
    )


def _source_addition_matches(
    evidence_rows: Sequence[Mapping[str, object]],
    candidate_additions: Sequence[DeltaLine],
) -> list[dict[str, object]]:
    by_path, by_digest = _line_index(candidate_additions, normalized=False)
    matches: dict[tuple[object, ...], dict[str, object]] = {}
    for evidence in evidence_rows:
        digest = str(evidence.get("content_sha256") or "")
        source_path = str(evidence.get("path") or "")
        line_kind = str(evidence.get("line_kind") or "")
        if not digest or not source_path:
            continue
        additions = by_path.get((source_path, digest), [])
        match_kind = "exact_same_path"
        if not additions:
            additions = [
                line for line in by_digest.get(digest, []) if line.path != source_path
            ]
            match_kind = "exact_cross_path"
        if not additions:
            continue
        addition = additions[0]
        key = (line_kind, match_kind, source_path, addition.path, digest)
        matches[key] = {
            "line_kind": line_kind,
            "match_kind": match_kind,
            "source_path": source_path,
            "candidate_added_path": addition.path,
            "content_sha256": digest,
            "content_excerpt": (
                addition.normalized[:179] + "…"
                if len(addition.normalized) > 180
                else addition.normalized
            ),
            "meaningful": _meaningful(addition.content),
            "guard_like_hunk": evidence.get("guard_like_hunk") is True,
            "generated_or_machine_artifact": (
                _generated_path(source_path) or _generated_path(addition.path)
            ),
        }
    return sorted(
        matches.values(),
        key=lambda row: (
            str(row["line_kind"]),
            str(row["match_kind"]),
            str(row["source_path"]),
            str(row["content_sha256"]),
        ),
    )


def _count_matches(
    rows: Sequence[Mapping[str, object]],
    *,
    match_kind: str | None = None,
    meaningful: bool | None = None,
    direction: str | None = None,
) -> int:
    return sum(
        (match_kind is None or row.get("match_kind") == match_kind)
        and (meaningful is None or row.get("meaningful") is meaningful)
        and (direction is None or row.get("direction") == direction)
        for row in rows
    )


def _bridge_class(
    delta_matches: Sequence[Mapping[str, object]],
    source_matches: Sequence[Mapping[str, object]],
) -> tuple[int, str]:
    forward = _count_matches(
        delta_matches,
        match_kind="exact_same_path",
        meaningful=True,
        direction="candidate_added_fix_removed",
    )
    reverse = _count_matches(
        delta_matches,
        match_kind="exact_same_path",
        meaningful=True,
        direction="candidate_removed_fix_added",
    )
    normalized = _count_matches(
        delta_matches, match_kind="normalized_same_path", meaningful=True
    )
    direct_source = sum(
        row.get("line_kind") == "direct_preimage"
        and row.get("match_kind") == "exact_same_path"
        and row.get("meaningful") is True
        for row in source_matches
    )
    guard_method = sum(
        row.get("line_kind") == "method_signature"
        and row.get("match_kind") == "exact_same_path"
        and row.get("guard_like_hunk") is True
        and row.get("meaningful") is True
        for row in source_matches
    )
    cross_path = _count_matches(
        delta_matches, match_kind="exact_cross_path", meaningful=True
    ) + sum(
        row.get("match_kind") == "exact_cross_path"
        and row.get("meaningful") is True
        for row in source_matches
    )
    if forward and reverse:
        return 0, "B0_BIDIRECTIONAL_EXACT_REVERSAL"
    if reverse:
        return 0, "B0_CANDIDATE_REMOVAL_EXACTLY_RESTORED"
    if forward:
        return 0, "B0_CANDIDATE_ADDITION_EXACTLY_REMOVED"
    if normalized:
        return 1, "B1_WHITESPACE_NORMALIZED_REVERSAL"
    if direct_source:
        return 2, "B2_EXACT_ADDED_PREIMAGE_PERSISTENCE"
    if guard_method:
        return 3, "B3_EXACT_GUARD_METHOD_INTRODUCTION"
    if cross_path:
        return 4, "B4_EXACT_CROSS_PATH_RESCUE"
    return 5, "B5_SOURCE_OWNER_ONLY_RETAINED"


def _delta_summary(delta: CommitDelta) -> dict[str, object]:
    paths = sorted(
        {line.path for line in (*delta.additions, *delta.removals)}
        | set(delta.binary_paths)
    )
    changed_line_count = len(delta.additions) + len(delta.removals)
    return {
        "parent_count": len(delta.parents),
        "compared_parent_count": len(delta.compared_parents),
        "compared_parents": list(delta.compared_parents),
        "changed_path_count": len(paths),
        "added_line_count": len(delta.additions),
        "removed_line_count": len(delta.removals),
        "binary_paths": list(delta.binary_paths),
        "coverage_gaps": list(delta.coverage_gaps),
        "inspection_complete": not delta.coverage_gaps,
        "carrier_risk": len(paths) > 25 or changed_line_count > 2_000,
    }


def _ledger_state(
    ledger: Mapping[str, object],
) -> tuple[dict[tuple[str, str], str], set[str]]:
    raw_rows = ledger.get("edge_ledger")
    if not isinstance(raw_rows, list):
        raise DeltaBridgeError("ledger edge_ledger is malformed")
    status_by_edge: dict[tuple[str, str], str] = {}
    confirmed_candidates: set[str] = set()
    for row in raw_rows:
        if not isinstance(row, Mapping):
            raise DeltaBridgeError("ledger contains a non-object edge row")
        edge = (str(row.get("candidate_sha") or ""), str(row.get("fix_sha") or ""))
        status = str(row.get("status") or "")
        status_by_edge[edge] = status
        if status == "CONFIRMED_TRUE_POSITIVE":
            confirmed_candidates.add(edge[0])
    return status_by_edge, confirmed_candidates


def _pair_score(
    source_pair: Mapping[str, object],
    *,
    bridge_class: str,
    delta_matches: Sequence[Mapping[str, object]],
    source_matches: Sequence[Mapping[str, object]],
    candidate_summary: Mapping[str, object],
    fix_summary: Mapping[str, object],
    edge_status: str,
    candidate_confirmed_elsewhere: bool,
) -> tuple[int, list[str]]:
    score = int(source_pair.get("review_priority_score") or 0)
    reasons = [f"source_owner_score:{score}"]
    bonus = _BRIDGE_BONUS[bridge_class]
    score += bonus
    reasons.append(f"delta_bridge:{bridge_class}:{bonus}")
    meaningful_exact = _count_matches(
        delta_matches, match_kind="exact_same_path", meaningful=True
    )
    line_bonus = min(meaningful_exact, 12) * 55
    score += line_bonus
    if line_bonus:
        reasons.append(f"meaningful_exact_line_bonus:{line_bonus}")
    control_count = sum(
        row.get("control_like") is True
        and row.get("match_kind") == "exact_same_path"
        for row in delta_matches
    )
    control_bonus = min(control_count, 6) * 90
    score += control_bonus
    if control_bonus:
        reasons.append(f"control_line_bonus:{control_bonus}")
    evidence_rows = [*delta_matches, *source_matches]
    meaningful_evidence = [row for row in evidence_rows if row.get("meaningful")]
    generated_only = bool(meaningful_evidence) and all(
        row.get("generated_or_machine_artifact") is True
        for row in meaningful_evidence
    )
    if generated_only:
        score -= 2_400
        reasons.append("generated_or_machine_artifact_only_penalty:2400")
    if candidate_summary.get("carrier_risk") is True:
        score -= 650
        reasons.append("candidate_carrier_penalty:650")
    if candidate_summary.get("inspection_complete") is not True:
        score -= 120
        reasons.append("candidate_delta_retry_penalty:120")
    if fix_summary.get("inspection_complete") is not True:
        score -= 120
        reasons.append("fix_delta_retry_penalty:120")
    if not candidate_confirmed_elsewhere:
        score += 500
        reasons.append("new_unique_candidate_opportunity:500")
    if edge_status == "CONFIRMED_TRUE_POSITIVE":
        score -= 20_000
        reasons.append("already_confirmed_edge_penalty:20000")
    elif edge_status == "REJECTED_NONCAUSAL":
        score -= 12_000
        reasons.append("already_rejected_edge_penalty:12000")
    return score, reasons


def _recall_at_budget(
    frontier: Sequence[Mapping[str, object]], confirmed_candidates: set[str]
) -> list[dict[str, object]]:
    present_confirmed = {
        str(row["candidate_sha"])
        for row in frontier
        if str(row["candidate_sha"]) in confirmed_candidates
    }
    budgets = [10, 25, 50, 100, 200, len(frontier)]
    result: list[dict[str, object]] = []
    for budget in dict.fromkeys(min(value, len(frontier)) for value in budgets):
        prefix = frontier[:budget]
        recovered = {
            str(row["candidate_sha"])
            for row in prefix
            if str(row["candidate_sha"]) in present_confirmed
        }
        result.append(
            {
                "budget": budget,
                "scheduled_unique_candidate_count": len(prefix),
                "exact_reversal_edge_count": sum(
                    int(row.get("delta_bridge_tier", 5)) <= 1 for row in prefix
                ),
                "known_confirmed_candidate_count": len(recovered),
                "known_confirmed_candidate_recall": (
                    len(recovered) / len(present_confirmed)
                    if present_confirmed
                    else None
                ),
                "known_confirmed_candidate_denominator": len(present_confirmed),
            }
        )
    return result


def build_delta_bridge(
    *,
    preimage_summary: Mapping[str, object],
    source_pairs: list[dict[str, object]],
    root_evidence: list[dict[str, object]],
    ledger: Mapping[str, object],
    candidate_deltas: Mapping[str, CommitDelta],
    fix_deltas: Mapping[str, CommitDelta],
    split_id: str,
) -> dict[str, object]:
    if preimage_summary.get("all_source_pairs_conserved") is not True:
        raise DeltaBridgeError("input preimage overlay is not lossless")
    if int(preimage_summary.get("hard_filter_count", -1)) != 0:
        raise DeltaBridgeError("input preimage overlay used a hard filter")
    expected_count = int(preimage_summary.get("strict_source_owner_pair_count") or -1)
    if expected_count != len(source_pairs):
        raise DeltaBridgeError("source-owner pair count disagrees with summary")
    source_edges = [
        (str(row.get("candidate_sha") or ""), str(row.get("fix_sha") or ""))
        for row in source_pairs
    ]
    if len(set(source_edges)) != len(source_edges) or any(
        not _FULL_SHA_RE.fullmatch(value) for edge in source_edges for value in edge
    ):
        raise DeltaBridgeError("source-owner edges are duplicate or malformed")
    expected_candidates = {edge[0] for edge in source_edges}
    expected_fixes = {edge[1] for edge in source_edges}
    if set(candidate_deltas) != expected_candidates:
        raise DeltaBridgeError("candidate delta coverage is not exact")
    if set(fix_deltas) != expected_fixes:
        raise DeltaBridgeError("fix delta coverage is not exact")
    root_parent_by_fix = {
        str(row.get("fix_sha") or ""): str(row.get("parent_sha") or "")
        for row in root_evidence
        if str(row.get("fix_sha") or "") in expected_fixes
    }
    if set(root_parent_by_fix) != expected_fixes:
        raise DeltaBridgeError("root evidence does not cover every source-owner fix")
    for fix_sha, expected_parent in root_parent_by_fix.items():
        delta = fix_deltas[fix_sha]
        if delta.parents and delta.parents[0] != expected_parent:
            raise DeltaBridgeError(f"fix parent drift for {fix_sha}")

    status_by_edge, confirmed_candidates = _ledger_state(ledger)
    candidate_addition_indexes = {
        sha: _cached_line_index(delta.additions)
        for sha, delta in candidate_deltas.items()
    }
    candidate_removal_indexes = {
        sha: _cached_line_index(delta.removals)
        for sha, delta in candidate_deltas.items()
    }
    fix_addition_indexes = {
        sha: _cached_line_index(delta.additions) for sha, delta in fix_deltas.items()
    }
    fix_removal_indexes = {
        sha: _cached_line_index(delta.removals) for sha, delta in fix_deltas.items()
    }
    rows: list[dict[str, object]] = []
    for source_index, source_pair in enumerate(source_pairs, start=1):
        candidate_sha = str(source_pair["candidate_sha"])
        fix_sha = str(source_pair["fix_sha"])
        candidate_delta = candidate_deltas[candidate_sha]
        fix_delta = fix_deltas[fix_sha]
        forward = _cached_delta_matches(
            candidate_addition_indexes[candidate_sha],
            fix_removal_indexes[fix_sha],
            direction="candidate_added_fix_removed",
        )
        reverse = _cached_delta_matches(
            candidate_removal_indexes[candidate_sha],
            fix_addition_indexes[fix_sha],
            direction="candidate_removed_fix_added",
        )
        delta_matches = [*forward, *reverse]
        raw_evidence = source_pair.get("matched_line_evidence")
        if not isinstance(raw_evidence, list) or not all(
            isinstance(value, Mapping) for value in raw_evidence
        ):
            raise DeltaBridgeError(f"malformed source evidence for {candidate_sha}")
        source_matches = _cached_source_addition_matches(
            raw_evidence, candidate_addition_indexes[candidate_sha]
        )
        bridge_tier, bridge_class = _bridge_class(delta_matches, source_matches)
        candidate_summary = _delta_summary(candidate_delta)
        fix_summary = _delta_summary(fix_delta)
        edge = (candidate_sha, fix_sha)
        edge_status = status_by_edge.get(
            edge, str(source_pair.get("ledger_edge_status") or "NEW_SOURCE_OWNER_EDGE")
        )
        candidate_confirmed = candidate_sha in confirmed_candidates
        score, reasons = _pair_score(
            source_pair,
            bridge_class=bridge_class,
            delta_matches=delta_matches,
            source_matches=source_matches,
            candidate_summary=candidate_summary,
            fix_summary=fix_summary,
            edge_status=edge_status,
            candidate_confirmed_elsewhere=candidate_confirmed,
        )
        meaningful_evidence = [
            row for row in [*delta_matches, *source_matches] if row.get("meaningful")
        ]
        generated_only = bool(meaningful_evidence) and all(
            row.get("generated_or_machine_artifact") is True
            for row in meaningful_evidence
        )
        rows.append(
            {
                "candidate_sha": candidate_sha,
                "candidate_subject": source_pair.get("candidate_subject"),
                "candidate_authored_at": source_pair.get("candidate_authored_at"),
                "fix_sha": fix_sha,
                "fix_subject": source_pair.get("fix_subject"),
                "fix_authored_at": source_pair.get("fix_authored_at"),
                "fix_review_lane": source_pair.get("fix_review_lane"),
                "source_pair_index": source_index,
                "source_pair_sha256": _canonical_sha256(source_pair),
                "source_priority_tier": source_pair.get("priority_tier"),
                "source_priority_class": source_pair.get("priority_class"),
                "source_review_priority_rank": source_pair.get(
                    "review_priority_rank"
                ),
                "delta_bridge_tier": bridge_tier,
                "delta_bridge_class": bridge_class,
                "delta_bridge_score": score,
                "delta_bridge_score_reasons": reasons,
                "delta_match_counts": dict(
                    sorted(
                        Counter(
                            f"{row['direction']}:{row['match_kind']}"
                            for row in delta_matches
                        ).items()
                    )
                ),
                "meaningful_exact_same_path_delta_count": _count_matches(
                    delta_matches,
                    match_kind="exact_same_path",
                    meaningful=True,
                ),
                "control_like_exact_same_path_delta_count": sum(
                    row.get("control_like") is True
                    and row.get("match_kind") == "exact_same_path"
                    for row in delta_matches
                ),
                "source_addition_match_counts": dict(
                    sorted(
                        Counter(
                            f"{row['line_kind']}:{row['match_kind']}"
                            for row in source_matches
                        ).items()
                    )
                ),
                "delta_match_evidence": delta_matches[:24],
                "source_addition_evidence": source_matches[:24],
                "delta_match_evidence_truncated": len(delta_matches) > 24,
                "source_addition_evidence_truncated": len(source_matches) > 24,
                "generated_or_machine_artifact_only": generated_only,
                "candidate_delta": candidate_summary,
                "fix_delta": fix_summary,
                "ledger_edge_status": edge_status,
                "candidate_already_confirmed_elsewhere": candidate_confirmed,
                "retained": True,
                "delta_bridge_rank": None,
            }
        )

    rows.sort(
        key=lambda row: (
            -int(row["delta_bridge_score"]),
            int(row["delta_bridge_tier"]),
            int(row["source_review_priority_rank"] or 10**9),
            str(row["fix_sha"]),
            str(row["candidate_sha"]),
        )
    )
    for rank, row in enumerate(rows, start=1):
        row["delta_bridge_rank"] = rank
    output_edges = {
        (str(row["candidate_sha"]), str(row["fix_sha"])) for row in rows
    }
    if output_edges != set(source_edges) or len(rows) != len(source_pairs):
        raise DeltaBridgeError("delta bridge failed source-edge conservation")

    review_queue = [
        {**row, "queue_kind": "all_unadjudicated_source_owner_edges"}
        for row in rows
        if str(row["ledger_edge_status"]) not in _ADJUDICATED_STATUSES
    ]
    best_by_candidate: dict[str, dict[str, object]] = {}
    for row in review_queue:
        best_by_candidate.setdefault(str(row["candidate_sha"]), row)
    candidate_frontier = [
        {**row, "frontier_kind": "best_exact_delta_edge_per_ai_candidate"}
        for row in best_by_candidate.values()
    ]
    class_counts = Counter(str(row["delta_bridge_class"]) for row in rows)
    coverage_gap_commits = sorted(
        {
            delta.sha
            for delta in [*candidate_deltas.values(), *fix_deltas.values()]
            if delta.coverage_gaps
        }
    )
    summary = {
        "schema_version": 1,
        "artifact_kind": "coolify_preimage_exact_delta_bridge",
        "split_id": split_id,
        "repository_identity": preimage_summary.get("repository_identity"),
        "source_owner_pair_count": len(source_pairs),
        "retained_delta_bridge_pair_count": len(rows),
        "unadjudicated_review_queue_count": len(review_queue),
        "candidate_frontier_count": len(candidate_frontier),
        "unique_candidate_count": len(expected_candidates),
        "unique_fix_count": len(expected_fixes),
        "delta_bridge_class_counts": dict(sorted(class_counts.items())),
        "exact_same_path_reversal_pair_count": sum(
            int(row["delta_bridge_tier"]) == 0 for row in rows
        ),
        "normalized_reversal_pair_count": sum(
            int(row["delta_bridge_tier"]) == 1 for row in rows
        ),
        "exact_added_preimage_pair_count": sum(
            int(row["delta_bridge_tier"]) == 2 for row in rows
        ),
        "exact_guard_method_pair_count": sum(
            int(row["delta_bridge_tier"]) == 3 for row in rows
        ),
        "source_owner_only_retained_pair_count": sum(
            int(row["delta_bridge_tier"]) == 5 for row in rows
        ),
        "generated_or_machine_artifact_only_pair_count": sum(
            row["generated_or_machine_artifact_only"] is True for row in rows
        ),
        "coverage_gap_commit_count": len(coverage_gap_commits),
        "coverage_gap_commits": coverage_gap_commits,
        "all_source_owner_pairs_conserved": True,
        "hard_filter_count": 0,
        "model_labels_used_for_membership": 0,
        "source_direct_ancestry_pair_count": preimage_summary.get(
            "source_direct_ancestry_pair_count"
        ),
        "unprocessed_direct_ancestry_pair_count": preimage_summary.get(
            "unprocessed_direct_ancestry_pair_count"
        ),
        "source_topology_fallback_root_count": preimage_summary.get(
            "source_topology_fallback_root_count"
        ),
        "known_confirmed_candidate_recall_at_budget": _recall_at_budget(
            candidate_frontier, confirmed_candidates
        ),
        "claim_boundary": (
            "Exact reverse deltas and candidate-added preimage persistence are "
            "deterministic review-priority evidence, not automatic causal labels. "
            "Common lines, broad carriers, generated files, merges, renames, and "
            "semantic cross-file repairs can still create false positives or lack "
            "an exact bridge. Every source-owner edge remains retained, and delta "
            "inspection gaps are retries rather than negative decisions."
        ),
    }
    return {
        "summary": summary,
        "pairs": rows,
        "review_queue": review_queue,
        "candidate_frontier": candidate_frontier,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.workers < 1 or args.repo_timeout < 1:
        raise SystemExit("--workers and --repo-timeout must be positive")
    repositories = [path.resolve() for path in args.repository]
    for repository in repositories:
        if not repository.is_dir() or not (repository / ".git").exists():
            raise SystemExit(f"repository is not a Git checkout: {repository}")
    overlay_dir = args.preimage_overlay_dir.resolve()
    summary_path = overlay_dir / "summary.json"
    source_pairs_path = overlay_dir / "source_owner_pairs.jsonl"
    root_evidence_path = overlay_dir / "root_evidence.jsonl"
    ledger_path = args.ledger.resolve()
    preimage_summary = _load_json(summary_path)
    source_pairs = _load_jsonl(source_pairs_path)
    root_evidence = _load_jsonl(root_evidence_path)
    ledger = _load_json(ledger_path)
    _validate_declared_repositories(preimage_summary, repositories)
    repository_identity = preimage_summary.get("repository_identity")
    if ledger.get("repository_identity") != repository_identity:
        raise SystemExit("ledger and preimage repository identities disagree")
    candidate_shas = sorted(
        {str(row.get("candidate_sha") or "") for row in source_pairs}
    )
    fix_shas = sorted({str(row.get("fix_sha") or "") for row in source_pairs})
    repository_by_sha: dict[str, Path] = {}
    repository_errors: dict[str, str] = {}
    for sha in sorted(set(candidate_shas) | set(fix_shas)):
        try:
            repository_by_sha[sha] = _repository_for_commit(
                repositories, sha, timeout=args.repo_timeout
            )
        except LineageEvidenceError as exc:
            repository_errors[sha] = str(exc)
    tasks = [(sha, True, "candidate") for sha in candidate_shas] + [
        (sha, False, "fix") for sha in fix_shas
    ]

    def inspect(task: tuple[str, bool, str]) -> tuple[str, str, CommitDelta]:
        sha, all_parents, kind = task
        if sha in repository_errors:
            return (
                kind,
                sha,
                CommitDelta(
                    sha=sha,
                    parents=(),
                    compared_parents=(),
                    additions=(),
                    removals=(),
                    coverage_gaps=(repository_errors[sha],),
                ),
            )
        return (
            kind,
            sha,
            _inspect_commit_delta(
                repository_by_sha[sha],
                sha,
                compare_all_parents=all_parents,
                timeout=args.repo_timeout,
            ),
        )

    inspected: list[tuple[str, str, CommitDelta]] = []
    if args.workers == 1:
        iterator = map(inspect, tasks)
        for index, result in enumerate(iterator, start=1):
            inspected.append(result)
            if index % 50 == 0 or index == len(tasks):
                print(f"delta commits inspected: {index}/{len(tasks)}", flush=True)
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(inspect, task) for task in tasks]
            for index, future in enumerate(as_completed(futures), start=1):
                inspected.append(future.result())
                if index % 50 == 0 or index == len(tasks):
                    print(f"delta commits inspected: {index}/{len(tasks)}", flush=True)
    candidate_deltas = {
        sha: delta for kind, sha, delta in inspected if kind == "candidate"
    }
    fix_deltas = {sha: delta for kind, sha, delta in inspected if kind == "fix"}
    artifacts = build_delta_bridge(
        preimage_summary=preimage_summary,
        source_pairs=source_pairs,
        root_evidence=root_evidence,
        ledger=ledger,
        candidate_deltas=candidate_deltas,
        fix_deltas=fix_deltas,
        split_id=args.split_id,
    )
    output_dir = args.output_dir.resolve()
    pairs_path = output_dir / "delta_bridge_pairs.jsonl"
    queue_path = output_dir / "edge_review_queue.jsonl"
    frontier_path = output_dir / "candidate_frontier.jsonl"
    summary_output = output_dir / "summary.json"
    _atomic_jsonl(pairs_path, artifacts["pairs"])
    _atomic_jsonl(queue_path, artifacts["review_queue"])
    _atomic_jsonl(frontier_path, artifacts["candidate_frontier"])
    summary = dict(artifacts["summary"])
    summary["configuration"] = {
        "candidate_parent_policy": "all_parents_union",
        "fix_parent_policy": "first_parent_matches_preimage_overlay",
        "workers": args.workers,
        "repositories": [str(repository) for repository in repositories],
        "candidate_repository_assignment_counts": _assignment_counts(
            {
                sha: repository_by_sha[sha]
                for sha in candidate_shas
                if sha in repository_by_sha
            }
        ),
        "fix_repository_assignment_counts": _assignment_counts(
            {
                sha: repository_by_sha[sha]
                for sha in fix_shas
                if sha in repository_by_sha
            }
        ),
        "commit_objects_missing_from_all_declared_clones": len(repository_errors),
        "repository_timeout_seconds": args.repo_timeout,
        "exact_and_whitespace_normalized_matches_retained": True,
        "cross_path_rescue_retained": True,
    }
    summary["source_artifacts"] = {
        "preimage_summary": {"path": str(summary_path), "sha256": _sha256(summary_path)},
        "source_owner_pairs": {
            "path": str(source_pairs_path),
            "sha256": _sha256(source_pairs_path),
        },
        "root_evidence": {
            "path": str(root_evidence_path),
            "sha256": _sha256(root_evidence_path),
        },
        "ledger": {"path": str(ledger_path), "sha256": _sha256(ledger_path)},
    }
    summary["output_artifacts"] = {
        "delta_bridge_pairs": {"path": str(pairs_path), "sha256": _sha256(pairs_path)},
        "edge_review_queue": {"path": str(queue_path), "sha256": _sha256(queue_path)},
        "candidate_frontier": {
            "path": str(frontier_path),
            "sha256": _sha256(frontier_path),
        },
    }
    _atomic_json(summary_output, summary)
    print("Coolify preimage exact-delta bridge frozen")
    print(f"  retained pairs : {summary['retained_delta_bridge_pair_count']}")
    print(f"  exact reversals: {summary['exact_same_path_reversal_pair_count']}")
    print(f"  candidate lane : {summary['candidate_frontier_count']}")
    print(f"  coverage gaps  : {summary['coverage_gap_commit_count']}")
    print(f"  output         : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
