#!/usr/bin/env python3
"""Freeze every possible in-graph repair after an observed AI commit.

The direct-ancestry lane is exact: a commit is included whenever at least one
frozen AI-attributed commit is a strict Git ancestor.  Repair-looking signals
only determine review order.  Every other commit remains in a separate
topology-fallback lane for squash, cherry-pick, copy, and cross-branch closure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort.fix_manifest import normalize_fix_manifest
from cohort.root_adjudication import canonical_sha256


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RECORD_SEPARATOR = "\x1e"
_FIELD_SEPARATOR = "\x00"
_ADDITION_PATTERNS = {
    "added_authorization_check": re.compile(
        r"(?:authorize\s*\(|Gate::|->can\s*\(|cannot\s*\(|"
        r"abort_(?:if|unless)\s*\([^\n]{0,160}(?:can|permission|team))",
        re.IGNORECASE,
    ),
    "added_tenant_scope": re.compile(
        r"(?:ownedByCurrentTeam|whereTeamId|where\s*\([^\n]{0,80}team_id|"
        r"getTeamIdFromToken|currentTeam)",
        re.IGNORECASE,
    ),
    "added_sensitive_redaction": re.compile(
        r"(?:makeHidden|setHidden|\$hidden|redact|sensitive|secret)",
        re.IGNORECASE,
    ),
    "added_input_validation": re.compile(
        r"(?:->validate\s*\(|Validator::|Rule::|rules\s*\(|preg_match\s*\(|"
        r"filter_var\s*\(|parse_url\s*\(|isValid|validate[A-Z_])",
        re.IGNORECASE,
    ),
    "added_shell_hardening": re.compile(
        r"(?:escapeshellarg|escapeShellArg|sanitizeShell|safeShell|"
        r"assertNothingSent)",
        re.IGNORECASE,
    ),
    "added_security_assertion": re.compile(
        r"(?:assertForbidden|assertUnauthorized|assertStatus\s*\(\s*403|"
        r"assertNothingSent|cross[-_ ]?(?:team|tenant)|GHSA-|CVE-|IDOR)",
        re.IGNORECASE,
    ),
    "added_guard_clause": re.compile(
        r"(?:if|unless)\s*\([^\n]{0,240}\)\s*\{?\s*"
        r"(?:abort|throw|return|continue|reject)|"
        r"(?:abort_if|abort_unless|throw_if|throw_unless)\s*\(",
        re.IGNORECASE,
    ),
    "added_secure_comparison": re.compile(
        r"(?:hash_equals|timingSafeEqual|constant.?time)", re.IGNORECASE
    ),
}
_EXPLICIT_SUBJECT_PATTERN = re.compile(
    r"(?:GHSA-|CVE-|IDOR|security|command[-_ ]?injection|cross[-_ ]?"
    r"(?:team|tenant)|authorization|permission|access[-_ ]?control)",
    re.IGNORECASE,
)
_REPAIR_SUBJECT_PATTERN = re.compile(
    r"(?:^fix(?:\(|:|\b)|\b(?:harden|enforce|prevent|restrict|validate|"
    r"escape|sanitize|hide|block|reject|isolate|clamp)\b)",
    re.IGNORECASE,
)
_TEST_SUBJECT_PATTERN = re.compile(r"^test(?:\(|:|\b)", re.IGNORECASE)
_ADDED_GUARD_SIGNALS = frozenset(_ADDITION_PATTERNS)


class RepairCensusError(ValueError):
    """The repair census could not preserve its structural contract."""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-path",
        type=Path,
        action="append",
        required=True,
        help=(
            "local clone whose refs contribute to the repository graph; repeat "
            "for duplicate clones with non-nested ref sets"
        ),
    )
    parser.add_argument("--repository-identity", required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--parent-fix-manifest", type=Path, required=True)
    parser.add_argument("--advisory", required=True)
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--frozen-at", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--git-timeout", type=int, default=900)
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
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _full_sha(value: object, label: str) -> str:
    sha = str(value or "").strip().lower()
    if not _FULL_SHA_RE.fullmatch(sha):
        raise RepairCensusError(f"{label} must be a full Git SHA")
    return sha


def _git(
    repository: Path,
    arguments: list[str],
    *,
    timeout: int,
) -> str:
    global_arguments = ["-c", "gc.auto=0"]
    if (repository / ".git" / "shallow").exists():
        global_arguments = ["--shallow-file", "", *global_arguments]
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *global_arguments, *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepairCensusError(
            f"git {arguments[0]} failed: {type(exc).__name__}: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = str(completed.stderr or "").strip().replace("\n", " ")[:500]
        raise RepairCensusError(
            f"git {arguments[0]} failed with {completed.returncode}: {detail}"
        )
    return str(completed.stdout or "")


def _history(repository: Path, *, timeout: int) -> list[dict[str, object]]:
    output = _git(
        repository,
        ["rev-list", "--topo-order", "--reverse", "--parents", "--all", "HEAD"],
        timeout=timeout,
    )
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for graph_order, line in enumerate(output.splitlines(), start=1):
        sha_text, *parent_texts = line.split()
        sha = _full_sha(sha_text, "history sha")
        parents = [_full_sha(parent, "history parent") for parent in parent_texts]
        if sha in seen:
            raise RepairCensusError(f"duplicate history commit: {sha}")
        missing_parents = [parent for parent in parents if parent not in seen]
        if missing_parents:
            raise RepairCensusError(
                f"history is not parent-before-child at {sha}: {missing_parents}"
            )
        seen.add(sha)
        rows.append({"sha": sha, "parents": parents, "graph_order": graph_order})
    if not rows:
        raise RepairCensusError("declared all-ref history is empty")
    return rows


def _repository_paths(
    repository: Path | Sequence[Path],
) -> tuple[Path, ...]:
    raw_paths = [repository] if isinstance(repository, Path) else list(repository)
    paths: list[Path] = []
    for raw_path in raw_paths:
        path = Path(raw_path).resolve()
        if path not in paths:
            paths.append(path)
    if not paths:
        raise RepairCensusError("at least one repository path is required")
    for path in paths:
        if not path.is_dir() or not (path / ".git").exists():
            raise RepairCensusError(f"repository is not a Git checkout: {path}")
    return tuple(paths)


def _union_histories(
    repositories: Sequence[Path],
    *,
    timeout: int,
) -> tuple[list[dict[str, object]], dict[str, Path], list[dict[str, object]]]:
    """Union non-nested clone ref graphs without mutating either checkout.

    Each clone already returns a parent-before-child sequence.  Keeping the
    first clone's order and appending unseen rows from later clones preserves
    that invariant: every unseen parent is either shared with an earlier clone
    or appeared earlier in the same later-clone sequence.  Overlapping commit
    objects must declare identical parents.
    """

    combined: list[dict[str, object]] = []
    parents_by_sha: dict[str, tuple[str, ...]] = {}
    source_by_sha: dict[str, Path] = {}
    clone_coverage: list[dict[str, object]] = []
    for repository in repositories:
        rows = _history(repository, timeout=timeout)
        new_count = 0
        for row in rows:
            sha = str(row["sha"])
            parents = tuple(str(parent) for parent in row["parents"])
            previous = parents_by_sha.get(sha)
            if previous is not None:
                if previous != parents:
                    raise RepairCensusError(
                        f"clone parent disagreement for immutable commit {sha}"
                    )
                continue
            missing_parents = [parent for parent in parents if parent not in parents_by_sha]
            if missing_parents:
                raise RepairCensusError(
                    f"clone-union history is not parent-before-child at {sha}: "
                    f"{missing_parents}"
                )
            parents_by_sha[sha] = parents
            source_by_sha[sha] = repository
            combined.append(
                {
                    "sha": sha,
                    "parents": list(parents),
                    "graph_order": len(combined) + 1,
                }
            )
            new_count += 1
        clone_coverage.append(
            {
                "repository_path": str(repository),
                "reachable_commit_count": len(rows),
                "new_union_commit_count": new_count,
            }
        )
    return combined, source_by_sha, clone_coverage


def _parse_show_records(output: str) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for segment in output.split(_RECORD_SEPARATOR)[1:]:
        header, separator, body = segment.partition("\n")
        if not separator:
            raise RepairCensusError("git show record has no body separator")
        fields = header.split(_FIELD_SEPARATOR, maxsplit=3)
        if len(fields) != 4:
            raise RepairCensusError("git show record header is malformed")
        sha = _full_sha(fields[0], "git show sha")
        if sha in records:
            raise RepairCensusError(f"duplicate git show record: {sha}")
        records[sha] = {
            "parents": [value for value in fields[1].split() if value],
            "authored_at": fields[2],
            "subject": fields[3],
            "body": body,
        }
    return records


def _batched_show(
    repository: Path,
    shas: list[str],
    *,
    patch: bool,
    timeout: int,
    batch_size: int = 96,
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    # Keep the control bytes in Git's pretty-format language.  Passing a
    # literal NUL through execve is invalid; Git expands %x00 in its output.
    format_value = "--format=%x1e%H%x00%P%x00%aI%x00%s"
    for offset in range(0, len(shas), batch_size):
        batch = shas[offset : offset + batch_size]
        arguments = [
            "show",
            "--no-ext-diff",
            "--no-renames",
            "--no-color",
            "--no-notes",
            "--first-parent",
            format_value,
        ]
        if patch:
            arguments.extend(["--patch", "--unified=0"])
        else:
            arguments.append("--name-only")
        arguments.extend(batch)
        parsed = _parse_show_records(
            _git(repository, arguments, timeout=timeout)
        )
        duplicates = set(result) & set(parsed)
        if duplicates:
            raise RepairCensusError(f"duplicate batched show rows: {sorted(duplicates)}")
        result.update(parsed)
    missing = sorted(set(shas) - set(result))
    if missing:
        raise RepairCensusError(f"git show omitted commits: {missing[:10]}")
    return result


def _batched_show_union(
    source_by_sha: Mapping[str, Path],
    shas: Sequence[str],
    *,
    patch: bool,
    timeout: int,
) -> dict[str, dict[str, object]]:
    grouped: dict[Path, list[str]] = defaultdict(list)
    for sha in shas:
        repository = source_by_sha.get(sha)
        if repository is None:
            raise RepairCensusError(f"no clone contains commit object {sha}")
        grouped[repository].append(sha)
    result: dict[str, dict[str, object]] = {}
    for repository in sorted(grouped, key=lambda path: str(path)):
        parsed = _batched_show(
            repository,
            grouped[repository],
            patch=patch,
            timeout=timeout,
        )
        duplicates = set(result) & set(parsed)
        if duplicates:
            raise RepairCensusError(
                f"duplicate union git show rows: {sorted(duplicates)[:10]}"
            )
        result.update(parsed)
    missing = sorted(set(shas) - set(result))
    if missing:
        raise RepairCensusError(f"union git show omitted commits: {missing[:10]}")
    return result


def _changed_paths(body: str) -> list[str]:
    return sorted({line.strip() for line in body.splitlines() if line.strip()})


def _added_lines(patch: str) -> str:
    return "\n".join(
        line[1:]
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def added_repair_signals(patch: str) -> list[str]:
    """Return review signals from added lines only; this never filters roots."""

    additions = _added_lines(patch)
    return sorted(
        signal
        for signal, pattern in _ADDITION_PATTERNS.items()
        if pattern.search(additions)
    )


def _subject_signals(subject: str) -> list[str]:
    signals: list[str] = []
    if _EXPLICIT_SUBJECT_PATTERN.search(subject):
        signals.append("explicit_security_subject")
    if _REPAIR_SUBJECT_PATTERN.search(subject):
        signals.append("repair_action_subject")
    if _TEST_SUBJECT_PATTERN.search(subject):
        signals.append("test_subject")
    return signals


def classify_review_lane(
    *,
    subject: str,
    changed_paths: list[str],
    patch_signals: list[str],
    is_merge: bool,
    observed_ai_commit: bool,
    direct_parent_is_observed_ai: bool,
    already_in_parent_manifest: bool,
    outside_parent_root_ancestry: bool,
) -> tuple[int, str, int, list[str]]:
    """Rank one retained root; lane assignment never changes membership."""

    subject_signals = _subject_signals(subject)
    signals = sorted(set(subject_signals) | set(patch_signals))
    has_test_path = any(
        path.startswith("tests/") or "/tests/" in f"/{path.lower()}"
        for path in changed_paths
    )
    if has_test_path:
        signals.append("test_path")
    if outside_parent_root_ancestry:
        signals.append("outside_parent_root_ancestry")
    if observed_ai_commit:
        signals.append("observed_ai_descendant_commit")
    if direct_parent_is_observed_ai:
        signals.append("direct_child_of_observed_ai")
    signals = sorted(set(signals))

    score = len(patch_signals) * 12
    if "added_security_assertion" in patch_signals:
        score += 70
    if "explicit_security_subject" in subject_signals:
        score += 55
    if set(patch_signals) & _ADDED_GUARD_SIGNALS:
        score += 45
    if "repair_action_subject" in subject_signals:
        score += 30
    if has_test_path:
        score += 25
    if outside_parent_root_ancestry:
        score += 10
    if observed_ai_commit:
        score += 55
    if direct_parent_is_observed_ai:
        score += 70
    if is_merge:
        score -= 20

    if already_in_parent_manifest:
        return 0, "sealed_existing_root", score, signals
    if is_merge:
        if patch_signals or "explicit_security_subject" in subject_signals:
            return 4, "merge_carrier_with_repair_signal", score, signals
        return 6, "merge_carrier_fallback", score, signals
    if (
        "added_security_assertion" in patch_signals
        or "explicit_security_subject" in subject_signals
    ):
        return 1, "explicit_security_or_regression", score, signals
    if set(patch_signals) & _ADDED_GUARD_SIGNALS:
        return 2, "added_check_or_guard", score, signals
    if observed_ai_commit or direct_parent_is_observed_ai:
        return 3, "direct_ai_repair_proximity", score, signals
    if "repair_action_subject" in subject_signals:
        return 3, "repair_action_subject", score, signals
    if has_test_path or "test_subject" in subject_signals:
        return 4, "test_change_fallback", score, signals
    return 5, "direct_ancestry_fallback", score, signals


def _ancestor_closure(
    repository: Path, roots: set[str], *, timeout: int
) -> set[str]:
    if not roots:
        return set()
    output = _git(
        repository,
        ["rev-list", *sorted(roots)],
        timeout=timeout,
    )
    return {
        _full_sha(line, "parent-root ancestor")
        for line in output.splitlines()
        if line.strip()
    }


def _ancestor_closure_union(
    source_by_sha: Mapping[str, Path],
    roots: set[str],
    *,
    timeout: int,
) -> set[str]:
    grouped: dict[Path, set[str]] = defaultdict(set)
    for sha in roots:
        repository = source_by_sha.get(sha)
        if repository is None:
            raise RepairCensusError(f"no clone contains parent root {sha}")
        grouped[repository].add(sha)
    closure: set[str] = set()
    for repository in sorted(grouped, key=lambda path: str(path)):
        closure |= _ancestor_closure(
            repository,
            grouped[repository],
            timeout=timeout,
        )
    return closure


def build_repair_census(
    *,
    repository: Path | Sequence[Path],
    repository_identity: str,
    ai_rows: list[dict[str, object]],
    parent_manifest: Mapping[str, object],
    advisory: str,
    split_id: str,
    frozen_at: str,
    git_timeout: int = 900,
) -> dict[str, object]:
    """Build a lossless all-ref routing census and direct-ancestry manifest."""

    identity = repository_identity.strip().lower()
    if not identity or not advisory.strip() or not split_id.strip() or not frozen_at.strip():
        raise RepairCensusError("identity, advisory, split-id, and frozen-at are required")
    repositories = _repository_paths(repository)

    normalized_parent = normalize_fix_manifest(parent_manifest, {})
    raw_parent_fixes = normalized_parent.get("fixes")
    if not isinstance(raw_parent_fixes, list):
        raise RepairCensusError("parent fix manifest is malformed")
    if any(str(row["repository_identity"]).lower() != identity for row in raw_parent_fixes):
        raise RepairCensusError("parent fix manifest contains another repository")
    parent_fix_shas = {_full_sha(row["fix_sha"], "parent fix") for row in raw_parent_fixes}

    ai_by_sha: dict[str, dict[str, object]] = {}
    for raw in ai_rows:
        if str(raw.get("repository_identity") or "").lower() != identity:
            continue
        sha = _full_sha(raw.get("sha"), "AI commit")
        row = dict(raw)
        prior = ai_by_sha.get(sha)
        if prior is not None and prior != row:
            raise RepairCensusError(f"conflicting AI rows for {sha}")
        ai_by_sha[sha] = row
    if not ai_by_sha:
        raise RepairCensusError("AI scan has no rows for the requested repository")

    history, source_by_sha, clone_coverage = _union_histories(
        repositories,
        timeout=git_timeout,
    )
    history_by_sha = {str(row["sha"]): row for row in history}
    missing_ai = sorted(set(ai_by_sha) - set(history_by_sha))
    missing_parent_fixes = sorted(parent_fix_shas - set(history_by_sha))
    if missing_ai:
        raise RepairCensusError(f"AI commits missing from all-ref graph: {missing_ai}")
    if missing_parent_fixes:
        raise RepairCensusError(
            f"parent fixes missing from all-ref graph: {missing_parent_fixes}"
        )

    ai_index = {sha: index for index, sha in enumerate(sorted(ai_by_sha))}
    bitsets: dict[str, int] = {}
    direct_root_shas: set[str] = set()
    for row in history:
        sha = str(row["sha"])
        inherited = 0
        for parent in row["parents"]:
            inherited |= bitsets[str(parent)]
        row["strict_ai_ancestor_bits"] = inherited
        if inherited:
            direct_root_shas.add(sha)
        complete = inherited
        if sha in ai_index:
            complete |= 1 << ai_index[sha]
        bitsets[sha] = complete

    all_shas = [str(row["sha"]) for row in history]
    metadata = _batched_show_union(
        source_by_sha,
        all_shas,
        patch=False,
        timeout=git_timeout,
    )
    # Inspect every single-parent direct descendant.  That includes ordinary
    # commits and indistinguishable squash landings, so a neutral subject that
    # merely says "add checks" cannot be buried by the subject classifier.
    # Merge carriers are redundant with their retained atomic side commits in
    # the ordinary case; inspect only repair-looking/test merge subjects while
    # keeping every other merge in its explicit fallback lane.
    patch_inspection_shas = sorted(
        sha
        for sha in direct_root_shas
        if len(history_by_sha[sha]["parents"]) <= 1
        or _REPAIR_SUBJECT_PATTERN.search(str(metadata[sha]["subject"]))
        or _EXPLICIT_SUBJECT_PATTERN.search(str(metadata[sha]["subject"]))
        or _TEST_SUBJECT_PATTERN.search(str(metadata[sha]["subject"]))
    )
    patches = _batched_show_union(
        source_by_sha,
        patch_inspection_shas,
        patch=True,
        timeout=git_timeout,
    )
    parent_root_ancestry = _ancestor_closure_union(
        source_by_sha,
        parent_fix_shas,
        timeout=git_timeout,
    )

    bitset_width = (len(ai_index) + 3) // 4
    all_commit_rows: list[dict[str, object]] = []
    schedule: list[dict[str, object]] = []
    direct_pair_count = 0
    for graph_row in history:
        sha = str(graph_row["sha"])
        parents = [str(parent) for parent in graph_row["parents"]]
        strict_bits = int(graph_row["strict_ai_ancestor_bits"])
        strict_count = strict_bits.bit_count()
        direct_pair_count += strict_count
        meta = metadata[sha]
        if [str(value) for value in meta["parents"]] != parents:
            raise RepairCensusError(f"parent metadata drift for {sha}")
        paths = _changed_paths(str(meta["body"]))
        already_parent = sha in parent_fix_shas
        is_direct = bool(strict_bits)
        if is_direct:
            route = "direct_ai_ancestry"
        elif already_parent:
            route = "sealed_parent_root_without_direct_ancestry"
        else:
            route = "nonancestral_topology_fallback"
        row: dict[str, object] = {
            "repository_identity": identity,
            "sha": sha,
            "parents": parents,
            "graph_order": int(graph_row["graph_order"]),
            "authored_at": str(meta["authored_at"]),
            "subject": str(meta["subject"]),
            "changed_paths": paths,
            "topology_kind": "merge_carrier" if len(parents) > 1 else "single_parent_or_root",
            "observed_ai_commit": sha in ai_by_sha,
            "strict_ai_ancestor_count": strict_count,
            "route": route,
            "already_in_parent_manifest": already_parent,
        }
        if is_direct:
            patch_signals = added_repair_signals(
                str(patches.get(sha, {}).get("body") or "")
            )
            tier, lane, score, signals = classify_review_lane(
                subject=str(meta["subject"]),
                changed_paths=paths,
                patch_signals=patch_signals,
                is_merge=len(parents) > 1,
                observed_ai_commit=sha in ai_by_sha,
                direct_parent_is_observed_ai=any(
                    parent in ai_by_sha for parent in parents
                ),
                already_in_parent_manifest=already_parent,
                outside_parent_root_ancestry=sha not in parent_root_ancestry,
            )
            row.update(
                {
                    "ai_ancestor_bitset_hex": format(strict_bits, f"0{bitset_width}x"),
                    "patch_inspected": sha in patches,
                    "review_tier": tier,
                    "review_lane": lane,
                    "review_score": score,
                    "review_signals": signals,
                    "outside_parent_root_ancestry": sha not in parent_root_ancestry,
                }
            )
            schedule.append(dict(row))
        all_commit_rows.append(row)

    # Parent roots without a strict observed-AI ancestor remain add-only sealed
    # inputs.  They have no direct pair in this census but stay in the manifest.
    for row in all_commit_rows:
        if row["route"] != "sealed_parent_root_without_direct_ancestry":
            continue
        schedule.append(
            {
                **row,
                "patch_inspected": False,
                "review_tier": 0,
                "review_lane": "sealed_existing_root",
                "review_score": 0,
                "review_signals": [],
                "outside_parent_root_ancestry": False,
            }
        )

    schedule.sort(
        key=lambda row: (
            int(row["review_tier"]),
            -int(row["review_score"]),
            int(row["graph_order"]),
            str(row["sha"]),
        )
    )
    new_rank = 0
    for rank, row in enumerate(schedule, start=1):
        row["priority_rank"] = rank
        if not row["already_in_parent_manifest"]:
            new_rank += 1
            row["new_root_priority_rank"] = new_rank
        else:
            row["new_root_priority_rank"] = None

    new_fix_shas = direct_root_shas - parent_fix_shas
    added_fixes = [
        {
            "advisory": advisory.strip(),
            "repository_identity": identity,
            "fix_sha": sha,
        }
        for sha in sorted(new_fix_shas)
    ]
    manifest = normalize_fix_manifest(
        {
            "schema_version": 1,
            "artifact_kind": "sealed_fix_manifest",
            "split_id": split_id,
            "frozen_at": frozen_at,
            "fixes": [dict(row) for row in raw_parent_fixes] + added_fixes,
        },
        {},
    )

    route_counts = Counter(str(row["route"]) for row in all_commit_rows)
    lane_counts = Counter(str(row["review_lane"]) for row in schedule)
    schedule_shas = {str(row["sha"]) for row in schedule}
    expected_schedule_shas = parent_fix_shas | direct_root_shas
    if schedule_shas != expected_schedule_shas or len(schedule) != len(schedule_shas):
        raise RepairCensusError("review schedule does not conserve the manifest roots")
    if sum(route_counts.values()) != len(history):
        raise RepairCensusError("all-ref route accounting is not conservative")
    manifest_shas = {str(row["fix_sha"]) for row in manifest["fixes"]}
    if manifest_shas != expected_schedule_shas:
        raise RepairCensusError("expanded manifest does not match scheduled roots")

    ancestor_index = {
        "schema_version": 1,
        "artifact_kind": "observed_ai_ancestor_bitset_index",
        "repository_identity": identity,
        "bit_order": "least_significant_bit_is_ai_shas_index_zero",
        "bitset_hex_width": bitset_width,
        "ai_shas": sorted(ai_index),
        "ai_shas_sha256": canonical_sha256(sorted(ai_index)),
    }
    summary = {
        "schema_version": 1,
        "artifact_kind": "ai_descendant_repair_census",
        "split_id": split_id,
        "repository_identity": identity,
        "declared_graph_view": (
            "union_of_all_local_refs_plus_HEAD_across_declared_clones"
        ),
        "repository_clone_count": len(repositories),
        "repository_clone_coverage": clone_coverage,
        "all_ref_commit_count": len(history),
        "observed_ai_commit_count": len(ai_index),
        "observed_ai_commits_missing_from_graph": 0,
        "direct_ancestry_root_count": len(direct_root_shas),
        "direct_ancestry_pair_count": direct_pair_count,
        "direct_roots_that_are_ai_commits": sum(
            sha in ai_by_sha for sha in direct_root_shas
        ),
        "direct_merge_carrier_count": sum(
            len(history_by_sha[sha]["parents"]) > 1 for sha in direct_root_shas
        ),
        "parent_fix_count": len(parent_fix_shas),
        "parent_fix_direct_overlap_count": len(parent_fix_shas & direct_root_shas),
        "added_direct_root_count": len(new_fix_shas),
        "expanded_manifest_fix_count": len(manifest_shas),
        "patch_inspected_root_count": len(patches),
        "all_commit_route_counts": dict(sorted(route_counts.items())),
        "review_lane_counts": dict(sorted(lane_counts.items())),
        "all_commits_retained_once": sum(route_counts.values()) == len(history),
        "all_direct_ancestry_pairs_losslessly_represented": True,
        "all_parent_fixes_retained": parent_fix_shas <= manifest_shas,
        "all_manifest_roots_scheduled_once": (
            schedule_shas == manifest_shas and len(schedule) == len(schedule_shas)
        ),
        "hard_root_deletes": 0,
        "model_labels_used_for_membership": 0,
        "parent_manifest_sha256": canonical_sha256(normalized_parent),
        "expanded_manifest_sha256": canonical_sha256(manifest),
        "ai_rows_sha256": canonical_sha256(
            [ai_by_sha[sha] for sha in sorted(ai_by_sha)]
        ),
        "all_commit_rows_sha256": canonical_sha256(all_commit_rows),
        "review_schedule_sha256": canonical_sha256(schedule),
        "ancestor_index_sha256": canonical_sha256(ancestor_index),
        "claim_boundary": (
            "Every commit in the declared all-ref graph is retained exactly once. "
            "Every strict observed-AI-ancestor pair is represented exactly by an "
            "indexed bitset and enters the direct review manifest; regex and subject "
            "signals change order only. Non-ancestral commits remain an explicit "
            "fallback for squash, cherry-pick, copy, and cross-branch closure. This "
            "is candidate-source completeness, not a causal or vulnerability label."
        ),
    }
    return {
        "manifest": manifest,
        "all_commits": all_commit_rows,
        "review_schedule": schedule,
        "ancestor_index": ancestor_index,
        "summary": summary,
    }


def _atomic_text(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _jsonl_text(rows: list[dict[str, object]]) -> str:
    return "".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.git_timeout < 1:
        raise SystemExit("git-timeout must be positive")
    scan_summary = _load_json(args.ai_scan_dir / "summary.json")
    ai_rows = _load_jsonl(args.ai_scan_dir / "commits.jsonl")
    identity = args.repository_identity.strip().lower()
    if scan_summary.get("artifact_kind") != "cohort_ai_commit_scan":
        raise SystemExit("AI scan summary is malformed")
    if scan_summary.get("ai_commit_count") != len(ai_rows):
        raise SystemExit("AI scan row count mismatch")
    complete = scan_summary.get("complete_repository_identities")
    if not isinstance(complete, list) or identity not in {
        str(value).lower() for value in complete
    }:
        raise SystemExit("AI scan does not claim complete coverage for repository")
    scan_coverage = scan_summary.get("repository_clone_coverage")
    if not isinstance(scan_coverage, list):
        raise SystemExit("AI scan does not expose clone-level coverage")
    matching_coverage = [
        entry
        for entry in scan_coverage
        if isinstance(entry, dict)
        and str(entry.get("repository_identity") or "").lower() == identity
    ]
    if len(matching_coverage) != 1:
        raise SystemExit("AI scan clone coverage is missing or ambiguous")
    clone_rows = matching_coverage[0].get("clone_coverage")
    if not isinstance(clone_rows, list) or not clone_rows:
        raise SystemExit("AI scan clone coverage has no clone rows")
    scanned_paths = {
        str(Path(str(entry.get("repo_path"))).resolve())
        for entry in clone_rows
        if isinstance(entry, dict) and entry.get("repo_path")
    }
    requested_paths = {str(path.resolve()) for path in args.repository_path}
    if requested_paths != scanned_paths:
        raise SystemExit(
            "repository paths do not match the AI scan clone coverage"
        )
    expected_refs = {
        str(Path(str(entry["repo_path"])).resolve()): str(
            entry.get("refs_digest") or ""
        )
        for entry in clone_rows
        if isinstance(entry, dict) and entry.get("repo_path")
    }
    from cve_analyzer.provenance import repository_refs_digest

    for path in args.repository_path:
        resolved_path = str(path.resolve())
        current_digest, _refs_view = repository_refs_digest(path.resolve())
        if not expected_refs.get(resolved_path) or current_digest != expected_refs[resolved_path]:
            raise SystemExit(
                f"repository refs drifted since AI scan: {resolved_path}"
            )
    try:
        artifacts = build_repair_census(
            repository=args.repository_path,
            repository_identity=identity,
            ai_rows=ai_rows,
            parent_manifest=_load_json(args.parent_fix_manifest),
            advisory=args.advisory,
            split_id=args.split_id,
            frozen_at=args.frozen_at,
            git_timeout=args.git_timeout,
        )
    except RepairCensusError as exc:
        raise SystemExit(f"repair census failed: {exc}") from exc

    artifacts["summary"]["source_ai_scan"] = {
        "directory": str(args.ai_scan_dir.resolve()),
        "summary_canonical_sha256": canonical_sha256(scan_summary),
        "commits_canonical_sha256": canonical_sha256(ai_rows),
        "repository_coverage_sha256": scan_summary.get(
            "repository_coverage_sha256"
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_text(args.output_dir / "manifest.json", _json_text(artifacts["manifest"]))
    _atomic_text(
        args.output_dir / "all_commits.jsonl",
        _jsonl_text(artifacts["all_commits"]),
    )
    _atomic_text(
        args.output_dir / "review_schedule.jsonl",
        _jsonl_text(artifacts["review_schedule"]),
    )
    _atomic_text(
        args.output_dir / "ancestor_index.json",
        _json_text(artifacts["ancestor_index"]),
    )
    _atomic_text(args.output_dir / "summary.json", _json_text(artifacts["summary"]))
    summary = artifacts["summary"]
    print("AI-descendant repair census frozen")
    print(f"  all-ref commits       : {summary['all_ref_commit_count']}")
    print(f"  direct repair roots   : {summary['direct_ancestry_root_count']}")
    print(f"  exact ancestry pairs  : {summary['direct_ancestry_pair_count']}")
    print(f"  expanded manifest     : {summary['expanded_manifest_fix_count']}")
    print(f"  topology fallback     : {summary['all_commit_route_counts'].get('nonancestral_topology_fallback', 0)}")
    print(f"  output                : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
