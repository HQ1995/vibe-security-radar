#!/usr/bin/env python3
"""Promote cross-file AI ancestors linked by exact internal dependencies.

The proof-carrying reduction keeps every explicitly attributed AI ancestor, but
cross-file compositional contributors can remain in the ancestry fallback
lane.  This scheduler reads the complete pre/post-fix blobs for affected
runtime files, extracts internal ``App\\...`` dependencies, and promotes an AI
candidate when its changed lines name the same dependency.  It never removes
or adjudicates an input edge.
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cohort.root_adjudication import canonical_sha256


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIFF_PATH_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")
_PHP_APP_USE_RE = re.compile(
    r"(?m)^\s*use\s+(\\?App\\(?:[A-Za-z_][A-Za-z0-9_]*\\)*"
    r"[A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*;"
)
_INLINE_APP_CLASS_RE = re.compile(
    r"(?<![A-Za-z0-9_])(\\?App\\(?:[A-Za-z_][A-Za-z0-9_]*\\)*"
    r"[A-Za-z_][A-Za-z0-9_]*)(?=\s*::)"
)
_CLASS_SYMBOL_RE = re.compile(r"\b[A-Z][A-Za-z0-9_]{5,}\b")
_GENERIC_SYMBOLS = frozenset(
    {
        "application",
        "collection",
        "component",
        "controller",
        "database",
        "environment",
        "exception",
        "instance",
        "livewire",
        "middleware",
        "model",
        "policy",
        "project",
        "request",
        "response",
        "security",
        "server",
        "service",
        "settings",
        "stringable",
        "throwable",
        "user",
    }
)


class DependencyBridgeError(RuntimeError):
    """Git evidence could not be materialized completely."""


@dataclass(frozen=True)
class PatchSymbols:
    sha256: str
    fqcns: frozenset[str]
    symbols: frozenset[str]
    fqcn_paths: Mapping[str, tuple[str, ...]]
    symbol_paths: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class FixDependencies:
    fix_sha: str
    parent_sha: str
    changed_runtime_paths: tuple[str, ...]
    fqcns: frozenset[str]
    symbols: frozenset[str]
    fqcn_paths: Mapping[str, tuple[str, ...]]
    symbol_paths: Mapping[str, tuple[str, ...]]
    coverage_gaps: tuple[Mapping[str, str], ...]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reduction-dir", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo-timeout", type=int, default=120)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object in {path}")
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


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def _git(
    repository: Path,
    arguments: Sequence[str],
    *,
    timeout: int,
    allow_missing: bool = False,
) -> str | None:
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
        raise DependencyBridgeError(f"git {arguments[0]} failed: {exc}") from exc
    if completed.returncode == 0:
        return completed.stdout
    if allow_missing:
        return None
    detail = completed.stderr.strip().replace("\n", " ")[:500]
    raise DependencyBridgeError(
        f"git {arguments[0]} exited {completed.returncode}: {detail}"
    )


def _runtime_path(source_path: str) -> bool:
    normalized = source_path.casefold().lstrip("./")
    segments = normalized.split("/")
    if not segments:
        return False
    if segments[0] in {
        ".github",
        "docs",
        "doc",
        "tests",
        "test",
        "spec",
        "specs",
        "vendor",
        "node_modules",
    }:
        return False
    if any(part in {"fixtures", "snapshots", "__tests__"} for part in segments):
        return False
    return not normalized.endswith((".md", ".mdx", ".rst", ".txt"))


def _normalize_fqcn(value: str) -> str:
    return value.lstrip("\\").casefold()


def _display_fqcn(value: str) -> str:
    return value.lstrip("\\")


def _dependency_tokens(text: str) -> tuple[dict[str, str], dict[str, str]]:
    fqcns: dict[str, str] = {}
    symbols: dict[str, str] = {}
    matches = [*_PHP_APP_USE_RE.finditer(text), *_INLINE_APP_CLASS_RE.finditer(text)]
    for match in matches:
        display = _display_fqcn(match.group(1))
        normalized = _normalize_fqcn(display)
        basename = display.rsplit("\\", 1)[-1]
        folded = basename.casefold()
        if len(basename) < 8 or folded in _GENERIC_SYMBOLS:
            continue
        fqcns.setdefault(normalized, display)
        symbols.setdefault(folded, basename)
    return fqcns, symbols


def _changed_line_symbols(text: str) -> tuple[set[str], set[str]]:
    changed = "\n".join(
        line[1:]
        for line in text.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    )
    raw_fqcns, raw_symbols = _dependency_tokens(changed)
    symbols = set(raw_symbols)
    for match in _CLASS_SYMBOL_RE.finditer(changed):
        value = match.group(0)
        folded = value.casefold()
        if len(value) >= 8 and folded not in _GENERIC_SYMBOLS:
            symbols.add(folded)
    return set(raw_fqcns), symbols


def _split_patch(text: str) -> dict[str, str]:
    by_path: defaultdict[str, list[str]] = defaultdict(list)
    current_path = ""
    for line in text.splitlines():
        match = _DIFF_PATH_RE.match(line)
        if match:
            current_path = match.group(2)
        if current_path:
            by_path[current_path].append(line)
    return {source_path: "\n".join(lines) for source_path, lines in by_path.items()}


def _candidate_patch_symbols(
    repository: Path,
    candidate_sha: str,
    *,
    timeout: int,
) -> PatchSymbols:
    patch = _git(
        repository,
        [
            "show",
            "--format=",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            "--find-renames",
            "--find-copies",
            candidate_sha,
            "--",
        ],
        timeout=timeout,
    )
    assert patch is not None
    fqcn_paths: defaultdict[str, set[str]] = defaultdict(set)
    symbol_paths: defaultdict[str, set[str]] = defaultdict(set)
    for source_path, section in _split_patch(patch).items():
        if not _runtime_path(source_path):
            continue
        fqcns, symbols = _changed_line_symbols(section)
        for token in fqcns:
            fqcn_paths[token].add(source_path)
        for token in symbols:
            symbol_paths[token].add(source_path)
    return PatchSymbols(
        sha256=_sha256_bytes(patch.encode("utf-8")),
        fqcns=frozenset(fqcn_paths),
        symbols=frozenset(symbol_paths),
        fqcn_paths={key: tuple(sorted(value)) for key, value in sorted(fqcn_paths.items())},
        symbol_paths={
            key: tuple(sorted(value)) for key, value in sorted(symbol_paths.items())
        },
    )


def _fix_dependencies(
    repository: Path,
    fix_sha: str,
    *,
    timeout: int,
) -> FixDependencies:
    parent = _git(repository, ["rev-parse", f"{fix_sha}^1"], timeout=timeout)
    assert parent is not None
    parent_sha = parent.strip()
    if not _FULL_SHA_RE.fullmatch(parent_sha):
        raise DependencyBridgeError(f"malformed parent for {fix_sha}: {parent_sha}")
    changed = _git(
        repository,
        ["diff", "--name-only", "--find-renames", parent_sha, fix_sha, "--"],
        timeout=timeout,
    )
    assert changed is not None
    runtime_paths = tuple(
        sorted({line.strip() for line in changed.splitlines() if _runtime_path(line.strip())})
    )
    fqcn_paths: defaultdict[str, set[str]] = defaultdict(set)
    symbol_paths: defaultdict[str, set[str]] = defaultdict(set)
    coverage_gaps: list[dict[str, str]] = []
    for source_path in runtime_paths:
        blobs: list[str] = []
        for label, revision in (("parent", parent_sha), ("fix", fix_sha)):
            blob = _git(
                repository,
                ["show", f"{revision}:{source_path}"],
                timeout=timeout,
                allow_missing=True,
            )
            if blob is not None:
                blobs.append(blob)
            elif label == "parent":
                # A newly added file legitimately has no parent blob.  The fix
                # blob still supplies dependencies, so this is not a gap.
                continue
        if not blobs:
            coverage_gaps.append(
                {
                    "fix_sha": fix_sha,
                    "path": source_path,
                    "operation": "read_fix_dependency_blob",
                    "reason": "path absent from both parent and fix states",
                }
            )
            continue
        for blob in blobs:
            fqcns, symbols = _dependency_tokens(blob)
            for token in fqcns:
                fqcn_paths[token].add(source_path)
            for token in symbols:
                symbol_paths[token].add(source_path)
    return FixDependencies(
        fix_sha=fix_sha,
        parent_sha=parent_sha,
        changed_runtime_paths=runtime_paths,
        fqcns=frozenset(fqcn_paths),
        symbols=frozenset(symbol_paths),
        fqcn_paths={key: tuple(sorted(value)) for key, value in sorted(fqcn_paths.items())},
        symbol_paths={
            key: tuple(sorted(value)) for key, value in sorted(symbol_paths.items())
        },
        coverage_gaps=tuple(coverage_gaps),
    )


def _bridge_evidence(
    fix: FixDependencies,
    candidate: PatchSymbols,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for token in sorted(fix.fqcns & candidate.fqcns):
        rows.append(
            {
                "match_kind": "exact_internal_dependency_fqcn",
                "token": token,
                "fix_paths": list(fix.fqcn_paths[token]),
                "candidate_paths": list(candidate.fqcn_paths[token]),
            }
        )
    fqcn_basenames = {token.rsplit("\\", 1)[-1] for token in fix.fqcns & candidate.fqcns}
    for token in sorted((fix.symbols & candidate.symbols) - fqcn_basenames):
        rows.append(
            {
                "match_kind": "exact_internal_dependency_symbol",
                "token": token,
                "fix_paths": list(fix.symbol_paths[token]),
                "candidate_paths": list(candidate.symbol_paths[token]),
            }
        )
    return rows


def _priority(
    source: Mapping[str, object], evidence: Sequence[Mapping[str, object]]
) -> tuple[int, str]:
    input_class = str(source.get("priority_class") or "")
    if input_class == "P0_OBSERVED_AI_CAUSAL_SIGNAL":
        return 0, "P0_EXISTING_STRUCTURAL_SIGNAL"
    if any(row.get("match_kind") == "exact_internal_dependency_fqcn" for row in evidence):
        return 1, "P1_EXACT_INTERNAL_DEPENDENCY_FQCN"
    if evidence:
        return 2, "P2_EXACT_INTERNAL_DEPENDENCY_SYMBOL"
    if input_class == "P2_OBSERVED_AI_AFFECTED_FILE_HISTORY":
        return 3, "P3_EXISTING_AFFECTED_FILE_HISTORY"
    return 4, "P4_AI_ANCESTRY_FALLBACK"


def _rank(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_fix: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        by_fix[str(row["fix_sha"])].append(row)
    for fix_rows in by_fix.values():
        by_tier: defaultdict[int, list[dict[str, object]]] = defaultdict(list)
        for row in fix_rows:
            by_tier[int(row["dependency_priority_tier"])].append(row)
        for tier_rows in by_tier.values():
            tier_rows.sort(
                key=lambda row: (
                    int(row.get("input_priority_rank") or 10**9),
                    -len(row.get("dependency_bridge_evidence") or []),
                    str(row["candidate_sha"]),
                )
            )
            for rank, row in enumerate(tier_rows, start=1):
                row["within_dependency_tier_rank"] = rank
        ordered = sorted(
            fix_rows,
            key=lambda row: (
                int(row["dependency_priority_tier"]),
                int(row["within_dependency_tier_rank"]),
                str(row["candidate_sha"]),
            ),
        )
        for rank, row in enumerate(ordered, start=1):
            row["within_fix_review_rank"] = rank
    schedule = sorted(
        rows,
        key=lambda row: (
            int(row["dependency_priority_tier"]),
            int(row["within_dependency_tier_rank"]),
            str(row["fix_sha"]),
            str(row["candidate_sha"]),
        ),
    )
    for rank, row in enumerate(schedule, start=1):
        row["global_review_rank"] = rank
    return schedule


def _build(
    *,
    reduction_dir: Path,
    repository: Path,
    timeout: int,
) -> dict[str, object]:
    summary = _load_json(reduction_dir / "summary.json")
    candidates = _load_jsonl(reduction_dir / "candidates.jsonl")
    fixes = _load_jsonl(reduction_dir / "fixes.jsonl")
    if summary.get("artifact_kind") != "proof_carrying_origin_candidate_reduction":
        raise SystemExit("unsupported reduction artifact")
    if canonical_sha256(candidates) != summary.get("candidate_rows_sha256"):
        raise SystemExit("reduction candidate digest mismatch")
    if canonical_sha256(fixes) != summary.get("fix_rows_sha256"):
        raise SystemExit("reduction fix digest mismatch")

    fix_shas = sorted({str(row.get("fix_sha") or "") for row in fixes})
    candidate_shas = sorted({str(row.get("sha") or "") for row in candidates})
    if any(not _FULL_SHA_RE.fullmatch(value) for value in [*fix_shas, *candidate_shas]):
        raise SystemExit("reduction contains malformed Git SHAs")
    fix_evidence = {
        fix_sha: _fix_dependencies(repository, fix_sha, timeout=timeout)
        for fix_sha in fix_shas
    }
    candidate_evidence: dict[str, PatchSymbols] = {}
    candidate_gaps: list[dict[str, str]] = []
    for candidate_sha in candidate_shas:
        try:
            candidate_evidence[candidate_sha] = _candidate_patch_symbols(
                repository, candidate_sha, timeout=timeout
            )
        except DependencyBridgeError as exc:
            candidate_gaps.append(
                {
                    "candidate_sha": candidate_sha,
                    "operation": "read_candidate_patch",
                    "reason": str(exc),
                }
            )

    rows: list[dict[str, object]] = []
    for source in candidates:
        candidate_sha = str(source["sha"])
        fix_sha = str(source["fix_sha"])
        patch_symbols = candidate_evidence.get(candidate_sha)
        evidence = (
            _bridge_evidence(fix_evidence[fix_sha], patch_symbols)
            if patch_symbols is not None
            else []
        )
        tier, priority_class = _priority(source, evidence)
        rows.append(
            {
                "repository_identity": source.get("repository_identity"),
                "candidate_sha": candidate_sha,
                "fix_sha": fix_sha,
                "candidate_retained": True,
                "input_priority_rank": source.get("priority_rank"),
                "input_priority_class": source.get("priority_class"),
                "input_signals": source.get("signals"),
                "input_materialization": source.get("materialization"),
                "candidate_patch_sha256": (
                    patch_symbols.sha256 if patch_symbols is not None else None
                ),
                "dependency_bridge_evidence": evidence,
                "dependency_priority_tier": tier,
                "dependency_priority_class": priority_class,
                "within_dependency_tier_rank": None,
                "within_fix_review_rank": None,
                "global_review_rank": None,
            }
        )
    schedule = _rank(rows)
    input_keys = {(str(row["sha"]), str(row["fix_sha"])) for row in candidates}
    output_keys = {
        (str(row["candidate_sha"]), str(row["fix_sha"])) for row in rows
    }
    conservation = {
        "input_edge_count": len(candidates),
        "output_edge_count": len(rows),
        "input_unique_edge_count": len(input_keys),
        "output_unique_edge_count": len(output_keys),
        "hard_delete_count": len(input_keys - output_keys),
        "invented_edge_count": len(output_keys - input_keys),
        "all_candidates_retained": all(row["candidate_retained"] is True for row in rows),
        "passed": input_keys == output_keys and len(rows) == len(candidates),
    }
    if not conservation["passed"]:
        raise SystemExit("dependency bridge changed the finite candidate inventory")
    priority_counts = Counter(str(row["dependency_priority_class"]) for row in rows)
    promoted = [
        row
        for row in rows
        if row["dependency_bridge_evidence"]
        and row["input_priority_class"] != "P0_OBSERVED_AI_CAUSAL_SIGNAL"
    ]
    fix_gaps = [gap for evidence in fix_evidence.values() for gap in evidence.coverage_gaps]
    return {
        "schema_version": 1,
        "artifact_kind": "coolify_lossless_cross_file_dependency_bridge_schedule",
        "claim_boundary": (
            "Exact internal dependency overlap is a review-order signal, not a "
            "causal label. Every input AI-ancestor edge is retained, and absence "
            "of a bridge must never be treated as negative evidence."
        ),
        "input": {
            "reduction_dir": str(reduction_dir),
            "summary_sha256": canonical_sha256(summary),
            "candidate_rows_sha256": canonical_sha256(candidates),
            "fix_rows_sha256": canonical_sha256(fixes),
            "candidate_count": len(candidates),
            "fix_count": len(fixes),
        },
        "summary": {
            "edge_count": len(rows),
            "unique_candidate_count": len(candidate_shas),
            "fix_count": len(fix_shas),
            "bridge_edge_count": sum(bool(row["dependency_bridge_evidence"]) for row in rows),
            "newly_promoted_edge_count": len(promoted),
            "newly_promoted_fallback_edge_count": sum(
                row["input_priority_class"] == "P4_OBSERVED_AI_ANCESTRY_FALLBACK"
                for row in promoted
            ),
            "priority_counts": dict(sorted(priority_counts.items())),
            "fix_dependency_coverage_gap_count": len(fix_gaps),
            "candidate_patch_coverage_gap_count": len(candidate_gaps),
        },
        "conservation": conservation,
        "fix_dependency_evidence": [
            {
                "fix_sha": evidence.fix_sha,
                "parent_sha": evidence.parent_sha,
                "changed_runtime_paths": list(evidence.changed_runtime_paths),
                "internal_fqcn_count": len(evidence.fqcns),
                "internal_symbol_count": len(evidence.symbols),
                "coverage_gaps": list(evidence.coverage_gaps),
            }
            for evidence in (fix_evidence[fix_sha] for fix_sha in fix_shas)
        ],
        "candidate_patch_coverage_gaps": candidate_gaps,
        "edge_schedule": sorted(
            rows, key=lambda row: (str(row["fix_sha"]), int(row["within_fix_review_rank"]))
        ),
        "review_schedule": [
            {
                "global_review_rank": row["global_review_rank"],
                "candidate_sha": row["candidate_sha"],
                "fix_sha": row["fix_sha"],
                "dependency_priority_class": row["dependency_priority_class"],
                "within_fix_review_rank": row["within_fix_review_rank"],
            }
            for row in schedule
        ],
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.repo_timeout < 1:
        raise SystemExit("repo-timeout must be positive")
    payload = _build(
        reduction_dir=args.reduction_dir.resolve(),
        repository=args.repository.resolve(),
        timeout=args.repo_timeout,
    )
    _atomic_json(args.output, payload)
    print("cross-file dependency bridge schedule frozen")
    print(f"  edges      : {payload['summary']['edge_count']}")
    print(f"  promoted   : {payload['summary']['newly_promoted_edge_count']}")
    print(f"  gaps       : {payload['summary']['fix_dependency_coverage_gap_count'] + payload['summary']['candidate_patch_coverage_gap_count']}")
    print(f"  output     : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
