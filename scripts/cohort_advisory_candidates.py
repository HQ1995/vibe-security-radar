#!/usr/bin/env python3
"""Build the uncapped advisory candidate inventory for the forward cohort.

This is candidate generation, not vulnerability adjudication.  It performs no
SZZ/blame and no model call.  Every resolvable advisory fix is walked backwards
through local commit topology; incomplete evidence is retained as BLOCKED.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.advisories import index_advisory_fixes
from cohort.advisory_candidates import (
    build_blocked_repository_inventory,
    build_campaign_artifacts,
    build_repository_inventory,
)
from cohort.complex_controls import (
    ComplexControlContractError,
    generation_fix_overlay,
    normalize_complex_controls,
)
from cohort.fix_manifest import (
    FixManifestContractError,
    generation_fix_overlay as sealed_generation_fix_overlay,
    normalize_fix_manifest,
)
from cohort.fix_sources import (
    associations_from_public_references,
    build_repository_recall_floor,
    load_description_search_sources,
    public_fix_observations,
    resolve_commit_refs,
    resolve_source_observations,
    scan_repository_reference_carriers,
)
from cohort.populations import (
    DISCOVERY_POPULATION,
    PopulationContractError,
    load_outcomes_population_contract,
    sha256_file as population_sha256_file,
)
from cohort.relations import (
    canonical_repository_identity,
    normalize_repository_aliases,
)
from cohort.repos import discover_local_clones
from cve_analyzer.git_ops import run_git


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_OSV_DIR = Path.home() / ".cache" / "cve-analyzer" / "osv-bulk"
DEFAULT_DESCRIPTION_SEARCH_DIR = (
    Path.home() / ".cache" / "cve-analyzer" / "desc-search"
)
DEFAULT_CVELIST_DIR = Path.home() / ".cache" / "cve-analyzer" / "cvelistV5" / "cves"
DEFAULT_WORKERS = 8
DEFAULT_REPOSITORY_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"
COHORT_STATE_RELATIVE = (
    Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"
)
DEFAULT_ADVISORY_INDEX_CACHE_DIR = (
    _REPO_ROOT
    / Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY)
    / "cache"
    / "osv-advisory-fix-index-v1"
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outcomes-dir", type=Path, default=None)
    parser.add_argument("--osv-dir", type=Path, default=DEFAULT_OSV_DIR)
    parser.add_argument(
        "--description-search-dir",
        type=Path,
        default=DEFAULT_DESCRIPTION_SEARCH_DIR,
        help=(
            "local cached description-search evidence; selected and rejected"
            " ranked candidates are retained without making a model call"
        ),
    )
    parser.add_argument(
        "--cvelist-dir",
        type=Path,
        default=DEFAULT_CVELIST_DIR,
        help="local CVE List used only for repository-scoped reference anchors",
    )
    parser.add_argument(
        "--no-enriched-fix-sources",
        action="store_true",
        help="diagnostic reproduction mode: use OSV/overlays only",
    )
    parser.add_argument(
        "--no-repository-carrier-scan",
        action="store_true",
        help="do not search local commit messages for advisory/issue reference carriers",
    )
    parser.add_argument(
        "--no-repository-recall-floor",
        action="store_true",
        help="do not materialize the separate repo x advisory x cohort-unit fallback",
    )
    parser.add_argument(
        "--advisory-index-cache-dir",
        type=Path,
        default=DEFAULT_ADVISORY_INDEX_CACHE_DIR,
        help="content-addressed per-archive fix-index cache",
    )
    parser.add_argument(
        "--no-advisory-index-cache",
        action="store_true",
        help="reparse every OSV archive; intended only for cache verification",
    )
    parser.add_argument(
        "--cutoff",
        default="",
        help=(
            "optional advisory publication cutoff for reproduction only; empty"
            " by default so recall-first runs scan every local OSV record"
        ),
    )
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--repo-timeout", type=int, default=300)
    parser.add_argument(
        "--repository-aliases",
        type=Path,
        default=DEFAULT_REPOSITORY_ALIASES,
        help="explicit alias ledger used before joining outcomes, advisories, and clones",
    )
    evaluation_overlay = parser.add_mutually_exclusive_group()
    evaluation_overlay.add_argument(
        "--positive-controls",
        type=Path,
        default=None,
        help="optional exact-fix evaluation overlay; never treated as public-source recall",
    )
    evaluation_overlay.add_argument(
        "--complex-controls",
        type=Path,
        default=None,
        help=(
            "optional complex-control evaluation overlay; generation sees only exact"
            " fix roots, never golden origins or relations"
        ),
    )
    evaluation_overlay.add_argument(
        "--fix-manifest",
        type=Path,
        default=None,
        help=(
            "sealed claim-grade input containing only advisory, repository, and"
            " exact fix SHA; strict schema rejects every golden relation field"
        ),
    )
    parser.add_argument(
        "--repository",
        action="append",
        default=[],
        help="diagnostic scope; repeat to select repositories explicitly",
    )
    parser.add_argument(
        "--limit-repos",
        type=int,
        default=0,
        help="diagnostic scope over sorted repositories; never claim-complete",
    )
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def _latest_outcomes_dir() -> Path:
    root = _REPO_ROOT / COHORT_STATE_RELATIVE
    candidates = sorted(
        path
        for path in root.glob("outcomes-*")
        if (path / "outcomes.jsonl").is_file()
    )
    if not candidates:
        raise SystemExit(f"no outcomes run under {root}")
    return candidates[-1]


def _load_units(path: Path) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                unit = json.loads(line)
            except ValueError as exc:
                raise SystemExit(f"malformed outcomes row {line_number}: {exc}") from exc
            if not isinstance(unit, dict):
                raise SystemExit(f"outcomes row {line_number} is not an object")
            units.append(unit)
    return units


def _require_discovery_population(outcomes_dir: Path) -> dict[str, object]:
    """Fail before OSV indexing if a maturity-filtered cohort is miswired."""

    try:
        return load_outcomes_population_contract(
            outcomes_dir, expected_role=DISCOVERY_POPULATION
        )
    except PopulationContractError as exc:
        raise SystemExit(f"discovery population contract failed: {exc}") from exc


def _load_repository_aliases(path: Path) -> dict[str, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read repository alias ledger {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise SystemExit("repository alias ledger must use schema_version 1")
    rows = payload.get("aliases")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise SystemExit("repository alias ledger aliases must be a list of objects")
    try:
        return normalize_repository_aliases(rows)
    except ValueError as exc:
        raise SystemExit(f"invalid repository alias ledger: {exc}") from exc


def _group_units_by_repository(
    units: list[dict[str, Any]],
    aliases: dict[str, str],
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Canonicalize outcome identities without erasing the observed identity."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    applied = 0
    for raw in units:
        observed = str(raw.get("repository_identity") or "").strip().lower()
        try:
            canonical = canonical_repository_identity(observed, aliases)
        except ValueError as exc:
            raise SystemExit(f"invalid outcome repository identity {observed!r}: {exc}") from exc
        unit = dict(raw)
        unit["repository_identity"] = canonical
        if canonical != observed:
            unit["observed_repository_identity"] = observed
            applied += 1
        grouped[canonical].append(unit)
    return dict(grouped), applied


def _canonicalize_repository_paths(
    repositories: dict[str, Path],
    aliases: dict[str, str],
) -> dict[str, Path]:
    """Join clones by canonical identity, preferring a canonically named clone."""

    canonical_paths: dict[str, tuple[bool, Path]] = {}
    for observed, path in sorted(repositories.items()):
        canonical = canonical_repository_identity(observed, aliases)
        candidate = (observed.strip().lower() == canonical, path)
        prior = canonical_paths.get(canonical)
        if prior is None or candidate[0] > prior[0]:
            canonical_paths[canonical] = candidate
    return {identity: value[1] for identity, value in canonical_paths.items()}


def _canonicalize_fixes_by_repository(
    fixes_by_repo: dict[str, list[dict[str, str]]],
    aliases: dict[str, str],
) -> dict[str, list[dict[str, str]]]:
    canonical: dict[str, list[dict[str, str]]] = defaultdict(list)
    for identity, fixes in fixes_by_repo.items():
        canonical_identity = canonical_repository_identity(identity, aliases)
        canonical[canonical_identity].extend(fixes)
    return dict(canonical)


def _load_positive_control_overlay(
    path: Path,
    aliases: dict[str, str],
) -> tuple[dict[str, list[dict[str, str]]], list[dict[str, object]]]:
    """Load explicit golden fixes while keeping their provenance auditable."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read positive-control overlay {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise SystemExit("positive-control overlay must use schema_version 1")
    rows = payload.get("controls")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise SystemExit("positive-control overlay controls must be a list of objects")

    fixes: dict[str, list[dict[str, str]]] = defaultdict(list)
    controls: list[dict[str, object]] = []
    for raw in rows:
        observed = str(raw.get("repository_identity") or "").strip().lower()
        canonical = canonical_repository_identity(observed, aliases)
        advisory = str(raw.get("advisory") or "").strip()
        source = str(raw.get("source") or "").strip()
        atomic_sha = str(raw.get("atomic_origin_sha") or "").strip().lower()
        fix_sha = str(raw.get("fix_sha") or "").strip().lower()
        for field, sha in (("atomic_origin_sha", atomic_sha), ("fix_sha", fix_sha)):
            if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
                raise SystemExit(f"positive control {advisory or '<unknown>'} has invalid {field}")
        if not advisory or not source:
            raise SystemExit("positive controls require advisory and source")
        control = dict(raw)
        control["repository_identity"] = canonical
        control["atomic_origin_sha"] = atomic_sha
        control["fix_sha"] = fix_sha
        if canonical != observed:
            control["observed_repository_identity"] = observed
        controls.append(control)
        fixes[canonical].append(
            {
                "advisory": advisory,
                "fix_sha": fix_sha,
                "published": "",
                "source": f"positive_control:{source}",
            }
        )
    controls.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]),
            str(row["fix_sha"]),
        )
    )
    return dict(fixes), controls


def _load_complex_control_overlay(
    path: Path,
    aliases: dict[str, str],
) -> tuple[dict[str, list[dict[str, str]]], list[dict[str, object]]]:
    """Validate complex controls, then expose only their fix roots to generation."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read complex-control overlay {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise SystemExit("complex-control overlay must use schema_version 1")
    rows = payload.get("controls")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise SystemExit("complex-control overlay controls must be a list of objects")
    try:
        controls = normalize_complex_controls(rows, aliases)
    except ComplexControlContractError as exc:
        raise SystemExit(f"invalid complex-control overlay: {exc}") from exc
    return generation_fix_overlay(controls), controls


def _load_fix_manifest(
    path: Path,
    aliases: dict[str, str],
) -> tuple[dict[str, list[dict[str, str]]], dict[str, object]]:
    """Load the strict fix-only contract without importing any golden ledger."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read sealed fix manifest {path}: {exc}") from exc
    try:
        manifest = normalize_fix_manifest(payload, aliases)
    except FixManifestContractError as exc:
        raise SystemExit(f"invalid sealed fix manifest: {exc}") from exc
    return sealed_generation_fix_overlay(manifest), manifest


def _flatten_fix_references(
    fixes_by_repo: dict[str, list[dict[str, str]]],
) -> list[dict[str, str]]:
    rows = [
        {"repository_identity": identity, **fix}
        for identity, fixes in fixes_by_repo.items()
        for fix in fixes
    ]
    return sorted(
        rows,
        key=lambda row: (
            row["repository_identity"],
            row["advisory"],
            row["fix_sha"],
            row["published"],
        ),
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _partition_fix_entries(
    repo_path: Path,
    fixes: list[dict[str, str]],
    *,
    timeout: int,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    resolutions = {
        ref: resolved
        for ref, (resolved, _reason) in resolve_commit_refs(
            repo_path,
            {entry["fix_sha"].lower() for entry in fixes},
            timeout=timeout,
        ).items()
    }
    resolved: list[dict[str, str]] = []
    blocked: list[dict[str, str]] = []
    for entry in fixes:
        raw_ref = entry["fix_sha"].lower()
        resolved_sha = resolutions[raw_ref]
        if resolved_sha:
            resolved.append({**entry, "fix_sha": resolved_sha})
        else:
            blocked.append({**entry, "fix_sha": raw_ref})
    return resolved, blocked


def _local_parent_index(
    repo_path: Path,
    repository_identity: str,
    *,
    roots: list[str],
    timeout: int,
) -> dict[str, object]:
    """Read a bounded parent topology without locks, writes, or fetches."""

    base: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "repo_commit_parent_index",
        "repository_identity": repository_identity,
        "since": "",
        "roots": roots,
        "complete": False,
        "error": "",
        "refs_view": {"shallow_commits": []},
        "commits": [],
    }
    try:
        git_dir_result = run_git(
            ["git", "-C", str(repo_path), "rev-parse", "--absolute-git-dir"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=min(timeout, 30),
            no_lazy_fetch=True,
        )
    except Exception as exc:  # noqa: BLE001 - converted to a blocked index
        return {**base, "error": f"git_dir_exception:{type(exc).__name__}"}
    if git_dir_result.returncode != 0:
        return {**base, "error": f"git_dir_nonzero:{git_dir_result.returncode}"}
    git_dir = Path(str(git_dir_result.stdout or "").strip())
    shallow: list[str] = []
    try:
        if (git_dir / "shallow").is_file():
            shallow = sorted(
                line.strip().lower()
                for line in (git_dir / "shallow").read_text(encoding="ascii").splitlines()
                if line.strip()
            )
    except OSError as exc:
        return {**base, "error": f"shallow_read_exception:{type(exc).__name__}"}
    base["refs_view"] = {"shallow_commits": shallow}

    try:
        completed = run_git(
            [
                "git",
                "-C",
                str(repo_path),
                "log",
                *roots,
                "--boundary",
                "--format=%m %H %P %ct",
            ],
            capture_output=True,
            encoding="ascii",
            errors="replace",
            timeout=timeout,
            no_lazy_fetch=True,
        )
    except Exception as exc:  # noqa: BLE001 - converted to a blocked index
        return {**base, "error": f"git_log_parents_exception:{type(exc).__name__}"}
    if completed.returncode != 0:
        return {
            **base,
            "error": f"git_log_parents_nonzero:{completed.returncode}",
        }

    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw_line in str(completed.stdout or "").splitlines():
        fields = raw_line.strip().split()
        if not fields:
            continue
        if len(fields) < 3:
            return {**base, "error": "git_log_parents_malformed_record"}
        marker, sha, *middle, timestamp = fields
        sha = sha.lower()
        parents = [parent.lower() for parent in middle]
        valid_sha = len(sha) == 40 and all(
            character in "0123456789abcdef" for character in sha
        )
        valid_parents = all(
            len(parent) == 40
            and all(character in "0123456789abcdef" for character in parent)
            for parent in parents
        )
        if (
            marker not in {"<", ">", "-", "^"}
            or not valid_sha
            or not valid_parents
            or not timestamp.isdigit()
            or sha in seen
        ):
            return {**base, "error": "git_log_parents_invalid_record"}
        seen.add(sha)
        records.append(
            {
                "sha": sha,
                "parents": sorted(parents),
                "committer_timestamp": int(timestamp),
                "cutoff_boundary": marker == "-",
            }
        )
    records.sort(key=lambda record: str(record["sha"]))
    return {
        **base,
        "complete": True,
        "error": "",
        "commit_count": len(records),
        "commits": records,
    }


def _repository_inventories(
    identity: str,
    repo_path: Path | None,
    units: list[dict[str, Any]],
    fixes: list[dict[str, str]],
    *,
    timeout: int,
) -> list[dict[str, object]]:
    if repo_path is None:
        return [
            build_blocked_repository_inventory(
                identity,
                units,
                fixes,
                reason="no_local_clone",
            )
        ]

    resolved, unresolved = _partition_fix_entries(repo_path, fixes, timeout=timeout)
    inventories: list[dict[str, object]] = []
    if resolved:
        roots = sorted({entry["fix_sha"] for entry in resolved})
        try:
            parent_index = _local_parent_index(
                repo_path,
                identity,
                roots=roots,
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001 - preserve the whole root set
            inventories.append(
                build_blocked_repository_inventory(
                    identity,
                    units,
                    resolved,
                    reason=f"parent_scan_exception:{type(exc).__name__}",
                )
            )
        else:
            inventories.append(
                build_repository_inventory(identity, units, resolved, parent_index)
            )
    if unresolved:
        inventories.append(
            build_blocked_repository_inventory(
                identity,
                units,
                unresolved,
                reason="fix_object_unavailable_or_ambiguous",
            )
        )
    return inventories


def _atomic_write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_write_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.workers < 1 or args.repo_timeout < 1 or args.limit_repos < 0:
        raise SystemExit("workers and repo-timeout must be positive; limit-repos cannot be negative")
    outcomes_dir = args.outcomes_dir or _latest_outcomes_dir()
    outcomes_path = outcomes_dir / "outcomes.jsonl"
    population_contract = _require_discovery_population(outcomes_dir)
    units = _load_units(outcomes_path)
    aliases = _load_repository_aliases(args.repository_aliases)
    by_repo_units, aliases_applied = _group_units_by_repository(units, aliases)

    cohort_repos = set(by_repo_units)
    requested = {
        canonical_repository_identity(identity.strip(), aliases)
        for identity in args.repository
        if identity.strip()
    }
    print(
        f"cohort: {len(units):,} units across {len(cohort_repos):,} repositories",
        flush=True,
    )
    print(
        f"indexing all local OSV records in {args.osv_dir}"
        + (f" with reproduction cutoff {args.cutoff}" if args.cutoff else ""),
        flush=True,
    )
    advisory_join_identities = cohort_repos | {
        alias for alias, canonical in aliases.items() if canonical in cohort_repos
    }
    fixes_by_repo, index_stats = index_advisory_fixes(
        args.osv_dir,
        advisory_join_identities,
        cutoff=args.cutoff,
        cache_dir=(
            None if args.no_advisory_index_cache else args.advisory_index_cache_dir
        ),
    )
    osv_manifest = index_stats.pop("archive_manifest")
    assert isinstance(osv_manifest, list)
    fixes_by_repo = _canonicalize_fixes_by_repository(fixes_by_repo, aliases)
    public_fix_references = _flatten_fix_references(fixes_by_repo)
    public_fix_reference_count = len(public_fix_references)

    repositories, unresolved_clones = discover_local_clones(_REPO_ROOT)
    repositories = _canonicalize_repository_paths(repositories, aliases)
    description_sources: dict[str, object] = {
        "associations": [],
        "observations": [],
        "stats": {},
        "associations_sha256": _canonical_sha256([]),
        "observations_sha256": _canonical_sha256([]),
    }
    enriched_fix_sources_active = (
        not args.no_enriched_fix_sources and args.fix_manifest is None
    )
    if enriched_fix_sources_active:
        print(
            f"loading cached enriched fix evidence from {args.description_search_dir}",
            flush=True,
        )
        description_sources = load_description_search_sources(
            args.description_search_dir,
            cohort_repos,
            aliases,
            cvelist_dir=args.cvelist_dir,
        )
    raw_associations = description_sources["associations"]
    raw_description_observations = description_sources["observations"]
    assert isinstance(raw_associations, list)
    assert isinstance(raw_description_observations, list)
    carrier_observations: list[dict[str, object]] = []
    carrier_stats: dict[str, object] = {
        "queries": 0,
        "observation_count": 0,
        "blocked": [],
        "observations_sha256": _canonical_sha256([]),
    }
    repository_carrier_scan_active = (
        enriched_fix_sources_active and not args.no_repository_carrier_scan
    )
    if repository_carrier_scan_active and raw_associations:
        carrier_observations, carrier_stats = scan_repository_reference_carriers(
            repositories,
            raw_associations,
            timeout=args.repo_timeout,
        )
    public_observations = public_fix_observations(public_fix_references)
    all_source_observations = [
        *public_observations,
        *raw_description_observations,
        *carrier_observations,
    ]
    (
        resolved_source_observations,
        source_fixes_by_repo,
        source_resolution_stats,
    ) = resolve_source_observations(
        all_source_observations,
        repositories,
        timeout=args.repo_timeout,
        workers=args.workers,
    )
    for identity, fixes in source_fixes_by_repo.items():
        if identity in cohort_repos:
            fixes_by_repo.setdefault(identity, []).extend(fixes)

    controls: list[dict[str, object]] = []
    if args.positive_controls is not None:
        control_fixes, controls = _load_positive_control_overlay(
            args.positive_controls,
            aliases,
        )
        for identity, fixes in control_fixes.items():
            if identity in cohort_repos:
                fixes_by_repo.setdefault(identity, []).extend(fixes)
    complex_controls: list[dict[str, object]] = []
    if args.complex_controls is not None:
        complex_control_fixes, complex_controls = _load_complex_control_overlay(
            args.complex_controls,
            aliases,
        )
        for identity, fixes in complex_control_fixes.items():
            if identity in cohort_repos:
                fixes_by_repo.setdefault(identity, []).extend(fixes)
    fix_manifest: dict[str, object] | None = None
    if args.fix_manifest is not None:
        manifest_fixes, fix_manifest = _load_fix_manifest(
            args.fix_manifest,
            aliases,
        )
        for identity, fixes in manifest_fixes.items():
            if identity in cohort_repos:
                fixes_by_repo.setdefault(identity, []).extend(fixes)

    all_associations = [
        *associations_from_public_references(public_fix_references),
        *raw_associations,
    ]
    identity_universe = set(fixes_by_repo) | {
        str(row.get("repository_identity") or "").strip().lower()
        for row in all_associations
    }
    selected_repository_scope = sorted(identity_universe)
    if requested:
        selected_repository_scope = [
            identity for identity in selected_repository_scope if identity in requested
        ]
    if args.limit_repos:
        selected_repository_scope = selected_repository_scope[: args.limit_repos]
    identities = [
        identity
        for identity in selected_repository_scope
        if identity in fixes_by_repo and identity in by_repo_units
    ]
    scope_complete = not requested and args.limit_repos == 0
    fallback_units = {
        identity: by_repo_units[identity]
        for identity in selected_repository_scope
        if identity in by_repo_units
    }
    recall_floor = build_repository_recall_floor(
        fallback_units,
        all_associations if not args.no_repository_recall_floor else [],
    )
    print(
        f"advisory fixes: {sum(len(value) for value in fixes_by_repo.values()):,} raw references"
        f" in {len(fixes_by_repo):,} repositories; processing {len(identities):,}"
        f" graph repositories and {len(selected_repository_scope):,} recall-floor repositories",
        flush=True,
    )

    inventories: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                _repository_inventories,
                identity,
                repositories.get(identity),
                by_repo_units[identity],
                fixes_by_repo[identity],
                timeout=args.repo_timeout,
            ): identity
            for identity in identities
        }
        for completed_count, future in enumerate(as_completed(futures), start=1):
            identity = futures[future]
            try:
                inventories.extend(future.result())
            except Exception as exc:  # noqa: BLE001 - retain an explicit run failure
                failures.append(
                    {
                        "repository_identity": identity,
                        "reason": f"inventory_exception:{type(exc).__name__}",
                    }
                )
                inventories.append(
                    build_blocked_repository_inventory(
                        identity,
                        by_repo_units[identity],
                        fixes_by_repo[identity],
                        reason=f"inventory_exception:{type(exc).__name__}",
                    )
                )
            if completed_count % 25 == 0 or completed_count == len(futures):
                print(f"  [{completed_count}/{len(futures)}] {identity}", flush=True)

    artifacts = build_campaign_artifacts(inventories)
    recall_floor_summary = recall_floor["summary"]
    fallback_candidates = recall_floor["candidates"]
    fallback_associations = recall_floor["associations"]
    assert isinstance(recall_floor_summary, dict)
    assert isinstance(fallback_candidates, list)
    assert isinstance(fallback_associations, list)
    source_kind_counts = Counter(
        str(row.get("evidence_kind") or "")
        for row in resolved_source_observations
    )
    inherited_model_evidence_count = sum(
        bool(str(row.get("inherited_model") or "").strip())
        for row in resolved_source_observations
    )
    summary = dict(artifacts["summary"])
    summary.pop("summary_sha256", None)
    summary.update(
        {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "outcomes_path": str(outcomes_path),
            "outcomes_sha256": _sha256_file(outcomes_path),
            "outcomes_summary_sha256": population_sha256_file(
                outcomes_dir / "summary.json"
            ),
            "population_contract": population_contract,
            "osv_dir": str(args.osv_dir),
            "osv_archives": osv_manifest,
            "osv_archives_sha256": _canonical_sha256(osv_manifest),
            "osv_index_stats": index_stats,
            "advisory_index_cache_enabled": not args.no_advisory_index_cache,
            "advisory_index_cache_dir": (
                str(args.advisory_index_cache_dir)
                if not args.no_advisory_index_cache
                else ""
            ),
            "public_fix_reference_count": public_fix_reference_count,
            "public_fix_references_sha256": _canonical_sha256(public_fix_references),
            "enriched_fix_sources_active": enriched_fix_sources_active,
            "description_search_dir": str(args.description_search_dir),
            "description_source_stats": description_sources["stats"],
            "description_source_associations_sha256": description_sources[
                "associations_sha256"
            ],
            "description_source_observations_sha256": description_sources[
                "observations_sha256"
            ],
            "repository_carrier_scan_active": repository_carrier_scan_active,
            "repository_carrier_stats": carrier_stats,
            "fix_source_resolution_stats": source_resolution_stats,
            "fix_source_observation_count": len(resolved_source_observations),
            "fix_source_observations_sha256": _canonical_sha256(
                resolved_source_observations
            ),
            "fix_source_evidence_kind_counts": dict(sorted(source_kind_counts.items())),
            "inherited_model_evidence_count": inherited_model_evidence_count,
            "inherited_model_calls_made_this_run": 0,
            "repository_recall_floor_active": not args.no_repository_recall_floor,
            "repository_recall_floor": recall_floor_summary,
            "advisory_publication_cutoff": args.cutoff,
            "repository_aliases_path": str(args.repository_aliases),
            "repository_aliases_sha256": _sha256_file(args.repository_aliases),
            "repository_alias_count": len(aliases),
            "repository_aliases_applied_to_units": aliases_applied,
            "positive_control_overlay_active": args.positive_controls is not None,
            "positive_control_overlay_path": (
                str(args.positive_controls) if args.positive_controls is not None else ""
            ),
            "positive_control_overlay_sha256": (
                _sha256_file(args.positive_controls)
                if args.positive_controls is not None
                else ""
            ),
            "positive_control_count": len(controls),
            "complex_control_overlay_active": args.complex_controls is not None,
            "complex_control_overlay_path": (
                str(args.complex_controls) if args.complex_controls is not None else ""
            ),
            "complex_control_overlay_sha256": (
                _sha256_file(args.complex_controls)
                if args.complex_controls is not None
                else ""
            ),
            "complex_control_count": len(complex_controls),
            "sealed_fix_manifest_active": args.fix_manifest is not None,
            "sealed_fix_manifest_path": (
                str(args.fix_manifest) if args.fix_manifest is not None else ""
            ),
            "sealed_fix_manifest_sha256": (
                _sha256_file(args.fix_manifest) if args.fix_manifest is not None else ""
            ),
            "sealed_fix_manifest_split_id": (
                str(fix_manifest["split_id"]) if fix_manifest is not None else ""
            ),
            "sealed_fix_manifest_fix_count": (
                len(fix_manifest["fixes"]) if fix_manifest is not None else 0
            ),
            "generation_process_boundary": (
                "sealed_fix_only_no_golden_ledger_read"
                if fix_manifest is not None
                else "public_plus_cached_enriched_recall_sources_no_golden_ledger"
            ),
            "scope_complete": scope_complete,
            "selected_repositories": (
                selected_repository_scope if not scope_complete else []
            ),
            "campaign_complete": bool(summary["coverage_complete"] and scope_complete),
            "unresolved_clone_directories": len(unresolved_clones),
            "inventory_failures": failures,
            "model_api_calls": 0,
            "model_input_tokens": 0,
            "model_output_tokens": 0,
            "model_cost_usd": 0.0,
            "claim_boundary": (
                "complete only for observed forward-cohort SHAs, local OSV fix"
                " references, locally cached enriched source observations, resolvable"
                " local commit history, and SHA ancestry; enriched selections are not"
                " public exact references and carriers are candidate roots, not verified"
                " fixes; the separate repository-advisory fallback retains every observed"
                " cohort unit without claiming ancestry;"
                " BLOCKED roots are unknown, never negatives; an explicit positive-control"
                " overlay evaluates relation recall and is not public advisory-source recall;"
                " a complex-control overlay exposes only fix roots to generation and keeps"
                " golden origins and relations evaluation-only; a sealed fix"
                " manifest is strict fix-only input and does not load the golden"
                " ledger in the generation process"
            ),
        }
    )
    summary["summary_sha256"] = _canonical_sha256(summary)

    output_dir = args.output_dir or (
        _REPO_ROOT
        / COHORT_STATE_RELATIVE
        / f"advisory-candidates-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    candidates = artifacts["candidates"]
    fix_roots = artifacts["fix_roots"]
    routing = artifacts["routing"]
    assert isinstance(candidates, list)
    assert isinstance(fix_roots, list)
    assert isinstance(routing, dict)
    routes = routing["routes"]
    assert isinstance(routes, list)
    _atomic_write_jsonl(output_dir / "candidates.jsonl", candidates)
    _atomic_write_jsonl(output_dir / "fix_roots.jsonl", fix_roots)
    _atomic_write_jsonl(
        output_dir / "public_fix_references.jsonl",
        public_fix_references,
    )
    _atomic_write_jsonl(
        output_dir / "fix_source_observations.jsonl",
        resolved_source_observations,
    )
    _atomic_write_jsonl(
        output_dir / "repository_advisory_associations.jsonl",
        fallback_associations,
    )
    _atomic_write_jsonl(
        output_dir / "repository_fallback_candidates.jsonl",
        fallback_candidates,
    )
    _atomic_write_json(
        output_dir / "repository_fallback_summary.json",
        recall_floor_summary,
    )
    _atomic_write_jsonl(output_dir / "routing.jsonl", routes)
    _atomic_write_json(output_dir / "summary.json", summary)

    conservation = summary["conservation"]
    assert isinstance(conservation, dict)
    print("\nRecall-first advisory candidate inventory")
    print(f"  fix roots       : {conservation['fix_root_count']:,}")
    print(f"  resolved        : {conservation['resolved_fix_root_count']:,}")
    print(f"  blocked         : {conservation['blocked_fix_root_count']:,}")
    print(f"  candidate edges : {conservation['candidate_edge_count']:,}")
    print(f"  initial DEFER   : {conservation['deferred_edge_count']:,}")
    print(f"  source fallback : {len(fallback_candidates):,} DEFER rows")
    print("  model/API cost  : $0.00")
    print(f"  output           : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
