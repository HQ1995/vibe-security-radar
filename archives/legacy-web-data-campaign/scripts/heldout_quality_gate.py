#!/usr/bin/env python3
"""Create and evaluate a leakage-resistant held-out detector-quality sample.

The workflow is deliberately two phase. ``select`` proves a complete fixed-contract
campaign, removes every advisory class named by the protected calibration/audit
inputs, and seals two deterministic samples before any labels exist. ``evaluate``
re-proves the campaign and selection, then accepts only blinded, independent
dual-review labels bound to that exact selection digest.

Precision trials are sampled from final predicted-positive alias classes. Recall
trials are independently sampled from classes with a production-v1 strict
``Co-authored-by`` trailer match on at least one candidate bug-introducing commit,
before the final publication predicate. This recall lane measures the final
classifier within the production source-matcher population; it does not estimate
upstream advisory-discovery or source-matcher recall.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import unquote

import evaluate_detector_quality as detector_quality
import data_refresh_paths
from evaluate_publication_quality import clopper_pearson_lower_bound
from cve_analyzer.source_matcher import bic_is_candidate
from web_data.loader import build_alias_map

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_DEFAULT_OUTPUT_DIR = (
    data_refresh_paths.data_refresh_state_root(_REPO_ROOT) / "heldout-v1"
)
_HELDOUT_STUDIES_ROOT = Path("scripts/heldout_studies")
_DEFAULT_PROTECTED_SOURCES = (
    Path("scripts/audit_adjudications.json"),
    Path("scripts/audit_overrides.json"),
    Path("scripts/audit_removed_94.json"),
    Path("scripts/audit_results"),
    Path("scripts/fixtures"),
    _HELDOUT_STUDIES_ROOT,
    data_refresh_paths.DATA_REFRESH_STATE_RELATIVE
    / "adjudicated-corpus-subjects.txt",
)
_ALLOWED_LABELS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"})
_FORMAL_LABELS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL"})
_LABEL_MATERIAL_KEYS = frozenset(
    {"adjudication", "adjudications", "ground_truth", "label", "labels", "verdict"}
)
_VULNERABILITY_TOKEN = re.compile(
    r"(?<![A-Za-z0-9._-])(?:"
    r"CVE-\d{4}-\d{3,}|"
    r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}|"
    r"[A-Za-z][A-Za-z0-9._]*-\d{4}-[A-Za-z0-9._-]+"
    r")(?![A-Za-z0-9._-])",
    re.IGNORECASE,
)
_EMBEDDED_PRIMARY_VULNERABILITY_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:CVE-\d{4}-\d{3,}|"
    r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4})"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_EMBEDDED_YEAR_VULNERABILITY_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z][A-Za-z0-9.]*-\d{4}-"
    r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_MAX_URL_UNQUOTE_ROUNDS = 8
_MAX_PROTECTED_VALUE_CHARS = 16 * 1024 * 1024
_SELECTION_ALGORITHM = "heldout-fixed-campaign-domain-separated-uniform-topk-v3"
_SELECTION_SCHEMA_VERSION = 3
_LABEL_SCHEMA_VERSION = 3
_DEFAULT_PRECISION_TARGET = 0.95
_DEFAULT_RECALL_TARGET = 0.95
_COMMIT_REFERENCE = re.compile(
    r"^(?P<commit>(?:[0-9a-f]{40}|[0-9a-f]{64})):(?P<path>[^:\x00]+)$"
)
_MAX_SELECTION_BYTES = 16 * 1024 * 1024
_MAX_LABEL_BYTES = 16 * 1024 * 1024
_MAX_PROTECTED_INPUT_BYTES = 32 * 1024 * 1024
_MAX_PROTECTED_INPUTS_TOTAL_BYTES = 128 * 1024 * 1024
_MAX_SELECTION_CODE_BYTES = 4 * 1024 * 1024
_GIT_EXECUTABLE = Path("/usr/bin/git")


class HeldoutQualityError(ValueError):
    """Raised when a held-out quality contract cannot be proved."""


@dataclass(frozen=True, slots=True)
class ResultReference:
    subject_id: str
    sha256: str


@dataclass(frozen=True, slots=True)
class SelectionUnit:
    """One source-backed advisory alias class in the fixed campaign."""

    canonical_id: str
    subject_ids: tuple[str, ...]
    predicted_positive: bool
    candidate_positive: bool
    prediction_reasons: tuple[str, ...]
    infrastructure_categories: tuple[str, ...]
    unresolved_reasons: tuple[str, ...]
    results: tuple[ResultReference, ...]
    screening_positive: bool = False


@dataclass(frozen=True, slots=True)
class CampaignSnapshot:
    """Content-addressed view of one fully proved campaign."""

    campaign_id: str
    contract_sha256: str
    source_snapshot_sha256: str
    campaign_proof_sha256: str
    campaign_result_manifest_sha256: str
    proof_complete: bool
    units: tuple[SelectionUnit, ...]


@dataclass(frozen=True, slots=True)
class ProtectedInventory:
    """Every pre-existing subject forbidden from the held-out sample."""

    subject_ids: frozenset[str]
    source_roots: tuple[dict[str, str], ...]
    files: tuple[dict[str, Any], ...]
    files_manifest_sha256: str
    subject_ids_sha256: str


def protected_inventory_contract(protected: ProtectedInventory) -> dict[str, Any]:
    """Return the exact provenance contract sealed into a selection artifact."""

    return {
        "source_roots": list(protected.source_roots),
        "files": list(protected.files),
        "files_manifest_sha256": protected.files_manifest_sha256,
        "subject_id_count": len(protected.subject_ids),
        "subject_ids_sha256": protected.subject_ids_sha256,
    }


@dataclass(frozen=True, slots=True)
class GitRepository:
    worktree: Path
    git_dir: Path
    common_dir: Path


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def canonical_artifact_bytes(value: object) -> bytes:
    """Render the exact tracked/archive JSON representation used by this workflow."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _read_regular_file_fd(
    path: Path,
    *,
    description: str,
    max_bytes: int,
) -> tuple[bytes, os.stat_result]:
    """Read one path through a no-follow descriptor and reject path replacement."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HeldoutQualityError(f"cannot open {description} {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise HeldoutQualityError(f"{description} is not a regular file: {path}")
        if before.st_size > max_bytes:
            raise HeldoutQualityError(
                f"{description} exceeds the {max_bytes}-byte size bound: {path}"
            )
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise HeldoutQualityError(
                    f"{description} exceeds the {max_bytes}-byte size bound: {path}"
                )
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise HeldoutQualityError(f"cannot read {description} {path}: {exc}") from exc
    finally:
        os.close(descriptor)

    signature = lambda value: (  # noqa: E731 - compact immutable stat projection
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    content = b"".join(chunks)
    if signature(before) != signature(after) or len(content) != after.st_size:
        raise HeldoutQualityError(f"{description} changed while read: {path}")
    try:
        current = path.lstat()
    except OSError as exc:
        raise HeldoutQualityError(
            f"cannot recheck {description} {path}: {exc}"
        ) from exc
    if signature(current) != signature(after):
        raise HeldoutQualityError(f"{description} path changed while read: {path}")
    return content, after


def _file_sha256(path: Path, *, description: str, max_bytes: int) -> str:
    content, _ = _read_regular_file_fd(
        path,
        description=description,
        max_bytes=max_bytes,
    )
    return hashlib.sha256(content).hexdigest()


def _stable_file(
    path: Path,
    *,
    description: str,
    max_bytes: int,
) -> tuple[bytes, os.stat_result]:
    return _read_regular_file_fd(
        path,
        description=description,
        max_bytes=max_bytes,
    )


def _validate_digest(value: object, description: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise HeldoutQualityError(f"{description} must be a lowercase SHA-256 digest")
    return value


def _validate_target(value: float, description: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HeldoutQualityError(f"{description} must be numeric")
    target = float(value)
    if not 0.0 <= target <= 1.0:
        raise HeldoutQualityError(f"{description} must be between 0 and 1")
    return target


def _id_family(value: str) -> str:
    prefix = value.split("-", 1)[0].upper()
    return prefix if prefix in {"CVE", "GHSA", "OSV", "RUSTSEC"} else "OTHER"


def _subject_key(value: str) -> str:
    """Return the case-insensitive identity key while retaining source display IDs."""

    return value.casefold()


def _normalized_alias_index(
    alias_map: Mapping[str, set[str]],
) -> dict[str, frozenset[str]]:
    """Index alias closures by case-insensitive ID and preserve map spellings."""

    groups: dict[str, set[str]] = defaultdict(set)
    for raw_key, raw_values in alias_map.items():
        if not isinstance(raw_key, str):
            continue
        values = {raw_key}
        values.update(value for value in raw_values if isinstance(value, str))
        groups[_subject_key(raw_key)].update(values)
    return {key: frozenset(values) for key, values in groups.items()}


def _subjects_overlap(left: Iterable[str], right: Iterable[str]) -> bool:
    right_keys = {_subject_key(value) for value in right}
    return any(_subject_key(value) in right_keys for value in left)


def _canonical_subject(subject_ids: Iterable[str]) -> str:
    ids = sorted(set(subject_ids))
    if not ids:
        raise HeldoutQualityError("alias class cannot be empty")
    priorities = {"CVE": 0, "GHSA": 1, "OSV": 2, "RUSTSEC": 3}
    return min(ids, key=lambda value: (priorities.get(_id_family(value), 4), value))


def _selection_seed(snapshot: CampaignSnapshot) -> str:
    return hashlib.sha256(
        b"\0".join(
            (
                _SELECTION_ALGORITHM.encode(),
                snapshot.campaign_id.encode(),
                snapshot.contract_sha256.encode(),
                snapshot.source_snapshot_sha256.encode(),
                snapshot.campaign_result_manifest_sha256.encode(),
            )
        )
    ).hexdigest()


def _selection_rank(seed: str, lane: str, unit: SelectionUnit) -> str:
    return hashlib.sha256(
        b"\0".join(
            (
                _SELECTION_ALGORITHM.encode(),
                seed.encode(),
                lane.encode(),
                unit.canonical_id.encode(),
                "\n".join(unit.subject_ids).encode(),
            )
        )
    ).hexdigest()


def _allocate_uniform_sample(
    units: Sequence[SelectionUnit],
    *,
    sample_size: int,
    seed: str,
    lane: str,
) -> tuple[SelectionUnit, ...]:
    """Select one global hash top-k so every unit has the same inclusion chance."""
    if isinstance(sample_size, bool) or not isinstance(sample_size, int):
        raise HeldoutQualityError(f"{lane} sample size must be an integer")
    if sample_size <= 0:
        raise HeldoutQualityError(f"{lane} sample size must be positive")
    if sample_size > len(units):
        raise HeldoutQualityError(
            f"{lane} sample size {sample_size} exceeds population {len(units)}"
        )

    selected = sorted(
        units,
        key=lambda unit: (_selection_rank(seed, lane, unit), unit.canonical_id),
    )[:sample_size]
    return tuple(sorted(selected, key=lambda unit: unit.canonical_id))


def _unit_manifest_row(unit: SelectionUnit, *, seed: str, lane: str) -> dict[str, Any]:
    execution_status = "ok"
    if unit.infrastructure_categories:
        execution_status = "infrastructure_error"
    elif unit.unresolved_reasons:
        execution_status = "unresolved"
    return {
        "sample_id": unit.canonical_id,
        "subject_ids": list(unit.subject_ids),
        "stratum": _id_family(unit.canonical_id),
        "selection_rank_sha256": _selection_rank(seed, lane, unit),
        "predicted_positive": unit.predicted_positive,
        "candidate_positive": unit.candidate_positive,
        "screening_positive": unit.screening_positive,
        "prediction_reasons": list(unit.prediction_reasons),
        "execution_status": execution_status,
        "infrastructure_categories": list(unit.infrastructure_categories),
        "unresolved_reasons": list(unit.unresolved_reasons),
        "campaign_results": [
            {"subject_id": result.subject_id, "sha256": result.sha256}
            for result in unit.results
        ],
    }


def _assert_no_label_material(value: object, path: str = "selection") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).casefold() in _LABEL_MATERIAL_KEYS:
                raise HeldoutQualityError(
                    f"label material is forbidden in the sealed selection: {path}.{key}"
                )
            _assert_no_label_material(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_no_label_material(child, f"{path}[{index}]")
    elif isinstance(value, str) and value in _ALLOWED_LABELS:
        raise HeldoutQualityError(
            f"label value is forbidden in the sealed selection: {path}"
        )


def _seal_selection(payload: dict[str, Any]) -> dict[str, Any]:
    _assert_no_label_material(payload)
    sealed = dict(payload)
    sealed["selection_manifest_sha256"] = canonical_sha256(payload)
    return sealed


def validate_selection_seal(manifest: Mapping[str, Any]) -> str:
    if not isinstance(manifest, Mapping):
        raise HeldoutQualityError("selection manifest must be an object")
    expected_fields = {
        "schema_version",
        "kind",
        "algorithm",
        "campaign",
        "selection_policy",
        "protected_inputs",
        "population",
        "samples",
        "lane_overlap",
        "measurement_boundary",
        "selection_manifest_sha256",
    }
    if set(manifest) != expected_fields:
        raise HeldoutQualityError("selection manifest requires exact schema-3 fields")
    if (
        manifest.get("schema_version") != _SELECTION_SCHEMA_VERSION
        or manifest.get("kind") != "heldout_detector_quality_selection"
        or manifest.get("algorithm") != _SELECTION_ALGORITHM
    ):
        raise HeldoutQualityError("selection manifest schema or algorithm is invalid")
    policy = manifest.get("selection_policy")
    expected_policy = {
        "seed_sha256",
        "selection_code_sha256",
        "precision_sample_size",
        "recall_sample_size",
        "precision_population",
        "recall_population",
        "sampling",
        "stratification",
        "lane_ranking",
        "labels_permitted_during_selection",
    }
    if (
        not isinstance(policy, Mapping)
        or set(policy) != expected_policy
        or policy.get("sampling") != "global_uniform_domain_separated_sha256_top_k"
        or policy.get("stratification") != "canonical_id_family_diagnostics_only"
        or policy.get("lane_ranking") != "global_domain_separated_sha256"
        or policy.get("labels_permitted_during_selection") is not False
    ):
        raise HeldoutQualityError("selection policy is invalid")
    if (
        policy.get("precision_population")
        != "fixed_campaign_predicted_positive_alias_classes"
        or policy.get("recall_population")
        != "fixed_campaign_strict_coauthor_candidate_positive_alias_classes"
    ):
        raise HeldoutQualityError("selection population policy is invalid")
    for lane in ("precision", "recall"):
        sample_size = policy.get(f"{lane}_sample_size")
        if (
            isinstance(sample_size, bool)
            or not isinstance(sample_size, int)
            or sample_size <= 0
        ):
            raise HeldoutQualityError(f"selection {lane} sample size is invalid")
    _validate_digest(policy.get("seed_sha256"), "selection seed")
    _validate_digest(policy.get("selection_code_sha256"), "selection code")
    payload = dict(manifest)
    digest = _validate_digest(
        payload.pop("selection_manifest_sha256", None),
        "selection_manifest_sha256",
    )
    _assert_no_label_material(payload)
    actual = canonical_sha256(payload)
    if actual != digest:
        raise HeldoutQualityError(
            f"selection manifest digest mismatch: expected {digest}, computed {actual}"
        )
    return digest


def build_selection_manifest(
    snapshot: CampaignSnapshot,
    protected: ProtectedInventory,
    *,
    precision_sample_size: int,
    recall_sample_size: int,
    selection_code_sha256: str,
) -> dict[str, Any]:
    """Build a deterministic pre-label selection from a proved campaign."""
    if not snapshot.proof_complete:
        raise HeldoutQualityError("fixed-contract campaign proof is incomplete")
    for field_name, value in (
        ("campaign_id", snapshot.campaign_id),
        ("contract_sha256", snapshot.contract_sha256),
        ("source_snapshot_sha256", snapshot.source_snapshot_sha256),
        ("campaign_proof_sha256", snapshot.campaign_proof_sha256),
        ("campaign_result_manifest_sha256", snapshot.campaign_result_manifest_sha256),
        ("selection_code_sha256", selection_code_sha256),
        ("protected files manifest", protected.files_manifest_sha256),
        ("protected subject IDs", protected.subject_ids_sha256),
    ):
        _validate_digest(value, field_name)

    excluded = tuple(
        unit
        for unit in snapshot.units
        if _subjects_overlap(protected.subject_ids, unit.subject_ids)
    )
    eligible = tuple(
        unit
        for unit in snapshot.units
        if not _subjects_overlap(protected.subject_ids, unit.subject_ids)
    )
    precision_population = tuple(unit for unit in eligible if unit.predicted_positive)
    recall_population = tuple(unit for unit in eligible if unit.candidate_positive)
    if not precision_population:
        raise HeldoutQualityError("predicted-positive precision population is empty")
    if not recall_population:
        raise HeldoutQualityError("candidate-positive recall population is empty")

    seed = _selection_seed(snapshot)
    precision_sample = _allocate_uniform_sample(
        precision_population,
        sample_size=precision_sample_size,
        seed=seed,
        lane="precision",
    )
    recall_sample = _allocate_uniform_sample(
        recall_population,
        sample_size=recall_sample_size,
        seed=seed,
        lane="recall",
    )
    precision_ids = {unit.canonical_id for unit in precision_sample}
    recall_ids = {unit.canonical_id for unit in recall_sample}

    payload = {
        "schema_version": _SELECTION_SCHEMA_VERSION,
        "kind": "heldout_detector_quality_selection",
        "algorithm": _SELECTION_ALGORITHM,
        "campaign": {
            "campaign_id": snapshot.campaign_id,
            "contract_sha256": snapshot.contract_sha256,
            "source_snapshot_sha256": snapshot.source_snapshot_sha256,
            "campaign_proof_sha256": snapshot.campaign_proof_sha256,
            "campaign_result_manifest_sha256": (
                snapshot.campaign_result_manifest_sha256
            ),
            "proof_complete": True,
        },
        "selection_policy": {
            "seed_sha256": seed,
            "selection_code_sha256": selection_code_sha256,
            "precision_sample_size": precision_sample_size,
            "recall_sample_size": recall_sample_size,
            "precision_population": "fixed_campaign_predicted_positive_alias_classes",
            "recall_population": (
                "fixed_campaign_strict_coauthor_candidate_positive_alias_classes"
            ),
            "sampling": "global_uniform_domain_separated_sha256_top_k",
            "stratification": "canonical_id_family_diagnostics_only",
            "lane_ranking": "global_domain_separated_sha256",
            "labels_permitted_during_selection": False,
        },
        "protected_inputs": protected_inventory_contract(protected),
        "population": {
            "campaign_alias_class_count": len(snapshot.units),
            "protected_overlap_class_count": len(excluded),
            "protected_overlap_ids": [unit.canonical_id for unit in excluded],
            "eligible_alias_class_count": len(eligible),
            "precision_population_count": len(precision_population),
            "recall_population_count": len(recall_population),
        },
        "samples": {
            "precision": [
                _unit_manifest_row(unit, seed=seed, lane="precision")
                for unit in precision_sample
            ],
            "recall": [
                _unit_manifest_row(unit, seed=seed, lane="recall")
                for unit in recall_sample
            ],
        },
        "lane_overlap": {
            "count": len(precision_ids & recall_ids),
            "ids": sorted(precision_ids & recall_ids),
            "interpretation": (
                "domain-separated draws are independent lanes; one audit may serve "
                "both metrics when the deterministic samples overlap"
            ),
        },
        "measurement_boundary": {
            "precision": (
                "final detector precision among fixed-campaign predicted positives"
            ),
            "recall": (
                "final classifier recall among fixed-campaign candidate-positive "
                "classes where raw bug-introducing-commit evidence already contains "
                "an AI signal"
            ),
            "excluded": (
                "upstream advisory discovery and AI-signature discovery recall"
            ),
        },
    }
    return _seal_selection(payload)


def _path_label(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise HeldoutQualityError(
            f"protected source escapes repository root: {path}"
        ) from exc


def _protected_files(
    repo_root: Path,
    source_paths: Sequence[Path],
    *,
    excluded_paths: Sequence[Path] = (),
) -> tuple[Path, ...]:
    files: list[Path] = []
    seen: set[Path] = set()
    excluded = {path.resolve() for path in excluded_paths}
    for raw_path in source_paths:
        path = raw_path if raw_path.is_absolute() else repo_root / raw_path
        if path.is_symlink() or not path.exists():
            raise HeldoutQualityError(f"protected source is missing or unsafe: {path}")
        candidates = [path] if path.is_file() else sorted(path.rglob("*"))
        for candidate in candidates:
            if candidate.is_symlink():
                raise HeldoutQualityError(
                    f"protected source contains a symlink: {candidate}"
                )
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if resolved in excluded:
                continue
            if resolved not in seen:
                seen.add(resolved)
                files.append(resolved)
    if not files:
        raise HeldoutQualityError("protected source inventory is empty")
    return tuple(sorted(files, key=lambda path: _path_label(path, repo_root)))


def _extract_subject_tokens(content: bytes, relative_path: PurePosixPath) -> set[str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HeldoutQualityError(
            f"protected source must be UTF-8 text: {relative_path}"
        ) from exc
    ids: set[str] = set()

    def collect(value: str, *, include_generic: bool = True) -> None:
        if len(value) > _MAX_PROTECTED_VALUE_CHARS:
            raise HeldoutQualityError(
                f"protected value exceeds decode bound: {relative_path}"
            )
        candidate = value
        for _round in range(_MAX_URL_UNQUOTE_ROUNDS):
            primary = {
                token.upper()
                for token in _EMBEDDED_PRIMARY_VULNERABILITY_TOKEN.findall(candidate)
            }
            year_based = set()
            for token in _EMBEDDED_YEAR_VULNERABILITY_TOKEN.findall(candidate):
                upper = token.upper()
                if ("CVE-" in upper and not upper.startswith("CVE-")) or (
                    "GHSA-" in upper and not upper.startswith("GHSA-")
                ):
                    continue
                year_based.add(upper)
            ids.update(primary | year_based)
            for token in (
                _VULNERABILITY_TOKEN.findall(candidate) if include_generic else ()
            ):
                upper = token.upper()
                if (
                    _EMBEDDED_PRIMARY_VULNERABILITY_TOKEN.search(upper) is not None
                    or _EMBEDDED_YEAR_VULNERABILITY_TOKEN.search(upper) is not None
                ):
                    continue
                if ("CVE-" in upper and not upper.startswith("CVE-")) or (
                    "GHSA-" in upper and not upper.startswith("GHSA-")
                ):
                    continue
                ids.add(upper)
            try:
                decoded = unquote(candidate, encoding="utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise HeldoutQualityError(
                    f"protected value contains invalid percent encoding: {relative_path}"
                ) from exc
            if len(decoded) > _MAX_PROTECTED_VALUE_CHARS:
                raise HeldoutQualityError(
                    f"decoded protected value exceeds bound: {relative_path}"
                )
            if decoded == candidate:
                return
            candidate = decoded
        raise HeldoutQualityError(
            f"protected percent decoding did not stabilize: {relative_path}"
        )

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                collect(str(key))
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
        elif isinstance(value, str):
            collect(value)

    collect(text)
    path_components = relative_path.parts
    for component in path_components[:-1]:
        # Directory suffixes are ordinary name material.  Scanning ``stem``
        # alone would silently drop a protected ID from names such as
        # ``bucket.CVE-2026-5555``.
        collect(component)
    if path_components:
        filename = path_components[-1]
        # The complete filename carries embedded CVE/GHSA tokens.  Generic
        # year-based IDs are collected from the stem so the file extension is
        # never mistaken for part of an advisory ID.
        collect(filename, include_generic=False)
        collect(PurePosixPath(filename).stem)
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        decoded = None
    if decoded is not None:
        walk(decoded)
    return ids


def build_protected_inventory(
    repo_root: Path,
    source_paths: Sequence[Path],
    alias_map: Mapping[str, set[str]],
    *,
    excluded_paths: Sequence[Path] = (),
) -> ProtectedInventory:
    """Hash protected roots/files and expand every referenced ID through aliases."""
    source_roots: list[dict[str, str]] = []
    seen_roots: set[Path] = set()
    for raw_path in source_paths:
        path = raw_path if raw_path.is_absolute() else repo_root / raw_path
        if path.is_symlink() or not path.exists():
            raise HeldoutQualityError(f"protected source is missing or unsafe: {path}")
        resolved = path.resolve()
        if resolved in seen_roots:
            continue
        seen_roots.add(resolved)
        source_roots.append(
            {
                "path": _path_label(resolved, repo_root),
                "kind": "file" if resolved.is_file() else "directory",
            }
        )
    source_roots.sort(key=lambda entry: entry["path"])

    raw_ids: set[str] = set()
    file_manifest: list[dict[str, Any]] = []
    total_input_bytes = 0
    for path in _protected_files(
        repo_root,
        source_paths,
        excluded_paths=excluded_paths,
    ):
        content, _stat = _stable_file(
            path,
            description="protected input",
            max_bytes=_MAX_PROTECTED_INPUT_BYTES,
        )
        total_input_bytes += len(content)
        if total_input_bytes > _MAX_PROTECTED_INPUTS_TOTAL_BYTES:
            raise HeldoutQualityError(
                "protected inputs exceed the aggregate input size bound"
            )
        relative_path = PurePosixPath(_path_label(path, repo_root))
        ids = _extract_subject_tokens(content, relative_path)
        raw_ids.update(ids)
        file_manifest.append(
            {
                "path": _path_label(path, repo_root),
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "referenced_subject_count": len(ids),
                "referenced_subject_ids_sha256": canonical_sha256(sorted(ids)),
            }
        )

    alias_index = _normalized_alias_index(alias_map)
    expanded_by_key: dict[str, str] = {}

    def add_subject(subject_id: str) -> None:
        key = _subject_key(subject_id)
        current = expanded_by_key.get(key)
        if current is None or subject_id < current:
            expanded_by_key[key] = subject_id

    for subject_id in raw_ids:
        add_subject(subject_id)
    for subject_id in tuple(raw_ids):
        for alias in alias_index.get(_subject_key(subject_id), {subject_id}):
            add_subject(alias)
    sorted_ids = sorted(expanded_by_key.values())
    return ProtectedInventory(
        subject_ids=frozenset(sorted_ids),
        source_roots=tuple(source_roots),
        files=tuple(file_manifest),
        files_manifest_sha256=canonical_sha256(file_manifest),
        subject_ids_sha256=canonical_sha256(sorted_ids),
    )


def _alias_units(
    plan_ids: Sequence[str],
    alias_map: Mapping[str, set[str]],
    inputs: Mapping[str, tuple[detector_quality.CachedPipelineInput, ...]],
) -> tuple[SelectionUnit, ...]:
    plan_by_key = {_subject_key(subject_id): subject_id for subject_id in plan_ids}
    if len(plan_by_key) != len(plan_ids):
        raise HeldoutQualityError(
            "fixed campaign plan contains case-insensitive duplicate subject IDs"
        )
    alias_index = _normalized_alias_index(alias_map)
    remaining = set(plan_by_key)
    units: list[SelectionUnit] = []
    while remaining:
        first_key = min(remaining)
        first = plan_by_key[first_key]
        subject_keys = {
            _subject_key(value)
            for value in alias_index.get(first_key, {first})
            if _subject_key(value) in plan_by_key
        }
        subject_keys.add(first_key)
        # Fail closed if a supplied alias map does not provide a symmetric closure.
        for subject_key in tuple(subject_keys):
            subject_id = plan_by_key[subject_key]
            reverse = {
                _subject_key(value)
                for value in alias_index.get(subject_key, {subject_id})
                if _subject_key(value) in plan_by_key
            }
            reverse.add(subject_key)
            if reverse != subject_keys:
                raise HeldoutQualityError(
                    f"alias closure is inconsistent for {first} and {subject_id}"
                )
        remaining.difference_update(subject_keys)
        subject_ids = {plan_by_key[key] for key in subject_keys}
        canonical_id = _canonical_subject(subject_ids)
        class_inputs = [
            item for subject_id in sorted(subject_ids) for item in inputs[subject_id]
        ]
        prediction_reasons = tuple(
            sorted({item.prediction_reason for item in class_inputs})
        )
        infrastructure = tuple(
            sorted(
                {
                    category
                    for item in class_inputs
                    for category in item.infrastructure_categories
                }
            )
        )
        terminal = sorted(
            {item.terminal_problem for item in class_inputs if item.terminal_problem}
        )
        if terminal:
            infrastructure = tuple(
                sorted(set(infrastructure) | {"terminal_result_problem"})
            )
        unresolved = tuple(
            sorted(
                {reason for item in class_inputs for reason in item.unresolved_reasons}
            )
        )
        candidate_positive = any(
            bic_is_candidate(bic)
            for item in class_inputs
            for bic in item.result.bug_introducing_commits
        )
        screening_positive = any(
            item.result.screening is not None
            and item.result.screening.worth_investigating is True
            for item in class_inputs
        )
        units.append(
            SelectionUnit(
                canonical_id=canonical_id,
                subject_ids=tuple(sorted(subject_ids)),
                predicted_positive=any(
                    item.predicted_positive for item in class_inputs
                ),
                candidate_positive=candidate_positive,
                screening_positive=screening_positive,
                prediction_reasons=prediction_reasons,
                infrastructure_categories=infrastructure,
                unresolved_reasons=unresolved,
                results=tuple(
                    ResultReference(item.subject_id, item.file_sha256)
                    for item in sorted(class_inputs, key=lambda value: value.subject_id)
                ),
            )
        )
    return tuple(sorted(units, key=lambda unit: unit.canonical_id))


def load_fixed_campaign_snapshot(
    repo_root: Path,
    *,
    alias_map: Mapping[str, set[str]] | None = None,
) -> CampaignSnapshot:
    """Read raw campaign results and fail unless the entire campaign re-proves."""
    try:
        context = detector_quality._current_fixed_campaign_context(repo_root)
    except Exception as exc:  # boundary normalizes runner/source validation failures
        raise HeldoutQualityError(f"cannot load fixed campaign context: {exc}") from exc

    plan_ids = tuple(
        subject_id for batch in context.batches for subject_id in batch.ids
    )
    if not plan_ids or len(plan_ids) != len({_subject_key(item) for item in plan_ids}):
        raise HeldoutQualityError("fixed campaign plan is empty or contains duplicates")
    corpus = tuple(
        detector_quality.CorpusEntry(subject_id, "INCONCLUSIVE", (subject_id,))
        for subject_id in plan_ids
    )
    try:
        inputs = detector_quality._load_class_snapshot_inputs(
            context.result_dir, corpus
        )
        proof = detector_quality._fixed_contract_campaign_proof(corpus, inputs, context)
    except (OSError, UnicodeError, ValueError) as exc:
        raise HeldoutQualityError(f"fixed campaign results are invalid: {exc}") from exc
    if proof.get("complete") is not True:
        failure_counts = proof.get("failure_counts", {})
        raise HeldoutQualityError(
            "fixed campaign proof is incomplete: "
            + json.dumps(failure_counts, sort_keys=True)
        )

    resolved_alias_map = alias_map if alias_map is not None else build_alias_map()
    units = _alias_units(plan_ids, resolved_alias_map, inputs)
    result_manifest = [
        {
            "canonical_id": unit.canonical_id,
            "subject_ids": list(unit.subject_ids),
            "results": [
                {"subject_id": result.subject_id, "sha256": result.sha256}
                for result in unit.results
            ],
        }
        for unit in units
    ]
    return CampaignSnapshot(
        campaign_id=context.campaign_id,
        contract_sha256=context.contract_sha256,
        source_snapshot_sha256=context.source_snapshot_sha256,
        campaign_proof_sha256=detector_quality.canonical_sha256(proof),
        campaign_result_manifest_sha256=canonical_sha256(result_manifest),
        proof_complete=True,
        units=units,
    )


def _read_json_object(
    path: Path,
    description: str,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    content, _stat = _stable_file(
        path,
        description=description,
        max_bytes=max_bytes,
    )
    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HeldoutQualityError(f"cannot parse {description} {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise HeldoutQualityError(f"{description} must contain an object")
    return payload


def _parse_iso(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise HeldoutQualityError(f"{description} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HeldoutQualityError(
            f"{description} must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise HeldoutQualityError(f"{description} must include a timezone")
    return parsed.astimezone(UTC).isoformat()


def _sanitized_git_environment() -> dict[str, str]:
    """Build a fixed Git environment with every caller-supplied GIT_* removed."""

    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": "/dev/null",
        "XDG_CONFIG_HOME": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _run_git(
    arguments: Sequence[str],
    *,
    description: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        executable = _GIT_EXECUTABLE.lstat()
        if not stat.S_ISREG(executable.st_mode) or executable.st_mode & 0o111 == 0:
            raise HeldoutQualityError(
                f"cannot verify {description}: trusted Git executable is unsafe"
            )
        return subprocess.run(
            [str(_GIT_EXECUTABLE), "--no-replace-objects", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            env=_sanitized_git_environment(),
        )
    except HeldoutQualityError:
        raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HeldoutQualityError(f"cannot verify {description}: {exc}") from exc


def _git_repository(repo_root: Path) -> GitRepository:
    requested = repo_root.resolve()

    def discover(arguments: Sequence[str], description: str) -> Path:
        result = _run_git(
            ["-C", str(requested), *arguments],
            description=description,
        )
        if result.returncode != 0:
            raise HeldoutQualityError(f"cannot bind {description}")
        try:
            raw = result.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise HeldoutQualityError(f"{description} is malformed") from exc
        if not raw or "\n" in raw or "\x00" in raw:
            raise HeldoutQualityError(f"{description} is malformed")
        return Path(raw).resolve()

    worktree = discover(
        ["rev-parse", "--path-format=absolute", "--show-toplevel"],
        "Git worktree",
    )
    git_dir = discover(["rev-parse", "--absolute-git-dir"], "Git directory")
    common_dir = discover(
        ["rev-parse", "--path-format=absolute", "--git-common-dir"],
        "Git common directory",
    )
    if worktree != requested:
        raise HeldoutQualityError(
            "repository root does not match the bound Git worktree"
        )
    for path, description in (
        (git_dir, "Git directory"),
        (common_dir, "Git common directory"),
        (common_dir / "objects", "Git object store"),
    ):
        if path.is_symlink() or not path.is_dir():
            raise HeldoutQualityError(f"{description} is missing or unsafe")
    if os.path.lexists(common_dir / "shallow"):
        raise HeldoutQualityError(
            "shallow Git repositories cannot prove artifact order"
        )
    if os.path.lexists(common_dir / "objects" / "info" / "alternates"):
        raise HeldoutQualityError("Git object alternates cannot prove artifact order")
    if os.path.lexists(common_dir / "info" / "grafts"):
        raise HeldoutQualityError("Git grafts cannot prove artifact order")
    return GitRepository(worktree=worktree, git_dir=git_dir, common_dir=common_dir)


def _git_command(
    repository: GitRepository,
    arguments: Sequence[str],
    *,
    description: str,
) -> subprocess.CompletedProcess[bytes]:
    return _run_git(
        [
            f"--git-dir={repository.git_dir}",
            f"--work-tree={repository.worktree}",
            *arguments,
        ],
        description=description,
    )


def _safe_git_path(
    path: Path,
    repo_root: Path,
    description: str,
    *,
    max_bytes: int,
) -> str:
    resolved = _study_artifact_path(
        path,
        repo_root,
        description,
        max_bytes=max_bytes,
    )
    relative = resolved.relative_to(repo_root.resolve())
    if any(re.fullmatch(r"[A-Za-z0-9._-]+", part) is None for part in relative.parts):
        raise HeldoutQualityError(f"{description} Git path is unsafe")
    return relative.as_posix()


def _validate_artifact_order(
    reference: object,
    *,
    selection: Mapping[str, Any],
    selection_digest: str,
    selection_path: Path,
    labels_path: Path,
    labels_payload: Mapping[str, Any],
    repo_root: Path,
    selection_seal_validator: Callable[
        [Mapping[str, Any]], str
    ] = validate_selection_seal,
) -> dict[str, Any]:
    """Prove repository artifact order without claiming trustworthy wall-clock time."""
    if not isinstance(reference, str):
        raise HeldoutQualityError(
            "selection_commit_reference requires a full Git commit and path"
        )
    match = _COMMIT_REFERENCE.fullmatch(reference.strip())
    if match is None:
        raise HeldoutQualityError(
            "selection_commit_reference requires a full Git commit and path"
        )
    commit = match.group("commit")
    raw_path = match.group("path")
    git_path = PurePosixPath(raw_path)
    if (
        git_path.is_absolute()
        or raw_path != git_path.as_posix()
        or not git_path.parts
        or any(part in {"", ".", "..", ".git"} for part in git_path.parts)
    ):
        raise HeldoutQualityError("selection commit path is unsafe")

    root = repo_root.resolve()
    repository = _git_repository(root)
    commit_type = _git_command(
        repository,
        ["cat-file", "-t", commit],
        description="selection commit object type",
    )
    if commit_type.returncode != 0 or commit_type.stdout != b"commit\n":
        raise HeldoutQualityError(
            "selection_commit_reference must name a Git commit object"
        )
    current_head = _git_command(
        repository,
        ["rev-parse", "HEAD"],
        description="current release HEAD",
    )
    try:
        head = current_head.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise HeldoutQualityError("current release HEAD is malformed") from exc
    if (
        current_head.returncode != 0
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head) is None
    ):
        raise HeldoutQualityError("current release HEAD is unavailable")
    if commit == head:
        raise HeldoutQualityError(
            "selection commit must be a strict ancestor of the label commit"
        )
    ancestor = _git_command(
        repository,
        ["merge-base", "--is-ancestor", commit, head],
        description="selection commit ancestry",
    )
    if ancestor.returncode != 0:
        raise HeldoutQualityError(
            "selection commit is not a strict ancestor of the current release"
        )

    actual_selection_path = _safe_git_path(
        selection_path,
        root,
        "held-out selection",
        max_bytes=_MAX_SELECTION_BYTES,
    )
    if actual_selection_path != git_path.as_posix():
        raise HeldoutQualityError(
            "selection input path does not match selection_commit_reference"
        )
    labels_git_path = _safe_git_path(
        labels_path,
        root,
        "held-out labels",
        max_bytes=_MAX_LABEL_BYTES,
    )
    labels_commit_result = _git_command(
        repository,
        ["log", "-1", "--format=%H", "--", labels_git_path],
        description="held-out labels commit",
    )
    try:
        labels_commit = labels_commit_result.stdout.decode(
            "ascii", errors="strict"
        ).strip()
    except UnicodeDecodeError as exc:
        raise HeldoutQualityError("held-out labels commit is malformed") from exc
    if (
        labels_commit_result.returncode != 0
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", labels_commit) is None
    ):
        raise HeldoutQualityError("held-out labels are not committed")
    labels_ancestor = _git_command(
        repository,
        ["merge-base", "--is-ancestor", labels_commit, head],
        description="labels-to-release ancestry",
    )
    if labels_ancestor.returncode != 0:
        raise HeldoutQualityError(
            "held-out labels commit is not an ancestor of the current release"
        )
    selection_to_labels = _git_command(
        repository,
        ["merge-base", "--is-ancestor", commit, labels_commit],
        description="selection-to-label ancestry",
    )
    if selection_to_labels.returncode != 0:
        raise HeldoutQualityError(
            "selection commit is not a strict ancestor of the label commit"
        )

    object_name = f"{commit}:{git_path.as_posix()}"
    size_result = _git_command(
        repository,
        ["cat-file", "-s", object_name],
        description="selection commit object size",
    )
    try:
        object_size = int(size_result.stdout.strip())
    except ValueError as exc:
        raise HeldoutQualityError("selection commit object is missing") from exc
    if size_result.returncode != 0 or not 0 < object_size <= _MAX_SELECTION_BYTES:
        raise HeldoutQualityError("selection commit object is missing or oversized")

    content_result = _git_command(
        repository,
        ["show", object_name],
        description="selection commit content",
    )
    if content_result.returncode != 0 or len(content_result.stdout) != object_size:
        raise HeldoutQualityError("selection commit content is incomplete")
    selection_content, _ = _stable_file(
        selection_path,
        description="held-out selection",
        max_bytes=_MAX_SELECTION_BYTES,
    )
    if selection_content != content_result.stdout:
        raise HeldoutQualityError(
            "held-out selection exact bytes differ from the committed artifact"
        )
    if selection_content != canonical_artifact_bytes(selection):
        raise HeldoutQualityError(
            "held-out selection must use the canonical tracked JSON encoding"
        )
    try:
        committed_selection = json.loads(content_result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HeldoutQualityError("selection commit content is malformed") from exc
    if not isinstance(committed_selection, dict):
        raise HeldoutQualityError("selection commit content must be an object")
    if selection_seal_validator(committed_selection) != selection_digest:
        raise HeldoutQualityError("selection commit seal does not match labels")
    if committed_selection != selection:
        raise HeldoutQualityError("selection commit content drifted from evaluation")

    prior_label = _git_command(
        repository,
        ["ls-tree", "-z", "--full-tree", commit, "--", labels_git_path],
        description="selection-commit label absence",
    )
    if prior_label.returncode != 0:
        raise HeldoutQualityError("cannot inspect selection commit label inventory")
    if prior_label.stdout:
        raise HeldoutQualityError(
            "held-out labels already exist in the selection commit"
        )

    labels_content, _ = _stable_file(
        labels_path,
        description="held-out labels",
        max_bytes=_MAX_LABEL_BYTES,
    )
    try:
        current_labels_payload = json.loads(labels_content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HeldoutQualityError("held-out labels are malformed") from exc
    if current_labels_payload != labels_payload:
        raise HeldoutQualityError("held-out labels changed during evaluation")
    if labels_content != canonical_artifact_bytes(labels_payload):
        raise HeldoutQualityError(
            "held-out labels must use the canonical tracked JSON encoding"
        )
    tracked_labels = _git_command(
        repository,
        ["show", f"{labels_commit}:{labels_git_path}"],
        description="committed held-out labels",
    )
    if tracked_labels.returncode != 0 or tracked_labels.stdout != labels_content:
        raise HeldoutQualityError(
            "held-out labels exact bytes must be tracked at current HEAD"
        )
    current_labels = _git_command(
        repository,
        ["show", f"{head}:{labels_git_path}"],
        description="release-head held-out labels",
    )
    if current_labels.returncode != 0 or current_labels.stdout != labels_content:
        raise HeldoutQualityError(
            "held-out labels changed after their committed audit artifact"
        )
    final_head = _git_command(
        repository,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        description="final release HEAD",
    )
    try:
        final_head_oid = final_head.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise HeldoutQualityError("final release HEAD is malformed") from exc
    if final_head.returncode != 0 or final_head_oid != head:
        raise HeldoutQualityError("current release HEAD changed during artifact proof")
    return {
        "selection_commit_reference": f"{commit}:{git_path.as_posix()}",
        "selection_commit": commit,
        "selection_path": git_path.as_posix(),
        "labels_commit": labels_commit,
        "labels_path": labels_git_path,
        "labels_blob_sha256": hashlib.sha256(labels_content).hexdigest(),
        "selection_is_strict_ancestor": True,
        "labels_absent_from_selection_commit": True,
        "labels_exact_bytes_tracked_at_head": True,
    }


def _selected_rows(manifest: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    samples = manifest.get("samples")
    if not isinstance(samples, dict) or set(samples) != {"precision", "recall"}:
        raise HeldoutQualityError(
            "selection samples require exact precision/recall lanes"
        )
    rows: list[dict[str, Any]] = []
    sample_contracts: dict[str, dict[str, Any]] = {}
    lane_sample_ids: dict[str, set[str]] = {}
    policy = manifest.get("selection_policy")
    if not isinstance(policy, Mapping):
        raise HeldoutQualityError("selection policy is missing")
    seed = _validate_digest(policy.get("seed_sha256"), "selection seed")
    expected_row_fields = {
        "sample_id",
        "subject_ids",
        "stratum",
        "selection_rank_sha256",
        "predicted_positive",
        "candidate_positive",
        "screening_positive",
        "prediction_reasons",
        "execution_status",
        "infrastructure_categories",
        "unresolved_reasons",
        "campaign_results",
    }
    for lane in ("precision", "recall"):
        lane_rows = samples.get(lane)
        if not isinstance(lane_rows, list) or not lane_rows:
            raise HeldoutQualityError(f"selection {lane} sample must be non-empty")
        if policy.get(f"{lane}_sample_size") != len(lane_rows):
            raise HeldoutQualityError(f"selection {lane} sample size is inconsistent")
        lane_ids: set[str] = set()
        lane_keys: set[str] = set()
        for row in lane_rows:
            if not isinstance(row, dict) or set(row) != expected_row_fields:
                raise HeldoutQualityError(
                    f"selection {lane} row requires exact schema-3 fields"
                )
            sample_id = row.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id:
                raise HeldoutQualityError(f"selection {lane} row requires sample_id")
            sample_key = _subject_key(sample_id)
            if sample_key in lane_keys:
                raise HeldoutQualityError(f"duplicate {lane} sample {sample_id}")
            subject_ids = row.get("subject_ids")
            if (
                not isinstance(subject_ids, list)
                or not subject_ids
                or subject_ids != sorted(set(subject_ids))
                or any(not isinstance(item, str) or not item for item in subject_ids)
                or len({_subject_key(item) for item in subject_ids}) != len(subject_ids)
            ):
                raise HeldoutQualityError(
                    f"selection {lane} row has invalid subject_ids"
                )
            if row.get("stratum") != _id_family(sample_id):
                raise HeldoutQualityError(
                    f"selection {lane} row has invalid stratum for {sample_id}"
                )
            if (
                sample_id not in subject_ids
                or not isinstance(row.get("predicted_positive"), bool)
                or not isinstance(row.get("candidate_positive"), bool)
                or not isinstance(row.get("screening_positive"), bool)
            ):
                raise HeldoutQualityError(
                    f"selection {lane} row has invalid prediction fields"
                )
            for list_field in (
                "prediction_reasons",
                "infrastructure_categories",
                "unresolved_reasons",
            ):
                values = row.get(list_field)
                if (
                    not isinstance(values, list)
                    or values != sorted(set(values))
                    or any(not isinstance(item, str) or not item for item in values)
                ):
                    raise HeldoutQualityError(
                        f"selection {lane} row has invalid {list_field}"
                    )
            expected_status = "ok"
            if row["infrastructure_categories"]:
                expected_status = "infrastructure_error"
            elif row["unresolved_reasons"]:
                expected_status = "unresolved"
            if row.get("execution_status") != expected_status:
                raise HeldoutQualityError(
                    f"selection {lane} row has invalid execution_status"
                )
            campaign_results = row.get("campaign_results")
            if not isinstance(campaign_results, list) or not campaign_results:
                raise HeldoutQualityError(
                    f"selection {lane} row has invalid campaign_results"
                )
            expected_result_ids = list(subject_ids)
            actual_result_ids = [
                result.get("subject_id") if isinstance(result, dict) else None
                for result in campaign_results
            ]
            if actual_result_ids != expected_result_ids:
                raise HeldoutQualityError(
                    f"selection {lane} row campaign_results must be sorted, unique, "
                    "and exactly match subject_ids"
                )
            for result in campaign_results:
                if (
                    not isinstance(result, dict)
                    or set(result) != {"subject_id", "sha256"}
                    or result.get("subject_id") not in subject_ids
                ):
                    raise HeldoutQualityError(
                        f"selection {lane} row has invalid campaign result"
                    )
                _validate_digest(
                    result.get("sha256"),
                    f"selection campaign result for {sample_id}",
                )
            cross_lane_contract = {
                key: row[key]
                for key in expected_row_fields
                if key not in {"selection_rank_sha256"}
            }
            prior_contract = sample_contracts.setdefault(
                sample_key, cross_lane_contract
            )
            if prior_contract != cross_lane_contract:
                raise HeldoutQualityError(
                    f"selection sample {sample_id} conflicts across lane rows"
                )
            rank_unit = SelectionUnit(
                canonical_id=sample_id,
                subject_ids=tuple(subject_ids),
                predicted_positive=row["predicted_positive"],
                candidate_positive=row["candidate_positive"],
                prediction_reasons=(),
                infrastructure_categories=(),
                unresolved_reasons=(),
                results=(),
            )
            if row.get("selection_rank_sha256") != _selection_rank(
                seed, lane, rank_unit
            ):
                raise HeldoutQualityError(
                    f"selection {lane} rank is inconsistent for {sample_id}"
                )
            lane_keys.add(sample_key)
            lane_ids.add(sample_id)
            rows.append({**row, "lane": lane})
        lane_sample_ids[lane] = lane_ids
    overlap = manifest.get("lane_overlap")
    expected_overlap_ids = sorted(
        lane_sample_ids["precision"] & lane_sample_ids["recall"]
    )
    if (
        not isinstance(overlap, Mapping)
        or set(overlap) != {"count", "ids", "interpretation"}
        or isinstance(overlap.get("count"), bool)
        or overlap.get("count") != len(expected_overlap_ids)
        or overlap.get("ids") != expected_overlap_ids
        or overlap.get("interpretation")
        != (
            "domain-separated draws are independent lanes; one audit may serve "
            "both metrics when the deterministic samples overlap"
        )
    ):
        raise HeldoutQualityError(
            "selection lane overlap does not match the exact sample IDs"
        )
    return tuple(rows)


def build_label_template(selection: Mapping[str, Any]) -> dict[str, Any]:
    """Return a blinded, intentionally incomplete dual-review audit packet."""
    digest = validate_selection_seal(selection)
    rows = _selected_rows(selection)
    sample_subjects: dict[str, list[str]] = {}
    for row in rows:
        sample_subjects[row["sample_id"]] = list(row.get("subject_ids", []))

    def empty_review() -> dict[str, Any]:
        return {
            "reviewer_id": "",
            "label": None,
            "reviewed_at_utc": "",
            "evidence_refs": [],
            "rationale": "",
        }

    return {
        "schema_version": _LABEL_SCHEMA_VERSION,
        "kind": "heldout_detector_quality_independent_audit",
        "selection_manifest_sha256": digest,
        "audit_protocol": {
            "selection_commit_reference": (
                "REPLACE_WITH_FULL_GIT_OID:REPO_RELATIVE_SELECTION_PATH"
            ),
            "audit_started_from_null_label_template": False,
            "reviewers_independent_from_detector_development": False,
            "reviewers_independent_from_each_other": False,
            "reviews_completed_without_access_to_other_review": False,
            "detector_predictions_hidden_from_reviewers": False,
            "sample_lane_membership_hidden_from_reviewers": False,
            "aggregate_quality_scores_hidden_until_resolution_complete": False,
            "all_disagreements_resolved_before_sealing": False,
        },
        "adjudications": [
            {
                "sample_id": sample_id,
                "subject_ids": sample_subjects[sample_id],
                "primary_review": empty_review(),
                "secondary_review": empty_review(),
                "resolved_label": None,
                "resolution": {
                    "status": None,
                    "resolver_id": None,
                    "resolved_at_utc": None,
                    "evidence_refs": [],
                    "rationale": "",
                },
            }
            for sample_id in sorted(sample_subjects)
        ],
    }


def _reviewer_identity(value: object, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HeldoutQualityError(f"{description} is missing")
    return value.strip().casefold()


def _require_evidence_refs(value: object, description: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise HeldoutQualityError(f"{description} are missing")
    return value


def _require_rationale(value: object, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HeldoutQualityError(f"{description} is missing")
    return value


def _load_independent_review(
    review: object,
    *,
    role: str,
    sample_id: str,
) -> tuple[str, str, datetime]:
    fields = {
        "reviewer_id",
        "label",
        "reviewed_at_utc",
        "evidence_refs",
        "rationale",
    }
    if not isinstance(review, dict) or set(review) != fields:
        raise HeldoutQualityError(
            f"{role} review requires the exact schema-3 fields for {sample_id}"
        )
    reviewer_id = _reviewer_identity(
        review.get("reviewer_id"), f"{role} reviewer_id for {sample_id}"
    )
    label = review.get("label")
    if label not in _FORMAL_LABELS:
        raise HeldoutQualityError(
            f"{role} review requires a conclusive formal label for {sample_id}"
        )
    reviewed_at = _parse_iso(
        review.get("reviewed_at_utc"),
        f"{role} reviewed_at_utc for {sample_id}",
    )
    _require_evidence_refs(
        review.get("evidence_refs"), f"{role} evidence_refs for {sample_id}"
    )
    _require_rationale(review.get("rationale"), f"{role} rationale for {sample_id}")
    return reviewer_id, label, datetime.fromisoformat(reviewed_at)


def _load_labels(
    payload: Mapping[str, Any],
    *,
    selection: Mapping[str, Any],
    selection_digest: str,
    selected_subjects: Mapping[str, tuple[str, ...]],
    selection_path: Path | None,
    labels_path: Path | None,
    repo_root: Path,
    verify_artifact_order: bool = True,
) -> tuple[dict[str, str], dict[str, Any]]:
    expected_top = {
        "schema_version",
        "kind",
        "selection_manifest_sha256",
        "audit_protocol",
        "adjudications",
    }
    if set(payload) != expected_top:
        raise HeldoutQualityError(
            "label file requires exact top-level fields; templates are not evaluable"
        )
    if payload.get("schema_version") != _LABEL_SCHEMA_VERSION:
        raise HeldoutQualityError("labels require schema_version 3")
    if payload.get("kind") != "heldout_detector_quality_independent_audit":
        raise HeldoutQualityError("label file kind is invalid")
    if payload.get("selection_manifest_sha256") != selection_digest:
        raise HeldoutQualityError("labels are not bound to the sealed selection")

    protocol = payload.get("audit_protocol")
    required_protocol = {
        "selection_commit_reference",
        "audit_started_from_null_label_template",
        "reviewers_independent_from_detector_development",
        "reviewers_independent_from_each_other",
        "reviews_completed_without_access_to_other_review",
        "detector_predictions_hidden_from_reviewers",
        "sample_lane_membership_hidden_from_reviewers",
        "aggregate_quality_scores_hidden_until_resolution_complete",
        "all_disagreements_resolved_before_sealing",
    }
    if not isinstance(protocol, dict) or set(protocol) != required_protocol:
        raise HeldoutQualityError("audit_protocol requires the exact schema-3 fields")
    reference = protocol.get("selection_commit_reference")
    artifact_order: dict[str, Any] = {}
    if verify_artifact_order:
        if selection_path is None or labels_path is None:
            raise HeldoutQualityError("artifact-order proof requires study paths")
        artifact_order = _validate_artifact_order(
            reference,
            selection=selection,
            selection_digest=selection_digest,
            selection_path=selection_path,
            labels_path=labels_path,
            labels_payload=payload,
            repo_root=repo_root,
        )
    for attestation in required_protocol - {"selection_commit_reference"}:
        if protocol.get(attestation) is not True:
            raise HeldoutQualityError(
                f"audit protocol attestation is false: {attestation}"
            )

    raw_entries = payload.get("adjudications")
    if not isinstance(raw_entries, list):
        raise HeldoutQualityError("labels require an adjudications array")
    labels: dict[str, str] = {}
    expected_entry = {
        "sample_id",
        "subject_ids",
        "primary_review",
        "secondary_review",
        "resolved_label",
        "resolution",
    }
    for entry in raw_entries:
        if not isinstance(entry, dict) or set(entry) != expected_entry:
            raise HeldoutQualityError(
                "every adjudication requires the exact schema-3 fields"
            )
        sample_id = entry.get("sample_id")
        if not isinstance(sample_id, str) or sample_id not in selected_subjects:
            raise HeldoutQualityError(
                f"label includes an unselected sample: {sample_id!r}"
            )
        if sample_id in labels:
            raise HeldoutQualityError(f"duplicate label for {sample_id}")
        if entry.get("subject_ids") != list(selected_subjects[sample_id]):
            raise HeldoutQualityError(f"label subject aliases drifted for {sample_id}")
        primary_id, primary_label, primary_time = _load_independent_review(
            entry.get("primary_review"), role="primary", sample_id=sample_id
        )
        secondary_id, secondary_label, secondary_time = _load_independent_review(
            entry.get("secondary_review"), role="secondary", sample_id=sample_id
        )
        if primary_id == secondary_id:
            raise HeldoutQualityError(
                f"primary and secondary reviews require distinct reviewers for {sample_id}"
            )

        resolved_label = entry.get("resolved_label")
        if resolved_label not in _FORMAL_LABELS:
            raise HeldoutQualityError(
                f"resolved_label requires a conclusive formal label for {sample_id}"
            )
        resolution = entry.get("resolution")
        resolution_fields = {
            "status",
            "resolver_id",
            "resolved_at_utc",
            "evidence_refs",
            "rationale",
        }
        if not isinstance(resolution, dict) or set(resolution) != resolution_fields:
            raise HeldoutQualityError(
                f"resolution requires the exact schema-3 fields for {sample_id}"
            )

        if primary_label == secondary_label:
            if (
                resolution.get("status") != "agreed"
                or resolved_label != primary_label
                or resolution.get("resolver_id") is not None
                or resolution.get("resolved_at_utc") is not None
                or resolution.get("evidence_refs") != []
                or resolution.get("rationale") != ""
            ):
                raise HeldoutQualityError(
                    f"agreed reviews require exact agreed resolution for {sample_id}"
                )
        else:
            if resolution.get("status") != "resolved":
                raise HeldoutQualityError(
                    f"disagreeing reviews require resolved status for {sample_id}"
                )
            resolver_id = _reviewer_identity(
                resolution.get("resolver_id"), f"resolver_id for {sample_id}"
            )
            if resolver_id in {primary_id, secondary_id}:
                raise HeldoutQualityError(
                    f"disagreeing reviews require a distinct resolver for {sample_id}"
                )
            resolved_at = datetime.fromisoformat(
                _parse_iso(
                    resolution.get("resolved_at_utc"),
                    f"resolved_at_utc for {sample_id}",
                )
            )
            if resolved_at < max(primary_time, secondary_time):
                raise HeldoutQualityError(
                    f"resolution predates an independent review for {sample_id}"
                )
            _require_evidence_refs(
                resolution.get("evidence_refs"),
                f"resolution evidence_refs for {sample_id}",
            )
            _require_rationale(
                resolution.get("rationale"), f"resolution rationale for {sample_id}"
            )
        labels[sample_id] = resolved_label

    missing = sorted(set(selected_subjects) - set(labels))
    if missing:
        raise HeldoutQualityError(
            f"labels are incomplete for selected samples: {missing}"
        )
    return labels, artifact_order


def _metric(successes: int, trials: int, target: float) -> dict[str, Any]:
    point = successes / trials if trials else None
    lower = clopper_pearson_lower_bound(successes, trials)
    return {
        "successes": successes,
        "trials": trials,
        "point": point,
        "one_sided_95pct_lower_bound": lower,
        "point_meets_target": point is not None and point >= target,
        "certified_meets_target": trials > 0 and lower >= target,
        "target": target,
        "confidence_bound_method": "exact_clopper_pearson",
    }


def _selection_subject_contract(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, tuple[str, ...]]:
    selected_subjects: dict[str, tuple[str, ...]] = {}
    for row in rows:
        sample_id = row["sample_id"]
        raw_subjects = row.get("subject_ids")
        if (
            not isinstance(raw_subjects, list)
            or not raw_subjects
            or any(not isinstance(item, str) or not item for item in raw_subjects)
            or raw_subjects != sorted(set(raw_subjects))
        ):
            raise HeldoutQualityError(f"invalid subject_ids for sample {sample_id}")
        subjects = tuple(raw_subjects)
        prior = selected_subjects.get(sample_id)
        if prior is not None and prior != subjects:
            raise HeldoutQualityError(
                f"sample aliases disagree across lanes: {sample_id}"
            )
        selected_subjects[sample_id] = subjects
    return selected_subjects


def _compute_quality_fields(
    selection: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    selected_subjects: Mapping[str, tuple[str, ...]],
    labels: Mapping[str, str],
    *,
    precision_target: float,
    recall_target: float,
    require_certified: bool,
) -> dict[str, Any]:
    precision_rows = selection["samples"]["precision"]
    recall_rows = selection["samples"]["recall"]
    if any(row.get("predicted_positive") is not True for row in precision_rows):
        raise HeldoutQualityError("precision lane contains a non-positive prediction")
    if any(row.get("candidate_positive") is not True for row in recall_rows):
        raise HeldoutQualityError(
            "recall lane contains a non-candidate-positive result"
        )

    precision_conclusive = [
        row for row in precision_rows if labels[row["sample_id"]] != "INCONCLUSIVE"
    ]
    precision_successes = sum(
        labels[row["sample_id"]] == "AI_CAUSAL" for row in precision_conclusive
    )
    recall_actual_positives = [
        row for row in recall_rows if labels[row["sample_id"]] == "AI_CAUSAL"
    ]
    recall_successes = sum(
        row.get("predicted_positive") is True for row in recall_actual_positives
    )
    screening_conclusive = [
        row for row in recall_rows if labels[row["sample_id"]] in _FORMAL_LABELS
    ]
    screening_tp = sum(
        labels[row["sample_id"]] == "AI_CAUSAL"
        and row.get("screening_positive") is True
        for row in screening_conclusive
    )
    screening_fn = sum(
        labels[row["sample_id"]] == "AI_CAUSAL"
        and row.get("screening_positive") is False
        for row in screening_conclusive
    )
    screening_fp = sum(
        labels[row["sample_id"]] == "NOT_AI_CAUSAL"
        and row.get("screening_positive") is True
        for row in screening_conclusive
    )
    screening_tn = sum(
        labels[row["sample_id"]] == "NOT_AI_CAUSAL"
        and row.get("screening_positive") is False
        for row in screening_conclusive
    )
    all_unique_rows = {row["sample_id"]: row for row in rows}
    infrastructure_ids = sorted(
        sample_id
        for sample_id, row in all_unique_rows.items()
        if row.get("infrastructure_categories")
        or row.get("execution_status") == "infrastructure_error"
    )
    unresolved_ids = sorted(
        sample_id
        for sample_id, row in all_unique_rows.items()
        if row.get("unresolved_reasons") or row.get("execution_status") == "unresolved"
    )
    inconclusive_ids = sorted(
        sample_id for sample_id, label in labels.items() if label == "INCONCLUSIVE"
    )
    precision = _metric(
        precision_successes, len(precision_conclusive), precision_target
    )
    recall = _metric(recall_successes, len(recall_actual_positives), recall_target)
    evaluation_complete = bool(
        not infrastructure_ids
        and not unresolved_ids
        and not inconclusive_ids
        and precision["trials"] > 0
        and recall["trials"] > 0
    )
    screening_zero_false_negatives = bool(
        evaluation_complete and screening_fn == 0 and screening_tp > 0
    )
    point_gate_passed = bool(
        evaluation_complete
        and precision["point_meets_target"]
        and recall["point_meets_target"]
        and screening_zero_false_negatives
    )
    certified_gate_passed = bool(
        evaluation_complete
        and precision["certified_meets_target"]
        and recall["certified_meets_target"]
        and screening_zero_false_negatives
    )
    return {
        "evaluation_complete": evaluation_complete,
        "precision": precision,
        "recall": recall,
        "stage_metrics": {
            "screening": {
                "measurement_population": (
                    "heldout_recall_lane_conclusive_strict_coauthor_candidates"
                ),
                "confusion": {
                    "tp": screening_tp,
                    "fp": screening_fp,
                    "fn": screening_fn,
                    "tn": screening_tn,
                },
                "recall": _metric(
                    screening_tp,
                    screening_tp + screening_fn,
                    1.0,
                ),
                "screening_zero_false_negatives": (
                    screening_zero_false_negatives
                ),
            }
        },
        "denominators": {
            "selected_unique_alias_classes": len(selected_subjects),
            "precision_selected": len(precision_rows),
            "precision_conclusive_trials": len(precision_conclusive),
            "recall_candidate_positive_selected": len(recall_rows),
            "recall_actual_positive_trials": len(recall_actual_positives),
            "inconclusive": len(inconclusive_ids),
            "infrastructure_error": len(infrastructure_ids),
            "unresolved": len(unresolved_ids),
        },
        "strata": {
            "inconclusive": {"count": len(inconclusive_ids), "ids": inconclusive_ids},
            "infrastructure_error": {
                "count": len(infrastructure_ids),
                "ids": infrastructure_ids,
            },
            "unresolved": {"count": len(unresolved_ids), "ids": unresolved_ids},
            "lane_overlap": selection["lane_overlap"],
            "label_counts": dict(sorted(Counter(labels.values()).items())),
        },
        "point_gate_passed": point_gate_passed,
        "certified_gate_passed": certified_gate_passed,
        "release_gate_passed": point_gate_passed
        and (certified_gate_passed if require_certified else True),
    }


def evaluate_selection(
    selection: Mapping[str, Any],
    labels_payload: Mapping[str, Any],
    protected: ProtectedInventory,
    *,
    precision_target: float = _DEFAULT_PRECISION_TARGET,
    recall_target: float = _DEFAULT_RECALL_TARGET,
    require_certified: bool = False,
    selection_path: Path,
    labels_path: Path,
    repo_root: Path = _REPO_ROOT,
) -> dict[str, Any]:
    """Evaluate exact labels against a re-proved, leakage-free selection."""
    precision_target = _validate_target(precision_target, "precision_target")
    recall_target = _validate_target(recall_target, "recall_target")
    if not isinstance(require_certified, bool):
        raise HeldoutQualityError("require_certified must be boolean")
    selection_digest = validate_selection_seal(selection)
    rows = _selected_rows(selection)

    protected_contract = selection.get("protected_inputs")
    if not isinstance(protected_contract, dict):
        raise HeldoutQualityError("selection protected_inputs is missing")
    expected_protected = protected_inventory_contract(protected)
    if protected_contract != expected_protected:
        raise HeldoutQualityError("protected inputs drifted after sample selection")

    selected_subjects = _selection_subject_contract(rows)
    overlap: list[str] = []
    for row in rows:
        sample_id = row["sample_id"]
        if _subjects_overlap(protected.subject_ids, selected_subjects[sample_id]):
            overlap.append(sample_id)
    if overlap:
        raise HeldoutQualityError(
            f"held-out sample overlaps protected calibration/audit inputs: {sorted(set(overlap))}"
        )

    labels, artifact_order = _load_labels(
        labels_payload,
        selection=selection,
        selection_digest=selection_digest,
        selected_subjects=selected_subjects,
        selection_path=selection_path,
        labels_path=labels_path,
        repo_root=repo_root,
    )
    quality = _compute_quality_fields(
        selection,
        rows,
        selected_subjects,
        labels,
        precision_target=precision_target,
        recall_target=recall_target,
        require_certified=require_certified,
    )

    return {
        "schema_version": 3,
        "evaluation_kind": "independent_heldout_fixed_campaign_detector_quality",
        "selection_manifest_sha256": selection_digest,
        "campaign": selection["campaign"],
        "evaluation_complete": quality["evaluation_complete"],
        "targets": {
            "precision": precision_target,
            "recall": recall_target,
            "require_certified": require_certified,
        },
        "precision": quality["precision"],
        "recall": quality["recall"],
        "stage_metrics": quality["stage_metrics"],
        "denominators": quality["denominators"],
        "strata": quality["strata"],
        "point_gate_passed": quality["point_gate_passed"],
        "certified_gate_passed": quality["certified_gate_passed"],
        "release_gate_passed": quality["release_gate_passed"],
        "measurement_boundary": selection["measurement_boundary"],
        "manual_evidence": {
            "label_file_sha256": canonical_sha256(labels_payload),
            "artifact_order": artifact_order,
            "independent_audit_attested": True,
        },
    }


def recompute_archived_quality_evidence(
    selection: Mapping[str, Any],
    labels_payload: Mapping[str, Any],
    *,
    precision_target: float,
    recall_target: float,
    require_certified: bool,
) -> dict[str, Any]:
    """Purely revalidate archived labels and recompute every statistical field."""

    precision_target = _validate_target(precision_target, "precision_target")
    recall_target = _validate_target(recall_target, "recall_target")
    selection_digest = validate_selection_seal(selection)
    rows = _selected_rows(selection)
    selected_subjects = _selection_subject_contract(rows)
    labels, _ = _load_labels(
        labels_payload,
        selection=selection,
        selection_digest=selection_digest,
        selected_subjects=selected_subjects,
        selection_path=None,
        labels_path=None,
        repo_root=_REPO_ROOT,
        verify_artifact_order=False,
    )
    return _compute_quality_fields(
        selection,
        rows,
        selected_subjects,
        labels,
        precision_target=precision_target,
        recall_target=recall_target,
        require_certified=require_certified,
    )


def _resolve_protected_sources(
    repo_root: Path,
    recorded_roots: Sequence[Mapping[str, Any]],
) -> tuple[Path, ...]:
    paths: list[Path] = []
    for entry in recorded_roots:
        if (
            not isinstance(entry, Mapping)
            or not isinstance(entry.get("path"), str)
            or entry.get("kind") not in {"file", "directory"}
        ):
            raise HeldoutQualityError("selection protected root manifest is malformed")
        unresolved = repo_root / entry["path"]
        if unresolved.is_symlink():
            raise HeldoutQualityError(
                f"selection protected root is unsafe: {unresolved}"
            )
        path = unresolved.resolve(strict=False)
        try:
            path.relative_to(repo_root.resolve())
        except ValueError as exc:
            raise HeldoutQualityError(
                "selection protected path escapes repository"
            ) from exc
        actual_kind = (
            "file" if path.is_file() else "directory" if path.is_dir() else None
        )
        if actual_kind != entry["kind"]:
            raise HeldoutQualityError(
                f"selection protected root is missing, unsafe, or changed kind: {path}"
            )
        paths.append(path)
    return tuple(paths)


def _authoritative_protected_sources(
    repo_root: Path,
    recorded_roots: Sequence[Mapping[str, Any]],
) -> tuple[Path, ...]:
    """Require every current mandatory root and accept recorded roots only as extras."""

    recorded = _resolve_protected_sources(repo_root, recorded_roots)
    mandatory = tuple(path.resolve() for path in _default_source_paths(repo_root))
    recorded_set = set(recorded)
    missing = [
        path.relative_to(repo_root.resolve()).as_posix()
        for path in mandatory
        if path not in recorded_set
    ]
    if missing:
        raise HeldoutQualityError(
            f"selection omits mandatory protected roots: {sorted(missing)}"
        )
    extras = tuple(path for path in recorded if path not in set(mandatory))
    return (*mandatory, *extras)


def build_authoritative_protected_inventory(
    repo_root: Path,
    *,
    recorded_roots: Sequence[Mapping[str, Any]] | None = None,
    extra_sources: Sequence[Path] = (),
    excluded_paths: Sequence[Path] = (),
    alias_map: Mapping[str, set[str]] | None = None,
) -> ProtectedInventory:
    """Build or replay the complete protected-input inventory.

    Selection starts from every current mandatory root and may add extra roots.
    Replay starts from the roots sealed by selection, while requiring that they
    still contain every current mandatory root. Recorded extras remain additive.
    """

    root = repo_root.resolve()
    if recorded_roots is None:
        source_paths = (*_default_source_paths(root), *extra_sources)
    else:
        if extra_sources:
            raise HeldoutQualityError(
                "recorded protected roots cannot be combined with new extras"
            )
        source_paths = _authoritative_protected_sources(root, recorded_roots)
    resolved_alias_map = alias_map if alias_map is not None else build_alias_map()
    return build_protected_inventory(
        root,
        source_paths,
        resolved_alias_map,
        excluded_paths=excluded_paths,
    )


def _study_artifact_path(
    path: Path,
    repo_root: Path,
    description: str,
    *,
    max_bytes: int,
) -> Path:
    """Resolve one tracked study artifact and require containment in its durable root."""

    unresolved = path if path.is_absolute() else repo_root / path
    resolved = unresolved.resolve()
    studies_root = (repo_root / _HELDOUT_STUDIES_ROOT).resolve()
    try:
        resolved.relative_to(studies_root)
    except ValueError as exc:
        raise HeldoutQualityError(
            f"{description} must be stored under {_HELDOUT_STUDIES_ROOT.as_posix()}"
        ) from exc
    _stable_file(
        resolved,
        description=description,
        max_bytes=max_bytes,
    )
    return resolved


def _atomic_write_json(path: Path, payload: object) -> None:
    rendered = (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise HeldoutQualityError(f"cannot write {path}: {exc}") from exc


def _selection_code_sha256() -> str:
    return _file_sha256(
        Path(__file__).resolve(),
        description="selection code",
        max_bytes=_MAX_SELECTION_CODE_BYTES,
    )


def _default_source_paths(repo_root: Path) -> tuple[Path, ...]:
    return tuple(repo_root / path for path in _DEFAULT_PROTECTED_SOURCES)


def _select(args: argparse.Namespace) -> int:
    repo_root = args.repo_root.resolve()
    alias_map = build_alias_map()
    snapshot = load_fixed_campaign_snapshot(repo_root, alias_map=alias_map)
    protected = build_authoritative_protected_inventory(
        repo_root,
        extra_sources=args.protected_source,
        alias_map=alias_map,
    )
    selection = build_selection_manifest(
        snapshot,
        protected,
        precision_sample_size=args.precision_sample_size,
        recall_sample_size=args.recall_sample_size,
        selection_code_sha256=_selection_code_sha256(),
    )
    digest = selection["selection_manifest_sha256"]
    output_dir = args.output_dir.resolve()
    selection_path = output_dir / f"selection-{digest}.json"
    template_path = output_dir / f"labels-{digest}.template.json"
    _atomic_write_json(selection_path, selection)
    _atomic_write_json(template_path, build_label_template(selection))
    print(
        json.dumps(
            {
                "selection": str(selection_path),
                "labels_template": str(template_path),
                "selection_manifest_sha256": digest,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    repo_root = args.repo_root.resolve()
    selection = _read_json_object(
        args.selection,
        "selection manifest",
        max_bytes=_MAX_SELECTION_BYTES,
    )
    validate_selection_seal(selection)
    protected_contract = selection.get("protected_inputs")
    if not isinstance(protected_contract, dict) or not isinstance(
        protected_contract.get("source_roots"), list
    ):
        raise HeldoutQualityError("selection protected input contract is missing")
    alias_map = build_alias_map()
    snapshot = load_fixed_campaign_snapshot(repo_root, alias_map=alias_map)
    protected = build_authoritative_protected_inventory(
        repo_root,
        recorded_roots=protected_contract["source_roots"],
        excluded_paths=(args.selection, args.labels),
        alias_map=alias_map,
    )
    policy = selection.get("selection_policy")
    if not isinstance(policy, dict):
        raise HeldoutQualityError("selection policy is missing")
    expected = build_selection_manifest(
        snapshot,
        protected,
        precision_sample_size=policy.get("precision_sample_size"),
        recall_sample_size=policy.get("recall_sample_size"),
        selection_code_sha256=_selection_code_sha256(),
    )
    if expected != selection:
        raise HeldoutQualityError(
            "selection does not exactly reproduce from the current fixed campaign"
        )
    labels = _read_json_object(
        args.labels,
        "held-out labels",
        max_bytes=_MAX_LABEL_BYTES,
    )
    report = evaluate_selection(
        selection,
        labels,
        protected,
        precision_target=args.precision_target,
        recall_target=args.recall_target,
        require_certified=args.require_certified,
        selection_path=args.selection,
        labels_path=args.labels,
        repo_root=repo_root,
    )
    if args.output is not None:
        _atomic_write_json(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["release_gate_passed"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    select = subparsers.add_parser("select", help="seal samples before labels exist")
    select.add_argument("--repo-root", type=Path, default=_REPO_ROOT)
    select.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIR)
    select.add_argument("--precision-sample-size", type=int, default=100)
    select.add_argument("--recall-sample-size", type=int, default=200)
    select.add_argument(
        "--protected-source",
        action="append",
        type=Path,
        default=[],
        help="additional calibration/adjudication input file or directory",
    )
    select.set_defaults(handler=_select)

    evaluate = subparsers.add_parser("evaluate", help="evaluate independent labels")
    evaluate.add_argument("--repo-root", type=Path, default=_REPO_ROOT)
    evaluate.add_argument("--selection", type=Path, required=True)
    evaluate.add_argument("--labels", type=Path, required=True)
    evaluate.add_argument("--output", type=Path)
    evaluate.add_argument(
        "--precision-target", type=float, default=_DEFAULT_PRECISION_TARGET
    )
    evaluate.add_argument("--recall-target", type=float, default=_DEFAULT_RECALL_TARGET)
    evaluate.add_argument("--require-certified", action="store_true")
    evaluate.set_defaults(handler=_evaluate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except HeldoutQualityError as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "evaluation_complete": False,
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
