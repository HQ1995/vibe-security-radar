#!/usr/bin/env python3
"""Measure fixed-contract or mixed-cache quality on an adjudication corpus.

This evaluator deliberately exposes two different predictions for every
advisory equivalence class:

* ``fixed_contract_campaign_metrics`` is emitted only when every batch in the
  current plan has a current marker and an exact staged result manifest, while
  every result carries a valid Flash-screening/Luna-verification receipt.
* ``cached_pipeline_snapshot_metrics`` is the fail-closed fallback when that
  proof is incomplete. It projects stored, mixed-version analyzer results
  through the current inclusion predicate.
* ``curated_publication_metrics`` treats membership in the validated web-data
  generation as the prediction.  It therefore measures the final curated
  publication on the same frozen corpus.

The report contains ordered corpus and prediction manifests, hashes of those
manifests, exact input/code hashes, cached model provenance, and explicit
unresolved/infrastructure strata.  Missing or conflicting corpus inputs are
fatal rather than silently removed from the denominator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from cve_analyzer.models import (
    CveAnalysisResult,
    investigation_scope_is_current,
    relevant_investigation_bics,
)

from evaluate_publication_quality import clopper_pearson_lower_bound
import run_data_refresh as refresh_runner
from web_data.constants import DEFAULT_CACHE_DIR, DEFAULT_GHSA_DB_DIR
from web_data.filters import _should_include_with_reason, is_fallback_verdict
from web_data.loader import build_alias_map, expand_audit_adjudications
from web_data.schema import VULNERABILITY_ID_PATTERN, validate_inventory_payload
from web_data.writer import PublishedDataError, load_published_web_data

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_DEFAULT_ADJUDICATIONS = _SCRIPT_DIR / "audit_adjudications.json"
_DEFAULT_PUBLICATION_DIR = _REPO_ROOT / "web" / "data"
_DEFAULT_OSV_BULK_DIR = Path.home() / ".cache" / "cve-analyzer" / "osv-bulk"

_ALLOWED_LABELS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"})
_TERMINAL_NON_INFRA_ERROR_CATEGORIES = frozenset(
    {"", "no_ai_activity", "no_fix_commits", "skipped_advisory"}
)
_PUBLIC_ID = re.compile(VULNERABILITY_ID_PATTERN)
_ALGORITHM = "fixed-contract-or-mixed-cache-detector-quality-v4"
_FIXED_CAMPAIGN_MODEL = "gpt-5.6-luna"
_FIXED_SCREENING_MODEL = "gemini-3.5-flash-lite"
_FIXED_CAMPAIGN_REASONING_EFFORT = "max"


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    """One independently adjudicated advisory equivalence class."""

    canonical_id: str
    label: str
    subject_ids: tuple[str, ...]
    source: str | None = None
    confidence: float | None = None


@dataclass(frozen=True, slots=True)
class CachedPipelineInput:
    """One validated cached analyzer result and its current projection."""

    subject_id: str
    path: Path
    file_sha256: str
    mtime_ns: int
    result: CveAnalysisResult
    predicted_positive: bool
    prediction_reason: str
    infrastructure_categories: tuple[str, ...]
    unresolved_reasons: tuple[str, ...]
    llm_provenance: tuple[dict[str, str], ...]
    terminal_problem: str | None


@dataclass(frozen=True, slots=True)
class FixedCampaignBatch:
    """One runner-validated batch needed to map adjudicated subjects."""

    key: str
    path: Path
    ids: tuple[str, ...]
    command: tuple[str, ...]
    class_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FixedCampaignProofContext:
    """Current refresh-runner contract and marker locations."""

    repo_root: Path
    marker_dir: Path
    marker_schema_version: int
    batches: tuple[FixedCampaignBatch, ...]
    contract_sha256: str
    source_snapshot_sha256: str
    source_snapshot: dict[str, Any]
    model: str
    reasoning_effort: str
    workers: int
    no_token_child_processes: int
    no_token_total_workers: int
    campaign_id: str
    result_dir: Path
    litellm_transport_sha256: str
    litellm_transport: dict[str, Any]
    batch_timeout_seconds: int
    incremental_plan_proof: dict[str, Any]
    campaign_mode: str = "incremental"
    population_policy: str = "incremental"
    analyzer_contract_sha256: str = ""
    signature_sha256: str = ""
    alias_class_manifest_sha256: str = ""
    alias_class_manifest: dict[str, Any] | None = None


def _canonical_json(value: object) -> bytes:
    """Return stable UTF-8 JSON bytes used by every manifest hash."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    """Hash a JSON-compatible value using the evaluator's canonical encoding."""
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _runner_source_snapshot_sha256(details: dict[str, Any]) -> str:
    """Hash source details with the refresh runner's canonical encoding."""
    encoded = json.dumps(
        details,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ValueError(f"Cannot hash input {path}: {exc}") from exc
    return digest.hexdigest()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_json_object(path: Path, description: str) -> tuple[dict[str, Any], str]:
    try:
        content = path.read_bytes()
        payload = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read {description} {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{description.capitalize()} {path} must contain an object")
    return payload, _sha256_bytes(content)


def _validate_public_id(value: object, description: str) -> str:
    """Return a public ID only when it is safe as one cache filename stem."""
    if not isinstance(value, str) or _PUBLIC_ID.fullmatch(value) is None:
        raise ValueError(
            f"{description} must be a path-safe public ID matching "
            f"{VULNERABILITY_ID_PATTERN!r}; got {value!r}"
        )
    return value


def _load_corpus(
    path: Path,
    alias_map: dict[str, set[str]],
) -> tuple[tuple[CorpusEntry, ...], str]:
    """Load, validate, and alias-expand the frozen adjudication corpus."""
    payload, input_sha256 = _read_json_object(path, "adjudication input")
    if payload.get("schema_version") != 1:
        raise ValueError("Adjudications require schema_version 1")
    entries = payload.get("adjudications")
    if not isinstance(entries, list):
        raise ValueError("Adjudications must contain an adjudications array")

    validated: list[dict[str, Any]] = []
    canonical_ids: set[str] = set()
    explicit_subject_owner: dict[str, str] = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise ValueError("Every adjudication must be an object")
        canonical_id = raw_entry.get("cve_id")
        label = raw_entry.get("label")
        if not isinstance(canonical_id, str) or not canonical_id.strip():
            raise ValueError("Every adjudication requires a non-empty cve_id")
        canonical_id = _validate_public_id(canonical_id, "Adjudication cve_id")
        if canonical_id in canonical_ids:
            raise ValueError(f"Duplicate adjudication for {canonical_id}")
        if label not in _ALLOWED_LABELS:
            raise ValueError(
                f"Invalid adjudication label for {canonical_id}: {label!r}"
            )
        aliases = raw_entry.get("aliases", [])
        if not isinstance(aliases, list) or any(
            not isinstance(alias, str) or not alias.strip() for alias in aliases
        ):
            raise ValueError(f"Invalid aliases for {canonical_id}")
        aliases = [
            _validate_public_id(alias, f"Alias for {canonical_id}") for alias in aliases
        ]
        if len(aliases) != len(set(aliases)) or canonical_id in aliases:
            raise ValueError(f"Duplicate aliases for {canonical_id}")
        confidence = raw_entry.get("confidence")
        if confidence is not None and (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            raise ValueError(f"Invalid audit confidence for {canonical_id}")

        for subject_id in (canonical_id, *aliases):
            owner = explicit_subject_owner.get(subject_id)
            if owner is not None:
                raise ValueError(
                    f"Duplicate adjudication subject {subject_id}: {owner} and {canonical_id}"
                )
            explicit_subject_owner[subject_id] = canonical_id
        canonical_ids.add(canonical_id)
        validated.append({**raw_entry, "cve_id": canonical_id, "aliases": aliases})

    # The repository's source-backed closure is the shared definition used by
    # publication.  It rejects overlap across adjudication rows, including a
    # same-label overlap that would otherwise double-count one vulnerability.
    expanded = expand_audit_adjudications(validated, alias_map)
    corpus: list[CorpusEntry] = []
    for entry in expanded:
        canonical_id = _validate_public_id(
            entry["cve_id"], "Expanded adjudication cve_id"
        )
        subject_ids = tuple(
            sorted(
                {
                    _validate_public_id(
                        subject_id, f"Expanded subject for {canonical_id}"
                    )
                    for subject_id in (entry["cve_id"], *entry.get("aliases", []))
                }
            )
        )
        corpus.append(
            CorpusEntry(
                canonical_id=canonical_id,
                label=entry["label"],
                subject_ids=subject_ids,
                source=entry.get("source")
                if isinstance(entry.get("source"), str)
                else None,
                confidence=(
                    float(entry["confidence"])
                    if isinstance(entry.get("confidence"), (int, float))
                    and not isinstance(entry.get("confidence"), bool)
                    else None
                ),
            )
        )
    return tuple(sorted(corpus, key=lambda entry: entry.canonical_id)), input_sha256


def _json_path(parent: str, key: str) -> str:
    if key.isidentifier():
        return f"{parent}.{key}"
    escaped = key.replace("\\", "\\\\").replace("'", "\\'")
    return f"{parent}['{escaped}']"


def _extract_llm_provenance(payload: object) -> tuple[dict[str, str], ...]:
    """Extract every cached model/effort pair with a stable JSON location."""
    records: list[dict[str, str]] = []

    def visit(value: object, path: str) -> None:
        if isinstance(value, dict):
            model = value.get("model")
            effort = value.get("reasoning_effort")
            if isinstance(model, str) and model.strip():
                record = {"json_path": path, "model": model.strip()}
                if isinstance(effort, str) and effort.strip():
                    record["reasoning_effort"] = effort.strip()
                records.append(record)
            for key in sorted(value):
                visit(value[key], _json_path(path, str(key)))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")

    visit(payload, "$")
    records.sort(
        key=lambda item: (
            item["json_path"],
            item["model"],
            item.get("reasoning_effort", ""),
        )
    )
    return tuple(records)


def _infrastructure_categories(payload: dict[str, Any]) -> tuple[str, ...]:
    categories: set[str] = set()
    raw_category = payload.get("error_category")
    category = raw_category.strip() if isinstance(raw_category, str) else ""
    error = payload.get("error")
    if category and category not in _TERMINAL_NON_INFRA_ERROR_CATEGORIES:
        categories.add(category)
    if error and not category:
        categories.add("uncategorized_error")
    elif error and category not in _TERMINAL_NON_INFRA_ERROR_CATEGORIES:
        categories.add(category)
    repo_activity = payload.get("repo_ai_activity", [])
    if isinstance(repo_activity, list):
        categories.update(
            reason
            for reason in repo_activity
            if isinstance(reason, str) and reason.startswith("incomplete:")
        )
    return tuple(sorted(categories))


def _unresolved_reasons(result: CveAnalysisResult) -> tuple[str, ...]:
    """Identify benefit-of-doubt/fallback detector decisions separately."""
    reasons: set[str] = set()
    scope_is_current = investigation_scope_is_current(result)
    for bic in result.bug_introducing_commits:
        if not bic.effective_signals() and bic.screening_verification is None:
            continue
        verification = bic.deep_verification
        if verification is None and not scope_is_current:
            reasons.add("unverified_ai_evidence")
        elif is_fallback_verdict(verification):
            reasons.add("fallback_deep_verification")
    return tuple(sorted(reasons))


def _load_cached_pipeline_input(path: Path, expected_id: str) -> CachedPipelineInput:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Cached pipeline snapshot input is missing or unsafe: {path}")
    try:
        stat_before = path.stat()
        content = path.read_bytes()
        stat_after = path.stat()
        payload = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"Cannot read cached pipeline snapshot input {path}: {exc}"
        ) from exc
    stable_fields_before = (
        stat_before.st_dev,
        stat_before.st_ino,
        stat_before.st_size,
        stat_before.st_mtime_ns,
    )
    stable_fields_after = (
        stat_after.st_dev,
        stat_after.st_ino,
        stat_after.st_size,
        stat_after.st_mtime_ns,
    )
    if stable_fields_before != stable_fields_after:
        raise ValueError(f"Cached pipeline snapshot input changed while read: {path}")
    if not isinstance(payload, dict):
        raise ValueError(
            f"Cached pipeline snapshot input {path} must contain an object"
        )
    actual_id = payload.get("cve_id")
    if actual_id != expected_id:
        raise ValueError(
            "Cached pipeline snapshot filename/id mismatch for "
            f"{path}: expected {expected_id!r}, got {actual_id!r}"
        )
    try:
        result = CveAnalysisResult.from_dict(payload)
        # This only aggregates stored per-BIC signals. It does not scan commit
        # text against the current signature registry.
        result.rebuild_signals()
        predicted_positive, reason = _should_include_with_reason(result, set(), set())
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid cached pipeline snapshot input {path}: {exc}"
        ) from exc
    return CachedPipelineInput(
        subject_id=expected_id,
        path=path.resolve(),
        file_sha256=_sha256_bytes(content),
        mtime_ns=stat_after.st_mtime_ns,
        result=result,
        predicted_positive=predicted_positive,
        prediction_reason=reason or "included",
        infrastructure_categories=_infrastructure_categories(payload),
        unresolved_reasons=_unresolved_reasons(result),
        llm_provenance=_extract_llm_provenance(payload),
        terminal_problem=refresh_runner._terminal_result_problem(payload),
    )


def _cache_input_path(cache_root: Path, subject_id: str) -> Path:
    """Resolve one cache filename and prove that it remains in cache_root."""
    subject_id = _validate_public_id(subject_id, "Cached pipeline subject")
    unresolved = cache_root / f"{subject_id}.json"
    if unresolved.is_symlink():
        raise ValueError(f"Cached pipeline snapshot input is unsafe: {unresolved}")
    candidate = unresolved.resolve(strict=False)
    if candidate.parent != cache_root:
        raise ValueError(
            f"Cached pipeline snapshot input escapes cache directory: {subject_id!r}"
        )
    return candidate


def _load_class_snapshot_inputs(
    cache_dir: Path,
    corpus: tuple[CorpusEntry, ...],
) -> dict[str, tuple[CachedPipelineInput, ...]]:
    if cache_dir.is_symlink() or not cache_dir.is_dir():
        raise ValueError(
            f"Cached pipeline snapshot directory is missing or unsafe: {cache_dir}"
        )
    cache_root = cache_dir.resolve(strict=True)
    loaded: dict[str, tuple[CachedPipelineInput, ...]] = {}
    input_owner: dict[str, str] = {}
    for entry in corpus:
        class_inputs: list[CachedPipelineInput] = []
        for subject_id in entry.subject_ids:
            path = _cache_input_path(cache_root, subject_id)
            if not path.exists():
                continue
            cache_input = _load_cached_pipeline_input(path, subject_id)
            owner = input_owner.get(cache_input.subject_id)
            if owner is not None:
                raise ValueError(
                    "Duplicate cached pipeline snapshot input "
                    f"{cache_input.subject_id}: {owner} and {entry.canonical_id}"
                )
            input_owner[cache_input.subject_id] = entry.canonical_id
            class_inputs.append(cache_input)
        if not class_inputs:
            raise ValueError(
                "Missing cached pipeline snapshot input for adjudication class "
                f"{entry.canonical_id}; expected one of {list(entry.subject_ids)!r}"
            )
        loaded[entry.canonical_id] = tuple(
            sorted(class_inputs, key=lambda cache_input: cache_input.subject_id)
        )
    return loaded


def _current_fixed_campaign_context(
    repo_root: Path = _REPO_ROOT,
) -> FixedCampaignProofContext:
    """Load the current runner plan and source/contract digests read-only."""
    paths = refresh_runner.RunnerPaths.defaults(repo_root)
    plan = refresh_runner.load_plan(paths)
    refresh_root = paths.grouped_dir.parent
    delta_path = refresh_root / "source-delta-current.json"
    candidate_path = refresh_root / "new-osv-candidates.txt"
    delta = json.loads(delta_path.read_text(encoding="utf-8"))
    candidate_ids = tuple(
        line.strip()
        for line in candidate_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    plan_ids = tuple(subject_id for batch in plan for subject_id in batch.ids)
    production = delta["production_discovery"]
    result_cache = delta["result_cache"]
    candidate = delta["candidate"]
    population_policy = delta["population_policy"]
    campaign_mode = "formal" if population_policy == "formal_full" else "incremental"
    alias_manifest = production.get("alias_class_manifest")
    if not isinstance(alias_manifest, dict):
        raise ValueError("current source delta has no alias-class manifest")
    alias_classes = alias_manifest.get("classes")
    if not isinstance(alias_classes, list):
        raise ValueError("current source delta alias-class records are malformed")
    subject_to_class = {
        item["analysis_subject"]: item["class_id"]
        for item in alias_classes
        if isinstance(item, dict) and item.get("scheduled_seed_ids")
    }
    sorted_plan_ids = sorted(plan_ids)
    plan_ids_bytes = ("\n".join(sorted_plan_ids) + "\n").encode()
    incremental_plan_proof = {
        "schema_version": 2,
        "scope": (
            "formal_current_source_alias_class_plan"
            if campaign_mode == "formal"
            else "incremental_current_source_candidate_plan"
        ),
        "campaign_mode": campaign_mode,
        "population_policy": population_policy,
        "formal_release_eligible": campaign_mode == "formal",
        "source_delta_schema_version": delta["schema_version"],
        "source_delta_path": delta_path.relative_to(paths.repo_root).as_posix(),
        "source_delta_sha256": _file_sha256(delta_path),
        "source_delta_integrity_payload_sha256": delta[
            "integrity_payload_sha256"
        ],
        "input_snapshot_sha256": delta["input_snapshot_sha256"],
        "result_cache_inventory_manifest_sha256": result_cache[
            "inventory_manifest_sha256"
        ],
        "production_discovered_id_count": production[
            "production_discovered_id_count"
        ],
        "cache_covered_discovered_id_count": production[
            "cache_covered_discovered_id_count"
        ],
        "uncached_discovered_id_count": production["uncached_discovered_id_count"],
        "candidate_id_count": len(candidate_ids),
        "candidate_sha256": _file_sha256(candidate_path),
        "plan_subject_id_count": len(plan_ids),
        "plan_subject_ids_sha256": hashlib.sha256(plan_ids_bytes).hexdigest(),
        "alias_class_manifest_sha256": alias_manifest["classes_sha256"],
        "source_alias_class_count": alias_manifest["class_count"],
        "scheduled_alias_class_count": alias_manifest.get(
            "scheduled_class_count", len(subject_to_class)
        ),
        "plan_alias_classes_exactly_once": (
            len(plan_ids) == len(subject_to_class)
            and set(plan_ids) == set(subject_to_class)
        ),
        "analyzer_contract_sha256": delta["analyzer_contract"]["sha256"],
        "signature_sha256": delta["analyzer_contract"]["signature_sha256"],
        "candidate_union_exact": candidate["union_exact"],
        "plan_exactly_matches_candidate": set(plan_ids) == set(candidate_ids)
        and len(plan_ids) == len(candidate_ids) == len(set(plan_ids)),
        "frozen_local_sources": production["frozen_local_sources"],
        "network_advisory_api_included": production[
            "network_advisory_api_included"
        ],
        "historical_cache_suppresses_current_classes": candidate[
            "historical_cache_suppresses_current_classes"
        ],
        "formal_current_epoch_stage_receipt_required": result_cache[
            "coverage_policy"
        ]["formal_current_epoch_stage_receipt_required"],
        "boundary": (
            "The plan covers each scheduled alias class exactly once. Campaign "
            "completion additionally requires current-epoch class/stage receipts."
        ),
    }
    source_snapshot = refresh_runner.capture_source_snapshot(paths)
    contract_digest = refresh_runner.contract_sha256(paths)
    campaign = refresh_runner.campaign_execution(
        paths,
        source_snapshot,
        contract_digest,
    )
    return FixedCampaignProofContext(
        repo_root=paths.repo_root.resolve(),
        marker_dir=paths.state_dir / "completed",
        marker_schema_version=refresh_runner.MARKER_SCHEMA_VERSION,
        batches=tuple(
            FixedCampaignBatch(
                key=batch.key,
                path=batch.path.resolve(),
                ids=tuple(batch.ids),
                command=tuple(
                    refresh_runner.build_command(batch, phase="verification")
                ),
                class_ids=(
                    tuple(batch.class_ids)
                    if batch.class_ids
                    else tuple(subject_to_class[subject] for subject in batch.ids)
                ),
            )
            for batch in plan
        ),
        contract_sha256=contract_digest,
        source_snapshot_sha256=source_snapshot.sha256,
        source_snapshot=source_snapshot.details,
        model=refresh_runner.MODEL,
        reasoning_effort=refresh_runner.REASONING_EFFORT,
        workers=refresh_runner.WORKERS,
        no_token_child_processes=refresh_runner.NO_TOKEN_CHILD_PROCESSES,
        no_token_total_workers=refresh_runner.NO_TOKEN_TOTAL_WORKERS,
        campaign_id=campaign.campaign_id,
        result_dir=campaign.result_dir,
        litellm_transport_sha256=campaign.litellm_transport_sha256,
        litellm_transport=campaign.litellm_transport,
        batch_timeout_seconds=refresh_runner.BATCH_TIMEOUT_SECONDS,
        incremental_plan_proof=incremental_plan_proof,
        campaign_mode=campaign_mode,
        population_policy=population_policy,
        analyzer_contract_sha256=campaign.analyzer_contract_sha256,
        signature_sha256=campaign.signature_sha256,
        alias_class_manifest_sha256=alias_manifest["classes_sha256"],
        alias_class_manifest=alias_manifest,
    )


def _iso_timestamp_ns(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    delta = parsed.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (
        delta.days * 86_400 + delta.seconds
    ) * 1_000_000_000 + delta.microseconds * 1_000


def _stable_json_file(path: Path, description: str) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{description} is missing or unsafe: {path}")
    try:
        stat_before = path.stat()
        content = path.read_bytes()
        stat_after = path.stat()
        payload = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read {description} {path}: {exc}") from exc
    before = (
        stat_before.st_dev,
        stat_before.st_ino,
        stat_before.st_size,
        stat_before.st_mtime_ns,
    )
    after = (
        stat_after.st_dev,
        stat_after.st_ino,
        stat_after.st_size,
        stat_after.st_mtime_ns,
    )
    if before != after:
        raise ValueError(f"{description} changed while read: {path}")
    if not isinstance(payload, dict):
        raise ValueError(f"{description} must contain an object: {path}")
    return payload, _sha256_bytes(content)


def _stable_campaign_result(
    result_root: Path,
    subject_id: str,
) -> dict[str, Any]:
    """Read one staged result once and bind its bytes, identity, and mtime."""
    subject_id = _validate_public_id(subject_id, "Campaign result subject")
    unresolved = result_root / f"{subject_id}.json"
    if unresolved.is_symlink():
        raise ValueError(f"Campaign result is unsafe: {unresolved}")
    path = unresolved.resolve(strict=False)
    if path.parent != result_root:
        raise ValueError(f"Campaign result escapes result directory: {subject_id!r}")
    if not path.is_file():
        raise ValueError(f"Campaign result is missing: {path}")
    try:
        before = path.stat()
        content = path.read_bytes()
        after = path.stat()
        payload = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read campaign result {path}: {exc}") from exc
    before_signature = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    after_signature = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if before_signature != after_signature:
        raise ValueError(f"Campaign result changed while read: {path}")
    if not isinstance(payload, dict) or payload.get("cve_id") != subject_id:
        raise ValueError(f"Campaign result identity mismatch for {subject_id}")
    return {
        "path": path,
        "payload": payload,
        "sha256": _sha256_bytes(content),
        "size_bytes": len(content),
        "mtime_ns": after.st_mtime_ns,
    }


def _runner_result_manifest_sha256(manifest: list[dict[str, Any]]) -> str:
    """Mirror run_data_refresh._canonical_json_bytes for marker manifests."""
    encoded = json.dumps(
        manifest,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _campaign_receipt_failures(
    *,
    payload: dict[str, Any],
    result: CveAnalysisResult,
    subject_id: str,
    batch_key: str,
    marker_started_at: object,
    marker_started_at_ns: int | None,
    marker_completed_at_ns: int | None,
    result_mtime_ns: int,
    context: FixedCampaignProofContext,
) -> list[dict[str, Any]]:
    """Validate the staged receipt and independently re-prove its stage claims."""
    failures: list[dict[str, Any]] = []

    def fail(code: str, **details: Any) -> None:
        failures.append(
            {"code": code, "subject_id": subject_id, "batch": batch_key, **details}
        )

    receipt = payload.get("campaign_receipt")
    if not isinstance(receipt, dict):
        fail("result_campaign_receipt_missing")
        return failures

    expected_keys = {
        "schema_version",
        "campaign_id",
        "pipeline_phase",
        "batch",
        "started_at",
        "completed_at",
        "source_snapshot_sha256",
        "contract_sha256",
        "litellm_transport_sha256",
        "requested_models",
        "reasoning_efforts",
        "llm_cache_disabled",
        "resource_governance",
        "stages",
        "status",
        "failed_stages",
    }
    if set(receipt) != expected_keys:
        fail(
            "result_campaign_receipt_fields_invalid",
            actual=sorted(receipt),
            expected=sorted(expected_keys),
        )

    expected_values = {
        "schema_version": 3,
        "campaign_id": context.campaign_id,
        "pipeline_phase": "verification",
        "batch": batch_key,
        "started_at": marker_started_at,
        "source_snapshot_sha256": context.source_snapshot_sha256,
        "contract_sha256": context.contract_sha256,
        "litellm_transport_sha256": context.litellm_transport_sha256,
        "requested_models": {
            "phase_c_screening": _FIXED_SCREENING_MODEL,
            "phase_d_deep_verification": _FIXED_CAMPAIGN_MODEL,
        },
        "reasoning_efforts": {
            "phase_c_screening": refresh_runner.SCREENING_REASONING_EFFORT,
            "phase_d_deep_verification": _FIXED_CAMPAIGN_REASONING_EFFORT,
        },
        "llm_cache_disabled": True,
        "resource_governance": {
            "llm_global_max": str(refresh_runner.LLM_MAX_CONCURRENCY),
            "llm_screening_max": str(refresh_runner.LLM_SCREENING_MAX_CONCURRENCY),
            "llm_verification_max": str(refresh_runner.LLM_VERIFY_MAX_CONCURRENCY),
            "llm_screening_rpm": os.environ.get(
                refresh_runner.LLM_SCREENING_RPM_ENV, ""
            ),
            "llm_screening_tpm": os.environ.get(
                refresh_runner.LLM_SCREENING_TPM_ENV, ""
            ),
            "llm_verification_rpm": os.environ.get(
                refresh_runner.LLM_VERIFY_RPM_ENV, ""
            ),
            "llm_verification_tpm": os.environ.get(
                refresh_runner.LLM_VERIFY_TPM_ENV, ""
            ),
            "github_max_in_flight": str(refresh_runner.GITHUB_MAX_IN_FLIGHT),
            "github_reserve_fraction": str(refresh_runner.GITHUB_RESERVE_FRACTION),
            "github_target_utilization": str(
                refresh_runner.GITHUB_TARGET_UTILIZATION
            ),
            "github_governor_backend": "sqlite_wal_v1",
        },
        "status": "success",
        "failed_stages": [],
    }
    for field, expected_value in expected_values.items():
        if receipt.get(field) != expected_value:
            fail(
                "result_campaign_receipt_mismatch",
                field=field,
                actual=receipt.get(field),
                expected=expected_value,
            )

    receipt_completed_at_ns = _iso_timestamp_ns(receipt.get("completed_at"))
    if (
        receipt_completed_at_ns is None
        or marker_started_at_ns is None
        or marker_completed_at_ns is None
        or not marker_started_at_ns <= receipt_completed_at_ns <= marker_completed_at_ns
    ):
        fail(
            "result_campaign_receipt_time_invalid",
            completed_at=receipt.get("completed_at"),
        )

    elif (
        result_mtime_ns - receipt_completed_at_ns
        > refresh_runner.RESULT_RECEIPT_WRITE_GRACE_NS
    ):
        fail(
            "result_campaign_receipt_precedes_result_write",
            receipt_completed_at_ns=receipt_completed_at_ns,
            result_mtime_ns=result_mtime_ns,
        )

    stages = receipt.get("stages")
    expected_stage_names = {"phase_c_screening", "phase_d_deep_verification"}
    if not isinstance(stages, dict) or set(stages) != expected_stage_names:
        fail("result_campaign_receipt_stages_invalid")
        return failures

    has_ai_bics = any(bic.all_ai_signals() for bic in result.bug_introducing_commits)
    relevant_bics = relevant_investigation_bics(result)
    screening_stage = stages.get("phase_c_screening")
    expected_screening_status = "success" if has_ai_bics else "not_applicable"
    if (
        not isinstance(screening_stage, dict)
        or screening_stage.get("status") != expected_screening_status
    ):
        fail(
            "result_campaign_screening_stage_invalid",
            actual=screening_stage,
            expected_status=expected_screening_status,
        )
    elif expected_screening_status == "not_applicable":
        if set(screening_stage) != {"status"}:
            fail("result_campaign_screening_stage_fields_invalid")
    elif (
        set(screening_stage) != {"status", "actual_model"}
        or screening_stage.get("actual_model") != _FIXED_SCREENING_MODEL
        or result.screening is None
        or result.screening.model != _FIXED_SCREENING_MODEL
    ):
        fail("result_campaign_screening_model_invalid")

    deep_stage = stages.get("phase_d_deep_verification")
    expected_deep_status = "success" if relevant_bics else "not_applicable"
    if (
        not isinstance(deep_stage, dict)
        or deep_stage.get("status") != expected_deep_status
    ):
        fail(
            "result_campaign_deep_stage_invalid",
            actual=deep_stage,
            expected_status=expected_deep_status,
        )
    elif expected_deep_status == "not_applicable":
        if set(deep_stage) != {"status"}:
            fail("result_campaign_deep_stage_fields_invalid")
    else:
        expected_deep_fields = {
            "status",
            "actual_models",
            "actual_reasoning_efforts",
        }
        if (
            set(deep_stage) != expected_deep_fields
            or deep_stage.get("actual_models") != [_FIXED_CAMPAIGN_MODEL]
            or deep_stage.get("actual_reasoning_efforts")
            != [_FIXED_CAMPAIGN_REASONING_EFFORT]
            or not investigation_scope_is_current(result)
        ):
            fail("result_campaign_deep_stage_contract_invalid")

    return failures


def _fixed_contract_campaign_proof(
    corpus: tuple[CorpusEntry, ...],
    snapshot_inputs: dict[str, tuple[CachedPipelineInput, ...]],
    context: FixedCampaignProofContext | None,
    setup_failures: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    """Prove the current class-keyed campaign over content-addressed results."""
    required_source_subjects = sorted(
        {subject_id for entry in corpus for subject_id in entry.subject_ids}
    )
    failures: list[dict[str, Any]] = [dict(failure) for failure in setup_failures]
    if context is None:
        if not failures:
            failures.append({"code": "campaign_proof_not_configured"})
        failure_counts = dict(
            sorted(
                Counter(
                    str(failure.get("code", "unknown")) for failure in failures
                ).items()
            )
        )
        return {
            "complete": False,
            "incremental_plan_complete": False,
            "full_incremental_plan_campaign_complete": False,
            "proof_scope": "incremental_current_source_candidate_plan",
            "population_uniform_luna_max_proof": False,
            "required_subject_count": len(required_source_subjects),
            "required_campaign_subject_count": len(required_source_subjects),
            "mapped_subject_count": 0,
            "campaign_batch_count": 0,
            "completed_marker_count": 0,
            "relevant_marker_count": 0,
            "failure_counts": failure_counts,
            "failures": sorted(failures, key=canonical_sha256),
            "marker_proofs": [],
            "subject_proofs": [],
        }

    formal_campaign = (
        context.campaign_mode == "formal"
        and context.population_policy == "formal_full"
    )
    expected: dict[str, Any] = {
        "marker_schema_version": refresh_runner.MARKER_SCHEMA_VERSION,
        "campaign_id": context.campaign_id,
        "result_dir": str(context.result_dir),
        "contract_sha256": context.contract_sha256,
        "analyzer_contract_sha256": context.analyzer_contract_sha256,
        "signature_sha256": context.signature_sha256,
        "alias_class_manifest_sha256": context.alias_class_manifest_sha256,
        "source_snapshot_sha256": context.source_snapshot_sha256,
        "model": _FIXED_CAMPAIGN_MODEL,
        "reasoning_effort": _FIXED_CAMPAIGN_REASONING_EFFORT,
        "workers": context.workers,
        "no_token_child_processes": context.no_token_child_processes,
        "no_token_total_workers": context.no_token_total_workers,
        "litellm_transport_sha256": context.litellm_transport_sha256,
        "litellm_transport": context.litellm_transport,
        "batch_timeout_seconds": context.batch_timeout_seconds,
        "campaign_mode": context.campaign_mode,
        "population_policy": context.population_policy,
        "incremental_plan_proof": context.incremental_plan_proof,
    }
    if context.marker_schema_version != refresh_runner.MARKER_SCHEMA_VERSION:
        failures.append(
            {
                "code": "current_campaign_marker_schema_invalid",
                "actual": context.marker_schema_version,
                "expected": refresh_runner.MARKER_SCHEMA_VERSION,
            }
        )
    if context.model != _FIXED_CAMPAIGN_MODEL:
        failures.append(
            {
                "code": "current_campaign_model_invalid",
                "actual": context.model,
                "expected": _FIXED_CAMPAIGN_MODEL,
            }
        )
    if context.reasoning_effort != _FIXED_CAMPAIGN_REASONING_EFFORT:
        failures.append(
            {
                "code": "current_campaign_reasoning_effort_invalid",
                "actual": context.reasoning_effort,
                "expected": _FIXED_CAMPAIGN_REASONING_EFFORT,
            }
        )
    if not re.fullmatch(r"[0-9a-f]{64}", context.contract_sha256):
        failures.append({"code": "current_contract_digest_invalid"})
    if not re.fullmatch(r"[0-9a-f]{64}", context.campaign_id):
        failures.append({"code": "current_campaign_id_invalid"})
    for field, value in (
        ("analyzer_contract_sha256", context.analyzer_contract_sha256),
        ("signature_sha256", context.signature_sha256),
        ("alias_class_manifest_sha256", context.alias_class_manifest_sha256),
    ):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            failures.append({"code": f"current_{field}_invalid"})
    source_digest = _runner_source_snapshot_sha256(context.source_snapshot)
    if source_digest != context.source_snapshot_sha256:
        failures.append(
            {
                "code": "current_source_digest_invalid",
                "computed": source_digest,
                "expected": context.source_snapshot_sha256,
            }
        )

    class_records_by_subject: dict[str, dict[str, Any]] = {}
    member_to_analysis_subject: dict[str, str] = {}
    scheduled_class_ids: set[str] = set()
    alias_manifest = context.alias_class_manifest
    alias_classes = (
        alias_manifest.get("classes") if isinstance(alias_manifest, dict) else None
    )
    if formal_campaign:
        if (
            not isinstance(alias_manifest, dict)
            or not isinstance(alias_classes, list)
            or alias_manifest.get("classes_sha256")
            != context.alias_class_manifest_sha256
            or hashlib.sha256(
                refresh_runner._canonical_json_bytes(alias_classes)
            ).hexdigest()
            != context.alias_class_manifest_sha256
        ):
            failures.append({"code": "current_alias_class_manifest_invalid"})
            alias_classes = []
        for item in alias_classes:
            if not isinstance(item, dict) or not item.get("scheduled_seed_ids"):
                continue
            class_id = item.get("class_id")
            analysis_subject = item.get("analysis_subject")
            member_ids = item.get("all_member_ids")
            if (
                not isinstance(class_id, str)
                or not isinstance(analysis_subject, str)
                or not isinstance(member_ids, list)
                or not member_ids
                or any(not isinstance(member, str) for member in member_ids)
                or analysis_subject not in member_ids
                or analysis_subject in class_records_by_subject
            ):
                failures.append({"code": "scheduled_alias_class_record_invalid"})
                continue
            class_records_by_subject[analysis_subject] = item
            scheduled_class_ids.add(class_id)
            for member in member_ids:
                previous = member_to_analysis_subject.setdefault(
                    member, analysis_subject
                )
                if previous != analysis_subject:
                    failures.append(
                        {
                            "code": "alias_class_member_has_multiple_owners",
                            "subject_id": member,
                        }
                    )

    required_campaign_subjects: list[str] = []
    for subject_id in required_source_subjects:
        analysis_subject = member_to_analysis_subject.get(subject_id)
        if formal_campaign and analysis_subject is None:
            failures.append(
                {
                    "code": "adjudicated_subject_absent_from_formal_population",
                    "subject_id": subject_id,
                }
            )
            continue
        required_campaign_subjects.append(analysis_subject or subject_id)
    required_campaign_subjects = sorted(set(required_campaign_subjects))

    repo_root = context.repo_root.resolve(strict=False)
    marker_dir = context.marker_dir
    if marker_dir.is_symlink() or not marker_dir.is_dir():
        failures.append(
            {
                "code": "marker_directory_missing_or_unsafe",
                "path": str(marker_dir),
            }
        )
    marker_root = marker_dir.resolve(strict=False)

    unresolved_result_dir = context.result_dir
    result_root = unresolved_result_dir.resolve(strict=False)
    if (
        unresolved_result_dir.is_symlink()
        or not unresolved_result_dir.is_dir()
        or result_root.name != "results"
        or result_root.parent.name != context.campaign_id
        or result_root.parent.parent.name != "campaigns-v1"
    ):
        failures.append(
            {
                "code": "campaign_result_directory_not_content_addressed",
                "path": str(unresolved_result_dir),
                "campaign_id": context.campaign_id,
            }
        )

    receipt_campaign = refresh_runner.CampaignExecution(
        campaign_id=context.campaign_id,
        root=result_root.parent,
        result_dir=result_root,
        api_cache_dir=result_root.parent / "api-responses",
        derived_cache_root=result_root.parent / "derived-cache",
        source_snapshot_sha256=context.source_snapshot_sha256,
        contract_sha256=context.contract_sha256,
        litellm_transport_sha256=context.litellm_transport_sha256,
        litellm_transport=context.litellm_transport,
        analyzer_contract_sha256=context.analyzer_contract_sha256,
        signature_sha256=context.signature_sha256,
        alias_class_manifest_sha256=context.alias_class_manifest_sha256,
    )

    batch_key_counts = Counter(batch.key for batch in context.batches)
    for batch_key, count in sorted(batch_key_counts.items()):
        if count != 1:
            failures.append(
                {
                    "code": "duplicate_campaign_batch_key",
                    "batch": batch_key,
                    "count": count,
                }
            )

    all_plan_ids = [subject_id for batch in context.batches for subject_id in batch.ids]
    duplicate_plan_ids = {
        subject_id: count
        for subject_id, count in Counter(all_plan_ids).items()
        if count != 1
    }
    if duplicate_plan_ids:
        failures.append(
            {
                "code": "campaign_plan_subjects_not_exactly_once",
                "subjects": dict(list(sorted(duplicate_plan_ids.items()))[:20]),
            }
        )
    all_plan_class_ids = [
        class_id for batch in context.batches for class_id in batch.class_ids
    ]
    if formal_campaign and (
        any(len(batch.class_ids) != len(batch.ids) for batch in context.batches)
        or len(all_plan_class_ids) != len(set(all_plan_class_ids))
        or set(all_plan_class_ids) != scheduled_class_ids
    ):
        failures.append(
            {
                "code": "campaign_plan_alias_classes_not_exactly_once",
                "plan_class_count": len(all_plan_class_ids),
                "scheduled_class_count": len(scheduled_class_ids),
            }
        )
    expected_result_ids = set(all_plan_ids)
    plan_proof = context.incremental_plan_proof
    plan_ids_bytes = (
        ("\n".join(sorted(all_plan_ids)) + "\n").encode()
        if all_plan_ids
        else b""
    )
    required_true = (
        "candidate_union_exact",
        "plan_exactly_matches_candidate",
        "frozen_local_sources",
    )
    digest_fields = (
        "source_delta_sha256",
        "source_delta_integrity_payload_sha256",
        "input_snapshot_sha256",
        "result_cache_inventory_manifest_sha256",
        "candidate_sha256",
        "plan_subject_ids_sha256",
        "alias_class_manifest_sha256",
        "analyzer_contract_sha256",
        "signature_sha256",
    )
    count_fields = (
        "production_discovered_id_count",
        "cache_covered_discovered_id_count",
        "uncached_discovered_id_count",
        "candidate_id_count",
        "plan_subject_id_count",
        "source_alias_class_count",
        "scheduled_alias_class_count",
    )
    plan_proof_valid = isinstance(plan_proof, dict)
    if plan_proof_valid:
        counts = {field: plan_proof.get(field) for field in count_fields}
        expected_scope = (
            "formal_current_source_alias_class_plan"
            if formal_campaign
            else "incremental_current_source_candidate_plan"
        )
        plan_proof_valid = (
            plan_proof.get("schema_version") == 2
            and plan_proof.get("scope") == expected_scope
            and plan_proof.get("campaign_mode") == context.campaign_mode
            and plan_proof.get("population_policy") == context.population_policy
            and plan_proof.get("formal_release_eligible") is formal_campaign
            and plan_proof.get("source_delta_schema_version")
            == refresh_runner.SOURCE_DELTA_SCHEMA_VERSION
            and all(plan_proof.get(field) is True for field in required_true)
            and plan_proof.get("network_advisory_api_included") is False
            and all(
                isinstance(plan_proof.get(field), str)
                and re.fullmatch(r"[0-9a-f]{64}", plan_proof[field])
                for field in digest_fields
            )
            and all(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in counts.values()
            )
            and counts["candidate_id_count"] == len(expected_result_ids)
            and counts["plan_subject_id_count"] == len(all_plan_ids)
            and counts["candidate_id_count"] == counts["plan_subject_id_count"]
            and counts["production_discovered_id_count"]
            == counts["cache_covered_discovered_id_count"]
            + counts["uncached_discovered_id_count"]
            and plan_proof.get("plan_subject_ids_sha256")
            == hashlib.sha256(plan_ids_bytes).hexdigest()
            and plan_proof.get("alias_class_manifest_sha256")
            == context.alias_class_manifest_sha256
            and plan_proof.get("analyzer_contract_sha256")
            == context.analyzer_contract_sha256
            and plan_proof.get("signature_sha256") == context.signature_sha256
            and (
                not formal_campaign
                or (
                    plan_proof.get("historical_cache_suppresses_current_classes")
                    is False
                    and plan_proof.get(
                        "formal_current_epoch_stage_receipt_required"
                    )
                    is True
                    and plan_proof.get("plan_alias_classes_exactly_once") is True
                    and counts["scheduled_alias_class_count"]
                    == len(expected_result_ids)
                    and len(scheduled_class_ids) == len(expected_result_ids)
                )
            )
            and isinstance(plan_proof.get("boundary"), str)
            and bool(plan_proof["boundary"])
        )
    if not plan_proof_valid:
        failures.append(
            {
                "code": "campaign_plan_completeness_proof_invalid",
                "actual": plan_proof,
            }
        )

    owners: dict[str, list[FixedCampaignBatch]] = {
        subject_id: [] for subject_id in required_campaign_subjects
    }
    for batch in context.batches:
        expected_command = tuple(
            refresh_runner.build_command(
                refresh_runner.BatchSpec(
                    key=batch.key,
                    path=batch.path,
                    kind="fixed_contract_proof",
                    ids=batch.ids,
                    repos=frozenset(),
                ),
                phase="verification",
            )
        )
        if batch.command != expected_command:
            failures.append(
                {
                    "code": "campaign_command_contract_mismatch",
                    "batch": batch.key,
                    "actual": list(batch.command),
                    "expected": list(expected_command),
                }
            )
        for subject_id in batch.ids:
            if subject_id in owners:
                owners[subject_id].append(batch)

    relevant_batches: dict[str, FixedCampaignBatch] = {}
    mapped_campaign_subjects: set[str] = set()
    for subject_id in required_campaign_subjects:
        subject_owners = owners[subject_id]
        if not subject_owners:
            failures.append({"code": "missing_subject_batch", "subject_id": subject_id})
            continue
        if len(subject_owners) != 1:
            failures.append(
                {
                    "code": "ambiguous_subject_batch",
                    "subject_id": subject_id,
                    "batches": sorted(batch.key for batch in subject_owners),
                }
            )
        else:
            mapped_campaign_subjects.add(subject_id)
        for batch in subject_owners:
            relevant_batches.setdefault(batch.key, batch)

    if result_root.is_dir():
        actual_result_ids: set[str] = set()
        try:
            result_paths = list(result_root.iterdir())
        except OSError as exc:
            failures.append(
                {"code": "campaign_result_inventory_unreadable", "detail": str(exc)}
            )
            result_paths = []
        for path in result_paths:
            if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                failures.append(
                    {
                        "code": "campaign_result_inventory_entry_invalid",
                        "path": str(path),
                    }
                )
                continue
            actual_result_ids.add(path.stem)
        missing_results = sorted(expected_result_ids - actual_result_ids)
        unexpected_results = sorted(actual_result_ids - expected_result_ids)
        if missing_results:
            failures.append(
                {
                    "code": "campaign_results_incomplete",
                    "count": len(missing_results),
                    "subjects": missing_results[:20],
                }
            )
        if unexpected_results:
            failures.append(
                {
                    "code": "campaign_results_contain_unplanned_subjects",
                    "count": len(unexpected_results),
                    "subjects": unexpected_results[:20],
                }
            )

    marker_records: dict[str, dict[str, Any]] = {}
    result_records: dict[str, dict[str, Any]] = {}
    subject_proofs: list[dict[str, Any]] = []
    for batch in sorted(context.batches, key=lambda item: item.key):
        if not batch.key or Path(batch.key).name != batch.key:
            failures.append({"code": "unsafe_batch_key", "batch": batch.key})
            continue
        batch_path = batch.path
        batch_hash: str | None = None
        expected_batch_file: str | None = None
        if batch_path.is_symlink() or not batch_path.is_file():
            failures.append(
                {
                    "code": "batch_file_missing_or_unsafe",
                    "batch": batch.key,
                    "path": str(batch_path),
                }
            )
        else:
            resolved_batch = batch_path.resolve()
            try:
                expected_batch_file = resolved_batch.relative_to(repo_root).as_posix()
            except ValueError:
                failures.append(
                    {
                        "code": "batch_file_outside_repo",
                        "batch": batch.key,
                        "path": str(resolved_batch),
                    }
                )
            try:
                lines = tuple(
                    line.strip()
                    for line in resolved_batch.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                )
            except (OSError, UnicodeError) as exc:
                failures.append(
                    {
                        "code": "batch_file_unreadable",
                        "batch": batch.key,
                        "detail": str(exc),
                    }
                )
            else:
                if lines != batch.ids:
                    failures.append({"code": "batch_ids_mismatch", "batch": batch.key})
            try:
                batch_hash = _file_sha256(resolved_batch)
            except ValueError as exc:
                failures.append(
                    {
                        "code": "batch_hash_unavailable",
                        "batch": batch.key,
                        "detail": str(exc),
                    }
                )

        unresolved_marker_path = marker_root / f"{batch.key}.json"
        if unresolved_marker_path.is_symlink():
            failures.append({"code": "marker_symlink_unsafe", "batch": batch.key})
            continue
        marker_path = unresolved_marker_path.resolve(strict=False)
        if marker_path.parent != marker_root:
            failures.append({"code": "marker_path_escape", "batch": batch.key})
            continue
        try:
            marker, marker_sha256 = _stable_json_file(
                marker_path, "refresh completion marker"
            )
        except ValueError as exc:
            failures.append(
                {
                    "code": "missing_or_invalid_marker",
                    "batch": batch.key,
                    "detail": str(exc),
                }
            )
            continue

        def mismatch(code: str, field: str, expected_value: object) -> None:
            if marker.get(field) != expected_value:
                failures.append(
                    {
                        "code": code,
                        "batch": batch.key,
                        "field": field,
                        "actual": marker.get(field),
                        "expected": expected_value,
                    }
                )

        mismatch(
            "marker_schema_mismatch",
            "schema_version",
            refresh_runner.MARKER_SCHEMA_VERSION,
        )
        mismatch("marker_batch_mismatch", "batch", batch.key)
        if expected_batch_file is not None:
            mismatch("marker_batch_file_mismatch", "batch_file", expected_batch_file)
        if batch_hash is not None:
            mismatch("marker_batch_hash_mismatch", "batch_sha256", batch_hash)
        mismatch("marker_contract_mismatch", "contract_sha256", context.contract_sha256)
        mismatch(
            "marker_analyzer_contract_mismatch",
            "analyzer_contract_sha256",
            context.analyzer_contract_sha256,
        )
        mismatch(
            "marker_signature_mismatch",
            "signature_sha256",
            context.signature_sha256,
        )
        mismatch(
            "marker_alias_class_manifest_mismatch",
            "alias_class_manifest_sha256",
            context.alias_class_manifest_sha256,
        )
        mismatch(
            "marker_source_mismatch",
            "source_snapshot_sha256",
            context.source_snapshot_sha256,
        )
        mismatch(
            "marker_source_details_mismatch", "source_snapshot", context.source_snapshot
        )
        marker_source = marker.get("source_snapshot")
        if isinstance(marker_source, dict):
            marker_source_digest = _runner_source_snapshot_sha256(marker_source)
            if marker_source_digest != marker.get("source_snapshot_sha256"):
                failures.append(
                    {
                        "code": "marker_source_digest_invalid",
                        "batch": batch.key,
                        "computed": marker_source_digest,
                        "declared": marker.get("source_snapshot_sha256"),
                    }
                )
        else:
            failures.append(
                {"code": "marker_source_details_invalid", "batch": batch.key}
            )
        mismatch("marker_command_mismatch", "command", list(batch.command))
        mismatch("marker_model_mismatch", "model", _FIXED_CAMPAIGN_MODEL)
        mismatch(
            "marker_reasoning_effort_mismatch",
            "reasoning_effort",
            _FIXED_CAMPAIGN_REASONING_EFFORT,
        )
        mismatch("marker_workers_mismatch", "workers", context.workers)
        mismatch("marker_exit_code_invalid", "exit_code", 0)
        mismatch("marker_campaign_id_mismatch", "campaign_id", context.campaign_id)
        mismatch(
            "marker_campaign_result_dir_mismatch",
            "campaign_result_dir",
            str(context.result_dir),
        )
        mismatch(
            "marker_campaign_api_cache_dir_mismatch",
            "campaign_api_cache_dir",
            str(result_root.parent / "api-responses"),
        )
        mismatch(
            "marker_campaign_derived_cache_root_mismatch",
            "campaign_derived_cache_root",
            str(result_root.parent / "derived-cache"),
        )
        mismatch(
            "marker_litellm_transport_digest_mismatch",
            "litellm_transport_sha256",
            context.litellm_transport_sha256,
        )
        mismatch(
            "marker_litellm_transport_mismatch",
            "litellm_transport",
            context.litellm_transport,
        )
        mismatch(
            "marker_batch_timeout_mismatch",
            "batch_timeout_seconds",
            context.batch_timeout_seconds,
        )
        unique_count = len(set(batch.ids))
        mismatch("marker_id_count_mismatch", "id_line_count", len(batch.ids))
        mismatch("marker_unique_count_mismatch", "unique_id_count", unique_count)

        started_at_ns = _iso_timestamp_ns(marker.get("started_at"))
        completed_at_ns = _iso_timestamp_ns(marker.get("completed_at"))
        if (
            started_at_ns is None
            or completed_at_ns is None
            or completed_at_ns < started_at_ns
        ):
            failures.append({"code": "marker_time_window_invalid", "batch": batch.key})

        batch_manifest: list[dict[str, Any]] = []
        computed_class_receipts: list[dict[str, Any]] = []
        if formal_campaign:
            for subject_id, class_id in zip(batch.ids, batch.class_ids, strict=False):
                class_record = class_records_by_subject.get(subject_id)
                if class_record is None or class_record.get("class_id") != class_id:
                    failures.append(
                        {
                            "code": "batch_alias_class_binding_mismatch",
                            "batch": batch.key,
                            "subject_id": subject_id,
                            "class_id": class_id,
                        }
                    )
        for subject_id in dict.fromkeys(batch.ids):
            try:
                record = _stable_campaign_result(result_root, subject_id)
            except ValueError as exc:
                failures.append(
                    {
                        "code": "missing_or_invalid_campaign_result",
                        "batch": batch.key,
                        "subject_id": subject_id,
                        "detail": str(exc),
                    }
                )
                continue
            result_records[subject_id] = record
            batch_manifest.append(
                {
                    "subject_id": subject_id,
                    "size_bytes": record["size_bytes"],
                    "sha256": record["sha256"],
                }
            )
            payload = record["payload"]
            terminal_problem = refresh_runner._terminal_result_problem(payload)
            if terminal_problem is not None:
                failures.append(
                    {
                        "code": "result_not_terminal",
                        "subject_id": subject_id,
                        "batch": batch.key,
                        "detail": terminal_problem,
                    }
                )
            try:
                parsed_result = CveAnalysisResult.from_dict(payload)
                parsed_result.rebuild_signals()
            except (KeyError, TypeError, ValueError) as exc:
                failures.append(
                    {
                        "code": "campaign_result_domain_schema_invalid",
                        "subject_id": subject_id,
                        "batch": batch.key,
                        "detail": str(exc),
                    }
                )
            else:
                failures.extend(
                    _campaign_receipt_failures(
                        payload=payload,
                        result=parsed_result,
                        subject_id=subject_id,
                        batch_key=batch.key,
                        marker_started_at=marker.get("started_at"),
                        marker_started_at_ns=started_at_ns,
                        marker_completed_at_ns=completed_at_ns,
                        result_mtime_ns=record["mtime_ns"],
                        context=context,
                    )
                )
            if formal_campaign:
                class_record = class_records_by_subject.get(subject_id)
                if class_record is None:
                    failures.append(
                        {
                            "code": "result_alias_class_binding_missing",
                            "batch": batch.key,
                            "subject_id": subject_id,
                        }
                    )
                else:
                    stage_problem, class_receipt = (
                        refresh_runner._analysis_stage_receipt_proof(
                            payload,
                            class_record=class_record,
                            campaign=receipt_campaign,
                            result_sha256=record["sha256"],
                        )
                    )
                    if stage_problem is not None or class_receipt is None:
                        failures.append(
                            {
                                "code": "result_analysis_stage_receipt_invalid",
                                "batch": batch.key,
                                "subject_id": subject_id,
                                "detail": stage_problem,
                            }
                        )
                    else:
                        computed_class_receipts.append(class_receipt)
            for provenance in _extract_llm_provenance(payload):
                model = provenance["model"]
                if model not in {
                    _FIXED_SCREENING_MODEL,
                    f"osv+{_FIXED_SCREENING_MODEL}",
                    _FIXED_CAMPAIGN_MODEL,
                    f"osv+{_FIXED_CAMPAIGN_MODEL}",
                }:
                    failures.append(
                        {
                            "code": "result_llm_model_mismatch",
                            "subject_id": subject_id,
                            "batch": batch.key,
                            "json_path": provenance["json_path"],
                            "actual": model,
                            "expected": _FIXED_CAMPAIGN_MODEL,
                        }
                    )
                if (
                    provenance["json_path"].endswith(".deep_verification")
                    and provenance.get("reasoning_effort")
                    != _FIXED_CAMPAIGN_REASONING_EFFORT
                ):
                    failures.append(
                        {
                            "code": "result_deep_verification_effort_mismatch",
                            "subject_id": subject_id,
                            "batch": batch.key,
                            "json_path": provenance["json_path"],
                            "actual": provenance.get("reasoning_effort"),
                            "expected": _FIXED_CAMPAIGN_REASONING_EFFORT,
                        }
                    )
            if (
                isinstance(started_at_ns, int)
                and isinstance(completed_at_ns, int)
                and not started_at_ns <= record["mtime_ns"] <= completed_at_ns
            ):
                failures.append(
                    {
                        "code": "result_mtime_outside_marker_window",
                        "subject_id": subject_id,
                        "batch": batch.key,
                        "result_mtime_ns": record["mtime_ns"],
                        "marker_started_at_ns": started_at_ns,
                        "marker_completed_at_ns": completed_at_ns,
                    }
                )
            if subject_id in required_campaign_subjects:
                subject_proofs.append(
                    {
                        "subject_id": subject_id,
                        "batch": batch.key,
                        "marker_sha256": marker_sha256,
                        "result_sha256": record["sha256"],
                        "result_mtime_ns": record["mtime_ns"],
                        "marker_started_at_ns": started_at_ns,
                        "marker_completed_at_ns": completed_at_ns,
                        "terminal_validation": terminal_problem or "passed",
                    }
                )

        batch_manifest.sort(key=lambda item: item["subject_id"])
        computed_manifest_sha256 = _runner_result_manifest_sha256(batch_manifest)
        result_validation = marker.get("result_validation")
        required_validation_keys = {
            "result_count",
            "terminal_count",
            "result_manifest_sha256",
        }
        if formal_campaign:
            required_validation_keys.update(
                {
                    "class_receipt_count",
                    "class_receipts_sha256",
                    "class_receipts",
                    "alias_classes_exactly_once",
                }
            )
        if (
            not isinstance(result_validation, dict)
            or set(result_validation) != required_validation_keys
        ):
            failures.append(
                {
                    "code": "marker_result_validation_mismatch",
                    "batch": batch.key,
                    "actual": result_validation,
                    "expected_keys": sorted(required_validation_keys),
                }
            )
        else:
            if (
                result_validation.get("result_count") != unique_count
                or result_validation.get("terminal_count") != unique_count
            ):
                failures.append(
                    {
                        "code": "marker_result_validation_mismatch",
                        "batch": batch.key,
                        "actual": result_validation,
                        "expected_result_count": unique_count,
                    }
                )
            if (
                result_validation.get("result_manifest_sha256")
                != computed_manifest_sha256
            ):
                failures.append(
                    {
                        "code": "marker_result_manifest_mismatch",
                        "batch": batch.key,
                        "actual": result_validation.get("result_manifest_sha256"),
                        "computed": computed_manifest_sha256,
                    }
                )
            if formal_campaign:
                computed_class_receipts.sort(key=lambda item: item["class_id"])
                class_receipts_sha256 = hashlib.sha256(
                    refresh_runner._canonical_json_bytes(computed_class_receipts)
                ).hexdigest()
                if (
                    result_validation.get("class_receipt_count") != unique_count
                    or result_validation.get("class_receipts")
                    != computed_class_receipts
                    or result_validation.get("class_receipts_sha256")
                    != class_receipts_sha256
                    or result_validation.get("alias_classes_exactly_once") is not True
                ):
                    failures.append(
                        {
                            "code": "marker_class_receipt_proof_mismatch",
                            "batch": batch.key,
                        }
                    )

        marker_records[batch.key] = {
            "path": str(marker_path),
            "marker_sha256": marker_sha256,
            "batch_sha256": batch_hash,
            "command_sha256": canonical_sha256(list(batch.command)),
            "result_manifest_sha256": computed_manifest_sha256,
            "class_receipts_sha256": (
                result_validation.get("class_receipts_sha256")
                if isinstance(result_validation, dict)
                else None
            ),
            "started_at_ns": started_at_ns,
            "completed_at_ns": completed_at_ns,
        }

    inputs_by_subject = {
        cache_input.subject_id: cache_input
        for class_inputs in snapshot_inputs.values()
        for cache_input in class_inputs
    }
    for subject_id in required_campaign_subjects:
        if subject_id not in inputs_by_subject:
            failures.append(
                {"code": "missing_subject_result", "subject_id": subject_id}
            )
        staged_record = result_records.get(subject_id)
        cache_input = inputs_by_subject.get(subject_id)
        if staged_record is not None and cache_input is not None:
            if (
                cache_input.path != staged_record["path"]
                or cache_input.file_sha256 != staged_record["sha256"]
            ):
                failures.append(
                    {
                        "code": "campaign_metric_input_not_staged_result",
                        "subject_id": subject_id,
                        "actual_path": str(cache_input.path),
                        "expected_path": str(staged_record["path"]),
                    }
                )

    failures.sort(key=canonical_sha256)
    subject_proofs.sort(key=lambda proof: proof["subject_id"])
    marker_proofs = [
        {"batch": batch_key, **marker_records[batch_key]}
        for batch_key in sorted(marker_records)
    ]
    failure_counts = dict(
        sorted(
            Counter(str(failure.get("code", "unknown")) for failure in failures).items()
        )
    )
    complete = not failures and len(marker_records) == len(context.batches)
    mapped_source_subject_count = sum(
        1
        for subject_id in required_source_subjects
        if (member_to_analysis_subject.get(subject_id) or subject_id)
        in mapped_campaign_subjects
    )
    return {
        "complete": complete,
        "campaign_mode": context.campaign_mode,
        "population_policy": context.population_policy,
        "formal_population_complete": complete and formal_campaign,
        "incremental_plan_complete": complete and not formal_campaign,
        "full_incremental_plan_campaign_complete": complete and not formal_campaign,
        "proof_scope": context.incremental_plan_proof.get("scope"),
        "population_uniform_luna_max_proof": False,
        "incremental_plan_proof": context.incremental_plan_proof,
        "required_subject_count": len(required_source_subjects),
        "required_campaign_subject_count": len(required_campaign_subjects),
        "mapped_subject_count": mapped_source_subject_count,
        "campaign_subject_count": len(expected_result_ids),
        "campaign_batch_count": len(context.batches),
        "completed_marker_count": len(marker_records),
        "relevant_marker_count": len(relevant_batches),
        "expected_contract": expected,
        "failure_counts": failure_counts,
        "failures": failures,
        "marker_proofs": marker_proofs,
        "subject_proofs": subject_proofs,
    }


def _outcome(label: str, predicted_positive: bool) -> str:
    if label == "INCONCLUSIVE":
        return "excluded_inconclusive"
    if label == "AI_CAUSAL":
        return "tp" if predicted_positive else "fn"
    return "fp" if predicted_positive else "tn"


def _state_outcome(label: str, prediction: str) -> str:
    """Map a three-state detector result without treating unknown work as negative."""
    if prediction == "incomplete":
        return "excluded_incomplete"
    if prediction not in {"positive", "negative"}:
        raise ValueError(f"unsupported detector prediction state: {prediction!r}")
    return _outcome(label, prediction == "positive")


def _metric_rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _metrics(
    prediction_manifest: list[dict[str, Any]],
    *,
    prediction_key: str,
    outcome_key: str,
) -> dict[str, Any]:
    confusion_ids: dict[str, list[str]] = {key: [] for key in ("tp", "fp", "fn", "tn")}
    for row in prediction_manifest:
        outcome = row[outcome_key]
        if outcome in confusion_ids:
            confusion_ids[outcome].append(row["canonical_id"])
    counts = {key: len(confusion_ids[key]) for key in ("tp", "fp", "fn", "tn")}
    tp = counts["tp"]
    fp = counts["fp"]
    fn = counts["fn"]
    tn = counts["tn"]
    conclusive = tp + fp + fn + tn
    precision = _metric_rate(tp, tp + fp)
    recall = _metric_rate(tp, tp + fn)
    precision_lower_bound = clopper_pearson_lower_bound(tp, tp + fp)
    recall_lower_bound = clopper_pearson_lower_bound(tp, tp + fn)
    return {
        "unit": "advisory_alias_equivalence_class",
        "prediction_field": prediction_key,
        "confusion_counts": counts,
        "confusion_ids": confusion_ids,
        "precision": precision,
        "precision_one_sided_95pct_lower_bound": precision_lower_bound,
        "recall": recall,
        "recall_one_sided_95pct_lower_bound": recall_lower_bound,
        "confidence_bound_method": "exact_clopper_pearson",
        "specificity": _metric_rate(tn, tn + fp),
        "accuracy": _metric_rate(tp + tn, conclusive),
        "f1": (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else None
        ),
        "conclusive_sample_size": conclusive,
        "inconclusive_excluded": sum(
            row[outcome_key] == "excluded_inconclusive" for row in prediction_manifest
        ),
        "incomplete_excluded": sum(
            row[outcome_key] == "excluded_incomplete" for row in prediction_manifest
        ),
    }


def _inventory_prediction_manifest(
    corpus: tuple[CorpusEntry, ...],
    inventory: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Project labels through inventory detector_state, independent of publication."""
    validate_inventory_payload(dict(inventory))
    rows = inventory["rows"]
    manifest: list[dict[str, Any]] = []
    for entry in corpus:
        subjects = set(entry.subject_ids)
        matches = [row for row in rows if subjects & set(row["member_ids"])]
        if len(matches) != 1:
            raise ValueError(
                f"detector inventory maps {entry.canonical_id} to {len(matches)} classes"
            )
        row = matches[0]
        if row["coverage_status"] != "complete" or row["detector_state"] in {
            "incomplete",
            "not_evaluated",
            "exhausted",
        }:
            prediction = "incomplete"
        elif row["detector_state"] == "positive":
            prediction = "positive"
        else:
            prediction = "negative"
        stage_predictions = row.get("stage_predictions")
        if not isinstance(stage_predictions, dict):
            # Schema-v2 inventories produced before stage telemetry existed
            # remain readable. They cannot recover intermediate distinctions,
            # so every stage is explicitly projected from the legacy terminal
            # state instead of invalidating the durable cache.
            terminal = (
                "incomplete"
                if prediction == "incomplete"
                else "positive" if prediction == "positive" else "negative"
            )
            stage_predictions = {
                "source_matcher": terminal,
                "screening": terminal,
                "verification": terminal,
                "final_publication": (
                    "positive"
                    if row["publication_state"] == "published"
                    else terminal
                ),
            }
        manifest.append(
            {
                "canonical_id": entry.canonical_id,
                "label": entry.label,
                "subject_ids": list(entry.subject_ids),
                "inventory_class_id": row["class_id"],
                "inventory_detector_prediction": prediction,
                "inventory_detector_outcome": _state_outcome(entry.label, prediction),
                "coverage_status": row["coverage_status"],
                "detector_state": row["detector_state"],
                "recall_stratum": row["recall_stratum"],
                "stage_predictions": dict(stage_predictions),
                "stage_outcomes": {
                    stage: _state_outcome(entry.label, prediction)
                    for stage, prediction in stage_predictions.items()
                },
            }
        )
    return manifest


def _code_provenance() -> dict[str, Any]:
    relative_paths = (
        Path("scripts/evaluate_detector_quality.py"),
        Path("scripts/evaluate_publication_quality.py"),
        Path("scripts/run_data_refresh.py"),
        Path("scripts/web_data/filters.py"),
        Path("scripts/web_data/loader.py"),
        Path("scripts/web_data/writer.py"),
        Path("cve-analyzer/src/cve_analyzer/ai_signatures.py"),
        Path("cve-analyzer/src/cve_analyzer/models.py"),
        Path("cve-analyzer/src/cve_analyzer/pipeline.py"),
        Path("cve-analyzer/src/cve_analyzer/pr_enrichment.py"),
        Path("cve-analyzer/src/cve_analyzer/verifier/coding_agent.py"),
    )
    files = [
        {"path": path.as_posix(), "sha256": _file_sha256(_REPO_ROOT / path)}
        for path in relative_paths
    ]
    return {
        "algorithm": _ALGORITHM,
        "scope": "current_projection_evaluator_and_campaign_proof_code",
        "files": files,
        "manifest_sha256": canonical_sha256(files),
    }


def _corpus_manifest(corpus: tuple[CorpusEntry, ...]) -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []
    for entry in corpus:
        row: dict[str, Any] = {
            "canonical_id": entry.canonical_id,
            "label": entry.label,
            "subject_ids": list(entry.subject_ids),
        }
        if entry.source is not None:
            row["source"] = entry.source
        if entry.confidence is not None:
            row["confidence"] = entry.confidence
        manifest.append(row)
    return manifest


def _snapshot_input_manifest(cache_input: CachedPipelineInput) -> dict[str, Any]:
    status = "ok"
    if cache_input.infrastructure_categories:
        status = "infrastructure_error"
    elif cache_input.unresolved_reasons:
        status = "unresolved"
    return {
        "subject_id": cache_input.subject_id,
        # Keep the hashed prediction manifest portable across cache roots.
        "path": cache_input.path.name,
        "sha256": cache_input.file_sha256,
        "stored_result_prediction": (
            "positive" if cache_input.predicted_positive else "negative"
        ),
        "stored_result_reason": cache_input.prediction_reason,
        "execution_status": status,
        "infrastructure_categories": list(cache_input.infrastructure_categories),
        "unresolved_reasons": list(cache_input.unresolved_reasons),
        "llm_provenance": list(cache_input.llm_provenance),
    }


def build_report(
    *,
    adjudications_path: Path,
    cache_dir: Path,
    alias_map: dict[str, set[str]],
    published_ids: set[str],
    publication_provenance: dict[str, Any],
    alias_source_provenance: dict[str, Any] | None = None,
    fixed_campaign_context: FixedCampaignProofContext | None = None,
    fixed_campaign_setup_failures: tuple[dict[str, Any], ...] = (),
    detector_inventory: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one deterministic cached-snapshot/publication quality report."""
    adjudications_path = Path(adjudications_path)
    cache_dir = Path(cache_dir)
    if adjudications_path.is_symlink() or not adjudications_path.is_file():
        raise ValueError(
            f"Adjudication input is missing or unsafe: {adjudications_path}"
        )
    if not isinstance(published_ids, set):
        raise ValueError("published_ids must be a set of non-empty strings")
    for public_id in published_ids:
        _validate_public_id(public_id, "Published entry ID")

    corpus, adjudications_sha256 = _load_corpus(adjudications_path, alias_map)
    mixed_snapshot_inputs = _load_class_snapshot_inputs(cache_dir, corpus)
    campaign_snapshot_inputs: dict[str, tuple[CachedPipelineInput, ...]] = {}
    campaign_setup_failures = list(fixed_campaign_setup_failures)
    if fixed_campaign_context is not None:
        try:
            campaign_snapshot_inputs = _load_class_snapshot_inputs(
                fixed_campaign_context.result_dir,
                corpus,
            )
        except ValueError as exc:
            campaign_setup_failures.append(
                {
                    "code": "campaign_metric_inputs_invalid",
                    "detail": str(exc),
                }
            )
    campaign_proof = _fixed_contract_campaign_proof(
        corpus,
        campaign_snapshot_inputs,
        fixed_campaign_context,
        tuple(campaign_setup_failures),
    )
    fixed_campaign_complete = campaign_proof["complete"] is True
    snapshot_inputs = (
        campaign_snapshot_inputs if fixed_campaign_complete else mixed_snapshot_inputs
    )
    detector_input_dir = (
        fixed_campaign_context.result_dir
        if fixed_campaign_complete and fixed_campaign_context is not None
        else cache_dir
    )
    detector_prediction_key = (
        "fixed_contract_campaign_prediction"
        if fixed_campaign_complete
        else "cached_pipeline_snapshot_prediction"
    )
    detector_outcome_key = (
        "fixed_contract_campaign_outcome"
        if fixed_campaign_complete
        else "cached_pipeline_snapshot_outcome"
    )
    detector_metrics_key = (
        "fixed_contract_campaign_metrics"
        if fixed_campaign_complete
        else "cached_pipeline_snapshot_metrics"
    )
    detector_inputs_key = (
        "fixed_contract_campaign_results"
        if fixed_campaign_complete
        else "cached_pipeline_snapshot"
    )
    detector_result_kind = (
        "fixed_contract_campaign_results"
        if fixed_campaign_complete
        else "mixed_version_cached_pipeline_results"
    )
    corpus_manifest = _corpus_manifest(corpus)

    prediction_manifest: list[dict[str, Any]] = []
    infrastructure_ids: list[str] = []
    unresolved_ids: list[str] = []
    inconclusive_ids: list[str] = []
    disagreement_ids: list[str] = []
    infrastructure_category_counts: Counter[str] = Counter()
    adjudicated_subject_ids: set[str] = set()

    for entry in corpus:
        class_inputs = snapshot_inputs[entry.canonical_id]
        snapshot_positive = any(
            cache_input.predicted_positive for cache_input in class_inputs
        )
        published_subjects = sorted(set(entry.subject_ids) & published_ids)
        curated_positive = bool(published_subjects)
        input_predictions = {
            cache_input.predicted_positive for cache_input in class_inputs
        }
        disagreement = len(input_predictions) > 1
        class_infrastructure = sorted(
            {
                category
                for cache_input in class_inputs
                for category in cache_input.infrastructure_categories
            }
        )
        class_unresolved = sorted(
            {
                reason
                for cache_input in class_inputs
                for reason in cache_input.unresolved_reasons
            }
        )
        class_terminal_problems = sorted(
            {
                str(cache_input.terminal_problem)
                for cache_input in class_inputs
                if cache_input.terminal_problem is not None
            }
        )
        if snapshot_positive:
            detector_prediction = "positive"
        elif class_infrastructure or class_unresolved or class_terminal_problems:
            detector_prediction = "incomplete"
        else:
            detector_prediction = "negative"
        if class_infrastructure:
            infrastructure_ids.append(entry.canonical_id)
            infrastructure_category_counts.update(class_infrastructure)
        if class_unresolved:
            unresolved_ids.append(entry.canonical_id)
        if entry.label == "INCONCLUSIVE":
            inconclusive_ids.append(entry.canonical_id)
        if disagreement:
            disagreement_ids.append(entry.canonical_id)
        adjudicated_subject_ids.update(entry.subject_ids)

        prediction_manifest.append(
            {
                "canonical_id": entry.canonical_id,
                "label": entry.label,
                "subject_ids": list(entry.subject_ids),
                detector_prediction_key: detector_prediction,
                detector_outcome_key: _state_outcome(
                    entry.label,
                    detector_prediction,
                ),
                "curated_publication_prediction": (
                    "positive" if curated_positive else "negative"
                ),
                "curated_publication_outcome": _outcome(entry.label, curated_positive),
                "published_subject_ids": published_subjects,
                "cached_pipeline_inputs": [
                    _snapshot_input_manifest(cache_input)
                    for cache_input in class_inputs
                ],
                "cache_subject_ids_missing": sorted(
                    set(entry.subject_ids)
                    - {cache_input.subject_id for cache_input in class_inputs}
                ),
                "alias_prediction_disagreement": disagreement,
                "infrastructure_categories": class_infrastructure,
                "unresolved_reasons": class_unresolved,
                "terminal_problems": class_terminal_problems,
            }
        )

    snapshot_cache_manifest = [
        {
            "canonical_id": row["canonical_id"],
            "inputs": [
                {
                    "subject_id": item["subject_id"],
                    "path": item["path"],
                    "sha256": item["sha256"],
                }
                for item in row["cached_pipeline_inputs"]
            ],
        }
        for row in prediction_manifest
    ]
    relevant_alias_manifest = [
        {
            "canonical_id": entry.canonical_id,
            "subject_ids": list(entry.subject_ids),
        }
        for entry in corpus
    ]
    unadjudicated_published = sorted(published_ids - adjudicated_subject_ids)
    code_provenance = _code_provenance()
    code_provenance["generation_contract_status"] = (
        "fixed_current_contract" if fixed_campaign_complete else "mixed_or_unknown"
    )
    inventory_manifest = (
        _inventory_prediction_manifest(corpus, detector_inventory)
        if detector_inventory is not None
        else None
    )
    inventory_complete = bool(
        detector_inventory is None
        or (
            detector_inventory.get("campaign_mode") == "formal"
            and detector_inventory.get("complete") is True
            and all(
                row["coverage_status"] == "complete"
                for row in inventory_manifest or []
            )
        )
    )
    report: dict[str, Any] = {
        "schema_version": 3,
        "evaluation_kind": (
            "frozen_adjudication_fixed_contract_campaign_vs_curated_publication"
            if fixed_campaign_complete
            else "frozen_adjudication_mixed_version_cached_pipeline_snapshot_vs_curated_publication"
        ),
        "evaluation_complete": (
            not infrastructure_ids
            and not unresolved_ids
            and not unadjudicated_published
            and fixed_campaign_complete
            and inventory_complete
        ),
        "methodology": {
            "result_kind": detector_result_kind,
            "signature_replay": False,
            "signature_generation": (
                "fixed_runner_contract"
                if fixed_campaign_complete
                else "stored_mixed_version_results"
            ),
            "projection_predicate": "current_hashed_code",
        },
        "fixed_contract_campaign_proof": campaign_proof,
        "corpus_manifest": corpus_manifest,
        "corpus_manifest_sha256": canonical_sha256(corpus_manifest),
        "prediction_manifest": prediction_manifest,
        "prediction_manifest_sha256": canonical_sha256(prediction_manifest),
        detector_metrics_key: _metrics(
            prediction_manifest,
            prediction_key=detector_prediction_key,
            outcome_key=detector_outcome_key,
        ),
        "curated_publication_metrics": _metrics(
            prediction_manifest,
            prediction_key="curated_publication_prediction",
            outcome_key="curated_publication_outcome",
        ),
        "strata": {
            "adjudication_inconclusive": {
                "count": len(inconclusive_ids),
                "ids": inconclusive_ids,
            },
            "detector_unresolved": {
                "count": len(unresolved_ids),
                "ids": unresolved_ids,
            },
            "infrastructure_error": {
                "count": len(infrastructure_ids),
                "ids": infrastructure_ids,
                "categories": dict(sorted(infrastructure_category_counts.items())),
            },
            "alias_prediction_disagreement": {
                "count": len(disagreement_ids),
                "ids": disagreement_ids,
            },
            "publication_outside_corpus": {
                "count": len(unadjudicated_published),
                "ids": unadjudicated_published,
            },
        },
        "input_provenance": {
            "adjudications": {
                "path": str(adjudications_path.resolve()),
                # Hash the exact byte snapshot parsed into corpus_manifest.
                "sha256": adjudications_sha256,
            },
            detector_inputs_key: {
                "directory": str(detector_input_dir.resolve()),
                "manifest": snapshot_cache_manifest,
                "manifest_sha256": canonical_sha256(snapshot_cache_manifest),
                "result_kind": detector_result_kind,
                "signature_replay": False,
            },
            "alias_closure": {
                "source": alias_source_provenance or {"provided_by_caller": True},
                "relevant_manifest": relevant_alias_manifest,
                "relevant_manifest_sha256": canonical_sha256(relevant_alias_manifest),
            },
            "curated_publication": publication_provenance,
        },
        "code_provenance": code_provenance,
        "selection_bias": {
            "status": "known_selection_bias",
            "probability_sample": False,
            "sample_construction": (
                "The frozen corpus consists of cases selected for prior audit; "
                "selection may correlate with detector and publication behavior."
            ),
            "generalization": (
                "Point estimates describe this frozen adjudicated corpus and do "
                "not establish population-wide precision or recall."
            ),
        },
        "interpretation": {
            detector_metrics_key: (
                "Binary predictions are fixed-contract campaign results bound to "
                "schema-current runner markers, current contract/source digests, "
                "Luna-max execution, and result hashes within marker time windows."
                if fixed_campaign_complete
                else "Binary predictions project stored, mixed-version cached analyzer "
                "results through the currently hashed inclusion predicate with no "
                "audit overrides, force-includes, or audit exclusions. Stored AI "
                "signals and verdicts are retained; signature_replay is false."
            ),
            "curated_publication_metrics": (
                "Binary predictions come from membership in the validated web-data publication after curation."
            ),
            "alias_unit": (
                "CVE, GHSA, OSV, and ecosystem aliases in one source-backed closure "
                "are one sample; any positive alias makes the class prediction positive."
            ),
            "input_completeness": (
                "Every adjudication class must have at least one cached pipeline record. "
                "Source-only aliases do not require duplicate analysis records; any "
                "available alias records are combined and absent alias records are "
                "listed in cache_subject_ids_missing."
            ),
            "unresolved_and_infrastructure": (
                "Fallback, capped, errored, and otherwise incomplete work is reported "
                "outside the binary confusion matrix instead of becoming a negative."
            ),
        },
    }
    if detector_inventory is not None and inventory_manifest is not None:
        stage_metrics = {
            stage: _metrics(
                [
                    {
                        **row,
                        "stage_prediction": row["stage_predictions"][stage],
                        "stage_outcome": row["stage_outcomes"][stage],
                    }
                    for row in inventory_manifest
                ],
                prediction_key="stage_prediction",
                outcome_key="stage_outcome",
            )
            for stage in (
                "source_matcher",
                "screening",
                "verification",
                "final_publication",
            )
        }
        final_metrics = stage_metrics["final_publication"]
        screening_metrics = stage_metrics["screening"]
        stage_quality_gate = {
            "screening_zero_false_negatives": (
                screening_metrics["confusion_counts"]["fn"] == 0
            ),
            "final_precision_lower_bound_at_least_0_95": (
                (final_metrics["precision_one_sided_95pct_lower_bound"] or 0.0)
                >= 0.95
            ),
            "final_recall_lower_bound_at_least_0_95": (
                (final_metrics["recall_one_sided_95pct_lower_bound"] or 0.0)
                >= 0.95
            ),
        }
        stage_quality_gate["passed"] = all(stage_quality_gate.values())
        report["detector_inventory"] = {
            "inventory_id": detector_inventory["inventory_id"],
            "source_snapshot_sha256": detector_inventory["source_snapshot_sha256"],
            "source_alias_class_manifest_sha256": detector_inventory[
                "source_alias_class_manifest_sha256"
            ],
            "campaign_id": detector_inventory["campaign_id"],
            "contract_sha256": detector_inventory["contract_sha256"],
            "campaign_mode": detector_inventory["campaign_mode"],
            "complete": detector_inventory["complete"],
            "alias_class_count": detector_inventory["alias_class_count"],
            "prediction_manifest": inventory_manifest,
            "prediction_manifest_sha256": canonical_sha256(inventory_manifest),
            "metrics": _metrics(
                inventory_manifest,
                prediction_key="inventory_detector_prediction",
                outcome_key="inventory_detector_outcome",
            ),
            "stage_metrics": stage_metrics,
            "stage_quality_gate": stage_quality_gate,
        }
    return report


def _publication_snapshot(publication_dir: Path) -> tuple[set[str], dict[str, Any]]:
    publication = load_published_web_data(publication_dir)
    bundle = {
        "index": publication.index,
        "entries": publication.entries,
        "stats": publication.stats,
    }
    published_ids = [entry["id"] for entry in publication.entries]
    return set(published_ids), {
        "directory": str(publication_dir.resolve()),
        "bundle_sha256": canonical_sha256(bundle),
        "ordered_ids": published_ids,
        "ordered_ids_sha256": canonical_sha256(published_ids),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate a mixed-version cached pipeline snapshot and curated "
            "publication on one frozen adjudication corpus."
        )
    )
    parser.add_argument(
        "--adjudications",
        type=Path,
        default=_DEFAULT_ADJUDICATIONS,
    )
    parser.add_argument("--cache-dir", type=Path, default=Path(DEFAULT_CACHE_DIR))
    parser.add_argument(
        "--publication-dir",
        type=Path,
        default=_DEFAULT_PUBLICATION_DIR,
    )
    parser.add_argument(
        "--ghsa-db-dir",
        type=Path,
        default=Path(DEFAULT_GHSA_DB_DIR),
    )
    parser.add_argument(
        "--osv-bulk-dir",
        type=Path,
        default=_DEFAULT_OSV_BULK_DIR,
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the deterministic report to this path as well as stdout.",
    )
    return parser


def _require_source_directory(path: Path, name: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{name} is missing or unsafe: {path}")


def _write_output(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    fixed_campaign_context: FixedCampaignProofContext | None
    fixed_campaign_setup_failures: tuple[dict[str, Any], ...]
    try:
        fixed_campaign_context = _current_fixed_campaign_context()
        fixed_campaign_setup_failures = ()
    except (OSError, UnicodeError, ValueError, refresh_runner.RunnerError) as exc:
        fixed_campaign_context = None
        fixed_campaign_setup_failures = (
            {
                "code": "campaign_context_invalid",
                "detail": str(exc),
            },
        )
    try:
        _require_source_directory(args.ghsa_db_dir, "GHSA advisory directory")
        _require_source_directory(args.osv_bulk_dir, "OSV bulk directory")
        alias_map = build_alias_map(
            str(args.ghsa_db_dir),
            str(args.osv_bulk_dir),
        )
        published_ids, publication_provenance = _publication_snapshot(
            args.publication_dir
        )
        report = build_report(
            adjudications_path=args.adjudications,
            cache_dir=args.cache_dir,
            alias_map=alias_map,
            published_ids=published_ids,
            publication_provenance=publication_provenance,
            alias_source_provenance={
                "ghsa_db_dir": str(args.ghsa_db_dir.resolve()),
                "osv_bulk_dir": str(args.osv_bulk_dir.resolve()),
            },
            fixed_campaign_context=fixed_campaign_context,
            fixed_campaign_setup_failures=fixed_campaign_setup_failures,
        )
    except (OSError, UnicodeError, ValueError, PublishedDataError) as exc:
        failure = {
            "schema_version": 3,
            "evaluation_kind": (
                "frozen_adjudication_mixed_version_cached_pipeline_snapshot_vs_curated_publication"
            ),
            "evaluation_complete": False,
            "error": str(exc),
        }
        print(json.dumps(failure, indent=2, sort_keys=True), file=sys.stderr)
        return 2

    rendered = (
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
        )
        + "\n"
    )
    if args.output is not None:
        _write_output(args.output, rendered)
    print(rendered, end="")
    return 0 if report["evaluation_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
