#!/usr/bin/env python3
"""Generate and gate one atomic Web-data release.

Formal releases consume only the current content-addressed fixed campaign and
the local advisory snapshot bound into that campaign.  A candidate generation
is built in a sibling staging directory, evaluated against the frozen audit
corpus, receipted, and promoted as one directory only after every release gate
passes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

# Formal verification rejects ignored bytecode/native shadows.  Disable local
# bytecode creation before importing any repository module so a clean trusted
# checkout remains clean through verifier-contract construction.  Existing
# bytecode is still rejected rather than trusted or deleted.
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Make cve_analyzer and the sibling scripts importable when invoked directly.
_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_CVE_SRC = _REPO_ROOT / "cve-analyzer" / "src"
for _import_root in (_CVE_SRC, _SCRIPT_DIR):
    if str(_import_root) not in sys.path:
        sys.path.insert(0, str(_import_root))

import evaluate_detector_quality as detector_quality  # noqa: E402
import evaluate_publication_quality as publication_quality  # noqa: E402
import build_recall_audit as recall_audit  # noqa: E402
import heldout_quality_gate as heldout_quality  # noqa: E402
import run_data_refresh as refresh_runner  # noqa: E402
from cve_analyzer.models import (  # noqa: E402
    CveAnalysisResult,
)
from web_data.constants import DEFAULT_OUTPUT_DIR  # noqa: E402
from web_data.entry_builder import QuarantineLog, build_entry  # noqa: E402
from web_data.filters import should_include  # noqa: E402
from web_data import inventory as detector_inventory_builder  # noqa: E402
from web_data import verifier_contract as verifier_contract_builder  # noqa: E402
from web_data.loader import (  # noqa: E402
    load_adjudicated_positive_ids,
    load_audit_exclusions,
    load_audit_override_details,
    load_audit_overrides,
    load_ghsa_published_dates,
    load_ghsa_severities,
    load_nvd_published_dates,
)
from web_data.release_evidence import (  # noqa: E402
    ReleaseEvidenceError,
    archive_release_evidence,
    prepare_release_activation_record,
    reconcile_release_activation_record,
    validate_release_evidence,
    write_release_activation_record,
)
from web_data.schema import VULNERABILITY_ID_PATTERN  # noqa: E402
from web_data.stats import build_stats  # noqa: E402
from web_data.writer import (  # noqa: E402
    PublishedDataError,
    StagedWebData,
    discard_staged_web_data,
    load_published_web_data,
    publication_bundle_sha256,
    publication_promotion_transaction,
    stage_web_data,
    write_staged_release_receipt,
)

_PUBLIC_ID = re.compile(VULNERABILITY_ID_PATTERN)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RELEASE_FLOOR = 0.95
_MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES = 32 * 1024 * 1024
# 2026-07-18: 1,495 current results used 11.4 MiB (mean 7.64 KiB,
# p95 27.9 KiB, max 1.03 MiB); the 27,725-ID campaign projects to ~212 MiB.
_MAX_ARCHIVED_CAMPAIGN_RESULTS_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_ARCHIVED_PROTECTED_INPUT_BYTES = 32 * 1024 * 1024
_MAX_ARCHIVED_PROTECTED_INPUTS_TOTAL_BYTES = 128 * 1024 * 1024
_ADJUDICATIONS_PATH = _SCRIPT_DIR / "publication_adjudications.json"
_BASE_ADJUDICATIONS_PATH = _SCRIPT_DIR / "audit_adjudications.json"
_PUBLICATION_ADJUDICATIONS_BUILDER_PATH = (
    _SCRIPT_DIR / "build_publication_adjudications.py"
)
_PUBLICATION_ADMISSION_HELPER_PATH = _SCRIPT_DIR / "cohort" / "publication_admission.py"
_FP211_DIR = _REPO_ROOT / "autoresearch" / "orchestrator-260813-fp211-audit"
_FP211_FINAL_PATH = _FP211_DIR / "final_mechanisms.jsonl"
_FP211_MANIFEST_PATH = _FP211_DIR / "manifest.jsonl"
_FP211_PUBLIC_CASES_PATH = _FP211_DIR / "public_cases.jsonl"
_AUDIT_OVERRIDES_PATH = _SCRIPT_DIR / "audit_overrides.json"


class ReleaseGateError(RuntimeError):
    """Raised when a candidate cannot satisfy the formal release contract."""


@dataclass(frozen=True, slots=True)
class CampaignResultSnapshot:
    """Exact, stable inventory loaded from one content-addressed campaign."""

    results: tuple[CveAnalysisResult, ...]
    manifest: tuple[dict[str, Any], ...]
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class BuiltPublication:
    """Candidate entries, aggregates, and explicit projection failures."""

    entries: list[dict]
    stats: dict
    quarantine: QuarantineLog
    inventory: dict | None = None


def _canonical_sha256(value: object) -> str:
    return detector_quality.canonical_sha256(value)


def _stable_regular_file(
    path: Path,
    description: str,
    *,
    max_bytes: int | None = None,
) -> tuple[bytes, os.stat_result]:
    """Read one regular file and reject replacement or mutation during the read."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseGateError(f"cannot open {description} {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseGateError(f"{description} is not a safe regular file: {path}")
        if max_bytes is not None and before.st_size > max_bytes:
            raise ReleaseGateError(f"{description} exceeds the archive size bound")
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if max_bytes is not None and bytes_read > max_bytes:
                raise ReleaseGateError(f"{description} exceeds the archive size bound")
        after = os.fstat(descriptor)
    except ReleaseGateError:
        raise
    except OSError as exc:
        raise ReleaseGateError(f"cannot read {description} {path}: {exc}") from exc
    finally:
        os.close(descriptor)

    signature = lambda value: (  # noqa: E731
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    content = b"".join(chunks)
    if signature(before) != signature(after) or len(content) != after.st_size:
        raise ReleaseGateError(f"{description} changed while being read: {path}")
    try:
        current = path.lstat()
    except OSError as exc:
        raise ReleaseGateError(f"cannot recheck {description} {path}: {exc}") from exc
    if signature(current) != signature(after):
        raise ReleaseGateError(f"{description} path changed while being read: {path}")
    return content, after


def _load_exact_campaign_results(context: Any) -> CampaignResultSnapshot:
    """Load exactly the planned files from the current campaign result directory."""
    campaign_id = getattr(context, "campaign_id", None)
    if not isinstance(campaign_id, str) or _SHA256.fullmatch(campaign_id) is None:
        raise ReleaseGateError("campaign_id must be a lowercase SHA-256")

    result_dir = Path(getattr(context, "result_dir", ""))
    campaign_root = result_dir.parent
    campaigns_root = campaign_root.parent
    if (
        result_dir.name != "results"
        or campaign_root.name != campaign_id
        or campaigns_root.name != "campaigns-v1"
    ):
        raise ReleaseGateError(
            "campaign result directory is not content-addressed as "
            "campaigns-v1/<campaign_id>/results"
        )
    for directory, description in (
        (campaigns_root, "campaign container"),
        (campaign_root, "campaign directory"),
        (result_dir, "campaign result directory"),
    ):
        if directory.is_symlink() or not directory.is_dir():
            raise ReleaseGateError(f"{description} is missing or unsafe: {directory}")

    planned_ids: list[str] = []
    for batch in getattr(context, "batches", ()):
        batch_ids = getattr(batch, "ids", None)
        if not isinstance(batch_ids, (tuple, list)):
            raise ReleaseGateError("campaign batch inventory is malformed")
        planned_ids.extend(batch_ids)
    if not planned_ids:
        raise ReleaseGateError("campaign result inventory is empty")
    for subject_id in planned_ids:
        if not isinstance(subject_id, str) or _PUBLIC_ID.fullmatch(subject_id) is None:
            raise ReleaseGateError(
                f"campaign inventory contains unsafe ID: {subject_id!r}"
            )
    if len(planned_ids) != len(set(planned_ids)):
        raise ReleaseGateError(
            "campaign result inventory contains duplicate planned IDs"
        )

    expected_names = {f"{subject_id}.json" for subject_id in planned_ids}
    try:
        actual_children = list(result_dir.iterdir())
    except OSError as exc:
        raise ReleaseGateError(
            f"cannot enumerate campaign result inventory: {exc}"
        ) from exc
    actual_names = {child.name for child in actual_children}
    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    if missing or unexpected or len(actual_names) != len(actual_children):
        raise ReleaseGateError(
            "campaign result inventory mismatch; "
            f"missing={missing}, unexpected={unexpected}"
        )

    results: list[CveAnalysisResult] = []
    manifest: list[dict[str, Any]] = []
    total_result_bytes = 0
    for subject_id in planned_ids:
        path = result_dir / f"{subject_id}.json"
        content, metadata = _stable_regular_file(
            path,
            f"campaign result {subject_id}",
            max_bytes=_MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES,
        )
        total_result_bytes += len(content)
        if total_result_bytes > _MAX_ARCHIVED_CAMPAIGN_RESULTS_TOTAL_BYTES:
            raise ReleaseGateError(
                "campaign results exceed the aggregate archive size bound"
            )
        try:
            payload = json.loads(content)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ReleaseGateError(
                f"campaign result {subject_id} is malformed JSON: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise ReleaseGateError(
                f"campaign result {subject_id} must contain an object"
            )
        if payload.get("cve_id") != subject_id:
            raise ReleaseGateError(
                f"campaign result filename/id mismatch for {subject_id}: "
                f"{payload.get('cve_id')!r}"
            )
        try:
            result = CveAnalysisResult.from_dict(payload)
            result.rebuild_signals()
        except (KeyError, TypeError, ValueError) as exc:
            raise ReleaseGateError(
                f"campaign result {subject_id} is invalid: {exc}"
            ) from exc
        results.append(result)
        manifest.append(
            {
                "subject_id": subject_id,
                "file_name": path.name,
                "size_bytes": metadata.st_size,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )

    return CampaignResultSnapshot(
        results=tuple(results),
        manifest=tuple(manifest),
        manifest_sha256=_canonical_sha256(manifest),
    )


def _strict_alias_id(value: object, source: str) -> str:
    normalized = value.strip() if isinstance(value, str) else ""
    if (
        not isinstance(value, str)
        or not normalized
        or len(normalized) > 512
        or any(ord(character) < 0x20 for character in normalized)
    ):
        raise ReleaseGateError(f"invalid advisory id in {source}: {value!r}")
    return normalized


def _strict_alias_record(content: bytes, source: str) -> tuple[str, ...]:
    try:
        payload = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseGateError(f"malformed advisory JSON {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReleaseGateError(f"advisory {source} must contain an object")
    advisory_id = _strict_alias_id(payload.get("id"), source)
    aliases = payload.get("aliases", [])
    if not isinstance(aliases, list):
        raise ReleaseGateError(f"advisory aliases in {source} must be an array")
    validated_aliases = tuple(_strict_alias_id(alias, source) for alias in aliases)
    if advisory_id in validated_aliases or len(validated_aliases) != len(
        set(validated_aliases)
    ):
        raise ReleaseGateError(f"advisory aliases in {source} contain duplicates")
    return (advisory_id, *validated_aliases)


def _safe_source_directory(path: Path, description: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReleaseGateError(
            f"{description} is missing or unreadable: {path}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseGateError(f"{description} is unsafe: {path}")
    return path


def _safe_archive_member(name: str) -> bool:
    candidate = PurePosixPath(name)
    return bool(
        name
        and "\\" not in name
        and not candidate.is_absolute()
        and all(part not in {"", ".", ".."} for part in candidate.parts)
    )


def _strict_build_alias_map(
    ghsa_advisories_dir: Path,
    osv_bulk_dir: Path,
) -> dict[str, set[str]]:
    """Build alias closure while failing on every malformed local source record."""
    ghsa_root = _safe_source_directory(Path(ghsa_advisories_dir), "GHSA advisories")
    osv_root = _safe_source_directory(Path(osv_bulk_dir), "OSV bulk source")

    parent: dict[str, str] = {}

    def find(advisory_id: str) -> str:
        root = advisory_id
        while parent[root] != root:
            root = parent[root]
        while parent[advisory_id] != advisory_id:
            previous = parent[advisory_id]
            parent[advisory_id] = root
            advisory_id = previous
        return root

    def add_group(group: tuple[str, ...], *, keep_singleton: bool) -> None:
        if len(group) == 1 and not keep_singleton:
            return
        for advisory_id in group:
            parent.setdefault(advisory_id, advisory_id)
        root = find(group[0])
        for advisory_id in group[1:]:
            other_root = find(advisory_id)
            if root != other_root:
                parent[other_root] = root

    ghsa_records = 0
    for subdirectory_name in ("github-reviewed", "unreviewed"):
        subdirectory = _safe_source_directory(
            ghsa_root / subdirectory_name,
            f"GHSA {subdirectory_name}",
        )
        paths = sorted(subdirectory.rglob("*"), key=lambda path: path.as_posix())
        for path in paths:
            if path.is_symlink():
                raise ReleaseGateError(f"GHSA source contains a symlink: {path}")
            if path.is_dir():
                continue
            if not path.is_file() or path.suffix != ".json":
                raise ReleaseGateError(
                    f"GHSA source contains an unexpected artifact: {path}"
                )
            content, _ = _stable_regular_file(path, "GHSA advisory")
            add_group(
                _strict_alias_record(content, str(path)),
                keep_singleton=True,
            )
            ghsa_records += 1
    if ghsa_records == 0:
        raise ReleaseGateError("GHSA advisory source contains no JSON records")

    try:
        osv_children = sorted(osv_root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise ReleaseGateError(f"cannot enumerate OSV bulk source: {exc}") from exc
    if not osv_children:
        raise ReleaseGateError("OSV bulk source contains no zip archives")
    for archive_path in osv_children:
        if (
            archive_path.is_symlink()
            or not archive_path.is_file()
            or archive_path.suffix != ".zip"
        ):
            raise ReleaseGateError(
                f"OSV bulk source contains an unexpected artifact: {archive_path}"
            )
        try:
            archive_metadata = archive_path.lstat()
        except OSError as exc:
            raise ReleaseGateError(
                f"cannot inspect OSV archive {archive_path}: {exc}"
            ) from exc
        if not stat.S_ISREG(archive_metadata.st_mode):
            raise ReleaseGateError(f"OSV archive is unsafe: {archive_path}")
        try:
            with zipfile.ZipFile(archive_path) as archive:
                members = archive.infolist()
                if not members:
                    raise ReleaseGateError(f"OSV archive is empty: {archive_path}")
                member_names: set[str] = set()
                json_records = 0
                for member in members:
                    if not _safe_archive_member(member.filename):
                        raise ReleaseGateError(
                            f"OSV archive has unsafe member {member.filename!r}: "
                            f"{archive_path}"
                        )
                    if member.filename in member_names:
                        raise ReleaseGateError(
                            f"OSV archive has duplicate member {member.filename!r}: "
                            f"{archive_path}"
                        )
                    member_names.add(member.filename)
                    file_type = stat.S_IFMT(member.external_attr >> 16)
                    if file_type == stat.S_IFLNK or member.flag_bits & 0x1:
                        raise ReleaseGateError(
                            f"OSV archive has unsafe member {member.filename!r}: "
                            f"{archive_path}"
                        )
                    if member.is_dir():
                        continue
                    if not member.filename.endswith(".json"):
                        raise ReleaseGateError(
                            f"OSV archive has non-JSON member {member.filename!r}: "
                            f"{archive_path}"
                        )
                    try:
                        content = archive.read(member)
                    except (KeyError, OSError, RuntimeError) as exc:
                        raise ReleaseGateError(
                            f"cannot read OSV record {member.filename!r}: {exc}"
                        ) from exc
                    add_group(
                        _strict_alias_record(
                            content,
                            f"{archive_path}:{member.filename}",
                        ),
                        keep_singleton=False,
                    )
                    json_records += 1
                if json_records == 0:
                    raise ReleaseGateError(
                        f"OSV archive contains no JSON records: {archive_path}"
                    )
        except ReleaseGateError:
            raise
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise ReleaseGateError(
                f"malformed OSV archive {archive_path}: {exc}"
            ) from exc
        try:
            after = archive_path.lstat()
        except OSError as exc:
            raise ReleaseGateError(
                f"cannot recheck OSV archive {archive_path}: {exc}"
            ) from exc
        before_signature = (
            archive_metadata.st_dev,
            archive_metadata.st_ino,
            archive_metadata.st_size,
            archive_metadata.st_mtime_ns,
            archive_metadata.st_ctime_ns,
        )
        after_signature = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_signature != after_signature:
            raise ReleaseGateError(
                f"OSV archive changed while being read: {archive_path}"
            )

    components: dict[str, set[str]] = {}
    for advisory_id in parent:
        components.setdefault(find(advisory_id), set()).add(advisory_id)
    alias_map: dict[str, set[str]] = {}
    for component in components.values():
        for advisory_id in component:
            alias_map[advisory_id] = component
    return alias_map


def _require_release_gates(
    detector_report: dict,
    curation_report: dict,
    heldout_report: dict,
    recall_report: dict,
    *,
    precision_target: float,
    recall_target: float,
) -> None:
    """Fail unless campaign, curation, held-out, and end-to-end recall gates pass."""
    _validate_release_targets(precision_target, recall_target)

    if detector_report.get("evaluation_complete") is not True:
        raise ReleaseGateError("detector evaluation_complete gate failed")
    proof = detector_report.get("fixed_contract_campaign_proof")
    if not isinstance(proof, dict):
        raise ReleaseGateError("detector fixed campaign proof is missing")
    if proof.get("complete") is not True:
        raise ReleaseGateError("detector fixed campaign proof is incomplete")
    if (
        proof.get("campaign_mode") != "formal"
        or proof.get("population_policy") != "formal_full"
        or proof.get("formal_population_complete") is not True
    ):
        raise ReleaseGateError("detector formal-population proof is incomplete")
    if proof.get("proof_scope") != "formal_current_source_alias_class_plan":
        raise ReleaseGateError("detector campaign proof scope is invalid")
    if proof.get("population_uniform_luna_max_proof") is not False:
        raise ReleaseGateError("detector campaign population boundary is invalid")
    if curation_report.get("curation_consistent") is not True:
        raise ReleaseGateError("publication curation-consistency gate failed")

    configured_targets = curation_report.get("targets")
    if not isinstance(configured_targets, dict):
        raise ReleaseGateError("curation target contract is missing or malformed")
    for metric, expected in (
        ("curation_precision", precision_target),
        ("curation_recall", recall_target),
    ):
        actual = configured_targets.get(metric)
        if (
            isinstance(actual, bool)
            or not isinstance(actual, (int, float))
            or float(actual) != float(expected)
        ):
            raise ReleaseGateError(f"{metric} target does not match the release target")

    for metric, target in (
        ("curation_precision", precision_target),
        ("curation_recall", recall_target),
    ):
        metric_report = curation_report.get(metric)
        point = metric_report.get("point") if isinstance(metric_report, dict) else None
        if (
            isinstance(point, bool)
            or not isinstance(point, (int, float))
            or not math.isfinite(float(point))
            or float(point) < float(target)
        ):
            raise ReleaseGateError(
                f"{metric} point estimate is below {float(target):.2%}"
            )

    if heldout_report.get("evaluation_complete") is not True:
        raise ReleaseGateError("independent held-out evaluation is incomplete")
    if (
        heldout_report.get("point_gate_passed") is not True
        or heldout_report.get("release_gate_passed") is not True
        or heldout_report.get("certified_gate_passed") is not True
    ):
        raise ReleaseGateError("independent held-out certified-quality gate failed")
    heldout_stage_metrics = heldout_report.get("stage_metrics")
    heldout_screening = (
        heldout_stage_metrics.get("screening")
        if isinstance(heldout_stage_metrics, dict)
        else None
    )
    screening_confusion = (
        heldout_screening.get("confusion")
        if isinstance(heldout_screening, dict)
        else None
    )
    if (
        not isinstance(screening_confusion, dict)
        or screening_confusion.get("fn") != 0
        or heldout_screening.get("screening_zero_false_negatives") is not True
    ):
        raise ReleaseGateError(
            "independent held-out screening false-negative gate failed"
        )
    for metric in ("precision", "recall"):
        evidence = heldout_report.get(metric)
        lower_bound = (
            evidence.get("one_sided_95pct_lower_bound")
            if isinstance(evidence, dict)
            else None
        )
        if (
            isinstance(lower_bound, bool)
            or not isinstance(lower_bound, (int, float))
            or float(lower_bound) < 0.95
        ):
            raise ReleaseGateError(
                f"independent held-out final {metric} lower bound is below 0.95"
            )
    heldout_campaign = heldout_report.get("campaign")
    expected_contract = proof.get("expected_contract")
    if not isinstance(heldout_campaign, dict) or not isinstance(
        expected_contract, dict
    ):
        raise ReleaseGateError("held-out/campaign proof binding is missing")
    for field in ("campaign_id", "contract_sha256", "source_snapshot_sha256"):
        if heldout_campaign.get(field) != expected_contract.get(field):
            raise ReleaseGateError(
                f"independent held-out report {field} does not match campaign proof"
            )

    _validate_recall_audit_report(recall_report, recall_target=recall_target)


def _validate_recall_audit_report(
    report: dict[str, Any],
    *,
    recall_target: float | None = None,
) -> None:
    """Require a complete end-to-end rejection-stratum recall evaluation."""

    recall = report.get("recall")
    point = recall.get("recall_point") if isinstance(recall, dict) else None
    interval = recall.get("recall_interval") if isinstance(recall, dict) else None
    protected_census = (
        recall.get("protected_census") if isinstance(recall, dict) else None
    )
    resolved = report.get("resolved_labels")
    census_resolved = report.get("protected_census_resolved_labels")
    protected_overlap_count = report.get("protected_overlap_class_count")
    protected_census_digest = report.get("protected_census_manifest_sha256")
    if (
        report.get("schema_version") != 2
        or report.get("evaluation_kind")
        != "stratified_end_to_end_finite_population_recall"
        or report.get("selection_replayed_from_inventory") is not True
        or report.get("evaluation_complete") is not True
        or report.get("evaluation_blockers") != []
        or report.get("coverage_failure_count") != 0
        or isinstance(protected_overlap_count, bool)
        or not isinstance(protected_overlap_count, int)
        or protected_overlap_count < 0
        or not isinstance(protected_census_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", protected_census_digest) is None
        or report.get("protected_census_complete") is not True
        or not isinstance(census_resolved, dict)
        or len(census_resolved) != protected_overlap_count
        or any(
            label not in {"AI_CAUSAL", "NOT_AI_CAUSAL"}
            for label in census_resolved.values()
        )
        or report.get("protected_census_unresolved_packet_ids") != []
        or report.get("protected_excluded_class_count") != 0
        or report.get("unresolved_packet_ids") != []
        or report.get("covered_unprotected_diagnostic_complete") is not True
        or not isinstance(report.get("artifact_order"), dict)
        or not report["artifact_order"]
        or not isinstance(resolved, dict)
        or any(
            label not in {"AI_CAUSAL", "NOT_AI_CAUSAL"} for label in resolved.values()
        )
        or not isinstance(recall, dict)
        or isinstance(point, bool)
        or not isinstance(point, (int, float))
        or not math.isfinite(float(point))
        or not 0.0 <= float(point) <= 1.0
        or not isinstance(interval, list)
        or len(interval) != 2
        or any(
            isinstance(bound, bool)
            or not isinstance(bound, (int, float))
            or not math.isfinite(float(bound))
            or not 0.0 <= float(bound) <= 1.0
            for bound in interval
        )
        or float(interval[0]) > float(point)
        or float(point) > float(interval[1])
        or not isinstance(protected_census, dict)
        or protected_census.get("class_count") != protected_overlap_count
    ):
        raise ReleaseGateError(
            "end-to-end recall evaluation is incomplete or malformed"
        )
    if recall_target is not None and (
        float(point) < float(recall_target) or float(interval[0]) < float(recall_target)
    ):
        raise ReleaseGateError(
            "end-to-end recall point estimate and confidence-interval lower "
            f"bound must both meet the {float(recall_target):.2%} release target"
        )


def _evaluate_recall_audit_inputs(
    *,
    selection_path: Path,
    labels_path: Path,
    report_path: Path,
    inventory: dict[str, Any],
    alias_map: dict[str, set[str]],
    repo_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Recompute the sealed end-to-end recall audit from authoritative inputs."""

    selection = _load_heldout_input(selection_path, "recall selection")
    labels = _load_heldout_input(labels_path, "recall independent labels")
    supplied_report = _load_heldout_input(report_path, "recall report")
    try:
        protected = recall_audit._rebuild_authoritative_protected_inventory(
            selection,
            repo_root=repo_root,
            selection_path=selection_path,
            labels_path=labels_path,
            alias_map=alias_map,
        )
        recomputed_report = recall_audit.evaluate_labels(
            selection,
            labels,
            inventory=inventory,
            protected=protected,
            selection_path=selection_path,
            labels_path=labels_path,
            repo_root=repo_root,
            verify_artifact_order=True,
        )
    except (recall_audit.RecallAuditError, heldout_quality.HeldoutQualityError) as exc:
        raise ReleaseGateError(f"end-to-end recall evaluation failed: {exc}") from exc
    if recomputed_report != supplied_report:
        raise ReleaseGateError(
            "recall report does not exactly recompute from inventory, selection, and labels"
        )
    _validate_recall_audit_report(recomputed_report)
    return selection, labels, recomputed_report


def _validate_release_targets(
    precision_target: float,
    recall_target: float,
) -> None:
    """Require release targets at or above the formal 95% floor."""
    for target_name, target in (
        ("precision", precision_target),
        ("recall", recall_target),
    ):
        if (
            isinstance(target, bool)
            or not isinstance(target, (int, float))
            or not math.isfinite(float(target))
            or not _RELEASE_FLOOR <= float(target) <= 1.0
        ):
            raise ReleaseGateError(
                f"{target_name} target must be between {_RELEASE_FLOOR:.2f} and 1"
            )


def _inventory_generated_at(source_remote_cutoff: dict[str, Any]) -> str:
    """Return the canonical cutoff time used in reproducible inventory identity."""

    cutoff_timestamp = source_remote_cutoff.get("checked_at_utc")
    if not isinstance(cutoff_timestamp, str) or not cutoff_timestamp:
        raise ReleaseGateError("source remote cutoff timestamp is missing")
    try:
        parsed_cutoff = datetime.fromisoformat(cutoff_timestamp)
    except ValueError as exc:
        raise ReleaseGateError("source remote cutoff timestamp is invalid") from exc
    if (
        parsed_cutoff.tzinfo is None
        or parsed_cutoff.utcoffset() != timezone.utc.utcoffset(parsed_cutoff)
        or parsed_cutoff.isoformat() != cutoff_timestamp
    ):
        raise ReleaseGateError(
            "source remote cutoff timestamp must be canonical UTC ISO-8601"
        )
    return cutoff_timestamp


def _load_heldout_input(path: Path, description: str) -> dict[str, Any]:
    """Read one stable held-out selection or independent-label input."""
    try:
        content, _ = heldout_quality._stable_file(
            Path(path),
            description=description,
        )
    except heldout_quality.HeldoutQualityError as exc:
        raise ReleaseGateError(f"cannot read {description}: {exc}") from exc
    try:
        payload = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseGateError(f"{description} is malformed JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReleaseGateError(f"{description} must contain an object")
    _canonical_sha256(payload)
    return payload


def _heldout_campaign_snapshot(alias_map: dict[str, set[str]]) -> Any:
    """Re-prove the whole fixed campaign through the held-out evaluator."""
    try:
        return heldout_quality.load_fixed_campaign_snapshot(
            _REPO_ROOT,
            alias_map=alias_map,
        )
    except heldout_quality.HeldoutQualityError as exc:
        raise ReleaseGateError(
            f"cannot re-prove held-out campaign inputs: {exc}"
        ) from exc


def _evaluate_heldout_quality_inputs(
    *,
    selection_path: Path,
    labels_path: Path,
    alias_map: dict[str, set[str]],
    context: Any,
    precision_target: float,
    recall_target: float,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Any]:
    """Reproduce selection and evaluate independent labels inside this process."""
    selection = _load_heldout_input(selection_path, "held-out selection")
    labels = _load_heldout_input(labels_path, "held-out independent labels")
    try:
        heldout_quality.validate_selection_seal(selection)
        protected_contract = selection.get("protected_inputs")
        if not isinstance(protected_contract, dict) or not isinstance(
            protected_contract.get("source_roots"), list
        ):
            raise heldout_quality.HeldoutQualityError(
                "selection protected input contract is missing"
            )
        protected_paths = heldout_quality._authoritative_protected_sources(
            _REPO_ROOT,
            protected_contract["source_roots"],
        )
        campaign_snapshot = _heldout_campaign_snapshot(alias_map)
        protected = heldout_quality.build_protected_inventory(
            _REPO_ROOT,
            protected_paths,
            alias_map,
            excluded_paths=(selection_path, labels_path),
        )
        policy = selection.get("selection_policy")
        if not isinstance(policy, dict):
            raise heldout_quality.HeldoutQualityError("selection policy is missing")
        expected_selection = heldout_quality.build_selection_manifest(
            campaign_snapshot,
            protected,
            precision_sample_size=policy.get("precision_sample_size"),
            recall_sample_size=policy.get("recall_sample_size"),
            selection_code_sha256=heldout_quality._selection_code_sha256(),
        )
        if expected_selection != selection:
            raise heldout_quality.HeldoutQualityError(
                "selection does not exactly reproduce from the release campaign"
            )
        report = heldout_quality.evaluate_selection(
            selection,
            labels,
            protected,
            precision_target=precision_target,
            recall_target=recall_target,
            require_certified=True,
            selection_path=selection_path,
            labels_path=labels_path,
            repo_root=_REPO_ROOT,
        )
    except heldout_quality.HeldoutQualityError as exc:
        raise ReleaseGateError(
            f"independent held-out evaluation failed: {exc}"
        ) from exc
    _validate_heldout_quality_report(
        report,
        context=context,
        campaign_snapshot=campaign_snapshot,
        precision_target=precision_target,
        recall_target=recall_target,
    )
    return selection, labels, report, campaign_snapshot


def _validated_metric_point(
    report: dict[str, Any],
    name: str,
    target: float,
) -> float:
    metric = report.get(name)
    expected_fields = {
        "successes",
        "trials",
        "point",
        "one_sided_95pct_lower_bound",
        "point_meets_target",
        "certified_meets_target",
        "target",
        "confidence_bound_method",
    }
    if not isinstance(metric, dict) or set(metric) != expected_fields:
        raise ReleaseGateError(f"held-out {name} metric contract is malformed")
    successes = metric.get("successes")
    trials = metric.get("trials")
    if (
        isinstance(successes, bool)
        or not isinstance(successes, int)
        or isinstance(trials, bool)
        or not isinstance(trials, int)
        or not 0 <= successes <= trials
        or trials <= 0
    ):
        raise ReleaseGateError(f"held-out {name} trial counts are invalid")
    point = metric.get("point")
    lower_bound = metric.get("one_sided_95pct_lower_bound")
    expected_point = successes / trials
    expected_lower_bound = publication_quality.clopper_pearson_lower_bound(
        successes,
        trials,
    )
    if (
        isinstance(point, bool)
        or not isinstance(point, (int, float))
        or not math.isfinite(float(point))
        or not math.isclose(float(point), expected_point, rel_tol=0.0, abs_tol=1e-15)
        or isinstance(lower_bound, bool)
        or not isinstance(lower_bound, (int, float))
        or not math.isfinite(float(lower_bound))
        or not math.isclose(
            float(lower_bound),
            expected_lower_bound,
            rel_tol=0.0,
            abs_tol=1e-15,
        )
        or metric.get("target") != float(target)
        or metric.get("point_meets_target") is not (expected_point >= target)
        or metric.get("certified_meets_target") is not (expected_lower_bound >= target)
        or metric.get("confidence_bound_method") != "exact_clopper_pearson"
    ):
        raise ReleaseGateError(f"held-out {name} metric proof is inconsistent")
    if expected_point < target:
        raise ReleaseGateError(f"held-out {name} point estimate is below {target:.2%}")
    return expected_point


def _validate_heldout_quality_report(
    report: dict[str, Any],
    *,
    context: Any,
    campaign_snapshot: Any,
    precision_target: float,
    recall_target: float,
) -> None:
    """Validate a complete, current, independently produced quality report."""
    expected_fields = {
        "schema_version",
        "evaluation_kind",
        "selection_manifest_sha256",
        "campaign",
        "evaluation_complete",
        "targets",
        "precision",
        "recall",
        "denominators",
        "strata",
        "point_gate_passed",
        "certified_gate_passed",
        "release_gate_passed",
        "measurement_boundary",
        "manual_evidence",
    }
    if set(report) != expected_fields:
        raise ReleaseGateError("independent held-out report fields are malformed")
    if (
        report.get("schema_version") != 2
        or report.get("evaluation_kind")
        != "independent_heldout_fixed_campaign_detector_quality"
        or report.get("evaluation_complete") is not True
        or report.get("point_gate_passed") is not True
        or report.get("certified_gate_passed") is not True
        or report.get("release_gate_passed") is not True
    ):
        raise ReleaseGateError(
            "independent held-out report did not pass its point gate"
        )
    selection_digest = report.get("selection_manifest_sha256")
    if (
        not isinstance(selection_digest, str)
        or _SHA256.fullmatch(selection_digest) is None
    ):
        raise ReleaseGateError("held-out selection digest is invalid")

    targets = report.get("targets")
    if not isinstance(targets, dict) or set(targets) != {
        "precision",
        "recall",
        "require_certified",
    }:
        raise ReleaseGateError("held-out target contract is malformed")
    if (
        targets.get("precision") != float(precision_target)
        or targets.get("recall") != float(recall_target)
        or targets.get("require_certified") is not True
    ):
        raise ReleaseGateError("held-out targets do not exactly match release targets")

    precision_point = _validated_metric_point(
        report,
        "precision",
        float(precision_target),
    )
    recall_point = _validated_metric_point(
        report,
        "recall",
        float(recall_target),
    )
    certified_expected = bool(
        report["precision"]["certified_meets_target"]
        and report["recall"]["certified_meets_target"]
    )
    if report.get("certified_gate_passed") is not certified_expected:
        raise ReleaseGateError("held-out certified gate is inconsistent")
    if not certified_expected:
        raise ReleaseGateError("held-out statistical certification did not pass")
    if precision_point < _RELEASE_FLOOR or recall_point < _RELEASE_FLOOR:
        raise ReleaseGateError("held-out point quality is below the formal 95% floor")

    campaign = report.get("campaign")
    expected_campaign = {
        "campaign_id": campaign_snapshot.campaign_id,
        "contract_sha256": campaign_snapshot.contract_sha256,
        "source_snapshot_sha256": campaign_snapshot.source_snapshot_sha256,
        "campaign_proof_sha256": campaign_snapshot.campaign_proof_sha256,
        "campaign_result_manifest_sha256": (
            campaign_snapshot.campaign_result_manifest_sha256
        ),
        "proof_complete": True,
    }
    if campaign != expected_campaign:
        raise ReleaseGateError(
            "held-out report campaign proof is stale or does not match current inputs"
        )
    if (
        campaign["campaign_id"] != context.campaign_id
        or campaign["contract_sha256"] != context.contract_sha256
        or campaign["source_snapshot_sha256"] != context.source_snapshot_sha256
    ):
        raise ReleaseGateError("held-out report does not match the release campaign")

    denominator_fields = {
        "selected_unique_alias_classes",
        "precision_selected",
        "precision_conclusive_trials",
        "recall_candidate_positive_selected",
        "recall_actual_positive_trials",
        "inconclusive",
        "infrastructure_error",
        "unresolved",
    }
    denominators = report.get("denominators")
    if (
        not isinstance(denominators, dict)
        or set(denominators) != denominator_fields
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in denominators.values()
        )
        or denominators["selected_unique_alias_classes"] <= 0
        or denominators["precision_selected"]
        != denominators["precision_conclusive_trials"]
        or denominators["precision_conclusive_trials"] != report["precision"]["trials"]
        or denominators["recall_actual_positive_trials"] != report["recall"]["trials"]
        or denominators["recall_actual_positive_trials"]
        > denominators["recall_candidate_positive_selected"]
        or any(
            denominators[field] != 0
            for field in ("inconclusive", "infrastructure_error", "unresolved")
        )
    ):
        raise ReleaseGateError(
            "held-out conclusive/infrastructure/unresolved denominators are incomplete"
        )

    strata = report.get("strata")
    if not isinstance(strata, dict) or set(strata) != {
        "inconclusive",
        "infrastructure_error",
        "unresolved",
        "lane_overlap",
        "label_counts",
    }:
        raise ReleaseGateError("held-out strata contract is malformed")
    for field in ("inconclusive", "infrastructure_error", "unresolved"):
        if strata.get(field) != {"count": 0, "ids": []}:
            raise ReleaseGateError(f"held-out {field} evidence is incomplete")
    label_counts = strata.get("label_counts")
    if (
        not isinstance(label_counts, dict)
        or set(label_counts) - {"AI_CAUSAL", "NOT_AI_CAUSAL"}
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in label_counts.values()
        )
        or sum(label_counts.values()) != denominators["selected_unique_alias_classes"]
    ):
        raise ReleaseGateError("held-out conclusive label denominator is malformed")

    boundary = report.get("measurement_boundary")
    if (
        not isinstance(boundary, dict)
        or set(boundary) != {"precision", "recall", "excluded"}
        or any(
            not isinstance(value, str) or not value.strip()
            for value in boundary.values()
        )
        or "candidate" not in boundary["recall"].casefold()
        or "advisory discovery" not in boundary["excluded"].casefold()
        or "signature discovery" not in boundary["excluded"].casefold()
    ):
        raise ReleaseGateError("held-out conditional recall boundary is missing")

    manual_evidence = report.get("manual_evidence")
    if not isinstance(manual_evidence, dict) or set(manual_evidence) != {
        "label_file_sha256",
        "artifact_order",
        "independent_audit_attested",
    }:
        raise ReleaseGateError("held-out independent evidence contract is malformed")
    label_digest = manual_evidence.get("label_file_sha256")
    artifact_order = manual_evidence.get("artifact_order")
    artifact_order_fields = {
        "selection_commit_reference",
        "selection_commit",
        "selection_path",
        "labels_commit",
        "labels_path",
        "labels_blob_sha256",
        "selection_is_strict_ancestor",
        "labels_absent_from_selection_commit",
        "labels_exact_bytes_tracked_at_head",
    }
    if (
        not isinstance(label_digest, str)
        or _SHA256.fullmatch(label_digest) is None
        or not isinstance(artifact_order, dict)
        or set(artifact_order) != artifact_order_fields
        or manual_evidence.get("independent_audit_attested") is not True
    ):
        raise ReleaseGateError("held-out independent evidence is incomplete")
    commit = artifact_order.get("selection_commit")
    path = artifact_order.get("selection_path")
    reference = artifact_order.get("selection_commit_reference")
    labels_commit = artifact_order.get("labels_commit")
    labels_path = artifact_order.get("labels_path")
    if (
        not isinstance(commit, str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit) is None
        or not isinstance(path, str)
        or not path
        or reference != f"{commit}:{path}"
        or not isinstance(labels_commit, str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", labels_commit) is None
        or labels_commit == commit
        or not isinstance(labels_path, str)
        or not labels_path
        or not isinstance(artifact_order.get("labels_blob_sha256"), str)
        or _SHA256.fullmatch(artifact_order["labels_blob_sha256"]) is None
        or any(
            artifact_order.get(field) is not True
            for field in (
                "selection_is_strict_ancestor",
                "labels_absent_from_selection_commit",
                "labels_exact_bytes_tracked_at_head",
            )
        )
    ):
        raise ReleaseGateError("held-out artifact-order proof is malformed")


def _deduplicate_alias_entries(
    entries: list[dict],
    alias_map: dict[str, set[str]],
) -> list[dict]:
    """Collapse equivalent advisory IDs, preferring a CVE publication ID."""
    seen_canonical: dict[str, dict] = {}
    deduplicated: list[dict] = []
    for entry in entries:
        entry_id = entry["id"]
        canonical = min(alias_map.get(entry_id, {entry_id}))
        if canonical not in seen_canonical:
            seen_canonical[canonical] = entry
            deduplicated.append(entry)
            continue
        existing = seen_canonical[canonical]
        if entry_id.startswith("CVE-") and not existing["id"].startswith("CVE-"):
            seen_canonical[canonical] = entry
            deduplicated = [
                item if item["id"] != existing["id"] else entry for item in deduplicated
            ]
    return deduplicated


def _select_publication_results(
    results: list | tuple,
    *,
    adjudicated_positive_ids: set[str],
    audit_exclusions: set[str],
    inclusion_predicate=should_include,
) -> list:
    """Select the fail-closed, independently adjudicated publication set."""
    overlap = adjudicated_positive_ids & audit_exclusions
    if overlap:
        raise ReleaseGateError(
            f"publication positive and exclusion sets overlap: {sorted(overlap)}"
        )
    return [
        result
        for result in results
        if result.cve_id in adjudicated_positive_ids
        and inclusion_predicate(
            result,
            adjudicated_positive_ids,
            audit_exclusions,
        )
    ]


def _coverage_counts(
    results: tuple[CveAnalysisResult, ...],
    published_dates: dict[str, str],
    coverage_since: str,
) -> tuple[int, int]:
    if not coverage_since:
        return len(results), sum(
            any(fix.sha for fix in result.fix_commits) for result in results
        )
    if re.fullmatch(r"\d{4}-\d{2}", coverage_since) is None:
        raise ReleaseGateError(f"invalid coverage start month: {coverage_since!r}")
    try:
        datetime.strptime(coverage_since, "%Y-%m")
    except ValueError as exc:
        raise ReleaseGateError(
            f"invalid coverage start month: {coverage_since!r}"
        ) from exc

    coverage_year = int(coverage_since[:4])
    total = 0
    with_fix_commits = 0
    for result in results:
        published = published_dates.get(result.cve_id, "")
        if published:
            in_range = published[:7] >= coverage_since
        elif result.cve_id.startswith("CVE-"):
            parts = result.cve_id.split("-")
            in_range = (
                len(parts) >= 2
                and parts[1].isdigit()
                and int(parts[1]) >= coverage_year
            )
        else:
            in_range = True
        if in_range:
            total += 1
            if any(fix.sha for fix in result.fix_commits):
                with_fix_commits += 1
    return total, with_fix_commits


def _inventory_summary(inventory: dict) -> dict:
    return {
        "path": "inventory.json",
        "inventory_id": inventory["inventory_id"],
        "source_snapshot_sha256": inventory["source_snapshot_sha256"],
        "source_alias_class_manifest_sha256": inventory[
            "source_alias_class_manifest_sha256"
        ],
        "campaign_id": inventory["campaign_id"],
        "campaign_mode": inventory["campaign_mode"],
        "complete": inventory["complete"],
        "coverage_to": inventory["coverage_to"],
        "alias_class_count": inventory["alias_class_count"],
        "detector_candidate_count": inventory["detector_candidate_count"],
        "pending_adjudication_count": inventory["pending_adjudication_count"],
        "coverage_failure_count": inventory["coverage_failure_count"],
    }


def _build_detector_inventory(
    results: tuple[CveAnalysisResult, ...],
    *,
    alias_map: dict[str, set[str]],
    adjudicated_positive_ids: set[str],
    audit_exclusions: set[str],
    published_ids: set[str],
    generated_at: str,
    source_snapshot_sha256: str,
    source_receipt_sha256: str,
    campaign_id: str,
    contract_sha256: str,
    campaign_mode: str,
    coverage_to: str,
    require_stage_receipts: bool = True,
    alias_class_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a content-addressed inventory without promoting candidates to CVEs."""
    try:
        return detector_inventory_builder.build_detector_inventory(
            results,
            alias_map=alias_map,
            adjudicated_positive_ids=adjudicated_positive_ids,
            audit_exclusions=audit_exclusions,
            published_ids=published_ids,
            generated_at=generated_at,
            source_snapshot_sha256=source_snapshot_sha256,
            source_receipt_sha256=source_receipt_sha256,
            campaign_id=campaign_id,
            contract_sha256=contract_sha256,
            campaign_mode=campaign_mode,
            coverage_to=coverage_to,
            require_stage_receipts=require_stage_receipts,
            alias_class_manifest=alias_class_manifest,
        )
    except detector_inventory_builder.DetectorInventoryError as exc:
        raise ReleaseGateError(str(exc)) from exc


def _build_publication(
    results: tuple[CveAnalysisResult, ...],
    *,
    alias_map: dict[str, set[str]],
    nvd_dates: dict[str, str],
    ghsa_severities: dict[str, str],
    coverage_since: str,
    inventory_context: dict[str, Any] | None = None,
) -> BuiltPublication:
    audit_overrides = load_audit_overrides(alias_map)
    adjudicated_positive_ids = load_adjudicated_positive_ids(alias_map)
    override_details = load_audit_override_details(alias_map)
    audit_exclusions = load_audit_exclusions(alias_map)
    selected = _select_publication_results(
        results,
        adjudicated_positive_ids=adjudicated_positive_ids,
        audit_exclusions=audit_exclusions,
    )

    quarantine = QuarantineLog()
    entries = [
        entry
        for entry in (
            build_entry(
                result,
                nvd_dates,
                ghsa_severities,
                {},
                audit_overrides,
                override_details,
                quarantine=quarantine,
            )
            for result in selected
        )
        if entry is not None
    ]
    for entry in entries:
        if not entry.get("ai_tools") and entry["id"] in audit_overrides:
            detail = override_details.get(entry["id"], {})
            tools = detail.get("tools")
            if isinstance(tools, list):
                entry["ai_tools"] = tools
    entries = [
        entry
        for entry in entries
        if entry.get("ai_tools") or entry["id"] in audit_overrides
    ]
    entries = _deduplicate_alias_entries(entries, alias_map)
    entries.sort(
        key=lambda entry: (
            any(
                (
                    bug_commit.get("screening_verification")
                    or bug_commit.get("llm_verdict")
                    or {}
                ).get("verdict")
                == "CONFIRMED"
                for bug_commit in entry.get("bug_commits", [])
            ),
            entry.get("confidence", 0),
        ),
        reverse=True,
    )

    total_analyzed, with_fix_commits = _coverage_counts(
        results,
        nvd_dates,
        coverage_since,
    )
    stats = build_stats(
        entries,
        total_analyzed=total_analyzed,
        with_fix_commits=with_fix_commits,
        coverage_since=coverage_since,
    )
    inventory = None
    if inventory_context is not None:
        inventory = _build_detector_inventory(
            results,
            alias_map=alias_map,
            adjudicated_positive_ids=adjudicated_positive_ids,
            audit_exclusions=audit_exclusions,
            published_ids={entry["id"] for entry in entries},
            **inventory_context,
        )
        stats["inventory"] = _inventory_summary(inventory)
    return BuiltPublication(
        entries=entries,
        stats=stats,
        quarantine=quarantine,
        inventory=inventory,
    )


def _campaign_batch_artifacts(context: Any) -> list[dict[str, Any]]:
    """Bind each logical batch to its exact bytes and command contract."""

    artifacts: list[dict[str, Any]] = []
    for batch in context.batches:
        batch_path = Path(batch.path).resolve()
        content, _ = _stable_regular_file(batch_path, "fixed campaign batch")
        expected_batch_content = ("\n".join(batch.ids) + "\n").encode("utf-8")
        if content != expected_batch_content:
            raise ReleaseGateError(
                f"fixed campaign batch bytes do not exactly match IDs: {batch.key}"
            )
        marker_path = Path(context.marker_dir).resolve() / f"{batch.key}.json"
        marker_content, _ = _stable_regular_file(
            marker_path, "fixed campaign completion marker"
        )
        artifacts.append(
            {
                "key": batch.key,
                "path": str(batch_path),
                "ids": list(batch.ids),
                "class_ids": list(getattr(batch, "class_ids", ())),
                "command": list(batch.command),
                "batch_sha256": hashlib.sha256(content).hexdigest(),
                "command_sha256": _canonical_sha256(list(batch.command)),
                "batch_bytes_base64": base64.b64encode(content).decode("ascii"),
                "marker_bytes_base64": base64.b64encode(marker_content).decode("ascii"),
            }
        )
    return artifacts


def _context_fingerprint(context: Any) -> str:
    return _canonical_sha256(
        {
            "campaign_id": context.campaign_id,
            "repo_root": str(Path(context.repo_root).resolve()),
            "marker_dir": str(Path(context.marker_dir).resolve()),
            "result_dir": str(Path(context.result_dir).resolve()),
            "contract_sha256": context.contract_sha256,
            "source_snapshot_sha256": context.source_snapshot_sha256,
            "source_snapshot": context.source_snapshot,
            "model": context.model,
            "reasoning_effort": context.reasoning_effort,
            "workers": context.workers,
            "marker_schema_version": context.marker_schema_version,
            "litellm_transport_sha256": context.litellm_transport_sha256,
            "litellm_transport": context.litellm_transport,
            "batch_timeout_seconds": context.batch_timeout_seconds,
            "campaign_mode": getattr(context, "campaign_mode", "incremental"),
            "population_policy": getattr(context, "population_policy", "incremental"),
            "analyzer_contract_sha256": getattr(
                context, "analyzer_contract_sha256", ""
            ),
            "signature_sha256": getattr(context, "signature_sha256", ""),
            "alias_class_manifest_sha256": getattr(
                context, "alias_class_manifest_sha256", ""
            ),
            "batches": _campaign_batch_artifacts(context),
        }
    )


def _release_input_hashes() -> dict[str, str]:
    _require_current_publication_adjudications()
    paths = (
        _ADJUDICATIONS_PATH,
        _BASE_ADJUDICATIONS_PATH,
        _PUBLICATION_ADJUDICATIONS_BUILDER_PATH,
        _PUBLICATION_ADMISSION_HELPER_PATH,
        _FP211_FINAL_PATH,
        _FP211_MANIFEST_PATH,
        _FP211_PUBLIC_CASES_PATH,
        _AUDIT_OVERRIDES_PATH,
        _SCRIPT_DIR / "generate_web_data.py",
        _SCRIPT_DIR / "build_recall_audit.py",
        _SCRIPT_DIR / "evaluate_detector_quality.py",
        _SCRIPT_DIR / "evaluate_publication_quality.py",
        _SCRIPT_DIR / "heldout_quality_gate.py",
        _SCRIPT_DIR / "web_data" / "release_evidence.py",
        _SCRIPT_DIR / "web_data" / "inventory.py",
        _SCRIPT_DIR / "web_data" / "schema.py",
        _SCRIPT_DIR / "web_data" / "verifier_contract.py",
        _SCRIPT_DIR / "web_data" / "writer.py",
    )
    hashes: dict[str, str] = {}
    for path in paths:
        content, _ = _stable_regular_file(path, "release-gate input")
        hashes[path.relative_to(_REPO_ROOT).as_posix()] = hashlib.sha256(
            content
        ).hexdigest()
    return hashes


def _require_current_publication_adjudications() -> None:
    checked = subprocess.run(
        [
            sys.executable,
            str(_PUBLICATION_ADJUDICATIONS_BUILDER_PATH),
            "--output",
            str(_ADJUDICATIONS_PATH),
            "--check",
        ],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if checked.returncode != 0:
        detail = (checked.stdout or checked.stderr).strip()
        raise ReleaseGateError(
            f"effective publication adjudications are stale: {detail}"
        )


def _publication_file_manifest(root: Path) -> tuple[dict[str, Any], ...]:
    root = Path(root)
    paths = [root / "index.json", root / "stats.json"]
    if (root / "inventory.json").exists():
        paths.append(root / "inventory.json")
    paths.extend(sorted((root / "cves").glob("*.json")))
    manifest: list[dict[str, Any]] = []
    for path in paths:
        content, metadata = _stable_regular_file(path, "staged publication artifact")
        manifest.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size_bytes": metadata.st_size,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return tuple(manifest)


def _publication_curation_inputs_artifact(
    *,
    adjudications: publication_quality.AdjudicationCorpus,
    alias_map: dict[str, set[str]],
    publication_root: Path,
) -> dict[str, Any]:
    """Archive the exact semantic inputs consumed by the curation evaluator."""

    adjudication_bytes, _ = _stable_regular_file(
        _ADJUDICATIONS_PATH, "publication adjudications"
    )
    index_bytes, _ = _stable_regular_file(
        Path(publication_root) / "index.json", "staged publication index"
    )
    try:
        index_payload = json.loads(index_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseGateError("staged publication index is invalid JSON") from exc
    published_ordered_ids = index_payload.get("ids")
    if (
        not isinstance(published_ordered_ids, list)
        or any(
            not isinstance(value, str) or not value for value in published_ordered_ids
        )
        or len(published_ordered_ids) != len(set(published_ordered_ids))
    ):
        raise ReleaseGateError("staged publication index IDs are invalid")
    alias_classes = [
        {"subject_id": subject_id, "aliases": sorted(subject_ids)}
        for subject_id, subject_ids in sorted(alias_map.items())
    ]
    normalized_adjudications = [
        {
            "canonical_id": entry.canonical_id,
            "label": entry.label,
            "subject_ids": sorted(entry.subject_ids),
        }
        for entry in sorted(adjudications.entries, key=lambda item: item.canonical_id)
    ]
    return {
        "schema_version": 1,
        "adjudications_path": str(Path(_ADJUDICATIONS_PATH).resolve()),
        "adjudications_sha256": hashlib.sha256(adjudication_bytes).hexdigest(),
        "adjudications_bytes_base64": base64.b64encode(adjudication_bytes).decode(
            "ascii"
        ),
        "alias_classes": alias_classes,
        "alias_classes_sha256": _canonical_sha256(alias_classes),
        "normalized_adjudications": normalized_adjudications,
        "normalized_adjudications_sha256": _canonical_sha256(normalized_adjudications),
        "publication_index_sha256": hashlib.sha256(index_bytes).hexdigest(),
        "publication_index_bytes_base64": base64.b64encode(index_bytes).decode("ascii"),
        "published_ordered_ids": published_ordered_ids,
        "published_ordered_ids_sha256": _canonical_sha256(published_ordered_ids),
    }


def _campaign_contract_artifact(context: Any) -> dict[str, Any]:
    """Serialize the exact logical campaign contract used by release proof."""
    return {
        "schema_version": 2,
        "campaign_id": context.campaign_id,
        "repo_root": str(Path(context.repo_root).resolve()),
        "marker_dir": str(Path(context.marker_dir).resolve()),
        "result_dir": str(Path(context.result_dir).resolve()),
        "contract_sha256": context.contract_sha256,
        "source_snapshot_sha256": context.source_snapshot_sha256,
        "model": context.model,
        "reasoning_effort": context.reasoning_effort,
        "workers": context.workers,
        "no_token_child_processes": context.no_token_child_processes,
        "no_token_total_workers": context.no_token_total_workers,
        "marker_schema_version": context.marker_schema_version,
        "litellm_transport_sha256": context.litellm_transport_sha256,
        "litellm_transport": context.litellm_transport,
        "batch_timeout_seconds": context.batch_timeout_seconds,
        "campaign_mode": getattr(context, "campaign_mode", "incremental"),
        "population_policy": getattr(context, "population_policy", "incremental"),
        "analyzer_contract_sha256": getattr(context, "analyzer_contract_sha256", ""),
        "signature_sha256": getattr(context, "signature_sha256", ""),
        "alias_class_manifest_sha256": getattr(
            context, "alias_class_manifest_sha256", ""
        ),
        "alias_class_manifest": getattr(context, "alias_class_manifest", None),
        "incremental_plan_proof": getattr(context, "incremental_plan_proof", None),
        "batches": _campaign_batch_artifacts(context),
    }


def _heldout_campaign_population_artifact(
    context: Any,
    campaign_snapshot: CampaignResultSnapshot,
    selection: dict[str, Any],
    alias_map: dict[str, set[str]],
) -> dict[str, Any]:
    """Archive the complete raw campaign and every protected selection input."""

    manifest = list(campaign_snapshot.manifest)
    if not manifest:
        raise ReleaseGateError("held-out campaign result inventory is empty")

    result_root = Path(context.result_dir).resolve()
    archived: list[dict[str, Any]] = []
    total_result_bytes = 0
    for manifest_entry in manifest:
        subject_id = manifest_entry.get("subject_id")
        expected_sha256 = manifest_entry.get("sha256")
        if (
            not isinstance(subject_id, str)
            or _PUBLIC_ID.fullmatch(subject_id) is None
            or not isinstance(expected_sha256, str)
            or _SHA256.fullmatch(expected_sha256) is None
        ):
            raise ReleaseGateError("held-out campaign result manifest is invalid")
        path = result_root / f"{subject_id}.json"
        content, metadata = _stable_regular_file(
            path,
            f"held-out campaign result {subject_id}",
            max_bytes=_MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES,
        )
        total_result_bytes += len(content)
        if total_result_bytes > _MAX_ARCHIVED_CAMPAIGN_RESULTS_TOTAL_BYTES:
            raise ReleaseGateError(
                "held-out campaign results exceed archive size bound"
            )
        sha256 = hashlib.sha256(content).hexdigest()
        if (
            sha256 != expected_sha256
            or manifest_entry.get("file_name") != path.name
            or manifest_entry.get("size_bytes") != metadata.st_size
        ):
            raise ReleaseGateError(
                f"held-out campaign result changed before archive: {subject_id}"
            )
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ReleaseGateError(
                f"held-out campaign result is invalid JSON: {subject_id}"
            ) from exc
        if not isinstance(payload, dict) or payload.get("cve_id") != subject_id:
            raise ReleaseGateError(
                f"held-out campaign result identity mismatch: {subject_id}"
            )
        archived.append(
            {
                "subject_id": subject_id,
                "source_path": str(path),
                "file_name": path.name,
                "archive_path": f"campaign-results/{path.name}",
                "size_bytes": metadata.st_size,
                "sha256": sha256,
            }
        )

    protected_contract = selection.get("protected_inputs")
    if not isinstance(protected_contract, dict):
        raise ReleaseGateError("held-out protected input contract is missing")
    source_roots = protected_contract.get("source_roots")
    protected_manifest = protected_contract.get("files")
    if not isinstance(source_roots, list) or not isinstance(protected_manifest, list):
        raise ReleaseGateError("held-out protected input contract is malformed")
    repo_root = Path(context.repo_root).resolve()
    protected_files: list[dict[str, Any]] = []
    total_protected_bytes = 0
    for expected in protected_manifest:
        if not isinstance(expected, dict):
            raise ReleaseGateError("held-out protected input manifest is malformed")
        relative = expected.get("path")
        candidate = PurePosixPath(relative) if isinstance(relative, str) else None
        if (
            candidate is None
            or candidate.is_absolute()
            or any(part in {"", ".", ".."} for part in candidate.parts)
        ):
            raise ReleaseGateError("held-out protected input path is unsafe")
        path = repo_root.joinpath(*candidate.parts)
        try:
            path.resolve(strict=False).relative_to(repo_root)
        except ValueError as exc:
            raise ReleaseGateError(
                "held-out protected input path escapes the repository"
            ) from exc
        content, metadata = _stable_regular_file(
            path,
            f"held-out protected input {relative}",
            max_bytes=_MAX_ARCHIVED_PROTECTED_INPUT_BYTES,
        )
        total_protected_bytes += len(content)
        if total_protected_bytes > _MAX_ARCHIVED_PROTECTED_INPUTS_TOTAL_BYTES:
            raise ReleaseGateError(
                "held-out protected inputs exceed archive size bound"
            )
        referenced_ids = sorted(
            heldout_quality._extract_subject_tokens(content, candidate)
        )
        sha256 = hashlib.sha256(content).hexdigest()
        if expected != {
            "path": relative,
            "size_bytes": metadata.st_size,
            "sha256": sha256,
            "referenced_subject_count": len(referenced_ids),
            "referenced_subject_ids_sha256": _canonical_sha256(referenced_ids),
        }:
            raise ReleaseGateError(
                f"held-out protected input changed before archive: {relative}"
            )
        protected_files.append(
            {
                **expected,
                "bytes_base64": base64.b64encode(content).decode("ascii"),
            }
        )

    alias_classes = sorted(
        {tuple(sorted(component)) for component in alias_map.values() if component}
    )
    alias_rows = [{"subject_ids": list(component)} for component in alias_classes]
    return {
        "schema_version": 1,
        "campaign_id": context.campaign_id,
        "result_dir": str(result_root),
        "result_count": len(archived),
        "total_result_size_bytes": total_result_bytes,
        "result_manifest_sha256": campaign_snapshot.manifest_sha256,
        "results": archived,
        "alias_classes": alias_rows,
        "alias_classes_sha256": _canonical_sha256(alias_rows),
        "protected_inputs": {
            "source_roots": source_roots,
            "file_count": len(protected_files),
            "total_size_bytes": total_protected_bytes,
            "files_manifest_sha256": protected_contract.get("files_manifest_sha256"),
            "files": protected_files,
        },
    }


def _release_evidence_artifacts(
    *,
    context: Any,
    campaign_snapshot: CampaignResultSnapshot,
    publication_manifest: tuple[dict[str, Any], ...],
    publication_hash: str,
    detector_report: dict[str, Any],
    detector_inventory: dict[str, Any],
    heldout_selection: dict[str, Any],
    heldout_labels: dict[str, Any],
    heldout_campaign_population: dict[str, Any],
    curation_report: dict[str, Any],
    curation_inputs: dict[str, Any],
    heldout_report: dict[str, Any],
    recall_selection: dict[str, Any],
    recall_labels: dict[str, Any],
    recall_report: dict[str, Any],
    verifier_contract: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return every full proof artifact required by the evidence contract."""
    source_remote_cutoff = context.source_snapshot.get("remote_cutoff")
    if not isinstance(source_remote_cutoff, dict):
        raise ReleaseGateError("fixed campaign source remote cutoff is missing")
    return {
        "campaign-contract.json": _campaign_contract_artifact(context),
        "campaign-result-manifest.json": {
            "schema_version": 1,
            "campaign_id": context.campaign_id,
            "result_count": len(campaign_snapshot.manifest),
            "manifest_sha256": campaign_snapshot.manifest_sha256,
            "results": list(campaign_snapshot.manifest),
        },
        "detector-report.json": detector_report,
        "detector-inventory.json": detector_inventory,
        "heldout-selection.json": heldout_selection,
        "heldout-labels.json": heldout_labels,
        "heldout-campaign-population.json": heldout_campaign_population,
        "publication-manifest.json": {
            "schema_version": 1,
            "generation_id": receipt["generation_id"],
            "publication_bundle_sha256": publication_hash,
            "manifest_sha256": _canonical_sha256(publication_manifest),
            "files": list(publication_manifest),
        },
        "publication-curation-consistency-report.json": curation_report,
        "publication-curation-inputs.json": curation_inputs,
        "heldout-quality-report.json": heldout_report,
        "recall-selection.json": recall_selection,
        "recall-labels.json": recall_labels,
        "recall-report.json": recall_report,
        "release-receipt.json": receipt,
        "source-remote-cutoff.json": source_remote_cutoff,
        "source-snapshot.json": context.source_snapshot,
        "verifier-contract.json": verifier_contract,
    }


def _refresh_context() -> detector_quality.FixedCampaignProofContext:
    try:
        return detector_quality._current_fixed_campaign_context(_REPO_ROOT)
    except (OSError, UnicodeError, ValueError, refresh_runner.RunnerError) as exc:
        raise ReleaseGateError(
            f"current fixed campaign context is invalid: {exc}"
        ) from exc


def _generate_release_locked(
    *,
    output_dir: Path,
    coverage_since: str,
    precision_target: float,
    recall_target: float,
    heldout_selection_path: Path,
    heldout_labels_path: Path,
    recall_selection_path: Path,
    recall_labels_path: Path,
    recall_report_path: Path,
    cache_dir: Path | None = None,
    evidence_root: Path | None = None,
    trusted_repo_root: Path | None = None,
) -> tuple[dict, dict, dict, dict]:
    """Build, gate, receipt, and promote one formal Website release."""
    _validate_release_targets(precision_target, recall_target)
    try:
        verifier_repo_root = (
            _REPO_ROOT
            if trusted_repo_root is None
            else Path(trusted_repo_root).resolve(strict=True)
        )
    except OSError as exc:
        raise ReleaseGateError(
            f"trusted release repository is unavailable: {exc}"
        ) from exc
    initial_context = _refresh_context()
    try:
        campaign_repo_root = Path(initial_context.repo_root).resolve(strict=True)
    except OSError as exc:
        raise ReleaseGateError(
            f"fixed campaign repository is unavailable: {exc}"
        ) from exc
    if campaign_repo_root != verifier_repo_root:
        raise ReleaseGateError(
            "fixed campaign repository does not match the trusted release repository"
        )
    try:
        verifier_contract = verifier_contract_builder.build_verifier_contract(
            verifier_repo_root
        )
    except verifier_contract_builder.VerifierContractError as exc:
        raise ReleaseGateError(f"formal verifier contract is invalid: {exc}") from exc
    initial_plan_proof = getattr(initial_context, "incremental_plan_proof", None)
    initial_alias_manifest = getattr(initial_context, "alias_class_manifest", None)
    initial_alias_classes = (
        initial_alias_manifest.get("classes")
        if isinstance(initial_alias_manifest, dict)
        else None
    )
    if (
        getattr(initial_context, "campaign_mode", None) != "formal"
        or getattr(initial_context, "population_policy", None) != "formal_full"
        or not isinstance(initial_plan_proof, dict)
        or initial_plan_proof.get("formal_release_eligible") is not True
        or initial_plan_proof.get("scope") != "formal_current_source_alias_class_plan"
        or not isinstance(initial_alias_manifest, dict)
        or not isinstance(initial_alias_classes, list)
        or initial_alias_manifest.get("classes_sha256")
        != getattr(initial_context, "alias_class_manifest_sha256", None)
        or hashlib.sha256(
            refresh_runner._canonical_json_bytes(initial_alias_classes)
        ).hexdigest()
        != initial_alias_manifest.get("classes_sha256")
    ):
        raise ReleaseGateError(
            "formal release requires a complete persisted formal alias-class plan"
        )
    initial_context_fingerprint = _context_fingerprint(initial_context)
    if (
        cache_dir is not None
        and Path(cache_dir).resolve() != Path(initial_context.result_dir).resolve()
    ):
        raise ReleaseGateError(
            "--cache-dir must name the current content-addressed campaign result directory"
        )
    campaign_snapshot = _load_exact_campaign_results(initial_context)
    release_input_hashes = _release_input_hashes()

    runner_paths = refresh_runner.RunnerPaths.defaults(_REPO_ROOT)
    if evidence_root is None:
        evidence_root = runner_paths.state_dir.parent / "release-evidence-v1"
    ghsa_advisories_dir = runner_paths.ghsa_dir / "advisories"
    alias_map = _strict_build_alias_map(
        ghsa_advisories_dir,
        runner_paths.osv_bulk_dir,
    )
    (
        heldout_selection,
        heldout_labels,
        heldout_report,
        _heldout_campaign,
    ) = _evaluate_heldout_quality_inputs(
        selection_path=heldout_selection_path,
        labels_path=heldout_labels_path,
        alias_map=alias_map,
        context=initial_context,
        precision_target=precision_target,
        recall_target=recall_target,
    )
    heldout_selection_sha256 = _canonical_sha256(heldout_selection)
    heldout_labels_sha256 = _canonical_sha256(heldout_labels)
    heldout_report_sha256 = _canonical_sha256(heldout_report)
    heldout_campaign_population = _heldout_campaign_population_artifact(
        initial_context,
        campaign_snapshot,
        heldout_selection,
        alias_map,
    )
    heldout_campaign_population_sha256 = _canonical_sha256(heldout_campaign_population)
    nvd_dates = load_nvd_published_dates(str(runner_paths.nvd_feeds_dir))
    ghsa_dates = load_ghsa_published_dates(str(ghsa_advisories_dir))
    for advisory_id, published in ghsa_dates.items():
        nvd_dates.setdefault(advisory_id, published)
    ghsa_severities = load_ghsa_severities(str(ghsa_advisories_dir))
    generated_at = datetime.now(timezone.utc).isoformat()
    source_remote_cutoff = initial_context.source_snapshot.get("remote_cutoff")
    if not isinstance(source_remote_cutoff, dict):
        raise ReleaseGateError("fixed campaign source remote cutoff is missing")
    plan_proof = getattr(initial_context, "incremental_plan_proof", {})
    campaign_mode = getattr(initial_context, "campaign_mode", None)
    if campaign_mode not in {"formal", "incremental"} and isinstance(plan_proof, dict):
        campaign_mode = plan_proof.get("campaign_mode") or plan_proof.get(
            "population_mode"
        )
    if campaign_mode not in {"formal", "incremental"}:
        proof_scope = (
            str(plan_proof.get("scope", "")) if isinstance(plan_proof, dict) else ""
        )
        campaign_mode = (
            "formal"
            if "formal" in proof_scope and "incremental" not in proof_scope
            else "incremental"
        )
    cutoff_timestamp = _inventory_generated_at(source_remote_cutoff)
    coverage_to = cutoff_timestamp[:10]
    alias_class_manifest = getattr(initial_context, "alias_class_manifest", None)
    if campaign_mode == "formal" and not isinstance(alias_class_manifest, dict):
        raise ReleaseGateError(
            "formal release requires the persisted alias-class manifest"
        )
    built = _build_publication(
        campaign_snapshot.results,
        alias_map=alias_map,
        nvd_dates=nvd_dates,
        ghsa_severities=ghsa_severities,
        coverage_since=coverage_since,
        inventory_context={
            # Inventory identity must be reproducible before independent recall
            # labels exist. The fixed source cutoff is stable; release wall-clock
            # time is intentionally reserved for the publication generation.
            "generated_at": cutoff_timestamp,
            "source_snapshot_sha256": initial_context.source_snapshot_sha256,
            "source_receipt_sha256": _canonical_sha256(source_remote_cutoff),
            "campaign_id": initial_context.campaign_id,
            "contract_sha256": initial_context.contract_sha256,
            "campaign_mode": campaign_mode,
            "coverage_to": coverage_to,
            "require_stage_receipts": True,
            "alias_class_manifest": alias_class_manifest,
        },
    )
    if built.inventory is not None and (
        built.inventory.get("campaign_mode") != "formal"
        or built.inventory.get("complete") is not True
    ):
        raise ReleaseGateError(
            "formal release requires a complete formal detector inventory"
        )
    if built.inventory is None:
        raise ReleaseGateError("formal release detector inventory is missing")
    recall_selection, recall_labels, recall_report = _evaluate_recall_audit_inputs(
        selection_path=recall_selection_path,
        labels_path=recall_labels_path,
        report_path=recall_report_path,
        inventory=built.inventory,
        alias_map=alias_map,
        repo_root=verifier_repo_root,
    )
    recall_selection_sha256 = _canonical_sha256(recall_selection)
    recall_labels_sha256 = _canonical_sha256(recall_labels)
    recall_report_sha256 = _canonical_sha256(recall_report)
    staged: StagedWebData | None = None
    staged_candidate_identity: tuple[int, int] | None = None
    try:
        staged = stage_web_data(
            built.entries,
            built.stats,
            Path(output_dir),
            generated_at=generated_at,
            inventory=built.inventory,
        )
        staged_metadata = staged.staging_dir.stat(follow_symlinks=False)
        staged_candidate_identity = (staged_metadata.st_dev, staged_metadata.st_ino)
        publication = load_published_web_data(staged.staging_dir)
        publication_hash = publication_bundle_sha256(publication)
        publication_manifest = _publication_file_manifest(staged.staging_dir)
        publication_manifest_sha256 = _canonical_sha256(publication_manifest)
        published_ids = {entry["id"] for entry in publication.entries}
        publication_provenance = {
            "directory": str(Path(output_dir).resolve()),
            "bundle_sha256": publication_hash,
            "ordered_ids": publication.index["ids"],
            "ordered_ids_sha256": _canonical_sha256(publication.index["ids"]),
        }

        detector_report = detector_quality.build_report(
            adjudications_path=_ADJUDICATIONS_PATH,
            cache_dir=Path(initial_context.result_dir),
            alias_map=alias_map,
            published_ids=published_ids,
            publication_provenance=publication_provenance,
            alias_source_provenance={
                "source_snapshot_sha256": initial_context.source_snapshot_sha256,
                "ghsa_advisories_dir": str(ghsa_advisories_dir.resolve()),
                "osv_bulk_dir": str(runner_paths.osv_bulk_dir.resolve()),
            },
            fixed_campaign_context=initial_context,
            detector_inventory=built.inventory,
        )
        adjudications = publication_quality.load_adjudications(
            _ADJUDICATIONS_PATH,
            alias_map=alias_map,
        )
        curation_report = publication_quality.evaluate(
            adjudications,
            published_ids,
            precision_target=precision_target,
            recall_target=recall_target,
        )
        curation_inputs = _publication_curation_inputs_artifact(
            adjudications=adjudications,
            alias_map=alias_map,
            publication_root=staged.staging_dir,
        )
        _require_release_gates(
            detector_report,
            curation_report,
            heldout_report,
            recall_report,
            precision_target=precision_target,
            recall_target=recall_target,
        )

        fixed_proof = detector_report["fixed_contract_campaign_proof"]
        detector_inventory_report = detector_report.get("detector_inventory")
        if not isinstance(detector_inventory_report, dict):
            raise ReleaseGateError("detector inventory report is missing")
        stage_metrics = detector_inventory_report.get("stage_metrics")
        stage_quality_gate = detector_inventory_report.get("stage_quality_gate")
        if not isinstance(stage_metrics, dict) or not isinstance(stage_quality_gate, dict):
            raise ReleaseGateError("detector stage evidence is missing")
        receipt = {
            "schema_version": 5,
            "generation_id": publication.index["generation_id"],
            "generated_at": generated_at,
            "campaign_id": initial_context.campaign_id,
            "campaign_mode": campaign_mode,
            "population_policy": initial_context.population_policy,
            "campaign_result_dir": str(Path(initial_context.result_dir).resolve()),
            "campaign_result_count": len(campaign_snapshot.results),
            "campaign_result_manifest_sha256": campaign_snapshot.manifest_sha256,
            "campaign_contract_sha256": _canonical_sha256(
                _campaign_contract_artifact(initial_context)
            ),
            "source_snapshot_sha256": initial_context.source_snapshot_sha256,
            "analyzer_contract_sha256": (initial_context.analyzer_contract_sha256),
            "signature_sha256": initial_context.signature_sha256,
            "alias_class_manifest_sha256": (
                initial_context.alias_class_manifest_sha256
            ),
            "source_remote_cutoff": source_remote_cutoff,
            "contract_sha256": initial_context.contract_sha256,
            "litellm_transport_sha256": initial_context.litellm_transport_sha256,
            "release_input_hashes": release_input_hashes,
            "publication_bundle_sha256": publication_hash,
            "publication_manifest_sha256": publication_manifest_sha256,
            "detector_report_sha256": _canonical_sha256(detector_report),
            "detector_stage_metrics_sha256": _canonical_sha256(stage_metrics),
            "detector_stage_quality_gate_sha256": _canonical_sha256(
                stage_quality_gate
            ),
            "detector_stage_quality_gate_passed": stage_quality_gate.get("passed")
            is True,
            "fixed_campaign_proof_sha256": _canonical_sha256(fixed_proof),
            "publication_curation_consistency_report_sha256": _canonical_sha256(
                curation_report
            ),
            "publication_curation_inputs_sha256": _canonical_sha256(curation_inputs),
            "heldout_quality_report_sha256": heldout_report_sha256,
            "heldout_selection_sha256": heldout_selection_sha256,
            "heldout_labels_sha256": heldout_labels_sha256,
            "heldout_campaign_population_sha256": (heldout_campaign_population_sha256),
            "heldout_campaign_proof_sha256": heldout_report["campaign"][
                "campaign_proof_sha256"
            ],
            "heldout_campaign_result_manifest_sha256": heldout_report["campaign"][
                "campaign_result_manifest_sha256"
            ],
            "recall_selection_sha256": recall_selection_sha256,
            "recall_labels_sha256": recall_labels_sha256,
            "recall_report_sha256": recall_report_sha256,
            "recall_inventory_id": built.inventory["inventory_id"],
            "recall_selection_manifest_sha256": recall_report[
                "selection_manifest_sha256"
            ],
            "protected_census_manifest_sha256": recall_report[
                "protected_census_manifest_sha256"
            ],
            "protected_overlap_class_count": recall_report[
                "protected_overlap_class_count"
            ],
            "protected_census_complete": recall_report["protected_census_complete"],
            "recall_evaluation_status": "complete_end_to_end",
            "recall_evaluation_complete": True,
            "recall_point_estimate": recall_report["recall"]["recall_point"],
            "recall_interval": recall_report["recall"]["recall_interval"],
            "verifier_contract_sha256": _canonical_sha256(verifier_contract),
            "verifier_git_commit": verifier_contract["git_commit"],
            "verifier_git_tree": verifier_contract["git_tree"],
            "verifier_files_manifest_sha256": verifier_contract[
                "files_manifest_sha256"
            ],
            "verifier_dependency_lock_sha256": verifier_contract[
                "dependency_lock_sha256"
            ],
            "evaluation_complete": True,
            "release_safe": True,
            "curation_consistent": True,
            "heldout_certified": True,
            "targets": {
                "precision": float(precision_target),
                "recall": float(recall_target),
            },
            "curation_consistency_point_estimates": {
                "precision": curation_report["curation_precision"]["point"],
                "recall": curation_report["curation_recall"]["point"],
            },
            "heldout_point_estimates": {
                "precision": heldout_report["precision"]["point"],
                "recall": heldout_report["recall"]["point"],
            },
            "heldout_measurement_boundary": heldout_report["measurement_boundary"],
            "model": initial_context.model,
            "reasoning_effort": initial_context.reasoning_effort,
            "workers": initial_context.workers,
            "no_token_child_processes": (
                initial_context.no_token_child_processes
            ),
            "no_token_total_workers": initial_context.no_token_total_workers,
        }
        if built.inventory is not None:
            receipt.update(
                {
                    "detector_inventory_id": built.inventory["inventory_id"],
                    "detector_inventory_sha256": _canonical_sha256(built.inventory),
                    "detector_inventory_campaign_mode": built.inventory[
                        "campaign_mode"
                    ],
                    "detector_inventory_complete": built.inventory["complete"],
                    "detector_inventory_source_snapshot_sha256": built.inventory[
                        "source_snapshot_sha256"
                    ],
                    "detector_inventory_alias_class_manifest_sha256": (
                        built.inventory["source_alias_class_manifest_sha256"]
                    ),
                    "detector_inventory_alias_class_count": built.inventory[
                        "alias_class_count"
                    ],
                }
            )

        detector_report_sha256 = receipt["detector_report_sha256"]

        def require_unchanged_release_inputs(
            phase: str,
            *,
            publication_root: Path,
        ) -> None:
            try:
                current_verifier_contract = (
                    verifier_contract_builder.build_verifier_contract(
                        verifier_repo_root,
                        git_commit=verifier_contract["git_commit"],
                    )
                )
            except verifier_contract_builder.VerifierContractError as exc:
                raise ReleaseGateError(
                    f"formal verifier contract changed {phase}: {exc}"
                ) from exc
            if current_verifier_contract != verifier_contract:
                raise ReleaseGateError(f"formal verifier contract changed {phase}")
            current_context = _refresh_context()
            if _context_fingerprint(current_context) != initial_context_fingerprint:
                raise ReleaseGateError(f"fixed campaign context changed {phase}")
            current_snapshot = _load_exact_campaign_results(current_context)
            if current_snapshot.manifest_sha256 != campaign_snapshot.manifest_sha256:
                raise ReleaseGateError(f"campaign result inventory changed {phase}")
            if _release_input_hashes() != release_input_hashes:
                raise ReleaseGateError(f"release-gate inputs changed {phase}")
            (
                current_heldout_selection,
                current_heldout_labels,
                current_heldout_report,
                current_heldout_campaign,
            ) = _evaluate_heldout_quality_inputs(
                selection_path=heldout_selection_path,
                labels_path=heldout_labels_path,
                alias_map=alias_map,
                context=current_context,
                precision_target=precision_target,
                recall_target=recall_target,
            )
            if (
                _canonical_sha256(current_heldout_selection) != heldout_selection_sha256
                or _canonical_sha256(current_heldout_labels) != heldout_labels_sha256
                or _canonical_sha256(current_heldout_report) != heldout_report_sha256
                or current_heldout_campaign.campaign_result_manifest_sha256
                != _heldout_campaign.campaign_result_manifest_sha256
            ):
                raise ReleaseGateError(
                    f"held-out evidence or protected inventory changed {phase}"
                )
            (
                current_recall_selection,
                current_recall_labels,
                current_recall_report,
            ) = _evaluate_recall_audit_inputs(
                selection_path=recall_selection_path,
                labels_path=recall_labels_path,
                report_path=recall_report_path,
                inventory=built.inventory,
                alias_map=alias_map,
                repo_root=verifier_repo_root,
            )
            if (
                _canonical_sha256(current_recall_selection) != recall_selection_sha256
                or _canonical_sha256(current_recall_labels) != recall_labels_sha256
                or _canonical_sha256(current_recall_report) != recall_report_sha256
            ):
                raise ReleaseGateError(f"recall evidence changed {phase}")
            if _canonical_sha256(_publication_file_manifest(publication_root)) != (
                publication_manifest_sha256
            ):
                raise ReleaseGateError(f"publication changed {phase}")

            # Rebuild the detector report so marker deletion, replacement, or
            # result/marker drift cannot occur between evaluation and promotion.
            current_detector_report = detector_quality.build_report(
                adjudications_path=_ADJUDICATIONS_PATH,
                cache_dir=Path(current_context.result_dir),
                alias_map=alias_map,
                published_ids=published_ids,
                publication_provenance=publication_provenance,
                alias_source_provenance={
                    "source_snapshot_sha256": current_context.source_snapshot_sha256,
                    "ghsa_advisories_dir": str(ghsa_advisories_dir.resolve()),
                    "osv_bulk_dir": str(runner_paths.osv_bulk_dir.resolve()),
                },
                fixed_campaign_context=current_context,
                detector_inventory=built.inventory,
            )
            _require_release_gates(
                current_detector_report,
                curation_report,
                heldout_report,
                recall_report,
                precision_target=precision_target,
                recall_target=recall_target,
            )
            if _canonical_sha256(current_detector_report) != detector_report_sha256:
                raise ReleaseGateError(f"detector proof changed {phase}")

        require_unchanged_release_inputs(
            "before receipt",
            publication_root=staged.staging_dir,
        )

        write_staged_release_receipt(staged, receipt)
        require_unchanged_release_inputs(
            "before evidence archive",
            publication_root=staged.staging_dir,
        )
        try:
            evidence = archive_release_evidence(
                root=Path(evidence_root),
                generation_id=receipt["generation_id"],
                generated_at=generated_at,
                trusted_repo_root=verifier_repo_root,
                artifacts=_release_evidence_artifacts(
                    context=initial_context,
                    campaign_snapshot=campaign_snapshot,
                    publication_manifest=publication_manifest,
                    publication_hash=publication_hash,
                    detector_report=detector_report,
                    detector_inventory=built.inventory,
                    heldout_selection=heldout_selection,
                    heldout_labels=heldout_labels,
                    heldout_campaign_population=heldout_campaign_population,
                    curation_report=curation_report,
                    curation_inputs=curation_inputs,
                    heldout_report=heldout_report,
                    recall_selection=recall_selection,
                    recall_labels=recall_labels,
                    recall_report=recall_report,
                    verifier_contract=verifier_contract,
                    receipt=receipt,
                ),
            )
            validate_release_evidence(
                evidence.path,
                expected_generation_id=receipt["generation_id"],
                expected_bundle_sha256=evidence.bundle_sha256,
                trusted_repo_root=verifier_repo_root,
            )
        except ReleaseEvidenceError as exc:
            raise ReleaseGateError(
                f"release-evidence archive failed validation: {exc}"
            ) from exc
        require_unchanged_release_inputs(
            "before promotion",
            publication_root=staged.staging_dir,
        )
        try:
            validate_release_evidence(
                evidence.path,
                expected_generation_id=receipt["generation_id"],
                expected_bundle_sha256=evidence.bundle_sha256,
                trusted_repo_root=verifier_repo_root,
            )
        except ReleaseEvidenceError as exc:
            raise ReleaseGateError(
                f"release-evidence archive changed before promotion: {exc}"
            ) from exc

        activation_bindings = {
            "root": Path(evidence_root),
            "generation_id": receipt["generation_id"],
            "evidence_bundle_sha256": evidence.bundle_sha256,
            "release_receipt_sha256": _canonical_sha256(receipt),
            "publication_bundle_sha256": receipt["publication_bundle_sha256"],
            "publication_manifest_sha256": receipt["publication_manifest_sha256"],
            "output_dir": Path(output_dir),
            "candidate_dir": staged.staging_dir,
        }
        try:
            prepare_release_activation_record(**activation_bindings)
        except ReleaseEvidenceError as exc:
            raise ReleaseGateError(
                f"release activation could not be prepared before promotion: {exc}"
            ) from exc

        try:
            with publication_promotion_transaction(
                staged,
                require_release_receipt=True,
                expected_release_receipt=receipt,
            ) as promotion:
                require_unchanged_release_inputs(
                    "after promotion",
                    publication_root=Path(output_dir),
                )
                promotion_commit = promotion.commit()
                write_release_activation_record(
                    **activation_bindings,
                    promotion_commit=promotion_commit,
                    publication_lock=promotion.parent_lock,
                )
        except BaseException as promotion_error:
            # Any exception after promotion may leave the previous generation at
            # the staging path. Disable generic cleanup before reconciling under
            # the publication lock so that recovery data can never be discarded.
            staged = None
            try:
                reconciled = reconcile_release_activation_record(
                    root=Path(evidence_root),
                    generation_id=receipt["generation_id"],
                )
            except BaseException as reconcile_error:
                if hasattr(promotion_error, "add_note"):
                    promotion_error.add_note(
                        "release activation reconciliation failed; the retained "
                        "generation requires inspection"
                    )
                if isinstance(
                    promotion_error, (KeyboardInterrupt, SystemExit, GeneratorExit)
                ):
                    raise promotion_error from reconcile_error
                raise ReleaseGateError(
                    "release activation and recovery reconciliation both failed; "
                    "the retained generation requires inspection: "
                    f"{reconcile_error}"
                ) from reconcile_error
            if isinstance(promotion_error, ReleaseEvidenceError):
                if reconciled is not None:
                    staged = None
                else:
                    raise ReleaseGateError(
                        "release activation commit was not durable; the candidate "
                        "was atomically rolled back"
                    ) from promotion_error
            else:
                raise
        staged = None
        return receipt, detector_report, curation_report, heldout_report
    finally:
        if staged is not None:
            discard_staged_web_data(
                staged,
                expected_candidate_identity=staged_candidate_identity,
            )


def generate_release(
    *,
    output_dir: Path,
    coverage_since: str,
    precision_target: float,
    recall_target: float,
    heldout_selection_path: Path,
    heldout_labels_path: Path,
    recall_selection_path: Path,
    recall_labels_path: Path,
    recall_report_path: Path,
    cache_dir: Path | None = None,
    evidence_root: Path | None = None,
    trusted_repo_root: Path | None = None,
) -> tuple[dict, dict, dict, dict]:
    """Hold the campaign-global lock throughout proof, staging, and promotion."""

    try:
        verifier_repo_root = (
            _REPO_ROOT
            if trusted_repo_root is None
            else Path(trusted_repo_root).resolve(strict=True)
        )
    except OSError as exc:
        raise ReleaseGateError(
            f"trusted release repository is unavailable: {exc}"
        ) from exc
    runner_paths = refresh_runner.RunnerPaths.defaults(verifier_repo_root)
    with refresh_runner.batch_singleton_lock(
        runner_paths.state_dir,
        refresh_runner.CAMPAIGN_LOCK_KEY,
    ):
        return _generate_release_locked(
            output_dir=output_dir,
            coverage_since=coverage_since,
            precision_target=precision_target,
            recall_target=recall_target,
            heldout_selection_path=heldout_selection_path,
            heldout_labels_path=heldout_labels_path,
            recall_selection_path=recall_selection_path,
            recall_labels_path=recall_labels_path,
            recall_report_path=recall_report_path,
            cache_dir=cache_dir,
            evidence_root=evidence_root,
            trusted_repo_root=verifier_repo_root,
        )


def _release_probability(value: str) -> float:
    try:
        probability = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a probability") from exc
    if not _RELEASE_FLOOR <= probability <= 1.0:
        raise argparse.ArgumentTypeError(f"must be between {_RELEASE_FLOOR:.2f} and 1")
    return probability


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate, evaluate, and atomically promote Web data."
    )
    parser.add_argument("--output-dir", type=Path, default=Path(DEFAULT_OUTPUT_DIR))
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help=(
            "Compatibility assertion only; must equal the current "
            "content-addressed campaign result directory."
        ),
    )
    parser.add_argument("--since", default="2025-05")
    parser.add_argument(
        "--precision-target",
        type=_release_probability,
        default=_RELEASE_FLOOR,
    )
    parser.add_argument(
        "--recall-target",
        type=_release_probability,
        default=_RELEASE_FLOOR,
    )
    parser.add_argument(
        "--heldout-selection",
        type=Path,
        required=True,
        help=("Sealed held-out selection produced before independent labels"),
    )
    parser.add_argument(
        "--heldout-labels",
        type=Path,
        required=True,
        help="Complete independent labels bound to --heldout-selection",
    )
    parser.add_argument(
        "--recall-selection",
        type=Path,
        required=True,
        help="Sealed rejection-stratum recall selection produced before labels",
    )
    parser.add_argument(
        "--recall-labels",
        type=Path,
        required=True,
        help="Independent recall labels bound to --recall-selection",
    )
    parser.add_argument(
        "--recall-report",
        type=Path,
        required=True,
        help="Recall report that must exactly recompute from inventory and labels",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt, detector_report, curation_report, heldout_report = generate_release(
            output_dir=args.output_dir,
            coverage_since=args.since,
            precision_target=args.precision_target,
            recall_target=args.recall_target,
            heldout_selection_path=args.heldout_selection,
            heldout_labels_path=args.heldout_labels,
            recall_selection_path=args.recall_selection,
            recall_labels_path=args.recall_labels,
            recall_report_path=args.recall_report,
            cache_dir=args.cache_dir,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        ReleaseGateError,
        PublishedDataError,
    ) as exc:
        print(f"release blocked: {exc}", file=sys.stderr)
        return 2

    print(
        "Promoted Web data from campaign "
        f"{receipt['campaign_id']} with "
        f"heldout_precision={heldout_report['precision']['point']:.3f}, "
        f"heldout_recall={heldout_report['recall']['point']:.3f}, "
        f"curation_consistent={curation_report['curation_consistent']}, "
        f"detector_complete={detector_report['evaluation_complete']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
