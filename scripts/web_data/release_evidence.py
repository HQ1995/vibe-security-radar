"""Write-once evidence bundles for formal Website data releases."""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import json
import math
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

import heldout_quality_gate as heldout_quality
import build_recall_audit as recall_audit
import evaluate_publication_quality as publication_quality
import evaluate_detector_quality as detector_quality
import run_data_refresh as refresh_runner
from web_data import inventory as detector_inventory_builder
from web_data import verifier_contract as verifier_contract_builder
import web_data.writer as web_writer
import web_data.schema as web_schema

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ALIAS_SUBJECT_ID = re.compile(
    r"[A-Za-z][A-Za-z0-9._:+-]{0,198}-[A-Za-z0-9][A-Za-z0-9._:+-]{0,198}"
)
_SCHEMA_VERSION = 5
_MANIFEST_NAME = "manifest.json"
_ACTIVATION_DIR = "activations"
_PENDING_ACTIVATION_DIR = "pending"
_CURATION_CONFIDENCE_LEVEL = 0.95
_MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES = 32 * 1024 * 1024
# 2026-07-18 pre-campaign measurement: 1,495 results occupied 11.4 MiB
# (mean 7.64 KiB, p95 27.9 KiB, max 1.03 MiB); 27,725 IDs project to
# about 212 MiB.  The 512 MiB ceiling preserves headroom while failing closed.
_MAX_ARCHIVED_CAMPAIGN_RESULTS_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_ARCHIVED_PROTECTED_INPUT_BYTES = 32 * 1024 * 1024
_MAX_ARCHIVED_PROTECTED_INPUTS_TOTAL_BYTES = 128 * 1024 * 1024
_MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES = 256 * 1024 * 1024
_MAX_RELEASE_EVIDENCE_ARTIFACTS_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_RELEASE_EVIDENCE_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_ACTIVATION_RECORD_BYTES = 1024 * 1024
_CAMPAIGN_RESULTS_DIR = "campaign-results"
_TRUSTED_REPO_ROOT = Path(__file__).resolve().parents[2]
# Explicit trusted roots support isolated test/embedding repositories during the
# creating process.  They are never read from bundle bytes and are intentionally
# not persistent: a later process must inject the authority again or use this
# module's own repository root.
_BUNDLE_TRUSTED_REPO_ROOTS: dict[Path, Path] = {}
_REQUIRED_ARTIFACTS = (
    "campaign-contract.json",
    "campaign-result-manifest.json",
    "detector-report.json",
    "detector-inventory.json",
    "heldout-labels.json",
    "heldout-campaign-population.json",
    "heldout-selection.json",
    "heldout-quality-report.json",
    "publication-manifest.json",
    "publication-curation-consistency-report.json",
    "publication-curation-inputs.json",
    "recall-selection.json",
    "recall-labels.json",
    "recall-report.json",
    "release-receipt.json",
    "source-remote-cutoff.json",
    "source-snapshot.json",
    "verifier-contract.json",
)


class ReleaseEvidenceError(RuntimeError):
    """Raised when release evidence cannot be durably archived or validated."""


def _trusted_repo_root_for_bundle(
    path: Path,
    trusted_repo_root: Path | None,
) -> Path:
    try:
        if trusted_repo_root is not None:
            return Path(trusted_repo_root).resolve(strict=True)
        absolute = Path(path).absolute()
        return _BUNDLE_TRUSTED_REPO_ROOTS.get(
            absolute,
            _TRUSTED_REPO_ROOT,
        ).resolve(strict=True)
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"trusted verifier repository is unavailable: {exc}"
        ) from exc


def _decode_archived_bytes(value: object, *, label: str) -> bytes:
    """Decode one exact base64 archive field with no ignored characters."""

    if not isinstance(value, str) or not value:
        raise ReleaseEvidenceError(f"{label} must contain base64 bytes")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReleaseEvidenceError(f"{label} is not canonical base64") from exc


def _runner_canonical_sha256(value: object) -> str:
    return hashlib.sha256(refresh_runner._canonical_json_bytes(value)).hexdigest()


def _campaign_identity_sha256(campaign_contract: Mapping[str, Any]) -> str:
    identity_payload = {
        "schema_version": refresh_runner.MARKER_SCHEMA_VERSION,
        "source_snapshot_sha256": campaign_contract["source_snapshot_sha256"],
        "contract_sha256": campaign_contract["contract_sha256"],
        "analyzer_contract_sha256": campaign_contract["analyzer_contract_sha256"],
        "signature_sha256": campaign_contract["signature_sha256"],
        "alias_class_manifest_sha256": campaign_contract["alias_class_manifest_sha256"],
        "model": refresh_runner.MODEL,
        "reasoning_effort": refresh_runner.REASONING_EFFORT,
        "workers": refresh_runner.WORKERS,
        "forced_verification": True,
        "result_cache_reads": False,
        "llm_cache_reads": False,
        "litellm_transport_sha256": campaign_contract["litellm_transport_sha256"],
        "batch_timeout_seconds": refresh_runner.BATCH_TIMEOUT_SECONDS,
    }
    return _runner_canonical_sha256(identity_payload)


@dataclass(frozen=True, slots=True)
class ReleaseEvidenceBundle:
    """One validated, content-addressed release-evidence directory."""

    path: Path
    manifest: dict[str, Any]
    bundle_sha256: str


def _inode_record(path: Path, label: str) -> dict[str, int]:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot inspect {label} {path}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseEvidenceError(f"{label} is not a safe directory: {path}")
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def _canonical_publication_path(path: Path, label: str) -> Path:
    absolute = Path(path).absolute()
    if absolute.is_symlink():
        raise ReleaseEvidenceError(f"{label} is symlinked: {absolute}")
    parent = absolute.parent.resolve()
    resolved = parent / absolute.name
    if resolved.parent != parent or not parent.is_dir() or parent.is_symlink():
        raise ReleaseEvidenceError(f"{label} parent is unsafe: {absolute}")
    return resolved


def _validate_activation_payload(
    payload: Mapping[str, Any],
    *,
    state: str,
    expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    expected_fields = {
        "schema_version",
        "state",
        "prepared_at_utc",
        "generation_id",
        "evidence_bundle_sha256",
        "release_receipt_sha256",
        "publication_bundle_sha256",
        "publication_manifest_sha256",
        "output_path",
        "recovery_path",
        "publication_parent_inode",
        "candidate_inode",
        "previous_inode",
    }
    if state in {"committed", "active"}:
        expected_fields.add("committed_at_utc")
    if state == "active":
        expected_fields.add("activated_at_utc")
    if set(payload) != expected_fields or payload.get("schema_version") != 5:
        raise ReleaseEvidenceError("release activation record fields are invalid")
    if payload.get("state") != state:
        raise ReleaseEvidenceError("release activation record state is invalid")
    for timestamp_field in (
        "prepared_at_utc",
        *(("committed_at_utc",) if state in {"committed", "active"} else ()),
        *(("activated_at_utc",) if state == "active" else ()),
    ):
        try:
            parsed = datetime.fromisoformat(payload.get(timestamp_field))
        except (TypeError, ValueError) as exc:
            raise ReleaseEvidenceError(
                f"release activation {timestamp_field} is invalid"
            ) from exc
        if parsed.tzinfo is None:
            raise ReleaseEvidenceError(
                f"release activation {timestamp_field} lacks a timezone"
            )
    for field in (
        "generation_id",
        "evidence_bundle_sha256",
        "release_receipt_sha256",
        "publication_bundle_sha256",
        "publication_manifest_sha256",
    ):
        value = payload.get(field)
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise ReleaseEvidenceError(f"release activation {field} is invalid")
    for field in ("output_path", "recovery_path"):
        value = payload.get(field)
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ReleaseEvidenceError(f"release activation {field} is invalid")
    for field in ("publication_parent_inode", "candidate_inode", "previous_inode"):
        value = payload.get(field)
        if value is None and field == "previous_inode":
            continue
        if (
            not isinstance(value, dict)
            or set(value) != {"device", "inode"}
            or any(
                isinstance(item, bool) or not isinstance(item, int) or item < 0
                for item in value.values()
            )
        ):
            raise ReleaseEvidenceError(f"release activation {field} is invalid")
    if expected is not None:
        for field, value in expected.items():
            if payload.get(field) != value:
                raise ReleaseEvidenceError(
                    f"release activation {field} does not match the approved release"
                )
    return dict(payload)


def _activation_roots(root: Path) -> tuple[Path, Path, Path]:
    archive_root = _ensure_archive_root(root)
    activation_root = archive_root / _ACTIVATION_DIR
    pending_root = activation_root / _PENDING_ACTIVATION_DIR
    try:
        activation_root.mkdir(exist_ok=True)
        pending_root.mkdir(exist_ok=True)
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot create release activation directories: {exc}"
        ) from exc
    _safe_existing_directory(activation_root, "release activation directory")
    _safe_existing_directory(pending_root, "pending activation directory")
    return archive_root, activation_root, pending_root


def _validate_activation_bindings(
    *,
    archive_root: Path,
    generation_id: str,
    evidence_bundle_sha256: str,
    release_receipt_sha256: str,
    publication_bundle_sha256: str,
    publication_manifest_sha256: str,
    trusted_repo_root: Path | None = None,
) -> dict[str, str]:
    bindings = {
        "generation_id": generation_id,
        "evidence_bundle_sha256": evidence_bundle_sha256,
        "release_receipt_sha256": release_receipt_sha256,
        "publication_bundle_sha256": publication_bundle_sha256,
        "publication_manifest_sha256": publication_manifest_sha256,
    }
    for field, value in bindings.items():
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise ReleaseEvidenceError(
                f"release activation {field} must be a lowercase SHA-256"
            )
    bundle = validate_release_evidence(
        archive_root / generation_id,
        expected_generation_id=generation_id,
        expected_bundle_sha256=evidence_bundle_sha256,
        trusted_repo_root=trusted_repo_root,
    )
    receipt_content, _ = _stable_regular_file(
        bundle.path / "release-receipt.json",
        "release-evidence receipt",
        max_bytes=_MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES,
    )
    receipt = _parse_json_object(receipt_content, "release-evidence receipt")
    if (
        _canonical_sha256(receipt) != release_receipt_sha256
        or receipt.get("publication_bundle_sha256") != publication_bundle_sha256
        or receipt.get("publication_manifest_sha256") != publication_manifest_sha256
    ):
        raise ReleaseEvidenceError(
            "release activation bindings do not match the evidence bundle"
        )
    return bindings


def _live_publication_manifest(output_path: Path) -> list[dict[str, Any]]:
    paths = [output_path / "index.json", output_path / "stats.json"]
    if (output_path / "inventory.json").exists():
        paths.append(output_path / "inventory.json")
    cves_dir = output_path / "cves"
    try:
        children = sorted(cves_dir.iterdir())
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot enumerate live CVE data: {exc}") from exc
    if any(child.is_symlink() or not child.is_file() for child in children):
        raise ReleaseEvidenceError("live CVE data contains an unsafe artifact")
    paths.extend(children)
    manifest: list[dict[str, Any]] = []
    total_bytes = 0
    for path in paths:
        if path.name == "index.json":
            max_bytes = web_writer._MAX_PUBLISHED_INDEX_BYTES
        elif path.name == "stats.json":
            max_bytes = web_writer._MAX_PUBLISHED_STATS_BYTES
        elif path.name == "inventory.json":
            max_bytes = web_writer._MAX_PUBLISHED_INVENTORY_BYTES
        else:
            max_bytes = web_writer._MAX_PUBLISHED_ENTRY_BYTES
        content, metadata = _stable_regular_file(
            path,
            "live publication artifact",
            max_bytes=max_bytes,
        )
        total_bytes += len(content)
        if total_bytes > web_writer._MAX_PUBLISHED_INPUT_BYTES:
            raise ReleaseEvidenceError(
                "live publication artifacts exceed aggregate size bound"
            )
        manifest.append(
            {
                "path": path.relative_to(output_path).as_posix(),
                "size_bytes": metadata.st_size,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return manifest


def _validate_live_activation(
    payload: Mapping[str, Any],
    publication_lock: web_writer.PublicationParentLock,
) -> None:
    output_path = _canonical_publication_path(
        Path(payload["output_path"]), "publication output"
    )
    recovery_path = _canonical_publication_path(
        Path(payload["recovery_path"]), "candidate recovery path"
    )
    if (
        str(output_path) != payload["output_path"]
        or str(recovery_path) != payload["recovery_path"]
        or output_path.parent != recovery_path.parent
        or output_path == recovery_path
        or not recovery_path.name.startswith(f".{output_path.name}.staging-")
    ):
        raise ReleaseEvidenceError("release activation publication paths are invalid")
    if publication_lock.path != output_path.parent or publication_lock.identity != (
        payload["publication_parent_inode"]["device"],
        payload["publication_parent_inode"]["inode"],
    ):
        raise ReleaseEvidenceError("release activation publication parent changed")
    try:
        publication_lock.assert_current()
        live_identity = publication_lock.child_identity(output_path.name)
    except (OSError, web_writer.PublicationWriteError) as exc:
        raise ReleaseEvidenceError(f"cannot bind live publication: {exc}") from exc
    if live_identity != (
        payload["candidate_inode"]["device"],
        payload["candidate_inode"]["inode"],
    ):
        raise ReleaseEvidenceError("approved candidate is not the live publication")
    try:
        web_writer._validate_staged_inventory(
            output_path,
            require_release_receipt=True,
        )
        publication = web_writer._load_published_web_data_unlocked(output_path)
    except (ValueError, OSError) as exc:
        raise ReleaseEvidenceError(f"live publication is invalid: {exc}") from exc
    if (
        publication.index.get("generation_id") != payload["generation_id"]
        or web_writer.publication_bundle_sha256(publication)
        != payload["publication_bundle_sha256"]
        or _canonical_sha256(_live_publication_manifest(output_path))
        != payload["publication_manifest_sha256"]
    ):
        raise ReleaseEvidenceError("live publication hashes do not match activation")
    receipt_content, _ = _stable_regular_file(
        output_path / "release-receipt.json",
        "live release receipt",
        max_bytes=web_writer._MAX_PUBLISHED_RECEIPT_BYTES,
    )
    if (
        publication._raw_input_bytes + len(receipt_content)
        > web_writer._MAX_PUBLISHED_INPUT_BYTES
    ):
        raise ReleaseEvidenceError(
            "live publication and receipt exceed aggregate size bound"
        )
    receipt = _parse_json_object(receipt_content, "live release receipt")
    if (
        _canonical_sha256(receipt) != payload["release_receipt_sha256"]
        or receipt.get("generation_id") != payload["generation_id"]
        or receipt.get("publication_bundle_sha256")
        != payload["publication_bundle_sha256"]
        or receipt.get("publication_manifest_sha256")
        != payload["publication_manifest_sha256"]
    ):
        raise ReleaseEvidenceError("live release receipt does not match activation")
    previous_inode = payload["previous_inode"]
    if previous_inode is None:
        if os.path.lexists(recovery_path):
            raise ReleaseEvidenceError("unexpected recovery generation exists")
    elif os.path.lexists(recovery_path):
        if _inode_record(recovery_path, "previous publication") != previous_inode:
            raise ReleaseEvidenceError("previous publication recovery inode changed")
    try:
        publication_lock.assert_current()
    except web_writer.PublicationWriteError as exc:
        raise ReleaseEvidenceError(
            "release activation publication parent changed"
        ) from exc


def _finalize_activation_payload(
    *,
    activation_root: Path,
    pending_root: Path,
    payload: Mapping[str, Any],
) -> Path:
    if payload.get("state") != "committed":
        raise ReleaseEvidenceError(
            "only a durable committed activation can become active"
        )
    generation_id = payload["generation_id"]
    final_path = activation_root / f"{generation_id}.json"
    active = {
        **dict(payload),
        "state": "active",
        "activated_at_utc": datetime.now(UTC).isoformat(),
    }
    temporary = activation_root / f".{generation_id}.{os.getpid()}.tmp"
    created_final = False
    try:
        _write_json(temporary, active, max_bytes=_MAX_ACTIVATION_RECORD_BYTES)
        try:
            os.link(temporary, final_path)
            created_final = True
        except FileExistsError:
            content, _ = _stable_regular_file(
                final_path,
                "release activation record",
                max_bytes=_MAX_ACTIVATION_RECORD_BYTES,
            )
            _validate_activation_payload(
                _parse_json_object(content, "release activation record"),
                state="active",
                expected={
                    field: active[field]
                    for field in active
                    if field not in {"state", "activated_at_utc"}
                },
            )
        _fsync_directory(activation_root)
    except (ReleaseEvidenceError, OSError) as exc:
        if created_final:
            try:
                final_path.unlink()
                _fsync_directory(activation_root)
            except (OSError, ReleaseEvidenceError) as cleanup_exc:
                raise ReleaseEvidenceError(
                    "release activation durability failed and its partial record "
                    "could not be removed"
                ) from cleanup_exc
        if isinstance(exc, ReleaseEvidenceError):
            raise
        raise ReleaseEvidenceError(
            f"cannot finalize release activation: {exc}"
        ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    pending_path = pending_root / f"{generation_id}.json"
    try:
        pending_path.unlink(missing_ok=True)
        _fsync_directory(pending_root)
        _fsync_directory(activation_root)
    except (OSError, ReleaseEvidenceError):
        # The active record is durable. A duplicate pending record is harmless
        # and can be removed by a later idempotent reconcile.
        pass
    return final_path


def prepare_release_activation_record(
    *,
    root: Path,
    generation_id: str,
    evidence_bundle_sha256: str,
    release_receipt_sha256: str,
    publication_bundle_sha256: str,
    publication_manifest_sha256: str,
    output_dir: Path,
    candidate_dir: Path,
) -> Path:
    """Durably bind an evidence-approved candidate and both publication inodes."""

    archive_root, activation_root, pending_root = _activation_roots(root)
    bindings = _validate_activation_bindings(
        archive_root=archive_root,
        generation_id=generation_id,
        evidence_bundle_sha256=evidence_bundle_sha256,
        release_receipt_sha256=release_receipt_sha256,
        publication_bundle_sha256=publication_bundle_sha256,
        publication_manifest_sha256=publication_manifest_sha256,
    )
    output_path = _canonical_publication_path(output_dir, "publication output")
    recovery_path = _canonical_publication_path(
        candidate_dir, "candidate recovery path"
    )
    if (
        output_path.parent != recovery_path.parent
        or output_path == recovery_path
        or not recovery_path.name.startswith(f".{output_path.name}.staging-")
    ):
        raise ReleaseEvidenceError("candidate and output paths are not safe siblings")
    try:
        with web_writer._publication_parent_lock(
            output_path,
            exclusive=True,
            error_type=web_writer.PublicationWriteError,
        ) as publication_lock:
            if publication_lock.path != output_path.parent:
                raise ReleaseEvidenceError(
                    "candidate and output paths are not bound to one parent"
                )
            candidate_identity = publication_lock.child_identity(recovery_path.name)
            previous_identity = (
                publication_lock.child_identity(output_path.name)
                if publication_lock.child_exists(output_path.name)
                else None
            )
            expected = {
                **bindings,
                "output_path": str(output_path),
                "recovery_path": str(recovery_path),
                "publication_parent_inode": {
                    "device": publication_lock.identity[0],
                    "inode": publication_lock.identity[1],
                },
                "candidate_inode": {
                    "device": candidate_identity[0],
                    "inode": candidate_identity[1],
                },
                "previous_inode": (
                    {
                        "device": previous_identity[0],
                        "inode": previous_identity[1],
                    }
                    if previous_identity is not None
                    else None
                ),
            }
    except web_writer.PublicationWriteError as exc:
        raise ReleaseEvidenceError(f"cannot lock publication candidate: {exc}") from exc
    final_path = activation_root / f"{generation_id}.json"
    if os.path.lexists(final_path):
        content, _ = _stable_regular_file(
            final_path,
            "release activation record",
            max_bytes=_MAX_ACTIVATION_RECORD_BYTES,
        )
        _validate_activation_payload(
            _parse_json_object(content, "release activation record"),
            state="active",
            expected=expected,
        )
        return final_path
    pending_path = pending_root / f"{generation_id}.json"
    if os.path.lexists(pending_path):
        content, _ = _stable_regular_file(
            pending_path,
            "pending activation record",
            max_bytes=_MAX_ACTIVATION_RECORD_BYTES,
        )
        pending_payload = _parse_json_object(content, "pending activation record")
        pending_state = pending_payload.get("state")
        if pending_state not in {"prepared", "committed"}:
            raise ReleaseEvidenceError("pending release activation state is invalid")
        _validate_activation_payload(
            pending_payload,
            state=pending_state,
            expected=expected,
        )
        return pending_path
    payload = {
        "schema_version": 5,
        "state": "prepared",
        "prepared_at_utc": datetime.now(UTC).isoformat(),
        **expected,
    }
    temporary = pending_root / f".{generation_id}.{os.getpid()}.tmp"
    try:
        _write_json(temporary, payload, max_bytes=_MAX_ACTIVATION_RECORD_BYTES)
        os.link(temporary, pending_path)
        _fsync_directory(pending_root)
        _fsync_directory(activation_root)
    except FileExistsError:
        content, _ = _stable_regular_file(
            pending_path,
            "pending activation record",
            max_bytes=_MAX_ACTIVATION_RECORD_BYTES,
        )
        raced_payload = _parse_json_object(content, "pending activation record")
        raced_state = raced_payload.get("state")
        if raced_state not in {"prepared", "committed"}:
            raise ReleaseEvidenceError("pending release activation state is invalid")
        _validate_activation_payload(
            raced_payload,
            state=raced_state,
            expected=expected,
        )
    except ReleaseEvidenceError:
        raise
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot persist pending release activation: {exc}"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)
    return pending_path


def _activation_payload_for_finalize(
    *,
    root: Path,
    generation_id: str,
    expected: Mapping[str, Any] | None,
) -> tuple[Path, Path, dict[str, Any]]:
    _archive_root, activation_root, pending_root = _activation_roots(root)
    final_path = activation_root / f"{generation_id}.json"
    if os.path.lexists(final_path):
        content, _ = _stable_regular_file(
            final_path,
            "release activation record",
            max_bytes=_MAX_ACTIVATION_RECORD_BYTES,
        )
        payload = _validate_activation_payload(
            _parse_json_object(content, "release activation record"),
            state="active",
            expected=expected,
        )
        return activation_root, pending_root, payload
    pending_path = pending_root / f"{generation_id}.json"
    content, _ = _stable_regular_file(
        pending_path,
        "pending activation record",
        max_bytes=_MAX_ACTIVATION_RECORD_BYTES,
    )
    parsed = _parse_json_object(content, "pending activation record")
    pending_state = parsed.get("state")
    if pending_state not in {"prepared", "committed"}:
        raise ReleaseEvidenceError("pending release activation state is invalid")
    payload = _validate_activation_payload(
        parsed,
        state=pending_state,
        expected=expected,
    )
    return activation_root, pending_root, payload


def _persist_committed_activation_payload(
    *,
    activation_root: Path,
    pending_root: Path,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Atomically and durably record that rollback has been disabled."""

    if payload.get("state") != "prepared":
        raise ReleaseEvidenceError("only a prepared activation can be committed")
    generation_id = payload["generation_id"]
    pending_path = pending_root / f"{generation_id}.json"
    committed = {
        **dict(payload),
        "state": "committed",
        "committed_at_utc": datetime.now(UTC).isoformat(),
    }
    temporary = pending_root / f".{generation_id}.{os.getpid()}.committed.tmp"
    replaced = False
    try:
        _write_json(temporary, committed, max_bytes=_MAX_ACTIVATION_RECORD_BYTES)
        os.replace(temporary, pending_path)
        replaced = True
        _fsync_directory(pending_root)
        _fsync_directory(activation_root)
        content, _ = _stable_regular_file(
            pending_path,
            "committed activation record",
            max_bytes=_MAX_ACTIVATION_RECORD_BYTES,
        )
        _validate_activation_payload(
            _parse_json_object(content, "committed activation record"),
            state="committed",
            expected={
                field: committed[field]
                for field in committed
                if field not in {"state", "committed_at_utc"}
            },
        )
    except (ReleaseEvidenceError, OSError) as exc:
        # Once replace succeeds the durable state may be either prepared or
        # committed after a crash. Reconciliation handles both safely.
        detail = " after replacement" if replaced else ""
        if isinstance(exc, ReleaseEvidenceError):
            raise ReleaseEvidenceError(
                f"cannot persist committed release activation{detail}: {exc}"
            ) from exc
        raise ReleaseEvidenceError(
            f"cannot persist committed release activation{detail}: {exc}"
        ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return committed


def write_release_activation_record(
    *,
    root: Path,
    generation_id: str,
    evidence_bundle_sha256: str,
    release_receipt_sha256: str,
    publication_bundle_sha256: str,
    publication_manifest_sha256: str,
    output_dir: Path,
    candidate_dir: Path,
    promotion_commit: web_writer.PromotionCommitToken | None = None,
    publication_lock: web_writer.PublicationParentLock | None = None,
) -> Path:
    """Validate the live candidate and finalize its prepared activation record."""

    expected = {
        "generation_id": generation_id,
        "evidence_bundle_sha256": evidence_bundle_sha256,
        "release_receipt_sha256": release_receipt_sha256,
        "publication_bundle_sha256": publication_bundle_sha256,
        "publication_manifest_sha256": publication_manifest_sha256,
        "output_path": str(
            _canonical_publication_path(output_dir, "publication output")
        ),
        "recovery_path": str(
            _canonical_publication_path(candidate_dir, "candidate recovery path")
        ),
    }

    def finalize(held_lock: web_writer.PublicationParentLock) -> Path:
        activation_root, pending_root, payload = _activation_payload_for_finalize(
            root=root,
            generation_id=generation_id,
            expected=expected,
        )
        _validate_activation_bindings(
            archive_root=_ensure_archive_root(root),
            generation_id=payload["generation_id"],
            evidence_bundle_sha256=payload["evidence_bundle_sha256"],
            release_receipt_sha256=payload["release_receipt_sha256"],
            publication_bundle_sha256=payload["publication_bundle_sha256"],
            publication_manifest_sha256=payload["publication_manifest_sha256"],
        )
        _validate_live_activation(payload, held_lock)
        if payload["state"] == "active":
            try:
                (pending_root / f"{generation_id}.json").unlink(missing_ok=True)
                _fsync_directory(pending_root)
            except (OSError, ReleaseEvidenceError):
                pass
            return activation_root / f"{generation_id}.json"
        if payload["state"] == "prepared":
            if promotion_commit is None:
                raise ReleaseEvidenceError(
                    "prepared release activation requires an explicit promotion "
                    "commit token"
                )
            expected_candidate_identity = (
                payload["candidate_inode"]["device"],
                payload["candidate_inode"]["inode"],
            )
            expected_parent_identity = (
                payload["publication_parent_inode"]["device"],
                payload["publication_parent_inode"]["inode"],
            )
            if (
                promotion_commit.output_path != Path(payload["output_path"])
                or promotion_commit.candidate_identity != expected_candidate_identity
                or promotion_commit.publication_parent_identity
                != expected_parent_identity
                or held_lock.identity != expected_parent_identity
            ):
                raise ReleaseEvidenceError(
                    "promotion commit token does not match the prepared activation"
                )
            payload = _persist_committed_activation_payload(
                activation_root=activation_root,
                pending_root=pending_root,
                payload=payload,
            )
        return _finalize_activation_payload(
            activation_root=activation_root,
            pending_root=pending_root,
            payload=payload,
        )

    if publication_lock is not None:
        return finalize(publication_lock)
    try:
        with web_writer._publication_parent_lock(
            Path(expected["output_path"]),
            exclusive=True,
            error_type=web_writer.PublicationWriteError,
        ) as held_lock:
            return finalize(held_lock)
    except web_writer.PublicationWriteError as exc:
        raise ReleaseEvidenceError(f"cannot lock live publication: {exc}") from exc


def _locked_activation_directory_identity(
    path: Path,
    publication_lock: web_writer.PublicationParentLock,
    label: str,
) -> tuple[int, int] | None:
    if path.absolute().parent != publication_lock.path:
        raise ReleaseEvidenceError(f"{label} does not match the publication parent")
    try:
        metadata = os.stat(
            path.name,
            dir_fd=publication_lock.descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseEvidenceError(f"{label} is not a safe directory")
    return metadata.st_dev, metadata.st_ino


def _remove_pending_activation(
    *,
    activation_root: Path,
    pending_root: Path,
    generation_id: str,
) -> None:
    pending_path = pending_root / f"{generation_id}.json"
    try:
        pending_path.unlink(missing_ok=True)
        _fsync_directory(pending_root)
        _fsync_directory(activation_root)
    except (OSError, ReleaseEvidenceError) as exc:
        raise ReleaseEvidenceError(
            f"cannot durably remove reconciled activation state: {exc}"
        ) from exc


def _rollback_prepared_activation(
    *,
    activation_root: Path,
    pending_root: Path,
    payload: Mapping[str, Any],
    publication_lock: web_writer.PublicationParentLock,
) -> None:
    """Restore the pre-promotion state for an activation without durable commit."""

    output_path = _canonical_publication_path(
        Path(payload["output_path"]), "publication output"
    )
    recovery_path = _canonical_publication_path(
        Path(payload["recovery_path"]), "candidate recovery path"
    )
    parent_identity = (
        payload["publication_parent_inode"]["device"],
        payload["publication_parent_inode"]["inode"],
    )
    if (
        str(output_path) != payload["output_path"]
        or str(recovery_path) != payload["recovery_path"]
        or output_path.parent != recovery_path.parent
        or output_path == recovery_path
        or not recovery_path.name.startswith(f".{output_path.name}.staging-")
        or publication_lock.path != output_path.parent
        or publication_lock.identity != parent_identity
    ):
        raise ReleaseEvidenceError("prepared activation publication paths changed")
    try:
        publication_lock.assert_current()
    except web_writer.PublicationWriteError as exc:
        raise ReleaseEvidenceError("prepared activation parent changed") from exc

    candidate_identity = (
        payload["candidate_inode"]["device"],
        payload["candidate_inode"]["inode"],
    )
    previous_record = payload["previous_inode"]
    previous_identity = (
        (previous_record["device"], previous_record["inode"])
        if previous_record is not None
        else None
    )
    live_identity = _locked_activation_directory_identity(
        output_path, publication_lock, "publication output"
    )
    recovery_identity = _locked_activation_directory_identity(
        recovery_path, publication_lock, "candidate recovery path"
    )

    try:
        if live_identity == candidate_identity:
            if previous_identity is None:
                if recovery_identity is not None:
                    raise ReleaseEvidenceError(
                        "prepared first publication has an unexpected recovery path"
                    )
                os.rename(
                    output_path.name,
                    recovery_path.name,
                    src_dir_fd=publication_lock.descriptor,
                    dst_dir_fd=publication_lock.descriptor,
                )
            else:
                if recovery_identity != previous_identity:
                    raise ReleaseEvidenceError(
                        "prepared live candidate lacks its exact previous generation"
                    )
                web_writer._rename_exchange(
                    recovery_path, output_path, publication_lock
                )
            web_writer._fsync_publication_parent(publication_lock)
            live_identity = _locked_activation_directory_identity(
                output_path, publication_lock, "restored publication output"
            )
            recovery_identity = _locked_activation_directory_identity(
                recovery_path, publication_lock, "rolled-back candidate"
            )
            if (
                live_identity != previous_identity
                or recovery_identity != candidate_identity
            ):
                raise ReleaseEvidenceError(
                    "prepared activation rollback inode proof failed"
                )
        elif previous_identity is not None and live_identity == previous_identity:
            if recovery_identity not in {None, candidate_identity}:
                raise ReleaseEvidenceError("prepared activation recovery inode changed")
        elif previous_identity is None and live_identity is None:
            if recovery_identity not in {None, candidate_identity}:
                raise ReleaseEvidenceError(
                    "prepared first-publication candidate inode changed"
                )
        else:
            raise ReleaseEvidenceError(
                "prepared activation publication state is ambiguous"
            )

        if recovery_identity == candidate_identity:
            web_writer._remove_tree_locked(recovery_path, publication_lock)
    except ReleaseEvidenceError:
        raise
    except (OSError, web_writer.PublicationWriteError) as exc:
        raise ReleaseEvidenceError(
            f"cannot atomically roll back prepared activation: {exc}"
        ) from exc

    _remove_pending_activation(
        activation_root=activation_root,
        pending_root=pending_root,
        generation_id=payload["generation_id"],
    )


def reconcile_release_activation_record(
    *,
    root: Path,
    generation_id: str,
) -> Path | None:
    """Finalize durable commits and roll back merely prepared candidates."""

    _activation_root, _pending_root, preliminary = _activation_payload_for_finalize(
        root=root,
        generation_id=generation_id,
        expected={"generation_id": generation_id},
    )
    output_path = _canonical_publication_path(
        Path(preliminary["output_path"]), "publication output"
    )
    try:
        with web_writer._publication_parent_lock(
            output_path,
            exclusive=True,
            error_type=web_writer.PublicationWriteError,
        ) as publication_lock:
            activation_root, pending_root, payload = _activation_payload_for_finalize(
                root=root,
                generation_id=generation_id,
                expected={
                    "generation_id": generation_id,
                    "output_path": str(output_path),
                },
            )
            _validate_activation_bindings(
                archive_root=_ensure_archive_root(root),
                generation_id=payload["generation_id"],
                evidence_bundle_sha256=payload["evidence_bundle_sha256"],
                release_receipt_sha256=payload["release_receipt_sha256"],
                publication_bundle_sha256=payload["publication_bundle_sha256"],
                publication_manifest_sha256=payload["publication_manifest_sha256"],
            )
            if payload["state"] == "prepared":
                _rollback_prepared_activation(
                    activation_root=activation_root,
                    pending_root=pending_root,
                    payload=payload,
                    publication_lock=publication_lock,
                )
                return None

            _validate_live_activation(payload, publication_lock)
            final_path = activation_root / f"{generation_id}.json"
            if payload["state"] == "committed":
                final_path = _finalize_activation_payload(
                    activation_root=activation_root,
                    pending_root=pending_root,
                    payload=payload,
                )
            stale_pending = pending_root / f"{generation_id}.json"
            try:
                stale_pending.unlink(missing_ok=True)
                _fsync_directory(pending_root)
            except (OSError, ReleaseEvidenceError):
                pass
            recovery_path = Path(payload["recovery_path"])
            if payload["previous_inode"] is not None and os.path.lexists(recovery_path):
                web_writer._remove_tree_locked(recovery_path, publication_lock)
            return final_path
    except web_writer.PublicationWriteError as exc:
        raise ReleaseEvidenceError(f"cannot lock live publication: {exc}") from exc


def validate_active_release(
    *,
    root: Path,
    generation_id: str,
    trusted_repo_root: Path | None = None,
) -> dict[str, Any]:
    """Read-only validation of one active record, evidence bundle, and live data."""

    if _SHA256.fullmatch(generation_id) is None:
        raise ReleaseEvidenceError("generation_id must be a lowercase SHA-256")
    archive_root = Path(root).resolve()
    _safe_existing_directory(archive_root, "release-evidence root")
    activation_root = archive_root / _ACTIVATION_DIR
    pending_root = activation_root / _PENDING_ACTIVATION_DIR
    _safe_existing_directory(activation_root, "release activation directory")
    _safe_existing_directory(pending_root, "pending activation directory")
    active_path = activation_root / f"{generation_id}.json"
    content, _ = _stable_regular_file(
        active_path,
        "active release record",
        max_bytes=_MAX_ACTIVATION_RECORD_BYTES,
    )
    payload = _validate_activation_payload(
        _parse_json_object(content, "active release record"),
        state="active",
        expected={"generation_id": generation_id},
    )
    if os.path.lexists(pending_root / f"{generation_id}.json"):
        raise ReleaseEvidenceError("active release retains a pending activation")
    _validate_activation_bindings(
        archive_root=archive_root,
        generation_id=generation_id,
        evidence_bundle_sha256=payload["evidence_bundle_sha256"],
        release_receipt_sha256=payload["release_receipt_sha256"],
        publication_bundle_sha256=payload["publication_bundle_sha256"],
        publication_manifest_sha256=payload["publication_manifest_sha256"],
        trusted_repo_root=trusted_repo_root,
    )
    output_path = _canonical_publication_path(
        Path(payload["output_path"]), "publication output"
    )
    try:
        with web_writer._publication_parent_lock(
            output_path,
            exclusive=False,
            error_type=web_writer.PublicationWriteError,
        ) as publication_lock:
            _validate_live_activation(payload, publication_lock)
            final_content, _ = _stable_regular_file(
                active_path,
                "active release record",
                max_bytes=_MAX_ACTIVATION_RECORD_BYTES,
            )
            if final_content != content:
                raise ReleaseEvidenceError(
                    "active release record changed during validation"
                )
    except web_writer.PublicationWriteError as exc:
        raise ReleaseEvidenceError(
            f"cannot lock active publication for validation: {exc}"
        ) from exc
    return payload


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReleaseEvidenceError(
            f"release evidence is not canonical JSON: {exc}"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _source_snapshot_sha256(value: object) -> str:
    """Match the refresh runner's ASCII-escaped snapshot digest contract."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReleaseEvidenceError(
            f"source snapshot is not canonical JSON: {exc}"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _safe_existing_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot inspect {label} {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseEvidenceError(f"{label} is unsafe: {path}")


def _ensure_archive_root(path: Path) -> Path:
    path = Path(path)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot create release-evidence root {path}: {exc}"
        ) from exc
    _safe_existing_directory(path, "release-evidence root")
    return path


def _stable_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot open {label} {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ReleaseEvidenceError(f"{label} is unsafe: {path}")
        if before.st_size > max_bytes:
            raise ReleaseEvidenceError(f"{label} exceeds the size bound: {path}")
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise ReleaseEvidenceError(f"{label} exceeds the size bound: {path}")
        after = os.fstat(descriptor)
    except ReleaseEvidenceError:
        raise
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        os.close(descriptor)

    content = b"".join(chunks)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity or len(content) != after.st_size:
        raise ReleaseEvidenceError(f"{label} changed while being read: {path}")
    try:
        current = path.lstat()
    except OSError as exc:
        raise ReleaseEvidenceError(f"cannot recheck {label} {path}: {exc}") from exc
    current_identity = (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )
    if current_identity != after_identity or not stat.S_ISREG(current.st_mode):
        raise ReleaseEvidenceError(f"{label} path changed while being read: {path}")
    return content, after


def _parse_json_object(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseEvidenceError(f"{label} is malformed JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseEvidenceError(f"{label} must contain a JSON object")
    _canonical_bytes(value)
    return value


def _write_json(
    path: Path,
    payload: Mapping[str, Any],
    *,
    max_bytes: int | None = None,
) -> None:
    try:
        content = (
            json.dumps(
                payload,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        if max_bytes is not None and len(content) > max_bytes:
            raise ReleaseEvidenceError(
                f"release-evidence artifact exceeds the size bound: {path.name}"
            )
        with path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except ReleaseEvidenceError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise ReleaseEvidenceError(
            f"cannot write release-evidence artifact {path}: {exc}"
        ) from exc


def _population_result_entries(
    population: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    """Return the exact flat raw-result inventory after path/size validation."""

    result_dir = population.get("result_dir")
    results = population.get("results")
    if (
        not isinstance(result_dir, str)
        or not Path(result_dir).is_absolute()
        or not isinstance(results, list)
        or not results
        or population.get("result_count") != len(results)
    ):
        raise ReleaseEvidenceError(
            "held-out campaign population result inventory is invalid"
        )
    root = Path(result_dir).resolve(strict=False)
    fields = {
        "subject_id",
        "source_path",
        "file_name",
        "archive_path",
        "size_bytes",
        "sha256",
    }
    seen: set[str] = set()
    total_size = 0
    validated: list[Mapping[str, Any]] = []
    for entry in results:
        subject_id = entry.get("subject_id") if isinstance(entry, dict) else None
        file_name = f"{subject_id}.json" if isinstance(subject_id, str) else None
        size = entry.get("size_bytes") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or set(entry) != fields
            or not isinstance(subject_id, str)
            or not subject_id
            or Path(subject_id).name != subject_id
            or subject_id in seen
            or entry.get("file_name") != file_name
            or entry.get("source_path") != str(root / file_name)
            or entry.get("archive_path") != f"{_CAMPAIGN_RESULTS_DIR}/{file_name}"
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or size > _MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES
            or not isinstance(entry.get("sha256"), str)
            or _SHA256.fullmatch(entry["sha256"]) is None
        ):
            raise ReleaseEvidenceError(
                "held-out campaign population result entry is invalid"
            )
        seen.add(subject_id)
        total_size += size
        if total_size > _MAX_ARCHIVED_CAMPAIGN_RESULTS_TOTAL_BYTES:
            raise ReleaseEvidenceError(
                "held-out campaign results exceed archive size bound"
            )
        validated.append(entry)
    if population.get("total_result_size_bytes") != total_size:
        raise ReleaseEvidenceError(
            "held-out campaign population result total is invalid"
        )
    return validated


def _authoritative_campaign_result_entries(
    *,
    population: Mapping[str, Any],
    result_manifest: Mapping[str, Any],
    campaign_contract: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    """Cross-check the two archived inventories before touching live results."""

    population_entries = _population_result_entries(population)
    manifest_entries = result_manifest.get("results")
    if (
        campaign_contract.get("result_dir") != population.get("result_dir")
        or not isinstance(manifest_entries, list)
        or result_manifest.get("result_count") != len(manifest_entries)
        or len(manifest_entries) != len(population_entries)
    ):
        raise ReleaseEvidenceError(
            "live campaign result inventories disagree before archival"
        )
    manifest_by_subject: dict[str, Mapping[str, Any]] = {}
    for entry in manifest_entries:
        subject_id = entry.get("subject_id") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or set(entry) != {"subject_id", "file_name", "size_bytes", "sha256"}
            or not isinstance(subject_id, str)
            or subject_id in manifest_by_subject
        ):
            raise ReleaseEvidenceError(
                "campaign result manifest is malformed before archival"
            )
        manifest_by_subject[subject_id] = entry
    for population_entry in population_entries:
        manifest_entry = manifest_by_subject.get(population_entry["subject_id"])
        if (
            manifest_entry is None
            or manifest_entry["file_name"] != population_entry["file_name"]
            or manifest_entry["size_bytes"] != population_entry["size_bytes"]
            or manifest_entry["sha256"] != population_entry["sha256"]
        ):
            raise ReleaseEvidenceError(
                "campaign population and result manifest disagree before archival"
            )
    return population_entries


def _directory_entry_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _campaign_result_inventory_from_descriptor(
    descriptor: int,
    *,
    result_dir: Path,
    expected: Mapping[str, Mapping[str, Any]],
) -> dict[str, tuple[int, ...]]:
    """Enumerate one already-open no-follow directory and reject all residue."""

    try:
        names = os.listdir(descriptor)
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot enumerate campaign result directory {result_dir}: {exc}"
        ) from exc
    expected_names = set(expected)
    actual_names = set(names)
    if (
        len(names) != len(actual_names)
        or actual_names != expected_names
        or any(
            not isinstance(name, str)
            or not name.endswith(".json")
            or name in {".", ".."}
            for name in names
        )
    ):
        raise ReleaseEvidenceError(
            "live campaign result directory inventory mismatch; "
            f"missing={sorted(expected_names - actual_names)}, "
            f"unexpected={sorted(actual_names - expected_names)}"
        )
    inventory: dict[str, tuple[int, ...]] = {}
    for name in sorted(names):
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as exc:
            raise ReleaseEvidenceError(
                f"cannot inspect live campaign result {result_dir / name}: {exc}"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != expected[name]["size_bytes"]
        ):
            raise ReleaseEvidenceError(
                f"live campaign result is unsafe or mismatched: {result_dir / name}"
            )
        inventory[name] = _directory_entry_signature(metadata)
    return inventory


def _open_live_campaign_result_directory(
    entries: list[Mapping[str, Any]],
    *,
    result_dir: Path,
) -> tuple[int, tuple[int, ...], dict[str, tuple[int, ...]]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(result_dir, flags)
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot open live campaign result directory {result_dir}: {exc}"
        ) from exc
    expected = {entry["file_name"]: entry for entry in entries}
    try:
        directory_signature = _directory_entry_signature(os.fstat(descriptor))
        if not stat.S_ISDIR(directory_signature[2]):
            raise ReleaseEvidenceError(
                f"live campaign result path is not a directory: {result_dir}"
            )
        inventory = _campaign_result_inventory_from_descriptor(
            descriptor,
            result_dir=result_dir,
            expected=expected,
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, directory_signature, inventory


def _revalidate_live_campaign_result_directory(
    descriptor: int,
    *,
    result_dir: Path,
    entries: list[Mapping[str, Any]],
    directory_signature: tuple[int, ...],
    inventory: Mapping[str, tuple[int, ...]],
) -> None:
    expected = {entry["file_name"]: entry for entry in entries}
    current_inventory = _campaign_result_inventory_from_descriptor(
        descriptor,
        result_dir=result_dir,
        expected=expected,
    )
    try:
        path_metadata = result_dir.stat(follow_symlinks=False)
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot recheck live campaign result directory {result_dir}: {exc}"
        ) from exc
    if (
        current_inventory != inventory
        or _directory_entry_signature(os.fstat(descriptor)) != directory_signature
        or _directory_entry_signature(path_metadata) != directory_signature
        or not stat.S_ISDIR(path_metadata.st_mode)
    ):
        raise ReleaseEvidenceError(
            "live campaign result directory changed during evidence archival"
        )


def _copy_campaign_result(
    source: Path,
    destination: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    source_directory_descriptor: int | None = None,
) -> dict[str, Any]:
    """Copy one result with no-follow stable-read and bounded streaming."""

    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    destination_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        source_descriptor = os.open(
            source.name if source_directory_descriptor is not None else source,
            source_flags,
            dir_fd=source_directory_descriptor,
        )
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot open campaign result source {source}: {exc}"
        ) from exc
    destination_descriptor: int | None = None
    try:
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size != expected_size
            or before.st_size > _MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES
        ):
            raise ReleaseEvidenceError(
                f"campaign result source metadata is invalid: {source}"
            )
        destination_descriptor = os.open(
            destination,
            destination_flags,
            0o600,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > _MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES:
                raise ReleaseEvidenceError(
                    f"campaign result source exceeds size bound: {source}"
                )
            digest.update(chunk)
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(destination_descriptor, remaining)
                if written <= 0:
                    raise OSError("short write")
                remaining = remaining[written:]
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
    except ReleaseEvidenceError:
        raise
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot archive campaign result {source}: {exc}"
        ) from exc
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)

    identity = lambda value: (  # noqa: E731
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    try:
        current = (
            os.stat(
                source.name,
                dir_fd=source_directory_descriptor,
                follow_symlinks=False,
            )
            if source_directory_descriptor is not None
            else source.lstat()
        )
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot recheck campaign result source {source}: {exc}"
        ) from exc
    actual_sha256 = digest.hexdigest()
    if (
        identity(before) != identity(after)
        or identity(current) != identity(after)
        or copied != expected_size
        or actual_sha256 != expected_sha256
    ):
        raise ReleaseEvidenceError(
            f"campaign result source changed or mismatched: {source}"
        )
    return {
        "path": destination.parent.name + "/" + destination.name,
        "size_bytes": copied,
        "sha256": actual_sha256,
    }


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot open evidence directory {path}: {exc}"
        ) from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot fsync evidence directory {path}: {exc}"
        ) from exc
    finally:
        os.close(descriptor)


def _artifact_manifest(path: Path, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    content, metadata = _stable_regular_file(
        path,
        f"release-evidence artifact {name}",
        max_bytes=_MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES,
    )
    payload = _parse_json_object(content, f"release-evidence artifact {name}")
    return (
        {
            "path": name,
            "size_bytes": metadata.st_size,
            "sha256": hashlib.sha256(content).hexdigest(),
            "canonical_sha256": _canonical_sha256(payload),
        },
        payload,
    )


def _validate_curation_report(
    report: Mapping[str, Any],
    *,
    targets: Mapping[str, float],
) -> None:
    """Recompute the curation point estimates and exact report schema."""

    required_fields = {
        "schema_version",
        "evaluation_kind",
        "measurement_boundary",
        "confidence_level",
        "targets",
        "counts",
        "confusion_ids",
        "curation_precision",
        "curation_recall",
        "known_negative_published",
        "known_inconclusive_published",
        "unadjudicated_published",
        "audit_coverage",
        "conclusive_coverage",
        "curation_recall_unresolved_sensitive",
        "curation_hard_fail",
        "curation_consistent",
        "curation_precision_certified",
        "curation_recall_certified",
        "curation_certified",
    }
    if (
        set(report) != required_fields
        or report.get("schema_version") != 2
        or report.get("evaluation_kind") != "publication_curation_consistency"
    ):
        raise ReleaseEvidenceError("publication curation report schema is invalid")
    if report.get("targets") != {
        "curation_precision": targets["precision"],
        "curation_recall": targets["recall"],
    }:
        raise ReleaseEvidenceError(
            "publication curation targets do not match the release receipt"
        )
    confidence_level = report.get("confidence_level")
    if (
        isinstance(confidence_level, bool)
        or not isinstance(confidence_level, (int, float))
        or not math.isfinite(float(confidence_level))
        or float(confidence_level) != _CURATION_CONFIDENCE_LEVEL
    ):
        raise ReleaseEvidenceError("publication curation confidence level is invalid")
    counts = report.get("counts")
    count_fields = {
        "tp",
        "fp",
        "fn",
        "tn",
        "adjudicated_positive",
        "adjudicated_negative",
        "inconclusive_excluded",
        "inconclusive_published",
        "published_total",
        "published_adjudicated",
        "published_unadjudicated",
    }
    confusion = report.get("confusion_ids")
    if (
        not isinstance(counts, dict)
        or set(counts) != count_fields
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in counts.values()
        )
        or not isinstance(confusion, dict)
        or set(confusion) != {"tp", "fp", "fn", "tn"}
    ):
        raise ReleaseEvidenceError("publication curation report counts are invalid")
    for outcome in ("tp", "fp", "fn", "tn"):
        identifiers = confusion[outcome]
        if (
            not isinstance(identifiers, list)
            or identifiers != sorted(set(identifiers))
            or any(not isinstance(item, str) or not item for item in identifiers)
            or counts[outcome] != len(identifiers)
        ):
            raise ReleaseEvidenceError(
                "publication curation report confusion inventory is invalid"
            )
    all_confusion_ids = [
        identifier
        for outcome in ("tp", "fp", "fn", "tn")
        for identifier in confusion[outcome]
    ]
    if len(set(all_confusion_ids)) != len(all_confusion_ids):
        raise ReleaseEvidenceError("publication curation confusion outcomes overlap")
    if (
        counts["adjudicated_positive"] != counts["tp"] + counts["fn"]
        or counts["adjudicated_negative"] != counts["fp"] + counts["tn"]
        or counts["published_adjudicated"] + counts["published_unadjudicated"]
        != counts["published_total"]
    ):
        raise ReleaseEvidenceError(
            "publication curation report denominators are invalid"
        )

    certified_by_metric: dict[str, bool] = {}
    point_gate_by_metric: dict[str, bool] = {}
    for name, successes, trials, target in (
        (
            "curation_precision",
            counts["tp"],
            counts["tp"] + counts["fp"],
            targets["precision"],
        ),
        (
            "curation_recall",
            counts["tp"],
            counts["tp"] + counts["fn"],
            targets["recall"],
        ),
    ):
        metric = report.get(name)
        expected_point = successes / trials if trials else None
        expected_lower_bound = heldout_quality.clopper_pearson_lower_bound(
            successes,
            trials,
            confidence_level=float(confidence_level),
        )
        expected_meets_target = bool(
            expected_point is not None
            and expected_point >= float(target)
            and expected_lower_bound >= float(target)
        )
        if (
            not isinstance(metric, dict)
            or set(metric)
            != {"successes", "trials", "point", "lower_bound", "meets_target"}
            or metric.get("successes") != successes
            or metric.get("trials") != trials
            or expected_point is None
            or isinstance(metric.get("point"), bool)
            or not isinstance(metric.get("point"), (int, float))
            or not math.isfinite(float(metric["point"]))
            or float(metric["point"]) != expected_point
            or isinstance(metric.get("lower_bound"), bool)
            or not isinstance(metric.get("lower_bound"), (int, float))
            or not math.isfinite(float(metric["lower_bound"]))
            or float(metric["lower_bound"]) != expected_lower_bound
            or metric.get("meets_target") is not expected_meets_target
        ):
            raise ReleaseEvidenceError(
                f"publication curation {name} point/count/confidence proof is invalid"
            )
        point_gate_by_metric[name] = expected_point >= float(target)
        certified_by_metric[name] = expected_meets_target

    hard_fail = bool(
        counts["fp"]
        or counts["inconclusive_published"]
        or counts["published_unadjudicated"]
    )
    expected_audit_coverage = (
        counts["published_adjudicated"] / counts["published_total"]
        if counts["published_total"]
        else 1.0
    )
    conclusive_count = counts["adjudicated_positive"] + counts["adjudicated_negative"]
    total_adjudications = conclusive_count + counts["inconclusive_excluded"]
    expected_conclusive_coverage = (
        conclusive_count / total_adjudications if total_adjudications else None
    )
    expected_unresolved_sensitive = {
        "lower": (
            counts["tp"]
            / (counts["adjudicated_positive"] + counts["inconclusive_excluded"])
            if counts["adjudicated_positive"] + counts["inconclusive_excluded"]
            else None
        ),
        "upper": (
            counts["tp"] / counts["adjudicated_positive"]
            if counts["adjudicated_positive"]
            else None
        ),
    }
    expected_consistent = bool(
        point_gate_by_metric["curation_precision"]
        and point_gate_by_metric["curation_recall"]
        and not hard_fail
    )
    expected_precision_certified = bool(
        certified_by_metric["curation_precision"] and not hard_fail
    )
    expected_recall_certified = bool(
        certified_by_metric["curation_recall"] and not hard_fail
    )
    expected_certified = bool(
        expected_precision_certified and expected_recall_certified
    )
    if (
        report.get("audit_coverage") != expected_audit_coverage
        or report.get("conclusive_coverage") != expected_conclusive_coverage
        or report.get("curation_recall_unresolved_sensitive")
        != expected_unresolved_sensitive
        or report.get("curation_hard_fail") is not hard_fail
        or report.get("curation_consistent") is not expected_consistent
        or report.get("curation_precision_certified")
        is not expected_precision_certified
        or report.get("curation_recall_certified") is not expected_recall_certified
        or report.get("curation_certified") is not expected_certified
    ):
        raise ReleaseEvidenceError(
            "publication curation derived confidence flags are invalid"
        )
    if (
        not expected_consistent
        or counts["fp"] != 0
        or counts["inconclusive_published"] != 0
        or counts["published_unadjudicated"] != 0
        or report.get("known_negative_published") != []
        or report.get("known_inconclusive_published") != []
        or report.get("unadjudicated_published") != []
    ):
        raise ReleaseEvidenceError(
            "publication curation report contains release failures"
        )


def _validate_curation_inputs(
    inputs: Mapping[str, Any],
    *,
    report: Mapping[str, Any],
    publication_manifest: Mapping[str, Any],
    targets: Mapping[str, Any],
) -> None:
    """Replay curation from the exact archived adjudication and index bytes."""

    fields = {
        "schema_version",
        "adjudications_path",
        "adjudications_sha256",
        "adjudications_bytes_base64",
        "alias_classes",
        "alias_classes_sha256",
        "normalized_adjudications",
        "normalized_adjudications_sha256",
        "publication_index_sha256",
        "publication_index_bytes_base64",
        "published_ordered_ids",
        "published_ordered_ids_sha256",
    }
    if (
        set(inputs) != fields
        or inputs.get("schema_version") != 1
        or not isinstance(inputs.get("adjudications_path"), str)
        or not Path(inputs["adjudications_path"]).is_absolute()
    ):
        raise ReleaseEvidenceError("publication curation inputs require exact schema")
    adjudication_bytes = _decode_archived_bytes(
        inputs.get("adjudications_bytes_base64"),
        label="publication adjudications",
    )
    index_bytes = _decode_archived_bytes(
        inputs.get("publication_index_bytes_base64"),
        label="publication index",
    )
    if hashlib.sha256(adjudication_bytes).hexdigest() != inputs.get(
        "adjudications_sha256"
    ) or hashlib.sha256(index_bytes).hexdigest() != inputs.get(
        "publication_index_sha256"
    ):
        raise ReleaseEvidenceError("publication curation raw input hash is invalid")

    alias_rows = inputs.get("alias_classes")
    if not isinstance(alias_rows, list) or inputs.get(
        "alias_classes_sha256"
    ) != _canonical_sha256(alias_rows):
        raise ReleaseEvidenceError("publication curation alias classes are invalid")
    alias_map: dict[str, set[str]] = {}
    for row in alias_rows:
        if not isinstance(row, dict) or set(row) != {"subject_id", "aliases"}:
            raise ReleaseEvidenceError(
                "publication curation alias class schema is invalid"
            )
        subject_id = row.get("subject_id")
        aliases = row.get("aliases")
        if (
            not isinstance(subject_id, str)
            or not subject_id
            or subject_id in alias_map
            or not isinstance(aliases, list)
            or aliases != sorted(aliases)
            or len(aliases) != len(set(aliases))
            or any(not isinstance(alias, str) or not alias for alias in aliases)
            or subject_id not in aliases
        ):
            raise ReleaseEvidenceError(
                "publication curation alias class inventory is invalid"
            )
        alias_map[subject_id] = set(aliases)
    if list(alias_map) != sorted(alias_map) or any(
        alias_map.get(alias) != aliases
        for aliases in alias_map.values()
        for alias in aliases
    ):
        raise ReleaseEvidenceError(
            "publication curation alias equivalence classes are incomplete"
        )

    try:
        with tempfile.NamedTemporaryFile(suffix=".json") as handle:
            handle.write(adjudication_bytes)
            handle.flush()
            corpus = publication_quality.load_adjudications(
                Path(handle.name), alias_map=alias_map
            )
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseEvidenceError(
            f"archived publication adjudications are invalid: {exc}"
        ) from exc
    normalized = [
        {
            "canonical_id": entry.canonical_id,
            "label": entry.label,
            "subject_ids": sorted(entry.subject_ids),
        }
        for entry in sorted(corpus.entries, key=lambda item: item.canonical_id)
    ]
    if inputs.get("normalized_adjudications") != normalized or inputs.get(
        "normalized_adjudications_sha256"
    ) != _canonical_sha256(normalized):
        raise ReleaseEvidenceError(
            "publication curation normalized adjudications are invalid"
        )

    try:
        index_payload = json.loads(index_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseEvidenceError(
            "archived publication index is not UTF-8 JSON"
        ) from exc
    ordered_ids = inputs.get("published_ordered_ids")
    if (
        not isinstance(index_payload, dict)
        or not isinstance(ordered_ids, list)
        or index_payload.get("ids") != ordered_ids
        or index_payload.get("total") != len(ordered_ids)
        or len(ordered_ids) != len(set(ordered_ids))
        or any(
            not isinstance(subject_id, str) or not subject_id
            for subject_id in ordered_ids
        )
        or inputs.get("published_ordered_ids_sha256") != _canonical_sha256(ordered_ids)
    ):
        raise ReleaseEvidenceError("publication curation ordered IDs are invalid")
    publication_files = publication_manifest.get("files")
    index_entries = (
        [
            entry
            for entry in publication_files
            if isinstance(entry, dict) and entry.get("path") == "index.json"
        ]
        if isinstance(publication_files, list)
        else []
    )
    if (
        len(index_entries) != 1
        or index_entries[0].get("sha256") != hashlib.sha256(index_bytes).hexdigest()
        or index_entries[0].get("size_bytes") != len(index_bytes)
    ):
        raise ReleaseEvidenceError(
            "publication curation index is not bound to the publication manifest"
        )
    recomputed = publication_quality.evaluate(
        corpus,
        set(ordered_ids),
        precision_target=float(targets["precision"]),
        recall_target=float(targets["recall"]),
    )
    if recomputed != report:
        raise ReleaseEvidenceError(
            "publication curation report does not match archived semantic inputs"
        )


def _replay_detector_inventory(
    inventory: Mapping[str, Any],
    *,
    campaign_contract: Mapping[str, Any],
    curation_inputs: Mapping[str, Any],
    source_remote_cutoff: Mapping[str, Any],
    heldout_campaign_population: Mapping[str, Any],
    bundle_path: Path,
) -> None:
    """Rebuild every detector-inventory row from archived formal inputs."""

    checked_at = source_remote_cutoff.get("checked_at_utc")
    try:
        parsed_checked_at = datetime.fromisoformat(checked_at)
    except (TypeError, ValueError) as exc:
        raise ReleaseEvidenceError(
            "detector inventory source cutoff timestamp is invalid"
        ) from exc
    if (
        not isinstance(checked_at, str)
        or parsed_checked_at.tzinfo is None
        or parsed_checked_at.utcoffset() != UTC.utcoffset(parsed_checked_at)
        or parsed_checked_at.isoformat() != checked_at
    ):
        raise ReleaseEvidenceError(
            "detector inventory source cutoff timestamp is not canonical UTC"
        )

    normalized = curation_inputs.get("normalized_adjudications")
    published = curation_inputs.get("published_ordered_ids")
    if not isinstance(normalized, list) or not isinstance(published, list):
        raise ReleaseEvidenceError(
            "detector inventory adjudication/publication inputs are missing"
        )
    adjudicated_positive_ids: set[str] = set()
    audit_exclusions: set[str] = set()
    for row in normalized:
        subject_ids = row.get("subject_ids") if isinstance(row, dict) else None
        label = row.get("label") if isinstance(row, dict) else None
        if (
            not isinstance(subject_ids, list)
            or any(not isinstance(subject_id, str) for subject_id in subject_ids)
            or label not in {"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"}
        ):
            raise ReleaseEvidenceError(
                "detector inventory normalized adjudications are malformed"
            )
        if label == "AI_CAUSAL":
            adjudicated_positive_ids.update(subject_ids)
        else:
            audit_exclusions.update(subject_ids)

    results = []
    try:
        for entry in _population_result_entries(heldout_campaign_population):
            item = detector_quality._load_cached_pipeline_input(
                bundle_path / entry["archive_path"],
                entry["subject_id"],
            )
            if item.file_sha256 != entry["sha256"]:
                raise ReleaseEvidenceError(
                    "detector inventory campaign result changed during replay"
                )
            results.append(item.result)
        expected = detector_inventory_builder.build_detector_inventory(
            tuple(results),
            alias_map={},
            adjudicated_positive_ids=adjudicated_positive_ids,
            audit_exclusions=audit_exclusions,
            published_ids=set(published),
            generated_at=checked_at,
            source_snapshot_sha256=campaign_contract["source_snapshot_sha256"],
            source_receipt_sha256=_canonical_sha256(source_remote_cutoff),
            campaign_id=campaign_contract["campaign_id"],
            contract_sha256=campaign_contract["contract_sha256"],
            campaign_mode="formal",
            coverage_to=checked_at[:10],
            require_stage_receipts=True,
            alias_class_manifest=campaign_contract.get("alias_class_manifest"),
        )
    except ReleaseEvidenceError:
        raise
    except (
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        detector_inventory_builder.DetectorInventoryError,
    ) as exc:
        raise ReleaseEvidenceError(
            f"detector inventory does not replay from archived inputs: {exc}"
        ) from exc
    if expected != inventory:
        raise ReleaseEvidenceError(
            "detector inventory does not exactly replay from archived campaign, "
            "alias, adjudication, publication, and source inputs"
        )


def _safe_alias_subject(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and _ALIAS_SUBJECT_ID.fullmatch(value)
        and "/" not in value
        and "\\" not in value
        and not any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        )
    )


def _reject_pilot_release_artifact(payload: Mapping[str, Any], *, label: str) -> None:
    if payload.get("artifact_kind") == "pilot":
        raise ReleaseEvidenceError(
            f"{label} is a pilot artifact and is not formal release eligible"
        )


def _validate_formal_alias_class_manifest(
    manifest: object,
    *,
    expected_manifest_sha256: object,
    expected_source_snapshot_sha256: object,
) -> tuple[dict[str, Mapping[str, Any]], dict[str, str]]:
    """Recompute every structural and source-evidence binding in a formal manifest."""

    manifest_fields = {
        "schema_version",
        "source_snapshot_sha256",
        "class_count",
        "eligible_seed_id_count",
        "all_eligible_seed_ids_exactly_once",
        "classes_sha256",
        "scheduled_class_count",
        "scheduled_analysis_subject_count",
        "scheduled_classes_exactly_once",
        "classes",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != manifest_fields
        or manifest.get("schema_version") != 1
        or manifest.get("source_snapshot_sha256") != expected_source_snapshot_sha256
        or not isinstance(expected_source_snapshot_sha256, str)
        or _SHA256.fullmatch(expected_source_snapshot_sha256) is None
        or manifest.get("classes_sha256") != expected_manifest_sha256
        or not isinstance(expected_manifest_sha256, str)
        or _SHA256.fullmatch(expected_manifest_sha256) is None
    ):
        raise ReleaseEvidenceError("campaign alias-class manifest is invalid")
    classes = manifest.get("classes")
    if (
        not isinstance(classes, list)
        or not classes
        or _runner_canonical_sha256(classes) != expected_manifest_sha256
        or isinstance(manifest.get("class_count"), bool)
        or manifest.get("class_count") != len(classes)
        or manifest.get("all_eligible_seed_ids_exactly_once") is not True
        or manifest.get("scheduled_classes_exactly_once") is not True
    ):
        raise ReleaseEvidenceError("campaign alias-class manifest is invalid")

    base_class_fields = {
        "class_id",
        "component_sha256",
        "all_member_ids",
        "eligible_seed_ids",
        "source_record_references",
        "merged_source_evidence_sha256",
        "analysis_subject",
        "analysis_input",
        "source_snapshot_sha256",
        "scheduled_seed_ids",
    }
    source_reference_fields = {
        "source",
        "record_id",
        "record_sha256",
        "reference",
    }
    analysis_input_fields = {
        "member_ids",
        "git_ranges",
        "fixed_events",
        "reference_urls",
    }
    class_ids: set[str] = set()
    member_owner: dict[str, str] = {}
    eligible_owner: dict[str, str] = {}
    scheduled_by_subject: dict[str, Mapping[str, Any]] = {}
    member_to_analysis_subject: dict[str, str] = {}
    scheduled_class_count = 0
    class_order: list[str] = []

    for class_record in classes:
        fields = set(class_record) if isinstance(class_record, dict) else set()
        supplemental = fields == base_class_fields | {"supplemental_candidate"}
        if (
            not isinstance(class_record, dict)
            or (fields != base_class_fields and not supplemental)
            or (supplemental and class_record.get("supplemental_candidate") is not True)
        ):
            raise ReleaseEvidenceError("campaign alias-class record is malformed")

        class_id = class_record.get("class_id")
        component_sha256 = class_record.get("component_sha256")
        members = class_record.get("all_member_ids")
        eligible = class_record.get("eligible_seed_ids")
        scheduled_seeds = class_record.get("scheduled_seed_ids")
        analysis_subject = class_record.get("analysis_subject")
        source_references = class_record.get("source_record_references")
        analysis_input = class_record.get("analysis_input")
        if (
            not isinstance(component_sha256, str)
            or _SHA256.fullmatch(component_sha256) is None
            or class_id != f"alias-{component_sha256[:24]}"
            or class_id in class_ids
            or not isinstance(members, list)
            or not members
            or any(not _safe_alias_subject(member) for member in members)
            or members != sorted(members)
            or len(members) != len(set(members))
            or not isinstance(eligible, list)
            or not eligible
            or any(not _safe_alias_subject(seed) for seed in eligible)
            or eligible != sorted(eligible)
            or len(eligible) != len(set(eligible))
            or not set(eligible).issubset(members)
            or not isinstance(scheduled_seeds, list)
            or not scheduled_seeds
            or any(not _safe_alias_subject(seed) for seed in scheduled_seeds)
            or scheduled_seeds != sorted(scheduled_seeds)
            or len(scheduled_seeds) != len(set(scheduled_seeds))
            or not set(scheduled_seeds).issubset(eligible)
            or not _safe_alias_subject(analysis_subject)
            or analysis_subject not in eligible
            or class_record.get("source_snapshot_sha256")
            != expected_source_snapshot_sha256
        ):
            raise ReleaseEvidenceError(
                "campaign alias-class component or member binding is invalid"
            )
        expected_component_sha256 = hashlib.sha256(
            ("\n".join(members) + "\n").encode("utf-8")
        ).hexdigest()
        expected_analysis_subject = next(
            (seed for seed in eligible if seed.startswith("CVE-")),
            next(
                (seed for seed in eligible if seed.startswith("GHSA-")),
                eligible[0],
            ),
        )
        if (
            component_sha256 != expected_component_sha256
            or analysis_subject != expected_analysis_subject
        ):
            raise ReleaseEvidenceError(
                "campaign alias-class component or analysis-subject binding is invalid"
            )

        if (
            not isinstance(analysis_input, dict)
            or set(analysis_input) != analysis_input_fields
            or analysis_input.get("member_ids") != members
        ):
            raise ReleaseEvidenceError("campaign alias-class analysis input is invalid")
        git_ranges = analysis_input.get("git_ranges")
        fixed_events = analysis_input.get("fixed_events")
        reference_urls = analysis_input.get("reference_urls")
        if (
            not isinstance(git_ranges, list)
            or any(not isinstance(item, dict) for item in git_ranges)
            or git_ranges
            != sorted(git_ranges, key=refresh_runner._canonical_json_bytes)
            or len({_runner_canonical_sha256(item) for item in git_ranges})
            != len(git_ranges)
            or not isinstance(fixed_events, list)
            or any(
                not isinstance(item, dict)
                or set(item) != {"kind", "value"}
                or item.get("kind") not in {"fixed", "last_affected", "limit"}
                or not isinstance(item.get("value"), str)
                or not item["value"]
                for item in fixed_events
            )
            or fixed_events
            != sorted(fixed_events, key=lambda item: (item["kind"], item["value"]))
            or len({_runner_canonical_sha256(item) for item in fixed_events})
            != len(fixed_events)
            or not isinstance(reference_urls, list)
            or any(not isinstance(url, str) or not url for url in reference_urls)
            or reference_urls != sorted(reference_urls)
            or len(reference_urls) != len(set(reference_urls))
        ):
            raise ReleaseEvidenceError(
                "campaign alias-class analysis evidence is invalid"
            )

        if not isinstance(source_references, list):
            raise ReleaseEvidenceError(
                "campaign alias-class source references are invalid"
            )
        expected_reference_order: list[tuple[str, str, str]] = []
        for source_reference in source_references:
            if (
                not isinstance(source_reference, dict)
                or set(source_reference) != source_reference_fields
            ):
                raise ReleaseEvidenceError(
                    "campaign alias-class source references are invalid"
                )
            source = source_reference.get("source")
            record_id = source_reference.get("record_id")
            record_sha256 = source_reference.get("record_sha256")
            if (
                not isinstance(source, str)
                or not source
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in source
                )
                or not isinstance(record_id, str)
                or (record_id != "" and not _safe_alias_subject(record_id))
                or not isinstance(record_sha256, str)
                or _SHA256.fullmatch(record_sha256) is None
                or source_reference.get("reference")
                != f"{source}:{record_id or record_sha256[:16]}"
            ):
                raise ReleaseEvidenceError(
                    "campaign alias-class source references are invalid"
                )
            expected_reference_order.append((source, record_id, record_sha256))
        if expected_reference_order != sorted(expected_reference_order):
            raise ReleaseEvidenceError(
                "campaign alias-class source references are invalid"
            )
        expected_source_evidence_sha256 = _runner_canonical_sha256(
            {"records": source_references, "analysis_input": analysis_input}
        )
        if (
            class_record.get("merged_source_evidence_sha256")
            != expected_source_evidence_sha256
        ):
            raise ReleaseEvidenceError(
                "campaign alias-class merged source evidence is invalid"
            )
        if supplemental and (
            len(members) != 1 or source_references or eligible != members
        ):
            raise ReleaseEvidenceError(
                "campaign supplemental alias-class binding is invalid"
            )

        class_ids.add(class_id)
        class_order.append(class_id)
        for member in members:
            if member in member_owner:
                raise ReleaseEvidenceError("campaign alias classes overlap")
            member_owner[member] = class_id
        for seed in eligible:
            if seed in eligible_owner:
                raise ReleaseEvidenceError(
                    "campaign alias-class eligible seeds overlap"
                )
            eligible_owner[seed] = class_id
        scheduled_class_count += 1
        if analysis_subject in scheduled_by_subject:
            raise ReleaseEvidenceError("campaign alias-class analysis subjects overlap")
        scheduled_by_subject[analysis_subject] = class_record
        for member in members:
            member_to_analysis_subject[member] = analysis_subject

    if (
        class_order != sorted(class_order)
        or isinstance(manifest.get("eligible_seed_id_count"), bool)
        or not isinstance(manifest.get("eligible_seed_id_count"), int)
        or manifest.get("eligible_seed_id_count") != len(eligible_owner)
        or isinstance(manifest.get("scheduled_class_count"), bool)
        or not isinstance(manifest.get("scheduled_class_count"), int)
        or manifest.get("scheduled_class_count") != scheduled_class_count
        or isinstance(manifest.get("scheduled_analysis_subject_count"), bool)
        or not isinstance(manifest.get("scheduled_analysis_subject_count"), int)
        or manifest.get("scheduled_analysis_subject_count") != len(scheduled_by_subject)
        or scheduled_class_count != len(scheduled_by_subject)
        or manifest.get("class_count") != scheduled_class_count
    ):
        raise ReleaseEvidenceError("campaign alias-class population counts are invalid")
    return scheduled_by_subject, member_to_analysis_subject


def _required_formal_analysis_subjects(
    corpus_manifest: object,
    *,
    corpus_manifest_sha256: object,
    normalized_adjudications: object,
    detector_adjudications_sha256: object,
    curation_adjudications_sha256: object,
    member_to_analysis_subject: Mapping[str, str],
) -> tuple[set[str], set[str]]:
    """Bind the frozen adjudication corpus to its scheduled analysis subjects."""

    if (
        not isinstance(corpus_manifest, list)
        or not corpus_manifest
        or not isinstance(corpus_manifest_sha256, str)
        or _SHA256.fullmatch(corpus_manifest_sha256) is None
        or _canonical_sha256(corpus_manifest) != corpus_manifest_sha256
    ):
        raise ReleaseEvidenceError("detector adjudication corpus manifest is invalid")
    if (
        not isinstance(detector_adjudications_sha256, str)
        or _SHA256.fullmatch(detector_adjudications_sha256) is None
        or detector_adjudications_sha256 != curation_adjudications_sha256
    ):
        raise ReleaseEvidenceError(
            "detector and publication frozen adjudication inputs differ"
        )
    required_source_subjects: set[str] = set()
    canonical_ids: set[str] = set()
    normalized_projection: list[dict[str, Any]] = []
    base_fields = {"canonical_id", "label", "subject_ids"}
    optional_fields = {"source", "confidence"}
    for row in corpus_manifest:
        fields = set(row) if isinstance(row, dict) else set()
        canonical_id = row.get("canonical_id") if isinstance(row, dict) else None
        label = row.get("label") if isinstance(row, dict) else None
        subject_ids = row.get("subject_ids") if isinstance(row, dict) else None
        confidence = row.get("confidence") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or not base_fields.issubset(fields)
            or not fields.issubset(base_fields | optional_fields)
            or not _safe_alias_subject(canonical_id)
            or canonical_id in canonical_ids
            or label not in {"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"}
            or not isinstance(subject_ids, list)
            or not subject_ids
            or any(not _safe_alias_subject(subject_id) for subject_id in subject_ids)
            or subject_ids != sorted(subject_ids)
            or len(subject_ids) != len(set(subject_ids))
            or canonical_id not in subject_ids
            or bool(required_source_subjects.intersection(subject_ids))
            or (
                "source" in row
                and (not isinstance(row["source"], str) or not row["source"])
            )
            or (
                "confidence" in row
                and (
                    isinstance(confidence, bool)
                    or not isinstance(confidence, (int, float))
                    or not math.isfinite(float(confidence))
                    or not 0.0 <= float(confidence) <= 1.0
                )
            )
        ):
            raise ReleaseEvidenceError(
                "detector adjudication corpus manifest is invalid"
            )
        canonical_ids.add(canonical_id)
        required_source_subjects.update(subject_ids)
        normalized_projection.append(
            {
                "canonical_id": canonical_id,
                "label": label,
                "subject_ids": subject_ids,
            }
        )

    normalized_projection.sort(key=lambda row: row["canonical_id"])
    if normalized_adjudications != normalized_projection:
        raise ReleaseEvidenceError(
            "detector and publication frozen adjudication corpora differ"
        )
    missing = sorted(required_source_subjects - set(member_to_analysis_subject))
    if missing:
        raise ReleaseEvidenceError(
            "frozen adjudication subjects are absent from the formal campaign: "
            f"{missing[:10]}"
        )
    required_analysis_subjects = {
        member_to_analysis_subject[subject_id]
        for subject_id in required_source_subjects
    }
    return required_source_subjects, required_analysis_subjects


def _validate_campaign_archive_contract(
    campaign_contract: Mapping[str, Any],
    *,
    campaign_result_entries: Mapping[str, Mapping[str, Any]],
    receipt: Mapping[str, Any],
) -> tuple[
    dict[str, Mapping[str, Any]],
    dict[str, str],
    dict[str, str],
]:
    """Validate and index the exact archived campaign and batch ownership graph."""

    _reject_pilot_release_artifact(campaign_contract, label="campaign contract")

    contract_fields = {
        "schema_version",
        "campaign_id",
        "repo_root",
        "marker_dir",
        "result_dir",
        "contract_sha256",
        "analyzer_contract_sha256",
        "signature_sha256",
        "alias_class_manifest_sha256",
        "source_snapshot_sha256",
        "model",
        "reasoning_effort",
        "workers",
        "marker_schema_version",
        "litellm_transport_sha256",
        "litellm_transport",
        "batch_timeout_seconds",
        "campaign_mode",
        "population_policy",
        "campaign_mode",
        "population_policy",
        "analyzer_contract_sha256",
        "signature_sha256",
        "alias_class_manifest_sha256",
        "alias_class_manifest",
        "incremental_plan_proof",
        "batches",
    }
    digest_fields = (
        "campaign_id",
        "contract_sha256",
        "source_snapshot_sha256",
        "litellm_transport_sha256",
        "analyzer_contract_sha256",
        "signature_sha256",
        "alias_class_manifest_sha256",
    )
    path_fields = ("repo_root", "marker_dir", "result_dir")
    if (
        set(campaign_contract) != contract_fields
        or campaign_contract.get("schema_version") != 2
        or any(
            not isinstance(campaign_contract.get(field), str)
            or _SHA256.fullmatch(campaign_contract[field]) is None
            for field in digest_fields
        )
        or any(
            not isinstance(campaign_contract.get(field), str)
            or not Path(campaign_contract[field]).is_absolute()
            for field in path_fields
        )
        or isinstance(campaign_contract.get("workers"), bool)
        or not isinstance(campaign_contract.get("workers"), int)
        or campaign_contract["workers"] <= 0
        or campaign_contract.get("marker_schema_version")
        != refresh_runner.MARKER_SCHEMA_VERSION
        or not isinstance(campaign_contract.get("litellm_transport"), dict)
        or _runner_canonical_sha256(campaign_contract["litellm_transport"])
        != campaign_contract.get("litellm_transport_sha256")
        or isinstance(campaign_contract.get("batch_timeout_seconds"), bool)
        or not isinstance(campaign_contract.get("batch_timeout_seconds"), int)
        or campaign_contract["batch_timeout_seconds"]
        != refresh_runner.BATCH_TIMEOUT_SECONDS
        or not isinstance(campaign_contract.get("incremental_plan_proof"), dict)
        or campaign_contract.get("campaign_mode") != "formal"
        or campaign_contract.get("population_policy") != "formal_full"
    ):
        raise ReleaseEvidenceError("campaign contract requires the exact schema")
    if (
        campaign_contract.get("model") != refresh_runner.MODEL
        or campaign_contract.get("reasoning_effort") != refresh_runner.REASONING_EFFORT
        or campaign_contract.get("workers") != refresh_runner.WORKERS
    ):
        raise ReleaseEvidenceError("campaign contract Luna/max proof is invalid")
    alias_manifest = campaign_contract.get("alias_class_manifest")
    alias_source_snapshot_sha256 = (
        alias_manifest.get("source_snapshot_sha256")
        if isinstance(alias_manifest, dict)
        else None
    )
    scheduled_by_subject, member_to_analysis_subject = (
        _validate_formal_alias_class_manifest(
            alias_manifest,
            expected_manifest_sha256=campaign_contract.get(
                "alias_class_manifest_sha256"
            ),
            # The class-source digest is derived from the source-delta input
            # guard.  It is intentionally distinct from the runner's broader
            # campaign source snapshot, and every class must bind to this one
            # manifest declaration.
            expected_source_snapshot_sha256=alias_source_snapshot_sha256,
        )
    )
    scheduled_class_ids = {
        str(class_record["class_id"]) for class_record in scheduled_by_subject.values()
    }
    expected_campaign_id = _campaign_identity_sha256(campaign_contract)
    marker_root = Path(campaign_contract["marker_dir"]).resolve(strict=False)
    expected_result_dir = (
        marker_root.parent.parent / "campaigns-v1" / expected_campaign_id / "results"
    )
    if (
        campaign_contract["campaign_id"] != expected_campaign_id
        or Path(campaign_contract["result_dir"]).resolve(strict=False)
        != expected_result_dir
    ):
        raise ReleaseEvidenceError(
            "campaign identity or content-addressed result path is invalid"
        )
    if (
        campaign_contract["campaign_id"] != receipt.get("campaign_id")
        or campaign_contract["contract_sha256"] != receipt.get("contract_sha256")
        or campaign_contract["source_snapshot_sha256"]
        != receipt.get("source_snapshot_sha256")
        or campaign_contract["result_dir"] != receipt.get("campaign_result_dir")
        or campaign_contract["model"] != receipt.get("model")
        or campaign_contract["reasoning_effort"] != receipt.get("reasoning_effort")
        or campaign_contract["workers"] != receipt.get("workers")
        or campaign_contract["litellm_transport_sha256"]
        != receipt.get("litellm_transport_sha256")
        or campaign_contract["campaign_mode"] != receipt.get("campaign_mode")
        or campaign_contract["population_policy"] != receipt.get("population_policy")
        or campaign_contract["analyzer_contract_sha256"]
        != receipt.get("analyzer_contract_sha256")
        or campaign_contract["signature_sha256"] != receipt.get("signature_sha256")
        or campaign_contract["alias_class_manifest_sha256"]
        != receipt.get("alias_class_manifest_sha256")
    ):
        raise ReleaseEvidenceError(
            "campaign contract does not match the release receipt"
        )

    batches = campaign_contract.get("batches")
    batch_fields = {
        "key",
        "path",
        "ids",
        "class_ids",
        "command",
        "batch_sha256",
        "command_sha256",
        "batch_bytes_base64",
        "marker_bytes_base64",
    }
    if not isinstance(batches, list) or not batches:
        raise ReleaseEvidenceError("campaign contract batch inventory is invalid")
    batch_by_key: dict[str, Mapping[str, Any]] = {}
    subject_owner: dict[str, str] = {}
    for batch in batches:
        if not isinstance(batch, dict) or set(batch) != batch_fields:
            raise ReleaseEvidenceError("campaign contract batch schema is invalid")
        key = batch.get("key")
        ids = batch.get("ids")
        class_ids = batch.get("class_ids")
        command = batch.get("command")
        batch_bytes = (
            _decode_archived_bytes(
                batch.get("batch_bytes_base64"),
                label=f"campaign batch {key!r}",
            )
            if isinstance(key, str)
            else b""
        )
        if (
            not isinstance(key, str)
            or not key
            or Path(key).name != key
            or key in batch_by_key
            or not isinstance(batch.get("path"), str)
            or not Path(batch["path"]).is_absolute()
            or not isinstance(ids, list)
            or not ids
            or any(
                not isinstance(subject_id, str) or not subject_id for subject_id in ids
            )
            or len(set(ids)) != len(ids)
            or not isinstance(class_ids, list)
            or len(class_ids) != len(ids)
            or any(not isinstance(class_id, str) for class_id in class_ids)
            or len(set(class_ids)) != len(class_ids)
            or not isinstance(command, list)
            or not command
            or any(
                not isinstance(argument, str) or not argument for argument in command
            )
            or not isinstance(batch.get("batch_sha256"), str)
            or _SHA256.fullmatch(batch["batch_sha256"]) is None
            or hashlib.sha256(batch_bytes).hexdigest() != batch["batch_sha256"]
            or batch.get("command_sha256") != _canonical_sha256(command)
        ):
            raise ReleaseEvidenceError("campaign contract batch schema is invalid")
        for subject_id, class_id in zip(ids, class_ids, strict=True):
            class_record = scheduled_by_subject.get(subject_id)
            if class_record is None or class_record.get("class_id") != class_id:
                raise ReleaseEvidenceError(
                    "campaign batch alias-class mapping is invalid"
                )
        expected_batch_bytes = ("\n".join(ids) + "\n").encode("utf-8")
        if batch_bytes != expected_batch_bytes:
            raise ReleaseEvidenceError(
                "campaign batch raw bytes do not exactly match its subject IDs"
            )
        repo_root = Path(campaign_contract["repo_root"]).resolve(strict=False)
        batch_path = Path(batch["path"]).resolve(strict=False)
        try:
            batch_path.relative_to(repo_root)
        except ValueError as exc:
            raise ReleaseEvidenceError(
                "campaign batch path escapes the bound repository"
            ) from exc
        expected_command = refresh_runner.build_command(
            refresh_runner.BatchSpec(
                key=key,
                path=batch_path,
                kind="archived_release_validation",
                ids=tuple(ids),
                repos=frozenset(),
            )
        )
        if command != expected_command:
            raise ReleaseEvidenceError(
                "campaign command does not match the canonical runner command"
            )
        # Decode here as part of the batch schema.  Its digest and semantic
        # runner contract are checked against the fixed proof below.
        _decode_archived_bytes(
            batch.get("marker_bytes_base64"),
            label=f"campaign marker {key!r}",
        )
        for subject_id in ids:
            if subject_id in subject_owner:
                raise ReleaseEvidenceError(
                    "campaign contract subjects must have exactly one batch owner"
                )
            subject_owner[subject_id] = key
        batch_by_key[key] = batch
    if set(subject_owner) != set(scheduled_by_subject):
        raise ReleaseEvidenceError(
            "campaign batches do not cover the scheduled alias classes exactly once"
        )
    archived_class_ids = {
        class_id for batch in batches for class_id in batch["class_ids"]
    }
    if archived_class_ids != scheduled_class_ids:
        raise ReleaseEvidenceError(
            "campaign batch class IDs do not match the alias manifest"
        )
    if list(batch_by_key) != sorted(batch_by_key):
        raise ReleaseEvidenceError("campaign contract batch keys must be sorted")
    if set(subject_owner) != set(campaign_result_entries):
        raise ReleaseEvidenceError(
            "campaign contract subject union does not match campaign results"
        )
    return batch_by_key, subject_owner, member_to_analysis_subject


def _archived_alias_map(population: Mapping[str, Any]) -> dict[str, set[str]]:
    """Validate and expand the archived source-derived alias-class projection."""

    rows = population.get("alias_classes")
    if not isinstance(rows, list):
        raise ReleaseEvidenceError("held-out campaign alias inventory is invalid")
    components: list[tuple[str, ...]] = []
    seen: set[str] = set()
    alias_map: dict[str, set[str]] = {}
    for row in rows:
        subject_ids = row.get("subject_ids") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or set(row) != {"subject_ids"}
            or not isinstance(subject_ids, list)
            or not subject_ids
            or any(
                not isinstance(subject_id, str)
                or not subject_id
                or Path(subject_id).name != subject_id
                for subject_id in subject_ids
            )
            or subject_ids != sorted(subject_ids)
            or len({_subject.casefold() for _subject in subject_ids})
            != len(subject_ids)
        ):
            raise ReleaseEvidenceError("held-out campaign alias row is invalid")
        normalized = {subject_id.casefold() for subject_id in subject_ids}
        if seen & normalized:
            raise ReleaseEvidenceError("held-out campaign alias classes overlap")
        seen.update(normalized)
        component = tuple(subject_ids)
        components.append(component)
        closure = set(subject_ids)
        for subject_id in subject_ids:
            alias_map[subject_id] = closure
    if components != sorted(components):
        raise ReleaseEvidenceError("held-out campaign alias rows are not sorted")
    if population.get("alias_classes_sha256") != _canonical_sha256(rows):
        raise ReleaseEvidenceError("held-out campaign alias manifest is invalid")
    return alias_map


def _archived_protected_inventory(
    population: Mapping[str, Any],
    *,
    selection: Mapping[str, Any],
    alias_map: Mapping[str, set[str]],
) -> heldout_quality.ProtectedInventory:
    """Rebuild the protected subject set from the archived exact input bytes."""

    archive = population.get("protected_inputs")
    selection_contract = selection.get("protected_inputs")
    fields = {
        "source_roots",
        "file_count",
        "total_size_bytes",
        "files_manifest_sha256",
        "files",
    }
    if (
        not isinstance(archive, dict)
        or set(archive) != fields
        or not isinstance(selection_contract, dict)
    ):
        raise ReleaseEvidenceError("held-out protected input archive is invalid")
    source_roots = archive.get("source_roots")
    files = archive.get("files")
    if (
        not isinstance(source_roots, list)
        or not isinstance(files, list)
        or archive.get("file_count") != len(files)
        or selection_contract.get("source_roots") != source_roots
    ):
        raise ReleaseEvidenceError("held-out protected input inventory is invalid")

    root_paths: list[tuple[PurePosixPath, str]] = []
    prior_root = ""
    for root in source_roots:
        relative = root.get("path") if isinstance(root, dict) else None
        kind = root.get("kind") if isinstance(root, dict) else None
        candidate = PurePosixPath(relative) if isinstance(relative, str) else None
        if (
            not isinstance(root, dict)
            or set(root) != {"path", "kind"}
            or candidate is None
            or candidate.is_absolute()
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or kind not in {"file", "directory"}
            or relative <= prior_root
        ):
            raise ReleaseEvidenceError("held-out protected source root is invalid")
        prior_root = relative
        root_paths.append((candidate, kind))

    metadata_rows: list[dict[str, Any]] = []
    raw_subjects: set[str] = set()
    total_size = 0
    prior_path = ""
    encoded_limit = ((_MAX_ARCHIVED_PROTECTED_INPUT_BYTES + 2) // 3) * 4
    for entry in files:
        expected_fields = {
            "path",
            "size_bytes",
            "sha256",
            "referenced_subject_count",
            "referenced_subject_ids_sha256",
            "bytes_base64",
        }
        relative = entry.get("path") if isinstance(entry, dict) else None
        candidate = PurePosixPath(relative) if isinstance(relative, str) else None
        encoded = entry.get("bytes_base64") if isinstance(entry, dict) else None
        size = entry.get("size_bytes") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or set(entry) != expected_fields
            or candidate is None
            or candidate.is_absolute()
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or relative <= prior_path
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > _MAX_ARCHIVED_PROTECTED_INPUT_BYTES
            or not isinstance(encoded, str)
            or len(encoded) > encoded_limit
            or not isinstance(entry.get("sha256"), str)
            or _SHA256.fullmatch(entry["sha256"]) is None
        ):
            raise ReleaseEvidenceError("held-out protected input entry is invalid")
        if not any(
            candidate == root_path
            if kind == "file"
            else candidate == root_path or root_path in candidate.parents
            for root_path, kind in root_paths
        ):
            raise ReleaseEvidenceError(
                "held-out protected input is outside its source roots"
            )
        content = _decode_archived_bytes(
            encoded,
            label=f"held-out protected input {relative}",
        )
        total_size += len(content)
        if total_size > _MAX_ARCHIVED_PROTECTED_INPUTS_TOTAL_BYTES:
            raise ReleaseEvidenceError(
                "held-out protected inputs exceed archive size bound"
            )
        try:
            referenced = sorted(
                heldout_quality._extract_subject_tokens(content, candidate)
            )
        except heldout_quality.HeldoutQualityError as exc:
            raise ReleaseEvidenceError(
                f"held-out protected input cannot be replayed: {exc}"
            ) from exc
        metadata = {key: entry[key] for key in expected_fields - {"bytes_base64"}}
        if (
            size != len(content)
            or entry["sha256"] != hashlib.sha256(content).hexdigest()
            or entry.get("referenced_subject_count") != len(referenced)
            or entry.get("referenced_subject_ids_sha256")
            != _canonical_sha256(referenced)
        ):
            raise ReleaseEvidenceError(
                "held-out protected input bytes do not match their manifest"
            )
        prior_path = relative
        metadata_rows.append(metadata)
        raw_subjects.update(referenced)

    if (
        archive.get("total_size_bytes") != total_size
        or archive.get("files_manifest_sha256") != _canonical_sha256(metadata_rows)
        or selection_contract.get("files") != metadata_rows
        or selection_contract.get("files_manifest_sha256")
        != archive.get("files_manifest_sha256")
    ):
        raise ReleaseEvidenceError("held-out protected input manifest is invalid")

    alias_index = heldout_quality._normalized_alias_index(alias_map)
    expanded = set(raw_subjects)
    for subject_id in tuple(raw_subjects):
        expanded.update(alias_index.get(subject_id.casefold(), frozenset({subject_id})))
    sorted_subjects = sorted(expanded)
    protected = heldout_quality.ProtectedInventory(
        subject_ids=frozenset(sorted_subjects),
        source_roots=tuple(dict(row) for row in source_roots),
        files=tuple(metadata_rows),
        files_manifest_sha256=_canonical_sha256(metadata_rows),
        subject_ids_sha256=_canonical_sha256(sorted_subjects),
    )
    if (
        selection_contract.get("subject_id_count") != len(protected.subject_ids)
        or selection_contract.get("subject_ids_sha256") != protected.subject_ids_sha256
    ):
        raise ReleaseEvidenceError(
            "held-out protected subject set does not replay from archived bytes"
        )
    return protected


def _replay_heldout_campaign_population(
    population: Mapping[str, Any],
    *,
    selection: Mapping[str, Any],
    campaign_contract: Mapping[str, Any],
    fixed_proof: Mapping[str, Any],
    result_manifest: Mapping[str, Any],
    campaign_result_entries: Mapping[str, Mapping[str, Any]],
    receipt: Mapping[str, Any],
    bundle_path: Path,
) -> None:
    """Rebuild the complete alias population and deterministic top-k selection."""

    fields = {
        "schema_version",
        "campaign_id",
        "result_dir",
        "result_count",
        "total_result_size_bytes",
        "result_manifest_sha256",
        "results",
        "alias_classes",
        "alias_classes_sha256",
        "protected_inputs",
    }
    if set(population) != fields or population.get("schema_version") != 1:
        raise ReleaseEvidenceError(
            "held-out campaign population requires the exact schema"
        )
    if _canonical_sha256(population) != receipt.get(
        "heldout_campaign_population_sha256"
    ):
        raise ReleaseEvidenceError(
            "held-out campaign population hash does not match the receipt"
        )
    population_results = _population_result_entries(population)
    if (
        population.get("campaign_id") != campaign_contract.get("campaign_id")
        or population.get("result_dir") != campaign_contract.get("result_dir")
        or population.get("result_count") != len(campaign_result_entries)
        or population.get("result_manifest_sha256")
        != result_manifest.get("manifest_sha256")
        or [entry["subject_id"] for entry in population_results]
        != list(campaign_result_entries)
    ):
        raise ReleaseEvidenceError(
            "held-out campaign population does not match the fixed campaign"
        )
    for entry in population_results:
        manifest_entry = campaign_result_entries.get(entry["subject_id"])
        if (
            manifest_entry is None
            or entry["file_name"] != manifest_entry.get("file_name")
            or entry["size_bytes"] != manifest_entry.get("size_bytes")
            or entry["sha256"] != manifest_entry.get("sha256")
        ):
            raise ReleaseEvidenceError(
                "held-out campaign raw result does not match its manifest"
            )

    alias_map = _archived_alias_map(population)
    protected = _archived_protected_inventory(
        population,
        selection=selection,
        alias_map=alias_map,
    )
    inputs: dict[str, tuple[detector_quality.CachedPipelineInput, ...]] = {}
    try:
        for entry in population_results:
            subject_id = entry["subject_id"]
            archived_path = bundle_path / entry["archive_path"]
            item = detector_quality._load_cached_pipeline_input(
                archived_path,
                subject_id,
            )
            if item.file_sha256 != entry["sha256"]:
                raise ReleaseEvidenceError(
                    "held-out campaign raw result changed during replay"
                )
            inputs[subject_id] = (item,)
        units = heldout_quality._alias_units(
            list(campaign_result_entries),
            alias_map,
            inputs,
        )
    except ReleaseEvidenceError:
        raise
    except (
        OSError,
        UnicodeError,
        ValueError,
        heldout_quality.HeldoutQualityError,
    ) as exc:
        raise ReleaseEvidenceError(
            f"held-out campaign population replay failed: {exc}"
        ) from exc

    unit_manifest = [
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
    snapshot = heldout_quality.CampaignSnapshot(
        campaign_id=campaign_contract["campaign_id"],
        contract_sha256=campaign_contract["contract_sha256"],
        source_snapshot_sha256=campaign_contract["source_snapshot_sha256"],
        campaign_proof_sha256=_canonical_sha256(fixed_proof),
        campaign_result_manifest_sha256=_canonical_sha256(unit_manifest),
        proof_complete=True,
        units=units,
    )
    policy = selection.get("selection_policy")
    if not isinstance(policy, dict):
        raise ReleaseEvidenceError("held-out selection policy is missing")
    try:
        expected = heldout_quality.build_selection_manifest(
            snapshot,
            protected,
            precision_sample_size=policy.get("precision_sample_size"),
            recall_sample_size=policy.get("recall_sample_size"),
            selection_code_sha256=policy.get("selection_code_sha256"),
        )
    except heldout_quality.HeldoutQualityError as exc:
        raise ReleaseEvidenceError(
            f"held-out deterministic selection replay failed: {exc}"
        ) from exc
    if expected != selection:
        raise ReleaseEvidenceError(
            "held-out selection does not deterministically replay from the full "
            "archived campaign population"
        )


def _validate_fixed_campaign_proof(
    proof: Mapping[str, Any],
    *,
    campaign_results: Mapping[str, str],
    campaign_result_entries: Mapping[str, Mapping[str, Any]],
    campaign_contract: Mapping[str, Any],
    corpus_manifest: object,
    corpus_manifest_sha256: object,
    normalized_adjudications: object,
    detector_adjudications_sha256: object,
    curation_adjudications_sha256: object,
    source_snapshot: Mapping[str, Any],
    receipt: Mapping[str, Any],
    bundle_path: Path,
) -> None:
    """Validate the exact successful campaign-proof shape and every count/hash link."""

    required_fields = {
        "complete",
        "campaign_mode",
        "population_policy",
        "formal_population_complete",
        "incremental_plan_complete",
        "full_incremental_plan_campaign_complete",
        "proof_scope",
        "population_uniform_luna_max_proof",
        "incremental_plan_proof",
        "required_subject_count",
        "required_campaign_subject_count",
        "mapped_subject_count",
        "campaign_subject_count",
        "campaign_batch_count",
        "completed_marker_count",
        "relevant_marker_count",
        "expected_contract",
        "failure_counts",
        "failures",
        "marker_proofs",
        "subject_proofs",
    }
    if set(proof) != required_fields:
        raise ReleaseEvidenceError("fixed campaign proof requires the exact schema")
    batch_by_key, subject_owner, member_to_analysis_subject = (
        _validate_campaign_archive_contract(
            campaign_contract,
            campaign_result_entries=campaign_result_entries,
            receipt=receipt,
        )
    )
    required_source_subjects, required_analysis_subjects = (
        _required_formal_analysis_subjects(
            corpus_manifest,
            corpus_manifest_sha256=corpus_manifest_sha256,
            normalized_adjudications=normalized_adjudications,
            detector_adjudications_sha256=detector_adjudications_sha256,
            curation_adjudications_sha256=curation_adjudications_sha256,
            member_to_analysis_subject=member_to_analysis_subject,
        )
    )
    if (
        proof.get("complete") is not True
        or proof.get("campaign_mode") != "formal"
        or proof.get("population_policy") != "formal_full"
        or proof.get("formal_population_complete") is not True
        or proof.get("incremental_plan_complete") is not False
        or proof.get("full_incremental_plan_campaign_complete") is not False
        or proof.get("proof_scope") != "formal_current_source_alias_class_plan"
        or proof.get("population_uniform_luna_max_proof") is not False
        or proof.get("failures") != []
        or proof.get("failure_counts") != {}
    ):
        raise ReleaseEvidenceError(
            "fixed campaign completeness proof records contradictory failures"
        )
    count_fields = (
        "required_subject_count",
        "required_campaign_subject_count",
        "mapped_subject_count",
        "campaign_subject_count",
        "campaign_batch_count",
        "completed_marker_count",
        "relevant_marker_count",
    )
    if any(
        isinstance(proof.get(field), bool)
        or not isinstance(proof.get(field), int)
        or proof[field] < 0
        for field in count_fields
    ):
        raise ReleaseEvidenceError("fixed campaign proof counts are invalid")
    if (
        proof["required_subject_count"] != len(required_source_subjects)
        or proof["mapped_subject_count"] != len(required_source_subjects)
        or proof["required_campaign_subject_count"] != len(required_analysis_subjects)
        or proof["required_campaign_subject_count"] > proof["campaign_subject_count"]
        or proof["campaign_subject_count"] != len(campaign_results)
        or proof["campaign_batch_count"] != len(batch_by_key)
        or proof["completed_marker_count"] != proof["campaign_batch_count"]
        or proof["relevant_marker_count"] > proof["campaign_batch_count"]
    ):
        raise ReleaseEvidenceError("fixed campaign proof counts are inconsistent")

    plan = proof.get("incremental_plan_proof")
    plan_fields = {
        "schema_version",
        "scope",
        "campaign_mode",
        "population_policy",
        "formal_release_eligible",
        "source_delta_schema_version",
        "source_delta_path",
        "source_delta_sha256",
        "source_delta_integrity_payload_sha256",
        "input_snapshot_sha256",
        "result_cache_inventory_manifest_sha256",
        "production_discovered_id_count",
        "cache_covered_discovered_id_count",
        "uncached_discovered_id_count",
        "candidate_id_count",
        "candidate_sha256",
        "plan_subject_id_count",
        "plan_subject_ids_sha256",
        "alias_class_manifest_sha256",
        "source_alias_class_count",
        "scheduled_alias_class_count",
        "plan_alias_classes_exactly_once",
        "analyzer_contract_sha256",
        "signature_sha256",
        "candidate_union_exact",
        "plan_exactly_matches_candidate",
        "frozen_local_sources",
        "network_advisory_api_included",
        "historical_cache_suppresses_current_classes",
        "formal_current_epoch_stage_receipt_required",
        "boundary",
    }
    result_ids_bytes = ("\n".join(sorted(campaign_results)) + "\n").encode("utf-8")
    plan_count_fields = (
        "production_discovered_id_count",
        "cache_covered_discovered_id_count",
        "uncached_discovered_id_count",
        "candidate_id_count",
        "plan_subject_id_count",
        "source_alias_class_count",
        "scheduled_alias_class_count",
    )
    if (
        not isinstance(plan, dict)
        or set(plan) != plan_fields
        or any(
            isinstance(plan.get(field), bool)
            or not isinstance(plan.get(field), int)
            or plan[field] < 0
            for field in plan_count_fields
        )
        or plan.get("schema_version") != 2
        or plan.get("scope") != "formal_current_source_alias_class_plan"
        or plan.get("campaign_mode") != "formal"
        or plan.get("population_policy") != "formal_full"
        or plan.get("formal_release_eligible") is not True
        or plan.get("source_delta_schema_version")
        != refresh_runner.SOURCE_DELTA_SCHEMA_VERSION
        or any(
            plan.get(field) is not True
            for field in (
                "candidate_union_exact",
                "plan_exactly_matches_candidate",
                "frozen_local_sources",
            )
        )
        or plan.get("network_advisory_api_included") is not False
        or plan.get("historical_cache_suppresses_current_classes") is not False
        or plan.get("formal_current_epoch_stage_receipt_required") is not True
        or plan.get("plan_alias_classes_exactly_once") is not True
        or plan.get("candidate_id_count") != len(campaign_results)
        or plan.get("plan_subject_id_count") != len(campaign_results)
        or plan.get("scheduled_alias_class_count") != len(campaign_results)
        or plan.get("source_alias_class_count")
        != plan.get("scheduled_alias_class_count")
        or plan.get("alias_class_manifest_sha256")
        != campaign_contract.get("alias_class_manifest_sha256")
        or plan.get("analyzer_contract_sha256")
        != campaign_contract.get("analyzer_contract_sha256")
        or plan.get("signature_sha256") != campaign_contract.get("signature_sha256")
        or plan.get("production_discovered_id_count")
        != plan.get("cache_covered_discovered_id_count")
        + plan.get("uncached_discovered_id_count")
        or plan.get("plan_subject_ids_sha256")
        != hashlib.sha256(result_ids_bytes).hexdigest()
        or any(
            not isinstance(plan.get(field), str)
            or _SHA256.fullmatch(plan[field]) is None
            for field in (
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
        )
    ):
        raise ReleaseEvidenceError("fixed campaign proof incremental plan is invalid")

    expected = proof.get("expected_contract")
    expected_fields = {
        "marker_schema_version",
        "campaign_id",
        "result_dir",
        "contract_sha256",
        "analyzer_contract_sha256",
        "signature_sha256",
        "alias_class_manifest_sha256",
        "source_snapshot_sha256",
        "model",
        "reasoning_effort",
        "workers",
        "litellm_transport_sha256",
        "litellm_transport",
        "batch_timeout_seconds",
        "campaign_mode",
        "population_policy",
        "incremental_plan_proof",
    }
    if (
        not isinstance(expected, dict)
        or set(expected) != expected_fields
        or expected.get("marker_schema_version")
        != campaign_contract.get("marker_schema_version")
        or expected.get("campaign_id") != receipt.get("campaign_id")
        or expected.get("contract_sha256") != receipt.get("contract_sha256")
        or expected.get("analyzer_contract_sha256")
        != campaign_contract.get("analyzer_contract_sha256")
        or expected.get("signature_sha256") != campaign_contract.get("signature_sha256")
        or expected.get("alias_class_manifest_sha256")
        != campaign_contract.get("alias_class_manifest_sha256")
        or expected.get("source_snapshot_sha256")
        != receipt.get("source_snapshot_sha256")
        or expected.get("result_dir") != campaign_contract.get("result_dir")
        or expected.get("model") != "gpt-5.6-luna"
        or expected.get("reasoning_effort") != "max"
        or expected.get("workers") != campaign_contract.get("workers")
        or expected.get("litellm_transport_sha256")
        != campaign_contract.get("litellm_transport_sha256")
        or expected.get("litellm_transport")
        != campaign_contract.get("litellm_transport")
        or expected.get("batch_timeout_seconds")
        != campaign_contract.get("batch_timeout_seconds")
        or expected.get("campaign_mode") != "formal"
        or expected.get("population_policy") != "formal_full"
        or expected.get("incremental_plan_proof") != plan
        or expected.get("incremental_plan_proof")
        != campaign_contract.get("incremental_plan_proof")
    ):
        raise ReleaseEvidenceError("fixed campaign proof Luna/max contract is invalid")

    markers = proof.get("marker_proofs")
    marker_fields = {
        "batch",
        "path",
        "marker_sha256",
        "batch_sha256",
        "command_sha256",
        "result_manifest_sha256",
        "class_receipts_sha256",
        "started_at_ns",
        "completed_at_ns",
    }
    if not isinstance(markers, list) or len(markers) != proof["completed_marker_count"]:
        raise ReleaseEvidenceError("fixed campaign proof marker inventory is invalid")
    marker_batches = [
        entry.get("batch") if isinstance(entry, dict) else None for entry in markers
    ]
    if (
        any(not isinstance(batch, str) or not batch for batch in marker_batches)
        or marker_batches != sorted(marker_batches)
        or len(set(marker_batches)) != len(marker_batches)
        or set(marker_batches) != set(batch_by_key)
    ):
        raise ReleaseEvidenceError("fixed campaign proof marker inventory is invalid")
    marker_by_batch: dict[str, Mapping[str, Any]] = {}
    for marker in markers:
        contract_batch = (
            batch_by_key.get(marker.get("batch")) if isinstance(marker, dict) else None
        )
        if (
            not isinstance(marker, dict)
            or set(marker) != marker_fields
            or not isinstance(marker.get("batch"), str)
            or not marker["batch"]
            or marker["batch"] in marker_by_batch
            or not isinstance(marker.get("path"), str)
            or any(
                not isinstance(marker.get(field), str)
                or _SHA256.fullmatch(marker[field]) is None
                for field in (
                    "marker_sha256",
                    "batch_sha256",
                    "command_sha256",
                    "result_manifest_sha256",
                    "class_receipts_sha256",
                )
            )
            or isinstance(marker.get("started_at_ns"), bool)
            or not isinstance(marker.get("started_at_ns"), int)
            or isinstance(marker.get("completed_at_ns"), bool)
            or not isinstance(marker.get("completed_at_ns"), int)
            or marker["completed_at_ns"] < marker["started_at_ns"]
            or contract_batch is None
            or marker.get("batch_sha256") != contract_batch["batch_sha256"]
            or marker.get("command_sha256") != contract_batch["command_sha256"]
        ):
            raise ReleaseEvidenceError("fixed campaign proof marker schema is invalid")
        batch_manifest = [
            {
                "subject_id": subject_id,
                "size_bytes": campaign_result_entries[subject_id]["size_bytes"],
                "sha256": campaign_result_entries[subject_id]["sha256"],
            }
            for subject_id in sorted(contract_batch["ids"])
        ]
        if marker.get("result_manifest_sha256") != _canonical_sha256(batch_manifest):
            raise ReleaseEvidenceError(
                "fixed campaign proof marker result manifest is invalid"
            )
        marker_bytes = _decode_archived_bytes(
            contract_batch.get("marker_bytes_base64"),
            label=f"campaign marker {marker['batch']!r}",
        )
        if hashlib.sha256(marker_bytes).hexdigest() != marker["marker_sha256"]:
            raise ReleaseEvidenceError(
                "fixed campaign proof marker hash does not match raw marker bytes"
            )
        try:
            marker_payload = json.loads(marker_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ReleaseEvidenceError(
                "archived campaign marker is not UTF-8 JSON"
            ) from exc
        if not isinstance(marker_payload, dict):
            raise ReleaseEvidenceError("archived campaign marker must be an object")
        _reject_pilot_release_artifact(marker_payload, label="campaign marker")
        canonical_marker_bytes = (
            json.dumps(marker_payload, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        if marker_bytes != canonical_marker_bytes:
            raise ReleaseEvidenceError(
                "archived campaign marker is not exact runner JSON output"
            )
        raw_marker_fields = {
            "schema_version",
            "batch",
            "kind",
            "batch_file",
            "batch_sha256",
            "contract_sha256",
            "analyzer_contract_sha256",
            "signature_sha256",
            "alias_class_manifest_sha256",
            "source_snapshot_sha256",
            "source_snapshot",
            "id_line_count",
            "unique_id_count",
            "command",
            "reasoning_effort",
            "model",
            "workers",
            "campaign_id",
            "campaign_result_dir",
            "campaign_api_cache_dir",
            "campaign_derived_cache_root",
            "litellm_transport_sha256",
            "litellm_transport",
            "batch_timeout_seconds",
            "free_bytes_before",
            "free_bytes_after",
            "log_file",
            "started_at",
            "completed_at",
            "exit_code",
            "result_validation",
        }
        campaign_root = Path(campaign_contract["result_dir"]).parent
        repo_root = Path(campaign_contract["repo_root"]).resolve(strict=False)
        batch_path = Path(contract_batch["path"]).resolve(strict=False)
        marker_path = (
            Path(campaign_contract["marker_dir"]).resolve(strict=False)
            / f"{marker['batch']}.json"
        )
        try:
            batch_file = batch_path.relative_to(repo_root).as_posix()
            log_path = repo_root / str(marker_payload.get("log_file", ""))
            log_path.resolve(strict=False).relative_to(repo_root)
        except ValueError as exc:
            raise ReleaseEvidenceError(
                "archived campaign marker path binding is invalid"
            ) from exc
        alias_manifest = campaign_contract["alias_class_manifest"]
        class_records = {
            item["analysis_subject"]: item
            for item in alias_manifest["classes"]
            if item.get("scheduled_seed_ids")
        }
        receipt_campaign = refresh_runner.CampaignExecution(
            campaign_id=campaign_contract["campaign_id"],
            root=campaign_root,
            result_dir=campaign_root / "results",
            api_cache_dir=campaign_root / "api-responses",
            derived_cache_root=campaign_root / "derived-cache",
            source_snapshot_sha256=campaign_contract["source_snapshot_sha256"],
            contract_sha256=campaign_contract["contract_sha256"],
            litellm_transport_sha256=campaign_contract["litellm_transport_sha256"],
            litellm_transport=campaign_contract["litellm_transport"],
            analyzer_contract_sha256=campaign_contract["analyzer_contract_sha256"],
            signature_sha256=campaign_contract["signature_sha256"],
            alias_class_manifest_sha256=campaign_contract[
                "alias_class_manifest_sha256"
            ],
        )
        class_receipts: list[dict[str, Any]] = []
        for subject_id in contract_batch["ids"]:
            result_bytes, _ = _stable_regular_file(
                bundle_path / _CAMPAIGN_RESULTS_DIR / f"{subject_id}.json",
                f"archived campaign result {subject_id}",
                max_bytes=_MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES,
            )
            try:
                result_payload = json.loads(result_bytes)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ReleaseEvidenceError(
                    "archived campaign result is invalid during receipt replay"
                ) from exc
            class_record = class_records.get(subject_id)
            if not isinstance(result_payload, dict) or class_record is None:
                raise ReleaseEvidenceError(
                    "archived campaign result has no alias-class receipt binding"
                )
            stage_problem, class_receipt = refresh_runner._analysis_stage_receipt_proof(
                result_payload,
                class_record=class_record,
                campaign=receipt_campaign,
                result_sha256=hashlib.sha256(result_bytes).hexdigest(),
            )
            if stage_problem is not None or class_receipt is None:
                raise ReleaseEvidenceError(
                    f"archived class receipt replay failed: {stage_problem}"
                )
            class_receipts.append(class_receipt)
        class_receipts.sort(key=lambda item: item["class_id"])
        class_receipts_sha256 = _runner_canonical_sha256(class_receipts)
        expected_result_validation = {
            "result_count": len(contract_batch["ids"]),
            "terminal_count": len(contract_batch["ids"]),
            "result_manifest_sha256": marker["result_manifest_sha256"],
            "class_receipt_count": len(class_receipts),
            "class_receipts_sha256": class_receipts_sha256,
            "class_receipts": class_receipts,
            "alias_classes_exactly_once": True,
        }
        raw_expected = {
            "schema_version": refresh_runner.MARKER_SCHEMA_VERSION,
            "batch": marker["batch"],
            "batch_file": batch_file,
            "batch_sha256": contract_batch["batch_sha256"],
            "contract_sha256": campaign_contract["contract_sha256"],
            "analyzer_contract_sha256": campaign_contract["analyzer_contract_sha256"],
            "signature_sha256": campaign_contract["signature_sha256"],
            "alias_class_manifest_sha256": campaign_contract[
                "alias_class_manifest_sha256"
            ],
            "source_snapshot_sha256": campaign_contract["source_snapshot_sha256"],
            "source_snapshot": source_snapshot,
            "id_line_count": len(contract_batch["ids"]),
            "unique_id_count": len(contract_batch["ids"]),
            "command": contract_batch["command"],
            "reasoning_effort": refresh_runner.REASONING_EFFORT,
            "model": refresh_runner.MODEL,
            "workers": refresh_runner.WORKERS,
            "campaign_id": campaign_contract["campaign_id"],
            "campaign_result_dir": str(campaign_root / "results"),
            "campaign_api_cache_dir": str(campaign_root / "api-responses"),
            "campaign_derived_cache_root": str(campaign_root / "derived-cache"),
            "litellm_transport_sha256": campaign_contract["litellm_transport_sha256"],
            "litellm_transport": campaign_contract["litellm_transport"],
            "batch_timeout_seconds": refresh_runner.BATCH_TIMEOUT_SECONDS,
            "exit_code": 0,
            "result_validation": expected_result_validation,
        }
        if (
            set(marker_payload) != raw_marker_fields
            or any(
                marker_payload.get(field) != value
                for field, value in raw_expected.items()
            )
            or not isinstance(marker_payload.get("kind"), str)
            or not marker_payload["kind"]
            or any(
                isinstance(marker_payload.get(field), bool)
                or not isinstance(marker_payload.get(field), int)
                or marker_payload[field] < 0
                for field in ("free_bytes_before", "free_bytes_after")
            )
            or not isinstance(marker_payload.get("log_file"), str)
            or not marker_payload["log_file"]
            or Path(marker["path"]).resolve(strict=False) != marker_path
            or marker.get("class_receipts_sha256") != class_receipts_sha256
        ):
            raise ReleaseEvidenceError(
                "archived campaign marker does not match the canonical runner contract"
            )
        try:
            started_at = datetime.fromisoformat(marker_payload["started_at"])
            completed_at = datetime.fromisoformat(marker_payload["completed_at"])
        except (TypeError, ValueError) as exc:
            raise ReleaseEvidenceError(
                "archived campaign marker timestamps are invalid"
            ) from exc
        if started_at.tzinfo is None or completed_at.tzinfo is None:
            raise ReleaseEvidenceError(
                "archived campaign marker timestamps require timezone offsets"
            )
        started_at_ns = int(started_at.timestamp() * 1_000_000_000)
        completed_at_ns = int(completed_at.timestamp() * 1_000_000_000)
        if (
            marker["started_at_ns"] != started_at_ns
            or marker["completed_at_ns"] != completed_at_ns
        ):
            raise ReleaseEvidenceError(
                "fixed campaign marker timestamps do not match raw marker bytes"
            )
        marker_by_batch[marker["batch"]] = marker

    subjects = proof.get("subject_proofs")
    subject_fields = {
        "subject_id",
        "batch",
        "marker_sha256",
        "result_sha256",
        "result_mtime_ns",
        "marker_started_at_ns",
        "marker_completed_at_ns",
        "terminal_validation",
    }
    if (
        not isinstance(subjects, list)
        or len(subjects) != proof["required_campaign_subject_count"]
    ):
        raise ReleaseEvidenceError("fixed campaign proof subject inventory is invalid")
    proof_subject_ids = [
        entry.get("subject_id") if isinstance(entry, dict) else None
        for entry in subjects
    ]
    if (
        any(
            not isinstance(subject_id, str) or not subject_id
            for subject_id in proof_subject_ids
        )
        or proof_subject_ids != sorted(proof_subject_ids)
        or len(set(proof_subject_ids)) != len(proof_subject_ids)
    ):
        raise ReleaseEvidenceError("fixed campaign proof subject inventory is invalid")
    subject_ids: set[str] = set()
    relevant_batches: set[str] = set()
    for subject in subjects:
        batch = (
            marker_by_batch.get(subject.get("batch"))
            if isinstance(subject, dict)
            else None
        )
        subject_id = subject.get("subject_id") if isinstance(subject, dict) else None
        if (
            not isinstance(subject, dict)
            or set(subject) != subject_fields
            or not isinstance(subject_id, str)
            or subject_id in subject_ids
            or campaign_results.get(subject_id) != subject.get("result_sha256")
            or subject_owner.get(subject_id) != subject.get("batch")
            or batch is None
            or subject.get("marker_sha256") != batch["marker_sha256"]
            or subject.get("marker_started_at_ns") != batch["started_at_ns"]
            or subject.get("marker_completed_at_ns") != batch["completed_at_ns"]
            or isinstance(subject.get("result_mtime_ns"), bool)
            or not isinstance(subject.get("result_mtime_ns"), int)
            or not batch["started_at_ns"]
            <= subject["result_mtime_ns"]
            <= batch["completed_at_ns"]
            or subject.get("terminal_validation") != "passed"
        ):
            raise ReleaseEvidenceError(
                "raw result or fixed campaign proof subject schema is invalid"
            )
        subject_ids.add(subject_id)
        relevant_batches.add(subject["batch"])
    if subject_ids != required_analysis_subjects:
        raise ReleaseEvidenceError(
            "fixed campaign proof subject inventory does not exactly match the "
            "frozen adjudication analysis subjects"
        )
    if len(relevant_batches) != proof["relevant_marker_count"]:
        raise ReleaseEvidenceError(
            "fixed campaign proof relevant marker count is invalid"
        )


def _trusted_study_path(
    repo_root: Path,
    value: object,
    *,
    label: str,
) -> Path:
    """Resolve a repository-relative study path under the verifier trust anchor."""

    if not isinstance(value, str) or not value:
        raise ReleaseEvidenceError(f"recall {label} path is missing")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or any(part in {"", ".", "..", ".git"} for part in relative.parts)
    ):
        raise ReleaseEvidenceError(f"recall {label} path is unsafe")
    path = repo_root.joinpath(*relative.parts)
    try:
        resolved_parent = path.parent.resolve(strict=True)
        trusted_root = repo_root.resolve(strict=True)
        resolved_parent.relative_to(trusted_root)
    except (OSError, ValueError) as exc:
        raise ReleaseEvidenceError(
            f"recall {label} path escapes the trusted repository"
        ) from exc
    return resolved_parent / path.name


def _validate_recall_evidence(
    *,
    selection: Mapping[str, Any],
    labels: Mapping[str, Any],
    report: Mapping[str, Any],
    inventory: Mapping[str, Any],
    receipt: Mapping[str, Any],
    trusted_repo_root: Path,
) -> None:
    """Replay end-to-end recall evidence against inventory and trusted Git state."""

    artifact_order = report.get("artifact_order")
    if not isinstance(artifact_order, dict):
        raise ReleaseEvidenceError("recall artifact-order proof is missing")
    selection_path = _trusted_study_path(
        trusted_repo_root,
        artifact_order.get("selection_path"),
        label="selection",
    )
    labels_path = _trusted_study_path(
        trusted_repo_root,
        artifact_order.get("labels_path"),
        label="labels",
    )
    alias_map: dict[str, set[str]] = {}
    rows = inventory.get("rows")
    if not isinstance(rows, list):
        raise ReleaseEvidenceError("detector inventory recall rows are missing")
    for row in rows:
        members = row.get("member_ids") if isinstance(row, dict) else None
        if not isinstance(members, list) or not members:
            raise ReleaseEvidenceError(
                "detector inventory recall aliases are malformed"
            )
        component = set(members)
        for member in members:
            if not isinstance(member, str) or not member:
                raise ReleaseEvidenceError(
                    "detector inventory recall aliases are malformed"
                )
            alias_map[member] = component
    try:
        protected = recall_audit._rebuild_authoritative_protected_inventory(
            selection,
            repo_root=trusted_repo_root,
            selection_path=selection_path,
            labels_path=labels_path,
            alias_map=alias_map,
        )
        recomputed = recall_audit.evaluate_labels(
            selection,
            labels,
            inventory=inventory,
            protected=protected,
            selection_path=selection_path,
            labels_path=labels_path,
            repo_root=trusted_repo_root,
            verify_artifact_order=True,
        )
    except (recall_audit.RecallAuditError, heldout_quality.HeldoutQualityError) as exc:
        raise ReleaseEvidenceError(
            f"archived recall evidence does not replay: {exc}"
        ) from exc
    if recomputed != report:
        raise ReleaseEvidenceError(
            "archived recall report does not recompute from inventory and labels"
        )
    try:
        census = recall_audit._validate_protected_census_manifest(
            selection.get("protected_census"),
            expected_protected_inputs=selection.get("protected_inputs"),
        )
    except recall_audit.RecallAuditError as exc:
        raise ReleaseEvidenceError(
            f"archived protected census manifest is invalid: {exc}"
        ) from exc
    census_labels = labels.get("protected_census")
    protocol = labels.get("audit_protocol")
    if (
        not isinstance(protocol, dict)
        or not isinstance(census_labels, dict)
        or set(census_labels)
        != {
            "schema_version",
            "kind",
            "census_manifest_sha256",
            "audit_protocol_sha256",
            "adjudications",
        }
        or census_labels.get("schema_version")
        != recall_audit.PROTECTED_CENSUS_LABEL_SCHEMA_VERSION
        or census_labels.get("kind") != "protected_alias_class_census_independent_audit"
        or census_labels.get("census_manifest_sha256")
        != census["census_manifest_sha256"]
        or census_labels.get("audit_protocol_sha256")
        != recall_audit.canonical_sha256(protocol)
    ):
        raise ReleaseEvidenceError(
            "archived protected census labels are not bound to the sealed manifest"
        )
    census_assignments = {row["packet_id"]: row for row in census["assignments"]}
    try:
        replayed_census_resolved, replayed_census_unresolved, _pairs = (
            recall_audit._resolve_adjudications(
                census_labels.get("adjudications"),
                census_assignments,
                description="protected census",
            )
        )
    except recall_audit.RecallAuditError as exc:
        raise ReleaseEvidenceError(
            f"archived protected census labels are invalid: {exc}"
        ) from exc
    census_population = census["population"]
    selection_population = selection.get("population")
    census_recall = (
        report.get("recall", {}).get("protected_census")
        if isinstance(report.get("recall"), dict)
        else None
    )
    recall = report.get("recall")
    point = recall.get("recall_point") if isinstance(recall, dict) else None
    interval = recall.get("recall_interval") if isinstance(recall, dict) else None
    targets = receipt.get("targets")
    recall_target = targets.get("recall") if isinstance(targets, dict) else None
    resolved = report.get("resolved_labels")
    census_resolved = report.get("protected_census_resolved_labels")
    protected_overlap_count = report.get("protected_overlap_class_count")
    protected_census_digest = report.get("protected_census_manifest_sha256")
    selection_inventory = selection.get("inventory")
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
        or _SHA256.fullmatch(protected_census_digest) is None
        or report.get("protected_census_complete") is not True
        or not isinstance(census_resolved, dict)
        or len(census_resolved) != protected_overlap_count
        or any(
            label not in {"AI_CAUSAL", "NOT_AI_CAUSAL"}
            for label in census_resolved.values()
        )
        or report.get("protected_census_unresolved_packet_ids") != []
        or report.get("protected_excluded_class_count") != 0
        or report.get("protected_overlap_class_count")
        != census_population["class_count"]
        or not isinstance(selection_population, dict)
        or selection_population.get("protected_excluded_class_count")
        != census_population["class_count"]
        or report.get("protected_census_manifest_sha256")
        != census["census_manifest_sha256"]
        or report.get("protected_census_resolved_labels")
        != dict(sorted(replayed_census_resolved.items()))
        or replayed_census_unresolved != []
        or report.get("unresolved_packet_ids") != []
        or report.get("covered_unprotected_diagnostic_complete") is not True
        or not isinstance(resolved, dict)
        or any(
            label not in {"AI_CAUSAL", "NOT_AI_CAUSAL"} for label in resolved.values()
        )
        or not isinstance(recall, dict)
        or not isinstance(census_recall, dict)
        or census_recall.get("class_count") != census_population["class_count"]
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
        or not isinstance(selection_inventory, dict)
        or selection_inventory.get("inventory_id") != inventory.get("inventory_id")
        or selection_inventory.get("source_snapshot_sha256")
        != inventory.get("source_snapshot_sha256")
        or selection_inventory.get("source_alias_class_manifest_sha256")
        != inventory.get("source_alias_class_manifest_sha256")
        or selection_inventory.get("campaign_id") != inventory.get("campaign_id")
        or selection_inventory.get("campaign_mode") != "formal"
        or selection_inventory.get("complete") is not True
        or census.get("inventory")
        != {
            "inventory_id": inventory.get("inventory_id"),
            "source_snapshot_sha256": inventory.get("source_snapshot_sha256"),
            "source_alias_class_manifest_sha256": inventory.get(
                "source_alias_class_manifest_sha256"
            ),
            "campaign_id": inventory.get("campaign_id"),
        }
        or report.get("selection_manifest_sha256")
        != selection.get("selection_manifest_sha256")
        or receipt.get("recall_inventory_id") != inventory.get("inventory_id")
        or receipt.get("recall_selection_manifest_sha256")
        != selection.get("selection_manifest_sha256")
        or receipt.get("protected_census_manifest_sha256") != protected_census_digest
        or receipt.get("protected_overlap_class_count") != protected_overlap_count
        or receipt.get("protected_census_complete") is not True
        or receipt.get("recall_evaluation_status") != "complete_end_to_end"
        or receipt.get("recall_evaluation_complete") is not True
        or receipt.get("recall_point_estimate") != point
        or receipt.get("recall_interval") != interval
        or isinstance(recall_target, bool)
        or not isinstance(recall_target, (int, float))
        or not math.isfinite(float(recall_target))
        or not 0.95 <= float(recall_target) <= 1.0
    ):
        raise ReleaseEvidenceError(
            "end-to-end recall evidence is incomplete or not bound to the detector inventory"
        )
    if float(point) < float(recall_target) or float(interval[0]) < float(recall_target):
        raise ReleaseEvidenceError(
            "end-to-end recall point estimate and confidence-interval lower "
            "bound do not meet the release receipt target"
        )


def _validate_cross_artifact_contract(
    *,
    generation_id: str,
    generated_at: str,
    payloads: Mapping[str, dict[str, Any]],
    bundle_path: Path,
    trusted_repo_root: Path,
) -> None:
    receipt = payloads["release-receipt.json"]
    detector_report = payloads["detector-report.json"]
    detector_inventory = payloads["detector-inventory.json"]
    curation_report = payloads["publication-curation-consistency-report.json"]
    curation_inputs = payloads["publication-curation-inputs.json"]
    heldout_report = payloads["heldout-quality-report.json"]
    heldout_selection = payloads["heldout-selection.json"]
    heldout_labels = payloads["heldout-labels.json"]
    heldout_campaign_population = payloads["heldout-campaign-population.json"]
    recall_selection = payloads["recall-selection.json"]
    recall_labels = payloads["recall-labels.json"]
    recall_report = payloads["recall-report.json"]
    verifier_contract = payloads["verifier-contract.json"]
    result_manifest = payloads["campaign-result-manifest.json"]
    campaign_contract = payloads["campaign-contract.json"]
    publication_manifest = payloads["publication-manifest.json"]
    source_snapshot = payloads["source-snapshot.json"]
    source_remote_cutoff = payloads["source-remote-cutoff.json"]
    try:
        web_schema.validate_inventory_payload(detector_inventory)
    except web_schema.SchemaValidationError as exc:
        raise ReleaseEvidenceError(
            f"detector inventory schema is invalid: {exc}"
        ) from exc
    try:
        refresh_runner.validate_source_snapshot_details(source_snapshot)
    except refresh_runner.RunnerError as exc:
        raise ReleaseEvidenceError(
            f"source snapshot exact schema is invalid: {exc}"
        ) from exc

    if receipt.get("generation_id") != generation_id:
        raise ReleaseEvidenceError(
            "release receipt generation_id does not match the evidence directory"
        )
    if receipt.get("generated_at") != generated_at:
        raise ReleaseEvidenceError(
            "release receipt generated_at does not match the evidence manifest"
        )
    for field in (
        "campaign_id",
        "contract_sha256",
        "campaign_contract_sha256",
        "campaign_result_manifest_sha256",
        "source_snapshot_sha256",
        "publication_bundle_sha256",
        "detector_report_sha256",
        "detector_inventory_sha256",
        "analyzer_contract_sha256",
        "signature_sha256",
        "alias_class_manifest_sha256",
        "publication_manifest_sha256",
        "publication_curation_consistency_report_sha256",
        "publication_curation_inputs_sha256",
        "heldout_quality_report_sha256",
        "heldout_selection_sha256",
        "heldout_labels_sha256",
        "heldout_campaign_population_sha256",
        "heldout_campaign_proof_sha256",
        "heldout_campaign_result_manifest_sha256",
        "recall_selection_sha256",
        "recall_labels_sha256",
        "recall_report_sha256",
        "recall_inventory_id",
        "recall_selection_manifest_sha256",
        "protected_census_manifest_sha256",
        "verifier_contract_sha256",
        "verifier_files_manifest_sha256",
        "verifier_dependency_lock_sha256",
    ):
        value = receipt.get(field)
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise ReleaseEvidenceError(
                f"release receipt {field} must be a lowercase SHA-256"
            )
    if receipt.get("schema_version") != 4:
        raise ReleaseEvidenceError("release receipt requires schema_version 4")
    if (
        receipt.get("evaluation_complete") is not True
        or receipt.get("release_safe") is not True
        or receipt.get("curation_consistent") is not True
        or receipt.get("heldout_certified") is not True
        or receipt.get("recall_evaluation_complete") is not True
        or receipt.get("recall_evaluation_status") != "complete_end_to_end"
        or receipt.get("protected_census_complete") is not True
    ):
        raise ReleaseEvidenceError(
            "release receipt must record complete curation, held-out, and recall evidence"
        )
    try:
        verifier_contract_builder.validate_verifier_contract(
            verifier_contract,
            repo_root=trusted_repo_root,
        )
    except verifier_contract_builder.VerifierContractError as exc:
        raise ReleaseEvidenceError(
            f"formal verifier contract does not replay: {exc}"
        ) from exc
    verifier_commit = verifier_contract.get("git_commit")
    verifier_tree = verifier_contract.get("git_tree")
    if (
        _canonical_sha256(verifier_contract) != receipt.get("verifier_contract_sha256")
        or verifier_commit != receipt.get("verifier_git_commit")
        or verifier_tree != receipt.get("verifier_git_tree")
        or verifier_contract.get("files_manifest_sha256")
        != receipt.get("verifier_files_manifest_sha256")
        or verifier_contract.get("dependency_lock_sha256")
        != receipt.get("verifier_dependency_lock_sha256")
        or not isinstance(verifier_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", verifier_commit) is None
        or not isinstance(verifier_tree, str)
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", verifier_tree) is None
    ):
        raise ReleaseEvidenceError(
            "formal verifier contract does not match the release receipt"
        )
    if _canonical_sha256(detector_report) != receipt["detector_report_sha256"]:
        raise ReleaseEvidenceError("detector report hash does not match the receipt")
    if _canonical_sha256(detector_inventory) != receipt["detector_inventory_sha256"]:
        raise ReleaseEvidenceError("detector inventory hash does not match the receipt")
    detector_inventory_report = detector_report.get("detector_inventory")
    if (
        not isinstance(detector_inventory_report, dict)
        or detector_inventory.get("inventory_id")
        != receipt.get("detector_inventory_id")
        or detector_inventory.get("inventory_id")
        != detector_inventory_report.get("inventory_id")
        or detector_inventory.get("source_alias_class_manifest_sha256")
        != detector_inventory_report.get("source_alias_class_manifest_sha256")
        or detector_inventory.get("contract_sha256")
        != detector_inventory_report.get("contract_sha256")
        or detector_inventory.get("alias_class_count")
        != detector_inventory_report.get("alias_class_count")
        or detector_inventory.get("campaign_id") != receipt.get("campaign_id")
        or detector_inventory.get("contract_sha256") != receipt.get("contract_sha256")
        or detector_inventory.get("source_snapshot_sha256")
        != receipt.get("source_snapshot_sha256")
        or detector_inventory.get("source_alias_class_manifest_sha256")
        != receipt.get("alias_class_manifest_sha256")
        or detector_inventory.get("alias_class_count")
        != receipt.get("detector_inventory_alias_class_count")
        or detector_inventory.get("campaign_mode") != "formal"
        or detector_inventory.get("complete") is not True
    ):
        raise ReleaseEvidenceError(
            "detector inventory does not match the formal campaign receipt"
        )
    if (
        _canonical_sha256(curation_report)
        != receipt["publication_curation_consistency_report_sha256"]
    ):
        raise ReleaseEvidenceError(
            "publication curation-consistency report hash does not match the receipt"
        )
    if (
        _canonical_sha256(curation_inputs)
        != receipt["publication_curation_inputs_sha256"]
    ):
        raise ReleaseEvidenceError(
            "publication curation inputs hash does not match the receipt"
        )
    if _canonical_sha256(heldout_report) != receipt["heldout_quality_report_sha256"]:
        raise ReleaseEvidenceError(
            "independent held-out report hash does not match the receipt"
        )
    if _canonical_sha256(heldout_selection) != receipt["heldout_selection_sha256"]:
        raise ReleaseEvidenceError("held-out selection hash does not match the receipt")
    if _canonical_sha256(heldout_labels) != receipt["heldout_labels_sha256"]:
        raise ReleaseEvidenceError("held-out labels hash does not match the receipt")
    if (
        _canonical_sha256(heldout_campaign_population)
        != receipt["heldout_campaign_population_sha256"]
    ):
        raise ReleaseEvidenceError(
            "held-out campaign population hash does not match the receipt"
        )
    if _canonical_sha256(recall_selection) != receipt["recall_selection_sha256"]:
        raise ReleaseEvidenceError("recall selection hash does not match the receipt")
    if _canonical_sha256(recall_labels) != receipt["recall_labels_sha256"]:
        raise ReleaseEvidenceError("recall labels hash does not match the receipt")
    if _canonical_sha256(recall_report) != receipt["recall_report_sha256"]:
        raise ReleaseEvidenceError("recall report hash does not match the receipt")
    try:
        heldout_quality.validate_selection_seal(heldout_selection)
    except heldout_quality.HeldoutQualityError as exc:
        raise ReleaseEvidenceError(
            f"held-out selection seal is invalid: {exc}"
        ) from exc
    if heldout_report.get("selection_manifest_sha256") != heldout_selection.get(
        "selection_manifest_sha256"
    ):
        raise ReleaseEvidenceError(
            "held-out report does not match the archived selection"
        )
    if heldout_labels.get("selection_manifest_sha256") != heldout_selection.get(
        "selection_manifest_sha256"
    ):
        raise ReleaseEvidenceError(
            "held-out labels do not match the archived selection"
        )
    manual_evidence = heldout_report.get("manual_evidence")
    if (
        not isinstance(manual_evidence, dict)
        or set(manual_evidence)
        != {
            "label_file_sha256",
            "artifact_order",
            "independent_audit_attested",
        }
        or manual_evidence.get("label_file_sha256") != _canonical_sha256(heldout_labels)
        or manual_evidence.get("independent_audit_attested") is not True
    ):
        raise ReleaseEvidenceError(
            "held-out report label hash does not match the archived labels"
        )
    artifact_order = manual_evidence.get("artifact_order")
    label_audit_protocol = heldout_labels.get("audit_protocol")
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
        not isinstance(artifact_order, dict)
        or set(artifact_order) != artifact_order_fields
        or not isinstance(artifact_order.get("selection_commit"), str)
        or re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
            artifact_order["selection_commit"],
        )
        is None
        or not isinstance(artifact_order.get("selection_path"), str)
        or not artifact_order["selection_path"]
        or artifact_order.get("selection_commit_reference")
        != f"{artifact_order['selection_commit']}:{artifact_order.get('selection_path')}"
        or not isinstance(artifact_order.get("labels_commit"), str)
        or re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
            artifact_order["labels_commit"],
        )
        is None
        or artifact_order["labels_commit"] == artifact_order["selection_commit"]
        or not isinstance(artifact_order.get("labels_path"), str)
        or not artifact_order["labels_path"]
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
        or not isinstance(label_audit_protocol, dict)
        or label_audit_protocol.get("selection_commit_reference")
        != artifact_order.get("selection_commit_reference")
        or artifact_order.get("labels_blob_sha256")
        != hashlib.sha256(
            heldout_quality.canonical_artifact_bytes(heldout_labels)
        ).hexdigest()
    ):
        raise ReleaseEvidenceError("held-out artifact-order proof is malformed")
    # This Git-object replay is part of the archive contract itself.  It keeps
    # the full-population, alias, protected-input, selection, label, report, and
    # receipt bundle from becoming a self-sealed proof that can all be rewritten
    # together after labels exist.
    _validate_committed_artifact_order(
        payloads,
        trusted_repo_root=trusted_repo_root,
    )
    fixed_proof = detector_report.get("fixed_contract_campaign_proof")
    if (
        not isinstance(fixed_proof, dict)
        or not isinstance(receipt.get("fixed_campaign_proof_sha256"), str)
        or _SHA256.fullmatch(receipt["fixed_campaign_proof_sha256"]) is None
        or _canonical_sha256(fixed_proof) != receipt["fixed_campaign_proof_sha256"]
    ):
        raise ReleaseEvidenceError(
            "fixed campaign proof hash does not match the receipt"
        )

    result_entries = result_manifest.get("results")
    if (
        result_manifest.get("schema_version") != 1
        or result_manifest.get("campaign_id") != receipt.get("campaign_id")
        or not isinstance(result_entries, list)
        or result_manifest.get("result_count") != len(result_entries)
        or result_manifest.get("manifest_sha256") != _canonical_sha256(result_entries)
        or result_manifest.get("manifest_sha256")
        != receipt["campaign_result_manifest_sha256"]
    ):
        raise ReleaseEvidenceError(
            "campaign result manifest does not match the release receipt"
        )
    if detector_inventory.get("alias_class_count") != result_manifest.get(
        "result_count"
    ) or result_manifest.get("result_count") != receipt.get("campaign_result_count"):
        raise ReleaseEvidenceError(
            "detector inventory, campaign results, and receipt do not cover the same alias classes"
        )
    campaign_results: dict[str, str] = {}
    campaign_result_entries: dict[str, Mapping[str, Any]] = {}
    for entry in result_entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"subject_id", "file_name", "size_bytes", "sha256"}
            or not isinstance(entry.get("subject_id"), str)
            or entry["subject_id"] in campaign_results
            or entry.get("file_name") != f"{entry['subject_id']}.json"
            or isinstance(entry.get("size_bytes"), bool)
            or not isinstance(entry.get("size_bytes"), int)
            or entry["size_bytes"] <= 0
            or not isinstance(entry.get("sha256"), str)
            or _SHA256.fullmatch(entry["sha256"]) is None
        ):
            raise ReleaseEvidenceError("campaign result inventory is malformed")
        campaign_results[entry["subject_id"]] = entry["sha256"]
        campaign_result_entries[entry["subject_id"]] = entry

    if (
        campaign_contract.get("schema_version") != 2
        or campaign_contract.get("campaign_id") != receipt.get("campaign_id")
        or _canonical_sha256(campaign_contract)
        != receipt.get("campaign_contract_sha256")
        or campaign_contract.get("contract_sha256") != receipt.get("contract_sha256")
        or campaign_contract.get("source_snapshot_sha256")
        != receipt["source_snapshot_sha256"]
        or campaign_contract.get("result_dir") != receipt.get("campaign_result_dir")
        or campaign_contract.get("model") != receipt.get("model")
        or campaign_contract.get("reasoning_effort") != receipt.get("reasoning_effort")
        or campaign_contract.get("workers") != receipt.get("workers")
        or campaign_contract.get("litellm_transport_sha256")
        != receipt.get("litellm_transport_sha256")
        or campaign_contract.get("campaign_mode") != "formal"
        or campaign_contract.get("population_policy") != "formal_full"
        or campaign_contract.get("analyzer_contract_sha256")
        != receipt.get("analyzer_contract_sha256")
        or campaign_contract.get("signature_sha256") != receipt.get("signature_sha256")
        or campaign_contract.get("alias_class_manifest_sha256")
        != receipt.get("alias_class_manifest_sha256")
    ):
        raise ReleaseEvidenceError(
            "campaign contract does not match the release receipt"
        )
    detector_input_provenance = detector_report.get("input_provenance")
    detector_adjudication_provenance = (
        detector_input_provenance.get("adjudications")
        if isinstance(detector_input_provenance, dict)
        else None
    )
    _validate_fixed_campaign_proof(
        fixed_proof,
        campaign_results=campaign_results,
        campaign_result_entries=campaign_result_entries,
        campaign_contract=campaign_contract,
        corpus_manifest=detector_report.get("corpus_manifest"),
        corpus_manifest_sha256=detector_report.get("corpus_manifest_sha256"),
        normalized_adjudications=curation_inputs.get("normalized_adjudications"),
        detector_adjudications_sha256=(
            detector_adjudication_provenance.get("sha256")
            if isinstance(detector_adjudication_provenance, dict)
            else None
        ),
        curation_adjudications_sha256=curation_inputs.get("adjudications_sha256"),
        source_snapshot=source_snapshot,
        receipt=receipt,
        bundle_path=bundle_path,
    )
    _replay_heldout_campaign_population(
        heldout_campaign_population,
        selection=heldout_selection,
        campaign_contract=campaign_contract,
        fixed_proof=fixed_proof,
        result_manifest=result_manifest,
        campaign_result_entries=campaign_result_entries,
        receipt=receipt,
        bundle_path=bundle_path,
    )

    publication_files = publication_manifest.get("files")
    if (
        publication_manifest.get("schema_version") != 1
        or publication_manifest.get("generation_id") != generation_id
        or publication_manifest.get("publication_bundle_sha256")
        != receipt["publication_bundle_sha256"]
        or not isinstance(publication_files, list)
        or publication_manifest.get("manifest_sha256")
        != _canonical_sha256(publication_files)
        or publication_manifest.get("manifest_sha256")
        != receipt["publication_manifest_sha256"]
    ):
        raise ReleaseEvidenceError(
            "publication manifest does not match the release receipt"
        )
    inventory_publication_bytes = (
        json.dumps(
            detector_inventory,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    inventory_entries = [
        entry
        for entry in publication_files
        if isinstance(entry, dict) and entry.get("path") == "inventory.json"
    ]
    if (
        len(inventory_entries) != 1
        or inventory_entries[0].get("size_bytes") != len(inventory_publication_bytes)
        or inventory_entries[0].get("sha256")
        != hashlib.sha256(inventory_publication_bytes).hexdigest()
    ):
        raise ReleaseEvidenceError(
            "detector inventory is not bound to the publication manifest"
        )

    if _source_snapshot_sha256(source_snapshot) != receipt["source_snapshot_sha256"]:
        raise ReleaseEvidenceError("source snapshot hash does not match the receipt")
    if source_snapshot.get("remote_cutoff") != source_remote_cutoff:
        raise ReleaseEvidenceError(
            "source remote cutoff does not match the archived source snapshot"
        )
    if receipt.get("source_remote_cutoff") != source_remote_cutoff:
        raise ReleaseEvidenceError(
            "source remote cutoff does not match the release receipt"
        )
    try:
        web_writer._validate_source_remote_cutoff(source_remote_cutoff)
    except web_writer.PublishedDataError as exc:
        raise ReleaseEvidenceError(
            f"source remote cutoff schema-3 proof is invalid: {exc}"
        ) from exc
    if result_manifest.get("result_count") != receipt.get("campaign_result_count"):
        raise ReleaseEvidenceError(
            "campaign result count does not match the release receipt"
        )
    targets = receipt.get("targets")
    if not isinstance(targets, dict) or set(targets) != {"precision", "recall"}:
        raise ReleaseEvidenceError("release receipt quality targets are malformed")
    if any(
        isinstance(targets[field], bool)
        or not isinstance(targets[field], (int, float))
        or not math.isfinite(float(targets[field]))
        or not 0.95 <= float(targets[field]) <= 1.0
        for field in ("precision", "recall")
    ):
        raise ReleaseEvidenceError("release receipt quality targets are below 95%")
    if curation_report.get("targets") != {
        "curation_precision": targets["precision"],
        "curation_recall": targets["recall"],
    }:
        raise ReleaseEvidenceError(
            "publication curation targets do not match the release receipt"
        )
    _validate_curation_report(curation_report, targets=targets)
    _validate_curation_inputs(
        curation_inputs,
        report=curation_report,
        publication_manifest=publication_manifest,
        targets=targets,
    )
    _replay_detector_inventory(
        detector_inventory,
        campaign_contract=campaign_contract,
        curation_inputs=curation_inputs,
        source_remote_cutoff=source_remote_cutoff,
        heldout_campaign_population=heldout_campaign_population,
        bundle_path=bundle_path,
    )
    _validate_recall_evidence(
        selection=recall_selection,
        labels=recall_labels,
        report=recall_report,
        inventory=detector_inventory,
        receipt=receipt,
        trusted_repo_root=trusted_repo_root,
    )
    heldout_targets = heldout_report.get("targets")
    if (
        not isinstance(heldout_targets, dict)
        or heldout_targets.get("precision") != targets["precision"]
        or heldout_targets.get("recall") != targets["recall"]
        or heldout_targets.get("require_certified") is not True
    ):
        raise ReleaseEvidenceError(
            "independent held-out targets do not match the release receipt"
        )
    try:
        recomputed_quality = heldout_quality.recompute_archived_quality_evidence(
            heldout_selection,
            heldout_labels,
            precision_target=targets["precision"],
            recall_target=targets["recall"],
            require_certified=True,
        )
    except heldout_quality.HeldoutQualityError as exc:
        raise ReleaseEvidenceError(
            f"archived held-out labels/metrics are invalid: {exc}"
        ) from exc
    selection_campaign = heldout_selection.get("campaign")
    if selection_campaign != heldout_report.get("campaign"):
        raise ReleaseEvidenceError(
            "held-out selection and report campaign contracts differ"
        )
    selected_subjects: set[str] = set()
    for lane in ("precision", "recall"):
        for row in heldout_selection["samples"][lane]:
            selected_subjects.update(row["subject_ids"])
            for result in row["campaign_results"]:
                if campaign_results.get(result["subject_id"]) != result["sha256"]:
                    raise ReleaseEvidenceError(
                        "held-out selected result is absent from the campaign manifest"
                    )
    if not selected_subjects or not selected_subjects.issubset(campaign_results):
        raise ReleaseEvidenceError(
            "held-out selected IDs are absent from the campaign manifest"
        )
    for field in (
        "evaluation_complete",
        "precision",
        "recall",
        "denominators",
        "strata",
        "point_gate_passed",
        "certified_gate_passed",
        "release_gate_passed",
    ):
        if heldout_report.get(field) != recomputed_quality[field]:
            raise ReleaseEvidenceError(
                f"archived held-out {field} does not recompute from labels"
            )
    if receipt.get("curation_consistency_point_estimates") != {
        "precision": curation_report.get("curation_precision", {}).get("point"),
        "recall": curation_report.get("curation_recall", {}).get("point"),
    }:
        raise ReleaseEvidenceError(
            "curation-consistency points do not match the release receipt"
        )
    if receipt.get("heldout_point_estimates") != {
        "precision": heldout_report.get("precision", {}).get("point"),
        "recall": heldout_report.get("recall", {}).get("point"),
    }:
        raise ReleaseEvidenceError(
            "independent held-out points do not match the release receipt"
        )
    if (
        curation_report.get("schema_version") != 2
        or curation_report.get("evaluation_kind") != "publication_curation_consistency"
        or curation_report.get("curation_consistent") is not True
    ):
        raise ReleaseEvidenceError(
            "publication curation-consistency report did not pass"
        )
    if (
        heldout_report.get("schema_version") != 2
        or heldout_report.get("evaluation_kind")
        != "independent_heldout_fixed_campaign_detector_quality"
        or heldout_report.get("evaluation_complete") is not True
        or heldout_report.get("point_gate_passed") is not True
        or heldout_report.get("release_gate_passed") is not True
    ):
        raise ReleaseEvidenceError("independent held-out report did not pass")
    heldout_campaign = heldout_report.get("campaign")
    fixed_expected_contract = fixed_proof.get("expected_contract")
    if (
        not isinstance(heldout_campaign, dict)
        or not isinstance(fixed_expected_contract, dict)
        or heldout_campaign.get("campaign_id") != receipt.get("campaign_id")
        or heldout_campaign.get("contract_sha256") != receipt.get("contract_sha256")
        or heldout_campaign.get("source_snapshot_sha256")
        != receipt.get("source_snapshot_sha256")
        or heldout_campaign.get("proof_complete") is not True
        or heldout_campaign.get("campaign_proof_sha256")
        != receipt.get("heldout_campaign_proof_sha256")
        or heldout_campaign.get("campaign_result_manifest_sha256")
        != receipt.get("heldout_campaign_result_manifest_sha256")
        or any(
            heldout_campaign.get(field) != fixed_expected_contract.get(field)
            for field in (
                "campaign_id",
                "contract_sha256",
                "source_snapshot_sha256",
            )
        )
    ):
        raise ReleaseEvidenceError(
            "independent held-out campaign does not match the release proof"
        )
    if (
        detector_report.get("evaluation_complete") is not True
        or fixed_proof.get("complete") is not True
        or fixed_proof.get("campaign_mode") != "formal"
        or fixed_proof.get("population_policy") != "formal_full"
        or fixed_proof.get("formal_population_complete") is not True
        or fixed_proof.get("incremental_plan_complete") is not False
        or fixed_proof.get("full_incremental_plan_campaign_complete") is not False
        or fixed_proof.get("proof_scope") != "formal_current_source_alias_class_plan"
        or fixed_proof.get("population_uniform_luna_max_proof") is not False
        or campaign_contract.get("model") != "gpt-5.6-luna"
        or receipt.get("model") != "gpt-5.6-luna"
        or fixed_expected_contract.get("model") != "gpt-5.6-luna"
        or campaign_contract.get("reasoning_effort") != "max"
        or receipt.get("reasoning_effort") != "max"
        or fixed_expected_contract.get("reasoning_effort") != "max"
        or fixed_expected_contract.get("result_dir")
        != campaign_contract.get("result_dir")
        or fixed_expected_contract.get("workers") != campaign_contract.get("workers")
        or fixed_expected_contract.get("litellm_transport_sha256")
        != campaign_contract.get("litellm_transport_sha256")
    ):
        raise ReleaseEvidenceError(
            "fixed campaign completeness or Luna/max contract is invalid"
        )
    if receipt.get("heldout_measurement_boundary") != heldout_report.get(
        "measurement_boundary"
    ):
        raise ReleaseEvidenceError(
            "held-out conditional recall boundary does not match the receipt"
        )
    denominators = heldout_report.get("denominators")
    required_denominators = {
        "selected_unique_alias_classes",
        "precision_selected",
        "precision_conclusive_trials",
        "recall_candidate_positive_selected",
        "recall_actual_positive_trials",
        "inconclusive",
        "infrastructure_error",
        "unresolved",
    }
    if (
        heldout_targets.get("require_certified") is not True
        or heldout_report.get("certified_gate_passed") is not True
        or not isinstance(denominators, dict)
        or set(denominators) != required_denominators
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in denominators.values()
        )
        or any(
            denominators[field] != 0
            for field in ("inconclusive", "infrastructure_error", "unresolved")
        )
        or denominators["precision_selected"]
        != denominators["precision_conclusive_trials"]
        or denominators["precision_conclusive_trials"]
        != heldout_report.get("precision", {}).get("trials")
        or denominators["recall_actual_positive_trials"]
        != heldout_report.get("recall", {}).get("trials")
    ):
        raise ReleaseEvidenceError(
            "independent held-out denominators/certification are incomplete"
        )


def validate_release_evidence(
    path: Path,
    *,
    expected_generation_id: str | None = None,
    expected_bundle_sha256: str | None = None,
    trusted_repo_root: Path | None = None,
    _allow_staging: bool = False,
) -> ReleaseEvidenceBundle:
    """Re-read a bundle and fail on missing, extra, unsafe, or changed evidence."""
    path = Path(path)
    verifier_repo_root = _trusted_repo_root_for_bundle(path, trusted_repo_root)
    _safe_existing_directory(path, "release-evidence bundle")
    if _allow_staging:
        generation_id = expected_generation_id or ""
        if _SHA256.fullmatch(generation_id) is None or not path.name.startswith(
            f".{generation_id}.staging-"
        ):
            raise ReleaseEvidenceError(
                "release-evidence staging directory identity is invalid"
            )
    else:
        generation_id = path.name
        if _SHA256.fullmatch(generation_id) is None:
            raise ReleaseEvidenceError(
                f"release-evidence directory must be a lowercase SHA-256: {path}"
            )
        if (
            expected_generation_id is not None
            and generation_id != expected_generation_id
        ):
            raise ReleaseEvidenceError("release-evidence generation_id is unexpected")

    expected_names = {*_REQUIRED_ARTIFACTS, _MANIFEST_NAME, _CAMPAIGN_RESULTS_DIR}
    try:
        children = list(path.iterdir())
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot enumerate release-evidence bundle {path}: {exc}"
        ) from exc
    actual_names = {child.name for child in children}
    if actual_names != expected_names or len(children) != len(actual_names):
        raise ReleaseEvidenceError(
            "release-evidence inventory mismatch; "
            f"missing={sorted(expected_names - actual_names)}, "
            f"unexpected={sorted(actual_names - expected_names)}"
        )
    _safe_existing_directory(
        path / _CAMPAIGN_RESULTS_DIR,
        "release-evidence campaign result directory",
    )

    manifest_content, _ = _stable_regular_file(
        path / _MANIFEST_NAME,
        "release-evidence manifest",
        max_bytes=_MAX_RELEASE_EVIDENCE_MANIFEST_BYTES,
    )
    manifest = _parse_json_object(manifest_content, "release-evidence manifest")
    if set(manifest) != {
        "schema_version",
        "generation_id",
        "generated_at",
        "artifacts",
        "campaign_result_files",
        "bundle_sha256",
    }:
        raise ReleaseEvidenceError("release-evidence manifest fields are invalid")
    generated_at = manifest.get("generated_at")
    artifacts = manifest.get("artifacts")
    campaign_result_files = manifest.get("campaign_result_files")
    if (
        manifest.get("schema_version") != _SCHEMA_VERSION
        or manifest.get("generation_id") != generation_id
        or not isinstance(generated_at, str)
        or not generated_at
        or not isinstance(artifacts, list)
        or not isinstance(campaign_result_files, list)
    ):
        raise ReleaseEvidenceError("release-evidence manifest identity is invalid")

    expected_entries: list[dict[str, Any]] = []
    payloads: dict[str, dict[str, Any]] = {}
    total_artifact_bytes = 0
    for name in _REQUIRED_ARTIFACTS:
        entry, payload = _artifact_manifest(path / name, name)
        total_artifact_bytes += entry["size_bytes"]
        if total_artifact_bytes > _MAX_RELEASE_EVIDENCE_ARTIFACTS_TOTAL_BYTES:
            raise ReleaseEvidenceError(
                "release-evidence artifacts exceed total size bound"
            )
        expected_entries.append(entry)
        payloads[name] = payload
    if artifacts != expected_entries:
        raise ReleaseEvidenceError("release-evidence artifact hashes do not match")

    population_results = _population_result_entries(
        payloads["heldout-campaign-population.json"]
    )
    result_directory = path / _CAMPAIGN_RESULTS_DIR
    try:
        result_children = list(result_directory.iterdir())
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot enumerate archived campaign results: {exc}"
        ) from exc
    expected_result_names = {entry["file_name"] for entry in population_results}
    actual_result_names = {child.name for child in result_children}
    if actual_result_names != expected_result_names or len(result_children) != len(
        actual_result_names
    ):
        raise ReleaseEvidenceError(
            "archived campaign result inventory mismatch; "
            f"missing={sorted(expected_result_names - actual_result_names)}, "
            f"unexpected={sorted(actual_result_names - expected_result_names)}"
        )
    expected_result_entries: list[dict[str, Any]] = []
    total_result_bytes = 0
    for population_entry in population_results:
        relative = population_entry["archive_path"]
        content, metadata = _stable_regular_file(
            path / relative,
            f"archived campaign result {population_entry['subject_id']}",
            max_bytes=_MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES,
        )
        total_result_bytes += len(content)
        if total_result_bytes > _MAX_ARCHIVED_CAMPAIGN_RESULTS_TOTAL_BYTES:
            raise ReleaseEvidenceError(
                "archived campaign results exceed total size bound"
            )
        expected_result_entries.append(
            {
                "path": relative,
                "size_bytes": metadata.st_size,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    if campaign_result_files != expected_result_entries:
        raise ReleaseEvidenceError(
            "archived campaign result hashes do not match the evidence manifest"
        )

    bundle_preimage = {
        "schema_version": _SCHEMA_VERSION,
        "generation_id": generation_id,
        "generated_at": generated_at,
        "artifacts": expected_entries,
        "campaign_result_files": expected_result_entries,
    }
    bundle_sha256 = _canonical_sha256(bundle_preimage)
    if manifest.get("bundle_sha256") != bundle_sha256:
        raise ReleaseEvidenceError("release-evidence bundle SHA-256 does not match")
    if expected_bundle_sha256 is not None and bundle_sha256 != expected_bundle_sha256:
        raise ReleaseEvidenceError("release-evidence bundle SHA-256 is unexpected")
    _validate_cross_artifact_contract(
        generation_id=generation_id,
        generated_at=generated_at,
        payloads=payloads,
        bundle_path=path,
        trusted_repo_root=verifier_repo_root,
    )
    return ReleaseEvidenceBundle(
        path=path,
        manifest=manifest,
        bundle_sha256=bundle_sha256,
    )


def _validate_committed_artifact_order(
    payloads: Mapping[str, Mapping[str, Any]],
    *,
    trusted_repo_root: Path,
) -> dict[str, Any]:
    """Bind archived selection/labels to immutable, ordered Git objects."""

    campaign_contract = payloads["campaign-contract.json"]
    selection = payloads["heldout-selection.json"]
    labels = payloads["heldout-labels.json"]
    report = payloads["heldout-quality-report.json"]
    verifier_contract = payloads["verifier-contract.json"]
    artifact_order = report.get("manual_evidence", {}).get("artifact_order")
    if not isinstance(artifact_order, dict):
        raise ReleaseEvidenceError("archived artifact-order proof is missing")
    declared_repo_root = campaign_contract.get("repo_root")
    if (
        not isinstance(declared_repo_root, str)
        or not declared_repo_root
        or not Path(declared_repo_root).is_absolute()
    ):
        raise ReleaseEvidenceError("campaign contract repository root is malformed")
    repo_root = Path(declared_repo_root).resolve()
    try:
        trusted_repo_root = Path(trusted_repo_root).resolve(strict=True)
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"trusted verifier repository is unavailable: {exc}"
        ) from exc
    if repo_root != trusted_repo_root:
        raise ReleaseEvidenceError(
            "campaign contract repository root does not match the trusted "
            "verifier repository"
        )
    try:
        repository = heldout_quality._git_repository(repo_root)
    except heldout_quality.HeldoutQualityError as exc:
        raise ReleaseEvidenceError(
            f"bound Git repository cannot replay artifact order: {exc}"
        ) from exc

    selection_commit = artifact_order["selection_commit"]
    labels_commit = artifact_order["labels_commit"]
    selection_path = artifact_order["selection_path"]
    labels_path = artifact_order["labels_path"]
    for value, label in (
        (selection_path, "selection"),
        (labels_path, "labels"),
    ):
        path_value = Path(value)
        if (
            not isinstance(value, str)
            or path_value.is_absolute()
            or value != path_value.as_posix()
            or any(part in {"", ".", "..", ".git"} for part in path_value.parts)
        ):
            raise ReleaseEvidenceError(f"archived {label} Git path is unsafe")

    def git(arguments: list[str], description: str) -> bytes:
        try:
            result = heldout_quality._git_command(
                repository,
                arguments,
                description=description,
            )
        except heldout_quality.HeldoutQualityError as exc:
            raise ReleaseEvidenceError(
                f"cannot replay archived artifact order: {exc}"
            ) from exc
        if result.returncode != 0:
            raise ReleaseEvidenceError(
                f"archived artifact-order Git proof failed: {description}"
            )
        return result.stdout

    for commit, label in (
        (selection_commit, "selection commit"),
        (labels_commit, "labels commit"),
    ):
        if git(["cat-file", "-t", commit], label) != b"commit\n":
            raise ReleaseEvidenceError(f"archived {label} object is unavailable")
    if selection_commit == labels_commit:
        raise ReleaseEvidenceError("selection commit must precede labels commit")
    git(
        ["merge-base", "--is-ancestor", selection_commit, labels_commit],
        "selection-to-label ancestry",
    )
    selection_bytes = git(
        ["show", f"{selection_commit}:{selection_path}"],
        "committed held-out selection",
    )
    if selection_bytes != heldout_quality.canonical_artifact_bytes(selection):
        raise ReleaseEvidenceError(
            "archived selection differs from its committed Git object"
        )
    prior_labels = git(
        ["ls-tree", "-z", "--full-tree", selection_commit, "--", labels_path],
        "selection-commit label absence",
    )
    if prior_labels:
        raise ReleaseEvidenceError("held-out labels existed at selection commit")
    verifier_commit = verifier_contract.get("git_commit")
    if not isinstance(verifier_commit, str):
        raise ReleaseEvidenceError("archived verifier commit is malformed")
    if git(["cat-file", "-t", verifier_commit], "verifier commit") != b"commit\n":
        raise ReleaseEvidenceError("archived verifier commit is unavailable")
    git(
        ["merge-base", "--is-ancestor", labels_commit, verifier_commit],
        "labels-to-verifier ancestry",
    )
    labels_bytes = git(
        ["show", f"{labels_commit}:{labels_path}"], "committed held-out labels"
    )
    if labels_bytes != heldout_quality.canonical_artifact_bytes(labels):
        raise ReleaseEvidenceError(
            "archived labels differ from their committed Git object"
        )
    verifier_labels_bytes = git(
        ["show", f"{verifier_commit}:{labels_path}"],
        "verifier-commit held-out labels",
    )
    if verifier_labels_bytes != labels_bytes:
        raise ReleaseEvidenceError(
            "held-out labels changed between label and verifier commits"
        )
    return dict(artifact_order)


def validate_archived_artifact_order(
    path: Path,
    *,
    trusted_repo_root: Path | None = None,
) -> dict[str, Any]:
    """Replay the archived selection-before-label proof against its Git objects."""

    root = _trusted_repo_root_for_bundle(path, trusted_repo_root)
    bundle = validate_release_evidence(path, trusted_repo_root=root)
    payloads: dict[str, dict[str, Any]] = {}
    for name in (
        "campaign-contract.json",
        "heldout-selection.json",
        "heldout-labels.json",
        "heldout-quality-report.json",
        "verifier-contract.json",
    ):
        content, _ = _stable_regular_file(
            bundle.path / name,
            name,
            max_bytes=_MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES,
        )
        payloads[name] = _parse_json_object(content, name)
    return _validate_committed_artifact_order(
        payloads,
        trusted_repo_root=root,
    )


def archive_release_evidence(
    *,
    root: Path,
    generation_id: str,
    generated_at: str,
    artifacts: Mapping[str, Mapping[str, Any]],
    trusted_repo_root: Path | None = None,
) -> ReleaseEvidenceBundle:
    """Atomically create or verify one exact, write-once evidence generation."""
    if _SHA256.fullmatch(generation_id) is None:
        raise ReleaseEvidenceError("generation_id must be a lowercase SHA-256")
    if not isinstance(generated_at, str) or not generated_at:
        raise ReleaseEvidenceError("generated_at must be a non-empty string")
    if set(artifacts) != set(_REQUIRED_ARTIFACTS):
        raise ReleaseEvidenceError(
            "release-evidence payload inventory mismatch; "
            f"missing={sorted(set(_REQUIRED_ARTIFACTS) - set(artifacts))}, "
            f"unexpected={sorted(set(artifacts) - set(_REQUIRED_ARTIFACTS))}"
        )
    normalized: dict[str, dict[str, Any]] = {}
    try:
        verifier_repo_root = (
            _TRUSTED_REPO_ROOT
            if trusted_repo_root is None
            else Path(trusted_repo_root).resolve(strict=True)
        )
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"trusted verifier repository is unavailable: {exc}"
        ) from exc
    total_artifact_bytes = 0
    for name in _REQUIRED_ARTIFACTS:
        payload = artifacts[name]
        if not isinstance(payload, Mapping):
            raise ReleaseEvidenceError(
                f"release-evidence artifact {name} must be an object"
            )
        canonical = _canonical_bytes(dict(payload))
        if len(canonical) > _MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES:
            raise ReleaseEvidenceError(
                f"release-evidence artifact {name} exceeds the size bound"
            )
        total_artifact_bytes += len(canonical)
        if total_artifact_bytes > _MAX_RELEASE_EVIDENCE_ARTIFACTS_TOTAL_BYTES:
            raise ReleaseEvidenceError(
                "release-evidence artifacts exceed total size bound"
            )
        normalized[name] = json.loads(canonical)
    population = normalized["heldout-campaign-population.json"]
    population_results = _authoritative_campaign_result_entries(
        population=population,
        result_manifest=normalized["campaign-result-manifest.json"],
        campaign_contract=normalized["campaign-contract.json"],
    )
    live_result_dir = Path(population["result_dir"])
    live_descriptor, live_directory_signature, live_inventory = (
        _open_live_campaign_result_directory(
            population_results,
            result_dir=live_result_dir,
        )
    )
    try:
        _revalidate_live_campaign_result_directory(
            live_descriptor,
            result_dir=live_result_dir,
            entries=population_results,
            directory_signature=live_directory_signature,
            inventory=live_inventory,
        )
    finally:
        os.close(live_descriptor)

    archive_root = _ensure_archive_root(root)
    final_path = archive_root / generation_id
    if os.path.lexists(final_path):
        existing = validate_release_evidence(
            final_path,
            expected_generation_id=generation_id,
            trusted_repo_root=verifier_repo_root,
        )
        if existing.manifest["generated_at"] != generated_at:
            raise ReleaseEvidenceError(
                "existing release-evidence generation has a different timestamp"
            )
        expected_canonical_hashes = {
            name: _canonical_sha256(payload) for name, payload in normalized.items()
        }
        actual_canonical_hashes = {
            entry["path"]: entry["canonical_sha256"]
            for entry in existing.manifest["artifacts"]
        }
        if expected_canonical_hashes != actual_canonical_hashes:
            raise ReleaseEvidenceError(
                "existing release-evidence generation has different contents"
            )
        _BUNDLE_TRUSTED_REPO_ROOTS[final_path.absolute()] = verifier_repo_root
        return existing

    try:
        staging_dir = Path(
            tempfile.mkdtemp(prefix=f".{generation_id}.staging-", dir=archive_root)
        )
    except OSError as exc:
        raise ReleaseEvidenceError(
            f"cannot create release-evidence staging directory: {exc}"
        ) from exc

    try:
        artifact_entries: list[dict[str, Any]] = []
        written_artifact_bytes = 0
        for name in _REQUIRED_ARTIFACTS:
            _write_json(
                staging_dir / name,
                normalized[name],
                max_bytes=_MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES,
            )
            entry, _ = _artifact_manifest(staging_dir / name, name)
            written_artifact_bytes += entry["size_bytes"]
            if written_artifact_bytes > _MAX_RELEASE_EVIDENCE_ARTIFACTS_TOTAL_BYTES:
                raise ReleaseEvidenceError(
                    "release-evidence artifacts exceed total size bound"
                )
            artifact_entries.append(entry)
        result_directory = staging_dir / _CAMPAIGN_RESULTS_DIR
        result_directory.mkdir(mode=0o700)
        campaign_result_entries: list[dict[str, Any]] = []
        total_result_bytes = 0
        live_descriptor, live_directory_signature, live_inventory = (
            _open_live_campaign_result_directory(
                population_results,
                result_dir=live_result_dir,
            )
        )
        try:
            for result in population_results:
                archived = _copy_campaign_result(
                    Path(result["source_path"]),
                    staging_dir / result["archive_path"],
                    expected_size=result["size_bytes"],
                    expected_sha256=result["sha256"],
                    source_directory_descriptor=live_descriptor,
                )
                total_result_bytes += archived["size_bytes"]
                if total_result_bytes > _MAX_ARCHIVED_CAMPAIGN_RESULTS_TOTAL_BYTES:
                    raise ReleaseEvidenceError(
                        "held-out campaign results exceed archive size bound"
                    )
                campaign_result_entries.append(archived)
            _revalidate_live_campaign_result_directory(
                live_descriptor,
                result_dir=live_result_dir,
                entries=population_results,
                directory_signature=live_directory_signature,
                inventory=live_inventory,
            )
        finally:
            os.close(live_descriptor)
        _fsync_directory(result_directory)
        bundle_preimage = {
            "schema_version": _SCHEMA_VERSION,
            "generation_id": generation_id,
            "generated_at": generated_at,
            "artifacts": artifact_entries,
            "campaign_result_files": campaign_result_entries,
        }
        bundle_sha256 = _canonical_sha256(bundle_preimage)
        manifest = {**bundle_preimage, "bundle_sha256": bundle_sha256}
        _write_json(
            staging_dir / _MANIFEST_NAME,
            manifest,
            max_bytes=_MAX_RELEASE_EVIDENCE_MANIFEST_BYTES,
        )
        _fsync_directory(staging_dir)
        validate_release_evidence(
            staging_dir,
            expected_generation_id=generation_id,
            expected_bundle_sha256=bundle_sha256,
            trusted_repo_root=verifier_repo_root,
            _allow_staging=True,
        )
        try:
            os.rename(staging_dir, final_path)
        except OSError as exc:
            if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                raise ReleaseEvidenceError(
                    f"cannot publish release-evidence bundle {final_path}: {exc}"
                ) from exc
            existing = validate_release_evidence(
                final_path,
                expected_generation_id=generation_id,
                expected_bundle_sha256=bundle_sha256,
                trusted_repo_root=verifier_repo_root,
            )
            _BUNDLE_TRUSTED_REPO_ROOTS[final_path.absolute()] = verifier_repo_root
            return existing
        _fsync_directory(archive_root)
        validated = validate_release_evidence(
            final_path,
            expected_generation_id=generation_id,
            expected_bundle_sha256=bundle_sha256,
            trusted_repo_root=verifier_repo_root,
        )
        _BUNDLE_TRUSTED_REPO_ROOTS[final_path.absolute()] = verifier_repo_root
        return validated
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
