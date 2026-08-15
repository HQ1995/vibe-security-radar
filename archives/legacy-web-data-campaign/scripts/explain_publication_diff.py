#!/usr/bin/env python3
"""Explain every row in the legacy-to-current publication transition.

The legacy publication was a single ``web/data/cves.json`` file.  The current
publication is an ``index.json`` plus one file per vulnerability.  This tool
binds both inputs, and the adjudications used to explain removals, to exact
hashes.  It then emits a machine-readable ledger and a human-readable report.

An independently adjudicated ``AI_CAUSAL`` row may disappear only through an
explicit alias canonicalization to a currently published ID.  Any other such
disappearance is recorded in the ledger and makes the command exit non-zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

import data_refresh_paths


DEFAULT_OLD_REF = "8100fd604255ce7e6758d0a09033dc1a8b23e51b"
DEFAULT_OLD_PATH = "web/data/cves.json"
DEFAULT_SOURCE_DELTA = str(
    data_refresh_paths.DATA_REFRESH_STATE_RELATIVE / "source-delta-current.json"
)

CLASSIFICATIONS = (
    "retained",
    "alias_canonicalized",
    "independent_not_ai_causal",
    "inconclusive_coverage_failure",
    "unadjudicated_coverage_failure",
)
ALLOWED_AUDIT_LABELS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"})
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_HEX_OBJECT_RE = re.compile(r"[0-9a-f]{40,64}\Z")
_REASON_FIELDS = (
    "reason",
    "reasoning",
    "root_cause",
    "analysis",
    "causality",
    "causality_notes",
    "notes",
    "vulnerability_summary",
    "pipeline_comparison",
    "evidence",
    "improvement_suggestions",
)


class LedgerError(ValueError):
    """Raised when publication evidence cannot be reconciled safely."""


@dataclass(frozen=True)
class LoadedRows:
    """Validated publication rows plus their immutable input provenance."""

    rows: tuple[dict[str, Any], ...]
    provenance: dict[str, Any]


@dataclass(frozen=True)
class AuditRecord:
    """One validated adjudication and its full source explanation."""

    cve_id: str
    label: str
    aliases: tuple[str, ...]
    source: str
    source_sha256: str
    reason_fields: dict[str, Any]
    reason: str

    @property
    def subject_ids(self) -> frozenset[str]:
        return frozenset((self.cve_id, *self.aliases))

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "cve_id": self.cve_id,
            "label": self.label,
            "aliases": list(self.aliases),
            "reason": self.reason,
            "reason_fields": self.reason_fields,
        }
        if self.source:
            result["source"] = self.source
            result["source_sha256"] = self.source_sha256
        return result


@dataclass(frozen=True)
class LoadedAdjudications:
    records: tuple[AuditRecord, ...]
    provenance: dict[str, Any]


@dataclass(frozen=True)
class LoadedAliasClosure:
    """Content-addressed alias equivalence classes from a formal source delta."""

    classes: tuple[frozenset[str], ...]
    provenance: dict[str, Any]


@dataclass(frozen=True)
class _AliasResolver:
    groups_by_member: dict[str, frozenset[str]]
    audits_by_member: dict[str, AuditRecord]

    def equivalents(self, advisory_id: str) -> frozenset[str]:
        return self.groups_by_member.get(advisory_id, frozenset({advisory_id}))

    def audit_for(self, advisory_id: str) -> AuditRecord | None:
        return self.audits_by_member.get(advisory_id)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_json_bytes(value))


def _formal_source_sha256(value: Any) -> str:
    """Match the source-delta builder's ensure_ascii=True canonical JSON."""
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(encoded)


def _decode_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LedgerError(f"{label} is not UTF-8: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise LedgerError(f"{label} is not valid JSON: {exc}") from exc


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise LedgerError(f"cannot read {label} at {path}: {exc}") from exc


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _validate_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise LedgerError(f"{label} requires a safe non-empty advisory ID")
    return value


def _row_id(row: dict[str, Any], label: str) -> str:
    value = row.get("id", row.get("cve_id"))
    return _validate_identifier(value, f"{label} row")


def _validate_rows(rows: Any, label: str) -> tuple[dict[str, Any], ...]:
    if not isinstance(rows, list):
        raise LedgerError(f"{label} must contain a row array")
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for position, row in enumerate(rows):
        if not isinstance(row, dict):
            raise LedgerError(f"{label} row {position} must be an object")
        advisory_id = _row_id(row, f"{label} row {position}")
        if advisory_id in seen:
            raise LedgerError(f"{label} contains duplicate ID {advisory_id}")
        seen.add(advisory_id)
        validated.append(row)
    return tuple(validated)


def _safe_git_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith(("-", "/"))
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise LedgerError(f"unsafe Git object path: {value!r}")
    return path.as_posix()


def _run_git(repo_root: Path, *args: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LedgerError(f"Git command failed to execute: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise LedgerError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout


def load_old_publication_from_git(
    repo_root: Path,
    old_ref: str,
    old_path: str = DEFAULT_OLD_PATH,
) -> LoadedRows:
    """Load and hash a legacy monolithic publication from an exact Git commit."""
    if not old_ref or old_ref.startswith("-") or any(character.isspace() for character in old_ref):
        raise LedgerError(f"unsafe Git ref: {old_ref!r}")
    git_path = _safe_git_path(old_path)
    resolved = _run_git(repo_root, "rev-parse", "--verify", f"{old_ref}^{{commit}}")
    commit = resolved.decode("ascii", errors="strict").strip()
    if _HEX_OBJECT_RE.fullmatch(commit) is None:
        raise LedgerError(f"Git resolved {old_ref!r} to an invalid commit ID")
    blob_raw = _run_git(repo_root, "rev-parse", f"{commit}:{git_path}")
    blob = blob_raw.decode("ascii", errors="strict").strip()
    if _HEX_OBJECT_RE.fullmatch(blob) is None:
        raise LedgerError(f"Git resolved {git_path!r} to an invalid blob ID")
    raw = _run_git(repo_root, "show", f"{commit}:{git_path}")
    payload = _decode_json(raw, f"{commit}:{git_path}")
    if isinstance(payload, dict):
        rows_value = payload.get("cves")
        declared_total = payload.get("total")
    else:
        rows_value = payload
        declared_total = None
    rows = _validate_rows(rows_value, "old publication")
    if declared_total is not None and (
        isinstance(declared_total, bool) or not isinstance(declared_total, int) or declared_total != len(rows)
    ):
        raise LedgerError(f"old publication total {declared_total!r} does not match {len(rows)} rows")
    return LoadedRows(
        rows=rows,
        provenance={
            "requested_ref": old_ref,
            "resolved_commit": commit,
            "git_path": git_path,
            "git_blob": blob,
            "sha256": _sha256(raw),
            "row_count": len(rows),
        },
    )


def load_current_split_publication(
    index_path: Path,
    cves_dir: Path,
    *,
    repo_root: Path,
) -> LoadedRows:
    """Load the indexed split publication and reject missing or orphaned rows."""
    index_raw = _read_bytes(index_path, "current publication index")
    index = _decode_json(index_raw, str(index_path))
    if not isinstance(index, dict):
        raise LedgerError("current publication index must be an object")
    ids_value = index.get("ids")
    if not isinstance(ids_value, list):
        raise LedgerError("current publication index requires an ids array")
    ids = [
        _validate_identifier(value, f"current publication index ids[{position}]")
        for position, value in enumerate(ids_value)
    ]
    if len(ids) != len(set(ids)):
        raise LedgerError("current publication index contains duplicate IDs")
    declared_total = index.get("total")
    if isinstance(declared_total, bool) or not isinstance(declared_total, int) or declared_total != len(ids):
        raise LedgerError(f"current publication total {declared_total!r} does not match {len(ids)} IDs")
    try:
        actual_names = {path.name for path in cves_dir.glob("*.json") if path.is_file()}
    except OSError as exc:
        raise LedgerError(f"cannot list current split directory {cves_dir}: {exc}") from exc
    expected_names = {f"{advisory_id}.json" for advisory_id in ids}
    missing = sorted(expected_names - actual_names)
    orphaned = sorted(actual_names - expected_names)
    if missing or orphaned:
        raise LedgerError(f"current split files do not match the index: missing={missing}, orphaned={orphaned}")

    rows: list[dict[str, Any]] = []
    entry_manifest: list[dict[str, str]] = []
    generation_id = index.get("generation_id")
    for advisory_id in ids:
        entry_path = cves_dir / f"{advisory_id}.json"
        raw = _read_bytes(entry_path, f"current entry {advisory_id}")
        row = _decode_json(raw, str(entry_path))
        if not isinstance(row, dict):
            raise LedgerError(f"current entry {advisory_id} must be an object")
        if _row_id(row, f"current entry {advisory_id}") != advisory_id:
            raise LedgerError(f"current entry filename and row ID disagree for {advisory_id}")
        if generation_id is not None and row.get("generation_id") != generation_id:
            raise LedgerError(f"current entry {advisory_id} has a mismatched generation_id")
        rows.append(row)
        entry_manifest.append(
            {
                "path": f"cves/{advisory_id}.json",
                "sha256": _sha256(raw),
            }
        )
    validated = _validate_rows(rows, "current publication")
    manifest = {
        "index_sha256": _sha256(index_raw),
        "entries": sorted(entry_manifest, key=lambda item: item["path"]),
    }
    return LoadedRows(
        rows=validated,
        provenance={
            "index_path": _display_path(index_path, repo_root),
            "cves_dir": _display_path(cves_dir, repo_root),
            "generation_id": generation_id,
            "index_sha256": manifest["index_sha256"],
            "entries_manifest_sha256": _canonical_sha256(manifest["entries"]),
            "bundle_sha256": _canonical_sha256(manifest),
            "row_count": len(validated),
        },
    )


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def load_source_delta_alias_closure(
    path: Path,
    *,
    repo_root: Path,
) -> LoadedAliasClosure:
    """Load only the content-addressed alias closure from a schema-3 formal delta."""
    raw = _read_bytes(path, "formal source delta")
    payload = _decode_json(raw, str(path))
    if not isinstance(payload, dict) or payload.get("schema_version") != 3:
        raise LedgerError("source delta must use formal schema_version 3")
    if payload.get("population_policy") != "formal_full":
        raise LedgerError("source delta must use the formal_full population policy")
    integrity = payload.get("integrity_payload_sha256")
    unsigned = dict(payload)
    unsigned.pop("integrity_payload_sha256", None)
    expected_integrity = _sha256((json.dumps(unsigned, indent=2, sort_keys=False) + "\n").encode("utf-8"))
    if not _is_sha256(integrity) or integrity != expected_integrity:
        raise LedgerError("source delta integrity_payload_sha256 is invalid or stale")

    production = payload.get("production_discovery")
    manifest = production.get("alias_class_manifest") if isinstance(production, dict) else None
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise LedgerError("schema-3 formal source delta has no alias_class_manifest")
    source_snapshot_sha256 = manifest.get("source_snapshot_sha256")
    classes = manifest.get("classes")
    manifest_sha256 = manifest.get("classes_sha256")
    if (
        not _is_sha256(source_snapshot_sha256)
        or not isinstance(classes, list)
        or not classes
        or not _is_sha256(manifest_sha256)
        or manifest_sha256 != _formal_source_sha256(classes)
    ):
        raise LedgerError("formal alias-class manifest digest is invalid or stale")
    required_manifest_fields = {
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
    if set(manifest) != required_manifest_fields:
        raise LedgerError("formal alias-class manifest fields are malformed")
    if (
        isinstance(manifest.get("class_count"), bool)
        or manifest.get("class_count") != len(classes)
        or manifest.get("all_eligible_seed_ids_exactly_once") is not True
        or manifest.get("scheduled_classes_exactly_once") is not True
    ):
        raise LedgerError("formal alias-class manifest population proof is malformed")

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
    class_groups: list[frozenset[str]] = []
    member_owner: dict[str, str] = {}
    eligible_owner: dict[str, str] = {}
    class_ids: list[str] = []
    scheduled_subjects: set[str] = set()
    scheduled_class_count = 0
    for position, class_record in enumerate(classes):
        fields = set(class_record) if isinstance(class_record, dict) else set()
        supplemental = fields == base_class_fields | {"supplemental_candidate"}
        if (
            not isinstance(class_record, dict)
            or (fields != base_class_fields and not supplemental)
            or (supplemental and class_record.get("supplemental_candidate") is not True)
        ):
            raise LedgerError(f"formal alias class {position} is malformed")
        members_value = class_record.get("all_member_ids")
        eligible_value = class_record.get("eligible_seed_ids")
        scheduled_value = class_record.get("scheduled_seed_ids")
        if (
            not isinstance(members_value, list)
            or not members_value
            or any(not isinstance(member, str) for member in members_value)
            or members_value != sorted(members_value)
            or len(members_value) != len(set(members_value))
            or not isinstance(eligible_value, list)
            or not eligible_value
            or any(not isinstance(member, str) for member in eligible_value)
            or eligible_value != sorted(eligible_value)
            or len(eligible_value) != len(set(eligible_value))
            or not set(eligible_value).issubset(members_value)
            or not isinstance(scheduled_value, list)
            or any(not isinstance(member, str) for member in scheduled_value)
            or scheduled_value != sorted(scheduled_value)
            or len(scheduled_value) != len(set(scheduled_value))
            or not set(scheduled_value).issubset(eligible_value)
        ):
            raise LedgerError(f"formal alias class {position} member closure is malformed")
        members = tuple(
            _validate_identifier(member, f"formal alias class {position} member") for member in members_value
        )
        component_sha256 = class_record.get("component_sha256")
        expected_component = _sha256(("\n".join(members) + "\n").encode("utf-8"))
        class_id = class_record.get("class_id")
        analysis_subject = class_record.get("analysis_subject")
        analysis_input = class_record.get("analysis_input")
        if (
            component_sha256 != expected_component
            or class_id != f"alias-{expected_component[:24]}"
            or not isinstance(analysis_subject, str)
            or analysis_subject not in eligible_value
            or class_record.get("source_snapshot_sha256") != source_snapshot_sha256
            or not isinstance(analysis_input, dict)
            or analysis_input.get("member_ids") != members_value
            or not isinstance(class_record.get("source_record_references"), list)
            or not _is_sha256(class_record.get("merged_source_evidence_sha256"))
        ):
            raise LedgerError(f"formal alias class {position} content binding is invalid")
        if supplemental and (
            len(members) != 1 or class_record["source_record_references"] or eligible_value != members_value
        ):
            raise LedgerError(f"formal supplemental alias class {position} is invalid")
        if class_id in class_ids:
            raise LedgerError(f"formal alias class ID is duplicated: {class_id}")
        class_ids.append(class_id)
        for member in members:
            previous = member_owner.setdefault(member, class_id)
            if previous != class_id:
                raise LedgerError(f"formal alias classes overlap on {member}")
        for eligible in eligible_value:
            previous = eligible_owner.setdefault(eligible, class_id)
            if previous != class_id:
                raise LedgerError(f"formal eligible alias seeds overlap on {eligible}")
        if scheduled_value:
            scheduled_class_count += 1
            if analysis_subject in scheduled_subjects:
                raise LedgerError(f"formal analysis subject is scheduled twice: {analysis_subject}")
            scheduled_subjects.add(analysis_subject)
        class_groups.append(frozenset(members))

    if class_ids != sorted(class_ids):
        raise LedgerError("formal alias classes are not in canonical class_id order")
    if (
        isinstance(manifest.get("eligible_seed_id_count"), bool)
        or manifest.get("eligible_seed_id_count") != len(eligible_owner)
        or isinstance(manifest.get("scheduled_class_count"), bool)
        or manifest.get("scheduled_class_count") != scheduled_class_count
        or isinstance(manifest.get("scheduled_analysis_subject_count"), bool)
        or manifest.get("scheduled_analysis_subject_count") != len(scheduled_subjects)
    ):
        raise LedgerError("formal alias-class manifest counts are inconsistent")

    closure = [sorted(group) for group in class_groups]
    return LoadedAliasClosure(
        classes=tuple(class_groups),
        provenance={
            "path": _display_path(path, repo_root),
            "schema_version": 3,
            "population_policy": "formal_full",
            "source_delta_sha256": _sha256(raw),
            "source_delta_integrity_payload_sha256": integrity,
            "alias_class_manifest_sha256": manifest_sha256,
            "alias_source_snapshot_sha256": source_snapshot_sha256,
            "alias_class_count": len(class_groups),
            "alias_member_count": len(member_owner),
            "alias_member_closure_sha256": _canonical_sha256(closure),
        },
    )


def _reason_fields(payload: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in _REASON_FIELDS:
        value = payload.get(field)
        if value not in (None, "", [], {}):
            result[field] = value
    return result


def _full_reason(fields: dict[str, Any]) -> str:
    sections: list[str] = []
    for field, value in fields.items():
        title = field.replace("_", " ").title()
        rendered = (
            value.strip()
            if isinstance(value, str)
            else json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
        )
        sections.append(f"{title}:\n{rendered}")
    return "\n\n".join(sections)


def _resolve_audit_source(source: str, repo_root: Path) -> Path:
    source_path = Path(source)
    resolved = source_path.resolve() if source_path.is_absolute() else (repo_root / source_path).resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise LedgerError(f"audit source escapes repository root: {source}") from exc
    return resolved


def _select_audit_source_record(
    payload: Any,
    subject_ids: set[str],
    source: str,
) -> dict[str, Any]:
    if isinstance(payload, dict) and isinstance(payload.get("adjudications"), list):
        candidates = payload["adjudications"]
    elif isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        return payload
    else:
        raise LedgerError(f"audit source {source} must contain an object or object array")
    matches = [item for item in candidates if isinstance(item, dict) and item.get("cve_id") in subject_ids]
    if len(matches) != 1:
        raise LedgerError(f"audit source {source} has {len(matches)} matching rows for {sorted(subject_ids)}")
    return matches[0]


def load_adjudications(path: Path, *, repo_root: Path) -> LoadedAdjudications:
    """Load adjudications, declared aliases, and full reasons from all source schemas."""
    raw = _read_bytes(path, "audit adjudications")
    payload = _decode_json(raw, str(path))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise LedgerError("audit adjudications require schema_version 1")
    entries = payload.get("adjudications")
    if not isinstance(entries, list):
        raise LedgerError("audit adjudications require an adjudications array")

    records: list[AuditRecord] = []
    owner_by_subject: dict[str, str] = {}
    source_cache: dict[Path, tuple[bytes, Any]] = {}
    source_manifest: dict[str, str] = {}
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise LedgerError(f"audit adjudication {position} must be an object")
        cve_id = _validate_identifier(entry.get("cve_id"), f"audit adjudication {position}")
        label = entry.get("label")
        if label not in ALLOWED_AUDIT_LABELS:
            raise LedgerError(f"audit adjudication {cve_id} has invalid label {label!r}")
        aliases_value = entry.get("aliases", [])
        if not isinstance(aliases_value, list):
            raise LedgerError(f"audit adjudication {cve_id} aliases must be an array")
        aliases = tuple(_validate_identifier(alias, f"audit adjudication {cve_id} alias") for alias in aliases_value)
        if len(aliases) != len(set(aliases)) or cve_id in aliases:
            raise LedgerError(f"audit adjudication {cve_id} contains duplicate aliases")
        subject_ids = {cve_id, *aliases}
        for subject_id in subject_ids:
            owner = owner_by_subject.get(subject_id)
            if owner is not None:
                raise LedgerError(f"advisory ID {subject_id} is declared by both {owner} and {cve_id}")
            owner_by_subject[subject_id] = cve_id

        source_value = entry.get("source", "")
        if source_value is None:
            source_value = ""
        if not isinstance(source_value, str):
            raise LedgerError(f"audit adjudication {cve_id} source must be a string")
        source = source_value.strip()
        source_sha256 = ""
        fields = _reason_fields(entry)
        if source:
            source_path = _resolve_audit_source(source, repo_root)
            cached = source_cache.get(source_path)
            if cached is None:
                source_raw = _read_bytes(source_path, f"audit source {source}")
                source_payload = _decode_json(source_raw, source)
                source_cache[source_path] = (source_raw, source_payload)
            else:
                source_raw, source_payload = cached
            source_sha256 = _sha256(source_raw)
            source_manifest[_display_path(source_path, repo_root)] = source_sha256
            selected = _select_audit_source_record(source_payload, subject_ids, source)
            fields = {**fields, **_reason_fields(selected)}
        records.append(
            AuditRecord(
                cve_id=cve_id,
                label=label,
                aliases=aliases,
                source=source,
                source_sha256=source_sha256,
                reason_fields=fields,
                reason=_full_reason(fields),
            )
        )

    source_manifest_rows = [{"path": source, "sha256": digest} for source, digest in sorted(source_manifest.items())]
    return LoadedAdjudications(
        records=tuple(records),
        provenance={
            "path": _display_path(path, repo_root),
            "sha256": _sha256(raw),
            "record_count": len(records),
            "source_count": len(source_manifest_rows),
            "source_manifest_sha256": _canonical_sha256(source_manifest_rows),
            "source_manifest": source_manifest_rows,
        },
    )


def _build_alias_resolver(
    authoritative: LoadedAliasClosure,
    records: Sequence[AuditRecord],
) -> _AliasResolver:
    """Merge audit aliases into one authoritative class without joining classes."""
    groups = [set(group) for group in authoritative.classes]
    authoritative_owner: dict[str, int] = {}
    for index, group in enumerate(groups):
        for member in group:
            previous = authoritative_owner.setdefault(member, index)
            if previous != index:
                raise LedgerError(f"authoritative alias classes overlap on {member}")

    audit_owner_by_group: dict[int, AuditRecord] = {}
    for record in records:
        source_groups = {
            authoritative_owner[subject_id] for subject_id in record.subject_ids if subject_id in authoritative_owner
        }
        if len(source_groups) > 1:
            class_members = [sorted(authoritative.classes[index]) for index in sorted(source_groups)]
            raise LedgerError(
                f"adjudication aliases for {record.cve_id} conflict with authoritative alias classes: {class_members}"
            )
        if source_groups:
            group_index = next(iter(source_groups))
            previous = audit_owner_by_group.get(group_index)
            if previous is not None and previous is not record:
                raise LedgerError(
                    f"adjudications {previous.cve_id} and {record.cve_id} overlap the same authoritative alias class"
                )
            groups[group_index].update(record.subject_ids)
        else:
            group_index = len(groups)
            groups.append(set(record.subject_ids))
        audit_owner_by_group[group_index] = record

    groups_by_member: dict[str, frozenset[str]] = {}
    audits_by_member: dict[str, AuditRecord] = {}
    for index, group in enumerate(groups):
        frozen = frozenset(group)
        for member in group:
            previous = groups_by_member.setdefault(member, frozen)
            if previous != frozen:
                raise LedgerError(f"supplemented alias groups overlap on {member}")
            audit = audit_owner_by_group.get(index)
            if audit is not None:
                audits_by_member[member] = audit
    return _AliasResolver(
        groups_by_member=groups_by_member,
        audits_by_member=audits_by_member,
    )


def _row_projection(
    row: dict[str, Any],
    classification: str,
    *,
    old_index: int,
    current_id: str = "",
    audit: AuditRecord | None = None,
    coverage_failure_kind: str = "",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "old_id": _row_id(row, "old publication"),
        "old_index": old_index,
        "old_row_sha256": _canonical_sha256(row),
        "classification": classification,
    }
    if current_id:
        result["current_id"] = current_id
    if audit is not None:
        result["adjudication"] = audit.to_dict()
    if coverage_failure_kind:
        result["coverage_failure_kind"] = coverage_failure_kind
    return result


def build_publication_ledger(
    old: LoadedRows,
    current: LoadedRows,
    adjudications: LoadedAdjudications,
    source_aliases: LoadedAliasClosure,
) -> dict[str, Any]:
    """Classify every legacy row and reconcile both publication counts exactly."""
    old_by_id = {_row_id(row, "old publication"): row for row in old.rows}
    current_by_id = {_row_id(row, "current publication"): row for row in current.rows}
    alias_resolver = _build_alias_resolver(source_aliases, adjudications.records)
    current_ids = set(current_by_id)

    classified: list[dict[str, Any]] = []
    alias_targets: set[str] = set()
    blockers: list[dict[str, Any]] = []
    for old_index, row in enumerate(old.rows):
        old_id = _row_id(row, "old publication")
        audit = alias_resolver.audit_for(old_id)
        if old_id in current_ids:
            classified.append(
                _row_projection(
                    row,
                    "retained",
                    old_index=old_index,
                    current_id=old_id,
                    audit=audit,
                )
            )
            continue

        current_aliases = sorted(alias_resolver.equivalents(old_id) & current_ids)
        if len(current_aliases) > 1:
            raise LedgerError(f"old row {old_id} maps to multiple current aliases: {current_aliases}")
        if current_aliases:
            target = current_aliases[0]
            alias_targets.add(target)
            classified.append(
                _row_projection(
                    row,
                    "alias_canonicalized",
                    old_index=old_index,
                    current_id=target,
                    audit=audit,
                )
            )
            continue

        if audit and audit.label == "NOT_AI_CAUSAL":
            classified.append(
                _row_projection(
                    row,
                    "independent_not_ai_causal",
                    old_index=old_index,
                    audit=audit,
                )
            )
            continue
        if audit and audit.label == "INCONCLUSIVE":
            classified.append(
                _row_projection(
                    row,
                    "inconclusive_coverage_failure",
                    old_index=old_index,
                    audit=audit,
                )
            )
            continue

        failure_kind = "missing_adjudication"
        if audit and audit.label == "AI_CAUSAL":
            failure_kind = "missing_ai_causal_publication"
            blockers.append(
                {
                    "code": failure_kind,
                    "old_id": old_id,
                    "adjudication_id": audit.cve_id,
                    "declared_aliases": list(audit.aliases),
                    "authoritative_alias_class": sorted(alias_resolver.equivalents(old_id)),
                    "message": (
                        f"AI_CAUSAL old row {old_id} is absent from the current publication "
                        "and its content-addressed alias closure"
                    ),
                }
            )
        classified.append(
            _row_projection(
                row,
                "unadjudicated_coverage_failure",
                old_index=old_index,
                audit=audit,
                coverage_failure_kind=failure_kind,
            )
        )

    retained_current_ids = set(old_by_id) & current_ids
    current_accounted_by_old = retained_current_ids | alias_targets
    true_new_ids = sorted(current_ids - current_accounted_by_old)
    true_new = []
    for advisory_id in true_new_ids:
        row = current_by_id[advisory_id]
        item: dict[str, Any] = {
            "current_id": advisory_id,
            "current_row_sha256": _canonical_sha256(row),
        }
        audit = alias_resolver.audit_for(advisory_id)
        if audit is not None:
            item["adjudication"] = audit.to_dict()
        true_new.append(item)

    classification_counts = {
        classification: sum(item["classification"] == classification for item in classified)
        for classification in CLASSIFICATIONS
    }
    removed_old_rows = sum(
        classification_counts[name]
        for name in (
            "independent_not_ai_causal",
            "inconclusive_coverage_failure",
            "unadjudicated_coverage_failure",
        )
    )
    alias_rows = classification_counts["alias_canonicalized"]
    alias_target_count = len(alias_targets - retained_current_ids)
    alias_collapse = alias_rows - alias_target_count
    old_total = len(old.rows)
    current_total = len(current.rows)
    expected_current = old_total - removed_old_rows - alias_collapse + len(true_new)

    report: dict[str, Any] = {
        "schema_version": 1,
        "status": "failed" if blockers else "pass",
        "inputs": {
            "old_publication": old.provenance,
            "current_publication": current.provenance,
            "audit_adjudications": adjudications.provenance,
            "source_delta": source_aliases.provenance,
        },
        "counts": {
            "old_total": old_total,
            "current_total": current_total,
            "old_classifications": classification_counts,
            "old_classification_sum": sum(classification_counts.values()),
            "removed_old_rows": removed_old_rows,
            "retained_current_ids": len(retained_current_ids),
            "alias_rows": alias_rows,
            "alias_canonical_targets": alias_target_count,
            "alias_collapse": alias_collapse,
            "true_new_publications": len(true_new),
            "net_delta": current_total - old_total,
            "reconciled_current_total": expected_current,
            "reconciled": (sum(classification_counts.values()) == old_total and expected_current == current_total),
            "formula": ("current_total = old_total - removed_old_rows - alias_collapse + true_new_publications"),
        },
        "old_rows": sorted(classified, key=lambda item: item["old_id"]),
        "true_new_publications": true_new,
        "blocking_errors": sorted(blockers, key=lambda item: item["old_id"]),
    }
    if not report["counts"]["reconciled"]:
        raise LedgerError("publication counts do not reconcile exactly")
    payload_sha256 = _canonical_sha256(report)
    report["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "UTF-8 JSON, sorted keys, compact separators",
        "scope": "complete report excluding this integrity object",
        "ledger_payload_sha256": payload_sha256,
    }
    return report


def assert_no_blocking_errors(report: dict[str, Any]) -> None:
    """Raise when the ledger contains an unexplained adjudicated positive."""
    blockers = report.get("blocking_errors", [])
    if blockers:
        ids = ", ".join(item["old_id"] for item in blockers)
        raise LedgerError(f"unexplained AI_CAUSAL publication removals: {ids}")


def _markdown_reason(reason: str) -> str:
    return "\n".join(f"> {line}" if line else ">" for line in reason.splitlines())


def render_markdown(report: dict[str, Any]) -> str:
    """Render the JSON ledger without truncating adjudication reasons."""
    counts = report["counts"]
    lines = [
        "# Publication Difference Ledger",
        "",
        f"Status: **{report['status'].upper()}**",
        "",
        "## Exact reconciliation",
        "",
        f"- Old publication: {counts['old_total']}",
        f"- Current publication: {counts['current_total']}",
        f"- Removed old rows: {counts['removed_old_rows']}",
        f"- Alias collapse: {counts['alias_collapse']}",
        f"- True new publications: {counts['true_new_publications']}",
        f"- Net delta: {counts['net_delta']:+d}",
        (
            f"- Formula: `{counts['current_total']} = {counts['old_total']} - "
            f"{counts['removed_old_rows']} - {counts['alias_collapse']} + "
            f"{counts['true_new_publications']}`"
        ),
        f"- Reconciled: **{'yes' if counts['reconciled'] else 'no'}**",
        "",
        "## Input hashes",
        "",
        "| Input | Bound identity | SHA-256 |",
        "|---|---|---|",
    ]
    old_input = report["inputs"]["old_publication"]
    current_input = report["inputs"]["current_publication"]
    audit_input = report["inputs"]["audit_adjudications"]
    source_delta_input = report["inputs"]["source_delta"]
    lines.extend(
        [
            (
                f"| Old monolith | `{old_input['resolved_commit']}:{old_input['git_path']}` "
                f"(blob `{old_input['git_blob']}`) | `{old_input['sha256']}` |"
            ),
            (
                f"| Current split | `{current_input['index_path']}` + "
                f"`{current_input['cves_dir']}` | `{current_input['bundle_sha256']}` |"
            ),
            (f"| Adjudications | `{audit_input['path']}` | `{audit_input['sha256']}` |"),
            (
                f"| Audit source manifest | {audit_input['source_count']} files | "
                f"`{audit_input['source_manifest_sha256']}` |"
            ),
            (
                f"| Formal source delta | `{source_delta_input['path']}` | "
                f"`{source_delta_input['source_delta_sha256']}` |"
            ),
            (
                "| Authoritative alias manifest | "
                f"{source_delta_input['alias_class_count']} classes | "
                f"`{source_delta_input['alias_class_manifest_sha256']}` |"
            ),
            (
                "| Alias member closure | "
                f"{source_delta_input['alias_member_count']} members | "
                f"`{source_delta_input['alias_member_closure_sha256']}` |"
            ),
            (
                f"| Ledger payload | report excluding integrity object | "
                f"`{report['integrity']['ledger_payload_sha256']}` |"
            ),
            "",
            "## Old-row classifications",
            "",
            "| Classification | Count |",
            "|---|---:|",
        ]
    )
    for classification in CLASSIFICATIONS:
        lines.append(f"| `{classification}` | {counts['old_classifications'][classification]} |")

    for classification in CLASSIFICATIONS:
        rows = [row for row in report["old_rows"] if row["classification"] == classification]
        lines.extend(["", f"### {classification}", ""])
        if not rows:
            lines.append("None.")
            continue
        for row in rows:
            target = f" -> `{row['current_id']}`" if row.get("current_id") else ""
            lines.append(f"- `{row['old_id']}`{target}")
            adjudication = row.get("adjudication")
            if adjudication:
                lines.append(f"  - Adjudication: `{adjudication['label']}` (`{adjudication['cve_id']}`)")
                if adjudication.get("source"):
                    lines.append(f"  - Source: `{adjudication['source']}`")
                reason = adjudication.get("reason", "")
                if reason and classification != "retained":
                    lines.extend(["  - Full reason:", "", _markdown_reason(reason), ""])
            if row.get("coverage_failure_kind"):
                lines.append(f"  - Failure: `{row['coverage_failure_kind']}`")

    lines.extend(["", "## True new publications", ""])
    if report["true_new_publications"]:
        for row in report["true_new_publications"]:
            lines.append(f"- `{row['current_id']}`")
    else:
        lines.append("None.")

    lines.extend(["", "## Blocking errors", ""])
    if report["blocking_errors"]:
        for error in report["blocking_errors"]:
            lines.append(f"- `{error['code']}`: {error['message']}")
    else:
        lines.append("None.")
    return "\n".join(lines).rstrip() + "\n"


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _resolve_cli_path(value: str, repo_root: Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (repo_root / path).resolve()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--old-ref", default=DEFAULT_OLD_REF)
    parser.add_argument("--old-path", default=DEFAULT_OLD_PATH)
    parser.add_argument("--current-index", default="web/data/index.json")
    parser.add_argument("--current-cves-dir", default="web/data/cves")
    parser.add_argument("--adjudications", default="scripts/audit_adjudications.json")
    parser.add_argument("--source-delta", default=DEFAULT_SOURCE_DELTA)
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--markdown-out", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    try:
        old = load_old_publication_from_git(repo_root, args.old_ref, args.old_path)
        current = load_current_split_publication(
            _resolve_cli_path(args.current_index, repo_root),
            _resolve_cli_path(args.current_cves_dir, repo_root),
            repo_root=repo_root,
        )
        adjudications = load_adjudications(
            _resolve_cli_path(args.adjudications, repo_root),
            repo_root=repo_root,
        )
        source_aliases = load_source_delta_alias_closure(
            _resolve_cli_path(args.source_delta, repo_root),
            repo_root=repo_root,
        )
        report = build_publication_ledger(
            old,
            current,
            adjudications,
            source_aliases,
        )
        json_path = _resolve_cli_path(args.json_out, repo_root)
        markdown_path = _resolve_cli_path(args.markdown_out, repo_root)
        if json_path == markdown_path:
            raise LedgerError("JSON and Markdown outputs must be different files")
        _write_atomic(
            json_path,
            json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )
        _write_atomic(markdown_path, render_markdown(report))
        assert_no_blocking_errors(report)
    except LedgerError as exc:
        print(f"publication ledger failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
