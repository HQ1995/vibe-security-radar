"""Published schema for the web data artifacts (index.json / cves/*.json / stats.json).

Single source of truth for the Python -> JSON -> TypeScript boundary:

- ``DEFS`` holds the contract as JSON Schema (2020-12 ``$defs``) definitions.
- ``validate()`` / ``validate_or_raise()`` enforce it on in-memory payloads
  before anything is written to ``web/data/`` (no pydantic in this project).
- ``cves_json_schema()`` / ``stats_json_schema()`` export standalone JSON
  Schema documents for external tooling.
- ``web_data.ts_types`` maps the same definitions to TypeScript interfaces
  (``web/src/lib/types.generated.ts``) so the web side cannot drift silently.

The validator intentionally supports only the JSON Schema subset used here:
``$ref``, ``anyOf``, ``type`` (single or list), ``enum``, ``pattern``,
``format``, numeric bounds, collection uniqueness, object properties, and
array items.
"""

from __future__ import annotations

import math
import re
import hashlib
import json
from datetime import date, datetime

# ---------------------------------------------------------------------------
# Schema definitions (ordered for TypeScript emission)
# ---------------------------------------------------------------------------

_STRING_LIST = {"type": "array", "items": {"type": "string"}}
_NON_NEGATIVE_INTEGER = {
    "type": "integer",
    "minimum": 0,
    "maximum": 9_007_199_254_740_991,
}
_INT_MAP = {
    "type": "object",
    "additionalProperties": _NON_NEGATIVE_INTEGER,
}
_CONFIDENCE = {"type": "number", "minimum": 0, "maximum": 1}
_CVSS = {"type": ["number", "null"], "minimum": 0, "maximum": 10}
_GENERATED_AT = {"type": "string", "format": "date-time"}
_GENERATION_ID = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
_DATE_OR_EMPTY = {"type": "string", "format": "date-or-empty"}
_MONTH = {"type": "string", "format": "month"}

#: ``published`` is exactly "YYYY-MM-DD", "YYYY" (year-only), or "" (unknown).
PUBLISHED_PATTERN = r"^(\d{4}-\d{2}-\d{2}|\d{4})?$"
VULNERABILITY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"

DEFS: dict[str, dict] = {
    "AiSignalEntry": {
        "type": "object",
        "properties": {
            "tool": {"type": "string"},
            "signal_type": {"type": "string"},
            "matched_text": {"type": "string"},
            "confidence": _CONFIDENCE,
        },
        "required": ["tool", "signal_type", "matched_text", "confidence"],
        "additionalProperties": False,
    },
    "LlmVerdict": {
        "type": "object",
        "properties": {
            # "" when a cached verdict row predates the verdict enum.
            "verdict": {
                "type": "string",
                "enum": ["CONFIRMED", "UNLIKELY", "UNRELATED", ""],
            },
            "reasoning": {"type": "string"},
            "model": {"type": "string"},
            "vuln_type": {"type": "string"},
            "vuln_description": {"type": "string"},
            "vulnerable_pattern": {"type": "string"},
            "causal_chain": {"type": "string"},
        },
        "required": ["verdict", "reasoning", "model"],
        "additionalProperties": False,
    },
    "VerifierResult": {
        "type": "object",
        "properties": {
            "model": {"type": "string"},
            "verdict": {"type": "string"},
            "reasoning": {"type": "string"},
            "confidence": _CONFIDENCE,
            "tool_calls_made": _NON_NEGATIVE_INTEGER,
            "steps_completed": _NON_NEGATIVE_INTEGER,
            "evidence": _STRING_LIST,
        },
        "required": [
            "model",
            "verdict",
            "reasoning",
            "confidence",
            "tool_calls_made",
            "steps_completed",
            "evidence",
        ],
        "additionalProperties": False,
    },
    "Verification": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string"},
            "confidence": {
                "type": ["number", "null"],
                "minimum": 0,
                "maximum": 1,
            },
            "models": _STRING_LIST,
            "agent_verdicts": {
                "type": "array",
                "items": {"$ref": "#/$defs/VerifierResult"},
            },
        },
        "required": ["verdict", "confidence", "models"],
        "additionalProperties": False,
    },
    "DecomposedCommit": {
        "type": "object",
        "properties": {
            "sha": {"type": "string", "minLength": 1},
            "author_name": {"type": "string"},
            "message": {"type": "string"},
            "ai_signals": {"type": "array", "items": {"$ref": "#/$defs/AiSignalEntry"}},
            "touched_blamed_file": {"type": ["boolean", "null"]},
        },
        "required": ["sha", "author_name", "message", "ai_signals"],
        "additionalProperties": False,
    },
    "BugCommit": {
        "type": "object",
        "properties": {
            "sha": {"type": "string", "minLength": 1},
            "author": {"type": "string"},
            "date": {"type": "string"},
            "message": {"type": "string"},
            "ai_signals": {"type": "array", "items": {"$ref": "#/$defs/AiSignalEntry"}},
            "blamed_file": {"type": "string", "minLength": 1},
            "blame_confidence": _CONFIDENCE,
            "screening_verification": {
                "anyOf": [{"$ref": "#/$defs/LlmVerdict"}, {"type": "null"}],
            },
            "verification": {"$ref": "#/$defs/Verification"},
            "pr_url": {"type": "string"},
            "pr_title": {"type": "string"},
            "decomposed_commits": {
                "type": "array",
                "items": {"$ref": "#/$defs/DecomposedCommit"},
            },
            "squash_merge_sha": {"type": "string"},
            "fix_commit_source": {"type": "string"},
            "blame_strategy": {"type": "string"},
            "fix_commit_sha": {"type": "string", "minLength": 1},
        },
        "required": [
            "sha",
            "author",
            "date",
            "message",
            "ai_signals",
            "blamed_file",
            "blame_confidence",
            "screening_verification",
            "fix_commit_sha",
        ],
        "additionalProperties": False,
    },
    "FixCommit": {
        "type": "object",
        "properties": {
            "sha": {"type": "string", "minLength": 1},
            "repo_url": {"type": "string", "minLength": 1},
            "source": {"type": "string", "minLength": 1},
            "blame_confidence": _CONFIDENCE,
        },
        "required": ["sha", "repo_url", "source"],
        "additionalProperties": False,
    },
    "CveEntry": {
        "type": "object",
        "properties": {
            "generation_id": _GENERATION_ID,
            "id": {
                "type": "string",
                "pattern": VULNERABILITY_ID_PATTERN,
            },
            "description": {"type": "string"},
            "severity": {"type": "string"},
            "cvss": _CVSS,
            "cwes": _STRING_LIST,
            "ecosystem": {"type": "string"},
            "published": {
                "type": "string",
                "pattern": PUBLISHED_PATTERN,
                "format": "published-date",
            },
            "ai_tools": _STRING_LIST,
            "ai_involved": {"type": ["boolean", "null"]},
            "ai_contribution": {"type": "string"},
            "signal_source": {"type": "string", "enum": ["commit", "pr_body", "both"]},
            "signal_note": {"type": "string"},
            "languages": _STRING_LIST,
            "confidence": _CONFIDENCE,
            "verified_by": {"type": "string"},
            "how_introduced": {"type": "string"},
            "root_cause": {"type": "string"},
            "vuln_type": {"type": "string"},
            "vulnerable_pattern": {"type": "string"},
            "verdict": {"type": "string"},
            "bug_commits": {"type": "array", "items": {"$ref": "#/$defs/BugCommit"}},
            "fix_commits": {"type": "array", "items": {"$ref": "#/$defs/FixCommit"}},
            "references": _STRING_LIST,
        },
        "required": [
            "generation_id",
            "id",
            "description",
            "severity",
            "cvss",
            "cwes",
            "ecosystem",
            "published",
            "ai_tools",
            "ai_involved",
            "signal_source",
            "languages",
            "confidence",
            "verified_by",
            "how_introduced",
            "verdict",
            "bug_commits",
            "fix_commits",
            "references",
        ],
        "additionalProperties": False,
    },
    "CvesData": {
        "type": "object",
        "properties": {
            "generation_id": _GENERATION_ID,
            "generated_at": _GENERATED_AT,
            "total": _NON_NEGATIVE_INTEGER,
            "cves": {"type": "array", "items": {"$ref": "#/$defs/CveEntry"}},
        },
        "required": ["generation_id", "generated_at", "total", "cves"],
        "additionalProperties": False,
    },
    # Manifest for the on-disk per-CVE layout: index.json carries the
    # metadata and the ordered id list; each id maps to cves/<ID>.json.
    "CvesIndex": {
        "type": "object",
        "properties": {
            "generation_id": _GENERATION_ID,
            "generated_at": _GENERATED_AT,
            "total": _NON_NEGATIVE_INTEGER,
            "ids": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": VULNERABILITY_ID_PATTERN,
                },
                "uniqueItems": True,
            },
        },
        "required": ["generation_id", "generated_at", "total", "ids"],
        "additionalProperties": False,
    },
    "InventoryRow": {
        "type": "object",
        "properties": {
            "class_id": {"type": "string", "pattern": VULNERABILITY_ID_PATTERN},
            "component_sha256": _GENERATION_ID,
            "source_evidence_sha256": _GENERATION_ID,
            "analysis_subject": {
                "type": "string",
                "pattern": VULNERABILITY_ID_PATTERN,
            },
            "member_ids": {
                "type": "array",
                "items": {"type": "string", "pattern": VULNERABILITY_ID_PATTERN},
                "uniqueItems": True,
            },
            "result_subject_ids": {
                "type": "array",
                "items": {"type": "string", "pattern": VULNERABILITY_ID_PATTERN},
                "uniqueItems": True,
            },
            "coverage_status": {
                "type": "string",
                "enum": ["complete", "incomplete", "missing", "error"],
            },
            "detector_state": {
                "type": "string",
                "enum": [
                    "positive",
                    "candidate",
                    "negative",
                    "exhausted",
                    "incomplete",
                    "not_evaluated",
                ],
            },
            "adjudication_state": {
                "type": "string",
                "enum": ["ai_causal", "not_ai_causal", "unknown", "unreviewed"],
            },
            "publication_state": {
                "type": "string",
                "enum": ["published", "eligible", "withheld", "not_applicable"],
            },
            "recall_stratum": {
                "type": "string",
                "enum": [
                    "detected_positive",
                    "coverage_failure",
                    "no_current_campaign_result",
                    "no_fix_commit",
                    "fix_no_bic",
                    "bic_no_trusted_authorship",
                    "trusted_signal_classifier_negative_or_incomplete",
                ],
            },
            "reasons": _STRING_LIST,
        },
        "required": [
            "class_id",
            "component_sha256",
            "source_evidence_sha256",
            "analysis_subject",
            "member_ids",
            "result_subject_ids",
            "coverage_status",
            "detector_state",
            "adjudication_state",
            "publication_state",
            "recall_stratum",
            "reasons",
        ],
        "additionalProperties": False,
    },
    "DetectorInventory": {
        "type": "object",
        "properties": {
            "schema_version": {"type": "integer", "enum": [2]},
            "kind": {"type": "string", "enum": ["ai_vulnerability_detector_inventory"]},
            "inventory_id": _GENERATION_ID,
            "generated_at": _GENERATED_AT,
            "source_snapshot_sha256": _GENERATION_ID,
            "source_receipt_sha256": _GENERATION_ID,
            "source_alias_class_manifest_sha256": _GENERATION_ID,
            "campaign_id": _GENERATION_ID,
            "contract_sha256": _GENERATION_ID,
            "campaign_mode": {"type": "string", "enum": ["formal", "incremental"]},
            "complete": {"type": "boolean"},
            "coverage_to": _DATE_OR_EMPTY,
            "alias_class_count": _NON_NEGATIVE_INTEGER,
            "detector_candidate_count": _NON_NEGATIVE_INTEGER,
            "pending_adjudication_count": _NON_NEGATIVE_INTEGER,
            "coverage_failure_count": _NON_NEGATIVE_INTEGER,
            "counts": {
                "type": "object",
                "properties": {
                    "coverage_status": _INT_MAP,
                    "detector_state": _INT_MAP,
                    "adjudication_state": _INT_MAP,
                    "publication_state": _INT_MAP,
                    "recall_stratum": _INT_MAP,
                },
                "required": [
                    "coverage_status",
                    "detector_state",
                    "adjudication_state",
                    "publication_state",
                    "recall_stratum",
                ],
                "additionalProperties": False,
            },
            "rows": {"type": "array", "items": {"$ref": "#/$defs/InventoryRow"}},
        },
        "required": [
            "schema_version",
            "kind",
            "inventory_id",
            "generated_at",
            "source_snapshot_sha256",
            "source_receipt_sha256",
            "source_alias_class_manifest_sha256",
            "campaign_id",
            "contract_sha256",
            "campaign_mode",
            "complete",
            "coverage_to",
            "alias_class_count",
            "detector_candidate_count",
            "pending_adjudication_count",
            "coverage_failure_count",
            "counts",
            "rows",
        ],
        "additionalProperties": False,
    },
    "InventorySummary": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "enum": ["inventory.json"]},
            "inventory_id": _GENERATION_ID,
            "source_snapshot_sha256": _GENERATION_ID,
            "source_alias_class_manifest_sha256": _GENERATION_ID,
            "campaign_id": _GENERATION_ID,
            "campaign_mode": {"type": "string", "enum": ["formal", "incremental"]},
            "complete": {"type": "boolean"},
            "coverage_to": _DATE_OR_EMPTY,
            "alias_class_count": _NON_NEGATIVE_INTEGER,
            "detector_candidate_count": _NON_NEGATIVE_INTEGER,
            "pending_adjudication_count": _NON_NEGATIVE_INTEGER,
            "coverage_failure_count": _NON_NEGATIVE_INTEGER,
        },
        "required": [
            "path",
            "inventory_id",
            "source_snapshot_sha256",
            "source_alias_class_manifest_sha256",
            "campaign_id",
            "campaign_mode",
            "complete",
            "coverage_to",
            "alias_class_count",
            "detector_candidate_count",
            "pending_adjudication_count",
            "coverage_failure_count",
        ],
        "additionalProperties": False,
    },
    "StatsData": {
        "type": "object",
        "properties": {
            "generation_id": _GENERATION_ID,
            "generated_at": _GENERATED_AT,
            "total_cves": _NON_NEGATIVE_INTEGER,
            "total_analyzed": _NON_NEGATIVE_INTEGER,
            "with_fix_commits": _NON_NEGATIVE_INTEGER,
            "coverage_from": _DATE_OR_EMPTY,
            "coverage_to": _DATE_OR_EMPTY,
            "inventory": {"$ref": "#/$defs/InventorySummary"},
            "by_tool": _INT_MAP,
            "by_severity": _INT_MAP,
            "by_language": _INT_MAP,
            "by_repo": _INT_MAP,
            "by_month": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "month": _MONTH,
                        "count": _NON_NEGATIVE_INTEGER,
                        "by_tool": _INT_MAP,
                    },
                    "required": ["month", "count", "by_tool"],
                    "additionalProperties": False,
                },
            },
        },
        "required": [
            "generation_id",
            "generated_at",
            "total_cves",
            "total_analyzed",
            "with_fix_commits",
            "coverage_from",
            "coverage_to",
            "by_tool",
            "by_severity",
            "by_language",
            "by_repo",
            "by_month",
        ],
        "additionalProperties": False,
    },
}

#: Root schemas for the published artifacts.
CVES_SCHEMA: dict = {"$ref": "#/$defs/CvesData"}
CVE_ENTRY_SCHEMA: dict = {"$ref": "#/$defs/CveEntry"}
INDEX_SCHEMA: dict = {"$ref": "#/$defs/CvesIndex"}
STATS_SCHEMA: dict = {"$ref": "#/$defs/StatsData"}
INVENTORY_SCHEMA: dict = {"$ref": "#/$defs/DetectorInventory"}

#: Cap on collected errors so a badly-drifting payload stays readable.
_MAX_ERRORS = 20


class SchemaValidationError(ValueError):
    """Raised when a payload violates the published web data schema."""


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def _is_finite_number(value: object) -> bool:
    """Return whether ``value`` is a JSON number that can be serialized safely."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return not isinstance(value, float) or math.isfinite(value)


_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "number": _is_finite_number,
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}

_JSON_TYPE_NAMES = {
    "str": "string",
    "int": "number",
    "float": "number",
    "bool": "boolean",
    "NoneType": "null",
    "list": "array",
    "dict": "object",
}


def _json_type(value: object) -> str:
    """Return the JSON Schema type name for a Python value."""
    return _JSON_TYPE_NAMES.get(type(value).__name__, type(value).__name__)


def _resolve(schema: dict) -> dict:
    """Resolve a local ``$ref`` against ``DEFS``."""
    ref = schema.get("$ref")
    if ref:
        name = ref.removeprefix("#/$defs/")
        if name not in DEFS:
            raise SchemaValidationError(f"unknown $ref {ref!r} in schema definition")
        return DEFS[name]
    return schema


def _valid_format(value: str, format_name: str) -> bool:
    """Validate the small set of canonical date formats used by artifacts."""
    try:
        if format_name == "published-date":
            if value == "":
                return True
            if re.fullmatch(r"\d{4}", value):
                return value != "0000"
            date.fromisoformat(value)
            return True
        if format_name == "date-or-empty":
            if value == "":
                return True
            date.fromisoformat(value)
            return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", value))
        if format_name == "month":
            if not re.fullmatch(r"\d{4}-\d{2}", value):
                return False
            date.fromisoformat(f"{value}-01")
            return True
        if format_name == "date-time":
            if not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
                r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
                value,
            ):
                return False
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.tzinfo is not None
    except ValueError:
        return False
    raise SchemaValidationError(f"unknown schema format {format_name!r}")


def _validate(instance: object, schema: dict, path: str, errors: list[str]) -> None:
    """Recursively validate ``instance``, appending human-readable errors."""
    if len(errors) >= _MAX_ERRORS:
        return
    schema = _resolve(schema)

    if "anyOf" in schema:
        for option in schema["anyOf"]:
            option_errors: list[str] = []
            _validate(instance, option, path, option_errors)
            if not option_errors:
                break
        else:
            expected = " | ".join(
                str(_resolve(o).get("type", o.get("$ref", "?")))
                for o in schema["anyOf"]
            )
            errors.append(f"{path}: expected {expected}, got {_json_type(instance)}")
        return

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed = (
            [expected_type] if isinstance(expected_type, str) else list(expected_type)
        )
        if not any(_TYPE_CHECKS[t](instance) for t in allowed):
            errors.append(
                f"{path}: expected {' | '.join(allowed)}, "
                f"got {_json_type(instance)} ({instance!r})"
            )
            return

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']!r}")

    if "pattern" in schema and isinstance(instance, str):
        if not re.fullmatch(schema["pattern"], instance):
            errors.append(
                f"{path}: {instance!r} does not match pattern {schema['pattern']!r}"
            )

    if "format" in schema and isinstance(instance, str):
        if not _valid_format(instance, schema["format"]):
            errors.append(f"{path}: {instance!r} is not a canonical {schema['format']}")

    if _is_finite_number(instance):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance!r} is below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: {instance!r} exceeds maximum {schema['maximum']}")

    if isinstance(instance, str) and "minLength" in schema:
        if len(instance) < schema["minLength"]:
            errors.append(
                f"{path}: string is shorter than minLength {schema['minLength']}"
            )

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required key {key!r}")
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            child_path = f"{path}.{key}" if path else key
            if key in properties:
                _validate(value, properties[key], child_path, errors)
            elif additional is False:
                errors.append(f"{path}: unexpected key {key!r}")
            elif isinstance(additional, dict):
                _validate(value, additional, child_path, errors)

    if isinstance(instance, list) and "items" in schema:
        item_schema = schema["items"]
        for index, item in enumerate(instance):
            # Use the CVE id (when present) so errors name the offending entry.
            label = item.get("id") if isinstance(item, dict) else None
            label = label if isinstance(label, str) and label else str(index)
            _validate(item, item_schema, f"{path}[{label}]", errors)
        if schema.get("uniqueItems"):
            seen: set[str] = set()
            for index, item in enumerate(instance):
                marker = repr(item)
                if marker in seen:
                    errors.append(f"{path}[{index}]: duplicate item {item!r}")
                seen.add(marker)


def validate(instance: object, schema: dict) -> list[str]:
    """Validate ``instance`` against ``schema``, returning a list of errors."""
    errors: list[str] = []
    _validate(instance, schema, "", errors)
    return errors


def validate_or_raise(instance: object, schema: dict, label: str = "payload") -> None:
    """Validate ``instance`` against ``schema``, raising on any violation.

    The exception message names the offending CVE id and field.
    """
    errors = validate(instance, schema)
    if errors:
        details = "\n".join(f"  - {e}" for e in errors)
        raise SchemaValidationError(
            f"{label} failed schema validation ({len(errors)} error(s)):\n{details}"
        )


def validate_cves_payload(payload: dict) -> None:
    """Validate an assembled CvesData payload, raising SchemaValidationError on drift."""
    validate_or_raise(payload, CVES_SCHEMA, label="cves payload")
    if payload["total"] != len(payload["cves"]):
        raise SchemaValidationError(
            "cves payload total does not match the number of CVE entries"
        )
    ids = [entry["id"] for entry in payload["cves"]]
    if len(ids) != len(set(ids)):
        raise SchemaValidationError("cves payload contains duplicate CVE ids")
    for entry in payload["cves"]:
        _validate_cve_semantics(entry)


def validate_cve_entry(entry: dict) -> None:
    """Validate a single per-CVE artifact (cves/<ID>.json)."""
    cve_id = entry.get("id", "<unknown>") if isinstance(entry, dict) else "<unknown>"
    validate_or_raise(entry, CVE_ENTRY_SCHEMA, label=f"cves/{cve_id}.json")
    _validate_cve_semantics(entry)


def _validate_cve_semantics(entry: dict) -> None:
    """Enforce cross-field publication invariants outside JSON Schema's subset."""
    cve_id = entry.get("id", "<unknown>")
    if entry.get("ai_involved") is None and entry.get("ai_contribution"):
        raise SchemaValidationError(
            f"cves/{cve_id}.json contains an unscoped ai_contribution"
        )

    subjects: set[tuple[str, str, str]] = set()
    known_fix_shas = {commit.get("sha", "") for commit in entry.get("fix_commits", [])}
    for commit in entry.get("bug_commits", []):
        subject = (
            commit.get("fix_commit_sha", ""),
            commit.get("sha", ""),
            commit.get("blamed_file", ""),
        )
        if not all(subject) or subject[2].startswith("("):
            raise SchemaValidationError(
                f"cves/{cve_id}.json has incomplete BIC subject identity {subject!r}"
            )
        if subject in subjects:
            raise SchemaValidationError(
                f"cves/{cve_id}.json has duplicate BIC subject identity {subject!r}"
            )
        if subject[0] not in known_fix_shas:
            raise SchemaValidationError(
                f"cves/{cve_id}.json BIC references unknown fix {subject[0]!r}"
            )
        subjects.add(subject)


def validate_index_payload(payload: dict) -> None:
    """Validate an index.json manifest, raising SchemaValidationError on drift."""
    validate_or_raise(payload, INDEX_SCHEMA, label="index.json")
    if payload["total"] != len(payload["ids"]):
        raise SchemaValidationError(
            "index.json total does not match the number of CVE ids"
        )


def validate_stats_payload(payload: dict) -> None:
    """Validate a stats.json payload, raising SchemaValidationError on drift."""
    validate_or_raise(payload, STATS_SCHEMA, label="stats.json")
    if payload["total_cves"] > payload["total_analyzed"]:
        raise SchemaValidationError("stats.json total_cves exceeds total_analyzed")
    if payload["with_fix_commits"] > payload["total_analyzed"]:
        raise SchemaValidationError(
            "stats.json with_fix_commits exceeds total_analyzed"
        )
    if (
        payload["coverage_from"]
        and payload["coverage_to"]
        and payload["coverage_from"] > payload["coverage_to"]
    ):
        raise SchemaValidationError(
            "stats.json coverage_from is later than coverage_to"
        )
    if sum(payload["by_severity"].values()) != payload["total_cves"]:
        raise SchemaValidationError(
            "stats.json severity counts do not sum to total_cves"
        )
    months = [bucket["month"] for bucket in payload["by_month"]]
    if months != sorted(set(months)):
        raise SchemaValidationError(
            "stats.json by_month buckets must be unique and sorted"
        )


def validate_inventory_payload(payload: dict) -> None:
    """Validate inventory.json and its content-addressed orthogonal state rows."""
    validate_or_raise(payload, INVENTORY_SCHEMA, label="inventory.json")
    rows = payload["rows"]
    if payload["alias_class_count"] != len(rows):
        raise SchemaValidationError(
            "inventory.json alias_class_count does not match rows"
        )
    class_ids = [row["class_id"] for row in rows]
    if class_ids != sorted(class_ids) or len(class_ids) != len(set(class_ids)):
        raise SchemaValidationError(
            "inventory.json class rows must be unique and sorted"
        )
    seen_members: set[str] = set()
    for row in rows:
        members = row["member_ids"]
        subjects = row["result_subject_ids"]
        reasons = row["reasons"]
        if not members or members != sorted(set(members)):
            raise SchemaValidationError(
                f"inventory.json class {row['class_id']} member_ids must be non-empty, unique, and sorted"
            )
        overlap = seen_members.intersection(members)
        if overlap:
            raise SchemaValidationError(
                f"inventory.json alias members occur in multiple classes: {sorted(overlap)!r}"
            )
        seen_members.update(members)
        if subjects != sorted(set(subjects)) or not set(subjects).issubset(members):
            raise SchemaValidationError(
                f"inventory.json class {row['class_id']} result subjects are invalid"
            )
        if row["analysis_subject"] not in members:
            raise SchemaValidationError(
                f"inventory.json class {row['class_id']} analysis subject is outside its members"
            )
        expected_component = hashlib.sha256(
            ("\n".join(members) + "\n").encode("utf-8")
        ).hexdigest()
        if row["component_sha256"] != expected_component:
            raise SchemaValidationError(
                f"inventory.json class {row['class_id']} component digest is invalid"
            )
        if row["coverage_status"] == "missing":
            expected_subjects: list[str] = []
        else:
            expected_subjects = [row["analysis_subject"]]
        if subjects != expected_subjects:
            raise SchemaValidationError(
                f"inventory.json class {row['class_id']} result subject coverage is invalid"
            )
        if reasons != sorted(set(reasons)):
            raise SchemaValidationError(
                f"inventory.json class {row['class_id']} reasons must be unique and sorted"
            )
        coverage_failure_strata = {
            "coverage_failure",
            "no_current_campaign_result",
        }
        if (row["coverage_status"] != "complete") != (
            row["recall_stratum"] in coverage_failure_strata
        ):
            raise SchemaValidationError(
                f"inventory.json class {row['class_id']} must keep coverage "
                "failures outside negative recall strata"
            )
    dimensions = (
        "coverage_status",
        "detector_state",
        "adjudication_state",
        "publication_state",
        "recall_stratum",
    )
    for dimension in dimensions:
        actual: dict[str, int] = {}
        for row in rows:
            value = row[dimension]
            actual[value] = actual.get(value, 0) + 1
        if payload["counts"][dimension] != actual:
            raise SchemaValidationError(
                f"inventory.json {dimension} counts do not match rows"
            )
    candidate_count = sum(
        row["detector_state"] in {"positive", "candidate"} for row in rows
    )
    pending_count = sum(
        row["adjudication_state"] in {"unknown", "unreviewed"} for row in rows
    )
    coverage_failure_count = sum(row["coverage_status"] != "complete" for row in rows)
    if payload["detector_candidate_count"] != candidate_count:
        raise SchemaValidationError(
            "inventory.json detector_candidate_count does not match rows"
        )
    if payload["pending_adjudication_count"] != pending_count:
        raise SchemaValidationError(
            "inventory.json pending_adjudication_count does not match rows"
        )
    if payload["coverage_failure_count"] != coverage_failure_count:
        raise SchemaValidationError(
            "inventory.json coverage_failure_count does not match rows"
        )
    fully_covered = all(row["coverage_status"] == "complete" for row in rows)
    if payload["complete"] is not fully_covered:
        raise SchemaValidationError(
            "inventory.json complete must exactly match class coverage"
        )
    preimage = dict(payload)
    inventory_id = preimage.pop("inventory_id")
    encoded = json.dumps(
        preimage,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if inventory_id != hashlib.sha256(encoded).hexdigest():
        raise SchemaValidationError(
            "inventory.json inventory_id does not match its canonical contents"
        )


# ---------------------------------------------------------------------------
# JSON Schema export
# ---------------------------------------------------------------------------


def _json_schema_document(root: dict, title: str) -> dict:
    """Wrap a root schema and DEFS into a standalone JSON Schema document."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "$defs": dict(DEFS),
        **root,
    }


def cves_json_schema() -> dict:
    """Standalone schema for the aggregate CVE dataset contract."""
    return _json_schema_document(CVES_SCHEMA, "CvesData")


def cve_entry_json_schema() -> dict:
    """Standalone JSON Schema document for one cves/<ID>.json artifact."""
    return _json_schema_document(CVE_ENTRY_SCHEMA, "CveEntry")


def index_json_schema() -> dict:
    """Standalone JSON Schema document for index.json."""
    return _json_schema_document(INDEX_SCHEMA, "CvesIndex")


def stats_json_schema() -> dict:
    """Standalone JSON Schema document for stats.json."""
    return _json_schema_document(STATS_SCHEMA, "StatsData")


def inventory_json_schema() -> dict:
    """Standalone JSON Schema document for inventory.json."""
    return _json_schema_document(INVENTORY_SCHEMA, "DetectorInventory")
