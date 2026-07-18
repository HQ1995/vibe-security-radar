"""Published schema for the web data artifacts (cves.json / stats.json).

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
``properties`` / ``required`` / ``additionalProperties``, and ``items``.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Schema definitions (ordered for TypeScript emission)
# ---------------------------------------------------------------------------

_STRING_LIST = {"type": "array", "items": {"type": "string"}}
_INT_MAP = {"type": "object", "additionalProperties": {"type": "integer"}}

#: ``published`` is exactly "YYYY-MM-DD", "YYYY" (year-only), or "" (unknown).
PUBLISHED_PATTERN = r"^(\d{4}-\d{2}-\d{2}|\d{4})?$"

DEFS: dict[str, dict] = {
    "AiSignalEntry": {
        "type": "object",
        "properties": {
            "tool": {"type": "string"},
            "signal_type": {"type": "string"},
            "matched_text": {"type": "string"},
            "confidence": {"type": "number"},
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
            "confidence": {"type": "number"},
            "tool_calls_made": {"type": "integer"},
            "steps_completed": {"type": "integer"},
            "evidence": _STRING_LIST,
        },
        "required": [
            "model", "verdict", "reasoning", "confidence",
            "tool_calls_made", "steps_completed", "evidence",
        ],
        "additionalProperties": False,
    },
    "Verification": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string"},
            "confidence": {"type": ["number", "null"]},
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
            "sha": {"type": "string"},
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
            "sha": {"type": "string"},
            "author": {"type": "string"},
            "date": {"type": "string"},
            "message": {"type": "string"},
            "ai_signals": {"type": "array", "items": {"$ref": "#/$defs/AiSignalEntry"}},
            "blamed_file": {"type": "string"},
            "blame_confidence": {"type": "number"},
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
            "fix_commit_sha": {"type": "string"},
        },
        "required": [
            "sha", "author", "date", "message", "ai_signals",
            "blamed_file", "blame_confidence", "screening_verification",
        ],
        "additionalProperties": False,
    },
    "FixCommit": {
        "type": "object",
        "properties": {
            "sha": {"type": "string"},
            "repo_url": {"type": "string"},
            "source": {"type": "string"},
            "blame_confidence": {"type": "number"},
        },
        "required": ["sha", "repo_url", "source"],
        "additionalProperties": False,
    },
    "CveEntry": {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "description": {"type": "string"},
            "severity": {"type": "string"},
            "cvss": {"type": ["number", "null"]},
            "cwes": _STRING_LIST,
            "ecosystem": {"type": "string"},
            "published": {"type": "string", "pattern": PUBLISHED_PATTERN},
            "ai_tools": _STRING_LIST,
            "ai_involved": {"type": ["boolean", "null"]},
            "ai_contribution": {"type": "string"},
            "signal_source": {"type": "string", "enum": ["commit", "pr_body", "both"]},
            "signal_note": {"type": "string"},
            "languages": _STRING_LIST,
            "confidence": {"type": "number"},
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
            "id", "description", "severity", "cvss", "cwes", "ecosystem",
            "published", "ai_tools", "ai_involved", "signal_source",
            "languages", "confidence", "verified_by", "how_introduced",
            "verdict", "bug_commits", "fix_commits", "references",
        ],
        "additionalProperties": False,
    },
    "CvesData": {
        "type": "object",
        "properties": {
            "generated_at": {"type": "string"},
            "total": {"type": "integer"},
            "cves": {"type": "array", "items": {"$ref": "#/$defs/CveEntry"}},
        },
        "required": ["generated_at", "total", "cves"],
        "additionalProperties": False,
    },
    "StatsData": {
        "type": "object",
        "properties": {
            "generated_at": {"type": "string"},
            "total_cves": {"type": "integer"},
            "total_analyzed": {"type": "integer"},
            "with_fix_commits": {"type": "integer"},
            "coverage_from": {"type": "string"},
            "coverage_to": {"type": "string"},
            "by_tool": _INT_MAP,
            "by_severity": _INT_MAP,
            "by_language": _INT_MAP,
            "by_repo": _INT_MAP,
            "by_month": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "month": {"type": "string"},
                        "count": {"type": "integer"},
                        "by_tool": _INT_MAP,
                    },
                    "required": ["month", "count", "by_tool"],
                    "additionalProperties": False,
                },
            },
        },
        "required": [
            "generated_at", "total_cves", "total_analyzed", "with_fix_commits",
            "coverage_from", "coverage_to", "by_tool", "by_severity",
            "by_language", "by_repo", "by_month",
        ],
        "additionalProperties": False,
    },
}

#: Root schemas for the two published artifacts.
CVES_SCHEMA: dict = {"$ref": "#/$defs/CvesData"}
STATS_SCHEMA: dict = {"$ref": "#/$defs/StatsData"}

#: Cap on collected errors so a badly-drifting payload stays readable.
_MAX_ERRORS = 20


class SchemaValidationError(ValueError):
    """Raised when a payload violates the published web data schema."""


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
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
                str(_resolve(o).get("type", o.get("$ref", "?"))) for o in schema["anyOf"]
            )
            errors.append(f"{path}: expected {expected}, got {_json_type(instance)}")
        return

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed = [expected_type] if isinstance(expected_type, str) else list(expected_type)
        if not any(_TYPE_CHECKS[t](instance) for t in allowed):
            errors.append(
                f"{path}: expected {' | '.join(allowed)}, "
                f"got {_json_type(instance)} ({instance!r})"
            )
            return

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']!r}")

    if "pattern" in schema and isinstance(instance, str):
        if not re.match(schema["pattern"], instance):
            errors.append(
                f"{path}: {instance!r} does not match pattern {schema['pattern']!r}"
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
    """Validate a cves.json payload, raising SchemaValidationError on drift."""
    validate_or_raise(payload, CVES_SCHEMA, label="cves.json")


def validate_stats_payload(payload: dict) -> None:
    """Validate a stats.json payload, raising SchemaValidationError on drift."""
    validate_or_raise(payload, STATS_SCHEMA, label="stats.json")


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
    """Standalone JSON Schema document for cves.json."""
    return _json_schema_document(CVES_SCHEMA, "CvesData")


def stats_json_schema() -> dict:
    """Standalone JSON Schema document for stats.json."""
    return _json_schema_document(STATS_SCHEMA, "StatsData")
