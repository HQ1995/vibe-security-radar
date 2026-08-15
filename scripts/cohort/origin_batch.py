"""Strict response contracts for recall-safe batched origin routing."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping


_CAUSALITY = frozenset({"likely", "possible", "unlikely", "insufficient"})


class OriginBatchContractError(ValueError):
    """A batch response does not conserve the requested candidate IDs."""


def _response_payload(text: str) -> dict[str, object]:
    """Extract one strict JSON object, tolerating only an outer code fence."""

    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end <= start:
            raise OriginBatchContractError("response has no JSON object") from None
        try:
            payload = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError as exc:
            raise OriginBatchContractError("response JSON is malformed") from exc
    if not isinstance(payload, dict) or set(payload) != {"results"}:
        raise OriginBatchContractError("response must contain only results")
    return payload


def parse_batch_response(
    text: str,
    expected_aliases: Iterable[str],
) -> list[dict[str, str]]:
    """Parse exactly one result for every expected alias, with no extras."""

    expected = list(expected_aliases)
    if not expected or len(expected) != len(set(expected)):
        raise OriginBatchContractError("expected aliases must be unique and non-empty")
    payload = _response_payload(text)
    raw_results = payload["results"]
    if not isinstance(raw_results, list):
        raise OriginBatchContractError("results must be a list")
    parsed: dict[str, dict[str, str]] = {}
    for raw in raw_results:
        if not isinstance(raw, dict) or set(raw) != {"id", "causality", "reason"}:
            raise OriginBatchContractError("each result needs id, causality, and reason")
        alias = str(raw["id"])
        causality = str(raw["causality"]).lower()
        reason = str(raw["reason"]).strip()
        if alias in parsed:
            raise OriginBatchContractError(f"duplicate result alias: {alias}")
        if causality not in _CAUSALITY:
            raise OriginBatchContractError(f"invalid causality for {alias}")
        if not reason:
            raise OriginBatchContractError(f"empty reason for {alias}")
        parsed[alias] = {"id": alias, "causality": causality, "reason": reason}
    if set(parsed) != set(expected):
        missing = sorted(set(expected) - set(parsed))
        extra = sorted(set(parsed) - set(expected))
        raise OriginBatchContractError(
            f"response ID conservation failed: missing={missing} extra={extra}"
        )
    return [parsed[alias] for alias in expected]


def parse_edge_batch_response(
    text: str,
    expected_fix_aliases: Mapping[str, Iterable[str]],
) -> list[dict[str, object]]:
    """Parse one verdict per candidate plus an exact candidate/fix edge subset."""

    expected = list(expected_fix_aliases)
    if not expected or len(expected) != len(set(expected)):
        raise OriginBatchContractError("expected aliases must be unique and non-empty")
    allowed_by_candidate: dict[str, set[str]] = {}
    for alias, raw_fixes in expected_fix_aliases.items():
        fixes = list(raw_fixes)
        if not fixes or len(fixes) != len(set(fixes)) or any(not fix for fix in fixes):
            raise OriginBatchContractError(
                f"eligible fix aliases must be unique and non-empty for {alias}"
            )
        allowed_by_candidate[str(alias)] = set(fixes)

    payload = _response_payload(text)
    raw_results = payload["results"]
    if not isinstance(raw_results, list):
        raise OriginBatchContractError("results must be a list")
    parsed: dict[str, dict[str, object]] = {}
    for raw in raw_results:
        if not isinstance(raw, dict) or set(raw) != {
            "id",
            "causality",
            "related_fixes",
            "reason",
        }:
            raise OriginBatchContractError(
                "each edge result needs id, causality, related_fixes, and reason"
            )
        alias = str(raw["id"])
        causality = str(raw["causality"]).lower()
        reason = str(raw["reason"]).strip()
        raw_related = raw["related_fixes"]
        if alias in parsed:
            raise OriginBatchContractError(f"duplicate result alias: {alias}")
        if alias not in allowed_by_candidate:
            raise OriginBatchContractError(f"unknown result alias: {alias}")
        if causality not in _CAUSALITY:
            raise OriginBatchContractError(f"invalid causality for {alias}")
        if not reason:
            raise OriginBatchContractError(f"empty reason for {alias}")
        if not isinstance(raw_related, list) or any(
            not isinstance(value, str) or not value for value in raw_related
        ):
            raise OriginBatchContractError(f"related fixes are malformed for {alias}")
        related = list(raw_related)
        if len(related) != len(set(related)):
            raise OriginBatchContractError(f"duplicate related fix for {alias}")
        unknown = set(related) - allowed_by_candidate[alias]
        if unknown:
            raise OriginBatchContractError(
                f"unknown related fix for {alias}: {sorted(unknown)}"
            )
        if causality in {"likely", "possible"} and not related:
            raise OriginBatchContractError(
                f"promoted candidate lacks a related fix: {alias}"
            )
        if causality == "unlikely" and related:
            raise OriginBatchContractError(
                f"unlikely candidate names a related fix: {alias}"
            )
        parsed[alias] = {
            "id": alias,
            "causality": causality,
            "related_fixes": related,
            "reason": reason,
        }
    if set(parsed) != set(expected):
        missing = sorted(set(expected) - set(parsed))
        extra = sorted(set(parsed) - set(expected))
        raise OriginBatchContractError(
            f"response ID conservation failed: missing={missing} extra={extra}"
        )
    return [parsed[alias] for alias in expected]
