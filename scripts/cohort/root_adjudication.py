"""Contracts for blinded source-root adjudication and sealed scoring."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence


PACKET_KEYS = frozenset(
    {
        "schema_version",
        "packet_id",
        "target_id",
        "vulnerability_description",
        "candidates",
    }
)
CANDIDATE_KEYS = frozenset(
    {
        "candidate_id",
        "authored_date",
        "subject",
        "body_excerpt",
        "changed_paths",
        "patch_excerpt",
        "patch_truncated",
        "evidence_status",
        "evidence_reason",
    }
)


class RootAdjudicationContractError(ValueError):
    """A blinded packet, response, or sealed mapping violates its contract."""


_ADVISORY_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z-]+)\b", re.IGNORECASE
)
_URL_RE = re.compile(r"https?://[^\s<>\])}\"']+", re.IGNORECASE)
_GITHUB_REPOSITORY_RE = re.compile(
    r"\bgithub\.com/[0-9a-z_.-]+/[0-9a-z_.-]+\b", re.IGNORECASE
)
_FULL_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE)


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def packet_id(repository_identity: str, advisory: str) -> str:
    return "root-packet-" + canonical_sha256(
        {"advisory": advisory, "repository_identity": repository_identity}
    )


def target_id(repository_identity: str, advisory: str) -> str:
    return "target-" + canonical_sha256(
        {"advisory": advisory, "repository_identity": repository_identity}
    )[:20]


def candidate_order_key(packet_identifier: str, sha: str) -> str:
    return canonical_sha256({"packet_id": packet_identifier, "sha": sha})


def redact_blind_text(
    value: object,
    *,
    repository_identity: str,
    advisory: str,
) -> str:
    """Remove direct target/source identifiers while preserving code semantics."""

    text = str(value or "")
    repository = repository_identity.strip()
    owner_repo = "/".join(repository.split("/")[1:])
    for literal, replacement in (
        (advisory.strip(), "[ADVISORY_ID]"),
        (repository, "[REPOSITORY]"),
        (owner_repo, "[REPOSITORY]"),
    ):
        if literal:
            text = re.sub(re.escape(literal), replacement, text, flags=re.IGNORECASE)
    text = _ADVISORY_RE.sub("[ADVISORY_ID]", text)
    text = _URL_RE.sub("[URL]", text)
    text = _GITHUB_REPOSITORY_RE.sub("[REPOSITORY]", text)
    return _FULL_SHA_RE.sub("[COMMIT]", text)


def validate_packet(raw: Mapping[str, object]) -> dict[str, object]:
    if frozenset(raw) != PACKET_KEYS:
        raise RootAdjudicationContractError(
            "blinded packet keys do not match the strict allowlist"
        )
    if raw.get("schema_version") != 1:
        raise RootAdjudicationContractError("unknown blinded packet schema")
    identifier = str(raw.get("packet_id") or "")
    opaque_target = str(raw.get("target_id") or "")
    description = str(raw.get("vulnerability_description") or "").strip()
    candidates = raw.get("candidates")
    if not identifier or not opaque_target or not description:
        raise RootAdjudicationContractError("blinded packet identity is incomplete")
    if not isinstance(candidates, list) or not candidates:
        raise RootAdjudicationContractError("blinded packet requires candidates")
    normalized_candidates: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw_candidate in candidates:
        if not isinstance(raw_candidate, Mapping) or frozenset(raw_candidate) != (
            CANDIDATE_KEYS
        ):
            raise RootAdjudicationContractError(
                "blinded candidate keys do not match the strict allowlist"
            )
        candidate_identifier = str(raw_candidate.get("candidate_id") or "")
        if not candidate_identifier or candidate_identifier in seen:
            raise RootAdjudicationContractError("candidate IDs must be unique")
        seen.add(candidate_identifier)
        paths = raw_candidate.get("changed_paths")
        if not isinstance(paths, list) or any(
            not isinstance(path, str) for path in paths
        ):
            raise RootAdjudicationContractError("changed_paths must be strings")
        if raw_candidate.get("patch_truncated") not in {True, False}:
            raise RootAdjudicationContractError("patch_truncated must be boolean")
        status = str(raw_candidate.get("evidence_status") or "")
        if status not in {"READY", "BLOCKED"}:
            raise RootAdjudicationContractError("unknown candidate evidence status")
        normalized_candidates.append(dict(raw_candidate))
    return {
        "schema_version": 1,
        "packet_id": identifier,
        "target_id": opaque_target,
        "vulnerability_description": description,
        "candidates": normalized_candidates,
    }


def build_pilot_spec(
    packet_metadata: Sequence[Mapping[str, object]],
    *,
    pilot_id: str,
    per_stratum: int = 2,
    source_classes: Sequence[str] | None = None,
) -> dict[str, object]:
    if not pilot_id or per_stratum < 1:
        raise RootAdjudicationContractError("pilot selection settings are invalid")
    allowed_strata = {"association_only", "public_exact_present"}
    strata = set(source_classes) if source_classes is not None else allowed_strata
    if not strata or not strata <= allowed_strata or len(strata) != len(source_classes or strata):
        raise RootAdjudicationContractError("pilot source classes are invalid")
    rows: list[dict[str, object]] = []
    seen_packets: set[str] = set()
    for raw in packet_metadata:
        identifier = str(raw.get("packet_id") or "")
        source_class = str(raw.get("source_class") or "")
        if not identifier or identifier in seen_packets or source_class not in strata:
            raise RootAdjudicationContractError("packet metadata is malformed")
        seen_packets.add(identifier)
        rows.append(
            {
                "packet_id": identifier,
                "source_class": source_class,
                "selection_hash": canonical_sha256(
                    {
                        "packet_id": identifier,
                        "pilot_id": pilot_id,
                        "source_class": source_class,
                    }
                ),
                "reasoning_effort": (
                    "medium" if source_class == "public_exact_present" else "high"
                ),
            }
        )
    selected: list[dict[str, object]] = []
    for source_class in sorted(strata):
        ranked = sorted(
            (row for row in rows if row["source_class"] == source_class),
            key=lambda row: (str(row["selection_hash"]), str(row["packet_id"])),
        )
        if len(ranked) < per_stratum:
            raise RootAdjudicationContractError(
                f"insufficient packets for stratum {source_class}"
            )
        selected.extend(ranked[:per_stratum])
    selected.sort(key=lambda row: str(row["selection_hash"]))
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "blinded_root_adjudication_pilot_spec",
        "pilot_id": pilot_id,
        "per_stratum": per_stratum,
        "sampled_source_classes": sorted(strata),
        "selection_rule": (
            "Select the lowest SHA-256 hashes per predeclared frozen source class; use medium "
            "reasoning for sealed public-exact controls and high reasoning for "
            "association-only targets. Do not change rows after model output."
        ),
        "selected": selected,
    }
    result["spec_sha256"] = canonical_sha256(result)
    return result


def parse_model_decision(
    raw: Mapping[str, object], candidate_ids: set[str]
) -> dict[str, object]:
    keys = frozenset(raw)
    expected = frozenset(
        {"decision", "selected_ids", "confidence", "rationale", "missing_evidence"}
    )
    if keys != expected:
        raise RootAdjudicationContractError("model decision keys are invalid")
    decision = str(raw.get("decision") or "")
    selected = raw.get("selected_ids")
    confidence = str(raw.get("confidence") or "")
    if decision not in {"select", "abstain", "blocked"}:
        raise RootAdjudicationContractError("model decision is invalid")
    if confidence not in {"low", "medium", "high"}:
        raise RootAdjudicationContractError("model confidence is invalid")
    if not isinstance(selected, list) or any(
        not isinstance(identifier, str) for identifier in selected
    ):
        raise RootAdjudicationContractError("selected_ids must be strings")
    if len(selected) != len(set(selected)) or not set(selected) <= candidate_ids:
        raise RootAdjudicationContractError("selected_ids contain duplicates or unknown IDs")
    if (decision == "select") != bool(selected):
        raise RootAdjudicationContractError(
            "select requires IDs and abstain/blocked require an empty selection"
        )
    rationale = str(raw.get("rationale") or "").strip()
    missing_evidence = str(raw.get("missing_evidence") or "").strip()
    if not rationale:
        raise RootAdjudicationContractError("model rationale is required")
    return {
        "decision": decision,
        "selected_ids": list(selected),
        "confidence": confidence,
        "rationale": rationale,
        "missing_evidence": missing_evidence,
    }
