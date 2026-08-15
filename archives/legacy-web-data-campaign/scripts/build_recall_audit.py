#!/usr/bin/env python3
"""Build and evaluate a blinded, finite-population end-to-end recall audit.

The detector inventory is partitioned by the stage at which an alias class left
the pipeline.  Selection reads no labels.  Evaluation accepts independent
repository-evidence reviews and expands each without-replacement sample back to
its finite stratum with Horvitz-Thompson estimates and exact hypergeometric
confidence sets.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import secrets
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

import heldout_quality_gate as heldout


class RecallAuditError(ValueError):
    """Raised when a recall artifact cannot support a formal estimate."""


AUDIT_STRATA = (
    "detected_positive",
    "no_fix_commit",
    "fix_no_bic",
    "bic_no_trusted_authorship",
    "trusted_signal_classifier_negative_or_incomplete",
)
COVERAGE_FAILURE_STRATA = frozenset({"coverage_failure", "no_current_campaign_result"})
SELECTION_SCHEMA_VERSION = 4
LABEL_SCHEMA_VERSION = 3
PROTECTED_CENSUS_SCHEMA_VERSION = 1
PROTECTED_CENSUS_LABEL_SCHEMA_VERSION = 1
SYSTEM_CSPRNG_SEED_ORIGIN = "system_csprng"
CALLER_SEED_ORIGIN = "caller_supplied"
PROTECTED_INPUT_POLICY = "heldout_authoritative_protected_roots_v1"
_SELECTION_KIND = "end_to_end_recall_audit_selection"
_LABEL_KIND = "end_to_end_recall_independent_audit"
_PROTECTED_CENSUS_KIND = "protected_alias_class_census_manifest"
_PROTECTED_CENSUS_LABEL_KIND = "protected_alias_class_census_independent_audit"
_LABELS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL", "UNKNOWN"})
_CONCLUSIVE_LABELS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL"})
_REVIEW_ATTESTATIONS = (
    "selection_sealed_before_labels",
    "reviewers_independent_from_detector_development",
    "reviewers_independent_from_each_other",
    "reviews_blinded_to_detector_output",
    "reviews_blinded_to_stratum",
    "reviews_blinded_to_signature_matches",
    "aggregate_scores_hidden_until_resolution",
)
_EVIDENCE_PREFIXES = (
    "repo:",
    "pr:",
    "issue:",
    "commit:",
    "audit-log:",
    "maintainer:",
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def selection_sha256(selection: Mapping[str, Any]) -> str:
    payload = dict(selection)
    payload.pop("selection_manifest_sha256", None)
    return canonical_sha256(payload)


def protected_census_sha256(census: Mapping[str, Any]) -> str:
    """Return the independent content identity of a protected-class census."""

    payload = dict(census)
    payload.pop("census_manifest_sha256", None)
    return canonical_sha256(payload)


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _protected_inputs_contract(
    protected: heldout.ProtectedInventory,
) -> dict[str, Any]:
    if not isinstance(protected, heldout.ProtectedInventory):
        raise RecallAuditError("protected inventory is required")
    subject_ids = sorted(protected.subject_ids)
    if (
        any(not isinstance(value, str) or not value for value in subject_ids)
        or heldout.canonical_sha256(subject_ids) != protected.subject_ids_sha256
        or heldout.canonical_sha256(list(protected.files))
        != protected.files_manifest_sha256
    ):
        raise RecallAuditError("protected inventory content identity is invalid")
    return {
        "policy": PROTECTED_INPUT_POLICY,
        **heldout.protected_inventory_contract(protected),
    }


def _validate_inventory(inventory: Mapping[str, Any]) -> list[dict[str, Any]]:
    if inventory.get("schema_version") != 2 or inventory.get("kind") != (
        "ai_vulnerability_detector_inventory"
    ):
        raise RecallAuditError("detector inventory schema is unsupported")
    if inventory.get("campaign_mode") != "formal":
        raise RecallAuditError("recall selection requires a formal campaign inventory")
    if inventory.get("complete") is not True:
        raise RecallAuditError("recall selection requires a complete inventory")
    inventory_id = inventory.get("inventory_id")
    if not _valid_sha256(inventory_id):
        raise RecallAuditError("inventory_id must be a lowercase SHA-256")
    for field in (
        "source_snapshot_sha256",
        "source_alias_class_manifest_sha256",
        "campaign_id",
    ):
        if not _valid_sha256(inventory.get(field)):
            raise RecallAuditError(
                f"formal detector inventory {field} must be a lowercase SHA-256"
            )
    inventory_preimage = dict(inventory)
    inventory_preimage.pop("inventory_id")
    if canonical_sha256(inventory_preimage) != inventory_id:
        raise RecallAuditError("detector inventory content identity is invalid")
    rows = inventory.get("rows")
    if not isinstance(rows, list):
        raise RecallAuditError("detector inventory rows are missing")
    if inventory.get("alias_class_count") != len(rows):
        raise RecallAuditError("detector inventory alias_class_count is inconsistent")
    seen: set[str] = set()
    member_owner: dict[str, str] = {}
    validated: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise RecallAuditError("detector inventory row must be an object")
        class_id = row.get("class_id")
        component_sha256 = row.get("component_sha256")
        analysis_subject = row.get("analysis_subject")
        member_ids = row.get("member_ids")
        stratum = row.get("recall_stratum")
        normalized_members = (
            [item.strip().casefold() for item in member_ids]
            if isinstance(member_ids, list)
            and all(isinstance(item, str) for item in member_ids)
            else []
        )
        if (
            not isinstance(class_id, str)
            or not class_id
            or class_id != class_id.strip()
            or class_id in seen
            or not isinstance(member_ids, list)
            or not member_ids
            or any(
                not isinstance(item, str) or not item or item != item.strip()
                for item in member_ids
            )
            or len(normalized_members) != len(set(normalized_members))
            or not isinstance(component_sha256, str)
            or len(component_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in component_sha256
            )
            or not isinstance(analysis_subject, str)
            or analysis_subject not in member_ids
            or stratum not in {*AUDIT_STRATA, *COVERAGE_FAILURE_STRATA}
        ):
            raise RecallAuditError(f"invalid detector inventory row: {row!r}")
        expected_component_sha256 = hashlib.sha256(
            ("\n".join(sorted(member_ids)) + "\n").encode()
        ).hexdigest()
        expected_alias_class_id = f"alias-{expected_component_sha256[:24]}"
        if component_sha256 != expected_component_sha256 or (
            class_id != expected_alias_class_id and class_id not in member_ids
        ):
            raise RecallAuditError(f"invalid detector inventory row: {row!r}")
        seen.add(class_id)
        for member_id, normalized_member in zip(member_ids, normalized_members):
            owner = member_owner.get(normalized_member)
            if owner is not None:
                raise RecallAuditError(
                    f"alias member {member_id!r} belongs to both {owner!r} "
                    f"and {class_id!r}"
                )
            member_owner[normalized_member] = class_id
        validated.append(row)
    return validated


def inventory_alias_map(inventory: Mapping[str, Any]) -> dict[str, set[str]]:
    """Return the exact formal-inventory alias closure used for protected replay."""

    rows = _validate_inventory(inventory)
    aliases: dict[str, set[str]] = {}
    for row in rows:
        component = set(row["member_ids"])
        for member_id in row["member_ids"]:
            aliases[member_id] = component
    return aliases


def _census_packet_id(inventory_id: str, class_id: str) -> str:
    return hashlib.sha256(
        f"protected-census-review-packet\0{inventory_id}\0{class_id}".encode()
    ).hexdigest()


def _census_class_projection(
    assignments: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "class_id": row["class_id"],
            "component_sha256": row["component_sha256"],
            "analysis_subject": row["analysis_subject"],
            "subject_ids": row["subject_ids"],
            "stratum": row["stratum"],
        }
        for row in assignments
    ]


def _build_protected_census_manifest(
    inventory: Mapping[str, Any],
    protected_contract: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    assignments = [
        {
            "packet_id": _census_packet_id(inventory["inventory_id"], row["class_id"]),
            "class_id": row["class_id"],
            "component_sha256": row["component_sha256"],
            "analysis_subject": row["analysis_subject"],
            "subject_ids": sorted(row["member_ids"]),
            "stratum": row["recall_stratum"],
        }
        for row in sorted(rows, key=lambda item: item["class_id"])
    ]
    class_projection = _census_class_projection(assignments)
    payload: dict[str, Any] = {
        "schema_version": PROTECTED_CENSUS_SCHEMA_VERSION,
        "kind": _PROTECTED_CENSUS_KIND,
        "inventory": {
            "inventory_id": inventory["inventory_id"],
            "source_snapshot_sha256": inventory["source_snapshot_sha256"],
            "source_alias_class_manifest_sha256": inventory[
                "source_alias_class_manifest_sha256"
            ],
            "campaign_id": inventory["campaign_id"],
        },
        "protected_inputs": dict(protected_contract),
        "protocol": {
            "coverage": "all_protected_overlapping_alias_classes_exactly_once",
            "labels_read_during_construction": False,
            "unit": "advisory_alias_class",
            "review": "blinded_independent_dual_review_with_third_resolution_v1",
        },
        "population": {
            "class_count": len(assignments),
            "class_ids": [row["class_id"] for row in assignments],
            "classes_manifest_sha256": canonical_sha256(class_projection),
        },
        "assignments": assignments,
        "blinded_review_packets": [
            {"packet_id": row["packet_id"], "subject_ids": row["subject_ids"]}
            for row in assignments
        ],
    }
    payload["census_manifest_sha256"] = protected_census_sha256(payload)
    return payload


def _validate_protected_census_manifest(
    value: object,
    *,
    expected_protected_inputs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    expected_fields = {
        "schema_version",
        "kind",
        "inventory",
        "protected_inputs",
        "protocol",
        "population",
        "assignments",
        "blinded_review_packets",
        "census_manifest_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise RecallAuditError("protected census manifest has an invalid schema")
    if (
        value.get("schema_version") != PROTECTED_CENSUS_SCHEMA_VERSION
        or value.get("kind") != _PROTECTED_CENSUS_KIND
        or value.get("census_manifest_sha256") != protected_census_sha256(value)
    ):
        raise RecallAuditError("protected census seal is invalid")
    inventory = value.get("inventory")
    inventory_fields = {
        "inventory_id",
        "source_snapshot_sha256",
        "source_alias_class_manifest_sha256",
        "campaign_id",
    }
    if (
        not isinstance(inventory, dict)
        or set(inventory) != inventory_fields
        or any(not _valid_sha256(inventory.get(field)) for field in inventory_fields)
    ):
        raise RecallAuditError("protected census inventory identity is invalid")
    protected_inputs = value.get("protected_inputs")
    if not isinstance(protected_inputs, dict) or (
        expected_protected_inputs is not None
        and protected_inputs != expected_protected_inputs
    ):
        raise RecallAuditError("protected census input identity is invalid")
    if value.get("protocol") != {
        "coverage": "all_protected_overlapping_alias_classes_exactly_once",
        "labels_read_during_construction": False,
        "unit": "advisory_alias_class",
        "review": "blinded_independent_dual_review_with_third_resolution_v1",
    }:
        raise RecallAuditError("protected census protocol is invalid")
    assignments = value.get("assignments")
    population = value.get("population")
    if not isinstance(assignments, list) or not isinstance(population, dict):
        raise RecallAuditError("protected census population is missing")
    prior_class_id = ""
    packet_ids: set[str] = set()
    for row in assignments:
        if not isinstance(row, dict) or set(row) != {
            "packet_id",
            "class_id",
            "component_sha256",
            "analysis_subject",
            "subject_ids",
            "stratum",
        }:
            raise RecallAuditError("protected census assignment is malformed")
        class_id = row.get("class_id")
        packet_id = row.get("packet_id")
        subject_ids = row.get("subject_ids")
        component_sha256 = row.get("component_sha256")
        if (
            not isinstance(class_id, str)
            or not class_id
            or class_id <= prior_class_id
            or not _valid_sha256(packet_id)
            or packet_id in packet_ids
            or packet_id != _census_packet_id(inventory["inventory_id"], class_id)
            or not isinstance(subject_ids, list)
            or not subject_ids
            or any(not isinstance(item, str) or not item for item in subject_ids)
            or subject_ids != sorted(subject_ids)
            or len({item.casefold() for item in subject_ids}) != len(subject_ids)
            or row.get("analysis_subject") not in subject_ids
            or not _valid_sha256(component_sha256)
            or component_sha256
            != hashlib.sha256(("\n".join(subject_ids) + "\n").encode()).hexdigest()
            or row.get("stratum") not in {*AUDIT_STRATA, *COVERAGE_FAILURE_STRATA}
        ):
            raise RecallAuditError("protected census assignment identity is invalid")
        prior_class_id = class_id
        packet_ids.add(packet_id)
    class_projection = _census_class_projection(assignments)
    if population != {
        "class_count": len(assignments),
        "class_ids": [row["class_id"] for row in assignments],
        "classes_manifest_sha256": canonical_sha256(class_projection),
    }:
        raise RecallAuditError("protected census population is not exact-once")
    expected_packets = [
        {"packet_id": row["packet_id"], "subject_ids": row["subject_ids"]}
        for row in assignments
    ]
    if value.get("blinded_review_packets") != expected_packets:
        raise RecallAuditError("protected census blinded packets are invalid")
    return value


def _rank(seed: str, stratum: str, class_id: str) -> str:
    return hashlib.sha256(f"{seed}\0{stratum}\0{class_id}".encode()).hexdigest()


def _packet_id(seed: str, class_id: str) -> str:
    return hashlib.sha256(f"review-packet\0{seed}\0{class_id}".encode()).hexdigest()


def build_selection_manifest(
    inventory: Mapping[str, Any],
    *,
    sample_sizes: Mapping[str, Any],
    protected: heldout.ProtectedInventory,
    seed: str | None = None,
    seed_origin: str | None = None,
) -> dict[str, Any]:
    """Seal deterministic SRSWOR samples without accepting any label input."""

    if seed is None:
        seed = secrets.token_hex(32)
        actual_seed_origin = SYSTEM_CSPRNG_SEED_ORIGIN
    else:
        actual_seed_origin = seed_origin or CALLER_SEED_ORIGIN
    if not isinstance(seed, str) or not seed:
        raise RecallAuditError("selection seed is required")
    if actual_seed_origin not in {SYSTEM_CSPRNG_SEED_ORIGIN, CALLER_SEED_ORIGIN}:
        raise RecallAuditError("selection seed origin is invalid")
    if actual_seed_origin == SYSTEM_CSPRNG_SEED_ORIGIN and (
        len(seed) != 64
        or any(character not in "0123456789abcdef" for character in seed)
    ):
        raise RecallAuditError("system CSPRNG seed must be 256-bit lowercase hex")
    if not isinstance(sample_sizes, Mapping):
        raise RecallAuditError("sample size contract must be an object")
    unknown_strata = set(sample_sizes) - set(AUDIT_STRATA)
    if unknown_strata:
        raise RecallAuditError(f"unknown sample strata: {sorted(unknown_strata)}")
    protected_contract = _protected_inputs_contract(protected)
    protected_subject_ids = protected.subject_ids
    if any(
        not isinstance(value, str) or not value or value != value.strip()
        for value in protected_subject_ids
    ) or len({value.casefold() for value in protected_subject_ids}) != len(
        protected_subject_ids
    ):
        raise RecallAuditError("protected subject IDs are invalid")
    rows = _validate_inventory(inventory)
    normalized_protected_ids = {
        subject_id.casefold() for subject_id in protected_subject_ids
    }
    protected_rows = [
        row
        for row in rows
        if bool(
            {member_id.casefold() for member_id in row["member_ids"]}
            & normalized_protected_ids
        )
    ]
    protected_census = _build_protected_census_manifest(
        inventory,
        protected_contract,
        protected_rows,
    )
    rows = [row for row in rows if row not in protected_rows]
    grouped = {stratum: [] for stratum in AUDIT_STRATA}
    coverage_failures = [
        row
        for row in (*rows, *protected_rows)
        if row["recall_stratum"] in COVERAGE_FAILURE_STRATA
    ]
    for row in rows:
        stratum = row["recall_stratum"]
        if stratum not in COVERAGE_FAILURE_STRATA:
            grouped[stratum].append(row)

    assignments: list[dict[str, Any]] = []
    population_contract: dict[str, dict[str, Any]] = {}
    normalized_sample_contract: dict[str, dict[str, Any]] = {}
    for stratum in AUDIT_STRATA:
        population = sorted(grouped[stratum], key=lambda row: row["class_id"])
        population_size = len(population)
        sample_contract = sample_sizes.get(stratum, 0)
        if isinstance(sample_contract, Mapping):
            requested = sample_contract.get("sample_size", 0)
            power_rationale = sample_contract.get("power_rationale", "")
        else:
            requested = sample_contract
            power_rationale = "fixed pre-label stratum sample size"
        if (
            isinstance(requested, bool)
            or not isinstance(requested, int)
            or requested < 0
        ):
            raise RecallAuditError(f"invalid sample size for {stratum}")
        if population_size and (
            not isinstance(power_rationale, str) or not power_rationale.strip()
        ):
            raise RecallAuditError(f"power rationale is missing for {stratum}")
        if population_size and requested <= 0:
            raise RecallAuditError(f"non-empty stratum requires a sample: {stratum}")
        normalized_rationale = (
            power_rationale.strip()
            if isinstance(power_rationale, str) and power_rationale.strip()
            else "empty stratum"
        )
        normalized_sample_contract[stratum] = {
            "sample_size": requested,
            "power_rationale": normalized_rationale,
        }
        sample_size = min(requested, population_size)
        ranked = sorted(
            population,
            key=lambda row: (_rank(seed, stratum, row["class_id"]), row["class_id"]),
        )
        population_contract[stratum] = {
            "population_size": population_size,
            "sample_size": sample_size,
            "selection_probability": (
                sample_size / population_size if population_size else None
            ),
            "power_rationale": normalized_rationale,
        }
        for row in ranked[:sample_size]:
            assignments.append(
                {
                    "packet_id": _packet_id(seed, row["class_id"]),
                    "class_id": row["class_id"],
                    "subject_ids": sorted(row["member_ids"]),
                    "stratum": stratum,
                    "selection_rank_sha256": _rank(seed, stratum, row["class_id"]),
                    "selection_probability": sample_size / population_size,
                }
            )

    assignments.sort(key=lambda row: (row["stratum"], row["selection_rank_sha256"]))
    payload: dict[str, Any] = {
        "schema_version": SELECTION_SCHEMA_VERSION,
        "kind": _SELECTION_KIND,
        "inventory": {
            "inventory_id": inventory["inventory_id"],
            "source_snapshot_sha256": inventory.get("source_snapshot_sha256"),
            "source_alias_class_manifest_sha256": inventory.get(
                "source_alias_class_manifest_sha256"
            ),
            "campaign_id": inventory.get("campaign_id"),
            "campaign_mode": "formal",
            "complete": True,
        },
        "selection_policy": {
            "algorithm": "domain_separated_sha256_top_k_srswor_v1",
            "seed": seed,
            "seed_sha256": hashlib.sha256(seed.encode()).hexdigest(),
            "seed_origin": actual_seed_origin,
            "labels_read_during_selection": False,
            "unit": "advisory_alias_class",
            "sample_sizes": normalized_sample_contract,
            "sample_size_rationale": (
                "Per-stratum sizes are fixed before labels; every non-empty rejection "
                "stratum has non-zero inclusion probability."
            ),
        },
        "protected_inputs": protected_contract,
        "protected_census": protected_census,
        "population": {
            "alias_class_count": len(rows),
            "source_alias_class_count": inventory["alias_class_count"],
            "protected_excluded_class_count": len(protected_rows),
            "protected_excluded_class_ids": sorted(
                row["class_id"] for row in protected_rows
            ),
            "protected_subject_ids": sorted(protected_subject_ids),
            "protected_subject_ids_sha256": canonical_sha256(
                sorted(protected_subject_ids)
            ),
            "coverage_failure_count": len(coverage_failures),
            "coverage_failure_class_ids": sorted(
                row["class_id"] for row in coverage_failures
            ),
            "strata": population_contract,
        },
        "assignments": assignments,
        "blinded_review_packets": [
            {
                "packet_id": row["packet_id"],
                "subject_ids": row["subject_ids"],
            }
            for row in sorted(assignments, key=lambda row: row["packet_id"])
        ],
        "measurement_boundary": {
            "coverage": (
                "Classes without a current campaign result are coverage failures and "
                "block a formal end-to-end recall estimate."
            ),
            "recall": (
                "Finite-population prevalence is estimated independently in every "
                "covered, unprotected post-campaign stratum. Protected exclusions or "
                "coverage failures limit the result to a named conditional diagnostic."
            ),
            "review_blinding": (
                "Review packets omit detector state, signature matches, stratum, and "
                "aggregate scores."
            ),
        },
    }
    payload["selection_manifest_sha256"] = selection_sha256(payload)
    return payload


def validate_selection_seal(selection: Mapping[str, Any]) -> str:
    """Validate the recall-selection content seal and return its digest."""

    digest = selection_sha256(selection)
    if selection.get("selection_manifest_sha256") != digest:
        raise RecallAuditError("selection seal is invalid")
    if (
        selection.get("schema_version") != SELECTION_SCHEMA_VERSION
        or selection.get("kind") != _SELECTION_KIND
    ):
        raise RecallAuditError("recall selection schema is unsupported")
    protected_inputs = selection.get("protected_inputs")
    if not isinstance(protected_inputs, dict):
        raise RecallAuditError("selection protected input contract is invalid")
    census = _validate_protected_census_manifest(
        selection.get("protected_census"),
        expected_protected_inputs=protected_inputs,
    )
    selection_inventory = selection.get("inventory")
    if not isinstance(selection_inventory, dict) or census["inventory"] != {
        field: selection_inventory.get(field)
        for field in (
            "inventory_id",
            "source_snapshot_sha256",
            "source_alias_class_manifest_sha256",
            "campaign_id",
        )
    }:
        raise RecallAuditError("protected census inventory binding is invalid")
    return digest


def replay_selection_manifest(
    selection: Mapping[str, Any],
    inventory: Mapping[str, Any],
    *,
    protected: heldout.ProtectedInventory,
) -> str:
    """Rebuild selection from its immutable inventory and embedded contract."""

    digest = validate_selection_seal(selection)
    policy = selection.get("selection_policy")
    population = selection.get("population")
    protected_contract = selection.get("protected_inputs")
    if not isinstance(policy, dict) or not isinstance(population, dict):
        raise RecallAuditError("selection replay contract is missing")
    if protected_contract != _protected_inputs_contract(protected):
        raise RecallAuditError("protected inputs drifted after sample selection")
    seed = policy.get("seed")
    seed_origin = policy.get("seed_origin")
    sample_sizes = policy.get("sample_sizes")
    if not isinstance(seed, str) or not seed:
        raise RecallAuditError("selection replay seed is missing")
    if not isinstance(sample_sizes, dict):
        raise RecallAuditError("selection replay sample contract is missing")
    expected = build_selection_manifest(
        inventory,
        sample_sizes=sample_sizes,
        protected=protected,
        seed=seed,
        seed_origin=seed_origin,
    )
    if expected != selection:
        raise RecallAuditError(
            "selection does not exactly replay from the formal detector inventory"
        )
    return digest


def _rebuild_authoritative_protected_inventory(
    selection: Mapping[str, Any],
    *,
    repo_root: Path,
    selection_path: Path,
    labels_path: Path,
    alias_map: Mapping[str, set[str]],
) -> heldout.ProtectedInventory:
    """Replay protected roots and exact file/subject provenance for evaluation."""

    contract = selection.get("protected_inputs")
    expected_fields = {
        "policy",
        "source_roots",
        "files",
        "files_manifest_sha256",
        "subject_id_count",
        "subject_ids_sha256",
    }
    if (
        not isinstance(contract, dict)
        or set(contract) != expected_fields
        or contract.get("policy") != PROTECTED_INPUT_POLICY
        or not isinstance(contract.get("source_roots"), list)
    ):
        raise RecallAuditError("selection protected input contract is invalid")
    try:
        protected = heldout.build_authoritative_protected_inventory(
            repo_root,
            recorded_roots=contract["source_roots"],
            excluded_paths=(selection_path, labels_path),
            alias_map=alias_map,
        )
    except heldout.HeldoutQualityError as exc:
        raise RecallAuditError(str(exc)) from exc
    if contract != _protected_inputs_contract(protected):
        raise RecallAuditError("protected inputs drifted after sample selection")
    return protected


def _prove_artifact_order(
    reference: object,
    *,
    selection: Mapping[str, Any],
    selection_digest: str,
    selection_path: Path,
    labels_path: Path,
    labels_payload: Mapping[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    """Reuse the hardened Git ancestry proof shared with the held-out gate."""

    import heldout_quality_gate as heldout

    try:
        return heldout._validate_artifact_order(
            reference,
            selection=selection,
            selection_digest=selection_digest,
            selection_path=selection_path,
            labels_path=labels_path,
            labels_payload=labels_payload,
            repo_root=repo_root,
            selection_seal_validator=validate_selection_seal,
        )
    except heldout.HeldoutQualityError as exc:
        raise RecallAuditError(str(exc)) from exc


def _hypergeom_numerator(
    population_size: int,
    population_positives: int,
    sample_size: int,
    observed: int,
) -> int:
    if observed < 0 or observed > sample_size:
        return 0
    negatives = population_size - population_positives
    if observed > population_positives or sample_size - observed > negatives:
        return 0
    return math.comb(population_positives, observed) * math.comb(
        negatives, sample_size - observed
    )


def _tail_probability(
    population_size: int,
    population_positives: int,
    sample_size: int,
    observed: int,
    *,
    upper: bool,
) -> float:
    denominator = math.comb(population_size, sample_size)
    support_min = max(0, sample_size - (population_size - population_positives))
    support_max = min(sample_size, population_positives)
    if upper:
        values = range(max(observed, support_min), support_max + 1)
    else:
        values = range(support_min, min(observed, support_max) + 1)
    numerator = sum(
        _hypergeom_numerator(population_size, population_positives, sample_size, value)
        for value in values
    )
    return numerator / denominator


def hypergeometric_total_interval(
    population_size: int,
    sample_size: int,
    observed_positives: int,
    *,
    confidence_level: float = 0.95,
) -> tuple[int, int]:
    """Invert equal-tailed exact hypergeometric tests for the population total."""

    for name, value in (
        ("population_size", population_size),
        ("sample_size", sample_size),
        ("observed_positives", observed_positives),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise RecallAuditError(f"{name} must be an integer")
    if population_size <= 0 or not 0 < sample_size <= population_size:
        raise RecallAuditError("sample size must be within the finite population")
    if not 0 <= observed_positives <= sample_size:
        raise RecallAuditError("observed positives exceed the sample")
    if not isinstance(confidence_level, (int, float)) or not 0 < confidence_level < 1:
        raise RecallAuditError("confidence_level must be between zero and one")
    if sample_size == population_size:
        return observed_positives, observed_positives

    alpha_tail = (1.0 - float(confidence_level)) / 2.0
    feasible_low = observed_positives
    feasible_high = population_size - sample_size + observed_positives

    lower_left, lower_right = feasible_low, feasible_high
    while lower_left < lower_right:
        candidate = (lower_left + lower_right) // 2
        if (
            _tail_probability(
                population_size,
                candidate,
                sample_size,
                observed_positives,
                upper=True,
            )
            >= alpha_tail
        ):
            lower_right = candidate
        else:
            lower_left = candidate + 1
    lower = lower_left

    upper_left, upper_right = feasible_low, feasible_high
    while upper_left < upper_right:
        candidate = (upper_left + upper_right + 1) // 2
        if (
            _tail_probability(
                population_size,
                candidate,
                sample_size,
                observed_positives,
                upper=False,
            )
            >= alpha_tail
        ):
            upper_left = candidate
        else:
            upper_right = candidate - 1
    return lower, upper_left


def estimate_recall(
    strata: Mapping[str, Mapping[str, int]],
    *,
    confidence_level: float = 0.95,
) -> dict[str, Any]:
    """Expand sampled labels and return a simultaneous recall confidence interval."""

    detected = strata.get("detected_positive")
    if detected is None:
        raise RecallAuditError("detected_positive stratum is required")
    detected_population_size = detected.get("population_size")
    if detected_population_size == 0 and any(
        isinstance(detected.get(field), bool)
        or not isinstance(detected.get(field), int)
        or detected.get(field) != 0
        for field in ("population_size", "sample_size", "ai_causal")
    ):
        raise RecallAuditError(
            "empty detected_positive stratum requires zero population, sample, and labels"
        )
    active = {
        name: values for name, values in strata.items() if values["population_size"]
    }
    family_size = len(active)
    simultaneous_stratum_confidence = (
        1.0 - (1.0 - confidence_level) / family_size
        if family_size
        else confidence_level
    )
    reports: dict[str, dict[str, Any]] = {}
    if detected_population_size == 0:
        reports["detected_positive"] = {
            "population_size": 0,
            "sample_size": 0,
            "observed_ai_causal": 0,
            "selection_probability": None,
            "horvitz_thompson_positive_estimate": 0.0,
            "population_positive_interval": [0, 0],
        }
    for name, values in active.items():
        population_size = values["population_size"]
        sample_size = values["sample_size"]
        observed = values["ai_causal"]
        if sample_size <= 0:
            raise RecallAuditError(f"stratum {name} has no completed sample")
        lower, upper = hypergeometric_total_interval(
            population_size,
            sample_size,
            observed,
            confidence_level=simultaneous_stratum_confidence,
        )
        reports[name] = {
            "population_size": population_size,
            "sample_size": sample_size,
            "observed_ai_causal": observed,
            "selection_probability": sample_size / population_size,
            "horvitz_thompson_positive_estimate": population_size
            * observed
            / sample_size,
            "population_positive_interval": [lower, upper],
        }

    true_positive = reports["detected_positive"]["horvitz_thompson_positive_estimate"]
    true_lower, true_upper = reports["detected_positive"][
        "population_positive_interval"
    ]
    missed = sum(
        report["horvitz_thompson_positive_estimate"]
        for name, report in reports.items()
        if name != "detected_positive"
    )
    missed_lower = sum(
        report["population_positive_interval"][0]
        for name, report in reports.items()
        if name != "detected_positive"
    )
    missed_upper = sum(
        report["population_positive_interval"][1]
        for name, report in reports.items()
        if name != "detected_positive"
    )
    point_denominator = true_positive + missed
    lower_denominator = true_lower + missed_upper
    upper_denominator = true_upper + missed_lower
    if point_denominator:
        if not lower_denominator or not upper_denominator:
            raise RecallAuditError(
                "positive recall denominator has invalid confidence bounds"
            )
        point = true_positive / point_denominator
        interval: list[float] | None = [
            true_lower / lower_denominator,
            true_upper / upper_denominator,
        ]
        recall_status = (
            "defined_zero_no_detected_positives"
            if detected_population_size == 0
            else "defined"
        )
    else:
        point = None
        interval = None
        recall_status = "zero_estimated_actual_positives"
    return {
        "unit": "advisory_alias_class",
        "confidence_method": "exact_hypergeometric_bonferroni_95pct",
        "family_wise_confidence_level": confidence_level,
        "stratum_confidence_level": simultaneous_stratum_confidence,
        "strata": reports,
        "true_positive_estimate": true_positive,
        "missed_positive_estimate": missed,
        "recall_denominator_estimate": point_denominator,
        "recall_status": recall_status,
        "recall_point": point,
        "recall_interval": interval,
    }


def required_review_protocol(selection_commit_reference: str) -> dict[str, Any]:
    return {
        "selection_commit_reference": selection_commit_reference,
        **{attestation: True for attestation in _REVIEW_ATTESTATIONS},
    }


def _load_review(value: object, description: str) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "reviewer_id",
        "label",
        "evidence_refs",
        "rationale",
    }:
        raise RecallAuditError(f"{description} has an invalid review schema")
    reviewer = value.get("reviewer_id")
    label = value.get("label")
    evidence = value.get("evidence_refs")
    rationale = value.get("rationale")
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise RecallAuditError(f"{description} reviewer is missing")
    if label not in _LABELS:
        raise RecallAuditError(f"{description} label is invalid")
    if (
        not isinstance(evidence, list)
        or not evidence
        or any(not isinstance(item, str) or not item.strip() for item in evidence)
        or not any(item.startswith(_EVIDENCE_PREFIXES) for item in evidence)
    ):
        raise RecallAuditError(
            f"{description} requires independent repository-hosted evidence"
        )
    if not isinstance(rationale, str) or not rationale.strip():
        raise RecallAuditError(f"{description} rationale is missing")
    return reviewer.strip().casefold(), label


def _resolve_reviews(row: Mapping[str, Any]) -> tuple[str | None, tuple[str, str]]:
    if set(row) != {
        "packet_id",
        "primary_review",
        "secondary_review",
        "third_review",
    }:
        raise RecallAuditError("adjudication has an invalid schema")
    packet_id = row.get("packet_id")
    primary_reviewer, primary = _load_review(
        row.get("primary_review"), f"primary review for {packet_id}"
    )
    secondary_reviewer, secondary = _load_review(
        row.get("secondary_review"), f"secondary review for {packet_id}"
    )
    if primary_reviewer == secondary_reviewer:
        raise RecallAuditError(f"reviewers must be distinct for {packet_id}")
    if primary == secondary and primary in _CONCLUSIVE_LABELS:
        if row.get("third_review") is not None:
            raise RecallAuditError(f"unneeded third review for {packet_id}")
        return primary, (primary, secondary)

    third = row.get("third_review")
    if third is None:
        return None, (primary, secondary)
    third_reviewer, third_label = _load_review(third, f"third review for {packet_id}")
    if third_reviewer in {primary_reviewer, secondary_reviewer}:
        raise RecallAuditError(f"third reviewer must be independent for {packet_id}")
    conclusive = [
        label
        for label in (primary, secondary, third_label)
        if label in _CONCLUSIVE_LABELS
    ]
    counts = Counter(conclusive)
    if not counts or max(counts.values()) < 2:
        return None, (primary, secondary)
    return counts.most_common(1)[0][0], (primary, secondary)


def _agreement(pairs: Sequence[tuple[str, str]]) -> dict[str, float | int | None]:
    conclusive = [pair for pair in pairs if set(pair) <= _CONCLUSIVE_LABELS]
    if not conclusive:
        return {
            "conclusive_pair_count": 0,
            "primary_secondary_agreement": None,
            "cohen_kappa": None,
        }
    observed = sum(left == right for left, right in conclusive) / len(conclusive)
    primary = Counter(left for left, _ in conclusive)
    secondary = Counter(right for _, right in conclusive)
    expected = sum(
        primary[label] / len(conclusive) * secondary[label] / len(conclusive)
        for label in _CONCLUSIVE_LABELS
    )
    kappa = (observed - expected) / (1 - expected) if expected < 1 else 1.0
    return {
        "conclusive_pair_count": len(conclusive),
        "primary_secondary_agreement": observed,
        "cohen_kappa": kappa,
    }


def _resolve_adjudications(
    value: object,
    assignments: Mapping[str, Mapping[str, Any]],
    *,
    description: str,
) -> tuple[dict[str, str], list[str], list[tuple[str, str]]]:
    if not isinstance(value, list) or len(value) != len(assignments):
        raise RecallAuditError(
            f"{description} requires exactly one adjudication for every packet"
        )
    resolved: dict[str, str] = {}
    unresolved: list[str] = []
    reviewer_pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict):
            raise RecallAuditError(f"{description} adjudication must be an object")
        packet_id = row.get("packet_id")
        if packet_id not in assignments or packet_id in seen:
            raise RecallAuditError(
                f"{description} has an unknown or duplicate packet: {packet_id}"
            )
        seen.add(packet_id)
        label, pair = _resolve_reviews(row)
        reviewer_pairs.append(pair)
        if label is None:
            unresolved.append(packet_id)
        else:
            resolved[packet_id] = label
    return resolved, sorted(unresolved), reviewer_pairs


def _incorporate_exact_protected_census(
    conditional: Mapping[str, Any],
    assignments: Mapping[str, Mapping[str, Any]],
    resolved: Mapping[str, str],
) -> dict[str, Any]:
    """Add fully enumerated protected labels without changing sample probabilities."""

    census_strata = {
        stratum: {"class_count": 0, "ai_causal": 0} for stratum in AUDIT_STRATA
    }
    for packet_id, assignment in assignments.items():
        stratum = assignment["stratum"]
        if stratum not in census_strata:
            continue
        census_strata[stratum]["class_count"] += 1
        census_strata[stratum]["ai_causal"] += resolved[packet_id] == "AI_CAUSAL"

    conditional_strata = conditional["strata"]
    detected = conditional_strata["detected_positive"]
    exact_true = census_strata["detected_positive"]["ai_causal"]
    exact_missed = sum(
        values["ai_causal"]
        for stratum, values in census_strata.items()
        if stratum != "detected_positive"
    )
    true_positive = conditional["true_positive_estimate"] + exact_true
    missed = conditional["missed_positive_estimate"] + exact_missed
    true_lower = detected["population_positive_interval"][0] + exact_true
    true_upper = detected["population_positive_interval"][1] + exact_true
    missed_lower = exact_missed + sum(
        report["population_positive_interval"][0]
        for stratum, report in conditional_strata.items()
        if stratum != "detected_positive"
    )
    missed_upper = exact_missed + sum(
        report["population_positive_interval"][1]
        for stratum, report in conditional_strata.items()
        if stratum != "detected_positive"
    )
    denominator = true_positive + missed
    if denominator:
        lower_denominator = true_lower + missed_upper
        upper_denominator = true_upper + missed_lower
        point: float | None = true_positive / denominator
        interval: list[float] | None = [
            true_lower / lower_denominator if lower_denominator else 0.0,
            true_upper / upper_denominator if upper_denominator else 1.0,
        ]
        detected_population = (
            detected["population_size"]
            + census_strata["detected_positive"]["class_count"]
        )
        status = (
            "defined_zero_no_detected_positives"
            if detected_population == 0
            else "defined"
        )
    else:
        point = None
        interval = None
        status = "zero_estimated_actual_positives"

    census_class_count = len(assignments)
    output = dict(conditional)
    if census_class_count:
        output["confidence_method"] = (
            "exact_protected_census_plus_hypergeometric_bonferroni_95pct"
        )
    output.update(
        {
            "true_positive_estimate": true_positive,
            "missed_positive_estimate": missed,
            "recall_denominator_estimate": denominator,
            "recall_status": status,
            "recall_point": point,
            "recall_interval": interval,
            "protected_census": {
                "class_count": census_class_count,
                "exact_true_positive_count": exact_true,
                "exact_missed_positive_count": exact_missed,
                "strata": census_strata,
            },
        }
    )
    return output


def evaluate_labels(
    selection: Mapping[str, Any],
    labels: Mapping[str, Any],
    *,
    inventory: Mapping[str, Any],
    protected: heldout.ProtectedInventory,
    selection_path: Path | None = None,
    labels_path: Path | None = None,
    repo_root: Path | None = None,
    verify_artifact_order: bool = True,
) -> dict[str, Any]:
    """Resolve blinded reviews; unresolved UNKNOWN values fail the estimate closed."""

    expected_digest = replay_selection_manifest(
        selection,
        inventory,
        protected=protected,
    )
    expected_label_fields = {
        "schema_version",
        "kind",
        "selection_manifest_sha256",
        "audit_protocol",
        "adjudications",
        "protected_census",
    }
    if set(labels) != expected_label_fields:
        raise RecallAuditError("label file requires exact schema-3 top-level fields")
    if (
        labels.get("schema_version") != LABEL_SCHEMA_VERSION
        or labels.get("kind") != _LABEL_KIND
    ):
        raise RecallAuditError("recall label schema is unsupported")
    if labels.get("selection_manifest_sha256") != expected_digest:
        raise RecallAuditError("labels are not bound to the sealed selection")
    protocol = labels.get("audit_protocol")
    expected_protocol_fields = {"selection_commit_reference", *_REVIEW_ATTESTATIONS}
    if not isinstance(protocol, dict) or set(protocol) != expected_protocol_fields:
        raise RecallAuditError("review blinding protocol is incomplete")
    for attestation in _REVIEW_ATTESTATIONS:
        if protocol.get(attestation) is not True:
            raise RecallAuditError(
                f"review blinding protocol attestation is false: {attestation}"
            )
    census_manifest = _validate_protected_census_manifest(
        selection.get("protected_census"),
        expected_protected_inputs=selection.get("protected_inputs"),
    )
    census_labels = labels.get("protected_census")
    if not isinstance(census_labels, dict) or set(census_labels) != {
        "schema_version",
        "kind",
        "census_manifest_sha256",
        "audit_protocol_sha256",
        "adjudications",
    }:
        raise RecallAuditError("protected census labels have an invalid schema")
    if (
        census_labels.get("schema_version") != PROTECTED_CENSUS_LABEL_SCHEMA_VERSION
        or census_labels.get("kind") != _PROTECTED_CENSUS_LABEL_KIND
        or census_labels.get("census_manifest_sha256")
        != census_manifest["census_manifest_sha256"]
    ):
        raise RecallAuditError(
            "protected census labels are not bound to the sealed census"
        )
    if census_labels.get("audit_protocol_sha256") != canonical_sha256(protocol):
        raise RecallAuditError(
            "protected census labels are not bound to the review protocol"
        )
    artifact_order: dict[str, Any] = {}
    if verify_artifact_order:
        if selection_path is None or labels_path is None:
            raise RecallAuditError("artifact-order proof requires study paths")
        artifact_order = _prove_artifact_order(
            protocol.get("selection_commit_reference"),
            selection=selection,
            selection_digest=expected_digest,
            selection_path=selection_path,
            labels_path=labels_path,
            labels_payload=labels,
            repo_root=(repo_root or Path.cwd()),
        )
    assignments = {row["packet_id"]: row for row in selection.get("assignments", [])}
    resolved, unresolved, reviewer_pairs = _resolve_adjudications(
        labels.get("adjudications"),
        assignments,
        description="random sample",
    )
    census_assignments = {
        row["packet_id"]: row for row in census_manifest["assignments"]
    }
    (
        census_resolved,
        census_unresolved,
        census_reviewer_pairs,
    ) = _resolve_adjudications(
        census_labels.get("adjudications"),
        census_assignments,
        description="protected census",
    )

    reviews_complete = not unresolved
    conditional_recall: dict[str, Any] | None = None
    if reviews_complete:
        stratum_counts: dict[str, dict[str, int]] = {}
        population = selection["population"]["strata"]
        for stratum in AUDIT_STRATA:
            contract = population[stratum]
            if not contract["population_size"]:
                if stratum == "detected_positive":
                    stratum_counts[stratum] = {
                        "population_size": 0,
                        "sample_size": 0,
                        "ai_causal": 0,
                    }
                continue
            sampled = [row for row in assignments.values() if row["stratum"] == stratum]
            stratum_counts[stratum] = {
                "population_size": contract["population_size"],
                "sample_size": len(sampled),
                "ai_causal": sum(
                    resolved[row["packet_id"]] == "AI_CAUSAL" for row in sampled
                ),
            }
        conditional_recall = estimate_recall(stratum_counts)
    census_complete = not census_unresolved
    whole_population_recall = (
        _incorporate_exact_protected_census(
            conditional_recall,
            census_assignments,
            census_resolved,
        )
        if conditional_recall is not None and census_complete
        else None
    )
    coverage_failure_count = selection["population"]["coverage_failure_count"]
    protected_overlap_count = selection["population"]["protected_excluded_class_count"]
    protected_excluded_count = 0 if census_complete else protected_overlap_count
    blockers: list[str] = []
    if unresolved:
        blockers.append("unresolved_adjudications")
    if census_unresolved:
        blockers.append("protected_census_incomplete")
    if not artifact_order:
        blockers.append("artifact_order_unproven")
    if selection["selection_policy"]["seed_origin"] != SYSTEM_CSPRNG_SEED_ORIGIN:
        blockers.append("selection_seed_not_system_csprng")
    if coverage_failure_count:
        blockers.append("campaign_coverage_failures")
    evaluation_complete = not blockers
    return {
        "schema_version": 2,
        "evaluation_kind": "stratified_end_to_end_finite_population_recall",
        "selection_manifest_sha256": expected_digest,
        "selection_replayed_from_inventory": True,
        "artifact_order": artifact_order,
        "evaluation_complete": evaluation_complete,
        "evaluation_blockers": blockers,
        "resolved_labels": dict(sorted(resolved.items())),
        "unresolved_packet_ids": sorted(unresolved),
        "inter_rater_agreement": _agreement(reviewer_pairs),
        "coverage_failure_count": coverage_failure_count,
        "protected_overlap_class_count": protected_overlap_count,
        "protected_census_manifest_sha256": census_manifest["census_manifest_sha256"],
        "protected_census_complete": census_complete,
        "protected_census_resolved_labels": dict(sorted(census_resolved.items())),
        "protected_census_unresolved_packet_ids": census_unresolved,
        "protected_census_inter_rater_agreement": _agreement(census_reviewer_pairs),
        "protected_excluded_class_count": protected_excluded_count,
        "covered_unprotected_diagnostic_complete": reviews_complete,
        "covered_unprotected_recall_diagnostic": conditional_recall,
        "measurement_boundary": (
            "The diagnostic estimates recall in covered, unprotected alias classes. "
            "Formal end-to-end recall adds the exact contribution from the separately "
            "sealed census of every protected overlapping class."
        ),
        "recall": whole_population_recall if evaluation_complete else None,
    }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecallAuditError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RecallAuditError(f"{path} must contain an object")
    return value


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    select = subcommands.add_parser("select")
    select.add_argument("--repo-root", type=Path, default=Path.cwd())
    select.add_argument("--inventory", type=Path, required=True)
    select.add_argument("--sample-sizes", type=Path, required=True)
    select.add_argument(
        "--protected-ids",
        type=Path,
        help=(
            "Deprecated add-only protected source; authoritative defaults are always "
            "included"
        ),
    )
    select.add_argument(
        "--protected-source",
        type=Path,
        action="append",
        default=[],
        help="Additional protected file or directory; may be repeated",
    )
    select.add_argument("--output", type=Path, required=True)
    evaluate = subcommands.add_parser("evaluate")
    evaluate.add_argument("--inventory", type=Path, required=True)
    evaluate.add_argument("--selection", type=Path, required=True)
    evaluate.add_argument("--labels", type=Path, required=True)
    evaluate.add_argument("--repo-root", type=Path, default=Path.cwd())
    evaluate.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "select":
        if args.output.exists() or args.output.is_symlink():
            raise RecallAuditError(
                f"selection output must not already exist: {args.output}"
            )
        repo_root = args.repo_root.resolve()
        inventory = _read_json(args.inventory)
        alias_map = inventory_alias_map(inventory)
        sample_sizes = _read_json(args.sample_sizes)
        extra_sources = list(args.protected_source)
        if args.protected_ids is not None:
            extra_sources.append(args.protected_ids)
        try:
            protected = heldout.build_authoritative_protected_inventory(
                repo_root,
                extra_sources=extra_sources,
                alias_map=alias_map,
            )
        except heldout.HeldoutQualityError as exc:
            raise RecallAuditError(str(exc)) from exc
        output = build_selection_manifest(
            inventory,
            sample_sizes=sample_sizes,
            protected=protected,
        )
    else:
        selection = _read_json(args.selection)
        inventory = _read_json(args.inventory)
        alias_map = inventory_alias_map(inventory)
        protected = _rebuild_authoritative_protected_inventory(
            selection,
            repo_root=args.repo_root.resolve(),
            selection_path=args.selection,
            labels_path=args.labels,
            alias_map=alias_map,
        )
        labels = _read_json(args.labels)
        output = evaluate_labels(
            selection,
            labels,
            inventory=inventory,
            protected=protected,
            selection_path=args.selection,
            labels_path=args.labels,
            repo_root=args.repo_root,
        )
    _write_json(args.output, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
