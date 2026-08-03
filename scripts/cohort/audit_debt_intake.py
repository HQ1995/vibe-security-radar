"""Freeze repository-disjoint audit debt before doing more case work.

This module deliberately operates on the complete ``AUDIT_CONTRACT_MISSING``
stratum from a previously sealed control census.  It is a structural control
recovery split, not a blinded estimate of detector or model quality: every row
already carries an ``AI_CAUSAL`` adjudication in the upstream census.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence

from cohort.relations import canonical_repository_identity


class AuditDebtIntakeContractError(ValueError):
    """The census or prior-control inventory cannot support a frozen split."""


_CONTROL_REPOSITORY_FIELDS = (
    "repository_identity",
    "target_repository_identity",
)
_IMPORT_REPOSITORY_FIELDS = (
    "origin_repository_identity",
    "source_repository_identity",
    "target_repository_identity",
)


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _identity(value: object, aliases: Mapping[str, str]) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    try:
        return canonical_repository_identity(raw, aliases)
    except ValueError as exc:
        raise AuditDebtIntakeContractError(
            f"invalid repository identity: {raw}"
        ) from exc


def prior_control_inventory(
    control_payloads: Sequence[Mapping[str, object]],
    aliases: Mapping[str, str],
) -> dict[str, list[str]]:
    """Return every advisory/repository touched by any earlier control split."""

    advisories: set[str] = set()
    repositories: set[str] = set()
    for payload in control_payloads:
        controls = payload.get("controls")
        if not isinstance(controls, list) or any(
            not isinstance(control, Mapping) for control in controls
        ):
            raise AuditDebtIntakeContractError("control payload is malformed")
        for control in controls:
            advisory = str(control.get("advisory") or "").strip()
            if not advisory:
                raise AuditDebtIntakeContractError(
                    "prior control is missing its advisory"
                )
            advisories.add(advisory.casefold())
            for field in _CONTROL_REPOSITORY_FIELDS:
                if identity := _identity(control.get(field), aliases):
                    repositories.add(identity)
            imports = control.get("upstream_imports", [])
            if not isinstance(imports, list) or any(
                not isinstance(row, Mapping) for row in imports
            ):
                raise AuditDebtIntakeContractError(
                    f"{advisory} has malformed upstream imports"
                )
            for row in imports:
                for field in _IMPORT_REPOSITORY_FIELDS:
                    if identity := _identity(row.get(field), aliases):
                        repositories.add(identity)
    return {
        "advisories": sorted(advisories),
        "repositories": sorted(repositories),
    }


def build_audit_debt_intake(
    census_rows: Sequence[Mapping[str, object]],
    *,
    control_payloads: Sequence[Mapping[str, object]],
    aliases: Mapping[str, str],
    minimum_new_repositories: int = 5,
) -> dict[str, object]:
    """Select the complete repository-disjoint audit-contract recovery queue."""

    if minimum_new_repositories < 1:
        raise AuditDebtIntakeContractError(
            "minimum_new_repositories must be positive"
        )
    inventory = prior_control_inventory(control_payloads, aliases)
    prior_advisories = set(inventory["advisories"])
    prior_repositories = set(inventory["repositories"])

    debt_rows: list[dict[str, object]] = []
    seen_advisories: set[str] = set()
    for raw in census_rows:
        if not isinstance(raw, Mapping):
            raise AuditDebtIntakeContractError("census rows must be objects")
        if raw.get("edge_status") != "AUDIT_CONTRACT_MISSING":
            continue
        advisory = str(raw.get("advisory") or "").strip()
        source = str(raw.get("audit_source") or "").strip()
        if not advisory or not source:
            raise AuditDebtIntakeContractError(
                "audit-debt rows require advisory and audit_source"
            )
        advisory_key = advisory.casefold()
        if advisory_key in seen_advisories:
            raise AuditDebtIntakeContractError(
                f"duplicate audit-debt advisory: {advisory}"
            )
        seen_advisories.add(advisory_key)
        repository = _identity(raw.get("repository_identity"), aliases)
        debt_rows.append(
            {
                "advisory": advisory,
                "audit_source": source,
                "repository_identity": repository,
                "frozen_edge_status": "AUDIT_CONTRACT_MISSING",
            }
        )

    debt_rows.sort(key=lambda row: str(row["advisory"]).casefold())
    eligible_by_repository: dict[str, list[dict[str, object]]] = defaultdict(list)
    census: list[dict[str, object]] = []
    for row in debt_rows:
        advisory_key = str(row["advisory"]).casefold()
        repository = str(row["repository_identity"])
        if not repository:
            row["intake_status"] = "BLOCKED_REPOSITORY_UNRESOLVED"
        elif advisory_key in prior_advisories:
            row["intake_status"] = "EXCLUDED_PRIOR_CONTROL_ADVISORY"
        elif repository in prior_repositories:
            row["intake_status"] = "EXCLUDED_PRIOR_CONTROL_REPOSITORY"
        else:
            row["intake_status"] = "ELIGIBLE_CONTRACT_RECOVERY"
            eligible_by_repository[repository].append(row)
        census.append(row)

    selected: list[dict[str, object]] = []
    for repository, rows in sorted(eligible_by_repository.items()):
        rows.sort(key=lambda row: str(row["advisory"]).casefold())
        winner = rows[0]
        winner["intake_status"] = "SELECTED_FOR_HISTORY_AUDIT"
        selected.append(
            {
                "advisory": winner["advisory"],
                "audit_source": winner["audit_source"],
                "repository_identity": repository,
            }
        )
        for deferred in rows[1:]:
            deferred["intake_status"] = "DEFERRED_REPOSITORY_DEDUP"
            deferred["selected_advisory_for_repository"] = winner["advisory"]

    census.sort(key=lambda row: str(row["advisory"]).casefold())
    selected.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]).casefold(),
        )
    )
    status_counts = Counter(str(row["intake_status"]) for row in census)
    ready = len(selected) >= minimum_new_repositories
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "repository_disjoint_audit_debt_intake",
        "selection_rule": (
            "Enumerate every AUDIT_CONTRACT_MISSING row from the sealed AI-causal "
            "control census; exclude every advisory or repository used by any "
            "prior atomic, expansion, complex-development, or complex-heldout "
            "control; then select the lexicographically first advisory for every "
            "remaining repository without inspecting new history or model output."
        ),
        "claim_boundary": (
            "This known-positive split tests audit-contract recovery and structural "
            "candidate-recall generalization only. It is not a blinded detector, "
            "routing-model, prevalence, or false-positive evaluation."
        ),
        "population": {
            "audit_contract_missing_count": len(debt_rows),
            "prior_control_advisory_count": len(prior_advisories),
            "prior_control_repository_count": len(prior_repositories),
        },
        "minimum_new_repositories": minimum_new_repositories,
        "selected_repository_count": len(selected),
        "gate_status": (
            "READY_FOR_HISTORY_AUDIT"
            if ready
            else "INSUFFICIENT_NEW_REPOSITORIES"
        ),
        "intake_status_counts": dict(sorted(status_counts.items())),
        "prior_control_inventory": inventory,
        "census": census,
        "selected": selected,
    }
    result["result_sha256"] = canonical_sha256(result)
    return result
