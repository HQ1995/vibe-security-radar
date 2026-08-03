"""Strict pre-history projection and deterministic prospective intake.

The projector may inspect rich local evidence, but its output is deliberately
small: repository/advisory identity, aggregate AI-exposure counts, and whether
an exact public fix reference exists.  The selector accepts only that allowlist
and therefore cannot inspect fix SHAs, commit text, SZZ output, or audit labels.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence

from cohort.audit_debt_intake import prior_control_inventory
from cohort.relations import canonical_repository_identity
from cve_analyzer.git_url import parse_repo_url


ASSOCIATION_ONLY = "association_only"
PUBLIC_EXACT_PRESENT = "public_exact_present"
SOURCE_CLASSES = frozenset({ASSOCIATION_ONLY, PUBLIC_EXACT_PRESENT})
NON_EXACT_PUBLIC_REFERENCE_KINDS = frozenset({"converted_version_boundary"})

POOL_ROW_KEYS = frozenset(
    {
        "candidate_id",
        "repository_identity",
        "advisory",
        "ai_unit_count",
        "ai_routes",
        "ai_tools",
        "source_class",
    }
)
EXCLUSION_KEYS = frozenset(
    {"schema_version", "artifact_kind", "advisories", "repositories"}
)
FORBIDDEN_HISTORY_KEYS = frozenset(
    {
        "fix_sha",
        "fix_shas",
        "origin_sha",
        "commit",
        "commits",
        "message",
        "description",
        "phase1",
        "phase2",
        "search",
        "szz",
        "audit_label",
        "audit_verdict",
    }
)


class ProspectiveIntakeContractError(ValueError):
    """A projection or selection input violates the pre-history contract."""


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
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = parse_repo_url(raw)
    if parsed is not None:
        raw = "/".join(str(part) for part in parsed)
    elif "://" in raw or "@" in raw or raw.startswith("git:"):
        return ""
    try:
        return canonical_repository_identity(raw, aliases)
    except ValueError:
        return ""


def _candidate_id(repository_identity: str, advisory: str) -> str:
    return "prospective-" + canonical_sha256(
        {"advisory": advisory, "repository_identity": repository_identity}
    )


def aggregate_ai_exposure(
    outcomes: Iterable[Mapping[str, object]],
    aliases: Mapping[str, str],
) -> dict[str, dict[str, object]]:
    """Collapse outcome rows without retaining any commit-level field."""

    counts: Counter[str] = Counter()
    routes: dict[str, set[str]] = defaultdict(set)
    tools: dict[str, set[str]] = defaultdict(set)
    for line_number, row in enumerate(outcomes, start=1):
        if not isinstance(row, Mapping):
            raise ProspectiveIntakeContractError(
                f"outcome row {line_number} is not an object"
            )
        identity = _identity(row.get("repository_identity"), aliases)
        if not identity:
            raise ProspectiveIntakeContractError(
                f"outcome row {line_number} has no canonical repository"
            )
        counts[identity] += 1
        route = str(row.get("route") or "").strip()
        if route:
            routes[identity].add(route)
        raw_tools = row.get("tools", [])
        if not isinstance(raw_tools, list) or any(
            not isinstance(tool, str) for tool in raw_tools
        ):
            raise ProspectiveIntakeContractError(
                f"outcome row {line_number} has malformed tools"
            )
        tools[identity].update(tool.strip() for tool in raw_tools if tool.strip())
    return {
        identity: {
            "ai_unit_count": counts[identity],
            "ai_routes": sorted(routes[identity]),
            "ai_tools": sorted(tools[identity]),
        }
        for identity in sorted(counts)
    }


def description_associations(
    payloads: Iterable[Mapping[str, object]],
    aliases: Mapping[str, str],
) -> tuple[set[tuple[str, str]], dict[str, int]]:
    """Read only the input repository and advisory ID from search-cache rows."""

    pairs: set[tuple[str, str]] = set()
    stats: Counter[str] = Counter()
    for payload in payloads:
        stats["records_seen"] += 1
        if not isinstance(payload, Mapping):
            stats["malformed_records"] += 1
            continue
        raw_input = payload.get("input")
        if not isinstance(raw_input, Mapping):
            stats["malformed_records"] += 1
            continue
        identity = _identity(raw_input.get("repo_url"), aliases)
        advisory = str(payload.get("cve_id") or "").strip()
        if not identity or not advisory:
            stats["malformed_records"] += 1
            continue
        pairs.add((identity, advisory))
    stats["association_count"] = len(pairs)
    return pairs, dict(sorted(stats.items()))


def public_exact_pairs(
    references: Iterable[Mapping[str, object]],
    aliases: Mapping[str, str],
) -> set[tuple[str, str]]:
    """Project exact public references to pair-presence without retaining SHAs."""

    pairs: set[tuple[str, str]] = set()
    for line_number, row in enumerate(references, start=1):
        if not isinstance(row, Mapping):
            raise ProspectiveIntakeContractError(
                f"public reference row {line_number} is not an object"
            )
        identity = _identity(row.get("repository_identity"), aliases)
        advisory = str(row.get("advisory") or "").strip()
        fix_sha = str(row.get("fix_sha") or "").strip().lower()
        if (
            not identity
            or not advisory
            or not 7 <= len(fix_sha) <= 40
            or any(character not in "0123456789abcdef" for character in fix_sha)
        ):
            raise ProspectiveIntakeContractError(
                f"public reference row {line_number} is malformed"
            )
        # A shortened Git reference is a useful carrier but not an exact public
        # root.  Do not let it promote a row into the easy stratum.  If another
        # source supplies the full SHA for the same pair, that full row will.
        reference_kind = str(row.get("reference_kind") or "").strip()
        if (
            len(fix_sha) == 40
            and reference_kind not in NON_EXACT_PUBLIC_REFERENCE_KINDS
        ):
            pairs.add((identity, advisory))
    return pairs


def build_pre_history_pool(
    associations: Iterable[tuple[str, str]],
    exposure_by_repository: Mapping[str, Mapping[str, object]],
    exact_public_pairs: set[tuple[str, str]],
) -> tuple[list[dict[str, object]], dict[str, int]]:
    """Build the selector's strict, commit-free candidate rows."""

    association_pairs = set(associations)
    rows: list[dict[str, object]] = []
    outside_ai_population = 0
    for repository, advisory in sorted(association_pairs):
        exposure = exposure_by_repository.get(repository)
        if exposure is None:
            outside_ai_population += 1
            continue
        source_class = (
            PUBLIC_EXACT_PRESENT
            if (repository, advisory) in exact_public_pairs
            else ASSOCIATION_ONLY
        )
        row = {
            "candidate_id": _candidate_id(repository, advisory),
            "repository_identity": repository,
            "advisory": advisory,
            "ai_unit_count": exposure.get("ai_unit_count"),
            "ai_routes": exposure.get("ai_routes"),
            "ai_tools": exposure.get("ai_tools"),
            "source_class": source_class,
        }
        _validate_pool_row(row)
        rows.append(row)
    rows.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]).casefold(),
        )
    )
    return rows, {
        "association_count": len(association_pairs),
        "outside_ai_population_count": outside_ai_population,
        "pool_row_count": len(rows),
    }


def _audit_repository_candidates(
    audit: Mapping[str, object],
    cached: Mapping[str, object],
    aliases: Mapping[str, str],
) -> set[str]:
    raw_values: list[object] = []
    evidence = audit.get("evidence")
    if isinstance(evidence, Mapping):
        for field in ("repo", "repository", "repository_identity"):
            if evidence.get(field):
                raw_values.append(evidence[field])
    for field in ("repo", "repository", "repository_identity"):
        if audit.get(field):
            raw_values.append(audit[field])
    fixes = cached.get("fix_commits")
    if isinstance(fixes, list):
        for fix in fixes:
            if isinstance(fix, Mapping) and fix.get("repo_url"):
                raw_values.append(fix["repo_url"])
    return {
        identity
        for value in raw_values
        if (identity := _identity(value, aliases))
    }


def build_prior_exclusion_projection(
    *,
    control_payloads: Sequence[Mapping[str, object]],
    audit_records_by_advisory: Mapping[str, Mapping[str, object]],
    cached_results_by_advisory: Mapping[str, Mapping[str, object]],
    adjudicated_advisories: Iterable[str],
    aliases: Mapping[str, str],
) -> dict[str, object]:
    """Project all prior case work to IDs only; no judgments or SHAs survive."""

    try:
        controls = prior_control_inventory(control_payloads, aliases)
    except ValueError as exc:
        raise ProspectiveIntakeContractError(str(exc)) from exc
    cached_by_key = {
        str(advisory).casefold(): value
        for advisory, value in cached_results_by_advisory.items()
    }
    advisories = {str(value).strip().casefold() for value in adjudicated_advisories}
    advisories.update(str(value).strip().casefold() for value in audit_records_by_advisory)
    advisories.update(controls["advisories"])
    advisories.discard("")
    repositories = set(controls["repositories"])
    for advisory, audit in audit_records_by_advisory.items():
        cached = cached_by_key.get(str(advisory).casefold(), {})
        repositories.update(_audit_repository_candidates(audit, cached, aliases))
    for advisory in advisories:
        cached = cached_by_key.get(advisory, {})
        repositories.update(_audit_repository_candidates({}, cached, aliases))
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "prospective_prior_exclusion_projection",
        "advisories": sorted(advisories),
        "repositories": sorted(repositories),
    }
    validate_exclusion_projection(result)
    return result


def _validate_string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ProspectiveIntakeContractError(f"{field} must be a string list")
    if value != sorted(set(value)):
        raise ProspectiveIntakeContractError(f"{field} must be sorted and unique")
    return value


def _validate_pool_row(raw: Mapping[str, object]) -> dict[str, object]:
    keys = frozenset(raw)
    if keys != POOL_ROW_KEYS:
        forbidden = sorted(keys & FORBIDDEN_HISTORY_KEYS)
        if forbidden:
            raise ProspectiveIntakeContractError(
                "pool row exposes forbidden history fields: " + ", ".join(forbidden)
            )
        raise ProspectiveIntakeContractError(
            f"pool row keys do not match strict allowlist: {sorted(keys)}"
        )
    repository = str(raw.get("repository_identity") or "").strip().lower()
    advisory = str(raw.get("advisory") or "").strip()
    candidate_id = str(raw.get("candidate_id") or "")
    count = raw.get("ai_unit_count")
    source_class = str(raw.get("source_class") or "")
    if not repository or not advisory:
        raise ProspectiveIntakeContractError("pool row requires repository and advisory")
    if candidate_id != _candidate_id(repository, advisory):
        raise ProspectiveIntakeContractError("pool row candidate_id is not canonical")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ProspectiveIntakeContractError("ai_unit_count must be a positive integer")
    if source_class not in SOURCE_CLASSES:
        raise ProspectiveIntakeContractError("pool row has an unknown source_class")
    routes = _validate_string_list(raw.get("ai_routes"), "ai_routes")
    tools = _validate_string_list(raw.get("ai_tools"), "ai_tools")
    return {
        "candidate_id": candidate_id,
        "repository_identity": repository,
        "advisory": advisory,
        "ai_unit_count": count,
        "ai_routes": list(routes),
        "ai_tools": list(tools),
        "source_class": source_class,
    }


def validate_exclusion_projection(raw: Mapping[str, object]) -> dict[str, object]:
    if frozenset(raw) != EXCLUSION_KEYS:
        raise ProspectiveIntakeContractError(
            "exclusion projection keys do not match strict allowlist"
        )
    if raw.get("schema_version") != 1 or raw.get("artifact_kind") != (
        "prospective_prior_exclusion_projection"
    ):
        raise ProspectiveIntakeContractError("unknown exclusion projection contract")
    advisories = _validate_string_list(raw.get("advisories"), "advisories")
    repositories = _validate_string_list(raw.get("repositories"), "repositories")
    return {
        "schema_version": 1,
        "artifact_kind": "prospective_prior_exclusion_projection",
        "advisories": list(advisories),
        "repositories": list(repositories),
    }


def _selection_hash(split_id: str, row: Mapping[str, object]) -> str:
    return canonical_sha256(
        {
            "split_id": split_id,
            "source_class": row["source_class"],
            "repository_identity": row["repository_identity"],
            "advisory": row["advisory"],
        }
    )


def build_prospective_intake(
    pool_rows: Sequence[Mapping[str, object]],
    exclusion_projection: Mapping[str, object],
    *,
    split_id: str,
    per_stratum: int = 6,
    minimum_ai_units: int = 8,
) -> dict[str, object]:
    """Select a deterministic, repository-disjoint prospective batch."""

    if not split_id.strip():
        raise ProspectiveIntakeContractError("split_id must be non-empty")
    if per_stratum < 1 or minimum_ai_units < 1:
        raise ProspectiveIntakeContractError("selection thresholds must be positive")
    exclusions = validate_exclusion_projection(exclusion_projection)
    prior_advisories = set(exclusions["advisories"])
    prior_repositories = set(exclusions["repositories"])

    normalized: list[dict[str, object]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for raw in pool_rows:
        row = _validate_pool_row(raw)
        pair = (str(row["repository_identity"]), str(row["advisory"]).casefold())
        if pair in seen_pairs:
            raise ProspectiveIntakeContractError("duplicate pool repository/advisory")
        seen_pairs.add(pair)
        row["selection_hash"] = _selection_hash(split_id, row)
        if str(row["advisory"]).casefold() in prior_advisories:
            row["intake_status"] = "EXCLUDED_PRIOR_ADVISORY"
        elif str(row["repository_identity"]) in prior_repositories:
            row["intake_status"] = "EXCLUDED_PRIOR_REPOSITORY"
        elif int(row["ai_unit_count"]) < minimum_ai_units:
            row["intake_status"] = "EXCLUDED_BELOW_MINIMUM_AI_UNITS"
        else:
            row["intake_status"] = "ELIGIBLE_PRE_HISTORY"
        normalized.append(row)

    eligible = sorted(
        (row for row in normalized if row["intake_status"] == "ELIGIBLE_PRE_HISTORY"),
        key=lambda row: (
            str(row["selection_hash"]),
            str(row["repository_identity"]),
            str(row["advisory"]).casefold(),
        ),
    )
    selected_repositories: set[str] = set()
    selected_counts: Counter[str] = Counter()
    selected: list[dict[str, object]] = []
    for row in eligible:
        source_class = str(row["source_class"])
        repository = str(row["repository_identity"])
        if repository in selected_repositories:
            row["intake_status"] = "DEFERRED_REPOSITORY_DEDUP"
            continue
        if selected_counts[source_class] >= per_stratum:
            row["intake_status"] = "DEFERRED_STRATUM_QUOTA"
            continue
        row["intake_status"] = "SELECTED_PROSPECTIVE"
        selected_repositories.add(repository)
        selected_counts[source_class] += 1
        selected.append(dict(row))

    selected.sort(
        key=lambda row: (
            str(row["source_class"]),
            str(row["selection_hash"]),
        )
    )
    normalized.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]).casefold(),
        )
    )
    required = per_stratum * len(SOURCE_CLASSES)
    ready = len(selected) == required and all(
        selected_counts[source_class] == per_stratum
        for source_class in SOURCE_CLASSES
    )
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "prospective_pre_history_intake",
        "split_id": split_id,
        "selection_rule": (
            "Hash split_id, source class, repository, and advisory; scan globally in "
            "ascending SHA-256 order; select at most one advisory per repository and "
            "exactly the fixed quota per source class. Never replace a selected row "
            "after inspecting repository history or downstream results."
        ),
        "claim_boundary": (
            "Selection sees only repository/advisory identity, aggregate legacy AI "
            "exposure, and public-exact-reference presence. It sees no fix SHA, commit "
            "content, SZZ result, origin, or audit judgment. This freezes a structural "
            "recall batch; it is not a prevalence or detector-precision estimate."
        ),
        "minimum_ai_units": minimum_ai_units,
        "per_stratum": per_stratum,
        "pool_row_count": len(normalized),
        "selected_count": len(selected),
        "selected_repository_count": len(selected_repositories),
        "selected_source_class_counts": {
            source_class: selected_counts[source_class]
            for source_class in sorted(SOURCE_CLASSES)
        },
        "intake_status_counts": dict(
            sorted(Counter(str(row["intake_status"]) for row in normalized).items())
        ),
        "gate_status": "READY_FOR_HISTORY_ENUMERATION" if ready else "BLOCKED_QUOTA",
        "exclusion_counts": {
            "advisories": len(prior_advisories),
            "repositories": len(prior_repositories),
        },
        "selected": selected,
        "census": normalized,
    }
    result["result_sha256"] = canonical_sha256(result)
    return result
