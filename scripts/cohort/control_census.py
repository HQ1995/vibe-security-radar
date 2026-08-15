"""Build a fail-closed census of independently audited positive controls."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence

from cohort.relations import canonical_repository_identity
from cve_analyzer.git_url import parse_repo_url


class ControlCensusContractError(ValueError):
    """The audit/control inputs cannot support an auditable census."""


_ORIGIN_FIELDS = frozenset(
    {
        "atomic_ai_node_origin",
        "atomic_ai_origin",
        "atomic_ai_origins",
        "atomic_origin_commit",
        "atomic_reimplementation_commit",
        "atomic_upstream_docx_origin",
        "atomic_upstream_media_origin",
        "composite_reimplementation_commit",
        "initial_origin_commit",
        "primary_origin_commit",
        "trigger_origin_commit",
        "unsafe_optimizer_commit",
        "upstream_atomic_ai_origin",
        "vulnerable_reimplementation_commit",
    }
)
_CROSS_REPOSITORY_ORIGIN_FIELDS = frozenset(
    {
        "atomic_upstream_docx_origin",
        "atomic_upstream_media_origin",
        "upstream_atomic_ai_origin",
    }
)
_FIX_FIELDS = frozenset(
    {
        "fix_commit",
        "fix_commits",
        "hardening_commits",
        "partition_mitigation_commit",
        "primary_fix_commit",
        "referenced_fix_merge",
        "release_hardening_commit",
    }
)
_LANDED_FIELDS = frozenset(
    {
        "carrying_squash",
        "carrying_squashes",
        "landed_ai_import",
        "landed_composite_squash",
        "landed_squash_commit",
        "mainline_squash",
        "squash_merge",
    }
)


def _sha256_json(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _full_sha(value: object) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        return ""
    return sha


def _field_sha_candidates(
    evidence: Mapping[str, object],
    fields: frozenset[str],
) -> tuple[list[dict[str, str]], list[str]]:
    rows: list[dict[str, str]] = []
    malformed: list[str] = []
    for field in sorted(fields & evidence.keys()):
        raw = evidence[field]
        values = raw if isinstance(raw, list) else [raw]
        if not values:
            malformed.append(field)
            continue
        for value in values:
            sha = _full_sha(value)
            if not sha:
                malformed.append(field)
                continue
            rows.append({"field": field, "sha": sha})
    rows.sort(key=lambda row: (row["sha"], row["field"]))
    return rows, sorted(set(malformed))


def _repository_identity(value: object, aliases: Mapping[str, str]) -> str:
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


def _repository_candidates(
    audit: Mapping[str, object],
    cached: Mapping[str, object],
    aliases: Mapping[str, str],
) -> list[str]:
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
    return sorted(
        {
            identity
            for raw in raw_values
            if (identity := _repository_identity(raw, aliases))
        }
    )


def _confidence(
    adjudication: Mapping[str, object],
    audit: Mapping[str, object],
) -> float:
    raw = adjudication.get("confidence", audit.get("confidence", 0))
    try:
        return float(raw or 0)
    except (TypeError, ValueError):
        return 0.0


def _has_atomic_ai_signal(evidence: Mapping[str, object]) -> bool:
    signal_markers = {"author", "authorship", "binding", "identity", "signal"}
    for field, value in evidence.items():
        field_parts = set(str(field).lower().split("_"))
        if value and "ai" in field_parts and field_parts & signal_markers:
            return True
    return False


def _edge_shape(
    adjudication: Mapping[str, object],
    audit: Mapping[str, object],
    repository_candidates: Sequence[str],
    *,
    minimum_confidence: float,
) -> tuple[str, dict[str, object]]:
    details: dict[str, object] = {}
    if (
        audit.get("cve_id") != adjudication.get("cve_id")
        or audit.get("audit_verdict") != "TRUE_POSITIVE"
        or audit.get("ai_authored_vulnerability") is not True
    ):
        return "AUDIT_CONTRACT_MISSING", details
    confidence = _confidence(adjudication, audit)
    details["confidence"] = confidence
    if confidence < minimum_confidence:
        return "LOW_CONFIDENCE", details
    if len(repository_candidates) != 1:
        details["repository_candidates"] = list(repository_candidates)
        return "REPOSITORY_AMBIGUOUS", details
    evidence = audit.get("evidence")
    if not isinstance(evidence, Mapping):
        return "STRUCTURED_EVIDENCE_MISSING", details

    origins, malformed_origins = _field_sha_candidates(evidence, _ORIGIN_FIELDS)
    fixes, malformed_fixes = _field_sha_candidates(evidence, _FIX_FIELDS)
    landed, malformed_landed = _field_sha_candidates(evidence, _LANDED_FIELDS)
    details.update(
        {
            "origin_candidates": origins,
            "fix_candidates": fixes,
            "landed_candidates": landed,
        }
    )
    malformed = sorted({*malformed_origins, *malformed_fixes, *malformed_landed})
    if malformed:
        details["malformed_fields"] = malformed
        return "MALFORMED_EDGE_EVIDENCE", details
    if any(row["field"] in _CROSS_REPOSITORY_ORIGIN_FIELDS for row in origins):
        return "CROSS_REPOSITORY_ORIGIN", details
    unique_origins = sorted({row["sha"] for row in origins})
    unique_fixes = sorted({row["sha"] for row in fixes})
    unique_landed = sorted({row["sha"] for row in landed})
    if not unique_origins:
        return "STRUCTURED_ORIGIN_MISSING", details
    if len(unique_origins) != 1:
        return "MULTI_ORIGIN", details
    if not unique_fixes:
        return "STRUCTURED_FIX_MISSING", details
    if len(unique_fixes) != 1:
        return "MULTI_FIX", details
    if len(unique_landed) > 1:
        return "MULTI_LANDED", details
    if not _has_atomic_ai_signal(evidence):
        return "ATOMIC_AI_SIGNAL_MISSING", details
    if unique_origins[0] == unique_fixes[0]:
        return "SELF_EDGE", details
    details.update(
        {
            "origin_sha": unique_origins[0],
            "fix_sha": unique_fixes[0],
            "landed_sha": unique_landed[0] if unique_landed else "",
        }
    )
    return "ATOMIC", details


def build_control_candidate_census(
    adjudications: Sequence[Mapping[str, object]],
    audits_by_source: Mapping[str, object],
    cached_results_by_advisory: Mapping[str, Mapping[str, object]],
    *,
    existing_controls: Sequence[Mapping[str, object]],
    aliases: Mapping[str, str],
    minimum_confidence: float = 0.98,
) -> dict[str, object]:
    """Account for every AI_CAUSAL row and select only simple unseen atomic edges."""

    if not 0 <= minimum_confidence <= 1:
        raise ControlCensusContractError("minimum confidence must be between zero and one")
    existing_advisories = {
        str(row.get("advisory") or "").strip() for row in existing_controls
    }
    existing_repositories = {
        identity
        for row in existing_controls
        if (
            identity := _repository_identity(
                row.get("repository_identity"), aliases
            )
        )
    }
    positives = sorted(
        (row for row in adjudications if row.get("label") == "AI_CAUSAL"),
        key=lambda row: str(row.get("cve_id") or ""),
    )
    seen_advisories: set[str] = set()
    census: list[dict[str, object]] = []
    atomic_by_repository: dict[str, list[dict[str, object]]] = defaultdict(list)
    for adjudication in positives:
        advisory = str(adjudication.get("cve_id") or "").strip()
        source = str(adjudication.get("source") or "").strip()
        if not advisory or not source or advisory in seen_advisories:
            raise ControlCensusContractError("AI_CAUSAL adjudications require unique IDs and sources")
        seen_advisories.add(advisory)
        audit_raw = audits_by_source.get(source)
        audit = audit_raw if isinstance(audit_raw, Mapping) else {}
        cached = cached_results_by_advisory.get(advisory, {})
        repositories = _repository_candidates(audit, cached, aliases)
        edge_status, details = _edge_shape(
            adjudication,
            audit,
            repositories,
            minimum_confidence=minimum_confidence,
        )
        repository = repositories[0] if len(repositories) == 1 else ""
        row: dict[str, object] = {
            "advisory": advisory,
            "audit_source": source,
            "edge_status": edge_status,
            "repository_identity": repository,
            **details,
        }
        if advisory in existing_advisories:
            row["selection_status"] = "ALREADY_USED_ADVISORY"
        elif repository and repository in existing_repositories:
            row["selection_status"] = "ALREADY_USED_REPOSITORY"
        elif edge_status != "ATOMIC":
            row["selection_status"] = f"BLOCKED_{edge_status}"
        else:
            row["selection_status"] = "ELIGIBLE_ATOMIC"
            atomic_by_repository[repository].append(row)
        census.append(row)

    selected_controls: list[dict[str, object]] = []
    for repository, rows in sorted(atomic_by_repository.items()):
        rows.sort(key=lambda row: str(row["advisory"]))
        selected = rows[0]
        selected["selection_status"] = "SELECTED"
        for deferred in rows[1:]:
            deferred["selection_status"] = "DEFER_REPOSITORY_DEDUP"
            deferred["selected_advisory_for_repository"] = selected["advisory"]
        control: dict[str, object] = {
            "advisory": selected["advisory"],
            "atomic_origin_sha": selected["origin_sha"],
            "expected_relation": "reachable_ancestor",
            "fix_sha": selected["fix_sha"],
            "repository_identity": repository,
            "source": selected["audit_source"],
        }
        landed_sha = str(selected.get("landed_sha") or "")
        if landed_sha:
            control["expected_landed_sha"] = landed_sha
            control["expected_relation"] = (
                "pull_request_member_landed_as_squash_then_reachable_ancestor"
            )
        selected_controls.append(control)

    census.sort(key=lambda row: str(row["advisory"]))
    selected_controls.sort(
        key=lambda row: (str(row["repository_identity"]), str(row["advisory"]))
    )
    edge_counts = Counter(str(row["edge_status"]) for row in census)
    selection_counts = Counter(str(row["selection_status"]) for row in census)
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "ai_causal_control_candidate_census",
        "minimum_confidence": minimum_confidence,
        "ai_causal_count": len(positives),
        "accounted_count": len(census),
        "selected_count": len(selected_controls),
        "edge_status_counts": dict(sorted(edge_counts.items())),
        "selection_status_counts": dict(sorted(selection_counts.items())),
        "census": census,
        "selected_controls": selected_controls,
        "claim_boundary": (
            "every independent AI_CAUSAL adjudication receives a disposition; only"
            " repository-disjoint, high-confidence, single-origin, single-fix audit"
            " edges enter the atomic routing control split; multi-origin and"
            " cross-repository cases remain explicit BLOCKED research obligations"
        ),
    }
    result["result_sha256"] = _sha256_json(result)
    return result
