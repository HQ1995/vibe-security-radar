"""Repository-wide commit universes for recall-first advisory screening.

Every locally reachable commit is materialized once per repository.  Advisory
fallbacks point to that immutable universe instead of expanding a Cartesian
repository x advisory x commit table.  AI-attribution signals are overlays;
they never control membership in the universe.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence


class AllCommitUniverseContractError(ValueError):
    """A repository graph or overlay violates the universe contract."""


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _full_sha(value: object, field: str) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 40 or any(
        character not in "0123456789abcdef" for character in sha
    ):
        raise AllCommitUniverseContractError(f"{field} must be a full commit SHA")
    return sha


def _normalize_records(
    repository_identity: str,
    records: Iterable[Mapping[str, object]],
) -> tuple[list[dict[str, object]], list[str]]:
    normalized: dict[str, dict[str, object]] = {}
    for index, raw in enumerate(records, start=1):
        if not isinstance(raw, Mapping):
            raise AllCommitUniverseContractError(
                f"commit record {index} is not an object"
            )
        sha = _full_sha(raw.get("sha"), "commit sha")
        raw_parents = raw.get("parents", [])
        if not isinstance(raw_parents, list):
            raise AllCommitUniverseContractError("commit parents must be a list")
        parents = sorted({_full_sha(parent, "parent sha") for parent in raw_parents})
        timestamp = raw.get("committer_timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
            raise AllCommitUniverseContractError(
                "committer_timestamp must be a non-negative integer"
            )
        record = {
            "repository_identity": repository_identity,
            "sha": sha,
            "parents": parents,
            "committer_timestamp": timestamp,
        }
        prior = normalized.get(sha)
        if prior is not None and prior != record:
            raise AllCommitUniverseContractError(f"conflicting commit record: {sha}")
        normalized[sha] = record
    rows = [normalized[sha] for sha in sorted(normalized)]
    known = set(normalized)
    missing_parents = sorted(
        {parent for row in rows for parent in row["parents"] if parent not in known}
    )
    return rows, missing_parents


def _normalize_ai_units(
    repository_identity: str,
    units: Iterable[Mapping[str, object]],
) -> tuple[dict[str, dict[str, object]], int]:
    overlays: dict[str, dict[str, object]] = {}
    input_count = 0
    routes: dict[str, set[str]] = defaultdict(set)
    tools: dict[str, set[str]] = defaultdict(set)
    for index, raw in enumerate(units, start=1):
        input_count += 1
        if not isinstance(raw, Mapping):
            raise AllCommitUniverseContractError(f"AI unit {index} is not an object")
        identity = str(raw.get("repository_identity") or "").strip().lower()
        if identity != repository_identity:
            raise AllCommitUniverseContractError("AI unit repository mismatch")
        sha = _full_sha(raw.get("sha"), "AI unit sha")
        route = str(raw.get("route") or "").strip()
        if route:
            routes[sha].add(route)
        raw_tools = raw.get("tools", [])
        if not isinstance(raw_tools, list) or any(
            not isinstance(tool, str) for tool in raw_tools
        ):
            raise AllCommitUniverseContractError("AI unit tools must be strings")
        tools[sha].update(tool.strip() for tool in raw_tools if tool.strip())
        overlays[sha] = {
            "ai_routes": sorted(routes[sha]),
            "ai_tools": sorted(tools[sha]),
        }
    return overlays, input_count


def build_repository_universe(
    repository_identity: str,
    records: Iterable[Mapping[str, object]],
    ai_units: Iterable[Mapping[str, object]],
    *,
    expected_ai_unit_count: int,
    refs_sha256: str,
    initial_block_reasons: Sequence[str] = (),
) -> dict[str, object]:
    """Attach AI overlays while retaining every visible commit exactly once."""

    identity = str(repository_identity).strip().lower()
    if not identity:
        raise AllCommitUniverseContractError("repository_identity is required")
    if (
        isinstance(expected_ai_unit_count, bool)
        or not isinstance(expected_ai_unit_count, int)
        or expected_ai_unit_count < 1
    ):
        raise AllCommitUniverseContractError(
            "expected_ai_unit_count must be a positive integer"
        )
    if len(refs_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in refs_sha256
    ):
        raise AllCommitUniverseContractError("refs_sha256 must be a SHA-256 digest")

    commit_rows, missing_parents = _normalize_records(identity, records)
    overlays, ai_input_count = _normalize_ai_units(identity, ai_units)
    visible_shas = {str(row["sha"]) for row in commit_rows}
    missing_ai_shas = sorted(set(overlays) - visible_shas)
    reasons = {str(reason).strip() for reason in initial_block_reasons if str(reason).strip()}
    if missing_parents:
        reasons.add("parent_closure_incomplete")
    if ai_input_count != expected_ai_unit_count:
        reasons.add("ai_exposure_count_mismatch")
    if len(overlays) != ai_input_count:
        reasons.add("duplicate_ai_unit_sha")
    if missing_ai_shas:
        reasons.add("ai_units_outside_local_refs")
    if not commit_rows:
        reasons.add("empty_local_commit_universe")

    materialized: list[dict[str, object]] = []
    for row in commit_rows:
        sha = str(row["sha"])
        overlay = overlays.get(sha, {"ai_routes": [], "ai_tools": []})
        materialized.append(
            {
                **row,
                "observed_ai_unit": sha in overlays,
                "ai_routes": list(overlay["ai_routes"]),
                "ai_tools": list(overlay["ai_tools"]),
            }
        )
    graph_projection = [
        {
            "sha": row["sha"],
            "parents": row["parents"],
            "committer_timestamp": row["committer_timestamp"],
        }
        for row in commit_rows
    ]
    graph_sha256 = canonical_sha256(graph_projection)
    universe_id = "commit-universe-" + canonical_sha256(
        {
            "graph_sha256": graph_sha256,
            "refs_sha256": refs_sha256,
            "repository_identity": identity,
        }
    )
    blocked_items = [
        {
            "repository_identity": identity,
            "item_kind": "missing_parent",
            "sha": sha,
            "status": "BLOCKED",
            "reason": "parent_not_enumerated_from_local_refs",
        }
        for sha in missing_parents
    ]
    blocked_items.extend(
        {
            "repository_identity": identity,
            "item_kind": "ai_unit",
            "sha": sha,
            "status": "BLOCKED",
            "reason": "ai_unit_not_enumerated_from_local_refs",
        }
        for sha in missing_ai_shas
    )
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "repository_all_commit_universe",
        "universe_id": universe_id,
        "repository_identity": identity,
        "status": "BLOCKED" if reasons else "RESOLVED",
        "block_reasons": sorted(reasons),
        "refs_sha256": refs_sha256,
        "graph_sha256": graph_sha256,
        "commit_rows_sha256": canonical_sha256(materialized),
        "visible_commit_count": len(materialized),
        "parent_edge_count": sum(len(row["parents"]) for row in commit_rows),
        "missing_parent_count": len(missing_parents),
        "expected_ai_unit_count": expected_ai_unit_count,
        "ai_unit_input_count": ai_input_count,
        "unique_ai_unit_count": len(overlays),
        "observed_ai_unit_count": len(overlays) - len(missing_ai_shas),
        "missing_ai_unit_count": len(missing_ai_shas),
        "all_visible_commits_retained": len(materialized) == len(commit_rows),
    }
    summary["summary_sha256"] = canonical_sha256(summary)
    return {
        "summary": summary,
        "commit_rows": materialized,
        "blocked_items": blocked_items,
    }


def build_repository_fallbacks(
    selected_rows: Sequence[Mapping[str, object]],
    universe_summaries: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    """Point each frozen advisory at its whole repository universe once."""

    fallbacks: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for raw in selected_rows:
        repository = str(raw.get("repository_identity") or "").strip().lower()
        advisory = str(raw.get("advisory") or "").strip()
        source_class = str(raw.get("source_class") or "").strip()
        pair = (repository, advisory.casefold())
        if not repository or not advisory or pair in seen:
            raise AllCommitUniverseContractError(
                "selected fallback rows require unique repository/advisory pairs"
            )
        seen.add(pair)
        universe = universe_summaries.get(repository)
        if universe is None:
            raise AllCommitUniverseContractError(
                f"selected repository has no universe summary: {repository}"
            )
        fallback = {
            "fallback_id": "repository-fallback-"
            + canonical_sha256(
                {"advisory": advisory, "repository_identity": repository}
            ),
            "repository_identity": repository,
            "advisory": advisory,
            "source_class": source_class,
            "candidate_scope": "all_locally_reachable_commits",
            "materialization": "compressed_repository_universe_reference",
            "universe_id": universe["universe_id"],
            "universe_graph_sha256": universe["graph_sha256"],
            "candidate_commit_count": universe["visible_commit_count"],
            "status": universe["status"],
            "block_reasons": list(universe["block_reasons"]),
        }
        fallbacks.append(fallback)
    fallbacks.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["advisory"]).casefold(),
        )
    )
    return fallbacks
