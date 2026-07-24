#!/usr/bin/env python3
"""Build and evaluate the deterministic 1,000-subject no-token pilot.

The formal sample contains 100 mapped and 100 unmapped alias classes in each
of five time/source strata.  Selection never reads detector predictions, and
evaluation rejects any result containing Flash/Luna output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Mapping

import data_refresh_paths
from cve_analyzer.models import CveAnalysisResult
from cve_analyzer.quality_ground_truth import evaluate_source_matcher_ground_truth
from cve_analyzer.repository_policy import (
    RepositoryCostClass,
    repository_cost_class,
)
from cve_analyzer.screening_router import (
    SCREENING_ROUTE_POLICY_ID,
    ScreeningRouteStatus,
    evaluate_evidence_availability,
    route_for_screening,
)
from cve_analyzer.source_matcher import (
    MATCHER_CONTRACT,
    candidate_evidence_complete,
    legacy_v2_coauthor_candidate_shas,
    match_result,
)

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_DEFAULT_SOURCE_DELTA = (
    data_refresh_paths.data_refresh_state_root(_REPO_ROOT)
    / "source-delta-current.json"
)
DEFAULT_SOURCE_ORACLE = (
    _REPO_ROOT
    / "cve-analyzer"
    / "tests"
    / "fixtures"
    / "source-matcher-oracle.json"
)
_PILOT_ROOT_NAME = "no-token-pilot-v1"

SELECTION_SCHEMA_VERSION = 2
REPORT_SCHEMA_VERSION = 2
SELECTION_ALGORITHM = "sha256-cell-order-v1"
SELECTION_SEED = "ai-slop-formal-no-token-pilot-v1"
LANES = ("mapped", "unmapped")
STRATA = ("le_2023", "2024", "2025", "2026", "ghsa_only")
FORMAL_PER_CELL = 100
FORMAL_SUBJECT_COUNT = len(LANES) * len(STRATA) * FORMAL_PER_CELL
_CVE_ID = re.compile(r"^CVE-(\d{4})-")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class NoTokenPilotError(ValueError):
    """The pilot input, selection, or result set is not formally usable."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _stable_json_file(path: Path, label: str) -> tuple[dict[str, Any], str]:
    try:
        before = path.lstat()
        if path.is_symlink() or not path.is_file() or before.st_size <= 0:
            raise NoTokenPilotError(f"{label} is not a regular non-empty file: {path}")
        raw = path.read_bytes()
        after = path.lstat()
    except NoTokenPilotError:
        raise
    except OSError as exc:
        raise NoTokenPilotError(f"cannot read {label} {path}: {exc}") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise NoTokenPilotError(f"{label} changed while being read: {path}")
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NoTokenPilotError(f"{label} is invalid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise NoTokenPilotError(f"{label} must contain an object: {path}")
    return payload, hashlib.sha256(raw).hexdigest()


def _class_stratum(member_ids: list[str]) -> str:
    years = [
        int(match.group(1))
        for member_id in member_ids
        if (match := _CVE_ID.match(member_id)) is not None
    ]
    if not years:
        return "ghsa_only"
    year = max(years)
    if year <= 2023:
        return "le_2023"
    if year in {2024, 2025, 2026}:
        return str(year)
    raise NoTokenPilotError(f"unsupported future CVE year in pilot population: {year}")


def _mapped_repositories(analysis_input: Mapping[str, Any]) -> list[str]:
    git_ranges = analysis_input.get("git_ranges")
    if not isinstance(git_ranges, list):
        raise NoTokenPilotError("alias-class git_ranges must be an array")
    repositories: set[str] = set()
    for item in git_ranges:
        if not isinstance(item, dict):
            raise NoTokenPilotError("alias-class git range must be an object")
        repository = item.get("repo")
        if repository is not None and (
            not isinstance(repository, str) or not repository.strip()
        ):
            raise NoTokenPilotError("alias-class repository mapping is malformed")
        if isinstance(repository, str) and repository.strip():
            repositories.add(repository.strip())
    return sorted(repositories)


def _selection_hash(class_id: str, subject_id: str) -> str:
    value = f"{SELECTION_SEED}\0{class_id}\0{subject_id}".encode()
    return hashlib.sha256(value).hexdigest()


def build_selection(
    source_delta_path: Path,
    *,
    per_cell: int = FORMAL_PER_CELL,
    cohort_subject_ids: Sequence[str] | None = None,
    cohort_cells: Mapping[str, tuple[str, str]] | None = None,
    cohort_binding: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build or rebind a prediction-blind sample from a formal source delta."""

    if per_cell <= 0:
        raise NoTokenPilotError("per-cell sample size must be positive")
    source_delta, source_delta_sha256 = _stable_json_file(
        source_delta_path,
        "source delta",
    )
    production = source_delta.get("production_discovery")
    manifest = (
        production.get("alias_class_manifest")
        if isinstance(production, dict)
        else None
    )
    classes = manifest.get("classes") if isinstance(manifest, dict) else None
    if (
        source_delta.get("schema_version") != 3
        or source_delta.get("population_policy") != "formal_full"
        or not isinstance(manifest, dict)
        or not isinstance(classes, list)
        or not classes
        or manifest.get("class_count") != len(classes)
        or manifest.get("classes_sha256") != _sha256_json(classes)
        or _SHA256.fullmatch(str(manifest.get("source_snapshot_sha256", "")))
        is None
    ):
        raise NoTokenPilotError("source delta lacks a valid formal alias-class manifest")

    cells: dict[tuple[str, str], list[dict[str, Any]]] = {
        (lane, stratum): [] for lane in LANES for stratum in STRATA
    }
    seen_classes: set[str] = set()
    seen_subjects: set[str] = set()
    for raw in classes:
        if not isinstance(raw, dict):
            raise NoTokenPilotError("alias-class record must be an object")
        class_id = raw.get("class_id")
        subject_id = raw.get("analysis_subject")
        member_ids = raw.get("all_member_ids")
        analysis_input = raw.get("analysis_input")
        if (
            not isinstance(class_id, str)
            or not class_id
            or class_id in seen_classes
            or not isinstance(subject_id, str)
            or not subject_id
            or subject_id in seen_subjects
            or not isinstance(member_ids, list)
            or not member_ids
            or any(not isinstance(item, str) or not item for item in member_ids)
            or not isinstance(analysis_input, dict)
        ):
            raise NoTokenPilotError("alias-class identity is malformed or duplicated")
        seen_classes.add(class_id)
        seen_subjects.add(subject_id)
        repositories = _mapped_repositories(analysis_input)
        lane = "mapped" if repositories else "unmapped"
        stratum = _class_stratum(member_ids)
        cells[(lane, stratum)].append(
            {
                "class_id": class_id,
                "analysis_subject": subject_id,
                "component_sha256": raw.get("component_sha256", ""),
                "lane": lane,
                "stratum": stratum,
                "repositories": repositories,
                "selection_hash": _selection_hash(class_id, subject_id),
            }
        )

    population_counts = {
        f"{lane}:{stratum}": len(cells[(lane, stratum)])
        for lane in LANES
        for stratum in STRATA
    }
    sparse = {
        cell: count for cell, count in population_counts.items() if count < per_cell
    }
    if sparse:
        raise NoTokenPilotError(
            f"pilot strata cannot satisfy {per_cell} subjects per cell: {sparse}"
        )

    selected: list[dict[str, Any]]
    if cohort_subject_ids is None:
        selected = []
        for lane in LANES:
            for stratum in STRATA:
                ordered = sorted(
                    cells[(lane, stratum)],
                    key=lambda row: (
                        row["selection_hash"],
                        row["class_id"],
                        row["analysis_subject"],
                    ),
                )
                selected.extend(ordered[:per_cell])
    else:
        expected_count = len(LANES) * len(STRATA) * per_cell
        requested = list(cohort_subject_ids)
        if (
            len(requested) != expected_count
            or len(requested) != len(set(requested))
            or any(not isinstance(item, str) or not item for item in requested)
        ):
            raise NoTokenPilotError(
                "frozen pilot cohort has an invalid subject count or duplicate"
            )
        if (
            not isinstance(cohort_cells, Mapping)
            or set(cohort_cells) != set(requested)
            or any(
                not isinstance(cell, tuple)
                or len(cell) != 2
                or cell[0] not in LANES
                or cell[1] not in STRATA
                for cell in cohort_cells.values()
            )
        ):
            raise NoTokenPilotError("frozen pilot cohort cell binding is invalid")
        by_subject = {
            row["analysis_subject"]: row
            for rows in cells.values()
            for row in rows
        }
        missing = sorted(set(requested) - set(by_subject))
        if missing:
            raise NoTokenPilotError(
                f"frozen pilot cohort is absent from the current population: {missing[:10]}"
            )
        selected = []
        for subject_id in requested:
            current = dict(by_subject[subject_id])
            current_lane = current["lane"]
            current_stratum = current["stratum"]
            frozen_lane, frozen_stratum = cohort_cells[subject_id]
            current["lane"] = frozen_lane
            current["stratum"] = frozen_stratum
            current["current_lane"] = current_lane
            current["current_stratum"] = current_stratum
            selected.append(current)
        rebound_counts = Counter(
            f"{row['lane']}:{row['stratum']}" for row in selected
        )
        expected_cells = {
            f"{lane}:{stratum}": per_cell
            for lane in LANES
            for stratum in STRATA
        }
        if dict(sorted(rebound_counts.items())) != dict(sorted(expected_cells.items())):
            raise NoTokenPilotError(
                "frozen pilot cohort no longer satisfies the formal strata"
            )
        if (
            not isinstance(cohort_binding, Mapping)
            or set(cohort_binding)
            != {"selection_sha256", "selection_file_sha256"}
            or any(_SHA256.fullmatch(value) is None for value in cohort_binding.values())
        ):
            raise NoTokenPilotError("frozen pilot cohort binding is invalid")
    selected_subjects = [row["analysis_subject"] for row in selected]
    if len(selected_subjects) != len(set(selected_subjects)):
        raise NoTokenPilotError("pilot selected a subject more than once")

    selection: dict[str, Any] = {
        "schema_version": SELECTION_SCHEMA_VERSION,
        "artifact_kind": "formal_no_token_pilot_selection",
        "selection_algorithm": SELECTION_ALGORITHM,
        "selection_seed": SELECTION_SEED,
        "source_delta_path": str(source_delta_path.resolve()),
        "source_delta_sha256": source_delta_sha256,
        "source_snapshot_sha256": manifest["source_snapshot_sha256"],
        "alias_class_manifest_sha256": manifest["classes_sha256"],
        "matcher_contract": MATCHER_CONTRACT,
        "screening_route_policy_id": SCREENING_ROUTE_POLICY_ID,
        "lanes": list(LANES),
        "strata": list(STRATA),
        "per_cell": per_cell,
        "expected_subject_count": len(LANES) * len(STRATA) * per_cell,
        "population_counts": population_counts,
        "selected_counts": {
            f"{lane}:{stratum}": per_cell
            for lane in LANES
            for stratum in STRATA
        },
        "selected_subjects_sha256": hashlib.sha256(
            ("\n".join(selected_subjects) + "\n").encode()
        ).hexdigest(),
        "execution_contract": {
            "phase": "no_token",
            "llm_allowed": False,
            "network_model_requests_allowed": False,
            "candidate_edge_cap": None,
            "required_candidate_contract": "repo-ai-index-to-causal-edge-v1",
            "required_screening_route_policy": SCREENING_ROUTE_POLICY_ID,
            "legacy_candidates_are_shadow_comparator": True,
        },
        "subjects": selected,
    }
    if cohort_subject_ids is not None:
        cell_drift = [
            {
                "analysis_subject": row["analysis_subject"],
                "selection_lane": row["lane"],
                "selection_stratum": row["stratum"],
                "current_lane": row["current_lane"],
                "current_stratum": row["current_stratum"],
            }
            for row in selected
            if (row["lane"], row["stratum"])
            != (row["current_lane"], row["current_stratum"])
        ]
        selection["cohort_rebind"] = {
            "contract": "frozen-subject-cohort-rebind-v1",
            **dict(cohort_binding),
            "current_cell_drift_count": len(cell_drift),
            "current_cell_drift_sha256": _sha256_json(cell_drift),
        }
        selection["cohort_cell_drift"] = cell_drift
    selection_sha256 = _sha256_json(selection)
    selection["selection_sha256"] = selection_sha256
    selection["pilot_id"] = selection_sha256
    return selection


def _load_frozen_cohort(
    path: Path,
) -> tuple[list[str], dict[str, tuple[str, str]], dict[str, str]]:
    """Load only the sealed subject identities from an earlier pilot."""

    selection, file_sha256 = _stable_json_file(path, "frozen pilot selection")
    supplied_digest = selection.get("selection_sha256")
    pilot_id = selection.get("pilot_id")
    digest_payload = dict(selection)
    digest_payload.pop("selection_sha256", None)
    digest_payload.pop("pilot_id", None)
    if (
        selection.get("schema_version") not in {1, SELECTION_SCHEMA_VERSION}
        or selection.get("artifact_kind") != "formal_no_token_pilot_selection"
        or not isinstance(supplied_digest, str)
        or _SHA256.fullmatch(supplied_digest) is None
        or pilot_id != supplied_digest
        or _sha256_json(digest_payload) != supplied_digest
        or not isinstance(selection.get("subjects"), list)
    ):
        raise NoTokenPilotError("frozen pilot selection identity is invalid")
    subjects: list[str] = []
    cells: dict[str, tuple[str, str]] = {}
    for row in selection["subjects"]:
        subject = row.get("analysis_subject") if isinstance(row, dict) else None
        lane = row.get("lane") if isinstance(row, dict) else None
        stratum = row.get("stratum") if isinstance(row, dict) else None
        if (
            not isinstance(subject, str)
            or not subject
            or subject in cells
            or lane not in LANES
            or stratum not in STRATA
        ):
            raise NoTokenPilotError(
                "frozen pilot selection contains malformed subjects"
            )
        subjects.append(subject)
        cells[subject] = (lane, stratum)
    expected_subject_count = selection.get("expected_subject_count")
    if (
        not isinstance(expected_subject_count, int)
        or isinstance(expected_subject_count, bool)
        or expected_subject_count <= 0
        or len(subjects) != expected_subject_count
    ):
        raise NoTokenPilotError("frozen pilot selection contains malformed subjects")
    return subjects, cells, {
        "selection_sha256": supplied_digest,
        "selection_file_sha256": file_sha256,
    }


def _validate_selection(selection: dict[str, Any]) -> list[dict[str, Any]]:
    supplied_digest = selection.get("selection_sha256")
    pilot_id = selection.get("pilot_id")
    digest_payload = dict(selection)
    digest_payload.pop("selection_sha256", None)
    digest_payload.pop("pilot_id", None)
    subjects = selection.get("subjects")
    if (
        selection.get("schema_version") != SELECTION_SCHEMA_VERSION
        or selection.get("artifact_kind") != "formal_no_token_pilot_selection"
        or selection.get("selection_algorithm") != SELECTION_ALGORITHM
        or selection.get("selection_seed") != SELECTION_SEED
        or selection.get("matcher_contract") != MATCHER_CONTRACT
        or selection.get("screening_route_policy_id")
        != SCREENING_ROUTE_POLICY_ID
        or not isinstance(subjects, list)
        or supplied_digest != _sha256_json(digest_payload)
        or pilot_id != supplied_digest
    ):
        raise NoTokenPilotError("pilot selection identity is invalid")
    expected = selection.get("expected_subject_count")
    if (
        isinstance(expected, bool)
        or not isinstance(expected, int)
        or expected <= 0
        or len(subjects) != expected
    ):
        raise NoTokenPilotError("pilot selection subject count is invalid")
    return subjects


def _result_has_llm_output(result: CveAnalysisResult) -> bool:
    return bool(
        result.screening is not None
        or result.ai_involved is not None
        or any(
            bic.screening_verification is not None
            or bic.tribunal_verdict is not None
            or bic.deep_verification is not None
            for bic in result.bug_introducing_commits
        )
    )


def evaluate_results(
    selection_path: Path,
    result_dir: Path,
) -> dict[str, Any]:
    """Evaluate exact no-token outputs and estimate full-population candidates."""

    selection, selection_file_sha256 = _stable_json_file(
        selection_path,
        "pilot selection",
    )
    subjects = _validate_selection(selection)
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    invalid: dict[str, str] = {}
    for selected in subjects:
        if not isinstance(selected, dict):
            raise NoTokenPilotError("pilot selection contains a malformed subject")
        subject_id = selected.get("analysis_subject")
        if not isinstance(subject_id, str) or not subject_id:
            raise NoTokenPilotError("pilot selection subject identity is malformed")
        path = result_dir / f"{subject_id}.json"
        if not path.is_file() or path.is_symlink():
            missing.append(subject_id)
            continue
        try:
            payload = json.loads(path.read_bytes())
            result = CveAnalysisResult.from_dict(payload)
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, ValueError) as exc:
            invalid[subject_id] = f"unreadable result: {type(exc).__name__}"
            continue
        if result.cve_id != subject_id:
            invalid[subject_id] = "result subject identity mismatch"
            continue
        if _result_has_llm_output(result):
            invalid[subject_id] = "no-token result contains LLM output"
            continue
        candidate_complete = candidate_evidence_complete(result)
        current = match_result(result, complete=candidate_complete)
        evidence = evaluate_evidence_availability(result)
        route = route_for_screening(result, current, evidence=evidence)
        if result.candidate_match != current.to_dict():
            invalid[subject_id] = "candidate matcher output is stale"
            continue
        if (
            result.evidence_availability != evidence.to_dict()
            or result.screening_route != route.to_dict()
        ):
            invalid[subject_id] = "screening route output is stale"
            continue
        legacy_positive = bool(legacy_v2_coauthor_candidate_shas(result))
        edge_count = 0
        module_edge_counts: dict[str, int] = {}
        malformed_ref = False
        for ref in result.candidate_set_refs:
            edge_ids = ref.get("edge_ids") if isinstance(ref, dict) else None
            declared = ref.get("edge_count") if isinstance(ref, dict) else None
            if (
                not isinstance(edge_ids, list)
                or any(not isinstance(edge_id, str) for edge_id in edge_ids)
                or isinstance(declared, bool)
                or not isinstance(declared, int)
                or declared != len(edge_ids)
                or len(edge_ids) != len(set(edge_ids))
            ):
                malformed_ref = True
                break
            edge_count += declared
            raw_module_counts = ref.get("source_module_edge_counts", {})
            if not isinstance(raw_module_counts, dict) or any(
                not isinstance(module, str)
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
                for module, count in raw_module_counts.items()
            ):
                malformed_ref = True
                break
            for module, count in raw_module_counts.items():
                module_edge_counts[module] = (
                    module_edge_counts.get(module, 0) + count
                )
        if malformed_ref:
            invalid[subject_id] = "candidate artifact reference is malformed"
            continue
        rows.append(
            {
                "analysis_subject": subject_id,
                "lane": selected.get("lane"),
                "stratum": selected.get("stratum"),
                "ai_first_candidate": route.eligible,
                "candidate_match_eligible": current.eligible,
                "route_status": route.status.value,
                "route_reason_code": route.reason_code,
                "route_blocking_stage": route.blocking_stage,
                "route_coverage_complete": route.coverage_complete,
                "evidence_status": evidence.status.value,
                "evidence_reason_code": evidence.reason_code,
                "repository_cost_classes": sorted(
                    {
                        repository_cost_class(fix.repo_url).value
                        for fix in result.fix_commits
                        if fix.repo_url
                    }
                ),
                "legacy_shadow_candidate": legacy_positive,
                "candidate_edge_count": edge_count if route.eligible else 0,
                "source_modules": sorted(
                    {match.source_module for match in current.primary_matches}
                ),
                "source_tools": sorted(
                    {match.tool for match in current.primary_matches}
                ),
                "source_module_edge_counts": dict(
                    sorted(module_edge_counts.items())
                ),
                "recovered_by_ai_first": route.eligible and not legacy_positive,
                "lost_vs_legacy": legacy_positive and not route.eligible,
            }
        )

    cell_reports: dict[str, dict[str, Any]] = {}
    estimate_subjects = 0.0
    estimate_edges = 0.0
    if not missing and not invalid:
        for lane in LANES:
            for stratum in STRATA:
                key = f"{lane}:{stratum}"
                cell_rows = [
                    row
                    for row in rows
                    if row["lane"] == lane and row["stratum"] == stratum
                ]
                population = selection["population_counts"][key]
                sample_count = len(cell_rows)
                positive_count = sum(row["ai_first_candidate"] for row in cell_rows)
                edge_count = sum(row["candidate_edge_count"] for row in cell_rows)
                route_counts = Counter(row["route_status"] for row in cell_rows)
                if sample_count != selection["selected_counts"][key]:
                    raise NoTokenPilotError(f"pilot result cell is incomplete: {key}")
                estimated_positive = population * positive_count / sample_count
                estimated_edge_count = population * edge_count / sample_count
                estimate_subjects += estimated_positive
                estimate_edges += estimated_edge_count
                cell_reports[key] = {
                    "population_count": population,
                    "sample_count": sample_count,
                    "candidate_subject_count": positive_count,
                    "candidate_edge_count": edge_count,
                    "route_status_counts": dict(sorted(route_counts.items())),
                    "estimated_population_candidate_subjects": estimated_positive,
                    "estimated_population_candidate_edges": estimated_edge_count,
                }

    legacy_positive = sum(row["legacy_shadow_candidate"] for row in rows)
    retained_legacy = sum(
        row["legacy_shadow_candidate"] and row["ai_first_candidate"] for row in rows
    )
    lost = [row["analysis_subject"] for row in rows if row["lost_vs_legacy"]]
    recovered = [
        row["analysis_subject"] for row in rows if row["recovered_by_ai_first"]
    ]
    classified = not missing and not invalid and len(rows) == len(subjects)
    route_status_counts = Counter(row["route_status"] for row in rows)
    route_reason_counts = Counter(row["route_reason_code"] for row in rows)
    evidence_status_counts = Counter(row["evidence_status"] for row in rows)
    evidence_reason_counts = Counter(row["evidence_reason_code"] for row in rows)
    code_target_ready_count = sum(
        row["evidence_status"] == "ready" for row in rows
    )
    heavyweight_subject_count = sum(
        RepositoryCostClass.HEAVYWEIGHT.value
        in row["repository_cost_classes"]
        for row in rows
    )
    deferred_ids = sorted(
        row["analysis_subject"]
        for row in rows
        if row["route_status"]
        == ScreeningRouteStatus.DEFERRED_RETRYABLE.value
    )
    incomplete_coverage_ids = sorted(
        row["analysis_subject"]
        for row in rows
        if not row["route_coverage_complete"]
    )
    terminal = classified and not deferred_ids and not incomplete_coverage_ids
    no_value_proven = all(
        row["route_coverage_complete"]
        for row in rows
        if row["route_status"]
        == ScreeningRouteStatus.NO_SCREENING_VALUE.value
    )
    source_module_subject_counts: dict[str, int] = {}
    source_tool_subject_counts: dict[str, int] = {}
    source_module_overlap_subject_counts: dict[str, int] = {}
    source_module_edge_counts: dict[str, int] = {}
    for row in rows:
        modules = row["source_modules"]
        for module in modules:
            source_module_subject_counts[module] = (
                source_module_subject_counts.get(module, 0) + 1
            )
        for tool in row["source_tools"]:
            source_tool_subject_counts[tool] = (
                source_tool_subject_counts.get(tool, 0) + 1
            )
        if modules:
            overlap = "+".join(modules)
            source_module_overlap_subject_counts[overlap] = (
                source_module_overlap_subject_counts.get(overlap, 0) + 1
            )
        for module, count in row["source_module_edge_counts"].items():
            source_module_edge_counts[module] = (
                source_module_edge_counts.get(module, 0) + count
            )
    report_core: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "artifact_kind": "formal_no_token_pilot_report",
        "pilot_id": selection["pilot_id"],
        "selection_sha256": selection["selection_sha256"],
        "selection_file_sha256": selection_file_sha256,
        "screening_route_policy_id": SCREENING_ROUTE_POLICY_ID,
        "result_directory": str(result_dir.resolve()),
        "expected_subject_count": len(subjects),
        "valid_result_count": len(rows),
        "missing_subject_ids": sorted(missing),
        "invalid_subjects": dict(sorted(invalid.items())),
        "llm_output_count": sum(
            reason == "no-token result contains LLM output"
            for reason in invalid.values()
        ),
        "candidate_subject_count": sum(row["ai_first_candidate"] for row in rows),
        "candidate_edge_count": sum(row["candidate_edge_count"] for row in rows),
        "route_status_counts": dict(sorted(route_status_counts.items())),
        "route_reason_counts": dict(sorted(route_reason_counts.items())),
        "evidence_status_counts": dict(sorted(evidence_status_counts.items())),
        "evidence_reason_counts": dict(sorted(evidence_reason_counts.items())),
        "code_target_ready_subject_count": code_target_ready_count,
        "metadata_to_code_target_ready_rate": (
            code_target_ready_count / len(rows) if rows else None
        ),
        "heavyweight_subject_count": heavyweight_subject_count,
        "deferred_subject_ids": deferred_ids,
        "incomplete_coverage_subject_ids": incomplete_coverage_ids,
        "route_audit_rows": [
            {
                "analysis_subject": row["analysis_subject"],
                "lane": row["lane"],
                "stratum": row["stratum"],
                "status": row["route_status"],
                "reason_code": row["route_reason_code"],
                "blocking_stage": row["route_blocking_stage"],
                "coverage_complete": row["route_coverage_complete"],
            }
            for row in sorted(rows, key=lambda item: item["analysis_subject"])
        ],
        "source_module_subject_counts": dict(
            sorted(source_module_subject_counts.items())
        ),
        "source_tool_subject_counts": dict(
            sorted(source_tool_subject_counts.items())
        ),
        "source_module_overlap_subject_counts": dict(
            sorted(source_module_overlap_subject_counts.items())
        ),
        "source_module_edge_counts": dict(
            sorted(source_module_edge_counts.items())
        ),
        "legacy_shadow_candidate_count": legacy_positive,
        "legacy_shadow_retained_count": retained_legacy,
        "lost_vs_legacy_subject_ids": sorted(lost),
        "recovered_by_ai_first_subject_ids": sorted(recovered),
        "exact_trailer_legacy_shadow_recall": (
            retained_legacy / legacy_positive if legacy_positive else None
        ),
        "cell_reports": cell_reports,
        "estimated_population_candidate_subjects": (
            estimate_subjects if terminal else None
        ),
        "estimated_population_candidate_edges": estimate_edges if terminal else None,
        "candidate_estimate_below_200_requires_manual_audit": bool(
            terminal and estimate_subjects < 200
        ),
        "acceptance": {
            "routing_classification_complete": classified,
            "all_subjects_terminal": terminal,
            "no_llm_outputs": classified and not invalid,
            "no_value_proofs_complete": classified and no_value_proven,
            "zero_legacy_candidate_drop": classified and not lost,
            "exact_trailer_causal_recall_100pct": bool(
                classified and (not legacy_positive or retained_legacy == legacy_positive)
            ),
            "resume_no_token_canary": bool(
                classified and no_value_proven and not lost
            ),
            "resume_paid_pipeline": bool(
                terminal and no_value_proven and not lost
            ),
        },
    }
    report_core["report_sha256"] = _sha256_json(report_core)
    return report_core


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json(path: Path, payload: object) -> None:
    _atomic_write(path, json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n")


def _default_pilot_root() -> Path:
    return data_refresh_paths.data_refresh_state_root(_REPO_ROOT) / _PILOT_ROOT_NAME


def _select(args: argparse.Namespace) -> int:
    cohort_subject_ids: list[str] | None = None
    cohort_cells: dict[str, tuple[str, str]] | None = None
    cohort_binding: dict[str, str] | None = None
    if args.reuse_subjects_from:
        cohort_subject_ids, cohort_cells, cohort_binding = (
            _load_frozen_cohort(Path(args.reuse_subjects_from))
        )
    selection = build_selection(
        Path(args.source_delta),
        per_cell=args.per_cell,
        cohort_subject_ids=cohort_subject_ids,
        cohort_cells=cohort_cells,
        cohort_binding=cohort_binding,
    )
    pilot_root = Path(args.output_root) / selection["pilot_id"]
    _write_json(pilot_root / "selection.json", selection)
    subjects = [row["analysis_subject"] for row in selection["subjects"]]
    _atomic_write(pilot_root / "batch.txt", ("\n".join(subjects) + "\n").encode())
    for lane in LANES:
        lane_subjects = [
            row["analysis_subject"]
            for row in selection["subjects"]
            if row["lane"] == lane
        ]
        _atomic_write(
            pilot_root / f"batch-{lane}.txt",
            ("\n".join(lane_subjects) + "\n").encode(),
        )
    ground_truth = evaluate_source_matcher_ground_truth(Path(args.source_oracle))
    _write_json(pilot_root / "source-ground-truth-report.json", ground_truth)
    print(
        json.dumps(
            {
                "pilot_id": selection["pilot_id"],
                "subject_count": len(subjects),
                "selection": str(pilot_root / "selection.json"),
                "batch": str(pilot_root / "batch.txt"),
                "source_ground_truth_gate": ground_truth[
                    "source_candidate_gate_ready"
                ],
            },
            sort_keys=True,
        )
    )
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    report = evaluate_results(Path(args.selection), Path(args.result_dir))
    output = Path(args.output) if args.output else Path(args.selection).with_name("report.json")
    _write_json(output, report)
    print(json.dumps(report["acceptance"], sort_keys=True))
    return 0 if report["acceptance"]["all_subjects_terminal"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    select = subparsers.add_parser("select", help="build the deterministic pilot sample")
    select.add_argument("--source-delta", default=str(_DEFAULT_SOURCE_DELTA))
    select.add_argument("--output-root", default=str(_default_pilot_root()))
    select.add_argument("--source-oracle", default=str(DEFAULT_SOURCE_ORACLE))
    select.add_argument("--per-cell", type=int, default=FORMAL_PER_CELL)
    select.add_argument(
        "--reuse-subjects-from",
        help="rebind an earlier sealed subject cohort to the current source contract",
    )
    select.set_defaults(handler=_select)
    evaluate = subparsers.add_parser("evaluate", help="evaluate completed no-token results")
    evaluate.add_argument("--selection", required=True)
    evaluate.add_argument("--result-dir", required=True)
    evaluate.add_argument("--output")
    evaluate.set_defaults(handler=_evaluate)
    args = parser.parse_args()
    if args.command == "select" and args.per_cell != FORMAL_PER_CELL:
        parser.error(
            f"formal CLI selection requires --per-cell={FORMAL_PER_CELL}; "
            "smaller values are test-only"
        )
    try:
        return args.handler(args)
    except NoTokenPilotError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
