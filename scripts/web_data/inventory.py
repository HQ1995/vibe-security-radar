"""Deterministic detector-inventory construction shared by release and replay."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

import run_data_refresh as refresh_runner
from cve_analyzer.models import (
    CveAnalysisResult,
    analysis_stage_receipts_are_valid,
)
from cve_analyzer.source_matcher import bic_is_candidate

from web_data.schema import validate_inventory_payload


class DetectorInventoryError(ValueError):
    """Raised when formal campaign inputs cannot produce an exact inventory."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _alias_classes(
    results: tuple[CveAnalysisResult, ...],
    alias_map: dict[str, set[str]],
) -> dict[str, set[str]]:
    """Return one stable source-backed class for every source or result ID."""

    all_ids = set(alias_map)
    all_ids.update(result.cve_id for result in results)
    classes: dict[str, set[str]] = {}
    for subject_id in sorted(all_ids):
        members = set(alias_map.get(subject_id, {subject_id})) | {subject_id}
        canonical = min(members)
        classes.setdefault(canonical, set()).update(members)
    changed = True
    while changed:
        changed = False
        keys = sorted(classes)
        for offset, left in enumerate(keys):
            if left not in classes:
                continue
            for right in keys[offset + 1 :]:
                if right not in classes or classes[left].isdisjoint(classes[right]):
                    continue
                merged = classes.pop(left) | classes.pop(right)
                classes[min(merged)] = merged
                changed = True
                break
            if changed:
                break
    return dict(sorted(classes.items()))


def _coverage_state(
    results: list[CveAnalysisResult],
    *,
    require_stage_receipts: bool,
) -> tuple[str, list[str]]:
    if not results:
        return "missing", ["no_current_campaign_result"]
    reasons: set[str] = set()
    status = "complete"
    required_stages = (
        "source_discovery",
        "fix_resolution",
        "bic_resolution",
        "signal_classification",
        "causal_verification",
    )
    for result in results:
        terminal_problem = refresh_runner._terminal_result_problem(result.to_dict())
        if terminal_problem is not None:
            status = "error"
            reasons.add(f"terminal:{terminal_problem}")
        receipts = result.analysis_stage_receipts
        if not analysis_stage_receipts_are_valid(receipts) and status != "error":
            status = "incomplete"
            reasons.add("invalid_stage_receipts")
        if require_stage_receipts:
            missing = [stage for stage in required_stages if stage not in receipts]
            if missing and status != "error":
                status = "incomplete"
                reasons.update(f"missing_stage_receipt:{stage}" for stage in missing)
        for stage, receipt in receipts.items():
            outcome = receipt.get("outcome") if isinstance(receipt, dict) else None
            if outcome == "error":
                status = "error"
                reasons.add(f"stage_error:{stage}")
            elif outcome == "incomplete" and status != "error":
                if (
                    stage == "adjudication"
                    and receipt.get("reason")
                    == "incomplete:independent_adjudication_required"
                ):
                    continue
                status = "incomplete"
                reasons.add(f"stage_incomplete:{stage}")
    return status, sorted(reasons)


def _deep_verdict(bic: Any) -> str:
    verdict = bic.deep_verification or {}
    return str(verdict.get("final_verdict") or verdict.get("verdict") or "").upper()


def build_detector_inventory(
    results: tuple[CveAnalysisResult, ...],
    *,
    alias_map: dict[str, set[str]],
    adjudicated_positive_ids: set[str],
    audit_exclusions: set[str],
    published_ids: set[str],
    generated_at: str,
    source_snapshot_sha256: str,
    source_receipt_sha256: str,
    campaign_id: str,
    contract_sha256: str,
    campaign_mode: str,
    coverage_to: str,
    require_stage_receipts: bool = True,
    alias_class_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the exact content-addressed detector inventory."""

    if campaign_mode not in {"formal", "incremental"}:
        raise DetectorInventoryError(
            f"invalid inventory campaign mode: {campaign_mode!r}"
        )
    class_metadata: dict[str, dict[str, Any]] = {}
    if alias_class_manifest is not None:
        raw_classes = alias_class_manifest.get("classes")
        manifest_sha256 = alias_class_manifest.get("classes_sha256")
        if (
            not isinstance(raw_classes, list)
            or not isinstance(manifest_sha256, str)
            or hashlib.sha256(
                refresh_runner._canonical_json_bytes(raw_classes)
            ).hexdigest()
            != manifest_sha256
        ):
            raise DetectorInventoryError(
                "detector inventory alias-class manifest is invalid"
            )
        for item in raw_classes:
            if not isinstance(item, dict) or not item.get("scheduled_seed_ids"):
                raise DetectorInventoryError(
                    "detector inventory alias-class manifest contains an "
                    "unscheduled class"
                )
            class_id = item.get("class_id")
            members = item.get("all_member_ids")
            analysis_subject = item.get("analysis_subject")
            if (
                not isinstance(class_id, str)
                or class_id in class_metadata
                or not isinstance(members, list)
                or not members
                or not isinstance(analysis_subject, str)
                or analysis_subject not in members
            ):
                raise DetectorInventoryError(
                    "detector inventory alias-class record is invalid"
                )
            class_metadata[class_id] = {
                "members": set(members),
                "analysis_subject": analysis_subject,
                "component_sha256": item.get("component_sha256"),
                "source_evidence_sha256": item.get("merged_source_evidence_sha256"),
            }
        source_alias_class_manifest_sha256 = manifest_sha256
    else:
        fallback_classes = _alias_classes(results, alias_map)
        for class_id, members in fallback_classes.items():
            sorted_members = sorted(members)
            component_sha256 = hashlib.sha256(
                ("\n".join(sorted_members) + "\n").encode()
            ).hexdigest()
            class_metadata[class_id] = {
                "members": members,
                "analysis_subject": class_id,
                "component_sha256": component_sha256,
                "source_evidence_sha256": _canonical_sha256(
                    {"legacy_alias_members": sorted_members}
                ),
            }
        source_alias_class_manifest_sha256 = _canonical_sha256(
            [
                {
                    "class_id": class_id,
                    "member_ids": sorted(metadata["members"]),
                }
                for class_id, metadata in sorted(class_metadata.items())
            ]
        )

    by_class: dict[str, list[CveAnalysisResult]] = {key: [] for key in class_metadata}
    owner = {
        metadata["analysis_subject"]: class_id
        for class_id, metadata in class_metadata.items()
    }
    for result in results:
        class_id = owner.get(result.cve_id)
        if class_id is None:
            if alias_class_manifest is not None:
                raise DetectorInventoryError(
                    "campaign result is outside the alias-class manifest: "
                    f"{result.cve_id}"
                )
            class_id = result.cve_id
            members = {result.cve_id}
            component_sha256 = hashlib.sha256(f"{result.cve_id}\n".encode()).hexdigest()
            class_metadata[class_id] = {
                "members": members,
                "analysis_subject": result.cve_id,
                "component_sha256": component_sha256,
                "source_evidence_sha256": _canonical_sha256(
                    {"legacy_alias_members": [result.cve_id]}
                ),
            }
            by_class[class_id] = []
        by_class[class_id].append(result)

    rows: list[dict[str, Any]] = []
    for canonical in sorted(class_metadata):
        metadata = class_metadata[canonical]
        members = metadata["members"]
        class_results = sorted(
            by_class.get(canonical, []), key=lambda item: item.cve_id
        )
        coverage_status, reasons = _coverage_state(
            class_results, require_stage_receipts=require_stage_receipts
        )
        bics = [
            bic for result in class_results for bic in result.bug_introducing_commits
        ]
        fixes = [
            fix for result in class_results for fix in result.fix_commits if fix.sha
        ]
        has_shadow_signal = any(bic.all_ai_signals() for bic in bics) or any(
            result.ai_signals for result in class_results
        )
        has_candidate_signal = any(bic_is_candidate(bic) for bic in bics)
        has_authorship = has_candidate_signal
        has_attested_confirmed = any(
            _deep_verdict(bic) == "CONFIRMED" and bic_is_candidate(bic)
            for bic in bics
        )
        if coverage_status != "complete":
            detector_state = (
                "not_evaluated" if coverage_status == "missing" else "incomplete"
            )
            # Infrastructure, API/PR, cache, and missing-result failures are
            # unknown coverage outcomes. They must never enter a negative
            # rejection stratum merely because downstream evidence is absent.
            recall_stratum = "coverage_failure"
        elif not fixes:
            detector_state = "exhausted"
            recall_stratum = "no_fix_commit"
        elif not bics:
            detector_state = "exhausted"
            recall_stratum = "fix_no_bic"
        elif not has_authorship:
            detector_state = "negative"
            recall_stratum = "bic_no_trusted_authorship"
            if has_shadow_signal:
                reasons.append("shadow_signal_only")
        elif has_attested_confirmed:
            detector_state = "positive"
            recall_stratum = "detected_positive"
        else:
            detector_state = "candidate"
            recall_stratum = "trusted_signal_classifier_negative_or_incomplete"

        if coverage_status != "complete":
            stage_predictions = {
                stage: "incomplete"
                for stage in (
                    "source_matcher",
                    "screening",
                    "verification",
                    "final_publication",
                )
            }
        else:
            screening_positive = any(
                any(bic_is_candidate(bic) for bic in result.bug_introducing_commits)
                and result.screening is not None
                and result.screening.worth_investigating
                for result in class_results
            )
            verification_positive = has_attested_confirmed
            stage_predictions = {
                "source_matcher": "positive" if has_candidate_signal else "negative",
                "screening": "positive" if screening_positive else "negative",
                "verification": "positive" if verification_positive else "negative",
                "final_publication": (
                    "positive" if members & published_ids else "negative"
                ),
            }

        positive = bool(members & adjudicated_positive_ids)
        excluded = bool(members & audit_exclusions)
        if positive and excluded:
            adjudication_state = "unknown"
            reasons.append("conflicting_adjudication")
        elif positive:
            adjudication_state = "ai_causal"
        elif excluded:
            adjudication_state = "not_ai_causal"
        else:
            adjudication_state = "unreviewed"

        if members & published_ids:
            publication_state = "published"
        elif adjudication_state == "ai_causal" and detector_state == "positive":
            publication_state = "eligible"
        elif detector_state in {"positive", "candidate", "incomplete"}:
            publication_state = "withheld"
        else:
            publication_state = "not_applicable"
        rows.append(
            {
                "class_id": canonical,
                "component_sha256": metadata["component_sha256"],
                "source_evidence_sha256": metadata["source_evidence_sha256"],
                "analysis_subject": metadata["analysis_subject"],
                "member_ids": sorted(members),
                "result_subject_ids": [result.cve_id for result in class_results],
                "coverage_status": coverage_status,
                "detector_state": detector_state,
                "adjudication_state": adjudication_state,
                "publication_state": publication_state,
                "recall_stratum": recall_stratum,
                "stage_predictions": stage_predictions,
                "reasons": sorted(set(reasons)),
            }
        )

    dimensions = (
        "coverage_status",
        "detector_state",
        "adjudication_state",
        "publication_state",
        "recall_stratum",
    )
    payload: dict[str, Any] = {
        "schema_version": 2,
        "kind": "ai_vulnerability_detector_inventory",
        "generated_at": generated_at,
        "source_snapshot_sha256": source_snapshot_sha256,
        "source_receipt_sha256": source_receipt_sha256,
        "source_alias_class_manifest_sha256": source_alias_class_manifest_sha256,
        "campaign_id": campaign_id,
        "contract_sha256": contract_sha256,
        "campaign_mode": campaign_mode,
        "complete": all(row["coverage_status"] == "complete" for row in rows),
        "coverage_to": coverage_to,
        "alias_class_count": len(rows),
        "detector_candidate_count": sum(
            row["detector_state"] in {"positive", "candidate"} for row in rows
        ),
        "pending_adjudication_count": sum(
            row["adjudication_state"] in {"unknown", "unreviewed"} for row in rows
        ),
        "coverage_failure_count": sum(
            row["coverage_status"] != "complete" for row in rows
        ),
        "counts": {
            dimension: dict(sorted(Counter(row[dimension] for row in rows).items()))
            for dimension in dimensions
        },
        "rows": rows,
    }
    payload["inventory_id"] = _canonical_sha256(payload)
    validate_inventory_payload(payload)
    return payload
