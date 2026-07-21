"""Contract tests for published per-CVE web data and normalization."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import pytest

from cve_analyzer.models import (
    AiSignal,
    AiTool,
    BugIntroducingCommit,
    CommitInfo,
    CveAnalysisResult,
    FixCommit,
)
from web_data.entry_builder import build_entry
from web_data.loader import load_reviews, normalize_published
from web_data.schema import (
    CVES_SCHEMA,
    CVE_ENTRY_SCHEMA,
    INDEX_SCHEMA,
    INVENTORY_SCHEMA,
    STATS_SCHEMA,
    SchemaValidationError,
    validate,
    validate_cve_entry,
    validate_cves_payload,
    validate_index_payload,
    validate_inventory_payload,
    validate_stats_payload,
)
from web_data.stats import _extract_month, build_stats
from web_data.ts_types import render_ts

_GENERATION_ID = "a" * 64


def _entry(**overrides: object) -> dict:
    entry = {
        "generation_id": _GENERATION_ID,
        "id": "CVE-2025-12345",
        "description": "A test vulnerability",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwes": [],
        "ecosystem": "",
        "published": "2025-06-01",
        "ai_tools": ["cursor"],
        "ai_involved": None,
        "signal_source": "commit",
        "languages": ["Python"],
        "confidence": 0.85,
        "verified_by": "",
        "how_introduced": "",
        "verdict": "CONFIRMED",
        "bug_commits": [],
        "fix_commits": [],
        "references": [],
    }
    entry.update(overrides)
    return entry


def _bug_commit(**overrides: object) -> dict:
    commit = {
        "sha": "abc123",
        "author": "Alice",
        "date": "2025-05-01T00:00:00Z",
        "message": "introduce bug",
        "ai_signals": [],
        "blamed_file": "src/main.py",
        "blame_confidence": 0.9,
        "screening_verification": None,
        "fix_commit_sha": "fix111",
    }
    commit.update(overrides)
    return commit


def _fix_commit() -> dict:
    return {
        "sha": "fix111",
        "repo_url": "https://github.com/org/repo",
        "source": "osv",
    }


def _stats(**overrides: object) -> dict:
    stats = {
        "generation_id": _GENERATION_ID,
        "generated_at": "2026-01-01T00:00:00+00:00",
        "total_cves": 1,
        "total_analyzed": 10,
        "with_fix_commits": 8,
        "coverage_from": "2025-05-01",
        "coverage_to": "2026-01-01",
        "by_tool": {"cursor": 1},
        "by_severity": {"HIGH": 1},
        "by_language": {"Python": 1},
        "by_repo": {"org/repo": 1},
        "by_month": [
            {"month": "2025-06", "count": 1, "by_tool": {"cursor": 1}},
        ],
    }
    stats.update(overrides)
    return stats


def _inventory(**overrides: object) -> dict:
    member_ids = ["CVE-2026-1", "GHSA-aaaa-bbbb-cccc"]
    component_sha256 = hashlib.sha256(
        ("\n".join(member_ids) + "\n").encode("utf-8")
    ).hexdigest()
    source_evidence_sha256 = hashlib.sha256(
        json.dumps(
            {"class_id": "CVE-2026-1", "member_ids": member_ids},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    row = {
        "class_id": "CVE-2026-1",
        "component_sha256": component_sha256,
        "source_evidence_sha256": source_evidence_sha256,
        "analysis_subject": "CVE-2026-1",
        "member_ids": member_ids,
        "result_subject_ids": ["CVE-2026-1"],
        "coverage_status": "complete",
        "detector_state": "candidate",
        "adjudication_state": "unreviewed",
        "publication_state": "withheld",
        "recall_stratum": "bic_no_trusted_authorship",
        "reasons": ["workflow_only_signal"],
    }
    payload = {
        "schema_version": 2,
        "kind": "ai_vulnerability_detector_inventory",
        "generated_at": "2026-07-19T00:00:00+00:00",
        "source_snapshot_sha256": "b" * 64,
        "source_receipt_sha256": "c" * 64,
        "source_alias_class_manifest_sha256": hashlib.sha256(
            json.dumps(
                [
                    {
                        "analysis_subject": row["analysis_subject"],
                        "class_id": row["class_id"],
                        "component_sha256": row["component_sha256"],
                        "member_ids": row["member_ids"],
                        "source_evidence_sha256": row["source_evidence_sha256"],
                    }
                ],
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
        "campaign_id": "d" * 64,
        "contract_sha256": "e" * 64,
        "campaign_mode": "formal",
        "complete": True,
        "coverage_to": "2026-07-19",
        "alias_class_count": 1,
        "detector_candidate_count": 1,
        "pending_adjudication_count": 1,
        "coverage_failure_count": 0,
        "counts": {
            "coverage_status": {"complete": 1},
            "detector_state": {"candidate": 1},
            "adjudication_state": {"unreviewed": 1},
            "publication_state": {"withheld": 1},
            "recall_stratum": {"bic_no_trusted_authorship": 1},
        },
        "rows": [row],
    }
    payload.update(overrides)
    preimage = dict(payload)
    preimage.pop("inventory_id", None)
    payload["inventory_id"] = hashlib.sha256(
        json.dumps(
            preimage,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return payload


class TestSchemaValidator:
    def test_valid_artifacts_pass(self) -> None:
        entry = _entry()
        cves = {
            "generation_id": _GENERATION_ID,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "total": 1,
            "cves": [entry],
        }
        index = {
            "generation_id": _GENERATION_ID,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "total": 1,
            "ids": [entry["id"]],
        }

        assert validate(entry, CVE_ENTRY_SCHEMA) == []
        assert validate(cves, CVES_SCHEMA) == []
        assert validate(index, INDEX_SCHEMA) == []
        assert validate(_stats(), STATS_SCHEMA) == []
        assert validate(_inventory(), INVENTORY_SCHEMA) == []

    def test_inventory_uses_orthogonal_states_and_content_identity(self) -> None:
        validate_inventory_payload(_inventory())

        mixed = _inventory()
        mixed["rows"][0]["coverage_status"] = "incomplete"
        mixed["counts"]["coverage_status"] = {"incomplete": 1}
        mixed["coverage_failure_count"] = 1
        mixed_preimage = dict(mixed)
        mixed_preimage.pop("inventory_id")
        mixed["inventory_id"] = hashlib.sha256(
            json.dumps(
                mixed_preimage,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        with pytest.raises(
            SchemaValidationError,
            match="coverage failures|exactly match class coverage",
        ):
            validate_inventory_payload(mixed)

        drifted = _inventory()
        drifted["rows"][0]["reasons"] = sorted(
            [*drifted["rows"][0]["reasons"], "changed_after_hash"]
        )
        with pytest.raises(SchemaValidationError, match="inventory_id"):
            validate_inventory_payload(drifted)

        component_tamper = _inventory()
        component_tamper["rows"][0]["component_sha256"] = "f" * 64
        component_preimage = dict(component_tamper)
        component_preimage.pop("inventory_id")
        component_tamper["inventory_id"] = hashlib.sha256(
            json.dumps(
                component_preimage,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        with pytest.raises(SchemaValidationError, match="component digest"):
            validate_inventory_payload(component_tamper)

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_numbers_are_rejected(self, value: float) -> None:
        errors = validate(_entry(confidence=value), CVE_ENTRY_SCHEMA)
        assert any("confidence" in error for error in errors)

    @pytest.mark.parametrize("value", [-0.01, 1.01, True])
    def test_confidence_outside_contract_is_rejected(self, value: object) -> None:
        errors = validate(_entry(confidence=value), CVE_ENTRY_SCHEMA)
        assert any("confidence" in error for error in errors)

    def test_invalid_calendar_date_is_rejected(self) -> None:
        errors = validate(_entry(published="2025-02-30"), CVE_ENTRY_SCHEMA)
        assert any("published" in error for error in errors)

    def test_generated_timestamp_requires_timezone(self) -> None:
        payload = {
            "generation_id": _GENERATION_ID,
            "generated_at": "2026-01-01T00:00:00",
            "total": 0,
            "ids": [],
        }
        assert any("generated_at" in error for error in validate(payload, INDEX_SCHEMA))

    def test_verifier_counters_are_non_negative_integers(self) -> None:
        verification = {
            "verdict": "CONFIRMED",
            "confidence": 0.9,
            "models": ["model"],
            "agent_verdicts": [
                {
                    "model": "model",
                    "verdict": "CONFIRMED",
                    "reasoning": "evidence",
                    "confidence": 0.9,
                    "tool_calls_made": 1,
                    "steps_completed": [],
                    "evidence": [],
                },
            ],
        }
        entry = _entry(
            bug_commits=[_bug_commit(verification=verification)],
            fix_commits=[_fix_commit()],
        )

        errors = validate(entry, CVE_ENTRY_SCHEMA)
        assert any("steps_completed" in error for error in errors)

    def test_validation_error_names_cve_and_field(self) -> None:
        with pytest.raises(SchemaValidationError, match="CVE-2025-12345"):
            validate_cve_entry(_entry(published="June 2025"))


class TestSemanticGates:
    def test_cves_total_matches_entries(self) -> None:
        payload = {
            "generation_id": _GENERATION_ID,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "total": 2,
            "cves": [_entry()],
        }
        with pytest.raises(SchemaValidationError, match="total"):
            validate_cves_payload(payload)

    def test_index_total_and_ids_are_consistent(self) -> None:
        duplicate = {
            "generation_id": _GENERATION_ID,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "total": 2,
            "ids": ["CVE-2025-1", "CVE-2025-1"],
        }
        with pytest.raises(SchemaValidationError, match="duplicate"):
            validate_index_payload(duplicate)

        wrong_total = {**duplicate, "total": 2, "ids": ["CVE-2025-1"]}
        with pytest.raises(SchemaValidationError, match="total"):
            validate_index_payload(wrong_total)

    def test_index_rejects_path_like_ids(self) -> None:
        payload = {
            "generation_id": _GENERATION_ID,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "total": 1,
            "ids": ["../outside"],
        }
        with pytest.raises(SchemaValidationError, match="ids"):
            validate_index_payload(payload)

    def test_unscoped_contribution_is_rejected(self) -> None:
        with pytest.raises(SchemaValidationError, match="unscoped"):
            validate_cve_entry(
                _entry(ai_involved=None, ai_contribution="stale narrative"),
            )

    def test_bic_requires_complete_known_unique_subject(self) -> None:
        missing_fix_sha = _bug_commit()
        del missing_fix_sha["fix_commit_sha"]
        errors = validate(
            _entry(bug_commits=[missing_fix_sha], fix_commits=[_fix_commit()]),
            CVE_ENTRY_SCHEMA,
        )
        assert any("fix_commit_sha" in error for error in errors)

        unknown_fix = _entry(
            bug_commits=[_bug_commit(fix_commit_sha="missing")],
            fix_commits=[_fix_commit()],
        )
        with pytest.raises(SchemaValidationError, match="unknown fix"):
            validate_cve_entry(unknown_fix)

        duplicate = _entry(
            bug_commits=[_bug_commit(), _bug_commit()],
            fix_commits=[_fix_commit()],
        )
        with pytest.raises(SchemaValidationError, match="duplicate BIC"):
            validate_cve_entry(duplicate)

    def test_stats_fix_count_cannot_exceed_analyzed(self) -> None:
        with pytest.raises(SchemaValidationError, match="exceeds"):
            validate_stats_payload(_stats(total_analyzed=1, with_fix_commits=2))


class TestDateNormalization:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("2025-10-03T19:15:43.490", "2025-10-03"),
            ("2026-03-24T00:00:00Z", "2026-03-24"),
            ("2026-03-15T12:34:56+00:00", "2026-03-15"),
            ("2026", "2026"),
            (" 2025-06-18 ", "2025-06-18"),
            ("2025-02-30", ""),
            ("2026-03", ""),
            ("June 2025", ""),
            ("0000", ""),
            (None, ""),
        ],
    )
    def test_normalize_published(self, raw: str | None, expected: str) -> None:
        assert normalize_published(raw) == expected

    def test_month_bucketing_requires_day_precision(self) -> None:
        assert _extract_month("2026-03-24") == "2026-03"
        assert _extract_month("2026") == ""
        assert _extract_month("2026-99-99") == ""

    def test_stats_emit_canonical_coverage_dates(self) -> None:
        stats = build_stats([_entry(published="2026")], coverage_since="2025-05")
        assert stats["coverage_from"] == "2025-05-01"
        assert stats["coverage_to"] == "2026-01-01"
        assert stats["by_month"] == []

    def test_invalid_coverage_month_fails_closed(self) -> None:
        with pytest.raises(ValueError, match="coverage month"):
            build_stats([], coverage_since="2025-13")


class TestProducerNormalization:
    def test_entry_normalizes_date_and_legacy_counters(self) -> None:
        signal = AiSignal(
            tool=AiTool.CURSOR,
            signal_type="co_author_trailer",
            matched_text="Co-authored-by: Cursor",
            confidence=0.95,
            origin="commit_metadata",
        )
        bic = BugIntroducingCommit(
            commit=CommitInfo(
                sha="abc123",
                author_name="Alice",
                author_email="alice@example.com",
                committer_name="Alice",
                committer_email="alice@example.com",
                message="introduce bug",
                authored_date="2025-05-01T00:00:00Z",
                ai_signals=[signal],
            ),
            fix_commit_sha="fix111",
            blamed_file="src/main.py",
            blamed_lines=[10],
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "causal evidence",
                "model": "model",
                "confidence": "high",
                "tool_calls_made": -4,
                "steps_completed": ["read", "verify"],
                "evidence": [],
            },
        )
        result = CveAnalysisResult(
            cve_id="CVE-2025-12345",
            description="A test vulnerability",
            bug_introducing_commits=[bic],
            fix_commits=[
                FixCommit(
                    sha="fix111",
                    repo_url="https://github.com/org/repo",
                    source="osv",
                ),
            ],
        )

        entry = build_entry(
            result,
            nvd_dates={"CVE-2025-12345": "2025-06-18T12:00:00Z"},
        )

        assert entry is not None
        entry["generation_id"] = _GENERATION_ID
        assert entry["published"] == "2025-06-18"
        agent = entry["bug_commits"][0]["verification"]["agent_verdicts"][0]
        assert agent["tool_calls_made"] == 0
        assert agent["steps_completed"] == 2
        validate_cve_entry(entry)

    def test_loader_parse_failure_emits_warning(
        self,
        tmp_path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        (tmp_path / "broken.json").write_text("{", encoding="utf-8")

        with caplog.at_level(logging.WARNING, logger="web_data.loader"):
            assert load_reviews(str(tmp_path)) == {}

        assert "Skipping review" in caplog.text


def test_typescript_contract_is_generated_from_schema() -> None:
    generated = render_ts()
    generated_path = (
        Path(__file__).resolve().parents[2]
        / "web"
        / "src"
        / "lib"
        / "types.generated.ts"
    )
    assert generated_path.read_text(encoding="utf-8") == generated
    assert "export interface CvesIndex" in generated
    assert "readonly generation_id: string;" in generated
    assert "readonly ai_involved: boolean | null;" in generated
    assert "readonly steps_completed: number;" in generated
    assert "readonly fix_commit_sha: string;" in generated
