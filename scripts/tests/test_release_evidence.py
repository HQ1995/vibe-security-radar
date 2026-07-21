"""Tests for immutable formal release-evidence archives."""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

import pytest

import evaluate_detector_quality as detector_quality
import build_recall_audit as recall_audit
import heldout_quality_gate as heldout
import evaluate_publication_quality as publication_quality
import build_source_delta as source_delta_builder
import generate_web_data as web_generator
import run_data_refresh as refresh_runner
import web_data.release_evidence as release_evidence
import web_data.inventory as detector_inventory_builder
import web_data.verifier_contract as verifier_contract_builder
import web_data.writer as writer
from cve_analyzer.models import (
    AiSignal,
    AiTool,
    BugIntroducingCommit,
    CommitInfo,
    CveAnalysisResult,
    FixCommit,
)
from verify_formal_release import verify_formal_release
from web_data.release_evidence import (
    ReleaseEvidenceError,
    archive_release_evidence as _archive_release_evidence,
    prepare_release_activation_record,
    reconcile_release_activation_record,
    validate_active_release,
    validate_archived_artifact_order,
    validate_release_evidence,
    write_release_activation_record,
)

_FIXTURE_TEMP_ROOT = tempfile.TemporaryDirectory(
    prefix="release-evidence-test-sources-"
)
_FIXTURE_SEQUENCE = itertools.count()
_REAL_VALIDATE_RECALL_EVIDENCE = release_evidence._validate_recall_evidence


@pytest.fixture(autouse=True)
def _separately_sealed_recall_census_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep legacy archive fixtures focused on their original contracts.

    The production validator remains fail-closed. Direct tests below call the
    saved validator to exercise exact recall replay and adversarial failures.
    """

    monkeypatch.setattr(
        release_evidence,
        "_validate_recall_evidence",
        lambda **_kwargs: None,
    )


def archive_release_evidence(**kwargs):
    """Inject the temporary repository as test authority, never bundle data."""

    artifacts = kwargs["artifacts"]
    trusted_repo_root = Path(artifacts["campaign-contract.json"]["repo_root"])
    return _archive_release_evidence(
        **kwargs,
        trusted_repo_root=trusted_repo_root,
    )


def _commit_fixture_artifact(
    repo_root: Path,
    relative_path: str,
    payload: dict,
    *,
    message: str,
) -> str:
    """Track exact canonical bytes and return the immutable fixture commit."""

    path = repo_root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(heldout.canonical_artifact_bytes(payload))
    subprocess.run(
        ["git", "-C", str(repo_root), "add", "--", relative_path],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "-c",
            "user.name=Release Evidence Fixture",
            "-c",
            "user.email=release-evidence@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            message,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return (
        subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        .stdout.decode("ascii")
        .strip()
    )


def _commit_minimal_verifier_scope(repo_root: Path) -> dict:
    files = {
        "cve-analyzer/src/cve_analyzer/__init__.py": b'"""fixture"""\n',
        "cve-analyzer/pyproject.toml": b"[project]\nname='fixture'\nversion='0'\n",
        "cve-analyzer/uv.lock": b"version = 1\n",
        "web/scripts/verify.mjs": b"export const fixture = true;\n",
        "web/src/index.ts": b"export const fixture = true;\n",
        "web/package.json": b'{"name":"fixture","version":"0.0.0"}\n',
        "web/package-lock.json": b'{"lockfileVersion":3,"name":"fixture"}\n',
        "web/next.config.ts": b"export default {};\n",
    }
    for relative, content in files.items():
        path = repo_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "add",
            "--",
            *verifier_contract_builder.TREE_SCOPES,
            *verifier_contract_builder.FILE_SCOPES,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "-c",
            "user.name=Release Evidence Fixture",
            "-c",
            "user.email=release-evidence@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "Bind verifier fixture",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return verifier_contract_builder.build_verifier_contract(repo_root)


def _canonical_sha256(value: object, *, ensure_ascii: bool = False) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=ensure_ascii,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _formal_alias_manifest_fixture() -> dict:
    source_snapshot_sha256 = "a" * 64
    members = ["CVE-2026-10001", "GHSA-aaaa-bbbb-cccc"]
    component_sha256 = hashlib.sha256(
        ("\n".join(members) + "\n").encode("utf-8")
    ).hexdigest()
    analysis_input = {
        "member_ids": members,
        "git_ranges": [
            {
                "repo": "https://github.com/example/project",
                "type": "GIT",
                "events": [{"fixed": "f" * 40}],
            }
        ],
        "fixed_events": [{"kind": "fixed", "value": "f" * 40}],
        "reference_urls": ["https://example.invalid/advisory"],
    }
    source_references = [
        {
            "source": "osv:PyPI",
            "record_id": "CVE-2026-10001",
            "record_sha256": "b" * 64,
            "reference": "osv:PyPI:CVE-2026-10001",
        }
    ]
    class_record = {
        "class_id": f"alias-{component_sha256[:24]}",
        "component_sha256": component_sha256,
        "all_member_ids": members,
        "eligible_seed_ids": members,
        "source_record_references": source_references,
        "merged_source_evidence_sha256": _canonical_sha256(
            {"records": source_references, "analysis_input": analysis_input},
            ensure_ascii=True,
        ),
        "analysis_subject": "CVE-2026-10001",
        "analysis_input": analysis_input,
        "source_snapshot_sha256": source_snapshot_sha256,
        "scheduled_seed_ids": ["GHSA-aaaa-bbbb-cccc"],
    }
    classes = [class_record]
    return {
        "schema_version": 1,
        "source_snapshot_sha256": source_snapshot_sha256,
        "class_count": 1,
        "eligible_seed_id_count": 2,
        "all_eligible_seed_ids_exactly_once": True,
        "classes_sha256": _canonical_sha256(classes, ensure_ascii=True),
        "scheduled_class_count": 1,
        "scheduled_analysis_subject_count": 1,
        "scheduled_classes_exactly_once": True,
        "classes": classes,
    }


def _reseal_alias_manifest(manifest: dict) -> str:
    digest = _canonical_sha256(manifest["classes"], ensure_ascii=True)
    manifest["classes_sha256"] = digest
    return digest


def _formal_alias_manifest_for_subjects(
    subject_ids: tuple[str, ...],
    *,
    source_snapshot_sha256: str,
) -> dict:
    """Build the exact source-delta alias-class projection used by a fixture."""

    classes: list[dict] = []
    for subject_id in subject_ids:
        members = [subject_id]
        component_sha256 = hashlib.sha256(f"{subject_id}\n".encode("utf-8")).hexdigest()
        analysis_input = {
            "member_ids": members,
            "git_ranges": [
                {
                    "events": [{"fixed": "b" * 40}],
                    "repo": "https://github.com/example/project",
                    "type": "GIT",
                }
            ],
            "fixed_events": [{"kind": "fixed", "value": "b" * 40}],
            "reference_urls": [f"https://evidence.invalid/{subject_id}"],
        }
        source_references = [
            {
                "source": "fixture:formal",
                "record_id": subject_id,
                "record_sha256": hashlib.sha256(subject_id.encode("utf-8")).hexdigest(),
                "reference": f"fixture:formal:{subject_id}",
            }
        ]
        classes.append(
            {
                "class_id": f"alias-{component_sha256[:24]}",
                "component_sha256": component_sha256,
                "all_member_ids": members,
                "eligible_seed_ids": members,
                "source_record_references": source_references,
                "merged_source_evidence_sha256": _canonical_sha256(
                    {
                        "records": source_references,
                        "analysis_input": analysis_input,
                    },
                    ensure_ascii=True,
                ),
                "analysis_subject": subject_id,
                "analysis_input": analysis_input,
                "source_snapshot_sha256": source_snapshot_sha256,
                "scheduled_seed_ids": members,
            }
        )
    classes.sort(key=lambda row: row["class_id"])
    return {
        "schema_version": 1,
        "source_snapshot_sha256": source_snapshot_sha256,
        "class_count": len(classes),
        "eligible_seed_id_count": len(subject_ids),
        "all_eligible_seed_ids_exactly_once": True,
        "classes_sha256": _canonical_sha256(classes, ensure_ascii=True),
        "scheduled_class_count": len(classes),
        "scheduled_analysis_subject_count": len(classes),
        "scheduled_classes_exactly_once": True,
        "classes": classes,
    }


def test_formal_alias_manifest_recomputes_component_and_source_bindings() -> None:
    manifest = _formal_alias_manifest_fixture()

    scheduled, member_map = release_evidence._validate_formal_alias_class_manifest(
        manifest,
        expected_manifest_sha256=manifest["classes_sha256"],
        expected_source_snapshot_sha256=manifest["source_snapshot_sha256"],
    )

    assert set(scheduled) == {"CVE-2026-10001"}
    assert member_map == {
        "CVE-2026-10001": "CVE-2026-10001",
        "GHSA-aaaa-bbbb-cccc": "CVE-2026-10001",
    }


def test_formal_alias_manifest_rejects_resealed_unscheduled_class() -> None:
    manifest = _formal_alias_manifest_fixture()
    manifest["classes"][0]["scheduled_seed_ids"] = []
    manifest["scheduled_class_count"] = 0
    manifest["scheduled_analysis_subject_count"] = 0
    digest = _reseal_alias_manifest(manifest)

    with pytest.raises(ReleaseEvidenceError, match="component or member binding"):
        release_evidence._validate_formal_alias_class_manifest(
            manifest,
            expected_manifest_sha256=digest,
            expected_source_snapshot_sha256=manifest["source_snapshot_sha256"],
        )


def test_formal_alias_manifest_rejects_schedule_outside_eligible_population() -> None:
    manifest = _formal_alias_manifest_fixture()
    manifest["classes"][0]["eligible_seed_ids"] = ["CVE-2026-10001"]
    manifest["eligible_seed_id_count"] = 1
    digest = _reseal_alias_manifest(manifest)

    with pytest.raises(ReleaseEvidenceError, match="component or member binding"):
        release_evidence._validate_formal_alias_class_manifest(
            manifest,
            expected_manifest_sha256=digest,
            expected_source_snapshot_sha256=manifest["source_snapshot_sha256"],
        )


def test_formal_alias_manifest_validator_matches_source_builder_semantics() -> None:
    source_snapshot_sha256 = "e" * 64
    record = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2026-10001"],
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/example/project",
                        "events": [{"fixed": "f" * 40}],
                    }
                ]
            }
        ],
        "references": [{"url": "https://example.invalid/advisory"}],
    }
    manifest = source_delta_builder._build_alias_class_manifest(
        [("osv:PyPI", record)],
        production_ids=["CVE-2026-10001", "GHSA-aaaa-bbbb-cccc"],
        source_snapshot_sha256=source_snapshot_sha256,
    )
    scheduled_manifest, scheduled_subjects = (
        source_delta_builder._schedule_alias_classes(
            manifest,
            ["GHSA-aaaa-bbbb-cccc"],
        )
    )

    scheduled, member_map = release_evidence._validate_formal_alias_class_manifest(
        scheduled_manifest,
        expected_manifest_sha256=scheduled_manifest["classes_sha256"],
        expected_source_snapshot_sha256=source_snapshot_sha256,
    )

    assert scheduled_subjects == ["CVE-2026-10001"]
    assert set(scheduled) == {"CVE-2026-10001"}
    assert set(member_map) == {"CVE-2026-10001", "GHSA-aaaa-bbbb-cccc"}


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("component", "component or analysis-subject"),
        ("analysis_members", "analysis input"),
        ("source_record", "merged source evidence"),
        ("member_type", "component or member binding"),
    ],
)
def test_formal_alias_manifest_rejects_resealed_internal_tampering(
    mutation: str,
    message: str,
) -> None:
    manifest = _formal_alias_manifest_fixture()
    class_record = manifest["classes"][0]
    if mutation == "component":
        class_record["component_sha256"] = "c" * 64
        class_record["class_id"] = f"alias-{'c' * 24}"
    elif mutation == "analysis_members":
        class_record["analysis_input"]["member_ids"] = ["CVE-2026-10001"]
        class_record["merged_source_evidence_sha256"] = _canonical_sha256(
            {
                "records": class_record["source_record_references"],
                "analysis_input": class_record["analysis_input"],
            },
            ensure_ascii=True,
        )
    elif mutation == "source_record":
        class_record["source_record_references"][0]["record_sha256"] = "d" * 64
    else:
        class_record["all_member_ids"].append(7)
    digest = _reseal_alias_manifest(manifest)

    with pytest.raises(ReleaseEvidenceError, match=message):
        release_evidence._validate_formal_alias_class_manifest(
            manifest,
            expected_manifest_sha256=digest,
            expected_source_snapshot_sha256=manifest["source_snapshot_sha256"],
        )


def test_required_formal_analysis_subjects_replay_frozen_corpus_exactly() -> None:
    corpus = [
        {
            "canonical_id": "CVE-2026-10001",
            "label": "AI_CAUSAL",
            "subject_ids": ["CVE-2026-10001", "GHSA-aaaa-bbbb-cccc"],
        }
    ]
    normalized = json.loads(json.dumps(corpus))

    source_subjects, analysis_subjects = (
        release_evidence._required_formal_analysis_subjects(
            corpus,
            corpus_manifest_sha256=_canonical_sha256(corpus),
            normalized_adjudications=normalized,
            detector_adjudications_sha256="f" * 64,
            curation_adjudications_sha256="f" * 64,
            member_to_analysis_subject={
                "CVE-2026-10001": "CVE-2026-10001",
                "GHSA-aaaa-bbbb-cccc": "CVE-2026-10001",
            },
        )
    )

    assert source_subjects == {"CVE-2026-10001", "GHSA-aaaa-bbbb-cccc"}
    assert analysis_subjects == {"CVE-2026-10001"}


@pytest.mark.parametrize(
    "mutation",
    ["curation_drift", "input_digest_drift", "missing_campaign_class"],
)
def test_required_formal_analysis_subjects_rejects_scope_tampering(
    mutation: str,
) -> None:
    corpus = [
        {
            "canonical_id": "CVE-2026-10001",
            "label": "AI_CAUSAL",
            "subject_ids": ["CVE-2026-10001", "GHSA-aaaa-bbbb-cccc"],
        }
    ]
    normalized = json.loads(json.dumps(corpus))
    member_map = {
        "CVE-2026-10001": "CVE-2026-10001",
        "GHSA-aaaa-bbbb-cccc": "CVE-2026-10001",
    }
    curation_digest = "f" * 64
    if mutation == "curation_drift":
        normalized[0]["subject_ids"].pop()
        message = "corpora differ"
    elif mutation == "input_digest_drift":
        curation_digest = "e" * 64
        message = "frozen adjudication inputs differ"
    else:
        member_map.pop("GHSA-aaaa-bbbb-cccc")
        message = "absent from the formal campaign"

    with pytest.raises(ReleaseEvidenceError, match=message):
        release_evidence._required_formal_analysis_subjects(
            corpus,
            corpus_manifest_sha256=_canonical_sha256(corpus),
            normalized_adjudications=normalized,
            detector_adjudications_sha256="f" * 64,
            curation_adjudications_sha256=curation_digest,
            member_to_analysis_subject=member_map,
        )


def test_formal_release_rejects_pilot_campaign_and_marker_artifacts() -> None:
    with pytest.raises(
        ReleaseEvidenceError,
        match="campaign contract.*pilot artifact.*not formal release eligible",
    ):
        release_evidence._validate_campaign_archive_contract(
            {"artifact_kind": "pilot"},
            campaign_result_entries={},
            receipt={},
        )

    with pytest.raises(
        ReleaseEvidenceError,
        match="campaign marker.*pilot artifact.*not formal release eligible",
    ):
        release_evidence._reject_pilot_release_artifact(
            {"artifact_kind": "pilot"},
            label="campaign marker",
        )


def _source_snapshot(cutoff: dict) -> dict:
    return {
        "schema_version": 2,
        "git_mirrors": {
            "cvelist_v5": {
                "clean": True,
                "head": "1" * 40,
                "origin": "https://github.com/CVEProject/cvelistV5.git",
                "path": "/tmp/sources/cvelist",
                "tree": "2" * 40,
            },
            "gemnasium_advisories": {
                "clean": True,
                "head": "3" * 40,
                "origin": "https://gitlab.com/gitlab-org/advisories-community.git",
                "path": "/tmp/sources/gemnasium",
                "tree": "4" * 40,
            },
            "github_advisories": {
                "clean": True,
                "head": "5" * 40,
                "origin": "https://github.com/github/advisory-database.git",
                "path": "/tmp/sources/ghsa",
                "tree": "6" * 40,
            },
        },
        "nvd_feeds": [
            {
                "name": f"nvdcve-2.0-{year}.json.gz",
                "path": f"/tmp/sources/nvdcve-2.0-{year}.json.gz",
                "sha256": str(year)[-1] * 64,
                "size_bytes": 10,
            }
            for year in (2025, 2026)
        ],
        "osv_ecosystem_manifest": {
            "name": "ecosystems.txt",
            "path": "/tmp/sources/ecosystems.txt",
            "sha256": "7" * 64,
            "size_bytes": 5,
            "ecosystem_count": 1,
            "ecosystems": ["PyPI"],
            "archive_names": ["PyPI.zip"],
        },
        "osv_archives": [
            {
                "name": "PyPI.zip",
                "path": "/tmp/sources/PyPI.zip",
                "sha256": "4" * 64,
                "size_bytes": 1,
            }
        ],
        "remote_cutoff": cutoff,
    }


def _campaign_result_bytes(
    subject_id: str,
    *,
    campaign: refresh_runner.CampaignExecution,
    batch_key: str,
    started_at: str,
    completed_at: str,
    with_fix_commit: bool = False,
) -> bytes:
    signal = AiSignal(
        tool=AiTool.CURSOR,
        signal_type="co_author_trailer",
        matched_text="Co-authored-by: Cursor",
        confidence=0.95,
    )
    commit = CommitInfo(
        sha="a" * 40,
        author_name="Fixture",
        author_email="fixture@example.invalid",
        committer_name="Fixture",
        committer_email="fixture@example.invalid",
        message="fixture campaign result",
        authored_date="2026-07-18T12:00:00Z",
        ai_signals=[signal],
    )
    bic = BugIntroducingCommit(
        commit=commit,
        fix_commit_sha="b" * 40,
        blamed_file="src/fixture.py",
        blamed_lines=[1],
        deep_verification={
            "verdict": "CONFIRMED",
            "reasoning": "Fixture causal evidence.",
            "model": "gpt-5.6-luna",
            "reasoning_effort": "max",
            "confidence": "high",
            "tool_calls_made": 1,
            "steps_completed": ["verify"],
            "evidence": ["fixture"],
        },
    )
    payload = CveAnalysisResult(
        cve_id=subject_id,
        fix_commits=(
            [
                FixCommit(
                    sha="b" * 40,
                    repo_url="https://github.com/example/project",
                    source="nvd",
                )
            ]
            if with_fix_commit
            else []
        ),
        bug_introducing_commits=[bic],
        campaign_receipt={
            "schema_version": 1,
            "campaign_id": campaign.campaign_id,
            "batch": batch_key,
            "started_at": started_at,
            "completed_at": completed_at,
            "source_snapshot_sha256": campaign.source_snapshot_sha256,
            "contract_sha256": campaign.contract_sha256,
            "litellm_transport_sha256": campaign.litellm_transport_sha256,
            "requested_model": refresh_runner.MODEL,
            "reasoning_effort": refresh_runner.REASONING_EFFORT,
            "llm_cache_disabled": True,
            "status": "success",
            "failed_stages": [],
            "stages": {
                "phase_c_screening": {"status": "success"},
                "phase_d_deep_verification": {"status": "success"},
            },
        },
        analysis_stage_receipts={
            stage: {"outcome": "resolved"}
            for stage in (
                "source_discovery",
                "fix_resolution",
                "bic_resolution",
                "signal_classification",
                "causal_verification",
                "adjudication",
            )
        },
    ).to_dict()
    return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")


def _artifacts(
    generation_id: str,
    *,
    publication_bundle_sha256: str = "5" * 64,
    publication_files: list[dict] | None = None,
    publication_index_bytes: bytes | None = None,
    repo_root: Path | None = None,
    with_fix_commits: bool = False,
) -> dict[str, dict]:
    manifest_entry = {
        "ecosystem_count": 1,
        "ecosystems": ["PyPI"],
        "etag": '"' + "0" * 32 + '"',
        "filename": "ecosystems.txt",
        "generation": "1784376000000000",
        "last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
        "md5_base64": "AAAAAAAAAAAAAAAAAAAAAA==",
        "path": "/tmp/sources/ecosystems.txt",
        "remote_size": 5,
        "sha256": "7" * 64,
        "size": 5,
        "url": "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt",
    }
    cutoff = {
        "checked_at_utc": "2026-07-18T12:00:00+00:00",
        "receipt_file": {
            "name": "source-remote-check-now.json",
            "path": "/tmp/source-remote-check-now.json",
            "sha256": "e" * 64,
            "size_bytes": 100,
        },
        "remote_parity": True,
        "receipt": {
            "schema_version": 3,
            "checked_at_utc": "2026-07-18T12:00:00+00:00",
            "git_sources": [
                {
                    "branch": "main",
                    "head": "1" * 40,
                    "name": "cvelistV5",
                    "origin": "https://example.invalid/cvelist.git",
                    "path": "/tmp/sources/cvelist",
                    "remote_head": "1" * 40,
                    "tree": "2" * 40,
                }
            ],
            "nvd_feeds": [
                {
                    "feed_path": "/tmp/sources/nvd.json.gz",
                    "feed_sha256": "3" * 64,
                    "feed_size": 10,
                    "meta_path": "/tmp/sources/nvd.meta",
                    "meta_sha256": "2" * 64,
                    "remote_etag": '"etag"',
                    "remote_last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
                    "remote_meta_sha256": "2" * 64,
                    "year": 2026,
                }
            ],
            "osv_ecosystem_manifest": manifest_entry,
            "osv_archive_count": 1,
            "osv_archives": [
                {
                    "crc32c_base64": "AAAAAA==",
                    "etag": '"' + "0" * 32 + '"',
                    "filename": "PyPI.zip",
                    "generation": "1784376000000000",
                    "last_modified": "Sat, 18 Jul 2026 12:00:00 GMT",
                    "md5_base64": "AAAAAAAAAAAAAAAAAAAAAA==",
                    "path": "/tmp/sources/PyPI.zip",
                    "remote_size": 1,
                    "sha256": "4" * 64,
                    "size": 1,
                    "url": "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip",
                }
            ],
            "remote_parity": True,
        },
    }
    source_snapshot = _source_snapshot(cutoff)
    population_size = 100
    subject_ids = tuple(
        f"CVE-2026-{10_000 + index}" for index in range(population_size)
    )
    if publication_index_bytes is None:
        publication_index_bytes = (
            json.dumps(
                {
                    "schema_version": 1,
                    "generation_id": generation_id,
                    "generated_at": "2026-07-18T13:00:00+00:00",
                    "total": len(subject_ids),
                    "ids": list(subject_ids),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    publication_index = json.loads(publication_index_bytes.decode("utf-8"))
    published_ordered_ids = publication_index["ids"]
    plan_ids_sha256 = hashlib.sha256(
        ("\n".join(sorted(subject_ids)) + "\n").encode()
    ).hexdigest()
    alias_source_snapshot_sha256 = "9" * 64
    alias_manifest = _formal_alias_manifest_for_subjects(
        subject_ids,
        source_snapshot_sha256=alias_source_snapshot_sha256,
    )
    analyzer_contract_sha256 = "8" * 64
    signature_sha256 = "6" * 64
    incremental_plan_proof = {
        "schema_version": 2,
        "scope": "formal_current_source_alias_class_plan",
        "campaign_mode": "formal",
        "population_policy": "formal_full",
        "formal_release_eligible": True,
        "source_delta_schema_version": refresh_runner.SOURCE_DELTA_SCHEMA_VERSION,
        "source_delta_path": "source-delta-current.json",
        "source_delta_sha256": "1" * 64,
        "source_delta_integrity_payload_sha256": "2" * 64,
        "input_snapshot_sha256": "3" * 64,
        "result_cache_inventory_manifest_sha256": "4" * 64,
        "production_discovered_id_count": len(subject_ids),
        "cache_covered_discovered_id_count": 0,
        "uncached_discovered_id_count": len(subject_ids),
        "candidate_id_count": len(subject_ids),
        "candidate_sha256": plan_ids_sha256,
        "plan_subject_id_count": len(subject_ids),
        "plan_subject_ids_sha256": plan_ids_sha256,
        "alias_class_manifest_sha256": alias_manifest["classes_sha256"],
        "source_alias_class_count": len(subject_ids),
        "scheduled_alias_class_count": len(subject_ids),
        "plan_alias_classes_exactly_once": True,
        "analyzer_contract_sha256": analyzer_contract_sha256,
        "signature_sha256": signature_sha256,
        "candidate_union_exact": True,
        "plan_exactly_matches_candidate": True,
        "frozen_local_sources": True,
        "network_advisory_api_included": False,
        "historical_cache_suppresses_current_classes": False,
        "formal_current_epoch_stage_receipt_required": True,
        "boundary": "fixture incremental campaign boundary",
    }
    litellm_transport = {
        "schema_version": 1,
        "api_base_sha256": "a" * 64,
        "base_env_vars": ["LITELLM_API_BASE"],
        "key_env_vars": ["LITELLM_API_KEY"],
        "api_modes": ["responses"],
        "api_key_configured": True,
    }
    litellm_transport_sha256 = _canonical_sha256(litellm_transport, ensure_ascii=True)
    repo_root = (
        Path(_FIXTURE_TEMP_ROOT.name) / f"repository-{next(_FIXTURE_SEQUENCE)}"
        if repo_root is None
        else Path(repo_root)
    )
    repo_root.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-q", str(repo_root)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    marker_dir = repo_root / ".ai-slop/state/data-refresh/refresh-runner-v1/completed"
    batch_path = (
        repo_root / ".ai-slop/state/data-refresh/grouped-batches-v1/grouped-001.txt"
    )
    batch_ids = subject_ids
    batch_bytes = ("\n".join(batch_ids) + "\n").encode("utf-8")
    batch_spec = refresh_runner.BatchSpec(
        key="grouped-001",
        path=batch_path,
        kind="fixture",
        ids=batch_ids,
        repos=frozenset(),
    )
    batch_command = refresh_runner.build_command(batch_spec)
    batch_sha256 = hashlib.sha256(batch_bytes).hexdigest()
    command_sha256 = _canonical_sha256(batch_command)
    campaign_identity = {
        "schema_version": refresh_runner.MARKER_SCHEMA_VERSION,
        "source_snapshot_sha256": _canonical_sha256(source_snapshot, ensure_ascii=True),
        "contract_sha256": "4" * 64,
        "analyzer_contract_sha256": analyzer_contract_sha256,
        "signature_sha256": signature_sha256,
        "alias_class_manifest_sha256": alias_manifest["classes_sha256"],
        "model": refresh_runner.MODEL,
        "reasoning_effort": refresh_runner.REASONING_EFFORT,
        "workers": refresh_runner.WORKERS,
        "forced_verification": True,
        "result_cache_reads": False,
        "llm_cache_reads": False,
        "litellm_transport_sha256": litellm_transport_sha256,
        "batch_timeout_seconds": refresh_runner.BATCH_TIMEOUT_SECONDS,
    }
    campaign_id = _canonical_sha256(campaign_identity, ensure_ascii=True)
    result_dir = marker_dir.parent.parent / "campaigns-v1" / campaign_id / "results"
    result_dir.mkdir(parents=True, exist_ok=True)
    campaign = refresh_runner.CampaignExecution(
        campaign_id=campaign_id,
        root=result_dir.parent,
        result_dir=result_dir,
        api_cache_dir=result_dir.parent / "api-responses",
        derived_cache_root=result_dir.parent / "derived-cache",
        source_snapshot_sha256=_canonical_sha256(source_snapshot, ensure_ascii=True),
        contract_sha256="4" * 64,
        litellm_transport_sha256=litellm_transport_sha256,
        litellm_transport=litellm_transport,
        analyzer_contract_sha256=analyzer_contract_sha256,
        signature_sha256=signature_sha256,
        alias_class_manifest_sha256=alias_manifest["classes_sha256"],
    )
    marker_started_at = "2026-07-18T12:00:00+00:00"
    marker_completed_at = "2026-07-18T12:00:01+00:00"
    raw_results = {
        subject_id: _campaign_result_bytes(
            subject_id,
            campaign=campaign,
            batch_key="grouped-001",
            started_at=marker_started_at,
            completed_at=marker_completed_at,
            with_fix_commit=with_fix_commits,
        )
        for subject_id in subject_ids
    }
    results = [
        {
            "subject_id": subject_id,
            "file_name": f"{subject_id}.json",
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for subject_id, content in raw_results.items()
    ]
    for subject_id, content in raw_results.items():
        (result_dir / f"{subject_id}.json").write_bytes(content)
    batch_result_manifest_sha256 = _canonical_sha256(
        [
            {
                "subject_id": entry["subject_id"],
                "size_bytes": entry["size_bytes"],
                "sha256": entry["sha256"],
            }
            for entry in results
        ]
    )
    expected_contract = {
        "marker_schema_version": refresh_runner.MARKER_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "result_dir": str(result_dir),
        "contract_sha256": "4" * 64,
        "analyzer_contract_sha256": analyzer_contract_sha256,
        "signature_sha256": signature_sha256,
        "alias_class_manifest_sha256": alias_manifest["classes_sha256"],
        "source_snapshot_sha256": _canonical_sha256(
            source_snapshot,
            ensure_ascii=True,
        ),
        "model": "gpt-5.6-luna",
        "reasoning_effort": "max",
        "workers": 32,
        "litellm_transport_sha256": litellm_transport_sha256,
        "litellm_transport": litellm_transport,
        "batch_timeout_seconds": refresh_runner.BATCH_TIMEOUT_SECONDS,
        "campaign_mode": "formal",
        "population_policy": "formal_full",
        "incremental_plan_proof": json.loads(json.dumps(incremental_plan_proof)),
    }
    marker_started_at_ns = 1_784_376_000_000_000_000
    marker_completed_at_ns = 1_784_376_001_000_000_000
    class_records = {
        item["analysis_subject"]: item for item in alias_manifest["classes"]
    }
    class_receipts: list[dict] = []
    for entry in results:
        subject_id = entry["subject_id"]
        problem, class_receipt = refresh_runner._analysis_stage_receipt_proof(
            json.loads(raw_results[subject_id]),
            class_record=class_records[subject_id],
            campaign=campaign,
            result_sha256=entry["sha256"],
        )
        assert problem is None
        assert class_receipt is not None
        class_receipts.append(class_receipt)
    class_receipts.sort(key=lambda item: item["class_id"])
    class_receipts_sha256 = _canonical_sha256(class_receipts, ensure_ascii=True)
    marker_payload = {
        "schema_version": refresh_runner.MARKER_SCHEMA_VERSION,
        "batch": "grouped-001",
        "kind": "fixture",
        "batch_file": batch_path.relative_to(repo_root).as_posix(),
        "batch_sha256": batch_sha256,
        "contract_sha256": "4" * 64,
        "analyzer_contract_sha256": analyzer_contract_sha256,
        "signature_sha256": signature_sha256,
        "alias_class_manifest_sha256": alias_manifest["classes_sha256"],
        "source_snapshot_sha256": _canonical_sha256(source_snapshot, ensure_ascii=True),
        "source_snapshot": source_snapshot,
        "id_line_count": len(batch_ids),
        "unique_id_count": len(batch_ids),
        "command": batch_command,
        "reasoning_effort": refresh_runner.REASONING_EFFORT,
        "model": refresh_runner.MODEL,
        "workers": refresh_runner.WORKERS,
        "campaign_id": campaign_id,
        "campaign_result_dir": str(result_dir),
        "campaign_api_cache_dir": str(result_dir.parent / "api-responses"),
        "campaign_derived_cache_root": str(result_dir.parent / "derived-cache"),
        "litellm_transport_sha256": litellm_transport_sha256,
        "litellm_transport": litellm_transport,
        "batch_timeout_seconds": refresh_runner.BATCH_TIMEOUT_SECONDS,
        "free_bytes_before": 10_000,
        "free_bytes_after": 9_000,
        "log_file": ".ai-slop/logs/data-refresh/grouped-001.log",
        "started_at": marker_started_at,
        "completed_at": marker_completed_at,
        "exit_code": 0,
        "result_validation": {
            "result_count": len(batch_ids),
            "terminal_count": len(batch_ids),
            "result_manifest_sha256": batch_result_manifest_sha256,
            "class_receipt_count": len(class_receipts),
            "class_receipts_sha256": class_receipts_sha256,
            "class_receipts": class_receipts,
            "alias_classes_exactly_once": True,
        },
    }
    marker_bytes = (json.dumps(marker_payload, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()
    fixed_proof = {
        "complete": True,
        "campaign_mode": "formal",
        "population_policy": "formal_full",
        "formal_population_complete": True,
        "incremental_plan_complete": False,
        "full_incremental_plan_campaign_complete": False,
        "proof_scope": "formal_current_source_alias_class_plan",
        "population_uniform_luna_max_proof": False,
        "incremental_plan_proof": json.loads(json.dumps(incremental_plan_proof)),
        "required_subject_count": len(published_ordered_ids),
        "required_campaign_subject_count": len(published_ordered_ids),
        "mapped_subject_count": len(published_ordered_ids),
        "campaign_subject_count": len(results),
        "campaign_batch_count": 1,
        "completed_marker_count": 1,
        "relevant_marker_count": 1,
        "expected_contract": expected_contract,
        "failure_counts": {},
        "failures": [],
        "marker_proofs": [
            {
                "batch": "grouped-001",
                "path": str(marker_dir / "grouped-001.json"),
                "marker_sha256": marker_sha256,
                "batch_sha256": batch_sha256,
                "command_sha256": command_sha256,
                "result_manifest_sha256": batch_result_manifest_sha256,
                "class_receipts_sha256": class_receipts_sha256,
                "started_at_ns": marker_started_at_ns,
                "completed_at_ns": marker_completed_at_ns,
            }
        ],
        "subject_proofs": [
            {
                "subject_id": entry["subject_id"],
                "batch": "grouped-001",
                "marker_sha256": marker_sha256,
                "result_sha256": entry["sha256"],
                "result_mtime_ns": marker_started_at_ns + 500_000_000,
                "marker_started_at_ns": marker_started_at_ns,
                "marker_completed_at_ns": marker_completed_at_ns,
                "terminal_validation": "passed",
            }
            for entry in results
            if entry["subject_id"] in set(published_ordered_ids)
        ],
    }
    adjudication_payload = {
        "schema_version": 1,
        "adjudications": [
            {"cve_id": subject_id, "label": "AI_CAUSAL", "aliases": []}
            for subject_id in published_ordered_ids
        ],
    }
    adjudication_bytes = (
        json.dumps(adjudication_payload, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    curation_corpus = publication_quality.AdjudicationCorpus(
        tuple(
            publication_quality.AdjudicationEntry(subject_id, "AI_CAUSAL")
            for subject_id in published_ordered_ids
        )
    )
    normalized_adjudications = [
        {
            "canonical_id": entry.canonical_id,
            "label": entry.label,
            "subject_ids": sorted(entry.subject_ids),
        }
        for entry in curation_corpus.entries
    ]
    alias_classes: list[dict] = []
    curation_inputs = {
        "schema_version": 1,
        "adjudications_path": "/tmp/repository/scripts/audit_adjudications.json",
        "adjudications_sha256": hashlib.sha256(adjudication_bytes).hexdigest(),
        "adjudications_bytes_base64": base64.b64encode(adjudication_bytes).decode(
            "ascii"
        ),
        "alias_classes": alias_classes,
        "alias_classes_sha256": _canonical_sha256(alias_classes),
        "normalized_adjudications": normalized_adjudications,
        "normalized_adjudications_sha256": _canonical_sha256(normalized_adjudications),
        "publication_index_sha256": hashlib.sha256(publication_index_bytes).hexdigest(),
        "publication_index_bytes_base64": base64.b64encode(
            publication_index_bytes
        ).decode("ascii"),
        "published_ordered_ids": published_ordered_ids,
        "published_ordered_ids_sha256": _canonical_sha256(published_ordered_ids),
    }
    curation_report = publication_quality.evaluate(
        curation_corpus,
        set(published_ordered_ids),
        precision_target=0.95,
        recall_target=0.95,
    )
    published_id_set = set(published_ordered_ids)
    detector_inventory = detector_inventory_builder.build_detector_inventory(
        tuple(
            CveAnalysisResult.from_dict(json.loads(content))
            for content in raw_results.values()
        ),
        alias_map={},
        adjudicated_positive_ids=published_id_set,
        audit_exclusions=set(),
        published_ids=published_id_set,
        generated_at=cutoff["checked_at_utc"],
        source_snapshot_sha256=_canonical_sha256(
            source_snapshot,
            ensure_ascii=True,
        ),
        source_receipt_sha256=_canonical_sha256(cutoff),
        campaign_id=campaign_id,
        contract_sha256="4" * 64,
        campaign_mode="formal",
        coverage_to=cutoff["checked_at_utc"][:10],
        require_stage_receipts=True,
        alias_class_manifest=alias_manifest,
    )
    corpus_manifest = json.loads(json.dumps(normalized_adjudications))
    detector_report = {
        "evaluation_complete": True,
        "sample_count": len(corpus_manifest),
        "fixed_contract_campaign_proof": fixed_proof,
        "corpus_manifest": corpus_manifest,
        "corpus_manifest_sha256": _canonical_sha256(corpus_manifest),
        "input_provenance": {
            "adjudications": {
                "path": curation_inputs["adjudications_path"],
                "sha256": curation_inputs["adjudications_sha256"],
            }
        },
        "detector_inventory": {
            "inventory_id": detector_inventory["inventory_id"],
            "source_snapshot_sha256": detector_inventory["source_snapshot_sha256"],
            "source_alias_class_manifest_sha256": detector_inventory[
                "source_alias_class_manifest_sha256"
            ],
            "campaign_id": detector_inventory["campaign_id"],
            "contract_sha256": detector_inventory["contract_sha256"],
            "campaign_mode": detector_inventory["campaign_mode"],
            "complete": detector_inventory["complete"],
            "alias_class_count": detector_inventory["alias_class_count"],
        },
    }
    if publication_files is None:
        inventory_bytes = (
            json.dumps(
                detector_inventory,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        publication_files = [
            {
                "path": "index.json",
                "size_bytes": len(publication_index_bytes),
                "sha256": hashlib.sha256(publication_index_bytes).hexdigest(),
            },
            {
                "path": "inventory.json",
                "size_bytes": len(inventory_bytes),
                "sha256": hashlib.sha256(inventory_bytes).hexdigest(),
            },
        ]
    units = tuple(
        heldout.SelectionUnit(
            canonical_id=f"CVE-2026-{10_000 + index}",
            subject_ids=(f"CVE-2026-{10_000 + index}",),
            predicted_positive=True,
            candidate_positive=True,
            prediction_reasons=("included",),
            infrastructure_categories=(),
            unresolved_reasons=(),
            results=(
                heldout.ResultReference(
                    f"CVE-2026-{10_000 + index}",
                    hashlib.sha256(
                        raw_results[f"CVE-2026-{10_000 + index}"]
                    ).hexdigest(),
                ),
            ),
        )
        for index in range(population_size)
    )
    unit_manifest = [
        {
            "canonical_id": unit.canonical_id,
            "subject_ids": list(unit.subject_ids),
            "results": [
                {"subject_id": result.subject_id, "sha256": result.sha256}
                for result in unit.results
            ],
        }
        for unit in units
    ]
    snapshot = heldout.CampaignSnapshot(
        campaign_id=campaign_id,
        contract_sha256="4" * 64,
        source_snapshot_sha256=_canonical_sha256(
            source_snapshot,
            ensure_ascii=True,
        ),
        campaign_proof_sha256=heldout.canonical_sha256(fixed_proof),
        campaign_result_manifest_sha256=heldout.canonical_sha256(unit_manifest),
        proof_complete=True,
        units=units,
    )
    protected_relative = "scripts/protected-fixture.txt"
    protected_bytes = b"fixture with no advisory identifiers\n"
    protected_path = repo_root / protected_relative
    protected_path.parent.mkdir(parents=True, exist_ok=True)
    protected_path.write_bytes(protected_bytes)
    protected_files = (
        {
            "path": protected_relative,
            "size_bytes": len(protected_bytes),
            "sha256": hashlib.sha256(protected_bytes).hexdigest(),
            "referenced_subject_count": 0,
            "referenced_subject_ids_sha256": heldout.canonical_sha256([]),
        },
    )
    protected = heldout.ProtectedInventory(
        subject_ids=frozenset(),
        source_roots=(({"path": protected_relative, "kind": "file"}),),
        files=protected_files,
        files_manifest_sha256=heldout.canonical_sha256(list(protected_files)),
        subject_ids_sha256=heldout.canonical_sha256([]),
    )
    selection = heldout.build_selection_manifest(
        snapshot,
        protected,
        precision_sample_size=59,
        recall_sample_size=59,
        selection_code_sha256="7" * 64,
    )
    population_results = [
        {
            **entry,
            "source_path": str(result_dir / entry["file_name"]),
            "archive_path": f"campaign-results/{entry['file_name']}",
        }
        for entry in results
    ]
    alias_classes: list[dict] = []
    heldout_campaign_population = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "result_dir": str(result_dir),
        "result_count": len(population_results),
        "total_result_size_bytes": sum(
            entry["size_bytes"] for entry in population_results
        ),
        "result_manifest_sha256": _canonical_sha256(results),
        "results": population_results,
        "alias_classes": alias_classes,
        "alias_classes_sha256": _canonical_sha256(alias_classes),
        "protected_inputs": {
            "source_roots": list(protected.source_roots),
            "file_count": len(protected_files),
            "total_size_bytes": len(protected_bytes),
            "files_manifest_sha256": protected.files_manifest_sha256,
            "files": [
                {
                    **protected_files[0],
                    "bytes_base64": base64.b64encode(protected_bytes).decode("ascii"),
                }
            ],
        },
    }
    selection_path = "scripts/heldout_studies/selection-fixture.json"
    labels_path = "scripts/heldout_studies/labels-fixture.json"
    selection_commit = _commit_fixture_artifact(
        repo_root,
        selection_path,
        selection,
        message="Seal held-out selection before labels",
    )
    selection_reference = f"{selection_commit}:{selection_path}"
    labels = heldout.build_label_template(selection)
    labels["audit_protocol"] = {
        "selection_commit_reference": selection_reference,
        "audit_started_from_null_label_template": True,
        "reviewers_independent_from_detector_development": True,
        "reviewers_independent_from_each_other": True,
        "reviews_completed_without_access_to_other_review": True,
        "detector_predictions_hidden_from_reviewers": True,
        "sample_lane_membership_hidden_from_reviewers": True,
        "aggregate_quality_scores_hidden_until_resolution_complete": True,
        "all_disagreements_resolved_before_sealing": True,
    }
    for entry in labels["adjudications"]:
        evidence_refs = [f"https://evidence.invalid/{entry['sample_id']}"]
        entry["primary_review"] = {
            "reviewer_id": "independent-primary",
            "label": "AI_CAUSAL",
            "reviewed_at_utc": "2026-07-18T12:00:00+00:00",
            "evidence_refs": evidence_refs,
            "rationale": "Repository evidence establishes causal AI authorship.",
        }
        entry["secondary_review"] = {
            "reviewer_id": "independent-secondary",
            "label": "AI_CAUSAL",
            "reviewed_at_utc": "2026-07-18T12:01:00+00:00",
            "evidence_refs": evidence_refs,
            "rationale": "Independently verified causal AI authorship.",
        }
        entry["resolved_label"] = "AI_CAUSAL"
        entry["resolution"] = {
            "status": "agreed",
            "resolver_id": None,
            "resolved_at_utc": None,
            "evidence_refs": [],
            "rationale": "",
        }
    labels_commit = _commit_fixture_artifact(
        repo_root,
        labels_path,
        labels,
        message="Track held-out labels after selection",
    )
    verifier_contract = _commit_minimal_verifier_scope(repo_root)
    quality = heldout.recompute_archived_quality_evidence(
        selection,
        labels,
        precision_target=0.95,
        recall_target=0.95,
        require_certified=True,
    )
    boundary = selection["measurement_boundary"]
    heldout_report = {
        "schema_version": 2,
        "evaluation_kind": "independent_heldout_fixed_campaign_detector_quality",
        "selection_manifest_sha256": selection["selection_manifest_sha256"],
        "campaign": selection["campaign"],
        "evaluation_complete": quality["evaluation_complete"],
        "targets": {
            "precision": 0.95,
            "recall": 0.95,
            "require_certified": True,
        },
        "precision": quality["precision"],
        "recall": quality["recall"],
        "denominators": quality["denominators"],
        "strata": quality["strata"],
        "point_gate_passed": quality["point_gate_passed"],
        "certified_gate_passed": quality["certified_gate_passed"],
        "release_gate_passed": quality["release_gate_passed"],
        "measurement_boundary": boundary,
        "manual_evidence": {
            "label_file_sha256": _canonical_sha256(labels),
            "artifact_order": {
                "selection_commit_reference": selection_reference,
                "selection_commit": selection_commit,
                "selection_path": selection_path,
                "labels_commit": labels_commit,
                "labels_path": labels_path,
                "labels_blob_sha256": hashlib.sha256(
                    heldout.canonical_artifact_bytes(labels)
                ).hexdigest(),
                "selection_is_strict_ancestor": True,
                "labels_absent_from_selection_commit": True,
                "labels_exact_bytes_tracked_at_head": True,
            },
            "independent_audit_attested": True,
        },
    }
    campaign_contract = {
        "schema_version": 2,
        "campaign_id": campaign_id,
        "repo_root": str(repo_root),
        "marker_dir": str(marker_dir),
        "result_dir": str(result_dir),
        "contract_sha256": "4" * 64,
        "analyzer_contract_sha256": analyzer_contract_sha256,
        "signature_sha256": signature_sha256,
        "alias_class_manifest_sha256": alias_manifest["classes_sha256"],
        "source_snapshot_sha256": _canonical_sha256(
            source_snapshot,
            ensure_ascii=True,
        ),
        "model": "gpt-5.6-luna",
        "reasoning_effort": "max",
        "workers": 32,
        "marker_schema_version": refresh_runner.MARKER_SCHEMA_VERSION,
        "litellm_transport_sha256": litellm_transport_sha256,
        "litellm_transport": litellm_transport,
        "batch_timeout_seconds": refresh_runner.BATCH_TIMEOUT_SECONDS,
        "campaign_mode": "formal",
        "population_policy": "formal_full",
        "alias_class_manifest": alias_manifest,
        "incremental_plan_proof": incremental_plan_proof,
        "batches": [
            {
                "key": "grouped-001",
                "path": str(batch_path),
                "ids": [entry["subject_id"] for entry in results],
                "class_ids": [
                    class_records[entry["subject_id"]]["class_id"] for entry in results
                ],
                "command": batch_command,
                "batch_sha256": batch_sha256,
                "command_sha256": command_sha256,
                "batch_bytes_base64": base64.b64encode(batch_bytes).decode("ascii"),
                "marker_bytes_base64": base64.b64encode(marker_bytes).decode("ascii"),
            }
        ],
    }
    recall_selection_digest = "b" * 64
    recall_selection = {
        "selection_manifest_sha256": recall_selection_digest,
        "inventory": {
            "inventory_id": detector_inventory["inventory_id"],
            "source_snapshot_sha256": detector_inventory["source_snapshot_sha256"],
            "campaign_id": detector_inventory["campaign_id"],
            "campaign_mode": "formal",
            "complete": True,
        },
    }
    recall_labels = {"selection_manifest_sha256": recall_selection_digest}
    recall_report = {
        "schema_version": 2,
        "evaluation_kind": "stratified_end_to_end_finite_population_recall",
        "selection_manifest_sha256": recall_selection_digest,
        "selection_replayed_from_inventory": True,
        "artifact_order": {"selection_commit": "1" * 40},
        "evaluation_complete": True,
        "evaluation_blockers": [],
        "resolved_labels": {"packet": "AI_CAUSAL"},
        "unresolved_packet_ids": [],
        "coverage_failure_count": 0,
        "protected_overlap_class_count": 0,
        "protected_census_manifest_sha256": "4" * 64,
        "protected_census_complete": True,
        "protected_census_resolved_labels": {},
        "protected_census_unresolved_packet_ids": [],
        "protected_excluded_class_count": 0,
        "covered_unprotected_diagnostic_complete": True,
        "recall": {
            "recall_point": 1.0,
            "recall_interval": [1.0, 1.0],
            "protected_census": {"class_count": 0},
        },
    }
    receipt = {
        "schema_version": 4,
        "generation_id": generation_id,
        "generated_at": "2026-07-18T13:00:00+00:00",
        "campaign_id": campaign_id,
        "contract_sha256": "4" * 64,
        "campaign_contract_sha256": _canonical_sha256(campaign_contract),
        "campaign_result_dir": campaign_contract["result_dir"],
        "campaign_result_count": len(results),
        "campaign_result_manifest_sha256": _canonical_sha256(results),
        "campaign_mode": "formal",
        "population_policy": "formal_full",
        "analyzer_contract_sha256": analyzer_contract_sha256,
        "signature_sha256": signature_sha256,
        "alias_class_manifest_sha256": alias_manifest["classes_sha256"],
        "source_snapshot_sha256": _canonical_sha256(
            source_snapshot,
            ensure_ascii=True,
        ),
        "source_remote_cutoff": cutoff,
        "publication_bundle_sha256": publication_bundle_sha256,
        "publication_manifest_sha256": _canonical_sha256(publication_files),
        "detector_report_sha256": _canonical_sha256(detector_report),
        "detector_inventory_id": detector_inventory["inventory_id"],
        "detector_inventory_sha256": _canonical_sha256(detector_inventory),
        "detector_inventory_campaign_mode": "formal",
        "detector_inventory_complete": True,
        "detector_inventory_source_snapshot_sha256": detector_inventory[
            "source_snapshot_sha256"
        ],
        "detector_inventory_alias_class_manifest_sha256": detector_inventory[
            "source_alias_class_manifest_sha256"
        ],
        "detector_inventory_alias_class_count": detector_inventory["alias_class_count"],
        "fixed_campaign_proof_sha256": _canonical_sha256(fixed_proof),
        "publication_curation_consistency_report_sha256": _canonical_sha256(
            curation_report
        ),
        "publication_curation_inputs_sha256": _canonical_sha256(curation_inputs),
        "heldout_selection_sha256": _canonical_sha256(selection),
        "heldout_labels_sha256": _canonical_sha256(labels),
        "heldout_campaign_population_sha256": _canonical_sha256(
            heldout_campaign_population
        ),
        "heldout_quality_report_sha256": _canonical_sha256(heldout_report),
        "heldout_campaign_proof_sha256": heldout_report["campaign"][
            "campaign_proof_sha256"
        ],
        "heldout_campaign_result_manifest_sha256": heldout_report["campaign"][
            "campaign_result_manifest_sha256"
        ],
        "recall_selection_sha256": _canonical_sha256(recall_selection),
        "recall_labels_sha256": _canonical_sha256(recall_labels),
        "recall_report_sha256": _canonical_sha256(recall_report),
        "recall_inventory_id": detector_inventory["inventory_id"],
        "recall_selection_manifest_sha256": recall_selection_digest,
        "protected_census_manifest_sha256": "4" * 64,
        "protected_overlap_class_count": 0,
        "protected_census_complete": True,
        "recall_evaluation_status": "complete_end_to_end",
        "recall_evaluation_complete": True,
        "recall_point_estimate": 1.0,
        "recall_interval": [1.0, 1.0],
        "verifier_contract_sha256": _canonical_sha256(verifier_contract),
        "verifier_git_commit": verifier_contract["git_commit"],
        "verifier_git_tree": verifier_contract["git_tree"],
        "verifier_files_manifest_sha256": verifier_contract["files_manifest_sha256"],
        "verifier_dependency_lock_sha256": verifier_contract["dependency_lock_sha256"],
        "evaluation_complete": True,
        "release_safe": True,
        "curation_consistent": True,
        "heldout_certified": True,
        "targets": {"precision": 0.95, "recall": 0.95},
        "curation_consistency_point_estimates": {
            "precision": 1.0,
            "recall": 1.0,
        },
        "heldout_point_estimates": {"precision": 1.0, "recall": 1.0},
        "heldout_measurement_boundary": boundary,
        "model": campaign_contract["model"],
        "reasoning_effort": campaign_contract["reasoning_effort"],
        "workers": campaign_contract["workers"],
        "litellm_transport_sha256": campaign_contract["litellm_transport_sha256"],
    }
    return {
        "campaign-contract.json": campaign_contract,
        "campaign-result-manifest.json": {
            "schema_version": 1,
            "campaign_id": receipt["campaign_id"],
            "result_count": len(results),
            "manifest_sha256": receipt["campaign_result_manifest_sha256"],
            "results": results,
        },
        "detector-report.json": detector_report,
        "detector-inventory.json": detector_inventory,
        "heldout-selection.json": selection,
        "heldout-labels.json": labels,
        "heldout-campaign-population.json": heldout_campaign_population,
        "heldout-quality-report.json": heldout_report,
        "publication-manifest.json": {
            "schema_version": 1,
            "generation_id": generation_id,
            "publication_bundle_sha256": receipt["publication_bundle_sha256"],
            "manifest_sha256": receipt["publication_manifest_sha256"],
            "files": publication_files,
        },
        "publication-curation-consistency-report.json": curation_report,
        "publication-curation-inputs.json": curation_inputs,
        "recall-selection.json": recall_selection,
        "recall-labels.json": recall_labels,
        "recall-report.json": recall_report,
        "release-receipt.json": receipt,
        "source-remote-cutoff.json": cutoff,
        "source-snapshot.json": source_snapshot,
        "verifier-contract.json": verifier_contract,
    }


def _publication_entry(cve_id: str) -> dict:
    return {
        "id": cve_id,
        "description": "A test vulnerability",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwes": [],
        "ecosystem": "",
        "published": "2026-06-01",
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


def _publication_stats(entries: list[dict]) -> dict:
    count = len(entries)
    return {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "total_cves": count,
        "total_analyzed": max(1, count),
        "with_fix_commits": 0,
        "coverage_from": "2026-01-01",
        "coverage_to": "2026-06-01" if entries else "",
        "by_tool": {"cursor": count} if count else {},
        "by_severity": {"HIGH": count} if count else {},
        "by_language": {"Python": count} if count else {},
        "by_repo": {},
        "by_month": [
            {
                "month": "2026-06",
                "count": count,
                "by_tool": {"cursor": count},
            }
        ]
        if entries
        else [],
    }


def _direct_recall_evidence_fixture(
    tmp_path: Path,
) -> tuple[dict, dict, dict, dict, dict]:
    studies = tmp_path / "scripts/heldout_studies"
    studies.mkdir(parents=True)
    selection_digest = "a" * 64
    inventory_id = "b" * 64
    inventory = {
        "inventory_id": inventory_id,
        "source_snapshot_sha256": "c" * 64,
        "source_alias_class_manifest_sha256": "e" * 64,
        "campaign_id": "d" * 64,
        "rows": [{"member_ids": ["CVE-2026-1"]}],
    }
    protected_inputs = {
        "policy": recall_audit.PROTECTED_INPUT_POLICY,
        "source_roots": [],
        "files": [],
        "files_manifest_sha256": recall_audit.canonical_sha256([]),
        "subject_id_count": 0,
        "subject_ids_sha256": recall_audit.canonical_sha256([]),
    }
    census = recall_audit._build_protected_census_manifest(
        inventory,
        protected_inputs,
        [],
    )
    selection = {
        "selection_manifest_sha256": selection_digest,
        "inventory": {
            "inventory_id": inventory_id,
            "source_snapshot_sha256": "c" * 64,
            "source_alias_class_manifest_sha256": "e" * 64,
            "campaign_id": "d" * 64,
            "campaign_mode": "formal",
            "complete": True,
        },
        "protected_inputs": protected_inputs,
        "protected_census": census,
        "population": {"protected_excluded_class_count": 0},
    }
    audit_protocol: dict = {}
    labels = {
        "selection_manifest_sha256": selection_digest,
        "audit_protocol": audit_protocol,
        "protected_census": {
            "schema_version": recall_audit.PROTECTED_CENSUS_LABEL_SCHEMA_VERSION,
            "kind": "protected_alias_class_census_independent_audit",
            "census_manifest_sha256": census["census_manifest_sha256"],
            "audit_protocol_sha256": recall_audit.canonical_sha256(audit_protocol),
            "adjudications": [],
        },
    }
    report = {
        "schema_version": 2,
        "evaluation_kind": "stratified_end_to_end_finite_population_recall",
        "selection_manifest_sha256": selection_digest,
        "selection_replayed_from_inventory": True,
        "artifact_order": {
            "selection_path": "scripts/heldout_studies/recall-selection.json",
            "labels_path": "scripts/heldout_studies/recall-labels.json",
        },
        "evaluation_complete": True,
        "evaluation_blockers": [],
        "resolved_labels": {"packet": "AI_CAUSAL"},
        "unresolved_packet_ids": [],
        "coverage_failure_count": 0,
        "protected_overlap_class_count": 0,
        "protected_census_manifest_sha256": census["census_manifest_sha256"],
        "protected_census_complete": True,
        "protected_census_resolved_labels": {},
        "protected_census_unresolved_packet_ids": [],
        "protected_excluded_class_count": 0,
        "covered_unprotected_diagnostic_complete": True,
        "recall": {
            "recall_point": 1.0,
            "recall_interval": [1.0, 1.0],
            "protected_census": {"class_count": 0},
        },
    }
    receipt = {
        "recall_inventory_id": inventory_id,
        "recall_selection_manifest_sha256": selection_digest,
        "protected_census_manifest_sha256": census["census_manifest_sha256"],
        "protected_overlap_class_count": 0,
        "protected_census_complete": True,
        "recall_evaluation_status": "complete_end_to_end",
        "recall_evaluation_complete": True,
        "recall_point_estimate": 1.0,
        "recall_interval": [1.0, 1.0],
        "targets": {"precision": 0.95, "recall": 0.95},
    }
    return selection, labels, report, inventory, receipt


def _attach_direct_protected_census(
    selection: dict,
    labels: dict,
    report: dict,
    inventory: dict,
    receipt: dict,
    *,
    primary: str = "AI_CAUSAL",
    secondary: str = "AI_CAUSAL",
) -> None:
    subject_id = "CVE-2026-1"
    component_sha256 = hashlib.sha256(f"{subject_id}\n".encode()).hexdigest()
    row = {
        "class_id": subject_id,
        "component_sha256": component_sha256,
        "analysis_subject": subject_id,
        "member_ids": [subject_id],
        "recall_stratum": "detected_positive",
    }
    inventory["rows"] = [row]
    census = recall_audit._build_protected_census_manifest(
        inventory,
        selection["protected_inputs"],
        [row],
    )
    selection["protected_census"] = census
    selection["population"]["protected_excluded_class_count"] = 1
    packet_id = census["assignments"][0]["packet_id"]

    def review(reviewer_id: str, label: str) -> dict:
        return {
            "reviewer_id": reviewer_id,
            "label": label,
            "evidence_refs": ["pr:https://example.invalid/pull/1"],
            "rationale": "Repository evidence establishes the causal label.",
        }

    labels["protected_census"] = {
        "schema_version": recall_audit.PROTECTED_CENSUS_LABEL_SCHEMA_VERSION,
        "kind": "protected_alias_class_census_independent_audit",
        "census_manifest_sha256": census["census_manifest_sha256"],
        "audit_protocol_sha256": recall_audit.canonical_sha256(
            labels["audit_protocol"]
        ),
        "adjudications": [
            {
                "packet_id": packet_id,
                "primary_review": review("census-reviewer-a", primary),
                "secondary_review": review("census-reviewer-b", secondary),
                "third_review": None,
            }
        ],
    }
    report.update(
        {
            "protected_overlap_class_count": 1,
            "protected_census_manifest_sha256": census["census_manifest_sha256"],
            "protected_census_complete": True,
            "protected_census_resolved_labels": {packet_id: "AI_CAUSAL"},
            "protected_census_unresolved_packet_ids": [],
        }
    )
    report["recall"]["protected_census"] = {"class_count": 1}
    receipt.update(
        {
            "protected_census_manifest_sha256": census["census_manifest_sha256"],
            "protected_overlap_class_count": 1,
            "protected_census_complete": True,
        }
    )


def test_recall_evidence_replays_exact_inventory_and_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection, labels, report, inventory, receipt = _direct_recall_evidence_fixture(
        tmp_path
    )
    monkeypatch.setattr(
        recall_audit,
        "_rebuild_authoritative_protected_inventory",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        recall_audit,
        "evaluate_labels",
        lambda *_args, **_kwargs: report,
    )

    _REAL_VALIDATE_RECALL_EVIDENCE(
        selection=selection,
        labels=labels,
        report=report,
        inventory=inventory,
        receipt=receipt,
        trusted_repo_root=tmp_path,
    )


def test_recall_evidence_accepts_complete_sealed_protected_census(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection, labels, report, inventory, receipt = _direct_recall_evidence_fixture(
        tmp_path
    )
    _attach_direct_protected_census(selection, labels, report, inventory, receipt)
    monkeypatch.setattr(
        recall_audit,
        "_rebuild_authoritative_protected_inventory",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        recall_audit,
        "evaluate_labels",
        lambda *_args, **_kwargs: report,
    )

    _REAL_VALIDATE_RECALL_EVIDENCE(
        selection=selection,
        labels=labels,
        report=report,
        inventory=inventory,
        receipt=receipt,
        trusted_repo_root=tmp_path,
    )


def test_recall_evidence_rejects_unknown_or_manifest_drift_in_protected_census(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection, labels, report, inventory, receipt = _direct_recall_evidence_fixture(
        tmp_path
    )
    _attach_direct_protected_census(
        selection,
        labels,
        report,
        inventory,
        receipt,
        primary="UNKNOWN",
        secondary="AI_CAUSAL",
    )
    monkeypatch.setattr(
        recall_audit,
        "_rebuild_authoritative_protected_inventory",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        recall_audit,
        "evaluate_labels",
        lambda *_args, **_kwargs: report,
    )

    with pytest.raises(ReleaseEvidenceError, match="incomplete|not bound"):
        _REAL_VALIDATE_RECALL_EVIDENCE(
            selection=selection,
            labels=labels,
            report=report,
            inventory=inventory,
            receipt=receipt,
            trusted_repo_root=tmp_path,
        )

    labels["protected_census"]["adjudications"][0]["primary_review"]["label"] = (
        "AI_CAUSAL"
    )
    selection["protected_census"]["inventory"]["source_alias_class_manifest_sha256"] = (
        "f" * 64
    )
    selection["protected_census"]["census_manifest_sha256"] = (
        recall_audit.protected_census_sha256(selection["protected_census"])
    )
    labels["protected_census"]["census_manifest_sha256"] = selection[
        "protected_census"
    ]["census_manifest_sha256"]
    report["protected_census_manifest_sha256"] = selection["protected_census"][
        "census_manifest_sha256"
    ]
    with pytest.raises(ReleaseEvidenceError, match="incomplete|not bound"):
        _REAL_VALIDATE_RECALL_EVIDENCE(
            selection=selection,
            labels=labels,
            report=report,
            inventory=inventory,
            receipt=receipt,
            trusted_repo_root=tmp_path,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evaluation_complete", False),
        ("evaluation_blockers", ["campaign_coverage_failures"]),
        ("coverage_failure_count", 1),
        ("protected_excluded_class_count", 1),
        ("unresolved_packet_ids", ["packet"]),
        ("resolved_labels", {"packet": "UNKNOWN"}),
        ("recall", None),
    ],
)
def test_recall_evidence_rejects_incomplete_formal_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    selection, labels, report, inventory, receipt = _direct_recall_evidence_fixture(
        tmp_path
    )
    report[field] = value
    monkeypatch.setattr(
        recall_audit,
        "_rebuild_authoritative_protected_inventory",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        recall_audit,
        "evaluate_labels",
        lambda *_args, **_kwargs: report,
    )

    with pytest.raises(ReleaseEvidenceError, match="incomplete|not bound"):
        _REAL_VALIDATE_RECALL_EVIDENCE(
            selection=selection,
            labels=labels,
            report=report,
            inventory=inventory,
            receipt=receipt,
            trusted_repo_root=tmp_path,
        )


def test_recall_evidence_rejects_correlated_reseal_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection, labels, report, inventory, receipt = _direct_recall_evidence_fixture(
        tmp_path
    )
    recomputed = json.loads(json.dumps(report))
    report["recall"]["recall_point"] = 0.5
    report["recall"]["recall_interval"] = [0.5, 0.5]
    receipt["recall_point_estimate"] = 0.5
    receipt["recall_interval"] = [0.5, 0.5]
    monkeypatch.setattr(
        recall_audit,
        "_rebuild_authoritative_protected_inventory",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        recall_audit,
        "evaluate_labels",
        lambda *_args, **_kwargs: recomputed,
    )

    with pytest.raises(ReleaseEvidenceError, match="does not recompute"):
        _REAL_VALIDATE_RECALL_EVIDENCE(
            selection=selection,
            labels=labels,
            report=report,
            inventory=inventory,
            receipt=receipt,
            trusted_repo_root=tmp_path,
        )


@pytest.mark.parametrize(
    ("point", "interval"),
    [
        (0.01, [0.0, 0.02]),
        (1.0, [0.94, 1.0]),
    ],
)
def test_recall_evidence_requires_point_and_interval_to_meet_receipt_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    point: float,
    interval: list[float],
) -> None:
    selection, labels, report, inventory, receipt = _direct_recall_evidence_fixture(
        tmp_path
    )
    report["recall"] = {
        **report["recall"],
        "recall_point": point,
        "recall_interval": interval,
    }
    receipt["recall_point_estimate"] = point
    receipt["recall_interval"] = interval
    monkeypatch.setattr(
        recall_audit,
        "_rebuild_authoritative_protected_inventory",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        recall_audit,
        "evaluate_labels",
        lambda *_args, **_kwargs: report,
    )

    with pytest.raises(ReleaseEvidenceError, match="do not meet.*target"):
        _REAL_VALIDATE_RECALL_EVIDENCE(
            selection=selection,
            labels=labels,
            report=report,
            inventory=inventory,
            receipt=receipt,
            trusted_repo_root=tmp_path,
        )


def _publication_file_manifest(root: Path) -> list[dict]:
    paths = [root / "index.json", root / "stats.json", root / "inventory.json"]
    paths.extend(sorted((root / "cves").glob("*.json")))
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "size_bytes": len(content := path.read_bytes()),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for path in paths
    ]


def _activation_fixture(
    tmp_path: Path,
    *,
    with_previous: bool = True,
) -> tuple[writer.StagedWebData, Path, dict, dict, Path]:
    output_dir = tmp_path / "published"
    if with_previous:
        previous_entries = [_publication_entry("CVE-2025-10000")]
        writer.write_web_data(
            previous_entries,
            _publication_stats(previous_entries),
            output_dir,
            generated_at="2026-01-01T00:00:00+00:00",
            allow_unreceipted=True,
        )

    candidate_entries = [_publication_entry("CVE-2026-10000")]
    preliminary_index_bytes = (
        json.dumps(
            {
                "schema_version": 1,
                "generation_id": "0" * 64,
                "generated_at": "2026-07-18T13:00:00+00:00",
                "total": 1,
                "ids": ["CVE-2026-10000"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    preliminary_artifacts = _artifacts(
        "0" * 64,
        publication_index_bytes=preliminary_index_bytes,
    )
    detector_inventory = preliminary_artifacts["detector-inventory.json"]
    candidate_stats = _publication_stats(candidate_entries)
    candidate_stats["inventory"] = web_generator._inventory_summary(detector_inventory)
    staged = writer.stage_web_data(
        candidate_entries,
        candidate_stats,
        output_dir,
        generated_at="2026-07-18T13:00:00+00:00",
        inventory=detector_inventory,
    )
    publication = writer.load_published_web_data(staged.staging_dir)
    generation_id = publication.index["generation_id"]
    publication_hash = writer.publication_bundle_sha256(publication)
    publication_files = _publication_file_manifest(staged.staging_dir)
    artifacts = _artifacts(
        generation_id,
        publication_bundle_sha256=publication_hash,
        publication_files=publication_files,
        publication_index_bytes=(staged.staging_dir / "index.json").read_bytes(),
    )
    assert artifacts["detector-inventory.json"] == detector_inventory
    receipt = artifacts["release-receipt.json"]
    writer.write_staged_release_receipt(staged, receipt)
    root = tmp_path / "release-evidence-v1"
    bundle = archive_release_evidence(
        root=root,
        generation_id=generation_id,
        generated_at="2026-07-18T13:00:00+00:00",
        artifacts=artifacts,
    )
    bindings = {
        "root": root,
        "generation_id": generation_id,
        "evidence_bundle_sha256": bundle.bundle_sha256,
        "release_receipt_sha256": _canonical_sha256(receipt),
        "publication_bundle_sha256": publication_hash,
        "publication_manifest_sha256": _canonical_sha256(publication_files),
        "output_dir": output_dir,
        "candidate_dir": staged.staging_dir,
    }
    return staged, root, receipt, bindings, output_dir


def test_archive_is_atomic_validated_and_idempotent(tmp_path: Path) -> None:
    generation_id = "a" * 64
    artifacts = _artifacts(generation_id)

    first = archive_release_evidence(
        root=tmp_path / "release-evidence-v1",
        generation_id=generation_id,
        generated_at="2026-07-18T13:00:00+00:00",
        artifacts=artifacts,
    )
    second = archive_release_evidence(
        root=tmp_path / "release-evidence-v1",
        generation_id=generation_id,
        generated_at="2026-07-18T13:00:00+00:00",
        artifacts=artifacts,
    )

    assert first.path == second.path
    assert first.bundle_sha256 == second.bundle_sha256
    assert set(child.name for child in first.path.iterdir()) == {
        *artifacts,
        "manifest.json",
        "campaign-results",
    }
    assert len(list((first.path / "campaign-results").iterdir())) == 100
    assert list((tmp_path / "release-evidence-v1").glob(".*.staging-*")) == []


def test_archive_replays_real_recall_census_and_git_order_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the production recall/census validator without any replay stub."""

    generation_id = "9" * 64
    repo_root = tmp_path / "repo"
    artifacts = _artifacts(
        generation_id,
        repo_root=repo_root,
        with_fix_commits=True,
    )
    inventory = artifacts["detector-inventory.json"]
    alias_map: dict[str, set[str]] = {}
    for row in inventory["rows"]:
        component = set(row["member_ids"])
        for member in component:
            alias_map[member] = component

    mandatory_files = {
        "scripts/audit_adjudications.json": "{}\n",
        "scripts/audit_overrides.json": "{}\n",
        "scripts/audit_removed_94.json": "{}\n",
        ".ai-slop/state/data-refresh/adjudicated-corpus-subjects.txt": "",
    }
    for relative, content in mandatory_files.items():
        path = repo_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (repo_root / "scripts/audit_results").mkdir(parents=True)
    (repo_root / "scripts/fixtures").mkdir(parents=True)

    selection_relative = "scripts/heldout_studies/recall-selection-real.json"
    labels_relative = "scripts/heldout_studies/recall-labels-real.json"
    selection_path = repo_root / selection_relative
    labels_path = repo_root / labels_relative
    protected = heldout.build_authoritative_protected_inventory(
        repo_root,
        alias_map=alias_map,
        excluded_paths=(selection_path, labels_path),
    )
    sample_sizes = {
        stratum: sum(row["recall_stratum"] == stratum for row in inventory["rows"])
        for stratum in recall_audit.AUDIT_STRATA
    }
    selection = recall_audit.build_selection_manifest(
        inventory,
        sample_sizes=sample_sizes,
        protected=protected,
        seed="f" * 64,
        seed_origin=recall_audit.SYSTEM_CSPRNG_SEED_ORIGIN,
    )
    selection_commit = _commit_fixture_artifact(
        repo_root,
        selection_relative,
        selection,
        message="Seal real recall selection",
    )
    protocol = recall_audit.required_review_protocol(
        f"{selection_commit}:{selection_relative}"
    )

    def review(reviewer_id: str) -> dict:
        return {
            "reviewer_id": reviewer_id,
            "label": "AI_CAUSAL",
            "evidence_refs": ["repo:https://example.invalid/project"],
            "rationale": "Repository history establishes causal AI authorship.",
        }

    def adjudication(packet_id: str, prefix: str) -> dict:
        return {
            "packet_id": packet_id,
            "primary_review": review(f"{prefix}-primary"),
            "secondary_review": review(f"{prefix}-secondary"),
            "third_review": None,
        }

    census = selection["protected_census"]
    labels = {
        "schema_version": recall_audit.LABEL_SCHEMA_VERSION,
        "kind": "end_to_end_recall_independent_audit",
        "selection_manifest_sha256": selection["selection_manifest_sha256"],
        "audit_protocol": protocol,
        "adjudications": [
            adjudication(row["packet_id"], "sample") for row in selection["assignments"]
        ],
        "protected_census": {
            "schema_version": recall_audit.PROTECTED_CENSUS_LABEL_SCHEMA_VERSION,
            "kind": "protected_alias_class_census_independent_audit",
            "census_manifest_sha256": census["census_manifest_sha256"],
            "audit_protocol_sha256": recall_audit.canonical_sha256(protocol),
            "adjudications": [
                adjudication(row["packet_id"], "census")
                for row in census["assignments"]
            ],
        },
    }
    _commit_fixture_artifact(
        repo_root,
        labels_relative,
        labels,
        message="Seal real recall labels",
    )
    report = recall_audit.evaluate_labels(
        selection,
        labels,
        inventory=inventory,
        protected=protected,
        selection_path=selection_path,
        labels_path=labels_path,
        repo_root=repo_root,
        verify_artifact_order=True,
    )
    assert report["protected_overlap_class_count"] > 0
    assert report["evaluation_complete"] is True
    assert report["recall"]["recall_interval"][0] >= 0.95

    verifier_contract = _commit_minimal_verifier_scope(repo_root)
    receipt = artifacts["release-receipt.json"]
    artifacts["recall-selection.json"] = selection
    artifacts["recall-labels.json"] = labels
    artifacts["recall-report.json"] = report
    artifacts["verifier-contract.json"] = verifier_contract
    receipt.update(
        {
            "recall_selection_sha256": _canonical_sha256(selection),
            "recall_labels_sha256": _canonical_sha256(labels),
            "recall_report_sha256": _canonical_sha256(report),
            "recall_inventory_id": inventory["inventory_id"],
            "recall_selection_manifest_sha256": selection["selection_manifest_sha256"],
            "protected_census_manifest_sha256": report[
                "protected_census_manifest_sha256"
            ],
            "protected_overlap_class_count": report["protected_overlap_class_count"],
            "protected_census_complete": True,
            "recall_point_estimate": report["recall"]["recall_point"],
            "recall_interval": report["recall"]["recall_interval"],
            "verifier_contract_sha256": _canonical_sha256(verifier_contract),
            "verifier_git_commit": verifier_contract["git_commit"],
            "verifier_git_tree": verifier_contract["git_tree"],
            "verifier_files_manifest_sha256": verifier_contract[
                "files_manifest_sha256"
            ],
            "verifier_dependency_lock_sha256": verifier_contract[
                "dependency_lock_sha256"
            ],
        }
    )
    monkeypatch.setattr(
        release_evidence,
        "_validate_recall_evidence",
        _REAL_VALIDATE_RECALL_EVIDENCE,
    )

    bundle = archive_release_evidence(
        root=tmp_path / "release-evidence-v1",
        generation_id=generation_id,
        generated_at="2026-07-18T13:00:00+00:00",
        artifacts=artifacts,
    )

    assert (
        validate_release_evidence(
            bundle.path,
            trusted_repo_root=repo_root,
        ).bundle_sha256
        == bundle.bundle_sha256
    )


@pytest.mark.parametrize(
    "name",
    ["recall-selection.json", "recall-labels.json", "recall-report.json"],
)
def test_archive_rejects_missing_required_recall_artifact(
    tmp_path: Path,
    name: str,
) -> None:
    generation_id = "2" * 64
    artifacts = _artifacts(generation_id)
    del artifacts[name]

    with pytest.raises(ReleaseEvidenceError, match="payload inventory mismatch"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize("bound", ["per_artifact", "aggregate"])
def test_archive_rejects_oversized_primary_artifact_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bound: str,
) -> None:
    generation_id = "6" * 64
    artifacts = _artifacts(generation_id)
    sizes = [
        len(release_evidence._canonical_bytes(payload))
        for payload in artifacts.values()
    ]
    if bound == "per_artifact":
        monkeypatch.setattr(
            release_evidence,
            "_MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES",
            max(sizes) - 1,
        )
    else:
        monkeypatch.setattr(
            release_evidence,
            "_MAX_RELEASE_EVIDENCE_ARTIFACTS_TOTAL_BYTES",
            sum(sizes) - 1,
        )

    root = tmp_path / "release-evidence-v1"
    with pytest.raises(ReleaseEvidenceError, match="size bound"):
        archive_release_evidence(
            root=root,
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )
    assert not (root / generation_id).exists()


def test_formal_artifact_order_replay_rejects_nonexistent_git_objects(
    tmp_path: Path,
) -> None:
    generation_id = "0" * 64
    artifacts = _artifacts(generation_id)
    bundle = archive_release_evidence(
        root=tmp_path / "release-evidence-v1",
        generation_id=generation_id,
        generated_at="2026-07-18T13:00:00+00:00",
        artifacts=artifacts,
    )
    repo_root = Path(artifacts["campaign-contract.json"]["repo_root"])
    (repo_root / ".git").rename(repo_root / ".git-detached")

    with pytest.raises(
        ReleaseEvidenceError,
        match="formal verifier contract does not replay",
    ):
        validate_archived_artifact_order(bundle.path)


def test_artifact_order_rejects_bundle_declared_alternate_repository(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts("7" * 64)
    trusted_root = Path(artifacts["campaign-contract.json"]["repo_root"])
    alternate_root = tmp_path / "alternate-repository"
    subprocess.run(
        ["git", "init", "-q", str(alternate_root)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    artifacts["campaign-contract.json"]["repo_root"] = str(alternate_root)

    with pytest.raises(ReleaseEvidenceError, match="trusted verifier repository"):
        release_evidence._validate_committed_artifact_order(
            artifacts,
            trusted_repo_root=trusted_root,
        )


def test_validation_fails_closed_after_artifact_tampering(tmp_path: Path) -> None:
    generation_id = "b" * 64
    bundle = archive_release_evidence(
        root=tmp_path / "release-evidence-v1",
        generation_id=generation_id,
        generated_at="2026-07-18T13:00:00+00:00",
        artifacts=_artifacts(generation_id),
    )
    detector_path = bundle.path / "detector-report.json"
    detector_path.write_text('{"evaluation_complete":false}\n', encoding="utf-8")

    with pytest.raises(ReleaseEvidenceError, match="artifact hashes"):
        validate_release_evidence(bundle.path)


def test_release_evidence_reader_rejects_symlinks_without_following_them(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"safe":true}\n', encoding="utf-8")
    link = tmp_path / "artifact.json"
    link.symlink_to(target)

    with pytest.raises(ReleaseEvidenceError, match="cannot open"):
        release_evidence._stable_regular_file(
            link,
            "release artifact",
            max_bytes=release_evidence._MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES,
        )


def test_existing_generation_cannot_be_replaced(tmp_path: Path) -> None:
    generation_id = "c" * 64
    root = tmp_path / "release-evidence-v1"
    original = _artifacts(generation_id)
    archive_release_evidence(
        root=root,
        generation_id=generation_id,
        generated_at="2026-07-18T13:00:00+00:00",
        artifacts=original,
    )
    changed = json.loads(json.dumps(original))
    changed["detector-report.json"]["sample_count"] = 2

    with pytest.raises(ReleaseEvidenceError, match="different contents"):
        archive_release_evidence(
            root=root,
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=changed,
        )


def test_invalid_cross_artifact_proof_never_publishes_a_bundle(
    tmp_path: Path,
) -> None:
    generation_id = "d" * 64
    root = tmp_path / "release-evidence-v1"
    artifacts = _artifacts(generation_id)
    artifacts["release-receipt.json"]["detector_report_sha256"] = "0" * 64

    with pytest.raises(ReleaseEvidenceError, match="detector report hash"):
        archive_release_evidence(
            root=root,
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )

    assert not (root / generation_id).exists()
    assert list(root.glob(".*.staging-*")) == []


def test_validator_rejects_resealed_malformed_source_snapshot(
    tmp_path: Path,
) -> None:
    generation_id = "8" * 64
    artifacts = _artifacts(generation_id)
    source_snapshot = artifacts["source-snapshot.json"]
    source_snapshot["nvd_feeds"].pop(0)
    snapshot_sha256 = _canonical_sha256(source_snapshot, ensure_ascii=True)
    contract = artifacts["campaign-contract.json"]
    contract["source_snapshot_sha256"] = snapshot_sha256
    receipt = artifacts["release-receipt.json"]
    receipt["source_snapshot_sha256"] = snapshot_sha256
    receipt["campaign_contract_sha256"] = _canonical_sha256(contract)

    with pytest.raises(ReleaseEvidenceError, match="source snapshot exact schema"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_recomputes_heldout_metrics_from_archived_labels(
    tmp_path: Path,
) -> None:
    generation_id = "1" * 64
    artifacts = _artifacts(generation_id)
    report = artifacts["heldout-quality-report.json"]
    report["precision"]["successes"] = 58
    artifacts["release-receipt.json"]["heldout_quality_report_sha256"] = (
        _canonical_sha256(report)
    )

    with pytest.raises(ReleaseEvidenceError, match="does not recompute"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_rejects_label_schema_or_membership_drift(tmp_path: Path) -> None:
    generation_id = "2" * 64
    artifacts = _artifacts(generation_id)
    labels = artifacts["heldout-labels.json"]
    labels["adjudications"][0]["lanes"] = []
    report = artifacts["heldout-quality-report.json"]
    report["manual_evidence"]["label_file_sha256"] = _canonical_sha256(labels)
    report["manual_evidence"]["artifact_order"]["labels_blob_sha256"] = hashlib.sha256(
        heldout.canonical_artifact_bytes(labels)
    ).hexdigest()
    receipt = artifacts["release-receipt.json"]
    receipt["heldout_labels_sha256"] = _canonical_sha256(labels)
    receipt["heldout_quality_report_sha256"] = _canonical_sha256(report)

    with pytest.raises(
        ReleaseEvidenceError, match="committed Git object|labels/metrics are invalid"
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_rejects_resealed_non_independent_dual_reviews(
    tmp_path: Path,
) -> None:
    generation_id = "3" * 64
    artifacts = _artifacts(generation_id)
    labels = artifacts["heldout-labels.json"]
    entry = labels["adjudications"][0]
    entry["secondary_review"]["reviewer_id"] = (
        f"  {entry['primary_review']['reviewer_id'].upper()}  "
    )
    report = artifacts["heldout-quality-report.json"]
    report["manual_evidence"]["label_file_sha256"] = _canonical_sha256(labels)
    report["manual_evidence"]["artifact_order"]["labels_blob_sha256"] = hashlib.sha256(
        heldout.canonical_artifact_bytes(labels)
    ).hexdigest()
    receipt = artifacts["release-receipt.json"]
    receipt["heldout_labels_sha256"] = _canonical_sha256(labels)
    receipt["heldout_quality_report_sha256"] = _canonical_sha256(report)

    with pytest.raises(
        ReleaseEvidenceError, match="committed Git object|labels/metrics are invalid"
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_rejects_a_tampered_selection_seal(tmp_path: Path) -> None:
    generation_id = "6" * 64
    artifacts = _artifacts(generation_id)
    selection = artifacts["heldout-selection.json"]
    selection["algorithm"] = "tampered"
    artifacts["release-receipt.json"]["heldout_selection_sha256"] = _canonical_sha256(
        selection
    )

    with pytest.raises(ReleaseEvidenceError, match="selection seal is invalid"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_independently_enforces_the_95_percent_target_floor(
    tmp_path: Path,
) -> None:
    generation_id = "7" * 64
    artifacts = _artifacts(generation_id)
    artifacts["release-receipt.json"]["targets"]["precision"] = 0.94

    with pytest.raises(ReleaseEvidenceError, match="below 95%"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize("metric", ["curation_precision", "curation_recall"])
def test_validator_rejects_curation_points_below_the_release_target(
    tmp_path: Path,
    metric: str,
) -> None:
    generation_id = "e" * 64
    artifacts = _artifacts(generation_id)
    report = artifacts["publication-curation-consistency-report.json"]
    report[metric]["point"] = 0.5
    receipt = artifacts["release-receipt.json"]
    receipt["curation_consistency_point_estimates"][
        "precision" if metric.endswith("precision") else "recall"
    ] = 0.5
    receipt["publication_curation_consistency_report_sha256"] = _canonical_sha256(
        report
    )

    with pytest.raises(ReleaseEvidenceError, match="curation.*point|curation report"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "lower_bound",
        "confidence_level",
        "consistent_flag",
        "certified_flag",
        "audit_coverage",
        "unresolved_sensitive",
    ],
)
def test_validator_recomputes_curation_confidence_and_every_derived_flag(
    tmp_path: Path,
    mutation: str,
) -> None:
    generation_id = "d" * 64
    artifacts = _artifacts(generation_id)
    report = artifacts["publication-curation-consistency-report.json"]
    if mutation == "lower_bound":
        report["curation_precision"]["lower_bound"] = 1.0
    elif mutation == "confidence_level":
        report["confidence_level"] = 0.90
    elif mutation == "consistent_flag":
        report["curation_consistent"] = False
    elif mutation == "certified_flag":
        report["curation_precision_certified"] = False
        report["curation_certified"] = False
    elif mutation == "audit_coverage":
        report["audit_coverage"] = 0.5
    else:
        report["curation_recall_unresolved_sensitive"]["lower"] = 0.5
    artifacts["release-receipt.json"][
        "publication_curation_consistency_report_sha256"
    ] = _canonical_sha256(report)

    with pytest.raises(ReleaseEvidenceError, match="curation"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("complete", False),
        ("incremental_plan_complete", True),
        ("full_incremental_plan_campaign_complete", True),
        ("proof_scope", "partial_campaign"),
    ],
)
def test_validator_independently_enforces_complete_incremental_campaign_proof(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    generation_id = "8" * 64
    artifacts = _artifacts(generation_id)
    proof = artifacts["detector-report.json"]["fixed_contract_campaign_proof"]
    proof[field] = value
    receipt = artifacts["release-receipt.json"]
    receipt["fixed_campaign_proof_sha256"] = _canonical_sha256(proof)
    receipt["detector_report_sha256"] = _canonical_sha256(
        artifacts["detector-report.json"]
    )

    with pytest.raises(ReleaseEvidenceError, match="campaign completeness"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "failure_list",
        "failure_counts",
        "marker_count",
        "subject_count",
        "marker_hash",
        "subject_hash",
        "plan_count",
        "unscheduled_source_class",
    ],
)
def test_validator_requires_exact_complete_campaign_proof_schema(
    tmp_path: Path,
    mutation: str,
) -> None:
    generation_id = "f" * 64
    artifacts = _artifacts(generation_id)
    proof = artifacts["detector-report.json"]["fixed_contract_campaign_proof"]
    if mutation == "failure_list":
        proof["failures"] = [{"code": "contradiction"}]
    elif mutation == "failure_counts":
        proof["failure_counts"] = {"contradiction": 1}
    elif mutation == "marker_count":
        proof["completed_marker_count"] = 0
    elif mutation == "subject_count":
        proof["subject_proofs"].pop()
    elif mutation == "marker_hash":
        proof["marker_proofs"][0]["marker_sha256"] = "invalid"
    elif mutation == "subject_hash":
        proof["subject_proofs"][0]["result_sha256"] = "0" * 64
    elif mutation == "plan_count":
        proof["incremental_plan_proof"]["plan_subject_id_count"] -= 1
    else:
        proof["incremental_plan_proof"]["source_alias_class_count"] += 1
    receipt = artifacts["release-receipt.json"]
    receipt["fixed_campaign_proof_sha256"] = _canonical_sha256(proof)
    receipt["detector_report_sha256"] = _canonical_sha256(
        artifacts["detector-report.json"]
    )

    with pytest.raises(
        ReleaseEvidenceError, match="campaign proof|campaign completeness"
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_rejects_correlated_subject_proof_omission(
    tmp_path: Path,
) -> None:
    generation_id = "0" * 64
    artifacts = _artifacts(generation_id)
    proof = artifacts["detector-report.json"]["fixed_contract_campaign_proof"]
    proof["subject_proofs"].pop()
    proof["required_subject_count"] -= 1
    proof["mapped_subject_count"] -= 1
    proof["campaign_subject_count"] -= 1
    receipt = artifacts["release-receipt.json"]
    receipt["fixed_campaign_proof_sha256"] = _canonical_sha256(proof)
    receipt["detector_report_sha256"] = _canonical_sha256(
        artifacts["detector-report.json"]
    )

    with pytest.raises(ReleaseEvidenceError, match="campaign proof counts"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_requires_inventory_campaign_result_count_set_equality(
    tmp_path: Path,
) -> None:
    generation_id = "3" * 64
    artifacts = _artifacts(generation_id)
    result_manifest = artifacts["campaign-result-manifest.json"]
    result_manifest["results"].pop()
    result_manifest["result_count"] = len(result_manifest["results"])
    result_manifest["manifest_sha256"] = _canonical_sha256(result_manifest["results"])
    population = artifacts["heldout-campaign-population.json"]
    removed_population_entry = population["results"].pop()
    Path(removed_population_entry["source_path"]).unlink()
    population["result_count"] = len(population["results"])
    population["total_result_size_bytes"] = sum(
        entry["size_bytes"] for entry in population["results"]
    )
    population["result_manifest_sha256"] = result_manifest["manifest_sha256"]
    receipt = artifacts["release-receipt.json"]
    receipt["campaign_result_count"] = result_manifest["result_count"]
    receipt["campaign_result_manifest_sha256"] = result_manifest["manifest_sha256"]
    receipt["heldout_campaign_population_sha256"] = _canonical_sha256(population)

    with pytest.raises(ReleaseEvidenceError, match="same alias classes"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize(
    "mutation", ["nonnumeric_plan_count", "malformed_marker_batch"]
)
def test_validator_fails_closed_on_malformed_campaign_proof_types(
    tmp_path: Path,
    mutation: str,
) -> None:
    generation_id = "1" * 64
    artifacts = _artifacts(generation_id)
    proof = artifacts["detector-report.json"]["fixed_contract_campaign_proof"]
    if mutation == "nonnumeric_plan_count":
        proof["incremental_plan_proof"]["cache_covered_discovered_id_count"] = None
    else:
        proof["marker_proofs"][0]["batch"] = None
    receipt = artifacts["release-receipt.json"]
    receipt["fixed_campaign_proof_sha256"] = _canonical_sha256(proof)
    receipt["detector_report_sha256"] = _canonical_sha256(
        artifacts["detector-report.json"]
    )

    with pytest.raises(ReleaseEvidenceError, match="campaign proof"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def _reseal_campaign_artifacts(artifacts: dict[str, dict]) -> None:
    receipt = artifacts["release-receipt.json"]
    proof = artifacts["detector-report.json"]["fixed_contract_campaign_proof"]
    receipt["campaign_contract_sha256"] = _canonical_sha256(
        artifacts["campaign-contract.json"]
    )
    receipt["fixed_campaign_proof_sha256"] = _canonical_sha256(proof)
    receipt["detector_report_sha256"] = _canonical_sha256(
        artifacts["detector-report.json"]
    )


def _reseal_detector_inventory_artifacts(artifacts: dict[str, dict]) -> None:
    inventory = artifacts["detector-inventory.json"]
    inventory.pop("inventory_id", None)
    inventory["inventory_id"] = _canonical_sha256(inventory)
    inventory_bytes = (
        json.dumps(
            inventory,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    report = artifacts["detector-report.json"]
    report["detector_inventory"]["inventory_id"] = inventory["inventory_id"]
    selection = artifacts["recall-selection.json"]
    selection["inventory"]["inventory_id"] = inventory["inventory_id"]
    publication_manifest = artifacts["publication-manifest.json"]
    inventory_entry = next(
        entry
        for entry in publication_manifest["files"]
        if entry["path"] == "inventory.json"
    )
    inventory_entry["size_bytes"] = len(inventory_bytes)
    inventory_entry["sha256"] = hashlib.sha256(inventory_bytes).hexdigest()
    publication_manifest["manifest_sha256"] = _canonical_sha256(
        publication_manifest["files"]
    )

    receipt = artifacts["release-receipt.json"]
    receipt["detector_inventory_id"] = inventory["inventory_id"]
    receipt["detector_inventory_sha256"] = _canonical_sha256(inventory)
    receipt["detector_report_sha256"] = _canonical_sha256(report)
    receipt["recall_inventory_id"] = inventory["inventory_id"]
    receipt["recall_selection_sha256"] = _canonical_sha256(selection)
    receipt["publication_manifest_sha256"] = publication_manifest["manifest_sha256"]


def _independently_label_selection(artifacts: dict[str, dict], selection: dict) -> dict:
    labels = heldout.build_label_template(selection)
    labels["audit_protocol"] = json.loads(
        json.dumps(artifacts["heldout-labels.json"]["audit_protocol"])
    )
    for entry in labels["adjudications"]:
        evidence_refs = [f"https://evidence.invalid/{entry['sample_id']}"]
        entry["primary_review"] = {
            "reviewer_id": "independent-primary",
            "label": "AI_CAUSAL",
            "reviewed_at_utc": "2026-07-18T12:00:00+00:00",
            "evidence_refs": evidence_refs,
            "rationale": "Repository evidence establishes causal AI authorship.",
        }
        entry["secondary_review"] = {
            "reviewer_id": "independent-secondary",
            "label": "AI_CAUSAL",
            "reviewed_at_utc": "2026-07-18T12:01:00+00:00",
            "evidence_refs": evidence_refs,
            "rationale": "Independently verified causal AI authorship.",
        }
        entry["resolved_label"] = "AI_CAUSAL"
        entry["resolution"] = {
            "status": "agreed",
            "resolver_id": None,
            "resolved_at_utc": None,
            "evidence_refs": [],
            "rationale": "",
        }
    return labels


def _reseal_heldout_artifacts(artifacts: dict[str, dict]) -> None:
    selection = artifacts["heldout-selection.json"]
    selection.pop("selection_manifest_sha256", None)
    selection["selection_manifest_sha256"] = _canonical_sha256(selection)

    labels = artifacts["heldout-labels.json"]
    labels["selection_manifest_sha256"] = selection["selection_manifest_sha256"]
    report = artifacts["heldout-quality-report.json"]
    report["selection_manifest_sha256"] = selection["selection_manifest_sha256"]
    report["campaign"] = json.loads(json.dumps(selection["campaign"]))
    quality = heldout.recompute_archived_quality_evidence(
        selection,
        labels,
        precision_target=0.95,
        recall_target=0.95,
        require_certified=True,
    )
    for field in (
        "evaluation_complete",
        "precision",
        "recall",
        "denominators",
        "strata",
        "point_gate_passed",
        "certified_gate_passed",
        "release_gate_passed",
    ):
        report[field] = quality[field]
    report["manual_evidence"]["label_file_sha256"] = _canonical_sha256(labels)
    report["manual_evidence"]["artifact_order"]["labels_blob_sha256"] = hashlib.sha256(
        heldout.canonical_artifact_bytes(labels)
    ).hexdigest()

    receipt = artifacts["release-receipt.json"]
    receipt["heldout_selection_sha256"] = _canonical_sha256(selection)
    receipt["heldout_labels_sha256"] = _canonical_sha256(labels)
    receipt["heldout_quality_report_sha256"] = _canonical_sha256(report)
    receipt["heldout_campaign_proof_sha256"] = report["campaign"][
        "campaign_proof_sha256"
    ]
    receipt["heldout_campaign_result_manifest_sha256"] = report["campaign"][
        "campaign_result_manifest_sha256"
    ]
    receipt["heldout_point_estimates"] = {
        "precision": report["precision"]["point"],
        "recall": report["recall"]["point"],
    }


def _correlate_result_hash_without_raw_population(
    artifacts: dict[str, dict],
) -> None:
    result_manifest = artifacts["campaign-result-manifest.json"]
    target = result_manifest["results"][0]
    target_id = target["subject_id"]
    forged_sha256 = "0" * 64
    target["sha256"] = forged_sha256
    result_manifest["manifest_sha256"] = _canonical_sha256(result_manifest["results"])

    contract = artifacts["campaign-contract.json"]
    proof = artifacts["detector-report.json"]["fixed_contract_campaign_proof"]
    batch = contract["batches"][0]
    marker = proof["marker_proofs"][0]
    batch_manifest = [
        {
            "subject_id": entry["subject_id"],
            "size_bytes": entry["size_bytes"],
            "sha256": entry["sha256"],
        }
        for entry in sorted(
            result_manifest["results"], key=lambda entry: entry["subject_id"]
        )
    ]
    marker_manifest_sha256 = _canonical_sha256(batch_manifest)
    marker["result_manifest_sha256"] = marker_manifest_sha256
    marker_payload = json.loads(base64.b64decode(batch["marker_bytes_base64"]))
    marker_payload["result_validation"]["result_manifest_sha256"] = (
        marker_manifest_sha256
    )
    marker_bytes = (json.dumps(marker_payload, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()
    batch["marker_bytes_base64"] = base64.b64encode(marker_bytes).decode("ascii")
    marker["marker_sha256"] = marker_sha256
    for subject in proof["subject_proofs"]:
        subject["marker_sha256"] = marker_sha256
        if subject["subject_id"] == target_id:
            subject["result_sha256"] = forged_sha256

    receipt = artifacts["release-receipt.json"]
    receipt["campaign_result_manifest_sha256"] = result_manifest["manifest_sha256"]
    _reseal_campaign_artifacts(artifacts)

    selection = artifacts["heldout-selection.json"]
    selection["campaign"]["campaign_proof_sha256"] = receipt[
        "fixed_campaign_proof_sha256"
    ]
    selection["campaign"]["campaign_result_manifest_sha256"] = result_manifest[
        "manifest_sha256"
    ]
    for lane in ("precision", "recall"):
        for row in selection["samples"][lane]:
            for result in row["campaign_results"]:
                if result["subject_id"] == target_id:
                    result["sha256"] = forged_sha256
    _reseal_heldout_artifacts(artifacts)


@pytest.mark.parametrize("mutation", ["batch_hash", "command"])
def test_validator_rejects_correlated_campaign_contract_and_proof_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    generation_id = "7" * 64
    artifacts = _artifacts(generation_id)
    batch = artifacts["campaign-contract.json"]["batches"][0]
    marker = artifacts["detector-report.json"]["fixed_contract_campaign_proof"][
        "marker_proofs"
    ][0]
    if mutation == "batch_hash":
        batch["batch_sha256"] = "0" * 64
        marker["batch_sha256"] = batch["batch_sha256"]
    else:
        batch["command"] = [*batch["command"], "--forged"]
        batch["command_sha256"] = _canonical_sha256(batch["command"])
        marker["command_sha256"] = batch["command_sha256"]
    _reseal_campaign_artifacts(artifacts)

    with pytest.raises(
        ReleaseEvidenceError,
        match="batch schema|raw bytes|canonical runner command|marker",
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_recomputes_campaign_identity_from_runner_contract(
    tmp_path: Path,
) -> None:
    generation_id = "8" * 64
    artifacts = _artifacts(generation_id)
    forged_id = "0" * 64
    contract = artifacts["campaign-contract.json"]
    contract["campaign_id"] = forged_id
    contract["result_dir"] = str(
        Path(contract["result_dir"]).parent.parent / forged_id / "results"
    )
    receipt = artifacts["release-receipt.json"]
    receipt["campaign_id"] = forged_id
    receipt["campaign_result_dir"] = contract["result_dir"]
    artifacts["campaign-result-manifest.json"]["campaign_id"] = forged_id
    proof = artifacts["detector-report.json"]["fixed_contract_campaign_proof"]
    proof["expected_contract"]["campaign_id"] = forged_id
    proof["expected_contract"]["result_dir"] = contract["result_dir"]
    _reseal_campaign_artifacts(artifacts)

    with pytest.raises(
        ReleaseEvidenceError,
        match="campaign identity|live campaign result inventories",
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_replays_curation_against_raw_semantic_inputs(
    tmp_path: Path,
) -> None:
    generation_id = "6" * 64
    artifacts = _artifacts(generation_id)
    published_ids = set(
        artifacts["publication-curation-inputs.json"]["published_ordered_ids"]
    )
    forged_id = "CVE-2099-99999"
    forged_ids = published_ids | {forged_id}
    forged_report = publication_quality.evaluate(
        {subject_id: "AI_CAUSAL" for subject_id in forged_ids},
        forged_ids,
        precision_target=0.95,
        recall_target=0.95,
    )
    artifacts["publication-curation-consistency-report.json"] = forged_report
    receipt = artifacts["release-receipt.json"]
    receipt["publication_curation_consistency_report_sha256"] = _canonical_sha256(
        forged_report
    )
    receipt["curation_consistency_point_estimates"] = {
        "precision": forged_report["curation_precision"]["point"],
        "recall": forged_report["curation_recall"]["point"],
    }

    with pytest.raises(ReleaseEvidenceError, match="archived semantic inputs"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize("mutation", ["equal_cardinality_row_swap", "recall_stratum"])
def test_validator_replays_every_detector_inventory_row_from_raw_inputs(
    tmp_path: Path,
    mutation: str,
) -> None:
    generation_id = "a" * 64
    artifacts = _artifacts(generation_id)
    inventory = artifacts["detector-inventory.json"]
    if mutation == "equal_cardinality_row_swap":
        first, second = inventory["rows"][:2]
        first["source_evidence_sha256"], second["source_evidence_sha256"] = (
            second["source_evidence_sha256"],
            first["source_evidence_sha256"],
        )
    else:
        original_stratum = inventory["rows"][0]["recall_stratum"]
        tampered_stratum = (
            "fix_no_bic" if original_stratum != "fix_no_bic" else "no_fix_commit"
        )
        inventory["rows"][0]["recall_stratum"] = tampered_stratum
        stratum_counts = inventory["counts"]["recall_stratum"]
        stratum_counts[original_stratum] -= 1
        if stratum_counts[original_stratum] == 0:
            del stratum_counts[original_stratum]
        stratum_counts[tampered_stratum] = stratum_counts.get(tampered_stratum, 0) + 1
        inventory["counts"]["recall_stratum"] = dict(sorted(stratum_counts.items()))
    _reseal_detector_inventory_artifacts(artifacts)

    with pytest.raises(ReleaseEvidenceError, match="does not exactly replay"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_batch_key",
        "duplicate_subject_owner",
        "missing_subject_union",
        "extra_subject_union",
        "marker_set",
        "command_hash",
        "batch_hash",
    ],
)
def test_validator_binds_exact_campaign_batches_and_marker_hashes(
    tmp_path: Path,
    mutation: str,
) -> None:
    generation_id = "2" * 64
    artifacts = _artifacts(generation_id)
    contract = artifacts["campaign-contract.json"]
    batch = contract["batches"][0]
    proof = artifacts["detector-report.json"]["fixed_contract_campaign_proof"]
    marker = proof["marker_proofs"][0]

    if mutation == "duplicate_batch_key":
        contract["batches"].append(json.loads(json.dumps(batch)))
    elif mutation == "duplicate_subject_owner":
        duplicate = json.loads(json.dumps(batch))
        duplicate.update(
            {
                "key": "grouped-002",
                "path": "/tmp/batches/grouped-002.txt",
                "ids": [batch["ids"][0]],
                "batch_sha256": "e" * 64,
            }
        )
        duplicate["command"] = ["analyze", "--batch", "grouped-002"]
        duplicate["command_sha256"] = _canonical_sha256(duplicate["command"])
        contract["batches"].append(duplicate)
    elif mutation == "missing_subject_union":
        batch["ids"].pop()
    elif mutation == "extra_subject_union":
        batch["ids"].append("CVE-2026-99999")
    elif mutation == "marker_set":
        marker["batch"] = "grouped-999"
    elif mutation == "command_hash":
        marker["command_sha256"] = "0" * 64
    else:
        marker["batch_sha256"] = "0" * 64
    _reseal_campaign_artifacts(artifacts)

    with pytest.raises(
        ReleaseEvidenceError,
        match="campaign contract|campaign batch|marker inventory|marker schema",
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_binds_every_subject_proof_to_its_exact_batch_owner(
    tmp_path: Path,
) -> None:
    generation_id = "3" * 64
    artifacts = _artifacts(generation_id)
    results = artifacts["campaign-result-manifest.json"]["results"]
    contract = artifacts["campaign-contract.json"]
    first_batch = contract["batches"][0]
    first_ids = first_batch["ids"][:30]
    second_ids = first_batch["ids"][30:]
    first_batch["ids"] = first_ids
    second_command = ["analyze", "--batch", "grouped-002"]
    second_batch = {
        "key": "grouped-002",
        "path": "/tmp/batches/grouped-002.txt",
        "ids": second_ids,
        "command": second_command,
        "batch_sha256": "e" * 64,
        "command_sha256": _canonical_sha256(second_command),
    }
    contract["batches"].append(second_batch)
    result_by_id = {entry["subject_id"]: entry for entry in results}

    proof = artifacts["detector-report.json"]["fixed_contract_campaign_proof"]
    first_marker = proof["marker_proofs"][0]
    first_marker["result_manifest_sha256"] = _canonical_sha256(
        [
            {
                "subject_id": subject_id,
                "size_bytes": result_by_id[subject_id]["size_bytes"],
                "sha256": result_by_id[subject_id]["sha256"],
            }
            for subject_id in sorted(first_ids)
        ]
    )
    second_marker_sha256 = "f" * 64
    second_marker = {
        **first_marker,
        "batch": second_batch["key"],
        "path": "/tmp/markers/grouped-002.json",
        "marker_sha256": second_marker_sha256,
        "batch_sha256": second_batch["batch_sha256"],
        "command_sha256": second_batch["command_sha256"],
        "result_manifest_sha256": _canonical_sha256(
            [
                {
                    "subject_id": subject_id,
                    "size_bytes": result_by_id[subject_id]["size_bytes"],
                    "sha256": result_by_id[subject_id]["sha256"],
                }
                for subject_id in sorted(second_ids)
            ]
        ),
    }
    proof["marker_proofs"].append(second_marker)
    proof["campaign_batch_count"] = 2
    proof["completed_marker_count"] = 2
    proof["relevant_marker_count"] = 2
    subjects = {entry["subject_id"]: entry for entry in proof["subject_proofs"]}
    for subject_id in second_ids:
        subject = subjects[subject_id]
        subject["batch"] = second_batch["key"]
        subject["marker_sha256"] = second_marker_sha256
    forged = subjects[second_ids[0]]
    forged["batch"] = first_batch["key"]
    forged["marker_sha256"] = first_marker["marker_sha256"]
    _reseal_campaign_artifacts(artifacts)

    with pytest.raises(
        ReleaseEvidenceError, match="campaign batch|campaign contract|subject schema"
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_independently_enforces_luna_max_across_campaign_proofs(
    tmp_path: Path,
) -> None:
    generation_id = "9" * 64
    artifacts = _artifacts(generation_id)
    contract = artifacts["campaign-contract.json"]
    contract["model"] = "gpt-5.6-other"
    receipt = artifacts["release-receipt.json"]
    receipt["model"] = contract["model"]
    receipt["campaign_contract_sha256"] = _canonical_sha256(contract)

    with pytest.raises(ReleaseEvidenceError, match="Luna/max"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_binds_raw_result_hashes_to_complete_campaign_inventory(
    tmp_path: Path,
) -> None:
    generation_id = "a" * 64
    artifacts = _artifacts(generation_id)
    result_manifest = artifacts["campaign-result-manifest.json"]
    result_manifest["results"][0]["sha256"] = "0" * 64
    result_manifest["manifest_sha256"] = _canonical_sha256(result_manifest["results"])
    artifacts["release-receipt.json"]["campaign_result_manifest_sha256"] = (
        result_manifest["manifest_sha256"]
    )

    with pytest.raises(
        ReleaseEvidenceError,
        match="marker result|raw result|population and result manifest",
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "duplicate", "path_escape", "altered_bytes"],
)
def test_validator_rejects_tampered_full_campaign_result_archive(
    tmp_path: Path,
    mutation: str,
) -> None:
    generation_id = "4" * 64
    artifacts = _artifacts(generation_id)
    archive = artifacts["heldout-campaign-population.json"]
    results = archive["results"]
    if mutation == "missing":
        results.pop()
    elif mutation == "extra":
        extra = json.loads(json.dumps(results[-1]))
        extra["subject_id"] = "CVE-2099-99999"
        extra["file_name"] = "CVE-2099-99999.json"
        extra["archive_path"] = "campaign-results/CVE-2099-99999.json"
        extra["source_path"] = str(
            Path(extra["source_path"]).parent / extra["file_name"]
        )
        results.append(extra)
    elif mutation == "duplicate":
        results.append(json.loads(json.dumps(results[0])))
    elif mutation == "path_escape":
        results[0]["archive_path"] = "../escaped-campaign-result.json"
    else:
        Path(results[0]["source_path"]).write_bytes(b"{}\n")
    archive["result_count"] = len(results)
    archive["total_result_size_bytes"] = sum(entry["size_bytes"] for entry in results)
    artifacts["release-receipt.json"]["heldout_campaign_population_sha256"] = (
        _canonical_sha256(archive)
    )

    with pytest.raises(
        ReleaseEvidenceError,
        match="campaign population|campaign result|raw result|archive path",
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


@pytest.mark.parametrize(
    "mutation",
    ["extra_json", "missing", "symlink", "directory", "unparseable_name"],
)
def test_archive_requires_exact_live_campaign_result_directory(
    tmp_path: Path,
    mutation: str,
) -> None:
    generation_id = "3" * 64
    artifacts = _artifacts(generation_id)
    population = artifacts["heldout-campaign-population.json"]
    result_dir = Path(population["result_dir"])
    first = Path(population["results"][0]["source_path"])
    if mutation == "extra_json":
        (result_dir / "CVE-2099-99999.json").write_text(
            '{"cve_id":"CVE-2099-99999"}\n', encoding="utf-8"
        )
    elif mutation == "missing":
        first.unlink()
    elif mutation == "symlink":
        first.unlink()
        first.symlink_to("/dev/null")
    elif mutation == "directory":
        first.unlink()
        first.mkdir()
    else:
        (result_dir / "temporary-result.partial").write_text("{}\n", encoding="utf-8")

    root = tmp_path / "release-evidence-v1"
    with pytest.raises(ReleaseEvidenceError, match="live campaign result"):
        archive_release_evidence(
            root=root,
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )
    assert not (root / generation_id).exists()


def test_validator_rejects_resealed_prediction_drift_from_full_raw_population(
    tmp_path: Path,
) -> None:
    generation_id = "5" * 64
    artifacts = _artifacts(generation_id)
    selection = artifacts["heldout-selection.json"]
    target_id = selection["samples"]["precision"][0]["sample_id"]
    for lane in ("precision", "recall"):
        for row in selection["samples"][lane]:
            if row["sample_id"] == target_id:
                row["prediction_reasons"] = ["forged-after-selection"]
    _reseal_heldout_artifacts(artifacts)

    with pytest.raises(
        ReleaseEvidenceError, match="committed Git object|deterministically replay"
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_rejects_correlated_result_hash_reseal_without_raw_population(
    tmp_path: Path,
) -> None:
    generation_id = "6" * 64
    artifacts = _artifacts(generation_id)
    original_archive = json.loads(
        json.dumps(artifacts["heldout-campaign-population.json"])
    )
    _correlate_result_hash_without_raw_population(artifacts)

    assert artifacts["heldout-campaign-population.json"] == original_archive
    with pytest.raises(
        ReleaseEvidenceError,
        match=(
            "committed Git object|campaign population|raw result|deterministically replay"
        ),
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_rejects_manifest_hash_only_selection_reseed(
    tmp_path: Path,
) -> None:
    """The prior selected-row-only archive accepted this correlated forgery."""

    generation_id = "d" * 64
    artifacts = _artifacts(generation_id)
    selection = artifacts["heldout-selection.json"]
    selection["campaign"]["campaign_result_manifest_sha256"] = "0" * 64
    _reseal_heldout_artifacts(artifacts)

    with pytest.raises(
        ReleaseEvidenceError, match="committed Git object|deterministically replay"
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_rejects_resealed_alias_population_drift(tmp_path: Path) -> None:
    generation_id = "e" * 64
    artifacts = _artifacts(generation_id)
    population = artifacts["heldout-campaign-population.json"]
    first, second = [entry["subject_id"] for entry in population["results"][:2]]
    population["alias_classes"] = [{"subject_ids": sorted([first, second])}]
    population["alias_classes_sha256"] = _canonical_sha256(population["alias_classes"])
    artifacts["release-receipt.json"]["heldout_campaign_population_sha256"] = (
        _canonical_sha256(population)
    )

    with pytest.raises(
        ReleaseEvidenceError, match="committed Git object|deterministically replay"
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_rejects_correlated_alias_selection_and_receipt_reseal(
    tmp_path: Path,
) -> None:
    generation_id = "a" * 64
    artifacts = _artifacts(generation_id)
    population = artifacts["heldout-campaign-population.json"]
    subject_ids = [entry["subject_id"] for entry in population["results"]]
    first, second = subject_ids[:2]
    alias_class = {first, second}
    inputs = {
        entry["subject_id"]: (
            detector_quality._load_cached_pipeline_input(
                Path(entry["source_path"]), entry["subject_id"]
            ),
        )
        for entry in population["results"]
    }
    units = heldout._alias_units(
        subject_ids,
        {first: alias_class, second: alias_class},
        inputs,
    )
    unit_manifest = [
        {
            "canonical_id": unit.canonical_id,
            "subject_ids": list(unit.subject_ids),
            "results": [
                {"subject_id": result.subject_id, "sha256": result.sha256}
                for result in unit.results
            ],
        }
        for unit in units
    ]
    contract = artifacts["campaign-contract.json"]
    snapshot = heldout.CampaignSnapshot(
        campaign_id=contract["campaign_id"],
        contract_sha256=contract["contract_sha256"],
        source_snapshot_sha256=contract["source_snapshot_sha256"],
        campaign_proof_sha256=artifacts["release-receipt.json"][
            "fixed_campaign_proof_sha256"
        ],
        campaign_result_manifest_sha256=heldout.canonical_sha256(unit_manifest),
        proof_complete=True,
        units=units,
    )
    original_selection = artifacts["heldout-selection.json"]
    protected_fields = original_selection["protected_inputs"]
    protected = heldout.ProtectedInventory(
        subject_ids=frozenset(),
        source_roots=tuple(protected_fields["source_roots"]),
        files=tuple(protected_fields["files"]),
        files_manifest_sha256=protected_fields["files_manifest_sha256"],
        subject_ids_sha256=protected_fields["subject_ids_sha256"],
    )
    policy = original_selection["selection_policy"]
    selection = heldout.build_selection_manifest(
        snapshot,
        protected,
        precision_sample_size=policy["precision_sample_size"],
        recall_sample_size=policy["recall_sample_size"],
        selection_code_sha256=policy["selection_code_sha256"],
    )
    artifacts["heldout-selection.json"] = selection
    artifacts["heldout-labels.json"] = _independently_label_selection(
        artifacts, selection
    )
    population["alias_classes"] = [{"subject_ids": sorted(alias_class)}]
    population["alias_classes_sha256"] = _canonical_sha256(population["alias_classes"])
    artifacts["release-receipt.json"]["heldout_campaign_population_sha256"] = (
        _canonical_sha256(population)
    )
    _reseal_heldout_artifacts(artifacts)

    with pytest.raises(ReleaseEvidenceError, match="committed Git object"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_reextracts_resealed_protected_input_bytes(tmp_path: Path) -> None:
    generation_id = "f" * 64
    artifacts = _artifacts(generation_id)
    selection = artifacts["heldout-selection.json"]
    protected_id = selection["samples"]["precision"][0]["sample_id"]
    population = artifacts["heldout-campaign-population.json"]
    protected = population["protected_inputs"]
    archived_file = protected["files"][0]
    content = f"late protected calibration ID: {protected_id}\n".encode()
    referenced = [protected_id]
    metadata = {
        "path": archived_file["path"],
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "referenced_subject_count": 1,
        "referenced_subject_ids_sha256": _canonical_sha256(referenced),
    }
    protected["files"] = [
        {**metadata, "bytes_base64": base64.b64encode(content).decode("ascii")}
    ]
    protected["total_size_bytes"] = len(content)
    protected["files_manifest_sha256"] = _canonical_sha256([metadata])
    selection["protected_inputs"].update(
        {
            "files": [metadata],
            "files_manifest_sha256": protected["files_manifest_sha256"],
            "subject_id_count": 1,
            "subject_ids_sha256": _canonical_sha256(referenced),
        }
    )
    _reseal_heldout_artifacts(artifacts)
    artifacts["release-receipt.json"]["heldout_campaign_population_sha256"] = (
        _canonical_sha256(population)
    )

    with pytest.raises(
        ReleaseEvidenceError, match="committed Git object|deterministically replay"
    ):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_rejects_correlated_protected_selection_and_receipt_reseal(
    tmp_path: Path,
) -> None:
    generation_id = "b" * 64
    artifacts = _artifacts(generation_id)
    population = artifacts["heldout-campaign-population.json"]
    subject_ids = [entry["subject_id"] for entry in population["results"]]
    inputs = {
        entry["subject_id"]: (
            detector_quality._load_cached_pipeline_input(
                Path(entry["source_path"]), entry["subject_id"]
            ),
        )
        for entry in population["results"]
    }
    units = heldout._alias_units(subject_ids, {}, inputs)
    unit_manifest = [
        {
            "canonical_id": unit.canonical_id,
            "subject_ids": list(unit.subject_ids),
            "results": [
                {"subject_id": result.subject_id, "sha256": result.sha256}
                for result in unit.results
            ],
        }
        for unit in units
    ]
    contract = artifacts["campaign-contract.json"]
    snapshot = heldout.CampaignSnapshot(
        campaign_id=contract["campaign_id"],
        contract_sha256=contract["contract_sha256"],
        source_snapshot_sha256=contract["source_snapshot_sha256"],
        campaign_proof_sha256=artifacts["release-receipt.json"][
            "fixed_campaign_proof_sha256"
        ],
        campaign_result_manifest_sha256=heldout.canonical_sha256(unit_manifest),
        proof_complete=True,
        units=units,
    )
    original_selection = artifacts["heldout-selection.json"]
    target = original_selection["samples"]["precision"][0]["sample_id"]
    protected_fields = original_selection["protected_inputs"]
    relative_path = protected_fields["files"][0]["path"]
    protected_bytes = f"late protected calibration ID: {target}\n".encode()
    referenced_ids = sorted(
        heldout._extract_subject_tokens(
            protected_bytes,
            PurePosixPath(relative_path),
        )
    )
    protected_metadata = {
        "path": relative_path,
        "size_bytes": len(protected_bytes),
        "sha256": hashlib.sha256(protected_bytes).hexdigest(),
        "referenced_subject_count": len(referenced_ids),
        "referenced_subject_ids_sha256": heldout.canonical_sha256(referenced_ids),
    }
    protected = heldout.ProtectedInventory(
        subject_ids=frozenset(referenced_ids),
        source_roots=tuple(protected_fields["source_roots"]),
        files=(protected_metadata,),
        files_manifest_sha256=heldout.canonical_sha256([protected_metadata]),
        subject_ids_sha256=heldout.canonical_sha256(referenced_ids),
    )
    policy = original_selection["selection_policy"]
    selection = heldout.build_selection_manifest(
        snapshot,
        protected,
        precision_sample_size=policy["precision_sample_size"],
        recall_sample_size=policy["recall_sample_size"],
        selection_code_sha256=policy["selection_code_sha256"],
    )
    artifacts["heldout-selection.json"] = selection
    artifacts["heldout-labels.json"] = _independently_label_selection(
        artifacts, selection
    )
    population["protected_inputs"] = {
        "source_roots": list(protected.source_roots),
        "file_count": 1,
        "total_size_bytes": len(protected_bytes),
        "files_manifest_sha256": protected.files_manifest_sha256,
        "files": [
            {
                **protected_metadata,
                "bytes_base64": base64.b64encode(protected_bytes).decode("ascii"),
            }
        ],
    }
    artifacts["release-receipt.json"]["heldout_campaign_population_sha256"] = (
        _canonical_sha256(population)
    )
    _reseal_heldout_artifacts(artifacts)

    with pytest.raises(ReleaseEvidenceError, match="committed Git object"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_archive_reads_every_unselected_campaign_result(tmp_path: Path) -> None:
    generation_id = "1" * 64
    artifacts = _artifacts(generation_id)
    selection = artifacts["heldout-selection.json"]
    selected = {
        result["subject_id"]
        for lane in ("precision", "recall")
        for row in selection["samples"][lane]
        for result in row["campaign_results"]
    }
    population = artifacts["heldout-campaign-population.json"]
    unselected = next(
        entry for entry in population["results"] if entry["subject_id"] not in selected
    )
    Path(unselected["source_path"]).write_bytes(b"{}\n")

    with pytest.raises(ReleaseEvidenceError, match="metadata is invalid|mismatched"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_archive_rejects_symlinked_campaign_result_source(tmp_path: Path) -> None:
    generation_id = "2" * 64
    artifacts = _artifacts(generation_id)
    entry = artifacts["heldout-campaign-population.json"]["results"][0]
    source = Path(entry["source_path"])
    target = source.parent.parent / "symlink-target.json"
    target.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(target)

    with pytest.raises(ReleaseEvidenceError, match="live campaign result"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_archive_enforces_per_file_and_total_campaign_size_caps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation_id = "3" * 64
    artifacts = _artifacts(generation_id)
    population = artifacts["heldout-campaign-population.json"]
    first_size = population["results"][0]["size_bytes"]
    monkeypatch.setattr(
        release_evidence,
        "_MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES",
        first_size - 1,
    )
    with pytest.raises(ReleaseEvidenceError, match="result entry is invalid"):
        archive_release_evidence(
            root=tmp_path / "per-file",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )

    monkeypatch.setattr(
        release_evidence,
        "_MAX_ARCHIVED_CAMPAIGN_RESULT_BYTES",
        32 * 1024 * 1024,
    )
    monkeypatch.setattr(
        release_evidence,
        "_MAX_ARCHIVED_CAMPAIGN_RESULTS_TOTAL_BYTES",
        population["total_result_size_bytes"] - 1,
    )
    with pytest.raises(ReleaseEvidenceError, match="size bound"):
        archive_release_evidence(
            root=tmp_path / "total",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_binds_selection_and_report_to_one_campaign(tmp_path: Path) -> None:
    generation_id = "b" * 64
    artifacts = _artifacts(generation_id)
    report = artifacts["heldout-quality-report.json"]
    report["campaign"] = dict(report["campaign"])
    report["campaign"]["campaign_proof_sha256"] = "0" * 64
    receipt = artifacts["release-receipt.json"]
    receipt["heldout_campaign_proof_sha256"] = "0" * 64
    receipt["heldout_quality_report_sha256"] = _canonical_sha256(report)

    with pytest.raises(ReleaseEvidenceError, match="campaign contracts differ"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_validator_recomputes_the_archived_label_blob_hash(tmp_path: Path) -> None:
    generation_id = "c" * 64
    artifacts = _artifacts(generation_id)
    report = artifacts["heldout-quality-report.json"]
    report["manual_evidence"]["artifact_order"]["labels_blob_sha256"] = "0" * 64
    artifacts["release-receipt.json"]["heldout_quality_report_sha256"] = (
        _canonical_sha256(report)
    )

    with pytest.raises(ReleaseEvidenceError, match="artifact-order proof"):
        archive_release_evidence(
            root=tmp_path / "release-evidence-v1",
            generation_id=generation_id,
            generated_at="2026-07-18T13:00:00+00:00",
            artifacts=artifacts,
        )


def test_activation_is_prepared_durably_then_finalized_after_promotion(
    tmp_path: Path,
) -> None:
    staged, root, receipt, bindings, output_dir = _activation_fixture(tmp_path)
    generation_id = bindings["generation_id"]
    activation_path = root / "activations" / f"{generation_id}.json"
    pending_path = root / "activations" / "pending" / f"{generation_id}.json"
    assert not activation_path.exists()

    prepared = prepare_release_activation_record(**bindings)

    assert prepared == pending_path
    assert not activation_path.exists()
    pending = json.loads(pending_path.read_text(encoding="utf-8"))
    assert pending["state"] == "prepared"
    assert pending["output_path"] == str(output_dir.resolve())
    assert pending["recovery_path"] == str(staged.staging_dir.resolve())
    assert pending["candidate_inode"] == {
        "device": staged.staging_dir.stat().st_dev,
        "inode": staged.staging_dir.stat().st_ino,
    }
    assert pending["previous_inode"] == {
        "device": output_dir.stat().st_dev,
        "inode": output_dir.stat().st_ino,
    }
    for field in (
        "generation_id",
        "evidence_bundle_sha256",
        "release_receipt_sha256",
        "publication_bundle_sha256",
        "publication_manifest_sha256",
    ):
        assert pending[field] == bindings[field]

    with writer.publication_promotion_transaction(
        staged,
        expected_release_receipt=receipt,
    ) as promotion:
        commit = promotion.commit()
        result = write_release_activation_record(
            **bindings,
            promotion_commit=commit,
            publication_lock=promotion.parent_lock,
        )

    assert result == activation_path
    assert not pending_path.exists()
    assert not staged.staging_dir.exists()
    activation = json.loads(result.read_text(encoding="utf-8"))
    assert activation["state"] == "active"
    assert validate_active_release(root=root, generation_id=generation_id) == activation
    formal = verify_formal_release(
        data_dir=output_dir,
        evidence_root=root,
        require_active=True,
        verify_artifact_order=False,
    )
    assert formal["generation_id"] == generation_id
    assert formal["active_release_verified"] is True
    assert formal["recall_evidence_bound"] is True
    assert formal["recall_evidence_replayed"] is True
    assert (
        verify_formal_release(data_dir=output_dir)["active_release_verified"] is False
    )
    assert (
        verify_formal_release(data_dir=output_dir, require_inventory=True)[
            "generation_id"
        ]
        == generation_id
    )
    assert activation["generation_id"] == generation_id
    assert activation["evidence_bundle_sha256"] == bindings["evidence_bundle_sha256"]
    assert writer.load_published_web_data(output_dir).index["generation_id"] == (
        generation_id
    )


def test_activation_record_is_write_once_for_one_exact_release(tmp_path: Path) -> None:
    staged, _root, receipt, bindings, _output_dir = _activation_fixture(tmp_path)
    prepare_release_activation_record(**bindings)
    with writer.publication_promotion_transaction(
        staged,
        expected_release_receipt=receipt,
    ) as promotion:
        commit = promotion.commit()
        first = write_release_activation_record(
            **bindings,
            promotion_commit=commit,
            publication_lock=promotion.parent_lock,
        )
    second = write_release_activation_record(**bindings)

    assert first == second
    with pytest.raises(ReleaseEvidenceError, match="approved release|evidence bundle"):
        write_release_activation_record(
            **{**bindings, "publication_bundle_sha256": "0" * 64}
        )


def test_exception_after_activation_cannot_roll_back_the_active_generation(
    tmp_path: Path,
) -> None:
    staged, root, receipt, bindings, output_dir = _activation_fixture(tmp_path)
    prepare_release_activation_record(**bindings)

    with pytest.raises(KeyboardInterrupt):
        with writer.publication_promotion_transaction(
            staged,
            expected_release_receipt=receipt,
        ) as promotion:
            commit = promotion.commit()
            active = write_release_activation_record(
                **bindings,
                promotion_commit=commit,
                publication_lock=promotion.parent_lock,
            )
            assert active.is_file()
            raise KeyboardInterrupt

    activation = json.loads(
        (root / "activations" / f"{bindings['generation_id']}.json").read_text(
            encoding="utf-8"
        )
    )
    assert activation["state"] == "active"
    assert (
        writer.load_published_web_data(output_dir).index["generation_id"]
        == (bindings["generation_id"])
    )


def test_failed_activation_finalize_leaves_idempotent_reconcile_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged, root, _receipt, bindings, output_dir = _activation_fixture(tmp_path)
    generation_id = bindings["generation_id"]
    pending = prepare_release_activation_record(**bindings)
    real_link = release_evidence.os.link

    def fail_final_link(source: Path, destination: Path) -> None:
        if Path(destination).parent.name == "activations":
            raise OSError("simulated activation durability failure")
        real_link(source, destination)

    monkeypatch.setattr(release_evidence.os, "link", fail_final_link)
    with pytest.raises(ReleaseEvidenceError, match="cannot finalize"):
        with writer.publication_promotion_transaction(staged) as promotion:
            commit = promotion.commit()
            write_release_activation_record(
                **bindings,
                promotion_commit=commit,
                publication_lock=promotion.parent_lock,
            )

    assert pending.is_file()
    assert json.loads(pending.read_text(encoding="utf-8"))["state"] == "committed"
    assert not (root / "activations" / f"{generation_id}.json").exists()

    monkeypatch.setattr(release_evidence.os, "link", real_link)
    reconcile_bindings = {"root": root, "generation_id": generation_id}
    first = reconcile_release_activation_record(**reconcile_bindings)
    second = reconcile_release_activation_record(**reconcile_bindings)
    assert first == second
    assert first.is_file()
    assert not pending.exists()
    assert not staged.staging_dir.exists()


def test_reconcile_rejects_a_candidate_that_was_never_made_live(
    tmp_path: Path,
) -> None:
    staged, root, _receipt, bindings, output_dir = _activation_fixture(tmp_path)
    pending = prepare_release_activation_record(**bindings)
    previous_generation = writer.load_published_web_data(output_dir).index[
        "generation_id"
    ]

    assert (
        reconcile_release_activation_record(
            root=root,
            generation_id=bindings["generation_id"],
        )
        is None
    )

    assert not pending.exists()
    assert not staged.staging_dir.exists()
    assert writer.load_published_web_data(output_dir).index["generation_id"] == (
        previous_generation
    )


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires process SIGKILL")
def test_sigkill_before_durable_activation_commit_rolls_back_prepared_candidate(
    tmp_path: Path,
) -> None:
    staged, root, receipt, bindings, output_dir = _activation_fixture(tmp_path)
    pending = prepare_release_activation_record(**bindings)
    previous_generation = writer.load_published_web_data(output_dir).index[
        "generation_id"
    ]
    read_descriptor, write_descriptor = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_descriptor)
        try:
            with writer.publication_promotion_transaction(
                staged,
                expected_release_receipt=receipt,
            ) as promotion:
                promotion.commit()
                os.write(write_descriptor, b"x")
                signal.pause()
        finally:
            os._exit(1)

    os.close(write_descriptor)
    try:
        assert os.read(read_descriptor, 1) == b"x"
        os.kill(child, signal.SIGKILL)
        _, wait_status = os.waitpid(child, 0)
        assert os.WIFSIGNALED(wait_status)
        assert os.WTERMSIG(wait_status) == signal.SIGKILL
    finally:
        os.close(read_descriptor)

    assert json.loads(pending.read_text(encoding="utf-8"))["state"] == "prepared"
    assert (
        writer.load_published_web_data(output_dir).index["generation_id"]
        == (bindings["generation_id"])
    )

    assert (
        reconcile_release_activation_record(
            root=root,
            generation_id=bindings["generation_id"],
        )
        is None
    )
    assert not pending.exists()
    assert not staged.staging_dir.exists()
    assert writer.load_published_web_data(output_dir).index["generation_id"] == (
        previous_generation
    )


def test_prepared_live_candidate_fails_closed_without_exact_recovery_generation(
    tmp_path: Path,
) -> None:
    staged, root, _receipt, bindings, output_dir = _activation_fixture(tmp_path)
    pending = prepare_release_activation_record(**bindings)
    with writer._publication_parent_lock(
        output_dir,
        exclusive=True,
        error_type=writer.PublicationWriteError,
    ) as publication_lock:
        writer._promote_generation(
            staged,
            retain_previous=True,
            parent_lock=publication_lock,
        )
    staged.staging_dir.rename(tmp_path / "detached-previous-generation")

    with pytest.raises(ReleaseEvidenceError, match="lacks its exact previous"):
        reconcile_release_activation_record(
            root=root,
            generation_id=bindings["generation_id"],
        )

    assert pending.is_file()
    assert not (root / "activations" / f"{bindings['generation_id']}.json").exists()
    assert (
        writer.load_published_web_data(output_dir).index["generation_id"]
        == (bindings["generation_id"])
    )


@pytest.mark.parametrize(
    ("relative_path", "replacement"),
    [
        ("index.json", b"{}\n"),
        ("stats.json", b"{}\n"),
        ("cves/CVE-2026-10000.json", b"{}\n"),
        ("release-receipt.json", b"{}\n"),
    ],
)
def test_reconcile_rolls_back_a_prepared_candidate_after_content_mutation(
    tmp_path: Path,
    relative_path: str,
    replacement: bytes,
) -> None:
    staged, root, _receipt, bindings, output_dir = _activation_fixture(tmp_path)
    pending = prepare_release_activation_record(**bindings)
    previous_generation = writer.load_published_web_data(output_dir).index[
        "generation_id"
    ]
    with writer._publication_parent_lock(
        output_dir,
        exclusive=True,
        error_type=writer.PublicationWriteError,
    ) as publication_lock:
        writer._promote_generation(
            staged,
            retain_previous=True,
            parent_lock=publication_lock,
        )
    (output_dir / relative_path).write_bytes(replacement)

    assert (
        reconcile_release_activation_record(
            root=root,
            generation_id=bindings["generation_id"],
        )
        is None
    )

    assert not (root / "activations" / f"{bindings['generation_id']}.json").exists()
    assert not pending.exists()
    assert not staged.staging_dir.exists()
    assert writer.load_published_web_data(output_dir).index["generation_id"] == (
        previous_generation
    )
