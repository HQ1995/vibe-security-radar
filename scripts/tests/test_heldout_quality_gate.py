"""Tests for the independent fixed-campaign held-out quality lane."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import heldout_quality_gate as heldout


_REAL_ARTIFACT_ORDER_VALIDATOR = heldout._validate_artifact_order
_SELECTION_PATH = Path("scripts/heldout_studies/selection.json")
_LABELS_PATH = Path("scripts/heldout_studies/labels.json")


@pytest.fixture(autouse=True)
def _stub_artifact_order_proof(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if request.node.name in {
        "test_labels_require_a_verifiable_git_artifact_order",
        "test_git_artifact_order_binds_exact_tracked_bytes",
    }:
        return
    monkeypatch.setattr(
        heldout,
        "_validate_artifact_order",
        lambda *_args, **_kwargs: {
            "selection_commit_reference": f"{'9' * 40}:{_SELECTION_PATH}",
            "selection_commit": "9" * 40,
            "selection_path": _SELECTION_PATH.as_posix(),
            "labels_commit": "8" * 40,
            "labels_path": _LABELS_PATH.as_posix(),
            "labels_blob_sha256": "7" * 64,
            "selection_is_strict_ancestor": True,
            "labels_absent_from_selection_commit": True,
            "labels_exact_bytes_tracked_at_head": True,
        },
    )


_DIGESTS = {
    "campaign_id": "1" * 64,
    "contract_sha256": "2" * 64,
    "source_snapshot_sha256": "3" * 64,
    "campaign_proof_sha256": "4" * 64,
    "campaign_result_manifest_sha256": "5" * 64,
}


def _unit(
    canonical_id: str,
    *,
    predicted_positive: bool,
    candidate_positive: bool = True,
    infrastructure: tuple[str, ...] = (),
    unresolved: tuple[str, ...] = (),
    aliases: tuple[str, ...] = (),
) -> heldout.SelectionUnit:
    subject_ids = tuple(sorted((canonical_id, *aliases)))
    return heldout.SelectionUnit(
        canonical_id=canonical_id,
        subject_ids=subject_ids,
        predicted_positive=predicted_positive,
        candidate_positive=candidate_positive,
        prediction_reasons=("fixture",),
        infrastructure_categories=infrastructure,
        unresolved_reasons=unresolved,
        results=tuple(
            heldout.ResultReference(subject_id, heldout.canonical_sha256(subject_id))
            for subject_id in subject_ids
        ),
    )


def _snapshot(*, proof_complete: bool = True) -> heldout.CampaignSnapshot:
    return heldout.CampaignSnapshot(
        **_DIGESTS,
        proof_complete=proof_complete,
        units=(
            _unit("CVE-2026-1001", predicted_positive=True),
            _unit("GHSA-aaaa-bbbb-cccc", predicted_positive=True),
            _unit("OSV-2026-100", predicted_positive=True),
            _unit("RUSTSEC-2026-0001", predicted_positive=True),
            _unit("CVE-2026-1002", predicted_positive=False),
            _unit("GHSA-dddd-eeee-ffff", predicted_positive=False),
            _unit(
                "OSV-2026-101",
                predicted_positive=False,
                candidate_positive=False,
            ),
            _unit("HSEC-2026-0001", predicted_positive=False),
        ),
    )


def _protected(*subject_ids: str) -> heldout.ProtectedInventory:
    sorted_ids = sorted(subject_ids)
    files = (
        {
            "path": "scripts/fixtures/protected.json",
            "size_bytes": 10,
            "sha256": "6" * 64,
            "referenced_subject_count": len(sorted_ids),
            "referenced_subject_ids_sha256": heldout.canonical_sha256(sorted_ids),
        },
    )
    return heldout.ProtectedInventory(
        subject_ids=frozenset(sorted_ids),
        source_roots=({"path": "scripts/fixtures/protected.json", "kind": "file"},),
        files=files,
        files_manifest_sha256=heldout.canonical_sha256(list(files)),
        subject_ids_sha256=heldout.canonical_sha256(sorted_ids),
    )


def _selection(
    *,
    snapshot: heldout.CampaignSnapshot | None = None,
    protected: heldout.ProtectedInventory | None = None,
) -> dict:
    return heldout.build_selection_manifest(
        snapshot or _snapshot(),
        protected or _protected(),
        precision_sample_size=4,
        recall_sample_size=7,
        selection_code_sha256="a" * 64,
    )


def _labels(selection: dict, values: dict[str, str]) -> dict:
    template = heldout.build_label_template(selection)
    template["audit_protocol"] = {
        "selection_commit_reference": f"{'9' * 40}:{_SELECTION_PATH}",
        "audit_started_from_null_label_template": True,
        "reviewers_independent_from_detector_development": True,
        "reviewers_independent_from_each_other": True,
        "reviews_completed_without_access_to_other_review": True,
        "detector_predictions_hidden_from_reviewers": True,
        "sample_lane_membership_hidden_from_reviewers": True,
        "aggregate_quality_scores_hidden_until_resolution_complete": True,
        "all_disagreements_resolved_before_sealing": True,
    }
    for entry in template["adjudications"]:
        sample_id = entry["sample_id"]
        label = values[sample_id]
        evidence = [f"https://evidence.invalid/{sample_id}"]
        entry["primary_review"] = {
            "reviewer_id": "independent-primary",
            "label": label,
            "reviewed_at_utc": "2026-07-18T12:00:00+00:00",
            "evidence_refs": evidence,
            "rationale": "Reviewed the introducing and fixing changes.",
        }
        entry["secondary_review"] = {
            "reviewer_id": "independent-secondary",
            "label": label,
            "reviewed_at_utc": "2026-07-18T12:01:00+00:00",
            "evidence_refs": evidence,
            "rationale": "Independently verified the causal evidence.",
        }
        entry["resolved_label"] = label
        entry["resolution"] = {
            "status": "agreed",
            "resolver_id": None,
            "resolved_at_utc": None,
            "evidence_refs": [],
            "rationale": "",
        }
    return template


def _quality_labels(selection: dict) -> dict:
    values = {
        "CVE-2026-1001": "AI_CAUSAL",
        "GHSA-aaaa-bbbb-cccc": "AI_CAUSAL",
        "OSV-2026-100": "AI_CAUSAL",
        "RUSTSEC-2026-0001": "NOT_AI_CAUSAL",
        "CVE-2026-1002": "AI_CAUSAL",
        "GHSA-dddd-eeee-ffff": "NOT_AI_CAUSAL",
        "HSEC-2026-0001": "NOT_AI_CAUSAL",
    }
    return _labels(selection, values)


def _evaluate_selection(
    selection: dict,
    labels: dict,
    protected: heldout.ProtectedInventory,
    **kwargs: object,
) -> dict:
    return heldout.evaluate_selection(
        selection,
        labels,
        protected,
        selection_path=_SELECTION_PATH,
        labels_path=_LABELS_PATH,
        **kwargs,
    )


def test_selection_is_deterministic_uniform_top_k_and_content_addressed() -> None:
    first = heldout.build_selection_manifest(
        _snapshot(),
        _protected(),
        precision_sample_size=2,
        recall_sample_size=3,
        selection_code_sha256="a" * 64,
    )
    second = heldout.build_selection_manifest(
        _snapshot(),
        _protected(),
        precision_sample_size=2,
        recall_sample_size=3,
        selection_code_sha256="a" * 64,
    )

    assert first == second
    assert heldout.validate_selection_seal(first) == first["selection_manifest_sha256"]
    seed = first["selection_policy"]["seed_sha256"]
    for lane, population_filter in (
        ("precision", lambda unit: unit.predicted_positive),
        ("recall", lambda unit: unit.candidate_positive),
    ):
        population = [unit for unit in _snapshot().units if population_filter(unit)]
        expected = sorted(
            population,
            key=lambda unit: (
                heldout._selection_rank(seed, lane, unit),
                unit.canonical_id,
            ),
        )[: len(first["samples"][lane])]
        assert {row["sample_id"] for row in first["samples"][lane]} == {
            unit.canonical_id for unit in expected
        }
    assert first["selection_policy"]["sampling"] == (
        "global_uniform_domain_separated_sha256_top_k"
    )
    assert first["selection_policy"]["stratification"] == (
        "canonical_id_family_diagnostics_only"
    )
    assert all(row["predicted_positive"] for row in first["samples"]["precision"])
    assert all(row["candidate_positive"] for row in first["samples"]["recall"])
    assert "OSV-2026-101" not in {
        row["sample_id"] for row in first["samples"]["recall"]
    }


def test_point_gate_and_optional_certification_are_separate() -> None:
    selection = _selection()
    labels = _quality_labels(selection)

    point_report = _evaluate_selection(
        selection,
        labels,
        _protected(),
        precision_target=0.75,
        recall_target=0.75,
    )
    certified_report = _evaluate_selection(
        selection,
        labels,
        _protected(),
        precision_target=0.75,
        recall_target=0.75,
        require_certified=True,
    )

    assert point_report["precision"]["point"] == 0.75
    assert point_report["recall"]["point"] == 0.75
    assert point_report["point_gate_passed"] is True
    assert point_report["certified_gate_passed"] is False
    assert point_report["release_gate_passed"] is True
    assert certified_report["release_gate_passed"] is False
    assert point_report["precision"]["one_sided_95pct_lower_bound"] < 0.75
    assert point_report["recall"]["one_sided_95pct_lower_bound"] < 0.75


def test_selection_rejects_incomplete_campaign_proof() -> None:
    with pytest.raises(heldout.HeldoutQualityError, match="proof is incomplete"):
        _selection(snapshot=_snapshot(proof_complete=False))


def test_protected_alias_class_is_excluded_before_selection() -> None:
    protected = _protected("CVE-2026-1001")
    selection = heldout.build_selection_manifest(
        _snapshot(),
        protected,
        precision_sample_size=3,
        recall_sample_size=6,
        selection_code_sha256="a" * 64,
    )

    selected_ids = {
        row["sample_id"] for lane in selection["samples"].values() for row in lane
    }
    assert "CVE-2026-1001" not in selected_ids
    assert selection["population"]["protected_overlap_ids"] == ["CVE-2026-1001"]


def test_lowercase_protected_ghsa_excludes_its_linked_cve_alias(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    protected_dir = repo / "protected"
    protected_dir.mkdir(parents=True)
    (protected_dir / "lowercase.json").write_text(
        '{"id":"ghsa-1111-2222-3333"}\n', encoding="utf-8"
    )
    aliases = {
        "ghsa-1111-2222-3333": {
            "GHSA-1111-2222-3333",
            "CVE-2026-1001",
        },
        "CVE-2026-1001": {
            "GHSA-1111-2222-3333",
            "CVE-2026-1001",
        },
    }
    protected = heldout.build_protected_inventory(repo, (protected_dir,), aliases)

    selection = heldout.build_selection_manifest(
        _snapshot(),
        protected,
        precision_sample_size=3,
        recall_sample_size=6,
        selection_code_sha256="a" * 64,
    )

    assert "CVE-2026-1001" in protected.subject_ids
    assert selection["population"]["protected_overlap_ids"] == ["CVE-2026-1001"]


def test_evaluator_fails_closed_when_protected_inputs_drift() -> None:
    selection = _selection()
    labels = _quality_labels(selection)

    with pytest.raises(heldout.HeldoutQualityError, match="protected inputs drifted"):
        _evaluate_selection(selection, labels, _protected("CVE-2026-1001"))


def test_seal_rejects_label_leakage_and_tampering() -> None:
    with pytest.raises(heldout.HeldoutQualityError, match="label material"):
        heldout._seal_selection({"label": "AI_CAUSAL"})

    selection = _selection()
    selection["population"]["eligible_alias_class_count"] += 1
    with pytest.raises(heldout.HeldoutQualityError, match="digest mismatch"):
        heldout.validate_selection_seal(selection)


def test_selection_recomputes_lane_overlap_from_exact_sample_ids() -> None:
    selection = _selection()
    selection["lane_overlap"] = dict(selection["lane_overlap"])
    selection["lane_overlap"]["count"] += 1
    selection.pop("selection_manifest_sha256")
    resealed = heldout._seal_selection(selection)

    with pytest.raises(heldout.HeldoutQualityError, match="lane overlap"):
        heldout.build_label_template(resealed)


def test_labels_must_be_complete_bound_and_independently_attested() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    labels["adjudications"].pop()
    with pytest.raises(heldout.HeldoutQualityError, match="labels are incomplete"):
        _evaluate_selection(selection, labels, _protected())

    labels = _quality_labels(selection)
    labels["selection_manifest_sha256"] = "f" * 64
    with pytest.raises(heldout.HeldoutQualityError, match="not bound"):
        _evaluate_selection(selection, labels, _protected())

    labels = _quality_labels(selection)
    labels["audit_protocol"]["reviewers_independent_from_detector_development"] = False
    with pytest.raises(heldout.HeldoutQualityError, match="attestation is false"):
        _evaluate_selection(selection, labels, _protected())


def test_schema_two_labels_are_rejected_after_dual_review_migration() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    labels["schema_version"] = 2

    with pytest.raises(heldout.HeldoutQualityError, match="schema_version 3"):
        _evaluate_selection(selection, labels, _protected())


@pytest.mark.parametrize(
    "attestation",
    [
        "reviewers_independent_from_each_other",
        "reviews_completed_without_access_to_other_review",
        "detector_predictions_hidden_from_reviewers",
        "sample_lane_membership_hidden_from_reviewers",
        "aggregate_quality_scores_hidden_until_resolution_complete",
        "all_disagreements_resolved_before_sealing",
    ],
)
def test_dual_review_protocol_requires_every_blinding_and_independence_attestation(
    attestation: str,
) -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    labels["audit_protocol"][attestation] = False

    with pytest.raises(heldout.HeldoutQualityError, match="attestation is false"):
        _evaluate_selection(selection, labels, _protected())


def test_reviewers_must_be_distinct_after_strip_and_casefold() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    entry = labels["adjudications"][0]
    entry["primary_review"]["reviewer_id"] = "  Reviewer-One "
    entry["secondary_review"]["reviewer_id"] = "reviewer-one"

    with pytest.raises(heldout.HeldoutQualityError, match="distinct reviewers"):
        _evaluate_selection(selection, labels, _protected())


def test_label_packet_rejects_missing_second_review_or_leaked_lane_fields() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    labels["adjudications"][0].pop("secondary_review")

    with pytest.raises(heldout.HeldoutQualityError, match="exact schema-3 fields"):
        _evaluate_selection(selection, labels, _protected())

    labels = _quality_labels(selection)
    labels["adjudications"][0]["lanes"] = ["precision"]
    with pytest.raises(heldout.HeldoutQualityError, match="exact schema-3 fields"):
        _evaluate_selection(selection, labels, _protected())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("reviewed_at_utc", "2026-07-18T12:00:00", "include a timezone"),
        ("evidence_refs", [], "evidence_refs.*missing"),
        ("rationale", "  ", "rationale.*missing"),
    ],
)
def test_each_independent_review_requires_timestamp_evidence_and_rationale(
    field: str,
    value: object,
    message: str,
) -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    labels["adjudications"][0]["secondary_review"][field] = value

    with pytest.raises(heldout.HeldoutQualityError, match=message):
        _evaluate_selection(selection, labels, _protected())


def test_agreeing_reviews_require_agreed_status_and_exact_resolved_label() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    entry = labels["adjudications"][0]
    entry["resolved_label"] = (
        "NOT_AI_CAUSAL"
        if entry["primary_review"]["label"] == "AI_CAUSAL"
        else "AI_CAUSAL"
    )

    with pytest.raises(heldout.HeldoutQualityError, match="agreed reviews"):
        _evaluate_selection(selection, labels, _protected())


def test_disagreement_requires_distinct_resolver_and_complete_resolution() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    entry = labels["adjudications"][0]
    entry["secondary_review"]["label"] = (
        "NOT_AI_CAUSAL"
        if entry["primary_review"]["label"] == "AI_CAUSAL"
        else "AI_CAUSAL"
    )
    entry["resolved_label"] = entry["primary_review"]["label"]
    entry["resolution"] = {
        "status": "resolved",
        "resolver_id": " independent-primary ",
        "resolved_at_utc": "2026-07-18T12:02:00+00:00",
        "evidence_refs": ["https://evidence.invalid/resolution"],
        "rationale": "Resolved from the full repository history.",
    }

    with pytest.raises(heldout.HeldoutQualityError, match="distinct resolver"):
        _evaluate_selection(selection, labels, _protected())

    entry["resolution"]["resolver_id"] = "  INDEPENDENT-SECONDARY  "
    with pytest.raises(heldout.HeldoutQualityError, match="distinct resolver"):
        _evaluate_selection(selection, labels, _protected())

    entry["resolution"]["resolver_id"] = "independent-resolver"
    entry["resolution"]["evidence_refs"] = []
    with pytest.raises(
        heldout.HeldoutQualityError, match="resolution evidence_refs.*missing"
    ):
        _evaluate_selection(selection, labels, _protected())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("resolved_at_utc", "2026-07-18T12:02:00", "include a timezone"),
        ("rationale", "", "resolution rationale.*missing"),
        (
            "resolved_at_utc",
            "2026-07-18T11:59:00+00:00",
            "predates an independent review",
        ),
    ],
)
def test_disagreement_resolution_requires_time_and_rationale(
    field: str,
    value: object,
    message: str,
) -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    entry = labels["adjudications"][0]
    entry["secondary_review"]["label"] = (
        "NOT_AI_CAUSAL"
        if entry["primary_review"]["label"] == "AI_CAUSAL"
        else "AI_CAUSAL"
    )
    entry["resolved_label"] = entry["primary_review"]["label"]
    entry["resolution"] = {
        "status": "resolved",
        "resolver_id": "independent-resolver",
        "resolved_at_utc": "2026-07-18T12:02:00+00:00",
        "evidence_refs": ["https://evidence.invalid/resolution"],
        "rationale": "Resolved from the full repository history.",
    }
    entry["resolution"][field] = value

    with pytest.raises(heldout.HeldoutQualityError, match=message):
        _evaluate_selection(selection, labels, _protected())


def test_complete_disagreement_resolution_produces_the_resolved_label() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    entry = labels["adjudications"][0]
    alternate = (
        "NOT_AI_CAUSAL"
        if entry["primary_review"]["label"] == "AI_CAUSAL"
        else "AI_CAUSAL"
    )
    entry["secondary_review"]["label"] = alternate
    entry["resolved_label"] = alternate
    entry["resolution"] = {
        "status": "resolved",
        "resolver_id": "independent-resolver",
        "resolved_at_utc": "2026-07-18T12:02:00+00:00",
        "evidence_refs": ["https://evidence.invalid/resolution"],
        "rationale": "Resolved from the full repository history.",
    }

    report = _evaluate_selection(selection, labels, _protected())

    assert report["evaluation_complete"] is True


def test_archived_release_recompute_revalidates_schema_three_reviews() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    quality = heldout.recompute_archived_quality_evidence(
        selection,
        labels,
        precision_target=0.75,
        recall_target=0.75,
        require_certified=False,
    )
    assert quality["evaluation_complete"] is True

    duplicate_reviewer = json.loads(json.dumps(labels))
    entry = duplicate_reviewer["adjudications"][0]
    entry["secondary_review"]["reviewer_id"] = (
        f"  {entry['primary_review']['reviewer_id'].upper()}  "
    )
    with pytest.raises(heldout.HeldoutQualityError, match="distinct reviewers"):
        heldout.recompute_archived_quality_evidence(
            selection,
            duplicate_reviewer,
            precision_target=0.75,
            recall_target=0.75,
            require_certified=False,
        )

    legacy = json.loads(json.dumps(labels))
    legacy["schema_version"] = 2
    with pytest.raises(heldout.HeldoutQualityError, match="schema_version 3"):
        heldout.recompute_archived_quality_evidence(
            selection,
            legacy,
            precision_target=0.75,
            recall_target=0.75,
            require_certified=False,
        )


def test_labels_require_a_verifiable_git_artifact_order() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    labels["audit_protocol"]["selection_commit_reference"] = "not-a-commit"

    with pytest.raises(heldout.HeldoutQualityError, match="full Git commit"):
        _evaluate_selection(selection, labels, _protected())


def test_git_artifact_order_binds_exact_tracked_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repo"
    study_dir = repository / "scripts" / "heldout_studies"
    study_dir.mkdir(parents=True)
    selection = _selection()
    selection_path = study_dir / "selection.json"
    selection_path.write_text(
        json.dumps(selection, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "audit@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Audit Seal"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "commit.gpgsign", "false"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "add", "scripts/heldout_studies/selection.json"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "Seal selection"],
        check=True,
    )
    commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    labels = _quality_labels(selection)
    labels["audit_protocol"]["selection_commit_reference"] = (
        f"{commit}:scripts/heldout_studies/selection.json"
    )
    labels_path = study_dir / "labels.json"
    labels_path.write_text(
        json.dumps(labels, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", str(repository), "add", "scripts/heldout_studies/labels.json"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "Add labels"],
        check=True,
    )
    hostile_git_environment = {
        "GIT_DIR": str(tmp_path / "attacker.git"),
        "GIT_WORK_TREE": str(tmp_path / "attacker-worktree"),
        "GIT_COMMON_DIR": str(tmp_path / "attacker-common"),
        "GIT_NAMESPACE": "attacker",
        "GIT_INDEX_FILE": str(tmp_path / "attacker-index"),
        "GIT_OBJECT_DIRECTORY": str(tmp_path / "attacker-objects"),
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(tmp_path / "alternate-objects"),
        "GIT_SHALLOW_FILE": str(tmp_path / "attacker-shallow"),
        "GIT_CEILING_DIRECTORIES": str(tmp_path),
        "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.repositoryformatversion",
        "GIT_CONFIG_VALUE_0": "99",
        "GIT_CONFIG_SYSTEM": str(tmp_path / "system-gitconfig"),
        "GIT_CONFIG_GLOBAL": str(tmp_path / "global-gitconfig"),
    }
    for key, value in hostile_git_environment.items():
        monkeypatch.setenv(key, value)
    fake_bin = tmp_path / "attacker-bin"
    fake_bin.mkdir()
    fake_git = fake_bin / "git"
    fake_git.write_text("#!/bin/sh\nexit 99\n", encoding="ascii")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))

    subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(repository),
            "tag",
            "-a",
            "-m",
            "selection tag",
            "selection-tag",
            commit,
        ],
        check=True,
        env=heldout._sanitized_git_environment(),
    )
    tag_oid = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "rev-parse", "selection-tag"],
        check=True,
        capture_output=True,
        text=True,
        env=heldout._sanitized_git_environment(),
    ).stdout.strip()
    with pytest.raises(heldout.HeldoutQualityError, match="commit object"):
        _REAL_ARTIFACT_ORDER_VALIDATOR(
            f"{tag_oid}:scripts/heldout_studies/selection.json",
            selection=selection,
            selection_digest=selection["selection_manifest_sha256"],
            selection_path=selection_path,
            labels_path=labels_path,
            labels_payload=labels,
            repo_root=repository,
        )

    proof = _REAL_ARTIFACT_ORDER_VALIDATOR(
        f"{commit}:scripts/heldout_studies/selection.json",
        selection=selection,
        selection_digest=selection["selection_manifest_sha256"],
        selection_path=selection_path,
        labels_path=labels_path,
        labels_payload=labels,
        repo_root=repository,
    )

    assert proof["selection_commit"] == commit
    assert proof["selection_path"] == "scripts/heldout_studies/selection.json"
    assert proof["labels_exact_bytes_tracked_at_head"] is True
    sanitized = heldout._sanitized_git_environment()
    assert sanitized["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert sanitized["GIT_CONFIG_NOSYSTEM"] == "1"
    assert not (set(hostile_git_environment) - {"GIT_CONFIG_GLOBAL"}).intersection(
        sanitized
    )

    selection_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(heldout.HeldoutQualityError, match="exact bytes differ"):
        _REAL_ARTIFACT_ORDER_VALIDATOR(
            f"{commit}:scripts/heldout_studies/selection.json",
            selection=selection,
            selection_digest=selection["selection_manifest_sha256"],
            selection_path=selection_path,
            labels_path=labels_path,
            labels_payload=labels,
            repo_root=repository,
        )

    selection_path.write_bytes(heldout.canonical_artifact_bytes(selection))
    real_git_command = heldout._git_command
    moved_head = False

    def move_head_after_ancestry_check(
        git_repository: heldout.GitRepository,
        arguments: tuple[str, ...] | list[str],
        *,
        description: str,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal moved_head
        result = real_git_command(
            git_repository,
            arguments,
            description=description,
        )
        if description == "selection commit ancestry" and not moved_head:
            moved_head = True
            subprocess.run(
                [
                    "git",
                    "--no-replace-objects",
                    "-C",
                    str(repository),
                    "commit",
                    "-q",
                    "--allow-empty",
                    "-m",
                    "Move release head",
                ],
                check=True,
                env=heldout._sanitized_git_environment(),
            )
        return result

    monkeypatch.setattr(heldout, "_git_command", move_head_after_ancestry_check)
    with pytest.raises(heldout.HeldoutQualityError, match="HEAD changed"):
        _REAL_ARTIFACT_ORDER_VALIDATOR(
            f"{commit}:scripts/heldout_studies/selection.json",
            selection=selection,
            selection_digest=selection["selection_manifest_sha256"],
            selection_path=selection_path,
            labels_path=labels_path,
            labels_payload=labels,
            repo_root=repository,
        )


@pytest.mark.parametrize(
    ("relative_path", "message"),
    [
        (Path("shallow"), "shallow Git repositories"),
        (Path("objects/info/alternates"), "object alternates"),
        (Path("info/grafts"), "Git grafts"),
    ],
)
def test_git_repository_rejects_external_object_graph_controls(
    tmp_path: Path,
    relative_path: Path,
    message: str,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    control = repository / ".git" / relative_path
    control.parent.mkdir(parents=True, exist_ok=True)
    control.write_text("0" * 40 + "\n", encoding="ascii")

    with pytest.raises(heldout.HeldoutQualityError, match=message):
        heldout._git_repository(repository)


def test_git_repository_rejects_a_symlinked_object_store(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    objects = repository / ".git" / "objects"
    real_objects = repository / ".git" / "objects.real"
    objects.rename(real_objects)
    objects.symlink_to(real_objects, target_is_directory=True)

    with pytest.raises(heldout.HeldoutQualityError, match="object store"):
        heldout._git_repository(repository)


def test_unresolved_and_infrastructure_denominators_fail_closed() -> None:
    snapshot = _snapshot()
    units = list(snapshot.units)
    units[0] = replace(units[0], unresolved_reasons=("fallback_verdict",))
    units[1] = replace(units[1], infrastructure_categories=("clone_failed",))
    selection = _selection(snapshot=replace(snapshot, units=tuple(units)))
    labels = _quality_labels(selection)

    report = _evaluate_selection(selection, labels, _protected())

    assert report["evaluation_complete"] is False
    assert report["release_gate_passed"] is False
    assert report["denominators"]["unresolved"] == 1
    assert report["denominators"]["infrastructure_error"] == 1


def test_formal_labels_reject_inconclusive_reviews_and_resolutions() -> None:
    selection = _selection()
    labels = _quality_labels(selection)
    entry = labels["adjudications"][0]
    entry["primary_review"]["label"] = "INCONCLUSIVE"
    entry["secondary_review"]["label"] = "INCONCLUSIVE"
    entry["resolved_label"] = "INCONCLUSIVE"

    with pytest.raises(heldout.HeldoutQualityError, match="formal label"):
        _evaluate_selection(selection, labels, _protected())


def test_protected_inventory_hashes_files_and_expands_aliases(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    protected_dir = repo / "inputs"
    protected_dir.mkdir(parents=True)
    (protected_dir / "audit.json").write_text(
        '{"cve_id":"CVE-2026-4242"}\n', encoding="utf-8"
    )
    aliases = {
        "CVE-2026-4242": {"CVE-2026-4242", "GHSA-1111-2222-3333"},
        "GHSA-1111-2222-3333": {"CVE-2026-4242", "GHSA-1111-2222-3333"},
    }

    inventory = heldout.build_protected_inventory(repo, [protected_dir], aliases)

    assert inventory.subject_ids == {
        "CVE-2026-4242",
        "GHSA-1111-2222-3333",
    }
    assert inventory.source_roots == ({"path": "inputs", "kind": "directory"},)
    assert inventory.files[0]["path"] == "inputs/audit.json"
    assert len(inventory.files_manifest_sha256) == 64

    prior_manifest = inventory.files_manifest_sha256
    (protected_dir / "later-labels.json").write_text(
        '{"cve_id":"CVE-2026-4343"}\n', encoding="utf-8"
    )
    refreshed = heldout.build_protected_inventory(repo, [protected_dir], aliases)
    assert refreshed.files_manifest_sha256 != prior_manifest
    assert "CVE-2026-4343" in refreshed.subject_ids


def test_protected_alias_closure_collapses_case_equivalent_subject_ids(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    protected = repo / "protected.json"
    protected.parent.mkdir(parents=True)
    protected.write_text('{"id":"GHSA-AAAA-BBBB-CCCC"}\n', encoding="utf-8")
    aliases = {
        "ghsa-aaaa-bbbb-cccc": {
            "ghsa-aaaa-bbbb-cccc",
            "CVE-2026-4242",
        }
    }

    inventory = heldout.build_protected_inventory(repo, (protected,), aliases)

    assert inventory.subject_ids == {
        "CVE-2026-4242",
        "GHSA-AAAA-BBBB-CCCC",
    }
    assert len({subject.casefold() for subject in inventory.subject_ids}) == len(
        inventory.subject_ids
    )


def test_current_mandatory_protected_roots_are_authoritative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    studies = repo / "scripts" / "heldout_studies"
    studies.mkdir(parents=True)
    mandatory = repo / "mandatory.json"
    mandatory.write_text('{"id":"CVE-2026-4000"}\n', encoding="utf-8")
    extra = repo / "extra.json"
    extra.write_text('{"id":"CVE-2026-4001"}\n', encoding="utf-8")
    monkeypatch.setattr(
        heldout,
        "_DEFAULT_PROTECTED_SOURCES",
        (Path("mandatory.json"), Path("scripts/heldout_studies")),
    )

    with pytest.raises(heldout.HeldoutQualityError, match="omits mandatory"):
        heldout._authoritative_protected_sources(
            repo,
            ({"path": "mandatory.json", "kind": "file"},),
        )

    sources = heldout._authoritative_protected_sources(
        repo,
        (
            {"path": "mandatory.json", "kind": "file"},
            {"path": "scripts/heldout_studies", "kind": "directory"},
            {"path": "extra.json", "kind": "file"},
        ),
    )
    assert sources == (mandatory.resolve(), studies.resolve(), extra.resolve())


def test_authoritative_protected_inventory_replays_defaults_and_recorded_extras(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    studies = repo / "scripts" / "heldout_studies"
    studies.mkdir(parents=True)
    mandatory = repo / "mandatory.json"
    mandatory.write_text('{"id":"CVE-2026-4000"}\n', encoding="utf-8")
    extra = repo / "extra.json"
    extra.write_text('{"id":"CVE-2026-4001"}\n', encoding="utf-8")
    monkeypatch.setattr(
        heldout,
        "_DEFAULT_PROTECTED_SOURCES",
        (Path("mandatory.json"), Path("scripts/heldout_studies")),
    )

    selected = heldout.build_authoritative_protected_inventory(
        repo,
        extra_sources=(extra,),
        alias_map={},
    )
    replayed = heldout.build_authoritative_protected_inventory(
        repo,
        recorded_roots=selected.source_roots,
        alias_map={},
    )

    assert replayed == selected
    assert heldout.protected_inventory_contract(replayed) == {
        "source_roots": list(selected.source_roots),
        "files": list(selected.files),
        "files_manifest_sha256": selected.files_manifest_sha256,
        "subject_id_count": 2,
        "subject_ids_sha256": selected.subject_ids_sha256,
    }


def test_historical_studies_remain_protected_while_current_pair_is_excluded(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    studies = repo / "scripts" / "heldout_studies"
    studies.mkdir(parents=True)
    historical = studies / "study-001-labels.json"
    current_selection = studies / "study-002-selection.json"
    current_labels = studies / "study-002-labels.json"
    historical.write_text('{"id":"CVE-2026-4100"}\n', encoding="utf-8")
    current_selection.write_text('{"id":"CVE-2026-4101"}\n', encoding="utf-8")
    current_labels.write_text('{"id":"CVE-2026-4102"}\n', encoding="utf-8")

    inventory = heldout.build_protected_inventory(
        repo,
        (studies,),
        {},
        excluded_paths=(current_selection, current_labels),
    )

    assert inventory.subject_ids == {"CVE-2026-4100"}
    assert [entry["path"] for entry in inventory.files] == [
        "scripts/heldout_studies/study-001-labels.json"
    ]


def test_protected_json_scans_decoded_keys_urls_case_and_filenames(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    protected = repo / "protected"
    protected.mkdir(parents=True)
    (protected / "cve-2026-4200.json").write_text(
        '{"cve\\u002d2026\\u002d4201": {'
        '"url":"https://example.invalid/advisories/ghsa-aaaa-bbbb-cccc",'
        '"encoded":"https://example.invalid/CVE%2D2026%2D4202"}}',
        encoding="utf-8",
    )

    inventory = heldout.build_protected_inventory(repo, (protected,), {})

    assert inventory.subject_ids == {
        "CVE-2026-4200",
        "CVE-2026-4201",
        "CVE-2026-4202",
        "GHSA-AAAA-BBBB-CCCC",
    }


def test_protected_inventory_decodes_twice_and_finds_ids_embedded_in_filenames(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    protected = repo / "protected"
    protected.mkdir(parents=True)
    (protected / "audit_CVE-2026-4300_final.json").write_text(
        json.dumps(
            {
                "attachment": "review_GHSA-aaaa-bbbb-cccc_notes.json",
                "double_encoded": "CVE%252D2026%252D4301",
            }
        ),
        encoding="utf-8",
    )

    inventory = heldout.build_protected_inventory(repo, (protected,), {})

    assert inventory.subject_ids == {
        "CVE-2026-4300",
        "CVE-2026-4301",
        "GHSA-AAAA-BBBB-CCCC",
    }


def test_protected_inventory_decodes_five_layers_and_scans_directory_components(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    protected = repo / "protected" / "audit_CVE-2026-4400_bucket"
    protected.mkdir(parents=True)
    encoded = "CVE%2D2026%2D4401"
    for _round in range(4):
        encoded = encoded.replace("%", "%25")
    (protected / "record.json").write_text(
        json.dumps({"five_layers": encoded}), encoding="utf-8"
    )

    inventory = heldout.build_protected_inventory(repo, (repo / "protected",), {})

    assert inventory.subject_ids == {"CVE-2026-4400", "CVE-2026-4401"}


def test_protected_inventory_scans_complete_dotted_directory_components(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    protected = repo / "protected" / "bucket.CVE-2026-5555"
    protected.mkdir(parents=True)
    (protected / "record.dat").write_text("{}\n", encoding="utf-8")

    inventory = heldout.build_protected_inventory(repo, (repo / "protected",), {})

    assert inventory.subject_ids == {"CVE-2026-5555"}


def test_protected_inventory_fails_closed_when_percent_decoding_never_stabilizes(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    protected = repo / "protected"
    protected.mkdir(parents=True)
    encoded = "CVE%2D2026%2D4402"
    for _round in range(heldout._MAX_URL_UNQUOTE_ROUNDS):
        encoded = encoded.replace("%", "%25")
    (protected / "record.json").write_text(
        json.dumps({"over_encoded": encoded}), encoding="utf-8"
    )

    with pytest.raises(heldout.HeldoutQualityError, match="did not stabilize"):
        heldout.build_protected_inventory(repo, (protected,), {})


def test_protected_inventory_bounds_percent_decoding_input_length(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    protected = repo / "protected"
    protected.mkdir(parents=True)
    (protected / "record.json").write_text(
        json.dumps({"oversized": "x" * 64}), encoding="utf-8"
    )
    monkeypatch.setattr(heldout, "_MAX_PROTECTED_VALUE_CHARS", 32)

    with pytest.raises(heldout.HeldoutQualityError, match="exceeds decode bound"):
        heldout.build_protected_inventory(repo, (protected,), {})


def test_protected_inventory_extracts_exact_and_embedded_year_based_ids(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    protected = repo / "protected"
    protected.mkdir(parents=True)
    (protected / "OSV-2026-371.json").write_text("{}\n", encoding="utf-8")
    (protected / "audit_RUSTSEC-2026-0207_final.json").write_text(
        "{}\n", encoding="utf-8"
    )

    inventory = heldout.build_protected_inventory(repo, (protected,), {})

    assert inventory.subject_ids == {"OSV-2026-371", "RUSTSEC-2026-0207"}


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unsorted"])
def test_selection_rejects_non_exact_campaign_result_subject_sets(
    mutation: str,
) -> None:
    selection = _selection()
    row = selection["samples"]["precision"][0]
    assert row["campaign_results"]
    if mutation == "missing":
        row["campaign_results"] = []
    elif mutation == "duplicate":
        row["campaign_results"].append(dict(row["campaign_results"][0]))
    else:
        row["campaign_results"].append(
            {
                "subject_id": row["subject_ids"][0],
                "sha256": "f" * 64,
            }
        )
        row["campaign_results"].reverse()
    selection.pop("selection_manifest_sha256")
    selection = heldout._seal_selection(selection)

    with pytest.raises(heldout.HeldoutQualityError, match="campaign_results"):
        heldout.build_label_template(selection)


def test_selection_rejects_conflicting_rows_for_one_cross_lane_sample() -> None:
    selection = _selection()
    precision_by_id = {
        row["sample_id"]: row for row in selection["samples"]["precision"]
    }
    overlap = next(
        row
        for row in selection["samples"]["recall"]
        if row["sample_id"] in precision_by_id
    )
    overlap["campaign_results"][0]["sha256"] = "f" * 64
    selection.pop("selection_manifest_sha256")
    selection = heldout._seal_selection(selection)

    with pytest.raises(heldout.HeldoutQualityError, match="conflicts across lane"):
        heldout.build_label_template(selection)


def test_selection_rejects_case_variant_cross_lane_duplicates() -> None:
    selection = _selection()
    precision_by_id = {
        row["sample_id"]: row for row in selection["samples"]["precision"]
    }
    overlap = next(
        row
        for row in selection["samples"]["recall"]
        if row["sample_id"] in precision_by_id
    )
    overlap["sample_id"] = overlap["sample_id"].lower()
    overlap["subject_ids"] = [item.lower() for item in overlap["subject_ids"]]
    for result in overlap["campaign_results"]:
        result["subject_id"] = result["subject_id"].lower()
    selection.pop("selection_manifest_sha256")
    selection = heldout._seal_selection(selection)

    with pytest.raises(heldout.HeldoutQualityError, match="conflicts across lane"):
        heldout.build_label_template(selection)


def test_selection_rejects_case_variant_subject_duplicates() -> None:
    selection = _selection()
    row = selection["samples"]["precision"][0]
    subject_id = row["subject_ids"][0]
    row["subject_ids"] = sorted([subject_id, subject_id.lower()])
    row["campaign_results"] = sorted(
        [
            *row["campaign_results"],
            {
                "subject_id": subject_id.lower(),
                "sha256": row["campaign_results"][0]["sha256"],
            },
        ],
        key=lambda result: result["subject_id"],
    )
    selection.pop("selection_manifest_sha256")
    selection = heldout._seal_selection(selection)

    with pytest.raises(heldout.HeldoutQualityError, match="invalid subject_ids"):
        heldout.build_label_template(selection)


def test_heldout_reader_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "selection.json"
    target.write_text("{}\n", encoding="utf-8")
    link = tmp_path / "selection-link.json"
    link.symlink_to(target)

    with pytest.raises(heldout.HeldoutQualityError, match="cannot open"):
        heldout._read_json_object(
            link,
            "held-out selection",
            max_bytes=heldout._MAX_SELECTION_BYTES,
        )


def test_protected_inventory_bounds_each_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = tmp_path / "protected.json"
    protected.write_text('{"payload":"xxxxxxxxxxxxxxxx"}\n', encoding="utf-8")
    monkeypatch.setattr(heldout, "_MAX_PROTECTED_INPUT_BYTES", 8)

    with pytest.raises(heldout.HeldoutQualityError, match="size bound"):
        heldout.build_protected_inventory(tmp_path, (protected,), {})


def test_protected_inventory_bounds_aggregate_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "one.json").write_text("{}\n", encoding="utf-8")
    (protected / "two.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(heldout, "_MAX_PROTECTED_INPUTS_TOTAL_BYTES", 4)

    with pytest.raises(heldout.HeldoutQualityError, match="aggregate input size bound"):
        heldout.build_protected_inventory(tmp_path, (protected,), {})


def test_heldout_label_reader_bounds_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    labels = tmp_path / "labels.json"
    labels.write_text('{"labels":[]}\n', encoding="utf-8")
    monkeypatch.setattr(heldout, "_MAX_LABEL_BYTES", 8)

    with pytest.raises(heldout.HeldoutQualityError, match="size bound"):
        heldout._read_json_object(
            labels,
            "held-out labels",
            max_bytes=heldout._MAX_LABEL_BYTES,
        )


def test_label_template_contains_no_fabricated_labels() -> None:
    template = heldout.build_label_template(_selection())

    assert template["schema_version"] == 3
    assert template["audit_protocol"]["audit_started_from_null_label_template"] is False
    forbidden_blinding_fields = {
        "aggregate_quality_scores",
        "candidate_positive",
        "lanes",
        "predicted_positive",
        "prediction_reasons",
        "precision",
        "recall",
        "selection_rank_sha256",
    }
    assert all(
        forbidden_blinding_fields.isdisjoint(entry)
        for entry in template["adjudications"]
    )
    assert all(
        entry["primary_review"]["label"] is None
        and entry["secondary_review"]["label"] is None
        and entry["resolved_label"] is None
        for entry in template["adjudications"]
    )
    assert all(
        entry["primary_review"]["evidence_refs"] == []
        and entry["secondary_review"]["evidence_refs"] == []
        and entry["resolution"]["evidence_refs"] == []
        for entry in template["adjudications"]
    )


def test_documented_label_fixture_matches_generated_schema_three_shape() -> None:
    documented = json.loads(
        (
            Path(__file__).parents[1] / "fixtures/heldout-quality-labels.template.json"
        ).read_text(encoding="utf-8")
    )
    generated = heldout.build_label_template(_selection())

    assert documented["schema_version"] == generated["schema_version"] == 3
    assert set(documented["audit_protocol"]) == set(generated["audit_protocol"])
    assert set(documented["adjudications"][0]) == set(generated["adjudications"][0])
    for field in ("primary_review", "secondary_review", "resolution"):
        assert set(documented["adjudications"][0][field]) == set(
            generated["adjudications"][0][field]
        )


def test_campaign_loader_rejects_missing_full_plan_proof(monkeypatch, tmp_path) -> None:
    class Batch:
        ids = ("CVE-2026-9000",)

    class Context:
        batches = (Batch(),)
        result_dir = tmp_path / "results"

    monkeypatch.setattr(
        heldout.detector_quality,
        "_current_fixed_campaign_context",
        lambda _repo_root: Context(),
    )
    monkeypatch.setattr(
        heldout.detector_quality,
        "_load_class_snapshot_inputs",
        lambda _result_dir, _corpus: {},
    )
    monkeypatch.setattr(
        heldout.detector_quality,
        "_fixed_contract_campaign_proof",
        lambda _corpus, _inputs, _context: {
            "complete": False,
            "failure_counts": {"missing_marker": 1},
        },
    )

    with pytest.raises(heldout.HeldoutQualityError, match="missing_marker"):
        heldout.load_fixed_campaign_snapshot(tmp_path, alias_map={})
