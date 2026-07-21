"""Finite-population and blinding contracts for the end-to-end recall audit."""

from __future__ import annotations

import itertools
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

import build_recall_audit as recall_audit
import heldout_quality_gate as heldout


_SYSTEM_TEST_SEED = "a" * 64
_SELECTION_PATH = "scripts/heldout_studies/recall-selection.json"


def _row(class_id: str, stratum: str) -> dict:
    row = {
        "class_id": class_id,
        "member_ids": [class_id],
        "analysis_subject": class_id,
        "coverage_status": "complete",
        "detector_state": "positive" if stratum == "detected_positive" else "negative",
        "adjudication_state": "unreviewed",
        "publication_state": "withheld",
        "recall_stratum": stratum,
    }
    row["component_sha256"] = hashlib.sha256(f"{class_id}\n".encode()).hexdigest()
    return row


def _set_members(row: dict, member_ids: list[str]) -> None:
    row["member_ids"] = member_ids
    row["component_sha256"] = hashlib.sha256(
        ("\n".join(sorted(member_ids)) + "\n").encode()
    ).hexdigest()


def _inventory(
    rows: list[dict], *, complete: bool = True, mode: str = "formal"
) -> dict:
    payload = {
        "schema_version": 2,
        "kind": "ai_vulnerability_detector_inventory",
        "generated_at": "2026-07-19T00:00:00+00:00",
        "source_snapshot_sha256": "b" * 64,
        "source_alias_class_manifest_sha256": "d" * 64,
        "campaign_id": "c" * 64,
        "campaign_mode": mode,
        "complete": complete,
        "alias_class_count": len(rows),
        "rows": rows,
    }
    payload["inventory_id"] = recall_audit.canonical_sha256(payload)
    return payload


def _review(reviewer: str, label: str) -> dict:
    return {
        "reviewer_id": reviewer,
        "label": label,
        "evidence_refs": ["pr:https://example.test/pull/1"],
        "rationale": "Repository history establishes causality and authorship.",
    }


def _protected(*subject_ids: str) -> heldout.ProtectedInventory:
    sorted_ids = sorted(subject_ids)
    return heldout.ProtectedInventory(
        subject_ids=frozenset(sorted_ids),
        source_roots=(),
        files=(),
        files_manifest_sha256=heldout.canonical_sha256([]),
        subject_ids_sha256=heldout.canonical_sha256(sorted_ids),
    )


def _selection(
    inventory: dict,
    sample_sizes: dict[str, object],
    *,
    protected_subject_ids: frozenset[str] = frozenset(),
) -> dict:
    return recall_audit.build_selection_manifest(
        inventory,
        sample_sizes=sample_sizes,
        seed=_SYSTEM_TEST_SEED,
        seed_origin=recall_audit.SYSTEM_CSPRNG_SEED_ORIGIN,
        protected=_protected(*protected_subject_ids),
    )


def _protected_from_selection(selection: dict) -> heldout.ProtectedInventory:
    contract = selection["protected_inputs"]
    return heldout.ProtectedInventory(
        subject_ids=frozenset(selection["population"]["protected_subject_ids"]),
        source_roots=tuple(contract["source_roots"]),
        files=tuple(contract["files"]),
        files_manifest_sha256=contract["files_manifest_sha256"],
        subject_ids_sha256=contract["subject_ids_sha256"],
    )


def _labels(
    selection: dict,
    *,
    primary: str = "AI_CAUSAL",
    secondary: str = "AI_CAUSAL",
    third: str | None = None,
    primary_reviewer: str = "reviewer-a",
    secondary_reviewer: str = "reviewer-b",
    census_primary: str = "AI_CAUSAL",
    census_secondary: str = "AI_CAUSAL",
    census_third: str | None = None,
    selection_commit_reference: str | None = None,
) -> dict:
    reference = selection_commit_reference or f"{'9' * 40}:{_SELECTION_PATH}"
    audit_protocol = recall_audit.required_review_protocol(reference)
    adjudications = []
    for assignment in selection["assignments"]:
        adjudications.append(
            {
                "packet_id": assignment["packet_id"],
                "primary_review": _review(primary_reviewer, primary),
                "secondary_review": _review(secondary_reviewer, secondary),
                "third_review": _review("reviewer-c", third) if third else None,
            }
        )
    census_adjudications = []
    for assignment in selection["protected_census"]["assignments"]:
        census_adjudications.append(
            {
                "packet_id": assignment["packet_id"],
                "primary_review": _review("census-reviewer-a", census_primary),
                "secondary_review": _review("census-reviewer-b", census_secondary),
                "third_review": (
                    _review("census-reviewer-c", census_third) if census_third else None
                ),
            }
        )
    return {
        "schema_version": recall_audit.LABEL_SCHEMA_VERSION,
        "kind": "end_to_end_recall_independent_audit",
        "selection_manifest_sha256": selection["selection_manifest_sha256"],
        "audit_protocol": audit_protocol,
        "adjudications": adjudications,
        "protected_census": {
            "schema_version": recall_audit.PROTECTED_CENSUS_LABEL_SCHEMA_VERSION,
            "kind": "protected_alias_class_census_independent_audit",
            "census_manifest_sha256": selection["protected_census"][
                "census_manifest_sha256"
            ],
            "audit_protocol_sha256": recall_audit.canonical_sha256(audit_protocol),
            "adjudications": census_adjudications,
        },
    }


def _stub_artifact_order(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recall_audit,
        "_prove_artifact_order",
        lambda *_args, **_kwargs: {
            "selection_commit_reference": f"{'9' * 40}:{_SELECTION_PATH}",
            "selection_is_strict_ancestor": True,
            "labels_absent_from_selection_commit": True,
            "labels_exact_bytes_tracked_at_head": True,
        },
    )


def _evaluate(
    selection: dict,
    labels: dict,
    inventory: dict,
    *,
    verify_artifact_order: bool = False,
) -> dict:
    return recall_audit.evaluate_labels(
        selection,
        labels,
        inventory=inventory,
        protected=_protected_from_selection(selection),
        selection_path=Path(_SELECTION_PATH),
        labels_path=Path("scripts/heldout_studies/recall-labels.json"),
        verify_artifact_order=verify_artifact_order,
    )


def _write_canonical(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )


def test_selection_partitions_all_end_to_end_strata_and_hides_detector_fields() -> None:
    strata = list(recall_audit.AUDIT_STRATA)
    rows = [
        _row(f"CVE-2026-{index + 1}", stratum) for index, stratum in enumerate(strata)
    ]
    rows.append(_row("CVE-2026-99", "no_current_campaign_result"))
    inventory = _inventory(rows)

    selection = _selection(inventory, {stratum: 1 for stratum in strata})

    assert selection["schema_version"] == 4
    assert set(selection["population"]["strata"]) == set(strata)
    assert selection["population"]["coverage_failure_count"] == 1
    assert len(selection["assignments"]) == len(strata)
    assert all(row["selection_probability"] == 1.0 for row in selection["assignments"])
    assert all(
        set(packet) == {"packet_id", "subject_ids"}
        for packet in selection["blinded_review_packets"]
    )
    assert selection["selection_policy"]["seed"] == _SYSTEM_TEST_SEED
    assert selection["protected_inputs"] == {
        "policy": "heldout_authoritative_protected_roots_v1",
        "source_roots": [],
        "files": [],
        "files_manifest_sha256": heldout.canonical_sha256([]),
        "subject_id_count": 0,
        "subject_ids_sha256": heldout.canonical_sha256([]),
    }
    assert selection["selection_manifest_sha256"] == recall_audit.selection_sha256(
        selection
    )
    assert (
        recall_audit.replay_selection_manifest(
            selection,
            inventory,
            protected=_protected_from_selection(selection),
        )
        == selection["selection_manifest_sha256"]
    )


def test_selection_generates_a_system_csprng_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recall_audit.secrets, "token_hex", lambda size: "d" * (size * 2)
    )
    inventory = _inventory([_row("CVE-2026-1", "detected_positive")])

    selection = recall_audit.build_selection_manifest(
        inventory,
        sample_sizes={"detected_positive": 1},
        protected=_protected(),
    )

    assert selection["selection_policy"]["seed"] == "d" * 64
    assert selection["selection_policy"]["seed_origin"] == "system_csprng"


def test_formal_selection_rejects_incremental_or_incomplete_inventory() -> None:
    rows = [_row("CVE-2026-1", "detected_positive")]
    with pytest.raises(recall_audit.RecallAuditError, match="formal"):
        _selection(_inventory(rows, mode="incremental"), {"detected_positive": 1})
    with pytest.raises(recall_audit.RecallAuditError, match="complete"):
        _selection(_inventory(rows, complete=False), {"detected_positive": 1})


def test_formal_selection_accepts_source_manifest_alias_class_identity() -> None:
    members = ["CVE-2026-1", "GHSA-aaaa-bbbb-cccc"]
    component_sha256 = hashlib.sha256(
        ("\n".join(sorted(members)) + "\n").encode()
    ).hexdigest()
    row = _row("CVE-2026-placeholder", "detected_positive")
    row.update(
        {
            "class_id": f"alias-{component_sha256[:24]}",
            "component_sha256": component_sha256,
            "analysis_subject": "CVE-2026-1",
            "member_ids": members,
        }
    )

    selection = _selection(
        _inventory([row]),
        {"detected_positive": 1},
    )

    assert selection["assignments"][0]["class_id"] == row["class_id"]
    assert selection["assignments"][0]["subject_ids"] == sorted(members)


def test_inventory_requires_disjoint_canonical_alias_classes() -> None:
    first = _row("CVE-2026-1", "detected_positive")
    _set_members(first, ["CVE-2026-1", "GHSA-aaaa-bbbb-cccc"])
    overlap = _row("CVE-2026-2", "fix_no_bic")
    _set_members(overlap, ["CVE-2026-2", "ghsa-AAAA-BBBB-CCCC"])
    with pytest.raises(recall_audit.RecallAuditError, match="belongs to both"):
        _selection(
            _inventory([first, overlap]),
            {"detected_positive": 1, "fix_no_bic": 1},
        )

    missing_canonical = _row("CVE-2026-3", "detected_positive")
    _set_members(missing_canonical, ["GHSA-dddd-eeee-ffff"])
    with pytest.raises(recall_audit.RecallAuditError, match="invalid detector"):
        _selection(_inventory([missing_canonical]), {"detected_positive": 1})


def test_selection_excludes_only_authoritative_alias_protected_subjects() -> None:
    prior = _row("CVE-2026-1", "detected_positive")
    prior["adjudication_state"] = "ai_causal"
    alias_protected = _row("CVE-2026-2", "detected_positive")
    _set_members(alias_protected, ["CVE-2026-2", "GHSA-aaaa-bbbb-cccc"])
    fresh = _row("CVE-2026-3", "detected_positive")
    inventory = _inventory([prior, alias_protected, fresh])

    selection = _selection(
        inventory,
        {"detected_positive": 2},
        protected_subject_ids=frozenset({"GHSA-aaaa-bbbb-cccc"}),
    )

    assert {row["class_id"] for row in selection["assignments"]} == {
        "CVE-2026-1",
        "CVE-2026-3",
    }
    assert selection["population"]["protected_excluded_class_count"] == 1
    assert selection["population"]["protected_excluded_class_ids"] == [
        "CVE-2026-2",
    ]


def test_protected_overlap_builds_separately_sealed_exact_once_census() -> None:
    protected_row = _row("CVE-2026-2", "detected_positive")
    _set_members(protected_row, ["CVE-2026-2", "GHSA-aaaa-bbbb-cccc"])
    fresh_row = _row("CVE-2026-3", "detected_positive")
    inventory = _inventory([protected_row, fresh_row])

    selection = _selection(
        inventory,
        {"detected_positive": 1},
        protected_subject_ids=frozenset({"GHSA-aaaa-bbbb-cccc"}),
    )

    census = selection["protected_census"]
    assert selection["schema_version"] == 4
    assert census["schema_version"] == recall_audit.PROTECTED_CENSUS_SCHEMA_VERSION
    assert census["census_manifest_sha256"] == (
        recall_audit.protected_census_sha256(census)
    )
    assert census["inventory"] == {
        "inventory_id": inventory["inventory_id"],
        "source_snapshot_sha256": inventory["source_snapshot_sha256"],
        "source_alias_class_manifest_sha256": inventory[
            "source_alias_class_manifest_sha256"
        ],
        "campaign_id": inventory["campaign_id"],
    }
    assert census["protected_inputs"] == selection["protected_inputs"]
    assert census["population"]["class_count"] == 1
    assert census["population"]["class_ids"] == [protected_row["class_id"]]
    assert [row["class_id"] for row in census["assignments"]] == [
        protected_row["class_id"]
    ]
    assert all(
        set(packet) == {"packet_id", "subject_ids"}
        for packet in census["blinded_review_packets"]
    )
    assert [row["class_id"] for row in selection["assignments"]] == [
        fresh_row["class_id"]
    ]


def test_protected_census_tamper_fails_independent_seal_and_exact_replay() -> None:
    protected_row = _row("CVE-2026-1", "detected_positive")
    fresh_row = _row("CVE-2026-2", "detected_positive")
    inventory = _inventory([protected_row, fresh_row])
    protected = _protected("CVE-2026-1")
    selection = recall_audit.build_selection_manifest(
        inventory,
        sample_sizes={"detected_positive": 1},
        seed=_SYSTEM_TEST_SEED,
        seed_origin=recall_audit.SYSTEM_CSPRNG_SEED_ORIGIN,
        protected=protected,
    )
    tampered = json.loads(json.dumps(selection))
    tampered["protected_census"]["assignments"] = []
    tampered["selection_manifest_sha256"] = recall_audit.selection_sha256(tampered)

    with pytest.raises(recall_audit.RecallAuditError, match="census seal"):
        recall_audit.validate_selection_seal(tampered)

    tampered = json.loads(json.dumps(selection))
    tampered["protected_census"]["assignments"][0]["stratum"] = "fix_no_bic"
    projection = recall_audit._census_class_projection(
        tampered["protected_census"]["assignments"]
    )
    tampered["protected_census"]["population"]["classes_manifest_sha256"] = (
        recall_audit.canonical_sha256(projection)
    )
    tampered["protected_census"]["census_manifest_sha256"] = (
        recall_audit.protected_census_sha256(tampered["protected_census"])
    )
    tampered["selection_manifest_sha256"] = recall_audit.selection_sha256(tampered)
    with pytest.raises(recall_audit.RecallAuditError, match="exactly replay"):
        recall_audit.replay_selection_manifest(
            tampered,
            inventory,
            protected=protected,
        )


def test_complete_protected_census_contributes_exact_counts_to_formal_recall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_artifact_order(monkeypatch)
    protected_row = _row("CVE-2026-1", "detected_positive")
    missed_row = _row("CVE-2026-2", "fix_no_bic")
    inventory = _inventory([protected_row, missed_row])
    selection = _selection(
        inventory,
        {"fix_no_bic": 1},
        protected_subject_ids=frozenset({"CVE-2026-1"}),
    )

    report = _evaluate(
        selection,
        _labels(selection),
        inventory,
        verify_artifact_order=True,
    )

    assert report["evaluation_complete"] is True
    assert report["evaluation_blockers"] == []
    assert report["protected_overlap_class_count"] == 1
    assert report["protected_census_complete"] is True
    assert report["protected_excluded_class_count"] == 0
    assert report["protected_census_resolved_labels"] == {
        selection["protected_census"]["assignments"][0]["packet_id"]: "AI_CAUSAL"
    }
    assert report["recall"]["true_positive_estimate"] == 1
    assert report["recall"]["missed_positive_estimate"] == 1
    assert report["recall"]["recall_point"] == 0.5
    assert report["recall"]["protected_census"]["class_count"] == 1


def test_unknown_or_incomplete_protected_census_remains_release_blocking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_artifact_order(monkeypatch)
    inventory = _inventory(
        [
            _row("CVE-2026-1", "detected_positive"),
            _row("CVE-2026-2", "fix_no_bic"),
        ]
    )
    selection = _selection(
        inventory,
        {"fix_no_bic": 1},
        protected_subject_ids=frozenset({"CVE-2026-1"}),
    )

    report = _evaluate(
        selection,
        _labels(
            selection,
            census_primary="UNKNOWN",
            census_secondary="AI_CAUSAL",
        ),
        inventory,
        verify_artifact_order=True,
    )

    census_packet = selection["protected_census"]["assignments"][0]["packet_id"]
    assert report["evaluation_complete"] is False
    assert report["evaluation_blockers"] == ["protected_census_incomplete"]
    assert report["protected_census_complete"] is False
    assert report["protected_census_unresolved_packet_ids"] == [census_packet]
    assert report["protected_excluded_class_count"] == 1
    assert report["recall"] is None


def test_protected_census_labels_are_digest_bound_and_exact_once() -> None:
    inventory = _inventory(
        [
            _row("CVE-2026-1", "detected_positive"),
            _row("CVE-2026-2", "fix_no_bic"),
        ]
    )
    selection = _selection(
        inventory,
        {"fix_no_bic": 1},
        protected_subject_ids=frozenset({"CVE-2026-1"}),
    )
    labels = _labels(selection)
    labels["protected_census"]["census_manifest_sha256"] = "0" * 64
    with pytest.raises(recall_audit.RecallAuditError, match="census labels.*sealed"):
        _evaluate(selection, labels, inventory)

    labels = _labels(selection)
    labels["protected_census"]["adjudications"].append(
        labels["protected_census"]["adjudications"][0]
    )
    with pytest.raises(recall_audit.RecallAuditError, match="exactly one adjudication"):
        _evaluate(selection, labels, inventory)


def test_authoritative_protected_provenance_replays_and_detects_file_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repo"
    studies = repository / "scripts" / "heldout_studies"
    studies.mkdir(parents=True)
    mandatory = repository / "mandatory.json"
    mandatory.write_text('{"id":"CVE-2026-1"}\n', encoding="utf-8")
    extra = repository / "extra.json"
    extra.write_text('{"id":"CVE-2026-2"}\n', encoding="utf-8")
    monkeypatch.setattr(
        heldout,
        "_DEFAULT_PROTECTED_SOURCES",
        (Path("mandatory.json"), Path("scripts/heldout_studies")),
    )
    protected = heldout.build_authoritative_protected_inventory(
        repository,
        extra_sources=(extra,),
        alias_map={},
    )
    inventory = _inventory(
        [
            _row("CVE-2026-1", "detected_positive"),
            _row("CVE-2026-2", "detected_positive"),
            _row("CVE-2026-3", "detected_positive"),
        ]
    )
    selection = recall_audit.build_selection_manifest(
        inventory,
        sample_sizes={"detected_positive": 1},
        protected=protected,
        seed=_SYSTEM_TEST_SEED,
        seed_origin=recall_audit.SYSTEM_CSPRNG_SEED_ORIGIN,
    )
    selection_path = studies / "recall-selection.json"
    labels_path = studies / "recall-labels.json"
    _write_canonical(selection_path, selection)
    labels_path.write_text('{"id":"CVE-2026-9999"}\n', encoding="utf-8")

    replayed = recall_audit._rebuild_authoritative_protected_inventory(
        selection,
        repo_root=repository,
        selection_path=selection_path,
        labels_path=labels_path,
        alias_map={},
    )

    assert replayed == protected
    assert (
        recall_audit.replay_selection_manifest(
            selection,
            inventory,
            protected=replayed,
        )
        == selection["selection_manifest_sha256"]
    )

    extra.write_text(
        '{"id":"CVE-2026-2","aliases":["CVE-2026-4"]}\n',
        encoding="utf-8",
    )
    with pytest.raises(recall_audit.RecallAuditError, match="protected inputs drifted"):
        recall_audit._rebuild_authoritative_protected_inventory(
            selection,
            repo_root=repository,
            selection_path=selection_path,
            labels_path=labels_path,
            alias_map={},
        )


def test_authoritative_protected_provenance_rejects_missing_mandatory_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repo"
    studies = repository / "scripts" / "heldout_studies"
    studies.mkdir(parents=True)
    mandatory = repository / "mandatory.json"
    mandatory.write_text('{"id":"CVE-2026-1"}\n', encoding="utf-8")
    monkeypatch.setattr(
        heldout,
        "_DEFAULT_PROTECTED_SOURCES",
        (Path("mandatory.json"), Path("scripts/heldout_studies")),
    )
    selection = _selection(
        _inventory([_row("CVE-2026-2", "detected_positive")]),
        {"detected_positive": 1},
    )
    selection["protected_inputs"]["source_roots"] = [
        {"path": "scripts/heldout_studies", "kind": "directory"}
    ]
    selection["selection_manifest_sha256"] = recall_audit.selection_sha256(selection)

    with pytest.raises(recall_audit.RecallAuditError, match="omits mandatory"):
        recall_audit._rebuild_authoritative_protected_inventory(
            selection,
            repo_root=repository,
            selection_path=studies / "recall-selection.json",
            labels_path=studies / "recall-labels.json",
            alias_map={},
        )


def test_legacy_protected_ids_is_an_additive_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repo"
    studies = repository / "scripts" / "heldout_studies"
    studies.mkdir(parents=True)
    mandatory = repository / "mandatory.json"
    mandatory.write_text('{"id":"CVE-2026-1"}\n', encoding="utf-8")
    extra = repository / "extra.json"
    extra.write_text('{"id":"CVE-2026-2"}\n', encoding="utf-8")
    legacy = repository / "legacy-protected-ids.json"
    legacy.write_text('{"subject_ids":[]}\n', encoding="utf-8")
    monkeypatch.setattr(
        heldout,
        "_DEFAULT_PROTECTED_SOURCES",
        (Path("mandatory.json"), Path("scripts/heldout_studies")),
    )
    monkeypatch.setattr(heldout, "build_alias_map", lambda: {})
    inventory_path = repository / "inventory.json"
    sample_sizes_path = repository / "sample-sizes.json"
    output_path = repository / "selection.json"
    _write_canonical(
        inventory_path,
        _inventory(
            [
                _row("CVE-2026-1", "detected_positive"),
                _row("CVE-2026-2", "detected_positive"),
                _row("CVE-2026-3", "detected_positive"),
            ]
        ),
    )
    _write_canonical(sample_sizes_path, {"detected_positive": 1})

    assert (
        recall_audit.main(
            [
                "select",
                "--repo-root",
                str(repository),
                "--inventory",
                str(inventory_path),
                "--sample-sizes",
                str(sample_sizes_path),
                "--protected-ids",
                str(legacy),
                "--protected-source",
                str(extra),
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    selection = json.loads(output_path.read_text(encoding="utf-8"))

    assert selection["population"]["protected_excluded_class_ids"] == [
        "CVE-2026-1",
        "CVE-2026-2",
    ]
    assert {root["path"] for root in selection["protected_inputs"]["source_roots"]} == {
        "extra.json",
        "legacy-protected-ids.json",
        "mandatory.json",
        "scripts/heldout_studies",
    }


def test_select_expands_protected_ids_from_formal_inventory_alias_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repo"
    studies = repository / "scripts" / "heldout_studies"
    studies.mkdir(parents=True)
    mandatory = repository / "mandatory.json"
    mandatory.write_text('{"id":"GHSA-aaaa-bbbb-cccc"}\n', encoding="utf-8")
    monkeypatch.setattr(
        heldout,
        "_DEFAULT_PROTECTED_SOURCES",
        (Path("mandatory.json"), Path("scripts/heldout_studies")),
    )
    monkeypatch.setattr(
        heldout,
        "build_alias_map",
        lambda: pytest.fail("global publication aliases must not drive recall census"),
    )
    protected_row = _row("CVE-2026-placeholder", "detected_positive")
    members = ["CVE-2026-1", "GHSA-aaaa-bbbb-cccc"]
    component_sha256 = hashlib.sha256(
        ("\n".join(sorted(members)) + "\n").encode()
    ).hexdigest()
    protected_row.update(
        {
            "class_id": f"alias-{component_sha256[:24]}",
            "component_sha256": component_sha256,
            "analysis_subject": "CVE-2026-1",
            "member_ids": members,
        }
    )
    fresh_row = _row("CVE-2026-2", "detected_positive")
    inventory_path = repository / "inventory.json"
    sample_sizes_path = repository / "sample-sizes.json"
    output_path = repository / "selection.json"
    _write_canonical(inventory_path, _inventory([protected_row, fresh_row]))
    _write_canonical(sample_sizes_path, {"detected_positive": 1})

    assert (
        recall_audit.main(
            [
                "select",
                "--repo-root",
                str(repository),
                "--inventory",
                str(inventory_path),
                "--sample-sizes",
                str(sample_sizes_path),
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    selection = json.loads(output_path.read_text(encoding="utf-8"))

    assert selection["population"]["protected_excluded_class_ids"] == [
        protected_row["class_id"]
    ]
    assert selection["protected_census"]["population"]["class_ids"] == [
        protected_row["class_id"]
    ]
    assert [row["class_id"] for row in selection["assignments"]] == [
        fresh_row["class_id"]
    ]


def test_select_rejects_existing_output_before_protected_inventory_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory_path = tmp_path / "inventory.json"
    sample_sizes_path = tmp_path / "sample-sizes.json"
    output_path = tmp_path / "selection.json"
    _write_canonical(
        inventory_path,
        _inventory([_row("CVE-2026-1", "detected_positive")]),
    )
    _write_canonical(sample_sizes_path, {"detected_positive": 1})
    output_path.write_text("sealed prior evidence\n", encoding="utf-8")

    def fail_if_scanned(*_args: object, **_kwargs: object) -> None:
        pytest.fail("protected inventory scan ran before output precondition")

    monkeypatch.setattr(
        heldout,
        "build_authoritative_protected_inventory",
        fail_if_scanned,
    )

    with pytest.raises(recall_audit.RecallAuditError, match="must not already exist"):
        recall_audit.main(
            [
                "select",
                "--repo-root",
                str(tmp_path),
                "--inventory",
                str(inventory_path),
                "--sample-sizes",
                str(sample_sizes_path),
                "--output",
                str(output_path),
            ]
        )

    assert output_path.read_text(encoding="utf-8") == "sealed prior evidence\n"


@pytest.mark.parametrize("population_size", range(1, 9))
def test_hypergeometric_interval_covers_every_exhaustive_finite_population(
    population_size: int,
) -> None:
    for true_total in range(population_size + 1):
        population = [1] * true_total + [0] * (population_size - true_total)
        for sample_size in range(1, population_size + 1):
            for sample in itertools.combinations(range(population_size), sample_size):
                observed = sum(population[index] for index in sample)
                lower, upper = recall_audit.hypergeometric_total_interval(
                    population_size,
                    sample_size,
                    observed,
                    confidence_level=0.95,
                )
                assert 0 <= lower <= upper <= population_size


def test_hypergeometric_interval_has_at_least_nominal_exhaustive_coverage() -> None:
    population_size = 9
    sample_size = 4
    for true_total in range(population_size + 1):
        covered = 0
        trials = 0
        population = [1] * true_total + [0] * (population_size - true_total)
        for sample in itertools.combinations(range(population_size), sample_size):
            observed = sum(population[index] for index in sample)
            interval = recall_audit.hypergeometric_total_interval(
                population_size,
                sample_size,
                observed,
                confidence_level=0.95,
            )
            covered += interval[0] <= true_total <= interval[1]
            trials += 1
        assert covered / trials >= 0.95


def test_stratified_recall_uses_ht_expansion_and_bonferroni_bounds() -> None:
    report = recall_audit.estimate_recall(
        {
            "detected_positive": {
                "population_size": 100,
                "sample_size": 20,
                "ai_causal": 16,
            },
            "no_fix_commit": {
                "population_size": 200,
                "sample_size": 20,
                "ai_causal": 2,
            },
            "fix_no_bic": {"population_size": 100, "sample_size": 20, "ai_causal": 1},
        }
    )

    assert report["true_positive_estimate"] == 80.0
    assert report["missed_positive_estimate"] == 25.0
    assert report["recall_point"] == pytest.approx(80 / 105)
    assert report["confidence_method"] == "exact_hypergeometric_bonferroni_95pct"
    assert 0 <= report["recall_interval"][0] <= report["recall_point"]
    assert report["recall_point"] <= report["recall_interval"][1] <= 1


def test_zero_detected_positive_population_reports_zero_recall_for_misses() -> None:
    report = recall_audit.estimate_recall(
        {
            "detected_positive": {
                "population_size": 0,
                "sample_size": 0,
                "ai_causal": 0,
            },
            "fix_no_bic": {
                "population_size": 2,
                "sample_size": 2,
                "ai_causal": 1,
            },
        }
    )

    assert report["true_positive_estimate"] == 0
    assert report["missed_positive_estimate"] == 1
    assert report["recall_denominator_estimate"] == 1
    assert report["recall_status"] == "defined_zero_no_detected_positives"
    assert report["recall_point"] == 0
    assert report["recall_interval"] == [0, 0]


def test_zero_positive_estimate_reports_undefined_recall_denominator() -> None:
    report = recall_audit.estimate_recall(
        {
            "detected_positive": {
                "population_size": 0,
                "sample_size": 0,
                "ai_causal": 0,
            },
            "fix_no_bic": {
                "population_size": 2,
                "sample_size": 2,
                "ai_causal": 0,
            },
        }
    )

    assert report["recall_denominator_estimate"] == 0
    assert report["recall_status"] == "zero_estimated_actual_positives"
    assert report["recall_point"] is None
    assert report["recall_interval"] is None


def test_simultaneous_recall_interval_covers_exhaustive_small_populations() -> None:
    population_size = 4
    sample_size = 2
    indices = range(population_size)
    for true_positives in range(population_size + 1):
        for missed_positives in range(population_size + 1):
            if true_positives + missed_positives == 0:
                continue
            detected_population = [1] * true_positives + [0] * (
                population_size - true_positives
            )
            missed_population = [1] * missed_positives + [0] * (
                population_size - missed_positives
            )
            covered = 0
            trials = 0
            truth = true_positives / (true_positives + missed_positives)
            for detected_sample in itertools.combinations(indices, sample_size):
                for missed_sample in itertools.combinations(indices, sample_size):
                    report = recall_audit.estimate_recall(
                        {
                            "detected_positive": {
                                "population_size": population_size,
                                "sample_size": sample_size,
                                "ai_causal": sum(
                                    detected_population[index]
                                    for index in detected_sample
                                ),
                            },
                            "fix_no_bic": {
                                "population_size": population_size,
                                "sample_size": sample_size,
                                "ai_causal": sum(
                                    missed_population[index] for index in missed_sample
                                ),
                            },
                        }
                    )
                    interval = report["recall_interval"]
                    if interval is None:
                        assert report["recall_denominator_estimate"] == 0
                        assert (
                            report["recall_status"] == "zero_estimated_actual_positives"
                        )
                        continue
                    lower, upper = interval
                    covered += lower <= truth <= upper
                    trials += 1
            assert trials
            assert covered / trials >= 0.95


def test_unknown_or_unresolved_third_review_blocks_formal_estimate() -> None:
    inventory = _inventory([_row("CVE-2026-1", "detected_positive")])
    selection = _selection(inventory, {"detected_positive": 1})
    labels = _labels(
        selection,
        primary="UNKNOWN",
        secondary="AI_CAUSAL",
        third="UNKNOWN",
    )

    report = _evaluate(selection, labels, inventory)

    assert report["evaluation_complete"] is False
    assert report["unresolved_packet_ids"] == [selection["assignments"][0]["packet_id"]]
    assert report["recall"] is None


def test_blind_third_review_resolves_disagreement_and_reports_agreement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_artifact_order(monkeypatch)
    inventory = _inventory([_row("CVE-2026-1", "detected_positive")])
    selection = _selection(inventory, {"detected_positive": 1})
    labels = _labels(
        selection,
        primary="AI_CAUSAL",
        secondary="NOT_AI_CAUSAL",
        third="AI_CAUSAL",
    )

    report = _evaluate(selection, labels, inventory, verify_artifact_order=True)

    assert report["evaluation_complete"] is True
    assert report["inter_rater_agreement"]["primary_secondary_agreement"] == 0.0
    assert report["recall"]["recall_point"] == 1.0


def test_coverage_failure_withholds_end_to_end_recall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_artifact_order(monkeypatch)
    inventory = _inventory(
        [
            _row("CVE-2026-1", "detected_positive"),
            _row("CVE-2026-2", "no_current_campaign_result"),
        ]
    )
    selection = _selection(inventory, {"detected_positive": 1})

    report = _evaluate(
        selection,
        _labels(selection),
        inventory,
        verify_artifact_order=True,
    )

    assert report["evaluation_complete"] is False
    assert report["evaluation_blockers"] == ["campaign_coverage_failures"]
    assert report["recall"] is None
    assert report["covered_unprotected_recall_diagnostic"]["recall_point"] == 1.0


def test_zero_detected_population_preserves_formal_coverage_blocker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_artifact_order(monkeypatch)
    inventory = _inventory(
        [
            _row("CVE-2026-1", "fix_no_bic"),
            _row("CVE-2026-2", "no_current_campaign_result"),
        ]
    )
    selection = _selection(inventory, {"fix_no_bic": 1})

    report = _evaluate(
        selection,
        _labels(selection),
        inventory,
        verify_artifact_order=True,
    )

    assert report["evaluation_complete"] is False
    assert report["evaluation_blockers"] == ["campaign_coverage_failures"]
    assert report["recall"] is None
    diagnostic = report["covered_unprotected_recall_diagnostic"]
    assert diagnostic["recall_status"] == "defined_zero_no_detected_positives"
    assert diagnostic["recall_point"] == 0
    assert diagnostic["recall_interval"] == [0, 0]


def test_protected_overlap_is_named_and_census_removes_exclusion_blocker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_artifact_order(monkeypatch)
    protected = _row("CVE-2026-1", "detected_positive")
    inventory = _inventory([protected, _row("CVE-2026-2", "detected_positive")])
    selection = _selection(
        inventory,
        {"detected_positive": 1},
        protected_subject_ids=frozenset({"CVE-2026-1"}),
    )

    report = _evaluate(
        selection,
        _labels(selection),
        inventory,
        verify_artifact_order=True,
    )

    assert report["evaluation_complete"] is True
    assert report["evaluation_blockers"] == []
    assert report["protected_overlap_class_count"] == 1
    assert report["protected_excluded_class_count"] == 0
    assert report["recall"]["recall_point"] == 1


def test_selection_swap_and_reseal_fails_exact_inventory_replay() -> None:
    inventory = _inventory(
        [
            _row("CVE-2026-1", "detected_positive"),
            _row("CVE-2026-2", "detected_positive"),
        ]
    )
    selection = _selection(inventory, {"detected_positive": 1})
    tampered = json.loads(json.dumps(selection))
    selected = tampered["assignments"][0]
    replacement = "CVE-2026-2" if selected["class_id"] == "CVE-2026-1" else "CVE-2026-1"
    selected["class_id"] = replacement
    selected["subject_ids"] = [replacement]
    tampered["blinded_review_packets"][0]["subject_ids"] = [replacement]
    tampered["selection_manifest_sha256"] = recall_audit.selection_sha256(tampered)

    with pytest.raises(recall_audit.RecallAuditError, match="exactly replay"):
        recall_audit.evaluate_labels(
            tampered,
            _labels(tampered),
            inventory=inventory,
            protected=_protected_from_selection(tampered),
            verify_artifact_order=False,
        )


def test_label_schema_rejects_detector_fields_and_reviewer_whitespace_aliases() -> None:
    inventory = _inventory([_row("CVE-2026-1", "detected_positive")])
    selection = _selection(inventory, {"detected_positive": 1})
    labels = _labels(selection)
    labels["detector_score"] = 1.0
    with pytest.raises(recall_audit.RecallAuditError, match="exact schema"):
        _evaluate(selection, labels, inventory)

    labels = _labels(
        selection,
        primary_reviewer=" Reviewer-A ",
        secondary_reviewer="reviewer-a",
    )
    with pytest.raises(recall_audit.RecallAuditError, match="distinct"):
        _evaluate(selection, labels, inventory)


def test_git_artifact_order_proves_selection_precedes_labels(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    study_dir = repository / "scripts" / "heldout_studies"
    study_dir.mkdir(parents=True)
    inventory = _inventory([_row("CVE-2026-1", "detected_positive")])
    selection = _selection(inventory, {"detected_positive": 1})
    selection_path = study_dir / "recall-selection.json"
    _write_canonical(selection_path, selection)
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
        [
            "git",
            "-C",
            str(repository),
            "add",
            "scripts/heldout_studies/recall-selection.json",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "Seal recall selection"],
        check=True,
    )
    commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    labels = _labels(
        selection,
        selection_commit_reference=(
            f"{commit}:scripts/heldout_studies/recall-selection.json"
        ),
    )
    labels_path = study_dir / "recall-labels.json"
    _write_canonical(labels_path, labels)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "add",
            "scripts/heldout_studies/recall-labels.json",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "Add recall labels"],
        check=True,
    )

    report = recall_audit.evaluate_labels(
        selection,
        labels,
        inventory=inventory,
        protected=_protected_from_selection(selection),
        selection_path=selection_path,
        labels_path=labels_path,
        repo_root=repository,
    )

    assert report["evaluation_complete"] is True
    assert report["artifact_order"]["selection_commit"] == commit
    assert report["recall"]["recall_point"] == 1.0
