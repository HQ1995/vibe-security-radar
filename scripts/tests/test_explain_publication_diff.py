"""Tests for the reproducible legacy-to-current publication ledger."""

from __future__ import annotations

import json
import hashlib
import subprocess
from pathlib import Path

import pytest

from explain_publication_diff import (
    LedgerError,
    assert_no_blocking_errors,
    build_publication_ledger,
    load_adjudications,
    load_current_split_publication,
    load_old_publication_from_git,
    load_source_delta_alias_closure,
    main,
    render_markdown,
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _write_old_git_publication(repo: Path, ids: list[str]) -> str:
    repo.mkdir()
    _run_git(repo, "init", "-q")
    path = repo / "web" / "data" / "cves.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "generated_at": "2026-04-04T00:00:00Z",
                "total": len(ids),
                "cves": [{"id": advisory_id, "description": advisory_id} for advisory_id in ids],
            }
        ),
        encoding="utf-8",
    )
    _run_git(repo, "add", "web/data/cves.json")
    _run_git(
        repo,
        "-c",
        "user.name=Publication Ledger Test",
        "-c",
        "user.email=ledger@example.invalid",
        "commit",
        "-qm",
        "Legacy publication",
    )
    return _run_git(repo, "rev-parse", "HEAD")


def _write_current_publication(root: Path, ids: list[str]) -> tuple[Path, Path]:
    data_dir = root / "web" / "data"
    cves_dir = data_dir / "cves"
    cves_dir.mkdir(parents=True)
    generation_id = "g" * 64
    index = {
        "generation_id": generation_id,
        "generated_at": "2026-07-19T00:00:00Z",
        "total": len(ids),
        "ids": ids,
    }
    index_path = data_dir / "index.json"
    index_path.write_text(json.dumps(index), encoding="utf-8")
    for advisory_id in ids:
        (cves_dir / f"{advisory_id}.json").write_text(
            json.dumps(
                {
                    "generation_id": generation_id,
                    "id": advisory_id,
                    "description": advisory_id,
                }
            ),
            encoding="utf-8",
        )
    return index_path, cves_dir


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _write_adjudications(root: Path, entries: list[dict]) -> Path:
    path = root / "scripts" / "audit_adjudications.json"
    _write_json(path, {"schema_version": 1, "adjudications": entries})
    return path


def _alias_class(members: list[str], source_snapshot_sha256: str) -> dict:
    ordered = sorted(members)
    component_sha256 = _sha256(("\n".join(ordered) + "\n").encode())
    analysis_subject = next(
        (member for member in ordered if member.startswith("CVE-")),
        next(
            (member for member in ordered if member.startswith("GHSA-")),
            ordered[0],
        ),
    )
    analysis_input = {
        "member_ids": ordered,
        "git_ranges": [],
        "fixed_events": [],
        "reference_urls": [],
    }
    return {
        "class_id": f"alias-{component_sha256[:24]}",
        "component_sha256": component_sha256,
        "all_member_ids": ordered,
        "eligible_seed_ids": ordered,
        "source_record_references": [],
        "merged_source_evidence_sha256": _sha256(
            _canonical_json_bytes({"records": [], "analysis_input": analysis_input})
        ),
        "analysis_subject": analysis_subject,
        "analysis_input": analysis_input,
        "source_snapshot_sha256": source_snapshot_sha256,
        "scheduled_seed_ids": [analysis_subject],
    }


def _write_source_delta(root: Path, classes: list[list[str]]) -> Path:
    source_snapshot_sha256 = "a" * 64
    class_records = sorted(
        (_alias_class(members, source_snapshot_sha256) for members in classes),
        key=lambda record: record["class_id"],
    )
    eligible_ids = {member for class_record in class_records for member in class_record["eligible_seed_ids"]}
    manifest = {
        "schema_version": 1,
        "source_snapshot_sha256": source_snapshot_sha256,
        "class_count": len(class_records),
        "eligible_seed_id_count": len(eligible_ids),
        "all_eligible_seed_ids_exactly_once": True,
        "classes_sha256": _sha256(_canonical_json_bytes(class_records)),
        "scheduled_class_count": len(class_records),
        "scheduled_analysis_subject_count": len(class_records),
        "scheduled_classes_exactly_once": True,
        "classes": class_records,
    }
    payload = {
        "schema_version": 3,
        "population_policy": "formal_full",
        "production_discovery": {"alias_class_manifest": manifest},
    }
    payload["integrity_payload_sha256"] = _sha256((json.dumps(payload, indent=2, sort_keys=False) + "\n").encode())
    path = root / ".ai-slop" / "state" / "data-refresh" / "source-delta-current.json"
    _write_json(path, payload)
    return path


def _rewrite_source_delta(path: Path, payload: dict) -> None:
    payload.pop("integrity_payload_sha256", None)
    payload["integrity_payload_sha256"] = _sha256((json.dumps(payload, indent=2, sort_keys=False) + "\n").encode())
    _write_json(path, payload)


def _load_all(
    repo: Path,
    old_ref: str,
    current_ids: list[str],
    adjudication_entries: list[dict],
    *,
    source_classes: list[list[str]] | None = None,
):
    index_path, cves_dir = _write_current_publication(repo, current_ids)
    adjudications_path = _write_adjudications(repo, adjudication_entries)
    source_delta_path = _write_source_delta(
        repo,
        source_classes or [["SOURCE-SINGLETON"]],
    )
    return (
        load_old_publication_from_git(repo, old_ref),
        load_current_split_publication(index_path, cves_dir, repo_root=repo),
        load_adjudications(adjudications_path, repo_root=repo),
        load_source_delta_alias_closure(source_delta_path, repo_root=repo),
    )


def test_ledger_classifies_all_states_and_reconciles_exactly(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    old_ref = _write_old_git_publication(
        repo,
        ["OLD-RETAIN", "OLD-ALIAS", "OLD-NOT-AI", "OLD-INCONCLUSIVE", "OLD-UNKNOWN"],
    )
    _write_json(
        repo / "scripts" / "audit_results" / "not-ai.json",
        {
            "cve_id": "OLD-NOT-AI",
            "root_cause": "Human commit introduced the vulnerable branch.",
            "notes": "The AI bot only reviewed the later fix.",
        },
    )
    _write_json(
        repo / "scripts" / "audit_results" / "inconclusive.json",
        {
            "cve_id": "OLD-INCONCLUSIVE",
            "analysis": "The repository history is incomplete.",
            "causality_notes": "Authorship could not be established.",
        },
    )
    _write_json(
        repo / "scripts" / "audit_overrides.json",
        [
            {
                "cve_id": "CURRENT-CANONICAL",
                "reason": "The old and current IDs identify one vulnerability.",
            }
        ],
    )
    old, current, adjudications, source_aliases = _load_all(
        repo,
        old_ref,
        ["OLD-RETAIN", "CURRENT-CANONICAL", "CURRENT-NEW"],
        [
            {"cve_id": "OLD-RETAIN", "label": "AI_CAUSAL"},
            {
                "cve_id": "CURRENT-CANONICAL",
                "aliases": ["OLD-ALIAS"],
                "label": "AI_CAUSAL",
                "source": "scripts/audit_overrides.json",
            },
            {
                "cve_id": "OLD-NOT-AI",
                "label": "NOT_AI_CAUSAL",
                "source": "scripts/audit_results/not-ai.json",
            },
            {
                "cve_id": "OLD-INCONCLUSIVE",
                "label": "INCONCLUSIVE",
                "source": "scripts/audit_results/inconclusive.json",
            },
        ],
        source_classes=[["CURRENT-CANONICAL", "OLD-ALIAS"]],
    )

    report = build_publication_ledger(old, current, adjudications, source_aliases)

    assert report["status"] == "pass"
    assert report["counts"]["old_classifications"] == {
        "retained": 1,
        "alias_canonicalized": 1,
        "independent_not_ai_causal": 1,
        "inconclusive_coverage_failure": 1,
        "unadjudicated_coverage_failure": 1,
    }
    assert {
        key: report["counts"][key]
        for key in (
            "old_total",
            "current_total",
            "old_classification_sum",
            "removed_old_rows",
            "retained_current_ids",
            "alias_rows",
            "alias_canonical_targets",
            "alias_collapse",
            "true_new_publications",
            "net_delta",
            "reconciled_current_total",
            "reconciled",
        )
    } == {
        "old_total": 5,
        "current_total": 3,
        "old_classification_sum": 5,
        "removed_old_rows": 3,
        "retained_current_ids": 1,
        "alias_rows": 1,
        "alias_canonical_targets": 1,
        "alias_collapse": 0,
        "true_new_publications": 1,
        "net_delta": -2,
        "reconciled_current_total": 3,
        "reconciled": True,
    }
    rows = {row["old_id"]: row for row in report["old_rows"]}
    assert rows["OLD-ALIAS"]["current_id"] == "CURRENT-CANONICAL"
    assert rows["OLD-UNKNOWN"]["coverage_failure_kind"] == "missing_adjudication"
    not_ai_reason = rows["OLD-NOT-AI"]["adjudication"]["reason"]
    assert "Human commit introduced the vulnerable branch." in not_ai_reason
    assert "The AI bot only reviewed the later fix." in not_ai_reason
    inconclusive_reason = rows["OLD-INCONCLUSIVE"]["adjudication"]["reason"]
    assert "The repository history is incomplete." in inconclusive_reason
    assert "Authorship could not be established." in inconclusive_reason
    assert [row["current_id"] for row in report["true_new_publications"]] == ["CURRENT-NEW"]
    assert len(report["inputs"]["old_publication"]["sha256"]) == 64
    assert len(report["inputs"]["current_publication"]["bundle_sha256"]) == 64
    assert len(report["inputs"]["audit_adjudications"]["sha256"]) == 64
    assert len(report["inputs"]["source_delta"]["source_delta_sha256"]) == 64
    assert len(report["inputs"]["source_delta"]["alias_class_manifest_sha256"]) == 64
    assert len(report["integrity"]["ledger_payload_sha256"]) == 64
    assert_no_blocking_errors(report)
    assert build_publication_ledger(old, current, adjudications, source_aliases) == report

    markdown = render_markdown(report)
    assert "5 = 5 - 3 - 0 + 1" not in markdown
    assert "3 = 5 - 3 - 0 + 1" in markdown
    assert "Human commit introduced the vulnerable branch." in markdown
    assert "`CURRENT-NEW`" in markdown


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"reasoning": "full reasoning"}, "full reasoning"),
        ({"root_cause": "full root cause"}, "full root cause"),
        ({"analysis": "full analysis", "causality": "full causality"}, "full causality"),
        ({"causality_notes": "full causality notes"}, "full causality notes"),
        ({"notes": "full notes"}, "full notes"),
        ({"evidence": {"commit": "a" * 40}}, '"commit"'),
    ],
)
def test_full_reason_is_extracted_across_audit_schemas(
    tmp_path: Path,
    payload: dict,
    expected: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = {"cve_id": "OLD-1", **payload}
    _write_json(repo / "scripts" / "audit_results" / "OLD-1.json", source)
    adjudications_path = _write_adjudications(
        repo,
        [
            {
                "cve_id": "OLD-1",
                "label": "NOT_AI_CAUSAL",
                "source": "scripts/audit_results/OLD-1.json",
            }
        ],
    )

    loaded = load_adjudications(adjudications_path, repo_root=repo)

    assert expected in loaded.records[0].reason
    for value in payload.values():
        if isinstance(value, str):
            assert value in loaded.records[0].reason


def test_missing_ai_causal_row_is_a_blocking_failure(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    old_ref = _write_old_git_publication(repo, ["OLD-POSITIVE"])
    old, current, adjudications, source_aliases = _load_all(
        repo,
        old_ref,
        [],
        [{"cve_id": "OLD-POSITIVE", "label": "AI_CAUSAL"}],
        source_classes=[["OLD-POSITIVE"]],
    )

    report = build_publication_ledger(old, current, adjudications, source_aliases)

    assert report["status"] == "failed"
    assert report["old_rows"][0]["classification"] == "unadjudicated_coverage_failure"
    assert report["old_rows"][0]["coverage_failure_kind"] == ("missing_ai_causal_publication")
    assert report["blocking_errors"][0]["old_id"] == "OLD-POSITIVE"
    with pytest.raises(LedgerError, match="OLD-POSITIVE"):
        assert_no_blocking_errors(report)


def test_authoritative_source_class_canonicalizes_without_audit_alias(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    old_ref = _write_old_git_publication(repo, ["OLD-AUTHORITATIVE"])
    old, current, adjudications, source_aliases = _load_all(
        repo,
        old_ref,
        ["CURRENT-AUTHORITATIVE"],
        [{"cve_id": "OLD-AUTHORITATIVE", "label": "AI_CAUSAL"}],
        source_classes=[["CURRENT-AUTHORITATIVE", "OLD-AUTHORITATIVE"]],
    )

    report = build_publication_ledger(old, current, adjudications, source_aliases)

    assert report["status"] == "pass"
    assert report["old_rows"][0]["classification"] == "alias_canonicalized"
    assert report["old_rows"][0]["current_id"] == "CURRENT-AUTHORITATIVE"
    assert report["true_new_publications"] == []


def test_source_delta_rejects_malformed_alias_manifest(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = _write_source_delta(repo, [["CVE-2026-1000"]])
    payload = json.loads(path.read_text())
    del payload["production_discovery"]["alias_class_manifest"]["classes_sha256"]
    _rewrite_source_delta(path, payload)

    with pytest.raises(LedgerError, match="manifest digest"):
        load_source_delta_alias_closure(path, repo_root=repo)


def test_source_delta_rejects_legacy_schema_without_formal_manifest(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = repo / ".ai-slop" / "state" / "data-refresh" / "source-delta-current.json"
    _write_json(
        path,
        {
            "schema_version": 2,
            "production_discovery": {"alias_components": {"transitive": True}},
        },
    )

    with pytest.raises(LedgerError, match="schema_version 3"):
        load_source_delta_alias_closure(path, repo_root=repo)


def test_source_delta_rejects_incremental_schema_three_delta(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = _write_source_delta(repo, [["CVE-2026-1000"]])
    payload = json.loads(path.read_text())
    payload["population_policy"] = "incremental"
    _rewrite_source_delta(path, payload)

    with pytest.raises(LedgerError, match="formal_full"):
        load_source_delta_alias_closure(path, repo_root=repo)


def test_source_delta_rejects_overlapping_authoritative_classes(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = _write_source_delta(
        repo,
        [
            ["CVE-2026-1000", "GHSA-aaaa-bbbb-cccc"],
            ["CVE-2026-1001", "GHSA-aaaa-bbbb-cccc"],
        ],
    )

    with pytest.raises(LedgerError, match="overlap"):
        load_source_delta_alias_closure(path, repo_root=repo)


def test_source_delta_rejects_content_address_drift(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = _write_source_delta(repo, [["CVE-2026-1000"]])
    payload = json.loads(path.read_text())
    payload["production_discovery"]["alias_class_manifest"]["classes"][0]["all_member_ids"].append(
        "GHSA-drift-drift-drift"
    )
    _rewrite_source_delta(path, payload)

    with pytest.raises(LedgerError, match="digest is invalid or stale"):
        load_source_delta_alias_closure(path, repo_root=repo)


def test_adjudication_alias_cannot_join_authoritative_classes(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    old_ref = _write_old_git_publication(repo, ["OLD-CLASS-A"])
    old, current, adjudications, source_aliases = _load_all(
        repo,
        old_ref,
        ["CURRENT-CLASS-B"],
        [
            {
                "cve_id": "OLD-CLASS-A",
                "aliases": ["CURRENT-CLASS-B"],
                "label": "AI_CAUSAL",
            }
        ],
        source_classes=[["OLD-CLASS-A"], ["CURRENT-CLASS-B"]],
    )

    with pytest.raises(LedgerError, match="conflict with authoritative"):
        build_publication_ledger(old, current, adjudications, source_aliases)


def test_cli_writes_diagnostic_outputs_then_fails_closed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    old_ref = _write_old_git_publication(repo, ["OLD-POSITIVE"])
    _write_current_publication(repo, [])
    _write_adjudications(
        repo,
        [{"cve_id": "OLD-POSITIVE", "label": "AI_CAUSAL"}],
    )
    _write_source_delta(repo, [["OLD-POSITIVE"]])
    json_out = tmp_path / "ledger.json"
    markdown_out = tmp_path / "ledger.md"

    exit_code = main(
        [
            "--repo-root",
            str(repo),
            "--old-ref",
            old_ref,
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ]
    )

    assert exit_code == 2
    assert json.loads(json_out.read_text())["status"] == "failed"
    assert "OLD-POSITIVE" in markdown_out.read_text()


def test_current_split_rejects_orphaned_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    index_path, cves_dir = _write_current_publication(repo, ["CURRENT-1"])
    (cves_dir / "ORPHAN.json").write_text(
        json.dumps({"id": "ORPHAN"}),
        encoding="utf-8",
    )

    with pytest.raises(LedgerError, match="orphaned"):
        load_current_split_publication(index_path, cves_dir, repo_root=repo)
