"""Tests for blinded root-adjudication contracts."""

from __future__ import annotations

import hashlib
import json

import pytest

import cohort_prepare_root_adjudication as prepare
from cohort_prepare_root_adjudication import (
    _advisory_context,
    _explicit_cvelist_commit_shas,
)
from cohort.root_adjudication import (
    RootAdjudicationContractError,
    build_pilot_spec,
    parse_model_decision,
    redact_blind_text,
    validate_packet,
)


def test_advisory_context_prefers_frozen_full_cve_description(tmp_path) -> None:
    path = tmp_path / "CVE-2025-1000.json"
    path.write_text(
        json.dumps(
            {
                "containers": {
                    "cna": {
                        "title": "Session hijacking",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "An email executes JavaScript because HTML is not sanitized.",
                            }
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    association = {
        "description": "Session hijacking",
        "cvelist_path": str(path),
        "cvelist_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }

    context, source = _advisory_context(association)

    assert source == "cvelist_cna"
    assert context == (
        "Title: Session hijacking\n"
        "Description: An email executes JavaScript because HTML is not sanitized."
    )


def test_advisory_context_fails_closed_on_cve_digest_mismatch(tmp_path) -> None:
    path = tmp_path / "CVE-2025-1000.json"
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(SystemExit, match="digest mismatch"):
        _advisory_context(
            {
                "description": "fallback",
                "cvelist_path": str(path),
                "cvelist_sha256": "0" * 64,
            }
        )


def test_public_control_closure_accepts_tree_identical_merge_parent(
    monkeypatch, tmp_path
) -> None:
    trees = {"merge^{tree}": "tree-a\n", "feature^{tree}": "tree-a\n"}

    def fake_git_text(_repo, _global, arguments, *, timeout):
        assert timeout == 30
        if arguments[:2] == ["rev-parse", "merge^{tree}"]:
            return trees["merge^{tree}"], ""
        if arguments[:3] == ["show", "--no-patch", "--format=%P"]:
            return "base feature\n", ""
        if arguments[:2] == ["rev-parse", "feature^{tree}"]:
            return trees["feature^{tree}"], ""
        raise AssertionError(arguments)

    monkeypatch.setattr(prepare, "_git_text", fake_git_text)
    accepted, equivalences = prepare._public_control_closure(
        tmp_path,
        [],
        [
            {
                "candidate_id": "C01",
                "sha": "feature",
                "public_control_seed": False,
            },
            {
                "candidate_id": "C02",
                "sha": "merge",
                "public_control_seed": True,
            },
        ],
        timeout=30,
    )

    assert accepted == ["C01", "C02"]
    assert equivalences == [
        {
            "candidate_id": "C01",
            "public_exact_candidate_id": "C02",
            "reason": "tree_identical_parent_of_public_merge",
        }
    ]


def test_explicit_cvelist_commit_shas_excludes_unstated_range_boundary(
    tmp_path,
) -> None:
    stated = "1" * 40
    inferred = "2" * 40
    path = tmp_path / "CVE-2026-1000.json"
    path.write_text(
        json.dumps(
            {
                "containers": {
                    "cna": {
                        "references": [
                            {"url": f"https://example.invalid/commit/{stated}"},
                            {"url": "https://example.invalid/releases/v2"},
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    association = {
        "cvelist_path": str(path),
        "cvelist_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }

    shas = _explicit_cvelist_commit_shas(association)

    assert stated in shas
    assert inferred not in shas


def _packet() -> dict[str, object]:
    return {
        "schema_version": 1,
        "packet_id": "packet",
        "target_id": "target",
        "vulnerability_description": "A bounds check is missing.",
        "candidates": [
            {
                "candidate_id": "C01",
                "authored_date": "2026-01-01",
                "subject": "validate input",
                "body_excerpt": "",
                "changed_paths": ["src/input.py"],
                "patch_excerpt": "+ if invalid: reject()",
                "patch_truncated": False,
                "evidence_status": "READY",
                "evidence_reason": "",
            }
        ],
    }


def test_packet_allowlist_rejects_sha_or_source_label_leakage() -> None:
    packet = _packet()
    packet["repository_identity"] = "github.com/acme/project"
    with pytest.raises(RootAdjudicationContractError, match="allowlist"):
        validate_packet(packet)

    packet = _packet()
    packet["candidates"][0]["fix_sha"] = "a" * 40
    with pytest.raises(RootAdjudicationContractError, match="allowlist"):
        validate_packet(packet)


def test_pilot_selection_is_deterministic_and_balanced() -> None:
    rows = [
        {"packet_id": f"hard-{index}", "source_class": "association_only"}
        for index in range(4)
    ] + [
        {"packet_id": f"easy-{index}", "source_class": "public_exact_present"}
        for index in range(4)
    ]
    first = build_pilot_spec(rows, pilot_id="pilot", per_stratum=2)
    second = build_pilot_spec(list(reversed(rows)), pilot_id="pilot", per_stratum=2)

    assert first == second
    assert len(first["selected"]) == 4
    assert {row["reasoning_effort"] for row in first["selected"]} == {
        "medium",
        "high",
    }


def test_model_decision_must_reference_only_packet_candidates() -> None:
    decision = parse_model_decision(
        {
            "decision": "select",
            "selected_ids": ["C01"],
            "confidence": "medium",
            "rationale": "The patch adds the missing validation.",
            "missing_evidence": "",
        },
        {"C01", "C02"},
    )
    assert decision["selected_ids"] == ["C01"]

    with pytest.raises(RootAdjudicationContractError, match="unknown"):
        parse_model_decision(
            {
                "decision": "select",
                "selected_ids": ["C99"],
                "confidence": "medium",
                "rationale": "unknown",
                "missing_evidence": "",
            },
            {"C01"},
        )


def test_blind_text_redacts_advisories_urls_repository_and_full_hashes() -> None:
    text = redact_blind_text(
        "Fix CVE-2026-12345 in github.com/acme/project at "
        "https://github.com/acme/project/commit/" + "a" * 40,
        repository_identity="github.com/acme/project",
        advisory="CVE-2026-12345",
    )
    assert "CVE-" not in text
    assert "github.com" not in text
    assert "a" * 40 not in text
    assert "[ADVISORY_ID]" in text
