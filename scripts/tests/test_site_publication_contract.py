from __future__ import annotations

import json
from pathlib import Path

import build_missing_code_evidence
import publish_tp_ledger
import site_preflight


def _case() -> dict:
    hunk = {"file": "src/app.py", "code": "@@ -1 +1 @@", "annotation": ""}
    return {
        "case_id": "CVE-2026-12345",
        "aliases": [],
        "candidate_set": ["a" * 40],
        "minimum_fix_set": ["b" * 40],
        "gates": dict(publish_tp_ledger.PASS_GATES),
        "vulnerable_release": {"version": "1.0.0"},
        "fixed_release": {"version": "1.0.1"},
        "advisory_url": "https://www.cve.org/CVERecord?id=CVE-2026-12345",
        "ai_provenance": {"coverage": "complete"},
        "code_evidence": {
            "candidate_hunks": [hunk],
            "fix_hunks": [hunk],
        },
    }


def test_publication_status_fails_closed() -> None:
    case = _case()
    case["publication_issues"] = publish_tp_ledger.publication_issues(case)
    assert publish_tp_ledger.publication_status(case) == "confirmed"

    case["gates"]["release"] = "NARROW"
    assert publish_tp_ledger.publication_status(case) == "qualified"

    case["gates"]["release"] = "UNKNOWN"
    assert publish_tp_ledger.publication_status(case) == "provisional"


def test_incomplete_security_boundary_is_not_misclassified_as_remediation() -> None:
    row = {"status": "AI_ROOT_CAUSE"}
    direct_origin = {
        "flaw_origin": "The feature introduced an incomplete builtins.open-only enforcement boundary."
    }
    incomplete_fix = {
        "flaw_origin": "The AI-authored remediation was an incomplete fix that left a residual bypass."
    }

    assert publish_tp_ledger.contribution_class(row, direct_origin) == "AI_DIRECT_ROOT"
    assert (
        publish_tp_ledger.contribution_class(row, incomplete_fix)
        == "AI_INCOMPLETE_REMEDIATION"
    )

def test_evidence_backfill_preserves_existing_canonical_entry() -> None:
    case_id = "GHSA-1234-5678-9ABC"
    existing = {case_id: {"comparison_hunks": [{"file": "src/app.py"}]}}

    assert not build_missing_code_evidence.needs_evidence(case_id, existing, set())
    assert build_missing_code_evidence.needs_evidence(case_id, existing, {case_id})
    assert build_missing_code_evidence.needs_evidence("GHSA-NEW1-NEW2-NEW3", existing, set())

def test_hunk_paths_are_recovered_from_git_diffs() -> None:
    assert publish_tp_ledger.infer_hunk_file(
        {"code": "diff --git a/src/app.py b/src/app.py\n@@ -1 +1 @@"}
    ) == "src/app.py"


def test_ir_chain_requires_a_reason_when_original_sha_is_unresolved() -> None:
    case = _case()
    case["published_at"] = "2026-01-01"
    case["contribution_class"] = "AI_INCOMPLETE_REMEDIATION"
    case["ir_chain"] = {"original_sha": None}
    assert publish_tp_ledger.publication_errors([case]) == [
        "CVE-2026-12345: ir_chain without original_sha needs unresolved_reason"
    ]

    case["ir_chain"]["unresolved_reason"] = "The available clone ends at a shallow boundary."
    assert publish_tp_ledger.publication_errors([case]) == []


def test_ir_chain_normalization_preserves_history_gap_reason() -> None:
    chain = publish_tp_ledger.normalize_ir_chain(
        {
            "original_introducing_commit": None,
            "original_introducing_commit_reason": "The parent commit is unavailable.",
        }
    )
    assert chain is not None
    assert chain["original_sha"] is None
    assert chain["unresolved_reason"] == "The parent commit is unavailable."


def test_site_preflight_rejects_an_unexplained_origin_gap() -> None:
    case = _case()
    case.update(
        {
            "contribution_class": "AI_INCOMPLETE_REMEDIATION",
            "ir_chain": {"original_sha": None},
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    expected = "CVE-2026-12345: ir_chain without original_sha needs unresolved_reason"
    assert expected in errors

    case["ir_chain"]["unresolved_reason"] = "The parent commit is unavailable."
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert expected not in errors


def test_generated_site_data_passes_publication_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    payload = json.loads(
        (root / "web/src/generated/research-data.json").read_text(encoding="utf-8")
    )
    allowlist = json.loads(
        (root / "scripts/site_preflight_allowlist.json").read_text(encoding="utf-8")
    )
    errors, _, stats = site_preflight.evaluate(payload, allowlist)

    assert errors == []
    assert sum(stats["publication_statuses"].values()) == len(payload["cases"])
