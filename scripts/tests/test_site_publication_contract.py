from __future__ import annotations

import hashlib
import inspect
import json
import re
import tempfile
import pytest
from copy import deepcopy
from pathlib import Path

import build_missing_code_evidence
import publish_tp_ledger
import site_preflight


def _case() -> dict:
    return {
        "case_id": "CVE-2026-12345",
        "aliases": [],
        "candidate_set": ["a" * 40],
        "minimum_fix_set": ["b" * 40],
        "gates": {key: "PASS" for key in publish_tp_ledger.DEFAULT_GATES},
        "vulnerable_release": {"version": "1.0.0"},
        "fixed_release": {"version": "1.0.1"},
        "advisory_url": "https://www.cve.org/CVERecord?id=CVE-2026-12345",
        "ai_provenance": {"coverage": "complete"},
        "code_evidence": {
            "summary": "The AI-linked change left user input able to cross the security boundary.",
            "candidate_url": f"https://github.com/acme/app/commit/{'a' * 40}",
            "fix_url": f"https://github.com/security-fork/app/commit/{'b' * 40}",
            "steps": [
                {
                    "title": "Fix",
                    "detail": "The later patch closes the vulnerable path.",
                }
            ],
            "candidate_hunks": [
                {
                    "file": "src/app.py",
                    "code": "@@ -1 +1 @@\n-old\n+unsafe(user_input)",
                    "annotation": "",
                    "role": "candidate",
                }
            ],
            "fix_hunks": [
                {
                    "file": "src/app.py",
                    "code": "@@ -1 +1 @@\n-unsafe(user_input)\n+safe(user_input)",
                    "annotation": "",
                    "role": "fix",
                }
            ],
        },
    }


def _ir_chain() -> dict:
    return {
        "original_advisory_ids": ["GHSA-1111-2222-3333"],
        "original_mechanism": "Untrusted input reached the command execution boundary.",
        "original_sink": "The command runner executed the unchecked value.",
        "original_author_kind": "HUMAN",
        "original_author_name": "Example Maintainer",
        "original_sha": "c" * 40,
        "unresolved_reason": None,
        "attempted_remediation": {
            "candidate_shas": ["a" * 40],
            "changed": "The attempted patch blocked one unsafe option spelling.",
            "missed": "A second equivalent option still reached the same sink.",
        },
        "residual_bypass": "The equivalent option preserved the vulnerable execution path.",
        "final_closure": {
            "minimum_fix_shas": ["b" * 40],
            "closed": "The final patch rejects both unsafe option spellings.",
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


def test_site_preflight_rejects_a_fail_gate_on_a_published_case() -> None:
    case = _case()
    case["gates"]["release"] = "FAIL"
    case.update(
        {
            "publication_status": "qualified",
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )

    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )

    assert any(
        case["case_id"] in error and "release" in error and "FAIL" in error
        for error in errors
    )


@pytest.mark.parametrize("release_gate", ["NARROW", "UNKNOWN"])
def test_nonpass_release_gate_does_not_require_release_facts(
    release_gate: str,
) -> None:
    case = _case()
    case.update(
        {
            "gates": {**case["gates"], "release": release_gate},
            "vulnerable_release": None,
            "fixed_release": None,
            "publication_status": "provisional",
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )

    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )

    assert not any("no vulnerable/fixed release" in error for error in errors)


def test_publisher_uses_only_sourced_ledger_gates() -> None:
    case_id = "GHSA-1111-2222-3333"
    class_id = "alias-gates"
    cached = {
        **_case(),
        "case_id": case_id,
        "class_id": class_id,
        "repository": "acme/app",
        "gates": {key: "PASS" for key in publish_tp_ledger.DEFAULT_GATES},
    }
    row = {
        "class_id": class_id,
        "status": "AI_ROOT_CAUSE",
        "repo": "acme/app",
        "site_tier": "ALL_GATES_PASS",
        "causal_research": {
            "case_id": case_id,
            "advisory_ids": [case_id],
            "repo": "acme/app",
            "introducer_sha": "a" * 40,
            "fix_sha": "b" * 40,
            "ai_marker": "Co-Authored-By: Claude",
            "bug_semantics": "Untrusted input reached a privileged operation.",
            "verdict": "AI_ROOT_CAUSE",
        },
    }

    def build(candidate: dict) -> dict:
        return publish_tp_ledger.build_case(
            candidate,
            {case_id: cached},
            {class_id.upper(): cached},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
        )

    assert build(row)["gates"] == publish_tp_ledger.DEFAULT_GATES

    row["gates"] = {key: "PASS" for key in publish_tp_ledger.DEFAULT_GATES}
    try:
        build(row)
    except ValueError as error:
        assert "unsourced ledger gates" in str(error)
    else:
        raise AssertionError("explicit ledger gates without gates_source were accepted")


def test_canonical_ledger_code_evidence_overrides_generated_and_cached_data(
    monkeypatch,
) -> None:
    case_id = "GHSA-1111-2222-3333"
    class_id = "alias-evidence"
    ledger_evidence = {
        "summary": "The canonical ledger explains the audited vulnerable path.",
        "candidate_hunks": [
            {
                "file": "src/app.py",
                "code": "@@ -1 +1 @@\n-  old_call()\n+  new_call()",
                "annotation": "The canonical hunk preserves exact diff indentation.",
            }
        ],
        "fix_hunks": [],
        "comparison_hunks": [],
    }
    stale_evidence = {
        "summary": "Stale generated evidence must not win.",
        "candidate_hunks": [],
        "fix_hunks": [],
        "comparison_hunks": [{"file": "stale.py", "code": "+stale", "annotation": ""}],
    }
    row = {
        "class_id": class_id,
        "status": "AI_ROOT_CAUSE",
        "repo": "acme/app",
        "advisory_ids": [case_id],
        "code_evidence": ledger_evidence,
        "causal_research": {
            "case_id": case_id,
            "advisory_ids": [case_id],
            "repo": "acme/app",
            "introducer_sha": "a" * 40,
            "fix_sha": "b" * 40,
            "ai_marker": "Co-Authored-By: Claude",
            "bug_semantics": "Untrusted input reached a privileged operation.",
            "verdict": "AI_ROOT_CAUSE",
        },
    }
    cached = {
        **_case(),
        "case_id": case_id,
        "class_id": class_id,
        "repository": "acme/app",
        "code_evidence": stale_evidence,
    }

    case = publish_tp_ledger.build_case(
        row,
        {case_id: cached},
        {class_id.upper(): cached},
        {},
        {},
        {},
        {},
        {case_id: stale_evidence},
        {},
        {},
    )

    assert case["code_evidence"]["summary"] == ledger_evidence["summary"]
    assert case["code_evidence"]["comparison_hunks"] == []
    assert case["code_evidence"]["candidate_hunks"][0]["code"] == (
        ledger_evidence["candidate_hunks"][0]["code"]
    )
    fallback = "A curated reader summary replaces non-canonical cached evidence."
    monkeypatch.setattr(
        publish_tp_ledger,
        "AI_SUMMARIES",
        {case_id: fallback},
    )
    monkeypatch.setattr(publish_tp_ledger, "AI_SUMMARIES_MECHANISM", {})
    assert publish_tp_ledger.ai_summary_overlay(case, canonical=True)
    assert case["code_evidence"]["summary"] == ledger_evidence["summary"]
    assert publish_tp_ledger.ai_summary_overlay(case)
    assert case["code_evidence"]["summary"] == fallback


def test_hunk_specific_evidence_requires_distinct_annotations_and_all_anchors() -> None:
    assert site_preflight.valid_unified_hunks(
        "@@ -1 +1 @@\n--- a removed SQL comment\n+++incremented"
    )
    case = _case()
    case.update(
        {
            "repository": "acme/app",
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )
    evidence = case["code_evidence"]
    evidence["annotation_mode"] = "hunk_specific"
    evidence["required_anchors"] = {
        "candidate": ["unsafe(user_input)"],
        "fix": ["safe(user_input)"],
    }
    evidence["candidate_hunks"][0]["annotation"] = (
        "The candidate forwards unchecked input into the unsafe call."
    )
    evidence["fix_hunks"][0]["annotation"] = (
        "The fix routes the same input through the validating call."
    )

    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert not [
        error
        for error in errors
        if "hunk-specific evidence" in error or "missing fix anchors" in error
    ]

    evidence["fix_hunks"][0]["annotation"] = ""
    evidence["fix_hunks"][0]["code"] = "@@ -1,1 +1,1 @@\n-a\n-b\n+c"
    evidence["required_anchors"]["fix"] = ["missing_fix_call"]
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert any("invalid unified diff" in error for error in errors)
    assert any("missing fix anchors" in error for error in errors)


def test_targeted_overrides_replace_stale_mechanism_and_release_metadata() -> None:
    case = _case()
    mechanism = "The canonical record identifies the corrected vulnerable data flow."
    carrier = ["c" * 40]
    vulnerable = {"version": "2.0.0"}
    fixed = {"version": "2.0.1"}
    updated = publish_tp_ledger.apply_case_overrides(
        case,
        {"class_id": "CVE-2026-12345"},
        None,
        {
            "cases": {
                "CVE-2026-12345": {
                    "mechanism": mechanism,
                    "carrier_set": carrier,
                    "minimum_fix_set": [],
                    "vulnerable_release": vulnerable,
                    "fixed_release": fixed,
                }
            }
        },
        {},
    )

    assert updated["mechanism"] == mechanism
    assert updated["carrier_set"] == carrier
    assert updated["minimum_fix_set"] == []
    assert updated["vulnerable_release"] == vulnerable
    assert updated["fixed_release"] == fixed

    canonical_case = _case()
    canonical_case.update(
        {
            "mechanism": "The ledger is authoritative.",
            "fixed_release": {"version": "2.0.2"},
            "candidate_set": ["d" * 40],
        }
    )
    canonical = publish_tp_ledger.apply_case_overrides(
        canonical_case,
        {
            "class_id": "CVE-2026-12345",
            "mechanism": "The ledger is authoritative.",
            "fixed_release": {"version": "2.0.2"},
            "candidate_set": ["d" * 40],
        },
        None,
        {
            "cases": {
                "CVE-2026-12345": {
                    "mechanism": mechanism,
                    "fixed_release": fixed,
                    "candidate_set": ["e" * 40],
                }
            }
        },
        {},
    )
    assert canonical["mechanism"] == "The ledger is authoritative."
    assert canonical["fixed_release"] == {"version": "2.0.2"}
    assert canonical["candidate_set"] == ["d" * 40]


def test_public_shas_preserve_a_multi_commit_set_when_evidence_overlaps() -> None:
    candidates = ["a" * 40, "c" * 40]
    evidence = {
        "candidate_url": f"https://github.com/upstream/app/commit/{candidates[0]}"
    }

    published, _ = publish_tp_ledger.public_shas(
        {"introducer_shas": candidates},
        None,
        evidence,
    )

    assert published == candidates


def test_public_shas_prefer_explicit_ledger_sets_over_stale_site_evidence() -> None:
    row = {"candidate_set": ["b" * 40], "minimum_fix_set": []}
    cached = {"candidate_set": ["a" * 40], "minimum_fix_set": ["c" * 40]}
    evidence = {
        "candidate_url": f"https://github.com/upstream/app/commit/{'a' * 40}",
        "fix_url": f"https://github.com/upstream/app/commit/{'c' * 40}",
    }

    assert publish_tp_ledger.public_shas(None, cached, evidence, row) == (
        ["b" * 40],
        [],
    )


def test_identity_replacement_does_not_reuse_a_dropped_by_class_cache() -> None:
    stale = {
        "case_id": "GHSA-1111-2222-3333",
        "class_id": "alias-example",
        "repository": "acme/app",
    }
    cached, official_hit = publish_tp_ledger.find_cached(
        ["GHSA-4444-5555-6666"],
        [],
        "alias-example",
        "acme/app",
        {},
        {"ALIAS-EXAMPLE": stale},
        {"GHSA-1111-2222-3333"},
    )

    assert cached is None
    assert not official_hit


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
    assert not build_missing_code_evidence.needs_evidence(
        "GHSA-NEW1-NEW2-NEW3", existing, {case_id}
    )


def test_hunk_paths_are_recovered_from_git_diffs() -> None:
    assert publish_tp_ledger.infer_hunk_file(
        {"code": "diff --git a/src/app.py b/src/app.py\n@@ -1 +1 @@"}
    ) == "src/app.py"


def test_evidence_generator_scores_only_file_content_and_honors_file_witnesses() -> None:
    mechanism = "Untrusted redirect validation must reject the bypass."
    relevant_patch = "+reject_untrusted_redirect_bypass(value)"
    unrelated_patch = "+subprocess.run(command, shell=True)"
    assert build_missing_code_evidence.score_file(
        "src/redirect_policy.py", relevant_patch, mechanism
    ) > build_missing_code_evidence.score_file(
        "src/command.py", unrelated_patch, mechanism
    )

    commit = {
        "files": [
            {"filename": "src/redirect_policy.py", "patch": relevant_patch},
            {"filename": "src/command.py", "patch": unrelated_patch},
        ]
    }
    hunks = build_missing_code_evidence.hunks_from_commit(
        commit, mechanism, allowed_files=["src/redirect_policy.py"]
    )
    assert [hunk["file"] for hunk in hunks] == ["src/redirect_policy.py"]


def test_github_commit_fetch_merges_paginated_file_lists() -> None:
    sha = "a" * 40
    pages = [
        {
            "sha": sha,
            "commit": {"message": "Root commit"},
            "files": [{"filename": "src/first.py", "patch": "+first"}],
        },
        {
            "sha": sha,
            "commit": {"message": "Root commit"},
            "files": [
                {"filename": "src/first.py", "patch": "+first"},
                {"filename": "src/last.py", "patch": "+last"},
            ],
        },
    ]
    original = build_missing_code_evidence.subprocess.run

    class Result:
        returncode = 0
        stdout = json.dumps(pages)

    def fake_run(args: list[str], **_: object) -> Result:
        assert "--paginate" in args
        assert "--slurp" in args
        return Result()

    try:
        build_missing_code_evidence.subprocess.run = fake_run
        commit = build_missing_code_evidence.gh_commit("acme/app", sha)
    finally:
        build_missing_code_evidence.subprocess.run = original

    assert commit is not None
    assert commit["commit"]["message"] == "Root commit"
    assert [item["filename"] for item in commit["files"]] == [
        "src/first.py",
        "src/last.py",
    ]
    hunks = build_missing_code_evidence.hunks_from_commit(
        commit,
        "The last-page change closes the redirect boundary.",
        allowed_files=["src/last.py"],
    )
    assert [hunk["file"] for hunk in hunks] == ["src/last.py"]


def test_large_allowlisted_blob_recovers_an_anchor_and_patch_witness() -> None:
    anchor = "const sandboxAutoAllowResult = checkSandboxAutoAllow("
    commit = {
        "sha": "a" * 40,
        "parents": [],
        "files": [
            {
                "filename": "src/tools/BashTool/bashPermissions.ts",
                "sha": "b" * 40,
                "patch": None,
            }
        ],
    }
    original = build_missing_code_evidence.gh_blob
    try:
        build_missing_code_evidence.gh_blob = lambda *_: "\n".join(
            [f"unrelated_{index}();" for index in range(140)] + [anchor, "deny();"]
        )
        hydrated = build_missing_code_evidence.hydrate_allowed_patches(
            "acme/app",
            commit,
            ["src/tools/BashTool/bashPermissions.ts"],
            [anchor],
        )
    finally:
        build_missing_code_evidence.gh_blob = original

    assert hydrated is not None
    hunks = build_missing_code_evidence.hunks_from_commit(
        hydrated,
        "Sandbox permissions must remain constrained.",
        allowed_files=["src/tools/BashTool/bashPermissions.ts"],
        anchors=[anchor],
    )
    assert anchor in hunks[0]["code"]
    assert build_missing_code_evidence.patch_file_witness(
        hydrated, ["src/tools/BashTool/bashPermissions.ts"]
    ) == ["src/tools/BashTool/bashPermissions.ts"]


def test_ledger_evidence_uses_publisher_priority_and_list_records() -> None:
    preferred = {
        "case_id": "GHSA-1111-2222-3333",
        "advisory_ids": ["GHSA-1111-2222-3333"],
        "repo": "acme/app",
        "verdict": "AI_ROOT_CAUSE",
        "introducer_sha": "a" * 40,
        "direct_fix_sha": "b" * 40,
        "bug_semantics": "The preferred list record identifies the vulnerable sink.",
    }
    case = build_missing_code_evidence.ledger_case(
        {
            "class_id": "alias-example",
            "repo": "acme/app",
            "status": "AI_ROOT_CAUSE",
            "round11_research": {
                "case_id": "GHSA-9999-9999-9999",
                "verdict": "NOT_AI",
                "introducer_sha": "c" * 40,
                "fix_sha": "d" * 40,
            },
            "partial_wave": [preferred],
            "squash_audit": [
                {
                    "verdict": "AI_ROOT_CAUSE",
                    "case_id": "GHSA-8888-8888-8888",
                }
            ],
        }
    )

    assert case is not None
    assert case["case_id"] == "GHSA-1111-2222-3333"
    assert case["candidate_set"] == ["a" * 40]
    assert case["minimum_fix_set"] == ["b" * 40]
    assert case["repository"] == "acme/app"

    overridden = build_missing_code_evidence.ledger_case(
        {
            "class_id": "alias-example",
            "repo": "acme/app",
            "status": "AI_ROOT_CAUSE",
            "partial_wave": [preferred],
        },
        {"cases": {"alias-example": {"case_id": "CVE-2026-12345"}}},
    )
    assert overridden is not None
    assert overridden["case_id"] == "CVE-2026-12345"
    assert "GHSA-1111-2222-3333" in overridden["aliases"]


def test_evidence_generator_targets_large_hunks_with_role_anchors() -> None:
    patch = "\n".join(
        ["@@ -0,0 +1,200 @@"]
        + [f"+unrelated_{index}()" for index in range(120)]
        + ["+async parseAuthRequest(request: Request) {", "+  rejectUnsafeRedirect()", "+}"]
    )
    commit = {
        "sha": "a" * 40,
        "commit": {"message": "AI change"},
        "files": [{"filename": "src/oauth.ts", "patch": patch}],
    }
    original = build_missing_code_evidence.gh_commit
    try:
        build_missing_code_evidence.gh_commit = lambda *_: commit
        evidence = build_missing_code_evidence.build_case(
            {
                "case_id": "GHSA-1111-2222-3333",
                "repository": "acme/oauth",
                "candidate_set": ["a" * 40],
                "minimum_fix_set": [],
                "mechanism": "An unsafe redirect reached authorization.",
            },
            {
                "candidate_files": ["src/oauth.ts"],
                "candidate_anchors": ["async parseAuthRequest(request: Request)"],
            },
        )
    finally:
        build_missing_code_evidence.gh_commit = original

    assert evidence is not None
    code = evidence["candidate_hunks"][0]["code"]
    assert "parseAuthRequest" in code
    assert "unrelated_0" not in code
    assert len(code.splitlines()) <= 90


def test_evidence_generator_uses_role_specific_repositories() -> None:
    calls: list[tuple[str, str]] = []
    candidate_sha = "a" * 40
    fix_sha = "b" * 40

    def commit(repository: str, sha: str) -> dict:
        calls.append((repository, sha))
        path = "src/media.ts" if sha == candidate_sha else "extensions/media.ts"
        return {
            "sha": sha,
            "commit": {"message": "Security change"},
            "files": [{"filename": path, "patch": "@@ -1 +1 @@\n-old\n+safe"}],
        }

    original = build_missing_code_evidence.gh_commit
    try:
        build_missing_code_evidence.gh_commit = commit
        evidence = build_missing_code_evidence.build_case(
            {
                "case_id": "GHSA-1111-2222-3333",
                "repository": "downstream/app",
                "candidate_set": [candidate_sha],
                "minimum_fix_set": [fix_sha],
                "mechanism": "Untrusted media reached a sensitive path.",
            },
            {
                "candidate_repo": "upstream/plugin",
                "candidate_files": ["src/media.ts"],
                "fix_repo": "downstream/app",
                "fix_files": ["extensions/media.ts"],
            },
        )
    finally:
        build_missing_code_evidence.gh_commit = original

    assert evidence is not None
    assert calls == [
        ("upstream/plugin", candidate_sha),
        ("downstream/app", fix_sha),
    ]
    assert evidence["candidate_url"] == (
        f"https://github.com/upstream/plugin/commit/{candidate_sha}"
    )
    assert evidence["fix_url"] == (
        f"https://github.com/downstream/app/commit/{fix_sha}"
    )


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


def test_multiple_ghsa_aliases_require_explicit_identity_adjudication() -> None:
    case = _case()
    case.update(
        case_id="GHSA-1111-2222-3333",
        class_id="alias-example",
        aliases=["GHSA-4444-5555-6666"],
        published_at="2026-01-01",
    )
    assert publish_tp_ledger.publication_errors([case]) == [
        "GHSA-1111-2222-3333: multiple GHSAs "
        "['GHSA-1111-2222-3333', 'GHSA-4444-5555-6666']"
    ]
    overrides = {
        "cases": {
            "alias-example": {"aliases_extra": ["GHSA-4444-5555-6666"]}
        }
    }
    assert publish_tp_ledger.publication_errors([case], overrides=overrides) == []


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


def test_publisher_removes_pseudo_annotations_and_assigns_hunk_roles() -> None:
    publish_tp_ledger._load_summary_maps()
    summary = "The candidate change passed an unchecked value into a command runner."
    candidate = {
        "file": "src/app.py",
        "code": "@@ -1 +1 @@\n-old\n+unsafe(user_input)",
        "annotation": "AI introduced this behavior: `unsafe(user_input)`",
    }
    fix = {
        "file": "src/app.py",
        "code": "@@ -1 +1 @@\n-unsafe(user_input)\n+safe(user_input)",
        "annotation": summary,
    }
    before_after = {
        "file": "src/guard.py",
        "code": "-allow(value)\n+reject(value)",
        "annotation": "The guard now rejects the unsafe value before execution.",
    }
    cleaned = publish_tp_ledger.scrub_evidence(
        {
            "summary": summary,
            "candidate_hunks": [candidate],
            "fix_hunks": [fix],
            "comparison_hunks": [candidate, fix, before_after],
        }
    )

    assert cleaned is not None
    assert cleaned["candidate_hunks"][0]["role"] == "candidate"
    assert cleaned["fix_hunks"][0]["role"] == "fix"
    assert [hunk["role"] for hunk in cleaned["comparison_hunks"]] == [
        "candidate",
        "fix",
        "before_after",
    ]
    assert cleaned["candidate_hunks"][0]["annotation"] == "`unsafe(user_input)`"
    assert cleaned["fix_hunks"][0]["annotation"] == ""
    assert cleaned["comparison_hunks"][2]["annotation"] == before_after["annotation"]

    note = "This hunk removes the unchecked call before the command can execute."
    deduped = publish_tp_ledger.scrub_evidence(
        {
            "summary": summary,
            "candidate_hunks": [{**candidate, "annotation": note}],
            "fix_hunks": [{**fix, "annotation": note}],
            "comparison_hunks": [],
        }
    )
    assert deduped is not None
    assert [
        deduped["candidate_hunks"][0]["annotation"],
        deduped["fix_hunks"][0]["annotation"],
    ] == [note, ""]


def test_reader_summaries_cover_public_cases_without_audit_identifiers() -> None:
    cases = json.loads(publish_tp_ledger.OUT.read_text())["cases"]
    missing: list[str] = []
    internal: list[str] = []
    for published in cases:
        summary = str(
            ((published.get("code_evidence") or {}).get("summary") or "")
        ).strip()
        if not summary:
            missing.append(published["case_id"])
            continue
        if (
            site_preflight.AUDIT_IDENTIFIER_RE.search(summary)
            or "PR #" in summary
        ):
            internal.append(published["case_id"])

    assert missing == []
    assert internal == []


def test_security_fix_context_replaces_the_generic_fix_step() -> None:
    case = _case()
    case["minimum_fix_set"] = ["d" * 40]
    evidence = case["code_evidence"]
    detail = (
        "The security patch switches command execution to a fixed binary and "
        "passes user input only as separated arguments."
    )
    fix_url = f"https://github.com/acme/app/commit/{'d' * 40}"
    fix_files = ["src/app.py"]

    publish_tp_ledger.apply_security_fix_context(
        evidence, {"detail": detail, "fix_url": fix_url, "fix_files": fix_files}
    )

    assert evidence["steps"] == [{"title": "Security fix", "detail": detail}]
    assert evidence["fix_url"] == fix_url
    assert evidence["fix_files"] == fix_files
    assert [hunk["file"] for hunk in evidence["fix_hunks"]] == fix_files
    case.update(
        {
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert not any("Security fix step" in error for error in errors)

    evidence["steps"][0]["detail"] = "fix"
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert any("Security fix step[0] detail is not public prose" in error for error in errors)

    evidence["steps"][0]["detail"] = detail
    evidence["fix_files"] = []
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert any("Security fix step has no fix_files witness" in error for error in errors)
    assert any("displayed fix-role files exceed fix_files witness" in error for error in errors)

    evidence["fix_files"] = fix_files
    evidence["fix_hunks"] = []
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert any(
        "Security fix minimum fix has no displayed hunk in fix_files" in error
        for error in errors
    )


def test_generic_fix_url_must_belong_to_the_minimum_fix_set() -> None:
    case = _case()
    case["code_evidence"]["steps"] = [
        {
            "title": "Fix",
            "detail": "The patch rejects unsafe arguments before execution reaches the command sink.",
        }
    ]
    case["code_evidence"]["fix_url"] = (
        f"https://github.com/acme/app/commit/{'e' * 40}"
    )
    case.update(
        {
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )

    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert any("fix_url does not match minimum_fix_set" in error for error in errors)


def test_displayed_candidate_url_must_belong_to_the_candidate_set() -> None:
    case = _case()
    case["code_evidence"]["candidate_url"] = (
        f"https://github.com/upstream/app/commit/{'e' * 40}"
    )
    case.update(
        {
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )

    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert any("candidate_url does not match candidate_set" in error for error in errors)


def test_security_fix_context_filters_only_fix_role_hunks() -> None:
    evidence = _case()["code_evidence"]
    evidence["fix_hunks"].append(
        {
            "file": "docs/release.md",
            "code": "+Document the release.",
            "annotation": "",
            "role": "fix",
        }
    )
    evidence["comparison_hunks"] = [
        *evidence["candidate_hunks"],
        *evidence["fix_hunks"],
        {
            "file": "src/combined.py",
            "code": "-unsafe(value)\n+safe(value)",
            "annotation": "The combined comparison shows the unsafe call replaced by validation.",
            "role": "before_after",
        },
    ]
    publish_tp_ledger.apply_security_fix_context(
        evidence,
        {
            "detail": "The security patch validates the value before it reaches the sink.",
            "fix_url": f"https://github.com/acme/app/commit/{'d' * 40}",
            "fix_files": ["src/app.py"],
        },
    )

    assert [hunk["file"] for hunk in evidence["candidate_hunks"]] == ["src/app.py"]
    assert [hunk["file"] for hunk in evidence["fix_hunks"]] == ["src/app.py"]
    assert [hunk["file"] for hunk in evidence["comparison_hunks"]] == [
        "src/app.py",
        "src/app.py",
        "src/combined.py",
    ]


def test_site_preflight_requires_a_role_and_public_role_context() -> None:
    case = _case()
    evidence = case["code_evidence"]
    evidence["summary"] = ""
    evidence["steps"] = []
    evidence["candidate_hunks"][0]["role"] = "fix"
    case.update(
        {
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert (
        "CVE-2026-12345: candidate_hunks[0] role 'fix' does not match 'candidate'"
        in errors
    )
    assert any(
        "displayed role 'fix' has no public context" in error for error in errors
    )

    evidence["candidate_hunks"][0]["role"] = "candidate"
    evidence["summary"] = (
        "The candidate change left user input able to cross the security boundary."
    )
    evidence["steps"] = [
        {
            "title": "Final fix details",
            "detail": "The later patch closes the vulnerable path.",
        }
    ]
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert not any(
        error.startswith(case["case_id"])
        and ("role " in error or "public context" in error)
        for error in errors
    )


def test_site_preflight_rejects_an_empty_hunk() -> None:
    case = _case()
    case["code_evidence"]["candidate_hunks"][0]["code"] = ""
    case.update(
        {
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )

    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert "CVE-2026-12345: candidate_hunks[0] has no code" in errors


def test_site_preflight_rejects_internal_or_repeated_hunk_annotations() -> None:
    case = _case()
    note = "The unchecked value crosses the command execution boundary here."
    case["code_evidence"]["candidate_hunks"][0]["annotation"] = note
    case["code_evidence"]["fix_hunks"][0]["annotation"] = note
    case.update(
        {
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )
    payload = {"cases": [case], "snapshot": {"case_count": 1}}

    errors, _, _ = site_preflight.evaluate(payload)
    assert "CVE-2026-12345: displayed hunks repeat the same annotation" in errors

    case["code_evidence"]["fix_hunks"][0]["annotation"] = "class_id=internal-alias"
    errors, _, _ = site_preflight.evaluate(payload)
    assert any("annotation is not a usable annotation" in error for error in errors)


def test_before_after_hunk_requires_an_independent_annotation() -> None:
    case = _case()
    case["code_evidence"]["comparison_hunks"] = [
        {
            "file": "src/app.py",
            "code": "-unsafe(user_input)\n+safe(user_input)",
            "annotation": "",
            "role": "before_after",
        }
    ]
    case.update(
        {
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    expected = (
        "CVE-2026-12345: comparison_hunks[0] before_after hunk has no "
        "genuine annotation"
    )
    assert expected in errors

    case["code_evidence"]["comparison_hunks"][0]["annotation"] = (
        "The comparison shows the unsafe call being replaced by the guarded call."
    )
    errors, _, _ = site_preflight.evaluate(
        {"cases": [case], "snapshot": {"case_count": 1}}
    )
    assert expected not in errors


def test_missing_diff_allowlist_reason_is_published_with_the_case() -> None:
    case = _case()
    case["code_evidence"]["candidate_hunks"] = []
    case["code_evidence"]["fix_hunks"] = []
    case.update(
        {
            "publication_status": "provisional",
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )
    reason = (
        "The source commits are no longer present in the public upstream history, "
        "so no trustworthy patch can be shown."
    )
    payload = {"cases": [case], "snapshot": {"case_count": 1}}
    allowlist = {"missing_diff": {case["case_id"]: reason}}
    expected = (
        "CVE-2026-12345: missing_diff reason is not published verbatim as "
        "code_evidence.unavailable_reason"
    )

    errors, _, _ = site_preflight.evaluate(payload, allowlist)
    assert expected in errors

    case["code_evidence"]["unavailable_reason"] = reason
    errors, _, _ = site_preflight.evaluate(payload, allowlist)
    assert expected not in errors

    case["code_evidence"]["candidate_hunks"] = [
        {
            "file": "src/app.py",
            "code": "+safe(user_input)",
            "annotation": "",
            "role": "candidate",
        }
    ]
    errors, _, _ = site_preflight.evaluate(payload, allowlist)
    assert "CVE-2026-12345: code diff exists but unavailable_reason is set" in errors


def test_site_preflight_requires_full_commit_shas() -> None:
    for field in ("candidate_set", "minimum_fix_set"):
        case = _case()
        case[field] = ["abcdef0"]
        case.update(
            {
                "publication_status": "confirmed",
                "publication_issues": [],
                "published_at": "2026-01-01",
                "repository_metadata": {"language": "Python"},
            }
        )

        errors, _, _ = site_preflight.evaluate(
            {"cases": [case], "snapshot": {"case_count": 1}}
        )
        assert (
            f"CVE-2026-12345: {field} must contain full 40-hex commit SHAs" in errors
        )


def test_displayed_roles_require_full_commit_source_urls() -> None:
    case = _case()
    case.update(
        {
            "publication_status": "confirmed",
            "publication_issues": [],
            "published_at": "2026-01-01",
            "repository_metadata": {"language": "Python"},
        }
    )
    payload = {"cases": [case], "snapshot": {"case_count": 1}}

    for role, field in (("candidate", "candidate_url"), ("fix", "fix_url")):
        valid = case["code_evidence"][field]
        case["code_evidence"][field] = "https://github.com/acme/app/commit/abcdef0"
        errors, _, _ = site_preflight.evaluate(payload)
        assert (
            f"CVE-2026-12345: displayed role {role!r} has no full commit {field}"
            in errors
        )
        case["code_evidence"][field] = valid

    errors, _, _ = site_preflight.evaluate(payload)
    assert not any("has no full commit candidate_url" in error for error in errors)
    assert not any("has no full commit fix_url" in error for error in errors)


def test_fix_object_witness_requires_exact_unique_commit_coverage() -> None:
    case = _case()
    record = {
        "case_id": case["case_id"],
        "sha": case["minimum_fix_set"][0],
        "repository": "security-fork/app",
        "object_type": "commit",
    }
    metadata = {
        "schema_version": 1,
        "verified_at": "2026-08-30",
        "verification_method": site_preflight.OFFLINE_WITNESS_VERIFICATION_METHOD,
        "live_verification_method": site_preflight.LIVE_WITNESS_VERIFICATION_METHOD,
        "objects_sha256": hashlib.sha256(
            json.dumps([record], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    witness = {**metadata, "objects": [record]}

    assert site_preflight.fix_object_witness_errors([case], witness) == []

    tag_witness = {"schema_version": 1, "objects": [{**record, "object_type": "tag"}]}
    assert any(
        "is not a commit" in error
        for error in site_preflight.fix_object_witness_errors([case], tag_witness)
    )
    assert any(
        "has duplicate" in error
        for error in site_preflight.fix_object_witness_errors(
            [case], {**metadata, "objects": [record, record]}
        )
    )
    assert any(
        "is missing" in error
        for error in site_preflight.fix_object_witness_errors(
            [case], {**metadata, "objects": []}
        )
    )
    assert any(
        "invalid verified_at" in error
        for error in site_preflight.fix_object_witness_errors(
            [case], {**witness, "verified_at": ""}
        )
    )
    assert any(
        "invalid verification_method" in error
        for error in site_preflight.fix_object_witness_errors(
            [case], {**witness, "verification_method": "manual"}
        )
    )
    assert any(
        "invalid live_verification_method" in error
        for error in site_preflight.fix_object_witness_errors(
            [case], {**witness, "live_verification_method": "manual"}
        )
    )
    forged_repository = [{**record, "repository": "forged/repository"}]
    assert any(
        "objects digest does not match" in error
        for error in site_preflight.fix_object_witness_errors(
            [case], {**metadata, "objects": forged_repository}
        )
    )


def test_live_fix_object_witness_binds_repository_and_full_sha() -> None:
    sha = "b" * 40
    url = (
        "https://github.com/fictional-owner/fictional-repo/commit/"
        f"{sha}"
    )
    witness = {
        "objects": [
            {
                "case_id": "CVE-2026-12345",
                "sha": sha,
                "repository": "fictional-owner/fictional-repo",
                "object_type": "commit",
            }
        ]
    }
    exact_meta = (
        '<meta property="og:url" content="'
        f'/fictional-owner/fictional-repo/commit/{sha}" />'
    ).encode()
    responses = [
        (url, exact_meta),
        (url, exact_meta.replace(sha.encode(), ("c" * 40).encode())),
        (
            url,
            exact_meta.replace(sha.encode(), sha[:12].encode()),
        ),
        (
            f"https://github.com/other-owner/other-repo/commit/{sha}",
            exact_meta,
        ),
        (f"https://github.com/login?return_to={url}", exact_meta),
        (
            url,
            exact_meta.replace(
                b"fictional-owner/fictional-repo",
                b"other-owner/other-repo",
            ),
        ),
        (url, b"<title>Page not found</title>"),
        (url, exact_meta[:20]),
    ]
    requests: list[str] = []

    class Response:
        def __init__(self, final_url: str, body: bytes) -> None:
            self.final_url = final_url
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def geturl(self) -> str:
            return self.final_url

        def read(self, _: int) -> bytes:
            return self.body

    def open_request(request, timeout: int):
        assert timeout == 20
        requests.append(request.full_url)
        return Response(*responses.pop(0))

    original = site_preflight.urlopen
    try:
        site_preflight.urlopen = open_request
        success = site_preflight.live_fix_object_witness_errors(witness)
        wrong_sha = site_preflight.live_fix_object_witness_errors(witness)
        abbreviated_sha = site_preflight.live_fix_object_witness_errors(witness)
        wrong_repo = site_preflight.live_fix_object_witness_errors(witness)
        login_redirect = site_preflight.live_fix_object_witness_errors(witness)
        wrong_meta_repo = site_preflight.live_fix_object_witness_errors(witness)
        soft_404 = site_preflight.live_fix_object_witness_errors(witness)
        truncated_html = site_preflight.live_fix_object_witness_errors(witness)
    finally:
        site_preflight.urlopen = original

    assert success == []
    expected = [
        "published fix object witness live check failed for "
        f"fictional-owner/fictional-repo@{sha}"
    ]
    assert wrong_sha == expected
    assert abbreviated_sha == expected
    assert wrong_repo == expected
    assert login_redirect == expected
    assert wrong_meta_repo == expected
    assert soft_404 == expected
    assert truncated_html == expected
    assert requests == [url] * 8


def _required_role_manifest(*roles: str) -> dict:
    values = sorted(roles)
    return {
        "schema_version": 1,
        "artifact_kind": "code_evidence_required_roles",
        "role_count": len(values),
        "roles": values,
        "roles_sha256": hashlib.sha256("\n".join(values).encode()).hexdigest(),
    }


def test_required_evidence_role_manifest_matches_file_overrides() -> None:
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads(
        (root / "scripts/code-evidence-required-roles.json").read_text()
    )
    overrides = json.loads(
        (root / "scripts/evidence_fetch_overrides.json").read_text()
    )
    roles = manifest["roles"]
    assert roles == sorted(
        f"{case_id.upper()}:{role}"
        for case_id, spec in overrides.items()
        for role in ("candidate", "fix")
        if spec.get(f"{role}_files")
    )


def test_required_role_needs_matching_source_hunk_and_patch_witness() -> None:
    case = _case()
    case["repository"] = "acme/app"
    case["code_evidence"]["candidate_url"] = (
        f"https://github.com/upstream/app/commit/{'a' * 40}"
    )
    case["code_evidence"]["candidate_patch_files"] = ["src/app.py"]
    manifest = _required_role_manifest(f"{case['case_id']}:candidate")
    override = {
        case["case_id"]: {
            "candidate": "a" * 40,
            "candidate_anchors": ["unsafe(user_input)"],
            "candidate_files": ["src/app.py"],
            "candidate_repo": "upstream/app",
        }
    }
    assert site_preflight.evidence_role_allowlist_errors(
        [case], override, manifest
    ) == []

    candidate_code = case["code_evidence"]["candidate_hunks"][0]["code"]
    case["code_evidence"]["candidate_hunks"][0]["code"] = "+unrelated_change()"
    assert "required candidate anchor is not emitted" in " ".join(
        site_preflight.evidence_role_allowlist_errors([case], override, manifest)
    )
    case["code_evidence"]["candidate_hunks"][0]["code"] = candidate_code
    case["code_evidence"]["comparison_hunks"] = [
        {
            "file": "src/app.py",
            "code": "+unrelated_change()",
            "annotation": "",
            "role": "candidate",
        }
    ]
    assert "required candidate anchor is not displayed" in " ".join(
        site_preflight.evidence_role_allowlist_errors([case], override, manifest)
    )
    case["code_evidence"].pop("comparison_hunks")

    assert "has no file allowlist" in " ".join(
        site_preflight.evidence_role_allowlist_errors([case], {}, manifest)
    )
    case["code_evidence"]["candidate_patch_files"] = []
    assert "allowlist is not present in fetched patches" in " ".join(
        site_preflight.evidence_role_allowlist_errors([case], override, manifest)
    )
    case["code_evidence"]["candidate_patch_files"] = ["src/app.py"]
    case["code_evidence"]["candidate_hunks"][0]["file"] = "src/unrelated.py"
    assert "displayed candidate path exceeds its file allowlist" in " ".join(
        site_preflight.evidence_role_allowlist_errors([case], override, manifest)
    )


def test_required_role_cannot_silently_outlive_its_published_identity() -> None:
    required = "GHSA-1111-2222-3333:candidate"
    errors = site_preflight.evidence_role_allowlist_errors(
        [_case()],
        {"GHSA-1111-2222-3333": {"candidate_files": ["src/app.py"]}},
        _required_role_manifest(required),
    )

    assert errors == [f"required code-evidence role {required} has no published identity"]


def test_allowlisted_fix_must_modify_a_file_from_the_minimum_fix() -> None:
    case = _case()
    case["repository"] = "acme/app"
    evidence = case["code_evidence"]
    evidence["fix_url"] = f"https://github.com/acme/app/commit/{'b' * 40}"
    evidence["fix_patch_files"] = ["src/app.py"]
    manifest = _required_role_manifest(f"{case['case_id']}:fix")
    override = {
        case["case_id"]: {
            "fix": "b" * 40,
            "fix_files": ["src/app.py"],
            "fetch_repo": "acme/app",
        }
    }
    assert site_preflight.evidence_role_allowlist_errors(
        [case], override, manifest
    ) == []

    case["minimum_fix_set"] = ["c" * 40]
    assert "allowlisted fix does not belong to minimum_fix_set" in " ".join(
        site_preflight.evidence_role_allowlist_errors([case], override, manifest)
    )


def test_effective_not_ai_adjudication_blocks_publication_through_an_alias() -> None:
    case = _case()
    case["aliases"] = ["GHSA-1111-2222-3333"]
    adjudications = {
        "schema_version": 1,
        "adjudications": [
            {
                "cve_id": "GHSA-1111-2222-3333",
                "aliases": [case["case_id"]],
                "label": "NOT_AI_CAUSAL",
            }
        ],
    }
    assert site_preflight.not_ai_publication_errors([case], adjudications) == [
        "CVE-2026-12345: published identity is adjudicated NOT_AI via "
        "['CVE-2026-12345', 'GHSA-1111-2222-3333']"
    ]

    adjudications["adjudications"][0]["label"] = "AI_CAUSAL"
    assert site_preflight.not_ai_publication_errors([case], adjudications) == []


def test_ir_chain_mutations_fail_closed() -> None:
    mutations = [
        (("original_advisory_ids",), [], "ir_chain has no original_advisory_ids"),
        (
            ("original_advisory_ids",),
            "GHSA-1111-2222-3333",
            "ir_chain has no original_advisory_ids",
        ),
        (("original_mechanism",), "", "ir_chain has no original_mechanism"),
        (("original_sink",), "", "ir_chain has no original_sink"),
        (
            ("original_author_kind",),
            "UNKNOWN",
            "resolved ir_chain has no original_author_kind",
        ),
        (
            ("original_author_name",),
            "",
            "resolved ir_chain has no original_author_name",
        ),
        (("attempted_remediation",), None, "ir_chain has no attempted_remediation"),
        (
            ("attempted_remediation", "candidate_shas"),
            [],
            "attempted_remediation has no candidate_shas",
        ),
        (
            ("attempted_remediation", "changed"),
            "",
            "attempted_remediation has no changed",
        ),
        (
            ("attempted_remediation", "missed"),
            "",
            "attempted_remediation has no missed",
        ),
        (("residual_bypass",), "", "ir_chain has no residual_bypass"),
        (("original_sha",), "UNKNOWN", "ir_chain has invalid original_sha"),
        (
            ("attempted_remediation", "candidate_shas"),
            ["abcdef0"],
            "attempted_remediation has invalid candidate_shas",
        ),
        (("final_closure",), None, "ir_chain has no final_closure"),
        (
            ("final_closure", "minimum_fix_shas"),
            [],
            "final_closure has no minimum_fix_shas",
        ),
        (("final_closure", "closed"), "", "final_closure has no closed"),
        (
            ("final_closure", "minimum_fix_shas"),
            ["abcdef0"],
            "final_closure has invalid minimum_fix_shas",
        ),
        (
            ("final_closure", "minimum_fix_shas"),
            ["d" * 40],
            "final_closure minimum_fix_shas do not match minimum_fix_set",
        ),
    ]
    for path, value, expected in mutations:
        case = _case()
        case["ir_chain"] = deepcopy(_ir_chain())
        target = case["ir_chain"]
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

        errors = site_preflight.ir_chain_errors(case["case_id"], case)
        assert any(expected in error for error in errors)


def test_unpatched_ir_chain_may_omit_final_closure() -> None:
    case = _case()
    case["minimum_fix_set"] = []
    case["ir_chain"] = {**_ir_chain(), "final_closure": None}
    case["unpatched"] = {"confirmed": True}

    assert site_preflight.ir_chain_errors(case["case_id"], case) == []


def test_unpatched_case_strips_and_rejects_stale_fix_claims() -> None:
    case = _case()
    case["fixed_release"] = {"version": "1.0.1"}
    case["unpatched"] = {
        "confirmed": True,
        "reason": "No remediation has been released in the audited public repository.",
        "potential_fix": {
            "approach": "Validate the target before any outbound request is attempted.",
            "rationale": "The validation removes the attacker-controlled path to the sink.",
        },
    }
    errors = site_preflight.unpatched_errors(case["case_id"], case)
    assert any("still has a fix set" in error for error in errors)
    assert any("still has a fixed release" in error for error in errors)
    assert any("still has fix evidence metadata" in error for error in errors)
    assert any("still has fix hunks" in error for error in errors)
    assert any("still has a fix step" in error for error in errors)

    publish_tp_ledger.strip_unpatched_fix_claims(case)
    assert site_preflight.unpatched_errors(case["case_id"], case) == []
    assert case["minimum_fix_set"] == []
    assert case["fixed_release"] is None
    assert case["code_evidence"]["fix_hunks"] == []
    assert not any(
        hunk.get("role") == "fix"
        for hunk in case["code_evidence"].get("comparison_hunks") or []
    )
    assert not any(
        "fix" in str(step.get("title") or "").lower()
        for step in case["code_evidence"]["steps"]
    )
    assert "fix_url" not in case["code_evidence"]


def test_ir_chain_rejects_a_short_original_sha_even_with_a_reason() -> None:
    case = _case()
    case["ir_chain"] = {
        **_ir_chain(),
        "original_sha": "abcdef0",
        "unresolved_reason": "The public history does not contain a full commit object.",
    }

    assert (
        "CVE-2026-12345: ir_chain has invalid original_sha"
        in site_preflight.ir_chain_errors(case["case_id"], case)
    )

    case["ir_chain"]["original_sha"] = None
    case["ir_chain"]["unresolved_reason"] = "shallow"
    assert (
        "CVE-2026-12345: ir_chain without original_sha needs unresolved_reason"
        in site_preflight.ir_chain_errors(case["case_id"], case)
    )

    case["ir_chain"]["unresolved_reason"] = (
        "The public repository history does not retain the original commit object."
    )
    case["ir_chain"]["original_author_kind"] = "HUMAN"
    assert (
        "CVE-2026-12345: unresolved ir_chain author kind must be UNKNOWN"
        in site_preflight.ir_chain_errors(case["case_id"], case)
    )

    case["ir_chain"]["original_author_kind"] = "UNKNOWN"
    assert (
        "CVE-2026-12345: unresolved ir_chain author kind must be UNKNOWN"
        not in site_preflight.ir_chain_errors(case["case_id"], case)
    )


def test_ir_chain_source_records_keep_atomic_qf5v_and_frvj_origin() -> None:
    root = Path(__file__).resolve().parents[2]
    # DB-first via publish's loader (falls back to the research/ file for local
    # dev) so CI with the untracked source removed still validates the record.
    chains = publish_tp_ledger.load_ir_chains(
        publish_tp_ledger.IR_CHAINS
    )
    qf5v = chains.get("GHSA-QF5V-M7P4-95RP")
    assert qf5v is not None
    assert qf5v["attempted_remediation"]["candidate_shas"] == [
        "2db76f65dbfe4f657b4a4efb506ed63b24623e92"
    ]

    ledger = [
        json.loads(line)
        for line in (root / "artifacts/funnel-account-20260817.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if "GHSA-FRVJ-C5QP-XJ4W" in line.upper()
    ]
    assert len(ledger) == 1
    assert ledger[0]["ir_chain"]["original_sha"] == (
        "4737e1f11847d057859ec78892fa89e24cbcd83b"
    )


def test_replaced_identities_publish_no_dropped_ids_or_stale_shas() -> None:
    root = Path(__file__).resolve().parents[2]
    cases = {
        case["class_id"]: case
        for case in json.loads(
            (root / "web/src/generated/research-data.json").read_text()
        )["cases"]
    }
    replacements = {
        "alias-61bd78ccafb20adcb14b905d": {
            "case_id": "GHSA-Q6QC-XP4Q-RJQ5",
            "candidate": "f82c783607ae0129386cc072160dfcfb151a31fe",
            "fix": "d0b02a800aa0689d9428cc4cc170e0b6589fb2c3",
            "forbidden": {
                "GHSA-95F6-RFPG-C3W8",
                "0a283f454ba19eeda5c0bde26009040a9b5ca2f1",
                "3f970a974c65a94555c25af9f2796f11315e4584",
            },
        },
        "alias-ef917a24bf7209fd1f889026": {
            "case_id": "GHSA-G8P2-7WF7-98MQ",
            "candidate": "c74551c2ae0611f3ef0e691dc93a38372f366765",
            "fix": "a7534dc22382c42465f3676724536a014ce0cbf7",
            "forbidden": {
                "GHSA-7JM2-G593-4QRC",
                "CVE-2026-45001",
                "53764bbb4cc8794aec255252f149990a855e3bd6",
                "fe30b31a97a917ecc6e92f6c85378b6b20352422",
            },
        },
    }
    for class_id, expected in replacements.items():
        case = cases[class_id]
        evidence = case["code_evidence"]
        assert case["case_id"] == expected["case_id"]
        assert case["candidate_set"] == [expected["candidate"]]
        assert case["minimum_fix_set"] == [expected["fix"]]
        assert evidence["candidate_url"].endswith(expected["candidate"])
        assert evidence["fix_url"].endswith(expected["fix"])
        published = json.dumps(case).upper()
        assert all(value.upper() not in published for value in expected["forbidden"])


def test_published_cross_repo_origins_keep_their_import_carrier() -> None:
    root = Path(__file__).resolve().parents[2]
    cases = {
        case["case_id"]: case
        for case in json.loads(
            (root / "web/src/generated/research-data.json").read_text()
        )["cases"]
    }
    carrier = "2267d58afcc70fe19408b8f0dce108c340f3426d"
    expected = {
        "GHSA-VJ3G-5PX3-GR46": {
            "candidates": ["a604df8c83d179a6e9fc07987ebef610faaf4991"],
            "fix": "c821099157a9767d4df208c6b12f214946507871",
            "anchor": "feishu_img_${Date.now()}_${imageKey}",
        },
        "GHSA-X22M-J5QQ-J49M": {
            "candidates": [
                "4286755f26bcfdd5c704cc4eb0cabfdc1b314e68",
                "822b5f37b76284d247823efea51c47e0b975e9d1",
            ],
            "fix": "5b4121d6011a48c71e747e3c18197f180b872c5d",
            "anchor": "fetch(mediaUrl)",
        },
    }
    for case_id, values in expected.items():
        case = cases[case_id]
        evidence = case["code_evidence"]
        assert case["candidate_set"] == values["candidates"]
        assert case["carrier_set"] == [carrier]
        assert case["minimum_fix_set"] == [values["fix"]]
        assert evidence["candidate_url"] == (
            "https://github.com/m1heng/clawdbot-feishu/commit/"
            f"{values['candidates'][0]}"
        )
        assert evidence["fix_url"] == (
            f"https://github.com/openclaw/openclaw/commit/{values['fix']}"
        )
        assert values["anchor"] in "\n".join(
            hunk["code"] for hunk in evidence["candidate_hunks"]
        )

    x22 = cases["GHSA-X22M-J5QQ-J49M"]
    assert {source["repository"] for source in x22["candidate_sources"]} == {
        "m1heng/clawdbot-feishu"
    }
    assert {
        edge["candidate_sha"] for edge in x22["candidate_fix_edges"]
    } == set(x22["candidate_set"])

    fetched_context = cases["GHSA-877V-W3F5-3PCQ"]
    assert fetched_context["candidate_set"] == [
        "4286755f26bcfdd5c704cc4eb0cabfdc1b314e68",
        "8a607d7553339fffa97870668c482734db1b2d68",
    ]
    assert fetched_context["carrier_set"] == [carrier]
    assert fetched_context["candidate_sources"] == [
        {
            "sha": "4286755f26bcfdd5c704cc4eb0cabfdc1b314e68",
            "repository": "m1heng/clawdbot-feishu",
        },
        {
            "sha": "8a607d7553339fffa97870668c482734db1b2d68",
            "repository": "openclaw/openclaw",
        },
    ]
    assert fetched_context["candidate_fix_edges"][0]["carrier_sha"] == carrier
    assert fetched_context["candidate_fix_edges"][1]["carrier_sha"] is None
    assert fetched_context["candidate_fix_edges"][1]["origin_kind"] == "direct_commit"

    assert "GHSA-C875-H985-HVRC" not in cases

    qf5v = cases["GHSA-QF5V-M7P4-95RP"]
    assert qf5v["candidate_set"] == [
        "2db76f65dbfe4f657b4a4efb506ed63b24623e92"
    ]
    assert qf5v["carrier_set"] == [
        "e484df8460bb4e8026e24210120602aa7f181f64"
    ]
    assert qf5v["minimum_fix_set"] == [
        "2569b42bfadbcb7d78b55a00a60f77937e522699"
    ]


def test_generated_site_data_passes_publication_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    payload = json.loads(
        (root / "web/src/generated/research-data.json").read_text(encoding="utf-8")
    )
    allowlist = json.loads(
        (root / "scripts/site_preflight_allowlist.json").read_text(encoding="utf-8")
    )
    errors, _, stats = site_preflight.evaluate(payload, allowlist)
    cases = {case["case_id"]: case for case in payload["cases"]}

    assert errors == []
    assert sum(stats["publication_statuses"].values()) == len(payload["cases"])
    assert "GHSA-723W-CRW6-P9HX" in cases["GHSA-8H88-GXP3-J7PG"]["aliases"]
    assert "GHSA-CCP9-5G7C-PJ86" in cases["GHSA-J48Q-4C78-RHF9"]["aliases"]


if __name__ == "__main__":
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        params = inspect.signature(test).parameters
        if "monkeypatch" in params:
            mp = pytest.MonkeyPatch()
            try:
                test(mp)
            finally:
                mp.undo()
        elif params:
            marks = [
                marker for marker in getattr(test, "pytestmark", [])
                if marker.name == "parametrize"
            ]
            if marks:
                values = marks[0].args[1]
                for value in values:
                    test(value)
            else:
                test()
        else:
            test()
    print(f"{len(tests)} tests passed")
