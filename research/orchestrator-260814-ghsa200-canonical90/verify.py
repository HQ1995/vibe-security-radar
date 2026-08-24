#!/usr/bin/env python3
"""Distinct structural, Git, and semantic verifiers. Fail-fast. Clean stderr on success."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
GATES = build.GATES
HAN = build.HAN
SHA_RE = build.SHA_RE
GHSA_RE = build.GHSA_RE
PRIOR_STRICT = build.PRIOR_STRICT
STRICT_COUNT = build.STRICT_COUNT
CASE_XMXX = build.CASE_XMXX
CASE_PQH8 = build.CASE_PQH8
CASE_6C8G = build.CASE_6C8G
CASE_8RW6 = build.CASE_8RW6
CASE_V52W = build.CASE_V52W
ALIAS_XMXX = build.ALIAS_XMXX
CAND_XMXX = build.CAND_XMXX
PARENT_XMXX = build.PARENT_XMXX
FIX_XMXX = build.FIX_XMXX
FIX_PARENT_XMXX = build.FIX_PARENT_XMXX
CAND_PQH8 = build.CAND_PQH8
PARENT_PQH8 = build.PARENT_PQH8
FIX_PQH8 = build.FIX_PQH8
FIX_PARENT_PQH8 = build.FIX_PARENT_PQH8
CASE_PIMCORE = build.CASE_PIMCORE
CASE_HHJV = build.CASE_HHJV
CASE_73HC = build.CASE_73HC
CASE_282G = build.CASE_282G
CASE_45Q4 = build.CASE_45Q4
CASE_954P = build.CASE_954P
CASE_C8JX = build.CASE_C8JX
CASE_FPXG = build.CASE_FPXG
CASE_6G9V = build.CASE_6G9V
CASE_9722 = build.CASE_9722
FILEBROWSER_NEG = build.FILEBROWSER_NEG
FILEBROWSER_POS = build.FILEBROWSER_POS
ORD200 = build.ORD200
FILE_XMXX = build.FILE_XMXX
FILE_XMXX_HTTP = build.FILE_XMXX_HTTP
FILE_PQH8_LV = build.FILE_PQH8_LV
FILE_PQH8_GE = build.FILE_PQH8_GE
GIT = (
    "/usr/bin/git",
    "--no-optional-locks",
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
)
GIT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LC_ALL": "C",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_LAZY_FETCH": "1",
}
CLONE_XMXX = str(
    Path("/home")
    / "hanqing"
    / ".cache"
    / "cve-analyzer"
    / "repos"
    / "openclaw_openclaw"
)
CLONE_PQH8 = str(
    Path("/home")
    / "hanqing"
    / ".cache"
    / "ghsa200-worker-clones"
    / "contributor-redteam"
    / "clones"
    / "dynatrace-mcp"
)
TIMEFRAME = "now()-" + "${timeframe}"


def load_rows() -> list[dict]:
    return build.load_jsonl(HERE / "ledger.jsonl")


def by_kind(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if row["record_kind"] == kind]


def gitx(*args: str, repo: str) -> str:
    proc = subprocess.run(
        [*GIT, "-C", repo, *args],
        capture_output=True,
        text=True,
        check=True,
        env=GIT_ENV,
    )
    return proc.stdout.strip()


def ls_tree_blob(repo: str, rev: str, rel: str) -> str:
    out = gitx("ls-tree", rev, "--", rel, repo=repo)
    if not out:
        return ""
    return out.split()[2]


def git_show(repo: str, rev: str, rel: str) -> str:
    return gitx("show", f"{rev}:{rel}", repo=repo)


def is_ancestor(repo: str, older: str, newer: str) -> bool:
    proc = subprocess.run(
        [*GIT, "-C", repo, "merge-base", "--is-ancestor", older, newer],
        capture_output=True,
        text=True,
        env=GIT_ENV,
    )
    return proc.returncode == 0


def verify_structural() -> dict:
    pins = build.pin_inputs()
    outputs = build.build_outputs()
    for path, expected in outputs.items():
        assert path.is_file() and path.read_text() == expected, path.name
    rows = load_rows()
    text = (HERE / "ledger.jsonl").read_text()
    assert not HAN.search(text)
    assert not HAN.search((HERE / "summary.json").read_text())
    assert not HAN.search((HERE / "report.md").read_text())
    summary = build.load_json(HERE / "summary.json")
    manifest = build.load_json(HERE / "manifest.json")
    cap = build.load_capsule()
    neg = build.load_negative()
    prior = build.load_json(build.ROOT / build.P_C88_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C88_LEDGER)
    prior_text = (build.ROOT / build.P_C88_LEDGER).read_text()
    assert text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n")
    assert len(prior_rows) == build.BASE_LEDGER_RECORDS
    assert len(rows) == build.LEDGER_RECORDS
    assert [line for line in prior_text.splitlines() if line.strip()] == text.splitlines()[
        : build.BASE_LEDGER_RECORDS
    ]

    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    hyp = by_kind(rows, "PRESERVED_HYPOTHESIS")
    pub = by_kind(rows, "PRESERVED_PUBLIC_CASE")
    supers = by_kind(rows, "SUPERSEDES_EDGE")
    assert len(hyp) == 211
    assert len(pub) == 212
    assert len(counted) == STRICT_COUNT
    assert len(supers) == 46
    assert all(row["counted"] is True for row in counted)
    prior_counted = [row for row in prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert prior_counted == counted[:PRIOR_STRICT]
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_XMXX, CASE_PQH8]
    row89 = counted[88]
    row90 = counted[89]
    assert row89["ordinal"] == 89
    assert row90["ordinal"] == 90
    assert row89["case_id"] == CASE_XMXX
    assert row90["case_id"] == CASE_PQH8
    assert row89["candidate_set"] == [CAND_XMXX]
    assert row90["candidate_set"] == [CAND_PQH8]
    assert row89["carrier_set"] == []
    assert row90["carrier_set"] == []
    assert row89["minimum_fix_set"] == [FIX_XMXX]
    assert row90["minimum_fix_set"] == [FIX_PQH8]
    assert row89["aliases"] == [ALIAS_XMXX]
    assert row90["aliases"] == []
    assert row89["n_parents"] == 1
    assert row90["n_parents"] == 1
    assert row89["authorship_transfer"] is False
    assert row90["authorship_transfer"] is False
    assert row89["leader_strict_case_accepted"] is True
    assert row90["leader_strict_case_accepted"] is True
    assert row89["contribution_class"] == "AI_NEW_SURFACE_CONTRIBUTOR"
    assert row90["contribution_class"] == "AI_NEW_SURFACE_CONTRIBUTOR"
    assert row89["whole_ghsa_direct_root"] is False
    assert row90["whole_ghsa_direct_root"] is False
    assert "causal_admission" not in row89
    assert "causal_admission" not in row90
    assert row89["in_fp211_212"] is True
    assert row90["in_fp211_212"] is True
    assert row89["action"] == "SUPERSEDE"
    assert row90["action"] == "SUPERSEDE"

    for row in counted:
        for field in GATES:
            assert row[field] == "PASS", (row["case_id"], field, row[field])
        for field in ("candidate_set", "carrier_set", "minimum_fix_set"):
            assert row[field] == sorted(set(row[field]))
            assert all(SHA_RE.fullmatch(item) for item in row[field])
        assert "candidate_fix_edges" not in row
        assert GHSA_RE.fullmatch(row["case_id"])
        assert row["case_id"] not in row["aliases"]
        assert row["counting_unit"] == "first-party GHSA case"

    assert summary["causal_admission"] is False
    assert summary["publication_ready"] is False
    assert summary["integration_ready"] is False
    assert summary["status"] == "HOLD"
    assert summary["public_200_claim_supported"] is False
    assert summary["canonical_strict_count"] == STRICT_COUNT
    prior_append = list(prior["conservation"]["append_identities"])
    assert summary["conservation"]["prior_append_identities"] == prior_append
    assert len(prior_append) == 18
    assert summary["conservation"]["new_append_identities"] == []
    assert summary["conservation"]["append_identities"] == prior_append
    assert len(summary["conservation"]["append_identities"]) == 18
    assert summary["conservation"]["new_identities_append"] is False
    assert summary["conservation"]["same_id_source_layer_promoted"] is True
    assert summary["conservation"]["appended_strict_rows"] == 2
    assert summary["conservation"]["promoted_same_id_identities"] == [CASE_XMXX, CASE_PQH8]
    auth = manifest["packet_authority"]
    assert auth[-2]["packet"] == build.P_NEAR
    assert auth[-1]["packet"] == build.P_CCB
    assert auth[-2]["authority_rank"] == 47
    assert auth[-1]["authority_rank"] == 48
    assert len(auth) == 27
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_XMXX, CASE_PQH8]
    assert CASE_XMXX not in prior["strict_released_case_ids"]
    assert CASE_PQH8 not in prior["strict_released_case_ids"]
    assert CASE_6C8G not in summary["strict_released_case_ids"]
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert pins["canonical88_ledger"]["sha256"] == "35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074"
    assert {row["case_id"] for row in neg["controls"]} == {
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    }
    assert cap["leader_strict_case_accepted"] is True
    assert counted[87]["case_id"] == CASE_8RW6
    assert counted[86]["case_id"] == CASE_V52W
    new_edges = [row for row in supers if row["case_id"] in (CASE_XMXX, CASE_PQH8)]
    assert {row["edge_id"] for row in new_edges} == {"E-XMXX-KEEP", "E-PQH8-KEEP"}
    for edge in new_edges:
        assert edge["from_verdict"] == "NARROW"
        assert edge["to_verdict"] == "KEEP"
        assert edge["applies_to_counted_set"] is True
        assert edge["from_packet"] == build.P_FP211
        assert edge["to_packet"] == build.P_CCB
        assert CASE_6C8G in edge["note"]
    return summary


def verify_git_xmxx(row89: dict, cap: dict) -> None:
    case = cap["cases"][CASE_XMXX]
    repo = CLONE_XMXX
    assert gitx("rev-parse", f"{CAND_XMXX}^", repo=repo) == PARENT_XMXX
    assert gitx("rev-parse", f"{FIX_XMXX}^", repo=repo) == FIX_PARENT_XMXX
    parents = gitx("rev-list", "--parents", "-n", "1", CAND_XMXX, repo=repo).split()
    assert parents[0] == CAND_XMXX
    assert parents[1:] == [PARENT_XMXX]
    fix_parents = gitx("rev-list", "--parents", "-n", "1", FIX_XMXX, repo=repo).split()
    assert fix_parents[1:] == [FIX_PARENT_XMXX]
    assert is_ancestor(repo, PARENT_XMXX, CAND_XMXX)
    assert is_ancestor(repo, CAND_XMXX, FIX_XMXX)
    assert ls_tree_blob(repo, PARENT_XMXX, FILE_XMXX) == ""
    assert ls_tree_blob(repo, CAND_XMXX, FILE_XMXX) == case["object_shas"]["candidate_openresponses_blob"]
    names = gitx("diff", "--name-only", PARENT_XMXX, CAND_XMXX, repo=repo)
    assert FILE_XMXX in names.splitlines()
    cand_http = git_show(repo, CAND_XMXX, FILE_XMXX_HTTP)
    assert "handleOpenResponsesHttpRequest" in cand_http
    assert "{ auth: resolvedAuth }" in cand_http
    assert "getResolvedAuth" not in cand_http
    parent_http = git_show(repo, PARENT_XMXX, FILE_XMXX_HTTP)
    assert "handleOpenResponsesHttpRequest" not in parent_http
    fix_http = git_show(repo, FIX_XMXX, FILE_XMXX_HTTP)
    assert "getResolvedAuth" in fix_http
    assert gitx("rev-parse", "v2026.4.14^{commit}", repo=repo) == build.PEEL_XMXX_VULN
    assert gitx("rev-parse", "v2026.4.15^{commit}", repo=repo) == build.PEEL_XMXX_FIX
    assert is_ancestor(repo, CAND_XMXX, build.PEEL_XMXX_VULN)
    assert not is_ancestor(repo, FIX_XMXX, build.PEEL_XMXX_VULN)
    assert is_ancestor(repo, CAND_XMXX, build.PEEL_XMXX_FIX)
    assert is_ancestor(repo, FIX_XMXX, build.PEEL_XMXX_FIX)
    vuln_http = git_show(repo, build.PEEL_XMXX_VULN, FILE_XMXX_HTTP)
    assert "getResolvedAuth" not in vuln_http
    assert ls_tree_blob(repo, build.PEEL_XMXX_VULN, FILE_XMXX) != ""
    fixed_http = git_show(repo, build.PEEL_XMXX_FIX, FILE_XMXX_HTTP)
    assert "getResolvedAuth" in fixed_http
    msg = gitx("log", "-1", "--format=%B", CAND_XMXX, repo=repo)
    assert "Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>" in msg
    assert row89["candidate_parent"] == PARENT_XMXX
    assert row89["fix_parent"] == FIX_PARENT_XMXX
    assert row89["vulnerable_release"]["git_tag_commit"] == build.PEEL_XMXX_VULN
    assert row89["fixed_release"]["git_tag_commit"] == build.PEEL_XMXX_FIX
    assert row89["vulnerable_release"]["contains_candidate_any_parent"] is True
    assert row89["vulnerable_release"]["contains_fix_any_parent"] is False
    assert row89["fixed_release"]["contains_fix_any_parent"] is True


def verify_git_pqh8(row90: dict, cap: dict) -> None:
    case = cap["cases"][CASE_PQH8]
    repo = CLONE_PQH8
    assert gitx("rev-parse", f"{CAND_PQH8}^", repo=repo) == PARENT_PQH8
    assert gitx("rev-parse", f"{FIX_PQH8}^", repo=repo) == FIX_PARENT_PQH8
    parents = gitx("rev-list", "--parents", "-n", "1", CAND_PQH8, repo=repo).split()
    assert parents[0] == CAND_PQH8
    assert parents[1:] == [PARENT_PQH8]
    fix_parents = gitx("rev-list", "--parents", "-n", "1", FIX_PQH8, repo=repo).split()
    assert fix_parents[1:] == [FIX_PARENT_PQH8]
    assert is_ancestor(repo, PARENT_PQH8, CAND_PQH8)
    assert is_ancestor(repo, CAND_PQH8, FIX_PQH8)
    names = gitx("diff", "--name-only", PARENT_PQH8, CAND_PQH8, repo=repo)
    assert FILE_PQH8_LV in names.splitlines()
    assert FILE_PQH8_GE in names.splitlines()
    parent_lv = git_show(repo, PARENT_PQH8, FILE_PQH8_LV)
    parent_ge = git_show(repo, PARENT_PQH8, FILE_PQH8_GE)
    cand_lv = git_show(repo, CAND_PQH8, FILE_PQH8_LV)
    cand_ge = git_show(repo, CAND_PQH8, FILE_PQH8_GE)
    assert TIMEFRAME not in parent_lv
    assert TIMEFRAME not in parent_ge
    assert TIMEFRAME in cand_lv
    assert TIMEFRAME in cand_ge
    assert "validateTimeframe" not in cand_lv
    assert "validateTimeframe" not in cand_ge
    assert ls_tree_blob(repo, CAND_PQH8, FILE_PQH8_LV) == case["object_shas"]["candidate_list_vulnerabilities_blob"]
    assert ls_tree_blob(repo, PARENT_PQH8, FILE_PQH8_LV) == case["object_shas"]["parent_list_vulnerabilities_blob"]
    fix_lv = git_show(repo, FIX_PQH8, FILE_PQH8_LV)
    fix_ge = git_show(repo, FIX_PQH8, FILE_PQH8_GE)
    assert "validateTimeframe" in fix_lv
    assert "validateTimeframe" in fix_ge
    assert gitx("rev-parse", "v2.1.0^{commit}", repo=repo) == build.PEEL_PQH8_VULN
    assert gitx("rev-parse", "v2.1.1^{commit}", repo=repo) == build.PEEL_PQH8_FIX
    assert gitx("rev-parse", "v1.2.0^{commit}", repo=repo) == build.PEEL_PQH8_V12
    assert is_ancestor(repo, CAND_PQH8, build.PEEL_PQH8_VULN)
    assert not is_ancestor(repo, FIX_PQH8, build.PEEL_PQH8_VULN)
    assert is_ancestor(repo, CAND_PQH8, build.PEEL_PQH8_FIX)
    assert is_ancestor(repo, FIX_PQH8, build.PEEL_PQH8_FIX)
    assert is_ancestor(repo, CAND_PQH8, build.PEEL_PQH8_V12)
    assert not is_ancestor(repo, FIX_PQH8, build.PEEL_PQH8_V12)
    vuln_lv = git_show(repo, build.PEEL_PQH8_VULN, FILE_PQH8_LV)
    vuln_ge = git_show(repo, build.PEEL_PQH8_VULN, FILE_PQH8_GE)
    assert TIMEFRAME in vuln_lv
    assert TIMEFRAME in vuln_ge
    assert "validateTimeframe" not in vuln_lv
    assert "validateTimeframe" not in vuln_ge
    fixed_lv = git_show(repo, build.PEEL_PQH8_FIX, FILE_PQH8_LV)
    fixed_ge = git_show(repo, build.PEEL_PQH8_FIX, FILE_PQH8_GE)
    assert "validateTimeframe" in fixed_lv
    assert "validateTimeframe" in fixed_ge
    author = gitx("log", "-1", "--format=%an", CAND_PQH8, repo=repo)
    assert author == "copilot-swe-agent[bot]"
    assert row90["candidate_parent"] == PARENT_PQH8
    assert row90["fix_parent"] == FIX_PARENT_PQH8
    assert row90["vulnerable_release"]["git_tag_commit"] == build.PEEL_PQH8_VULN
    assert row90["fixed_release"]["git_tag_commit"] == build.PEEL_PQH8_FIX
    assert row90["vulnerable_release"]["contains_candidate_any_parent"] is True
    assert row90["vulnerable_release"]["contains_fix_any_parent"] is False
    assert row90["fixed_release"]["contains_fix_any_parent"] is True


def verify_git() -> None:
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    cap = build.load_capsule()
    verify_git_xmxx(counted[88], cap)
    verify_git_pqh8(counted[89], cap)
    row88 = counted[87]
    assert row88["case_id"] == CASE_8RW6
    assert row88["candidate_set"] == ["15579bd2cc57a3f88074acf54b42008598d9c87f"]
    assert row88["minimum_fix_set"] == ["8f89b260bb9692e5b0d58930793d482a8207eedc"]


def verify_semantic() -> None:
    rows = load_rows()
    hyp = by_kind(rows, "PRESERVED_HYPOTHESIS")
    pub = by_kind(rows, "PRESERVED_PUBLIC_CASE")
    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    by_key = {row["row_key"]: row for row in hyp}
    assert by_key[FILEBROWSER_NEG]["ordinal"] == 165
    assert by_key[FILEBROWSER_POS]["ordinal"] == 166
    dual = [row for row in pub if row["ordinal"] == 200]
    assert {row["case_id"] for row in dual} == set(ORD200)

    counted_ids = [row["case_id"] for row in counted]
    for banned in (
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
        CASE_C8JX,
        CASE_FPXG,
        CASE_6G9V,
        CASE_9722,
        CASE_6C8G,
        ALIAS_XMXX,
    ):
        assert banned not in counted_ids
    assert counted_ids.count(CASE_XMXX) == 1
    assert counted_ids.count(CASE_PQH8) == 1
    assert counted_ids[-2:] == [CASE_XMXX, CASE_PQH8]
    assert counted_ids[-3] == CASE_8RW6
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT
    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    assert build.MECH_FP_XMXX in fps
    assert build.MECH_FP_PQH8 in fps
    assert build.MECH_KEY_XMXX in mechs
    assert build.MECH_KEY_PQH8 in mechs
    alias_bag = []
    for row in counted:
        alias_bag.extend(row["aliases"])
        for alias in row["aliases"]:
            assert alias not in counted_ids
            assert alias != row["case_id"]
    assert ALIAS_XMXX in alias_bag
    assert alias_bag.count(ALIAS_XMXX) == 1
    neg = build.load_negative()
    for ctrl in neg["controls"]:
        assert ctrl["case_id"] not in counted_ids
        assert ctrl["verdict"] == "REJECT"
    summary = build.load_json(HERE / "summary.json")
    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "Causal admission is false" in report
    assert "canonical strict count 90" in report
    assert counted[88]["admission_source"] == "scoped_contributor_dual_keep"
    assert counted[89]["admission_source"] == "scoped_contributor_dual_keep"
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    for name in ("ledger.jsonl", "summary.json", "manifest.json", "report.md", "xmxx_pqh8_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "/home/hanqing/.cache" not in blob
        build.assert_no_leak(blob)
        for line in blob.splitlines():
            assert line == line.rstrip(), name
    for name in ("summary.json", "manifest.json", "report.md", "xmxx_pqh8_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "pages/ghsa/" not in blob
        assert "pages/GHSA" not in blob
    for row in counted[PRIOR_STRICT:]:
        assert not any("pages/ghsa/" in item for item in row["first_party_source_refs"])
        assert "clone_path" not in row
        assert "clone" not in row
        assert build.P_NEAR in row["first_party_source_refs"]
        assert build.P_CCB in row["first_party_source_refs"]
    assert summary["counts"]["keep_xmxx"] == 1
    assert summary["counts"]["keep_pqh8"] == 1
    assert CASE_6C8G in summary["excluded"]
    assert ALIAS_XMXX in summary["excluded"]
    assert "whole_ghsa_direct_root_xmxx" in summary["excluded"]
    assert "whole_ghsa_direct_root_pqh8" in summary["excluded"]
    pub_ids = {row["case_id"] for row in pub}
    assert CASE_XMXX in pub_ids
    assert CASE_PQH8 in pub_ids
    assert CASE_6C8G in pub_ids
    hyp_ids = set()
    for row in hyp:
        hyp_ids.update(row.get("declared_public_ids") or [])
    assert CASE_XMXX in hyp_ids
    assert CASE_PQH8 in hyp_ids
    assert CASE_6C8G in hyp_ids


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    return summary, counted


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical90 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert counted[-2]["case_id"] == CASE_XMXX
    assert counted[-1]["case_id"] == CASE_PQH8
    assert CASE_6C8G not in [row["case_id"] for row in counted]


if __name__ == "__main__":
    main()
