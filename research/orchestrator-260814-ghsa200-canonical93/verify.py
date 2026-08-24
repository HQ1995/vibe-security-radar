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
CASE_MFMP = build.CASE_MFMP
CASE_M649 = build.CASE_M649
CASE_G353 = build.CASE_G353
CASE_Q447 = build.CASE_Q447
CASE_2Q7J = build.CASE_2Q7J
CASE_6C8G = build.CASE_6C8G
CASE_5WP8 = build.CASE_5WP8
CASE_PQH8 = build.CASE_PQH8
CASE_XMXX = build.CASE_XMXX
CASE_HM7V = build.CASE_HM7V
CASE_CWP8 = build.CASE_CWP8
CASE_2QRV = build.CASE_2QRV
CASE_R5JH = build.CASE_R5JH
CASE_J8Q9 = build.CASE_J8Q9
CAND = build.CAND
PARENT = build.PARENT
FIX_MFMP = build.FIX_MFMP
FIX_PARENT_MFMP = build.FIX_PARENT_MFMP
FIX_M649 = build.FIX_M649
FIX_PARENT_M649 = build.FIX_PARENT_M649
MEM_0EA20 = build.MEM_0EA20
MEM_3B8B = build.MEM_3B8B
MEM_367D = build.MEM_367D
MEM_5631 = build.MEM_5631
EDE1 = build.EDE1
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
FILE_GV = build.FILE_GV
FILE_GR = build.FILE_GR
UNESC_PILL = "i18next.t(role.OptionName)"
ESC_PILL = "window.CRM.escapeHtml(i18next.t(role.OptionName))"
TEL_UNESC = """href="tel:' + escaped"""
TEL_ESC = """href="tel:' + window.CRM.escapeAttribute(data)"""
MAIL_UNESC = """href="mailto:' + escaped"""
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
CLONE = str(
    Path("/home")
    / "hanqing"
    / ".cache"
    / "cve-analyzer"
    / "repos"
    / "churchcrm_crm"
)


def load_rows() -> list[dict]:
    return build.load_jsonl(HERE / "ledger.jsonl")


def by_kind(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if row["record_kind"] == kind]


def gitx(*args: str, repo: str = CLONE) -> str:
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
    prior = build.load_json(build.ROOT / build.P_C91_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C91_LEDGER)
    prior_text = (build.ROOT / build.P_C91_LEDGER).read_text()
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
    appends = by_kind(rows, "APPEND_IDENTITY")
    assert len(hyp) == 211
    assert len(pub) == 212
    assert len(counted) == STRICT_COUNT
    assert len(supers) == 47
    assert len(appends) == 14
    assert all(row["counted"] is True for row in counted)
    prior_counted = [row for row in prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert prior_counted == counted[:PRIOR_STRICT]
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_MFMP, CASE_M649]
    row92 = counted[91]
    row93 = counted[92]
    assert row92["ordinal"] == 92
    assert row93["ordinal"] == 93
    assert row92["case_id"] == CASE_MFMP
    assert row93["case_id"] == CASE_M649
    assert row92["candidate_set"] == [CAND]
    assert row93["candidate_set"] == [CAND]
    assert row92["carrier_set"] == [CAND]
    assert row93["carrier_set"] == [CAND]
    assert row92["minimum_fix_set"] == [FIX_MFMP]
    assert row93["minimum_fix_set"] == [FIX_M649]
    assert row92["aliases"] == []
    assert row93["aliases"] == []
    assert row92["n_parents"] == 1
    assert row93["n_parents"] == 1
    assert row92["authorship_transfer"] is False
    assert row93["authorship_transfer"] is False
    assert row92["leader_strict_case_accepted"] is True
    assert row93["leader_strict_case_accepted"] is True
    assert row92["contribution_class"] == "AI_SCOPED_CONTRIBUTOR"
    assert row93["contribution_class"] == "AI_SCOPED_CONTRIBUTOR"
    assert row92["whole_ghsa_direct_root"] is False
    assert row93["whole_ghsa_direct_root"] is False
    assert "causal_admission" not in row92
    assert "causal_admission" not in row93
    assert row92["in_fp211_212"] is False
    assert row93["in_fp211_212"] is False
    assert row92["action"] == "APPEND"
    assert row93["action"] == "APPEND"
    assert MEM_0EA20 not in row92["candidate_set"]
    assert MEM_0EA20 not in row93["candidate_set"]

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
    assert summary["conservation"]["new_append_identities"] == [CASE_MFMP, CASE_M649]
    assert summary["conservation"]["append_identities"] == prior_append + [CASE_MFMP, CASE_M649]
    assert len(summary["conservation"]["append_identities"]) == 20
    assert summary["conservation"]["new_identities_append"] is True
    assert summary["conservation"]["same_id_source_layer_promoted"] is False
    assert summary["conservation"]["appended_strict_rows"] == 2
    assert summary["uniqueness"]["promoted_ids"] == [CASE_MFMP, CASE_M649]
    assert summary["uniqueness"]["absent_from_prior_strict"] is True
    assert summary["uniqueness"]["shared_candidate_sha_not_duplication"] is True
    assert summary["uniqueness"]["mfmp_distinct_from_m649"] is True
    assert summary["uniqueness"]["m649_distinct_from_counted_hm7v"] is True
    assert summary["uniqueness"]["g353_not_promoted"] is True
    assert summary["uniqueness"]["member_0ea20d01_not_transferred"] is True
    auth = manifest["packet_authority"]
    assert auth[-2]["packet"] == build.P_NEAR
    assert auth[-1]["packet"] == build.P_HOSTILE
    assert auth[-2]["authority_rank"] == 51
    assert auth[-1]["authority_rank"] == 52
    assert len(auth) == 31
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_MFMP, CASE_M649]
    assert CASE_MFMP not in prior["strict_released_case_ids"]
    assert CASE_M649 not in prior["strict_released_case_ids"]
    assert CASE_G353 not in summary["strict_released_case_ids"]
    assert CASE_Q447 not in summary["strict_released_case_ids"]
    assert CASE_2Q7J not in summary["strict_released_case_ids"]
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert pins["canonical91_ledger"]["sha256"] == "70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e"
    assert {row["case_id"] for row in neg["controls"]} == {
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    }
    assert cap["leader_strict_case_accepted"] is True
    assert counted[90]["case_id"] == CASE_5WP8
    assert counted[89]["case_id"] == CASE_PQH8
    new_appends = [row for row in appends if row["case_id"] in (CASE_MFMP, CASE_M649)]
    assert [row["case_id"] for row in new_appends] == [CASE_MFMP, CASE_M649]
    assert [row["ordinal"] for row in new_appends] == [92, 93]
    for rec in new_appends:
        assert rec["counted"] is False
        assert rec["in_fp211_212"] is False
        assert rec["action"] == "APPEND"
        assert rec["source_layer"] is True
    assert not any(row["case_id"] in (CASE_MFMP, CASE_M649) for row in supers)
    new_tail = text.splitlines()[build.BASE_LEDGER_RECORDS :]
    assert len(new_tail) == 4
    kinds_tail = [json.loads(line)["record_kind"] for line in new_tail]
    assert kinds_tail == [
        "APPEND_IDENTITY",
        "STRICT_RELEASED_CASE",
        "APPEND_IDENTITY",
        "STRICT_RELEASED_CASE",
    ]
    return summary


def verify_git_shared(repo: str) -> None:
    assert gitx("rev-parse", f"{CAND}^", repo=repo) == PARENT
    parents = gitx("rev-list", "--parents", "-n", "1", CAND, repo=repo).split()
    assert parents[0] == CAND
    assert parents[1:] == [PARENT]
    assert is_ancestor(repo, PARENT, CAND)
    assert not is_ancestor(repo, MEM_0EA20, CAND)
    assert not is_ancestor(repo, MEM_0EA20, build.PEEL_742)
    assert not is_ancestor(repo, MEM_0EA20, build.PEEL_743)
    assert ls_tree_blob(repo, PARENT, FILE_GV) == build.BLOB_PARENT_GV
    assert ls_tree_blob(repo, CAND, FILE_GV) == build.BLOB_CAND_GV
    assert ls_tree_blob(repo, MEM_0EA20, FILE_GV) == build.BLOB_MEM_GV
    assert ls_tree_blob(repo, PARENT, FILE_GR) == build.BLOB_GR_PARENT
    assert ls_tree_blob(repo, CAND, FILE_GR) == build.BLOB_GR_PARENT
    names = gitx("diff", "--name-only", PARENT, CAND, repo=repo)
    assert FILE_GV in names.splitlines()
    parent_src = git_show(repo, PARENT, FILE_GV)
    cand_src = git_show(repo, CAND, FILE_GV)
    assert "buildRolePills" not in parent_src
    assert UNESC_PILL not in parent_src
    assert "tel:" not in parent_src
    assert "mailto:" not in parent_src
    assert "data-name" in parent_src
    assert "buildRolePills" in cand_src
    assert UNESC_PILL in cand_src
    assert ESC_PILL not in cand_src
    assert TEL_UNESC in cand_src
    assert MAIL_UNESC in cand_src
    msg = gitx("log", "-1", "--format=%B", CAND, repo=repo)
    assert build.AI_MARKER in msg


def verify_git_mfmp(row92: dict, cap: dict) -> None:
    case = cap["cases"][CASE_MFMP]
    repo = CLONE
    assert gitx("rev-parse", f"{FIX_MFMP}^", repo=repo) == FIX_PARENT_MFMP
    fix_parents = gitx("rev-list", "--parents", "-n", "1", FIX_MFMP, repo=repo).split()
    assert fix_parents[1:] == [FIX_PARENT_MFMP]
    assert is_ancestor(repo, CAND, FIX_MFMP)
    assert not is_ancestor(repo, MEM_3B8B, FIX_MFMP)
    assert not is_ancestor(repo, MEM_367D, FIX_MFMP)
    assert ls_tree_blob(repo, FIX_MFMP, FILE_GV) == case["object_shas"]["fixed_release_groupview_blob"]
    fix_src = git_show(repo, FIX_MFMP, FILE_GV)
    assert ESC_PILL in fix_src
    assert gitx("rev-parse", "7.4.2^{commit}", repo=repo) == build.PEEL_742
    assert gitx("rev-parse", "7.4.3^{commit}", repo=repo) == build.PEEL_743
    assert is_ancestor(repo, CAND, build.PEEL_742)
    assert not is_ancestor(repo, FIX_MFMP, build.PEEL_742)
    assert is_ancestor(repo, CAND, build.PEEL_743)
    assert is_ancestor(repo, FIX_MFMP, build.PEEL_743)
    vuln_src = git_show(repo, build.PEEL_742, FILE_GV)
    assert UNESC_PILL in vuln_src
    assert ESC_PILL not in vuln_src
    assert ls_tree_blob(repo, build.PEEL_742, FILE_GV) == build.BLOB_742_GV
    fixed_src = git_show(repo, build.PEEL_743, FILE_GV)
    assert ESC_PILL in fixed_src
    assert ls_tree_blob(repo, build.PEEL_743, FILE_GV) == build.BLOB_743_GV
    pickaxe = gitx(
        "log",
        "--first-parent",
        "-S",
        "buildRolePills",
        "--format=%H",
        "7.4.2",
        "--",
        FILE_GV,
        repo=repo,
    )
    assert pickaxe.splitlines() == [CAND]
    assert row92["candidate_parent"] == PARENT
    assert row92["fix_parent"] == FIX_PARENT_MFMP
    assert row92["vulnerable_release"]["git_tag_commit"] == build.PEEL_742
    assert row92["fixed_release"]["git_tag_commit"] == build.PEEL_743
    assert row92["vulnerable_release"]["contains_candidate_any_parent"] is True
    assert row92["vulnerable_release"]["contains_fix_any_parent"] is False
    assert row92["fixed_release"]["contains_fix_any_parent"] is True


def verify_git_m649(row93: dict, cap: dict) -> None:
    case = cap["cases"][CASE_M649]
    repo = CLONE
    assert gitx("rev-parse", f"{FIX_M649}^", repo=repo) == FIX_PARENT_M649
    fix_parents = gitx("rev-list", "--parents", "-n", "1", FIX_M649, repo=repo).split()
    assert fix_parents[1:] == [FIX_PARENT_M649]
    assert is_ancestor(repo, CAND, FIX_M649)
    assert not is_ancestor(repo, MEM_5631, FIX_M649)
    assert not is_ancestor(repo, MEM_5631, build.PEEL_760)
    assert ls_tree_blob(repo, FIX_M649, FILE_GV) == case["object_shas"]["fixed_release_groupview_blob"]
    fix_src = git_show(repo, FIX_M649, FILE_GV)
    assert TEL_ESC in fix_src
    assert "escapeAttribute" in fix_src
    assert gitx("rev-parse", "7.5.1^{commit}", repo=repo) == build.PEEL_751
    assert gitx("rev-parse", "7.6.0^{commit}", repo=repo) == build.PEEL_760
    assert is_ancestor(repo, CAND, build.PEEL_751)
    assert not is_ancestor(repo, FIX_M649, build.PEEL_751)
    assert is_ancestor(repo, CAND, build.PEEL_760)
    assert is_ancestor(repo, FIX_M649, build.PEEL_760)
    vuln_src = git_show(repo, build.PEEL_751, FILE_GV)
    assert TEL_UNESC in vuln_src
    assert TEL_ESC not in vuln_src
    assert ls_tree_blob(repo, build.PEEL_751, FILE_GV) == build.BLOB_751_GV
    fixed_src = git_show(repo, build.PEEL_760, FILE_GV)
    assert TEL_ESC in fixed_src
    assert ls_tree_blob(repo, build.PEEL_760, FILE_GV) == build.BLOB_760_GV
    tel_pick = gitx(
        "log",
        "--first-parent",
        "-S",
        'href="tel:',
        "--format=%H",
        "7.5.1",
        "--",
        FILE_GV,
        repo=repo,
    )
    assert tel_pick.splitlines() == [CAND]
    mail_pick = gitx(
        "log",
        "--first-parent",
        "-S",
        'href="mailto:',
        "--format=%H",
        "7.5.1",
        "--",
        FILE_GV,
        repo=repo,
    )
    assert mail_pick.splitlines() == [CAND]
    data_pick = gitx(
        "log",
        "--first-parent",
        "-S",
        "data-name",
        "--format=%H",
        "7.5.1",
        "--",
        FILE_GV,
        repo=repo,
    )
    assert data_pick.splitlines()[0] == EDE1
    assert row93["candidate_parent"] == PARENT
    assert row93["fix_parent"] == FIX_PARENT_M649
    assert row93["vulnerable_release"]["git_tag_commit"] == build.PEEL_751
    assert row93["fixed_release"]["git_tag_commit"] == build.PEEL_760
    assert row93["vulnerable_release"]["contains_candidate_any_parent"] is True
    assert row93["vulnerable_release"]["contains_fix_any_parent"] is False
    assert row93["fixed_release"]["contains_fix_any_parent"] is True


def verify_git() -> None:
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    cap = build.load_capsule()
    verify_git_shared(CLONE)
    verify_git_mfmp(counted[91], cap)
    verify_git_m649(counted[92], cap)
    row91 = counted[90]
    assert row91["case_id"] == CASE_5WP8
    assert row91["candidate_set"] == ["1712debbea60af6adf4a8a5939a43f7ef9a1ac16"]


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
        CASE_2QRV,
        CASE_R5JH,
        CASE_J8Q9,
        CASE_G353,
        CASE_Q447,
        CASE_2Q7J,
    ):
        assert banned not in counted_ids
    assert counted_ids.count(CASE_MFMP) == 1
    assert counted_ids.count(CASE_M649) == 1
    assert counted_ids[-2:] == [CASE_MFMP, CASE_M649]
    assert counted_ids[-3] == CASE_5WP8
    assert CASE_HM7V in counted_ids
    assert CASE_CWP8 in counted_ids
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT
    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    assert build.MECH_FP_MFMP in fps
    assert build.MECH_FP_M649 in fps
    assert build.MECH_KEY_MFMP in mechs
    assert build.MECH_KEY_M649 in mechs
    alias_bag = []
    for row in counted:
        alias_bag.extend(row["aliases"])
        for alias in row["aliases"]:
            assert alias not in counted_ids
            assert alias != row["case_id"]
    neg = build.load_negative()
    for ctrl in neg["controls"]:
        assert ctrl["case_id"] not in counted_ids
        assert ctrl["verdict"] == "REJECT"
    summary = build.load_json(HERE / "summary.json")
    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "Causal admission is false" in report
    assert "canonical strict count 93" in report
    assert counted[91]["admission_source"] == "scoped_contributor_wave_l_dual_keep"
    assert counted[92]["admission_source"] == "scoped_contributor_wave_l_dual_keep"
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    for name in ("ledger.jsonl", "summary.json", "manifest.json", "report.md", "acceptance.json"):
        blob = (HERE / name).read_text()
        assert "/home/hanqing/.cache" not in blob
        build.assert_no_leak(blob)
        for line in blob.splitlines():
            assert line == line.rstrip(), name
    for name in ("summary.json", "manifest.json", "report.md", "acceptance.json"):
        blob = (HERE / name).read_text()
        assert "pages/ghsa/" not in blob
        assert "pages/GHSA" not in blob
    for row in counted[PRIOR_STRICT:]:
        assert not any("pages/ghsa/" in item for item in row["first_party_source_refs"])
        assert "clone_path" not in row
        assert "clone" not in row
        assert build.P_NEAR in row["first_party_source_refs"]
        assert build.P_HOSTILE in row["first_party_source_refs"]
    assert summary["counts"]["keep_mfmp"] == 1
    assert summary["counts"]["keep_m649"] == 1
    assert CASE_G353 in summary["excluded"]
    assert CASE_Q447 in summary["excluded"]
    assert CASE_2Q7J in summary["excluded"]
    assert "whole_ghsa_direct_root_mfmp" in summary["excluded"]
    assert "whole_ghsa_direct_root_m649" in summary["excluded"]
    assert "shared_closer_hm7v_m649" in summary["excluded"]
    pub_ids = {row["case_id"] for row in pub}
    assert CASE_G353 in pub_ids
    assert CASE_Q447 in pub_ids
    assert CASE_2Q7J in pub_ids
    assert CASE_6C8G in pub_ids
    row_hm7v = next(row for row in counted if row["case_id"] == CASE_HM7V)
    assert row_hm7v["mechanism_key"] != build.MECH_KEY_M649
    assert row_hm7v["mechanism_key"] != build.MECH_KEY_MFMP
    assert FIX_M649 in row_hm7v["minimum_fix_set"]
    assert counted[91]["minimum_fix_set"] != counted[92]["minimum_fix_set"]
    assert counted[91]["mechanism_fingerprint"] != counted[92]["mechanism_fingerprint"]
    assert counted[91]["candidate_set"] == counted[92]["candidate_set"]


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    return summary, counted


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical93 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert counted[-2]["case_id"] == CASE_MFMP
    assert counted[-1]["case_id"] == CASE_M649
    assert CASE_G353 not in [row["case_id"] for row in counted]
    assert CASE_Q447 not in [row["case_id"] for row in counted]
    assert CASE_2Q7J not in [row["case_id"] for row in counted]


if __name__ == "__main__":
    main()
