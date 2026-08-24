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
CASE_5WP8 = build.CASE_5WP8
CASE_2QRV = build.CASE_2QRV
CASE_R5JH = build.CASE_R5JH
CASE_46Q5 = build.CASE_46Q5
CASE_J8Q9 = build.CASE_J8Q9
CASE_XMXX = build.CASE_XMXX
CASE_PQH8 = build.CASE_PQH8
CASE_6C8G = build.CASE_6C8G
CASE_8RW6 = build.CASE_8RW6
CASE_V52W = build.CASE_V52W
CAND_5WP8 = build.CAND_5WP8
CARR_5WP8 = build.CARR_5WP8
PARENT_5WP8 = build.PARENT_5WP8
FIX_5WP8 = build.FIX_5WP8
FIX_PARENT_5WP8 = build.FIX_PARENT_5WP8
MEM_5WP8 = build.MEM_5WP8
BLK_5WP8 = build.BLK_5WP8
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
FILE_5WP8 = build.FILE_5WP8
SKIP_5WP8 = build.SKIP_5WP8
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
CLONE_5WP8 = str(
    Path("/home")
    / "hanqing"
    / ".cache"
    / "cve-analyzer"
    / "repos"
    / "qhkm_zeptoclaw"
)


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
    prior = build.load_json(build.ROOT / build.P_C90_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C90_LEDGER)
    prior_text = (build.ROOT / build.P_C90_LEDGER).read_text()
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
    assert len(supers) == 47
    assert all(row["counted"] is True for row in counted)
    prior_counted = [row for row in prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert prior_counted == counted[:PRIOR_STRICT]
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_5WP8]
    row91 = counted[90]
    assert row91["ordinal"] == 91
    assert row91["case_id"] == CASE_5WP8
    assert row91["candidate_set"] == [CAND_5WP8]
    assert row91["carrier_set"] == [CARR_5WP8]
    assert row91["minimum_fix_set"] == [FIX_5WP8]
    assert row91["aliases"] == []
    assert row91["n_parents"] == 1
    assert row91["authorship_transfer"] is False
    assert row91["leader_strict_case_accepted"] is True
    assert row91["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert row91["whole_ghsa_direct_root"] is False
    assert "causal_admission" not in row91
    assert row91["in_fp211_212"] is True
    assert row91["action"] == "SUPERSEDE"
    assert MEM_5WP8 not in row91["candidate_set"]
    assert MEM_5WP8 not in row91["carrier_set"]
    assert BLK_5WP8 not in row91["candidate_set"]

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
    assert summary["conservation"]["appended_strict_rows"] == 1
    assert summary["conservation"]["promoted_same_id_identities"] == [CASE_5WP8]
    assert summary["uniqueness"]["promoted_id"] == CASE_5WP8
    assert summary["uniqueness"]["absent_from_prior_strict"] is True
    assert summary["uniqueness"]["distinct_from_counted_46q5"] is True
    assert summary["uniqueness"]["distinct_from_negative_hhjv"] is True
    assert summary["uniqueness"]["member_3c4368da_not_transferred"] is True
    assert summary["uniqueness"]["2qrv_not_promoted"] is True
    assert summary["uniqueness"]["r5jh_not_promoted"] is True
    auth = manifest["packet_authority"]
    assert auth[-2]["packet"] == build.P_NEAR
    assert auth[-1]["packet"] == build.P_HOSTILE
    assert auth[-2]["authority_rank"] == 49
    assert auth[-1]["authority_rank"] == 50
    assert len(auth) == 29
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_5WP8]
    assert CASE_5WP8 not in prior["strict_released_case_ids"]
    assert CASE_2QRV not in summary["strict_released_case_ids"]
    assert CASE_R5JH not in summary["strict_released_case_ids"]
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert pins["canonical90_ledger"]["sha256"] == "daf706e14d514ad62d197e61aa8ec7f52eefd958bc19a4a7c58591a0be8654ec"
    assert {row["case_id"] for row in neg["controls"]} == {
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    }
    assert cap["leader_strict_case_accepted"] is True
    assert counted[89]["case_id"] == CASE_PQH8
    assert counted[88]["case_id"] == CASE_XMXX
    assert counted[87]["case_id"] == CASE_8RW6
    new_edges = [row for row in supers if row["case_id"] == CASE_5WP8]
    assert {row["edge_id"] for row in new_edges} == {"E-5WP8-KEEP"}
    for edge in new_edges:
        assert edge["from_verdict"] == "NARROW"
        assert edge["to_verdict"] == "KEEP"
        assert edge["applies_to_counted_set"] is True
        assert edge["from_packet"] == build.P_FP211
        assert edge["to_packet"] == build.P_HOSTILE
        assert CASE_2QRV in edge["note"]
        assert CASE_R5JH in edge["note"]
    return summary


def verify_git_5wp8(row91: dict, cap: dict) -> None:
    case = cap["cases"][CASE_5WP8]
    repo = CLONE_5WP8
    assert gitx("rev-parse", f"{CAND_5WP8}^", repo=repo) == PARENT_5WP8
    assert gitx("rev-parse", f"{FIX_5WP8}^", repo=repo) == FIX_PARENT_5WP8
    parents = gitx("rev-list", "--parents", "-n", "1", CAND_5WP8, repo=repo).split()
    assert parents[0] == CAND_5WP8
    assert parents[1:] == [PARENT_5WP8]
    fix_parents = gitx("rev-list", "--parents", "-n", "1", FIX_5WP8, repo=repo).split()
    assert fix_parents[1:] == [FIX_PARENT_5WP8]
    assert is_ancestor(repo, PARENT_5WP8, CAND_5WP8)
    assert is_ancestor(repo, CAND_5WP8, FIX_5WP8)
    assert not is_ancestor(repo, MEM_5WP8, CAND_5WP8)
    assert not is_ancestor(repo, MEM_5WP8, FIX_5WP8)
    assert is_ancestor(repo, BLK_5WP8, CAND_5WP8)
    assert ls_tree_blob(repo, PARENT_5WP8, FILE_5WP8) == case["object_shas"]["parent_shell_blob"]
    assert ls_tree_blob(repo, CAND_5WP8, FILE_5WP8) == case["object_shas"]["candidate_shell_blob"]
    assert ls_tree_blob(repo, MEM_5WP8, FILE_5WP8) == case["object_shas"]["member_3c4368da_shell_blob"]
    names = gitx("diff", "--name-only", PARENT_5WP8, CAND_5WP8, repo=repo)
    assert FILE_5WP8 in names.splitlines()
    parent_src = git_show(repo, PARENT_5WP8, FILE_5WP8)
    cand_src = git_show(repo, CAND_5WP8, FILE_5WP8)
    assert "ShellAllowlistMode" not in parent_src
    assert "allowlist.is_empty" not in parent_src
    assert "fn validate_command" in parent_src
    assert SKIP_5WP8 in cand_src
    assert "ShellAllowlistMode" in cand_src
    fix_src = git_show(repo, FIX_5WP8, FILE_5WP8)
    assert SKIP_5WP8 not in fix_src
    assert "if self.allowlist_mode != ShellAllowlistMode::Off {" in fix_src
    assert "Previously, `!self.allowlist.is_empty()` guard skipped the check" in fix_src
    assert gitx("rev-parse", "v0.6.1^{commit}", repo=repo) == build.PEEL_5WP8_VULN
    assert gitx("rev-parse", "v0.6.2^{commit}", repo=repo) == build.PEEL_5WP8_FIX
    assert gitx("rev-parse", "v0.5.8^{commit}", repo=repo) == build.PEEL_5WP8_058
    assert is_ancestor(repo, CAND_5WP8, build.PEEL_5WP8_VULN)
    assert not is_ancestor(repo, FIX_5WP8, build.PEEL_5WP8_VULN)
    assert is_ancestor(repo, CAND_5WP8, build.PEEL_5WP8_FIX)
    assert is_ancestor(repo, FIX_5WP8, build.PEEL_5WP8_FIX)
    assert not is_ancestor(repo, MEM_5WP8, build.PEEL_5WP8_VULN)
    vuln_src = git_show(repo, build.PEEL_5WP8_VULN, FILE_5WP8)
    assert SKIP_5WP8 in vuln_src
    assert ls_tree_blob(repo, build.PEEL_5WP8_VULN, FILE_5WP8) == build.BLOB_VULN_5WP8
    assert ls_tree_blob(repo, "v0.5.8", FILE_5WP8) == build.BLOB_VULN_5WP8
    fixed_src = git_show(repo, build.PEEL_5WP8_FIX, FILE_5WP8)
    assert SKIP_5WP8 not in fixed_src
    assert ls_tree_blob(repo, build.PEEL_5WP8_FIX, FILE_5WP8) == build.BLOB_FIX_5WP8
    pickaxe = gitx(
        "log",
        "--first-parent",
        "-S",
        "allowlist.is_empty",
        "--format=%H",
        "v0.6.1",
        "--",
        FILE_5WP8,
        repo=repo,
    )
    assert pickaxe.splitlines() == [CAND_5WP8]
    msg = gitx("log", "-1", "--format=%B", CAND_5WP8, repo=repo)
    assert build.AI_MARKER_5WP8 in msg
    assert row91["candidate_parent"] == PARENT_5WP8
    assert row91["fix_parent"] == FIX_PARENT_5WP8
    assert row91["vulnerable_release"]["git_tag_commit"] == build.PEEL_5WP8_VULN
    assert row91["fixed_release"]["git_tag_commit"] == build.PEEL_5WP8_FIX
    assert row91["vulnerable_release"]["contains_candidate_any_parent"] is True
    assert row91["vulnerable_release"]["contains_fix_any_parent"] is False
    assert row91["fixed_release"]["contains_fix_any_parent"] is True
    assert row91["vulnerable_release"]["has_empty_strict_skip"] is True
    assert row91["fixed_release"]["has_empty_strict_skip"] is False


def verify_git() -> None:
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    cap = build.load_capsule()
    verify_git_5wp8(counted[90], cap)
    row90 = counted[89]
    assert row90["case_id"] == CASE_PQH8
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
        CASE_2QRV,
        CASE_R5JH,
        CASE_J8Q9,
    ):
        assert banned not in counted_ids
    assert counted_ids.count(CASE_5WP8) == 1
    assert counted_ids[-1] == CASE_5WP8
    assert counted_ids[-2] == CASE_PQH8
    assert counted_ids[-3] == CASE_XMXX
    assert CASE_46Q5 in counted_ids
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT
    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    assert build.MECH_FP_5WP8 in fps
    assert build.MECH_KEY_5WP8 in mechs
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
    assert "canonical strict count 91" in report
    assert counted[90]["admission_source"] == "incomplete_remediation_dual_keep"
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    for name in ("ledger.jsonl", "summary.json", "manifest.json", "report.md", "5wp8_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "/home/hanqing/.cache" not in blob
        build.assert_no_leak(blob)
        for line in blob.splitlines():
            assert line == line.rstrip(), name
    for name in ("summary.json", "manifest.json", "report.md", "5wp8_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "pages/ghsa/" not in blob
        assert "pages/GHSA" not in blob
    for row in counted[PRIOR_STRICT:]:
        assert not any("pages/ghsa/" in item for item in row["first_party_source_refs"])
        assert "clone_path" not in row
        assert "clone" not in row
        assert build.P_NEAR in row["first_party_source_refs"]
        assert build.P_HOSTILE in row["first_party_source_refs"]
    assert summary["counts"]["keep_5wp8"] == 1
    assert CASE_2QRV in summary["excluded"]
    assert CASE_R5JH in summary["excluded"]
    assert CASE_J8Q9 in summary["excluded"]
    assert "whole_ghsa_direct_root_5wp8" in summary["excluded"]
    assert "member_3c4368da_5wp8" in summary["excluded"]
    pub_ids = {row["case_id"] for row in pub}
    assert CASE_5WP8 in pub_ids
    assert CASE_2QRV in pub_ids
    assert CASE_R5JH in pub_ids
    hyp_ids = set()
    for row in hyp:
        hyp_ids.update(row.get("declared_public_ids") or [])
    assert CASE_5WP8 in hyp_ids
    assert CASE_2QRV in hyp_ids
    assert CASE_R5JH in hyp_ids
    row46 = next(row for row in counted if row["case_id"] == CASE_46Q5)
    assert row46["mechanism_key"] != build.MECH_KEY_5WP8
    assert row46["repository"] == "qhkm/zeptoclaw"


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    return summary, counted


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical91 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert counted[-1]["case_id"] == CASE_5WP8
    assert CASE_2QRV not in [row["case_id"] for row in counted]
    assert CASE_R5JH not in [row["case_id"] for row in counted]


if __name__ == "__main__":
    main()
