#!/usr/bin/env python3
"""Distinct structural, Git, and semantic verifiers. Fail-fast. Clean stderr on success."""

from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
GATES = build.GATES
REMEDIATION_GATE = build.REMEDIATION_GATE
HAN = build.HAN
SHA_RE = build.SHA_RE
GHSA_RE = build.GHSA_RE
EXCLUDE_NARROW = build.EXCLUDE_NARROW
EXCLUDE_F38V = build.EXCLUDE_F38V
EXCLUDE_4FXP = build.EXCLUDE_4FXP
EXCLUDE_XW57 = build.EXCLUDE_XW57
EXCLUDE_QCR8 = build.EXCLUDE_QCR8
EXCLUDE_GOPACKET = build.EXCLUDE_GOPACKET
CASE_Q855 = build.CASE_Q855
B3_KEEP = build.B3_KEEP
PRIOR_STRICT = build.PRIOR_STRICT
STRICT_COUNT = build.STRICT_COUNT
FILEBROWSER_NEG = build.FILEBROWSER_NEG
FILEBROWSER_POS = build.FILEBROWSER_POS
ORD200 = build.ORD200
NEW_IDS = build.NEW_IDS
NOGGIN_IDS = build.NOGGIN_IDS
CASE_X4HG = build.CASE_X4HG
CASE_322X = build.CASE_322X
CASE_PMCH = build.CASE_PMCH
CAND_X4HG = build.CAND_X4HG
CAND_322X = build.CAND_322X
CAND_PMCH = build.CAND_PMCH
FIX_X4HG = build.FIX_X4HG
FIX_322X = build.FIX_322X
FIX_PMCH = build.FIX_PMCH
EXPECTED_CANDIDATES = build.EXPECTED_CANDIDATES
EXPECTED_FIXES = build.EXPECTED_FIXES
EXPECTED_MECHS = build.EXPECTED_MECHS
EXPECTED_CLASS = build.EXPECTED_CLASS
NPM_VULN_SHA = build.NPM_VULN_SHA
NPM_FIX_SHA = build.NPM_FIX_SHA
PYPI_VULN_SHA = build.PYPI_VULN_SHA
PYPI_FIX_SHA = build.PYPI_FIX_SHA


def load_rows() -> list[dict]:
    return build.load_jsonl(HERE / "ledger.jsonl")


def by_kind(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if row["record_kind"] == kind]


GIT_ENV = {
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}


def git_run(repo: str, *args: str) -> int:
    proc = subprocess.run(
        [
            "/usr/bin/git",
            "--no-optional-locks",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-C",
            repo,
            *args,
        ],
        env=GIT_ENV,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.stderr:
        raise AssertionError("git stderr was not empty")
    return proc.returncode


def verify_structural() -> dict:
    pins = build.pin_frozen()
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
    prior = build.load_json(build.ROOT / build.P_C78_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C78_LEDGER)

    hyp = by_kind(rows, "PRESERVED_HYPOTHESIS")
    pub = by_kind(rows, "PRESERVED_PUBLIC_CASE")
    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    appends = by_kind(rows, "APPEND_IDENTITY")
    auth = by_kind(rows, "PACKET_AUTHORITY")
    edges = by_kind(rows, "SUPERSEDES_EDGE")
    assert len(hyp) == 211
    assert len(pub) == 212
    assert len(counted) == STRICT_COUNT
    assert len(appends) == 12
    assert len(auth) == 15
    assert len(edges) == 43
    assert [row["ordinal"] for row in hyp] == list(range(1, 212))
    assert len({row["row_key"] for row in hyp}) == 211
    assert len({row["case_id"] for row in pub}) == 212
    assert all(GHSA_RE.fullmatch(row["case_id"]) for row in pub)
    assert all(row["counted"] is False for row in hyp + pub + appends + auth + edges)
    assert all(row["counted"] is True for row in counted)
    assert all(row["source_layer"] is True for row in hyp + pub)

    prior_counted = [row for row in prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert prior_counted == counted[:PRIOR_STRICT]
    assert [build.compact_json(row) for row in prior_counted] == [
        build.compact_json(row) for row in counted[:PRIOR_STRICT]
    ]
    prior_hyp = [row for row in prior_rows if row["record_kind"] == "PRESERVED_HYPOTHESIS"]
    prior_pub = [row for row in prior_rows if row["record_kind"] == "PRESERVED_PUBLIC_CASE"]
    assert prior_hyp == hyp
    assert prior_pub == pub
    assert [build.compact_json(row) for row in prior_hyp] == [build.compact_json(row) for row in hyp]
    assert [build.compact_json(row) for row in prior_pub] == [build.compact_json(row) for row in pub]

    new_counted = counted[PRIOR_STRICT:]
    assert [row["case_id"] for row in new_counted] == list(NEW_IDS)
    assert [row["ordinal"] for row in new_counted] == [79, 80, 81]
    new_appends = [row for row in appends if row["case_id"] in NEW_IDS]
    assert [row["case_id"] for row in new_appends] == list(NEW_IDS)
    source_ids = {row["case_id"] for row in pub}
    for row in new_appends:
        assert row["case_id"] not in source_ids
        assert row["row_key"].startswith("ghsa200-next:")
        assert row["ordinal"] in {79, 80, 81}
        assert all(row[field] == "PASS" for field in GATES)
        if row["case_id"] == CASE_PMCH:
            assert row[REMEDIATION_GATE] == "PASS"
        else:
            assert REMEDIATION_GATE not in row

    for row in counted:
        for field in GATES:
            assert row[field] == "PASS", (row["case_id"], field, row[field])
            assert row[field] is not None and row[field] != "NA"
        for field in ("candidate_set", "carrier_set", "minimum_fix_set"):
            assert row[field] == sorted(set(row[field]))
            assert all(SHA_RE.fullmatch(item) for item in row[field])
        assert "candidate_fix_edges" not in row
        assert row["edge_authority"] == "candidate_set/carrier_set/minimum_fix_set"
        assert GHSA_RE.fullmatch(row["case_id"])
        aliases = row["aliases"]
        assert row["case_id"] not in aliases
        assert not any(GHSA_RE.fullmatch(item) and item != row["case_id"] for item in aliases)
        assert row["mechanism_key"]
        assert row["mechanism_fingerprint"]
        assert row["counting_unit"] == "first-party GHSA case"

    for row in new_counted:
        assert row["contribution_class"] == EXPECTED_CLASS[row["case_id"]]
        assert row["cartesian_candidate_fix_refused"] is True
        assert row["candidate_set"] == EXPECTED_CANDIDATES[row["case_id"]]
        assert row["minimum_fix_set"] == EXPECTED_FIXES[row["case_id"]]
        assert row["mechanism_key"] == EXPECTED_MECHS[row["case_id"]]
        refs = row["first_party_source_refs"]
        assert refs[0] == "https://github.com/advisories/GHSA-" + row["case_id"].split("-", 1)[1].lower()
        assert any("pages/ghsa/" in item for item in refs)

    x4hg, row_322x, pmch = new_counted
    assert x4hg["case_id"] == CASE_X4HG
    assert row_322x["case_id"] == CASE_322X
    assert pmch["case_id"] == CASE_PMCH
    assert REMEDIATION_GATE not in x4hg
    assert REMEDIATION_GATE not in row_322x
    assert pmch[REMEDIATION_GATE] == "PASS"
    for row in (x4hg, row_322x):
        assert row["vulnerable_release"]["version"] == "0.0.21"
        assert row["vulnerable_release"]["tag"] == "v0.0.21"
        assert row["vulnerable_release"]["sha"] == NPM_VULN_SHA
        assert row["vulnerable_release"]["npm_gitHead"] == NPM_VULN_SHA
        assert row["vulnerable_release"]["tarball_sha256"] == build.NPM_VULN_TAR_SHA
        assert row["vulnerable_release"]["contains_candidate"] is True
        assert row["vulnerable_release"]["contains_fix"] is False
        assert row["fixed_release"]["version"] == "0.0.22"
        assert row["fixed_release"]["tag"] == "v0.0.22"
        assert row["fixed_release"]["sha"] == NPM_FIX_SHA
        assert row["fixed_release"]["npm_gitHead"] == NPM_FIX_SHA
        assert row["fixed_release"]["tarball_sha256"] == build.NPM_FIX_TAR_SHA
        assert row["fixed_release"]["contains_fix"] is True
        assert row["fixed_release"]["equals_minimum_fix"] is False
        assert row["vulnerable_release"]["github_release_object"] == "404"
    assert pmch["vulnerable_release"]["version"] == "0.63.0"
    assert pmch["vulnerable_release"]["wheel_sha256"] == build.PYPI_VULN_WHEEL
    assert pmch["vulnerable_release"]["sdist_sha256"] == build.PYPI_VULN_SDIST
    assert pmch["vulnerable_release"]["sql_chat_agent_blob"] == build.PYPI_VULN_BLOB
    assert pmch["vulnerable_release"]["contains_candidate"] is True
    assert pmch["vulnerable_release"]["contains_fix"] is False
    assert pmch["fixed_release"]["version"] == "0.64.0"
    assert pmch["fixed_release"]["wheel_sha256"] == build.PYPI_FIX_WHEEL
    assert pmch["fixed_release"]["sdist_sha256"] == build.PYPI_FIX_SDIST
    assert pmch["fixed_release"]["sql_chat_agent_blob"] == build.PYPI_FIX_BLOB
    assert pmch["fixed_release"]["contains_fix"] is True
    assert pmch["fixed_release"]["equals_minimum_fix"] is False

    assert summary["counts"]["strict_released_first_party_ghsa"] == STRICT_COUNT
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["checkpoint"]["prior_strict_count"] == PRIOR_STRICT
    assert summary["checkpoint"]["corrected_strict_count"] == STRICT_COUNT
    assert summary["counts"]["batch9_three_keep"] == 2
    assert summary["counts"]["langroid_one_keep"] == 1
    assert summary["counts"]["batch9_three_narrow_excluded"] == 1
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["status"] == "HOLD"
    assert summary["public_200_claim_supported"] is False
    assert summary["causal_admission"] is False
    assert summary["conservation"]["fp211_hypotheses"] == 211
    assert summary["conservation"]["fp211_source_ghsa_cases"] == 212
    assert summary["conservation"]["cve_aliases_counted"] is False
    assert summary["conservation"]["base_counted_rows_byte_identical"] is True
    assert manifest["strict_released_first_party_ghsa"] == STRICT_COUNT
    assert manifest["integration_ready"] is False
    assert manifest["publication_ready"] is False
    assert manifest["public_200_claim_supported"] is False
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert manifest["outputs"]["ledger.jsonl_sha256"] == summary["ledger_sha256"]
    assert manifest["hash_roles"]["frozen"]["canonical78_ledger"]["sha256"] == pins["canonical78_ledger"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["batch9_three_cases"]["sha256"] == pins["batch9_three_cases"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["langroid_one_cases"]["sha256"] == pins["langroid_one_cases"]["sha256"]
    assert Counter(row["admission_source"] for row in counted) == Counter(
        {
            "fp211_released_publication_admitted": 47,
            "netnew22_redteam_keep": 21,
            "actual_gogs_redteam_keep": 2,
            "b3_redteam_keep": 2,
            "q855_redteam_keep": 1,
            "specifyjs_five_redteam_keep": 5,
            "batch9_three_redteam_keep": 2,
            "langroid_one_redteam_keep": 1,
        }
    )
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == list(NEW_IDS)
    return summary


def verify_git() -> None:
    rows = load_rows()
    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    replay = [row for row in counted if row["case_id"] in NEW_IDS]
    assert [row["case_id"] for row in replay] == list(NEW_IDS)
    noggin = build.CLONES["asymmetric-effort/NogginLessDom"]
    langroid = build.CLONES["langroid/langroid"]
    assert Path(noggin).is_dir()
    assert Path(langroid).is_dir()
    for row in replay[:2]:
        assert row["repository"] == "asymmetric-effort/NogginLessDom"
        vuln = row["vulnerable_release"]["sha"]
        fixed = row["fixed_release"]["sha"]
        assert vuln == NPM_VULN_SHA
        assert fixed == NPM_FIX_SHA
        assert len(row["candidate_set"]) == 1
        assert len(row["minimum_fix_set"]) == 1
        for cand in row["candidate_set"]:
            assert git_run(noggin, "merge-base", "--is-ancestor", cand, vuln) == 0, (
                row["case_id"],
                cand,
                vuln,
            )
        for fix in row["minimum_fix_set"]:
            assert git_run(noggin, "merge-base", "--is-ancestor", fix, vuln) == 1, (
                row["case_id"],
                fix,
                vuln,
            )
            assert git_run(noggin, "merge-base", "--is-ancestor", fix, fixed) == 0, (
                row["case_id"],
                fix,
                fixed,
            )
    pmch = replay[2]
    assert pmch["repository"] == "langroid/langroid"
    assert pmch["candidate_set"] == [CAND_PMCH]
    assert pmch["minimum_fix_set"] == [FIX_PMCH]
    assert git_run(langroid, "merge-base", "--is-ancestor", CAND_PMCH, "0.63.0") == 0
    assert git_run(langroid, "merge-base", "--is-ancestor", FIX_PMCH, "0.63.0") == 1
    assert git_run(langroid, "merge-base", "--is-ancestor", FIX_PMCH, "0.64.0") == 0
    assert git_run(langroid, "merge-base", "--is-ancestor", CAND_PMCH, PYPI_VULN_SHA) == 0
    assert git_run(langroid, "merge-base", "--is-ancestor", FIX_PMCH, PYPI_VULN_SHA) == 1
    assert git_run(langroid, "merge-base", "--is-ancestor", FIX_PMCH, PYPI_FIX_SHA) == 0


def verify_semantic() -> None:
    rows = load_rows()
    hyp = by_kind(rows, "PRESERVED_HYPOTHESIS")
    pub = by_kind(rows, "PRESERVED_PUBLIC_CASE")
    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    by_key = {row["row_key"]: row for row in hyp}
    negative = by_key[FILEBROWSER_NEG]
    positive = by_key[FILEBROWSER_POS]
    assert negative["ordinal"] == 165
    assert positive["ordinal"] == 166
    assert negative["fp211_verdict"] == "FALSE_POSITIVE"
    assert positive["fp211_verdict"] == "CONFIRM"
    assert negative["fp211_candidate_set"] == positive["fp211_candidate_set"]
    assert negative["fp211_minimum_fix_set"] == positive["fp211_minimum_fix_set"]
    assert negative["row_key"] != positive["row_key"]

    dual = [row for row in pub if row["ordinal"] == 200]
    assert {row["case_id"] for row in dual} == set(ORD200)
    assert len(dual) == 2
    assert dual[0]["row_key"] == dual[1]["row_key"]
    assert not any(row["case_id"] in ORD200 for row in counted)

    counted_ids = [row["case_id"] for row in counted]
    assert EXCLUDE_NARROW not in counted_ids
    assert EXCLUDE_F38V not in counted_ids
    assert EXCLUDE_4FXP not in counted_ids
    assert EXCLUDE_XW57 not in counted_ids
    assert EXCLUDE_QCR8 not in counted_ids
    assert EXCLUDE_GOPACKET not in counted_ids
    assert CASE_Q855 in counted_ids
    assert counted_ids.count(CASE_Q855) == 1
    assert set(B3_KEEP) <= set(counted_ids)
    for case_id in NEW_IDS:
        assert counted_ids.count(case_id) == 1
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT

    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    cve_aliases = [item for row in counted for item in row["aliases"] if item.startswith("CVE-")]
    assert not any(item in counted_ids for item in cve_aliases)

    noggin_rows = [row for row in counted if row["case_id"] in NOGGIN_IDS]
    assert [row["case_id"] for row in noggin_rows] == list(NOGGIN_IDS)
    assert noggin_rows[0]["candidate_set"] == [CAND_X4HG]
    assert noggin_rows[0]["minimum_fix_set"] == [FIX_X4HG]
    assert noggin_rows[1]["candidate_set"] == [CAND_322X]
    assert noggin_rows[1]["minimum_fix_set"] == [FIX_322X]
    assert CAND_322X not in noggin_rows[0]["candidate_set"]
    assert FIX_322X not in noggin_rows[0]["minimum_fix_set"]
    assert CAND_X4HG not in noggin_rows[1]["candidate_set"]
    assert FIX_X4HG not in noggin_rows[1]["minimum_fix_set"]
    assert not any("candidate_fix_edges" in row for row in counted)
    patch_delta_new = [row for row in counted[PRIOR_STRICT:] if REMEDIATION_GATE in row]
    assert [row["case_id"] for row in patch_delta_new] == [CASE_PMCH]

    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "worker-only PASS" in report
    assert "canonical strict count 81" in report
    assert "0.0.21" in report
    assert "0.0.22" in report
    assert "0.63.0" in report
    assert "0.64.0" in report
    assert CASE_Q855 in report
    assert EXCLUDE_F38V in report
    assert EXCLUDE_4FXP in report
    assert EXCLUDE_GOPACKET in report
    assert "gopacket" in report
    for case_id in NEW_IDS:
        assert case_id in report

    assert build.P_B9_PKT in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    assert build.P_LR_PKT in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    assert build.P_C78_PKT in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    new_edges = [row for row in by_kind(rows, "SUPERSEDES_EDGE") if row["case_id"] in NEW_IDS]
    assert [row["case_id"] for row in new_edges] == list(NEW_IDS)
    for edge in new_edges[:2]:
        assert edge["to_packet"] == build.P_B9_PKT
        assert edge["to_verdict"] == "KEEP"
        assert edge["from_packet"] == build.P_BATCH9
        assert edge["from_verdict"] == "PASS"
        assert edge["applies_to_counted_set"] is True
    assert new_edges[2]["to_packet"] == build.P_LR_PKT
    assert new_edges[2]["from_packet"] == build.P_BATCH11
    assert not any(row["case_id"] == EXCLUDE_GOPACKET for row in by_kind(rows, "SUPERSEDES_EDGE") if row.get("to_verdict") == "KEEP")
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    assert all(row["admission_source"] == "batch9_three_redteam_keep" for row in counted if row["case_id"] in NOGGIN_IDS)
    assert all(row["admission_source"] == "langroid_one_redteam_keep" for row in counted if row["case_id"] == CASE_PMCH)


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    return summary, by_kind(load_rows(), "STRICT_RELEASED_CASE")


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical81 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["public_200_claim_supported"] is False


if __name__ == "__main__":
    main()
