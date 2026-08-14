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
CASE_Q855 = build.CASE_Q855
B3_KEEP = build.B3_KEEP
PRIOR_STRICT = build.PRIOR_STRICT
STRICT_COUNT = build.STRICT_COUNT
FILEBROWSER_NEG = build.FILEBROWSER_NEG
FILEBROWSER_POS = build.FILEBROWSER_POS
ORD200 = build.ORD200
NEW_IDS = build.NEW_IDS
CAND_HTTPS = build.CAND_HTTPS
CAND_SAST = build.CAND_SAST
FIX_PT = build.FIX_PT
VULN_SHA = build.VULN_SHA
HTTPS_IDS = build.HTTPS_IDS
SAST_IDS = build.SAST_IDS
EXPECTED_CANDIDATES = build.EXPECTED_CANDIDATES
EXPECTED_MECHS = build.EXPECTED_MECHS


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
    prior = build.load_json(build.ROOT / build.P_C73_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C73_LEDGER)

    hyp = by_kind(rows, "PRESERVED_HYPOTHESIS")
    pub = by_kind(rows, "PRESERVED_PUBLIC_CASE")
    counted = by_kind(rows, "STRICT_RELEASED_CASE")
    appends = by_kind(rows, "APPEND_IDENTITY")
    auth = by_kind(rows, "PACKET_AUTHORITY")
    edges = by_kind(rows, "SUPERSEDES_EDGE")
    assert len(hyp) == 211
    assert len(pub) == 212
    assert len(counted) == STRICT_COUNT
    assert len(appends) == 9
    assert len(auth) == 12
    assert len(edges) == 40
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

    new_counted = counted[PRIOR_STRICT:]
    assert [row["case_id"] for row in new_counted] == list(NEW_IDS)
    assert [row["ordinal"] for row in new_counted] == [74, 75, 76, 77, 78]
    new_appends = [row for row in appends if row["case_id"] in NEW_IDS]
    assert [row["case_id"] for row in new_appends] == list(NEW_IDS)
    source_ids = {row["case_id"] for row in pub}
    for row in new_appends:
        assert row["case_id"] not in source_ids
        assert row["row_key"].startswith("ghsa200-next:")
        assert row["ordinal"] in {74, 75, 76, 77, 78}
        assert all(row[field] == "PASS" for field in GATES)
        assert row[REMEDIATION_GATE] == "PASS"

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
        assert row["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
        assert row[REMEDIATION_GATE] == "PASS"
        assert row["cartesian_candidate_fix_refused"] is True
        assert row["candidate_set"] == EXPECTED_CANDIDATES[row["case_id"]]
        assert row["minimum_fix_set"] == [FIX_PT]
        assert row["mechanism_key"] == EXPECTED_MECHS[row["case_id"]]
        assert row["vulnerable_release"]["version"] == "0.2.135"
        assert row["vulnerable_release"]["tag"] == "v0.2.135"
        assert row["vulnerable_release"]["sha"] == VULN_SHA
        assert row["vulnerable_release"]["npm_gitHead"] == VULN_SHA
        assert row["vulnerable_release"]["contains_candidate"] is True
        assert row["vulnerable_release"]["contains_fix"] is False
        assert row["fixed_release"]["version"] == "0.2.136"
        assert row["fixed_release"]["tag"] == "v0.2.136"
        assert row["fixed_release"]["sha"] == FIX_PT
        assert row["fixed_release"]["npm_gitHead"] == FIX_PT
        assert row["fixed_release"]["equals_minimum_fix"] is True
        refs = row["first_party_source_refs"]
        assert refs[0] == "https://github.com/advisories/GHSA-" + row["case_id"].split("-", 1)[1].lower()
        assert any("pages/ghsa/" in item for item in refs)

    assert summary["counts"]["strict_released_first_party_ghsa"] == STRICT_COUNT
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["checkpoint"]["prior_strict_count"] == PRIOR_STRICT
    assert summary["checkpoint"]["corrected_strict_count"] == STRICT_COUNT
    assert summary["counts"]["specifyjs_five_keep"] == 5
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
    assert manifest["hash_roles"]["frozen"]["canonical73_ledger"]["sha256"] == pins["canonical73_ledger"]["sha256"]
    assert manifest["hash_roles"]["frozen"]["specifyjs_five_cases"]["sha256"] == pins["specifyjs_five_cases"]["sha256"]
    assert Counter(row["admission_source"] for row in counted) == Counter(
        {
            "fp211_released_publication_admitted": 47,
            "netnew22_redteam_keep": 21,
            "actual_gogs_redteam_keep": 2,
            "b3_redteam_keep": 2,
            "q855_redteam_keep": 1,
            "specifyjs_five_redteam_keep": 5,
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
    repo = build.CLONES["asymmetric-effort/specifyjs"]
    assert Path(repo).is_dir()
    for row in replay:
        assert row["repository"] == "asymmetric-effort/specifyjs"
        vuln = row["vulnerable_release"]["sha"]
        fixed = row["fixed_release"]["sha"]
        assert vuln == VULN_SHA
        assert fixed == FIX_PT
        assert row["vulnerable_release"]["version"] == "0.2.135"
        assert row["fixed_release"]["version"] == "0.2.136"
        assert len(row["candidate_set"]) == 1
        assert len(row["minimum_fix_set"]) == 1
        for cand in row["candidate_set"]:
            assert git_run(repo, "merge-base", "--is-ancestor", cand, vuln) == 0, (
                row["case_id"],
                cand,
                vuln,
            )
        for fix in row["minimum_fix_set"]:
            assert git_run(repo, "merge-base", "--is-ancestor", fix, vuln) == 1, (
                row["case_id"],
                fix,
                vuln,
            )
            assert git_run(repo, "merge-base", "--is-ancestor", fix, fixed) == 0, (
                row["case_id"],
                fix,
                fixed,
            )


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
    assert CASE_Q855 in counted_ids
    assert counted_ids.count(CASE_Q855) == 1
    assert set(B3_KEEP) <= set(counted_ids)
    assert counted_ids.count(CASE_Q855) == 1
    for case_id in NEW_IDS:
        assert counted_ids.count(case_id) == 1
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT

    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    cve_aliases = [item for row in counted for item in row["aliases"] if item.startswith("CVE-")]
    assert not any(item in counted_ids for item in cve_aliases)

    https_rows = [row for row in counted if row["case_id"] in HTTPS_IDS]
    sast_rows = [row for row in counted if row["case_id"] in SAST_IDS]
    assert [row["case_id"] for row in https_rows] == list(HTTPS_IDS)
    assert [row["case_id"] for row in sast_rows] == list(SAST_IDS)
    assert all(row["candidate_set"] == [CAND_HTTPS] for row in https_rows)
    assert all(row["candidate_set"] == [CAND_SAST] for row in sast_rows)
    assert all(row["minimum_fix_set"] == [FIX_PT] for row in https_rows + sast_rows)
    assert not any(CAND_SAST in row["candidate_set"] for row in https_rows)
    assert not any(CAND_HTTPS in row["candidate_set"] for row in sast_rows)
    assert not any("candidate_fix_edges" in row for row in counted)

    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "worker-only PASS" in report
    assert "canonical strict count 78" in report
    assert "0.2.135" in report
    assert "0.2.136" in report
    assert CASE_Q855 in report
    assert EXCLUDE_F38V in report
    assert EXCLUDE_4FXP in report
    assert EXCLUDE_XW57 in report
    for case_id in NEW_IDS:
        assert case_id in report

    sj = build.P_SJ_PKT
    assert sj in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    assert build.P_C73_PKT in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    sj_edges = [row for row in by_kind(rows, "SUPERSEDES_EDGE") if row["case_id"] in NEW_IDS]
    assert [row["case_id"] for row in sj_edges] == list(NEW_IDS)
    for edge in sj_edges:
        assert edge["to_packet"] == sj
        assert edge["to_verdict"] == "KEEP"
        assert edge["from_packet"] == build.P_BATCH4
        assert edge["from_verdict"] == "PASS"
        assert edge["applies_to_counted_set"] is True
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    assert all(row["admission_source"] == "specifyjs_five_redteam_keep" for row in counted if row["case_id"] in NEW_IDS)


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    return summary, by_kind(load_rows(), "STRICT_RELEASED_CASE")


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical78 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["public_200_claim_supported"] is False


if __name__ == "__main__":
    main()
