#!/usr/bin/env python3
"""Distinct structural, Git, and semantic verifiers. Fail-fast. Clean stderr on success."""

from __future__ import annotations

from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
GATES = build.GATES
REMEDIATION_GATE = build.REMEDIATION_GATE
HAN = build.HAN
SHA_RE = build.SHA_RE
GHSA_RE = build.GHSA_RE
PRIOR_STRICT = build.PRIOR_STRICT
STRICT_COUNT = build.STRICT_COUNT
CASE_8359 = build.CASE_8359
CASE_425G = build.CASE_425G
CASE_HC8V = build.CASE_HC8V
CASE_QF5V = build.CASE_QF5V
CASE_PIMCORE = build.CASE_PIMCORE
CASE_HHJV = build.CASE_HHJV
CASE_73HC = build.CASE_73HC
CASE_282G = build.CASE_282G
CASE_45Q4 = build.CASE_45Q4
CASE_954P = build.CASE_954P
ALIAS_8359 = build.ALIAS_8359
ALIAS_HC8V = build.ALIAS_HC8V
CAND_8359 = build.CAND_8359
FIX_8359 = build.FIX_8359
FIX_954P = build.FIX_954P
LINEAGE_425G = build.LINEAGE_425G
FILEBROWSER_NEG = build.FILEBROWSER_NEG
FILEBROWSER_POS = build.FILEBROWSER_POS
ORD200 = build.ORD200
EXCLUDE_NARROW = build.EXCLUDE_NARROW
EXCLUDE_F38V = build.EXCLUDE_F38V
EXCLUDE_4FXP = build.EXCLUDE_4FXP
EXCLUDE_XW57 = build.EXCLUDE_XW57
EXCLUDE_QCR8 = build.EXCLUDE_QCR8
EXCLUDE_GOPACKET = build.EXCLUDE_GOPACKET
CASE_Q855 = build.CASE_Q855
CASE_M63V = build.CASE_M63V
B3_KEEP = build.B3_KEEP


def load_rows() -> list[dict]:
    return build.load_jsonl(HERE / "ledger.jsonl")


def by_kind(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if row["record_kind"] == kind]


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
    cap_8359 = build.load_capsule_8359()
    neg = build.load_negative()
    prior = build.load_json(build.ROOT / build.P_C84_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C84_LEDGER)
    prior_text = (build.ROOT / build.P_C84_LEDGER).read_text()
    assert text.startswith(prior_text if prior_text.endswith("\n") else prior_text + "\n")
    assert len(prior_rows) == build.BASE_LEDGER_RECORDS
    assert len(rows) == build.LEDGER_RECORDS
    assert [build.compact_json(row) for row in prior_rows] == [
        build.compact_json(row) for row in rows[: build.BASE_LEDGER_RECORDS]
    ]
    assert [line for line in prior_text.splitlines() if line.strip()] == text.splitlines()[
        : build.BASE_LEDGER_RECORDS
    ]

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
    assert len(auth) == 18
    assert len(edges) == 44
    assert all(row["counted"] is False for row in hyp + pub + appends + auth + edges)
    assert all(row["counted"] is True for row in counted)

    prior_counted = [row for row in prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert prior_counted == counted[:PRIOR_STRICT]
    assert [build.compact_json(row) for row in prior_counted] == [
        build.compact_json(row) for row in counted[:PRIOR_STRICT]
    ]
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_8359]
    assert counted[84]["ordinal"] == 85
    row85 = counted[84]
    assert row85["case_id"] == CASE_8359
    assert row85["candidate_set"] == [CAND_8359]
    assert row85["carrier_set"] == [CAND_8359]
    assert row85["minimum_fix_set"] == [FIX_8359]
    assert FIX_954P not in row85["candidate_set"]
    assert FIX_954P not in row85["minimum_fix_set"]
    assert row85["aliases"] == [ALIAS_8359]
    assert row85["n_parents"] == 1
    assert row85["candidate_on_release_first_parent"] is True
    assert row85["carrier_on_release_first_parent"] is True
    assert row85["authorship_transfer"] is False
    assert row85["leader_strict_case_accepted"] is True
    assert row85["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert row85[REMEDIATION_GATE] == "PASS"
    assert "causal_admission" not in row85
    assert row85["in_fp211_212"] is False
    assert row85["action"] == "APPEND"

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

    assert summary["causal_admission"] is False
    assert summary["publication_ready"] is False
    assert summary["publication_admission"] is False
    assert summary["integration_ready"] is False
    assert summary["status"] == "HOLD"
    assert summary["public_200_claim_supported"] is False
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["counts"]["strict_released_first_party_ghsa"] == STRICT_COUNT
    assert summary["counts"]["ledger_records"] == build.LEDGER_RECORDS
    assert summary["counts"]["keep_8359"] == 1
    assert summary["conservation"]["fp211_hypotheses"] == 211
    assert summary["conservation"]["fp211_source_ghsa_cases"] == 212
    assert summary["conservation"]["cve_aliases_counted"] is False
    assert summary["conservation"]["base_counted_rows_byte_identical"] is True
    assert summary["conservation"]["base_ledger_rows_byte_identical"] is True
    prior_append = list(prior["conservation"]["append_identities"])
    assert summary["conservation"]["prior_append_identities"] == prior_append
    assert len(summary["conservation"]["prior_append_identities"]) == 14
    assert summary["conservation"]["new_append_identities"] == [CASE_8359]
    assert summary["conservation"]["append_identities"] == prior_append + [CASE_8359]
    assert len(summary["conservation"]["append_identities"]) == 15
    assert summary["conservation"]["new_identities_append"] is True
    assert summary["conservation"]["same_id_source_layer_promoted"] is False
    assert summary["conservation"]["upgrades_append"] is False
    assert summary["conservation"]["appended_strict_rows"] == 1
    assert manifest["conservation"] == summary["conservation"]
    auth = manifest["packet_authority"]
    assert auth[-1]["packet"] == build.P_PKT
    assert auth[-1]["authority_rank"] == 42
    assert auth[-1]["role"] == "redteam"
    assert len(auth) == 21
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_8359]
    assert CASE_8359 not in prior["strict_released_case_ids"]
    assert manifest["causal_admission"] is False
    assert manifest["publication_ready"] is False
    assert manifest["integration_ready"] is False
    assert manifest["public_200_claim_supported"] is False
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert manifest["outputs"]["ledger.jsonl_sha256"] == summary["ledger_sha256"]
    assert pins["canonical84_ledger"]["sha256"] == "a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06"
    assert {row["case_id"] for row in neg["controls"]} == {
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    }
    assert cap_8359["leader_strict_case_accepted"] is True
    assert counted[82]["case_id"] == CASE_425G
    assert counted[83]["case_id"] == CASE_HC8V
    return summary


def verify_git() -> None:
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    row85 = counted[84]
    cap_8359 = build.load_capsule_8359()
    assert row85["candidate_set"][0] == cap_8359["object_shas"]["counted_candidate"] == CAND_8359
    assert row85["minimum_fix_set"][0] == cap_8359["object_shas"]["minimum_fix"] == FIX_8359
    assert row85["carrier_set"][0] == cap_8359["object_shas"]["carrier"] == CAND_8359
    assert cap_8359["object_shas"]["sibling_954p_closer_not_counted"] == FIX_954P
    assert cap_8359["n_parents"] == 1
    assert cap_8359["candidate_on_release_first_parent"] is True
    assert cap_8359["carrier_on_release_first_parent"] is True
    assert cap_8359["authorship_transfer"] is False
    assert row85["vulnerable_release"]["peeled"] == build.PEEL_061
    assert row85["vulnerable_release"]["first_containing_candidate_peeled"] == build.PEEL_056
    assert row85["vulnerable_release"]["pre_attempt_peeled"] == build.PEEL_055
    assert row85["fixed_release"]["peeled"] == build.PEEL_062
    assert row85["vulnerable_release"]["contains_candidate"] is True
    assert row85["vulnerable_release"]["contains_fix"] is False
    assert row85["vulnerable_release"]["file_exemption_present"] is True
    assert row85["fixed_release"]["contains_fix"] is True
    assert row85["fixed_release"]["file_exemption_present"] is False
    assert row85["fixed_release"]["resolve_local_ref_path_present"] is True
    assert FIX_954P == row85["sibling_954p_closer_not_counted"]
    assert FIX_954P not in row85["minimum_fix_set"]


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
    dual = [row for row in pub if row["ordinal"] == 200]
    assert {row["case_id"] for row in dual} == set(ORD200)

    counted_ids = [row["case_id"] for row in counted]
    for banned in (
        EXCLUDE_NARROW,
        EXCLUDE_F38V,
        EXCLUDE_4FXP,
        EXCLUDE_XW57,
        EXCLUDE_QCR8,
        EXCLUDE_GOPACKET,
        CASE_M63V,
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
        ALIAS_HC8V,
        ALIAS_8359,
        LINEAGE_425G,
    ):
        assert banned not in counted_ids
    assert CASE_Q855 in counted_ids
    assert CASE_QF5V in counted_ids
    assert counted_ids.count(CASE_8359) == 1
    assert counted_ids[-1] == CASE_8359
    assert set(B3_KEEP) <= set(counted_ids)
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT

    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    cve_aliases = [item for row in counted for item in row["aliases"] if item.startswith("CVE-")]
    assert not any(item in counted_ids for item in cve_aliases)
    assert ALIAS_8359 in cve_aliases
    assert ALIAS_8359 not in counted_ids

    neg = build.load_negative()
    for ctrl in neg["controls"]:
        assert ctrl["case_id"] not in counted_ids
        assert ctrl["verdict"] == "REJECT"
        assert ctrl["countable"] is False
        assert ctrl["must_be_absent_from_all_counted_ids"] is True

    summary = build.load_json(HERE / "summary.json")
    assert summary["causal_admission"] is False
    assert CASE_8359 in summary["strict_released_case_ids"]
    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "canonical strict count 85" in report
    assert "new_identities_append is true" in report
    assert "prior packet authorities do not admit them" in report
    assert "only prior" not in report.lower()
    assert CASE_8359 in report
    assert CASE_282G in report and CASE_45Q4 in report and CASE_954P in report
    assert "0.55.0" in report and "0.56.0" in report and "0.61.0" in report and "0.62.0" in report
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    assert counted[84]["admission_source"] == "w3_p123_narrow_redteam_keep"
    for name in (
        "ledger.jsonl",
        "summary.json",
        "manifest.json",
        "report.md",
        "8359_acceptance.json",
        "negative_controls.json",
    ):
        blob = (HERE / name).read_text()
        assert "/home/hanqing/.cache" not in blob
        build.assert_no_leak(blob)
        assert not blob.endswith(" ")
        for line in blob.splitlines():
            assert line == line.rstrip(), name
    for name in ("summary.json", "manifest.json", "report.md"):
        assert "pages/ghsa/" not in (HERE / name).read_text()
    for row in counted[PRIOR_STRICT:]:
        assert "clone_path" not in row
        assert "clone" not in row
        assert not any("pages/ghsa/" in item for item in row["first_party_source_refs"])


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    return summary, counted


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical85 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert counted[-1]["case_id"] == CASE_8359


if __name__ == "__main__":
    main()
