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
CASE_425G = build.CASE_425G
CASE_HC8V = build.CASE_HC8V
CASE_QF5V = build.CASE_QF5V
CASE_PIMCORE = build.CASE_PIMCORE
CASE_HHJV = build.CASE_HHJV
CASE_73HC = build.CASE_73HC
ALIAS_HC8V = build.ALIAS_HC8V
CAND_425G = build.CAND_425G
CARRIER_425G = build.CARRIER_425G
LINEAGE_425G = build.LINEAGE_425G
FIX_425G = build.FIX_425G
CAND_HC8V = build.CAND_HC8V
CARRIER_HC8V = build.CARRIER_HC8V
FIX_HC8V = build.FIX_HC8V
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
    cap_425g = build.load_capsule_425g()
    cap_hc8v = build.load_capsule_hc8v()
    neg = build.load_negative()
    prior = build.load_json(build.ROOT / build.P_C82_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C82_LEDGER)
    prior_text = (build.ROOT / build.P_C82_LEDGER).read_text()
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
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_425G, CASE_HC8V]
    assert counted[82]["ordinal"] == 83
    assert counted[83]["ordinal"] == 84
    row83 = counted[82]
    row84 = counted[83]
    assert row83["case_id"] == CASE_425G
    assert row84["case_id"] == CASE_HC8V
    assert row83["candidate_set"] == [CAND_425G]
    assert row83["carrier_set"] == [CARRIER_425G]
    assert row83["minimum_fix_set"] == [FIX_425G]
    assert LINEAGE_425G not in row83["candidate_set"]
    assert LINEAGE_425G not in row83["carrier_set"]
    assert row83["aliases"] == []
    assert row84["candidate_set"] == [CAND_HC8V]
    assert row84["carrier_set"] == [CARRIER_HC8V]
    assert row84["minimum_fix_set"] == [FIX_HC8V]
    assert row84["aliases"] == [ALIAS_HC8V]
    assert row84["candidate_any_parent"] is True
    assert row84["candidate_on_release_first_parent"] is False
    assert row84["carrier_on_release_first_parent"] is True
    assert row84["authorship_transfer"] is False
    for row in (row83, row84):
        assert row["leader_strict_case_accepted"] is True
        assert row["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
        assert row[REMEDIATION_GATE] == "PASS"
        assert "causal_admission" not in row
        assert row["in_fp211_212"] is False
        assert row["action"] == "APPEND"

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
    assert summary["counts"]["keep_425g"] == 1
    assert summary["counts"]["keep_hc8v"] == 1
    assert summary["conservation"]["fp211_hypotheses"] == 211
    assert summary["conservation"]["fp211_source_ghsa_cases"] == 212
    assert summary["conservation"]["cve_aliases_counted"] is False
    assert summary["conservation"]["base_counted_rows_byte_identical"] is True
    assert summary["conservation"]["base_ledger_rows_byte_identical"] is True
    prior_append = list(prior["conservation"]["append_identities"])
    assert summary["conservation"]["prior_append_identities"] == prior_append
    assert len(summary["conservation"]["prior_append_identities"]) == 12
    assert summary["conservation"]["new_append_identities"] == [CASE_425G, CASE_HC8V]
    assert summary["conservation"]["append_identities"] == prior_append + [CASE_425G, CASE_HC8V]
    assert len(summary["conservation"]["append_identities"]) == 14
    assert summary["conservation"]["new_identities_append"] is True
    assert summary["conservation"]["same_id_source_layer_promoted"] is False
    assert summary["conservation"]["upgrades_append"] is False
    assert summary["conservation"]["appended_strict_rows"] == 2
    assert manifest["conservation"] == summary["conservation"]
    auth = manifest["packet_authority"]
    assert auth[-2]["packet"] == build.P_425G_PKT
    assert auth[-1]["packet"] == build.P_HC8V_PKT
    assert auth[-2]["authority_rank"] == 40
    assert auth[-1]["authority_rank"] == 41
    assert auth[-2]["role"] == "redteam"
    assert auth[-1]["role"] == "redteam"
    assert len(auth) == 20
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_425G, CASE_HC8V]
    assert CASE_425G not in prior["strict_released_case_ids"]
    assert CASE_HC8V not in prior["strict_released_case_ids"]
    assert manifest["causal_admission"] is False
    assert manifest["publication_ready"] is False
    assert manifest["integration_ready"] is False
    assert manifest["public_200_claim_supported"] is False
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert manifest["outputs"]["ledger.jsonl_sha256"] == summary["ledger_sha256"]
    assert pins["canonical82_ledger"]["sha256"] == "58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23"
    assert {row["case_id"] for row in neg["controls"]} == {CASE_PIMCORE, CASE_HHJV, CASE_73HC}
    assert cap_425g["leader_strict_case_accepted"] is True
    assert cap_hc8v["leader_strict_case_accepted"] is True
    return summary


def verify_git() -> None:
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    row83 = counted[82]
    row84 = counted[83]
    cap_425g = build.load_capsule_425g()
    cap_hc8v = build.load_capsule_hc8v()
    assert row83["candidate_set"][0] == cap_425g["object_shas"]["counted_candidate"] == CAND_425G
    assert row83["minimum_fix_set"][0] == cap_425g["object_shas"]["minimum_fix"] == FIX_425G
    assert row83["carrier_set"][0] == cap_425g["object_shas"]["carrier"] == CARRIER_425G
    assert cap_425g["object_shas"]["lineage_duplicate_not_counted"] == LINEAGE_425G
    assert row84["candidate_set"][0] == cap_hc8v["object_shas"]["counted_candidate"] == CAND_HC8V
    assert row84["minimum_fix_set"][0] == cap_hc8v["object_shas"]["minimum_fix"] == FIX_HC8V
    assert row84["carrier_set"][0] == cap_hc8v["object_shas"]["carrier"] == CARRIER_HC8V
    assert cap_hc8v["candidate_any_parent"] is True
    assert cap_hc8v["candidate_on_release_first_parent"] is False
    assert cap_hc8v["carrier_on_release_first_parent"] is True
    assert cap_hc8v["authorship_transfer"] is False
    assert row84["vulnerable_release"]["peeled"] == build.VULN_HC8V
    assert row84["fixed_release"]["peeled"] == build.FIX_PEEL_HC8V
    assert row84["vulnerable_release"]["tarball_sha256"] == build.TARBALL_V5191
    assert row84["fixed_release"]["tarball_sha256"] == build.TARBALL_V5192
    assert row83["vulnerable_release"]["sha256_sdist"] == build.PYPI_VULN_SDIST
    assert row83["fixed_release"]["sha256_sdist"] == build.PYPI_FIX_SDIST


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
        ALIAS_HC8V,
        LINEAGE_425G,
    ):
        assert banned not in counted_ids
    assert CASE_Q855 in counted_ids
    assert CASE_QF5V in counted_ids
    assert counted_ids.count(CASE_425G) == 1
    assert counted_ids.count(CASE_HC8V) == 1
    assert counted_ids[-2:] == [CASE_425G, CASE_HC8V]
    assert set(B3_KEEP) <= set(counted_ids)
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT

    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    cve_aliases = [item for row in counted for item in row["aliases"] if item.startswith("CVE-")]
    assert not any(item in counted_ids for item in cve_aliases)
    assert ALIAS_HC8V in cve_aliases
    assert ALIAS_HC8V not in counted_ids

    neg = build.load_negative()
    for ctrl in neg["controls"]:
        assert ctrl["case_id"] not in counted_ids
        assert ctrl["verdict"] == "REJECT"
        assert ctrl["countable"] is False
        assert ctrl["must_be_absent_from_all_counted_ids"] is True

    summary = build.load_json(HERE / "summary.json")
    assert summary["causal_admission"] is False
    assert CASE_425G in summary["strict_released_case_ids"]
    assert CASE_HC8V in summary["strict_released_case_ids"]
    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "canonical strict count 84" in report
    assert "new_identities_append is true" in report
    assert "prior packet authorities do not admit them" in report
    assert "only prior" not in report.lower()
    assert CASE_425G in report and CASE_HC8V in report
    assert CASE_HHJV in report and CASE_73HC in report
    assert "1.3.5" in report and "1.4.0" in report
    assert "v5.19.1" in report and "v5.19.2" in report
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    assert counted[82]["admission_source"] == "425g_redteam_keep"
    assert counted[83]["admission_source"] == "hc8v_redteam_keep"
    for name in (
        "ledger.jsonl",
        "summary.json",
        "manifest.json",
        "report.md",
        "425g_acceptance.json",
        "hc8v_acceptance.json",
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
        "PASS: canonical84 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert [row["case_id"] for row in counted[-2:]] == [CASE_425G, CASE_HC8V]


if __name__ == "__main__":
    main()
