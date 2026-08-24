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
CASE_QF5V = build.CASE_QF5V
CASE_M63V = build.CASE_M63V
CASE_PIMCORE = build.CASE_PIMCORE
ALIAS_QF5V = build.ALIAS_QF5V
CAND_QF5V = build.CAND_QF5V
PARENT_QF5V = build.PARENT_QF5V
MEMBER_QF5V = build.MEMBER_QF5V
FIX_QF5V = build.FIX_QF5V
MECH_KEY = build.MECH_KEY
MECH_FP = build.MECH_FP
MAP_SHA = build.MAP_SHA
VULN_PEEL = build.VULN_PEEL
FIX_PEEL = build.FIX_PEEL
BLOB_V124 = build.BLOB_V124
BLOB_FIX = build.BLOB_FIX
HUMAN_PIMCORE = build.HUMAN_PIMCORE
SQUASH_PIMCORE = build.SQUASH_PIMCORE


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
    cap = build.load_capsule()
    neg = build.load_negative()
    prior = build.load_json(build.ROOT / build.P_C81_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C81_LEDGER)

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

    qf5v = counted[PRIOR_STRICT]
    assert qf5v["case_id"] == CASE_QF5V
    assert qf5v["ordinal"] == 82
    assert [row["case_id"] for row in counted].count(CASE_QF5V) == 1
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_QF5V]
    assert qf5v["leader_strict_case_accepted"] is True
    assert qf5v["counted"] is True
    assert "causal_admission" not in qf5v
    assert qf5v.get("causal_admission") is not True
    assert qf5v["candidate_set"] == [CAND_QF5V]
    assert qf5v["minimum_fix_set"] == [FIX_QF5V]
    assert qf5v["carrier_set"] == []
    assert qf5v["candidate_parent"] == PARENT_QF5V
    assert qf5v["hypothesized_unreleased_member"] == MEMBER_QF5V
    assert MEMBER_QF5V not in qf5v["candidate_set"]
    assert MEMBER_QF5V not in qf5v["carrier_set"]
    assert qf5v["member_binding_rejected"] is True
    assert qf5v["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert qf5v["mechanism_key"] == MECH_KEY
    assert qf5v["mechanism_fingerprint"] == MECH_FP
    assert qf5v["aliases"] == [ALIAS_QF5V]
    assert qf5v[REMEDIATION_GATE] == "PASS"
    assert qf5v["cartesian_candidate_fix_refused"] is True
    assert "candidate_fix_edges" not in qf5v

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

    vuln = qf5v["vulnerable_release"]
    fixed = qf5v["fixed_release"]
    assert vuln["sha"] == VULN_PEEL
    assert vuln["peeled"] == VULN_PEEL
    assert vuln["go_proxy_origin_hash"] == VULN_PEEL
    assert vuln["contains_candidate"] is True
    assert vuln["contains_fix"] is False
    assert vuln["contains_member"] is False
    assert vuln["github_release_prerelease"] is True
    assert vuln["github_prerelease_flag_is_not_sole_release_proof"] is True
    assert vuln["podspec_safety_blob"] == BLOB_V124
    assert vuln["six_cap_map_sha256"] == MAP_SHA
    assert vuln["kind"] == "git_tag_and_go_module"
    assert fixed["sha"] == FIX_PEEL
    assert fixed["peeled"] == FIX_PEEL
    assert fixed["contains_fix"] is True
    assert fixed["equals_minimum_fix"] is False
    assert fixed["equals_fix_blob"] is True
    assert fixed["fix_parent_podspec_blob_equals_v1_24_0"] is True
    assert fixed["podspec_safety_blob"] == BLOB_FIX
    refs = qf5v["first_party_source_refs"]
    assert refs[0] == "https://github.com/advisories/GHSA-qf5v-m7p4-95rp"
    assert build.P_CAPSULE in refs
    assert not any("pages/ghsa/" in item for item in refs)

    assert cap["leader_strict_case_accepted"] is True
    assert cap["countable_in_this_snapshot"] is True
    assert cap["causal_admission"] is False
    assert cap["publication_admission"] is False
    assert cap["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["publication_ready"] is False
    assert summary["publication_admission"] is False
    assert summary["integration_ready"] is False
    assert summary["status"] == "HOLD"
    assert summary["public_200_claim_supported"] is False
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["counts"]["strict_released_first_party_ghsa"] == STRICT_COUNT
    assert summary["counts"]["qf5v_keep"] == 1
    assert summary["conservation"]["fp211_hypotheses"] == 211
    assert summary["conservation"]["fp211_source_ghsa_cases"] == 212
    assert summary["conservation"]["cve_aliases_counted"] is False
    assert summary["conservation"]["base_counted_rows_byte_identical"] is True
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_QF5V]
    assert CASE_QF5V not in prior["strict_released_case_ids"]
    assert prior["causal_admission"] is False
    assert manifest["causal_admission"] is False
    assert manifest["publication_ready"] is False
    assert manifest["integration_ready"] is False
    assert manifest["public_200_claim_supported"] is False
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert manifest["outputs"]["ledger.jsonl_sha256"] == summary["ledger_sha256"]
    assert pins["canonical81_ledger"]["sha256"] == "3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9"
    ctrl = neg["controls"][0]
    assert ctrl["case_id"] == CASE_PIMCORE
    assert ctrl["verdict"] == "REJECT"
    assert ctrl["causal_admission"] is False
    assert ctrl["must_be_absent_from_all_counted_ids"] is True
    return summary


def verify_git() -> None:
    cap = build.load_capsule()
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    qf5v = counted[-1]
    assert qf5v["case_id"] == CASE_QF5V
    anc = cap["ancestry"]
    assert anc["candidate_ancestor_of_v1_24_0"] is True
    assert anc["fix_ancestor_of_v1_24_0"] is False
    assert anc["fix_ancestor_of_v1_25_0"] is True
    assert anc["member_ancestor_of_v1_24_0"] is False
    assert anc["member_ancestor_of_v1_25_0"] is False
    assert anc["member_ancestor_of_squash"] is False
    assert cap["object_shas"]["counted_candidate"] == qf5v["candidate_set"][0] == CAND_QF5V
    assert cap["object_shas"]["minimum_fix"] == qf5v["minimum_fix_set"][0] == FIX_QF5V
    assert cap["object_shas"]["hypothesized_unreleased_member"] == MEMBER_QF5V
    assert cap["hunk"]["fix_parent_blob_equals_v1_24_0"] is True
    assert cap["hunk"]["fix_blob_equals_v1_25_0"] is True
    assert cap["hunk"]["six_cap_map_sha256"] == MAP_SHA
    assert cap["vulnerable_release"]["go_proxy_origin_hash_equals_peel"] is True
    assert cap["vulnerable_release"]["commit_only_substitution_refused"] is True
    assert cap["fixed_release"]["commit_only_substitution_refused"] is True
    assert qf5v["vulnerable_release"]["podspec_safety_blob"] == BLOB_V124
    assert qf5v["fixed_release"]["podspec_safety_blob"] == BLOB_FIX


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
    assert CASE_M63V not in counted_ids
    assert CASE_PIMCORE not in counted_ids
    assert ALIAS_QF5V not in counted_ids
    assert CASE_Q855 in counted_ids
    assert counted_ids.count(CASE_Q855) == 1
    assert counted_ids.count(CASE_QF5V) == 1
    assert counted_ids[-1] == CASE_QF5V
    assert set(B3_KEEP) <= set(counted_ids)
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT

    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    cve_aliases = [item for row in counted for item in row["aliases"] if item.startswith("CVE-")]
    assert not any(item in counted_ids for item in cve_aliases)
    assert ALIAS_QF5V in cve_aliases
    assert ALIAS_QF5V not in counted_ids

    qf5v = counted[-1]
    assert qf5v["candidate_set"] == [CAND_QF5V]
    assert qf5v["minimum_fix_set"] == [FIX_QF5V]
    assert (CASE_QF5V, CAND_QF5V, FIX_QF5V) == (
        qf5v["case_id"],
        qf5v["candidate_set"][0],
        qf5v["minimum_fix_set"][0],
    )
    assert MEMBER_QF5V not in qf5v["candidate_set"]
    assert MEMBER_QF5V not in qf5v["carrier_set"]
    assert not any("candidate_fix_edges" in row for row in counted)

    pub_qf = [row for row in pub if row["case_id"] == CASE_QF5V]
    assert len(pub_qf) == 1
    assert pub_qf[0]["ordinal"] == 130
    assert pub_qf[0]["row_key"] == "post:fission-capabilities@canonical"
    assert pub_qf[0]["counted"] is False
    hyp_qf = [
        row
        for row in hyp
        if CASE_QF5V in row.get("declared_public_ids", [])
        or ALIAS_QF5V in row.get("declared_public_ids", [])
    ]
    assert hyp_qf
    assert MEMBER_QF5V in hyp_qf[0]["fp211_candidate_set"]
    assert CAND_QF5V in hyp_qf[0]["fp211_carrier_set"]
    assert qf5v["candidate_set"] != hyp_qf[0]["fp211_candidate_set"]

    cap = build.load_capsule()
    summary = build.load_json(HERE / "summary.json")
    assert cap["leader_strict_case_accepted"] is True
    assert summary["causal_admission"] is False
    assert cap["causal_admission"] is False
    assert cap["leader_strict_case_accepted"] is not cap["causal_admission"]
    assert CASE_QF5V in summary["strict_released_case_ids"]
    assert CASE_QF5V not in [row["case_id"] for row in counted[:PRIOR_STRICT]]

    neg = build.load_negative()["controls"][0]
    assert neg["case_id"] == CASE_PIMCORE
    assert CASE_PIMCORE not in counted_ids
    assert neg["verdict"] == "REJECT"
    assert neg["gates"]["ai_hunk_gate"] == "FAIL"
    assert neg["gates"]["topology_gate"] == "FAIL"
    assert neg["gates"]["but_for_gate"] == "FAIL"
    assert neg["gates"][REMEDIATION_GATE] == "FAIL"
    assert neg["gates"]["identity_gate"] == "PASS"
    assert neg["gates"]["fix_reversal_gate"] == "PASS"
    assert neg["gates"]["release_gate"] == "PASS"
    assert neg["gates"]["uniqueness_gate"] == "PASS"
    assert neg["authorship_transfer"] is True
    assert neg["object_shas"]["human_regex_member"] == HUMAN_PIMCORE
    assert neg["object_shas"]["hypothesized_squash_carrier"] == SQUASH_PIMCORE
    assert neg["copilot_members_do_not_touch_classdefinition"] is True
    assert SQUASH_PIMCORE != HUMAN_PIMCORE
    assert neg["rule"] == "An AI-marked squash carrier cannot transfer authorship to a human member."

    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "worker-only PASS" in report
    assert "canonical strict count 82" in report
    assert CASE_QF5V in report
    assert CASE_PIMCORE in report
    assert EXCLUDE_GOPACKET in report
    assert "v1.24.0" in report
    assert "v1.25.0" in report

    assert build.P_C81 in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    assert build.P_QF5V_PKT in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    assert build.P_PIMCORE_PKT in {row["packet"] for row in by_kind(rows, "PACKET_AUTHORITY")}
    qf_edges = [row for row in by_kind(rows, "SUPERSEDES_EDGE") if row.get("case_id") == CASE_QF5V]
    assert len(qf_edges) == 1
    assert qf_edges[0]["to_packet"] == build.P_QF5V_PKT
    assert qf_edges[0]["to_verdict"] == "KEEP"
    assert qf_edges[0]["from_packet"] == build.P_CONFIRM11
    assert qf_edges[0]["from_verdict"] == "PASS"
    assert qf_edges[0]["applies_to_counted_set"] is True
    assert not any(row["admission_source"] == "worker_pass" for row in counted)
    assert counted[-1]["admission_source"] == "qf5v_redteam_keep"
    for name in ("ledger.jsonl", "summary.json", "manifest.json", "report.md", "qf5v_acceptance.json"):
        blob = (HERE / name).read_text()
        assert "/home/hanqing/.cache" not in blob
        build.assert_no_leak(blob)
    for name in ("summary.json", "manifest.json", "report.md", "qf5v_acceptance.json"):
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
        "PASS: canonical82 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["canonical_strict_count"] == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert counted[-1]["case_id"] == CASE_QF5V
    assert counted[-1]["leader_strict_case_accepted"] is True
    assert "causal_admission" not in counted[-1]


if __name__ == "__main__":
    main()
