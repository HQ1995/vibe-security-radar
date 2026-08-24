#!/usr/bin/env python3
"""Distinct structural, Git, and semantic verifiers. Fail-fast. Clean stderr on success.

Git layer replays pinned first-party facts from the terminal 76PC packet.
No network. Leader live advisory/commit/tag checks already passed.
"""

from __future__ import annotations

import json
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
GATES = build.GATES
HAN = build.HAN
SHA_RE = build.SHA_RE
GHSA_RE = build.GHSA_RE
PRIOR_STRICT = build.PRIOR_STRICT
STRICT_COUNT = build.STRICT_COUNT
CASE_76PC = build.CASE_76PC
ALIAS_76PC = build.ALIAS_76PC
CASE_49MQ = build.CASE_49MQ
CASE_29P3 = build.CASE_29P3
CASE_8W8Q = build.CASE_8W8Q
CASE_G353 = build.CASE_G353
CASE_Q447 = build.CASE_Q447
CASE_2Q7J = build.CASE_2Q7J
CASE_6C8G = build.CASE_6C8G
CASE_5WP8 = build.CASE_5WP8
CASE_PQH8 = build.CASE_PQH8
CASE_XMXX = build.CASE_XMXX
CASE_MFMP = build.CASE_MFMP
CASE_M649 = build.CASE_M649
CASE_2QRV = build.CASE_2QRV
CASE_R5JH = build.CASE_R5JH
CASE_J8Q9 = build.CASE_J8Q9
CAND = build.CAND
PARENT = build.PARENT
FIX = build.FIX
FIX_PARENT = build.FIX_PARENT
MERGE = build.MERGE
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
FILE_WS = build.FILE_WS


def load_rows() -> list[dict]:
    return build.load_jsonl(HERE / "ledger.jsonl")


def by_kind(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if row["record_kind"] == kind]


def load_packet_case() -> dict:
    rows = build.load_jsonl(build.ROOT / (build.P_HOSTILE + "/cases.jsonl"))
    assert len(rows) == 1
    return rows[0]


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
    prior = build.load_json(build.ROOT / build.P_C93_SUM)
    prior_rows = build.load_jsonl(build.ROOT / build.P_C93_LEDGER)
    prior_text = (build.ROOT / build.P_C93_LEDGER).read_text()
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
    assert len(appends) == 15
    assert all(row["counted"] is True for row in counted)
    prior_counted = [row for row in prior_rows if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert prior_counted == counted[:PRIOR_STRICT]
    assert [row["case_id"] for row in counted[PRIOR_STRICT:]] == [CASE_76PC]
    row94 = counted[93]
    assert row94["ordinal"] == 94
    assert row94["case_id"] == CASE_76PC
    assert row94["candidate_set"] == [CAND]
    assert row94["carrier_set"] == []
    assert row94["minimum_fix_set"] == [FIX]
    assert row94["aliases"] == [ALIAS_76PC]
    assert row94["n_parents"] == 1
    assert row94["authorship_transfer"] is False
    assert row94["leader_strict_case_accepted"] is True
    assert row94["contribution_class"] == "AI_DIRECT_ROOT"
    assert row94["whole_ghsa_direct_root"] is True
    assert row94["empty_carrier"] is True
    assert "causal_admission" not in row94
    assert row94["in_fp211_212"] is False
    assert row94["action"] == "APPEND"
    assert MERGE not in row94["candidate_set"]
    assert MERGE not in row94["carrier_set"]

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
    assert summary["publication_admission"] is False
    assert summary["status"] == "HOLD"
    assert summary["public_200_claim_supported"] is False
    assert summary["canonical_strict_count"] == STRICT_COUNT
    prior_append = list(prior["conservation"]["append_identities"])
    assert summary["conservation"]["prior_append_identities"] == prior_append
    assert len(prior_append) == 20
    assert summary["conservation"]["new_append_identities"] == [CASE_76PC]
    assert summary["conservation"]["append_identities"] == prior_append + [CASE_76PC]
    assert len(summary["conservation"]["append_identities"]) == 21
    assert summary["conservation"]["new_identities_append"] is True
    assert summary["conservation"]["same_id_source_layer_promoted"] is False
    assert summary["conservation"]["appended_strict_rows"] == 1
    assert summary["uniqueness"]["promoted_ids"] == [CASE_76PC]
    assert summary["uniqueness"]["absent_from_prior_strict"] is True
    assert summary["uniqueness"]["empty_carrier"] is True
    assert summary["uniqueness"]["merge_90e3a4b8_not_transferred"] is True
    assert summary["uniqueness"]["49mq_not_promoted"] is True
    auth = manifest["packet_authority"]
    assert auth[-1]["packet"] == build.P_HOSTILE
    assert auth[-1]["authority_rank"] == 53
    assert len(auth) == 32
    assert summary["strict_released_case_ids"][:PRIOR_STRICT] == prior["strict_released_case_ids"]
    assert summary["strict_released_case_ids"][PRIOR_STRICT:] == [CASE_76PC]
    assert CASE_76PC not in prior["strict_released_case_ids"]
    assert CASE_49MQ not in summary["strict_released_case_ids"]
    assert CASE_G353 not in summary["strict_released_case_ids"]
    assert CASE_Q447 not in summary["strict_released_case_ids"]
    assert CASE_2Q7J not in summary["strict_released_case_ids"]
    assert summary["ledger_sha256"] == build.sha256_file(HERE / "ledger.jsonl")
    assert pins["canonical93_ledger"]["sha256"] == "6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d"
    assert {row["case_id"] for row in neg["controls"]} == {
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    }
    assert cap["leader_strict_case_accepted"] is True
    assert counted[92]["case_id"] == CASE_M649
    assert counted[91]["case_id"] == CASE_MFMP
    new_appends = [row for row in appends if row["case_id"] == CASE_76PC]
    assert [row["case_id"] for row in new_appends] == [CASE_76PC]
    assert [row["ordinal"] for row in new_appends] == [94]
    for rec in new_appends:
        assert rec["counted"] is False
        assert rec["in_fp211_212"] is False
        assert rec["action"] == "APPEND"
        assert rec["source_layer"] is True
        assert rec["carrier_set"] == []
    assert not any(row["case_id"] == CASE_76PC for row in supers)
    new_tail = text.splitlines()[build.BASE_LEDGER_RECORDS :]
    assert len(new_tail) == 2
    kinds_tail = [json.loads(line)["record_kind"] for line in new_tail]
    assert kinds_tail == ["APPEND_IDENTITY", "STRICT_RELEASED_CASE"]
    return summary


def verify_git() -> None:
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    cap = build.load_capsule()
    pkt = load_packet_case()
    result = build.load_json(build.ROOT / (build.P_HOSTILE + "/result.json"))
    case = cap["cases"][CASE_76PC]
    row94 = counted[93]
    assert pkt["case_id"] == CASE_76PC
    assert pkt["candidate_set"] == [CAND]
    assert pkt["carrier_set"] == []
    assert pkt["minimum_fix_set"] == [FIX]
    assert pkt["candidate_parent"] == PARENT
    assert pkt["fix_parent"] == FIX_PARENT
    assert pkt["first_parent_landing"] == MERGE
    assert pkt["n_parents"] == 1
    assert pkt["contribution_class"] == "AI_DIRECT_ROOT"
    assert pkt["aliases"] == [ALIAS_76PC]
    assert pkt["gates"] == case["gates"]
    blobs = pkt["blobs"]
    shas = case["object_shas"]
    assert shas["origin_web_server_ts"] == blobs["origin_web_server_ts"] == build.BLOB_ORIGIN
    assert shas["merge_web_server_ts"] == blobs["merge_web_server_ts"] == build.BLOB_MERGE
    assert shas["vulnerable_web_server_ts_v5_0_1"] == blobs["vulnerable_web_server_ts_v5_0_1"] == build.BLOB_VULN
    assert shas["closer_web_server_ts"] == blobs["closer_web_server_ts"] == build.BLOB_CLOSER
    assert (
        shas["fixed_web_server_ts_v5_1_0_and_npm_5_1_1"]
        == blobs["fixed_web_server_ts_v5_1_0_and_npm_5_1_1"]
        == build.BLOB_FIXED
    )
    assert shas["origin_web_server_ts"] != shas["merge_web_server_ts"]
    assert shas["closer_web_server_ts"] != shas["fixed_web_server_ts_v5_1_0_and_npm_5_1_1"]
    vuln = pkt["vulnerable_release_evidence"]
    fixed = pkt["fixed_release_evidence"]
    assert vuln["gitHead"] == build.PEEL_VULN
    assert vuln["peel"] == build.PEEL_VULN
    assert vuln["npm_version"] == "5.0.1"
    assert fixed["gitHead"] == build.PEEL_FIX
    assert fixed["peel"] == build.PEEL_FIX
    assert fixed["npm_version"] == "5.1.1"
    assert fixed["supporting_unpublished_npm_510"]["peel"] == build.PEEL_510
    assert row94["candidate_parent"] == PARENT
    assert row94["fix_parent"] == FIX_PARENT
    assert row94["vulnerable_release"]["git_tag_commit"] == build.PEEL_VULN
    assert row94["vulnerable_release"]["npm_githead"] == build.PEEL_VULN
    assert row94["fixed_release"]["git_tag_commit"] == build.PEEL_FIX
    assert row94["fixed_release"]["npm_githead"] == build.PEEL_FIX
    assert row94["fixed_release"]["supporting_fixed_tag"]["git_tag_commit"] == build.PEEL_510
    assert row94["vulnerable_release"]["contains_candidate_any_parent"] is True
    assert row94["vulnerable_release"]["contains_fix_any_parent"] is False
    assert row94["fixed_release"]["contains_fix_any_parent"] is True
    assert row94["vulnerable_release"]["has_isValidSessionId"] is False
    assert row94["fixed_release"]["has_isValidSessionId"] is True
    assert SHA_RE.fullmatch(CAND)
    assert SHA_RE.fullmatch(PARENT)
    assert SHA_RE.fullmatch(FIX)
    assert SHA_RE.fullmatch(FIX_PARENT)
    assert SHA_RE.fullmatch(MERGE)
    assert SHA_RE.fullmatch(build.PEEL_VULN)
    assert SHA_RE.fullmatch(build.PEEL_FIX)
    assert SHA_RE.fullmatch(build.PEEL_510)
    proj = result["advisory_projections"][CASE_76PC]
    assert proj["aliases"] == [ALIAS_76PC]
    assert proj["repository"] == "ooples/token-optimizer-mcp"
    assert proj["package_name"] == "@ooples/token-optimizer-mcp"
    assert proj["github_reviewed"] is True
    assert proj["withdrawn"] is False
    assert proj["sha256"] == "68f6243932a4fce66b3682ebcde01a677d10d9367ac3fde5f07b72cde92a679c"
    assert result["uniqueness"]["49mq_overlap"] is False
    assert CASE_76PC not in result["uniqueness"]["canonical91_strict_overlap"]
    assert FILE_WS in case["scope_statement"]
    assert "session-log-${sessionId}.jsonl" in pkt["scope_statement"]
    assert pkt["authorship_transfer"] is False
    assert MERGE not in pkt["candidate_set"]
    row91 = counted[90]
    assert row91["case_id"] == CASE_5WP8


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
        CASE_49MQ,
        CASE_29P3,
        CASE_8W8Q,
        ALIAS_76PC,
    ):
        assert banned not in counted_ids
    assert counted_ids.count(CASE_76PC) == 1
    assert counted_ids[-1] == CASE_76PC
    assert counted_ids[-2] == CASE_M649
    assert counted_ids[-3] == CASE_MFMP
    assert CASE_5WP8 in counted_ids
    assert len(counted_ids) == len(set(counted_ids)) == STRICT_COUNT
    fps = [row["mechanism_fingerprint"] for row in counted]
    assert len(fps) == len(set(fps)) == STRICT_COUNT
    mechs = [row["mechanism_key"] for row in counted]
    assert len(mechs) == len(set(mechs)) == STRICT_COUNT
    assert build.MECH_FP in fps
    assert build.MECH_KEY in mechs
    alias_bag = []
    for row in counted:
        alias_bag.extend(row["aliases"])
        for alias in row["aliases"]:
            assert alias not in counted_ids
            assert alias != row["case_id"]
    assert ALIAS_76PC in alias_bag
    assert alias_bag.count(ALIAS_76PC) == 1
    neg = build.load_negative()
    for ctrl in neg["controls"]:
        assert ctrl["case_id"] not in counted_ids
        assert ctrl["verdict"] == "REJECT"
    summary = build.load_json(HERE / "summary.json")
    report = (HERE / "report.md").read_text()
    assert "more than 200" not in report.lower()
    assert "Causal admission is false" in report
    assert "canonical strict count 94" in report
    assert counted[93]["admission_source"] == "76pc_hostile_redteam_keep"
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
        assert build.P_HOSTILE in row["first_party_source_refs"]
        assert build.P_CAP in row["first_party_source_refs"]
    assert summary["counts"]["keep_76pc"] == 1
    assert CASE_49MQ in summary["excluded"]
    assert CASE_Q447 in summary["excluded"]
    assert CASE_2Q7J in summary["excluded"]
    assert ALIAS_76PC in summary["excluded"]
    assert "merge_90e3a4b8_not_transferred" in summary["excluded"]
    pub_ids = {row["case_id"] for row in pub}
    assert CASE_G353 in pub_ids
    assert CASE_Q447 in pub_ids
    assert CASE_2Q7J in pub_ids
    assert CASE_6C8G in pub_ids
    assert CASE_76PC not in pub_ids
    assert counted[93]["carrier_set"] == []
    assert counted[93]["repository"] == "ooples/token-optimizer-mcp"


def verify() -> tuple[dict, list[dict]]:
    summary = verify_structural()
    verify_git()
    verify_semantic()
    counted = by_kind(load_rows(), "STRICT_RELEASED_CASE")
    return summary, counted


def main() -> None:
    summary, counted = verify()
    print(
        "PASS: canonical94 HOLD structural+git+semantic; "
        f"counted={len(counted)}; publication=HOLD"
    )
    assert summary["counts"]["strict_released_first_party_ghsa"] == len(counted) == STRICT_COUNT
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False
    assert summary["publication_admission"] is False
    assert summary["causal_admission"] is False
    assert summary["public_200_claim_supported"] is False
    assert counted[-1]["case_id"] == CASE_76PC
    assert CASE_49MQ not in [row["case_id"] for row in counted]
    assert CASE_G353 not in [row["case_id"] for row in counted]
    assert CASE_Q447 not in [row["case_id"] for row in counted]
    assert CASE_2Q7J not in [row["case_id"] for row in counted]


if __name__ == "__main__":
    main()
