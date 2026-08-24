#!/usr/bin/env python3
"""Build the HOLD canonical93-directory snapshot at strict count 93. Stdlib only.

Consumes the local MFMP/M649 capsule plus immutable canonical91 tracked artifacts.
Does not read raw API pages, crates, worker caches, or owned clones.
Does not scan live mutable autoresearch trees.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = 4
GATES = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
HAN = re.compile(r"[\u3400-\u9fff]")
PRIOR_STRICT = 91
STRICT_COUNT = 93
BASE_LEDGER_RECORDS = 591
LEDGER_RECORDS = 595
CASE_MFMP = "GHSA-MFMP-Q643-VJ39"
CASE_M649 = "GHSA-M649-24Q9-Q6R4"
CASE_G353 = "GHSA-G353-MGV3-8PCJ"
CASE_Q447 = "GHSA-Q447-RJ3R-2CGH"
CASE_2Q7J = "GHSA-2Q7J-2VHX-56G8"
CASE_6C8G = "GHSA-6C8G-7P36-R338"
CASE_5WP8 = "GHSA-5WP8-Q9MX-8JX8"
CASE_PQH8 = "GHSA-PQH8-P93P-2RX7"
CASE_XMXX = "GHSA-XMXX-7P24-H892"
CASE_HM7V = "GHSA-HM7V-JRHM-FMFX"
CASE_CWP8 = "GHSA-CWP8-RM8G-Q5C9"
CASE_2QRV = "GHSA-2QRV-RC5X-2G2H"
CASE_R5JH = "GHSA-R5JH-Q2MW-GCX4"
CASE_J8Q9 = "GHSA-J8Q9-R9PQ-2HH9"
CAND = "80a3e620a4aa046c2644937a5a2fa799a2e750d6"
PARENT = "9166d9983afcc59df343cf19c7595351d6f750af"
FIX_MFMP = "330d0d6a2e6995f017d5943bd3b4806d713b181c"
FIX_PARENT_MFMP = "10520f164268d0ee76307b785de176a31198e4d7"
FIX_M649 = "ae2b73550452056cc45a65a4165340ae17c2c3e5"
FIX_PARENT_M649 = "07be35d7fdaae872f2f6ff404779368f201fe8b5"
MEM_0EA20 = "0ea20d01050cd25b30bca1418bb821fbd3bcb7ab"
MEM_3B8B = "3b8b474519272e0d6bb2a7f07c4f1202d2a02bf4"
MEM_367D = "367dd18e4b017a5bc893e1fab1ce55cc34647f08"
MEM_5631 = "5631bb084da530732dbef5aa2f3f71c67c739298"
EDE1 = "ede1bfb08633e6d1157744e99d176e258fc58aba"
MECH_KEY_MFMP = "churchcrm.groupview.optionname.html-text-xss"
MECH_FP_MFMP = MECH_KEY_MFMP
MECH_KEY_M649 = "churchcrm.groupview.tel-mailto.attribute-xss"
MECH_FP_M649 = MECH_KEY_M649
PEEL_742 = "f54eea0ff476d4a343e98be0cbbaee42440c436f"
PEEL_743 = "dbdc6133165b906a84c5bf4d919c74ee797c192b"
PEEL_751 = "9ee9c00c6ea99582a7d65b5d1d8c6197b51a77a8"
PEEL_760 = "9b5993c0918ce45522e57f28114929ac75a29b9b"
BLOB_PARENT_GV = "32b10e7ebc49494ba79eaefe8a034c4488855268"
BLOB_CAND_GV = "23fb4f55f25d6e1e881163891152fe2a3cb6ccaa"
BLOB_MEM_GV = "6d1eae1066039f7e0b32b870cf4c82ddc3b3d815"
BLOB_742_GV = "1cb473c551a7625ef1c35f9e3d8d449853b54c1a"
BLOB_743_GV = "116f1bffe566960053ee9aff479dfa3c02e8d9a7"
BLOB_751_GV = "ed5347f0d5562d99266539e83a1db9e05b53b92d"
BLOB_760_GV = "041a9794dc64be0b0c3931edba027ca7a1030a47"
BLOB_GR_PARENT = "62dfbce14ca2bd0f7ff7a0e5f69152ef289ea2b0"
FILE_GV = "src/skin/js/GroupView.js"
FILE_GR = "src/skin/js/GroupRoles.js"
AI_MARKER = "Co-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>"
CASE_PIMCORE = "GHSA-2MHJ-FHVG-V428"
CASE_HHJV = "GHSA-HHJV-JQ77-CMVX"
CASE_73HC = "GHSA-73HC-M4HX-79PJ"
CASE_282G = "GHSA-282G-FHMX-XF54"
CASE_45Q4 = "GHSA-45Q4-X4R9-8FQJ"
CASE_954P = "GHSA-954P-556P-R752"
CASE_C8JX = "GHSA-C8JX-96C9-8XRP"
CASE_FPXG = "GHSA-FPXG-5XMV-922M"
CASE_6G9V = "GHSA-6G9V-7GQ3-P2C6"
CASE_9722 = "GHSA-9722-9J67-VJCR"
FILEBROWSER_NEG = "post:filebrowser-delete-scope@canonical"
FILEBROWSER_POS = "post:filebrowser-dangling-write@canonical"
ORD200 = ("GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7")
ADMITTED = (CASE_MFMP, CASE_M649)

P_C91 = "autoresearch/orchestrator-260814-ghsa200-canonical91"
P_C91_LEDGER = P_C91 + "/ledger.jsonl"
P_C91_SUM = P_C91 + "/summary.json"
P_C91_MAN = P_C91 + "/manifest.json"
P_C91_REP = P_C91 + "/report.md"
P_C91_CAP = P_C91 + "/5wp8_acceptance.json"
P_NEG = "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json"
P_CONTRACT = "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
P_NEAR = "autoresearch/herdr-260814-nearclosed-l-grok46-high"
P_HOSTILE = "autoresearch/herdr-260814-wave-l-hostile-redteam-grok46-xhigh"
P_CAP = "autoresearch/orchestrator-260814-ghsa200-canonical93/acceptance.json"
P_FP211 = "autoresearch/orchestrator-260813-fp211-audit"
P_PUBLIC = P_FP211 + "/public_cases.jsonl"
P_TRUTH = "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md"
NEW_APPEND_IDENTITIES = (CASE_MFMP, CASE_M649)
NEW_PACKET_AUTHORITY = (
    {
        "authority_rank": 51,
        "packet": P_NEAR,
        "role": "worker",
        "status": "TERMINAL",
        "terminal": True,
    },
    {
        "authority_rank": 52,
        "packet": P_HOSTILE,
        "role": "redteam",
        "status": "TERMINAL",
        "terminal": True,
    },
)

FROZEN = {
    "canonical91_ledger": (P_C91_LEDGER, "70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e"),
    "canonical91_summary": (P_C91_SUM, "ab47f927a20f374a9b0e3253a1a5a0778e355dda9414189927022325d81ad86f"),
    "canonical91_manifest": (P_C91_MAN, "1a8b1c17592d85beddc99e73c3bdf99e1cbe26562efd197bc63767a3629c9720"),
    "canonical91_report": (P_C91_REP, "e1c8390c966660566af1e0bab75ababa2418ced7dc14d57e36ed8e8a7b747404"),
    "canonical91_5wp8_capsule": (P_C91_CAP, "6d018b39328389c8a6b78d6b4c03ce3b30f42b04d53464090ebb370fc59bf8b9"),
    "canonical85_negative_controls": (P_NEG, "c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0"),
    "contract_md": (P_CONTRACT, "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"),
    "fp211_public_cases": (P_PUBLIC, "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257"),
    "research_truth_layers": (P_TRUTH, "70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f"),
    "nearclosed_assignment": (P_NEAR + "/assignment.jsonl", "9a39827cbd34547719629377752843c3bebb19c00c8f4a9fe6ef3b1da331f600"),
    "nearclosed_cases": (P_NEAR + "/cases.jsonl", "203963af356be6bd0bc9c780f1f10ae0a7d8ca956a291d693bb03901edd7e1be"),
    "nearclosed_report": (P_NEAR + "/report.md", "28985cd0eaa88a36bf02c99e866f448f6860bd0bf153170815c5bd87ef8dfe98"),
    "nearclosed_replay": (P_NEAR + "/replay.zsh", "818d1149a5391419117ed5b5ccae1d6d5959edbd14d09bf4a6bdca9722ddc98b"),
    "nearclosed_result": (P_NEAR + "/result.json", "5ff70d476b1e30acd41b156c53d9f66b4acfdfc27a6ead70ef8d68a44892e912"),
    "hostile_assignment": (P_HOSTILE + "/assignment.jsonl", "9b2aa800ed60dc39a0034e703cc9c0de2f40a84553912150161d086ebad0dd34"),
    "hostile_cases": (P_HOSTILE + "/cases.jsonl", "2090af09f332c9d6e26671445f9eddef8995334ff4b88a2700237fa03d77fbaf"),
    "hostile_report": (P_HOSTILE + "/report.md", "dc8f44541bb107dd26486e5ee41f1305e4bdcf4e94d7bd1544a04fee1cb38590"),
    "hostile_replay": (P_HOSTILE + "/replay.zsh", "abc1ab516f9cb8a0aaf3be20284bce21f1528af66c6fa5499a20e1d03ee3a19d"),
    "hostile_result": (P_HOSTILE + "/result.json", "ad71f4488df0d9a50392df0ff7bc106851c3f095ea64d57161bd6e823cafad18"),
}
LOCAL_PINS = {
    "acceptance_mfmp_m649": (P_CAP, "6c85adc74de17b55804b28eaff90c18fcae302ee5ea891748a7379e53acf8c65"),
}


def compact_json(value) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def leak_needles() -> tuple[str, ...]:
    return (
        "os" + ".environ",
        "environ" + ".copy",
        "print" + "env",
        "get" + "env(",
        "HIST" + "FILE",
        "xtr" + "ace",
        "set " + "-x",
        "PS" + "4=",
        "GITHUB" + "_TOKEN",
        "GH_" + "TOKEN",
        "API" + "_KEY",
        "OPENAI" + "_API",
        "ANTHROPIC" + "_API",
        "Authorization:",
        "Bearer ",
        "DEBUG" + "=",
        "BEGIN " + "PRIVATE",
        "BEGIN " + "RSA",
    )


def assert_no_leak(text: str) -> None:
    blob = text.lower()
    for needle in leak_needles():
        assert needle.lower() not in blob


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path):
    return json.loads(path.read_text())


def load_jsonl_raw(path: Path) -> list[tuple[str, dict]]:
    pairs = []
    for line in path.read_text().splitlines():
        if line.strip():
            pairs.append((line, json.loads(line)))
    return pairs


def load_jsonl(path: Path) -> list[dict]:
    return [row for _, row in load_jsonl_raw(path)]


def pin_inputs() -> dict[str, dict]:
    pinned = {}
    fills = []
    for name, (relative, expected) in FROZEN.items():
        path = ROOT / relative
        got = sha256_file(path)
        if got != expected:
            fills.append(f"frozen mismatch {name}: {got}")
        pinned[name] = {"path": relative, "role": "frozen", "sha256": got}
    for name, (relative, expected) in LOCAL_PINS.items():
        path = ROOT / relative
        got = sha256_file(path)
        if got != expected:
            fills.append(f"capsule mismatch {name}: {got}")
        pinned[name] = {"path": relative, "role": "curated_capsule", "sha256": got}
    if fills:
        raise SystemExit("PIN_FILL\n" + "\n".join(fills))
    return pinned


def seven_pass(row: dict) -> bool:
    for field in GATES:
        value = row.get(field)
        if value is None or value != "PASS":
            return False
    return True


def load_capsule() -> dict:
    cap = load_json(HERE / "acceptance.json")
    assert cap["admitted_ids"] == [CASE_MFMP, CASE_M649]
    assert cap["excluded_from_this_promotion"] == [CASE_G353]
    assert cap["remaining_absent"] == [CASE_Q447, CASE_2Q7J, CASE_6C8G]
    assert cap["verdict"] == "KEEP"
    assert cap["countable_in_this_snapshot"] is True
    assert cap["leader_strict_case_accepted"] is True
    assert cap["causal_admission"] is False
    assert cap["publication_admission"] is False
    assert cap["publication_ready"] is False
    assert cap["cve_alias_is_not_a_counting_unit"] is True
    assert cap["cartesian_candidate_fix_refused"] is True
    assert cap["in_fp211_212"] is False
    assert cap["in_canonical91_strict"] is False
    assert cap["new_identities_append"] is True
    assert cap["same_id_source_layer_promoted"] is False
    assert cap["shared_candidate_sha_is_not_duplication"] is True
    assert cap["admission_source"] == "scoped_contributor_wave_l_dual_keep"
    assert cap["independent_terminal_packets"] == [P_NEAR, P_HOSTILE]
    sh = cap["source_hashes"]
    assert sh["nearclosed_l_assignment_jsonl"] == FROZEN["nearclosed_assignment"][1]
    assert sh["nearclosed_l_cases_jsonl"] == FROZEN["nearclosed_cases"][1]
    assert sh["nearclosed_l_report_md"] == FROZEN["nearclosed_report"][1]
    assert sh["nearclosed_l_replay_zsh"] == FROZEN["nearclosed_replay"][1]
    assert sh["nearclosed_l_result_json"] == FROZEN["nearclosed_result"][1]
    assert sh["hostile_assignment_jsonl"] == FROZEN["hostile_assignment"][1]
    assert sh["hostile_cases_jsonl"] == FROZEN["hostile_cases"][1]
    assert sh["hostile_report_md"] == FROZEN["hostile_report"][1]
    assert sh["hostile_replay_zsh"] == FROZEN["hostile_replay"][1]
    assert sh["hostile_result_json"] == FROZEN["hostile_result"][1]
    assert sh["canonical91_ledger"] == FROZEN["canonical91_ledger"][1]
    assert sh["canonical91_summary"] == FROZEN["canonical91_summary"][1]
    assert sh["canonical91_manifest"] == FROZEN["canonical91_manifest"][1]
    assert sh["canonical91_report"] == FROZEN["canonical91_report"][1]
    assert sh["fp211_public_cases_jsonl"] == FROZEN["fp211_public_cases"][1]
    assert sh["research_truth_layers_md"] == FROZEN["research_truth_layers"][1]
    assert sh["nearclosed_l_packet"] == P_NEAR
    assert sh["hostile_packet"] == P_HOSTILE
    mfmp = cap["cases"][CASE_MFMP]
    m649 = cap["cases"][CASE_M649]
    assert mfmp["ordinal"] == 92
    assert m649["ordinal"] == 93
    assert mfmp["contribution_class"] == "AI_SCOPED_CONTRIBUTOR"
    assert m649["contribution_class"] == "AI_SCOPED_CONTRIBUTOR"
    assert mfmp["mechanism_key"] == MECH_KEY_MFMP
    assert m649["mechanism_key"] == MECH_KEY_M649
    assert mfmp["mechanism_fingerprint"] == MECH_FP_MFMP
    assert m649["mechanism_fingerprint"] == MECH_FP_M649
    assert mfmp["candidate_set"] == [CAND]
    assert m649["candidate_set"] == [CAND]
    assert mfmp["carrier_set"] == [CAND]
    assert m649["carrier_set"] == [CAND]
    assert mfmp["minimum_fix_set"] == [FIX_MFMP]
    assert m649["minimum_fix_set"] == [FIX_M649]
    assert mfmp["aliases"] == []
    assert m649["aliases"] == []
    assert mfmp["n_parents"] == 1
    assert m649["n_parents"] == 1
    assert mfmp["in_fp211_212"] is False
    assert m649["in_fp211_212"] is False
    assert mfmp["action"] == "APPEND"
    assert m649["action"] == "APPEND"
    assert mfmp["whole_ghsa_direct_root"] is False
    assert m649["whole_ghsa_direct_root"] is False
    assert mfmp["member_0ea20d01_not_transferred"] is True
    assert m649["member_0ea20d01_not_transferred"] is True
    assert all(mfmp["gates"][field] == "PASS" for field in GATES)
    assert all(m649["gates"][field] == "PASS" for field in GATES)
    assert mfmp["object_shas"]["candidate_parent"] == PARENT
    assert m649["object_shas"]["candidate_parent"] == PARENT
    assert mfmp["object_shas"]["counted_carrier"] == CAND
    assert m649["object_shas"]["counted_carrier"] == CAND
    assert mfmp["object_shas"]["fix_parent"] == FIX_PARENT_MFMP
    assert m649["object_shas"]["fix_parent"] == FIX_PARENT_M649
    assert mfmp["object_shas"]["non_ancestor_member"] == MEM_0EA20
    assert m649["object_shas"]["non_ancestor_member"] == MEM_0EA20
    assert mfmp["vulnerable_release"]["git_tag_commit"] == PEEL_742
    assert mfmp["fixed_release"]["git_tag_commit"] == PEEL_743
    assert m649["vulnerable_release"]["git_tag_commit"] == PEEL_751
    assert m649["fixed_release"]["git_tag_commit"] == PEEL_760
    assert "OptionName HTML-text" in mfmp["scope_statement"]
    assert "GroupRoles" in mfmp["scope_statement"]
    assert "tel:" in m649["scope_statement"]
    assert "mailto:" in m649["scope_statement"]
    assert "data-name" in m649["scope_statement"]
    assert CASE_G353 not in cap["cases"]
    assert CASE_Q447 not in cap["cases"]
    assert_no_leak(compact_json(cap))
    assert not HAN.search(compact_json(cap))
    return cap


def load_negative() -> dict:
    blob = load_json(ROOT / P_NEG)
    assert blob["capsule_kind"] == "negative_control_regression_guard"
    assert len(blob["controls"]) == 6
    by_id = {row["case_id"]: row for row in blob["controls"]}
    for case_id in (CASE_PIMCORE, CASE_HHJV, CASE_73HC, CASE_282G, CASE_45Q4, CASE_954P):
        assert by_id[case_id]["verdict"] == "REJECT"
        assert by_id[case_id]["countable"] is False
        assert by_id[case_id]["must_be_absent_from_all_counted_ids"] is True
    assert_no_leak(compact_json(blob))
    return blob


def counted_from_case(cap: dict, case_id: str) -> dict:
    case = cap["cases"][case_id]
    g = {field: case["gates"][field] for field in GATES}
    refs = list(case["primary_urls"]) + [P_CAP, P_NEAR, P_HOSTILE]
    out = {
        "action": "APPEND",
        "admission_source": cap["admission_source"],
        "aliases": list(case["aliases"]),
        "authorship_transfer": False,
        "candidate_parent": case["object_shas"]["candidate_parent"],
        "candidate_set": list(case["candidate_set"]),
        "carrier_set": list(case["carrier_set"]),
        "cartesian_candidate_fix_refused": True,
        "case_id": case["case_id"],
        "contribution_class": case["contribution_class"],
        "counted": True,
        "counting_unit": "first-party GHSA case",
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "first_party_source_refs": refs,
        "fix_parent": case["object_shas"]["fix_parent"],
        "in_fp211_212": False,
        "leader_strict_case_accepted": True,
        "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        "mechanism_fingerprint": case["mechanism_fingerprint"],
        "mechanism_key": case["mechanism_key"],
        "minimum_fix_set": list(case["minimum_fix_set"]),
        "n_parents": 1,
        "ordinal": case["ordinal"],
        "overlay_state": "KEEP",
        "record_kind": "STRICT_RELEASED_CASE",
        "repository": case["repository"],
        "row_key": f"ghsa200-next:{case['case_id']}",
        "schema_version": SCHEMA,
        "scope_statement": case["scope_statement"],
        "source_layer": False,
        **g,
        "whole_ghsa_direct_root": False,
        "vulnerable_release": dict(case["vulnerable_release"]),
        "fixed_release": dict(case["fixed_release"]),
    }
    assert SHA_RE.fullmatch(out["candidate_set"][0])
    assert SHA_RE.fullmatch(out["carrier_set"][0])
    assert SHA_RE.fullmatch(out["minimum_fix_set"][0])
    assert SHA_RE.fullmatch(out["candidate_parent"])
    assert SHA_RE.fullmatch(out["fix_parent"])
    assert out["candidate_set"] == [CAND]
    assert out["carrier_set"] == [CAND]
    assert out["candidate_set"] == out["carrier_set"]
    assert out["contribution_class"] == "AI_SCOPED_CONTRIBUTOR"
    assert out["whole_ghsa_direct_root"] is False
    assert out["in_fp211_212"] is False
    assert out["action"] == "APPEND"
    assert MEM_0EA20 not in out["candidate_set"]
    assert MEM_0EA20 not in out["carrier_set"]
    assert "causal_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "candidate_fix_edges" not in out
    assert CASE_G353 not in compact_json(out)
    return out


def append_from_counted(counted: dict) -> dict:
    return {
        "action": "APPEND",
        "admission_source": counted["admission_source"],
        "candidate_set": counted["candidate_set"],
        "carrier_set": counted["carrier_set"],
        "case_id": counted["case_id"],
        "counted": False,
        "in_fp211_212": False,
        "minimum_fix_set": counted["minimum_fix_set"],
        "ordinal": counted["ordinal"],
        "overlay_state": "KEEP",
        "record_kind": "APPEND_IDENTITY",
        "row_key": counted["row_key"],
        "schema_version": SCHEMA,
        "source_layer": True,
        **{field: counted[field] for field in GATES},
    }


def build_outputs() -> dict[Path, str]:
    pins = pin_inputs()
    cap = load_capsule()
    neg = load_negative()
    base_pairs = load_jsonl_raw(ROOT / P_C91_LEDGER)
    prior_summary = load_json(ROOT / P_C91_SUM)
    prior_manifest = load_json(ROOT / P_C91_MAN)
    base_text = (ROOT / P_C91_LEDGER).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["ledger_sha256"] == pins["canonical91_ledger"]["sha256"]
    assert sha256_bytes(base_text.encode()) == pins["canonical91_ledger"]["sha256"]
    assert prior_summary["integration_ready"] is False
    assert prior_summary["publication_ready"] is False
    assert prior_summary["causal_admission"] is False
    assert prior_summary["public_200_claim_supported"] is False
    assert prior_summary["status"] == "HOLD"
    assert len(base_pairs) == BASE_LEDGER_RECORDS

    by_kind: dict[str, list[dict]] = {}
    for _, row in base_pairs:
        by_kind.setdefault(row["record_kind"], []).append(row)
    assert len(by_kind["STRICT_RELEASED_CASE"]) == PRIOR_STRICT
    base_counted = by_kind["STRICT_RELEASED_CASE"]
    base_ids = [row["case_id"] for row in base_counted]
    source_ids = {row["case_id"] for row in by_kind["PRESERVED_PUBLIC_CASE"]}
    base_fps = {row["mechanism_fingerprint"] for row in base_counted}
    base_mechs = {row["mechanism_key"] for row in base_counted}
    assert len(base_ids) == len(set(base_ids)) == PRIOR_STRICT
    for case_id in (
        CASE_MFMP,
        CASE_M649,
        CASE_G353,
        CASE_Q447,
        CASE_2Q7J,
        CASE_6C8G,
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
        CASE_2QRV,
        CASE_R5JH,
        CASE_J8Q9,
    ):
        assert case_id not in base_ids
    assert CASE_5WP8 in base_ids
    assert CASE_HM7V in base_ids
    assert CASE_CWP8 in base_ids
    assert CASE_5WP8 in source_ids
    assert CASE_HM7V in source_ids
    assert CASE_G353 in source_ids
    assert CASE_Q447 in source_ids
    assert CASE_2Q7J in source_ids
    assert CASE_6C8G in source_ids
    assert MECH_FP_MFMP not in base_fps
    assert MECH_FP_M649 not in base_fps
    assert MECH_KEY_MFMP not in base_mechs
    assert MECH_KEY_M649 not in base_mechs

    counted_mfmp = counted_from_case(cap, CASE_MFMP)
    counted_m649 = counted_from_case(cap, CASE_M649)
    assert counted_mfmp["ordinal"] == 92
    assert counted_m649["ordinal"] == 93
    assert seven_pass(counted_mfmp)
    assert seven_pass(counted_m649)
    append_mfmp = append_from_counted(counted_mfmp)
    append_m649 = append_from_counted(counted_m649)
    for rec in (counted_mfmp, counted_m649, append_mfmp, append_m649):
        assert_no_leak(compact_json(rec))
        assert not HAN.search(compact_json(rec))
        assert rec.get("record_kind") != "SUPERSEDES_EDGE"

    new_lines = [
        compact_json(append_mfmp),
        compact_json(counted_mfmp),
        compact_json(append_m649),
        compact_json(counted_m649),
    ]
    ledger_text = base_text if base_text.endswith("\n") else base_text + "\n"
    ledger_text = ledger_text + "\n".join(new_lines) + "\n"
    records = [json.loads(line) for line in ledger_text.splitlines() if line.strip()]
    assert [line for line, _ in base_pairs] == ledger_text.splitlines()[:BASE_LEDGER_RECORDS]

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == [counted_mfmp, counted_m649]
    assert len(counted_rows) == STRICT_COUNT
    assert len(records) == LEDGER_RECORDS
    for banned in (
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
        CASE_6C8G,
        CASE_2QRV,
        CASE_R5JH,
        CASE_J8Q9,
        CASE_G353,
        CASE_Q447,
        CASE_2Q7J,
    ):
        assert not any(row["case_id"] == banned for row in counted_rows)
    assert not any(row["record_kind"] == "SUPERSEDES_EDGE" and row["case_id"] in ADMITTED for row in records)

    kinds = Counter(row["record_kind"] for row in records)
    assert kinds["PRESERVED_HYPOTHESIS"] == 211
    assert kinds["PRESERVED_PUBLIC_CASE"] == 212
    assert kinds["APPEND_IDENTITY"] == 14
    assert kinds["STRICT_RELEASED_CASE"] == STRICT_COUNT
    assert kinds["PACKET_AUTHORITY"] == 18
    assert kinds["SUPERSEDES_EDGE"] == 47
    assert sum(row.get("counted") is True for row in records) == STRICT_COUNT
    assert not HAN.search(ledger_text)

    counted_ids = [row["case_id"] for row in counted_rows]
    prior_append = list(prior_summary["conservation"]["append_identities"])
    new_append = list(NEW_APPEND_IDENTITIES)
    append_identities = prior_append + new_append
    assert len(prior_append) == 18
    assert new_append == [CASE_MFMP, CASE_M649]
    assert append_identities[-2:] == [CASE_MFMP, CASE_M649]
    checkpoint = dict(prior_summary["checkpoint"])
    checkpoint["prior_strict_count"] = PRIOR_STRICT
    checkpoint["corrected_strict_count"] = STRICT_COUNT
    checkpoint["appended_mfmp_m649_two"] = [CASE_MFMP, CASE_M649]
    checkpoint["excluded_g353_this_promotion"] = [CASE_G353]
    checkpoint["directory_name"] = "orchestrator-260814-ghsa200-canonical93"
    checkpoint["prior_directory"] = "orchestrator-260814-ghsa200-canonical91"
    checkpoint["note"] = (
        "Directory name is canonical93. Semantic target is canonical strict count 93: "
        "the prior 91 exact strict IDs plus new counted identities GHSA-MFMP-Q643-VJ39 "
        "at ordinal 92 and GHSA-M649-24Q9-Q6R4 at ordinal 93. Source conservation remains "
        "211 hypotheses and 212 GHSA cases. Leader admission records each as "
        "APPEND_IDENTITY then STRICT_RELEASED_CASE (in_fp211_212=false, action=APPEND). "
        "No SUPERSEDES_EDGE is appended. Counted class is AI_SCOPED_CONTRIBUTOR on the "
        "scoped GroupView HTML-text and tel/mailto surfaces only. Shared squash 80a3e620 "
        "is not duplication. GHSA-G353-MGV3-8PCJ is excluded after hostile REJECT. "
        "GHSA-Q447, GHSA-2Q7J, GHSA-6C8G, and inherited negatives stay absent. "
        "Publication and integration stay closed. Greater-than-200 remains unsupported."
    )
    excluded = dict(prior_summary["excluded"])
    excluded[CASE_G353] = (
        "Independent wave-l hostile REJECT: later unmarked humans author the released "
        "Feishu verificationToken-without-encryptKey path. Squash 5c2cb6c5 is not the "
        "advisory-named 2026.3.11 hole. Not promoted."
    )
    excluded[CASE_Q447] = "remains absent from the strict set; unbounded-body Feishu identity is not this snapshot"
    excluded[CASE_2Q7J] = "remains absent from the strict set; Feishu tools merge/first-account gate is not this snapshot"
    excluded["grouproles_optionname_sibling_mfmp"] = (
        "Preexisting GroupRoles.js OptionName HTML labels stay out of scope; blob 62dfbce1 "
        "is identical on parent and squash"
    )
    excluded["data_name_sibling_m649"] = (
        "Preexisting GroupView data-name attribute from ede1bfb0 stays out of scope; "
        "pickaxe on 7.5.1 hits that earlier commit"
    )
    excluded["member_0ea20d01_not_transferred"] = (
        "Non-ancestor Claude member 0ea20d01 has a different GroupView.js blob and is not "
        "transferred onto squash 80a3e620"
    )
    excluded["whole_ghsa_direct_root_mfmp"] = (
        "GHSA-MFMP whole-GHSA direct root is not counted; only AI-added GroupView HTML-text "
        "sinks are counted"
    )
    excluded["whole_ghsa_direct_root_m649"] = (
        "GHSA-M649 whole-GHSA direct root is not counted; only AI-added tel/mailto attribute "
        "sinks are counted"
    )
    excluded["shared_closer_hm7v_m649"] = (
        "Closer ae2b7355 also names counted GHSA-HM7V CRMJSOM.js data-person_name; shared SHA "
        "is not duplication"
    )
    excluded["cartesian_candidate_fix_edges"] = (
        excluded["cartesian_candidate_fix_edges"]
        + "; MFMP binds 80a3e620a4 as candidate and carrier to 330d0d6a2e"
        + "; M649 binds 80a3e620a4 as candidate and carrier to ae2b735504"
    )
    counts = dict(prior_summary["counts"])
    counts["strict_released_first_party_ghsa"] = STRICT_COUNT
    counts["ledger_records"] = len(records)
    counts["keep_mfmp"] = 1
    counts["keep_m649"] = 1
    counts["excluded_g353_this_promotion"] = 1
    counts["by_record_kind"] = dict(kinds)
    counts["by_admission_source"] = dict(Counter(row["admission_source"] for row in counted_rows))
    uniqueness = {
        "strict_ids_unique": True,
        "mechanism_keys_unique": True,
        "mechanism_fingerprints_unique": True,
        "promoted_ids": [CASE_MFMP, CASE_M649],
        "absent_from_prior_strict": True,
        "shared_candidate_sha_not_duplication": True,
        "mfmp_distinct_from_m649": True,
        "m649_distinct_from_counted_hm7v": True,
        "g353_not_promoted": True,
        "q447_not_promoted": True,
        "2q7j_not_promoted": True,
        "6c8g_not_promoted": True,
        "member_0ea20d01_not_transferred": True,
        "cve_aliases_counted": False,
    }
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical93-hold",
        "canonical_strict_count": STRICT_COUNT,
        "checkpoint": checkpoint,
        "counting_unit": "first-party GHSA case",
        "language": "en",
        "causal_admission": False,
        "integration_ready": False,
        "publication_admission": False,
        "publication_ready": False,
        "public_200_claim_supported": False,
        "claim_boundary": (
            "HOLD snapshot of canonical strict count 93 first-party GHSA identities: "
            "the prior 91 plus GHSA-MFMP-Q643-VJ39 and GHSA-M649-24Q9-Q6R4. Source "
            "conservation remains 211 hypotheses and 212 GHSA cases. This does not "
            "support a greater-than-200 claim. Publication and integration stay closed."
        ),
        "conservation": {
            "fp211_hypotheses": 211,
            "fp211_source_ghsa_cases": 212,
            "cve_aliases_counted": False,
            "upgrades_append": False,
            "new_identities_append": True,
            "same_id_source_layer_promoted": False,
            "promoted_same_id_identities": list(prior_summary["conservation"].get("promoted_same_id_identities") or []),
            "prior_append_identities": prior_append,
            "new_append_identities": new_append,
            "append_identities": append_identities,
            "base_counted_rows_byte_identical": True,
            "base_ledger_rows_byte_identical": True,
            "appended_strict_rows": 2,
        },
        "counts": counts,
        "strict_released_case_ids": counted_ids,
        "excluded": excluded,
        "uniqueness": uniqueness,
        "seven_gates": list(GATES),
        "gate_exact_value": "PASS",
        "null_fails": True,
        "na_fails": True,
        "verification_layers": ["structural", "git", "semantic"],
        "blockers": [
            "Leader review of this HOLD snapshot is still required before integration.",
            "Pending discovery tabs and worker-only PASS rows are excluded.",
            "The public 200-case claim remains unsupported.",
        ],
        "hash_roles": {
            "frozen": {k: v for k, v in pins.items() if v["role"] == "frozen"},
            "curated_capsule": {k: v for k, v in pins.items() if v["role"] == "curated_capsule"},
            "current": {},
            "overlap_check": {},
        },
        "negative_controls": [
            {
                "case_id": row["case_id"],
                "verdict": "REJECT",
                "counted": False,
                "fail_gates": list(row["fail_gates"]),
                "rule": row["rule"],
            }
            for row in neg["controls"]
        ],
        "ledger_sha256": sha256_bytes(ledger_text.encode()),
    }
    report = "\n".join(
        [
            "# Canonical93 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 93 first-party GHSA identities. It extends the frozen canonical91 snapshot in orchestrator-260814-ghsa200-canonical91 by appending exactly two leader-accepted new identities. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical91 meaning and are not flipped by counting GHSA-MFMP or GHSA-M649. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical91 ledger row is preserved byte-for-byte and in order. The prior 91 counted rows stay byte-identical. All 591 canonical91 records stay byte-identical as the prefix. Four records are appended: APPEND_IDENTITY then STRICT_RELEASED_CASE for GHSA-MFMP-Q643-VJ39, then APPEND_IDENTITY then STRICT_RELEASED_CASE for GHSA-M649-24Q9-Q6R4. No SUPERSEDES_EDGE is appended. Count is by first-party GHSA identity once. CVE aliases are stored and never counted. Neither admitted identity has a CVE alias.",
            "",
            "The admitted identity at ordinal 92 is GHSA-MFMP-Q643-VJ39, repository ChurchCRM/CRM, class AI_SCOPED_CONTRIBUTOR. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. Counted surface is only the AI-added GroupView OptionName HTML-text pills and cart/actions dropdowns. Parent 9166d998 has no buildRolePills. Candidate and carrier are squash 80a3e620, which adds unescaped i18next.t(role.OptionName) into those HTML-text sinks. n_parents is 1. Member 0ea20d01 is not an ancestor of the squash or of tags 7.4.2/7.4.3 and is not transferred. Preexisting GroupRoles.js option-label sibling blob 62dfbce1 is identical on parent and squash and is excluded. minimum_fix_set is 330d0d6a, parent 10520f16, which wraps escapeHtml on those GroupView sites. Whole-GHSA direct root is excluded. Public GitHub tag 7.4.2 peel f54eea0f contains the candidate and excludes the fix. Public tag 7.4.3 peel dbdc6133 contains the fix. Mechanism key and fingerprint are unique versus canonical91.",
            "",
            "The admitted identity at ordinal 93 is GHSA-M649-24Q9-Q6R4, repository ChurchCRM/CRM, class AI_SCOPED_CONTRIBUTOR. Counted surface is only the AI-added tel: and mailto: attribute concatenations on the same squash 80a3e620. Shared candidate SHA is a positive control, not duplication: advisory identity, mechanism fingerprint, sink context, fix, and release interval all differ from MFMP. Parent already had quoted data-name from ede1bfb0; that sibling is excluded. Member 5631bb08 is not transferred. minimum_fix_set is ae2b7355, parent 07be35d7, which switches tel/mailto to escapeAttribute. M649 is distinct from counted GHSA-HM7V-JRHM-FMFX despite shared closer ae2b7355. Public GitHub tag 7.5.1 peel 9ee9c00c contains the candidate and excludes the fix. Public tag 7.6.0 peel 9b5993c0 contains the fix.",
            "",
            "Admission evidence pins both independent terminal packets herdr-260814-nearclosed-l-grok46-high and herdr-260814-wave-l-hostile-redteam-grok46-xhigh, including assignment, cases, report, replay, and result hashes, plus fp211 public_cases.jsonl and RESEARCH-TRUTH-LAYERS source manifests. Worker PASS remains proposal-only until this leader snapshot. GHSA-G353-MGV3-8PCJ is explicitly excluded after hostile REJECT. GHSA-Q447-RJ3R-2CGH, GHSA-2Q7J-2VHX-56G8, GHSA-6C8G-7P36-R338, and all canonical91 negatives stay absent from strict rows.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer. Same-id upgrades still do not append. GHSA-MFMP and GHSA-M649 are new counted identities (in_fp211_212=false, action=APPEND). Conservation prior_append_identities stays the prior 18. new_append_identities is exactly those two IDs. append_identities is the prior 18 followed by those two (20). new_identities_append is true. same_id_source_layer_promoted is false. APPEND_IDENTITY record count rises by two, from 12 to 14. The two worker packets admit these rows at authority ranks 51 and 52. Discovery tabs and worker-only PASS are not loaded. Raw pages, crates, and owned clones are not committed; the builder consumes acceptance.json plus immutable canonical91 tracked artifacts and the two pinned packets.",
            "",
            "Every counted row has all seven contract gates equal to the string PASS. Null and NA fail closed. Candidate, carrier, and minimum-fix sets are sorted unique 40-hex SHAs. Cartesian candidate times fix pairs are not invented.",
            "",
            "Status HOLD until leader review.",
            "",
        ]
    )
    assert not HAN.search(report)
    assert "more than 200" not in report.lower()
    assert_no_leak(report)
    assert CASE_MFMP in report
    assert CASE_M649 in report
    assert CASE_G353 in report
    assert CASE_Q447 in report
    assert CASE_2Q7J in report
    assert CASE_HM7V in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "new_identities_append is true" in report
    assert "same_id_source_layer_promoted is false" in report
    assert "AI_SCOPED_CONTRIBUTOR" in report
    assert "Shared candidate SHA is a positive control" in report
    inherited_authority = [dict(item) for item in prior_manifest["packet_authority"]]
    packet_authority = inherited_authority + [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert len(inherited_authority) == 29
    assert inherited_authority[-1]["authority_rank"] == 50
    assert packet_authority[-2]["authority_rank"] == 51
    assert packet_authority[-1]["authority_rank"] == 52
    assert packet_authority[-2]["packet"] == P_NEAR
    assert packet_authority[-1]["packet"] == P_HOSTILE
    assert len(packet_authority) == 31
    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical93-hold",
        "canonical_strict_count": STRICT_COUNT,
        "checkpoint": summary["checkpoint"],
        "counting_unit": "first-party GHSA case",
        "causal_admission": False,
        "integration_ready": False,
        "publication_admission": False,
        "publication_ready": False,
        "public_200_claim_supported": False,
        "packet_authority": packet_authority,
        "hash_roles": summary["hash_roles"],
        "conservation": summary["conservation"],
        "uniqueness": uniqueness,
        "strict_released_first_party_ghsa": STRICT_COUNT,
        "outputs": {
            "ledger.jsonl_sha256": summary["ledger_sha256"],
            "report.md_sha256": sha256_bytes(report.encode()),
        },
    }
    summary_text = json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    assert not HAN.search(summary_text)
    manifest["outputs"]["summary.json_sha256"] = sha256_bytes(summary_text.encode())
    manifest_text = json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    assert_no_leak(summary_text)
    assert_no_leak(manifest_text)
    return {
        HERE / "ledger.jsonl": ledger_text,
        HERE / "summary.json": summary_text,
        HERE / "manifest.json": manifest_text,
        HERE / "report.md": report,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = build_outputs()
    if args.check:
        for path, text in outputs.items():
            assert path.is_file() and path.read_text() == text, path.name
        print("PASS: canonical93 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
