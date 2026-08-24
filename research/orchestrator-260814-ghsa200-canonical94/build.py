#!/usr/bin/env python3
"""Build the HOLD canonical94-directory snapshot at strict count 94. Stdlib only.

Consumes the local 76PC capsule plus immutable canonical93 tracked artifacts.
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
PRIOR_STRICT = 93
STRICT_COUNT = 94
BASE_LEDGER_RECORDS = 595
LEDGER_RECORDS = 597
CASE_76PC = "GHSA-76PC-MQXP-3RQ5"
ALIAS_76PC = "CVE-2026-55156"
CASE_49MQ = "GHSA-49MQ-FC6Q-3H46"
CASE_29P3 = "GHSA-29P3-56WX-GGFH"
CASE_8W8Q = "GHSA-8W8Q-FGV9-J286"
CASE_G353 = "GHSA-G353-MGV3-8PCJ"
CASE_Q447 = "GHSA-Q447-RJ3R-2CGH"
CASE_2Q7J = "GHSA-2Q7J-2VHX-56G8"
CASE_6C8G = "GHSA-6C8G-7P36-R338"
CASE_5WP8 = "GHSA-5WP8-Q9MX-8JX8"
CASE_PQH8 = "GHSA-PQH8-P93P-2RX7"
CASE_XMXX = "GHSA-XMXX-7P24-H892"
CASE_MFMP = "GHSA-MFMP-Q643-VJ39"
CASE_M649 = "GHSA-M649-24Q9-Q6R4"
CASE_2QRV = "GHSA-2QRV-RC5X-2G2H"
CASE_R5JH = "GHSA-R5JH-Q2MW-GCX4"
CASE_J8Q9 = "GHSA-J8Q9-R9PQ-2HH9"
CAND = "051f27474d85d7f3299b56fc61bfcb0666a4e198"
PARENT = "5fe1380e53eee6d08ec47980fd7b32a08eb077b6"
FIX = "b4ee96dac799cbfba0a9f9c17844ce9d613cbcc7"
FIX_PARENT = "4ae7c351659b3a1a7f741f6dc427577aead9fdd8"
MERGE = "90e3a4b8d2719cf027e8079510ac41521ee1c60e"
MECH_KEY = "token-optimizer-mcp.web-server.sessionId.pathjoin.jsonl-traversal"
MECH_FP = MECH_KEY
PEEL_VULN = "8138f3a6d32eff80387f24d6068039ae8fb7bfa9"
PEEL_FIX = "687b55460d752fa4ee011c58535c733191b831c8"
PEEL_510 = "94815a16e3322101694e97561fc1dc8b5af904dc"
BLOB_ORIGIN = "1cdd93c63455f91d58d5b8fbac667e7760858667"
BLOB_MERGE = "b2038a0995ae3aaf3258ba4d6ccc8444b09ed99b"
BLOB_VULN = "d8cf67f68b5bebb4fbf063de863065bc4d78d769"
BLOB_CLOSER = "3f750e6ce7bed24a41395c8578e8ca98ad094f15"
BLOB_FIXED = "40e8be9bbd27d877285cddb7192249eed40f202b"
FILE_WS = "src/server/web-server.ts"
AI_MARKER = "Co-Authored-By: Claude <noreply@anthropic.com>"
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
ADMITTED = (CASE_76PC,)

P_C93 = "autoresearch/orchestrator-260814-ghsa200-canonical93"
P_C93_LEDGER = P_C93 + "/ledger.jsonl"
P_C93_SUM = P_C93 + "/summary.json"
P_C93_MAN = P_C93 + "/manifest.json"
P_C93_REP = P_C93 + "/report.md"
P_C93_CAP = P_C93 + "/acceptance.json"
P_NEG = "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json"
P_CONTRACT = "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
P_HOSTILE = "autoresearch/herdr-260814-76pc-hostile-redteam-grok46-xhigh"
P_CAP = "autoresearch/orchestrator-260814-ghsa200-canonical94/acceptance.json"
P_FP211 = "autoresearch/orchestrator-260813-fp211-audit"
P_PUBLIC = P_FP211 + "/public_cases.jsonl"
P_TRUTH = "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md"
NEW_APPEND_IDENTITIES = (CASE_76PC,)
NEW_PACKET_AUTHORITY = (
    {
        "authority_rank": 53,
        "packet": P_HOSTILE,
        "role": "redteam",
        "status": "TERMINAL",
        "terminal": True,
    },
)

FROZEN = {
    "canonical93_ledger": (P_C93_LEDGER, "6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d"),
    "canonical93_summary": (P_C93_SUM, "cf8a3eb231830303803e2e1a198207b2a8e117990a675982e8d9e346c9cc46c0"),
    "canonical93_manifest": (P_C93_MAN, "fee404f0f7a2883cd37903f21664b82b91fe68e43c9e24af8a7400341d7be965"),
    "canonical93_report": (P_C93_REP, "4eb306413d0e51c852d59477c4cb7c2fff20de98404a97968cdbc814d08a472e"),
    "canonical93_acceptance": (P_C93_CAP, "6c85adc74de17b55804b28eaff90c18fcae302ee5ea891748a7379e53acf8c65"),
    "canonical85_negative_controls": (P_NEG, "c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0"),
    "contract_md": (P_CONTRACT, "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"),
    "fp211_public_cases": (P_PUBLIC, "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257"),
    "research_truth_layers": (P_TRUTH, "70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f"),
    "hostile_assignment": (P_HOSTILE + "/assignment.jsonl", "41e474e8fcb1d17b038dc3cf4240eef6055aba846d6a7a57ddb5b2ec09ccf521"),
    "hostile_cases": (P_HOSTILE + "/cases.jsonl", "a44283803dbb28608719a8de828892b9d3437752e58e3f8953836cb93c9b1134"),
    "hostile_report": (P_HOSTILE + "/report.md", "f06fe2621a12364b5c43224a38ebaf332d0a73a436dc6fc71b128cf3003252eb"),
    "hostile_replay": (P_HOSTILE + "/replay.zsh", "35291ef91575bd6e8f7671fc2788d72602ac985a40a85a79f36cc1e85c555d06"),
    "hostile_result": (P_HOSTILE + "/result.json", "64616eccb295c6951889fa04d0d0ea2b24da3977fb76d3b466780d268f75df29"),
}
LOCAL_PINS = {
    "acceptance_76pc": (P_CAP, "b02f2824c63648b47804d870b8eeb72f55dfea4293ac06103573bb5cf74d38dc"),
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
    assert cap["admitted_ids"] == [CASE_76PC]
    assert cap["excluded_from_this_promotion"] == [CASE_49MQ]
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
    assert cap["in_canonical93_strict"] is False
    assert cap["new_identities_append"] is True
    assert cap["same_id_source_layer_promoted"] is False
    assert cap["empty_carrier"] is True
    assert cap["authorship_transfer"] is False
    assert cap["shared_closer_sha_is_not_duplication"] is True
    assert cap["admission_source"] == "76pc_hostile_redteam_keep"
    assert cap["independent_terminal_packets"] == [P_HOSTILE]
    sh = cap["source_hashes"]
    assert sh["hostile_assignment_jsonl"] == FROZEN["hostile_assignment"][1]
    assert sh["hostile_cases_jsonl"] == FROZEN["hostile_cases"][1]
    assert sh["hostile_report_md"] == FROZEN["hostile_report"][1]
    assert sh["hostile_replay_zsh"] == FROZEN["hostile_replay"][1]
    assert sh["hostile_result_json"] == FROZEN["hostile_result"][1]
    assert sh["canonical93_ledger"] == FROZEN["canonical93_ledger"][1]
    assert sh["canonical93_summary"] == FROZEN["canonical93_summary"][1]
    assert sh["canonical93_manifest"] == FROZEN["canonical93_manifest"][1]
    assert sh["canonical93_report"] == FROZEN["canonical93_report"][1]
    assert sh["canonical93_acceptance"] == FROZEN["canonical93_acceptance"][1]
    assert sh["fp211_public_cases_jsonl"] == FROZEN["fp211_public_cases"][1]
    assert sh["research_truth_layers_md"] == FROZEN["research_truth_layers"][1]
    assert sh["hostile_packet"] == P_HOSTILE
    case = cap["cases"][CASE_76PC]
    assert case["ordinal"] == 94
    assert case["contribution_class"] == "AI_DIRECT_ROOT"
    assert case["mechanism_key"] == MECH_KEY
    assert case["mechanism_fingerprint"] == MECH_FP
    assert case["candidate_set"] == [CAND]
    assert case["carrier_set"] == []
    assert case["minimum_fix_set"] == [FIX]
    assert case["aliases"] == [ALIAS_76PC]
    assert case["n_parents"] == 1
    assert case["in_fp211_212"] is False
    assert case["action"] == "APPEND"
    assert case["whole_ghsa_direct_root"] is True
    assert case["empty_carrier"] is True
    assert case["merge_90e3a4b8_not_transferred"] is True
    assert all(case["gates"][field] == "PASS" for field in GATES)
    assert case["object_shas"]["candidate_parent"] == PARENT
    assert case["object_shas"]["counted_candidate"] == CAND
    assert case["object_shas"]["minimum_fix"] == FIX
    assert case["object_shas"]["fix_parent"] == FIX_PARENT
    assert case["object_shas"]["first_parent_landing_merge"] == MERGE
    assert case["object_shas"]["vulnerable_npm_githead"] == PEEL_VULN
    assert case["object_shas"]["fixed_npm_githead"] == PEEL_FIX
    assert case["object_shas"]["supporting_fixed_tag_v5_1_0"] == PEEL_510
    assert case["vulnerable_release"]["git_tag_commit"] == PEEL_VULN
    assert case["vulnerable_release"]["npm_githead"] == PEEL_VULN
    assert case["fixed_release"]["git_tag_commit"] == PEEL_FIX
    assert case["fixed_release"]["npm_githead"] == PEEL_FIX
    assert case["fixed_release"]["supporting_fixed_tag"]["git_tag_commit"] == PEEL_510
    assert "session-log-${sessionId}.jsonl" in case["scope_statement"]
    assert "carrier_set is empty" in case["scope_statement"]
    assert "90e3a4b8" in case["scope_statement"]
    assert CASE_49MQ not in cap["cases"]
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
    refs = list(case["primary_urls"]) + [P_CAP, P_HOSTILE]
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
        "empty_carrier": True,
        "first_party_source_refs": refs,
        "fix_parent": case["object_shas"]["fix_parent"],
        "in_fp211_212": False,
        "leader_strict_case_accepted": True,
        "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        "mechanism_fingerprint": case["mechanism_fingerprint"],
        "mechanism_key": case["mechanism_key"],
        "merge_90e3a4b8_not_transferred": True,
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
        "whole_ghsa_direct_root": True,
        "vulnerable_release": dict(case["vulnerable_release"]),
        "fixed_release": dict(case["fixed_release"]),
    }
    assert SHA_RE.fullmatch(out["candidate_set"][0])
    assert SHA_RE.fullmatch(out["minimum_fix_set"][0])
    assert SHA_RE.fullmatch(out["candidate_parent"])
    assert SHA_RE.fullmatch(out["fix_parent"])
    assert out["carrier_set"] == []
    assert out["candidate_set"] == [CAND]
    assert out["minimum_fix_set"] == [FIX]
    assert out["contribution_class"] == "AI_DIRECT_ROOT"
    assert out["whole_ghsa_direct_root"] is True
    assert out["in_fp211_212"] is False
    assert out["action"] == "APPEND"
    assert MERGE not in out["candidate_set"]
    assert MERGE not in out["carrier_set"]
    assert MERGE not in out["minimum_fix_set"]
    assert ALIAS_76PC in out["aliases"]
    assert "causal_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "candidate_fix_edges" not in out
    assert CASE_49MQ not in compact_json(out) or CASE_49MQ in out["scope_statement"]
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
    base_pairs = load_jsonl_raw(ROOT / P_C93_LEDGER)
    prior_summary = load_json(ROOT / P_C93_SUM)
    prior_manifest = load_json(ROOT / P_C93_MAN)
    base_text = (ROOT / P_C93_LEDGER).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["ledger_sha256"] == pins["canonical93_ledger"]["sha256"]
    assert sha256_bytes(base_text.encode()) == pins["canonical93_ledger"]["sha256"]
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
        CASE_76PC,
        CASE_49MQ,
        CASE_29P3,
        CASE_8W8Q,
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
    assert CASE_MFMP in base_ids
    assert CASE_M649 in base_ids
    assert CASE_G353 in source_ids
    assert CASE_Q447 in source_ids
    assert CASE_2Q7J in source_ids
    assert CASE_6C8G in source_ids
    assert CASE_76PC not in source_ids
    assert MECH_FP not in base_fps
    assert MECH_KEY not in base_mechs
    assert ALIAS_76PC not in base_ids

    counted_76pc = counted_from_case(cap, CASE_76PC)
    assert counted_76pc["ordinal"] == 94
    assert seven_pass(counted_76pc)
    append_76pc = append_from_counted(counted_76pc)
    for rec in (counted_76pc, append_76pc):
        assert_no_leak(compact_json(rec))
        assert not HAN.search(compact_json(rec))
        assert rec.get("record_kind") != "SUPERSEDES_EDGE"

    new_lines = [
        compact_json(append_76pc),
        compact_json(counted_76pc),
    ]
    ledger_text = base_text if base_text.endswith("\n") else base_text + "\n"
    ledger_text = ledger_text + "\n".join(new_lines) + "\n"
    records = [json.loads(line) for line in ledger_text.splitlines() if line.strip()]
    assert [line for line, _ in base_pairs] == ledger_text.splitlines()[:BASE_LEDGER_RECORDS]

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == [counted_76pc]
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
        CASE_49MQ,
        CASE_29P3,
        CASE_8W8Q,
        ALIAS_76PC,
    ):
        assert not any(row["case_id"] == banned for row in counted_rows)
    assert not any(row["record_kind"] == "SUPERSEDES_EDGE" and row["case_id"] in ADMITTED for row in records)

    kinds = Counter(row["record_kind"] for row in records)
    assert kinds["PRESERVED_HYPOTHESIS"] == 211
    assert kinds["PRESERVED_PUBLIC_CASE"] == 212
    assert kinds["APPEND_IDENTITY"] == 15
    assert kinds["STRICT_RELEASED_CASE"] == STRICT_COUNT
    assert kinds["PACKET_AUTHORITY"] == 18
    assert kinds["SUPERSEDES_EDGE"] == 47
    assert sum(row.get("counted") is True for row in records) == STRICT_COUNT
    assert not HAN.search(ledger_text)

    counted_ids = [row["case_id"] for row in counted_rows]
    prior_append = list(prior_summary["conservation"]["append_identities"])
    new_append = list(NEW_APPEND_IDENTITIES)
    append_identities = prior_append + new_append
    assert len(prior_append) == 20
    assert new_append == [CASE_76PC]
    assert append_identities[-1:] == [CASE_76PC]
    checkpoint = dict(prior_summary["checkpoint"])
    checkpoint["prior_strict_count"] = PRIOR_STRICT
    checkpoint["corrected_strict_count"] = STRICT_COUNT
    checkpoint["appended_76pc_one"] = [CASE_76PC]
    checkpoint["excluded_49mq_this_promotion"] = [CASE_49MQ]
    checkpoint["directory_name"] = "orchestrator-260814-ghsa200-canonical94"
    checkpoint["prior_directory"] = "orchestrator-260814-ghsa200-canonical93"
    checkpoint["prior_commit"] = "60e8f2c354c89dd5ab33db2e214652ab1cbc578d"
    checkpoint["note"] = (
        "Directory name is canonical94. Semantic target is canonical strict count 94: "
        "the prior 93 exact strict IDs plus new counted identity GHSA-76PC-MQXP-3RQ5 "
        "at ordinal 94. Source conservation remains 211 hypotheses and 212 GHSA cases. "
        "Leader admission records APPEND_IDENTITY then STRICT_RELEASED_CASE "
        "(in_fp211_212=false, action=APPEND). No SUPERSEDES_EDGE is appended. Counted "
        "class is AI_DIRECT_ROOT of the named dashboard sessionId path-traversal. "
        "carrier_set is empty. Merge 90e3a4b8 is not transferred. Alias CVE-2026-55156 "
        "is stored and is not a counting unit. GHSA-49MQ is excluded. GHSA-Q447, "
        "GHSA-2Q7J, GHSA-6C8G, and inherited negatives stay absent. Publication and "
        "integration stay closed. Greater-than-200 remains unsupported."
    )
    excluded = dict(prior_summary["excluded"])
    excluded[CASE_49MQ] = (
        "Distinct first-party reviewed identity (CVE-2026-55157, smart_user getent "
        "interpolation). Shared closer b4ee96dac799 is not a merge of cases. Not promoted."
    )
    excluded[ALIAS_76PC] = "alias of GHSA-76PC-MQXP-3RQ5; not a counting unit"
    excluded["merge_90e3a4b8_not_transferred"] = (
        "First-parent pickaxe on v5.0.1 hits merge 90e3a4b8; that merge does not author "
        "the hunk versus its second parent and is not transferred onto 051f27474d85"
    )
    excluded["npm_510_unpublished"] = (
        "npm 5.1.0 returns HTTP 404; git tag v5.1.0 peel 94815a16 supports containment "
        "and is not a published npm artifact"
    )
    excluded["advisory_typo_8137147"] = (
        "Advisory table commit 8137147 peels to SECURITY.md, not tag v5.0.1 gitHead "
        "8138f3a6; not a second identity"
    )
    excluded["29p3_8w8q_404"] = (
        "Closer-named GHSA-29P3-56WX-GGFH and GHSA-8W8Q-FGV9-J286 are 404 in global "
        "and repo advisory APIs; not this sessionId path-traversal identity"
    )
    excluded["cartesian_candidate_fix_edges"] = (
        excluded["cartesian_candidate_fix_edges"]
        + "; 76PC binds 051f27474d as candidate to b4ee96dac7 with empty carrier_set"
    )
    counts = dict(prior_summary["counts"])
    counts["strict_released_first_party_ghsa"] = STRICT_COUNT
    counts["ledger_records"] = len(records)
    counts["keep_76pc"] = 1
    counts["excluded_49mq_this_promotion"] = 1
    counts["by_record_kind"] = dict(kinds)
    counts["by_admission_source"] = dict(Counter(row["admission_source"] for row in counted_rows))
    uniqueness = {
        "strict_ids_unique": True,
        "mechanism_keys_unique": True,
        "mechanism_fingerprints_unique": True,
        "promoted_ids": [CASE_76PC],
        "absent_from_prior_strict": True,
        "empty_carrier": True,
        "merge_90e3a4b8_not_transferred": True,
        "49mq_not_promoted": True,
        "29p3_8w8q_not_this_identity": True,
        "shared_closer_sha_not_duplication": True,
        "g353_not_promoted": True,
        "q447_not_promoted": True,
        "2q7j_not_promoted": True,
        "6c8g_not_promoted": True,
        "cve_aliases_counted": False,
    }
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical94-hold",
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
            "HOLD snapshot of canonical strict count 94 first-party GHSA identities: "
            "the prior 93 plus GHSA-76PC-MQXP-3RQ5. Source conservation remains 211 "
            "hypotheses and 212 GHSA cases. This does not support a greater-than-200 "
            "claim. Publication and integration stay closed."
        ),
        "conservation": {
            "fp211_hypotheses": 211,
            "fp211_source_ghsa_cases": 212,
            "cve_aliases_counted": False,
            "upgrades_append": False,
            "new_identities_append": True,
            "same_id_source_layer_promoted": False,
            "promoted_same_id_identities": list(
                prior_summary["conservation"].get("promoted_same_id_identities") or []
            ),
            "prior_append_identities": prior_append,
            "new_append_identities": new_append,
            "append_identities": append_identities,
            "base_counted_rows_byte_identical": True,
            "base_ledger_rows_byte_identical": True,
            "appended_strict_rows": 1,
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
            "# Canonical94 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 94 first-party GHSA identities. It extends the frozen canonical93 snapshot in orchestrator-260814-ghsa200-canonical93 by appending exactly one leader-accepted new identity. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical93 meaning and are not flipped by counting GHSA-76PC. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical93 ledger row is preserved byte-for-byte and in order. The prior 93 counted rows stay byte-identical. All 595 canonical93 records stay byte-identical as the prefix. Two records are appended: APPEND_IDENTITY then STRICT_RELEASED_CASE for GHSA-76PC-MQXP-3RQ5. No SUPERSEDES_EDGE is appended. Count is by first-party GHSA identity once. CVE aliases are stored and never counted. Alias CVE-2026-55156 is stored on the admitted row and is not a counting unit.",
            "",
            "The admitted identity at ordinal 94 is GHSA-76PC-MQXP-3RQ5, repository ooples/token-optimizer-mcp, class AI_DIRECT_ROOT. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. Counted surface is the AI-added dashboard /api/session-summary and /api/session-events path.join of caller sessionId into session-log-${sessionId}.jsonl. Parent 5fe1380e has no src/server/web-server.ts. Candidate is atomic 051f27474d85. n_parents is 1. carrier_set is empty. Merge 90e3a4b8 is not transferred. Later restyle commits and AI-on-fix closer trailers are not transferred. minimum_fix_set is b4ee96dac799, parent 4ae7c351, which adds SESSION_ID_RE and isValidSessionId. Vulnerable published npm @ooples/token-optimizer-mcp 5.0.1 gitHead/tag peel 8138f3a6 contains the candidate and excludes the fix. Fixed published npm 5.1.1 gitHead/tag peel 687b5546 contains the fix. Supporting fixed git tag v5.1.0 peel 94815a16 contains the closer; npm 5.1.0 is unpublished. Mechanism key and fingerprint are unique versus canonical93.",
            "",
            "Admission evidence pins independent terminal packet herdr-260814-76pc-hostile-redteam-grok46-xhigh, including assignment, cases, report, replay, and result hashes, plus fp211 public_cases.jsonl and RESEARCH-TRUTH-LAYERS source manifests. Leader replay and live first-party advisory/commit/tag checks passed. Worker PASS remains proposal-only until this leader snapshot. GHSA-49MQ-FC6Q-3H46 is explicitly excluded. GHSA-Q447-RJ3R-2CGH, GHSA-2Q7J-2VHX-56G8, GHSA-6C8G-7P36-R338, and all canonical93 negatives stay absent from strict rows.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer. Same-id upgrades still do not append. GHSA-76PC is a new counted identity (in_fp211_212=false, action=APPEND). Conservation prior_append_identities stays the prior 20. new_append_identities is exactly that one ID. append_identities is the prior 20 followed by that one (21). new_identities_append is true. same_id_source_layer_promoted is false. APPEND_IDENTITY record count rises by one, from 14 to 15. The worker packet admits this row at authority rank 53. Discovery tabs and worker-only PASS are not loaded. Raw pages, crates, and owned clones are not committed; the builder consumes acceptance.json plus immutable canonical93 tracked artifacts and the pinned packet.",
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
    assert CASE_76PC in report
    assert ALIAS_76PC in report
    assert CASE_49MQ in report
    assert CASE_Q447 in report
    assert CASE_2Q7J in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "new_identities_append is true" in report
    assert "same_id_source_layer_promoted is false" in report
    assert "AI_DIRECT_ROOT" in report
    assert "carrier_set is empty" in report
    inherited_authority = [dict(item) for item in prior_manifest["packet_authority"]]
    packet_authority = inherited_authority + [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert len(inherited_authority) == 31
    assert inherited_authority[-1]["authority_rank"] == 52
    assert packet_authority[-1]["authority_rank"] == 53
    assert packet_authority[-1]["packet"] == P_HOSTILE
    assert len(packet_authority) == 32
    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical94-hold",
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
        print("PASS: canonical94 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
