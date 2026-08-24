#!/usr/bin/env python3
"""Build the HOLD canonical90-directory snapshot at strict count 90. Stdlib only.

Consumes the local XMXX/PQH8 capsule plus immutable canonical88 tracked artifacts.
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
PRIOR_STRICT = 88
STRICT_COUNT = 90
BASE_LEDGER_RECORDS = 585
LEDGER_RECORDS = 589
CASE_XMXX = "GHSA-XMXX-7P24-H892"
CASE_PQH8 = "GHSA-PQH8-P93P-2RX7"
CASE_6C8G = "GHSA-6C8G-7P36-R338"
CASE_8RW6 = "GHSA-8RW6-P7M8-63JP"
CASE_V52W = "GHSA-V52W-28XH-V562"
ALIAS_XMXX = "CVE-2026-43585"
CAND_XMXX = "f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f"
PARENT_XMXX = "7f6e87e9180b9f236aa88b90936be8f6f7988bc2"
FIX_XMXX = "acd4e0a32f12e1ad85f3130f63b42443ce90f094"
FIX_PARENT_XMXX = "0a877070923e266e5e80aea3553711e3a68af8ee"
CAND_PQH8 = "66ff2a7c8bedc23939d6d70ab4c3bdce53673843"
PARENT_PQH8 = "c11191125271e676109e78fef32df4a61bfa4ce6"
FIX_PQH8 = "15d3546c0618ffbaeaeca477337e08e92f2151bc"
FIX_PARENT_PQH8 = "35db4695ce24f19d5326edee5a86e9ba39e13f69"
MECH_KEY_XMXX = "openclaw.gateway.http.openresponses.startup-captured-resolvedAuth"
MECH_FP_XMXX = "openclaw.gateway.http.openresponses.startup-captured-resolvedAuth"
MECH_KEY_PQH8 = "dynatrace-mcp-server.dql-interpolation.timeframe.list-vulnerabilities-and-get-events"
MECH_FP_PQH8 = "dynatrace-mcp-server.dql-interpolation.timeframe.list-vulnerabilities-and-get-events"
PEEL_XMXX_VULN = "323493fa1b6adc1e10b9954a68d5eaa5a6ef1170"
PEEL_XMXX_FIX = "041266a6699cac3baef8ef39db41fa26f29f9db3"
PEEL_PQH8_VULN = "35db4695ce24f19d5326edee5a86e9ba39e13f69"
PEEL_PQH8_FIX = "9a5f6f86d186f1168645e24673c73bc56a94dda8"
PEEL_PQH8_V12 = "1c192a0427bb348b0843779207f556052d6c28e7"
FILE_XMXX = "src/gateway/openresponses-http.ts"
FILE_XMXX_HTTP = "src/gateway/server-http.ts"
FILE_PQH8_LV = "src/capabilities/list-vulnerabilities.ts"
FILE_PQH8_GE = "src/capabilities/get-events-for-cluster.ts"
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
ADMITTED = (CASE_XMXX, CASE_PQH8)

P_C88 = "autoresearch/orchestrator-260814-ghsa200-canonical88"
P_C88_LEDGER = P_C88 + "/ledger.jsonl"
P_C88_SUM = P_C88 + "/summary.json"
P_C88_MAN = P_C88 + "/manifest.json"
P_C88_REP = P_C88 + "/report.md"
P_C88_CAP = P_C88 + "/8rw6_acceptance.json"
P_NEG = "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json"
P_CONTRACT = "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
P_NEAR = "autoresearch/herdr-260814-nearclosed-b-grok46-medium"
P_CCB = "autoresearch/herdr-260814-causal-consensus-b-grok46-xhigh"
P_CAP = "autoresearch/orchestrator-260814-ghsa200-canonical90/xmxx_pqh8_acceptance.json"
P_FP211 = "autoresearch/orchestrator-260813-fp211-audit"
NEW_APPEND_IDENTITIES: tuple[str, ...] = ()
NEW_PACKET_AUTHORITY = (
    {
        "authority_rank": 47,
        "packet": P_NEAR,
        "role": "worker",
        "status": "TERMINAL",
        "terminal": True,
    },
    {
        "authority_rank": 48,
        "packet": P_CCB,
        "role": "worker",
        "status": "TERMINAL",
        "terminal": True,
    },
)

FROZEN = {
    "canonical88_ledger": (P_C88_LEDGER, "35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074"),
    "canonical88_summary": (P_C88_SUM, "81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921"),
    "canonical88_manifest": (P_C88_MAN, "6ae10261514f2e3ce1a0a9d7408d468f38059fcf1e17c86e591d9a8b1bf11fcd"),
    "canonical88_report": (P_C88_REP, "9f31d6891c0598e9ca9394006ff9ec39041d1d6df486625a64a2c85edfe4c7e3"),
    "canonical88_8rw6_capsule": (P_C88_CAP, "8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9"),
    "canonical85_negative_controls": (P_NEG, "c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0"),
    "contract_md": (P_CONTRACT, "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"),
    "nearclosed_assignment": (P_NEAR + "/assignment.jsonl", "f3ab6499f1b7aa2cdf72172243b3b215c5b25eeb94e5ac5941815436e61d6f85"),
    "nearclosed_cases": (P_NEAR + "/cases.jsonl", "3645fede5d364ddb006b4726e9dafcde78e0adbf62a4b96f1ec290b188da07cb"),
    "nearclosed_report": (P_NEAR + "/report.md", "507519cdb934c2ea3fa0812f2c3ebf375ef48ef1c805a5d1bd054bc8ddff1c11"),
    "nearclosed_replay": (P_NEAR + "/replay.zsh", "b6347d6373b445d3964313f53ce604dca274cc7aa144651774153cbb8c0ab1b6"),
    "nearclosed_result": (P_NEAR + "/result.json", "bb70dcfcce2253e954ffadeadece81774426c5b70b8739aba49344f21d81dcda"),
    "ccb_assignment": (P_CCB + "/assignment.jsonl", "ca98a3fb0d122a910c2295f04c04f1f17e59e89a550cdc3233b14095b63286fa"),
    "ccb_cases": (P_CCB + "/cases.jsonl", "24250aa21c24e01ddf042fe42b233e1ff2eac7a12abd0d4eb6626d0f3ec65979"),
    "ccb_report": (P_CCB + "/report.md", "0dc351caa09186d16cf715a39603c8831fdf5714a1a1c00aa1d10f6de4933969"),
    "ccb_replay": (P_CCB + "/replay.zsh", "b4e271111b4079139778b652a19619976f432964590216d0911fa54a7068000b"),
    "ccb_result": (P_CCB + "/result.json", "5c06b04888a83ea762702f4403dda0894af27c4209001d78ebc3b35c7d8c203f"),
}
LOCAL_PINS = {
    "acceptance_xmxx_pqh8": (P_CAP, "296546a64ee54ae14e89b1be0092fa26b1d8900058a744cdc16d7f37f8a4167d"),
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
    cap = load_json(HERE / "xmxx_pqh8_acceptance.json")
    assert cap["admitted_ids"] == [CASE_XMXX, CASE_PQH8]
    assert cap["excluded_from_this_promotion"] == [CASE_6C8G]
    assert cap["verdict"] == "KEEP"
    assert cap["countable_in_this_snapshot"] is True
    assert cap["leader_strict_case_accepted"] is True
    assert cap["causal_admission"] is False
    assert cap["publication_admission"] is False
    assert cap["publication_ready"] is False
    assert cap["cve_alias_is_not_a_counting_unit"] is True
    assert cap["cartesian_candidate_fix_refused"] is True
    assert cap["in_fp211_212"] is True
    assert cap["in_canonical88_strict"] is False
    assert cap["new_identities_append"] is False
    assert cap["same_id_source_layer_promoted"] is True
    assert cap["admission_source"] == "scoped_contributor_dual_keep"
    assert cap["independent_terminal_packets"] == [P_NEAR, P_CCB]
    sh = cap["source_hashes"]
    assert sh["nearclosed_b_assignment_jsonl"] == FROZEN["nearclosed_assignment"][1]
    assert sh["nearclosed_b_cases_jsonl"] == FROZEN["nearclosed_cases"][1]
    assert sh["nearclosed_b_report_md"] == FROZEN["nearclosed_report"][1]
    assert sh["nearclosed_b_replay_zsh"] == FROZEN["nearclosed_replay"][1]
    assert sh["nearclosed_b_result_json"] == FROZEN["nearclosed_result"][1]
    assert sh["causal_consensus_b_assignment_jsonl"] == FROZEN["ccb_assignment"][1]
    assert sh["causal_consensus_b_cases_jsonl"] == FROZEN["ccb_cases"][1]
    assert sh["causal_consensus_b_report_md"] == FROZEN["ccb_report"][1]
    assert sh["causal_consensus_b_replay_zsh"] == FROZEN["ccb_replay"][1]
    assert sh["causal_consensus_b_result_json"] == FROZEN["ccb_result"][1]
    assert sh["canonical88_ledger"] == FROZEN["canonical88_ledger"][1]
    assert sh["nearclosed_b_packet"] == P_NEAR
    assert sh["causal_consensus_b_packet"] == P_CCB
    xmxx = cap["cases"][CASE_XMXX]
    pqh8 = cap["cases"][CASE_PQH8]
    assert xmxx["ordinal"] == 89
    assert pqh8["ordinal"] == 90
    assert xmxx["contribution_class"] == "AI_NEW_SURFACE_CONTRIBUTOR"
    assert pqh8["contribution_class"] == "AI_NEW_SURFACE_CONTRIBUTOR"
    assert xmxx["mechanism_key"] == MECH_KEY_XMXX
    assert pqh8["mechanism_key"] == MECH_KEY_PQH8
    assert xmxx["mechanism_fingerprint"] == MECH_FP_XMXX
    assert pqh8["mechanism_fingerprint"] == MECH_FP_PQH8
    assert xmxx["candidate_set"] == [CAND_XMXX]
    assert pqh8["candidate_set"] == [CAND_PQH8]
    assert xmxx["carrier_set"] == []
    assert pqh8["carrier_set"] == []
    assert xmxx["minimum_fix_set"] == [FIX_XMXX]
    assert pqh8["minimum_fix_set"] == [FIX_PQH8]
    assert xmxx["aliases"] == [ALIAS_XMXX]
    assert pqh8["aliases"] == []
    assert xmxx["n_parents"] == 1
    assert pqh8["n_parents"] == 1
    assert xmxx["in_fp211_212"] is True
    assert pqh8["in_fp211_212"] is True
    assert xmxx["action"] == "SUPERSEDE"
    assert pqh8["action"] == "SUPERSEDE"
    assert xmxx["whole_ghsa_direct_root"] is False
    assert pqh8["whole_ghsa_direct_root"] is False
    assert all(xmxx["gates"][field] == "PASS" for field in GATES)
    assert all(pqh8["gates"][field] == "PASS" for field in GATES)
    assert xmxx["object_shas"]["candidate_parent"] == PARENT_XMXX
    assert pqh8["object_shas"]["candidate_parent"] == PARENT_PQH8
    assert xmxx["object_shas"]["fix_parent"] == FIX_PARENT_XMXX
    assert pqh8["object_shas"]["fix_parent"] == FIX_PARENT_PQH8
    assert xmxx["vulnerable_release"]["git_tag_commit"] == PEEL_XMXX_VULN
    assert xmxx["fixed_release"]["git_tag_commit"] == PEEL_XMXX_FIX
    assert pqh8["vulnerable_release"]["git_tag_commit"] == PEEL_PQH8_VULN
    assert pqh8["fixed_release"]["git_tag_commit"] == PEEL_PQH8_FIX
    assert "/v1/responses" in xmxx["scope_statement"]
    assert "startup-captured resolvedAuth" in xmxx["scope_statement"]
    assert "list-vulnerabilities.ts" in pqh8["scope_statement"]
    assert "get-events-for-cluster.ts" in pqh8["scope_statement"]
    assert "validateTimeframe" in pqh8["scope_statement"]
    assert CASE_6C8G not in cap["cases"]
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
    refs = list(case["primary_urls"]) + [P_CAP, P_NEAR, P_CCB]
    out = {
        "action": "SUPERSEDE",
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
        "in_fp211_212": True,
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
    assert SHA_RE.fullmatch(out["minimum_fix_set"][0])
    assert SHA_RE.fullmatch(out["candidate_parent"])
    assert SHA_RE.fullmatch(out["fix_parent"])
    assert out["carrier_set"] == []
    assert out["contribution_class"] == "AI_NEW_SURFACE_CONTRIBUTOR"
    assert out["whole_ghsa_direct_root"] is False
    assert out["in_fp211_212"] is True
    assert out["action"] == "SUPERSEDE"
    assert "causal_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "candidate_fix_edges" not in out
    assert CASE_6C8G not in compact_json(out)
    return out


def edge_from_case(case_id: str, edge_id: str) -> dict:
    return {
        "applies_now": True,
        "applies_to_counted_set": True,
        "authority_rank": 48,
        "case_id": case_id,
        "counted": False,
        "edge_id": edge_id,
        "failed_gate": None,
        "from_packet": P_FP211,
        "from_verdict": "NARROW",
        "note": (
            "Independent dual-packet leader admission after replay of "
            "herdr-260814-nearclosed-b-grok46-medium and "
            "herdr-260814-causal-consensus-b-grok46-xhigh. Both packets "
            "PASS_PROPOSAL at scoped AI_NEW_SURFACE_CONTRIBUTOR. fp211 NARROW "
            "is superseded. GHSA-6C8G-7P36-R338 is not promoted."
        ),
        "pending_until_to_packet_terminal": False,
        "record_kind": "SUPERSEDES_EDGE",
        "schema_version": SCHEMA,
        "source_layer": True,
        "to_packet": P_CCB,
        "to_verdict": "KEEP",
    }


def build_outputs() -> dict[Path, str]:
    pins = pin_inputs()
    cap = load_capsule()
    neg = load_negative()
    base_pairs = load_jsonl_raw(ROOT / P_C88_LEDGER)
    prior_summary = load_json(ROOT / P_C88_SUM)
    prior_manifest = load_json(ROOT / P_C88_MAN)
    base_text = (ROOT / P_C88_LEDGER).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["ledger_sha256"] == pins["canonical88_ledger"]["sha256"]
    assert sha256_bytes(base_text.encode()) == pins["canonical88_ledger"]["sha256"]
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
        CASE_XMXX,
        CASE_PQH8,
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
        ALIAS_XMXX,
    ):
        assert case_id not in base_ids
    assert CASE_XMXX in source_ids
    assert CASE_PQH8 in source_ids
    assert CASE_6C8G in source_ids
    assert CASE_8RW6 in base_ids
    assert MECH_FP_XMXX not in base_fps
    assert MECH_FP_PQH8 not in base_fps
    assert MECH_KEY_XMXX not in base_mechs
    assert MECH_KEY_PQH8 not in base_mechs

    counted_xmxx = counted_from_case(cap, CASE_XMXX)
    counted_pqh8 = counted_from_case(cap, CASE_PQH8)
    assert counted_xmxx["ordinal"] == 89
    assert counted_pqh8["ordinal"] == 90
    assert seven_pass(counted_xmxx)
    assert seven_pass(counted_pqh8)
    edge_xmxx = edge_from_case(CASE_XMXX, "E-XMXX-KEEP")
    edge_pqh8 = edge_from_case(CASE_PQH8, "E-PQH8-KEEP")
    for rec in (counted_xmxx, counted_pqh8, edge_xmxx, edge_pqh8):
        assert_no_leak(compact_json(rec))
        assert not HAN.search(compact_json(rec))

    new_lines = [
        compact_json(edge_xmxx),
        compact_json(edge_pqh8),
        compact_json(counted_xmxx),
        compact_json(counted_pqh8),
    ]
    ledger_text = base_text if base_text.endswith("\n") else base_text + "\n"
    ledger_text = ledger_text + "\n".join(new_lines) + "\n"
    records = [json.loads(line) for line in ledger_text.splitlines() if line.strip()]
    assert [line for line, _ in base_pairs] == ledger_text.splitlines()[:BASE_LEDGER_RECORDS]

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == [counted_xmxx, counted_pqh8]
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
        ALIAS_XMXX,
    ):
        assert not any(row["case_id"] == banned for row in counted_rows)

    kinds = Counter(row["record_kind"] for row in records)
    assert kinds["PRESERVED_HYPOTHESIS"] == 211
    assert kinds["PRESERVED_PUBLIC_CASE"] == 212
    assert kinds["APPEND_IDENTITY"] == 12
    assert kinds["STRICT_RELEASED_CASE"] == STRICT_COUNT
    assert kinds["PACKET_AUTHORITY"] == 18
    assert kinds["SUPERSEDES_EDGE"] == 46
    assert sum(row.get("counted") is True for row in records) == STRICT_COUNT
    assert not HAN.search(ledger_text)

    counted_ids = [row["case_id"] for row in counted_rows]
    prior_append = list(prior_summary["conservation"]["append_identities"])
    new_append = list(NEW_APPEND_IDENTITIES)
    append_identities = prior_append + new_append
    assert len(prior_append) == 18
    assert CASE_8RW6 in prior_append
    assert new_append == []
    assert append_identities == prior_append
    checkpoint = dict(prior_summary["checkpoint"])
    checkpoint["prior_strict_count"] = PRIOR_STRICT
    checkpoint["corrected_strict_count"] = STRICT_COUNT
    checkpoint["promoted_xmxx_pqh8_two"] = [CASE_XMXX, CASE_PQH8]
    checkpoint["excluded_6c8g_this_promotion"] = [CASE_6C8G]
    checkpoint["directory_name"] = "orchestrator-260814-ghsa200-canonical90"
    checkpoint["prior_directory"] = "orchestrator-260814-ghsa200-canonical88"
    checkpoint["note"] = (
        "Directory name is canonical90. Semantic target is canonical strict count 90: "
        "the prior 88 exact strict IDs plus same-id source-layer promotions of "
        "GHSA-XMXX-7P24-H892 at ordinal 89 and GHSA-PQH8-P93P-2RX7 at ordinal 90. "
        "Source conservation remains 211 hypotheses and 212 GHSA cases. Both IDs "
        "already exist in the 212 source layer, so they SUPERSEDE matching NARROW "
        "hypotheses (same_id_source_layer_promoted=true, new_identities_append=false). "
        "Counted class is AI_NEW_SURFACE_CONTRIBUTOR on the scoped surfaces only. "
        "GHSA-6C8G-7P36-R338 is excluded from this promotion. Negative-control REJECT "
        "identities are not counted. Publication and integration stay closed. "
        "Greater-than-200 remains unsupported."
    )
    excluded = dict(prior_summary["excluded"])
    excluded[CASE_6C8G] = (
        "Independent dual-packet reopen REJECT at ai_hunk_gate: Copilot 8b95e0a7 "
        "adds WriteToDirectoryAsync, not advisory-named WriteToDirectoryAsyncInternal. "
        "Human b501bac5 later adds IAsyncArchiveExtensions.cs as a new file. Not promoted."
    )
    excluded[ALIAS_XMXX] = "alias of GHSA-XMXX-7P24-H892; not a counting unit"
    excluded["whole_ghsa_direct_root_xmxx"] = (
        "GHSA-XMXX whole-GHSA direct root is not counted; parent Chat Completions "
        "stale snapshot remains out of scope"
    )
    excluded["parent_chat_completions_xmxx"] = (
        "Parent Chat Completions HTTP and WebSocket upgrade capture are older; not counted"
    )
    excluded["whole_ghsa_direct_root_pqh8"] = (
        "GHSA-PQH8 whole-GHSA direct root is not counted; only list-vulnerabilities "
        "and get-events-for-cluster timeframe interpolations are counted"
    )
    excluded["parent_list_problems_pqh8"] = (
        "Parent additionalFilter, clusterId, list-problems, and list-exceptions stay out of scope"
    )
    excluded["cartesian_candidate_fix_edges"] = (
        excluded["cartesian_candidate_fix_edges"]
        + "; XMXX binds f4b03599f0 to acd4e0a32f with empty carrier_set"
        + "; PQH8 binds 66ff2a7c8b to 15d3546c06 with empty carrier_set"
    )
    counts = dict(prior_summary["counts"])
    counts["strict_released_first_party_ghsa"] = STRICT_COUNT
    counts["ledger_records"] = len(records)
    counts["keep_xmxx"] = 1
    counts["keep_pqh8"] = 1
    counts["excluded_6c8g_this_promotion"] = 1
    counts["by_record_kind"] = dict(kinds)
    counts["by_admission_source"] = dict(Counter(row["admission_source"] for row in counted_rows))
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical90-hold",
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
            "HOLD snapshot of canonical strict count 90 first-party GHSA identities: "
            "the prior 88 plus GHSA-XMXX-7P24-H892 and GHSA-PQH8-P93P-2RX7. Source "
            "conservation remains 211 hypotheses and 212 GHSA cases. This does not "
            "support a greater-than-200 claim. Publication and integration stay closed."
        ),
        "conservation": {
            "fp211_hypotheses": 211,
            "fp211_source_ghsa_cases": 212,
            "cve_aliases_counted": False,
            "upgrades_append": False,
            "new_identities_append": False,
            "same_id_source_layer_promoted": True,
            "promoted_same_id_identities": [CASE_XMXX, CASE_PQH8],
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
            "# Canonical90 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 90 first-party GHSA identities. It extends the frozen canonical88 snapshot in orchestrator-260814-ghsa200-canonical88 by promoting exactly two leader-accepted same-id identities. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical88 meaning and are not flipped by counting GHSA-XMXX or GHSA-PQH8. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical88 ledger row is preserved byte-for-byte and in order. The prior 88 counted rows stay byte-identical. Two SUPERSEDES_EDGE records then two STRICT_RELEASED_CASE records are appended. Count is by first-party GHSA identity once. CVE aliases are stored and never counted. GHSA-XMXX stores CVE-2026-43585 as an alias. GHSA-PQH8 has no CVE alias.",
            "",
            "The admitted identity at ordinal 89 is GHSA-XMXX-7P24-H892, repository openclaw/openclaw, class AI_NEW_SURFACE_CONTRIBUTOR. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. Counted surface is only the AI-added POST /v1/responses Gateway HTTP handler that used startup-captured resolvedAuth. Parent 7f6e87e9 lacks src/gateway/openresponses-http.ts. Candidate f4b03599 adds that file and dispatches handleOpenResponsesHttpRequest with captured resolvedAuth. carrier_set is empty. minimum_fix_set is acd4e0a3, which calls getResolvedAuth() per request. Whole-GHSA direct root is excluded. Parent Chat Completions HTTP and WebSocket upgrade capture are excluded. Public GitHub tag v2026.4.14 contains the candidate and excludes the fix. Public tag v2026.4.15 contains the fix. Mechanism key and fingerprint are unique versus canonical88.",
            "",
            "The admitted identity at ordinal 90 is GHSA-PQH8-P93P-2RX7, repository dynatrace-oss/dynatrace-mcp, class AI_NEW_SURFACE_CONTRIBUTOR. Counted surface is only the Copilot-added unvalidated timeframe interpolations on list-vulnerabilities.ts and get-events-for-cluster.ts. Parent c1119112 lacks that param on those two files. Candidate 66ff2a7c adds it. carrier_set is empty. minimum_fix_set is 15d3546c, which calls validateTimeframe. Parent additionalFilter, clusterId, list-problems, and list-exceptions stay out of scope. Public GitHub tag v2.1.0 contains the candidate and excludes the fix. Public tag v2.1.1 contains the fix. Supporting earlier tag v1.2.0 also contains the candidate. Mechanism key and fingerprint are unique versus canonical88.",
            "",
            "Admission evidence pins both independent terminal packets herdr-260814-nearclosed-b-grok46-medium and herdr-260814-causal-consensus-b-grok46-xhigh, including assignment, cases, report, replay, and result hashes. Worker PASS remains proposal-only until this leader snapshot. GHSA-6C8G-7P36-R338 is explicitly excluded from this promotion after dual-packet REJECT at ai_hunk_gate. Inherited negative controls remain rejected and absent from strict rows.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer. Same-id upgrades still do not append. GHSA-XMXX and GHSA-PQH8 are source-layer promotions (in_fp211_212=true, action=SUPERSEDE). Conservation prior_append_identities stays the prior 18. new_append_identities is empty. append_identities stays those 18. new_identities_append is false. same_id_source_layer_promoted is true. The two worker packets admit these rows at authority ranks 47 and 48. Discovery tabs and worker-only PASS are not loaded. Raw pages, crates, and owned clones are not committed; the builder consumes xmxx_pqh8_acceptance.json plus immutable canonical88 tracked artifacts and the two pinned packets.",
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
    assert CASE_XMXX in report
    assert CASE_PQH8 in report
    assert CASE_6C8G in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "new_identities_append is false" in report
    assert "same_id_source_layer_promoted is true" in report
    assert "AI_NEW_SURFACE_CONTRIBUTOR" in report
    inherited_authority = [dict(item) for item in prior_manifest["packet_authority"]]
    packet_authority = inherited_authority + [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert len(inherited_authority) == 25
    assert inherited_authority[-1]["authority_rank"] == 46
    assert packet_authority[-2]["authority_rank"] == 47
    assert packet_authority[-1]["authority_rank"] == 48
    assert packet_authority[-2]["packet"] == P_NEAR
    assert packet_authority[-1]["packet"] == P_CCB
    assert len(packet_authority) == 27
    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical90-hold",
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
        print("PASS: canonical90 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
