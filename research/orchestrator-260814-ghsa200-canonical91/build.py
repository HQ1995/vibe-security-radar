#!/usr/bin/env python3
"""Build the HOLD canonical91-directory snapshot at strict count 91. Stdlib only.

Consumes the local 5WP8 capsule plus immutable canonical90 tracked artifacts.
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
PRIOR_STRICT = 90
STRICT_COUNT = 91
BASE_LEDGER_RECORDS = 589
LEDGER_RECORDS = 591
CASE_5WP8 = "GHSA-5WP8-Q9MX-8JX8"
CASE_2QRV = "GHSA-2QRV-RC5X-2G2H"
CASE_R5JH = "GHSA-R5JH-Q2MW-GCX4"
CASE_46Q5 = "GHSA-46Q5-G3J9-WX5C"
CASE_J8Q9 = "GHSA-J8Q9-R9PQ-2HH9"
CASE_XMXX = "GHSA-XMXX-7P24-H892"
CASE_PQH8 = "GHSA-PQH8-P93P-2RX7"
CASE_6C8G = "GHSA-6C8G-7P36-R338"
CASE_8RW6 = "GHSA-8RW6-P7M8-63JP"
CASE_V52W = "GHSA-V52W-28XH-V562"
CAND_5WP8 = "1712debbea60af6adf4a8a5939a43f7ef9a1ac16"
CARR_5WP8 = CAND_5WP8
PARENT_5WP8 = "c5bd830cd8969336f03a87f416d2ac7b4d244be2"
FIX_5WP8 = "68916c3e4f3af107f11940b27854fc7ef517058b"
FIX_PARENT_5WP8 = "fda2f10c3ee4df20ec58bb6b112baa6cbda318bf"
MEM_5WP8 = "3c4368da0ab48c1091858d3f9503c378a209997f"
BLK_5WP8 = "91f6c2bf98e40238ad4d175513f0ee400fd62068"
MECH_KEY_5WP8 = "zeptoclaw.shell.allowlist.empty-strict-passthrough"
MECH_FP_5WP8 = "zeptoclaw.shell.allowlist.empty-strict-passthrough"
PEEL_5WP8_VULN = "ad14ed8d4e6f982af272523f4accc107b191fb18"
PEEL_5WP8_FIX = "f052aa21f298559729aa19b770da988f00a193df"
PEEL_5WP8_058 = "fe2ef07cfec5bb46b42cdd65f52b9230c03e9270"
BLOB_PARENT_5WP8 = "d82f28d314d572dc685c15ede7b8aeaa3b0fe8ae"
BLOB_CAND_5WP8 = "165b10b5034f1782eb84ad8e97834581c07bddc4"
BLOB_MEM_5WP8 = "a09e61719a32cb101160796755f777787007bdc6"
BLOB_VULN_5WP8 = "87b9d900ab6e3a3504908518c1f62270ccb0cc97"
BLOB_FIX_5WP8 = "d923a585eb91f1cd6fb2c9e16874f64f14cab5b6"
CRATE_061 = "6df2cb167c5333e6152cc64bf14c8d4af1492aea5778fe6bf2870a418590aaf5"
CRATE_062 = "1b834e0d7e0079342c339abb8620a7aca51cf22a330a8a754d0095a4da57cdb0"
FILE_5WP8 = "src/security/shell.rs"
SKIP_5WP8 = "allowlist_mode != ShellAllowlistMode::Off && !self.allowlist.is_empty()"
AI_MARKER_5WP8 = "Co-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>"
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
ADMITTED = (CASE_5WP8,)

P_C90 = "autoresearch/orchestrator-260814-ghsa200-canonical90"
P_C90_LEDGER = P_C90 + "/ledger.jsonl"
P_C90_SUM = P_C90 + "/summary.json"
P_C90_MAN = P_C90 + "/manifest.json"
P_C90_REP = P_C90 + "/report.md"
P_C90_CAP = P_C90 + "/xmxx_pqh8_acceptance.json"
P_NEG = "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json"
P_CONTRACT = "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
P_NEAR = "autoresearch/herdr-260814-nearclosed-e-grok46-high"
P_HOSTILE = "autoresearch/herdr-260814-5wp8-hostile-redteam-grok46-high"
P_CAP = "autoresearch/orchestrator-260814-ghsa200-canonical91/5wp8_acceptance.json"
P_FP211 = "autoresearch/orchestrator-260813-fp211-audit"
P_PUBLIC = P_FP211 + "/public_cases.jsonl"
P_TRUTH = "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md"
NEW_APPEND_IDENTITIES: tuple[str, ...] = ()
NEW_PACKET_AUTHORITY = (
    {
        "authority_rank": 49,
        "packet": P_NEAR,
        "role": "worker",
        "status": "TERMINAL",
        "terminal": True,
    },
    {
        "authority_rank": 50,
        "packet": P_HOSTILE,
        "role": "redteam",
        "status": "TERMINAL",
        "terminal": True,
    },
)

FROZEN = {
    "canonical90_ledger": (P_C90_LEDGER, "daf706e14d514ad62d197e61aa8ec7f52eefd958bc19a4a7c58591a0be8654ec"),
    "canonical90_summary": (P_C90_SUM, "5222879219a975fa4388f3f07f5c62cd6687a642b6509afe48a4250fb4be81ef"),
    "canonical90_manifest": (P_C90_MAN, "2ca55ae4b266a6a8dd80389fb194eebffd61e4ec17949a0eeb123ee17f52d2ac"),
    "canonical90_report": (P_C90_REP, "12e789b88b972563885c52e3279e01dfb37982a0f7d3fdb6ecf06eb05735519e"),
    "canonical90_xmxx_pqh8_capsule": (P_C90_CAP, "296546a64ee54ae14e89b1be0092fa26b1d8900058a744cdc16d7f37f8a4167d"),
    "canonical85_negative_controls": (P_NEG, "c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0"),
    "contract_md": (P_CONTRACT, "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"),
    "fp211_public_cases": (P_PUBLIC, "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257"),
    "research_truth_layers": (P_TRUTH, "70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f"),
    "nearclosed_assignment": (P_NEAR + "/assignment.jsonl", "756d450c8529065467fdbd6b075aebca3ebd448d10afca49581c0b1bc05f8c6a"),
    "nearclosed_cases": (P_NEAR + "/cases.jsonl", "c11ac29971f8fd4836a21ce60f8ce657f3fdd43eba3eaa8cb1e413377583628f"),
    "nearclosed_report": (P_NEAR + "/report.md", "0f4d52727c2753adc82e0f5b1f2d7fbb6bf274dd62bdcd25df3a50059f848e9a"),
    "nearclosed_replay": (P_NEAR + "/replay.zsh", "6b2e145b6b132f96f4e06c7f01f6db9a34a3af10c5da030bf0e2268de1fbbdfb"),
    "nearclosed_result": (P_NEAR + "/result.json", "571765397f5729cd115d852cc20e6e5f925fb4df96668bf129798e46b0a95c74"),
    "hostile_assignment": (P_HOSTILE + "/assignment.jsonl", "94aae563c0a53e24911930bac0c7f5e33c7d79faec0e0a85ee42830bf0c7a3b7"),
    "hostile_cases": (P_HOSTILE + "/cases.jsonl", "832900b9ed2521d6858ff5670c7d8afbae8a46b42d7bf5fcef52b07f095a66d5"),
    "hostile_report": (P_HOSTILE + "/report.md", "5655fb1cbb72e53ca8b4d0c75b0ae02002e3abd9e8097bd4e0b7cf3f8e3b56d1"),
    "hostile_replay": (P_HOSTILE + "/replay.zsh", "fb244c18ddb6c331fdc2f969e4aedd8193c8d4adef2c400161c6423371dd72dd"),
    "hostile_result": (P_HOSTILE + "/result.json", "d31aa8c08f367301b0a74133169f230851372082b5daaac220dd33934480124b"),
}
LOCAL_PINS = {
    "acceptance_5wp8": (P_CAP, "6d018b39328389c8a6b78d6b4c03ce3b30f42b04d53464090ebb370fc59bf8b9"),
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
    cap = load_json(HERE / "5wp8_acceptance.json")
    assert cap["admitted_ids"] == [CASE_5WP8]
    assert cap["excluded_from_this_promotion"] == [CASE_2QRV, CASE_R5JH]
    assert cap["verdict"] == "KEEP"
    assert cap["countable_in_this_snapshot"] is True
    assert cap["leader_strict_case_accepted"] is True
    assert cap["causal_admission"] is False
    assert cap["publication_admission"] is False
    assert cap["publication_ready"] is False
    assert cap["cve_alias_is_not_a_counting_unit"] is True
    assert cap["cartesian_candidate_fix_refused"] is True
    assert cap["in_fp211_212"] is True
    assert cap["in_canonical90_strict"] is False
    assert cap["new_identities_append"] is False
    assert cap["same_id_source_layer_promoted"] is True
    assert cap["admission_source"] == "incomplete_remediation_dual_keep"
    assert cap["patch_delta_incomplete_remediation"] is True
    assert cap["independent_terminal_packets"] == [P_NEAR, P_HOSTILE]
    sh = cap["source_hashes"]
    assert sh["nearclosed_e_assignment_jsonl"] == FROZEN["nearclosed_assignment"][1]
    assert sh["nearclosed_e_cases_jsonl"] == FROZEN["nearclosed_cases"][1]
    assert sh["nearclosed_e_report_md"] == FROZEN["nearclosed_report"][1]
    assert sh["nearclosed_e_replay_zsh"] == FROZEN["nearclosed_replay"][1]
    assert sh["nearclosed_e_result_json"] == FROZEN["nearclosed_result"][1]
    assert sh["hostile_assignment_jsonl"] == FROZEN["hostile_assignment"][1]
    assert sh["hostile_cases_jsonl"] == FROZEN["hostile_cases"][1]
    assert sh["hostile_report_md"] == FROZEN["hostile_report"][1]
    assert sh["hostile_replay_zsh"] == FROZEN["hostile_replay"][1]
    assert sh["hostile_result_json"] == FROZEN["hostile_result"][1]
    assert sh["canonical90_ledger"] == FROZEN["canonical90_ledger"][1]
    assert sh["canonical90_summary"] == FROZEN["canonical90_summary"][1]
    assert sh["canonical90_manifest"] == FROZEN["canonical90_manifest"][1]
    assert sh["canonical90_report"] == FROZEN["canonical90_report"][1]
    assert sh["fp211_public_cases_jsonl"] == FROZEN["fp211_public_cases"][1]
    assert sh["research_truth_layers_md"] == FROZEN["research_truth_layers"][1]
    assert sh["nearclosed_e_packet"] == P_NEAR
    assert sh["hostile_packet"] == P_HOSTILE
    case = cap["cases"][CASE_5WP8]
    assert case["ordinal"] == 91
    assert case["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert case["mechanism_key"] == MECH_KEY_5WP8
    assert case["mechanism_fingerprint"] == MECH_FP_5WP8
    assert case["candidate_set"] == [CAND_5WP8]
    assert case["carrier_set"] == [CARR_5WP8]
    assert case["minimum_fix_set"] == [FIX_5WP8]
    assert case["aliases"] == []
    assert case["n_parents"] == 1
    assert case["in_fp211_212"] is True
    assert case["action"] == "SUPERSEDE"
    assert case["whole_ghsa_direct_root"] is False
    assert case["patch_delta_incomplete_remediation"] is True
    assert case["member_3c4368da_not_transferred"] is True
    assert case["blocklist_91f6c2bf_not_counted"] is True
    assert case["hhjv_not_merged"] is True
    assert all(case["gates"][field] == "PASS" for field in GATES)
    assert case["object_shas"]["candidate_parent"] == PARENT_5WP8
    assert case["object_shas"]["carrier_parent"] == PARENT_5WP8
    assert case["object_shas"]["counted_carrier"] == CARR_5WP8
    assert case["object_shas"]["fix_parent"] == FIX_PARENT_5WP8
    assert case["object_shas"]["non_ancestor_member"] == MEM_5WP8
    assert case["object_shas"]["blocklist_member"] == BLK_5WP8
    assert case["vulnerable_release"]["git_tag_commit"] == PEEL_5WP8_VULN
    assert case["fixed_release"]["git_tag_commit"] == PEEL_5WP8_FIX
    assert case["vulnerable_release"]["crates_io_zeptoclaw_checksum"] == CRATE_061
    assert case["fixed_release"]["crates_io_zeptoclaw_checksum"] == CRATE_062
    assert "empty-strict" in case["scope_statement"]
    assert "1712debb" in case["scope_statement"]
    assert "3c4368da" in case["scope_statement"]
    assert CASE_2QRV not in cap["cases"]
    assert CASE_R5JH not in cap["cases"]
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
    assert SHA_RE.fullmatch(out["carrier_set"][0])
    assert SHA_RE.fullmatch(out["minimum_fix_set"][0])
    assert SHA_RE.fullmatch(out["candidate_parent"])
    assert SHA_RE.fullmatch(out["fix_parent"])
    assert out["candidate_set"] == [CAND_5WP8]
    assert out["carrier_set"] == [CARR_5WP8]
    assert out["candidate_set"] == out["carrier_set"]
    assert out["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert out["whole_ghsa_direct_root"] is False
    assert out["in_fp211_212"] is True
    assert out["action"] == "SUPERSEDE"
    assert MEM_5WP8 not in out["candidate_set"]
    assert MEM_5WP8 not in out["carrier_set"]
    assert BLK_5WP8 not in out["candidate_set"]
    assert "causal_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "candidate_fix_edges" not in out
    assert CASE_2QRV not in compact_json(out)
    assert CASE_R5JH not in compact_json(out)
    return out


def edge_from_case(case_id: str, edge_id: str) -> dict:
    return {
        "applies_now": True,
        "applies_to_counted_set": True,
        "authority_rank": 50,
        "case_id": case_id,
        "counted": False,
        "edge_id": edge_id,
        "failed_gate": None,
        "from_packet": P_FP211,
        "from_verdict": "NARROW",
        "note": (
            "Independent dual-packet leader admission after replay of "
            "herdr-260814-nearclosed-e-grok46-high and "
            "herdr-260814-5wp8-hostile-redteam-grok46-high. Both packets "
            "PASS_PROPOSAL at AI_INCOMPLETE_REMEDIATION on squash 1712debb. "
            "fp211 NARROW is superseded. Member 3c4368da is not transferred. "
            "GHSA-2QRV-RC5X-2G2H and GHSA-R5JH-Q2MW-GCX4 are not promoted."
        ),
        "pending_until_to_packet_terminal": False,
        "record_kind": "SUPERSEDES_EDGE",
        "schema_version": SCHEMA,
        "source_layer": True,
        "to_packet": P_HOSTILE,
        "to_verdict": "KEEP",
    }


def build_outputs() -> dict[Path, str]:
    pins = pin_inputs()
    cap = load_capsule()
    neg = load_negative()
    base_pairs = load_jsonl_raw(ROOT / P_C90_LEDGER)
    prior_summary = load_json(ROOT / P_C90_SUM)
    prior_manifest = load_json(ROOT / P_C90_MAN)
    base_text = (ROOT / P_C90_LEDGER).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["ledger_sha256"] == pins["canonical90_ledger"]["sha256"]
    assert sha256_bytes(base_text.encode()) == pins["canonical90_ledger"]["sha256"]
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
        CASE_5WP8,
        CASE_2QRV,
        CASE_R5JH,
        CASE_J8Q9,
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
    ):
        assert case_id not in base_ids
    assert CASE_5WP8 in source_ids
    assert CASE_2QRV in source_ids
    assert CASE_R5JH in source_ids
    assert CASE_46Q5 in base_ids
    assert CASE_XMXX in base_ids
    assert CASE_PQH8 in base_ids
    assert CASE_8RW6 in base_ids
    assert MECH_FP_5WP8 not in base_fps
    assert MECH_KEY_5WP8 not in base_mechs

    counted_5wp8 = counted_from_case(cap, CASE_5WP8)
    assert counted_5wp8["ordinal"] == 91
    assert seven_pass(counted_5wp8)
    edge_5wp8 = edge_from_case(CASE_5WP8, "E-5WP8-KEEP")
    for rec in (counted_5wp8, edge_5wp8):
        assert_no_leak(compact_json(rec))
        assert not HAN.search(compact_json(rec))

    new_lines = [
        compact_json(edge_5wp8),
        compact_json(counted_5wp8),
    ]
    ledger_text = base_text if base_text.endswith("\n") else base_text + "\n"
    ledger_text = ledger_text + "\n".join(new_lines) + "\n"
    records = [json.loads(line) for line in ledger_text.splitlines() if line.strip()]
    assert [line for line, _ in base_pairs] == ledger_text.splitlines()[:BASE_LEDGER_RECORDS]

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == [counted_5wp8]
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
    ):
        assert not any(row["case_id"] == banned for row in counted_rows)

    kinds = Counter(row["record_kind"] for row in records)
    assert kinds["PRESERVED_HYPOTHESIS"] == 211
    assert kinds["PRESERVED_PUBLIC_CASE"] == 212
    assert kinds["APPEND_IDENTITY"] == 12
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
    assert CASE_8RW6 in prior_append
    assert new_append == []
    assert append_identities == prior_append
    checkpoint = dict(prior_summary["checkpoint"])
    checkpoint["prior_strict_count"] = PRIOR_STRICT
    checkpoint["corrected_strict_count"] = STRICT_COUNT
    checkpoint["promoted_5wp8_one"] = [CASE_5WP8]
    checkpoint["excluded_2qrv_r5jh_this_promotion"] = [CASE_2QRV, CASE_R5JH]
    checkpoint["directory_name"] = "orchestrator-260814-ghsa200-canonical91"
    checkpoint["prior_directory"] = "orchestrator-260814-ghsa200-canonical90"
    checkpoint["note"] = (
        "Directory name is canonical91. Semantic target is canonical strict count 91: "
        "the prior 90 exact strict IDs plus same-id source-layer promotion of "
        "GHSA-5WP8-Q9MX-8JX8 at ordinal 91. Source conservation remains 211 "
        "hypotheses and 212 GHSA cases. The ID already exists in the 212 source "
        "layer, so it SUPERSEDES the matching NARROW hypothesis "
        "(same_id_source_layer_promoted=true, new_identities_append=false). "
        "Counted class is AI_INCOMPLETE_REMEDIATION on the empty-strict allowlist "
        "skip only. Candidate and carrier are squash 1712debb. Member 3c4368da is "
        "not transferred. GHSA-2QRV-RC5X-2G2H and GHSA-R5JH-Q2MW-GCX4 are excluded "
        "from this promotion. Negative-control REJECT identities are not counted. "
        "Publication and integration stay closed. Greater-than-200 remains unsupported."
    )
    excluded = dict(prior_summary["excluded"])
    excluded[CASE_2QRV] = (
        "Independent nearclosed-e NARROW: squash onlyPluginIds snapshots are not "
        "the named setup-shadow catalog resolution. Not promoted."
    )
    excluded[CASE_R5JH] = (
        "Independent nearclosed-e NARROW: parent already defined HasPrefix "
        "SanitizeFilePath plus Handler/fetcher callers. Not promoted."
    )
    excluded[CASE_J8Q9] = "distinct zeptoclaw SSRF identity; not this empty-strict allowlist residual; not counted"
    excluded["member_3c4368da_5wp8"] = (
        "Non-ancestor Claude member 3c4368da authors a side-branch empty-skip; "
        "not transferred onto squash 1712debb"
    )
    excluded["blocklist_91f6c2bf_5wp8"] = (
        "Ancestor 91f6c2bf authors the older blocklist and has no allowlist; not this residual"
    )
    excluded["sibling_first_token_regex_glob_5wp8"] = (
        "GHSA-5WP8 sibling first-token, regex, and glob vectors stay out of scope"
    )
    excluded["whole_ghsa_direct_root_5wp8"] = (
        "GHSA-5WP8 whole-GHSA direct root is not counted; only the AI-added "
        "empty-strict allowlist skip is counted"
    )
    excluded["shared_closer_hhjv_5wp8"] = (
        "Closer 68916c3e also names GHSA-HHJV Android device_shell; shared SHA "
        "is not duplication; HHJV remains a negative-control REJECT"
    )
    excluded["cartesian_candidate_fix_edges"] = (
        excluded["cartesian_candidate_fix_edges"]
        + "; 5WP8 binds 1712debbea as candidate and carrier to 68916c3e4f"
    )
    counts = dict(prior_summary["counts"])
    counts["strict_released_first_party_ghsa"] = STRICT_COUNT
    counts["ledger_records"] = len(records)
    counts["keep_5wp8"] = 1
    counts["excluded_2qrv_this_promotion"] = 1
    counts["excluded_r5jh_this_promotion"] = 1
    counts["by_record_kind"] = dict(kinds)
    counts["by_admission_source"] = dict(Counter(row["admission_source"] for row in counted_rows))
    uniqueness = {
        "strict_ids_unique": True,
        "mechanism_keys_unique": True,
        "mechanism_fingerprints_unique": True,
        "promoted_id": CASE_5WP8,
        "absent_from_prior_strict": True,
        "distinct_from_counted_46q5": True,
        "distinct_from_negative_hhjv": True,
        "distinct_from_j8q9": True,
        "shared_closer_sha_not_duplication": True,
        "member_3c4368da_not_transferred": True,
        "blocklist_91f6c2bf_not_counted": True,
        "2qrv_not_promoted": True,
        "r5jh_not_promoted": True,
        "cve_aliases_counted": False,
    }
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical91-hold",
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
            "HOLD snapshot of canonical strict count 91 first-party GHSA identities: "
            "the prior 90 plus GHSA-5WP8-Q9MX-8JX8. Source conservation remains 211 "
            "hypotheses and 212 GHSA cases. This does not support a greater-than-200 "
            "claim. Publication and integration stay closed."
        ),
        "conservation": {
            "fp211_hypotheses": 211,
            "fp211_source_ghsa_cases": 212,
            "cve_aliases_counted": False,
            "upgrades_append": False,
            "new_identities_append": False,
            "same_id_source_layer_promoted": True,
            "promoted_same_id_identities": [CASE_5WP8],
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
            "# Canonical91 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 91 first-party GHSA identities. It extends the frozen canonical90 snapshot in orchestrator-260814-ghsa200-canonical90 by promoting exactly one leader-accepted same-id identity. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical90 meaning and are not flipped by counting GHSA-5WP8. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical90 ledger row is preserved byte-for-byte and in order. The prior 90 counted rows stay byte-identical. One SUPERSEDES_EDGE record then one STRICT_RELEASED_CASE record is appended. Count is by first-party GHSA identity once. CVE aliases are stored and never counted. GHSA-5WP8 has no CVE alias.",
            "",
            "The admitted identity at ordinal 91 is GHSA-5WP8-Q9MX-8JX8, repository qhkm/zeptoclaw, class AI_INCOMPLETE_REMEDIATION. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. Counted surface is only the AI-added ShellAllowlistMode empty-strict passthrough residual in src/security/shell.rs. Parent c5bd830c lacks ShellAllowlistMode and allowlist.is_empty. Candidate and carrier are squash 1712debb, which adds the allowlist and the empty-strict skip. n_parents is 1. Member 3c4368da is not an ancestor of the squash, of v0.6.1, or of closer 68916c3e and is not transferred. Blocklist member 91f6c2bf is an ancestor with no allowlist and is not counted. minimum_fix_set is 68916c3e, parent fda2f10c, which removes the empty skip. Whole-GHSA direct root is excluded. Sibling first-token, regex, and glob vectors are excluded. Shared closer SHA with negative-control GHSA-HHJV is not duplication. Public GitHub tag v0.6.1 contains the candidate and excludes the fix. Public tag v0.6.2 contains the fix. crates.io zeptoclaw 0.6.1 / 0.6.2 checksums are pinned and not yanked. Mechanism key and fingerprint are unique versus canonical90. Uniqueness versus counted GHSA-46Q5 and versus GHSA-J8Q9 is explicit.",
            "",
            "Admission evidence pins both independent terminal packets herdr-260814-nearclosed-e-grok46-high and herdr-260814-5wp8-hostile-redteam-grok46-high, including assignment, cases, report, replay, and result hashes, plus fp211 public_cases.jsonl and RESEARCH-TRUTH-LAYERS source manifests. Worker PASS remains proposal-only until this leader snapshot. GHSA-2QRV-RC5X-2G2H and GHSA-R5JH-Q2MW-GCX4 are explicitly excluded from this promotion after nearclosed-e NARROW. Inherited negative controls remain rejected and absent from strict rows.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer. Same-id upgrades still do not append. GHSA-5WP8 is a source-layer promotion (in_fp211_212=true, action=SUPERSEDE). Conservation prior_append_identities stays the prior 18. new_append_identities is empty. append_identities stays those 18. new_identities_append is false. same_id_source_layer_promoted is true. The two worker packets admit this row at authority ranks 49 and 50. Discovery tabs and worker-only PASS are not loaded. Raw pages, crates, and owned clones are not committed; the builder consumes 5wp8_acceptance.json plus immutable canonical90 tracked artifacts and the two pinned packets.",
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
    assert CASE_5WP8 in report
    assert CASE_2QRV in report
    assert CASE_R5JH in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "new_identities_append is false" in report
    assert "same_id_source_layer_promoted is true" in report
    assert "AI_INCOMPLETE_REMEDIATION" in report
    assert "Uniqueness versus counted GHSA-46Q5" in report
    inherited_authority = [dict(item) for item in prior_manifest["packet_authority"]]
    packet_authority = inherited_authority + [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert len(inherited_authority) == 27
    assert inherited_authority[-1]["authority_rank"] == 48
    assert packet_authority[-2]["authority_rank"] == 49
    assert packet_authority[-1]["authority_rank"] == 50
    assert packet_authority[-2]["packet"] == P_NEAR
    assert packet_authority[-1]["packet"] == P_HOSTILE
    assert len(packet_authority) == 29
    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical91-hold",
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
        print("PASS: canonical91 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
