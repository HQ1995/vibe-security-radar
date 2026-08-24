#!/usr/bin/env python3
"""Build the HOLD canonical82-directory snapshot at strict count 82. Stdlib only.

Consumes the local curated capsules plus immutable canonical81 tracked artifacts.
Does not read raw API pages, worker caches, or owned clones.
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
REMEDIATION_GATE = "remediation_patch_delta_gate"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
HAN = re.compile(r"[\u3400-\u9fff]")
PRIOR_STRICT = 81
STRICT_COUNT = 82
CASE_QF5V = "GHSA-QF5V-M7P4-95RP"
CASE_M63V = "GHSA-M63V-2G9W-2W6V"
CASE_PIMCORE = "GHSA-2MHJ-FHVG-V428"
ALIAS_QF5V = "CVE-2026-50570"
CAND_QF5V = "e484df8460bb4e8026e24210120602aa7f181f64"
PARENT_QF5V = "8fa799417c77ce8a0189d9858bfe11ece29b84a6"
MEMBER_QF5V = "2db76f65dbfe4f657b4a4efb506ed63b24623e92"
FIX_QF5V = "2569b42bfadbcb7d78b55a00a60f77937e522699"
MECH_KEY = "fission.podspec_safety.dangerousCapabilities.omitted-SYS_TIME"
MECH_FP = "fission.pkg.apis.core.v1.podspec_safety.dangerousCapabilities.six-cap-denylist.omits-SYS_TIME"
MAP_SHA = "ad325615ca2257b65de131f8b48fe673c8f8f174b5b0dcb22f167bbe361f8b88"
VULN_PEEL = "ce617120c41b9e4a51d577f81b441238264e88fd"
FIX_PEEL = "ae970aaa9bc76ec93d748bdaf03fd7523b6b6a62"
BLOB_V124 = "1d7219e7f592cc6ea631866328820475617141bd"
BLOB_FIX = "43e361d3ab7bf4145f704e23d8654256444c1e86"
EXCLUDE_NARROW = "GHSA-7C3W-FXGH-FRC7"
EXCLUDE_F38V = "GHSA-F38V-77QJ-H4JQ"
EXCLUDE_4FXP = "GHSA-4FXP-2M36-QV64"
EXCLUDE_XW57 = "GHSA-XW57-23P8-9WC5"
EXCLUDE_QCR8 = "GHSA-QCR8-X557-7CP3"
EXCLUDE_GOPACKET = "GHSA-6R28-9PPF-4HJ5"
CASE_Q855 = "GHSA-Q855-8RH5-JFGQ"
B3_KEEP = ("GHSA-G3XQ-3GMV-QQ8G", "GHSA-PV2J-RGHR-V5R9")
FILEBROWSER_NEG = "post:filebrowser-delete-scope@canonical"
FILEBROWSER_POS = "post:filebrowser-dangling-write@canonical"
ORD200 = ("GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7")
HUMAN_PIMCORE = "e96631216bb439896cc5979ed9f2850eaf28d2f4"
SQUASH_PIMCORE = "dbe1d131e49421eee5a427f1ae0dec5735639ff3"

P_C81 = "autoresearch/orchestrator-260814-ghsa200-canonical81"
P_C81_LEDGER = P_C81 + "/ledger.jsonl"
P_C81_SUM = P_C81 + "/summary.json"
P_C81_MAN = P_C81 + "/manifest.json"
P_QF5V_PKT = "autoresearch/herdr-260814-ghsa200-qf5v-redteam-grok46-high"
P_CONFIRM11 = "autoresearch/herdr-260814-ghsa200-fp211-confirm11-closure-grok46-medium"
P_PIMCORE_PKT = "autoresearch/herdr-260814-ghsa200-pimcore-2mhj-counterredteam-grok46-xhigh"
P_CAPSULE = "autoresearch/orchestrator-260814-ghsa200-canonical82/qf5v_acceptance.json"
P_NEG = "autoresearch/orchestrator-260814-ghsa200-canonical82/negative_controls.json"

FROZEN = {
    "canonical81_ledger": (P_C81_LEDGER, "3cda5bfe3ed6f94e680b78cd125fbd40db3b17ac0d02051475e7ff65b0ff0de9"),
    "canonical81_summary": (P_C81_SUM, "dc53b9558ca7066d4eba3b28d3e52db95ec2fb2384d63822bbea1bc04d0a4c6c"),
    "canonical81_manifest": (P_C81_MAN, "7805c1285bf99dd7e945bc75867a3ce3ec285bcb1f1e4751017c01f38682b2df"),
}
LOCAL_PINS = {
    "qf5v_acceptance": (P_CAPSULE, "267c13464ca042ed0a2fefa8ab988615ec9b8b3e61500691fd63ecd07cddb042"),
    "negative_controls": (P_NEG, "088be053e5d0fd7b77894ba7dadc5002e28d40cd377d3136ede1f19306871afd"),
}

NEW_AUTHORITY = [
    {
        "packet": P_C81,
        "role": "frozen_base",
        "terminal": True,
        "status": "HOLD",
        "authority_rank": 0,
    },
    {
        "packet": P_QF5V_PKT,
        "role": "redteam",
        "terminal": True,
        "status": "TERMINAL",
        "authority_rank": 38,
    },
    {
        "packet": P_PIMCORE_PKT,
        "role": "negative_control",
        "terminal": True,
        "status": "TERMINAL_REJECT",
        "authority_rank": 39,
    },
]


def compact_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


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
        "z" + "sh",
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
    for name, (relative, expected) in FROZEN.items():
        path = ROOT / relative
        got = sha256_file(path)
        assert got == expected, f"frozen mismatch {name}: {got}"
        pinned[name] = {"path": relative, "role": "frozen", "sha256": got}
    for name, (relative, expected) in LOCAL_PINS.items():
        path = ROOT / relative
        got = sha256_file(path)
        assert got == expected, f"capsule mismatch {name}: {got}"
        pinned[name] = {"path": relative, "role": "curated_capsule", "sha256": got}
    return pinned


def seven_pass(row: dict) -> bool:
    for field in GATES:
        value = row.get(field)
        if value is None or value != "PASS":
            return False
    return True


def load_capsule() -> dict:
    cap = load_json(HERE / "qf5v_acceptance.json")
    assert cap["case_id"] == CASE_QF5V
    assert cap["aliases"] == [ALIAS_QF5V]
    assert cap["cve_alias_is_not_a_counting_unit"] is True
    assert cap["repository"] == "fission/fission"
    assert cap["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert cap["mechanism_key"] == MECH_KEY
    assert cap["mechanism_fingerprint"] == MECH_FP
    assert cap["ordinal"] == STRICT_COUNT
    assert cap["verdict"] == "KEEP"
    assert cap["countable_in_this_snapshot"] is True
    assert cap["leader_strict_case_accepted"] is True
    assert cap["causal_admission"] is False
    assert cap["publication_admission"] is False
    assert cap["publication_ready"] is False
    assert cap["in_canonical81_strict"] is False
    assert cap["in_fp211_212"] is True
    assert cap["member_binding_rejected"] is True
    assert cap["hypothesized_member_must_never_be_counted_candidate_or_carrier"] is True
    assert cap["cartesian_candidate_fix_refused"] is True
    assert cap["carrier_set"] == []
    shas = cap["object_shas"]
    assert shas["counted_candidate"] == CAND_QF5V
    assert shas["candidate_parent"] == PARENT_QF5V
    assert shas["hypothesized_unreleased_member"] == MEMBER_QF5V
    assert shas["minimum_fix"] == FIX_QF5V
    assert MEMBER_QF5V != CAND_QF5V
    assert MEMBER_QF5V not in cap["carrier_set"]
    hunk = cap["hunk"]
    assert hunk["six_cap_map_sha256"] == MAP_SHA
    assert hunk["map_byte_identical_member_squash_v1_24_0"] is True
    assert hunk["fix_parent_blob_equals_v1_24_0"] is True
    assert hunk["fix_blob_equals_v1_25_0"] is True
    assert hunk["v1_24_0_dangerousCapabilities_blame"] == CAND_QF5V
    assert shas["fix_parent_podspec_blob"] == shas["v1_24_0_podspec_blob"] == BLOB_V124
    assert shas["fix_podspec_blob"] == shas["v1_25_0_podspec_blob"] == BLOB_FIX
    anc = cap["ancestry"]
    assert anc["candidate_ancestor_of_v1_24_0"] is True
    assert anc["fix_ancestor_of_v1_24_0"] is False
    assert anc["fix_ancestor_of_v1_25_0"] is True
    assert anc["member_ancestor_of_v1_24_0"] is False
    assert anc["member_ancestor_of_v1_25_0"] is False
    assert anc["member_ancestor_of_squash"] is False
    gates = cap["gates"]
    assert all(gates[field] == "PASS" for field in GATES)
    assert gates[REMEDIATION_GATE] == "PASS"
    ident = cap["identity"]
    assert ident["global_type"] == "reviewed"
    assert ident["withdrawn_at"] is None
    assert ident["published"] is True
    assert ident["package_name"] == "github.com/fission/fission"
    assert ident["vulnerable_version_range"] == "<= 1.24.0"
    assert ident["first_patched_version"] == "1.25.0"
    vuln = cap["vulnerable_release"]
    assert vuln["peeled"] == VULN_PEEL
    assert vuln["go_proxy_origin_hash"] == VULN_PEEL
    assert vuln["go_proxy_origin_hash_equals_peel"] is True
    assert vuln["contains_candidate"] is True
    assert vuln["contains_fix"] is False
    assert vuln["contains_member"] is False
    assert vuln["github_release_prerelease"] is True
    assert vuln["github_prerelease_flag_is_not_sole_release_proof"] is True
    assert vuln["commit_only_substitution_refused"] is True
    fixed = cap["fixed_release"]
    assert fixed["peeled"] == FIX_PEEL
    assert fixed["go_proxy_origin_hash"] == FIX_PEEL
    assert fixed["contains_fix"] is True
    assert fixed["equals_minimum_fix"] is False
    assert fixed["commit_only_substitution_refused"] is True
    urls = cap["primary_urls"]
    assert urls[0] == "https://github.com/advisories/GHSA-qf5v-m7p4-95rp"
    assert CASE_M63V in cap["distinct_from"]
    assert_no_leak(compact_json(cap))
    assert not HAN.search(compact_json(cap))
    return cap


def load_negative() -> dict:
    blob = load_json(HERE / "negative_controls.json")
    assert blob["capsule_kind"] == "negative_control_regression_guard"
    assert blob["role"] == "regression_guard_not_ledger_admission"
    assert len(blob["controls"]) == 1
    row = blob["controls"][0]
    assert row["case_id"] == CASE_PIMCORE
    assert row["verdict"] == "REJECT"
    assert row["countable"] is False
    assert row["must_be_absent_from_all_counted_ids"] is True
    assert row["authorship_transfer"] is True
    assert row["rule"] == "An AI-marked squash carrier cannot transfer authorship to a human member."
    assert row["object_shas"]["human_regex_member"] == HUMAN_PIMCORE
    assert row["object_shas"]["hypothesized_squash_carrier"] == SQUASH_PIMCORE
    assert row["copilot_members_do_not_touch_classdefinition"] is True
    assert row["gates"]["identity_gate"] == "PASS"
    assert row["gates"]["fix_reversal_gate"] == "PASS"
    assert row["gates"]["release_gate"] == "PASS"
    assert row["gates"]["uniqueness_gate"] == "PASS"
    assert row["gates"]["ai_hunk_gate"] == "FAIL"
    assert row["gates"]["topology_gate"] == "FAIL"
    assert row["gates"]["but_for_gate"] == "FAIL"
    assert row["gates"][REMEDIATION_GATE] == "FAIL"
    assert row["fail_gates"] == [
        "ai_hunk_gate",
        "topology_gate",
        "but_for_gate",
        "remediation_patch_delta_gate",
    ]
    assert_no_leak(compact_json(blob))
    assert not HAN.search(compact_json(blob))
    return blob


def authority_record(item: dict) -> dict:
    return {
        "schema_version": SCHEMA,
        "record_kind": "PACKET_AUTHORITY",
        "counted": False,
        "source_layer": True,
        **item,
    }


def counted_from_capsule(cap: dict) -> dict:
    candidate_set = [cap["object_shas"]["counted_candidate"]]
    minimum_fix_set = [cap["object_shas"]["minimum_fix"]]
    carrier_set = list(cap["carrier_set"])
    assert candidate_set == [CAND_QF5V]
    assert minimum_fix_set == [FIX_QF5V]
    assert carrier_set == []
    assert MEMBER_QF5V not in candidate_set
    assert MEMBER_QF5V not in carrier_set
    assert MEMBER_QF5V not in minimum_fix_set
    g = {field: cap["gates"][field] for field in GATES}
    assert all(g[field] == "PASS" for field in GATES)
    refs = list(cap["primary_urls"]) + [P_CAPSULE]
    assert refs[0] == "https://github.com/advisories/GHSA-qf5v-m7p4-95rp"
    vuln = cap["vulnerable_release"]
    fixed = cap["fixed_release"]
    ident = cap["identity"]
    out = {
        "action": "APPEND",
        "admission_source": cap["admission_source"],
        "aliases": list(cap["aliases"]),
        "candidate_parent": cap["object_shas"]["candidate_parent"],
        "candidate_set": candidate_set,
        "carrier_set": carrier_set,
        "cartesian_candidate_fix_refused": True,
        "case_id": CASE_QF5V,
        "contribution_class": cap["contribution_class"],
        "counted": True,
        "counting_unit": "first-party GHSA case",
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "first_party_source_refs": refs,
        "hypothesized_unreleased_member": MEMBER_QF5V,
        "in_fp211_212": True,
        "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        "mechanism_fingerprint": MECH_FP,
        "mechanism_key": MECH_KEY,
        "member_binding_rejected": True,
        "minimum_fix_set": minimum_fix_set,
        "ordinal": STRICT_COUNT,
        "overlay_state": "KEEP",
        "leader_strict_case_accepted": True,
        "record_kind": "STRICT_RELEASED_CASE",
        "repository": cap["repository"],
        "row_key": f"ghsa200-next:{CASE_QF5V}",
        "schema_version": SCHEMA,
        "scope_statement": cap["scope_statement"],
        "source_layer": False,
        **g,
        REMEDIATION_GATE: "PASS",
        "vulnerable_release": {
            "advisory_range": ident["vulnerable_version_range"],
            "contains_candidate": True,
            "contains_fix": False,
            "contains_member": False,
            "ecosystem": "Go",
            "equals_ai_blob_map": True,
            "git_tag_commit": VULN_PEEL,
            "github_release_draft": False,
            "github_release_id": vuln["github_release_id"],
            "github_release_prerelease": True,
            "github_prerelease_flag_is_not_sole_release_proof": True,
            "go_module": ident["package_name"],
            "go_proxy_origin_hash": VULN_PEEL,
            "kind": "git_tag_and_go_module",
            "name": ident["package_name"],
            "peeled": VULN_PEEL,
            "podspec_safety_blob": BLOB_V124,
            "published_at": vuln["published_at"],
            "sha": VULN_PEEL,
            "six_cap_map_sha256": MAP_SHA,
            "tag": "v1.24.0",
            "version": "v1.24.0",
        },
        "fixed_release": {
            "advisory_first_patched": ident["first_patched_version"],
            "contains_fix": True,
            "ecosystem": "Go",
            "equals_fix_blob": True,
            "equals_minimum_fix": False,
            "fix_parent_podspec_blob_equals_v1_24_0": True,
            "git_tag_commit": FIX_PEEL,
            "github_release_draft": False,
            "github_release_id": fixed["github_release_id"],
            "github_release_prerelease": False,
            "go_module": ident["package_name"],
            "go_proxy_origin_hash": FIX_PEEL,
            "kind": "git_tag_and_go_module",
            "name": ident["package_name"],
            "peeled": FIX_PEEL,
            "podspec_safety_blob": BLOB_FIX,
            "published_at": fixed["published_at"],
            "sha": FIX_PEEL,
            "tag": "v1.25.0",
            "version": "v1.25.0",
        },
    }
    assert SHA_RE.fullmatch(out["candidate_set"][0])
    assert SHA_RE.fullmatch(out["minimum_fix_set"][0])
    assert SHA_RE.fullmatch(out["candidate_parent"])
    assert CASE_QF5V not in out["aliases"]
    assert ALIAS_QF5V in out["aliases"]
    assert out["leader_strict_case_accepted"] is True
    assert out["counted"] is True
    assert "causal_admission" not in out
    assert "publication_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "pages/ghsa/" not in compact_json(out)
    assert MEMBER_QF5V not in out["candidate_set"]
    assert MEMBER_QF5V not in out["carrier_set"]
    return out


def edge_from_counted(counted: dict) -> dict:
    return {
        "applies_now": True,
        "applies_to_counted_set": True,
        "authority_rank": 38,
        "case_id": counted["case_id"],
        "counted": False,
        "edge_id": "E-QF5V-KEEP",
        "failed_gate": None,
        "from_packet": P_CONFIRM11,
        "from_verdict": "PASS",
        "note": "Independent qf5v red-team KEEP after leader replay. confirm11 PASS is a supporting proposal, not admission. Hypothesized member 2db76f65 is rejected and is never the counted candidate or carrier. Distinct from GHSA-M63V.",
        "pending_until_to_packet_terminal": False,
        "record_kind": "SUPERSEDES_EDGE",
        "schema_version": SCHEMA,
        "source_layer": True,
        "to_packet": P_QF5V_PKT,
        "to_verdict": "KEEP",
    }


def build_outputs() -> dict[Path, str]:
    pins = pin_inputs()
    cap = load_capsule()
    neg = load_negative()
    base_pairs = load_jsonl_raw(ROOT / P_C81_LEDGER)
    prior_summary = load_json(ROOT / P_C81_SUM)

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["integration_ready"] is False
    assert prior_summary["publication_ready"] is False
    assert prior_summary["causal_admission"] is False
    assert prior_summary["public_200_claim_supported"] is False
    assert prior_summary["status"] == "HOLD"

    by_kind_lines: dict[str, list[str]] = {}
    by_kind: dict[str, list[dict]] = {}
    for line, row in base_pairs:
        kind = row["record_kind"]
        by_kind_lines.setdefault(kind, []).append(line)
        by_kind.setdefault(kind, []).append(row)
    assert [row["record_kind"] for _, row in base_pairs[:15]] == ["PACKET_AUTHORITY"] * 15
    assert len(by_kind["PACKET_AUTHORITY"]) == 15
    assert len(by_kind["SUPERSEDES_EDGE"]) == 43
    assert len(by_kind["PRESERVED_HYPOTHESIS"]) == 211
    assert len(by_kind["PRESERVED_PUBLIC_CASE"]) == 212
    assert len(by_kind["APPEND_IDENTITY"]) == 12
    assert len(by_kind["STRICT_RELEASED_CASE"]) == PRIOR_STRICT
    assert len(base_pairs) == 574
    base_counted = by_kind["STRICT_RELEASED_CASE"]
    assert [row["case_id"] for row in base_counted] == prior_summary["strict_released_case_ids"]
    base_ids = [row["case_id"] for row in base_counted]
    source_ids = {row["case_id"] for row in by_kind["PRESERVED_PUBLIC_CASE"]}
    base_fps = {row["mechanism_fingerprint"] for row in base_counted}
    base_mechs = {row["mechanism_key"] for row in base_counted}
    assert len(base_ids) == len(set(base_ids)) == PRIOR_STRICT
    assert len(base_fps) == PRIOR_STRICT
    assert len(base_mechs) == PRIOR_STRICT
    assert CASE_QF5V not in base_ids
    assert CASE_PIMCORE not in base_ids
    assert CASE_M63V not in base_ids
    assert CASE_QF5V in source_ids
    assert CASE_M63V in source_ids
    assert CASE_PIMCORE not in source_ids
    assert MECH_FP not in base_fps
    assert MECH_KEY not in base_mechs
    assert ALIAS_QF5V not in base_ids

    counted = counted_from_capsule(cap)
    assert counted["ordinal"] == STRICT_COUNT
    assert counted["case_id"] == CASE_QF5V
    assert counted["mechanism_fingerprint"] not in base_fps
    assert counted["mechanism_key"] not in base_mechs
    assert seven_pass(counted)
    assert counted[REMEDIATION_GATE] == "PASS"
    assert counted["leader_strict_case_accepted"] is True
    assert counted["counted"] is True
    assert "causal_admission" not in counted
    assert_no_leak(compact_json(counted))
    new_edge = edge_from_counted(counted)
    new_auth = [authority_record(item) for item in NEW_AUTHORITY]
    for rec in new_auth + [new_edge, counted]:
        assert_no_leak(compact_json(rec))
        assert not HAN.search(compact_json(rec))
        assert "clone_path" not in rec

    records_text: list[str] = []
    records_text.extend(by_kind_lines["PACKET_AUTHORITY"])
    records_text.extend(compact_json(row) for row in new_auth)
    records_text.extend(by_kind_lines["SUPERSEDES_EDGE"])
    records_text.append(compact_json(new_edge))
    records_text.extend(by_kind_lines["PRESERVED_HYPOTHESIS"])
    records_text.extend(by_kind_lines["PRESERVED_PUBLIC_CASE"])
    records_text.extend(by_kind_lines["APPEND_IDENTITY"])
    records_text.extend(by_kind_lines["STRICT_RELEASED_CASE"])
    records_text.append(compact_json(counted))
    ledger_text = "".join(item + "\n" for item in records_text)
    records = [json.loads(item) for item in records_text]

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert [build_line for build_line in by_kind_lines["STRICT_RELEASED_CASE"]] == [
        compact_json(row) for row in counted_rows[:PRIOR_STRICT]
    ]
    assert counted_rows[PRIOR_STRICT:] == [counted]
    assert len(counted_rows) == STRICT_COUNT
    assert len({row["case_id"] for row in counted_rows}) == STRICT_COUNT
    assert counted_rows[-1]["case_id"] == CASE_QF5V
    assert counted_rows[-1]["ordinal"] == 82
    assert not any(row["case_id"] == CASE_PIMCORE for row in counted_rows)
    assert not any(row["case_id"] == CASE_M63V for row in counted_rows)
    assert not any(row["case_id"] == ALIAS_QF5V for row in counted_rows)
    assert all("candidate_fix_edges" not in row for row in counted_rows)
    assert MEMBER_QF5V not in counted["candidate_set"]
    assert MEMBER_QF5V not in counted["carrier_set"]

    kinds = Counter(row["record_kind"] for row in records)
    assert kinds["PRESERVED_HYPOTHESIS"] == 211
    assert kinds["PRESERVED_PUBLIC_CASE"] == 212
    assert kinds["APPEND_IDENTITY"] == 12
    assert kinds["STRICT_RELEASED_CASE"] == STRICT_COUNT
    assert kinds["PACKET_AUTHORITY"] == 18
    assert kinds["SUPERSEDES_EDGE"] == 44
    assert sum(row.get("counted") is True for row in records) == STRICT_COUNT
    assert len(records) == 579

    assert not HAN.search(ledger_text)
    base_ledger_text = (ROOT / P_C81_LEDGER).read_text()
    base_counted_text = "".join(line + "\n" for line in by_kind_lines["STRICT_RELEASED_CASE"])
    new_base_counted_text = "".join(compact_json(row) + "\n" for row in counted_rows[:PRIOR_STRICT])
    assert new_base_counted_text == base_counted_text
    assert sha256_bytes(base_ledger_text.encode()) == pins["canonical81_ledger"]["sha256"]
    hyp_text = "".join(line + "\n" for line in by_kind_lines["PRESERVED_HYPOTHESIS"])
    pub_layer_text = "".join(line + "\n" for line in by_kind_lines["PRESERVED_PUBLIC_CASE"])
    new_hyp_text = "".join(
        compact_json(row) + "\n" for row in records if row["record_kind"] == "PRESERVED_HYPOTHESIS"
    )
    new_pub_text = "".join(
        compact_json(row) + "\n" for row in records if row["record_kind"] == "PRESERVED_PUBLIC_CASE"
    )
    assert new_hyp_text == hyp_text
    assert new_pub_text == pub_layer_text
    base_all_text = "".join(line + "\n" for line, _ in base_pairs)
    rebuilt_base = "".join(
        compact_json(row) + "\n"
        for row in records
        if not (
            row["record_kind"] == "PACKET_AUTHORITY" and row.get("packet") in {P_C81, P_QF5V_PKT, P_PIMCORE_PKT}
        )
        and not (row["record_kind"] == "SUPERSEDES_EDGE" and row.get("case_id") == CASE_QF5V)
        and not (row["record_kind"] == "STRICT_RELEASED_CASE" and row.get("case_id") == CASE_QF5V)
    )
    assert rebuilt_base == base_all_text

    counted_ids = [row["case_id"] for row in counted_rows]
    prior_append = list(prior_summary["conservation"]["append_identities"])
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical82-hold",
        "canonical_strict_count": STRICT_COUNT,
        "checkpoint": {
            "prior_strict_count": PRIOR_STRICT,
            "corrected_strict_count": STRICT_COUNT,
            "corrected_baseline": 47,
            "fp211_released_admitted_raw": 48,
            "added_b3": list(B3_KEEP),
            "appended_q855": [CASE_Q855],
            "appended_specifyjs_five": list(prior_summary["checkpoint"]["appended_specifyjs_five"]),
            "appended_batch9_two": list(prior_summary["checkpoint"]["appended_batch9_two"]),
            "appended_langroid_one": list(prior_summary["checkpoint"]["appended_langroid_one"]),
            "appended_qf5v_one": [CASE_QF5V],
            "downgraded": [EXCLUDE_4FXP],
            "narrow_noncounting": [EXCLUDE_F38V, EXCLUDE_4FXP, EXCLUDE_NARROW, EXCLUDE_GOPACKET],
            "negative_control_rejected": [CASE_PIMCORE],
            "directory_name": "orchestrator-260814-ghsa200-canonical82",
            "prior_directory": "orchestrator-260814-ghsa200-canonical81",
            "note": "Directory name is canonical82. Semantic target is canonical strict count 82: the prior 81 exact strict IDs plus first-party GHSA-QF5V-M7P4-95RP at ordinal 82. Source conservation remains 211 hypotheses and 212 GHSA cases. QF5V is already in the 212 source layer and is not a new source identity. GHSA-2MHJ-FHVG-V428 is a negative-control REJECT and is not counted. Publication and integration stay closed. Greater-than-200 remains unsupported.",
        },
        "counting_unit": "first-party GHSA case",
        "language": "en",
        "causal_admission": False,
        "integration_ready": False,
        "publication_admission": False,
        "publication_ready": False,
        "public_200_claim_supported": False,
        "claim_boundary": "HOLD snapshot of canonical strict count 82 first-party GHSA identities: the prior 81 plus GHSA-QF5V-M7P4-95RP. Source conservation remains 211 hypotheses and 212 GHSA cases. This does not support a greater-than-200 claim. Publication and integration stay closed.",
        "conservation": {
            "fp211_hypotheses": 211,
            "fp211_source_ghsa_cases": 212,
            "cve_aliases_counted": False,
            "upgrades_append": False,
            "new_identities_append": False,
            "same_id_source_layer_promoted": True,
            "prior_append_identities": prior_append,
            "append_identities": prior_append,
            "base_counted_rows_byte_identical": True,
            "base_ledger_rows_byte_identical": True,
        },
        "counts": {
            "strict_released_first_party_ghsa": STRICT_COUNT,
            "corrected_baseline_47": 47,
            "fp211_released_admitted_raw": 48,
            "netnew22_keep": 21,
            "actual_gogs_keep": 2,
            "b3_keep": 2,
            "q855_keep": 1,
            "specifyjs_five_keep": 5,
            "batch9_three_keep": 2,
            "langroid_one_keep": 1,
            "qf5v_keep": 1,
            "netnew22_narrow_excluded": 1,
            "b3_narrow_excluded": 1,
            "batch9_three_narrow_excluded": 1,
            "pimcore_2mhj_negative_control_rejected": 1,
            "source_hypotheses": 211,
            "source_ghsa_cases": 212,
            "ledger_records": len(records),
            "by_record_kind": dict(kinds),
            "by_admission_source": dict(Counter(row["admission_source"] for row in counted_rows)),
        },
        "strict_released_case_ids": counted_ids,
        "excluded": {
            "GHSA-7C3W-FXGH-FRC7": "netnew22 NARROW but_for_gate; not counted",
            "GHSA-F38V-77QJ-H4JQ": "B3 NARROW; not counted",
            "GHSA-4FXP-2M36-QV64": "final-review NARROW identity_gate supersedes fp211 released-admitted; not counted",
            "GHSA-XW57-23P8-9WC5": "specifyjs PT-008 localhost; not in the five leader-accepted rows",
            "GHSA-QCR8-X557-7CP3": "not reviewed by the specifyjs-five red-team; not counted",
            "GHSA-6R28-9PPF-4HJ5": "batch9-three NARROW: squash-carrier Copilot on ports.go, human authored Diameter AVP underflow; not counted",
            "GHSA-2MHJ-FHVG-V428": "negative-control REJECT: human PR member e96631216bb4 authored the regex hunk; Copilot only touched sibling files; AI-marked squash carrier cannot transfer authorship to a human member; not counted",
            "GHSA-M63V-2G9W-2W6V": "distinct fission identity; not merged with QF5V; not counted in this snapshot",
            "discovery_tabs": "not included",
            "worker_only_PASS": "not included",
            "cartesian_candidate_fix_edges": "not invented; QF5V binds e484df84 to 2569b42b; hypothesized member 2db76f65 is rejected",
        },
        "seven_gates": list(GATES),
        "remediation_patch_delta_gate": "required PASS on GHSA-QF5V-M7P4-95RP",
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
        "negative_control": {
            "case_id": CASE_PIMCORE,
            "verdict": "REJECT",
            "counted": False,
            "fail_gates": list(neg["controls"][0]["fail_gates"]),
            "rule": neg["controls"][0]["rule"],
        },
        "ledger_sha256": sha256_bytes(ledger_text.encode()),
    }
    report = "\n".join(
        [
            "# Canonical82 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 82 first-party GHSA identities. It extends the frozen canonical81 snapshot in orchestrator-260814-ghsa200-canonical81 by appending exactly one leader-replayed identity. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical81 meaning and are not flipped by counting QF5V. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical81 ledger row is preserved byte-for-byte and in order. The prior 81 counted rows stay byte-identical. Terminal qf5v red-team KEEP 1 is appended at ordinal 82. Corrected baseline 47, plus terminal netnew22 KEEP 21, plus independent Actual/Gogs KEEP 2, plus terminal B3 KEEP 2, plus GHSA-Q855-8RH5-JFGQ, plus specifyjs five, plus batch9-three KEEP 2, plus langroid-one KEEP 1, plus this one. GHSA-F38V-77QJ-H4JQ, GHSA-4FXP-2M36-QV64, GHSA-7C3W-FXGH-FRC7, and GHSA-6R28-9PPF-4HJ5 remain noncounting. Count is by first-party GHSA identity once. CVE aliases are stored and never counted.",
            "",
            "The admitted identity at ordinal 82 is GHSA-QF5V-M7P4-95RP, alias CVE-2026-50570, repository fission/fission, class AI_INCOMPLETE_REMEDIATION. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. It maps counted candidate e484df84 (parent 8fa79941, empty carrier_set) to minimum fix 2569b42b. Hypothesized unreleased member 2db76f65 never appears as the counted candidate or carrier. Member binding is rejected. All seven contract gates are PASS. Remediation patch-delta is PASS. The mapping is not a Cartesian product. Distinct from GHSA-M63V.",
            "",
            "First-party identity is GitHub-reviewed (type=reviewed, withdrawn_at=null, published, source_code_location=fission/fission, Go package github.com/fission/fission, range <=1.24.0, fixed 1.25.0). Vulnerable containment is Go module/tag v1.24.0 peel ce617120. Public Go proxy Origin.Hash equals that peel. The artifact contains the candidate and not the fix. GitHub Release prerelease=true is recorded and is not the sole release proof. Fixed containment is Go module/tag v1.25.0 peel ae970aaa, which contains the fix. Fix-parent podspec blob equals v1.24.0; fix blob equals v1.25.0. Member/squash/v1.24.0 six-cap map hash is ad325615ca2257b65de131f8b48fe673c8f8f174b5b0dcb22f167bbe361f8b88. Commit-only substitution is refused.",
            "",
            "GHSA-2MHJ-FHVG-V428 is a compact negative-control REJECT, not a ledger admission. Identity, fix, release, and uniqueness PASS. ai_hunk, topology, but_for, and remediation_patch_delta FAIL because human PR member e96631216bb4 authored the regex hunk and Copilot only touched sibling files. An AI-marked squash carrier cannot transfer authorship to a human member.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer, including dual ordinal-200 identities GHSA-3J8Q-FWPJ-F8J5 and GHSA-JJCJ-H3CM-P7X7. Same-id upgrades still do not append a new source identity. QF5V is already in the 212 and is promoted into the counted set. confirm11 PASS is a supporting proposal only; independent qf5v KEEP after leader replay is the terminal admission edge. Discovery tabs and worker-only PASS are not loaded. Raw API pages and owned clones are not committed; the builder consumes qf5v_acceptance.json plus immutable canonical81 tracked artifacts.",
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
    assert CASE_QF5V in report
    assert CASE_PIMCORE in report
    assert ALIAS_QF5V in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report

    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical82-hold",
        "canonical_strict_count": STRICT_COUNT,
        "checkpoint": summary["checkpoint"],
        "counting_unit": "first-party GHSA case",
        "causal_admission": False,
        "integration_ready": False,
        "publication_admission": False,
        "publication_ready": False,
        "public_200_claim_supported": False,
        "packet_authority": [
            {
                "authority_rank": row["authority_rank"],
                "packet": row["packet"],
                "role": row["role"],
                "status": row["status"],
                "terminal": row["terminal"],
            }
            for row in records
            if row["record_kind"] == "PACKET_AUTHORITY"
        ],
        "hash_roles": summary["hash_roles"],
        "conservation": summary["conservation"],
        "strict_released_first_party_ghsa": STRICT_COUNT,
        "outputs": {
            "ledger.jsonl_sha256": summary["ledger_sha256"],
            "report.md_sha256": sha256_bytes(report.encode()),
        },
    }
    summary_text = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    assert not HAN.search(summary_text)
    manifest["outputs"]["summary.json_sha256"] = sha256_bytes(summary_text.encode())
    manifest_text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
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
        print("PASS: canonical82 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
