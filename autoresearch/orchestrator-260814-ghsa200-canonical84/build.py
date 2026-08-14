#!/usr/bin/env python3
"""Build the HOLD canonical84-directory snapshot at strict count 84. Stdlib only.

Consumes local curated capsules plus immutable canonical82 tracked artifacts.
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
PRIOR_STRICT = 82
STRICT_COUNT = 84
BASE_LEDGER_RECORDS = 579
LEDGER_RECORDS = 581
CASE_425G = "GHSA-425G-FJHQ-5H92"
CASE_HC8V = "GHSA-HC8V-WWC9-VGXM"
CASE_QF5V = "GHSA-QF5V-M7P4-95RP"
CASE_PIMCORE = "GHSA-2MHJ-FHVG-V428"
CASE_HHJV = "GHSA-HHJV-JQ77-CMVX"
CASE_73HC = "GHSA-73HC-M4HX-79PJ"
ALIAS_HC8V = "CVE-2026-71556"
CAND_425G = "a3d7f417be601a15865e8817086644d9451cdb73"
PARENT_425G = "c9c932afbe0f6f0036f0f4913070c3be14e759d7"
CARRIER_425G = "bb8915d2673d448b7b89ef484d7fef464f9c6684"
LINEAGE_425G = "6ad5d5ca79a0c7db6b6ae542192fc3cfa2ae4925"
FIX_425G = "6e7f938dcb7928faf5fd12bb5559f6dae2944124"
MECH_KEY_425G = "openssl-encrypt.json_validator.jsonschema-missing.fail-open"
MECH_FP_425G = (
    "openssl-encrypt.modules.json_validator.validate_against_schema."
    "jsonschema-missing.fail-open-return"
)
CAND_HC8V = "d83871ed0314f604e417f40733f762acfdcbc35c"
PARENT_HC8V = "c6d8721af933337e0ef616eba1920b195da27f67"
CARRIER_HC8V = "b1fab6cb0d33be2e084565bf04bb9222c8d1f419"
FIX_HC8V = "008a78f2dd86f52544ddff8b8e8ddeecdf3f7aab"
MECH_KEY_HC8V = "go-git.worktreeFilesystem.validPath.symlink-follow"
MECH_FP_HC8V = "go-git.v5.worktree_fs.worktreeFilesystem.validPath.omits-validNoLeadingSymlink"
VULN_HC8V = "3c3be601aa6c0fd0d536c0d1e4f898b4c60e65fe"
FIX_PEEL_HC8V = "3eeb238da61eb9c7a324f3ee04f990ce89175642"
ORIG_2081 = "a0e1969181c482fad64a016167bb95d0eba80eef"
V6_CLOSER = "661d1c7f101d34e002a3cfcf8dbea5b7421d07ac"
PYPI_VULN_SDIST = "3a8d8c2943ef4abd39ecb364a037f3aaa99921e59a4fd4b9450c42d536244fb6"
PYPI_VULN_WHEEL = "c8d7a129da8459cfaf4f09722cb1cd1fd3a6c9393aed847cf0571f937ff740d3"
PYPI_FIX_SDIST = "77a024c126ec6757703bd5e74da8c3af34683537b6e3f31585d9c3cf4497ca4f"
PYPI_FIX_WHEEL = "6f819ae67dc22ce06f204ff40b14daf19047263fbf3d9614214de6ee5cf6ab60"
TARBALL_V5191 = "91b44587081b94cee4c379f7eaad28e660384f77c334da57cf53551e7e710596"
TARBALL_V5192 = "6c4524af67065f3b28708c3a3aa0931c43aa17c0cddd5762a38717e1286e8ed8"
HUMAN_PIMCORE = "e96631216bb439896cc5979ed9f2850eaf28d2f4"
SQUASH_PIMCORE = "dbe1d131e49421eee5a427f1ae0dec5735639ff3"
HUMAN_HHJV = "92396b576d1ec8a39600ad510930d3e1a21484e7"
SQUASH_HHJV = "8f1c1db4f3e6d9e0beb16dc69bf07b10f12276cc"
CLAIMED_73HC = "fd2bbf49cca2b01ee6cbd158b053e7051f586b7e"
ORIGIN_73HC = "4e796e2814149f966901dc59528da230a9da93b3"
EXCLUDE_NARROW = "GHSA-7C3W-FXGH-FRC7"
EXCLUDE_F38V = "GHSA-F38V-77QJ-H4JQ"
EXCLUDE_4FXP = "GHSA-4FXP-2M36-QV64"
EXCLUDE_XW57 = "GHSA-XW57-23P8-9WC5"
EXCLUDE_QCR8 = "GHSA-QCR8-X557-7CP3"
EXCLUDE_GOPACKET = "GHSA-6R28-9PPF-4HJ5"
CASE_Q855 = "GHSA-Q855-8RH5-JFGQ"
CASE_M63V = "GHSA-M63V-2G9W-2W6V"
B3_KEEP = ("GHSA-G3XQ-3GMV-QQ8G", "GHSA-PV2J-RGHR-V5R9")
FILEBROWSER_NEG = "post:filebrowser-delete-scope@canonical"
FILEBROWSER_POS = "post:filebrowser-dangling-write@canonical"
ORD200 = ("GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7")

P_C82 = "autoresearch/orchestrator-260814-ghsa200-canonical82"
P_C82_LEDGER = P_C82 + "/ledger.jsonl"
P_C82_SUM = P_C82 + "/summary.json"
P_C82_MAN = P_C82 + "/manifest.json"
P_425G_PKT = "autoresearch/herdr-260814-ghsa200-425g-hostile-redteam-grok46-medium"
P_HC8V_PKT = "autoresearch/herdr-260814-ghsa200-hc8v-hostile-redteam-grok46-xhigh"
P_HHJV_PKT = "autoresearch/herdr-260814-ghsa200-hhjv-hostile-redteam-grok46-high"
P_73HC_PKT = "autoresearch/herdr-260814-ghsa200-ai-route-surface20-grok46-xhigh"
P_CAP_425G = "autoresearch/orchestrator-260814-ghsa200-canonical84/425g_acceptance.json"
P_CAP_HC8V = "autoresearch/orchestrator-260814-ghsa200-canonical84/hc8v_acceptance.json"
P_NEG = "autoresearch/orchestrator-260814-ghsa200-canonical84/negative_controls.json"
NEW_APPEND_IDENTITIES = (CASE_425G, CASE_HC8V)
NEW_PACKET_AUTHORITY = (
    {
        "authority_rank": 40,
        "packet": P_425G_PKT,
        "role": "redteam",
        "status": "TERMINAL",
        "terminal": True,
    },
    {
        "authority_rank": 41,
        "packet": P_HC8V_PKT,
        "role": "redteam",
        "status": "TERMINAL",
        "terminal": True,
    },
)

FROZEN = {
    "canonical82_ledger": (P_C82_LEDGER, "58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23"),
    "canonical82_summary": (P_C82_SUM, "d436f47f82297eb0d9363ad0f3876adc639b1f61e9b23c7f9d613545741e106e"),
    "canonical82_manifest": (P_C82_MAN, "5f868f76fbaf76a1ed62fd7b5036d681dcf6bbf7be9f174574ed8e589153ab45"),
    "case_425g": (P_425G_PKT + "/case.json", "d86e3dfd98274a6768d234386e9775c7d64144602952cec73dbe45d303787c93"),
    "result_425g": (P_425G_PKT + "/result.json", "530dbf2eb10ef2d1b9f23dfb6f7ee8b66c9192aa4b11b2cfa3c89f52b6248921"),
    "case_hc8v": (P_HC8V_PKT + "/case.json", "0b9bdbbcffabdf43b0f69fc6f273489396d2fabd8b9dfc31956683d5c435df37"),
    "result_hc8v": (P_HC8V_PKT + "/result.json", "626ec205d17be3ce203c6a09467ef69f03dbc3e78b8b7a82f2f63d7cbc822d89"),
}
LOCAL_PINS = {
    "acceptance_425g": (P_CAP_425G, "245d5dfa6478a0bae9980e0c9cf2bf9feeaf34c3acd45bf6a1fe8a667c37d77e"),
    "acceptance_hc8v": (P_CAP_HC8V, "b604cae8e404443d06071c589a6d57075ab8fa1aac6041c17443d890601d87f5"),
    "negative_controls": (P_NEG, "740f6d5e4bae66b87fe821537d2cb48fffeb6d83365e79659a584b484ab7c00c"),
}


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


def _common_capsule_checks(cap: dict, case_id: str, ordinal: int) -> None:
    assert cap["case_id"] == case_id
    assert cap["ordinal"] == ordinal
    assert cap["verdict"] == "KEEP"
    assert cap["countable_in_this_snapshot"] is True
    assert cap["leader_strict_case_accepted"] is True
    assert cap["causal_admission"] is False
    assert cap["publication_admission"] is False
    assert cap["publication_ready"] is False
    assert cap["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert cap["cve_alias_is_not_a_counting_unit"] is True
    assert cap["cartesian_candidate_fix_refused"] is True
    assert cap["in_fp211_212"] is False
    assert cap["in_canonical82_strict"] is False
    gates = cap["gates"]
    assert all(gates[field] == "PASS" for field in GATES)
    assert gates[REMEDIATION_GATE] == "PASS"
    ident = cap["identity"]
    assert ident["global_type"] == "reviewed"
    assert ident["withdrawn_at"] is None
    assert ident["published"] is True
    assert_no_leak(compact_json(cap))
    assert not HAN.search(compact_json(cap))


def load_capsule_425g() -> dict:
    cap = load_json(HERE / "425g_acceptance.json")
    _common_capsule_checks(cap, CASE_425G, 83)
    assert cap["aliases"] == []
    assert cap["repository"] == "jahlives/openssl_encrypt"
    assert cap["mechanism_key"] == MECH_KEY_425G
    assert cap["mechanism_fingerprint"] == MECH_FP_425G
    assert cap["candidate_set"] == [CAND_425G]
    assert cap["carrier_set"] == [CARRIER_425G]
    assert cap["minimum_fix_set"] == [FIX_425G]
    assert cap["lineage_evidence_not_counted"] == [LINEAGE_425G]
    shas = cap["object_shas"]
    assert shas["counted_candidate"] == CAND_425G
    assert shas["candidate_parent"] == PARENT_425G
    assert shas["carrier"] == CARRIER_425G
    assert shas["lineage_duplicate_not_counted"] == LINEAGE_425G
    assert shas["minimum_fix"] == FIX_425G
    assert LINEAGE_425G not in cap["candidate_set"]
    assert LINEAGE_425G not in cap["carrier_set"]
    assert LINEAGE_425G not in cap["minimum_fix_set"]
    assert cap["authorship_transfer"] is False
    vuln = cap["vulnerable_release"]
    assert vuln["version"] == "1.3.5"
    assert vuln["sha256_sdist"] == PYPI_VULN_SDIST
    assert vuln["sha256_wheel"] == PYPI_VULN_WHEEL
    assert vuln["contains_ai_fail_open"] is True
    assert vuln["jsonschema_required"] is False
    assert vuln["yanked"] is False
    fixed = cap["fixed_release"]
    assert fixed["version"] == "1.4.0"
    assert fixed["sha256_sdist"] == PYPI_FIX_SDIST
    assert fixed["sha256_wheel"] == PYPI_FIX_WHEEL
    assert fixed["contains_fix"] is True
    assert fixed["jsonschema_required"] is True
    assert cap["source_hashes"]["case_json"] == FROZEN["case_425g"][1]
    assert cap["source_hashes"]["result_json"] == FROZEN["result_425g"][1]
    return cap


def load_capsule_hc8v() -> dict:
    cap = load_json(HERE / "hc8v_acceptance.json")
    _common_capsule_checks(cap, CASE_HC8V, 84)
    assert cap["aliases"] == [ALIAS_HC8V]
    assert cap["repository"] == "go-git/go-git"
    assert cap["mechanism_key"] == MECH_KEY_HC8V
    assert cap["mechanism_fingerprint"] == MECH_FP_HC8V
    assert cap["candidate_set"] == [CAND_HC8V]
    assert cap["carrier_set"] == [CARRIER_HC8V]
    assert cap["minimum_fix_set"] == [FIX_HC8V]
    assert cap["candidate_any_parent"] is True
    assert cap["candidate_on_release_first_parent"] is False
    assert cap["carrier_on_release_first_parent"] is True
    assert cap["authorship_transfer"] is False
    shas = cap["object_shas"]
    assert shas["counted_candidate"] == CAND_HC8V
    assert shas["candidate_parent"] == PARENT_HC8V
    assert shas["carrier"] == CARRIER_HC8V
    assert shas["minimum_fix"] == FIX_HC8V
    assert shas["orig_2081_not_counted"] == ORIG_2081
    assert ORIG_2081 not in cap["candidate_set"]
    assert ORIG_2081 not in cap["carrier_set"]
    assert V6_CLOSER not in cap["minimum_fix_set"]
    vuln = cap["vulnerable_release"]
    assert vuln["tag"] == "v5.19.1"
    assert vuln["peeled"] == VULN_HC8V
    assert vuln["tarball_sha256"] == TARBALL_V5191
    assert vuln["contains_candidate"] is True
    assert vuln["contains_fix"] is False
    assert vuln["immutable"] is True
    fixed = cap["fixed_release"]
    assert fixed["tag"] == "v5.19.2"
    assert fixed["peeled"] == FIX_PEEL_HC8V
    assert fixed["tarball_sha256"] == TARBALL_V5192
    assert fixed["contains_fix"] is True
    assert fixed["worktree_fs_equals_fix_blob"] is True
    assert cap["source_hashes"]["case_json"] == FROZEN["case_hc8v"][1]
    assert cap["source_hashes"]["result_json"] == FROZEN["result_hc8v"][1]
    return cap


def load_negative() -> dict:
    blob = load_json(HERE / "negative_controls.json")
    assert blob["capsule_kind"] == "negative_control_regression_guard"
    assert blob["role"] == "regression_guard_not_ledger_admission"
    assert len(blob["controls"]) == 3
    by_id = {row["case_id"]: row for row in blob["controls"]}
    pim = by_id[CASE_PIMCORE]
    assert pim["verdict"] == "REJECT"
    assert pim["countable"] is False
    assert pim["must_be_absent_from_all_counted_ids"] is True
    assert pim["authorship_transfer"] is True
    assert pim["object_shas"]["human_regex_member"] == HUMAN_PIMCORE
    assert pim["object_shas"]["hypothesized_squash_carrier"] == SQUASH_PIMCORE
    hhjv = by_id[CASE_HHJV]
    assert hhjv["verdict"] == "REJECT"
    assert hhjv["countable"] is False
    assert hhjv["authorship_transfer"] is True
    assert hhjv["object_shas"]["human_device_shell_member"] == HUMAN_HHJV
    assert hhjv["object_shas"]["hypothesized_squash_carrier"] == SQUASH_HHJV
    assert hhjv["fail_gates"] == ["ai_hunk_gate", "topology_gate", "but_for_gate"]
    assert hhjv["gates"]["identity_gate"] == "PASS"
    hc73 = by_id[CASE_73HC]
    assert hc73["verdict"] == "REJECT"
    assert hc73["countable"] is False
    assert hc73["reject_class"] == "SIBLING_ROUTE_PARENT_HAD_EQUIVALENT_ENTRYPOINT"
    assert hc73["object_shas"]["claimed_ai_sibling"] == CLAIMED_73HC
    assert hc73["object_shas"]["unmarked_health_origin"] == ORIGIN_73HC
    assert hc73["fail_gates"] == [
        "ai_hunk_gate",
        "topology_gate",
        "but_for_gate",
        "fix_reversal_gate",
        "release_gate",
    ]
    assert hc73["gates"]["identity_gate"] == "PASS"
    assert hc73["gates"]["uniqueness_gate"] == "PASS"
    assert_no_leak(compact_json(blob))
    assert not HAN.search(compact_json(blob))
    return blob


def counted_from_capsule(cap: dict) -> dict:
    case_id = cap["case_id"]
    candidate_set = list(cap["candidate_set"])
    carrier_set = list(cap["carrier_set"])
    minimum_fix_set = list(cap["minimum_fix_set"])
    assert candidate_set == sorted(set(candidate_set))
    assert carrier_set == sorted(set(carrier_set))
    assert minimum_fix_set == sorted(set(minimum_fix_set))
    g = {field: cap["gates"][field] for field in GATES}
    assert all(g[field] == "PASS" for field in GATES)
    refs = list(cap["primary_urls"])
    if case_id == CASE_425G:
        refs = refs + [P_CAP_425G]
        extra = {
            "lineage_evidence_not_counted": [LINEAGE_425G],
            "authorship_transfer": False,
        }
    else:
        refs = refs + [P_CAP_HC8V]
        extra = {
            "candidate_any_parent": True,
            "candidate_on_release_first_parent": False,
            "carrier_on_release_first_parent": True,
            "authorship_transfer": False,
            "v5_and_v6_are_one_ghsa_case": True,
        }
    out = {
        "action": "APPEND",
        "admission_source": cap["admission_source"],
        "aliases": list(cap["aliases"]),
        "candidate_parent": cap["object_shas"]["candidate_parent"],
        "candidate_set": candidate_set,
        "carrier_set": carrier_set,
        "cartesian_candidate_fix_refused": True,
        "case_id": case_id,
        "contribution_class": cap["contribution_class"],
        "counted": True,
        "counting_unit": "first-party GHSA case",
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "first_party_source_refs": refs,
        "in_fp211_212": False,
        "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        "mechanism_fingerprint": cap["mechanism_fingerprint"],
        "mechanism_key": cap["mechanism_key"],
        "minimum_fix_set": minimum_fix_set,
        "ordinal": cap["ordinal"],
        "overlay_state": "KEEP",
        "leader_strict_case_accepted": True,
        "record_kind": "STRICT_RELEASED_CASE",
        "repository": cap["repository"],
        "row_key": f"ghsa200-next:{case_id}",
        "schema_version": SCHEMA,
        "scope_statement": cap["scope_statement"],
        "source_layer": False,
        **g,
        REMEDIATION_GATE: "PASS",
        "vulnerable_release": dict(cap["vulnerable_release"]),
        "fixed_release": dict(cap["fixed_release"]),
        **extra,
    }
    assert SHA_RE.fullmatch(out["candidate_set"][0])
    assert SHA_RE.fullmatch(out["minimum_fix_set"][0])
    assert SHA_RE.fullmatch(out["candidate_parent"])
    assert all(SHA_RE.fullmatch(item) for item in out["carrier_set"])
    assert case_id not in out["aliases"]
    assert out["leader_strict_case_accepted"] is True
    assert out["counted"] is True
    assert "causal_admission" not in out
    assert "publication_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "pages/ghsa/" not in compact_json(out)
    if case_id == CASE_425G:
        assert LINEAGE_425G not in out["candidate_set"]
        assert LINEAGE_425G not in out["carrier_set"]
        assert out["aliases"] == []
    else:
        assert ALIAS_HC8V in out["aliases"]
        assert ORIG_2081 not in out["candidate_set"]
        assert V6_CLOSER not in out["minimum_fix_set"]
    return out


def build_outputs() -> dict[Path, str]:
    pins = pin_inputs()
    cap_425g = load_capsule_425g()
    cap_hc8v = load_capsule_hc8v()
    neg = load_negative()
    base_pairs = load_jsonl_raw(ROOT / P_C82_LEDGER)
    prior_summary = load_json(ROOT / P_C82_SUM)
    base_text = (ROOT / P_C82_LEDGER).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["ledger_sha256"] == pins["canonical82_ledger"]["sha256"]
    assert sha256_bytes(base_text.encode()) == pins["canonical82_ledger"]["sha256"]
    assert prior_summary["integration_ready"] is False
    assert prior_summary["publication_ready"] is False
    assert prior_summary["causal_admission"] is False
    assert prior_summary["public_200_claim_supported"] is False
    assert prior_summary["status"] == "HOLD"
    assert len(base_pairs) == BASE_LEDGER_RECORDS

    by_kind: dict[str, list[dict]] = {}
    for _, row in base_pairs:
        by_kind.setdefault(row["record_kind"], []).append(row)
    assert len(by_kind["PACKET_AUTHORITY"]) == 18
    assert len(by_kind["SUPERSEDES_EDGE"]) == 44
    assert len(by_kind["PRESERVED_HYPOTHESIS"]) == 211
    assert len(by_kind["PRESERVED_PUBLIC_CASE"]) == 212
    assert len(by_kind["APPEND_IDENTITY"]) == 12
    assert len(by_kind["STRICT_RELEASED_CASE"]) == PRIOR_STRICT
    base_counted = by_kind["STRICT_RELEASED_CASE"]
    assert [row["case_id"] for row in base_counted] == prior_summary["strict_released_case_ids"]
    base_ids = [row["case_id"] for row in base_counted]
    source_ids = {row["case_id"] for row in by_kind["PRESERVED_PUBLIC_CASE"]}
    base_fps = {row["mechanism_fingerprint"] for row in base_counted}
    base_mechs = {row["mechanism_key"] for row in base_counted}
    assert len(base_ids) == len(set(base_ids)) == PRIOR_STRICT
    for case_id in (CASE_425G, CASE_HC8V, CASE_PIMCORE, CASE_HHJV, CASE_73HC, ALIAS_HC8V):
        assert case_id not in base_ids
    assert CASE_425G not in source_ids
    assert CASE_HC8V not in source_ids
    assert MECH_FP_425G not in base_fps
    assert MECH_FP_HC8V not in base_fps
    assert MECH_KEY_425G not in base_mechs
    assert MECH_KEY_HC8V not in base_mechs

    counted_425g = counted_from_capsule(cap_425g)
    counted_hc8v = counted_from_capsule(cap_hc8v)
    assert counted_425g["ordinal"] == 83
    assert counted_hc8v["ordinal"] == 84
    assert counted_425g["case_id"] == CASE_425G
    assert counted_hc8v["case_id"] == CASE_HC8V
    assert seven_pass(counted_425g) and seven_pass(counted_hc8v)
    assert counted_425g[REMEDIATION_GATE] == "PASS"
    assert counted_hc8v[REMEDIATION_GATE] == "PASS"
    for rec in (counted_425g, counted_hc8v):
        assert rec["leader_strict_case_accepted"] is True
        assert "causal_admission" not in rec
        assert_no_leak(compact_json(rec))
        assert not HAN.search(compact_json(rec))

    new_lines = [compact_json(counted_425g), compact_json(counted_hc8v)]
    ledger_text = base_text if base_text.endswith("\n") else base_text + "\n"
    ledger_text = ledger_text + new_lines[0] + "\n" + new_lines[1] + "\n"
    records = [json.loads(line) for line in ledger_text.splitlines() if line.strip()]
    assert [line for line, _ in base_pairs] == ledger_text.splitlines()[:BASE_LEDGER_RECORDS]
    assert "".join(line + "\n" for line, _ in base_pairs) == "".join(
        line + "\n" for line in ledger_text.splitlines()[:BASE_LEDGER_RECORDS]
    )

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == [counted_425g, counted_hc8v]
    assert len(counted_rows) == STRICT_COUNT
    assert len(records) == LEDGER_RECORDS
    assert LINEAGE_425G not in counted_425g["candidate_set"]
    assert ALIAS_HC8V not in [row["case_id"] for row in counted_rows]
    for banned in (CASE_PIMCORE, CASE_HHJV, CASE_73HC, LINEAGE_425G, ALIAS_HC8V):
        assert not any(row["case_id"] == banned for row in counted_rows)

    kinds = Counter(row["record_kind"] for row in records)
    assert kinds["PRESERVED_HYPOTHESIS"] == 211
    assert kinds["PRESERVED_PUBLIC_CASE"] == 212
    assert kinds["APPEND_IDENTITY"] == 12
    assert kinds["STRICT_RELEASED_CASE"] == STRICT_COUNT
    assert kinds["PACKET_AUTHORITY"] == 18
    assert kinds["SUPERSEDES_EDGE"] == 44
    assert sum(row.get("counted") is True for row in records) == STRICT_COUNT
    assert not HAN.search(ledger_text)

    counted_ids = [row["case_id"] for row in counted_rows]
    prior_append = list(prior_summary["conservation"]["append_identities"])
    new_append = list(NEW_APPEND_IDENTITIES)
    append_identities = prior_append + new_append
    assert len(prior_append) == 12
    assert prior_append == list(prior_summary["conservation"]["append_identities"])
    assert new_append == [CASE_425G, CASE_HC8V]
    assert append_identities == prior_append + [CASE_425G, CASE_HC8V]
    assert len(append_identities) == 14
    assert counted_425g["action"] == counted_hc8v["action"] == "APPEND"
    assert counted_425g["in_fp211_212"] is False
    assert counted_hc8v["in_fp211_212"] is False
    neg_ids = [row["case_id"] for row in neg["controls"]]
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical84-hold",
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
            "appended_425g_one": [CASE_425G],
            "appended_hc8v_one": [CASE_HC8V],
            "downgraded": [EXCLUDE_4FXP],
            "narrow_noncounting": [EXCLUDE_F38V, EXCLUDE_4FXP, EXCLUDE_NARROW, EXCLUDE_GOPACKET],
            "negative_control_rejected": [CASE_PIMCORE, CASE_HHJV, CASE_73HC],
            "directory_name": "orchestrator-260814-ghsa200-canonical84",
            "prior_directory": "orchestrator-260814-ghsa200-canonical82",
            "prior_commit": "6800d2127c19532160cc88880115ae28cc446aa5",
            "note": "Directory name is canonical84. Semantic target is canonical strict count 84: the prior 82 exact strict IDs plus first-party GHSA-425G-FJHQ-5H92 at ordinal 83 and GHSA-HC8V-WWC9-VGXM at ordinal 84. Source conservation remains 211 hypotheses and 212 GHSA cases. The two new identities are absent from the 212 source layer, so they APPEND the counted set (new_identities_append=true) without promoting a same-id source row and without adding PRESERVED_PUBLIC_CASE or APPEND_IDENTITY ledger rows. Negative-control REJECT identities are not counted. Publication and integration stay closed. Greater-than-200 remains unsupported.",
        },
        "counting_unit": "first-party GHSA case",
        "language": "en",
        "causal_admission": False,
        "integration_ready": False,
        "publication_admission": False,
        "publication_ready": False,
        "public_200_claim_supported": False,
        "claim_boundary": "HOLD snapshot of canonical strict count 84 first-party GHSA identities: the prior 82 plus GHSA-425G-FJHQ-5H92 and GHSA-HC8V-WWC9-VGXM. Source conservation remains 211 hypotheses and 212 GHSA cases. This does not support a greater-than-200 claim. Publication and integration stay closed.",
        "conservation": {
            "fp211_hypotheses": 211,
            "fp211_source_ghsa_cases": 212,
            "cve_aliases_counted": False,
            "upgrades_append": False,
            "new_identities_append": True,
            "same_id_source_layer_promoted": False,
            "prior_append_identities": prior_append,
            "new_append_identities": new_append,
            "append_identities": append_identities,
            "base_counted_rows_byte_identical": True,
            "base_ledger_rows_byte_identical": True,
            "appended_strict_rows": 2,
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
            "keep_425g": 1,
            "keep_hc8v": 1,
            "netnew22_narrow_excluded": 1,
            "b3_narrow_excluded": 1,
            "batch9_three_narrow_excluded": 1,
            "pimcore_2mhj_negative_control_rejected": 1,
            "hhjv_negative_control_rejected": 1,
            "route73hc_negative_control_rejected": 1,
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
            "GHSA-HHJV-JQ77-CMVX": "negative-control REJECT: human PR member 92396b57 authored Android device_shell; AI-marked squash 8f1c1db4 cannot transfer authorship; not counted",
            "GHSA-73HC-M4HX-79PJ": "negative-control REJECT: sibling /memory-stats on a parent that already had equivalent /health entrypoints; not counted",
            "GHSA-M63V-2G9W-2W6V": "distinct fission identity; not merged with QF5V; not counted in this snapshot",
            "lineage_duplicate_6ad5d5ca": "lineage evidence for GHSA-425G; not a separately counted candidate",
            "CVE-2026-71556": "alias of GHSA-HC8V-WWC9-VGXM; not a counting unit",
            "discovery_tabs": "not included",
            "worker_only_PASS": "not included",
            "cartesian_candidate_fix_edges": "not invented; 425G binds a3d7f417 to 6e7f938d; HC8V binds d83871ed to 008a78f2",
        },
        "seven_gates": list(GATES),
        "remediation_patch_delta_gate": "required PASS on GHSA-425G-FJHQ-5H92 and GHSA-HC8V-WWC9-VGXM",
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
    assert neg_ids == [CASE_PIMCORE, CASE_HHJV, CASE_73HC]
    report = "\n".join(
        [
            "# Canonical84 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 84 first-party GHSA identities. It extends the frozen canonical82 snapshot in orchestrator-260814-ghsa200-canonical82 by appending exactly two leader-replayed identities. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical82 meaning and are not flipped by counting GHSA-425G or GHSA-HC8V. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical82 ledger row is preserved byte-for-byte and in order. The prior 82 counted rows stay byte-identical. Terminal 425g red-team KEEP 1 is appended at ordinal 83. Terminal hc8v red-team KEEP 1 is appended at ordinal 84. Count is by first-party GHSA identity once. CVE aliases are stored and never counted. Lineage duplicate 6ad5d5ca is not a counted candidate.",
            "",
            "The admitted identity at ordinal 83 is GHSA-425G-FJHQ-5H92, repository jahlives/openssl_encrypt, class AI_INCOMPLETE_REMEDIATION. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. candidate_set is a3d7f417. carrier_set is first-parent landing merge bb8915d2. minimum_fix_set is 6e7f938d. Duplicate atomic 6ad5d5ca is lineage evidence only. All seven contract gates are PASS. Remediation patch-delta is PASS. Immutable PyPI 1.3.5 is the vulnerable artifact (fail-open, jsonschema not required). Immutable PyPI 1.4.0 is the fixed artifact (raise, jsonschema required).",
            "",
            "The admitted identity at ordinal 84 is GHSA-HC8V-WWC9-VGXM, alias CVE-2026-71556, repository go-git/go-git, class AI_INCOMPLETE_REMEDIATION. leader_strict_case_accepted is true. candidate_set is d83871ed. carrier_set is b1fab6cb. minimum_fix_set is 008a78f2. candidate_any_parent is true. candidate_on_release_first_parent is false. carrier_on_release_first_parent is true. Authorship is not transferred from member to carrier or from original 2081. All seven contract gates are PASS. Remediation patch-delta is PASS. Immutable GitHub tag, release, and source tarball v5.19.1 is vulnerable. v5.19.2 is fixed. v5 and v6 ranges are one first-party GHSA case.",
            "",
            "GHSA-2MHJ-FHVG-V428 remains a compact negative-control REJECT. GHSA-HHJV-JQ77-CMVX is a compact negative-control REJECT: human member 92396b57 authored Android device_shell; AI-marked squash 8f1c1db4 cannot transfer authorship; ai_hunk, topology, and but_for FAIL. GHSA-73HC-M4HX-79PJ is a compact negative-control REJECT: sibling /memory-stats on a parent that already had equivalent /health entrypoints; ai_hunk, topology, but_for, fix, and release FAIL. Negative controls are not ledger admissions and are absent from strict rows.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer, including dual ordinal-200 identities GHSA-3J8Q-FWPJ-F8J5 and GHSA-JJCJ-H3CM-P7X7. Same-id upgrades still do not append. GHSA-425G and GHSA-HC8V are new identities (in_fp211_212=false, action=APPEND). Conservation prior_append_identities stays the prior 12. new_append_identities is exactly those two. append_identities is the prior 12 followed by those two (14). new_identities_append is true. same_id_source_layer_promoted is false. The 425g and hc8v hostile-redteam packets admit these rows at authority ranks 40 and 41; prior packet authorities do not admit them. Discovery tabs and worker-only PASS are not loaded. Raw API pages and owned clones are not committed; the builder consumes 425g_acceptance.json, hc8v_acceptance.json, negative_controls.json, plus immutable canonical82 tracked artifacts.",
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
    assert CASE_425G in report
    assert CASE_HC8V in report
    assert CASE_PIMCORE in report
    assert CASE_HHJV in report
    assert CASE_73HC in report
    assert ALIAS_HC8V in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "new_identities_append is true" in report
    assert "prior packet authorities do not admit them" in report
    assert "only prior" not in report.lower()

    inherited_authority = [
        {
            "authority_rank": row["authority_rank"],
            "packet": row["packet"],
            "role": row["role"],
            "status": row["status"],
            "terminal": row["terminal"],
        }
        for row in records
        if row["record_kind"] == "PACKET_AUTHORITY"
    ]
    packet_authority = inherited_authority + [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert len(inherited_authority) == 18
    assert packet_authority[-2:] == [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert packet_authority[-2]["packet"] == P_425G_PKT
    assert packet_authority[-1]["packet"] == P_HC8V_PKT
    assert packet_authority[-2]["authority_rank"] == 40
    assert packet_authority[-1]["authority_rank"] == 41
    cons = summary["conservation"]
    assert cons["new_identities_append"] is True
    assert cons["same_id_source_layer_promoted"] is False
    assert cons["upgrades_append"] is False
    assert cons["new_append_identities"] == [CASE_425G, CASE_HC8V]
    assert cons["prior_append_identities"] == prior_append
    assert cons["append_identities"] == prior_append + [CASE_425G, CASE_HC8V]
    assert cons["appended_strict_rows"] == 2
    assert cons["fp211_hypotheses"] == 211
    assert cons["fp211_source_ghsa_cases"] == 212

    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical84-hold",
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
        print("PASS: canonical84 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
