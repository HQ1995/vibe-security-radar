#!/usr/bin/env python3
"""Build the HOLD canonical85-directory snapshot at strict count 85. Stdlib only.

Consumes local curated capsules plus immutable canonical84 tracked artifacts.
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
PRIOR_STRICT = 84
STRICT_COUNT = 85
BASE_LEDGER_RECORDS = 581
LEDGER_RECORDS = 582
CASE_8359 = "GHSA-8359-H9FX-J6V9"
CASE_425G = "GHSA-425G-FJHQ-5H92"
CASE_HC8V = "GHSA-HC8V-WWC9-VGXM"
CASE_QF5V = "GHSA-QF5V-M7P4-95RP"
CASE_PIMCORE = "GHSA-2MHJ-FHVG-V428"
CASE_HHJV = "GHSA-HHJV-JQ77-CMVX"
CASE_73HC = "GHSA-73HC-M4HX-79PJ"
CASE_282G = "GHSA-282G-FHMX-XF54"
CASE_45Q4 = "GHSA-45Q4-X4R9-8FQJ"
CASE_954P = "GHSA-954P-556P-R752"
ALIAS_8359 = "CVE-2026-55389"
ALIAS_HC8V = "CVE-2026-71556"
CAND_8359 = "f6d4cbd3440a84e801566fa758ab2bf483322082"
PARENT_8359 = "7e1a5c751b7b4b07aaf7d860d93162f1a75822b7"
FIX_8359 = "2ff4a72b4550a2b2069754c5b075b1655067e5fb"
FIX_PARENT_8359 = "2dbe5b5794472a4cad8e9286c942dffda7359816"
FIX_954P = "5fdba4a09f2d7a9996a504975b7ef7d63e3715bb"
MECH_KEY_8359 = "datamodel_file_ref_no_allow_remote_refs_bypass"
MECH_FP_8359 = (
    "datamodel-code-generator.parser.jsonschema._get_ref_body."
    "file-uri.allow_remote_refs-exempt"
)
PEEL_055 = "362453380f453d53cdd236d8817488631a8f9652"
PEEL_056 = "52d9ef9dec52f3ad14130710eefb010f0e492160"
PEEL_061 = "21a25c4aa3ac6cf55c2e20e33467b95d07892602"
PEEL_062 = "00de1a3517b0c41eb478c6efbd58220aea249db1"
CAND_425G = "a3d7f417be601a15865e8817086644d9451cdb73"
CARRIER_425G = "bb8915d2673d448b7b89ef484d7fef464f9c6684"
LINEAGE_425G = "6ad5d5ca79a0c7db6b6ae542192fc3cfa2ae4925"
FIX_425G = "6e7f938dcb7928faf5fd12bb5559f6dae2944124"
CAND_HC8V = "d83871ed0314f604e417f40733f762acfdcbc35c"
CARRIER_HC8V = "b1fab6cb0d33be2e084565bf04bb9222c8d1f419"
FIX_HC8V = "008a78f2dd86f52544ddff8b8e8ddeecdf3f7aab"
HUMAN_PIMCORE = "e96631216bb439896cc5979ed9f2850eaf28d2f4"
SQUASH_PIMCORE = "dbe1d131e49421eee5a427f1ae0dec5735639ff3"
HUMAN_HHJV = "92396b576d1ec8a39600ad510930d3e1a21484e7"
SQUASH_HHJV = "8f1c1db4f3e6d9e0beb16dc69bf07b10f12276cc"
CLAIMED_73HC = "fd2bbf49cca2b01ee6cbd158b053e7051f586b7e"
ORIGIN_73HC = "4e796e2814149f966901dc59528da230a9da93b3"
CAND_282G = "8fc11a7366dcaf24a11d3c4fd26e86f5e61d4d1f"
CAND_45Q4 = "5f795bb531eefb1ada2d4597a47074af0e8fbc90"
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

P_C84 = "autoresearch/orchestrator-260814-ghsa200-canonical84"
P_C84_LEDGER = P_C84 + "/ledger.jsonl"
P_C84_SUM = P_C84 + "/summary.json"
P_C84_MAN = P_C84 + "/manifest.json"
P_PKT = "autoresearch/herdr-260814-w3-p123-narrow-redteam-grok46-xhigh"
P_CAP_8359 = "autoresearch/orchestrator-260814-ghsa200-canonical85/8359_acceptance.json"
P_NEG = "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json"
NEW_APPEND_IDENTITIES = (CASE_8359,)
NEW_PACKET_AUTHORITY = (
    {
        "authority_rank": 42,
        "packet": P_PKT,
        "role": "redteam",
        "status": "TERMINAL",
        "terminal": True,
    },
)

FROZEN = {
    "canonical84_ledger": (P_C84_LEDGER, "a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06"),
    "canonical84_summary": (P_C84_SUM, "6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a"),
    "canonical84_manifest": (P_C84_MAN, "a4b930757e97a3ecaa76fde28a0ee37ebd851717bc0eb214d42fb6292fc00bec"),
    "cases_p123": (P_PKT + "/cases.jsonl", "272e8a7b3085d085b0b4134fcaafe6809f08665e8747658a1d9a4bdcb7e0ab80"),
    "result_p123": (P_PKT + "/result.json", "bef578650551db047aa240cc492a9b32df54e45c733cdeaeafe2cf3f79f49119"),
    "report_p123": (P_PKT + "/report.md", "eeb9e0966c2d85920bd1c63c367d4879b4ef7d81331d1c1ca73e708a8576a791"),
}
LOCAL_PINS = {
    "acceptance_8359": (P_CAP_8359, "c55facb25ee7ed22c02865d6b36149b306874b7ef67fbe6095be9bab9a11542e"),
    "negative_controls": (P_NEG, "c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0"),
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
    fills = []
    for name, (relative, expected) in FROZEN.items():
        path = ROOT / relative
        got = sha256_file(path)
        if not expected:
            fills.append(f'    "{name}": ({relative!r}, "{got}"),')
        elif got != expected:
            fills.append(f"frozen mismatch {name}: {got}")
        pinned[name] = {"path": relative, "role": "frozen", "sha256": got}
    for name, (relative, expected) in LOCAL_PINS.items():
        path = ROOT / relative
        got = sha256_file(path)
        if not expected:
            fills.append(f'    "{name}": ({relative!r}, "{got}"),')
        elif got != expected:
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
    assert cap["in_canonical84_strict"] is False
    gates = cap["gates"]
    assert all(gates[field] == "PASS" for field in GATES)
    assert gates[REMEDIATION_GATE] == "PASS"
    ident = cap["identity"]
    assert ident["global_type"] == "reviewed"
    assert ident["withdrawn_at"] is None
    assert ident["published"] is True
    assert_no_leak(compact_json(cap))
    assert not HAN.search(compact_json(cap))


def load_capsule_8359() -> dict:
    cap = load_json(HERE / "8359_acceptance.json")
    _common_capsule_checks(cap, CASE_8359, 85)
    assert cap["aliases"] == [ALIAS_8359]
    assert cap["repository"] == "koxudaxi/datamodel-code-generator"
    assert cap["mechanism_key"] == MECH_KEY_8359
    assert cap["mechanism_fingerprint"] == MECH_FP_8359
    assert cap["candidate_set"] == [CAND_8359]
    assert cap["carrier_set"] == [CAND_8359]
    assert cap["minimum_fix_set"] == [FIX_8359]
    assert cap["n_parents"] == 1
    assert cap["candidate_on_release_first_parent"] is True
    assert cap["carrier_on_release_first_parent"] is True
    assert cap["authorship_transfer"] is False
    shas = cap["object_shas"]
    assert shas["counted_candidate"] == CAND_8359
    assert shas["candidate_parent"] == PARENT_8359
    assert shas["carrier"] == CAND_8359
    assert shas["minimum_fix"] == FIX_8359
    assert shas["fix_parent"] == FIX_PARENT_8359
    assert shas["sibling_954p_closer_not_counted"] == FIX_954P
    assert FIX_954P not in cap["candidate_set"]
    assert FIX_954P not in cap["carrier_set"]
    assert FIX_954P not in cap["minimum_fix_set"]
    vuln = cap["vulnerable_release"]
    assert vuln["tag"] == "0.61.0"
    assert vuln["peeled"] == PEEL_061
    assert vuln["first_containing_candidate"] == "0.56.0"
    assert vuln["first_containing_candidate_peeled"] == PEEL_056
    assert vuln["pre_attempt_tag"] == "0.55.0"
    assert vuln["pre_attempt_peeled"] == PEEL_055
    assert vuln["contains_candidate"] is True
    assert vuln["contains_fix"] is False
    assert vuln["file_exemption_present"] is True
    assert vuln["contains_954p_closer"] is True
    fixed = cap["fixed_release"]
    assert fixed["tag"] == "0.62.0"
    assert fixed["peeled"] == PEEL_062
    assert fixed["contains_fix"] is True
    assert fixed["file_exemption_present"] is False
    assert fixed["resolve_local_ref_path_present"] is True
    assert cap["source_hashes"]["cases_jsonl"] == FROZEN["cases_p123"][1]
    assert cap["source_hashes"]["result_json"] == FROZEN["result_p123"][1]
    assert cap["source_hashes"]["report_md"] == FROZEN["report_p123"][1]
    assert cap["source_hashes"]["advisory_json"] == "33c217e32b14c99e7846997031ea8374dd7840868e67fb85ba60e76d24fe3c75"
    return cap


def load_negative() -> dict:
    blob = load_json(HERE / "negative_controls.json")
    assert blob["capsule_kind"] == "negative_control_regression_guard"
    assert blob["role"] == "regression_guard_not_ledger_admission"
    assert len(blob["controls"]) == 6
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
    hc73 = by_id[CASE_73HC]
    assert hc73["verdict"] == "REJECT"
    assert hc73["countable"] is False
    assert hc73["reject_class"] == "SIBLING_ROUTE_PARENT_HAD_EQUIVALENT_ENTRYPOINT"
    assert hc73["object_shas"]["claimed_ai_sibling"] == CLAIMED_73HC
    assert hc73["object_shas"]["unmarked_health_origin"] == ORIGIN_73HC
    zit = by_id[CASE_282G]
    assert zit["verdict"] == "REJECT"
    assert zit["countable"] is False
    assert zit["object_shas"]["hypothesized_squash_carrier"] == CAND_282G
    assert zit["fail_gates"] == ["ai_hunk_gate", "topology_gate", "but_for_gate"]
    vik = by_id[CASE_45Q4]
    assert vik["verdict"] == "REJECT"
    assert vik["object_shas"]["claimed_candidate"] == CAND_45Q4
    assert vik["fail_gates"] == ["ai_hunk_gate", "but_for_gate"]
    assert vik["gates"]["topology_gate"] == "PASS"
    http = by_id[CASE_954P]
    assert http["verdict"] == "REJECT"
    assert http["object_shas"]["shared_candidate_not_merged"] == CAND_8359
    assert http["object_shas"]["minimum_fix"] == FIX_954P
    assert http["fail_gates"] == ["but_for_gate", "remediation_patch_delta_gate"]
    assert http["shared_candidate_does_not_merge_cases"] is True
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
    refs = list(cap["primary_urls"]) + [P_CAP_8359]
    extra = {
        "n_parents": 1,
        "candidate_on_release_first_parent": True,
        "carrier_on_release_first_parent": True,
        "authorship_transfer": False,
        "sibling_954p_closer_not_counted": FIX_954P,
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
    assert ALIAS_8359 in out["aliases"]
    assert out["leader_strict_case_accepted"] is True
    assert out["counted"] is True
    assert "causal_admission" not in out
    assert "publication_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "pages/ghsa/" not in compact_json(out)
    assert FIX_954P not in out["candidate_set"]
    assert FIX_954P not in out["minimum_fix_set"]
    assert out["minimum_fix_set"] == [FIX_8359]
    return out


def build_outputs() -> dict[Path, str]:
    pins = pin_inputs()
    cap_8359 = load_capsule_8359()
    neg = load_negative()
    base_pairs = load_jsonl_raw(ROOT / P_C84_LEDGER)
    prior_summary = load_json(ROOT / P_C84_SUM)
    prior_manifest = load_json(ROOT / P_C84_MAN)
    base_text = (ROOT / P_C84_LEDGER).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["ledger_sha256"] == pins["canonical84_ledger"]["sha256"]
    assert sha256_bytes(base_text.encode()) == pins["canonical84_ledger"]["sha256"]
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
    for case_id in (
        CASE_8359,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        ALIAS_8359,
    ):
        assert case_id not in base_ids
    assert CASE_8359 not in source_ids
    assert MECH_FP_8359 not in base_fps
    assert MECH_KEY_8359 not in base_mechs

    counted_8359 = counted_from_capsule(cap_8359)
    assert counted_8359["ordinal"] == 85
    assert counted_8359["case_id"] == CASE_8359
    assert seven_pass(counted_8359)
    assert counted_8359[REMEDIATION_GATE] == "PASS"
    assert counted_8359["leader_strict_case_accepted"] is True
    assert "causal_admission" not in counted_8359
    assert_no_leak(compact_json(counted_8359))
    assert not HAN.search(compact_json(counted_8359))

    new_line = compact_json(counted_8359)
    ledger_text = base_text if base_text.endswith("\n") else base_text + "\n"
    ledger_text = ledger_text + new_line + "\n"
    records = [json.loads(line) for line in ledger_text.splitlines() if line.strip()]
    assert [line for line, _ in base_pairs] == ledger_text.splitlines()[:BASE_LEDGER_RECORDS]
    assert "".join(line + "\n" for line, _ in base_pairs) == "".join(
        line + "\n" for line in ledger_text.splitlines()[:BASE_LEDGER_RECORDS]
    )

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == [counted_8359]
    assert len(counted_rows) == STRICT_COUNT
    assert len(records) == LEDGER_RECORDS
    assert ALIAS_8359 not in [row["case_id"] for row in counted_rows]
    for banned in (
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
        ALIAS_8359,
        LINEAGE_425G,
    ):
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
    assert len(prior_append) == 14
    assert new_append == [CASE_8359]
    assert append_identities == prior_append + [CASE_8359]
    assert len(append_identities) == 15
    assert counted_8359["action"] == "APPEND"
    assert counted_8359["in_fp211_212"] is False
    neg_ids = [row["case_id"] for row in neg["controls"]]
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical85-hold",
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
            "appended_8359_one": [CASE_8359],
            "downgraded": [EXCLUDE_4FXP],
            "narrow_noncounting": [EXCLUDE_F38V, EXCLUDE_4FXP, EXCLUDE_NARROW, EXCLUDE_GOPACKET],
            "negative_control_rejected": [
                CASE_PIMCORE,
                CASE_HHJV,
                CASE_73HC,
                CASE_282G,
                CASE_45Q4,
                CASE_954P,
            ],
            "directory_name": "orchestrator-260814-ghsa200-canonical85",
            "prior_directory": "orchestrator-260814-ghsa200-canonical84",
            "prior_commit": "6800d2127c19532160cc88880115ae28cc446aa5",
            "note": "Directory name is canonical85. Semantic target is canonical strict count 85: the prior 84 exact strict IDs plus first-party GHSA-8359-H9FX-J6V9 at ordinal 85. Source conservation remains 211 hypotheses and 212 GHSA cases. The new identity is absent from the 212 source layer, so it APPENDS the counted set (new_identities_append=true) without promoting a same-id source row and without adding PRESERVED_PUBLIC_CASE or APPEND_IDENTITY ledger rows. Negative-control REJECT identities are not counted. Publication and integration stay closed. Greater-than-200 remains unsupported.",
        },
        "counting_unit": "first-party GHSA case",
        "language": "en",
        "causal_admission": False,
        "integration_ready": False,
        "publication_admission": False,
        "publication_ready": False,
        "public_200_claim_supported": False,
        "claim_boundary": "HOLD snapshot of canonical strict count 85 first-party GHSA identities: the prior 84 plus GHSA-8359-H9FX-J6V9. Source conservation remains 211 hypotheses and 212 GHSA cases. This does not support a greater-than-200 claim. Publication and integration stay closed.",
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
            "appended_strict_rows": 1,
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
            "keep_8359": 1,
            "netnew22_narrow_excluded": 1,
            "b3_narrow_excluded": 1,
            "batch9_three_narrow_excluded": 1,
            "pimcore_2mhj_negative_control_rejected": 1,
            "hhjv_negative_control_rejected": 1,
            "route73hc_negative_control_rejected": 1,
            "zitadel_282g_negative_control_rejected": 1,
            "vikunja_45q4_negative_control_rejected": 1,
            "datamodel_954p_negative_control_rejected": 1,
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
            "GHSA-282G-FHMX-XF54": "negative-control REJECT: squash copy of parent UpdateHumanUser IsVerified mapping; Copilot trailer on a many-author carrier; not counted",
            "GHSA-45Q4-X4R9-8FQJ": "negative-control REJECT: Copilot grammar sibling; GHSA-quoted overdue task-title join is in the parent; not counted",
            "GHSA-954P-556P-R752": "negative-control REJECT: shared candidate SHA with GHSA-8359; closer 5fdba4a hardens the pre-existing shared HTTP fetcher and leaves allow_remote_refs=None fetching; not counted",
            "GHSA-M63V-2G9W-2W6V": "distinct fission identity; not merged with QF5V; not counted in this snapshot",
            "lineage_duplicate_6ad5d5ca": "lineage evidence for GHSA-425G; not a separately counted candidate",
            "CVE-2026-71556": "alias of GHSA-HC8V-WWC9-VGXM; not a counting unit",
            "CVE-2026-55389": "alias of GHSA-8359-H9FX-J6V9; not a counting unit",
            "discovery_tabs": "not included",
            "worker_only_PASS": "not included",
            "cartesian_candidate_fix_edges": "not invented; 425G binds a3d7f417 to 6e7f938d; HC8V binds d83871ed to 008a78f2; 8359 binds f6d4cbd3 to 2ff4a72b",
        },
        "seven_gates": list(GATES),
        "remediation_patch_delta_gate": "required PASS on GHSA-8359-H9FX-J6V9",
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
    assert neg_ids == [
        CASE_PIMCORE,
        CASE_HHJV,
        CASE_73HC,
        CASE_282G,
        CASE_45Q4,
        CASE_954P,
    ]
    report = "\n".join(
        [
            "# Canonical85 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 85 first-party GHSA identities. It extends the frozen canonical84 snapshot in orchestrator-260814-ghsa200-canonical84 by appending exactly one leader-replayed identity. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical84 meaning and are not flipped by counting GHSA-8359. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical84 ledger row is preserved byte-for-byte and in order. The prior 84 counted rows stay byte-identical. Terminal w3-p123 narrow red-team KEEP 1 is appended at ordinal 85. Count is by first-party GHSA identity once. CVE aliases are stored and never counted.",
            "",
            "The admitted identity at ordinal 85 is GHSA-8359-H9FX-J6V9, alias CVE-2026-55389, repository koxudaxi/datamodel-code-generator, class AI_INCOMPLETE_REMEDIATION. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. candidate_set is f6d4cbd3. carrier_set equals candidate_set: the GitHub squash is the first-parent landing and no separate merge is invented. minimum_fix_set is 2ff4a72b. The Claude-coauthored candidate explicitly added the allow_remote_refs security gate but exempted file://. The minimum fix closes that residual in 0.62.0. All seven contract gates are PASS. Remediation patch-delta is PASS. Candidate is absent from tag 0.55.0 and present from 0.56.0 through 0.61.0. Immutable git tag 0.61.0 is the last vulnerable artifact (file:// exemption still present). Immutable git tag 0.62.0 is the fixed artifact.",
            "",
            "GHSA-282G-FHMX-XF54 is a compact negative-control REJECT: squash copy of parent UpdateHumanUser IsVerified mapping. GHSA-45Q4-X4R9-8FQJ is a compact negative-control REJECT: Copilot grammar sibling of a parent overdue-title sink. GHSA-954P-556P-R752 is a compact negative-control REJECT: shared candidate SHA with GHSA-8359; closer 5fdba4a hardens the pre-existing shared HTTP fetcher and leaves allow_remote_refs=None fetching. Shared SHA does not merge cases. Inherited negative controls GHSA-2MHJ, GHSA-HHJV, and GHSA-73HC remain rejected. Negative controls are not ledger admissions and are absent from strict rows.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer, including dual ordinal-200 identities GHSA-3J8Q-FWPJ-F8J5 and GHSA-JJCJ-H3CM-P7X7. Same-id upgrades still do not append. GHSA-8359 is a new identity (in_fp211_212=false, action=APPEND). Conservation prior_append_identities stays the prior 14. new_append_identities is exactly GHSA-8359-H9FX-J6V9. append_identities is the prior 14 followed by that one (15). new_identities_append is true. same_id_source_layer_promoted is false. The w3-p123 narrow red-team packet admits this row at authority rank 42; prior packet authorities do not admit them. Discovery tabs and worker-only PASS are not loaded. Raw API pages and owned clones are not committed; the builder consumes 8359_acceptance.json, negative_controls.json, plus immutable canonical84 tracked artifacts.",
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
    assert CASE_8359 in report
    assert CASE_282G in report
    assert CASE_45Q4 in report
    assert CASE_954P in report
    assert ALIAS_8359 in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "new_identities_append is true" in report
    assert "prior packet authorities do not admit them" in report
    assert "only prior" not in report.lower()

    inherited_authority = [dict(item) for item in prior_manifest["packet_authority"]]
    packet_authority = inherited_authority + [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert len(inherited_authority) == 20
    assert inherited_authority[-2]["authority_rank"] == 40
    assert inherited_authority[-1]["authority_rank"] == 41
    assert packet_authority[-1] == dict(NEW_PACKET_AUTHORITY[0])
    assert packet_authority[-1]["packet"] == P_PKT
    assert packet_authority[-1]["authority_rank"] == 42
    assert len(packet_authority) == 21
    cons = summary["conservation"]
    assert cons["new_identities_append"] is True
    assert cons["same_id_source_layer_promoted"] is False
    assert cons["upgrades_append"] is False
    assert cons["new_append_identities"] == [CASE_8359]
    assert cons["prior_append_identities"] == prior_append
    assert cons["append_identities"] == prior_append + [CASE_8359]
    assert cons["appended_strict_rows"] == 1
    assert cons["fp211_hypotheses"] == 211
    assert cons["fp211_source_ghsa_cases"] == 212

    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical85-hold",
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
        print("PASS: canonical85 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
