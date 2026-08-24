#!/usr/bin/env python3
"""Build the HOLD canonical86-directory snapshot at strict count 86. Stdlib only.

Consumes the local FRVJ capsule plus immutable canonical85 tracked artifacts.
Does not read raw API pages, wheels, worker caches, or owned clones.
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
PRIOR_STRICT = 85
STRICT_COUNT = 86
BASE_LEDGER_RECORDS = 582
LEDGER_RECORDS = 583
CASE_FRVJ = "GHSA-FRVJ-C5QP-XJ4W"
CASE_R2WG = "GHSA-R2WG-2MCR-66RV"
ALIAS_FRVJ = "CVE-2026-59221"
CAND_FRVJ = "03547759179672d216d2e1376dd1ae4fdad76a94"
PARENT_FRVJ = "d4030a8aa5d48c2a1cb06c461566844aca2530ab"
FIX_FRVJ = "05098d25a58d03738e01c4e85e8852c3b4ad849c"
FIX_PARENT_FRVJ = "3266a8c9eb6b8408a869a33378a0f4ad8a46809e"
MECH_KEY_FRVJ = "open-webui.terminals.sanitize-proxy-path.decode-cap"
MECH_FP_FRVJ = "open-webui.routers.terminals._sanitize_proxy_path.range8-fail-open"
WHEEL_096 = "ce5fdd1b8acf2b823c87417242dea4e6686d6130a98e766954ec6f04e5e146ed"
WHEEL_010 = "4bd16d93dc86e955939bb1b40409a7013108708bf4cba61871e0ff5112802460"
CASE_PIMCORE = "GHSA-2MHJ-FHVG-V428"
CASE_HHJV = "GHSA-HHJV-JQ77-CMVX"
CASE_73HC = "GHSA-73HC-M4HX-79PJ"
CASE_282G = "GHSA-282G-FHMX-XF54"
CASE_45Q4 = "GHSA-45Q4-X4R9-8FQJ"
CASE_954P = "GHSA-954P-556P-R752"
CASE_8359 = "GHSA-8359-H9FX-J6V9"
FILEBROWSER_NEG = "post:filebrowser-delete-scope@canonical"
FILEBROWSER_POS = "post:filebrowser-dangling-write@canonical"
ORD200 = ("GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7")

P_C85 = "autoresearch/orchestrator-260814-ghsa200-canonical85"
P_C85_LEDGER = P_C85 + "/ledger.jsonl"
P_C85_SUM = P_C85 + "/summary.json"
P_C85_MAN = P_C85 + "/manifest.json"
P_NEG = P_C85 + "/negative_controls.json"
P_HOSTILE = "autoresearch/herdr-260814-frvj-hostile2-grok46-medium"
P_WORKER = "autoresearch/herdr-260814-fresh-strict-grok46-xhigh"
P_CAP = "autoresearch/orchestrator-260814-ghsa200-canonical86/frvj_acceptance.json"
NEW_APPEND_IDENTITIES = (CASE_FRVJ,)
NEW_PACKET_AUTHORITY = (
    {
        "authority_rank": 43,
        "packet": P_WORKER,
        "role": "worker",
        "status": "TERMINAL",
        "terminal": True,
    },
    {
        "authority_rank": 44,
        "packet": P_HOSTILE,
        "role": "redteam",
        "status": "TERMINAL",
        "terminal": True,
    },
)

FROZEN = {
    "canonical85_ledger": (P_C85_LEDGER, "2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568"),
    "canonical85_summary": (P_C85_SUM, "47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c"),
    "canonical85_manifest": (P_C85_MAN, "5781078c8b286a454b647c84447fa8c9ff4dc2068f3c45acb45acddb50167abd"),
    "canonical85_negative_controls": (P_NEG, "c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0"),
    "hostile_case": (P_HOSTILE + "/case.json", "e7a8f1a543f9750acd3a71265b403950de8c0dfa28ad39de8b231dec78ae7c94"),
    "hostile_result": (P_HOSTILE + "/result.json", "09f6766fd94bf30ee0232e7ad05cc69fe9f92748181a18794a234f3cb2c51013"),
    "hostile_report": (P_HOSTILE + "/report.md", "c389b9f8d3f7f65a953d1e0cbac43334449800ce670d3f0a3936ac0a5d82adf5"),
    "hostile_replay": (P_HOSTILE + "/replay.zsh", "09d040976e91bbf99a1c3e43bbac9ce3ea55b370dcc05bdb5b02a5fa96a7e8a5"),
    "worker_cases": (P_WORKER + "/cases.jsonl", "6a13b08e9b569dfab705385985d5ea49f561c26e8ac28831e620c3e4dce1a742"),
    "worker_result": (P_WORKER + "/result.json", "6144d75201cd2f9bd01af484708db80a485825ef6bcc91fa22b6334de3beded4"),
    "worker_report": (P_WORKER + "/report.md", "94bc6f93423407f51115fcae412b690fdc497ce8d81f800c0ad3dd33cad02eec"),
    "worker_replay": (P_WORKER + "/replay.zsh", "a81169488f8480c542f13e0888522fb463eb537e737e9a945be4dd8c8f4bf9d7"),
}
LOCAL_PINS = {
    "acceptance_frvj": (P_CAP, "5549499c04a1f1cba5377f2e59214d370822110f9c0c451df82f100a172696d9"),
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


def load_capsule_frvj() -> dict:
    cap = load_json(HERE / "frvj_acceptance.json")
    assert cap["case_id"] == CASE_FRVJ
    assert cap["ordinal"] == 86
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
    assert cap["in_canonical85_strict"] is False
    assert cap["distinct_from_r2wg"] is True
    assert cap["r2wg_identity_not_counted"] == CASE_R2WG
    assert cap["aliases"] == [ALIAS_FRVJ]
    assert cap["repository"] == "open-webui/open-webui"
    assert cap["mechanism_key"] == MECH_KEY_FRVJ
    assert cap["mechanism_fingerprint"] == MECH_FP_FRVJ
    assert cap["candidate_set"] == [CAND_FRVJ]
    assert cap["carrier_set"] == []
    assert cap["minimum_fix_set"] == [FIX_FRVJ]
    assert cap["n_parents"] == 1
    assert cap["authorship_transfer"] is False
    gates = cap["gates"]
    assert all(gates[field] == "PASS" for field in GATES)
    assert gates[REMEDIATION_GATE] == "PASS"
    ident = cap["identity"]
    assert ident["global_type"] == "reviewed"
    assert ident["withdrawn_at"] is None
    assert ident["published"] is True
    shas = cap["object_shas"]
    assert shas["counted_candidate"] == CAND_FRVJ
    assert shas["candidate_parent"] == PARENT_FRVJ
    assert shas["minimum_fix"] == FIX_FRVJ
    assert shas["fix_parent"] == FIX_PARENT_FRVJ
    vuln = cap["vulnerable_release"]
    assert vuln["version"] == "0.9.6"
    assert vuln["sha256"] == WHEEL_096
    assert vuln["contains_attempt_sanitizer"] is True
    assert vuln["contains_fail_closed"] is False
    assert vuln["yanked"] is False
    fixed = cap["fixed_release"]
    assert fixed["version"] == "0.10.0"
    assert fixed["sha256"] == WHEEL_010
    assert fixed["contains_fail_closed"] is True
    assert fixed["yanked"] is False
    assert cap["source_hashes"]["hostile_case_json"] == FROZEN["hostile_case"][1]
    assert cap["source_hashes"]["hostile_result_json"] == FROZEN["hostile_result"][1]
    assert cap["source_hashes"]["hostile_report_md"] == FROZEN["hostile_report"][1]
    assert cap["source_hashes"]["hostile_replay_script"] == FROZEN["hostile_replay"][1]
    assert cap["source_hashes"]["worker_cases_jsonl"] == FROZEN["worker_cases"][1]
    assert cap["admission_source"] == "frvj_hostile2_redteam_keep"
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


def counted_from_capsule(cap: dict) -> dict:
    g = {field: cap["gates"][field] for field in GATES}
    refs = list(cap["primary_urls"]) + [P_CAP]
    out = {
        "action": "APPEND",
        "admission_source": cap["admission_source"],
        "aliases": list(cap["aliases"]),
        "authorship_transfer": False,
        "candidate_parent": cap["object_shas"]["candidate_parent"],
        "candidate_set": list(cap["candidate_set"]),
        "carrier_set": list(cap["carrier_set"]),
        "cartesian_candidate_fix_refused": True,
        "case_id": cap["case_id"],
        "contribution_class": cap["contribution_class"],
        "counted": True,
        "counting_unit": "first-party GHSA case",
        "distinct_from_r2wg": True,
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "first_party_source_refs": refs,
        "fix_parent": cap["object_shas"]["fix_parent"],
        "in_fp211_212": False,
        "leader_strict_case_accepted": True,
        "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        "mechanism_fingerprint": cap["mechanism_fingerprint"],
        "mechanism_key": cap["mechanism_key"],
        "minimum_fix_set": list(cap["minimum_fix_set"]),
        "n_parents": 1,
        "ordinal": cap["ordinal"],
        "overlay_state": "KEEP",
        "record_kind": "STRICT_RELEASED_CASE",
        "repository": cap["repository"],
        "row_key": f"ghsa200-next:{cap['case_id']}",
        "schema_version": SCHEMA,
        "scope_statement": cap["scope_statement"],
        "source_layer": False,
        **g,
        REMEDIATION_GATE: "PASS",
        "vulnerable_release": dict(cap["vulnerable_release"]),
        "fixed_release": dict(cap["fixed_release"]),
    }
    assert SHA_RE.fullmatch(out["candidate_set"][0])
    assert SHA_RE.fullmatch(out["minimum_fix_set"][0])
    assert SHA_RE.fullmatch(out["candidate_parent"])
    assert SHA_RE.fullmatch(out["fix_parent"])
    assert out["carrier_set"] == []
    assert CASE_FRVJ not in out["aliases"]
    assert ALIAS_FRVJ in out["aliases"]
    assert "causal_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "candidate_fix_edges" not in out
    return out


def build_outputs() -> dict[Path, str]:
    pins = pin_inputs()
    cap = load_capsule_frvj()
    neg = load_negative()
    base_pairs = load_jsonl_raw(ROOT / P_C85_LEDGER)
    prior_summary = load_json(ROOT / P_C85_SUM)
    prior_manifest = load_json(ROOT / P_C85_MAN)
    base_text = (ROOT / P_C85_LEDGER).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["ledger_sha256"] == pins["canonical85_ledger"]["sha256"]
    assert sha256_bytes(base_text.encode()) == pins["canonical85_ledger"]["sha256"]
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
    for case_id in (CASE_FRVJ, CASE_R2WG, ALIAS_FRVJ, CASE_PIMCORE, CASE_HHJV, CASE_73HC, CASE_282G, CASE_45Q4, CASE_954P):
        assert case_id not in base_ids
    assert CASE_FRVJ not in source_ids
    assert MECH_FP_FRVJ not in base_fps
    assert MECH_KEY_FRVJ not in base_mechs

    counted_frvj = counted_from_capsule(cap)
    assert counted_frvj["ordinal"] == 86
    assert seven_pass(counted_frvj)
    assert counted_frvj[REMEDIATION_GATE] == "PASS"
    assert_no_leak(compact_json(counted_frvj))
    assert not HAN.search(compact_json(counted_frvj))

    new_line = compact_json(counted_frvj)
    ledger_text = base_text if base_text.endswith("\n") else base_text + "\n"
    ledger_text = ledger_text + new_line + "\n"
    records = [json.loads(line) for line in ledger_text.splitlines() if line.strip()]
    assert [line for line, _ in base_pairs] == ledger_text.splitlines()[:BASE_LEDGER_RECORDS]

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == [counted_frvj]
    assert len(counted_rows) == STRICT_COUNT
    assert len(records) == LEDGER_RECORDS
    assert ALIAS_FRVJ not in [row["case_id"] for row in counted_rows]
    for banned in (CASE_PIMCORE, CASE_HHJV, CASE_73HC, CASE_282G, CASE_45Q4, CASE_954P, ALIAS_FRVJ, CASE_R2WG):
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
    assert len(prior_append) == 15
    assert new_append == [CASE_FRVJ]
    checkpoint = dict(prior_summary["checkpoint"])
    checkpoint["prior_strict_count"] = PRIOR_STRICT
    checkpoint["corrected_strict_count"] = STRICT_COUNT
    checkpoint["appended_frvj_one"] = [CASE_FRVJ]
    checkpoint["directory_name"] = "orchestrator-260814-ghsa200-canonical86"
    checkpoint["prior_directory"] = "orchestrator-260814-ghsa200-canonical85"
    checkpoint["note"] = (
        "Directory name is canonical86. Semantic target is canonical strict count 86: "
        "the prior 85 exact strict IDs plus first-party GHSA-FRVJ-C5QP-XJ4W at ordinal 86. "
        "Source conservation remains 211 hypotheses and 212 GHSA cases. The new identity is "
        "absent from the 212 source layer, so it APPENDS the counted set "
        "(new_identities_append=true). Negative-control REJECT identities are not counted. "
        "Publication and integration stay closed. Greater-than-200 remains unsupported."
    )
    excluded = dict(prior_summary["excluded"])
    excluded[ALIAS_FRVJ] = "alias of GHSA-FRVJ-C5QP-XJ4W; not a counting unit"
    excluded[CASE_R2WG] = (
        "older terminal-proxy single-decode / missing-sanitizer advisory; distinct GHSA; not counted"
    )
    excluded["cartesian_candidate_fix_edges"] = (
        excluded["cartesian_candidate_fix_edges"] + "; FRVJ binds 0354775917 to 05098d25"
    )
    counts = dict(prior_summary["counts"])
    counts["strict_released_first_party_ghsa"] = STRICT_COUNT
    counts["ledger_records"] = len(records)
    counts["keep_frvj"] = 1
    counts["by_record_kind"] = dict(kinds)
    counts["by_admission_source"] = dict(Counter(row["admission_source"] for row in counted_rows))
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical86-hold",
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
            "HOLD snapshot of canonical strict count 86 first-party GHSA identities: "
            "the prior 85 plus GHSA-FRVJ-C5QP-XJ4W. Source conservation remains 211 "
            "hypotheses and 212 GHSA cases. This does not support a greater-than-200 claim. "
            "Publication and integration stay closed."
        ),
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
        "counts": counts,
        "strict_released_case_ids": counted_ids,
        "excluded": excluded,
        "seven_gates": list(GATES),
        "remediation_patch_delta_gate": "required PASS on GHSA-FRVJ-C5QP-XJ4W",
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
            "# Canonical86 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 86 first-party GHSA identities. It extends the frozen canonical85 snapshot in orchestrator-260814-ghsa200-canonical85 by appending exactly one leader-replayed identity. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical85 meaning and are not flipped by counting GHSA-FRVJ. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical85 ledger row is preserved byte-for-byte and in order. The prior 85 counted rows stay byte-identical. Terminal hostile red-team KEEP GHSA-FRVJ-C5QP-XJ4W is appended at ordinal 86. Count is by first-party GHSA identity once. CVE aliases are stored and never counted.",
            "",
            "The admitted identity at ordinal 86 is GHSA-FRVJ-C5QP-XJ4W, alias CVE-2026-59221, repository open-webui/open-webui, class AI_INCOMPLETE_REMEDIATION. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. candidate_set is 0354775917. carrier_set is empty. minimum_fix_set is 05098d25. The Claude-coauthored candidate rewrote _sanitize_proxy_path from one unquote pass to a range(8) loop. The first-party advisory names the 9x residual of that cap. The minimum fix fail-closes the same loop. All seven contract gates are PASS. Remediation patch-delta is PASS. Public PyPI 0.9.6 contains the attempt sanitizer without fail-closed. Public PyPI 0.10.0 contains the exact reversal. Mechanism key and fingerprint distinguish this residual from uncounted GHSA-R2WG.",
            "",
            "Worker PASS in herdr-260814-fresh-strict-grok46-xhigh is proposal only and lower authority than the hostile review. Inherited negative controls remain rejected and absent from strict rows.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer. Same-id upgrades still do not append. GHSA-FRVJ is a new identity (in_fp211_212=false, action=APPEND). Conservation prior_append_identities stays the prior 15. new_append_identities is exactly GHSA-FRVJ-C5QP-XJ4W. append_identities is the prior 15 followed by that one (16). new_identities_append is true. same_id_source_layer_promoted is false. The hostile red-team packet admits this row at authority rank 44; the worker packet is recorded at rank 43 and does not admit the row. Discovery tabs and worker-only PASS are not loaded. Raw wheels, pages, and owned clones are not committed; the builder consumes frvj_acceptance.json plus immutable canonical85 tracked artifacts.",
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
    assert CASE_FRVJ in report
    assert ALIAS_FRVJ in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "new_identities_append is true" in report
    inherited_authority = [dict(item) for item in prior_manifest["packet_authority"]]
    packet_authority = inherited_authority + [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert len(inherited_authority) == 21
    assert inherited_authority[-1]["authority_rank"] == 42
    assert packet_authority[-1]["authority_rank"] == 44
    assert packet_authority[-2]["authority_rank"] == 43
    assert packet_authority[-2]["role"] == "worker"
    assert packet_authority[-1]["role"] == "redteam"
    assert len(packet_authority) == 23
    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical86-hold",
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
        print("PASS: canonical86 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
