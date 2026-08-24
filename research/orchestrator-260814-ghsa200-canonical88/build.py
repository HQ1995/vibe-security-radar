#!/usr/bin/env python3
"""Build the HOLD canonical88-directory snapshot at strict count 88. Stdlib only.

Consumes the local 8RW6 capsule plus immutable canonical87 tracked artifacts.
Does not read raw API pages, crates, worker caches, or owned clones.
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
PRIOR_STRICT = 87
STRICT_COUNT = 88
BASE_LEDGER_RECORDS = 584
LEDGER_RECORDS = 585
CASE_8RW6 = "GHSA-8RW6-P7M8-63JP"
CASE_V52W = "GHSA-V52W-28XH-V562"
CASE_FRVJ = "GHSA-FRVJ-C5QP-XJ4W"
CAND_8RW6 = "15579bd2cc57a3f88074acf54b42008598d9c87f"
PARENT_8RW6 = "ce74c0278e0a6901e197ec4fa1b55c90dee2e491"
FIX_8RW6 = "8f89b260bb9692e5b0d58930793d482a8207eedc"
FIX_PARENT_8RW6 = "11430e25f523b6a8f84fa1800a236c828351bf28"
HUMAN_DOC = "25d16748781259d4d6854227ee4a287bcd2e96b1"
MECH_KEY_8RW6 = "surrealdb.scan.pipeline.filter_fields_by_permission.each-cut.forward-index-shift"
MECH_FP_8RW6 = "surrealdb.scan.pipeline.filter_fields_by_permission.each-cut.forward-index-shift"
CRATE_313 = "68e4926bc2f0cd6d1eb6a95da2024432510cbf37571133c22c62ddce3d98e22a"
CRATE_314 = "f3097d6247661f5c5a319fa1f4683d5beba2956c6b86615ad69b55f988ab135b"
PEEL_313 = "7db9a42083e164dcaede273a48bf22df53a3c8c6"
PEEL_314 = "c9e039542e85c3853f26219198df1ae64291edda"
BLOB_PARENT = "844402787fbbf75e9bdab2432ed664e48266db01"
BLOB_CAND = "876132653b5c095d3787a57c86e28e728e05cbc1"
BLOB_313 = "0160c213fea8f30027867cb90b187947d1901a2e"
BLOB_314 = "e0e00f7ab83bdffa355d0fc71ece39c35699997b"
BLOB_313_OUT = "beee67cad49fe72ce861d9b09694b0f95652305d"
BLOB_314_OUT = "8c0392d701c5ab4f486d1a9fb8b47dd64642d4a6"
BLOB_313_RED = "dffe1b59006781f04ae0e112535d8772709bbd5f"
BLOB_314_RED = "fb4e9cd56fd35129995ce6899a1f8f6bf82bbe10"
FILE = "surrealdb/core/src/exec/operators/scan/pipeline.rs"
OUTF = "surrealdb/core/src/doc/output.rs"
RED = "surrealdb/core/src/doc/reduce.rs"
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

P_C87 = "autoresearch/orchestrator-260814-ghsa200-canonical87"
P_C87_LEDGER = P_C87 + "/ledger.jsonl"
P_C87_SUM = P_C87 + "/summary.json"
P_C87_MAN = P_C87 + "/manifest.json"
P_NEG = "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json"
P_HOSTILE = "autoresearch/herdr-260814-surrealdb-8rw6-hostile-grok46-xhigh"
P_CAP = "autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json"
NEW_APPEND_IDENTITIES = (CASE_8RW6,)
NEW_PACKET_AUTHORITY = (
    {
        "authority_rank": 46,
        "packet": P_HOSTILE,
        "role": "redteam",
        "status": "TERMINAL",
        "terminal": True,
    },
)

FROZEN = {
    "canonical87_ledger": (P_C87_LEDGER, "b6dc7e781017e60a94725696b5a08b229a5cb026ffd098e6306e9a8941f9fdbe"),
    "canonical87_summary": (P_C87_SUM, "17487d40720f4c20475df7df270e5bb1139726887c42bc50d999f0f7e713a722"),
    "canonical87_manifest": (P_C87_MAN, "467b57fdabb059b6b9aabb196a247c0b8f9429ad3dff6ac1d351030bd172385c"),
    "canonical85_negative_controls": (P_NEG, "c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0"),
    "hostile_case": (P_HOSTILE + "/case.json", "243a5e18cc2628398b0e2b3843ba910c418eb3d9479ce64b2364ac4c3b48de50"),
    "hostile_result": (P_HOSTILE + "/result.json", "56cbb18b7a1896232eb62c49880941115d637fce9caa8b853339493038b18a4c"),
    "hostile_report": (P_HOSTILE + "/report.md", "925b72330cdcd4e6a8c660f11abff91d09f247103d481a86dae92b00d21ca022"),
    "hostile_replay": (P_HOSTILE + "/replay.zsh", "c3fc9607f07ce6d17fc3d127db99cb1af35a1bc8a9d5451c26ad8f9c28105721"),
    "hostile_facts_git": (P_HOSTILE + "/facts/git.json", "043c1948f45d27f5faa3b7190cd3fe739b58ef902c2834b6656a8d2be103d8a7"),
    "hostile_facts_releases": (P_HOSTILE + "/facts/releases.json", "314804ef4dbef14d942b4e2f38a332d6a3e62160e20a6aaa1812de4847c1f69f"),
    "hostile_facts_identity": (P_HOSTILE + "/facts/identity.json", "1614038ba16c35720c8157063d4d9b045d40b452d0c974915bdf0da10a3324b8"),
    "hostile_facts_gates": (P_HOSTILE + "/facts/gates.json", "e555c67c566a3c700ececc126f59274dd6c7f21e6ee61d8c0798763261bdc505"),
    "hostile_facts_uniqueness": (P_HOSTILE + "/facts/uniqueness.json", "712d5acbb6d7521a96c73919ad207ea42bd3445150a88c8575a32aedf3ddc64c"),
}
LOCAL_PINS = {
    "acceptance_8rw6": (P_CAP, "8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9"),
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


def ascii_norm(text: str) -> str:
    return (
        text.replace("\u2014", "--")
        .replace("\u2013", "--")
        .replace("\u2026", "...")
        .replace("\u00a0", " ")
    )


def extract_filter_fields(text: str) -> str:
    lines = text.splitlines(True)
    fn_i = next(i for i, line in enumerate(lines) if "filter_fields_by_permission" in line and "fn " in line)
    start = fn_i
    while start > 0 and lines[start - 1].startswith("///"):
        start -= 1
    depth = 0
    started = False
    end = None
    for j in range(fn_i, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if "{" in lines[j]:
            started = True
        if started and depth == 0:
            end = j + 1
            break
    return ascii_norm("".join(lines[start:end]).rstrip() + "\n")


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


def load_capsule_8rw6() -> dict:
    cap = load_json(HERE / "8rw6_acceptance.json")
    assert cap["case_id"] == CASE_8RW6
    assert cap["ordinal"] == 88
    assert cap["verdict"] == "KEEP"
    assert cap["countable_in_this_snapshot"] is True
    assert cap["leader_strict_case_accepted"] is True
    assert cap["causal_admission"] is False
    assert cap["publication_admission"] is False
    assert cap["publication_ready"] is False
    assert cap["contribution_class"] == "AI_NEW_SURFACE_CONTRIBUTOR"
    assert cap["cve_alias_is_not_a_counting_unit"] is True
    assert cap["cartesian_candidate_fix_refused"] is True
    assert cap["in_fp211_212"] is False
    assert cap["in_canonical87_strict"] is False
    assert cap["whole_ghsa_direct_root"] is False
    assert cap["human_pluck_doc_siblings_excluded"] is True
    assert cap["production_default_planner"] == "best-effort"
    assert cap["record_id_reuses_pipeline_filter"] is True
    assert cap["aliases"] == []
    assert cap["repository"] == "surrealdb/surrealdb"
    assert cap["mechanism_key"] == MECH_KEY_8RW6
    assert cap["mechanism_fingerprint"] == MECH_FP_8RW6
    assert cap["candidate_set"] == [CAND_8RW6]
    assert cap["carrier_set"] == []
    assert cap["minimum_fix_set"] == [FIX_8RW6]
    assert cap["n_parents"] == 1
    assert cap["authorship_transfer"] is False
    gates = cap["gates"]
    assert all(gates[field] == "PASS" for field in GATES)
    ident = cap["identity"]
    assert ident["global_type"] == "reviewed"
    assert ident["withdrawn_at"] is None
    assert ident["published"] is True
    assert ident["engine_crate"] == "surrealdb-core"
    shas = cap["object_shas"]
    assert shas["counted_candidate"] == CAND_8RW6
    assert shas["candidate_parent"] == PARENT_8RW6
    assert shas["minimum_fix"] == FIX_8RW6
    assert shas["fix_parent"] == FIX_PARENT_8RW6
    assert shas["parent_pipeline_blob"] == BLOB_PARENT
    assert shas["candidate_pipeline_blob"] == BLOB_CAND
    assert shas["vulnerable_release_pipeline_blob"] == BLOB_313
    assert shas["fixed_release_pipeline_blob"] == BLOB_314
    assert shas["human_output_reduce_added_later_by"] == HUMAN_DOC
    vuln = cap["vulnerable_release"]
    assert vuln["version"] == "3.1.3"
    assert vuln["crates_io_surrealdb_core_checksum"] == CRATE_313
    assert vuln["git_tag_commit"] == PEEL_313
    assert vuln["pipeline_has_forward_each_cut"] is True
    assert vuln["pipeline_has_rev"] is False
    assert vuln["pipeline_blob_equals_fixparent"] is True
    assert vuln["contains_candidate_any_parent"] is True
    assert vuln["contains_fix_any_parent"] is False
    fixed = cap["fixed_release"]
    assert fixed["version"] == "3.1.4"
    assert fixed["crates_io_surrealdb_core_checksum"] == CRATE_314
    assert fixed["git_tag_commit"] == PEEL_314
    assert fixed["pipeline_blob_equals_fix"] is True
    assert fixed["contains_fix_sha_as_ancestor"] is False
    assert fixed["contains_fix_bytes"] is True
    assert cap["source_hashes"]["hostile_case_json"] == FROZEN["hostile_case"][1]
    assert cap["source_hashes"]["hostile_result_json"] == FROZEN["hostile_result"][1]
    assert cap["source_hashes"]["hostile_report_md"] == FROZEN["hostile_report"][1]
    assert cap["source_hashes"]["hostile_replay_script"] == FROZEN["hostile_replay"][1]
    assert cap["admission_source"] == "8rw6_hostile_redteam_keep"
    assert "Do not count whole-GHSA direct root" in cap["scope_statement"]
    assert "pluck_select" in cap["scope_statement"]
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
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "first_party_source_refs": refs,
        "fix_parent": cap["object_shas"]["fix_parent"],
        "human_pluck_doc_siblings_excluded": True,
        "in_fp211_212": False,
        "leader_strict_case_accepted": True,
        "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        "mechanism_fingerprint": cap["mechanism_fingerprint"],
        "mechanism_key": cap["mechanism_key"],
        "minimum_fix_set": list(cap["minimum_fix_set"]),
        "n_parents": 1,
        "ordinal": cap["ordinal"],
        "overlay_state": "KEEP",
        "production_default_planner": "best-effort",
        "record_id_reuses_pipeline_filter": True,
        "record_kind": "STRICT_RELEASED_CASE",
        "repository": cap["repository"],
        "row_key": f"ghsa200-next:{cap['case_id']}",
        "schema_version": SCHEMA,
        "scope_statement": cap["scope_statement"],
        "source_layer": False,
        **g,
        "whole_ghsa_direct_root": False,
        "vulnerable_release": dict(cap["vulnerable_release"]),
        "fixed_release": dict(cap["fixed_release"]),
    }
    assert SHA_RE.fullmatch(out["candidate_set"][0])
    assert SHA_RE.fullmatch(out["minimum_fix_set"][0])
    assert SHA_RE.fullmatch(out["candidate_parent"])
    assert SHA_RE.fullmatch(out["fix_parent"])
    assert out["carrier_set"] == []
    assert out["aliases"] == []
    assert out["contribution_class"] == "AI_NEW_SURFACE_CONTRIBUTOR"
    assert out["whole_ghsa_direct_root"] is False
    assert HUMAN_DOC not in out["candidate_set"]
    assert HUMAN_DOC not in out["minimum_fix_set"]
    assert "causal_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "candidate_fix_edges" not in out
    return out


def build_outputs() -> dict[Path, str]:
    pins = pin_inputs()
    cap = load_capsule_8rw6()
    neg = load_negative()
    base_pairs = load_jsonl_raw(ROOT / P_C87_LEDGER)
    prior_summary = load_json(ROOT / P_C87_SUM)
    prior_manifest = load_json(ROOT / P_C87_MAN)
    base_text = (ROOT / P_C87_LEDGER).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["ledger_sha256"] == pins["canonical87_ledger"]["sha256"]
    assert sha256_bytes(base_text.encode()) == pins["canonical87_ledger"]["sha256"]
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
        CASE_8RW6,
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
    ):
        assert case_id not in base_ids
    assert CASE_8RW6 not in source_ids
    assert MECH_FP_8RW6 not in base_fps
    assert MECH_KEY_8RW6 not in base_mechs

    counted_8rw6 = counted_from_capsule(cap)
    assert counted_8rw6["ordinal"] == 88
    assert seven_pass(counted_8rw6)
    assert_no_leak(compact_json(counted_8rw6))
    assert not HAN.search(compact_json(counted_8rw6))

    new_line = compact_json(counted_8rw6)
    ledger_text = base_text if base_text.endswith("\n") else base_text + "\n"
    ledger_text = ledger_text + new_line + "\n"
    records = [json.loads(line) for line in ledger_text.splitlines() if line.strip()]
    assert [line for line, _ in base_pairs] == ledger_text.splitlines()[:BASE_LEDGER_RECORDS]

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == [counted_8rw6]
    assert len(counted_rows) == STRICT_COUNT
    assert len(records) == LEDGER_RECORDS
    for banned in (CASE_PIMCORE, CASE_HHJV, CASE_73HC, CASE_282G, CASE_45Q4, CASE_954P):
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
    assert len(prior_append) == 17
    assert new_append == [CASE_8RW6]
    checkpoint = dict(prior_summary["checkpoint"])
    checkpoint["prior_strict_count"] = PRIOR_STRICT
    checkpoint["corrected_strict_count"] = STRICT_COUNT
    checkpoint["appended_8rw6_one"] = [CASE_8RW6]
    checkpoint["directory_name"] = "orchestrator-260814-ghsa200-canonical88"
    checkpoint["prior_directory"] = "orchestrator-260814-ghsa200-canonical87"
    checkpoint["note"] = (
        "Directory name is canonical88. Semantic target is canonical strict count 88: "
        "the prior 87 exact strict IDs plus first-party GHSA-8RW6-P7M8-63JP at ordinal 88. "
        "Source conservation remains 211 hypotheses and 212 GHSA cases. The new identity is "
        "absent from the 212 source layer, so it APPENDS the counted set "
        "(new_identities_append=true). Counted class is AI_NEW_SURFACE_CONTRIBUTOR on the "
        "streaming pipeline path only. Whole-GHSA direct root and human pluck/doc siblings "
        "are excluded. Negative-control REJECT identities are not counted. Publication and "
        "integration stay closed. Greater-than-200 remains unsupported."
    )
    excluded = dict(prior_summary["excluded"])
    excluded["whole_ghsa_direct_root_8rw6"] = (
        "GHSA-8RW6 whole-GHSA direct root is not counted; document executor already had each+forward-cut"
    )
    excluded["human_pluck_select_8rw6"] = (
        "Document::pluck_select each+forward-cut at parent ce74c027 is older human origin; not counted"
    )
    excluded["human_doc_output_reduce_8rw6"] = (
        "doc/output.rs and doc/reduce.rs added later by unmarked 25d16748; closer also reverses them; not counted"
    )
    excluded["github_pr_81_unrelated"] = (
        "github.com/surrealdb/surrealdb/pull/81 is an unrelated integer-range PR; not the candidate member"
    )
    excluded["crates_io_surrealdb_client"] = (
        "crates.io package surrealdb is a client crate; engine bytes ship in surrealdb-core"
    )
    excluded["moving_branch_main"] = (
        "GitHub release target_commitish main is not containment; tags and crates.io bytes are"
    )
    excluded["GHSA-C8JX-96C9-8XRP"] = "same-repo older SELECT-permission COUNT path; different fingerprint; not counted"
    excluded["GHSA-FPXG-5XMV-922M"] = "same-repo older JSON Patch SELECT-permission GHSA; different fingerprint; not counted"
    excluded["GHSA-6G9V-7GQ3-P2C6"] = "same-repo older error-message leak; different fingerprint; not counted"
    excluded["GHSA-9722-9J67-VJCR"] = "same-repo distinct SELECT-permission identity; different fingerprint; not counted"
    excluded["cartesian_candidate_fix_edges"] = (
        excluded["cartesian_candidate_fix_edges"] + "; 8RW6 binds 15579bd2cc to 8f89b260bb with empty carrier_set"
    )
    counts = dict(prior_summary["counts"])
    counts["strict_released_first_party_ghsa"] = STRICT_COUNT
    counts["ledger_records"] = len(records)
    counts["keep_8rw6"] = 1
    counts["by_record_kind"] = dict(kinds)
    counts["by_admission_source"] = dict(Counter(row["admission_source"] for row in counted_rows))
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical88-hold",
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
            "HOLD snapshot of canonical strict count 88 first-party GHSA identities: "
            "the prior 87 plus GHSA-8RW6-P7M8-63JP. Source conservation remains 211 "
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
            "# Canonical88 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 88 first-party GHSA identities. It extends the frozen canonical87 snapshot in orchestrator-260814-ghsa200-canonical87 by appending exactly one leader-accepted identity. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical87 meaning and are not flipped by counting GHSA-8RW6. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical87 ledger row is preserved byte-for-byte and in order. The prior 87 counted rows stay byte-identical. Terminal hostile red-team KEEP GHSA-8RW6-P7M8-63JP is appended at ordinal 88. Count is by first-party GHSA identity once. CVE aliases are stored and never counted. This identity has no CVE alias.",
            "",
            "The admitted identity at ordinal 88 is GHSA-8RW6-P7M8-63JP, repository surrealdb/surrealdb, class AI_NEW_SURFACE_CONTRIBUTOR. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. Counted surface is only surrealdb/core/src/exec/operators/scan/pipeline.rs filter_fields_by_permission. Parent ce74c027 used HashMap top-level remove. Candidate 15579bd2 adds Value::each plus forward value.cut. carrier_set is empty. minimum_fix_set is 8f89b260, parent 11430e25. Whole-GHSA direct root is excluded. Older human pluck_select and later human doc/output.rs and doc/reduce.rs siblings are excluded. Default production planner is best-effort; record-id scans reuse the pipeline. All seven contract gates are PASS. Public GitHub tag v3.1.3 and crates.io surrealdb-core 3.1.3 contain the forward loop. Public tag v3.1.4 and crates.io surrealdb-core 3.1.4 contain the closer pipeline bytes even though 8f89 is not a tag ancestor. Mechanism key and fingerprint are unique versus canonical87.",
            "",
            "Admission source is the compact hostile packet herdr-260814-surrealdb-8rw6-hostile-grok46-xhigh after leader replay. Inherited negative controls remain rejected and absent from strict rows.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer. Same-id upgrades still do not append. GHSA-8RW6 is a new identity (in_fp211_212=false, action=APPEND). Conservation prior_append_identities stays the prior 17. new_append_identities is exactly GHSA-8RW6-P7M8-63JP. append_identities is the prior 17 followed by that one (18). new_identities_append is true. same_id_source_layer_promoted is false. The hostile red-team packet admits this row at authority rank 46. Discovery tabs and worker-only PASS are not loaded. Raw pages, crates, and owned clones are not committed; the builder consumes 8rw6_acceptance.json plus immutable canonical87 tracked artifacts.",
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
    assert CASE_8RW6 in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "new_identities_append is true" in report
    assert "AI_NEW_SURFACE_CONTRIBUTOR" in report
    assert "whole-GHSA" in report or "Whole-GHSA" in report
    inherited_authority = [dict(item) for item in prior_manifest["packet_authority"]]
    packet_authority = inherited_authority + [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert len(inherited_authority) == 24
    assert inherited_authority[-1]["authority_rank"] == 45
    assert packet_authority[-1]["authority_rank"] == 46
    assert packet_authority[-1]["role"] == "redteam"
    assert packet_authority[-1]["packet"] == P_HOSTILE
    assert len(packet_authority) == 25
    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical88-hold",
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
        print("PASS: canonical88 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
