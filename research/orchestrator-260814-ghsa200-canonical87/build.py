#!/usr/bin/env python3
"""Build the HOLD canonical87-directory snapshot at strict count 87. Stdlib only.

Consumes the local V52W capsule plus immutable canonical86 tracked artifacts.
Does not read raw API pages, npm tarballs, worker caches, or owned clones.
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
PRIOR_STRICT = 86
STRICT_COUNT = 87
BASE_LEDGER_RECORDS = 583
LEDGER_RECORDS = 584
CASE_V52W = "GHSA-V52W-28XH-V562"
CASE_FRVJ = "GHSA-FRVJ-C5QP-XJ4W"
CAND_V52W = "4f86724bd112b07e68033098562c1c4ddc37d93b"
PARENT_V52W = "c84c70c7088f70718a5411d4ef20fabbfe3a429c"
CARR_V52W = "bc9dc69d62aaa567a2ccefee12d28a58b96d96c4"
FIX_V52W = "7c3ae2e3b7c996571acc07c96222b6dc2de01a3e"
FIX_PARENT_V52W = "41f68feccccfa34a93834a70ce2abc9311aeb2d9"
REST_164 = "07368b7e8630e471be3a046dcd8e3a51c3190bdc"
MECH_KEY_V52W = "kozou.mcp.startHttpServer.host-origin-and-body-cap"
MECH_FP_V52W = "kozou.mcp.startHttpServer.no-host-origin-unbounded-readJsonBody"
NPM_180 = "bf19ad97d101a2a08327811c9b91aee9c38eb3d48be633a2d1511e79e52d6ff2"
NPM_181 = "d785844b2c97d7c274a5fc5b08523daaab9338fd181b251b6d818a27f51b7eb8"
PEEL_180 = "e631527918dc2e90c3f324d64af6cf75db8f8aa2"
PEEL_181 = "17f3207e24ca0e7858d6836824539bfb0628415b"
BLOB_INTRO = "1c4a96662fa37741472954bae28a834156802ded"
BLOB_180 = "9643e54351d621ce8af90ef5b8f8365d6b9cd643"
BLOB_181 = "91cc618dbf3ccc448f13deb0e72e0f48b7616898"
CASE_PIMCORE = "GHSA-2MHJ-FHVG-V428"
CASE_HHJV = "GHSA-HHJV-JQ77-CMVX"
CASE_73HC = "GHSA-73HC-M4HX-79PJ"
CASE_282G = "GHSA-282G-FHMX-XF54"
CASE_45Q4 = "GHSA-45Q4-X4R9-8FQJ"
CASE_954P = "GHSA-954P-556P-R752"
FILEBROWSER_NEG = "post:filebrowser-delete-scope@canonical"
FILEBROWSER_POS = "post:filebrowser-dangling-write@canonical"
ORD200 = ("GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7")

P_C86 = "autoresearch/orchestrator-260814-ghsa200-canonical86"
P_C86_LEDGER = P_C86 + "/ledger.jsonl"
P_C86_SUM = P_C86 + "/summary.json"
P_C86_MAN = P_C86 + "/manifest.json"
P_NEG = "autoresearch/orchestrator-260814-ghsa200-canonical85/negative_controls.json"
P_HOSTILE = "autoresearch/herdr-260814-v52w-hostile-grok46-low"
P_CAP = "autoresearch/orchestrator-260814-ghsa200-canonical87/v52w_acceptance.json"
NEW_APPEND_IDENTITIES = (CASE_V52W,)
NEW_PACKET_AUTHORITY = (
    {
        "authority_rank": 45,
        "packet": P_HOSTILE,
        "role": "redteam",
        "status": "TERMINAL",
        "terminal": True,
    },
)

FROZEN = {
    "canonical86_ledger": (P_C86_LEDGER, "3150a7925cc31645b00862595d553db49ec5e07076d87e6c42beec401a647ee7"),
    "canonical86_summary": (P_C86_SUM, "74efef286737bcbd852bf1887ffa34b30224f7902f96a2c45455ba399a4d739c"),
    "canonical86_manifest": (P_C86_MAN, "308c848be3773156b65df6f44135bbaabab63092448e83931b1d76bb686d3ae8"),
    "canonical85_negative_controls": (P_NEG, "c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0"),
    "hostile_case": (P_HOSTILE + "/case.json", "4d0eb83d36943f1551de7c661d1ad43d53e5843d57cae316ea3fa7958d216995"),
    "hostile_result": (P_HOSTILE + "/result.json", "123164d8d6be09f941bfe469256aba6ce77c9eaaba929a21e53a70ec50d58803"),
    "hostile_report": (P_HOSTILE + "/report.md", "2032ee5d2b67fad9a10023014d9c337613e6c3fcd8e74a93ff0512885899e281"),
    "hostile_replay": (P_HOSTILE + "/replay.zsh", "c5ab146c7163599338a5611acb1f9f2264d6ef63e5b54c7ec4171ae40defd03c"),
}
LOCAL_PINS = {
    "acceptance_v52w": (P_CAP, "c01a2b9d54ccc60acdf5bd51ebb35bcaf7d17912a0c4c89017b45c2cb079ebf8"),
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


def load_capsule_v52w() -> dict:
    cap = load_json(HERE / "v52w_acceptance.json")
    assert cap["case_id"] == CASE_V52W
    assert cap["ordinal"] == 87
    assert cap["verdict"] == "KEEP"
    assert cap["countable_in_this_snapshot"] is True
    assert cap["leader_strict_case_accepted"] is True
    assert cap["causal_admission"] is False
    assert cap["publication_admission"] is False
    assert cap["publication_ready"] is False
    assert cap["contribution_class"] == "AI_DIRECT_ROOT"
    assert cap["cve_alias_is_not_a_counting_unit"] is True
    assert cap["cartesian_candidate_fix_refused"] is True
    assert cap["in_fp211_212"] is False
    assert cap["in_canonical86_strict"] is False
    assert cap["counted_bundled_issues"] == [1, 2]
    assert cap["excluded_bundled_issues"] == [3, 4]
    assert cap["aliases"] == []
    assert cap["repository"] == "kozou-dev/kozou"
    assert cap["mechanism_key"] == MECH_KEY_V52W
    assert cap["mechanism_fingerprint"] == MECH_FP_V52W
    assert cap["candidate_set"] == [CAND_V52W]
    assert cap["carrier_set"] == [CARR_V52W]
    assert cap["minimum_fix_set"] == [FIX_V52W]
    assert cap["n_parents"] == 1
    assert cap["authorship_transfer"] is False
    gates = cap["gates"]
    assert all(gates[field] == "PASS" for field in GATES)
    ident = cap["identity"]
    assert ident["global_type"] == "reviewed"
    assert ident["withdrawn_at"] is None
    assert ident["published"] is True
    shas = cap["object_shas"]
    assert shas["counted_candidate"] == CAND_V52W
    assert shas["candidate_parent"] == PARENT_V52W
    assert shas["mainline_carrier"] == CARR_V52W
    assert shas["carrier_parent"] == PARENT_V52W
    assert shas["minimum_fix"] == FIX_V52W
    assert shas["fix_parent"] == FIX_PARENT_V52W
    assert shas["intro_blob"] == BLOB_INTRO
    assert shas["vulnerable_release_blob"] == BLOB_180
    assert shas["fixed_release_blob"] == BLOB_181
    assert shas["excluded_issue3_readonly"] == FIX_PARENT_V52W
    assert shas["excluded_rest_body_164"] == REST_164
    vuln = cap["vulnerable_release"]
    assert vuln["version"] == "1.8.0"
    assert vuln["tarball_sha256"] == NPM_180
    assert vuln["git_tag_commit"] == PEEL_180
    assert vuln["contains_allowed_hosts"] is False
    assert vuln["contains_max_body_bytes"] is False
    assert vuln["unbounded_readJsonBody"] is True
    fixed = cap["fixed_release"]
    assert fixed["version"] == "1.8.1"
    assert fixed["tarball_sha256"] == NPM_181
    assert fixed["git_tag_commit"] == PEEL_181
    assert fixed["contains_allowed_hosts"] is True
    assert fixed["contains_max_body_bytes"] is True
    assert fixed["startHttpServer_blob_equals_fix"] is True
    assert cap["source_hashes"]["hostile_case_json"] == FROZEN["hostile_case"][1]
    assert cap["source_hashes"]["hostile_result_json"] == FROZEN["hostile_result"][1]
    assert cap["source_hashes"]["hostile_report_md"] == FROZEN["hostile_report"][1]
    assert cap["source_hashes"]["hostile_replay_script"] == FROZEN["hostile_replay"][1]
    assert cap["admission_source"] == "v52w_hostile_redteam_keep"
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
        "carrier_parent": cap["object_shas"]["carrier_parent"],
        "carrier_set": list(cap["carrier_set"]),
        "cartesian_candidate_fix_refused": True,
        "case_id": cap["case_id"],
        "contribution_class": cap["contribution_class"],
        "counted": True,
        "counted_bundled_issues": list(cap["counted_bundled_issues"]),
        "counting_unit": "first-party GHSA case",
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "excluded_bundled_issues": list(cap["excluded_bundled_issues"]),
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
        "vulnerable_release": dict(cap["vulnerable_release"]),
        "fixed_release": dict(cap["fixed_release"]),
    }
    assert SHA_RE.fullmatch(out["candidate_set"][0])
    assert SHA_RE.fullmatch(out["carrier_set"][0])
    assert SHA_RE.fullmatch(out["minimum_fix_set"][0])
    assert SHA_RE.fullmatch(out["candidate_parent"])
    assert SHA_RE.fullmatch(out["carrier_parent"])
    assert SHA_RE.fullmatch(out["fix_parent"])
    assert REST_164 not in out["candidate_set"]
    assert REST_164 not in out["carrier_set"]
    assert REST_164 not in out["minimum_fix_set"]
    assert FIX_PARENT_V52W not in out["candidate_set"]
    assert FIX_PARENT_V52W not in out["carrier_set"]
    assert FIX_PARENT_V52W not in out["minimum_fix_set"]
    assert out["counted_bundled_issues"] == [1, 2]
    assert out["excluded_bundled_issues"] == [3, 4]
    assert out["aliases"] == []
    assert "causal_admission" not in out
    assert "clone_path" not in out
    assert "clone" not in out
    assert "candidate_fix_edges" not in out
    return out


def build_outputs() -> dict[Path, str]:
    pins = pin_inputs()
    cap = load_capsule_v52w()
    neg = load_negative()
    base_pairs = load_jsonl_raw(ROOT / P_C86_LEDGER)
    prior_summary = load_json(ROOT / P_C86_SUM)
    prior_manifest = load_json(ROOT / P_C86_MAN)
    base_text = (ROOT / P_C86_LEDGER).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["ledger_sha256"] == pins["canonical86_ledger"]["sha256"]
    assert sha256_bytes(base_text.encode()) == pins["canonical86_ledger"]["sha256"]
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
    for case_id in (CASE_V52W, CASE_PIMCORE, CASE_HHJV, CASE_73HC, CASE_282G, CASE_45Q4, CASE_954P):
        assert case_id not in base_ids
    assert CASE_V52W not in source_ids
    assert MECH_FP_V52W not in base_fps
    assert MECH_KEY_V52W not in base_mechs

    counted_v52w = counted_from_capsule(cap)
    assert counted_v52w["ordinal"] == 87
    assert seven_pass(counted_v52w)
    assert_no_leak(compact_json(counted_v52w))
    assert not HAN.search(compact_json(counted_v52w))

    new_line = compact_json(counted_v52w)
    ledger_text = base_text if base_text.endswith("\n") else base_text + "\n"
    ledger_text = ledger_text + new_line + "\n"
    records = [json.loads(line) for line in ledger_text.splitlines() if line.strip()]
    assert [line for line, _ in base_pairs] == ledger_text.splitlines()[:BASE_LEDGER_RECORDS]

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == [counted_v52w]
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
    assert len(prior_append) == 16
    assert new_append == [CASE_V52W]
    checkpoint = dict(prior_summary["checkpoint"])
    checkpoint["prior_strict_count"] = PRIOR_STRICT
    checkpoint["corrected_strict_count"] = STRICT_COUNT
    checkpoint["appended_v52w_one"] = [CASE_V52W]
    checkpoint["directory_name"] = "orchestrator-260814-ghsa200-canonical87"
    checkpoint["prior_directory"] = "orchestrator-260814-ghsa200-canonical86"
    checkpoint["note"] = (
        "Directory name is canonical87. Semantic target is canonical strict count 87: "
        "the prior 86 exact strict IDs plus first-party GHSA-V52W-28XH-V562 at ordinal 87. "
        "Source conservation remains 211 hypotheses and 212 GHSA cases. The new identity is "
        "absent from the 212 source layer, so it APPENDS the counted set "
        "(new_identities_append=true). Counted GHSA issues are 1 and 2 only. "
        "Negative-control REJECT identities are not counted. Publication and integration "
        "stay closed. Greater-than-200 remains unsupported."
    )
    excluded = dict(prior_summary["excluded"])
    excluded["bundled_issue_3_readonly"] = (
        "GHSA-V52W bundled issue 3 READ ONLY GET transactions; origin 41f68fec #161; not counted"
    )
    excluded["bundled_issue_4_compose_bind"] = (
        "GHSA-V52W bundled issue 4 compose/all-interface bind; extra files in #163; not counted"
    )
    excluded["rest_body_164"] = (
        "in-house REST body cap 07368b7e #164; sibling of counted MCP HTTP issue 2; not counted"
    )
    excluded["cartesian_candidate_fix_edges"] = (
        excluded["cartesian_candidate_fix_edges"] + "; V52W binds 4f86724bd1 via bc9dc69d62 to 7c3ae2e3b7"
    )
    counts = dict(prior_summary["counts"])
    counts["strict_released_first_party_ghsa"] = STRICT_COUNT
    counts["ledger_records"] = len(records)
    counts["keep_v52w"] = 1
    counts["by_record_kind"] = dict(kinds)
    counts["by_admission_source"] = dict(Counter(row["admission_source"] for row in counted_rows))
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical87-hold",
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
            "HOLD snapshot of canonical strict count 87 first-party GHSA identities: "
            "the prior 86 plus GHSA-V52W-28XH-V562. Source conservation remains 211 "
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
            "# Canonical87 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 87 first-party GHSA identities. It extends the frozen canonical86 snapshot in orchestrator-260814-ghsa200-canonical86 by appending exactly one leader-accepted identity. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical86 meaning and are not flipped by counting GHSA-V52W. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: every canonical86 ledger row is preserved byte-for-byte and in order. The prior 86 counted rows stay byte-identical. Terminal hostile red-team KEEP GHSA-V52W-28XH-V562 is appended at ordinal 87. Count is by first-party GHSA identity once. CVE aliases are stored and never counted. This identity has no CVE alias.",
            "",
            "The admitted identity at ordinal 87 is GHSA-V52W-28XH-V562, repository kozou-dev/kozou, class AI_DIRECT_ROOT. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. Counted bundled issues are 1 and 2 only, on the new MCP Streamable HTTP startHttpServer.ts surface. Bundled issues 3 and 4 are excluded. REST body #164 is excluded. candidate_set is 4f86724bd1 (PR #20 member). carrier_set is bc9dc69d62 (mainline squash). minimum_fix_set is 7c3ae2e3b7. All seven contract gates are PASS. Public npm @kozou/mcp 1.8.0 / git tag v1.8.0 contains the unguarded HTTP server. Public npm 1.8.1 / git tag v1.8.1 contains Host/Origin and the streaming body cap. Mechanism key and fingerprint are unique versus canonical86.",
            "",
            "Admission source is the compact hostile packet herdr-260814-v52w-hostile-grok46-low. Inherited negative controls remain rejected and absent from strict rows.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer. Same-id upgrades still do not append. GHSA-V52W is a new identity (in_fp211_212=false, action=APPEND). Conservation prior_append_identities stays the prior 16. new_append_identities is exactly GHSA-V52W-28XH-V562. append_identities is the prior 16 followed by that one (17). new_identities_append is true. same_id_source_layer_promoted is false. The hostile red-team packet admits this row at authority rank 45. Discovery tabs and worker-only PASS are not loaded. Raw pages, tarballs, and owned clones are not committed; the builder consumes v52w_acceptance.json plus immutable canonical86 tracked artifacts.",
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
    assert CASE_V52W in report
    assert "Causal admission is false" in report
    assert "leader_strict_case_accepted is true" in report
    assert "causal_admission is true" not in report
    assert "new_identities_append is true" in report
    inherited_authority = [dict(item) for item in prior_manifest["packet_authority"]]
    packet_authority = inherited_authority + [dict(item) for item in NEW_PACKET_AUTHORITY]
    assert len(inherited_authority) == 23
    assert inherited_authority[-1]["authority_rank"] == 44
    assert packet_authority[-1]["authority_rank"] == 45
    assert packet_authority[-1]["role"] == "redteam"
    assert packet_authority[-1]["packet"] == P_HOSTILE
    assert len(packet_authority) == 24
    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical87-hold",
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
        print("PASS: canonical87 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
