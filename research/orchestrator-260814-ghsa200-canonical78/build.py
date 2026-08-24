#!/usr/bin/env python3
"""Build the HOLD canonical78-directory snapshot at strict count 78. Stdlib only."""

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
EXCLUDE_NARROW = "GHSA-7C3W-FXGH-FRC7"
EXCLUDE_F38V = "GHSA-F38V-77QJ-H4JQ"
EXCLUDE_4FXP = "GHSA-4FXP-2M36-QV64"
EXCLUDE_XW57 = "GHSA-XW57-23P8-9WC5"
EXCLUDE_QCR8 = "GHSA-QCR8-X557-7CP3"
CASE_Q855 = "GHSA-Q855-8RH5-JFGQ"
B3_KEEP = ("GHSA-G3XQ-3GMV-QQ8G", "GHSA-PV2J-RGHR-V5R9")
PRIOR_STRICT = 73
STRICT_COUNT = 78
FILEBROWSER_NEG = "post:filebrowser-delete-scope@canonical"
FILEBROWSER_POS = "post:filebrowser-dangling-write@canonical"
ORD200 = ("GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7")
CAND_HTTPS = "30f9b76f848b681e2806ac6ebcebebb055af3999"
CAND_SAST = "caa8fbfa4d7d99e02dca3ee0df642b30a5d856cc"
FIX_PT = "25d1fb491d99479efdf501f5f75e0bb80c908f0a"
VULN_SHA = "a84103e7dc3e3283279058d8f7e5a3c01a79fa3d"
NEW_IDS = (
    "GHSA-8882-FRVV-92W4",
    "GHSA-J5QP-P44G-2M49",
    "GHSA-2944-57XV-2682",
    "GHSA-5C7W-4WM3-85VW",
    "GHSA-93Q6-WWJH-JC6H",
)
EXPECTED_CANDIDATES = {
    "GHSA-8882-FRVV-92W4": [CAND_HTTPS],
    "GHSA-J5QP-P44G-2M49": [CAND_HTTPS],
    "GHSA-2944-57XV-2682": [CAND_HTTPS],
    "GHSA-5C7W-4WM3-85VW": [CAND_SAST],
    "GHSA-93Q6-WWJH-JC6H": [CAND_SAST],
}
EXPECTED_MECHS = {
    "GHSA-8882-FRVV-92W4": "specifyjs.secure-fetch.assertSecureUrl.parse-fail-open",
    "GHSA-J5QP-P44G-2M49": "specifyjs.secure-fetch.redirect-follow-ssrf",
    "GHSA-2944-57XV-2682": "specifyjs.secure-fetch.data-uri-unbounded",
    "GHSA-5C7W-4WM3-85VW": "specifyjs.gql.metacharacter-warn-not-throw",
    "GHSA-93Q6-WWJH-JC6H": "specifyjs.render-to-string.css-expression-regex-bypass",
}
HTTPS_IDS = NEW_IDS[:3]
SAST_IDS = NEW_IDS[3:]

P_CONTRACT = "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
P_C73_LEDGER = "autoresearch/orchestrator-260813-ghsa200-canonical73/ledger.jsonl"
P_C73_SUM = "autoresearch/orchestrator-260813-ghsa200-canonical73/summary.json"
P_C73_MAN = "autoresearch/orchestrator-260813-ghsa200-canonical73/manifest.json"
P_SJ_RES = "autoresearch/herdr-260814-ghsa200-specifyjs-five-redteam-grok46-xhigh/result.json"
P_SJ_CASES = "autoresearch/herdr-260814-ghsa200-specifyjs-five-redteam-grok46-xhigh/cases.jsonl"
P_PUB = "scripts/publication_adjudications.json"
P_SJ_PKT = "autoresearch/herdr-260814-ghsa200-specifyjs-five-redteam-grok46-xhigh"
P_C73_PKT = "autoresearch/orchestrator-260813-ghsa200-canonical73"
P_BATCH4 = "autoresearch/herdr-260814-ghsa200-directroot-batch4-grok46-high"

FROZEN = {
    "contract": (P_CONTRACT, "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"),
    "canonical73_ledger": (P_C73_LEDGER, "3fbde654a718bbb62780f74faf4f4bbb9019654f0f6882af6ec7a39bd2e75acc"),
    "canonical73_summary": (P_C73_SUM, "699f6160b6ecb9c9ce2cdae257c9a12dbdf4f7ef8a925196fcfd4fcf0b1140d8"),
    "canonical73_manifest": (P_C73_MAN, "0bf433a0d64eac633d6b9ddd17b95de43b40d3760685e999ca94081faea8db6d"),
    "specifyjs_five_result": (P_SJ_RES, "916cc7ec45536524dd79cd486060af3c7e9ad9ad3b8a892723574ba6f5f67743"),
    "specifyjs_five_cases": (P_SJ_CASES, "35d68b458f8505bf116f5f46a7b5380b3a76306cbfd0a48d69aa473abb629fdf"),
}
OVERLAP = {
    "publication_adjudications": (P_PUB, "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f"),
}

NEW_AUTHORITY = [
    {
        "packet": P_C73_PKT,
        "role": "frozen_base",
        "terminal": True,
        "status": "HOLD",
        "authority_rank": 0,
    },
    {
        "packet": P_SJ_PKT,
        "role": "redteam",
        "terminal": True,
        "status": "TERMINAL",
        "authority_rank": 35,
    },
]

CLONES = {
    "asymmetric-effort/specifyjs": "/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/asymmetric-effort__specifyjs",
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


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sha_set(values) -> list[str]:
    out = sorted(set(values or []))
    assert all(SHA_RE.fullmatch(item) for item in out), out
    return out


def seven_pass(row: dict) -> bool:
    for field in GATES:
        value = row.get(field)
        if value is None or value != "PASS":
            return False
    return True


def fingerprint(case_id: str, mechanism_key: str, candidate_set: list[str], minimum_fix_set: list[str]) -> str:
    return sha256_bytes(
        compact_json(
            {
                "candidate_set": candidate_set,
                "case_id": case_id,
                "mechanism_key": mechanism_key,
                "minimum_fix_set": minimum_fix_set,
            }
        ).encode()
    )


def pin_frozen() -> dict[str, dict]:
    pinned = {}
    for name, (relative, expected) in FROZEN.items():
        path = ROOT / relative
        got = sha256_file(path)
        assert got == expected, f"frozen mismatch {name}: {got}"
        pinned[name] = {"path": relative, "role": "frozen", "sha256": got}
    for name, (relative, expected) in OVERLAP.items():
        path = ROOT / relative
        got = sha256_file(path)
        assert got == expected, f"overlap mismatch {name}"
        pinned[name] = {"path": relative, "role": "overlap_check", "sha256": got}
    return pinned


def gates_from(row: dict) -> dict[str, str]:
    if isinstance(row.get("gates"), dict):
        src = row["gates"]
    else:
        src = row
    out = {field: src[field] for field in GATES}
    for field, value in out.items():
        assert value is not None and value != "NA"
        assert isinstance(value, str)
    return out


def npm_release(evidence: dict, *, role: str) -> dict:
    out = {
        "github_release_object": evidence["github_release_object"],
        "git_tag_commit": evidence["git_tag_commit"],
        "kind": evidence["kind"],
        "name": evidence["name"],
        "npm_gitHead": evidence["npm_gitHead"],
        "sha": evidence["git_tag_commit"],
        "tag": evidence["git_tag"],
        "tarball": evidence["tarball"],
        "tarball_sha256": evidence["tarball_sha256"],
        "version": evidence["version"],
    }
    if role == "vulnerable":
        assert evidence["version"] == "0.2.135"
        assert evidence["git_tag"] == "v0.2.135"
        assert evidence["npm_gitHead"] == VULN_SHA
        assert evidence["git_tag_commit"] == VULN_SHA
        assert evidence["contains_candidate"] is True
        assert evidence["contains_fix"] is False
        out["advisory_range"] = evidence["advisory_range"]
        out["contains_candidate"] = True
        out["contains_fix"] = False
    else:
        assert evidence["version"] == "0.2.136"
        assert evidence["git_tag"] == "v0.2.136"
        assert evidence["npm_gitHead"] == FIX_PT
        assert evidence["git_tag_commit"] == FIX_PT
        assert evidence["equals_minimum_fix"] is True
        assert evidence["contains_fix"] is True
        out["advisory_first_patched"] = evidence["advisory_first_patched"]
        out["contains_fix"] = True
        out["equals_minimum_fix"] = True
    return out


def counted_from_specifyjs(row: dict, ordinal: int) -> dict:
    candidate_set = list(row["candidate_set"])
    assert candidate_set == sha_set(candidate_set)
    carrier_set = sha_set(row.get("carrier_set") or [])
    minimum_fix_set = list(row["minimum_fix_set"])
    assert minimum_fix_set == sha_set(minimum_fix_set)
    case_id = row["case_id"]
    assert GHSA_RE.fullmatch(case_id)
    assert case_id in EXPECTED_CANDIDATES
    assert candidate_set == EXPECTED_CANDIDATES[case_id]
    assert minimum_fix_set == [FIX_PT]
    mechanism_key = row["mechanism_key"]
    assert mechanism_key == EXPECTED_MECHS[case_id]
    aliases = list(row.get("aliases") or [])
    assert all(not item.startswith("GHSA-") or item == case_id for item in aliases)
    g = gates_from(row)
    assert all(g[field] == "PASS" for field in GATES)
    assert row[REMEDIATION_GATE] == "PASS"
    assert row["gates"][REMEDIATION_GATE] == "PASS"
    assert row["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert row["cartesian_candidate_fix_refused"] is True
    assert "candidate_fix_edges" not in row
    refs = list(row["first_party_source_refs"])
    assert refs
    assert refs[0].startswith("https://github.com/advisories/GHSA-")
    return {
        "action": "APPEND",
        "admission_source": "specifyjs_five_redteam_keep",
        "aliases": aliases,
        "candidate_set": candidate_set,
        "carrier_set": carrier_set,
        "cartesian_candidate_fix_refused": True,
        "case_id": case_id,
        "contribution_class": "AI_INCOMPLETE_REMEDIATION",
        "counted": True,
        "counting_unit": "first-party GHSA case",
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "first_party_source_refs": refs,
        "fixed_release": npm_release(row["fixed_release_evidence"], role="fixed"),
        "in_fp211_212": False,
        "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        "mechanism_fingerprint": fingerprint(case_id, mechanism_key, candidate_set, minimum_fix_set),
        "mechanism_key": mechanism_key,
        "minimum_fix_set": minimum_fix_set,
        "ordinal": ordinal,
        "overlay_state": "KEEP",
        "record_kind": "STRICT_RELEASED_CASE",
        "repository": row["repository"],
        "row_key": f"ghsa200-next:{case_id}",
        "schema_version": SCHEMA,
        "scope_statement": row["scope_statement"],
        "source_layer": False,
        "vulnerable_release": npm_release(row["vulnerable_release_evidence"], role="vulnerable"),
        **g,
        REMEDIATION_GATE: "PASS",
    }


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
        REMEDIATION_GATE: counted[REMEDIATION_GATE],
    }


def edge_from_counted(counted: dict) -> dict:
    case_id = counted["case_id"]
    return {
        "applies_now": True,
        "applies_to_counted_set": True,
        "authority_rank": 35,
        "case_id": case_id,
        "counted": False,
        "edge_id": f"E-SJ-{case_id[5:9]}",
        "failed_gate": None,
        "from_packet": P_BATCH4,
        "from_verdict": "PASS",
        "note": "Independent specifyjs-five red-team KEEP. Direct-root batch4 PASS is not admission. Absent identity appends. Shared closer 25d1fb49 does not create a Cartesian candidate-fix relation.",
        "pending_until_to_packet_terminal": False,
        "record_kind": "SUPERSEDES_EDGE",
        "schema_version": SCHEMA,
        "source_layer": True,
        "to_packet": P_SJ_PKT,
        "to_verdict": "KEEP",
    }


def authority_record(item: dict) -> dict:
    return {
        "schema_version": SCHEMA,
        "record_kind": "PACKET_AUTHORITY",
        "counted": False,
        "source_layer": True,
        **item,
    }


def build_outputs() -> dict[Path, str]:
    pins = pin_frozen()
    base_rows = load_jsonl(ROOT / P_C73_LEDGER)
    prior_summary = load_json(ROOT / P_C73_SUM)
    src_rows = load_jsonl(ROOT / P_SJ_CASES)
    src_res = load_json(ROOT / P_SJ_RES)
    pub_text = (ROOT / P_PUB).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["integration_ready"] is False
    assert prior_summary["publication_ready"] is False
    assert prior_summary["public_200_claim_supported"] is False
    assert src_res["status"] == "TERMINAL"
    assert src_res["causal_admission"] is False
    assert src_res["more_than_200_unsupported"] is True
    assert src_res["worker_pass_is_proposal_only"] is True
    assert src_res["verdicts"] == {"KEEP": 5, "NARROW": 0, "REJECT": 0, "UNKNOWN": 0, "BLOCKED": 0}
    assert src_res["conservation"] == {
        "assigned": 5,
        "reviewed": 5,
        "unreviewed": 0,
        "identity": "assigned = reviewed + unreviewed",
        "check": "5 = 5 + 0",
    }
    assert [row["case_id"] for row in src_rows] == list(NEW_IDS)
    assert src_res["scope"]["case_ids"] == list(NEW_IDS)
    assert src_res["per_case"] == {case_id: "KEEP" for case_id in NEW_IDS}
    assert EXCLUDE_XW57 in src_res["did_not_review"]
    assert EXCLUDE_QCR8 in src_res["did_not_review"]

    by_kind: dict[str, list[dict]] = {}
    for row in base_rows:
        by_kind.setdefault(row["record_kind"], []).append(row)
    assert [row["record_kind"] for row in base_rows[:10]] == ["PACKET_AUTHORITY"] * 10
    assert len(by_kind["PACKET_AUTHORITY"]) == 10
    assert len(by_kind["SUPERSEDES_EDGE"]) == 35
    assert len(by_kind["PRESERVED_HYPOTHESIS"]) == 211
    assert len(by_kind["PRESERVED_PUBLIC_CASE"]) == 212
    assert len(by_kind["APPEND_IDENTITY"]) == 4
    assert len(by_kind["STRICT_RELEASED_CASE"]) == PRIOR_STRICT
    base_counted = by_kind["STRICT_RELEASED_CASE"]
    assert [row["case_id"] for row in base_counted] == prior_summary["strict_released_case_ids"]
    base_ids = [row["case_id"] for row in base_counted]
    source_ids = {row["case_id"] for row in by_kind["PRESERVED_PUBLIC_CASE"]}
    base_fps = {row["mechanism_fingerprint"] for row in base_counted}
    base_mechs = {row["mechanism_key"] for row in base_counted}
    assert len(base_ids) == len(set(base_ids)) == PRIOR_STRICT
    assert len(base_fps) == PRIOR_STRICT
    assert len(base_mechs) == PRIOR_STRICT

    new_counted: list[dict] = []
    new_appends: list[dict] = []
    new_edges: list[dict] = []
    seen_pairs: set[tuple[str, str, str]] = set()
    for offset, row in enumerate(src_rows):
        assert row["verdict"] == "KEEP"
        assert row["countable_proposal"] is True
        assert row["causal_admission"] is False
        assert seven_pass(gates_from(row))
        case_id = row["case_id"]
        assert case_id not in base_ids
        assert case_id not in source_ids
        assert case_id not in pub_text
        assert case_id.lower() not in pub_text.lower()
        assert case_id != EXCLUDE_XW57
        counted = counted_from_specifyjs(row, ordinal=74 + offset)
        pair = (counted["case_id"], counted["candidate_set"][0], counted["minimum_fix_set"][0])
        assert pair not in seen_pairs
        seen_pairs.add(pair)
        assert "clone_path" not in counted
        assert counted["mechanism_fingerprint"] not in base_fps
        assert counted["mechanism_key"] not in base_mechs
        assert_no_leak(compact_json(counted))
        base_fps.add(counted["mechanism_fingerprint"])
        base_mechs.add(counted["mechanism_key"])
        new_counted.append(counted)
        new_appends.append(append_from_counted(counted))
        new_edges.append(edge_from_counted(counted))

    assert [row["case_id"] for row in new_counted] == list(NEW_IDS)
    assert [row["ordinal"] for row in new_counted] == [74, 75, 76, 77, 78]
    assert [row["candidate_set"][0] for row in new_counted[:3]] == [CAND_HTTPS] * 3
    assert [row["candidate_set"][0] for row in new_counted[3:]] == [CAND_SAST] * 2
    assert all(row["minimum_fix_set"] == [FIX_PT] for row in new_counted)
    assert len(seen_pairs) == 5
    cartesian = {(case_id, cand, FIX_PT) for case_id in NEW_IDS for cand in (CAND_HTTPS, CAND_SAST)}
    assert seen_pairs < cartesian
    assert len(cartesian) == 10
    assert {row["mechanism_fingerprint"] for row in new_counted} == set(base_fps) - {
        row["mechanism_fingerprint"] for row in base_counted
    }
    assert len({row["mechanism_fingerprint"] for row in new_counted}) == 5
    assert len({row["mechanism_key"] for row in new_counted}) == 5

    records: list[dict] = []
    records.extend(by_kind["PACKET_AUTHORITY"])
    records.extend(authority_record(item) for item in NEW_AUTHORITY)
    records.extend(by_kind["SUPERSEDES_EDGE"])
    records.extend(new_edges)
    records.extend(by_kind["PRESERVED_HYPOTHESIS"])
    records.extend(by_kind["PRESERVED_PUBLIC_CASE"])
    records.extend(by_kind["APPEND_IDENTITY"])
    records.extend(new_appends)
    records.extend(base_counted)
    records.extend(new_counted)

    counted_rows = [row for row in records if row["record_kind"] == "STRICT_RELEASED_CASE"]
    assert counted_rows[:PRIOR_STRICT] == base_counted
    assert counted_rows[PRIOR_STRICT:] == new_counted
    assert len(counted_rows) == STRICT_COUNT
    assert len({row["case_id"] for row in counted_rows}) == STRICT_COUNT
    assert not any(row["case_id"] == EXCLUDE_NARROW for row in counted_rows)
    assert not any(row["case_id"] == EXCLUDE_F38V for row in counted_rows)
    assert not any(row["case_id"] == EXCLUDE_4FXP for row in counted_rows)
    assert not any(row["case_id"] == EXCLUDE_XW57 for row in counted_rows)
    assert CASE_Q855 in {row["case_id"] for row in counted_rows}
    assert set(B3_KEEP) <= {row["case_id"] for row in counted_rows}
    assert all("candidate_fix_edges" not in row for row in counted_rows)

    kinds = Counter(row["record_kind"] for row in records)
    assert kinds["PRESERVED_HYPOTHESIS"] == 211
    assert kinds["PRESERVED_PUBLIC_CASE"] == 212
    assert kinds["APPEND_IDENTITY"] == 9
    assert kinds["STRICT_RELEASED_CASE"] == STRICT_COUNT
    assert kinds["PACKET_AUTHORITY"] == 12
    assert kinds["SUPERSEDES_EDGE"] == 40
    assert sum(row.get("counted") is True for row in records) == STRICT_COUNT
    assert len(records) == 562

    ledger_text = "".join(compact_json(row) + "\n" for row in records)
    assert not HAN.search(ledger_text)
    base_ledger_text = (ROOT / P_C73_LEDGER).read_text()
    base_counted_text = "".join(
        compact_json(row) + "\n" for row in base_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
    )
    new_base_counted_text = "".join(compact_json(row) + "\n" for row in counted_rows[:PRIOR_STRICT])
    assert new_base_counted_text == base_counted_text
    assert sha256_bytes(base_ledger_text.encode()) == pins["canonical73_ledger"]["sha256"]

    counted_ids = [row["case_id"] for row in counted_rows]
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical78-hold",
        "canonical_strict_count": STRICT_COUNT,
        "checkpoint": {
            "prior_strict_count": PRIOR_STRICT,
            "corrected_strict_count": STRICT_COUNT,
            "corrected_baseline": 47,
            "fp211_released_admitted_raw": 48,
            "added_b3": list(B3_KEEP),
            "appended_q855": [CASE_Q855],
            "appended_specifyjs_five": list(NEW_IDS),
            "downgraded": [EXCLUDE_4FXP],
            "narrow_noncounting": [EXCLUDE_F38V, EXCLUDE_4FXP, EXCLUDE_NARROW],
            "directory_name": "orchestrator-260814-ghsa200-canonical78",
            "prior_directory": "orchestrator-260813-ghsa200-canonical73",
            "note": "Directory name is canonical78. Semantic target is canonical strict count 78: the prior 73 exact strict IDs plus five independently red-teamed specifyjs identities, ordinals 74 through 78 in source order. Source conservation remains 211 hypotheses and 212 GHSA cases. Publication and integration stay closed. Greater-than-200 remains unsupported.",
        },
        "counting_unit": "first-party GHSA case",
        "language": "en",
        "causal_admission": False,
        "integration_ready": False,
        "publication_ready": False,
        "public_200_claim_supported": False,
        "claim_boundary": "HOLD snapshot of canonical strict count 78 first-party GHSA identities: the prior 73 plus five specifyjs identities. Source conservation remains 211 hypotheses and 212 GHSA cases. This does not support a greater-than-200 claim. Publication and integration stay closed.",
        "conservation": {
            "fp211_hypotheses": 211,
            "fp211_source_ghsa_cases": 212,
            "cve_aliases_counted": False,
            "upgrades_append": False,
            "new_identities_append": True,
            "prior_append_identities": prior_summary["conservation"]["append_identities"],
            "append_identities": prior_summary["conservation"]["append_identities"] + list(NEW_IDS),
            "base_counted_rows_byte_identical": True,
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
            "netnew22_narrow_excluded": 1,
            "b3_narrow_excluded": 1,
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
            "discovery_tabs": "not included",
            "worker_only_PASS": "not included",
            "cartesian_candidate_fix_edges": "not invented; three rows bind 30f9b76f and two bind caa8fbfa, each to closer 25d1fb49",
        },
        "seven_gates": list(GATES),
        "remediation_patch_delta_gate": "required PASS on the five specifyjs AI_INCOMPLETE_REMEDIATION rows",
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
            "current": {},
            "overlap_check": {k: v for k, v in pins.items() if v["role"] == "overlap_check"},
        },
        "ledger_sha256": sha256_bytes(ledger_text.encode()),
    }
    report = "\n".join(
        [
            "# Canonical78 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 78 first-party GHSA identities. It extends the frozen canonical73 snapshot in orchestrator-260813-ghsa200-canonical73 by appending exactly five independently red-teamed specifyjs identities. Integration_ready is false. Publication_ready is false. Causal admission is false. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: the prior 73 counted rows are preserved byte-for-byte, plus terminal specifyjs-five red-team KEEP 5. Corrected baseline 47, plus terminal netnew22 KEEP 21, plus independent Actual/Gogs KEEP 2, plus terminal B3 KEEP 2, plus GHSA-Q855-8RH5-JFGQ, plus specifyjs five. GHSA-F38V-77QJ-H4JQ, GHSA-4FXP-2M36-QV64, and GHSA-7C3W-FXGH-FRC7 remain noncounting. Count is by first-party GHSA identity once. CVE aliases are stored and never counted.",
            "",
            "The five admitted identities, ordinals 74 through 78 in source order, are GHSA-8882-FRVV-92W4, GHSA-J5QP-P44G-2M49, GHSA-2944-57XV-2682, GHSA-5C7W-4WM3-85VW, and GHSA-93Q6-WWJH-JC6H. Each is AI_INCOMPLETE_REMEDIATION with all seven contract gates PASS and an explicit remediation patch-delta PASS. Three rows bind candidate 30f9b76f; two bind candidate caa8fbfa; every row binds minimum fix 25d1fb49. Those shared SHAs do not merge identities and do not invent Cartesian candidate-fix edges. GHSA-XW57-23P8-9WC5 is a different identity and is not counted.",
            "",
            "Identity uses the GitHub-reviewed global GHSA objects (type=reviewed, withdrawn_at=null, source_code_location=asymmetric-effort/specifyjs). Repo advisory REST GET is 404. Vulnerable containment is npm @asymmetric-effort/specifyjs 0.2.135 (gitHead a84103e7, tag v0.2.135). Fixed containment is npm 0.2.136 (gitHead 25d1fb49, tag v0.2.136, equals the minimum fix). GitHub Release objects are 404. First-party source references are the reviewed global GHSA URLs and the red-team frozen GHSA/npm pages; those pages are not copied into this directory.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer, including dual ordinal-200 identities GHSA-3J8Q-FWPJ-F8J5 and GHSA-JJCJ-H3CM-P7X7. Same-id upgrades still do not append. The five specifyjs identities are absent from the 212 and append. Direct-root batch4 PASS is a proposal only; independent specifyjs-five red-team KEEP is the terminal admission edge. Discovery tabs and worker-only PASS are not loaded.",
            "",
            "Every counted row has all seven contract gates equal to the string PASS. Null and NA fail closed. The five new rows also require remediation_patch_delta_gate PASS. Candidate, carrier, and minimum-fix sets are sorted unique 40-hex SHAs. Cartesian candidate times fix pairs are not invented. Git replay of the five specifyjs rows uses npm gitHead commits, not missing local tags.",
            "",
            "Status HOLD until leader review.",
            "",
        ]
    )
    assert not HAN.search(report)
    assert "more than 200" not in report.lower()
    for row in new_counted + new_appends + new_edges:
        assert_no_leak(compact_json(row))
    assert_no_leak(report)

    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical78-hold",
        "canonical_strict_count": STRICT_COUNT,
        "checkpoint": summary["checkpoint"],
        "counting_unit": "first-party GHSA case",
        "integration_ready": False,
        "publication_ready": False,
        "causal_admission": False,
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
        print("PASS: canonical78 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
