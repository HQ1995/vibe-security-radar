#!/usr/bin/env python3
"""Build the HOLD canonical81-directory snapshot at strict count 81. Stdlib only."""

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
EXCLUDE_GOPACKET = "GHSA-6R28-9PPF-4HJ5"
CASE_Q855 = "GHSA-Q855-8RH5-JFGQ"
B3_KEEP = ("GHSA-G3XQ-3GMV-QQ8G", "GHSA-PV2J-RGHR-V5R9")
PRIOR_STRICT = 78
STRICT_COUNT = 81
FILEBROWSER_NEG = "post:filebrowser-delete-scope@canonical"
FILEBROWSER_POS = "post:filebrowser-dangling-write@canonical"
ORD200 = ("GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7")

CASE_X4HG = "GHSA-X4HG-HFWF-P9MW"
CASE_322X = "GHSA-322X-V876-G883"
CASE_PMCH = "GHSA-PMCH-G965-GRMR"
NOGGIN_IDS = (CASE_X4HG, CASE_322X)
NEW_IDS = (CASE_X4HG, CASE_322X, CASE_PMCH)

CAND_X4HG = "f8ee181be67344f12aeb30ec39e5ab611c65b826"
CAND_322X = "ed0124d37f548be12f2ff91b48ce7e33380d0ab4"
CAND_PMCH = "60933b4860a8952894b31caa0dd3f9dcba512c8e"
FIX_X4HG = "25a3cbac665fae5663f8b71c073b80c3152dbe7b"
FIX_322X = "785e6ac6e124d1a89b3ccf40bbd75fc8e4cb215d"
FIX_PMCH = "00b7dd7b79c5d03c94be284cf3459d98195ebfba"

NPM_NAME = "@asymmetric-effort/nogginlessdom"
NPM_KIND = "npm_gitHead_equals_peeled_annotated_tag"
NPM_VULN_VER = "0.0.21"
NPM_FIX_VER = "0.0.22"
NPM_VULN_TAG = "v0.0.21"
NPM_FIX_TAG = "v0.0.22"
NPM_VULN_SHA = "7cd241350fb7669b006fed46b81436925d1bb55c"
NPM_FIX_SHA = "00dc8ad39071140d1d76c03d93c6e10f19e51138"
NPM_VULN_TAR = "https://registry.npmjs.org/@asymmetric-effort/nogginlessdom/-/nogginlessdom-0.0.21.tgz"
NPM_FIX_TAR = "https://registry.npmjs.org/@asymmetric-effort/nogginlessdom/-/nogginlessdom-0.0.22.tgz"
NPM_VULN_TAR_SHA = "47aba8a9ba8e004c13d0cae23af47ffd19ca11344c4bb491ce05216411b5d11b"
NPM_FIX_TAR_SHA = "d33559d28bd1ba66c014019271e65b63b198374b8fe160355cff2d9303cf8348"

PYPI_NAME = "langroid"
PYPI_KIND = "pypi_wheel_and_sdist_git_blob_equals_peeled_tag"
PYPI_VULN_VER = "0.63.0"
PYPI_FIX_VER = "0.64.0"
PYPI_VULN_SHA = "fee670d502ed6d82b8414388bd137a315830331f"
PYPI_FIX_SHA = "84d2aff0af173d75417fc37fc629be97177098f3"
PYPI_VULN_BLOB = "887a10a4e2c2c5758560d0783b1b526a345502af"
PYPI_FIX_BLOB = "a55f6d345c8f3f33b5b316939359b52a1e4fb6e3"
PYPI_VULN_WHEEL = "8a91de0ea8cb02b636b33a0ec9cca4b8455059c994dd832caff7de8b3e36ea6a"
PYPI_VULN_SDIST = "da8d2250817e97090ab8a586f81e72b0e85cd37fe5cdbcbdc983e71e3df6e21d"
PYPI_FIX_WHEEL = "795bd1f62e08ba6f5381248cbf17404dc501db59fdc11c14fcbdb80fedab91f6"
PYPI_FIX_SDIST = "dcb6c6e46118dfab37fbc5f6f44e2bfe1a94206912d09cba03ab113ee41046f7"
PYPI_VULN_REL = 329816455
PYPI_FIX_REL = 331122123

EXPECTED_CANDIDATES = {
    CASE_X4HG: [CAND_X4HG],
    CASE_322X: [CAND_322X],
    CASE_PMCH: [CAND_PMCH],
}
EXPECTED_FIXES = {
    CASE_X4HG: [FIX_X4HG],
    CASE_322X: [FIX_322X],
    CASE_PMCH: [FIX_PMCH],
}
EXPECTED_MECHS = {
    CASE_X4HG: "nogginlessdom.htmlinput.checkValidity.pattern-unbounded-regexp",
    CASE_322X: "nogginlessdom.matchFileSnapshot.unvalidated-write",
    CASE_PMCH: "langroid.sqlchat._validate_query.pg_read_file_family_denylist_gap",
}
EXPECTED_CLASS = {
    CASE_X4HG: "AI_DIRECT_ROOT",
    CASE_322X: "AI_DIRECT_ROOT",
    CASE_PMCH: "AI_INCOMPLETE_REMEDIATION",
}
EXPECTED_REPOS = {
    CASE_X4HG: "asymmetric-effort/NogginLessDom",
    CASE_322X: "asymmetric-effort/NogginLessDom",
    CASE_PMCH: "langroid/langroid",
}

P_CONTRACT = "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
P_C78_LEDGER = "autoresearch/orchestrator-260814-ghsa200-canonical78/ledger.jsonl"
P_C78_SUM = "autoresearch/orchestrator-260814-ghsa200-canonical78/summary.json"
P_C78_MAN = "autoresearch/orchestrator-260814-ghsa200-canonical78/manifest.json"
P_B9_RES = "autoresearch/herdr-260814-ghsa200-batch9-three-redteam-grok46-xhigh/result.json"
P_B9_CASES = "autoresearch/herdr-260814-ghsa200-batch9-three-redteam-grok46-xhigh/cases.jsonl"
P_LR_RES = "autoresearch/herdr-260814-ghsa200-langroid-one-redteam-grok46-low/result.json"
P_LR_CASES = "autoresearch/herdr-260814-ghsa200-langroid-one-redteam-grok46-low/cases.jsonl"
P_PUB = "scripts/publication_adjudications.json"
P_B9_PKT = "autoresearch/herdr-260814-ghsa200-batch9-three-redteam-grok46-xhigh"
P_LR_PKT = "autoresearch/herdr-260814-ghsa200-langroid-one-redteam-grok46-low"
P_C78_PKT = "autoresearch/orchestrator-260814-ghsa200-canonical78"
P_BATCH9 = "autoresearch/herdr-260814-ghsa200-directroot-batch9-grok46-low"
P_BATCH11 = "autoresearch/herdr-260814-ghsa200-directroot-batch11-grok46-medium"

FROZEN = {
    "contract": (P_CONTRACT, "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"),
    "canonical78_ledger": (P_C78_LEDGER, "f35a327fc43e0de371700d7da2406544a2c7d790cdafb531d0c71aaad1fb7f72"),
    "canonical78_summary": (P_C78_SUM, "f856e51325b1a6dfba6e8811ac303e6280a83a27c08bd70f78af993eb051113d"),
    "canonical78_manifest": (P_C78_MAN, "c8784129d1d69c8cdf097af0bb4f0eea4b16bd03d45f07140493e90459fa40e1"),
    "batch9_three_result": (P_B9_RES, "06c8aa73b8577dbea1743afbd46993f9c68ccdc6bda0486d398c81aaea664a88"),
    "batch9_three_cases": (P_B9_CASES, "15de6f28690ba33dbba72df7a32212cc2fbd4873cdb6ec6a3ca28f72c7a1cf14"),
    "langroid_one_result": (P_LR_RES, "1e4dcacf5fbd8ed11342af922e021c558a98ce632be9e16c04eb913f122f8e69"),
    "langroid_one_cases": (P_LR_CASES, "0ce1c58b9bd71653f710afc598e9a966089fa18de1d4004e42c642756bdb48da"),
}
OVERLAP = {
    "publication_adjudications": (P_PUB, "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f"),
}

NEW_AUTHORITY = [
    {
        "packet": P_C78_PKT,
        "role": "frozen_base",
        "terminal": True,
        "status": "HOLD",
        "authority_rank": 0,
    },
    {
        "packet": P_B9_PKT,
        "role": "redteam",
        "terminal": True,
        "status": "REDTEAM_TERMINAL",
        "authority_rank": 36,
    },
    {
        "packet": P_LR_PKT,
        "role": "redteam",
        "terminal": True,
        "status": "TERMINAL",
        "authority_rank": 37,
    },
]

CLONES = {
    "asymmetric-effort/NogginLessDom": "/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/asymmetric-effort__NogginLessDom",
    "langroid/langroid": "/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/langroid",
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


def advisory_url(case_id: str) -> str:
    return "https://github.com/advisories/GHSA-" + case_id.split("-", 1)[1].lower()


def noggin_release(*, role: str) -> dict:
    if role == "vulnerable":
        return {
            "advisory_range": "<= 0.0.21",
            "contains_candidate": True,
            "contains_fix": False,
            "git_tag_commit": NPM_VULN_SHA,
            "github_release_object": "404",
            "kind": NPM_KIND,
            "name": NPM_NAME,
            "npm_gitHead": NPM_VULN_SHA,
            "sha": NPM_VULN_SHA,
            "tag": NPM_VULN_TAG,
            "tarball": NPM_VULN_TAR,
            "tarball_sha256": NPM_VULN_TAR_SHA,
            "version": NPM_VULN_VER,
        }
    return {
        "advisory_first_patched": NPM_FIX_VER,
        "contains_fix": True,
        "equals_minimum_fix": False,
        "git_tag_commit": NPM_FIX_SHA,
        "github_release_object": "404",
        "kind": NPM_KIND,
        "name": NPM_NAME,
        "npm_gitHead": NPM_FIX_SHA,
        "sha": NPM_FIX_SHA,
        "tag": NPM_FIX_TAG,
        "tarball": NPM_FIX_TAR,
        "tarball_sha256": NPM_FIX_TAR_SHA,
        "version": NPM_FIX_VER,
    }


def pypi_release(*, role: str) -> dict:
    if role == "vulnerable":
        return {
            "advisory_range": "<= 0.63.0",
            "contains_candidate": True,
            "contains_fix": False,
            "ecosystem": "PyPI",
            "equals_ai_blob": True,
            "git_tag_commit": PYPI_VULN_SHA,
            "github_release_asset_wheel_digest": "sha256:" + PYPI_VULN_WHEEL,
            "github_release_id": PYPI_VULN_REL,
            "kind": PYPI_KIND,
            "name": PYPI_NAME,
            "sdist_sha256": PYPI_VULN_SDIST,
            "sha": PYPI_VULN_SHA,
            "sql_chat_agent_blob": PYPI_VULN_BLOB,
            "tag": PYPI_VULN_VER,
            "version": PYPI_VULN_VER,
            "wheel_sha256": PYPI_VULN_WHEEL,
        }
    return {
        "advisory_first_patched": PYPI_FIX_VER,
        "contains_fix": True,
        "ecosystem": "PyPI",
        "equals_fix_blob": True,
        "equals_minimum_fix": False,
        "git_tag_commit": PYPI_FIX_SHA,
        "github_release_asset_wheel_digest": "sha256:" + PYPI_FIX_WHEEL,
        "github_release_id": PYPI_FIX_REL,
        "kind": PYPI_KIND,
        "name": PYPI_NAME,
        "sdist_sha256": PYPI_FIX_SDIST,
        "sha": PYPI_FIX_SHA,
        "sql_chat_agent_blob": PYPI_FIX_BLOB,
        "tag": PYPI_FIX_VER,
        "version": PYPI_FIX_VER,
        "wheel_sha256": PYPI_FIX_WHEEL,
    }


def refs_from(row: dict) -> list[str]:
    refs = list(row.get("first_party_source_refs") or row.get("first_party_sources") or [])
    assert refs
    assert refs[0] == advisory_url(row["case_id"])
    assert any("pages/ghsa/" in item for item in refs)
    return refs


def counted_common(row: dict, ordinal: int, admission_source: str) -> dict:
    candidate_set = list(row["candidate_set"])
    assert candidate_set == sha_set(candidate_set)
    carrier_set = sha_set(row.get("carrier_set") or [])
    minimum_fix_set = list(row["minimum_fix_set"])
    assert minimum_fix_set == sha_set(minimum_fix_set)
    case_id = row["case_id"]
    assert GHSA_RE.fullmatch(case_id)
    assert candidate_set == EXPECTED_CANDIDATES[case_id]
    assert minimum_fix_set == EXPECTED_FIXES[case_id]
    mechanism_key = row["mechanism_key"]
    assert mechanism_key == EXPECTED_MECHS[case_id]
    aliases = list(row.get("aliases") or [])
    assert case_id not in aliases
    assert all(not item.startswith("GHSA-") or item == case_id for item in aliases)
    g = gates_from(row)
    assert all(g[field] == "PASS" for field in GATES)
    contribution_class = row["contribution_class"]
    assert contribution_class == EXPECTED_CLASS[case_id]
    assert row.get("repository") == EXPECTED_REPOS[case_id]
    out = {
        "action": "APPEND",
        "admission_source": admission_source,
        "aliases": aliases,
        "candidate_set": candidate_set,
        "carrier_set": carrier_set,
        "cartesian_candidate_fix_refused": True,
        "case_id": case_id,
        "contribution_class": contribution_class,
        "counted": True,
        "counting_unit": "first-party GHSA case",
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "first_party_source_refs": refs_from(row),
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
        **g,
    }
    return out


def counted_from_noggin(row: dict, ordinal: int) -> dict:
    out = counted_common(row, ordinal, "batch9_three_redteam_keep")
    assert out["contribution_class"] == "AI_DIRECT_ROOT"
    assert REMEDIATION_GATE not in row
    assert REMEDIATION_GATE not in (row.get("gates") or {})
    ev_v = row["vulnerable_release_evidence"]
    ev_f = row["fixed_release_evidence"]
    assert ev_v["npm_gitHead"] == NPM_VULN_SHA
    assert ev_v["git_tag_commit"] == NPM_VULN_SHA
    assert ev_v["git_tag"] == NPM_VULN_TAG
    assert ev_v.get("contains_candidate_ancestor") is True
    assert ev_v.get("contains_fix_ancestor") is False
    assert ev_f["npm_gitHead"] == NPM_FIX_SHA
    assert ev_f["git_tag_commit"] == NPM_FIX_SHA
    assert ev_f["git_tag"] == NPM_FIX_TAG
    assert ev_f.get("contains_fix_ancestor") is True
    if "tarball_sha256" in ev_v:
        assert ev_v["tarball_sha256"] == NPM_VULN_TAR_SHA
    if "tarball_sha256" in ev_f:
        assert ev_f["tarball_sha256"] == NPM_FIX_TAR_SHA
    out["vulnerable_release"] = noggin_release(role="vulnerable")
    out["fixed_release"] = noggin_release(role="fixed")
    return out


def counted_from_langroid(row: dict, ordinal: int) -> dict:
    out = counted_common(row, ordinal, "langroid_one_redteam_keep")
    assert out["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert row[REMEDIATION_GATE] == "PASS"
    assert row["gates"][REMEDIATION_GATE] == "PASS"
    ev_v = row["vulnerable_release_evidence"]
    ev_f = row["fixed_release_evidence"]
    assert ev_v["version"] == PYPI_VULN_VER
    assert ev_v["git_tag_commit"] == PYPI_VULN_SHA
    assert ev_v["wheel_sha256"] == PYPI_VULN_WHEEL
    assert ev_v["sdist_sha256"] == PYPI_VULN_SDIST
    assert ev_v["sql_chat_agent_blob"] == PYPI_VULN_BLOB
    assert ev_v["contains_candidate"] is True
    assert ev_v["contains_fix"] is False
    assert ev_f["version"] == PYPI_FIX_VER
    assert ev_f["git_tag_commit"] == PYPI_FIX_SHA
    assert ev_f["wheel_sha256"] == PYPI_FIX_WHEEL
    assert ev_f["sdist_sha256"] == PYPI_FIX_SDIST
    assert ev_f["sql_chat_agent_blob"] == PYPI_FIX_BLOB
    assert ev_f["contains_fix"] is True
    out["vulnerable_release"] = pypi_release(role="vulnerable")
    out["fixed_release"] = pypi_release(role="fixed")
    out[REMEDIATION_GATE] = "PASS"
    return out


def append_from_counted(counted: dict) -> dict:
    out = {
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
    if REMEDIATION_GATE in counted:
        out[REMEDIATION_GATE] = counted[REMEDIATION_GATE]
    return out


def edge_from_counted(counted: dict) -> dict:
    case_id = counted["case_id"]
    if case_id in NOGGIN_IDS:
        return {
            "applies_now": True,
            "applies_to_counted_set": True,
            "authority_rank": 36,
            "case_id": case_id,
            "counted": False,
            "edge_id": f"E-B9-{case_id[5:9]}",
            "failed_gate": None,
            "from_packet": P_BATCH9,
            "from_verdict": "PASS",
            "note": "Independent batch9-three red-team KEEP. Direct-root batch9 PASS is not admission. Absent identity appends. Shared npm 0.0.21/0.0.22 does not create a Cartesian candidate-fix relation.",
            "pending_until_to_packet_terminal": False,
            "record_kind": "SUPERSEDES_EDGE",
            "schema_version": SCHEMA,
            "source_layer": True,
            "to_packet": P_B9_PKT,
            "to_verdict": "KEEP",
        }
    return {
        "applies_now": True,
        "applies_to_counted_set": True,
        "authority_rank": 37,
        "case_id": case_id,
        "counted": False,
        "edge_id": f"E-LR-{case_id[5:9]}",
        "failed_gate": None,
        "from_packet": P_BATCH11,
        "from_verdict": "PASS",
        "note": "Independent langroid-one red-team KEEP. Direct-root batch11 PASS is not admission. Absent identity appends. Patch-delta incomplete remediation; not AI_DIRECT_ROOT.",
        "pending_until_to_packet_terminal": False,
        "record_kind": "SUPERSEDES_EDGE",
        "schema_version": SCHEMA,
        "source_layer": True,
        "to_packet": P_LR_PKT,
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
    base_rows = load_jsonl(ROOT / P_C78_LEDGER)
    prior_summary = load_json(ROOT / P_C78_SUM)
    b9_rows = load_jsonl(ROOT / P_B9_CASES)
    b9_res = load_json(ROOT / P_B9_RES)
    lr_rows = load_jsonl(ROOT / P_LR_CASES)
    lr_res = load_json(ROOT / P_LR_RES)
    pub_text = (ROOT / P_PUB).read_text()

    assert prior_summary["canonical_strict_count"] == PRIOR_STRICT
    assert prior_summary["integration_ready"] is False
    assert prior_summary["publication_ready"] is False
    assert prior_summary["public_200_claim_supported"] is False
    assert b9_res["status"] == "REDTEAM_TERMINAL"
    assert b9_res["causal_admission"] is False
    assert b9_res["worker_pass_is_proposal_only"] is True
    assert b9_res["verdicts"] == {"KEEP": 2, "NARROW": 1, "REJECT": 0, "UNKNOWN": 0, "BLOCKED": 0}
    assert b9_res["per_case"][CASE_X4HG] == "KEEP"
    assert b9_res["per_case"][CASE_322X] == "KEEP"
    assert b9_res["per_case"][EXCLUDE_GOPACKET] == "NARROW"
    assert b9_res["frozen_verdicts"][EXCLUDE_GOPACKET] == "NARROW"
    assert [row["case_id"] for row in b9_rows] == [CASE_X4HG, CASE_322X, EXCLUDE_GOPACKET]
    assert lr_res["status"] == "TERMINAL"
    assert lr_res["causal_admission"] is False
    assert lr_res["more_than_200_unsupported"] is True
    assert lr_res["worker_pass_is_proposal_only"] is True
    assert lr_res["verdicts"] == {"KEEP": 1, "NARROW": 0, "REJECT": 0, "UNKNOWN": 0, "BLOCKED": 0}
    assert lr_res["conservation"] == {
        "assigned": 1,
        "reviewed": 1,
        "unreviewed": 0,
        "identity": "assigned = reviewed + unreviewed",
        "check": "1 = 1 + 0",
    }
    assert [row["case_id"] for row in lr_rows] == [CASE_PMCH]
    assert lr_res["scope"]["case_ids"] == [CASE_PMCH]
    assert lr_res["per_case"] == {CASE_PMCH: "KEEP"}

    by_kind: dict[str, list[dict]] = {}
    for row in base_rows:
        by_kind.setdefault(row["record_kind"], []).append(row)
    assert [row["record_kind"] for row in base_rows[:12]] == ["PACKET_AUTHORITY"] * 12
    assert len(by_kind["PACKET_AUTHORITY"]) == 12
    assert len(by_kind["SUPERSEDES_EDGE"]) == 40
    assert len(by_kind["PRESERVED_HYPOTHESIS"]) == 211
    assert len(by_kind["PRESERVED_PUBLIC_CASE"]) == 212
    assert len(by_kind["APPEND_IDENTITY"]) == 9
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

    keep_b9 = [row for row in b9_rows if row["verdict"] == "KEEP"]
    assert [row["case_id"] for row in keep_b9] == list(NOGGIN_IDS)
    gopacket = [row for row in b9_rows if row["case_id"] == EXCLUDE_GOPACKET][0]
    assert gopacket["verdict"] == "NARROW"
    assert gopacket["countable_proposal"] is False
    src_keep = keep_b9 + lr_rows
    assert [row["case_id"] for row in src_keep] == list(NEW_IDS)

    builders = {
        CASE_X4HG: counted_from_noggin,
        CASE_322X: counted_from_noggin,
        CASE_PMCH: counted_from_langroid,
    }
    new_counted: list[dict] = []
    new_appends: list[dict] = []
    new_edges: list[dict] = []
    seen_pairs: set[tuple[str, str, str]] = set()
    for offset, row in enumerate(src_keep):
        assert row["verdict"] == "KEEP"
        assert row["countable_proposal"] is True
        assert row["causal_admission"] is False
        assert seven_pass(gates_from(row))
        case_id = row["case_id"]
        assert case_id not in base_ids
        assert case_id not in source_ids
        assert case_id not in pub_text
        assert case_id.lower() not in pub_text.lower()
        assert case_id != EXCLUDE_GOPACKET
        counted = builders[case_id](row, ordinal=79 + offset)
        pair = (counted["case_id"], counted["candidate_set"][0], counted["minimum_fix_set"][0])
        assert pair not in seen_pairs
        seen_pairs.add(pair)
        assert "clone_path" not in counted
        assert "clone" not in counted
        assert counted["mechanism_fingerprint"] not in base_fps
        assert counted["mechanism_key"] not in base_mechs
        assert_no_leak(compact_json(counted))
        base_fps.add(counted["mechanism_fingerprint"])
        base_mechs.add(counted["mechanism_key"])
        new_counted.append(counted)
        new_appends.append(append_from_counted(counted))
        new_edges.append(edge_from_counted(counted))

    assert [row["case_id"] for row in new_counted] == list(NEW_IDS)
    assert [row["ordinal"] for row in new_counted] == [79, 80, 81]
    assert new_counted[0]["candidate_set"] == [CAND_X4HG]
    assert new_counted[0]["minimum_fix_set"] == [FIX_X4HG]
    assert new_counted[1]["candidate_set"] == [CAND_322X]
    assert new_counted[1]["minimum_fix_set"] == [FIX_322X]
    assert new_counted[2]["candidate_set"] == [CAND_PMCH]
    assert new_counted[2]["minimum_fix_set"] == [FIX_PMCH]
    assert new_counted[0]["contribution_class"] == "AI_DIRECT_ROOT"
    assert new_counted[1]["contribution_class"] == "AI_DIRECT_ROOT"
    assert new_counted[2]["contribution_class"] == "AI_INCOMPLETE_REMEDIATION"
    assert REMEDIATION_GATE not in new_counted[0]
    assert REMEDIATION_GATE not in new_counted[1]
    assert new_counted[2][REMEDIATION_GATE] == "PASS"
    assert REMEDIATION_GATE not in new_appends[0]
    assert REMEDIATION_GATE not in new_appends[1]
    assert new_appends[2][REMEDIATION_GATE] == "PASS"
    assert len(seen_pairs) == 3
    noggin_cartesian = {
        (case_id, cand, fix)
        for case_id in NOGGIN_IDS
        for cand in (CAND_X4HG, CAND_322X)
        for fix in (FIX_X4HG, FIX_322X)
    }
    noggin_pairs = {pair for pair in seen_pairs if pair[0] in NOGGIN_IDS}
    assert noggin_pairs < noggin_cartesian
    assert len(noggin_cartesian) == 8
    assert len(noggin_pairs) == 2
    assert (CASE_X4HG, CAND_X4HG, FIX_322X) not in seen_pairs
    assert (CASE_322X, CAND_322X, FIX_X4HG) not in seen_pairs
    assert len({row["mechanism_fingerprint"] for row in new_counted}) == 3
    assert len({row["mechanism_key"] for row in new_counted}) == 3

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
    assert not any(row["case_id"] == EXCLUDE_GOPACKET for row in counted_rows)
    assert CASE_Q855 in {row["case_id"] for row in counted_rows}
    assert set(B3_KEEP) <= {row["case_id"] for row in counted_rows}
    assert all("candidate_fix_edges" not in row for row in counted_rows)

    kinds = Counter(row["record_kind"] for row in records)
    assert kinds["PRESERVED_HYPOTHESIS"] == 211
    assert kinds["PRESERVED_PUBLIC_CASE"] == 212
    assert kinds["APPEND_IDENTITY"] == 12
    assert kinds["STRICT_RELEASED_CASE"] == STRICT_COUNT
    assert kinds["PACKET_AUTHORITY"] == 15
    assert kinds["SUPERSEDES_EDGE"] == 43
    assert sum(row.get("counted") is True for row in records) == STRICT_COUNT
    assert len(records) == 574

    ledger_text = "".join(compact_json(row) + "\n" for row in records)
    assert not HAN.search(ledger_text)
    base_ledger_text = (ROOT / P_C78_LEDGER).read_text()
    base_counted_text = "".join(
        compact_json(row) + "\n" for row in base_rows if row["record_kind"] == "STRICT_RELEASED_CASE"
    )
    new_base_counted_text = "".join(compact_json(row) + "\n" for row in counted_rows[:PRIOR_STRICT])
    assert new_base_counted_text == base_counted_text
    assert sha256_bytes(base_ledger_text.encode()) == pins["canonical78_ledger"]["sha256"]
    hyp_text = "".join(compact_json(row) + "\n" for row in by_kind["PRESERVED_HYPOTHESIS"])
    pub_layer_text = "".join(compact_json(row) + "\n" for row in by_kind["PRESERVED_PUBLIC_CASE"])
    new_hyp_text = "".join(
        compact_json(row) + "\n" for row in records if row["record_kind"] == "PRESERVED_HYPOTHESIS"
    )
    new_pub_text = "".join(
        compact_json(row) + "\n" for row in records if row["record_kind"] == "PRESERVED_PUBLIC_CASE"
    )
    assert new_hyp_text == hyp_text
    assert new_pub_text == pub_layer_text

    counted_ids = [row["case_id"] for row in counted_rows]
    prior_append = list(prior_summary["conservation"]["append_identities"])
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical81-hold",
        "canonical_strict_count": STRICT_COUNT,
        "checkpoint": {
            "prior_strict_count": PRIOR_STRICT,
            "corrected_strict_count": STRICT_COUNT,
            "corrected_baseline": 47,
            "fp211_released_admitted_raw": 48,
            "added_b3": list(B3_KEEP),
            "appended_q855": [CASE_Q855],
            "appended_specifyjs_five": list(prior_summary["checkpoint"]["appended_specifyjs_five"]),
            "appended_batch9_two": list(NOGGIN_IDS),
            "appended_langroid_one": [CASE_PMCH],
            "downgraded": [EXCLUDE_4FXP],
            "narrow_noncounting": [EXCLUDE_F38V, EXCLUDE_4FXP, EXCLUDE_NARROW, EXCLUDE_GOPACKET],
            "directory_name": "orchestrator-260814-ghsa200-canonical81",
            "prior_directory": "orchestrator-260814-ghsa200-canonical78",
            "note": "Directory name is canonical81. Semantic target is canonical strict count 81: the prior 78 exact strict IDs plus two independently red-teamed NogginLessDom identities and one langroid incomplete-remediation identity, ordinals 79 through 81 in leader-accepted order. Source conservation remains 211 hypotheses and 212 GHSA cases. gopacket GHSA-6R28-9PPF-4HJ5 stays NARROW and is not counted. Publication and integration stay closed. Greater-than-200 remains unsupported.",
        },
        "counting_unit": "first-party GHSA case",
        "language": "en",
        "causal_admission": False,
        "integration_ready": False,
        "publication_ready": False,
        "public_200_claim_supported": False,
        "claim_boundary": "HOLD snapshot of canonical strict count 81 first-party GHSA identities: the prior 78 plus GHSA-X4HG-HFWF-P9MW, GHSA-322X-V876-G883, and GHSA-PMCH-G965-GRMR. Source conservation remains 211 hypotheses and 212 GHSA cases. This does not support a greater-than-200 claim. Publication and integration stay closed.",
        "conservation": {
            "fp211_hypotheses": 211,
            "fp211_source_ghsa_cases": 212,
            "cve_aliases_counted": False,
            "upgrades_append": False,
            "new_identities_append": True,
            "prior_append_identities": prior_append,
            "append_identities": prior_append + list(NEW_IDS),
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
            "batch9_three_keep": 2,
            "langroid_one_keep": 1,
            "netnew22_narrow_excluded": 1,
            "b3_narrow_excluded": 1,
            "batch9_three_narrow_excluded": 1,
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
            "discovery_tabs": "not included",
            "worker_only_PASS": "not included",
            "cartesian_candidate_fix_edges": "not invented; X4HG binds f8ee181b to 25a3cbac and 322X binds ed0124d3 to 785e6ac6; shared npm 0.0.21/0.0.22 does not merge those pairs",
        },
        "seven_gates": list(GATES),
        "remediation_patch_delta_gate": "required PASS only on GHSA-PMCH-G965-GRMR among the three new rows; the two NogginLessDom rows are AI_DIRECT_ROOT",
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
            "# Canonical81 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 81 first-party GHSA identities. It extends the frozen canonical78 snapshot in orchestrator-260814-ghsa200-canonical78 by appending exactly three leader-accepted identities. Integration_ready is false. Publication_ready is false. Causal admission is false. This packet does not support a greater-than-200 claim.",
            "",
            "Composition: the prior 78 counted rows are preserved byte-for-byte, plus terminal batch9-three red-team KEEP 2 and terminal langroid-one red-team KEEP 1. Corrected baseline 47, plus terminal netnew22 KEEP 21, plus independent Actual/Gogs KEEP 2, plus terminal B3 KEEP 2, plus GHSA-Q855-8RH5-JFGQ, plus specifyjs five, plus these three. GHSA-F38V-77QJ-H4JQ, GHSA-4FXP-2M36-QV64, GHSA-7C3W-FXGH-FRC7, and GHSA-6R28-9PPF-4HJ5 remain noncounting. Count is by first-party GHSA identity once. CVE aliases are stored and never counted.",
            "",
            "The three admitted identities, ordinals 79 through 81 in leader-accepted order, are GHSA-X4HG-HFWF-P9MW, GHSA-322X-V876-G883, and GHSA-PMCH-G965-GRMR. X4HG maps candidate f8ee181b to minimum fix 25a3cbac as AI_DIRECT_ROOT. 322X maps candidate ed0124d3 to minimum fix 785e6ac6 as AI_DIRECT_ROOT. PMCH maps candidate 60933b48 to minimum fix 00b7dd7b as AI_INCOMPLETE_REMEDIATION with remediation patch-delta PASS. All seven contract gates are PASS. Patch-delta is required only for PMCH among the three new rows. Those mappings are not Cartesian products: shared npm 0.0.21/0.0.22 does not pair f8ee181b with 785e6ac6 or ed0124d3 with 25a3cbac. GHSA-6R28-9PPF-4HJ5 is the gopacket NARROW row from the same batch9-three packet and is not counted.",
            "",
            "NogginLessDom identity uses GitHub-reviewed global GHSA objects (type=reviewed, withdrawn_at=null, source_code_location=asymmetric-effort/NogginLessDom). Repo advisory REST GET succeeded. Vulnerable containment is npm @asymmetric-effort/nogginlessdom 0.0.21 (gitHead 7cd24135, tag v0.0.21, tarball sha256 47aba8a9). Fixed containment is npm 0.0.22 (gitHead 00dc8ad3, tag v0.0.22, tarball sha256 d33559d2). GitHub Release objects are 404. The version-bump commits are not equal to the minimum fixes. Git replay uses npm gitHead commits because the partial clone has no local tags.",
            "",
            "Langroid identity uses the GitHub-reviewed global GHSA object (type=reviewed, withdrawn_at=null, source_code_location=langroid/langroid, alias CVE-2026-50180). Distinct from GHSA-MXFR-6HCW-J9RQ. Vulnerable containment is PyPI langroid 0.63.0 (tag 0.63.0 peels to fee670d5, wheel sha256 8a91de0e, sdist sha256 da8d2250, sql blob 887a10a4 equals the AI blob). Fixed containment is PyPI 0.64.0 (tag 0.64.0 peels to 84d2aff0, wheel sha256 795bd1f6, sdist sha256 dcb6c6e4, sql blob a55f6d34 equals the closer). GitHub Release objects exist and their wheel digests match PyPI. First-party source references are the reviewed global GHSA URLs and the red-team frozen GHSA/npm/PyPI pages; those pages are not copied into this directory.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer, including dual ordinal-200 identities GHSA-3J8Q-FWPJ-F8J5 and GHSA-JJCJ-H3CM-P7X7. Same-id upgrades still do not append. The three new identities are absent from the 212 and append. Direct-root batch9 and batch11 PASS rows are proposals only; independent batch9-three KEEP and langroid-one KEEP are the terminal admission edges. Discovery tabs and worker-only PASS are not loaded.",
            "",
            "Every counted row has all seven contract gates equal to the string PASS. Null and NA fail closed. Candidate, carrier, and minimum-fix sets are sorted unique 40-hex SHAs. Cartesian candidate times fix pairs are not invented.",
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
        "overlay_name": "canonical81-hold",
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
        print("PASS: canonical81 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
