#!/usr/bin/env python3
"""Build the HOLD canonical71-directory snapshot at strict count 72. Stdlib only."""

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
EXCLUDE_NARROW = "GHSA-7C3W-FXGH-FRC7"
EXCLUDE_F38V = "GHSA-F38V-77QJ-H4JQ"
EXCLUDE_4FXP = "GHSA-4FXP-2M36-QV64"
B3_KEEP = ("GHSA-G3XQ-3GMV-QQ8G", "GHSA-PV2J-RGHR-V5R9")
STRICT_COUNT = 72
UNCORRECTED_COUNT_73 = 73
FILEBROWSER_NEG = "post:filebrowser-delete-scope@canonical"
FILEBROWSER_POS = "post:filebrowser-dangling-write@canonical"
ORD200 = ("GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7")

P_CONTRACT = "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
P_BASELINE = "autoresearch/orchestrator-260813-ghsa200-leader/baseline.json"
P_LEDGER = "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl"
P_SRC_MAN = "autoresearch/orchestrator-260813-fp211-canonical/source_manifest.json"
P_MECH = "autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl"
P_CASES = "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl"
P_FINAL_RES = "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/result.json"
P_FINAL_CASES = "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/cases.jsonl"
P_NN_RES = "autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/result.json"
P_NN_CASES = "autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh/cases.jsonl"
P_AG_RES = "autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/result.json"
P_AG_CASES = "autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high/cases.jsonl"
P_B3_RES = "autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/result.json"
P_B3_CASES = "autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh/cases.jsonl"
P_PUB = "scripts/publication_adjudications.json"

FROZEN = {
    "contract": (P_CONTRACT, "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3"),
    "leader_baseline": (P_BASELINE, "d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132"),
    "fp211_ledger": (P_LEDGER, "1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6"),
    "fp211_source_manifest": (P_SRC_MAN, "679dbac540bf2f8dad0a24a85d8fc309c613977a2b58a1ad44b40e5a85798ccb"),
    "fp211_mechanisms": (P_MECH, "0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2"),
    "fp211_public_cases": (P_CASES, "e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257"),
    "final_review_result": (P_FINAL_RES, "4be2620a548370c845e22c0d7cbe3ed10ab156ef39b1a0432ff4220ff406e528"),
    "final_review_cases": (P_FINAL_CASES, "e275437954890dca07855b5fcfa545f8f1a366fb85a7ee9f067da5b710b2b3da"),
    "netnew22_result": (P_NN_RES, "c50b878583f3b09f37d7c88638ea179e75cf6b0ccf2e4ade689f2d673f7b0829"),
    "netnew22_cases": (P_NN_CASES, "d4d3c96ba0a60214971ab88f3de7adce1edfc27f39a388906600aad91b5c1889"),
    "actual_gogs_result": (P_AG_RES, "bf3676928fb61809f425e0b369b010d79018a890852e8d6310d13912a6d83b9d"),
    "actual_gogs_cases": (P_AG_CASES, "3a74a0133dbfd3e128834f9bbc641b78c1515e5647fd07085bba30e2984d827f"),
    "b3_result": (P_B3_RES, "78a101f809e7d65269db834e60211d87404d2faa48b8e3bf6a46693fa7dfd644"),
    "b3_cases": (P_B3_CASES, "b423591122de906c65c49ac62ba581ffcd3442880eae638e8de773c90bc689dd"),
}
OVERLAP = {
    "publication_adjudications": (P_PUB, "9fdff2e65bb2e4e1ac6b83c355bbb27e08542005fe572700340e1567a4e9cc4f"),
}

PACKET_AUTHORITY = [
    {"packet": "autoresearch/orchestrator-260813-fp211-canonical", "role": "frozen_base", "terminal": True, "status": "HOLD", "authority_rank": 0},
    {"packet": "autoresearch/orchestrator-260813-fp211-audit", "role": "frozen_base", "terminal": True, "status": "FINAL_AUDIT_COMPLETE", "authority_rank": 0},
    {"packet": "autoresearch/orchestrator-260813-ghsa200-leader", "role": "frozen_base", "terminal": True, "status": "ACTIVE_RESEARCH", "authority_rank": 0},
    {"packet": "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex", "role": "final_review", "terminal": True, "status": "COMPLETE_BOUNDED_REVIEW", "authority_rank": 20},
    {"packet": "autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam", "role": "redteam", "terminal": True, "status": "REDTEAM_COMPLETE", "authority_rank": 25},
    {"packet": "autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh", "role": "redteam", "terminal": True, "status": "REDTEAM_TERMINAL", "authority_rank": 30},
    {"packet": "autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high", "role": "redteam", "terminal": True, "status": "REDTEAM_COMPLETE", "authority_rank": 31},
    {"packet": "autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh", "role": "redteam", "terminal": True, "status": "REDTEAM_COMPLETE", "authority_rank": 32},
]

INCOMPLETE_NARROW = (
    "GHSA-2X93-H3HG-2XFP",
    "GHSA-4MR5-G6F9-CFRH",
    "GHSA-94P4-4CQ8-9G67",
    "GHSA-9C3V-684M-579C",
    "GHSA-P538-C434-8V24",
    "GHSA-V396-V7Q4-X2QJ",
)

CLONES = {
    "gitpython-developers/GitPython": "/home/hanqing/.cache/ghsa200-worker-clones/increm-patchdelta-even/clones/GitPython",
    "MervinPraison/PraisonAI": "/home/hanqing/.cache/ghsa200-worker-clones/increm-patchdelta-odd/clones/praisonai",
    "zereight/gitlab-mcp": "/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/gitlab-mcp",
    "openclaw/openclaw": "/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/openclaw",
    "homeassistant-ai/ha-mcp": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/homeassistant-ai__ha-mcp",
    "szTheory/relyra": "/home/hanqing/.cache/ghsa200-worker-clones/red-upgrade-b-ord211-release/clones/szTheory__relyra",
    "modelcontextprotocol/registry": "/home/hanqing/.cache/ghsa200-worker-clones/increm-patchdelta-odd/clones/mcp-registry",
    "j178/prek-action": "/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/prek-action",
    "microsoft/prompty": "/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/prompty",
    "craigjbass/clearancekit": "/home/hanqing/.cache/ghsa200-worker-clones/increm-patchdelta-even/clones/clearancekit",
    "Jo-Jo98/ciguard": "/home/hanqing/.cache/ghsa200-worker-clones/third-review-upgrade-a/clones/ciguard",
    "actualbudget/actual": "/tmp/ghsa200-worker-clones/narrow-recovery-a-grok46-xhigh/clones/actual",
    "gogs/gogs": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs",
    "cnighswonger/claude-code-cache-fix": "/tmp/ghsa200-worker-clones/upgrade-b/clones/claude-code-cache-fix",
}


def compact_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


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


def packet_releases(row: dict) -> tuple[str, str, str | None, str | None, str | None, str | None]:
    vuln = row.get("vulnerable_release") or row.get("vulnerable_release_evidence") or {}
    fixed = row.get("fixed_release") or row.get("fixed_release_evidence") or {}
    vtag = vuln.get("tag") or vuln.get("git_tag")
    ftag = fixed.get("tag") or fixed.get("git_tag")
    if row["case_id"] == "GHSA-PV2J-RGHR-V5R9" and not vtag:
        vtag = "v4.6.52"
    vsha = vuln.get("sha") or vuln.get("git_tag_commit")
    fsha = fixed.get("sha") or fixed.get("git_tag_commit")
    assert vtag and ftag, row["case_id"]
    return vtag, ftag, vsha, fsha, vuln.get("kind"), fixed.get("kind")


def counted_from_packet(row: dict, *, action: str, in_fp211: bool, row_key, ordinal, admission_source: str) -> dict:
    candidate_set = sha_set(row["candidate_set"])
    carrier_set = sha_set(row.get("carrier_set") or [])
    minimum_fix_set = sha_set(row["minimum_fix_set"])
    case_id = row["case_id"]
    assert GHSA_RE.fullmatch(case_id)
    mechanism_key = row["mechanism_key"]
    assert mechanism_key
    aliases = list(row.get("aliases") or [])
    assert all(not item.startswith("GHSA-") or item == case_id for item in aliases)
    g = gates_from(row)
    assert all(g[field] == "PASS" for field in GATES)
    vtag, ftag, vsha, fsha, vkind, fkind = packet_releases(row)
    return {
        "action": action,
        "admission_source": admission_source,
        "aliases": aliases,
        "candidate_set": candidate_set,
        "carrier_set": carrier_set,
        "case_id": case_id,
        "contribution_class": row["contribution_class"],
        "counted": True,
        "counting_unit": "first-party GHSA case",
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "fixed_release": {
            "kind": fkind,
            "sha": fsha,
            "tag": ftag,
        },
        "in_fp211_212": in_fp211,
        "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        "mechanism_fingerprint": fingerprint(case_id, mechanism_key, candidate_set, minimum_fix_set),
        "mechanism_key": mechanism_key,
        "minimum_fix_set": minimum_fix_set,
        "ordinal": ordinal,
        "overlay_state": "KEEP",
        "record_kind": "STRICT_RELEASED_CASE",
        "repository": row["repository"],
        "row_key": row_key,
        "schema_version": SCHEMA,
        "source_layer": False,
        "vulnerable_release": {
            "kind": vkind,
            "sha": vsha,
            "tag": vtag,
        },
        **g,
    }


def counted_from_fp211(case: dict, hyp: dict, ledger_row: dict) -> dict:
    audit = ledger_row["fp211_adjudication"]
    candidate_set = sha_set(audit["candidate_set"])
    carrier_set = sha_set(audit["carrier_set"])
    minimum_fix_set = sha_set(audit["minimum_fix_set"])
    case_id = case["case_id"]
    mechanism_key = ledger_row.get("mechanism_key") or case.get("mechanism_key") or ledger_row["row_key"]
    aliases = [item for item in case.get("aliases") or [] if item != case_id]
    g = {field: audit[field] for field in GATES}
    assert all(g[field] == "PASS" for field in GATES)
    assert ledger_row["counting"]["fp211_released_publication_admitted"] is True
    fp = ledger_row.get("mechanism_fingerprint") or fingerprint(
        case_id, mechanism_key, candidate_set, minimum_fix_set
    )
    rel = ledger_row.get("release_evidence") or {}
    return {
        "action": "PRESERVE",
        "admission_source": "fp211_released_publication_admitted",
        "aliases": aliases,
        "candidate_set": candidate_set,
        "carrier_set": carrier_set,
        "case_id": case_id,
        "contribution_class": audit["causal_class"],
        "counted": True,
        "counting_unit": "first-party GHSA case",
        "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
        "fixed_release": {
            "kind": rel.get("kind"),
            "sha": rel.get("fix_sha"),
            "tag": rel.get("fixed_tag"),
        },
        "in_fp211_212": True,
        "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
        "mechanism_fingerprint": fp,
        "mechanism_key": mechanism_key,
        "minimum_fix_set": minimum_fix_set,
        "ordinal": case["ordinal"],
        "overlay_state": "PRESERVE",
        "record_kind": "STRICT_RELEASED_CASE",
        "repository": case["repository"],
        "row_key": case["row_key"],
        "schema_version": SCHEMA,
        "source_layer": False,
        "vulnerable_release": {
            "kind": rel.get("kind"),
            "sha": rel.get("candidate_sha"),
            "tag": rel.get("vulnerable_tag"),
        },
        **g,
    }


def supersedes_edges(nn_keep: list[str]) -> list[dict]:
    edges = [
        {
            "edge_id": "E-4FXP-ID",
            "case_id": EXCLUDE_4FXP,
            "from_packet": "autoresearch/orchestrator-260813-fp211-canonical",
            "to_packet": "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex",
            "from_verdict": "fp211_released_publication_admitted",
            "to_verdict": "NARROW",
            "authority_rank": 20,
            "failed_gate": "identity_gate",
            "applies_now": True,
            "applies_to_counted_set": True,
            "pending_until_to_packet_terminal": False,
            "authority_lineage": [
                "fp211 released_publication_admitted CONFIRM/HIGH seven PASS",
                "baseline-increm-even KEEP revalidation",
                "final-candidate-review-codex NARROW identity_gate supersedes counted membership",
            ],
            "note": "Mandatory leader correction: final-review identity_gate NARROW (repo advisory 404; global GHSA empty vulnerabilities / no repository object) supersedes the old fp211 released-admitted flag. Do not KEEP or count.",
        }
    ]
    for case_id in INCOMPLETE_NARROW:
        edges.append(
            {
                "edge_id": f"E-{case_id[5:9]}",
                "case_id": case_id,
                "from_packet": "autoresearch/herdr-260813-ghsa200-upgrade-b",
                "to_packet": "autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam",
                "from_verdict": "PASS",
                "to_verdict": "NARROW",
                "authority_rank": 25,
                "failed_gate": None,
                "applies_now": True,
                "applies_to_counted_set": False,
                "pending_until_to_packet_terminal": False,
                "note": "Terminal incomplete-rem NARROW. Identity was not in the frozen 48.",
            }
        )
    edges.append(
        {
            "edge_id": "E-7C3W-RT",
            "case_id": EXCLUDE_NARROW,
            "from_packet": "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex",
            "to_packet": "autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh",
            "from_verdict": "ACCEPT",
            "to_verdict": "NARROW",
            "authority_rank": 30,
            "failed_gate": "but_for_gate",
            "applies_now": True,
            "applies_to_counted_set": True,
            "pending_until_to_packet_terminal": False,
            "note": "Mandatory: netnew22 NARROW overrides final-review ACCEPT. Do not KEEP or count.",
        }
    )
    for case_id in nn_keep:
        in_fp = case_id not in {"GHSA-G39V-CVJH-8FPF", "GHSA-PF93-J98V-25PV"}
        edges.append(
            {
                "edge_id": f"E-NN-{case_id[5:9]}",
                "case_id": case_id,
                "from_packet": "autoresearch/orchestrator-260813-fp211-audit" if in_fp else "absent",
                "to_packet": "autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh",
                "from_verdict": "fp211" if in_fp else "ABSENT",
                "to_verdict": "KEEP",
                "authority_rank": 30,
                "failed_gate": None,
                "applies_now": True,
                "applies_to_counted_set": True,
                "pending_until_to_packet_terminal": False,
                "note": "Terminal netnew22 KEEP. Same-id upgrade does not append; absent ids append.",
            }
        )
    edges.append(
        {
            "edge_id": "E-7GH7-AG",
            "case_id": "GHSA-7GH7-258J-4MPQ",
            "from_packet": "autoresearch/herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh",
            "to_packet": "autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high",
            "from_verdict": "PASS",
            "to_verdict": "KEEP",
            "authority_rank": 31,
            "failed_gate": None,
            "applies_now": True,
            "applies_to_counted_set": True,
            "pending_until_to_packet_terminal": False,
            "note": "Independent Actual red-team KEEP. Worker PASS is not admission. Same-id upgrade, not append.",
        }
    )
    edges.append(
        {
            "edge_id": "E-6P9M-AG",
            "case_id": "GHSA-6P9M-Q3JP-47H4",
            "from_packet": "autoresearch/herdr-260813-ghsa200-commitfirst-gj-grok46-medium",
            "to_packet": "autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high",
            "from_verdict": "PASS",
            "to_verdict": "KEEP",
            "authority_rank": 31,
            "failed_gate": None,
            "applies_now": True,
            "applies_to_counted_set": True,
            "pending_until_to_packet_terminal": False,
            "note": "Independent Gogs red-team KEEP on leader-corrected edge. Worker PASS is not admission. Absent identity appends.",
        }
    )
    edges.append(
        {
            "edge_id": "E-F38V-B3",
            "case_id": EXCLUDE_F38V,
            "from_packet": "autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high",
            "to_packet": "autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh",
            "from_verdict": "PASS",
            "to_verdict": "NARROW",
            "authority_rank": 32,
            "failed_gate": "but_for_gate",
            "applies_now": True,
            "applies_to_counted_set": True,
            "pending_until_to_packet_terminal": False,
            "note": "Mandatory: B3 NARROW. Do not KEEP or count GHSA-F38V-77QJ-H4JQ.",
        }
    )
    for case_id in B3_KEEP:
        edges.append(
            {
                "edge_id": f"E-B3-{case_id[5:9]}",
                "case_id": case_id,
                "from_packet": "autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high",
                "to_packet": "autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh",
                "from_verdict": "PASS",
                "to_verdict": "KEEP",
                "authority_rank": 32,
                "failed_gate": None,
                "applies_now": True,
                "applies_to_counted_set": True,
                "pending_until_to_packet_terminal": False,
                "note": "Terminal B3 KEEP. Same-id upgrade, not append. Worker PASS is not admission.",
            }
        )
    edges.sort(key=lambda item: (item["authority_rank"], item["edge_id"]))
    for edge in edges:
        edge["record_kind"] = "SUPERSEDES_EDGE"
        edge["schema_version"] = SCHEMA
        edge["source_layer"] = True
        edge["counted"] = False
    return edges


def overlay_for(case_id: str, row_key: str, audit: dict, edges_by_case: dict[str, list[dict]]) -> dict:
    state = {
        "overlay_state": "PRESERVE",
        "action": "PRESERVE",
        "candidate_set": sha_set(audit["candidate_set"]),
        "carrier_set": sha_set(audit["carrier_set"]),
        "minimum_fix_set": sha_set(audit["minimum_fix_set"]),
        "gates": {field: audit[field] for field in GATES},
        "authority_packet": "autoresearch/orchestrator-260813-fp211-audit",
    }
    for edge in edges_by_case.get(case_id, []):
        if not edge["applies_now"]:
            continue
        state["overlay_state"] = edge["to_verdict"]
        state["action"] = "SUPERSEDE"
        state["authority_packet"] = edge["to_packet"]
        state["edge_id"] = edge["edge_id"]
    return state


def build_outputs() -> dict[Path, str]:
    pins = pin_frozen()
    ledger_fp211 = load_jsonl(ROOT / P_LEDGER)
    mechs = load_jsonl(ROOT / P_MECH)
    cases = load_jsonl(ROOT / P_CASES)
    nn_rows = load_jsonl(ROOT / P_NN_CASES)
    nn_res = load_json(ROOT / P_NN_RES)
    ag_rows = load_jsonl(ROOT / P_AG_CASES)
    ag_res = load_json(ROOT / P_AG_RES)
    b3_rows = load_jsonl(ROOT / P_B3_CASES)
    b3_res = load_json(ROOT / P_B3_RES)
    final_rows = load_jsonl(ROOT / P_FINAL_CASES)
    assert nn_res["status"] == "REDTEAM_TERMINAL"
    assert ag_res["status"] == "REDTEAM_COMPLETE"
    assert b3_res["status"] == "REDTEAM_COMPLETE"
    assert b3_res["replay_run"]["rc"] == 0
    assert nn_res["verdicts"]["KEEP"] == 21 and nn_res["per_case"][EXCLUDE_NARROW] == "NARROW"
    assert ag_res["verdicts"]["KEEP"] == 2
    assert b3_res["verdicts"] == {"KEEP": 2, "NARROW": 1, "REJECT": 0, "UNKNOWN": 0, "BLOCKED": 0}
    assert b3_res["per_case"][EXCLUDE_F38V] == "NARROW"
    assert [row["case_id"] for row in ag_rows] == ["GHSA-7GH7-258J-4MPQ", "GHSA-6P9M-Q3JP-47H4"]
    assert [row["case_id"] for row in b3_rows] == [
        "GHSA-G3XQ-3GMV-QQ8G",
        "GHSA-F38V-77QJ-H4JQ",
        "GHSA-PV2J-RGHR-V5R9",
    ]

    hyp = [
        row
        for row in ledger_fp211
        if row.get("record_kind") == "COMPONENT_ROW" and row["counting"]["canonical_instance"]
    ]
    assert len(hyp) == len(mechs) == 211
    assert [row["row_key"] for row in hyp] == [row["row_key"] for row in mechs]
    assert [row["ordinal"] for row in mechs] == list(range(1, 212))
    assert len(cases) == 212
    assert len({row["case_id"] for row in cases}) == 212
    assert {row["row_key"] for row in cases} == {row["row_key"] for row in hyp}

    hyp_by_key = {row["row_key"]: row for row in hyp}
    case_by_id = {row["case_id"]: row for row in cases}
    source_ids = {row["case_id"] for row in cases}

    nn_keep_rows = [row for row in nn_rows if row["verdict"] == "KEEP"]
    nn_narrow = [row for row in nn_rows if row["verdict"] == "NARROW"]
    assert len(nn_keep_rows) == 21 and len(nn_narrow) == 1
    assert nn_narrow[0]["case_id"] == EXCLUDE_NARROW
    assert nn_narrow[0]["but_for_gate"] == "NARROW"
    nn_keep_ids = [row["case_id"] for row in nn_keep_rows]
    assert EXCLUDE_NARROW not in nn_keep_ids

    edges = supersedes_edges(nn_keep_ids)
    edges_by_case: dict[str, list[dict]] = {}
    for edge in edges:
        edges_by_case.setdefault(edge["case_id"], []).append(edge)

    admitted = [row for row in hyp if row["counting"]["fp211_released_publication_admitted"]]
    assert len(admitted) == 48
    baseline_cases = []
    for row in admitted:
        matched = [item for item in cases if item["row_key"] == row["row_key"]]
        assert len(matched) == 1, row["row_key"]
        baseline_cases.append(matched[0]["case_id"])
    assert len(baseline_cases) == 48
    assert EXCLUDE_NARROW not in baseline_cases
    assert EXCLUDE_4FXP in baseline_cases
    four_final = next(row for row in final_rows if row["case_id"] == EXCLUDE_4FXP)
    assert four_final["final_verdict"] == "NARROW"
    assert four_final["countable_first_party_ghsa"] is False
    assert four_final["gates"]["identity_gate"] == "NARROW"
    corrected_baseline = [case_id for case_id in baseline_cases if case_id != EXCLUDE_4FXP]
    assert len(corrected_baseline) == 47

    append_src = []
    counted_rows = []
    for case_id in corrected_baseline:
        counted_rows.append(counted_from_fp211(case_by_id[case_id], hyp_by_key[case_by_id[case_id]["row_key"]], hyp_by_key[case_by_id[case_id]["row_key"]]))
    for row in nn_keep_rows:
        case_id = row["case_id"]
        assert case_id not in baseline_cases
        in_fp = case_id in source_ids
        if in_fp:
            src = case_by_id[case_id]
            counted_rows.append(
                counted_from_packet(
                    row,
                    action="SUPERSEDE",
                    in_fp211=True,
                    row_key=src["row_key"],
                    ordinal=src["ordinal"],
                    admission_source="netnew22_redteam_keep",
                )
            )
        else:
            append_src.append(row)
            counted_rows.append(
                counted_from_packet(
                    row,
                    action="APPEND",
                    in_fp211=False,
                    row_key=f"ghsa200-next:{case_id}",
                    ordinal=None,
                    admission_source="netnew22_redteam_keep",
                )
            )
    for row in ag_rows:
        assert row["verdict"] == "KEEP"
        assert seven_pass(gates_from(row))
        case_id = row["case_id"]
        assert case_id not in baseline_cases
        assert case_id not in nn_keep_ids
        in_fp = case_id in source_ids
        if in_fp:
            src = case_by_id[case_id]
            counted_rows.append(
                counted_from_packet(
                    row,
                    action="SUPERSEDE",
                    in_fp211=True,
                    row_key=src["row_key"],
                    ordinal=src["ordinal"],
                    admission_source="actual_gogs_redteam_keep",
                )
            )
        else:
            append_src.append(row)
            counted_rows.append(
                counted_from_packet(
                    row,
                    action="APPEND",
                    in_fp211=False,
                    row_key=f"ghsa200-next:{case_id}",
                    ordinal=None,
                    admission_source="actual_gogs_redteam_keep",
                )
            )

    b3_keep_rows = [row for row in b3_rows if row["verdict"] == "KEEP"]
    b3_narrow = [row for row in b3_rows if row["verdict"] == "NARROW"]
    assert len(b3_keep_rows) == 2 and len(b3_narrow) == 1
    assert b3_narrow[0]["case_id"] == EXCLUDE_F38V
    assert not seven_pass(gates_from(b3_narrow[0]))
    assert [row["case_id"] for row in b3_keep_rows] == list(B3_KEEP)
    for row in b3_keep_rows:
        assert seven_pass(gates_from(row))
        case_id = row["case_id"]
        assert case_id not in baseline_cases
        assert case_id not in nn_keep_ids
        assert case_id in source_ids
        src = case_by_id[case_id]
        counted_rows.append(
            counted_from_packet(
                row,
                action="SUPERSEDE",
                in_fp211=True,
                row_key=src["row_key"],
                ordinal=src["ordinal"],
                admission_source="b3_redteam_keep",
            )
        )

    counted_rows.sort(key=lambda item: item["case_id"])
    assert len(counted_rows) == STRICT_COUNT
    assert len({row["case_id"] for row in counted_rows}) == STRICT_COUNT
    append_src.sort(key=lambda item: item["case_id"])
    assert [row["case_id"] for row in append_src] == [
        "GHSA-6P9M-Q3JP-47H4",
        "GHSA-G39V-CVJH-8FPF",
        "GHSA-PF93-J98V-25PV",
    ]
    for index, row in enumerate(append_src, start=212):
        for item in counted_rows:
            if item["case_id"] == row["case_id"]:
                item["ordinal"] = index

    records: list[dict] = []
    for item in PACKET_AUTHORITY:
        records.append(
            {
                "schema_version": SCHEMA,
                "record_kind": "PACKET_AUTHORITY",
                "counted": False,
                "source_layer": True,
                **item,
            }
        )
    records.extend(edges)

    nn_by_id = {row["case_id"]: row for row in nn_rows}
    ag_by_id = {row["case_id"]: row for row in ag_rows}
    b3_by_id = {row["case_id"]: row for row in b3_rows}
    for audit, row in zip(mechs, hyp, strict=True):
        related = [item for item in cases if item["row_key"] == row["row_key"]]
        overlay = overlay_for(related[0]["case_id"], row["row_key"], audit, edges_by_case)
        for item in related[1:]:
            later = overlay_for(item["case_id"], row["row_key"], audit, edges_by_case)
            if later["overlay_state"] != "PRESERVE":
                overlay = later
        if related[0]["case_id"] in nn_by_id and nn_by_id[related[0]["case_id"]]["verdict"] == "KEEP":
            src = nn_by_id[related[0]["case_id"]]
            overlay.update(
                {
                    "overlay_state": "KEEP",
                    "action": "SUPERSEDE",
                    "candidate_set": sha_set(src["candidate_set"]),
                    "carrier_set": sha_set(src.get("carrier_set") or []),
                    "minimum_fix_set": sha_set(src["minimum_fix_set"]),
                    "gates": gates_from(src),
                    "authority_packet": "autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh",
                }
            )
        for item in related:
            if item["case_id"] in ag_by_id:
                src = ag_by_id[item["case_id"]]
                overlay.update(
                    {
                        "overlay_state": "KEEP",
                        "action": "SUPERSEDE",
                        "candidate_set": sha_set(src["candidate_set"]),
                        "carrier_set": sha_set(src.get("carrier_set") or []),
                        "minimum_fix_set": sha_set(src["minimum_fix_set"]),
                        "gates": gates_from(src),
                        "authority_packet": "autoresearch/herdr-260813-ghsa200-actual-gogs-redteam-grok46-high",
                    }
                )
            if item["case_id"] == EXCLUDE_4FXP:
                overlay.update(
                    {
                        "overlay_state": "NARROW",
                        "action": "SUPERSEDE",
                        "candidate_set": sha_set(four_final["candidate_set"]),
                        "carrier_set": sha_set(four_final.get("carrier_set") or []),
                        "minimum_fix_set": sha_set(four_final["minimum_fix_set"]),
                        "gates": {field: four_final["gates"][field] for field in GATES},
                        "authority_packet": "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex",
                        "authority_lineage": [
                            "fp211 released_publication_admitted CONFIRM/HIGH seven PASS",
                            "baseline-increm-even KEEP revalidation",
                            "final-candidate-review-codex NARROW identity_gate supersedes counted membership",
                        ],
                        "failed_gate": "identity_gate",
                    }
                )
            if item["case_id"] == EXCLUDE_NARROW:
                src = nn_by_id[EXCLUDE_NARROW]
                overlay.update(
                    {
                        "overlay_state": "NARROW",
                        "action": "SUPERSEDE",
                        "candidate_set": sha_set(src["candidate_set"]),
                        "carrier_set": sha_set(src.get("carrier_set") or []),
                        "minimum_fix_set": sha_set(src["minimum_fix_set"]),
                        "gates": gates_from(src),
                        "authority_packet": "autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh",
                    }
                )
            if item["case_id"] in b3_by_id:
                src = b3_by_id[item["case_id"]]
                overlay.update(
                    {
                        "overlay_state": src["verdict"],
                        "action": "SUPERSEDE",
                        "candidate_set": sha_set(src["candidate_set"]),
                        "carrier_set": sha_set(src.get("carrier_set") or []),
                        "minimum_fix_set": sha_set(src["minimum_fix_set"]),
                        "gates": gates_from(src),
                        "authority_packet": "autoresearch/herdr-260813-ghsa200-b3-redteam-grok46-xhigh",
                    }
                )
        records.append(
            {
                "schema_version": SCHEMA,
                "record_kind": "PRESERVED_HYPOTHESIS",
                "counted": False,
                "source_layer": True,
                "row_key": row["row_key"],
                "ordinal": audit["ordinal"],
                "repository": row["repository"],
                "fp211_verdict": audit["verdict"],
                "fp211_confidence": audit["confidence"],
                "source_tier": row["source_tier"],
                "released_publication_admitted": row["counting"]["fp211_released_publication_admitted"],
                "public_ids": list(row["public_ids"]),
                "declared_public_ids": list(row["declared_public_ids"]),
                "mechanism_key": row.get("mechanism_key"),
                "mechanism_fingerprint": row.get("mechanism_fingerprint"),
                "fp211_candidate_set": sha_set(audit["candidate_set"]),
                "fp211_carrier_set": sha_set(audit["carrier_set"]),
                "fp211_minimum_fix_set": sha_set(audit["minimum_fix_set"]),
                "legacy_candidate_fix_edges": row.get("candidate_fix_edges") or [],
                "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
                "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
                **overlay,
            }
        )

    for case in cases:
        records.append(
            {
                "schema_version": SCHEMA,
                "record_kind": "PRESERVED_PUBLIC_CASE",
                "counted": False,
                "source_layer": True,
                "case_id": case["case_id"],
                "aliases": list(case.get("aliases") or []),
                "row_key": case["row_key"],
                "ordinal": case["ordinal"],
                "verdict": case["verdict"],
                "repository": case["repository"],
                "identity_relation": case.get("identity_relation"),
                "counting_unit": "first-party GHSA case",
                "cve_aliases_counted": False,
            }
        )

    for row in append_src:
        case_id = row["case_id"]
        counted = next(item for item in counted_rows if item["case_id"] == case_id)
        records.append(
            {
                "schema_version": SCHEMA,
                "record_kind": "APPEND_IDENTITY",
                "counted": False,
                "source_layer": True,
                "case_id": case_id,
                "row_key": counted["row_key"],
                "ordinal": counted["ordinal"],
                "overlay_state": "KEEP",
                "action": "APPEND",
                "in_fp211_212": False,
                "admission_source": counted["admission_source"],
                "candidate_set": counted["candidate_set"],
                "carrier_set": counted["carrier_set"],
                "minimum_fix_set": counted["minimum_fix_set"],
                **{field: counted[field] for field in GATES},
            }
        )

    records.extend(counted_rows)

    kinds = Counter(row["record_kind"] for row in records)
    assert kinds["PRESERVED_HYPOTHESIS"] == 211
    assert kinds["PRESERVED_PUBLIC_CASE"] == 212
    assert kinds["APPEND_IDENTITY"] == 3
    assert kinds["STRICT_RELEASED_CASE"] == STRICT_COUNT
    assert kinds["PACKET_AUTHORITY"] == len(PACKET_AUTHORITY)
    assert sum(row.get("counted") is True for row in records) == STRICT_COUNT
    assert not any(row["case_id"] == EXCLUDE_NARROW for row in counted_rows)
    assert not any(row["case_id"] == EXCLUDE_F38V for row in counted_rows)
    assert not any(row["case_id"] == EXCLUDE_4FXP for row in counted_rows)
    assert set(B3_KEEP) <= {row["case_id"] for row in counted_rows}

    ledger_text = "".join(compact_json(row) + "\n" for row in records)
    assert not HAN.search(ledger_text)

    counted_ids = [row["case_id"] for row in counted_rows]
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical71-hold",
        "canonical_strict_count": STRICT_COUNT,
        "checkpoint": {
            "uncorrected_count_not_terminal": UNCORRECTED_COUNT_73,
            "corrected_strict_count": STRICT_COUNT,
            "corrected_baseline": 47,
            "fp211_released_admitted_raw": 48,
            "added_b3": list(B3_KEEP),
            "downgraded": [EXCLUDE_4FXP],
            "narrow_noncounting": [EXCLUDE_F38V, EXCLUDE_4FXP, EXCLUDE_NARROW],
            "directory_name": "orchestrator-260813-ghsa200-canonical71",
            "note": "Directory name remains canonical71. Semantic target is canonical strict count 72. The 73 figure is not terminal: final-review NARROW uncounts GHSA-4FXP-2M36-QV64 from the old fp211 released-admitted baseline.",
        },
        "counting_unit": "first-party GHSA case",
        "language": "en",
        "causal_admission": False,
        "integration_ready": False,
        "publication_ready": False,
        "public_200_claim_supported": False,
        "claim_boundary": "HOLD snapshot of canonical strict count 72 leader-accepted strict released first-party GHSA identities. Source conservation remains 211 hypotheses and 212 GHSA cases. This does not support a more-than-200 claim. The 73 figure is not terminal. Publication and integration stay closed.",
        "conservation": {
            "fp211_hypotheses": 211,
            "fp211_source_ghsa_cases": 212,
            "cve_aliases_counted": False,
            "upgrades_append": False,
            "new_identities_append": True,
            "append_identities": [row["case_id"] for row in append_src],
        },
        "counts": {
            "strict_released_first_party_ghsa": STRICT_COUNT,
            "corrected_baseline_47": 47,
            "fp211_released_admitted_raw": 48,
            "netnew22_keep": 21,
            "actual_gogs_keep": 2,
            "b3_keep": 2,
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
            "discovery_tabs": "not included",
            "worker_only_PASS": "not included",
        },
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
            "current": {},
            "overlap_check": {k: v for k, v in pins.items() if v["role"] == "overlap_check"},
        },
        "ledger_sha256": sha256_bytes(ledger_text.encode()),
    }
    report = "\n".join(
        [
            "# Canonical71 HOLD snapshot",
            "",
            "Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 72 first-party GHSA identities. The owned directory name remains canonical71. The 73 figure is not terminal: final-review NARROW uncounts GHSA-4FXP-2M36-QV64 from the old fp211 released-admitted baseline. Integration_ready is false. Publication_ready is false. Causal admission is false. This packet does not support a more-than-200 claim.",
            "",
            "Composition: corrected baseline 47 (fp211 released-admitted 48 minus GHSA-4FXP-2M36-QV64), plus terminal netnew22 red-team KEEP 21 (GHSA-7C3W-FXGH-FRC7 NARROW excluded), plus independent Actual/Gogs red-team KEEP 2, plus terminal B3 red-team KEEP 2. GHSA-F38V-77QJ-H4JQ is B3 NARROW and is not counted. Count is by first-party GHSA identity once. CVE aliases are stored and never counted.",
            "",
            "Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer, including dual ordinal-200 identities GHSA-3J8Q-FWPJ-F8J5 and GHSA-JJCJ-H3CM-P7X7. Same-id upgrades rewrite overlay fields and do not append. Only GHSA-6P9M-Q3JP-47H4, GHSA-G39V-CVJH-8FPF, and GHSA-PF93-J98V-25PV are absent from the 212 and append.",
            "",
            "Authority is the named PACKET_AUTHORITY table. Glob order is not authority. Discovery tabs and worker-only PASS are not loaded. GHSA-7C3W-FXGH-FRC7 cannot be KEEP. GHSA-F38V-77QJ-H4JQ cannot be KEEP. GHSA-4FXP-2M36-QV64 cannot be KEEP: final-candidate review NARROW on identity_gate supersedes the old fp211 released-admitted flag because the repo advisory is 404 and the global GHSA has empty vulnerabilities and no repository object. Filebrowser ordinal 165 remains FALSE_POSITIVE and ordinal 166 remains CONFIRM; shared SHAs do not merge identities.",
            "",
            "Every counted row has all seven contract gates equal to the string PASS. Null and NA fail closed. Candidate, carrier, and minimum-fix sets are sorted unique 40-hex SHAs. Cartesian candidate times fix pairs are not invented. Git replay of the 25 KEEP upgrade/append rows is fail-fast with empty stderr on success.",
            "",
            "Status HOLD until leader review.",
            "",
        ]
    )
    assert not HAN.search(report)

    manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "overlay_name": "canonical71-hold",
        "canonical_strict_count": STRICT_COUNT,
        "checkpoint": summary["checkpoint"],
        "counting_unit": "first-party GHSA case",
        "integration_ready": False,
        "publication_ready": False,
        "causal_admission": False,
        "public_200_claim_supported": False,
        "packet_authority": PACKET_AUTHORITY,
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
        print("PASS: canonical71 artifacts are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json manifest.json report.md")


if __name__ == "__main__":
    main()
