#!/usr/bin/env python3
"""Read-only proposal-gap census vs canonical84. Writes only this directory."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OUT = ROOT / "autoresearch/herdr-260814-ghsa200-current-proposal-gap-grok46-low"
OWN = OUT.resolve()
LEDGER = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl"
NEG_CONTROLS = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical84/negative_controls.json"

GHSA_RE = re.compile(r"\bGHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\b", re.I)

POSITIVE = {
    "PASS",
    "ACCEPT",
    "KEEP",
    "PROPOSED_PASS",
    "PROPOSED-PASS",
    "PROPOSED PASS",
    "COUNTABLE_PASS",
    "WORKER_PASS",
    "REDTEAM_KEEP",
    "REDTEAM_KEEP_PROPOSAL",
    "KEEP_PROPOSAL",
}

NEGATIVE = {
    "NARROW",
    "UNKNOWN",
    "REJECT",
    "BLOCKED",
    "FAIL",
    "FALSE_POSITIVE",
    "FALSE-POSITIVE",
    "ROUTE",
    "HOLD",
    "UNREVIEWED",
    "PARTIAL",
    "NOT_APPLICABLE",
    "NA",
    "N/A",
    "ABSENT",
    "SKIP",
    "SKIPPED",
    "NO",
    "NONE",
    "NOT_SELECTED",
    "TERMINAL_REJECT",
}

VERDICT_KEYS = (
    "worker_verdict",
    "final_verdict",
    "verdict",
    "disposition",
    "worker_disposition",
    "row_verdict",
    "proposal_verdict",
    "acceptance",
    "review_verdict",
    "redteam_verdict",
)

ENVELOPE_KINDS = {
    "SOURCE_ENVELOPE",
    "SOURCE_DECLARED",
    "ROUTE_CONTROL",
    "ROUTING_SIGNAL",
    "KEYWORD_HIT",
}

SKIP_DIR_PARTS = {
    "node_modules",
    ".git",
    "snapshot",
    "work",
    "pages",
    "clones",
    "clone",
    "cache",
    "raw_cache",
    "tmp",
}

SKIP_PACKET_NEEDLES = (
    "proposal-census",
    "current-proposal-gap",
)

RESULT_ID_LIST_KEYS = (
    "pass_proposals",
    "proposed_pass_ids",
    "PASS_proposals",
    "accepted_net_new_candidates",
    "accepted_baseline_revalidations",
    "countable_first_party_ghsa_ids",
    "keep_ids",
    "keep_proposals",
    "keep_cases",
    "accepted_ids",
    "accept_ids",
    "pass_ids",
    "keep_first_party_ghsa_ids",
)

TERMINAL_STATUSES = {
    "COMPLETE",
    "TERMINAL",
    "COMPLETE_BOUNDED_REVIEW",
    "REDTEAM_COMPLETE",
    "REDTEAM_TERMINAL",
    "REVIEW_COMPLETE",
    "COMPLETE_THIRD_REVIEW",
    "PARTIAL_TERMINAL",
    "TERMINAL_REJECT",
    "CENSUS_COMPLETE",
    "FINAL",
}

NONPOSITIVE_DOWNGRADE = {
    "NARROW",
    "REJECT",
    "BLOCKED",
    "UNKNOWN",
    "FAIL",
    "FALSE_POSITIVE",
    "TERMINAL_REJECT",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def jsonl(path: Path) -> list:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def norm_ghsa(value: str) -> str:
    return value.strip().upper()


def extract_ghsa(value) -> str | None:
    if isinstance(value, str):
        m = GHSA_RE.search(value)
        if m:
            return norm_ghsa(m.group(0))
    return None


def first_ghsa_from_obj(obj: dict) -> str | None:
    for key in ("case_id", "ghsa_id", "ghsa", "id", "primary_id", "advisory_id"):
        if key in obj:
            g = extract_ghsa(obj.get(key))
            if g:
                return g
    aliases = obj.get("aliases") or obj.get("public_ids") or obj.get("public_ids_keep") or []
    if isinstance(aliases, list):
        for item in aliases:
            g = extract_ghsa(item)
            if g:
                return g
    return None


def as_upper(value) -> str | None:
    if isinstance(value, str):
        return value.strip().upper().replace(" ", "_")
    return None


def sha_list(value) -> list[str]:
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return [value.lower()]
    if not isinstance(value, list):
        return []
    out = []
    seen = set()
    for item in value:
        if isinstance(item, str) and re.fullmatch(r"[0-9a-fA-F]{40}", item):
            s = item.lower()
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out


def row_verdict(obj: dict) -> tuple[str | None, str | None]:
    for key in VERDICT_KEYS:
        if key not in obj:
            continue
        raw = obj[key]
        if raw is None or isinstance(raw, dict):
            continue
        text = as_upper(str(raw))
        if not text:
            continue
        if "PROPOSED_PASS" in text:
            return "PROPOSED_PASS", key
        if text in POSITIVE or text in NEGATIVE:
            return text, key
        if text.startswith("KEEP"):
            return "KEEP", key
        if text.startswith("ACCEPT"):
            return "ACCEPT", key
        if text.startswith("PASS"):
            return "PASS", key
        if "REDTEAM_KEEP" in text:
            return "KEEP", key
    return None, None


def is_positive(verdict: str | None) -> bool:
    return verdict in POSITIVE or verdict in {"PASS", "ACCEPT", "KEEP", "PROPOSED_PASS"}


def is_envelope(obj: dict) -> bool:
    kind = str(obj.get("record_kind") or obj.get("row_kind") or obj.get("kind") or "").upper()
    if kind in ENVELOPE_KINDS:
        return True
    if obj.get("source_envelopes_are_input_only"):
        return True
    if str(obj.get("source_layer") or "") == "SOURCE_ENVELOPE":
        return True
    pop = str(obj.get("population") or "")
    if pop in {"routed_candidate_pool", "keyword_hits", "route_keyword_hits"}:
        return True
    if obj.get("keyword_is_not_proof") and obj.get("routing_disposition") == "ROUTE" and not any(
        k in obj for k in VERDICT_KEYS
    ):
        return True
    if obj.get("inventory_role") in {"assignment_coverage", "routing", "identity_routing"}:
        return True
    note = str(obj.get("note") or "")
    if "Inventory routing only" in note or "not a seven-gate PASS" in note:
        return True
    if str(obj.get("row_kind") or "") in {"identity_routing", "ROUTING_SIGNAL"}:
        return True
    if str(obj.get("status") or "").upper() == "ROUTE":
        return True
    return False


def is_routing_only(obj: dict) -> bool:
    if obj.get("keyword_is_not_proof") and not is_positive(row_verdict(obj)[0]):
        return True
    basis = str(obj.get("evidence_basis") or "").lower()
    if "routing" in basis and row_verdict(obj)[0] is None:
        return True
    return False


def skip_packet_dir(d: Path) -> bool:
    name = d.name.lower()
    if d.resolve() == OWN:
        return True
    return any(n in name for n in SKIP_PACKET_NEEDLES)


def list_scan_files() -> list[Path]:
    base = ROOT / "autoresearch"
    files = []
    for d in sorted(base.glob("herdr-*-ghsa200-*")):
        if not d.is_dir() or skip_packet_dir(d):
            continue
        for p in sorted(d.rglob("*")):
            if not p.is_file():
                continue
            if any(part in SKIP_DIR_PARTS for part in p.parts):
                continue
            name = p.name
            if name in {"result.json", "cases.jsonl", "case.json"}:
                files.append(p)
            elif name.startswith("selected") and name.endswith(".jsonl"):
                files.append(p)
            elif "adjudication" in name and name.endswith(".jsonl"):
                files.append(p)
    seen = set()
    out = []
    for p in files:
        rp = p.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        out.append(p)
    return sorted(out, key=lambda x: str(x))


def packet_of(path: Path) -> str:
    rel = path.relative_to(ROOT / "autoresearch")
    return str(Path("autoresearch") / rel.parts[0])


def parse_when(value) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def review_role(packet: str, ledger_role: str | None = None) -> str:
    if ledger_role == "negative_control":
        return "negative_control"
    n = packet.lower()
    if "final-candidate-review" in n:
        return "final_review"
    if "narrow-recovery" in n or "increm-patchdelta" in n or "third-review" in n or "baseline-increm" in n:
        return "independent_gate_closing_review"
    if "unified-verifier" in n:
        return "independent_gate_closing_review"
    if "counterredteam" in n:
        return "negative_control"
    if "hostile-redteam" in n:
        return "hostile_redteam"
    if "redteam" in n or "red-upgrade" in n:
        return "redteam"
    if "redbase" in n:
        return "redteam"
    if any(
        x in n
        for x in (
            "gap",
            "freshness",
            "current-delta",
            "cross-dedupe",
            "tail11",
            "proposal-census",
            "canonical-sourcetier",
        )
    ):
        return "inventory"
    if n.endswith("remediation") or n.endswith("/herdr-260813-ghsa200-remediation"):
        return "inventory"
    return "worker"


def role_rank(role: str) -> int:
    return {
        "inventory": 1,
        "worker": 2,
        "redteam": 4,
        "independent_gate_closing_review": 5,
        "final_review": 6,
        "hostile_redteam": 8,
        "negative_control": 10,
        "canonical_negative_control": 12,
    }.get(role, 2)


def authority_score(meta: dict) -> int:
    role = meta.get("role") or review_role(meta.get("packet") or "")
    base = role_rank(role) * 1000
    rank = meta.get("authority_rank")
    if isinstance(rank, int):
        base += rank
    return base


def load_packet_meta(packet: str, packet_dir: Path) -> dict:
    result = packet_dir / "result.json"
    meta = {
        "packet": packet,
        "status": "NO_RESULT_JSON",
        "when": None,
        "when_raw": None,
        "hold": False,
        "role": review_role(packet),
        "authority_rank": None,
        "ledger_terminal": None,
    }
    if not result.is_file():
        meta["terminal"] = is_terminal_packet(meta)
        return meta
    try:
        obj = json.loads(result.read_text(encoding="utf-8"))
    except Exception:
        meta["status"] = "RESULT_PARSE_FAIL"
        meta["terminal"] = False
        return meta
    if not isinstance(obj, dict):
        meta["status"] = "RESULT_NOT_OBJECT"
        meta["terminal"] = False
        return meta
    status = "STATUS_ABSENT"
    for key in ("status", "terminal_status", "worker_status"):
        if key in obj and obj[key]:
            status = str(obj[key])
            break
    meta["status"] = status
    meta["hold"] = bool(obj.get("hold"))
    when_raw = obj.get("ended_at") or obj.get("frozen_at_utc") or obj.get("completed_at")
    meta["when_raw"] = when_raw
    meta["when"] = parse_when(when_raw)
    meta["terminal"] = is_terminal_packet(meta)
    return meta


def is_terminal_packet(meta: dict) -> bool:
    if meta.get("hold") is True and "PARTIAL" in str(meta.get("status") or "").upper():
        return False
    status = str(meta.get("status") or "").upper()
    if status in {
        "PARTIAL",
        "HOLD",
        "IN_PROGRESS",
        "ACTIVE",
        "STATUS_ABSENT",
        "NO_RESULT_JSON",
        "RESULT_PARSE_FAIL",
        "RESULT_NOT_OBJECT",
        "CENSUS_IN_FLIGHT_HOLD",
    }:
        return False
    if meta.get("ledger_terminal") is True:
        return True
    return status in TERMINAL_STATUSES


def later_redteam_or_review_downgrade(pass_meta: dict, neg_meta: dict, neg_verdict: str) -> bool:
    r_neg = neg_meta.get("role") or review_role(neg_meta.get("packet") or "")
    if not is_terminal_packet(neg_meta) and r_neg not in {
        "negative_control",
        "canonical_negative_control",
        "hostile_redteam",
    }:
        return False
    if neg_verdict not in NONPOSITIVE_DOWNGRADE:
        return False
    r_pass = pass_meta.get("role") or review_role(pass_meta.get("packet") or "")
    if r_neg == "inventory":
        return False
    if r_pass == "independent_gate_closing_review" and r_neg in {"worker", "inventory"}:
        return False
    if r_neg in {"canonical_negative_control", "negative_control", "hostile_redteam"}:
        return authority_score(neg_meta) >= authority_score(pass_meta)
    if r_neg not in {"redteam", "independent_gate_closing_review", "final_review"}:
        return False
    t_pass = pass_meta.get("when")
    t_neg = neg_meta.get("when")
    if t_pass and t_neg:
        if t_neg <= t_pass:
            return False
        return True
    if authority_score(neg_meta) > authority_score(pass_meta):
        return True
    if r_pass in {"worker", "inventory"} and r_neg in {"redteam", "independent_gate_closing_review", "final_review"}:
        return True
    return False


def gate_map(obj: dict) -> dict:
    g = obj.get("gates")
    if isinstance(g, dict):
        return {k: as_upper(str(v)) if v is not None else None for k, v in g.items()}
    out = {}
    for k in (
        "identity_gate",
        "ai_hunk_gate",
        "topology_gate",
        "but_for_gate",
        "fix_reversal_gate",
        "release_gate",
        "uniqueness_gate",
        "remediation_patch_delta_gate",
    ):
        if k in obj:
            out[k] = as_upper(str(obj[k]))
    return out


def seven_all_pass(gates: dict) -> bool:
    needed = [
        "identity_gate",
        "ai_hunk_gate",
        "topology_gate",
        "but_for_gate",
        "fix_reversal_gate",
        "release_gate",
        "uniqueness_gate",
    ]
    return all(gates.get(k) == "PASS" for k in needed)


def load_canonical84() -> tuple[set[str], dict[str, dict], dict[str, dict], dict[str, list]]:
    counted = {}
    packet_auth = {}
    edges = defaultdict(list)
    aliases_to_counted = {}
    for row in jsonl(LEDGER):
        if not isinstance(row, dict):
            continue
        kind = row.get("record_kind")
        if kind == "PACKET_AUTHORITY":
            pkt = row.get("packet")
            if pkt:
                packet_auth[pkt] = row
        elif kind == "SUPERSEDES_EDGE":
            cid = extract_ghsa(row.get("case_id") or "")
            if cid:
                edges[cid].append(row)
        elif kind == "STRICT_RELEASED_CASE" and row.get("counted") is True:
            cid = extract_ghsa(row.get("case_id") or "")
            if cid:
                counted[cid] = row
                for a in row.get("aliases") or []:
                    g = extract_ghsa(a)
                    if g:
                        aliases_to_counted[g] = cid
    return set(counted), counted, packet_auth, edges


HASH_KEY_FILES = {
    "cases_jsonl": "cases.jsonl",
    "result_json": "result.json",
    "report_md": "report.md",
    "case_json": "case.json",
}


def load_negative_controls() -> tuple[dict[str, dict], list[dict], list[dict]]:
    """Load every canonical84 negative-control row. IDs are data, not code constants."""
    assert NEG_CONTROLS.is_file(), "canonical84 negative_controls.json missing"
    obj = json.loads(NEG_CONTROLS.read_text(encoding="utf-8"))
    by_id: dict[str, dict] = {}
    hash_notes = []
    for ctrl in obj.get("controls") or []:
        if not isinstance(ctrl, dict):
            continue
        v = as_upper(str(ctrl.get("verdict") or ""))
        if v not in NONPOSITIVE_DOWNGRADE:
            continue
        cid = extract_ghsa(ctrl.get("case_id") or "")
        if not cid:
            continue
        by_id[cid] = ctrl
        for a in ctrl.get("aliases") or []:
            g = extract_ghsa(a)
            if g:
                by_id[g] = ctrl
        src = ctrl.get("source_hashes") or {}
        pkt = src.get("packet")
        if pkt:
            pdir = ROOT / pkt
            for key, fname in HASH_KEY_FILES.items():
                exp = src.get(key)
                if not exp:
                    continue
                fpath = pdir / fname
                if not fpath.is_file():
                    hash_notes.append({"kind": "NEG_CONTROL_SOURCE_MISSING", "path": str(fpath.relative_to(ROOT)), "case_id": cid})
                    continue
                got = sha256_path(fpath)
                if got != exp:
                    hash_notes.append(
                        {
                            "kind": "NEG_CONTROL_HASH_MISMATCH",
                            "path": str(fpath.relative_to(ROOT)),
                            "case_id": cid,
                            "expected": exp,
                            "actual": got,
                        }
                    )
    return by_id, obj.get("controls") or [], hash_notes


def hit_from_row(row: dict, *, rel: str, packet: str, kind: str, lineno: int | None, v: str, vk: str | None) -> dict:
    return {
        "case_id": first_ghsa_from_obj(row),
        "source_path": rel,
        "packet": packet,
        "source_kind": kind,
        "source_line": lineno,
        "verdict": v,
        "verdict_key": vk,
        "repository": row.get("repository"),
        "mechanism_key": row.get("mechanism_key"),
        "candidate_set": sha_list(row.get("candidate_set") or row.get("counted_candidate")),
        "carrier_set": sha_list(row.get("carrier_set")),
        "minimum_fix_set": sha_list(row.get("minimum_fix_set") or row.get("minimum_fix")),
        "gates": gate_map(row),
        "contribution_class": row.get("contribution_class") or row.get("causal_class"),
        "scope_statement": row.get("scope_statement") or row.get("note"),
        "row_kind": row.get("row_kind") or kind,
        "release_status": (gate_map(row) or {}).get("release_gate"),
    }


def ingest_jsonl_row(
    row: dict,
    *,
    rel: str,
    packet: str,
    kind: str,
    lineno: int,
    positive_hits: list,
    later_nonpositive: dict,
    skipped: Counter,
    failures: list,
) -> None:
    if not isinstance(row, dict):
        failures.append({"kind": "SCHEMA", "path": rel, "line": lineno, "reason": "non-object"})
        return
    if is_envelope(row):
        skipped["source_envelope"] += 1
        return
    if is_routing_only(row):
        skipped["routing_signal"] += 1
        return
    v, vk = row_verdict(row)
    g = first_ghsa_from_obj(row)
    if v is None:
        skipped["no_verdict"] += 1
        return
    if not is_positive(v):
        skipped["nonpositive"] += 1
        if g:
            later_nonpositive[g].append(
                {"packet": packet, "source_path": rel, "verdict": v, "line": lineno, "source_kind": kind}
            )
        return
    if not g:
        skipped["positive_without_ghsa"] += 1
        failures.append(
            {
                "kind": "SCHEMA",
                "path": rel,
                "line": lineno,
                "reason": "positive verdict without GHSA case_id",
                "verdict": v,
            }
        )
        return
    primary = row.get("primary_id") or row.get("case_id")
    if isinstance(primary, str) and primary.upper().startswith("CVE-") and not extract_ghsa(primary):
        skipped["cve_alias_primary"] += 1
        return
    h = hit_from_row(row, rel=rel, packet=packet, kind=kind, lineno=lineno, v=v, vk=vk)
    h["case_id"] = g
    positive_hits.append(h)


def ingest_result_obj(
    obj: dict,
    *,
    rel: str,
    packet: str,
    positive_hits: list,
    later_nonpositive: dict,
    skipped: Counter,
    failures: list,
) -> None:
    for key in RESULT_ID_LIST_KEYS:
        val = obj.get(key)
        if val is None:
            continue
        items = val if isinstance(val, list) else []
        for item in items:
            if isinstance(item, str):
                g = extract_ghsa(item)
                if not g:
                    skipped["result_id_not_ghsa"] += 1
                    continue
                positive_hits.append(
                    {
                        "case_id": g,
                        "source_path": rel,
                        "packet": packet,
                        "source_kind": "result.json:" + key,
                        "source_line": None,
                        "verdict": "KEEP" if "keep" in key.lower() else "PROPOSED_PASS",
                        "verdict_key": key,
                        "repository": None,
                        "mechanism_key": None,
                        "candidate_set": [],
                        "carrier_set": [],
                        "minimum_fix_set": [],
                        "gates": {},
                        "contribution_class": None,
                        "scope_statement": None,
                        "row_kind": "RESULT_LIST",
                        "release_status": None,
                    }
                )
            elif isinstance(item, dict):
                if is_envelope(item):
                    skipped["source_envelope"] += 1
                    continue
                g = first_ghsa_from_obj(item)
                if not g:
                    skipped["result_dict_no_ghsa"] += 1
                    continue
                v, vk = row_verdict(item)
                if v is None:
                    v, vk = "PROPOSED_PASS", key
                if not is_positive(v):
                    skipped["result_dict_nonpositive"] += 1
                    continue
                h = hit_from_row(item, rel=rel, packet=packet, kind="result.json:" + key, lineno=None, v=v, vk=vk)
                h["case_id"] = g
                positive_hits.append(h)
            else:
                skipped["result_list_non_id"] += 1
    per = obj.get("per_case")
    if isinstance(per, dict):
        for cid, raw in per.items():
            g = extract_ghsa(cid)
            v = as_upper(str(raw)) if raw is not None else None
            if not g or not v:
                continue
            if is_positive(v) or v.startswith("KEEP") or v.startswith("PASS") or v.startswith("ACCEPT"):
                nv = "KEEP" if v.startswith("KEEP") else ("PASS" if v.startswith("PASS") else ("ACCEPT" if v.startswith("ACCEPT") else v))
                if is_positive(nv):
                    positive_hits.append(
                        {
                            "case_id": g,
                            "source_path": rel,
                            "packet": packet,
                            "source_kind": "result.json:per_case",
                            "source_line": None,
                            "verdict": nv,
                            "verdict_key": "per_case",
                            "repository": None,
                            "mechanism_key": None,
                            "candidate_set": [],
                            "carrier_set": [],
                            "minimum_fix_set": [],
                            "gates": {},
                            "contribution_class": None,
                            "scope_statement": None,
                            "row_kind": "RESULT_PER_CASE",
                            "release_status": None,
                        }
                    )
            elif v in NONPOSITIVE_DOWNGRADE or v.startswith("NARROW") or v.startswith("REJECT"):
                later_nonpositive[g].append(
                    {
                        "packet": packet,
                        "source_path": rel,
                        "verdict": "REJECT" if v.startswith("REJECT") else ("NARROW" if v.startswith("NARROW") else v),
                        "line": None,
                        "source_kind": "result.json:per_case",
                    }
                )
    for key in ("reject_cases", "narrow_cases"):
        val = obj.get(key)
        if not isinstance(val, list):
            continue
        forced = "REJECT" if key.startswith("reject") else "NARROW"
        for item in val:
            if isinstance(item, str):
                g = extract_ghsa(item)
                row = {}
            elif isinstance(item, dict):
                g = first_ghsa_from_obj(item)
                row = item
            else:
                continue
            if not g:
                continue
            v, _vk = row_verdict(row) if row else (forced, key)
            if v is None:
                v = forced
            if v in NONPOSITIVE_DOWNGRADE or v.startswith("REJECT") or v.startswith("NARROW"):
                later_nonpositive[g].append(
                    {
                        "packet": packet,
                        "source_path": rel,
                        "verdict": as_upper(v) or forced,
                        "line": None,
                        "source_kind": "result.json:" + key,
                    }
                )
    counts = obj.get("counts") or obj.get("case_verdicts") or obj.get("verdicts") or {}
    if isinstance(counts, dict):
        npass = 0
        for k in ("PASS", "ACCEPT", "KEEP"):
            if isinstance(counts.get(k), int):
                npass += counts[k]
        if npass and not any(h["source_path"] == rel for h in positive_hits):
            skipped["count_without_row_ids"] += 1
            failures.append(
                {
                    "kind": "SCHEMA_NOTE",
                    "path": rel,
                    "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists",
                    "count": npass,
                }
            )


def classify(
    *,
    cid: str,
    in_canonical: bool,
    alias_of: str | None,
    sources: list[dict],
    superseding: list[dict],
    ledger_edges: list,
    negative_control: dict | None,
) -> tuple[str, str]:
    if in_canonical:
        return "ALREADY_CANONICAL", "Identity is a counted STRICT_RELEASED_CASE in canonical84."
    if alias_of:
        return "DUPLICATE_ALIAS", f"Identity aliases counted canonical84 row {alias_of}."
    if negative_control:
        src = (negative_control.get("source_hashes") or {}).get("packet") or "canonical84/negative_controls.json"
        return (
            "SUPERSEDED_DOWNGRADED",
            "canonical84 negative-control authority REJECT supersedes an earlier PASS/KEEP/ACCEPT "
            f"({src}:{negative_control.get('verdict')}). An AI-marked squash carrier cannot transfer authorship "
            "to a human member when that is the recorded fatal rule, and other recorded REJECT rules likewise bind.",
        )
    if any("/snapshot/" in (s.get("source_path") or "") for s in sources):
        return "DUPLICATE_SNAPSHOT", "Row is a snapshot copy, not an independent proposal."
    if not any(s.get("case_id") for s in sources):
        return "NONTERMINAL_INVALID_SCHEMA", "Positive label without a first-party GHSA case_id row."
    if superseding:
        bits = sorted({f"{x['packet']}:{x['verdict']}" for x in superseding})
        return (
            "SUPERSEDED_DOWNGRADED",
            "Later terminal hostile/counter red-team or independent-review downgrade supersedes an earlier PASS/KEEP/ACCEPT ("
            + "; ".join(bits)
            + ").",
        )
    edge_down = [
        e
        for e in ledger_edges
        if e.get("applies_now") is True and as_upper(str(e.get("to_verdict") or "")) in NONPOSITIVE_DOWNGRADE
    ]
    if edge_down:
        bits = sorted({f"{e.get('to_packet')}:{e.get('to_verdict')}" for e in edge_down})
        return (
            "SUPERSEDED_DOWNGRADED",
            "canonical84 SUPERSEDES_EDGE records a later nonpositive override (" + "; ".join(bits) + ").",
        )
    if any(seven_all_pass(s.get("gates") or {}) for s in sources) or any(
        s.get("verdict") in {"PASS", "KEEP", "ACCEPT", "PROPOSED_PASS"} for s in sources
    ):
        # genuine only if some source is terminal worker/redteam/review with explicit positive
        return (
            "GENUINE_UNRESOLVED_PROPOSAL",
            "Terminal worker PASS/KEEP/ACCEPT first-party GHSA proposal absent from canonical84 counted set; no later terminal red-team supersession found. Census only; not admission.",
        )
    return "NONTERMINAL_INVALID_SCHEMA", "Positive-looking row lacks a usable structured proposal."


def main() -> int:
    failures: list[dict] = []
    assert LEDGER.is_file(), "canonical84 ledger missing"
    canonical_ids, counted_rows, packet_auth, ledger_edges = load_canonical84()
    neg_by_id, neg_controls, neg_hash_notes = load_negative_controls()
    failures.extend(neg_hash_notes)
    if len(canonical_ids) != 84:
        failures.append({"kind": "COUNT", "what": "canonical84_counted", "expected": 84, "actual": len(canonical_ids)})

    scan_files = list_scan_files()
    file_hashes = []
    scanned_result = 0
    scanned_cases = 0
    scanned_selected = 0
    scanned_adj = 0
    case_lines_total = 0
    case_lines_parsed = 0
    selected_lines_total = 0
    selected_lines_parsed = 0
    adj_lines_total = 0
    adj_lines_parsed = 0
    positive_hits: list[dict] = []
    skipped = Counter()
    packet_meta: dict[str, dict] = {}
    packets_seen: set[str] = set()
    later_nonpositive: dict[str, list[dict]] = defaultdict(list)

    for path in scan_files:
        rel = str(path.relative_to(ROOT))
        packet = packet_of(path)
        packets_seen.add(packet)
        if packet not in packet_meta:
            meta = load_packet_meta(packet, ROOT / packet)
            auth = packet_auth.get(packet)
            if auth:
                meta["authority_rank"] = auth.get("authority_rank")
                meta["ledger_terminal"] = auth.get("terminal")
                meta["role"] = review_role(packet, auth.get("role"))
                meta["terminal"] = is_terminal_packet(meta) or bool(auth.get("terminal"))
            packet_meta[packet] = meta
        try:
            raw = path.read_bytes()
        except Exception as e:
            failures.append({"kind": "READ", "path": rel, "error": type(e).__name__})
            continue
        file_hashes.append({"path": rel, "sha256": sha256_bytes(raw), "bytes": len(raw)})
        name = path.name
        if name == "result.json":
            scanned_result += 1
            try:
                obj = json.loads(raw.decode("utf-8"))
            except Exception as e:
                failures.append({"kind": "PARSE", "path": rel, "error": type(e).__name__})
                continue
            if not isinstance(obj, dict):
                failures.append({"kind": "SCHEMA", "path": rel, "reason": "result.json is not an object"})
                continue
            ingest_result_obj(
                obj,
                rel=rel,
                packet=packet,
                positive_hits=positive_hits,
                later_nonpositive=later_nonpositive,
                skipped=skipped,
                failures=failures,
            )
        elif name == "case.json":
            scanned_cases += 1
            try:
                row = json.loads(raw.decode("utf-8"))
            except Exception as e:
                failures.append({"kind": "PARSE", "path": rel, "error": type(e).__name__})
                continue
            case_lines_total += 1
            case_lines_parsed += 1
            ingest_jsonl_row(
                row,
                rel=rel,
                packet=packet,
                kind="case.json",
                lineno=1,
                positive_hits=positive_hits,
                later_nonpositive=later_nonpositive,
                skipped=skipped,
                failures=failures,
            )
        else:
            text = raw.decode("utf-8")
            is_cases = name == "cases.jsonl"
            is_sel = name.startswith("selected")
            is_adj = "adjudication" in name
            if is_cases:
                scanned_cases += 1
            elif is_sel:
                scanned_selected += 1
            elif is_adj:
                scanned_adj += 1
            kind = "cases.jsonl" if is_cases else ("selected.jsonl" if is_sel else "adjudication.jsonl")
            for lineno, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                if is_cases:
                    case_lines_total += 1
                elif is_sel:
                    selected_lines_total += 1
                else:
                    adj_lines_total += 1
                try:
                    row = json.loads(line)
                except Exception as e:
                    failures.append({"kind": "PARSE", "path": rel, "line": lineno, "error": type(e).__name__})
                    continue
                if is_cases:
                    case_lines_parsed += 1
                elif is_sel:
                    selected_lines_parsed += 1
                else:
                    adj_lines_parsed += 1
                ingest_jsonl_row(
                    row,
                    rel=rel,
                    packet=packet,
                    kind=kind,
                    lineno=lineno,
                    positive_hits=positive_hits,
                    later_nonpositive=later_nonpositive,
                    skipped=skipped,
                    failures=failures,
                )

    # Apply ledger packet terminal flags for packets we saw
    for packet, auth in packet_auth.items():
        if packet in packet_meta:
            packet_meta[packet]["authority_rank"] = auth.get("authority_rank")
            packet_meta[packet]["ledger_terminal"] = auth.get("terminal")
            packet_meta[packet]["role"] = review_role(packet, auth.get("role"))
            packet_meta[packet]["terminal"] = is_terminal_packet(packet_meta[packet]) or bool(auth.get("terminal"))

    canon_neg_packet = "autoresearch/orchestrator-260814-ghsa200-canonical84"
    packet_meta[canon_neg_packet] = {
        "packet": canon_neg_packet,
        "status": "HOLD",
        "when": None,
        "when_raw": None,
        "hold": False,
        "role": "canonical_negative_control",
        "authority_rank": 100,
        "ledger_terminal": True,
        "terminal": True,
    }
    for cid, ctrl in neg_by_id.items():
        later_nonpositive[cid].append(
            {
                "packet": canon_neg_packet,
                "source_path": str(NEG_CONTROLS.relative_to(ROOT)),
                "verdict": as_upper(str(ctrl.get("verdict") or "REJECT")),
                "line": None,
                "source_kind": "canonical84_negative_controls",
                "source_packet": (ctrl.get("source_hashes") or {}).get("packet"),
                "rule": ctrl.get("rule"),
            }
        )
        src_pkt = (ctrl.get("source_hashes") or {}).get("packet")
        if src_pkt and src_pkt in packet_meta:
            if packet_meta[src_pkt].get("role") not in {"canonical_negative_control", "negative_control"}:
                if "hostile" in src_pkt.lower():
                    packet_meta[src_pkt]["role"] = "hostile_redteam"
                else:
                    packet_meta[src_pkt]["role"] = "negative_control"

    terminal_hits = []
    inflight_hits = []
    for h in positive_hits:
        meta = packet_meta.get(h["packet"]) or load_packet_meta(h["packet"], ROOT / h["packet"])
        packet_meta[h["packet"]] = meta
        h["packet_terminal"] = bool(meta.get("terminal"))
        h["packet_role"] = meta.get("role")
        h["packet_when"] = meta.get("when_raw")
        h["authority_rank"] = meta.get("authority_rank")
        if not meta.get("terminal"):
            inflight_hits.append(h)
        else:
            terminal_hits.append(h)

    by_id: dict[str, list[dict]] = defaultdict(list)
    for h in terminal_hits:
        by_id[h["case_id"]].append(h)

    # alias map from counted rows
    alias_of: dict[str, str] = {}
    for cid, row in counted_rows.items():
        for a in row.get("aliases") or []:
            g = extract_ghsa(a)
            if g and g != cid:
                alias_of[g] = cid

    set_all = set(by_id)
    class_counts = Counter()
    class_ids: dict[str, list[str]] = defaultdict(list)
    genuine = []
    classified_rows = []

    for cid in sorted(set_all):
        sources = by_id[cid]
        cases_sources = [s for s in sources if s["source_kind"] in {"cases.jsonl", "adjudication.jsonl", "case.json"}]
        use = cases_sources or sources
        best = max(
            use,
            key=lambda s: (
                1 if seven_all_pass(s.get("gates") or {}) else 0,
                1 if s.get("mechanism_key") else 0,
                1 if s.get("candidate_set") else 0,
                role_rank(s.get("packet_role") or review_role(s["packet"])),
                s.get("packet_when") or "",
            ),
        )
        later = later_nonpositive.get(cid) or []
        superseding = []
        for x in later:
            if x["verdict"] not in NONPOSITIVE_DOWNGRADE:
                continue
            neg_meta = packet_meta.get(x["packet"])
            if not neg_meta:
                continue
            for src in use:
                pass_meta = packet_meta.get(src["packet"])
                if not pass_meta:
                    continue
                if later_redteam_or_review_downgrade(pass_meta, neg_meta, x["verdict"]):
                    superseding.append(x)
                    break
        klass, why = classify(
            cid=cid,
            in_canonical=cid in canonical_ids,
            alias_of=alias_of.get(cid),
            sources=use,
            superseding=superseding,
            ledger_edges=ledger_edges.get(cid) or [],
            negative_control=neg_by_id.get(cid),
        )
        class_counts[klass] += 1
        class_ids[klass].append(cid)
        rec = {
            "schema_version": 1,
            "row_kind": "PROPOSAL_GAP_CENSUS",
            "case_id": cid,
            "census_class": klass,
            "omission_reason": why,
            "in_canonical84": cid in canonical_ids,
            "source_packet": best.get("packet"),
            "source_path": best.get("source_path"),
            "source_line": best.get("source_line"),
            "source_kind": best.get("source_kind"),
            "best_verdict": best.get("verdict"),
            "best_verdict_key": best.get("verdict_key"),
            "repository": best.get("repository"),
            "mechanism_key": best.get("mechanism_key"),
            "contribution_class": best.get("contribution_class"),
            "candidate_set": best.get("candidate_set") or [],
            "carrier_set": best.get("carrier_set") or [],
            "minimum_fix_set": best.get("minimum_fix_set") or [],
            "gates": best.get("gates") or {},
            "seven_gates_pass": seven_all_pass(best.get("gates") or {}),
            "release_status": (best.get("gates") or {}).get("release_gate") or best.get("release_status"),
            "scope_statement": best.get("scope_statement"),
            "packets": sorted({s["packet"] for s in sources}),
            "source_paths": sorted({s["source_path"] for s in sources}),
            "source_verdicts": sorted({s["verdict"] for s in sources}),
            "source_terminal_status": sorted({str(packet_meta[s["packet"]]["status"]) for s in sources}),
            "occurrence_count": len(sources),
            "later_contrary_evidence": superseding
            + [
                {
                    "packet": e.get("to_packet"),
                    "verdict": e.get("to_verdict"),
                    "source_kind": "ledger_SUPERSEDES_EDGE",
                    "edge_id": e.get("edge_id"),
                    "note": e.get("note"),
                }
                for e in (ledger_edges.get(cid) or [])
                if e.get("applies_now") is True
                and as_upper(str(e.get("to_verdict") or "")) in NONPOSITIVE_DOWNGRADE
            ],
            "counting_unit": "first-party GHSA identity",
            "causal_admission": False,
            "worker_pass_is_proposal_only": True,
            "this_packet_does_not_claim_pass": True,
        }
        classified_rows.append(rec)
        if klass == "GENUINE_UNRESOLVED_PROPOSAL":
            genuine.append(rec)

    inflight_ids = sorted({h["case_id"] for h in inflight_hits})
    inflight_not_canonical = sorted(set(inflight_ids) - canonical_ids)

    leftover_check = set_all - set(r["case_id"] for r in classified_rows)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    genuine_ids = [r["case_id"] for r in genuine]
    neg_control_ids = sorted({extract_ghsa(c.get("case_id") or "") for c in neg_controls if extract_ghsa(c.get("case_id") or "")})
    if any(g in neg_by_id for g in genuine_ids):
        leftover_check = leftover_check | {"NEGATIVE_CONTROL_LEAK"}
    ranked_hostile = []
    for p, m in packet_meta.items():
        role = m.get("role")
        if role not in {"hostile_redteam", "negative_control", "canonical_negative_control"}:
            continue
        if p == canon_neg_packet:
            continue
        if not m.get("terminal"):
            continue
        ranked_hostile.append(
            {
                "packet": p,
                "role": role,
                "status": m.get("status"),
                "terminal": bool(m.get("terminal")),
                "authority_rank": m.get("authority_rank"),
                "authority_score": authority_score(m),
                "when": m.get("when_raw"),
            }
        )
    ranked_hostile.sort(key=lambda x: (-x["authority_score"], x["packet"]))
    status = "CENSUS_HOLD"
    if leftover_check:
        status = "CENSUS_CONSERVATION_FAIL"

    OUT.mkdir(parents=True, exist_ok=True)
    cases_path = OUT / "cases.jsonl"
    with cases_path.open("w", encoding="utf-8") as f:
        for row in genuine:
            f.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")

    ledger_hash = sha256_path(LEDGER)
    scan_counts = {
        "packets": len(packets_seen),
        "files_scanned": len(scan_files),
        "result_json_files": scanned_result,
        "cases_jsonl_files": scanned_cases,
        "selected_jsonl_files": scanned_selected,
        "adjudication_jsonl_files": scanned_adj,
        "case_lines_total": case_lines_total,
        "case_lines_parsed": case_lines_parsed,
        "selected_lines_total": selected_lines_total,
        "selected_lines_parsed": selected_lines_parsed,
        "adjudication_lines_total": adj_lines_total,
        "adjudication_lines_parsed": adj_lines_parsed,
        "jsonl_rows_total": case_lines_total + selected_lines_total + adj_lines_total,
        "jsonl_rows_parsed": case_lines_parsed + selected_lines_parsed + adj_lines_parsed,
    }

    result = {
        "schema_version": 1,
        "task": "current-proposal-gap-census",
        "lane": "herdr-260814-ghsa200-current-proposal-gap-grok46-low",
        "status": status,
        "language": "en",
        "english_only": True,
        "causal_admission": False,
        "this_packet_does_not_claim_pass": True,
        "claim_boundary": "Read-only accounting census. Worker PASS/KEEP/ACCEPT is a proposal, never admission. Does not rebuild canonical84.",
        "counting_unit": "first-party GHSA identity",
        "frozen_at_utc": now,
        "accepted_set": {
            "packet": "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl",
            "sha256": ledger_hash,
            "counted_ids": sorted(canonical_ids),
            "counted": len(canonical_ids),
            "negative_controls_path": str(NEG_CONTROLS.relative_to(ROOT)),
            "negative_controls_sha256": sha256_path(NEG_CONTROLS),
            "negative_control_reject_ids": neg_control_ids,
        },
        "hostile_negative_control_authority": {
            "ranked_terminal_packets": ranked_hostile,
            "rule": "canonical84 negative_controls.json REJECT outranks worker or recovery PASS. Terminal hostile-redteam and counterredteam packets outrank earlier PASS on the same identity. IDs come from the capsule, not from hardcoded literals.",
        },
        "scan": scan_counts,
        "conservation": {
            "terminal_positive_ghsa_ids": len(set_all),
            "positive_hit_rows": len(positive_hits),
            "canonical84": len(canonical_ids),
            "intersection_positive_and_canonical84": len(set_all & canonical_ids),
            "classified_unique_ids": len(classified_rows),
            "leftover_ids": sorted(leftover_check),
            "id_conservation": not leftover_check and len(classified_rows) == len(set_all),
            "unique_ids": len(set_all),
            "canonical_exclusion_of_genuine": all(g not in canonical_ids for g in genuine_ids),
            "negative_control_exclusion_of_genuine": all(g not in neg_by_id for g in genuine_ids),
        },
        "census_class_counts": dict(class_counts),
        "census_class_ids": {k: v for k, v in class_ids.items()},
        "genuine_unresolved_count": len(genuine),
        "genuine_unresolved_count_is_final": False,
        "genuine_unresolved_ids": genuine_ids,
        "nonterminal_positive_ids_not_in_canonical84": inflight_not_canonical,
        "nonterminal_or_forced_packets": sorted(
            p for p, m in packet_meta.items() if not m.get("terminal")
        ),
        "packet_authority": {
            p: {
                "status": m.get("status"),
                "terminal": m.get("terminal"),
                "role": m.get("role"),
                "when": m.get("when_raw"),
                "authority_rank": m.get("authority_rank"),
            }
            for p, m in sorted(packet_meta.items())
        },
        "skipped_non_proposal": dict(skipped),
        "parse_schema_failures": failures,
        "parse_schema_failure_count": len(failures),
        "did_not_edit_outside_owned_dir": True,
        "did_not_commit_or_push": True,
        "no_cached_clones_or_pages_retained": True,
    }

    # report
    lines = [
        "# Current proposal-gap census versus canonical84",
        "",
        "## Verdict first",
        "",
    ]
    if genuine:
        lines.append(
            f"**{len(genuine)} genuine unresolved first-party GHSA proposal(s)** absent from canonical84 counted identities. This is an accounting census, not causal acceptance. This packet does not claim PASS."
        )
    else:
        lines.append(
            "**Zero genuine unresolved first-party GHSA proposals** among terminal worker PASS/KEEP/ACCEPT rows after canonical84 exclusion and later red-team supersession. Census only; this packet does not claim PASS."
        )
    lines.append("")
    lines.append(
        f"`genuine_unresolved_count_is_final` is **false**. Scanned **{scan_counts['packets']}** packets, **{scan_counts['files_scanned']}** files "
        f"({scan_counts['result_json_files']} result.json, {scan_counts['cases_jsonl_files']} cases.jsonl, "
        f"{scan_counts['selected_jsonl_files']} selected JSONL, {scan_counts['adjudication_jsonl_files']} adjudication JSONL). "
        f"Parsed **{scan_counts['case_lines_parsed']}/{scan_counts['case_lines_total']}** cases.jsonl rows, "
        f"**{scan_counts['selected_lines_parsed']}/{scan_counts['selected_lines_total']}** selected rows, "
        f"**{scan_counts['adjudication_lines_parsed']}/{scan_counts['adjudication_lines_total']}** adjudication rows. "
        f"Terminal positive GHSA ids: **{len(set_all)}**. Canonical84 counted: **{len(canonical_ids)}**. "
        f"Already canonical among those positives: **{class_counts.get('ALREADY_CANONICAL', 0)}**. "
        f"ID conservation: **{result['conservation']['id_conservation']}**."
    )
    lines.append("")
    lines.append("## Accepted set")
    lines.append("")
    lines.append(
        f"canonical84 ledger `{LEDGER.relative_to(ROOT)}` sha256 `{ledger_hash}` counted **{len(canonical_ids)}** first-party GHSA identities. Negative-control capsule `{NEG_CONTROLS.relative_to(ROOT)}` sha256 `{sha256_path(NEG_CONTROLS)}` REJECT identities: {', '.join(f'`{x}`' for x in neg_control_ids) or 'none'}."
    )
    lines.append("")
    lines.append("## Hostile and counter-redteam authority")
    lines.append("")
    lines.append(
        "canonical84 negative-control REJECT outranks any earlier worker or recovery PASS on the same first-party identity. Terminal packets classified hostile-redteam or counterredteam/negative_control are ranked below by ledger authority_rank then role. An AI-marked squash carrier cannot transfer authorship to a human member."
    )
    if ranked_hostile:
        for item in ranked_hostile:
            lines.append(
                f"- score `{item['authority_score']}` rank `{item['authority_rank']}` role `{item['role']}` terminal `{item['terminal']}` `{item['packet']}` status `{item['status']}`"
            )
    else:
        lines.append("No terminal hostile or counter-redteam packets were present.")
    lines.append("")
    lines.append("## Class counts")
    lines.append("")
    for k in sorted(class_counts):
        lines.append(f"- `{k}`: {class_counts[k]}")
    if not class_counts:
        lines.append("- none")
    lines.append("")
    lines.append("## Genuine unresolved (needs leader red-team; not admission)")
    lines.append("")
    if not genuine:
        lines.append("Empty. `cases.jsonl` has zero rows.")
    else:
        for r in genuine:
            lines.append(
                f"- `{r['case_id']}` packet `{r['source_packet']}` row `{r.get('source_line')}` verdict `{r['best_verdict']}` "
                f"candidate `{r.get('candidate_set')}` carrier `{r.get('carrier_set')}` fix `{r.get('minimum_fix_set')}` "
                f"release `{r.get('release_status')}` — {r['omission_reason']}"
            )
    lines.append("")
    lines.append("## Later superseded or downgraded")
    lines.append("")
    supers = [r for r in classified_rows if r["census_class"] == "SUPERSEDED_DOWNGRADED"]
    if not supers:
        lines.append("None among terminal positives absent-or-present after classification.")
    else:
        for r in supers:
            lines.append(f"- `{r['case_id']}` `{r['source_packet']}` `{r['best_verdict']}` — {r['omission_reason']}")
    lines.append("")
    lines.append("## Duplicate or alias")
    lines.append("")
    dups = [r for r in classified_rows if r["census_class"] in {"DUPLICATE_ALIAS", "DUPLICATE_SNAPSHOT"}]
    if not dups:
        lines.append("None.")
    else:
        for r in dups:
            lines.append(f"- `{r['case_id']}` `{r['census_class']}` — {r['omission_reason']}")
    lines.append("")
    lines.append("## Nonterminal or invalid schema")
    lines.append("")
    bad = [r for r in classified_rows if r["census_class"] == "NONTERMINAL_INVALID_SCHEMA"]
    lines.append(f"Terminal classified invalid-schema positives: {len(bad)}.")
    lines.append(
        f"Nonterminal packet positive ids absent from canonical84 (excluded from genuine): {len(inflight_not_canonical)}."
    )
    if inflight_not_canonical[:40]:
        lines.append("First nonterminal-absent ids: " + ", ".join(f"`{x}`" for x in inflight_not_canonical[:40]))
    lines.append("")
    lines.append("## Already canonical")
    lines.append("")
    lines.append(
        f"{class_counts.get('ALREADY_CANONICAL', 0)} terminal positive identities are already counted in canonical84. They are not gap proposals."
    )
    lines.append("")
    lines.append("## Parse / schema notes")
    lines.append("")
    if not failures:
        lines.append("None.")
    else:
        lines.append(f"{len(failures)} notes/failures (first 40):")
        for item in failures[:40]:
            lines.append(f"- `{json.dumps(item, sort_keys=True)}`")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append(
        "Only structured result.json named ID lists, cases.jsonl, selected JSONL, and adjudication JSONL with explicit PASS/KEEP/ACCEPT (or KEEP_* / ACCEPT_* / PASS_*) were treated as proposals. Prose, routing signals, counts without IDs, stale labels, snapshot/work/pages/clone trees, and this census packet were excluded. Later terminal hostile/counter red-team or independent-review NARROW/REJECT, canonical84 SUPERSEDES_EDGE nonpositive overrides, and every REJECT row in canonical84/negative_controls.json reclassify an earlier worker proposal. Snapshot, work, pages, and clone trees were not scanned and are not retained here."
    )
    (OUT / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    replay = r"""#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/hanqing/agents/ai-slop
OUT=$ROOT/autoresearch/herdr-260814-ghsa200-current-proposal-gap-grok46-low
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl
NEG=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/negative_controls.json
test -f "$LEDGER"
test -f "$NEG"
test -f "$OUT/census.py"
# No cached clones or advisory pages in the owned packet.
if find "$OUT" -type d \( -name clones -o -name pages -o -name cache -o -name snapshot \) | grep -q .; then
  echo "owned packet must not retain clones/pages/cache/snapshot" >&2
  exit 1
fi
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
ledger = root / "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl"
neg = root / "autoresearch/orchestrator-260814-ghsa200-canonical84/negative_controls.json"
import json, re
ghsa = re.compile(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}", re.I)
ids = []
for line in ledger.read_text().splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    if row.get("record_kind") == "STRICT_RELEASED_CASE" and row.get("counted") is True:
        m = ghsa.search(row.get("case_id") or "")
        assert m, row
        ids.append(m.group(0).upper())
assert len(ids) == 84, len(ids)
assert len(set(ids)) == 84, "canonical ids not unique"
controls = json.loads(neg.read_text())["controls"]
control_ids = [ghsa.search(c["case_id"]).group(0).upper() for c in controls]
assert control_ids, "negative_controls.json empty"
assert not (set(control_ids) & set(ids)), "negative-control ids must not be counted"
print("canonical84-unique-84:", sha256(ledger.read_bytes()).hexdigest())
print("negative_controls:", sha256(neg.read_bytes()).hexdigest(), control_ids)
PY
python3 "$OUT/census.py"
test -f "$OUT/result.json"
test -f "$OUT/cases.jsonl"
test -f "$OUT/report.md"
test -f "$OUT/manifest.json"
python3 - <<'PY'
import json
from pathlib import Path
out = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-current-proposal-gap-grok46-low")
r = json.loads((out / "result.json").read_text())
assert r["conservation"]["id_conservation"] is True
assert r["accepted_set"]["counted"] == 84
assert r["conservation"]["canonical_exclusion_of_genuine"] is True
assert r["conservation"]["negative_control_exclusion_of_genuine"] is True
assert r["this_packet_does_not_claim_pass"] is True
assert r["causal_admission"] is False
canon = set(r["accepted_set"]["counted_ids"])
genuine = r["genuine_unresolved_ids"]
assert len(genuine) == len(set(genuine))
assert not (set(genuine) & canon)
neg_ids = set(r["accepted_set"]["negative_control_reject_ids"])
assert neg_ids
assert not (set(genuine) & neg_ids)
assert all(x not in genuine for x in neg_ids)
n = sum(1 for line in (out / "cases.jsonl").read_text().splitlines() if line.strip())
assert n == r["genuine_unresolved_count"]
m = json.loads((out / "manifest.json").read_text())
assert m["accepted_ledger_sha256"] == r["accepted_set"]["sha256"]
print("census-conservation: PASS")
print("unresolved", genuine)
print("packets", r["scan"]["packets"], "files", r["scan"]["files_scanned"], "rows", r["scan"]["jsonl_rows_parsed"])
PY
"""
    (OUT / "replay.sh").write_text(replay, encoding="utf-8")
    (OUT / "replay.sh").chmod(0o755)

    artifact_hashes = {
        "cases.jsonl": sha256_path(OUT / "cases.jsonl"),
        "report.md": sha256_path(OUT / "report.md"),
        "replay.sh": sha256_path(OUT / "replay.sh"),
        "census.py": sha256_path(OUT / "census.py"),
    }
    result["artifact_hashes"] = artifact_hashes
    (OUT / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest = {
        "lane": "herdr-260814-ghsa200-current-proposal-gap-grok46-low",
        "accepted_ledger": str(LEDGER.relative_to(ROOT)),
        "accepted_ledger_sha256": ledger_hash,
        "negative_controls_sha256": sha256_path(NEG_CONTROLS),
        "scan": scan_counts,
        "file_hashes": file_hashes,
        "artifact_hashes": {
            **artifact_hashes,
            "result.json": sha256_path(OUT / "result.json"),
        },
        "no_cached_clones_or_pages": True,
        "english_only": True,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # refresh result.json with manifest hash
    result["artifact_hashes"]["manifest.json"] = sha256_path(OUT / "manifest.json")
    result["artifact_hashes"]["result.json"] = None
    (OUT / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result["artifact_hashes"]["result.json"] = sha256_path(OUT / "result.json")
    (OUT / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"STATUS={status}")
    print(f"packets={scan_counts['packets']}")
    print(f"files={scan_counts['files_scanned']}")
    print(f"rows={scan_counts['jsonl_rows_parsed']}")
    print(f"canonical84={len(canonical_ids)}")
    print(f"terminal_positive_ids={len(set_all)}")
    print(f"classes={dict(class_counts)}")
    print(f"genuine={genuine_ids}")
    print(str(OUT))
    return 0 if leftover_check == set() else 1


if __name__ == "__main__":
    sys.exit(main())
