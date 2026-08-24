#!/usr/bin/env python3
"""Read-only next-pool inventory vs canonical85. Writes only this directory."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OUT = ROOT / "autoresearch/herdr-260814-next-pool-map-grok46-low"
OWN = OUT.resolve()
CANON_DIR = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical85"
LEDGER = CANON_DIR / "ledger.jsonl"
SUMMARY = CANON_DIR / "summary.json"
NEG_CONTROLS = CANON_DIR / "negative_controls.json"

GHSA_RE = re.compile(r"\bGHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\b", re.I)
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")

POSITIVE = {
    "PASS",
    "ACCEPT",
    "KEEP",
    "PROPOSED_PASS",
    "PROPOSED-PASS",
    "COUNTABLE_PASS",
    "WORKER_PASS",
    "REDTEAM_KEEP",
    "KEEP_PROPOSAL",
}

NONPOSITIVE = {
    "NARROW",
    "UNKNOWN",
    "REJECT",
    "BLOCKED",
    "FAIL",
    "FALSE_POSITIVE",
    "FALSE-POSITIVE",
    "HOLD",
    "UNREVIEWED",
    "PARTIAL",
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
    "redteam_verdict",
    "review_verdict",
)

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
    "next-pool-map",
    "current-proposal-gap",
    "proposal-census",
)

RESULT_ID_LIST_KEYS = (
    "pass_proposals",
    "proposed_pass_ids",
    "keep_ids",
    "keep_proposals",
    "keep_cases",
    "accepted_ids",
    "accept_ids",
    "pass_ids",
    "keep_first_party_ghsa_ids",
    "countable_first_party_ghsa_ids",
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
    "HOLD",
}

SEVEN = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
)


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


def ascii_ok(text: str) -> bool:
    return all(ord(c) < 128 for c in text)


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
        g = extract_ghsa(obj.get(key) if isinstance(obj.get(key), str) else None)
        if g:
            return g
    for key in ("aliases", "public_ids"):
        aliases = obj.get(key) or []
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
    if isinstance(value, str) and SHA_RE.fullmatch(value):
        return [value.lower()]
    if not isinstance(value, list):
        return []
    out = []
    seen = set()
    for item in value:
        if isinstance(item, str) and SHA_RE.fullmatch(item):
            s = item.lower()
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out


def aliases_of(obj: dict) -> list[str]:
    out = []
    seen = set()
    for key in ("aliases", "cve_aliases", "public_ids"):
        val = obj.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip() and item.strip() not in seen:
                    seen.add(item.strip())
                    out.append(item.strip())
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
        if text in POSITIVE or text in NONPOSITIVE:
            return text, key
        if text.startswith("KEEP"):
            return "KEEP", key
        if text.startswith("ACCEPT"):
            return "ACCEPT", key
        if text.startswith("PASS"):
            return "PASS", key
        if text.startswith("NARROW"):
            return "NARROW", key
        if text.startswith("REJECT"):
            return "REJECT", key
        if text.startswith("UNKNOWN"):
            return "UNKNOWN", key
    return None, None


def is_positive(verdict: str | None) -> bool:
    return verdict in POSITIVE


def is_envelope(obj: dict) -> bool:
    kind = str(obj.get("record_kind") or obj.get("row_kind") or obj.get("kind") or "").upper()
    if kind in {"SOURCE_ENVELOPE", "SOURCE_DECLARED", "ROUTE_CONTROL", "ROUTING_SIGNAL", "KEYWORD_HIT"}:
        return True
    if obj.get("source_envelopes_are_input_only"):
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


def skip_packet_dir(d: Path) -> bool:
    name = d.name.lower()
    if d.resolve() == OWN:
        return True
    if any(n in name for n in SKIP_PACKET_NEEDLES):
        return True
    if name.startswith("orchestrator-260814-ghsa200-canonical"):
        return True
    return False


def review_role(packet: str) -> str:
    n = packet.lower()
    if "canonical" in n and "negative" in n:
        return "canonical_negative_control"
    if "counterredteam" in n:
        return "negative_control"
    if "hostile-redteam" in n or "hostile_redteam" in n:
        return "hostile_redteam"
    if "final-candidate-review" in n:
        return "final_review"
    if any(x in n for x in ("narrow-recovery", "increm-patchdelta", "third-review", "unified-verifier")):
        return "independent_gate_closing_review"
    if "redteam" in n or "red-upgrade" in n or "redbase" in n:
        return "redteam"
    if any(x in n for x in ("gap", "freshness", "current-delta", "cross-dedupe", "coverage-closure")):
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


def gate_map(obj: dict) -> dict:
    g = obj.get("gates")
    if isinstance(g, dict):
        return {k: as_upper(str(v)) if v is not None else None for k, v in g.items()}
    out = {}
    for k in SEVEN + ("remediation_patch_delta_gate",):
        if k in obj:
            out[k] = as_upper(str(obj[k]))
    return out


def packet_of(path: Path) -> str:
    rel = path.relative_to(ROOT / "autoresearch")
    return str(Path("autoresearch") / rel.parts[0])


def list_scan_dirs() -> list[Path]:
    base = ROOT / "autoresearch"
    dirs = []
    for pattern in ("herdr-260814-*", "orchestrator-260814-*"):
        for d in sorted(base.glob(pattern)):
            if d.is_dir() and not skip_packet_dir(d):
                dirs.append(d)
    return dirs


def list_scan_files() -> list[Path]:
    files = []
    for d in list_scan_dirs():
        for p in sorted(d.iterdir()):
            if not p.is_file():
                continue
            name = p.name
            if name in {"result.json", "cases.jsonl", "case.json"}:
                files.append(p)
            elif name.startswith("selected") and name.endswith(".jsonl"):
                files.append(p)
            elif "adjudication" in name and name.endswith(".jsonl"):
                files.append(p)
    return files


def is_terminal_status(status: str) -> bool:
    s = status.upper()
    if s in {"PARTIAL", "IN_PROGRESS", "ACTIVE", "STATUS_ABSENT", "NO_RESULT_JSON", "RESULT_PARSE_FAIL"}:
        return False
    return s in TERMINAL_STATUSES or s.startswith("COMPLETE") or s.startswith("TERMINAL")


def load_packet_meta(packet: str, packet_dir: Path) -> dict:
    result = packet_dir / "result.json"
    meta = {
        "packet": packet,
        "status": "NO_RESULT_JSON",
        "role": review_role(packet),
        "terminal": False,
        "result_sha256": None,
    }
    if not result.is_file():
        return meta
    try:
        raw = result.read_bytes()
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        meta["status"] = "RESULT_PARSE_FAIL"
        return meta
    meta["result_sha256"] = sha256_bytes(raw)
    status = "STATUS_ABSENT"
    for key in ("status", "terminal_status", "worker_status"):
        if key in obj and obj[key]:
            status = str(obj[key])
            break
    meta["status"] = status
    meta["terminal"] = bool(obj.get("terminal")) or is_terminal_status(status) or bool(obj.get("analysis_complete"))
    return meta


def hit_from_row(row: dict, *, rel: str, packet: str, kind: str, lineno: int | None, v: str, vk: str | None, src_sha: str) -> dict:
    gates = gate_map(row)
    return {
        "case_id": first_ghsa_from_obj(row),
        "source_path": rel,
        "source_sha256": src_sha,
        "packet": packet,
        "source_kind": kind,
        "source_line": lineno,
        "verdict": v,
        "verdict_key": vk,
        "aliases": aliases_of(row),
        "repository": row.get("repository"),
        "mechanism_key": row.get("mechanism_key"),
        "mechanism_fingerprint": row.get("mechanism_fingerprint"),
        "candidate_set": sha_list(row.get("candidate_set") or row.get("counted_candidate")),
        "carrier_set": sha_list(row.get("carrier_set")),
        "minimum_fix_set": sha_list(row.get("minimum_fix_set") or row.get("minimum_fix")),
        "gates": gates,
        "release_gate": gates.get("release_gate"),
        "contribution_class": row.get("contribution_class") or row.get("causal_class"),
        "scope_statement": row.get("scope_statement"),
        "row_kind": row.get("row_kind") or kind,
        "semantic_duplicate_of": row.get("semantic_duplicate_of") or row.get("duplicate_of") or row.get("uniqueness_target"),
    }


def empty_hit(g: str, *, rel: str, packet: str, kind: str, v: str, vk: str, src_sha: str) -> dict:
    return {
        "case_id": g,
        "source_path": rel,
        "source_sha256": src_sha,
        "packet": packet,
        "source_kind": kind,
        "source_line": None,
        "verdict": v,
        "verdict_key": vk,
        "aliases": [],
        "repository": None,
        "mechanism_key": None,
        "mechanism_fingerprint": None,
        "candidate_set": [],
        "carrier_set": [],
        "minimum_fix_set": [],
        "gates": {},
        "release_gate": None,
        "contribution_class": None,
        "scope_statement": None,
        "row_kind": kind,
        "semantic_duplicate_of": None,
    }


def ingest_jsonl_row(row: dict, *, rel: str, packet: str, kind: str, lineno: int, src_sha: str, hits: list, skipped: Counter, failures: list) -> None:
    if not isinstance(row, dict):
        failures.append({"kind": "SCHEMA", "path": rel, "line": lineno, "reason": "non-object"})
        return
    if is_envelope(row):
        skipped["source_envelope"] += 1
        return
    v, vk = row_verdict(row)
    g = first_ghsa_from_obj(row)
    if v is None:
        skipped["no_verdict"] += 1
        return
    if not g:
        if is_positive(v):
            failures.append({"kind": "SCHEMA", "path": rel, "line": lineno, "reason": "positive verdict without GHSA", "verdict": v})
        skipped["no_ghsa"] += 1
        return
    h = hit_from_row(row, rel=rel, packet=packet, kind=kind, lineno=lineno, v=v, vk=vk, src_sha=src_sha)
    h["case_id"] = g
    hits.append(h)


def ingest_result_obj(obj: dict, *, rel: str, packet: str, src_sha: str, hits: list, skipped: Counter, failures: list) -> None:
    for key in RESULT_ID_LIST_KEYS:
        val = obj.get(key)
        if not isinstance(val, list):
            continue
        default_v = "KEEP" if "keep" in key.lower() else "PROPOSED_PASS"
        for item in val:
            if isinstance(item, str):
                g = extract_ghsa(item)
                if g:
                    hits.append(empty_hit(g, rel=rel, packet=packet, kind="result.json:" + key, v=default_v, vk=key, src_sha=src_sha))
            elif isinstance(item, dict):
                if is_envelope(item):
                    skipped["source_envelope"] += 1
                    continue
                g = first_ghsa_from_obj(item)
                if not g:
                    continue
                v, vk = row_verdict(item)
                if v is None:
                    v, vk = default_v, key
                h = hit_from_row(item, rel=rel, packet=packet, kind="result.json:" + key, lineno=None, v=v, vk=vk, src_sha=src_sha)
                h["case_id"] = g
                hits.append(h)
    per = obj.get("per_case")
    if isinstance(per, dict):
        for cid, raw in per.items():
            g = extract_ghsa(cid)
            v = as_upper(str(raw)) if raw is not None else None
            if not g or not v:
                continue
            if v.startswith("KEEP"):
                v = "KEEP"
            elif v.startswith("PASS"):
                v = "PASS"
            elif v.startswith("ACCEPT"):
                v = "ACCEPT"
            elif v.startswith("NARROW"):
                v = "NARROW"
            elif v.startswith("REJECT"):
                v = "REJECT"
            elif v.startswith("UNKNOWN"):
                v = "UNKNOWN"
            if is_positive(v) or v in NONPOSITIVE:
                hits.append(empty_hit(g, rel=rel, packet=packet, kind="result.json:per_case", v=v, vk="per_case", src_sha=src_sha))
    gv = obj.get("gate_vectors")
    if isinstance(gv, dict):
        for cid, vec in gv.items():
            g = extract_ghsa(cid)
            if not g or not isinstance(vec, dict):
                continue
            v, vk = row_verdict(vec)
            if v is None:
                continue
            h = hit_from_row(vec, rel=rel, packet=packet, kind="result.json:gate_vectors", lineno=None, v=v, vk=vk, src_sha=src_sha)
            h["case_id"] = g
            hits.append(h)
    for key, forced in (("reject_cases", "REJECT"), ("narrow_cases", "NARROW"), ("unknown_cases", "UNKNOWN"), ("keep_cases", "KEEP")):
        val = obj.get(key)
        if not isinstance(val, list):
            continue
        for item in val:
            if isinstance(item, str):
                g = extract_ghsa(item)
                if g:
                    hits.append(empty_hit(g, rel=rel, packet=packet, kind="result.json:" + key, v=forced, vk=key, src_sha=src_sha))
            elif isinstance(item, dict):
                g = first_ghsa_from_obj(item)
                if not g:
                    continue
                v, vk = row_verdict(item)
                if v is None:
                    v, vk = forced, key
                h = hit_from_row(item, rel=rel, packet=packet, kind="result.json:" + key, lineno=None, v=v, vk=vk, src_sha=src_sha)
                h["case_id"] = g
                hits.append(h)
    counts = obj.get("counts") or obj.get("verdicts") or {}
    if isinstance(counts, dict):
        npass = 0
        for k in ("PASS", "ACCEPT", "KEEP"):
            if isinstance(counts.get(k), int):
                npass += counts[k]
        if npass and not any(h["source_path"] == rel and is_positive(h["verdict"]) for h in hits):
            skipped["count_without_row_ids"] += 1
            failures.append(
                {
                    "kind": "SCHEMA_NOTE",
                    "path": rel,
                    "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object",
                    "count": npass,
                }
            )


def richest(hits: list[dict]) -> dict:
    def score(h):
        return (
            len(h.get("candidate_set") or []),
            len(h.get("minimum_fix_set") or []),
            1 if h.get("repository") else 0,
            1 if h.get("mechanism_key") else 0,
            len(h.get("gates") or {}),
            1 if h.get("source_line") else 0,
        )

    return max(hits, key=score)


def hostile_status(hits: list[dict], packet_meta: dict) -> dict:
    hostile = [h for h in hits if packet_meta.get(h["packet"], {}).get("role") in {"hostile_redteam", "negative_control", "canonical_negative_control"}]
    independent = [h for h in hits if packet_meta.get(h["packet"], {}).get("role") in {"hostile_redteam", "negative_control", "canonical_negative_control", "redteam", "independent_gate_closing_review", "final_review"}]
    if not independent:
        return {
            "independent_hostile_review": "absent",
            "independent_verdict": None,
            "independent_packet": None,
            "independent_source_path": None,
            "independent_source_sha256": None,
        }
    ranked = sorted(
        independent,
        key=lambda h: (role_rank(packet_meta.get(h["packet"], {}).get("role") or "worker"), 1 if packet_meta.get(h["packet"], {}).get("terminal") else 0),
        reverse=True,
    )
    top = ranked[0]
    role = packet_meta.get(top["packet"], {}).get("role")
    kind = "hostile" if role in {"hostile_redteam", "negative_control", "canonical_negative_control"} else "independent_review"
    return {
        "independent_hostile_review": kind,
        "independent_verdict": top["verdict"],
        "independent_packet": top["packet"],
        "independent_source_path": top["source_path"],
        "independent_source_sha256": top["source_sha256"],
        "hostile_hits": len(hostile),
    }


def load_canonical() -> tuple[dict, dict, dict, dict]:
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    counted_ids = [norm_ghsa(x) for x in summary["strict_released_case_ids"]]
    counted = {}
    alias_to = {}
    mech_to = {}
    sha_index = defaultdict(list)
    for row in jsonl(LEDGER):
        if row.get("record_kind") != "STRICT_RELEASED_CASE" or row.get("counted") is not True:
            continue
        cid = extract_ghsa(row.get("case_id") or "")
        if not cid:
            continue
        counted[cid] = row
        for a in row.get("aliases") or []:
            g = extract_ghsa(a)
            if g and g != cid:
                alias_to[g] = cid
            if isinstance(a, str) and a.upper().startswith("CVE-"):
                alias_to[a.strip().upper()] = cid
        mk = row.get("mechanism_key")
        mf = row.get("mechanism_fingerprint")
        if isinstance(mk, str) and mk:
            mech_to[mk] = cid
        if isinstance(mf, str) and mf:
            mech_to[mf] = cid
        for s in sha_list(row.get("candidate_set")) + sha_list(row.get("carrier_set")) + sha_list(row.get("minimum_fix_set")):
            sha_index[s].append(cid)
    assert set(counted_ids) == set(counted), "summary vs ledger counted mismatch"
    assert len(counted) == 85, len(counted)
    return counted, alias_to, mech_to, sha_index


def load_neg() -> dict:
    obj = json.loads(NEG_CONTROLS.read_text(encoding="utf-8"))
    by_id = {}
    for ctrl in obj.get("controls") or []:
        cid = extract_ghsa(ctrl.get("case_id") or "")
        if cid:
            by_id[cid] = ctrl
    return by_id


def classify(cid: str, hits: list[dict], packet_meta: dict, counted: dict, alias_to: dict, mech_to: dict, neg: dict) -> tuple[str, str, str | None]:
    if cid in counted:
        return "EXCLUDED", "ALREADY_COUNTED", None
    if cid in alias_to:
        return "D", "ALIAS_OF_COUNTED", alias_to[cid]
    if cid in neg:
        return "D", "NEGATIVE_CONTROL_REJECT", None

    rich = richest(hits)
    mk = rich.get("mechanism_key")
    mf = rich.get("mechanism_fingerprint")
    dup_target = None
    if isinstance(mk, str) and mk in mech_to and mech_to[mk] != cid:
        dup_target = mech_to[mk]
    if isinstance(mf, str) and mf in mech_to and mech_to[mf] != cid:
        dup_target = mech_to[mf]
    stated = rich.get("semantic_duplicate_of")
    if isinstance(stated, str):
        g = extract_ghsa(stated)
        if g and g in counted:
            dup_target = g
        elif stated in mech_to:
            dup_target = mech_to[stated]

    hs = hostile_status(hits, packet_meta)
    worker_pos = [h for h in hits if is_positive(h["verdict"]) and packet_meta.get(h["packet"], {}).get("role") in {"worker", "inventory", "redteam"}]
    indep_pos = [h for h in hits if is_positive(h["verdict"]) and packet_meta.get(h["packet"], {}).get("role") in {"hostile_redteam", "independent_gate_closing_review", "final_review"}]
    any_pos = [h for h in hits if is_positive(h["verdict"])]

    ranked = sorted(
        hits,
        key=lambda h: (
            role_rank(packet_meta.get(h["packet"], {}).get("role") or "worker"),
            1 if packet_meta.get(h["packet"], {}).get("terminal") else 0,
            1 if is_positive(h["verdict"]) else 0,
        ),
        reverse=True,
    )
    top = ranked[0]
    top_role = packet_meta.get(top["packet"], {}).get("role") or "worker"
    top_v = top["verdict"]

    if dup_target:
        return "D", "MECHANISM_FINGERPRINT_DUPLICATE", dup_target

    if top_v in {"REJECT", "FALSE_POSITIVE", "TERMINAL_REJECT", "FAIL", "BLOCKED"}:
        return "D", "REJECT", dup_target
    if top_role in {"hostile_redteam", "negative_control", "canonical_negative_control"} and top_v == "REJECT":
        return "D", "REJECT", dup_target

    if indep_pos and top_v in POSITIVE and top_role in {"hostile_redteam", "independent_gate_closing_review", "final_review"}:
        return "A", "INDEPENDENT_KEEP_NOT_INTEGRATED", dup_target
    if top_v in POSITIVE and top_role == "hostile_redteam":
        return "A", "INDEPENDENT_KEEP_NOT_INTEGRATED", dup_target

    if top_v in {"NARROW", "UNKNOWN", "HOLD", "PARTIAL", "UNREVIEWED"}:
        return "C", top_v, dup_target
    if hs.get("independent_verdict") in {"NARROW", "UNKNOWN"} and not indep_pos:
        return "C", hs["independent_verdict"], dup_target

    if any_pos and (not hs.get("independent_verdict") or hs.get("independent_hostile_review") == "absent"):
        return "B", "WORKER_PASS_NEEDS_HOSTILE_REVIEW", dup_target
    if worker_pos and hs.get("independent_verdict") in POSITIVE and top_role == "worker":
        return "B", "WORKER_PASS_NEEDS_HOSTILE_REVIEW", dup_target
    if any_pos and hs.get("independent_verdict") not in {"REJECT", "NARROW", "UNKNOWN"}:
        return "B", "WORKER_PASS_NEEDS_HOSTILE_REVIEW", dup_target

    if dup_target:
        return "D", "MECHANISM_FINGERPRINT_DUPLICATE", dup_target
    if top_v in POSITIVE:
        return "B", "WORKER_PASS_NEEDS_HOSTILE_REVIEW", None
    return "C", top_v or "UNKNOWN", dup_target


def record_from(cid: str, hits: list[dict], packet_meta: dict, bucket: str, reason: str, dup: str | None) -> dict:
    rich = richest(hits)
    hs = hostile_status(hits, packet_meta)
    authority_hits = hits
    if bucket == "C" and hs.get("independent_source_path"):
        authority_hits = [h for h in hits if h["source_path"] == hs["independent_source_path"]] or hits
    elif bucket == "A" and hs.get("independent_source_path"):
        authority_hits = [h for h in hits if h["source_path"] == hs["independent_source_path"]] or hits
    elif bucket == "B":
        authority_hits = [h for h in hits if is_positive(h["verdict"])] or hits
    primary = richest(authority_hits)
    if not rich.get("candidate_set") and primary.get("candidate_set"):
        rich = primary
    if not rich.get("repository"):
        rich = {**rich, "repository": primary.get("repository")}
    rich = {
        **rich,
        "source_path": primary["source_path"],
        "source_sha256": primary["source_sha256"],
        "release_gate": primary.get("release_gate") or rich.get("release_gate"),
        "repository": primary.get("repository") or rich.get("repository"),
        "candidate_set": primary.get("candidate_set") or rich.get("candidate_set") or [],
        "carrier_set": primary.get("carrier_set") or rich.get("carrier_set") or [],
        "minimum_fix_set": primary.get("minimum_fix_set") or rich.get("minimum_fix_set") or [],
        "mechanism_key": primary.get("mechanism_key") or rich.get("mechanism_key"),
        "mechanism_fingerprint": primary.get("mechanism_fingerprint") or rich.get("mechanism_fingerprint"),
        "contribution_class": primary.get("contribution_class") or rich.get("contribution_class"),
    }
    aliases = []
    seen_a = set()
    repos = []
    for h in hits:
        for a in h.get("aliases") or []:
            if a not in seen_a:
                seen_a.add(a)
                aliases.append(a)
        if h.get("repository") and h["repository"] not in repos:
            repos.append(h["repository"])
    sources = []
    seen_s = set()
    for h in hits:
        key = (h["source_path"], h["source_sha256"], h["verdict"], h.get("source_line"))
        if key in seen_s:
            continue
        seen_s.add(key)
        sources.append(
            {
                "path": h["source_path"],
                "sha256": h["source_sha256"],
                "packet": h["packet"],
                "packet_role": packet_meta.get(h["packet"], {}).get("role"),
                "packet_terminal": bool(packet_meta.get(h["packet"], {}).get("terminal")),
                "source_kind": h["source_kind"],
                "source_line": h.get("source_line"),
                "recorded_verdict": h["verdict"],
            }
        )
    pos = [h for h in hits if is_positive(h["verdict"])]
    return {
        "case_id": cid,
        "bucket": bucket,
        "reason": reason,
        "aliases": aliases,
        "repository": rich.get("repository") or (repos[0] if repos else None),
        "candidate_set": rich.get("candidate_set") or [],
        "carrier_set": rich.get("carrier_set") or [],
        "minimum_fix_set": rich.get("minimum_fix_set") or [],
        "mechanism_key": rich.get("mechanism_key"),
        "mechanism_fingerprint": rich.get("mechanism_fingerprint"),
        "release_evidence_status": rich.get("release_gate") or "ABSENT",
        "independent_hostile_review_status": hs,
        "semantic_duplicate_target": dup,
        "contribution_class": rich.get("contribution_class"),
        "had_pass_or_keep": bool(pos),
        "primary_source_path": rich["source_path"],
        "primary_source_sha256": rich["source_sha256"],
        "sources": sources,
        "labels_not_inherited": True,
        "counted": False,
        "causal_admission": False,
    }


def write_json(path: Path, obj) -> None:
    text = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    assert ascii_ok(text), path
    path.write_text(text, encoding="ascii")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    lines = []
    for row in rows:
        line = json.dumps(row, sort_keys=True, ensure_ascii=True)
        assert ascii_ok(line), path
        lines.append(line)
    path.write_text(("\n".join(lines) + ("\n" if lines else "")), encoding="ascii")


def main() -> int:
    failures: list[dict] = []
    counted, alias_to, mech_to, _sha_index = load_canonical()
    neg = load_neg()
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    conservation = summary.get("conservation") or {}

    scan_files = list_scan_files()
    packets_seen = set()
    packet_meta = {}
    hits: list[dict] = []
    skipped = Counter()
    files_hashed = []
    jsonl_parsed = 0
    jsonl_total = 0

    for path in scan_files:
        rel = str(path.relative_to(ROOT))
        packet = packet_of(path)
        packets_seen.add(packet)
        if packet not in packet_meta:
            packet_meta[packet] = load_packet_meta(packet, ROOT / packet)
        try:
            raw = path.read_bytes()
        except Exception as e:
            failures.append({"kind": "READ", "path": rel, "error": type(e).__name__})
            continue
        src_sha = sha256_bytes(raw)
        files_hashed.append({"path": rel, "sha256": src_sha, "bytes": len(raw)})
        name = path.name
        if name == "result.json":
            try:
                obj = json.loads(raw.decode("utf-8"))
            except Exception as e:
                failures.append({"kind": "PARSE", "path": rel, "error": type(e).__name__})
                continue
            if isinstance(obj, dict):
                ingest_result_obj(obj, rel=rel, packet=packet, src_sha=src_sha, hits=hits, skipped=skipped, failures=failures)
            else:
                failures.append({"kind": "SCHEMA", "path": rel, "reason": "result.json is not an object"})
        elif name == "case.json":
            try:
                row = json.loads(raw.decode("utf-8"))
            except Exception as e:
                failures.append({"kind": "PARSE", "path": rel, "error": type(e).__name__})
                continue
            jsonl_total += 1
            jsonl_parsed += 1
            ingest_jsonl_row(row, rel=rel, packet=packet, kind="case.json", lineno=1, src_sha=src_sha, hits=hits, skipped=skipped, failures=failures)
        else:
            text = raw.decode("utf-8")
            kind = "cases.jsonl" if name == "cases.jsonl" else ("selected.jsonl" if name.startswith("selected") else "adjudication.jsonl")
            for lineno, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                jsonl_total += 1
                try:
                    row = json.loads(line)
                except Exception as e:
                    failures.append({"kind": "PARSE", "path": rel, "line": lineno, "error": type(e).__name__})
                    continue
                jsonl_parsed += 1
                ingest_jsonl_row(row, rel=rel, packet=packet, kind=kind, lineno=lineno, src_sha=src_sha, hits=hits, skipped=skipped, failures=failures)

    by_id: dict[str, list[dict]] = defaultdict(list)
    for h in hits:
        by_id[h["case_id"]].append(h)

    # Only identities that had at least one PASS/KEEP/ACCEPT, plus NARROW/UNKNOWN/REJECT that workers proposed then lost.
    pool_ids = sorted(cid for cid, hs in by_id.items() if any(is_positive(h["verdict"]) for h in hs))

    bucket_rows = {"A": [], "B": [], "C": [], "D": []}
    excluded = []
    already = []

    for cid in pool_ids:
        bucket, reason, dup = classify(cid, by_id[cid], packet_meta, counted, alias_to, mech_to, neg)
        rec = record_from(cid, by_id[cid], packet_meta, bucket if bucket != "EXCLUDED" else "EXCLUDED", reason, dup)
        if bucket == "EXCLUDED":
            already.append(rec)
            excluded.append(rec)
        elif bucket == "D":
            bucket_rows["D"].append(rec)
            excluded.append(rec)
        else:
            bucket_rows[bucket].append(rec)

    # Conservation: none of A/B/C/D may include counted 85.
    live = bucket_rows["A"] + bucket_rows["B"] + bucket_rows["C"] + bucket_rows["D"]
    live_ids = [r["case_id"] for r in live]
    assert not (set(live_ids) & set(counted)), sorted(set(live_ids) & set(counted))
    assert len(live_ids) == len(set(live_ids))
    assert len(already) == len(set(r["case_id"] for r in already))
    assert set(r["case_id"] for r in already) <= set(counted)
    id_conservation = (
        len(pool_ids) == len(already) + len(bucket_rows["A"]) + len(bucket_rows["B"]) + len(bucket_rows["C"]) + len(bucket_rows["D"])
    )

    queue = bucket_rows["A"] + bucket_rows["B"] + bucket_rows["C"]

    result = {
        "schema_version": 1,
        "artifact_kind": "next_pool_map_vs_canonical85",
        "language": "en",
        "ascii_only": True,
        "status": "INVENTORY_COMPLETE",
        "analysis_stopped": True,
        "inventory_only": True,
        "this_packet_does_not_claim_pass": True,
        "this_packet_does_not_claim_a_case_count": True,
        "causal_admission": False,
        "publication_ready": False,
        "integration_ready": False,
        "canonical_ledger_edited": False,
        "public_200_claim_supported": False,
        "authoritative_snapshot": {
            "path": "autoresearch/orchestrator-260814-ghsa200-canonical85",
            "ledger_sha256": sha256_path(LEDGER),
            "summary_sha256": sha256_path(SUMMARY),
            "negative_controls_sha256": sha256_path(NEG_CONTROLS),
            "counted_first_party_ghsa": 85,
            "counted_ids": sorted(counted),
            "counting_unit": "first-party GHSA case",
            "status": "HOLD",
        },
        "conservation": {
            "fp211_hypotheses": conservation.get("fp211_hypotheses"),
            "fp211_source_ghsa_cases": conservation.get("fp211_source_ghsa_cases"),
            "append_identities": conservation.get("append_identities"),
            "canonical85_counted_unchanged": True,
            "cve_aliases_counted": False,
            "shared_sha_alone_is_not_duplication": True,
            "id_conservation": id_conservation,
            "pool_pass_keep_identities": len(pool_ids),
            "already_counted_among_pool": len(already),
            "A": len(bucket_rows["A"]),
            "B": len(bucket_rows["B"]),
            "C": len(bucket_rows["C"]),
            "D": len(bucket_rows["D"]),
            "equation": "pool = already_counted + A + B + C + D",
            "holds": id_conservation,
        },
        "scan": {
            "packets": len(packets_seen),
            "files_scanned": len(scan_files),
            "files_hashed": len(files_hashed),
            "jsonl_rows_total": jsonl_total,
            "jsonl_rows_parsed": jsonl_parsed,
            "skipped": dict(skipped),
        },
        "buckets": {
            "A_independent_keep_not_integrated": [r["case_id"] for r in bucket_rows["A"]],
            "B_worker_proposal_needs_hostile_review": [r["case_id"] for r in bucket_rows["B"]],
            "C_narrow_or_unknown": [r["case_id"] for r in bucket_rows["C"]],
            "D_reject_or_duplicate": [r["case_id"] for r in bucket_rows["D"]],
        },
        "queue_count": len(queue),
        "excluded_count": len(excluded),
        "blockers": [
            "Inventory only. Worker PASS/KEEP is a proposal. Independent KEEP is not integration.",
            "Canonical85 remains HOLD at 85 first-party GHSA identities.",
            "This packet does not support a greater-than-200 claim.",
            "Shared candidate SHA is not a merge key.",
        ],
        "schema_notes": failures[:40],
        "file_hashes_sample": files_hashed[:20],
        "negative_control_ids": sorted(neg),
    }

    report_lines = [
        "# Next-pool map versus canonical85",
        "",
        "## Verdict first",
        "",
        "Inventory only. This packet does not claim PASS and does not claim a case count.",
        "Authoritative counted HOLD snapshot is canonical85 (85 first-party GHSA identities).",
        "Source conservation remains 211 fp211 hypotheses and 212 source GHSA cases.",
        "Publication, integration, and causal admission stay closed.",
        "",
        "PASS/KEEP identities seen in herdr-260814-* and orchestrator-260814-* worker packets: %d."
        % len(pool_ids),
        "Already among the 85 counted IDs: %d." % len(already),
        "A independent KEEP not integrated: %d." % len(bucket_rows["A"]),
        "B worker proposal needing hostile review: %d." % len(bucket_rows["B"]),
        "C NARROW/UNKNOWN: %d." % len(bucket_rows["C"]),
        "D REJECT/duplicate: %d." % len(bucket_rows["D"]),
        "ID conservation (%s): %s." % (result["conservation"]["equation"], str(id_conservation)),
        "",
        "## Method",
        "",
        "Labels are not inherited. Each recorded verdict is copied from its source path and sha256.",
        "Dedupe is exact first-party GHSA identity or matching mechanism_key / mechanism_fingerprint.",
        "Shared SHA alone is not duplication.",
        "Canonical HOLD snapshots are the counted set, not proposal sources.",
        "snapshot/work/pages/clone trees were not scanned.",
        "",
        "## A independent KEEP not integrated",
        "",
    ]
    if not bucket_rows["A"]:
        report_lines.append("Empty.")
    for r in bucket_rows["A"]:
        report_lines.append(
            "- %s repo=%s cand=%s fix=%s release=%s hostile=%s src=%s sha256=%s"
            % (
                r["case_id"],
                r["repository"],
                ",".join(r["candidate_set"]) or "none",
                ",".join(r["minimum_fix_set"]) or "none",
                r["release_evidence_status"],
                r["independent_hostile_review_status"].get("independent_verdict"),
                r["primary_source_path"],
                r["primary_source_sha256"],
            )
        )
    report_lines += ["", "## B worker proposal needing hostile review", ""]
    if not bucket_rows["B"]:
        report_lines.append("Empty.")
    for r in bucket_rows["B"]:
        report_lines.append(
            "- %s repo=%s cand=%s fix=%s release=%s hostile_review=%s src=%s sha256=%s"
            % (
                r["case_id"],
                r["repository"],
                ",".join(r["candidate_set"]) or "none",
                ",".join(r["minimum_fix_set"]) or "none",
                r["release_evidence_status"],
                r["independent_hostile_review_status"].get("independent_hostile_review"),
                r["primary_source_path"],
                r["primary_source_sha256"],
            )
        )
    report_lines += ["", "## C NARROW/UNKNOWN", ""]
    if not bucket_rows["C"]:
        report_lines.append("Empty.")
    for r in bucket_rows["C"]:
        report_lines.append(
            "- %s reason=%s repo=%s src=%s sha256=%s"
            % (r["case_id"], r["reason"], r["repository"], r["primary_source_path"], r["primary_source_sha256"])
        )
    report_lines += ["", "## D REJECT/duplicate", ""]
    if not bucket_rows["D"]:
        report_lines.append("Empty.")
    for r in bucket_rows["D"]:
        report_lines.append(
            "- %s reason=%s dup_target=%s src=%s sha256=%s"
            % (r["case_id"], r["reason"], r["semantic_duplicate_target"], r["primary_source_path"], r["primary_source_sha256"])
        )
    report_lines += [
        "",
        "## Excluded already counted",
        "",
        "%d PASS/KEEP identities are already canonical85 counted IDs and are listed in excluded.jsonl." % len(already),
        "",
        "## Stop",
        "",
        "Inventory complete. No ledger, site, or code edits. No clone or advisory fetch.",
        "",
    ]
    report = "\n".join(report_lines)
    assert ascii_ok(report)

    write_json(OUT / "result.json", result)
    write_jsonl(OUT / "queue.jsonl", queue)
    write_jsonl(OUT / "excluded.jsonl", excluded)
    (OUT / "report.md").write_text(report, encoding="ascii")
    return 0


if __name__ == "__main__":
    sys.exit(main())
