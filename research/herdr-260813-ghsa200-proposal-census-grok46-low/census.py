#!/usr/bin/env python3
"""Deterministic GHSA proposal census. Writes only this directory."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OUT = ROOT / "autoresearch/herdr-260813-ghsa200-proposal-census-grok46-low"
OWN = OUT.resolve()

CONTRACT = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
BASELINE = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/baseline.json"
MECHS = ROOT / "autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl"
PUBLIC = ROOT / "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl"
LEDGER = ROOT / "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl"
FINAL_CASES = ROOT / "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/cases.jsonl"
FINAL_RESULT = ROOT / "autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/result.json"

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
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def jsonl(path: Path) -> list:
    rows = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
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


def row_verdict(obj: dict) -> tuple[str | None, str | None]:
    """Return (normalized_verdict, source_key)."""
    for key in VERDICT_KEYS:
        if key not in obj:
            continue
        raw = obj[key]
        if raw is None:
            continue
        if isinstance(raw, dict):
            continue
        text = as_upper(str(raw))
        if not text:
            continue
        # Map common compounds
        if text in {"PROPOSED_PASS", "PROPOSED-PASS"}:
            return "PROPOSED_PASS", key
        if text.startswith("PROPOSED_PASS"):
            return "PROPOSED_PASS", key
        if text in POSITIVE or text in NEGATIVE:
            return text, key
        # KEEP_* treated as KEEP if keep-as-proposal language
        if text.startswith("KEEP"):
            return "KEEP", key
        if text.startswith("ACCEPT"):
            return "ACCEPT", key
        if text.startswith("PASS"):
            return "PASS", key
    return None, None


def is_positive(verdict: str | None) -> bool:
    return verdict in POSITIVE or verdict in {"PASS", "ACCEPT", "KEEP", "PROPOSED_PASS"}


def is_envelope(obj: dict) -> bool:
    kind = str(obj.get("record_kind") or obj.get("row_kind") or obj.get("kind") or "").upper()
    if kind in ENVELOPE_KINDS:
        return True
    if obj.get("source_envelopes_are_input_only"):
        return True
    layer = str(obj.get("source_layer") or "")
    if layer == "SOURCE_ENVELOPE":
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


def list_scan_files() -> list[Path]:
    files = []
    for prefix in ("herdr-260812-", "herdr-260813-"):
        base = ROOT / "autoresearch"
        for d in sorted(base.glob(prefix + "*")):
            if not d.is_dir():
                continue
            if d.resolve() == OWN:
                continue
            for name in ("result.json", "cases.jsonl"):
                for p in sorted(d.rglob(name)):
                    if any(part in SKIP_DIR_PARTS for part in p.parts):
                        continue
                    files.append(p)
    # unique, stable
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
    parts = rel.parts
    return str(Path("autoresearch") / parts[0])


def load_packet_meta(packet: str, packet_dir: Path) -> dict:
    result = packet_dir / "result.json"
    meta = {
        "packet": packet,
        "status": "NO_RESULT_JSON",
        "when": None,
        "when_raw": None,
        "hold": False,
        "forced_inflight": forced_inflight(packet),
        "role": review_role(packet),
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


def pick_list(obj: dict, *keys):
    for k in keys:
        v = obj.get(k)
        if isinstance(v, list):
            return v
    return []


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


IN_FLIGHT_PACKET_NEEDLES = (
    "narrow-recovery-a-grok46",
    "narrow-recovery-b-grok46",
    "netnew22-redteam",
)

TERMINAL_STATUSES = {
    "COMPLETE",
    "TERMINAL",
    "COMPLETE_BOUNDED_REVIEW",
    "REDTEAM_COMPLETE",
    "REVIEW_COMPLETE",
    "COMPLETE_THIRD_REVIEW",
    "PARTIAL_TERMINAL",
}

NONPOSITIVE_DOWNGRADE = {
    "NARROW",
    "REJECT",
    "BLOCKED",
    "UNKNOWN",
    "FAIL",
    "FALSE_POSITIVE",
}

REGRESSION_RECOVERY_IDS = (
    "GHSA-F38V-77QJ-H4JQ",
    "GHSA-G3XQ-3GMV-QQ8G",
    "GHSA-PV2J-RGHR-V5R9",
)


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


def review_role(packet: str) -> str:
    n = packet.lower()
    if "final-candidate-review" in n:
        return "final_review"
    if "narrow-recovery" in n:
        return "independent_gate_closing_review"
    if "increm-patchdelta" in n or "third-review" in n or "baseline-increm" in n or "unified-verifier" in n:
        return "independent_gate_closing_review"
    if "redteam" in n or "red-upgrade" in n or "/redbase" in n or n.endswith("redbase") or "redbase-" in n:
        return "redteam"
    if "netnew22-redteam" in n:
        return "redteam"
    if any(x in n for x in ("gap", "freshness", "current-delta", "cross-dedupe", "tail11")):
        return "inventory"
    if n.endswith("remediation") or "/herdr-260813-ghsa200-remediation" in n:
        return "inventory"
    return "worker"


def role_rank(role: str) -> int:
    return {
        "inventory": 1,
        "worker": 2,
        "redteam": 4,
        "independent_gate_closing_review": 5,
        "final_review": 6,
    }.get(role, 2)


def forced_inflight(packet: str) -> bool:
    n = packet.lower()
    return any(needle in n for needle in IN_FLIGHT_PACKET_NEEDLES)


def is_terminal_packet(meta: dict) -> bool:
    if meta.get("forced_inflight"):
        return False
    if meta.get("hold") is True and "PARTIAL" in str(meta.get("status") or "").upper():
        return False
    status = str(meta.get("status") or "").upper()
    if status in {"PARTIAL", "HOLD", "IN_PROGRESS", "ACTIVE", "STATUS_ABSENT", "NO_RESULT_JSON", "RESULT_PARSE_FAIL"}:
        return False
    return status in TERMINAL_STATUSES


def later_redteam_or_review_downgrade(pass_meta: dict, neg_meta: dict, neg_verdict: str) -> bool:
    """True only when a later terminal red-team/review downgrade may override PASS.

    Older worker/inventory NARROW never overrides a later independent gate-closing PASS.
    """
    if not is_terminal_packet(neg_meta):
        return False
    if neg_verdict not in NONPOSITIVE_DOWNGRADE:
        return False
    if review_role(neg_meta["packet"]) == "inventory":
        return False
    t_pass = pass_meta.get("when")
    t_neg = neg_meta.get("when")
    r_pass = review_role(pass_meta["packet"])
    r_neg = review_role(neg_meta["packet"])
    if t_pass and t_neg:
        if t_neg <= t_pass:
            return False
        return r_neg in {"redteam", "independent_gate_closing_review", "final_review"}
    # Missing timestamps: role only. Red-team or later review role may downgrade a worker PASS.
    # Independent gate-closing PASS is not downgraded by worker/inventory NARROW.
    if r_pass == "independent_gate_closing_review" and r_neg in {"worker", "inventory"}:
        return False
    if r_pass == "final_review":
        return False
    if r_pass == "worker" and r_neg in {"redteam", "independent_gate_closing_review", "final_review"}:
        return True
    return False


def test_recovery_not_overridden_by_old_narrow() -> None:
    upgrade_b = {
        "packet": "autoresearch/herdr-260813-ghsa200-upgrade-b",
        "status": "COMPLETE",
        "when": parse_when("2026-08-13T16:48:21-04:00"),
        "hold": False,
        "forced_inflight": False,
    }
    remediation = {
        "packet": "autoresearch/herdr-260813-ghsa200-remediation",
        "status": "COMPLETE",
        "when": parse_when("2026-08-13T16:42:18-04:00"),
        "hold": False,
        "forced_inflight": False,
    }
    recovery_b = {
        "packet": "autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high",
        "status": "COMPLETE_BOUNDED_REVIEW",
        "when": parse_when("2026-08-13T22:40:00Z"),
        "hold": False,
        "forced_inflight": False,
    }
    redteam = {
        "packet": "autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam",
        "status": "REDTEAM_COMPLETE",
        "when": parse_when("2026-08-13T21:30:00Z"),
        "hold": False,
        "forced_inflight": False,
    }
    for _cid in REGRESSION_RECOVERY_IDS:
        assert later_redteam_or_review_downgrade(recovery_b, upgrade_b, "NARROW") is False
        assert later_redteam_or_review_downgrade(recovery_b, remediation, "NARROW") is False
    assert later_redteam_or_review_downgrade(upgrade_b, redteam, "NARROW") is True
    inflight = dict(recovery_b)
    inflight["forced_inflight"] = True
    assert is_terminal_packet(inflight) is False
    assert is_terminal_packet(recovery_b) is True


def classify_omission(
    *,
    case_id: str,
    in_48: bool,
    in_32: bool,
    sources: list[dict],
    packet_status: dict[str, str],
) -> tuple[str, str]:
    if in_32:
        return "ABSORBED_FINAL_32", "Present in the 32-row final-candidate-review-codex set."
    if in_48:
        return "ABSORBED_BASELINE_48", "Present in the 48 strict released fp211 baseline."
    # remaining: unabsorbed relative to both sets
    statuses = [packet_status.get(s["packet"], "UNKNOWN") for s in sources]
    partial = any("PARTIAL" in st.upper() for st in statuses)
    commit_only = False
    unsupported = False
    superseded = False
    snapshot = False
    for s in sources:
        if "/snapshot/" in s["source_path"]:
            snapshot = True
        gates = s.get("gates") or {}
        rel = gates.get("release_gate")
        if rel and rel != "PASS":
            commit_only = True
        if s.get("verdict") in POSITIVE and not seven_all_pass(gates) and gates:
            if rel != "PASS" and any(gates.get(k) == "PASS" for k in gates):
                if rel in {"FAIL", "UNKNOWN", "NARROW", None}:
                    commit_only = commit_only or rel != "PASS"
        if not s.get("case_id"):
            unsupported = True
        note = " ".join(
            str(s.get(k) or "")
            for k in ("scope_statement", "contribution_class", "omission_hint")
        ).lower()
        if "supersed" in note:
            superseded = True
    packets = {s["packet"] for s in sources}
    # later independent recoveries that were not in the 32 freeze
    later_recovery = any("narrow-recovery" in p or "commitfirst-gj" in p or "commitfirst-kn" in p or "commitfirst-oz" in p or "commitfirst-af" in p for p in packets)
    if snapshot and len(packets) > 1:
        return "DUPLICATE_SNAPSHOT", "Row is a snapshot copy of another worker artifact, not an independent proposal."
    if superseded:
        return "SUPERSEDED", "Source text marks the hypothesis as superseded."
    if unsupported:
        return "UNSUPPORTED", "Positive label without a first-party GHSA case_id row."
    if commit_only and not any(seven_all_pass(s.get("gates") or {}) for s in sources):
        return "COMMIT_ONLY", "Positive label without closed release_gate / seven-gate proof."
    if partial and not any(seven_all_pass(s.get("gates") or {}) for s in sources):
        return "PARTIAL_UNSUPPORTED", "Source packet is PARTIAL and the row does not close seven gates."
    if any(seven_all_pass(s.get("gates") or {}) for s in sources):
        if later_recovery:
            return "GENUINE_UNABSORBED", "Seven-gate PASS/ACCEPT/KEEP proposal with a first-party GHSA id, absent from both the 48 baseline and the 32-row final review (including post-freeze recoveries)."
        return "GENUINE_UNABSORBED", "Seven-gate PASS/ACCEPT/KEEP proposal with a first-party GHSA id, absent from both comparison sets."
    if later_recovery:
        return "PARTIAL_OR_POSTFREEZE", "Proposal-shaped row from a packet outside the 32-row freeze, without full seven-gate closure in the parsed row."
    return "UNSUPPORTED", "Positive-looking row lacks closed seven-gate evidence and was not in the 32-row review."


def main() -> int:
    test_recovery_not_overridden_by_old_narrow()
    failures: list[dict] = []
    assert CONTRACT.is_file(), "CONTRACT.md missing"
    contract_hash = sha256_path(CONTRACT)
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    expected_contract = baseline["inputs"]["contract_sha256"]
    if contract_hash != expected_contract:
        failures.append(
            {
                "kind": "HASH_MISMATCH",
                "path": str(CONTRACT.relative_to(ROOT)),
                "expected": expected_contract,
                "actual": contract_hash,
            }
        )

    mechs = jsonl(MECHS)
    cases_pub = jsonl(PUBLIC)
    if len(mechs) != 211:
        failures.append({"kind": "COUNT", "path": str(MECHS), "expected": 211, "actual": len(mechs)})
    if len(cases_pub) != 212:
        failures.append({"kind": "COUNT", "path": str(PUBLIC), "expected": 212, "actual": len(cases_pub)})

    mech_by_ord = {m["ordinal"]: m for m in mechs}
    pub_by_ord: dict[int, list] = defaultdict(list)
    for c in cases_pub:
        pub_by_ord[c["ordinal"]].append(c)

    confirm_high = [m for m in mechs if m.get("verdict") == "CONFIRM" and m.get("confidence") == "HIGH"]
    if len(confirm_high) != 51:
        failures.append({"kind": "COUNT", "what": "confirm_high", "expected": 51, "actual": len(confirm_high)})
    strict_released_mechs = [m for m in confirm_high if m.get("release_gate") == "PASS"]
    # 51 HIGH; 3 lack released containment
    if len(strict_released_mechs) != 48:
        # some HIGH may have release NARROW/FAIL
        failures.append(
            {
                "kind": "COUNT",
                "what": "strict_released_mechs_release_gate_PASS",
                "expected": 48,
                "actual": len(strict_released_mechs),
                "note": "Will also bind via public_cases.strict_confirmed + ledger admitted flag",
            }
        )

    baseline_48: dict[str, dict] = {}
    for m in strict_released_mechs:
        pubs = pub_by_ord.get(m["ordinal"], [])
        for p in pubs:
            cid = extract_ghsa(p.get("case_id") or "")
            if cid:
                baseline_48[cid] = {
                    "ordinal": m["ordinal"],
                    "mechanism_key": p.get("mechanism_key"),
                    "repository": p.get("repository"),
                    "verdict": p.get("verdict"),
                    "confidence": p.get("confidence"),
                    "strict_confirmed": p.get("strict_confirmed"),
                    "source_tier": p.get("source_tier"),
                    "release_gate": m.get("release_gate"),
                }
        for pid in m.get("public_ids_keep") or []:
            g = extract_ghsa(pid)
            if g and g not in baseline_48:
                baseline_48[g] = {
                    "ordinal": m["ordinal"],
                    "from": "public_ids_keep",
                    "release_gate": m.get("release_gate"),
                }

    # Canonical admitted GHSA identities as a cross-check
    ledger_admitted = set()
    for row in jsonl(LEDGER):
        if not isinstance(row, dict):
            continue
        counting = row.get("counting") or {}
        if counting.get("fp211_released_publication_admitted") is True:
            for pid in (row.get("public_ids") or []) + (row.get("declared_public_ids") or []):
                g = extract_ghsa(pid)
                if g:
                    ledger_admitted.add(g)
            g = extract_ghsa(row.get("primary_id") or "")
            if g:
                ledger_admitted.add(g)

    if len(baseline_48) != 48:
        # public_cases may have 1:1 GHSA for 48 mechs; extra aliases must not inflate
        # Keep only first-party GHSA from public_cases rows tied to the 48 mechs
        slim = {}
        for m in strict_released_mechs:
            pubs = pub_by_ord.get(m["ordinal"], [])
            ghsa_rows = [p for p in pubs if extract_ghsa(p.get("case_id") or "")]
            if len(ghsa_rows) == 1:
                cid = extract_ghsa(ghsa_rows[0]["case_id"])
                slim[cid] = baseline_48[cid]
            elif len(ghsa_rows) > 1:
                for p in ghsa_rows:
                    cid = extract_ghsa(p["case_id"])
                    slim[cid] = baseline_48[cid]
        baseline_48 = slim

    # If still not 48, use public_cases: CONFIRM + strict_confirmed + HIGH with matching mech release PASS
    if len(baseline_48) != 48:
        alt = {}
        for p in cases_pub:
            if p.get("verdict") != "CONFIRM" or not p.get("strict_confirmed"):
                continue
            m = mech_by_ord.get(p["ordinal"])
            if not m:
                continue
            if m.get("confidence") != "HIGH":
                continue
            if m.get("release_gate") != "PASS":
                continue
            cid = extract_ghsa(p.get("case_id") or "")
            if cid:
                alt[cid] = {
                    "ordinal": p["ordinal"],
                    "mechanism_key": p.get("mechanism_key"),
                    "repository": p.get("repository"),
                    "release_gate": m.get("release_gate"),
                }
        baseline_48 = alt

    final_rows = jsonl(FINAL_CASES)
    if len(final_rows) != 32:
        failures.append({"kind": "COUNT", "path": str(FINAL_CASES), "expected": 32, "actual": len(final_rows)})
    final_32 = {}
    for r in final_rows:
        cid = extract_ghsa(r.get("case_id") or "")
        if not cid:
            failures.append({"kind": "SCHEMA", "path": str(FINAL_CASES), "reason": "missing case_id"})
            continue
        final_32[cid] = {
            "final_verdict": r.get("final_verdict"),
            "lane": r.get("lane"),
            "mechanism_key": r.get("mechanism_key"),
            "repository": r.get("repository"),
        }

    scan_files = list_scan_files()
    file_hashes = []
    scanned_result = 0
    scanned_cases = 0
    case_lines_total = 0
    case_lines_parsed = 0
    positive_hits: list[dict] = []
    skipped_non_proposal = Counter()
    packet_meta: dict[str, dict] = {}
    packets_seen = set()
    later_nonpositive: dict[str, list[dict]] = defaultdict(list)

    for path in scan_files:
        rel = str(path.relative_to(ROOT))
        packet = packet_of(path)
        packets_seen.add(packet)
        packet_dir = ROOT / packet
        if packet not in packet_meta:
            packet_meta[packet] = load_packet_meta(packet, packet_dir)
        try:
            raw = path.read_bytes()
        except Exception as e:
            failures.append({"kind": "READ", "path": rel, "error": type(e).__name__})
            continue
        file_hashes.append({"path": rel, "sha256": sha256_bytes(raw), "bytes": len(raw)})
        if path.name == "result.json":
            scanned_result += 1
            try:
                obj = json.loads(raw.decode("utf-8"))
            except Exception as e:
                failures.append({"kind": "PARSE", "path": rel, "error": type(e).__name__})
                continue
            if not isinstance(obj, dict):
                failures.append({"kind": "SCHEMA", "path": rel, "reason": "result.json is not an object"})
                continue
            # Structured proposal lists with IDs only
            for key in (
                "pass_proposals",
                "proposed_pass_ids",
                "PASS_proposals",
                "accepted_net_new_candidates",
                "accepted_baseline_revalidations",
                "countable_first_party_ghsa_ids",
                "keep_ids",
                "keep_proposals",
            ):
                val = obj.get(key)
                if val is None:
                    continue
                items = val if isinstance(val, list) else []
                for item in items:
                    if isinstance(item, str):
                        g = extract_ghsa(item)
                        if not g:
                            skipped_non_proposal["result_id_not_ghsa"] += 1
                            continue
                        positive_hits.append(
                            {
                                "case_id": g,
                                "source_path": rel,
                                "packet": packet,
                                "source_kind": "result.json:" + key,
                                "verdict": "PROPOSED_PASS" if "pass" in key.lower() or "accept" in key.lower() or "countable" in key.lower() else "KEEP",
                                "verdict_key": key,
                                "repository": None,
                                "mechanism_key": None,
                                "candidate_set": [],
                                "minimum_fix_set": [],
                                "gates": {},
                                "contribution_class": None,
                                "scope_statement": None,
                                "row_kind": "RESULT_LIST",
                            }
                        )
                    elif isinstance(item, dict):
                        g = first_ghsa_from_obj(item)
                        if not g:
                            skipped_non_proposal["result_dict_no_ghsa"] += 1
                            continue
                        if is_envelope(item):
                            skipped_non_proposal["source_envelope"] += 1
                            continue
                        v, vk = row_verdict(item)
                        if v is None:
                            v, vk = "PROPOSED_PASS", key
                        if not is_positive(v):
                            skipped_non_proposal["result_dict_nonpositive"] += 1
                            continue
                        positive_hits.append(
                            {
                                "case_id": g,
                                "source_path": rel,
                                "packet": packet,
                                "source_kind": "result.json:" + key,
                                "verdict": v,
                                "verdict_key": vk,
                                "repository": item.get("repository"),
                                "mechanism_key": item.get("mechanism_key"),
                                "candidate_set": item.get("candidate_set") or [],
                                "minimum_fix_set": item.get("minimum_fix_set") or [],
                                "gates": gate_map(item),
                                "contribution_class": item.get("contribution_class") or item.get("causal_class"),
                                "scope_statement": item.get("scope_statement") or item.get("note"),
                                "row_kind": item.get("row_kind") or "RESULT_DICT",
                            }
                        )
                    else:
                        skipped_non_proposal["result_list_non_id"] += 1
            # Do not treat numeric PASS counts as proposals
            counts = obj.get("counts") or obj.get("case_verdicts") or {}
            if isinstance(counts, dict):
                npass = counts.get("PASS") or counts.get("ACCEPT") or counts.get("KEEP")
                if isinstance(npass, int) and npass and not any(
                    h["source_path"] == rel for h in positive_hits
                ):
                    skipped_non_proposal["count_without_row_ids"] += 1
                    failures.append(
                        {
                            "kind": "SCHEMA_NOTE",
                            "path": rel,
                            "reason": "PASS/ACCEPT/KEEP count present without matching ID list on this object; IDs must come from cases.jsonl or named proposal lists",
                            "count": npass,
                        }
                    )
        elif path.name == "cases.jsonl":
            scanned_cases += 1
            text = raw.decode("utf-8")
            for lineno, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                case_lines_total += 1
                try:
                    row = json.loads(line)
                except Exception as e:
                    failures.append(
                        {
                            "kind": "PARSE",
                            "path": rel,
                            "line": lineno,
                            "error": type(e).__name__,
                        }
                    )
                    continue
                case_lines_parsed += 1
                if not isinstance(row, dict):
                    failures.append({"kind": "SCHEMA", "path": rel, "line": lineno, "reason": "non-object"})
                    continue
                if is_envelope(row):
                    skipped_non_proposal["source_envelope"] += 1
                    continue
                if is_routing_only(row):
                    skipped_non_proposal["routing_signal"] += 1
                    continue
                v, vk = row_verdict(row)
                g = first_ghsa_from_obj(row)
                if v is None:
                    skipped_non_proposal["no_verdict"] += 1
                    continue
                if not is_positive(v):
                    skipped_non_proposal["nonpositive"] += 1
                    if g:
                        later_nonpositive[g].append(
                            {
                                "packet": packet,
                                "source_path": rel,
                                "verdict": v,
                                "line": lineno,
                            }
                        )
                    continue
                if not g:
                    skipped_non_proposal["positive_without_ghsa"] += 1
                    failures.append(
                        {
                            "kind": "SCHEMA",
                            "path": rel,
                            "line": lineno,
                            "reason": "positive verdict without GHSA case_id",
                            "verdict": v,
                        }
                    )
                    continue
                # CVE-only primary is not a proposal
                primary = row.get("primary_id") or row.get("case_id")
                if isinstance(primary, str) and primary.upper().startswith("CVE-") and not extract_ghsa(primary):
                    skipped_non_proposal["cve_alias_primary"] += 1
                    continue
                positive_hits.append(
                    {
                        "case_id": g,
                        "source_path": rel,
                        "packet": packet,
                        "source_kind": "cases.jsonl",
                        "source_line": lineno,
                        "verdict": v,
                        "verdict_key": vk,
                        "repository": row.get("repository"),
                        "mechanism_key": row.get("mechanism_key"),
                        "candidate_set": row.get("candidate_set") or [],
                        "carrier_set": row.get("carrier_set") or [],
                        "minimum_fix_set": row.get("minimum_fix_set") or [],
                        "gates": gate_map(row),
                        "contribution_class": row.get("contribution_class") or row.get("causal_class"),
                        "scope_statement": row.get("scope_statement"),
                        "row_kind": row.get("row_kind") or "CASE_ROW",
                        "lane": row.get("lane"),
                        "ordinal": row.get("ordinal"),
                    }
                )

    # Dedup hits. Authority uses terminal packets only; in-flight PASS ids are listed separately.
    terminal_hits = []
    inflight_hits = []
    for h in positive_hits:
        meta = packet_meta.get(h["packet"]) or load_packet_meta(h["packet"], ROOT / h["packet"])
        packet_meta[h["packet"]] = meta
        h["packet_terminal"] = bool(meta.get("terminal"))
        h["packet_role"] = meta.get("role")
        h["packet_when"] = meta.get("when_raw")
        if meta.get("forced_inflight") or not meta.get("terminal"):
            inflight_hits.append(h)
        else:
            terminal_hits.append(h)

    by_id: dict[str, list[dict]] = defaultdict(list)
    for h in terminal_hits:
        by_id[h["case_id"]].append(h)
    inflight_by_id: dict[str, list[dict]] = defaultdict(list)
    for h in inflight_hits:
        inflight_by_id[h["case_id"]].append(h)

    set_all = set(by_id)
    set_48 = set(baseline_48)
    set_32 = set(final_32)
    diff = sorted(set_all - set_48 - set_32)
    inflight_ids = sorted(inflight_by_id)
    inflight_proposal_ids = sorted(set(inflight_by_id) - set_48 - set_32)

    unabsorbed_rows = []
    class_counts = Counter()
    genuine = []
    for cid in diff:
        sources = by_id[cid]
        cases_sources = [s for s in sources if s["source_kind"] == "cases.jsonl"]
        use = cases_sources or sources
        best = max(
            use,
            key=lambda s: (
                1 if seven_all_pass(s.get("gates") or {}) else 0,
                1 if s.get("mechanism_key") else 0,
                1 if s.get("candidate_set") else 0,
                role_rank(review_role(s["packet"])),
                s.get("packet_when") or "",
            ),
        )
        in_48 = cid in set_48
        in_32 = cid in set_32
        later = later_nonpositive.get(cid) or []
        superseding = []
        for x in later:
            if x["verdict"] not in NONPOSITIVE_DOWNGRADE:
                continue
            neg_meta = packet_meta.get(x["packet"])
            if not neg_meta:
                continue
            if not is_terminal_packet(neg_meta):
                continue
            for src in use:
                pass_meta = packet_meta.get(src["packet"])
                if not pass_meta:
                    continue
                if later_redteam_or_review_downgrade(pass_meta, neg_meta, x["verdict"]):
                    superseding.append(x)
                    break
        klass, why = classify_omission(
            case_id=cid,
            in_48=in_48,
            in_32=in_32,
            sources=use,
            packet_status={p: packet_meta[p]["status"] for p in packet_meta},
        )
        if superseding and klass == "GENUINE_UNABSORBED":
            bits = sorted({f"{x['packet']}:{x['verdict']}" for x in superseding})
            klass = "SUPERSEDED"
            why = (
                "A later terminal red-team or independent-review downgrade supersedes an earlier "
                f"PASS/KEEP ({'; '.join(bits)}). Older worker/inventory NARROW is not used as override."
            )
        mk = best.get("mechanism_key")
        mech_dup_32 = False
        if mk:
            for _fid, meta32 in final_32.items():
                if meta32.get("mechanism_key") and meta32["mechanism_key"] == mk:
                    mech_dup_32 = True
                    break
        if mech_dup_32 and klass == "GENUINE_UNABSORBED":
            klass = "DUPLICATE_MECHANISM"
            why = f"mechanism_key {mk} already present in the 32-row final review; duplicate mechanism is not a new proposal."
        class_counts[klass] += 1
        row = {
            "schema_version": 1,
            "row_kind": "PROPOSAL_CENSUS",
            "case_id": cid,
            "census_class": klass,
            "omission_reason": why,
            "in_strict_released_48": in_48,
            "in_final_review_32": in_32,
            "source_terminal_status": sorted({packet_meta[s["packet"]]["status"] for s in sources}),
            "packets": sorted({s["packet"] for s in sources}),
            "source_paths": sorted({s["source_path"] for s in sources}),
            "source_verdicts": sorted({s["verdict"] for s in sources}),
            "repository": best.get("repository"),
            "mechanism_key": best.get("mechanism_key"),
            "contribution_class": best.get("contribution_class"),
            "candidate_set": best.get("candidate_set") or [],
            "carrier_set": best.get("carrier_set") or [],
            "minimum_fix_set": best.get("minimum_fix_set") or [],
            "gates": best.get("gates") or {},
            "seven_gates_pass": seven_all_pass(best.get("gates") or {}),
            "scope_statement": best.get("scope_statement"),
            "best_source_path": best.get("source_path"),
            "best_source_kind": best.get("best_source_kind") or best.get("source_kind"),
            "best_verdict": best.get("verdict"),
            "best_verdict_key": best.get("verdict_key"),
            "occurrence_count": len(sources),
            "later_nonpositive": superseding,
            "authority": "ended_at_or_frozen_at_plus_review_role",
            "counting_unit": "first-party GHSA identity",
            "causal_admission": False,
            "worker_pass_is_proposal_only": True,
        }
        unabsorbed_rows.append(row)
        if klass == "GENUINE_UNABSORBED":
            genuine.append(row)

    inflight_rows = []
    for cid in inflight_ids:
        srcs = inflight_by_id[cid]
        best_if = max(srcs, key=lambda s: (1 if seven_all_pass(s.get("gates") or {}) else 0, s.get("packet") or ""))
        inflight_rows.append(
            {
                "schema_version": 1,
                "row_kind": "PROPOSAL_CENSUS_IN_FLIGHT",
                "case_id": cid,
                "census_class": "IN_FLIGHT_EXCLUDED",
                "omission_reason": "Source packet is still in-flight (narupa/narupb/netred or nonterminal). Listed separately; not counted in genuine_unabsorbed_count.",
                "in_strict_released_48": cid in set_48,
                "in_final_review_32": cid in set_32,
                "packets": sorted({s["packet"] for s in srcs}),
                "source_paths": sorted({s["source_path"] for s in srcs}),
                "source_verdicts": sorted({s["verdict"] for s in srcs}),
                "repository": best_if.get("repository"),
                "mechanism_key": best_if.get("mechanism_key"),
                "candidate_set": best_if.get("candidate_set") or [],
                "minimum_fix_set": best_if.get("minimum_fix_set") or [],
                "gates": best_if.get("gates") or {},
                "seven_gates_pass": seven_all_pass(best_if.get("gates") or {}),
                "best_source_path": best_if.get("source_path"),
                "best_verdict": best_if.get("verdict"),
                "counting_unit": "first-party GHSA identity",
                "causal_admission": False,
            }
        )

    leftover = set_all - set_48 - set_32 - {r["case_id"] for r in unabsorbed_rows}
    absorbed_48_hits = sorted(set_all & set_48)
    absorbed_32_hits = sorted(set_all & set_32)

    # Bind hashes
    frozen = {
        "CONTRACT.md": sha256_path(CONTRACT),
        "baseline.json": sha256_path(BASELINE),
        "final_mechanisms.jsonl": sha256_path(MECHS),
        "public_cases.jsonl": sha256_path(PUBLIC),
        "canonical_ledger.jsonl": sha256_path(LEDGER),
        "final_candidate_review_codex/cases.jsonl": sha256_path(FINAL_CASES),
        "final_candidate_review_codex/result.json": sha256_path(FINAL_RESULT),
    }
    expected = {
        "CONTRACT.md": baseline["inputs"]["contract_sha256"],
        "final_mechanisms.jsonl": baseline["inputs"]["fp211_final_mechanisms_sha256"],
        "public_cases.jsonl": baseline["inputs"]["fp211_public_cases_sha256"],
        "canonical_ledger.jsonl": baseline["inputs"]["fp211_canonical_ledger_sha256"],
    }
    for k, exp in expected.items():
        if frozen[k] != exp:
            failures.append({"kind": "HASH_MISMATCH", "role": k, "expected": exp, "actual": frozen[k]})

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    genuine_ids = [r["case_id"] for r in genuine]
    inflight_packets = sorted(
        p for p, m in packet_meta.items() if m.get("forced_inflight") or not m.get("terminal")
    )
    status = "CENSUS_IN_FLIGHT_HOLD"
    if leftover:
        status = "CENSUS_CONSERVATION_FAIL"

    result = {
        "schema_version": 1,
        "task": "proposal-census",
        "lane": "herdr-260813-ghsa200-proposal-census-grok46-low",
        "status": status,
        "language": "en",
        "causal_admission": False,
        "claim_boundary": "Census only. Worker PASS/ACCEPT/KEEP is a proposal, never admission. This packet does not promote causality or rebuild the canonical ledger.",
        "counting_unit": "first-party GHSA identity",
        "frozen_at_utc": now,
        "input_hashes": frozen,
        "hash_roles": {
            "contract": frozen["CONTRACT.md"],
            "fp211_final_mechanisms": frozen["final_mechanisms.jsonl"],
            "fp211_public_cases": frozen["public_cases.jsonl"],
            "fp211_canonical_ledger": frozen["canonical_ledger.jsonl"],
            "final_review_cases": frozen["final_candidate_review_codex/cases.jsonl"],
            "final_review_result": frozen["final_candidate_review_codex/result.json"],
            "leader_baseline": frozen["baseline.json"],
        },
        "scan": {
            "files_scanned": len(scan_files),
            "result_json_files": scanned_result,
            "cases_jsonl_files": scanned_cases,
            "case_lines_total": case_lines_total,
            "case_lines_parsed": case_lines_parsed,
            "packets": len(packets_seen),
            "file_hashes": file_hashes,
        },
        "conservation": {
            "positive_ghsa_ids": len(set_all),
            "positive_hit_rows": len(positive_hits),
            "baseline_48": len(set_48),
            "final_32": len(set_32),
            "intersection_positive_and_48": len(set_all & set_48),
            "intersection_positive_and_32": len(set_all & set_32),
            "unabsorbed_unique_ids": len(unabsorbed_rows),
            "leftover_ids": sorted(leftover),
            "id_conservation": not leftover and len(unabsorbed_rows) == len(diff),
            "formula": "|positives| = |pos∩48| + |pos∩32 - 48| + |unabsorbed| with unabsorbed = positives - 48 - 32",
            "pos_minus_48_minus_32": len(diff),
            "arithmetic_check": {
                "pos_intersect_48": len(set_all & set_48),
                "pos_intersect_32_not_48": len((set_all & set_32) - set_48),
                "unabsorbed": len(diff),
                "sum": len(set_all & set_48) + len((set_all & set_32) - set_48) + len(diff),
                "equals_positive_ids": (
                    len(set_all & set_48) + len((set_all & set_32) - set_48) + len(diff) == len(set_all)
                ),
            },
            "baseline_48_without_worker_positive_row": sorted(set_48 - set_all),
            "cases_jsonl_terminal_unabsorbed": len(unabsorbed_rows),
            "cases_jsonl_inflight_excluded_rows": len(
                [r for r in inflight_rows if r["case_id"] not in set_48 and r["case_id"] not in set_32]
            ),
        },
        "baseline_48_ids": sorted(set_48),
        "final_32_ids": sorted(set_32),
        "ledger_admitted_ghsa_count": len(ledger_admitted),
        "ledger_admitted_vs_48_note": "Canonical admitted GHSA aliases may exceed 48 because aliases are not counting units; the comparison set (a) is 48 first-party GHSA case ids bound to CONFIRM/HIGH + release_gate PASS.",
        "positive_ids_absorbed_by_48": absorbed_48_hits,
        "positive_ids_absorbed_by_32": absorbed_32_hits,
        "census_class_counts": dict(class_counts),
        "genuine_unabsorbed_count": len(genuine),
        "genuine_unabsorbed_count_is_final": False,
        "genuine_unabsorbed_ids": genuine_ids,
        "in_flight": {
            "excluded_until_terminal": True,
            "forced_packets": [
                "autoresearch/herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh",
                "autoresearch/herdr-260813-ghsa200-narrow-recovery-b-grok46-high",
                "autoresearch/herdr-260813-ghsa200-netnew22-redteam-grok46-xhigh",
            ],
            "nonterminal_or_forced_packets": inflight_packets,
            "positive_ids_all": inflight_ids,
            "proposal_ids_not_in_48_or_32": inflight_proposal_ids,
            "note": "narupa/narupb/netred remain IN_FLIGHT_EXCLUDED. Their PASS/KEEP ids are listed here and are not added to genuine_unabsorbed_count.",
        },
        "regression": {
            "recovery_ids_old_narrow_must_not_override": list(REGRESSION_RECOVERY_IDS),
            "rule": "Later independent gate-closing PASS is not superseded by older upgrade-b or remediation NARROW.",
            "tested": True,
        },
        "packet_authority": {
            p: {
                "status": m.get("status"),
                "terminal": m.get("terminal"),
                "forced_inflight": m.get("forced_inflight"),
                "role": m.get("role"),
                "when": m.get("when_raw"),
            }
            for p, m in sorted(packet_meta.items())
        },
        "skipped_non_proposal": dict(skipped_non_proposal),
        "parse_schema_failures": failures,
        "parse_schema_failure_count": len(failures),
        "did_not_edit_tracked_or_canonical": True,
        "did_not_commit_or_push": True,
        "english_only": True,
    }

    cases_path = OUT / "cases.jsonl"
    with cases_path.open("w", encoding="utf-8") as f:
        for row in unabsorbed_rows:
            f.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")
        for row in inflight_rows:
            if row["case_id"] in set_48 or row["case_id"] in set_32:
                continue
            f.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")

    result["artifact_hashes"] = {
        "cases.jsonl": sha256_path(cases_path),
    }
    (OUT / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # report
    lines = []
    lines.append("# GHSA proposal census")
    lines.append("")
    lines.append("## Verdict first")
    lines.append("")
    if genuine:
        lines.append(
            f"**{len(genuine)} terminal genuine unabsorbed first-party GHSA proposal(s)** (not a final count). In-flight packets narupa/narupb/netred are excluded until terminal. Census only; not admission."
        )
    else:
        lines.append(
            "**Zero terminal genuine unabsorbed first-party GHSA proposals among terminal packets.** This is not a final count: in-flight narupa/narupb/netred proposal ids are listed separately."
        )
    lines.append("")
    lines.append(
        f"`genuine_unabsorbed_count_is_final` is **false**. Scanned **{len(scan_files)}** files ({scanned_result} `result.json`, {scanned_cases} `cases.jsonl`) across **{len(packets_seen)}** packets. Parsed **{case_lines_parsed}/{case_lines_total}** case lines. Terminal positive GHSA ids: **{len(set_all)}**. Terminal set difference vs 48 and 32: **{len(diff)}**. ID conservation: **{result['conservation']['id_conservation']}**. Arithmetic: {result['conservation']['arithmetic_check']['pos_intersect_48']} + {result['conservation']['arithmetic_check']['pos_intersect_32_not_48']} + {result['conservation']['arithmetic_check']['unabsorbed']} = {result['conservation']['arithmetic_check']['sum']}."
    )
    lines.append("")
    lines.append("## Comparison sets")
    lines.append("")
    lines.append(f"- (a) Strict released baseline: **{len(set_48)}** first-party GHSA ids (CONFIRM/HIGH and `release_gate=PASS` on fp211 mechanisms, bound through `public_cases.jsonl`).")
    lines.append(f"- (b) Final candidate review: **{len(set_32)}** rows in `herdr-260813-ghsa200-final-candidate-review-codex/cases.jsonl`.")
    lines.append("")
    lines.append("## Census class counts (unabsorbed = positives − 48 − 32)")
    lines.append("")
    for k in sorted(class_counts):
        lines.append(f"- `{k}`: {class_counts[k]}")
    if not class_counts:
        lines.append("- none")
    lines.append("")
    lines.append("## Genuine unabsorbed")
    lines.append("")
    if not genuine:
        lines.append(
            "Proof of zero: `positives - baseline_48 - final_32` contains no row classified `GENUINE_UNABSORBED`. Remaining difference rows, if any, fail the genuine test (missing seven-gate closure, snapshot duplicate, duplicate mechanism_key, commit-only, partial packet without gates, or unsupported schema)."
        )
    else:
        for r in genuine:
            lines.append(
                f"- `{r['case_id']}` packet `{r['best_source_path']}` status `{','.join(r['source_terminal_status'])}` verdict `{r['best_verdict']}` mechanism `{r.get('mechanism_key')}` candidate `{r.get('candidate_set')}` fix `{r.get('minimum_fix_set')}` — {r['omission_reason']}"
            )
    lines.append("")
    lines.append("## In-flight excluded (not counted)")
    lines.append("")
    lines.append("Forced IN_FLIGHT_EXCLUDED until terminal: `narrow-recovery-a-grok46-xhigh` (narupa), `narrow-recovery-b-grok46-high` (narupb), `netnew22-redteam-grok46-xhigh` (netred). Other nonterminal packets are also excluded from the terminal positive set.")
    lines.append("")
    if inflight_proposal_ids:
        lines.append("In-flight proposal ids absent from both the 48 and the 32:")
        for cid in inflight_proposal_ids:
            packs = ",".join(sorted({s["packet"] for s in inflight_by_id[cid]}))
            lines.append(f"- `{cid}` from `{packs}`")
    else:
        lines.append("No in-flight proposal ids outside the 48 and 32.")
    lines.append("")
    lines.append("Regression: `GHSA-F38V-77QJ-H4JQ`, `GHSA-G3XQ-3GMV-QQ8G`, and `GHSA-PV2J-RGHR-V5R9` are not superseded by older upgrade-b or remediation NARROW if a later independent recovery review closes gates. Those packets are currently in-flight, so the ids appear in the in-flight list rather than as a final genuine count.")
    lines.append("")
    lines.append("## Other terminal difference rows")
    lines.append("")
    others = [r for r in unabsorbed_rows if r["census_class"] != "GENUINE_UNABSORBED"]
    if not others:
        lines.append("None.")
    else:
        for r in others:
            lines.append(
                f"- `{r['case_id']}` `{r['census_class']}` `{r['best_source_path']}` `{r['best_verdict']}` — {r['omission_reason']}"
            )
    lines.append("")
    lines.append("## Parse / schema failures")
    lines.append("")
    if not failures:
        lines.append("None.")
    else:
        lines.append(f"{len(failures)} notes/failures:")
        for item in failures[:80]:
            lines.append(f"- `{json.dumps(item, sort_keys=True)}`")
        if len(failures) > 80:
            lines.append(f"- … {len(failures) - 80} more in result.json")
    lines.append("")
    lines.append("## Frozen hashes")
    lines.append("")
    for k, v in sorted(frozen.items()):
        lines.append(f"- `{k}`: `{v}`")
    lines.append("")
    lines.append("## Non-proposals excluded")
    lines.append("")
    lines.append("Source envelopes, routing signals, CVE-primary rows, counts without row IDs, and duplicate snapshot copies were not treated as proposals. See `skipped_non_proposal` in result.json.")
    lines.append("")
    (OUT / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    replay = """# Replay (fail-fast, deterministic)

set -euo pipefail
ROOT=/home/hanqing/agents/ai-slop
OUT=$ROOT/autoresearch/herdr-260813-ghsa200-proposal-census-grok46-low
test -f $ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
root = Path("/home/hanqing/agents/ai-slop")
paths = {
  "contract": root/"autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md",
  "baseline": root/"autoresearch/orchestrator-260813-ghsa200-leader/baseline.json",
  "mechs": root/"autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl",
  "public": root/"autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl",
  "ledger": root/"autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl",
  "final_cases": root/"autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/cases.jsonl",
}
import json
b = json.loads(paths["baseline"].read_text())
got = {k: sha256(p.read_bytes()).hexdigest() for k,p in paths.items()}
exp = b["inputs"]
assert got["contract"] == exp["contract_sha256"], (got["contract"], exp["contract_sha256"])
assert got["mechs"] == exp["fp211_final_mechanisms_sha256"]
assert got["public"] == exp["fp211_public_cases_sha256"]
assert got["ledger"] == exp["fp211_canonical_ledger_sha256"]
n = sum(1 for line in paths["final_cases"].read_text().splitlines() if line.strip())
assert n == 32, n
print("frozen-hash-and-32-row-check: PASS")
PY
python3 $OUT/census.py
test -f $OUT/result.json
test -f $OUT/cases.jsonl
test -f $OUT/report.md
python3 - <<'PY'
import json
from pathlib import Path
out = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-proposal-census-grok46-low")
r = json.loads((out/"result.json").read_text())
assert r["conservation"]["id_conservation"] is True
assert r["conservation"]["baseline_48"] == 48
assert r["conservation"]["final_32"] == 32
assert r["conservation"]["arithmetic_check"]["equals_positive_ids"] is True
assert r["genuine_unabsorbed_count_is_final"] is False
assert r["in_flight"]["excluded_until_terminal"] is True
assert r["regression"]["tested"] is True
for cid in ("GHSA-F38V-77QJ-H4JQ", "GHSA-G3XQ-3GMV-QQ8G", "GHSA-PV2J-RGHR-V5R9"):
    assert cid in r["in_flight"]["proposal_ids_not_in_48_or_32"] or cid in r["in_flight"]["positive_ids_all"]
assert r["scan"]["files_scanned"] == r["scan"]["result_json_files"] + r["scan"]["cases_jsonl_files"]
n = sum(1 for line in (out/"cases.jsonl").read_text().splitlines() if line.strip())
expect = r["conservation"]["cases_jsonl_terminal_unabsorbed"] + r["conservation"]["cases_jsonl_inflight_excluded_rows"]
assert n == expect, (n, expect)
print("census-conservation: PASS")
print("artifact", out)
PY
"""
    (OUT / "replay.txt").write_text(replay, encoding="utf-8")

    # refresh hashes including report/replay/result
    result["artifact_hashes"] = {
        "cases.jsonl": sha256_path(OUT / "cases.jsonl"),
        "report.md": sha256_path(OUT / "report.md"),
        "replay.txt": sha256_path(OUT / "replay.txt"),
        "census.py": sha256_path(OUT / "census.py"),
    }
    (OUT / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"STATUS={status}")
    print(f"scanned_files={len(scan_files)}")
    print(f"baseline_48={len(set_48)}")
    print(f"final_32={len(set_32)}")
    print(f"terminal_positive_ids={len(set_all)}")
    print(f"unabsorbed={len(unabsorbed_rows)}")
    print(f"genuine_not_final={len(genuine)} {genuine_ids}")
    print(f"inflight_proposals={inflight_proposal_ids}")
    print(f"conservation={result['conservation']['id_conservation']}")
    print(f"failures={len(failures)}")
    print(str(OUT))
    return 0 if leftover == set() and result["conservation"]["id_conservation"] else 1


if __name__ == "__main__":
    sys.exit(main())
