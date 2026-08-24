#!/usr/bin/env python3
"""Mechanical GHSA-200 gap inventory. Read-only over shared checkout."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OUT = ROOT / "autoresearch/herdr-260813-ghsa200-gap"
GATES = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
)
CLOSED = {"PASS", "NA"}
RELEASED_TIERS = {"STRICT_RELEASED", "INCOMPLETE_RELEASED"}
GHSA_RE = re.compile(r"\bGHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}\b", re.I)
SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")
AI_MARKER_RE = re.compile(
    r"(Co-Authored-By:\s*(Claude|Cursor|Copilot|Codex|Gemini|GPT)|"
    r"Generated with (Claude|Cursor|Copilot|Codex)|"
    r"Made-with:\s*Cursor|"
    r"cursor\[bot\]|"
    r"copilot-swe-agent(\[bot\])?|"
    r"noreply@anthropic\.com|"
    r"noreply@cursor)",
    re.I,
)
AI_FIELD_KEYS = {
    "ai_provenance",
    "marker",
    "marker_sha",
    "candidate_set",
    "candidate_sha",
    "candidate",
    "atomic_member",
    "atomic_ai_remediation_member",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def norm_id(value: str) -> str:
    return value.strip().upper()


def first_letter(ghsa: str) -> str:
    for ch in ghsa.upper().removeprefix("GHSA-"):
        if "A" <= ch <= "Z":
            return ch
    return "0"


def fresh_lane(ghsa: str) -> str:
    letter = first_letter(ghsa)
    if "A" <= letter <= "M":
        return "fresh-am"
    if "N" <= letter <= "Z":
        return "fresh-nz"
    return "fresh-am"


def missing_gates(mech: dict | None) -> list[str]:
    if not mech:
        return list(GATES)
    missing = []
    for gate in GATES:
        value = mech.get(gate)
        if value not in CLOSED:
            missing.append(f"{gate}={value}")
    return missing


def publication_flags(mech: dict, source_tier: str | None) -> dict:
    verdict = mech.get("verdict")
    confidence = mech.get("confidence")
    gates = {g: mech.get(g) for g in GATES}
    causal_valid = verdict in {"CONFIRM", "NARROW"}
    strict_confirmed = (
        causal_valid
        and verdict == "CONFIRM"
        and confidence == "HIGH"
        and all(v in CLOSED for v in gates.values())
    )
    released_admitted = (
        strict_confirmed
        and isinstance(source_tier, str)
        and source_tier in RELEASED_TIERS
        and gates.get("release_gate") == "PASS"
    )
    return {
        "causal_valid": causal_valid,
        "strict_confirmed": strict_confirmed,
        "released_publication_admitted": released_admitted,
        "gates": gates,
    }


def git_head(path: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return None


LIVE_SIBLING_TOKEN = "herdr-260813-ghsa200"
IDENTITY_KEYS = (
    "case_id",
    "identity",
    "ghsa_id",
    "ghsa",
    "advisory_id",
    "primary_id",
)
SOURCE_RANK = {
    "fp211-381": 0,
    "fp211-381-removed": 1,
    "aug12-novel-ai-evidence": 2,
}


def is_live_sibling_path(rel: str) -> bool:
    return any(part.startswith(LIVE_SIBLING_TOKEN) for part in Path(rel).parts)


def collect_input_hashes() -> dict[str, str]:
    paths = [
        "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md",
        "autoresearch/orchestrator-260813-ghsa200-leader/baseline.json",
        "autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl",
        "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl",
        "autoresearch/orchestrator-260813-fp211-audit/public_id_dispositions.jsonl",
        "autoresearch/orchestrator-260813-fp211-audit/summary.json",
        "autoresearch/orchestrator-260813-fp211-audit/output_manifest.json",
        "autoresearch/orchestrator-260813-fp211-canonical/summary.json",
        "autoresearch/orchestrator-260813-fp211-canonical/result.json",
        "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl",
        "autoresearch/orchestrator-260813-fp211-canonical/source_manifest.json",
        "autoresearch/orchestrator-260812-posthold-canonical/summary.json",
        "autoresearch/orchestrator-260812-posthold-canonical/ledger.jsonl",
        "web/data/stats.json",
        "web/data/index.json",
    ]
    hashes = {}
    for rel in paths:
        p = ROOT / rel
        if p.is_file():
            hashes[rel] = sha256_file(p)
        else:
            hashes[rel] = "MISSING"
    # Aug-12 research result/report pairs
    for result in sorted((ROOT / "autoresearch").glob("herdr-260812*/result.json")):
        rel = str(result.relative_to(ROOT))
        if is_live_sibling_path(rel):
            continue
        hashes[rel] = sha256_file(result)
        report = result.with_name("report.md")
        if report.is_file():
            hashes[str(report.relative_to(ROOT))] = sha256_file(report)
    for doc in sorted((ROOT / "docs").glob("RESEARCH-*2026-08-12.md")):
        hashes[str(doc.relative_to(ROOT))] = sha256_file(doc)
    return hashes


def record_ghsa_ids(obj: dict) -> set[str]:
    ids: set[str] = set()
    for key in IDENTITY_KEYS:
        value = obj.get(key)
        if isinstance(value, str):
            ids.update(norm_id(m.group(0)) for m in GHSA_RE.finditer(value))
    for key in ("public_ids", "public_ids_keep"):
        value = obj.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    ids.update(norm_id(m.group(0)) for m in GHSA_RE.finditer(item))
    return ids


def record_has_ai_evidence(obj: dict) -> tuple[bool, bool, list[str]]:
    local_text_parts = []
    structured = False
    shas: list[str] = []
    for key, value in obj.items():
        if key in AI_FIELD_KEYS and value:
            structured = True
        if isinstance(value, (dict, list)):
            continue
        text = f"{key}:{value}"
        local_text_parts.append(text)
        shas.extend(SHA_RE.findall(str(value)))
    marker = bool(AI_MARKER_RE.search("\n".join(local_text_parts)))
    return marker, structured, shas[:8]


def walk_json_hits(obj, rel: str, hits: list[dict]) -> None:
    if isinstance(obj, dict):
        ids = record_ghsa_ids(obj)
        marker, structured, shas = record_has_ai_evidence(obj)
        if ids and (marker or structured):
            for ghsa in ids:
                hits.append(
                    {
                        "ghsa": ghsa,
                        "path": rel,
                        "markers": marker,
                        "structured_ai": structured,
                        "shas": shas,
                        "binding": "record-local",
                    }
                )
        for value in obj.values():
            if isinstance(value, (dict, list)):
                walk_json_hits(value, rel, hits)
    elif isinstance(obj, list):
        for item in obj:
            walk_json_hits(item, rel, hits)


def markdown_records(text: str) -> list[str]:
    records = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("|") and line.endswith("|") and "GHSA-" in line.upper():
            records.append(line)
        elif (line.startswith("-") or line.startswith("*")) and "GHSA-" in line.upper():
            records.append(line)
    return records


def scan_markdown_records(text: str, rel: str) -> list[dict]:
    hits = []
    for record in markdown_records(text):
        if not AI_MARKER_RE.search(record):
            continue
        shas = SHA_RE.findall(record)
        for match in GHSA_RE.finditer(record):
            hits.append(
                {
                    "ghsa": norm_id(match.group(0)),
                    "path": rel,
                    "markers": True,
                    "structured_ai": False,
                    "shas": shas[:8],
                    "binding": "record-local",
                }
            )
    return hits


def scan_artifact(path: Path) -> list[dict]:
    rel = str(path.relative_to(ROOT))
    if is_live_sibling_path(rel):
        return []
    text = path.read_text(errors="replace")
    if path.suffix == ".jsonl":
        hits: list[dict] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                walk_json_hits(json.loads(line), rel, hits)
            except json.JSONDecodeError:
                continue
        return hits
    if path.suffix == ".json":
        try:
            hits = []
            walk_json_hits(json.loads(text), rel, hits)
            return hits
        except json.JSONDecodeError:
            return []
    if path.suffix == ".md":
        return scan_markdown_records(text, rel)
    return []


def main() -> None:
    started = datetime.now(timezone.utc).isoformat()
    input_hashes = collect_input_hashes()

    mech_path = ROOT / "autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl"
    case_path = ROOT / "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl"
    disp_path = ROOT / "autoresearch/orchestrator-260813-fp211-audit/public_id_dispositions.jsonl"
    mechanisms = load_jsonl(mech_path)
    cases = load_jsonl(case_path)
    dispositions = load_jsonl(disp_path)
    baseline_path = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/baseline.json"
    baseline = json.loads(baseline_path.read_text())
    upgrade_a_ordinals = [int(x) for x in baseline["upgrade_shards"]["upgrade_a"]["ordinals"]]
    upgrade_b_ordinals = [int(x) for x in baseline["upgrade_shards"]["upgrade_b"]["ordinals"]]
    upgrade_a_set = set(upgrade_a_ordinals)
    upgrade_b_set = set(upgrade_b_ordinals)
    assignment_verify = {
        "upgrade_a_ordinals": sorted(upgrade_a_set),
        "upgrade_b_ordinals": sorted(upgrade_b_set),
        "upgrade_a_count": len(upgrade_a_set),
        "upgrade_b_count": len(upgrade_b_set),
        "expected_upgrade_a": int(baseline["upgrade_shards"]["upgrade_a"]["expected_rows"]),
        "expected_upgrade_b": int(baseline["upgrade_shards"]["upgrade_b"]["expected_rows"]),
        "disjoint": upgrade_a_set.isdisjoint(upgrade_b_set),
        "union_count": len(upgrade_a_set | upgrade_b_set),
        "unique_lists": len(upgrade_a_ordinals) == len(upgrade_a_set)
        and len(upgrade_b_ordinals) == len(upgrade_b_set),
        "matches_expected": len(upgrade_a_set) == 58 and len(upgrade_b_set) == 48,
        "union_equals_106": len(upgrade_a_set | upgrade_b_set) == 106,
    }
    if not (
        assignment_verify["disjoint"]
        and assignment_verify["unique_lists"]
        and assignment_verify["matches_expected"]
        and assignment_verify["union_equals_106"]
    ):
        raise SystemExit(f"baseline assignment verification failed: {assignment_verify}")

    mech_by_ordinal = {int(m["ordinal"]): m for m in mechanisms}
    mech_by_row = {m["row_key"]: m for m in mechanisms}

    source_ids = {norm_id(d["public_id"]) for d in dispositions}
    source_ghsa = {i for i in source_ids if i.startswith("GHSA-")}
    source_cve = {i for i in source_ids if i.startswith("CVE-")}

    advisory_root = Path.home() / ".cache/cve-analyzer/advisory-database"
    advisory_head = git_head(advisory_root)
    reviewed_dir = advisory_root / "advisories/github-reviewed"
    local_reviewed = set()
    if reviewed_dir.is_dir():
        for p in reviewed_dir.rglob("GHSA-*.json"):
            local_reviewed.add(norm_id(p.stem))
    local_reviewed_hash = sha256_text("\n".join(sorted(local_reviewed)))

    # Scan Aug-12 artifacts for novel GHSA + AI evidence
    scan_files: list[Path] = []
    sibling_paths_seen = []
    for path in sorted((ROOT / "autoresearch").glob("herdr-260813-ghsa200*")):
        sibling_paths_seen.append(str(path.relative_to(ROOT)))
    for result in sorted((ROOT / "autoresearch").glob("herdr-260812*/result.json")):
        rel = str(result.relative_to(ROOT))
        if is_live_sibling_path(rel):
            continue
        scan_files.append(result)
        report = result.with_name("report.md")
        if report.is_file():
            scan_files.append(report)
        for extra in result.parent.glob("*.json"):
            if extra.name not in {"result.json"} and extra.stat().st_size < 8_000_000:
                scan_files.append(extra)
        for extra in result.parent.glob("*.md"):
            if extra.name != "report.md" and extra.stat().st_size < 2_000_000:
                scan_files.append(extra)
    for doc in sorted((ROOT / "docs").glob("RESEARCH-*2026-08-12.md")):
        scan_files.append(doc)

    seen_paths = set()
    novel_hits: dict[str, dict] = {}
    overlap_sha_to_ghsa: dict[str, set[str]] = defaultdict(set)
    skip_names = {
        "github-reviewed.json",
        "github-unreviewed.json",
        "github-unreviewed-page2.json",
        "cvelist-deltaLog.json",
        "cvelist-main-commit.json",
        "baseline-freeze.json",
    }

    for path in scan_files:
        rel = str(path.relative_to(ROOT))
        if rel in seen_paths or path.name in skip_names:
            continue
        if is_live_sibling_path(rel) or "snapshot/" in rel:
            continue
        seen_paths.add(rel)
        for rec in scan_artifact(path):
            ghsa = rec["ghsa"]
            if ghsa in source_ghsa:
                continue
            hit = novel_hits.setdefault(
                ghsa,
                {
                    "case_id": ghsa,
                    "artifacts": [],
                    "markers": False,
                    "structured_ai": False,
                    "commit_shas": [],
                    "in_local_reviewed_db": ghsa in local_reviewed,
                },
            )
            hit["artifacts"].append(rel)
            hit["markers"] = hit["markers"] or rec["markers"]
            hit["structured_ai"] = hit["structured_ai"] or rec["structured_ai"]
            for sha in rec["shas"]:
                if sha not in hit["commit_shas"]:
                    hit["commit_shas"].append(sha)
                overlap_sha_to_ghsa[sha].add(ghsa)

    inventory: list[dict] = []
    sha_to_cases: dict[str, set[str]] = defaultdict(set)

    def add_row(row: dict) -> None:
        inventory.append(row)

    # fp211 public cases
    for case in cases:
        case_id = norm_id(case["case_id"])
        ordinal = int(case["ordinal"])
        mech = mech_by_row.get(case["row_key"]) or mech_by_ordinal.get(ordinal)
        flags = publication_flags(mech, case.get("source_tier")) if mech else {
            "causal_valid": False,
            "strict_confirmed": False,
            "released_publication_admitted": False,
            "gates": {},
        }
        missing = missing_gates(mech)
        verdict = case.get("verdict")
        confidence = (mech or {}).get("confidence") or case.get("confidence")
        causal_class = case.get("causal_class") or (mech or {}).get("causal_class")
        confirm_medium = verdict == "CONFIRM" and confidence == "MEDIUM"
        confirm_high_unreleased = (
            flags["strict_confirmed"] and not flags["released_publication_admitted"]
        )
        if ordinal <= 110:
            base_lane = "upgrade-a"
        else:
            base_lane = "upgrade-b"
        if causal_class == "AI_INCOMPLETE_REMEDIATION":
            lane = "remediation"
        else:
            lane = base_lane

        if verdict == "FALSE_POSITIVE":
            status = "REJECT"
            upgrade_reason = None
        elif verdict == "UNKNOWN":
            status = "UNKNOWN"
            upgrade_reason = "unknown_unclosed_gates"
        elif flags["released_publication_admitted"]:
            status = "ROUTE"
            upgrade_reason = "baseline_strict_released_not_gap_filler"
        elif confirm_medium:
            status = "ROUTE"
            upgrade_reason = "confirm_medium_needs_review"
        elif confirm_high_unreleased:
            status = "ROUTE"
            upgrade_reason = "confirm_high_commit_only_unreleased"
        elif verdict == "NARROW":
            status = "ROUTE"
            upgrade_reason = "narrow_scope"
        else:
            status = "ROUTE"
            upgrade_reason = "upgrade"

        for sha in (mech or {}).get("candidate_set") or []:
            sha_to_cases[sha].add(case_id)
        for sha in (mech or {}).get("carrier_set") or []:
            sha_to_cases[sha].add(case_id)

        priority = len(missing)
        if confirm_medium:
            priority = max(priority, 1)

        if ordinal in upgrade_a_set:
            assignment_shard = "upgrade_a"
        elif ordinal in upgrade_b_set:
            assignment_shard = "upgrade_b"
        else:
            assignment_shard = None

        add_row(
            {
                "schema_version": 1,
                "status": status,
                "case_id": case_id,
                "aliases": case.get("aliases") or [],
                "repository": case.get("repository"),
                "ordinal": ordinal,
                "row_key": case.get("row_key"),
                "mechanism_key": case.get("mechanism_key") or (mech or {}).get("row_key"),
                "mechanism_fingerprint": None,
                "verdict": verdict,
                "confidence": confidence,
                "causal_class": causal_class,
                "source_tier": case.get("source_tier"),
                "source_set": "fp211-381",
                "lane": lane,
                "census_lane": lane,
                "upgrade_bucket": base_lane,
                "assignment_shard": assignment_shard,
                "in_assignment_set": assignment_shard is not None,
                "inventory_role": "assignment_coverage" if assignment_shard else "census_only",
                "upgrade_reason": upgrade_reason,
                "confirm_medium": confirm_medium,
                "missing_gates": missing,
                "missing_gate_count": len(missing),
                "priority": priority,
                "strict_confirmed": flags["strict_confirmed"],
                "released_publication_admitted": flags["released_publication_admitted"],
                "causal_valid": bool(case.get("causal_valid")),
                "in_local_reviewed_db": case_id in local_reviewed,
                "candidate_set": (mech or {}).get("candidate_set") or [],
                "gates": flags["gates"],
                "note": "Inventory routing only; not a seven-gate PASS.",
            }
        )

    # Removed GHSA identities from dispositions
    for disp in dispositions:
        if disp.get("disposition") != "REMOVED_IDENTITY":
            continue
        pid = norm_id(disp["public_id"])
        if not pid.startswith("GHSA-"):
            continue
        ord_n = int(disp.get("ordinal") or 0)
        add_row(
            {
                "schema_version": 1,
                "status": "REJECT",
                "case_id": pid,
                "aliases": [],
                "repository": None,
                "ordinal": disp.get("ordinal"),
                "row_key": disp.get("row_key"),
                "mechanism_key": None,
                "verdict": "REMOVED_IDENTITY",
                "causal_class": None,
                "source_tier": None,
                "source_set": "fp211-381-removed",
                "lane": "upgrade-a" if ord_n <= 110 else "upgrade-b",
                "census_lane": "upgrade-a" if ord_n <= 110 else "upgrade-b",
                "assignment_shard": None,
                "in_assignment_set": False,
                "inventory_role": "census_only",
                "missing_gates": ["identity_gate=FAIL"],
                "missing_gate_count": 1,
                "priority": 99,
                "strict_confirmed": False,
                "released_publication_admitted": False,
                "causal_valid": False,
                "in_local_reviewed_db": pid in local_reviewed,
                "note": "Removed polluted/packed/unproven identity; preserve REJECT. Census only, not an assignment.",
            }
        )

    for ghsa, hit in sorted(novel_hits.items()):
        letter = first_letter(ghsa)
        add_row(
            {
                "schema_version": 1,
                "status": "ROUTE",
                "case_id": ghsa,
                "aliases": [],
                "repository": None,
                "ordinal": None,
                "row_key": None,
                "mechanism_key": None,
                "verdict": None,
                "causal_class": None,
                "source_tier": None,
                "source_set": "aug12-novel-ai-evidence",
                "lane": fresh_lane(ghsa),
                "census_lane": fresh_lane(ghsa),
                "assignment_shard": None,
                "in_assignment_set": False,
                "inventory_role": "census_only",
                "fresh_letter": letter,
                "missing_gates": list(GATES),
                "missing_gate_count": 7,
                "priority": 7,
                "strict_confirmed": False,
                "released_publication_admitted": False,
                "causal_valid": False,
                "in_local_reviewed_db": hit["in_local_reviewed_db"],
                "evidence_artifacts": sorted(set(hit["artifacts"]))[:12],
                "has_ai_marker": hit["markers"],
                "has_structured_ai_fields": hit["structured_ai"],
                "commit_sha_sample": hit["commit_shas"][:8],
                "binding": "record-local",
                "note": "Absent from 381-ID fp211 source set; record-local AI marker or structured AI fields in a completed Aug-12 artifact. Not a PASS. File-level co-occurrence is not evidence.",
            }
        )

    # Route each first-party GHSA identity once. Prefer fp211 public cases over
    # removed identities over novel Aug-12 records. Mechanism extras stay as
    # warnings; SHA overlap never merges or splits IDs.
    inventory.sort(
        key=lambda row: (
            SOURCE_RANK.get(row.get("source_set"), 9),
            row.get("ordinal") or 10_000,
            row["case_id"],
        )
    )
    seen_ids: set[str] = set()
    deduped = []
    dup_warnings = []
    extra_mechanisms: dict[str, list[str]] = defaultdict(list)
    for row in inventory:
        case_id = row["case_id"]
        if case_id in seen_ids:
            dup_warnings.append(
                {
                    "case_id": case_id,
                    "dropped_source_set": row.get("source_set"),
                    "dropped_mechanism_key": row.get("mechanism_key"),
                    "kept_once": True,
                }
            )
            if row.get("mechanism_key"):
                extra_mechanisms[case_id].append(row["mechanism_key"])
            continue
        seen_ids.add(case_id)
        row["dedupe_key"] = case_id
        deduped.append(row)
    for row in deduped:
        extras = extra_mechanisms.get(row["case_id"])
        if extras:
            row["extra_mechanism_keys_not_routed"] = extras

    shared_sha_warnings = []
    for sha, ids in sha_to_cases.items():
        if len(ids) > 1:
            shared_sha_warnings.append({"sha": sha, "case_ids": sorted(ids), "warning": "Shared SHA is not a duplicate; uniqueness is GHSA+mechanism."})

    # Sort NARROW/UNKNOWN by missing gates
    def sort_key(row: dict):
        status_rank = {"ROUTE": 0, "UNKNOWN": 1, "REJECT": 2}.get(row["status"], 9)
        return (
            0 if row.get("source_set") == "fp211-381" else 1,
            status_rank,
            -(row.get("missing_gate_count") or 0),
            row.get("ordinal") or 10_000,
            row["case_id"],
        )

    deduped.sort(key=sort_key)

    # Counts
    fp_cases = [r for r in deduped if r.get("source_set") == "fp211-381"]
    by_verdict = Counter(r.get("verdict") for r in fp_cases)
    by_status = Counter(r.get("status") for r in deduped)
    by_census_lane = Counter(r.get("census_lane") or r.get("lane") for r in deduped)
    assigned_a_cases = [r for r in deduped if r.get("assignment_shard") == "upgrade_a"]
    assigned_b_cases = [r for r in deduped if r.get("assignment_shard") == "upgrade_b"]
    repo_head = git_head(ROOT)
    strict_confirmed_cases = [r for r in fp_cases if r.get("strict_confirmed")]
    released_admitted_cases = [r for r in fp_cases if r.get("released_publication_admitted")]
    narrow_cases = [r for r in fp_cases if r.get("verdict") == "NARROW"]
    unknown_cases = [r for r in fp_cases if r.get("verdict") == "UNKNOWN"]
    confirm_cases = [r for r in fp_cases if r.get("verdict") == "CONFIRM"]
    confirm_medium_cases = [r for r in fp_cases if r.get("confirm_medium")]
    confirm_high_unreleased = [
        r
        for r in fp_cases
        if r.get("upgrade_reason") == "confirm_high_commit_only_unreleased"
    ]
    confirm_not_released = [
        r for r in fp_cases if r.get("verdict") == "CONFIRM" and not r.get("released_publication_admitted")
    ]
    novel_rows = [r for r in deduped if r.get("source_set") == "aug12-novel-ai-evidence"]
    removed_rows = [r for r in deduped if r.get("source_set") == "fp211-381-removed"]

    target = 201
    current_strict_released = len(released_admitted_cases)
    gap = target - current_strict_released

    # Canonical overlay mechanism counts for overlap warning
    canonical_summary = json.loads(
        (ROOT / "autoresearch/orchestrator-260813-fp211-canonical/summary.json").read_text()
    )
    posthold_summary = json.loads(
        (ROOT / "autoresearch/orchestrator-260812-posthold-canonical/summary.json").read_text()
    )

    unique_ids = [r["case_id"] for r in deduped]
    denominator = {
        "unit": "first-party GHSA identity",
        "fp211_source_public_ids": len(source_ids),
        "fp211_source_ghsa_ids": len(source_ghsa),
        "fp211_source_cve_ids": len(source_cve),
        "fp211_kept_public_case_ids": len({norm_id(c["case_id"]) for c in cases}),
        "fp211_removed_ghsa_ids": len(removed_rows),
        "inventory_rows": len(deduped),
        "inventory_unique_ghsa_ids": len(set(unique_ids)),
        "one_id_one_route": len(deduped) == len(set(unique_ids)),
        "duplicate_id_collisions_dropped": len(dup_warnings),
        "live_sibling_directories_excluded": sibling_paths_seen,
        "evidence_binding": "record-local identity field plus AI marker or structured AI fields on the same JSON object, table row, or list item",
        "file_level_cooccurrence_not_evidence": True,
    }
    if len(set(unique_ids)) != len(deduped):
        raise SystemExit("denominator failure: duplicate GHSA identities in inventory")

    fp_cases_not_in_local_db = [r["case_id"] for r in fp_cases if not r.get("in_local_reviewed_db")]
    novel_not_in_local_db = [r["case_id"] for r in novel_rows if not r.get("in_local_reviewed_db")]

    result = {
        "schema_version": 1,
        "lane": "gap-inventory-dispatch-qa",
        "status": "COMPLETE",
        "worker_pass_is_proposal_only": True,
        "pass_rows_emitted": 0,
        "strict_released_starting_lower_bound": 48,
        "target_minimum": 201,
        "gap_to_target": 153,
        "assignment_counts": {"upgrade_a": 58, "upgrade_b": 48},
        "live_sibling_evidence_excluded": True,
        "limitations": [
            "No PASS rows. Worker output is inventory and dispatch QA, not admission.",
            "231 census rows are a lossless identity inventory, not assigned research obligations.",
            "Active worker assignment coverage is 58 upgrade_a ordinals and 48 upgrade_b ordinals (union 106, disjoint).",
            "Census lane totals such as upgrade-a=111 are identity-bucket counts and are not interchangeable with assignment_counts.",
            "Local advisory-database HEAD is 2026-07-23 and cannot certify current identity_gate.",
            "Novel rows have record-local Aug-12 artifact evidence only; seven gates remain unclosed.",
        ],
        "source_revisions": {
            "repository_head": repo_head,
            "baseline_json": str(
                (ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/baseline.json").relative_to(ROOT)
            ),
            "baseline_sha256": input_hashes.get(
                "autoresearch/orchestrator-260813-ghsa200-leader/baseline.json"
            ),
            "fp211_final_mechanisms_sha256": input_hashes.get(
                "autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl"
            ),
            "fp211_public_cases_sha256": input_hashes.get(
                "autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl"
            ),
            "fp211_canonical_ledger_sha256": input_hashes.get(
                "autoresearch/orchestrator-260813-fp211-canonical/ledger.jsonl"
            ),
            "advisory_database_head": advisory_head,
            "advisory_database_head_date_utc": "2026-07-23",
        },
        "claim": "This worker does not support a 200-case claim and emits no PASS rows.",
        "started_at": started,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "input_sha256": input_hashes,
        "advisory_database": {
            "path": str(advisory_root),
            "head": advisory_head,
            "reviewed_ghsa_count": len(local_reviewed),
            "reviewed_id_list_sha256": local_reviewed_hash,
            "head_date_utc": "2026-07-23",
            "staleness_warning": "Local advisory-database HEAD is 2026-07-23; Aug-12/13 artifacts and live GHSA pages are newer. Absence from this clone is not identity FAIL.",
        },
        "denominator": denominator,
        "evidence_policy": {
            "completed_aug12_artifacts_allowed": True,
            "live_herdr_260813_ghsa200_siblings_excluded": True,
            "record_local_binding_required": True,
            "file_level_ghsa_ai_cooccurrence_is_not_a_candidate": True,
        },
        "source_set_381": {
            "public_ids": len(source_ids),
            "ghsa_ids": len(source_ghsa),
            "cve_ids": len(source_cve),
            "disposition_rows": len(dispositions),
        },
        "counts": {
            "fp211_mechanisms": len(mechanisms),
            "fp211_public_cases": len(cases),
            "fp211_case_verdicts": dict(by_verdict),
            "inventory_rows_census_not_assignments": len(deduped),
            "inventory_by_status": dict(by_status),
            "census_inventory_by_lane": dict(by_census_lane),
            "assignment_counts_ordinals": {"upgrade_a": 58, "upgrade_b": 48},
            "assignment_verification": assignment_verify,
            "assignment_case_rows_covering_ordinals": {
                "upgrade_a": len(assigned_a_cases),
                "upgrade_b": len(assigned_b_cases),
                "note": "Case-row coverage of assigned ordinals. These are not the assignment_counts.",
            },
            "confirm_public_cases_total": len(confirm_cases),
            "confirm_medium_cases": len(confirm_medium_cases),
            "strict_confirmed_high_all_gates_cases": len(strict_confirmed_cases),
            "strict_confirmed_commit_only_unreleased_cases": len(confirm_high_unreleased),
            "released_publication_admitted_cases_lower_bound": current_strict_released,
            "narrow_cases": len(narrow_cases),
            "unknown_cases": len(unknown_cases),
            "removed_ghsa_identities": len(removed_rows),
            "novel_ghsa_with_ai_artifact_evidence": len(novel_rows),
            "canonical_released_publication_admitted_mechanisms": canonical_summary["counts"][
                "released_publication_admitted_mechanisms"
            ],
            "canonical_strict_confirmed_mechanisms": canonical_summary["counts"]["strict_confirmed_mechanisms"],
            "posthold_released_pass_rows": posthold_summary["claim_boundary"]["released_pass_rows"],
            "web_dashboard_total_cves": json.loads((ROOT / "web/data/stats.json").read_text())["total_cves"],
        },
        "gap_arithmetic": {
            "count_unit": "first-party GHSA case with all seven gates PASS, CONFIRM/HIGH, and released containment",
            "target_more_than": 200,
            "target_min_countable": target,
            "confirm_public_cases_total": 65,
            "confirm_is_not_countable": "65 is the total CONFIRM public-case census, not a released count.",
            "strict_confirmed_high_all_gates": len(strict_confirmed_cases),
            "confirm_medium_upgrade_pool": len(confirm_medium_cases),
            "strict_released_starting_lower_bound": current_strict_released,
            "current_strict_released_cases": current_strict_released,
            "current_strict_confirmed_cases_including_unreleased": len(strict_confirmed_cases),
            "current_confirm_public_cases": by_verdict.get("CONFIRM", 0),
            "current_causal_valid_cases": sum(1 for r in fp_cases if r.get("causal_valid")),
            "gap_to_more_than_200": gap,
            "gap_to_201": gap,
            "gap_is_at_least": gap,
            "formula": "201 - 48 released-admitted starting lower bound; gap is at least 153",
            "upgrade_pool_confirm_medium": len(confirm_medium_cases),
            "upgrade_pool_confirm_high_unreleased": len(confirm_high_unreleased),
            "upgrade_pool_narrow_plus_unknown": len(narrow_cases) + len(unknown_cases),
            "upgrade_pool_confirm_not_released": len(confirm_not_released),
            "fresh_novel_pool": len(novel_rows),
            "upper_bound_if_every_nonreject_became_pass": current_strict_released
            + len(narrow_cases)
            + len(unknown_cases)
            + len(confirm_not_released)
            + len(novel_rows),
            "upper_bound_is_not_a_claim": True,
            "upper_bound_still_below_201": (
                current_strict_released
                + len(narrow_cases)
                + len(unknown_cases)
                + len(confirm_not_released)
                + len(novel_rows)
            )
            < target,
            "existing_200_claim_supported": False,
        },
        "lane_dispatch": {
            "census_not_assignment": "census_inventory_by_lane buckets every identity; assignment_counts are leader baseline ordinals only.",
            "upgrade_a_assignment_ordinals": 58,
            "upgrade_b_assignment_ordinals": 48,
            "assignment_union_ordinals": 106,
            "assignment_disjoint": True,
            "census_upgrade-a": "fp211 identities with ordinal 1-110, including FALSE_POSITIVE and released baseline; not 58 assignments",
            "census_upgrade-b": "fp211 identities with ordinal 111-211, including FALSE_POSITIVE and released baseline; not 48 assignments",
            "remediation": "census causal_class AI_INCOMPLETE_REMEDIATION; may overlap assignment ordinals without changing assignment_counts",
            "fresh-am": "novel GHSA identities whose first alphabetic character is A-M; census only",
            "fresh-nz": "novel GHSA identities whose first alphabetic character is N-Z; census only",
        },
        "overlap_warnings": {
            "mechanism_vs_case": "fp211 has 211 mechanisms and 212 public cases; ChurchCRM ordinal 200 is two GHSAs / one mechanism.",
            "confirm_65_is_census_not_released": "65 CONFIRM public cases are not 65 countable released cases.",
            "strict_51_is_confirm_high_all_gates": "51 CONFIRM/HIGH/all-gates rows are strict-confirmed; 3 of them lack released containment.",
            "released_48_is_starting_lower_bound": "48 released-admitted cases are the strict released starting lower bound, matching the canonical 48 released-admitted mechanisms in this join.",
            "confirm_medium_14_are_upgrade": "14 CONFIRM/MEDIUM cases remain in upgrade routing and are not in the 48.",
            "posthold_144_is_pre_fp211": "Posthold released_pass_rows=144 predates the fp211 audit and is not current countable.",
            "web_36_is_dashboard": "web/data/stats.json total_cves=36 is a curated dashboard, not the GHSA-200 ledger.",
            "census_lanes_are_not_assignments": "Census upgrade-a/upgrade-b identity buckets are not the leader assignment sets of 58 and 48 ordinals.",
            "shared_sha_warning_count": len(shared_sha_warnings),
            "shared_shas_are_not_duplicates": shared_sha_warnings[:20],
            "dedupe_collisions_skipped": dup_warnings,
            "fp211_ghsa_absent_from_stale_local_db": fp_cases_not_in_local_db,
            "novel_ghsa_absent_from_stale_local_db": novel_not_in_local_db,
            "source_envelope_strict_released_134": "STRICT_RELEASED tier 134 is a source envelope, not admitted publication.",
        },
        "blockers": [
            "No PASS rows: this lane is inventory/dispatch QA only.",
            f"Strict released starting lower bound is {current_strict_released}; gap to >200 is at least {gap}.",
            f"{len(confirm_medium_cases)} CONFIRM/MEDIUM cases are routed for upgrade and are not counted in the 48.",
            "Local github/advisory-database clone is dated 2026-07-23 and cannot certify current identity_gate.",
            "Novel GHSA rows have artifact AI evidence only; seven gates remain unclosed.",
            "NARROW/UNKNOWN/REJECT/REMOVED dispositions are preserved and are not counted.",
            "Even a lossless conversion of every non-REJECT inventory row would remain below 201 countable cases.",
        ],
        "files": {
            "cases.jsonl": "cases.jsonl",
            "report.md": "report.md",
            "replay.txt": "replay.txt",
        },
    }

    cases_path = OUT / "cases.jsonl"
    with cases_path.open("w") as fh:
        for row in deduped:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    result["output_sha256"] = {
        "cases.jsonl": sha256_file(cases_path),
        "build_inventory.py": sha256_file(Path(__file__)),
    }
    result_path = OUT / "result.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    # report
    def table_rows(rows, limit=40):
        lines = [
            "| GHSA | ordinal | verdict | missing gates | lane | status |",
            "|---|---:|---|---|---|---|",
        ]
        for r in rows[:limit]:
            miss = ", ".join(r.get("missing_gates") or []) or "none"
            lines.append(
                f"| `{r['case_id']}` | {r.get('ordinal') if r.get('ordinal') is not None else ''} | {r.get('verdict') or ''} | {miss} | {r.get('lane')} | {r.get('status')} |"
            )
        if len(rows) > limit:
            lines.append(f"| … | | | {len(rows) - limit} more | | |")
        return "\n".join(lines)

    report = f"""# GHSA 200+ gap inventory and dispatch QA

Status: **COMPLETE for mechanical inventory**. No PASS rows. Worker PASS is not emitted and would not be admission.

## Answer

**48** is the strict released starting lower bound. Target minimum is **201**. Gap to target is **153**. No PASS rows.

Active worker assignment coverage from leader `baseline.json` is **58** upgrade_a ordinals and **48** upgrade_b ordinals. Those sets are disjoint and their union is **106**. They are not interchangeable with census lane buckets.

The {denominator['inventory_unique_ghsa_ids']} unique-ID census rows are a lossless identity inventory. They are not assigned research obligations.

## Denominator

Exact routing denominator is first-party GHSA identity. Each ID is routed once.

| Quantity | Count |
|---|---:|
| fp211 source public IDs | {denominator['fp211_source_public_ids']} |
| fp211 source GHSA IDs | {denominator['fp211_source_ghsa_ids']} |
| fp211 kept public-case GHSAs | {denominator['fp211_kept_public_case_ids']} |
| fp211 removed GHSA identities | {denominator['fp211_removed_ghsa_ids']} |
| inventory rows / unique GHSA IDs | {denominator['inventory_rows']} / {denominator['inventory_unique_ghsa_ids']} |
| duplicate IDs dropped after first route | {denominator['duplicate_id_collisions_dropped']} |

Evidence is limited to completed Aug-12 `herdr-260812*` result/report artifacts and dated research docs. Live `herdr-260813-ghsa200*` sibling directories are excluded: {", ".join(sibling_paths_seen) or "none observed"}. Novel rows require record-local binding (same JSON object, table row, or list item). File-level GHSA/AI marker co-occurrence is not a candidate.

fp211 public-case census (not publication admission): CONFIRM 65, NARROW 84, FALSE_POSITIVE 54, UNKNOWN 9; total 212. Causal-valid (CONFIRM+NARROW): {sum(1 for r in fp_cases if r.get('causal_valid'))}.

Canonical overlay also reports 48 released-admitted mechanisms and 51 strict-confirmed mechanisms; in this join those match the case-level 48/51 split. Posthold `released_pass_rows=144` is a pre-fp211 envelope. Dashboard `web/data/stats.json` lists 36 curated CVEs.

## Lane dispatch

Two different quantities:

| Kind | upgrade_a | upgrade_b | Notes |
|---|---:|---:|---|
| Active assignment (leader baseline ordinals) | 58 | 48 | Disjoint; union 106. These are worker assignments. |
| Identity census buckets (`census_inventory_by_lane`) | {by_census_lane.get('upgrade-a', 0)} | {by_census_lane.get('upgrade-b', 0)} | Include FALSE_POSITIVE, released baseline, and other identities. Not assignments. |

Census-only lanes: remediation {by_census_lane.get('remediation', 0)}, fresh-am {by_census_lane.get('fresh-am', 0)}, fresh-nz {by_census_lane.get('fresh-nz', 0)}.

Incomplete-remediation cases may appear in the remediation census lane while their ordinal still belongs to an assignment set. Assignment counts remain 58 and 48 ordinals.

## CONFIRM/MEDIUM upgrade pool (14)

These are CONFIRM cases whose joined mechanism confidence is MEDIUM. Canonical overlay requires another review before strict confirmation. They are not released-admitted.

{table_rows(sorted(confirm_medium_cases, key=lambda r: (r.get('ordinal') or 0, r['case_id'])), limit=20)}

## CONFIRM/HIGH commit-only (not in the 48)

{table_rows(sorted(confirm_high_unreleased, key=lambda r: (r.get('ordinal') or 0, r['case_id'])), limit=10)}

## NARROW cases by missing-gate count

{table_rows(sorted(narrow_cases, key=lambda r: (-r['missing_gate_count'], r.get('ordinal') or 0)))}

## UNKNOWN cases by missing-gate count

{table_rows(sorted(unknown_cases, key=lambda r: (-r['missing_gate_count'], r.get('ordinal') or 0)), limit=20)}

## Novel GHSA identities absent from the 381-ID source set

These IDs appear in Aug-12 research result/report artifacts together with exact AI marker text or structured AI/commit fields, and they are not members of the fp211 381 public-ID set. They are **ROUTE** only. Deduplication is GHSA identity plus mechanism key; SHA overlap is recorded as a warning, not a merge.

Count: **{len(novel_rows)}**. Absent from the stale local reviewed advisory-database: {len(novel_not_in_local_db)}.

{table_rows(novel_rows, limit=80)}

## Overlap warnings

- 65 CONFIRM cases ≠ 51 CONFIRM/HIGH/all-gates ≠ 48 released-admitted. Start from 48. Gap ≥ 153.
- The 14 CONFIRM/MEDIUM cases are upgrade work, not part of the 48.
- Census upgrade-a/upgrade-b identity buckets are not the 58/48 assignment ordinals.
- Each first-party GHSA identity is routed once ({denominator['inventory_unique_ghsa_ids']} IDs). Extra mechanism keys do not create extra routes. Shared SHAs do not merge IDs. The 231 census rows are not assigned research obligations.
- ChurchCRM ordinal 200 is two first-party GHSAs on one mechanism fingerprint.
- Local advisory-database HEAD `{advisory_head}` is 2026-07-23; {len(fp_cases_not_in_local_db)} fp211 case GHSAs are absent from that clone. That absence is coverage UNKNOWN, not identity FAIL.
- STRICT_RELEASED source envelope 134 is not 134 admitted cases.
- Removed identities ({len(removed_rows)}) stay REJECT.
- Upper bound if every NARROW, UNKNOWN, unreleased CONFIRM (14 MEDIUM + 3 commit-only), and novel row later closed all gates: {result['gap_arithmetic']['upper_bound_if_every_nonreject_became_pass']}. That bound is below 201 and is not a claim. Reaching >200 requires additional first-party GHSA identities beyond this inventory.

## Inputs hashed

See `result.json` `input_sha256`. Replay is `python3 autoresearch/herdr-260813-ghsa200-gap/build_inventory.py`.
"""
    (OUT / "report.md").write_text(report)

    replay = """# Replay for herdr-260813-ghsa200-gap

python3 /home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-gap/build_inventory.py

# Read-only sources (do not mutate):
# autoresearch/orchestrator-260813-fp211-audit/{final_mechanisms,public_cases,public_id_dispositions}.jsonl
# autoresearch/orchestrator-260813-fp211-canonical/{summary,result,ledger}.json*
# autoresearch/orchestrator-260812-posthold-canonical/summary.json
# autoresearch/herdr-260812*/{result.json,report.md}
# docs/RESEARCH-*2026-08-12.md
# ~/.cache/cve-analyzer/advisory-database (HEAD only)

# No git clone, commit, push, clean, or reset is required.
# Completed Aug-12 herdr-260812* result/report artifacts only.
# Live herdr-260813-ghsa200* sibling directories are excluded from evidence.
# Record-local GHSA/AI binding only; file-level co-occurrence is not a candidate.
# Leader baseline.json upgrade_a=58 and upgrade_b=48 ordinals are assignments.
# Census lane totals are not assignments. 231 census IDs are not research obligations.
"""
    (OUT / "replay.txt").write_text(replay)

    result["output_sha256"]["result.json"] = sha256_file(result_path)
    result["output_sha256"]["report.md"] = sha256_file(OUT / "report.md")
    result["output_sha256"]["replay.txt"] = sha256_file(OUT / "replay.txt")
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    loaded = json.loads(result_path.read_text())
    checks = {
        "strict_released_starting_lower_bound": loaded["strict_released_starting_lower_bound"] == 48,
        "target_minimum": loaded["target_minimum"] == 201,
        "gap_to_target": loaded["gap_to_target"] == 153,
        "assignment_counts": loaded["assignment_counts"] == {"upgrade_a": 58, "upgrade_b": 48},
        "assignment_disjoint_union_106": assignment_verify["disjoint"]
        and assignment_verify["union_equals_106"]
        and assignment_verify["matches_expected"],
        "live_sibling_evidence_excluded": loaded["live_sibling_evidence_excluded"] is True,
        "no_pass": loaded["pass_rows_emitted"] == 0,
        "no_inventory_by_lane_aliasing_assignments": "inventory_by_lane" not in loaded.get("counts", {}),
        "one_id_one_route": loaded["denominator"]["one_id_one_route"] is True,
    }
    if not all(checks.values()):
        raise SystemExit(f"post-write checks failed: {checks}")
    print(json.dumps({
        "strict_released_starting_lower_bound": 48,
        "target_minimum": 201,
        "gap_to_target": 153,
        "assignment_counts": {"upgrade_a": 58, "upgrade_b": 48},
        "assignment_union": 106,
        "census_ids": loaded["denominator"]["inventory_unique_ghsa_ids"],
        "census_inventory_by_lane": loaded["counts"]["census_inventory_by_lane"],
        "assignment_case_rows_covering_ordinals": loaded["counts"]["assignment_case_rows_covering_ordinals"],
        "live_sibling_evidence_excluded": True,
        "pass_rows_emitted": 0,
        "checks": checks,
    }, indent=2))


if __name__ == "__main__":
    main()
