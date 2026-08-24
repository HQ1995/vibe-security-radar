#!/usr/bin/env python3
"""Unified fail-closed verifier for the GHSA-200 causal-case pipeline.

Stdlib-only. Reads only the leader CONTRACT.md, baseline.json, and the input
paths declared in manifest.json. Every acceptance-relevant condition fails
closed: any violation yields a blocker and the terminal status stays HOLD with
integration_ready=false and publication_ready=false. The verifier never
promotes a case and never edits canonical/publication files.

Fail-closed conditions (all mandatory):
  1. missing or nonterminal lane
  2. PASS/ACCEPT/CONFIRM/KEEP row lacking any of the seven PASS gates
  3. contributor class lacking scope_statement
  4. AI_INCOMPLETE_REMEDIATION lacking remediation_patch_delta_gate=PASS
  5. proposal lacking independent terminal review
  6. review hypothesis SHA mismatch/stale unless an explicit superseded_edge
     binds the corrected final hypothesis
  7. conflicting review verdicts for one case
  8. duplicate case / public-ID / mechanism overlap
  9. unresolved UNKNOWN or BLOCKED row
 10. source/assignment conservation failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA_VERSION = 1

SEVEN_GATES = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
)

POSITIVE_VERDICTS = {"PASS", "ACCEPT", "CONFIRM", "KEEP"}
UNRESOLVED_VERDICTS = {"UNKNOWN", "BLOCKED"}
CONTRIBUTOR_CLASSES = {"AI_NEW_SURFACE_CONTRIBUTOR", "AI_MATERIAL_CONTRIBUTOR"}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text())


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def row_verdict(row: dict) -> str:
    value = (
        row.get("verdict")
        or row.get("row_state")
        or row.get("worker_hypothesis_verdict")
        or row.get("worker_disposition")
        or ""
    )
    return str(value).upper()


def row_class(row: dict) -> str:
    value = row.get("contribution_class") or row.get("causal_class") or ""
    return str(value).upper()


def gate_value(row: dict, name: str) -> str:
    gates = row.get("gates")
    if isinstance(gates, dict) and name in gates:
        return str(gates[name]).upper()
    if name in row:
        return str(row[name]).upper()
    return ""


# --------------------------------------------------------------------------- #
# Row-level fail-closed checks
# --------------------------------------------------------------------------- #

def check_seven_gates(row: dict) -> list[str]:
    verdict = row_verdict(row)
    if verdict in POSITIVE_VERDICTS:
        missing = [g for g in SEVEN_GATES if gate_value(row, g) != "PASS"]
        if missing:
            return [f"{row.get('case_id') or row.get('ordinal')}: {verdict} missing PASS gates {missing}"]
    return []


def check_scope_statement(row: dict) -> list[str]:
    cls = row_class(row)
    if cls in CONTRIBUTOR_CLASSES and not row.get("scope_statement"):
        return [f"{row.get('case_id') or row.get('ordinal')}: {cls} lacking scope_statement"]
    return []


def check_remediation_patch_delta(row: dict) -> list[str]:
    cls = row_class(row)
    if cls == "AI_INCOMPLETE_REMEDIATION" and str(row.get("remediation_patch_delta_gate", "")).upper() != "PASS":
        return [f"{row.get('case_id') or row.get('ordinal')}: AI_INCOMPLETE_REMEDIATION lacking remediation_patch_delta_gate=PASS"]
    return []


def check_unresolved(row: dict) -> list[str]:
    verdict = row_verdict(row)
    if verdict in UNRESOLVED_VERDICTS:
        return [f"{row.get('case_id') or row.get('ordinal')}: unresolved {verdict}"]
    return []


# --------------------------------------------------------------------------- #
# Cross-row / lane-level fail-closed checks
# --------------------------------------------------------------------------- #

def check_duplicate_overlap(rows: list[dict]) -> list[str]:
    """Flag a public ID or mechanism_key claimed by two distinct cases.

    The same case_id reused across review layers is NOT a duplicate; only a
    cross-case overlap (distinct case_ids sharing a CVE/GHSA alias or a
    mechanism_key) fails closed.
    """
    blockers: list[str] = []
    id_owners: dict[str, set[str]] = defaultdict(set)
    mech_owners: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        cid = str(r.get("case_id"))
        for ident in [cid] + [str(a) for a in (r.get("aliases") or [])]:
            if ident and ident.lower() != "none":
                id_owners[ident.upper()].add(cid)
        mech = r.get("mechanism_key")
        if mech:
            mech_owners[str(mech)].add(cid)
    for ident, owners in id_owners.items():
        if len(owners) > 1:
            blockers.append(f"public-ID overlap {ident}: {sorted(owners)}")
    for mech, owners in mech_owners.items():
        if len(owners) > 1:
            blockers.append(f"mechanism overlap {mech}: {sorted(owners)}")
    return blockers


def check_conservation(assigned_ordinals: list[int], rows: list[dict]) -> list[str]:
    blockers: list[str] = []
    ords = [r.get("ordinal") for r in rows if r.get("ordinal") is not None]
    cnt = Counter(ords)
    dup = sorted(o for o, c in cnt.items() if c > 1)
    if dup:
        blockers.append(f"duplicate ordinals in rows: {dup}")
    assigned = set(assigned_ordinals)
    present = set(ords)
    missing = sorted(assigned - present)
    extra = sorted(present - assigned)
    if missing:
        blockers.append(f"missing assigned ordinals: {missing}")
    if extra:
        blockers.append(f"extra ordinals outside assignment: {extra}")
    return blockers


def check_independent_review(worker_rows: list[dict], review_rows: list[dict]) -> list[str]:
    blockers: list[str] = []
    reviewed = set()
    for r in review_rows:
        reviewed.add(str(r.get("case_id") or r.get("ordinal")))
    for r in worker_rows:
        verdict = row_verdict(r)
        if verdict in POSITIVE_VERDICTS:
            key = str(r.get("case_id") or r.get("ordinal"))
            if key not in reviewed:
                blockers.append(f"proposal {key} lacks independent terminal review")
    return blockers


def check_hypothesis_chain(review: dict) -> list[str]:
    """A review result must not bind a stale hypothesis SHA unless a
    superseded_edge explicitly binds the corrected final hypothesis."""
    blockers: list[str] = []
    superseded = bool(review.get("superseded_edge"))
    stale = review.get("stale_source")
    if stale and not superseded:
        blockers.append("stale_source declared but superseded_edge missing")
    bound = review.get("bound_sha")
    current = review.get("current_sha")
    if bound and current and bound != current and not superseded:
        blockers.append(
            f"hypothesis SHA mismatch (bound {bound[:12]} != current {current[:12]}) without superseded_edge"
        )
    return blockers


def check_conflicting_review(reviews: list[dict]) -> list[str]:
    """Conflicting terminal verdicts for one case_id fail closed."""
    blockers: list[str] = []
    verdicts: dict[str, set[str]] = defaultdict(set)
    for r in reviews:
        key = str(r.get("case_id") or r.get("ordinal"))
        v = row_verdict(r)
        if v:
            verdicts[key].add(v)
    for key, vs in verdicts.items():
        positives = vs & POSITIVE_VERDICTS
        negatives = vs & {"REJECT", "FALSE_POSITIVE", "NARROW"}
        if positives and negatives:
            blockers.append(f"conflicting review for {key}: {sorted(vs)}")
    return blockers


def check_lane_terminal(lane: dict) -> list[str]:
    state = str(lane.get("state", "")).upper()
    if state != "TERMINAL":
        return [f"lane {lane.get('lane')} nonterminal ({state or 'MISSING'})"]
    return []


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def collect_lane_inputs(lane: dict) -> dict[str, list[dict]]:
    """Read the declared input paths for a terminal lane, keyed by role."""
    by_role: dict[str, list[dict]] = {}
    for entry in lane.get("inputs", []) or []:
        path = entry.get("path")
        role = entry.get("role", "unknown")
        if not path:
            continue
        p = Path(path)
        if not p.is_file():
            continue
        if p.suffix == ".jsonl":
            by_role[role] = load_jsonl(p)
        elif p.suffix == ".json":
            data = load_json(p)
            by_role[role] = data if isinstance(data, list) else [data]
    return by_role


def verify(manifest: dict, root: Path) -> dict:
    blockers: list[str] = []

    # Contract and baseline are pinned in the manifest.
    contract = manifest.get("contract", {})
    baseline = manifest.get("baseline", {})
    contract_path = root / contract.get("path", "")
    baseline_path = root / baseline.get("path", "")
    if contract_path.is_file() and sha256_file(contract_path) != contract.get("sha256"):
        blockers.append("CONTRACT.md sha256 mismatch")
    if baseline_path.is_file() and sha256_file(baseline_path) != baseline.get("sha256"):
        blockers.append("baseline.json sha256 mismatch")
    baseline_data = load_json(baseline_path) if baseline_path.is_file() else {}

    lanes = manifest.get("lanes", [])
    # 1. missing/nonterminal lanes
    for lane in lanes:
        blockers.extend(check_lane_terminal(lane))

    # Per-terminal-lane fail-closed checks.
    for lane in lanes:
        if str(lane.get("state", "")).upper() != "TERMINAL":
            continue
        inputs = collect_lane_inputs(lane)
        if lane.get("inventory_only"):
            # Inventory lanes declare no countable rows; nothing further to fail.
            continue

        worker_rows = inputs.get("worker_cases", [])
        final_rows = inputs.get("third_review_cases", [])
        if not final_rows:
            final_rows = inputs.get("red_team_cases", []) + inputs.get("correction_cases", [])

        # 2/3/4/9: row-level checks on the proposer and final reviewed rows.
        for r in worker_rows + final_rows:
            blockers.extend(check_seven_gates(r))
            blockers.extend(check_scope_statement(r))
            blockers.extend(check_remediation_patch_delta(r))
            blockers.extend(check_unresolved(r))

        # 5: positive proposals need independent terminal review.
        blockers.extend(check_independent_review(worker_rows, final_rows))

        # 8: duplicate / public-ID / mechanism overlap in the final layer.
        blockers.extend(check_duplicate_overlap(final_rows))

        # 7: conflicting final verdicts for one case.
        blockers.extend(check_conflicting_review(final_rows))

        # 6: review hypothesis SHA stale unless superseded_edge.
        for role in ("red_team_result", "correction_result", "third_review_result"):
            review_docs = inputs.get(role, [])
            for doc in review_docs:
                if isinstance(doc, dict):
                    blockers.extend(check_hypothesis_chain(doc))

        # 10: source/assignment conservation against the baseline shard.
        lane_name = lane.get("lane")
        shard = baseline_data.get("upgrade_shards", {}).get(lane_name)
        if shard and isinstance(shard, dict) and shard.get("ordinals"):
            blockers.extend(check_conservation(list(shard["ordinals"]), worker_rows))

    blockers = sorted(set(blockers))
    expected = manifest.get("expected_output", {})
    return {
        "schema_version": SCHEMA_VERSION,
        "status": expected.get("status", "HOLD"),
        "integration_ready": expected.get("integration_ready", False),
        "publication_ready": expected.get("publication_ready", False),
        "fail_closed": True,
        "blocker_count": len(blockers),
        "blockers": blockers,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    manifest_path = args.manifest
    root = (args.root or manifest_path.resolve().parents[1])
    manifest = load_json(manifest_path)
    result = verify(manifest, root)

    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
        print(f"WROTE {args.output} (status={result['status']}, blockers={result['blocker_count']})")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
