#!/usr/bin/env python3
"""Generate result.json and cases.jsonl for the cross-dedupe lane.

Deterministic; reads only frozen baseline / canonical / publication artifacts
and the stable terminal worker artifacts. Emits into this directory. Never
promotes a case and never writes outside this directory.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import dedupe_checker as dc  # noqa: E402

AUDIT_DIR = ROOT / "autoresearch/orchestrator-260813-fp211-audit"
CANONICAL_DIR = ROOT / "autoresearch/orchestrator-260813-fp211-canonical"
LEADER_DIR = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader"
PUBLICATION = ROOT / "scripts/publication_adjudications.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    mechanisms = load_jsonl(AUDIT_DIR / "final_mechanisms.jsonl")
    cases = load_jsonl(AUDIT_DIR / "public_cases.jsonl")
    dispositions = load_jsonl(AUDIT_DIR / "public_id_dispositions.jsonl")
    ledger = load_jsonl(CANONICAL_DIR / "ledger.jsonl")

    audit = dc.audit(ROOT)

    # --- canonical intra-corpus collisions ---
    component_rows = [r for r in ledger if r.get("record_kind") == "COMPONENT_ROW"]
    alias_map = dc.build_alias_map(component_rows)
    views = [dc.RowView(r, label=str(r.get("row_key") or r.get("canonical_component_id") or i)) for i, r in enumerate(component_rows)]
    canonical_collisions = []
    for i in range(len(views)):
        for j in range(i + 1, len(views)):
            rel = dc.classify(views[i], views[j], alias_map)
            if rel["verdict"] != "DISTINCT" or any(rel["shared_shas"].values()):
                canonical_collisions.append(rel)
    canonical_tally = Counter(r["verdict"] for r in canonical_collisions)

    # --- batch1 terminal proposals vs canonical reference ---
    proposals = [r for r in ledger if r.get("record_kind") == "BATCH1_PENDING_PROPOSAL"]
    prop_views = [dc.RowView(r, label=str(r.get("row_key") or r.get("case_id") or i)) for i, r in enumerate(proposals)]
    prop_collisions = []
    for i in range(len(prop_views)):
        for j in range(i + 1, len(prop_views)):
            rel = dc.classify(prop_views[i], prop_views[j], alias_map)
            if rel["verdict"] != "DISTINCT":
                prop_collisions.append(rel)
    release_checks = [{"row": v.label, **dc.release_check(v)} for v in prop_views]

    # --- build cases.jsonl ---
    case_rows = []

    def emit(case_id, kind, verdict, **kw):
        row = {
            "schema_version": dc.SCHEMA_VERSION,
            "case_id": case_id,
            "kind": kind,
            "verdict": verdict,
        }
        row.update(kw)
        case_rows.append(row)

    # A / B clean classes
    emit("A-alias-class-duplicates", "alias_class_duplicate", "CLEAN",
         cve_claimed_by_multiple_ghsa=audit["A_alias_class_duplicates"]["cve_claimed_by_multiple_ghsa"],
         disposition_rows_with_multiple_cases=audit["A_alias_class_duplicates"]["disposition_rows_with_multiple_cases"],
         case_id_also_used_as_alias=audit["A_alias_class_duplicates"]["case_id_also_used_as_alias"])
    emit("B-same-advisory-split-rows", "advisory_split", "CLEAN",
         duplicate_case_id_rows=audit["B_same_advisory_split_rows"]["duplicate_case_id_rows"],
         cases_with_multiple_mechanism_keys=audit["B_same_advisory_split_rows"]["cases_with_multiple_mechanism_keys"])

    # C candidate+fix clusters -> DISTINCT
    for label, cluster in audit["C_same_candidate_fix_distinct_mechanisms"]["candidate_and_fix_shared_clusters"].items():
        emit(f"C-candidate-fix-{label}", "candidate_fix_distinct", "DISTINCT",
             candidate_sha=cluster["candidate_sha"],
             fix_sha=cluster["fix_sha"],
             ordinals=cluster["ordinals"],
             reasons=["shared candidate/fix SHA only; distinct mechanisms; never merge by SHA"])

    # D same mechanism under different IDs (ChurchCRM cross-advisory overlap)
    emit("D-churchcrm-cross-advisory-overlap", "same_mechanism_different_id", "ALIAS_SAME_COMPONENT",
         mechanism_key="churchcrm-notes-object-scope-authorization",
         case_ids=["GHSA-3J8Q-FWPJ-F8J5", "GHSA-JJCJ-H3CM-P7X7"],
         canonical_component="posthold:G01",
         reasons=["same mechanism_key across two non-aliased advisories; cross-advisory same-component overlap; one mechanism component, two public cases"])

    # D audit duplicate_of rows
    for d in audit["D_same_mechanism_different_ids"]["audit_duplicate_of_rows"]:
        verdict = "DUPLICATE" if d["false_positive_class"] == "same_mechanism_duplicate" else "CONFLICT"
        emit(f"D-audit-ordinal-{d['ordinal']}", "audit_declared_duplicate", verdict,
             ordinal=d["ordinal"],
             duplicate_of=d["duplicate_of"],
             false_positive_class=d["false_positive_class"],
             reasons=["frozen audit duplicate_of declaration; not independently re-merged by this lane"])

    # E canonical DUPLICATE rows (checker re-derived via SAME_ID + SAME fingerprint)
    for rel in canonical_collisions:
        if rel["verdict"] == "DUPLICATE":
            emit("E-canonical-duplicate", "canonical_duplicate", "DUPLICATE",
                 left=rel["left"], right=rel["right"],
                 left_ids=rel["left_ids"], right_ids=rel["right_ids"],
                 identity=rel["identity"], mechanism=rel["mechanism"],
                 shared_shas=rel["shared_shas"], reasons=rel["reasons"])

    # F n8n-mcp same-advisory split rows (proposal_vs_proposal)
    for rel in prop_collisions:
        emit("F-proposal-advisory-split", "proposal_advisory_split", rel["verdict"],
             left=rel["left"], right=rel["right"],
             left_ids=rel["left_ids"], right_ids=rel["right_ids"],
             identity=rel["identity"], mechanism=rel["mechanism"],
             shared_shas=rel["shared_shas"], reasons=rel["reasons"])

    # release failures on proposals
    for rc in release_checks:
        emit("G-proposal-release", "release_containment", rc["verdict"],
             left=rc["row"], reasons=rc["reasons"])

    # git verification results (computed by replay.txt step; embed if present)
    git_verify_path = HERE / "work/git_verify.json"
    git_verify = json.loads(git_verify_path.read_text()) if git_verify_path.is_file() else []

    # --- result.json ---
    result = {
        "schema_version": dc.SCHEMA_VERSION,
        "status": "COMPLETE_ADVERSARIAL_LAYER",
        "lane": "cross-dedupe",
        "read_only": True,
        "promotes_cases": False,
        "objective": "audit the public-ID projection for alias/split/SHA/mechanism collisions and provide a deterministic stdlib-only collision checker that vetoes/narrows/routes duplicates and release failures",
        "inputs": {
            "CONTRACT.md": sha256_file(LEADER_DIR / "CONTRACT.md"),
            "baseline.json": sha256_file(LEADER_DIR / "baseline.json"),
            "final_mechanisms.jsonl": sha256_file(AUDIT_DIR / "final_mechanisms.jsonl"),
            "public_cases.jsonl": sha256_file(AUDIT_DIR / "public_cases.jsonl"),
            "public_id_dispositions.jsonl": sha256_file(AUDIT_DIR / "public_id_dispositions.jsonl"),
            "canonical_ledger.jsonl": sha256_file(CANONICAL_DIR / "ledger.jsonl"),
            "publication_adjudications.json": sha256_file(PUBLICATION),
        },
        "audit": {
            "counts": audit["counts"],
            "A_alias_class_duplicates": audit["A_alias_class_duplicates"],
            "B_same_advisory_split_rows": audit["B_same_advisory_split_rows"],
            "C_same_candidate_fix_distinct_mechanisms": {
                k: audit["C_same_candidate_fix_distinct_mechanisms"][k]
                for k in ("candidate_sha_shared_count", "fix_sha_shared_count", "carrier_sha_shared_count")
            },
            "D_same_mechanism_different_ids": audit["D_same_mechanism_different_ids"],
        },
        "checker": {
            "negative_controls": dc.self_test(),
            "canonical_intra_collision_tally": dict(canonical_tally),
            "canonical_duplicates": [
                {"left": r["left"], "right": r["right"]}
                for r in canonical_collisions if r["verdict"] == "DUPLICATE"
            ],
            "canonical_shared_sha_distinct_pairs": sum(
                1 for r in canonical_collisions
                if r["verdict"] == "DISTINCT" and any(r["shared_shas"].values())
            ),
            "batch1_proposal_collisions": [
                {"verdict": r["verdict"], "left": r["left"], "right": r["right"]}
                for r in prop_collisions
            ],
            "batch1_release_tally": dict(Counter(r["verdict"] for r in release_checks)),
        },
        "release_verification": {
            "method": "git merge-base --is-ancestor candidate<->vulnerable_tag, fix<->fixed_tag, fix<->vulnerable_tag",
            "sample_size": len(git_verify),
            "full_containment_pass": sum(
                1 for g in git_verify
                if g.get("candidate_in_vulnerable") is True
                and g.get("fix_in_fixed") is True
                and g.get("fix_in_vulnerable") is False
            ),
            "results": git_verify,
        },
        "blockers": [
            "This lane emits no PASS rows; it only vetoes/narrows/routes duplicates and release failures.",
            "Shared SHA alone is never treated as duplicate; DUPLICATE requires a SHA-free source/sink/invariant fingerprint plus first-party identity or a first-party duplicate_of linkage.",
            "Pre-existing mechanism_key alone is never treated as duplicate.",
            "5 batch1 pending proposals carry no release_evidence; release containment cannot be certified until they do.",
            "The frozen public_cases.jsonl carries mechanism_key for only 131 of 212 rows and no source/sink/invariant; full SHA-free fingerprinting is possible against the canonical overlay's mechanism text, not the projection itself.",
        ],
    }

    (HERE / "cases.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in case_rows)
    )
    (HERE / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    print(f"WROTE cases.jsonl ({len(case_rows)} rows) and result.json")


if __name__ == "__main__":
    main()
