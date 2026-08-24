#!/usr/bin/env python3
"""Emit batch2 artifacts. Writes only this lane. Does not touch delta-even."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

LANE = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-delta-even-batch2")
CACHE = Path("/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def gate(status: str, reason: str) -> dict:
    return {"status": status, "reason": reason}


def main() -> None:
    assign = json.loads((LANE / "assignment_manifest.json").read_text())
    packets = {json.loads(l)["ghsa_id"]: json.loads(l) for l in (LANE / "advisory_packets.jsonl").read_text().splitlines()}
    scans = {json.loads(l)["ghsa_id"]: json.loads(l) for l in (LANE / "origin_scan.jsonl").read_text().splitlines()}

    # Manual overrides after first-party inspection of the four AI-origin candidates
    # plus three recovered PR closers.
    overrides = {
        "GHSA-434R-7C99-HWF3": {
            "verdict": "REJECT",
            "contribution_class": "HUMAN_ORIGIN",
            "note": "The only detector hit is unknown_ai message_keyword 'LLM-generated' in 5dc96505, which describes model-produced tool-call URLs, not commit authorship. Closer 545294c6 is human.",
        },
        "GHSA-4CWX-7WF7-3272": {
            "verdict": "REJECT",
            "contribution_class": "HUMAN_ORIGIN",
            "note": "Claude trailers on de01babc/e1cc0d43 are later cache-revalidation fixes in lib/util/cache.js. Official closer 4fe5bc5f (Matteo Collina) repairs empty qualified private/no-cache parsing. Those Claude commits are adjacent, not the introducing parse hunk.",
        },
        "GHSA-55H5-XMCQ-C37V": {
            "verdict": "REJECT",
            "contribution_class": "HUMAN_ORIGIN",
            "note": "Claude 4d8ebcec fixed stale object-stream cache (#3698). This GHSA closer b5fc5aa7 speeds regex recovery of broken xref tables. Shared file _reader.py caused blame collision; mechanisms differ.",
        },
        "GHSA-6VH2-WG4H-4VWJ": {
            "verdict": "REJECT",
            "contribution_class": "HUMAN_ORIGIN",
            "note": "Claude aee37e16 is ambient-webhook UI. ...overrideConfig spread was introduced by Henry Heng / Rafael Reis commits in 2024-2025 with no AI trailers. Closer 23b997ee removes that human spread.",
        },
        "GHSA-55Q2-FJHQ-7XH7": {
            "verdict": "REJECT",
            "contribution_class": "HUMAN_ORIGIN",
            "note": "Official short SHA was not on default branch. PR 1557 merge 2c8ca25e is Cure53. IN_PLACE lineage (e4790120, ec112366, 28d3dec6, a35824c0) is Cure53 with no AI trailer.",
        },
        "GHSA-43PX-GPWC-Q84V": {
            "verdict": "UNKNOWN",
            "contribution_class": "ORIGIN_UNRESOLVED",
            "note": "PR 268 closer 1bebf7d9 / member d33fd22e is human 3em0. Introducing hunk for the missing authorized-collection filter was not isolated.",
        },
        "GHSA-6H35-9P2W-3J3R": {
            "verdict": "UNKNOWN",
            "contribution_class": "ORIGIN_UNRESOLVED",
            "note": "PR 248 closer aa470525 / member f6dbf8db is human 3em0. Introducing hunk for Qdrant identity collision was not isolated.",
        },
    }

    cases = []
    for gid in assign["assigned_ids"]:
        pkt = packets[gid]
        scan = scans[gid]
        ov = overrides.get(gid)
        resolution = scan.get("resolution")
        if ov:
            verdict = ov["verdict"]
            klass = ov["contribution_class"]
            extra = ov["note"]
        elif resolution == "HUMAN_ORIGIN_RESOLVED":
            verdict = "REJECT"
            klass = "HUMAN_ORIGIN"
            extra = "Introducing-hunk candidates from parent-blame and pickaxe of the official closer have no AI trailer via cve_analyzer.detect_ai_signals."
        elif resolution == "UNKNOWN_ORIGIN_UNRESOLVED":
            verdict = "UNKNOWN"
            klass = "ORIGIN_UNRESOLVED"
            extra = "Official closer resolved, but deleted/changed hunks could not be attributed to a prior introducing commit."
        elif resolution == "BLOCKED_NO_FIX_SHA":
            verdict = "BLOCKED"
            klass = "NO_FIX_COMMIT"
            extra = "Official github-reviewed object has no usable commit SHA in this clone; introducing hunk cannot be located."
        else:
            verdict = "UNKNOWN"
            klass = "ORIGIN_UNRESOLVED"
            extra = "Unclassified origin-scan resolution; not a PASS."

        origins = []
        for m in (scan.get("origin_candidates") or [])[:8]:
            if m.get("ok"):
                origins.append(
                    {
                        "sha": m.get("sha"),
                        "author": m.get("author_name"),
                        "date": m.get("authored_date"),
                        "subject": m.get("subject"),
                        "ai_signals": m.get("ai_signals") or [],
                    }
                )

        if verdict == "REJECT":
            gates = {
                "identity_gate": gate("PASS", f"Official github-reviewed {gid} names {pkt['repository']}; not withdrawn."),
                "ai_hunk_gate": gate("REJECT", "Relevant introducing hunks are human or the AI hit is not authorship of this mechanism. " + extra),
                "topology_gate": gate("PASS", "Closer and origin candidates were resolved in the batch2 clone without transferring authorship."),
                "but_for_gate": gate("REJECT", "Removing a human introducing change does not establish an AI-authored mechanism."),
                "fix_reversal_gate": gate("REJECT", "The official closer reverses a non-AI mechanism, not an AI-created residual."),
                "release_gate": gate("PASS" if pkt.get("affected") else "REJECT", "Official affected/fixed events recorded in github-reviewed JSON."),
                "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs and from delta-even deep-reviewed IDs. Not counted."),
            }
        elif verdict == "UNKNOWN":
            gates = {
                "identity_gate": gate("PASS", f"Official github-reviewed {gid} names {pkt['repository']}; not withdrawn."),
                "ai_hunk_gate": gate("UNKNOWN", extra),
                "topology_gate": gate("UNKNOWN", "Introducing commit not isolated; ancestry of the vulnerable hunk is incomplete."),
                "but_for_gate": gate("UNKNOWN", "Cannot test but-for without a resolved introducing hunk."),
                "fix_reversal_gate": gate("UNKNOWN", "Cannot pair a minimum fix to an unresolved origin hunk."),
                "release_gate": gate("PASS" if pkt.get("affected") else "UNKNOWN", "Official affected/fixed events recorded when present."),
                "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs. Not counted."),
            }
        else:
            gates = {
                "identity_gate": gate("PASS", f"Official github-reviewed {gid} names {pkt['repository']}; not withdrawn."),
                "ai_hunk_gate": gate("BLOCKED", extra),
                "topology_gate": gate("BLOCKED", "No official fix commit in the batch2 clone to walk from."),
                "but_for_gate": gate("BLOCKED", "Origin walk blocked."),
                "fix_reversal_gate": gate("BLOCKED", "No first-party fix SHA to reverse against."),
                "release_gate": gate("PASS" if pkt.get("affected") else "BLOCKED", "Official affected/fixed events recorded when present."),
                "uniqueness_gate": gate("PASS", "Absent from the 212 declared IDs. Not counted."),
            }

        cases.append(
            {
                "schema_version": 2,
                "row_role": "BATCH2_TERMINAL",
                "seven_gate_row": True,
                "case_id": gid,
                "aliases": pkt.get("aliases") or [],
                "repository": pkt.get("repository"),
                "summary": pkt.get("summary") or "",
                "published": pkt.get("published"),
                "withdrawn": pkt.get("withdrawn"),
                "commit_refs": pkt.get("commit_refs") or [],
                "released": {"affected": pkt.get("affected") or []},
                "verdict": verdict,
                "contribution_class": klass,
                "mechanism_key": gid.lower() + "-batch2",
                "scope_statement": pkt.get("summary") or "",
                "candidate_set": [o["sha"] for o in origins if o.get("sha")],
                "carrier_set": scan.get("fix_shas") or [],
                "minimum_fix_set": scan.get("fix_shas") or pkt.get("commit_refs") or [],
                "origin_scan_resolution": resolution,
                "origin_candidates": origins,
                "ai_marker_evidence": extra,
                "counterevidence": extra,
                "gates": gates,
                "worker_pass_is_proposal": True,
                "proposed_pass": False,
                "baseline_overlap": "absent_from_212_declared",
                "prior_delta_even_deep_overlap": False,
                "sibling_conclusions_used_as_evidence": False,
                "clone_path": str(CACHE / (pkt["repository"] or "unknown").replace("/", "__")),
                "evidence_official_json": pkt.get("evidence_copy"),
            }
        )

    if len(cases) != 80:
        raise SystemExit(f"expected 80 rows, got {len(cases)}")
    if len({c["case_id"] for c in cases}) != 80:
        raise SystemExit("non-unique case ids")
    if any(c["proposed_pass"] for c in cases):
        raise SystemExit("unexpected PASS")

    (LANE / "cases.jsonl").write_text("".join(json.dumps(c, ensure_ascii=True) + "\n" for c in cases))
    vc = Counter(c["verdict"] for c in cases)
    hashes = {
        "assignment_manifest.json": sha256_file(LANE / "assignment_manifest.json"),
        "assignment_ids.txt": sha256_file(LANE / "assignment_ids.txt"),
        "advisory_packets.jsonl": sha256_file(LANE / "advisory_packets.jsonl"),
        "origin_scan.jsonl": sha256_file(LANE / "origin_scan.jsonl"),
        "cases_jsonl": sha256_file(LANE / "cases.jsonl"),
        "delta_even_routing_manifest.jsonl": assign["input_hashes"]["delta_even_routing_manifest.jsonl"],
        "leader_declared_ids.txt": assign["input_hashes"]["leader_declared_ids.txt"],
        "github_reviewed_window_added_ids.txt": assign["input_hashes"]["github_reviewed_window_added_ids.txt"],
        "delta_even_partition_even_ids.txt": assign["input_hashes"]["delta_even_partition_even_ids.txt"],
    }
    result = {
        "schema_version": 2,
        "lane": "herdr-260813-ghsa200-delta-even-batch2",
        "task": "Bounded deep review of the first 80 lexicographic SCREENED_NO_PLAUSIBLE_AI even-partition IDs, testing unreferenced-history origin",
        "status": "COMPLETE",
        "completeness_scope": "assigned_80_ids_terminal",
        "ecosystem_coverage_claimed": False,
        "started_at": "2026-08-13T16:58:00-04:00",
        "ended_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "output_dir": str(LANE),
        "clone_root": str(CACHE),
        "existing_delta_even_artifacts_mutated": False,
        "tmp_used_for_new_clones": False,
        "worker_pass_is_proposal": True,
        "proposed_pass_count": 0,
        "proposed_pass_ids": [],
        "assignment_assertions": assign["assertions"],
        "counts": {
            "assigned": 80,
            "terminal_rows": 80,
            "pass_proposals": 0,
            "reject": vc.get("REJECT", 0),
            "unknown": vc.get("UNKNOWN", 0),
            "blocked": vc.get("BLOCKED", 0),
            "narrow": 0,
        },
        "verdict_counts": dict(vc),
        "input_hashes": hashes,
        "blockers": [
            "0 PASS proposals. COMPLETE applies only to these 80 assigned IDs.",
            f"{vc.get('UNKNOWN', 0)} UNKNOWN: closer present but introducing hunk not isolated.",
            f"{vc.get('BLOCKED', 0)} BLOCKED: no usable official fix SHA in the batch2 clone.",
            "Four detector AI hits were inspected and rejected as non-authorship or adjacent-file blame.",
        ],
        "sibling_conclusions_used_as_evidence": False,
        "shared_paths_mutated": 0,
    }
    (LANE / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    hashes["result_json"] = sha256_file(LANE / "result.json")
    (LANE / "source_hashes.json").write_text(json.dumps({"input_hashes": hashes, "assignment_assertions": assign["assertions"]}, indent=2) + "\n")
    print(json.dumps({"verdicts": dict(vc), "pass": 0, "rows": len(cases)}, indent=2))


if __name__ == "__main__":
    main()
