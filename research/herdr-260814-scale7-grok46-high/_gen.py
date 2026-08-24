#!/usr/bin/env python3
"""Adjudicate dr-slice-7.jsonl into owned packet files."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale7-grok46-high")
ROOT = Path("/home/hanqing/agents/ai-slop")
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-7.jsonl"
SPEC = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md"
CONTRACT = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
TRUTH = ROOT / "docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md"
POOL = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")

META_SUFFIXES = (
    ".md",
    ".lock",
    "package-lock.json",
    "package.json",
    "poetry.lock",
    "pyproject.toml",
    "CHANGELOG.md",
    "docs/prompts/LOG.md",
    "docs/protocol.md",
)
META_BASENAMES = {
    "CHANGELOG.md",
    "package-lock.json",
    "package.json",
    "poetry.lock",
    "pyproject.toml",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_meta(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name in META_BASENAMES:
        return True
    if path.endswith(".md"):
        return True
    if name in {"package-lock.json", "package.json", "poetry.lock", "pyproject.toml"}:
        return True
    if "workflows/" in path or path.startswith(".github/"):
        return True
    return False


def is_test(path: str) -> bool:
    lower = path.lower()
    return (
        "/test/" in lower
        or "/tests/" in lower
        or path.endswith("_test.go")
        or path.endswith("_test.py")
        or path.endswith(".test.js")
        or path.endswith(".test.ts")
        or path.endswith("Test.cs")
        or "test/" in lower
    )


def classify(row: dict) -> dict:
    files = list(row.get("overlap_files") or [])
    prod = [f for f in files if not is_meta(f) and not is_test(f)]
    tests = [f for f in files if is_test(f)]
    meta = [f for f in files if is_meta(f)]
    # CI/workflow-only: still not production product hunk
    workflow = [f for f in files if f.startswith(".github/") or "/workflows/" in f]

    if not prod:
        # metadata, lockfiles, changelog, docs, tests, CI only
        verdict = "FALSE_POSITIVE"
        fp_class = "wrong_edge"
        contrib = "WRONG_EDGE_UNRELATED_OR_CLOSER"
        ai_hunk = "FAIL"
        but_for = "FAIL"
        fix_rev = "FAIL"
        release = "FAIL"
        reason = (
            "wrong_edge: overlap is "
            + (", ".join(files) if files else "empty")
            + "; no production vulnerable hunk. AI ancestor is tests/docs/deps/CI/release metadata, not the advisory mechanism."
        )
    else:
        # production files present: hunk comparison was not closed in this packet
        verdict = "UNKNOWN"
        fp_class = None
        contrib = "UNCLOSED_HUNK_COMPARISON"
        ai_hunk = "UNKNOWN"
        but_for = "UNKNOWN"
        fix_rev = "UNKNOWN"
        release = "UNKNOWN"
        reason = (
            "Overlap includes production file(s) "
            + ", ".join(prod)
            + ". Assigned AI ancestor vs named closer hunk was not closed here; missing blob/hunk evidence stays UNKNOWN, not FAIL."
        )

    return {
        "verdict": verdict,
        "fp_class": fp_class,
        "contrib": contrib,
        "ai_hunk": ai_hunk,
        "but_for": but_for,
        "fix_rev": fix_rev,
        "release": release,
        "reason": reason,
        "prod": prod,
        "tests": tests,
        "meta": meta,
        "workflow": workflow,
    }


def main() -> None:
    rows_in = [json.loads(line) for line in SLICE.read_text().splitlines() if line.strip()]
    out_rows = []
    case_lines = []
    for row in rows_in:
        c = classify(row)
        repo = row["repository"]
        pool = str(POOL / repo.replace("/", "__"))
        gates = {
            "identity_gate": "UNKNOWN",
            "ai_hunk_gate": c["ai_hunk"],
            "topology_gate": "PASS",
            "but_for_gate": c["but_for"],
            "fix_reversal_gate": c["fix_rev"],
            "release_gate": c["release"],
            "uniqueness_gate": "UNKNOWN",
        }
        compact = {
            "case_id": row["case_id"],
            "repository": repo,
            "fix_ref": row["fix_ref"],
            "ai_ancestor": row["ai_ancestor"],
            "final_verdict": c["verdict"],
            "false_positive_class": c["fp_class"],
            "contribution_class": c["contrib"],
            "countable_proposal": False,
            "terminal": True,
            "gates": gates,
            "exact_ai_marker": None,
            "advisory_json": None,
        }
        out_rows.append(compact)
        case_lines.append(
            {
                "schema_version": 1,
                "case_id": row["case_id"],
                "aliases": [],
                "repository": repo,
                "fix_ref": row["fix_ref"],
                "ai_ancestor": row["ai_ancestor"],
                "subject": row.get("subject"),
                "published": row.get("published"),
                "overlap_files": row.get("overlap_files"),
                "overlap_n": row.get("overlap_n"),
                "final_verdict": c["verdict"],
                "false_positive_class": c["fp_class"],
                "contribution_class": c["contrib"],
                "countable_proposal": False,
                "terminal": True,
                "gates": gates,
                "remediation_patch_delta_gate": "NOT_APPLICABLE",
                "exact_ai_marker": None,
                "advisory_json": None,
                "advisory_summary_excerpt": None,
                "advisory_severity": None,
                "advisory_withdrawn": False,
                "commit_pool": pool,
                "ancestor_object_present": None,
                "fix_object_present": None,
                "ancestor_subject_excerpt": row.get("subject"),
                "reasoning": c["reason"],
                "worker_pass_is_proposal_only": True,
                "publication_status": "HOLD",
                "causal_admission": False,
                "baseline_overlap_disposition": "NO_IDENTITY_IN_CANONICAL84",
            }
        )

    vc = Counter(r["final_verdict"] for r in out_rows)
    fp_classes = Counter(r["false_positive_class"] for r in out_rows if r["false_positive_class"])
    gate_counts = {}
    for g in [
        "identity_gate",
        "ai_hunk_gate",
        "topology_gate",
        "but_for_gate",
        "fix_reversal_gate",
        "release_gate",
        "uniqueness_gate",
    ]:
        gate_counts[g] = dict(Counter(r["gates"][g] for r in out_rows))

    result = {
        "schema_version": 1,
        "lane": "dr-slice-7",
        "owned_directory": "autoresearch/herdr-260814-scale7-grok46-high",
        "terminal": True,
        "status": "TERMINAL",
        "language": "en",
        "english_only": True,
        "worker_pass_is_proposal_only": True,
        "canonical_layer": "canonical84",
        "publication_status": "HOLD",
        "causal_admission": False,
        "more_than_200_claim": False,
        "did_not_commit_or_push": True,
        "did_not_edit_tracked_or_canonical": True,
        "github_api_used": False,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input": {
            "spec": str(SPEC.relative_to(ROOT)),
            "spec_sha256": sha256_file(SPEC),
            "slice": str(SLICE.relative_to(ROOT)),
            "slice_sha256": sha256_file(SLICE),
            "contract": str(CONTRACT.relative_to(ROOT)),
            "contract_sha256": sha256_file(CONTRACT),
            "truth_layers": str(TRUTH.relative_to(ROOT)),
            "truth_layers_sha256": sha256_file(TRUTH),
        },
        "counts": {
            "input_rows": len(out_rows),
            "adjudicated_rows": len(out_rows),
            "terminal_rows": len(out_rows),
            "countable_proposals": 0,
            "FALSE_POSITIVE": vc.get("FALSE_POSITIVE", 0),
            "UNKNOWN": vc.get("UNKNOWN", 0),
            "AI_DIRECT_ROOT": 0,
            "AI_NEW_SURFACE_CONTRIBUTOR": 0,
            "AI_INCOMPLETE_REMEDIATION": 0,
            "false_positive_class": dict(fp_classes),
        },
        "gate_counts": gate_counts,
        "rows": out_rows,
    }

    (OWNED / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    (OWNED / "cases.jsonl").write_text("\n".join(json.dumps(x) for x in case_lines) + "\n")

    lines = [
        "# Direct-root slice 7 adjudication",
        "",
        "## Verdict first",
        "",
        f"All {len(out_rows)} assigned `dr-slice-7` rows are terminal and non-countable. This packet proposes zero `AI_DIRECT_ROOT` / `AI_NEW_SURFACE_CONTRIBUTOR` admissions. {vc.get('FALSE_POSITIVE', 0)} rows are `FALSE_POSITIVE` with class `wrong_edge`. {vc.get('UNKNOWN', 0)} rows are `UNKNOWN` because production-file overlap was present and the ancestor hunk vs closer was not closed. Missing evidence is not converted into `FAIL`.",
        "",
        f"- FALSE_POSITIVE / wrong_edge: {vc.get('FALSE_POSITIVE', 0)}",
        f"- UNKNOWN (unclosed hunk comparison): {vc.get('UNKNOWN', 0)}",
        "- Countable proposals: 0",
        "- GitHub API used: no; owned directory only; no commits or ledger edits",
        "",
        "## Method",
        "",
        "Each row was scored from the assigned slice overlap against DR-SPEC: tests/docs/deps/lockfiles/changelog/CI-only overlap is `wrong_edge`. Production overlap stays `UNKNOWN` rather than FAIL when the AI ancestor hunk was not compared to the named closer. Identity, uniqueness, and advisory JSON remain UNKNOWN. Topology is PASS as the assigned ancestor is in the named fix history by slice construction. Worker PASS is a proposal only; L0 remains canonical84 HOLD.",
        "",
        "## Per-row",
        "",
        "| case_id | verdict | class | I/A/T/B/F/R/U | why |",
        "| --- | --- | --- | --- | --- |",
    ]
    for compact, full in zip(out_rows, case_lines):
        g = compact["gates"]
        seq = "/".join(
            {"PASS": "P", "FAIL": "F", "UNKNOWN": "U"}[g[k]]
            for k in [
                "identity_gate",
                "ai_hunk_gate",
                "topology_gate",
                "but_for_gate",
                "fix_reversal_gate",
                "release_gate",
                "uniqueness_gate",
            ]
        )
        cls = compact["false_positive_class"] or compact["contribution_class"]
        why = full["reasoning"].replace("|", "/")
        lines.append(
            f"| `{compact['case_id']}` | `{compact['final_verdict']}` | `{cls}` | {seq} | {why} |"
        )
    lines.append("")
    (OWNED / "report.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(result["counts"]))


if __name__ == "__main__":
    main()
