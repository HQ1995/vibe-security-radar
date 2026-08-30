#!/usr/bin/env python3
"""Generate the complete human double-confirm report for all 200 cases."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def text(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).replace("\n", " ").strip() or "—"


def short_sha(value: object) -> str:
    value = text(value)
    return value if value == "—" else f"`{value}`"


def main() -> None:
    manifest = {row["worker"]: row for row in jsonl(LANE / "manifest.jsonl")}
    comparisons = {row["worker"]: row for row in jsonl(LANE / "comparison.jsonl")}
    finals = jsonl(LANE / "final-records.jsonl")
    summary = json.loads((LANE / "finalization-summary.json").read_text())
    comparison_summary = json.loads((LANE / "comparison-summary.json").read_text())
    lines = [
        "# Round 9 top-200 causal audit — complete double-confirm report",
        "",
        "Exactly 200 cases selected from the current UNANALYZED/PARTIALLY_ANALYZED union by the frozen manifest. Each case received two blind, clean-context audits under `docs/AUDIT-PROTOCOL.md`; core disagreements received a third adjudication. This report retains both blind judgments and the final reviewer-ready evidence chain.",
        "",
        "## Campaign invariants",
        "",
        f"- Selected/finished: **{summary['cases']}/200** unique class IDs and disjoint official advisory identities.",
        f"- Blind core agreement: **{comparison_summary['core_agreement']}**; adjudicated: **{comparison_summary['needs_adjudication']}**.",
        f"- Final verdicts: `{json.dumps(summary['verdicts'], sort_keys=True)}`.",
        f"- Final ledger states: `{json.dumps(summary['ledger_statuses'], sort_keys=True)}`.",
        f"- Duplicate-TP gate: **{summary['duplicate_tp_gate']}**; terminal envelope gate: **{summary['terminal_envelope_gate']}**.",
        f"- Accepted contract corrections: **{sum(len(row.get('correction_assessment_ids') or []) for row in finals)}** assessment links, including **{sum(any('correction2' in value for value in row.get('correction_assessment_ids') or []) for row in finals)}** post-final reasoning alignments; every superseded assessment remains immutable in Neon.",
        "- Primary and reviewer contexts contained only the assigned bundle, validated clone, advisory, and sanitized same-repository mechanism hits; neither saw prior case verdicts or each other's result.",
        "- AI attribution uses the BIC commit object only. PR-body disclosure, branch names, later AI refactors, and AI-only-on-fix are not BIC attribution.",
        "",
        "## Selection method",
        "",
        (LANE / "selection-summary.json").read_text().strip(),
        "",
        "## Per-case double-confirm records",
        "",
    ]
    for final in finals:
        worker = final["worker"]
        item = manifest[worker]
        comparison = comparisons[worker]
        primary = final["primary_record"]
        review = final["review_record"]
        record = final["audit_record"]
        lines.extend(
            [
                f"### {item['ordinal'] + 1}. {record['case_id']} — `{final['class_id']}`",
                "",
                f"- Repository: `{item['repo']}`",
                f"- Official IDs: {', '.join(f'`{value}`' for value in item['advisory_ids'])}",
                f"- Selection: score `{item['score']}`; signals `{', '.join(item['signals'])}`; base revision `{item['base_ledger_revision']}`.",
                f"- Primary: **{primary['verdict']}**; BIC {short_sha(primary['introducer_sha'])}; fix {short_sha(primary['direct_fix_sha'] or primary['fix_sha'])}; parent absence `{primary['introducer_parent_absent']}`.",
                f"- Reviewer: **{review['verdict']}**; BIC {short_sha(review['introducer_sha'])}; fix {short_sha(review['direct_fix_sha'] or review['fix_sha'])}; parent absence `{review['introducer_parent_absent']}`.",
                f"- Comparison: `{'AGREE' if not comparison['needs_adjudication'] else 'ADJUDICATED'}`; topics `{', '.join(comparison['disagreement_topics']) or 'none'}`.",
                f"- Accepted assessments: {', '.join(f'`{value}`' for value in final['assessment_ids'])}.",
                f"- Contract corrections: {', '.join(f'`{value}`' for value in final.get('correction_assessment_ids') or []) or 'none'}.",
                f"- Final: **{record['verdict']}** → ledger `{final['ledger_status']}` via `{final['final_source']}`.",
                "",
                f"**Vulnerability semantics.** {text(record['bug_semantics'])}",
                "",
                f"**Flaw origin.** {text(record['flaw_origin'])}",
                "",
                f"**BIC lifecycle.** introducer {short_sha(record['introducer_sha'])}; parent {short_sha(record['introducer_parent'])}; parent absence verified `{record['introducer_parent_absent']}`; squash decomposed `{record['squash_decomposed']}`; members `{text(record['decomposed_shas'])}`.",
                "",
                f"**AI marker on BIC.** {text(record['ai_marker'])}",
                "",
                f"**Fix.** fix {short_sha(record['fix_sha'])}; direct fix {short_sha(record['direct_fix_sha'])}.",
                "",
                f"**Evidence for double confirmation.** {text(record['evidence'])}",
                "",
                f"**Reasoning.** {text(record['reasoning'])}",
                "",
                f"**Remaining gap.** {text(record['remaining_gap'])}",
                "",
            ]
        )
    (LANE / "report.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({"cases": len(finals), "report": str(LANE / 'report.md')}))


if __name__ == "__main__":
    main()
