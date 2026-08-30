#!/usr/bin/env python3
"""Write the round11 campaign report from frozen manifest + primary records."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round11-top500-20260829"


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    manifest = jsonl(LANE / "manifest.jsonl")
    summary = json.loads((LANE / "selection-summary.json").read_text())
    coverage = json.loads((LANE / "coverage.json").read_text())
    landing = json.loads((LANE / "ledger-landing-result.json").read_text())
    records = []
    for item in manifest:
        path = ROOT / item["primary_out"]
        records.append(json.loads(path.read_text()))
    verdicts = Counter(record["verdict"] for record in records)
    lines = [
        "# Round11 top-500 remaining-open TP-likelihood audits",
        "",
        "Wave of 500 `UNANALYZED`/`PARTIALLY_ANALYZED` ledger cases ranked for",
        "true-positive likelihood after excluding every class/advisory in",
        "`research/round10-top200-20260828/`. Protocol:",
        "`docs/AUDIT-PROTOCOL.md`. The reconciled results were landed to the canonical",
        "Neon ledger and exported to the repository after all publication gates passed.",
        "",
        "## Selection",
        "",
        f"- eligible open after round10 exclude: {summary['eligible']}",
        f"- selected: {summary['target']}",
        f"- statuses: `{summary['selected_statuses']}`",
        f"- repositories: {summary['selected_repositories']} (cap {summary['repo_cap']})",
        f"- score range: {summary['score_max']} .. {summary['score_min']}",
        f"- clone-ready at freeze: {summary['clone_ready_cases']}",
        f"- known-TP-repo cases: {summary['known_tp_repo_cases']}",
        f"- excluded overlap: {summary['excluded_overlap']}",
        f"- ledger sha256 at freeze: `{summary['ledger_sha256_at_freeze']}`",
        f"- ledger sha256 at verification: `{coverage['ledger_sha256_live']}`",
        f"- ledger changed since freeze: `{coverage['ledger_changed_since_freeze']}`",
        f"- frozen selection recomputed from live ledger: `{coverage['selection_recomputed']}`",
        "",
        "## Verdict histogram",
        "",
    ]
    for verdict, count in verdicts.most_common():
        lines.append(f"- `{verdict}`: {count}")
    review_paths = sorted((LANE / "independent-review").glob("w[0-9][0-9][0-9].json"))
    reviews = [json.loads(path.read_text()) for path in review_paths]
    if reviews:
        review_verdicts = Counter(review["review_verdict"] for review in reviews)
        lines.extend([
            "",
            "## Independent review of the original completed set",
            "",
            f"- reviewed records: {len(reviews)}",
        ])
        for verdict, count in review_verdicts.most_common():
            lines.append(f"- `{verdict}`: {count}")
        lines.extend([
            "",
            "These are the historical second-pass findings for the original 389-record set.",
        ])
        for verdict in ("CORRECTION_REQUIRED", "EVIDENCE_GAP", "BLOCKED"):
            workers = [r["worker"] for r in reviews if r["review_verdict"] == verdict]
            if workers:
                lines.extend(["", f"### {verdict}", "", " ".join(workers)])
    correction_path = LANE / "canonical-corrections.jsonl"
    if correction_path.exists():
        corrections = jsonl(correction_path)
        scopes = Counter(row["correction_scope"] for row in corrections)
        lines.extend([
            "",
            "## Disagreement re-review landing",
            "",
            f"- re-researched cases: {len(corrections)}",
        ])
        for scope in ("CORRECTION_REQUIRED", "FIELD_ERRATUM", "CONFIRMED", "EVIDENCE_GAP"):
            lines.append(f"- `{scope}`: {scopes[scope]}")
        lines.extend([
            "",
            "The 33-case clean-context disagreement re-review has been reconciled into",
            "the canonical primary records. `FIELD_ERRATUM` is a derived landing scope,",
            "not a new protocol review-verdict enum. Six `CONFIRMED` cases required no",
            "canonical field change.",
        ])
    review111 = [
        json.loads(path.read_text())
        for path in sorted((LANE / "independent-review-111").glob("w[0-9][0-9][0-9].json"))
    ]
    review111_verdicts = Counter(row["review_verdict"] for row in review111)
    reconciliation111 = jsonl(LANE / "review-111-reconciliation.jsonl")
    lines.extend([
        "",
        "## Independent review of the final 111 and reconciliation",
        "",
        f"- reviewed records: {len(review111)}",
    ])
    for verdict, count in review111_verdicts.most_common():
        lines.append(f"- `{verdict}`: {count}")
    lines.extend([
        f"- substantive reconciliation records: {len(reconciliation111)}",
        "- accepted verdict changes: `w350 NOT_AI → EVIDENCE_GAP`; `w434 EVIDENCE_GAP → NOT_AI`",
        "- rejected verdict change: `w440 FALSE_POSITIVE → NOT_AI`",
        "",
        "## Canonical ledger landing",
        "",
        f"- run id: `{landing['run_id']}`",
        f"- change set id: `{landing['change_set_id']}`",
        f"- rows finalized: {landing['rows']}",
        f"- assessments appended: {landing['assessments']}",
        f"- exported ledger sha256: `{landing['export_sha256']}`",
        f"- local export equals canonical database: `{landing['database_export_identical']}`",
        f"- publication records: {landing['publication_records']}",
        f"- publication gate: `{landing['publication_gate']}`",
    ])
    lines.extend(["", "## Cases", ""])
    lines.append("| worker | class_id | case_id | repo | verdict | introducer | fix |")
    lines.append("|---|---|---|---|---|---|---|")
    for item, record in zip(manifest, records, strict=True):
        lines.append(
            "| {worker} | `{cid}` | {case} | {repo} | {verdict} | `{intro}` | `{fix}` |".format(
                worker=item["worker"],
                cid=record["class_id"],
                case=record.get("case_id") or "",
                repo=record["repo"],
                verdict=record["verdict"],
                intro=(record.get("introducer_sha") or "")[:12] or "—",
                fix=(record.get("fix_sha") or record.get("direct_fix_sha") or "")[:12] or "—",
            )
        )
    lines.append("")
    (LANE / "report.md").write_text("\n".join(lines))
    print(json.dumps({"cases": len(records), "verdicts": dict(verdicts)}))


if __name__ == "__main__":
    main()
