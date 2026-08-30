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
        "`docs/AUDIT-PROTOCOL.md`. This wave does not land ledger rows.",
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
            "These second-pass verdicts are review findings; they do not silently mutate",
            "the primary records below. The 111 records completed after the original freeze",
            "were each audited by their own clean-context worker but are not part of this",
            "389-record second-pass set.",
        ])
        for verdict in ("CORRECTION_REQUIRED", "EVIDENCE_GAP", "BLOCKED"):
            workers = [r["worker"] for r in reviews if r["review_verdict"] == verdict]
            if workers:
                lines.extend(["", f"### {verdict}", "", " ".join(workers)])
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
