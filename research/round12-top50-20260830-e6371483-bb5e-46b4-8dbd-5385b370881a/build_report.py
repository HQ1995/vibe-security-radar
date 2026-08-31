#!/usr/bin/env python3
"""Build the independent review report from 50 validated case JSON files."""
from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LANE = Path(__file__).resolve().parent
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    validation = subprocess.run(
        ["python3", str(LANE / "validate_results.py")],
        check=True,
        capture_output=True,
        text=True,
    )
    verified = json.loads(validation.stdout)
    manifest = jsonl(LANE / "manifest.jsonl")
    selection = json.loads((LANE / "selection-summary.json").read_text())
    records = {
        row["worker"]: json.loads((ROOT / row["primary_out"]).read_text())
        for row in manifest
    }
    verdicts = Counter(record["verdict"] for record in records.values())
    current_ledger_sha = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    lines = [
        "# Round12 top-50 clean-context causal audits",
        "",
        "Independent, read-only research report. No result in this lane has been",
        "landed to Neon or written to the canonical ledger. Each case was assigned",
        "to one fresh subagent context and audited under `docs/AUDIT-PROTOCOL.md`.",
        "",
        "## Selection and integrity",
        "",
        f"- selected/result count: {selection['selected']}/{verified['records']}",
        f"- selection statuses: `{selection['selection_statuses']}`",
        f"- repositories: {selection['repositories']} (maximum five cases per repo)",
        f"- score range: {selection['score_max']} .. {selection['score_min']}",
        f"- excluded prior/in-flight classes: {selection['excluded_classes']}",
        f"- excluded advisory identities: {selection['excluded_advisories']}",
        f"- full-history non-shallow clones at freeze: {selection['clone_ready_full_history']}/50",
        f"- manifest sha256: `{hashlib.sha256((LANE / 'manifest.jsonl').read_bytes()).hexdigest()}`",
        f"- ledger sha256 at selection freeze: `{selection['ledger_sha256_at_freeze']}`",
        f"- ledger sha256 when report built: `{current_ledger_sha}`",
        f"- result validation problems: {len(verified['problems'])}",
        "",
        "The ledger may change concurrently outside this lane; the two hashes are",
        "reported as observations, not as a claim that this lane landed anything.",
        "Ranking is a review-priority heuristic, not causal evidence. Repository-level",
        "AI activity contributes to selection only; verdicts require BIC-local proof.",
        "",
        "## Verdict histogram",
        "",
    ]
    for verdict, count in verdicts.most_common():
        lines.append(f"- `{verdict}`: {count}")
    lines.extend([
        "",
        "## Review index",
        "",
        "| worker | case | repo | verdict | BIC | direct fix | result sha256 |",
        "|---|---|---|---|---|---|---|",
    ])
    for assignment in manifest:
        worker = assignment["worker"]
        record = records[worker]
        lines.append(
            f"| {worker} | {record['case_id']} | {record['repo']} | `{record['verdict']}` | "
            f"`{(record.get('introducer_sha') or '—')[:12]}` | "
            f"`{(record.get('direct_fix_sha') or record.get('fix_sha') or '—')[:12]}` | "
            f"`{verified['result_sha256'][worker]}` |"
        )

    lines.extend(["", "## Case dossiers", ""])
    for assignment in manifest:
        worker = assignment["worker"]
        record = records[worker]
        lines.extend([
            f"### {worker} — {record['case_id']} — `{record['verdict']}`",
            "",
            f"- class: `{record['class_id']}`",
            f"- repository: `{record['repo']}`",
            f"- review context: `{record['review_agent_id']}`",
            f"- bundle sha256: `{record['input_binding']['bundle_sha256']}`",
            f"- clone HEAD at freeze: `{record['input_binding']['clone_head_sha']}`",
            f"- introducer: `{record.get('introducer_sha') or 'null'}`",
            f"- immediate parent: `{record.get('introducer_parent') or 'null'}`",
            f"- direct fix: `{record.get('direct_fix_sha') or 'null'}`",
            f"- fix/carrier: `{record.get('fix_sha') or 'null'}`",
            "",
            f"**Mechanism.** {record['bug_semantics']}",
            "",
            f"**Origin.** {record['flaw_origin']}",
            "",
            f"**AI marker.** `{record['ai_marker']['state']}` — " + " ".join(record['ai_marker']['evidence']),
            "",
            f"**Reasoning.** {record['reasoning']}",
        ])
        if record.get("remaining_gap"):
            lines.extend(["", f"**Remaining gap.** {record['remaining_gap']}"])
        lines.extend(["", "Protocol checks:", ""])
        for name, check in record["protocol_checks"].items():
            lines.append(f"- `{name}` — **{check['status']}**: " + " ".join(check["evidence"]))
        lines.extend(["", "Primary/Git evidence:", ""])
        lines.extend(f"- {item}" for item in record["evidence"])
        lines.append("")

    (LANE / "report.md").write_text("\n".join(lines))
    print(json.dumps({"cases": len(records), "verdicts": dict(verdicts), "report": str((LANE / 'report.md').relative_to(ROOT))}))


if __name__ == "__main__":
    main()
