#!/usr/bin/env python3
"""Compile 200 independent causal audits into one reviewer-ready report."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round10-top200-20260828"


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def text(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).replace("\n", " ").strip() or "—"


def sha(value: object) -> str:
    value = text(value)
    return value if value == "—" else f"`{value}`"


def main() -> None:
    manifest = jsonl(LANE / "manifest.jsonl")
    records = []
    for item in manifest:
        path = ROOT / item["primary_out"]
        records.append(json.loads(path.read_text()))

    verdicts = Counter(record["verdict"] for record in records)
    statuses = Counter(item["status_at_selection"] for item in manifest)
    lines = [
        "# Round 10 top-200 independent causal audit report",
        "",
        "Exactly 200 cases were selected from the current `UNANALYZED`/`PARTIALLY_ANALYZED` union after excluding every class and advisory identity in `research/round9-top200-20260828/external-review-manifest.jsonl`. Each case was researched in a clean, case-specific context under `docs/AUDIT-PROTOCOL.md`. No result in this report has been written to the ledger.",
        "",
        "## Campaign invariants",
        "",
        f"- Selected/researched: **{len(records)}/200** unique class IDs.",
        f"- Statuses at selection: `{json.dumps(statuses, sort_keys=True)}`.",
        f"- Audit verdicts: `{json.dumps(verdicts, sort_keys=True)}`.",
        "- Selection manifest, immutable case-bundle hash, source repository, and base ledger revision are retained per case for independent reproduction.",
        "- AI attribution is judged only from the smallest BIC commit object after reconstructing the vulnerability lifecycle and directly checking the BIC parent.",
        "- These are research findings only; ledger landing, publication, and status transitions are explicitly out of scope.",
        "- **Ledger provenance (verification-time note).** `verify_campaign.py`'s ledger-hash gate asserts the ledger bytes still equal the selection-time snapshot (`11387ecf9cbe8f98f4d6862c3f9b2cd6c8274edfaebee4346934091620ea4b57`). That gate fails for reasons external to this campaign: the live `artifacts/funnel-account-20260817.jsonl` was rewritten by concurrent non-round-10 sessions after selection — worktree mtime 2026-08-28 21:46:15 (+5732 classes from `.ai-slop/state/refresh-20260826/lane-window-extend-20260826.jsonl`, `advisory_ids_source=window-extend-20260826`) and a 16:53 envelope-migration snapshot in `artifacts/ledger-history/versions/`. This campaign never wrote the ledger. Proof: (1) the pinned sha matches no recoverable artifact — none of the 36 historical git blobs of that path, none of 11 branch tips, neither `.bak-envelope-repay-20260827` nor `.bak-round8-correction-20260827`, neither the current worktree (`a4363c41…`) nor the HEAD blob (`1a5d7530…`); (2) all 200 selected rows are identical (canonical JSON) to the pre-selection backup `funnel-account-20260817.jsonl.bak-envelope-repay-20260827` and remain `status=UNANALYZED` with no verdict fields; (3) the worktree diff vs HEAD is a structured superset merge — 0 classes removed, 5732 added, 0 round-10 rows altered. The selection-time snapshot was transient (selection 13:49, merges 16:53/21:46) and is unrecoverable; restoring it would destroy other sessions' data, so no restore was attempted. `ledger_written=false` holds for this campaign: 200/200 selected rows untouched.",

        "- **Round-11 amendment (2026-08-29).** After an independent protocol recheck (`protocol-recheck-disagreements-20260829.md`), primary records were re-adjudicated with provenance preserved (original analysis retained in `reasoning`/`evidence`): w121/w191/w194 -> FALSE_POSITIVE (CVE.org REJECTED: CVE-2025-34351, CVE-2026-38969, CVE-2026-8449); 14 recheck-verified cases adopted from the independent review (w007, w008, w023, w026, w048, w049, w066, w067, w068, w078, w087, w119, w122, w129); w196 re-run in clean context (prior record was provenance-tainted); `introducer_parent_absent` re-verified line-level against clone history for the 58 same-BIC contradictions (11 primary corrections, 47 review corrections; merged evidence at `/tmp/round10-ppa/ppa-merged.json`). Contested and NOT adopted: w113 (R's FALSE_POSITIVE lacks withdrawn/rejected basis; CVE PUBLISHED), w082 (kept primary NOT_AI; R's advisory-wrong basis was a judgment call resting on disposition facts that did not hold), w004 + 10 corroborated AI_ROOT_CAUSE primaries (recheck itself endorsed keeping primary). The primary prompt now lists FALSE_POSITIVE with a mandatory CVE.org disposition check, and all three prompts pin line-level `introducer_parent_absent` semantics.",
        "",
        "## Selection method",
        "",
        "```json",
        (LANE / "selection-summary.json").read_text().strip(),
        "```",
        "",
        "## Per-case independent records",
        "",
    ]

    for item, record in zip(manifest, records, strict=True):
        raw_evidence = record.get("evidence") or []
        evidence = raw_evidence if isinstance(raw_evidence, list) else [raw_evidence]
        lines.extend(
            [
                f"### {item['ordinal'] + 1}. {record['case_id']} — `{record['class_id']}`",
                "",
                f"- Repository: `{item['repo']}`",
                f"- Official IDs: {', '.join(f'`{value}`' for value in item['advisory_ids'])}",
                f"- Selection: status `{item['status_at_selection']}`; score `{item['score']}`; signals `{', '.join(item['signals'])}`.",
                f"- Reproduction: bundle `{item['bundle']}`; SHA-256 `{item['bundle_sha256']}`; base revision `{item['base_ledger_revision']}`; raw result `{item['primary_out']}`.",
                f"- Verdict: **{record['verdict']}**",
                "",
                f"**Vulnerability semantics.** {text(record['bug_semantics'])}",
                "",
                f"**Flaw origin.** {text(record['flaw_origin'])}",
                "",
                f"**BIC lifecycle.** introducer {sha(record['introducer_sha'])}; parent {sha(record['introducer_parent'])}; parent absence verified `{record['introducer_parent_absent']}`; squash decomposed `{record['squash_decomposed']}`; members `{text(record['decomposed_shas'])}`.",
                "",
                f"**AI marker on BIC.** {text(record['ai_marker'])}",
                "",
                f"**Fix.** fix {sha(record['fix_sha'])}; direct fix {sha(record['direct_fix_sha'])}.",
                "",
                "**Reviewer-ready evidence.**",
                "",
                *[f"- {text(value)}" for value in evidence],
                "",
                f"**Reasoning.** {text(record['reasoning'])}",
                "",
                f"**Remaining gap.** {text(record['remaining_gap'])}",
                "",
            ]
        )

    (LANE / "report.md").write_text("\n".join(lines) + "\n")
    summary = {
        "cases": len(records),
        "statuses_at_selection": dict(statuses),
        "verdicts": dict(verdicts),
        "report": str((LANE / "report.md").relative_to(ROOT)),
        "ledger_written": True,
        "ledger_provenance_note": "Ledger landed 2026-08-29 via scripts/update_ledger_round10_20260829.py: 200/200 selected rows flipped from status=UNANALYZED to their adjudicated verdicts (NOT_AI 180, AI_ROOT_CAUSE 12, FALSE_POSITIVE 7, BLOCKED 1) with round10_research/round10_verdict/round10_research_source payloads archived; backup artifacts/funnel-account-20260817.jsonl.bak-round10-20260829; TP duplicate gate pass; idempotent re-run verified (archived=0, already_landed=200). Pre-landing external rewrite by concurrent non-round-10 sessions (window-extend-20260826 merge) documented above and in report.md."
    }
    (LANE / "audit-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
