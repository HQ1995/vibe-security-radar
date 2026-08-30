#!/usr/bin/env python3
"""Build the glm-5.3-flash vs independent-Grok disagreement report for round 10."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round10-top200-20260828"
OUT = LANE / "disagreement-report.md"
JSONL = LANE / "disagreements.jsonl"


def records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def clip(value: object, n: int = 900) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= n:
        return text
    return text[: n - 1] + "…"


def md_escape(value: object) -> str:
    return str(value or "").replace("|", "\\|")


def sha(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text or text in {"none", "null"}:
        return "—"
    return text


def topic_label(topic: str) -> str:
    return {
        "verdict": "verdict",
        "introducer_sha": "BIC SHA",
        "introducer_parent": "BIC parent",
        "parent_absence": "parent-absence flag",
        "fix_sha": "fix SHA",
        "repo": "repo",
        "marker_state": "AI-marker presence",
    }.get(topic, topic)


def main() -> None:
    summary_path = LANE / "comparison-summary.json"
    comparison_path = LANE / "comparison.jsonl"
    if not comparison_path.exists():
        raise SystemExit("comparison.jsonl missing; run compare_results.py first")
    comparisons = records(comparison_path)
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}

    verdict_disagreements = [row for row in comparisons if row.get("verdict_disagreement")]
    other_disagreements = [
        row for row in comparisons if row.get("needs_adjudication") and not row.get("verdict_disagreement")
    ]
    agreements = [row for row in comparisons if not row.get("needs_adjudication")]

    pair_counts = Counter((row["glm_verdict"], row["grok_verdict"]) for row in verdict_disagreements)
    topic_counts = Counter(topic for row in comparisons for topic in row.get("disagreement_topics") or [])

    JSONL.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False) + "\n"
            for row in comparisons
            if row.get("needs_adjudication")
        )
    )

    lines: list[str] = []
    lines.append("# Round 10 independent re-review — disagreement report")
    lines.append("")
    lines.append(
        "Independent Grok re-review of the 200 cases in "
        "`research/round10-top200-20260828/` versus the glm-5.3-flash primary "
        "campaign (`primary/wNNN.json`). Reviewers were assigned the same "
        "case bundles and `docs/AUDIT-PROTOCOL.md` and were forbidden from "
        "reading `primary/`, `report.md`, or other workers' outputs."
    )
    lines.append("")
    lines.append("Ledger was not written. These are research findings only.")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append(f"- Cases in the campaign: **200**")
    lines.append(f"- Independent reviews compared: **{summary.get('cases_compared', len(comparisons))}**")
    missing = summary.get("missing_review") or []
    invalid = summary.get("invalid_review") or []
    if missing:
        lines.append(f"- Missing independent reviews: `{', '.join(missing)}`")
    else:
        lines.append("- Missing independent reviews: **none**")
    if invalid:
        lines.append(f"- Invalid independent reviews: `{invalid}`")
    else:
        lines.append("- Invalid independent reviews: **none**")
    lines.append(
        f"- glm-5.3-flash verdicts: `{json.dumps(summary.get('glm_verdicts') or dict(Counter(r['glm_verdict'] for r in comparisons)), sort_keys=True)}`"
    )
    lines.append(
        f"- Independent Grok verdicts: `{json.dumps(summary.get('grok_verdicts') or dict(Counter(r['grok_verdict'] for r in comparisons)), sort_keys=True)}`"
    )
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append(
        f"- Full core agreement (verdict + BIC + parent + parent-absence + fix + repo + AI-marker state): "
        f"**{len(agreements)} / {len(comparisons)}**"
    )
    lines.append(
        f"- Any disagreement topic (needs adjudication): **{len(verdict_disagreements) + len(other_disagreements)}**"
    )
    lines.append(f"- **Verdict disagreements (this report's primary set): {len(verdict_disagreements)}**")
    lines.append(
        f"- Same verdict, different BIC/fix/marker/parent: **{len(other_disagreements)}** "
        "(listed in an appendix; they are disagreements, but not verdict flips)"
    )
    lines.append("")
    lines.append("### Verdict-pair matrix (glm-5.3-flash → Grok)")
    lines.append("")
    if pair_counts:
        lines.append("| glm-5.3-flash | independent Grok | n |")
        lines.append("|---|---|---|")
        for (a, b), n in sorted(pair_counts.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1])):
            lines.append(f"| `{md_escape(a)}` | `{md_escape(b)}` | {n} |")
    else:
        lines.append("No verdict disagreements.")
    lines.append("")
    lines.append("### Disagreement topics (all compared cases)")
    lines.append("")
    if topic_counts:
        lines.append("| topic | n |")
        lines.append("|---|---|")
        for topic, n in topic_counts.most_common():
            lines.append(f"| {topic_label(topic)} | {n} |")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## Verdict disagreements")
    lines.append("")
    if not verdict_disagreements:
        lines.append("None. glm-5.3-flash and independent Grok assigned the same verdict on every compared case.")
        lines.append("")
    else:
        lines.append(
            "Every case below has a different `verdict` between glm-5.3-flash (`primary/`) "
            "and independent Grok (`review/`). Evidence quotes are clipped; full records remain "
            "in those JSON files."
        )
        lines.append("")
        for i, row in enumerate(verdict_disagreements, 1):
            topics = ", ".join(topic_label(t) for t in row.get("disagreement_topics") or [])
            lines.append(
                f"### {i}. `{row['worker']}` — {row.get('case_id') or row.get('class_id')} — `{row.get('repo')}`"
            )
            lines.append("")
            lines.append(f"- class_id: `{row.get('class_id')}`")
            ids = row.get("advisory_ids") or []
            lines.append(f"- advisory_ids: `{', '.join(map(str, ids))}`")
            lines.append(f"- glm-5.3-flash verdict: **{row.get('glm_verdict')}**")
            lines.append(f"- independent Grok verdict: **{row.get('grok_verdict')}**")
            lines.append(f"- disagreement topics: {topics or 'verdict'}")
            lines.append(f"- glm BIC: `{sha(row.get('glm_introducer_sha'))}`")
            lines.append(f"- grok BIC: `{sha(row.get('grok_introducer_sha'))}`")
            lines.append(f"- glm parent: `{sha(row.get('glm_introducer_parent'))}`")
            lines.append(f"- grok parent: `{sha(row.get('grok_introducer_parent'))}`")
            lines.append(f"- glm fix: `{sha(row.get('glm_fix_sha'))}`")
            lines.append(f"- grok fix: `{sha(row.get('grok_fix_sha'))}`")
            lines.append("")
            lines.append("**glm-5.3-flash AI marker.**")
            lines.append("")
            lines.append(clip(row.get("glm_ai_marker"), 500) or "—")
            lines.append("")
            lines.append("**independent Grok AI marker.**")
            lines.append("")
            lines.append(clip(row.get("grok_ai_marker"), 500) or "—")
            lines.append("")
            lines.append("**glm-5.3-flash bug semantics.**")
            lines.append("")
            lines.append(clip(row.get("glm_bug_semantics")) or "—")
            lines.append("")
            lines.append("**independent Grok bug semantics.**")
            lines.append("")
            lines.append(clip(row.get("grok_bug_semantics")) or "—")
            lines.append("")
            lines.append("**glm-5.3-flash flaw origin.**")
            lines.append("")
            lines.append(clip(row.get("glm_flaw_origin")) or "—")
            lines.append("")
            lines.append("**independent Grok flaw origin.**")
            lines.append("")
            lines.append(clip(row.get("grok_flaw_origin")) or "—")
            lines.append("")
            lines.append("**glm-5.3-flash reasoning.**")
            lines.append("")
            lines.append(clip(row.get("glm_reasoning"), 1200) or "—")
            lines.append("")
            lines.append("**independent Grok reasoning.**")
            lines.append("")
            lines.append(clip(row.get("grok_reasoning"), 1200) or "—")
            lines.append("")
            glm_gap = row.get("glm_remaining_gap")
            grok_gap = row.get("grok_remaining_gap")
            if glm_gap or grok_gap:
                lines.append("**remaining_gap.**")
                lines.append("")
                lines.append(f"- glm: {clip(glm_gap, 400) or '—'}")
                lines.append(f"- grok: {clip(grok_gap, 400) or '—'}")
                lines.append("")

    lines.append("## Appendix — same verdict, other disagreements")
    lines.append("")
    if not other_disagreements:
        lines.append("None.")
        lines.append("")
    else:
        lines.append(
            "These cases share a verdict but disagree on BIC SHA, parent, parent-absence, "
            "fix SHA, repo, and/or AI-marker presence. They are included because the goal "
            "asked for every disagreement with glm-5.3-flash, not only verdict flips."
        )
        lines.append("")
        lines.append("| worker | case | repo | verdict | topics | glm BIC | grok BIC | glm fix | grok fix |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for row in other_disagreements:
            topics = ", ".join(topic_label(t) for t in row.get("disagreement_topics") or [])
            lines.append(
                "| `{worker}` | {case} | `{repo}` | {verdict} | {topics} | `{gb}` | `{rb}` | `{gf}` | `{rf}` |".format(
                    worker=row["worker"],
                    case=md_escape(row.get("case_id") or row.get("class_id")),
                    repo=md_escape(row.get("repo")),
                    verdict=md_escape(row.get("glm_verdict")),
                    topics=md_escape(topics),
                    gb=sha(row.get("glm_introducer_sha"))[:12],
                    rb=sha(row.get("grok_introducer_sha"))[:12],
                    gf=sha(row.get("glm_fix_sha"))[:12],
                    rf=sha(row.get("grok_fix_sha"))[:12],
                )
            )
        lines.append("")
        for i, row in enumerate(other_disagreements, 1):
            topics = ", ".join(topic_label(t) for t in row.get("disagreement_topics") or [])
            lines.append(
                f"### A{i}. `{row['worker']}` — {row.get('case_id') or row.get('class_id')} — `{row.get('repo')}`"
            )
            lines.append("")
            lines.append(f"- shared verdict: **{row.get('glm_verdict')}**")
            lines.append(f"- disagreement topics: {topics}")
            lines.append(f"- glm BIC / parent / fix: `{sha(row.get('glm_introducer_sha'))}` / `{sha(row.get('glm_introducer_parent'))}` / `{sha(row.get('glm_fix_sha'))}`")
            lines.append(f"- grok BIC / parent / fix: `{sha(row.get('grok_introducer_sha'))}` / `{sha(row.get('grok_introducer_parent'))}` / `{sha(row.get('grok_fix_sha'))}`")
            lines.append(f"- glm AI marker: {clip(row.get('glm_ai_marker'), 280) or '—'}")
            lines.append(f"- grok AI marker: {clip(row.get('grok_ai_marker'), 280) or '—'}")
            lines.append("")
            lines.append(f"- glm flaw origin: {clip(row.get('glm_flaw_origin'), 500) or '—'}")
            lines.append(f"- grok flaw origin: {clip(row.get('grok_flaw_origin'), 500) or '—'}")
            lines.append("")

    lines.append("## Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("python3 research/round10-top200-20260828/compare_results.py")
    lines.append("python3 research/round10-top200-20260828/build_disagreement_report.py")
    lines.append("```")
    lines.append("")
    lines.append("Outputs: `comparison.jsonl`, `comparison-summary.json`, `disagreements.jsonl`, `disagreement-report.md`.")
    lines.append("")

    OUT.write_text("\n".join(lines) + "\n")
    print(
        json.dumps(
            {
                "compared": len(comparisons),
                "verdict_disagreements": len(verdict_disagreements),
                "other_disagreements": len(other_disagreements),
                "core_agreement": len(agreements),
                "report": str(OUT),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
