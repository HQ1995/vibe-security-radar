#!/usr/bin/env python3
"""Compare 200 blind primary/reviewer AuditResults."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"


def records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def marker_state(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "missing"
    if any(token in text for token in ("absent", "none on", "no ai", "no co-authored", "human; no")):
        return "absent"
    return "present"


def fix(record: dict) -> str | None:
    return record.get("direct_fix_sha") or record.get("fix_sha")


def main() -> None:
    manifest = records(LANE / "manifest.jsonl")
    comparisons = []
    for item in manifest:
        primary = json.loads((ROOT / item["primary_out"]).read_text())
        review = json.loads((ROOT / item["review_out"]).read_text())
        topics = []
        checks = {
            "verdict": primary["verdict"] == review["verdict"],
            "introducer_sha": primary["introducer_sha"] == review["introducer_sha"],
            "introducer_parent": primary["introducer_parent"] == review["introducer_parent"],
            "parent_absence": primary["introducer_parent_absent"] == review["introducer_parent_absent"],
            "fix_sha": fix(primary) == fix(review),
            "repo": primary["repo"].lower() == review["repo"].lower(),
            "marker_state": marker_state(primary["ai_marker"]) == marker_state(review["ai_marker"]),
        }
        topics.extend(key for key, agrees in checks.items() if not agrees)
        comparisons.append(
            {
                "worker": item["worker"],
                "class_id": item["class_id"],
                "case_id": primary["case_id"],
                "repo": item["repo"],
                "primary_verdict": primary["verdict"],
                "review_verdict": review["verdict"],
                "primary_introducer_sha": primary["introducer_sha"],
                "review_introducer_sha": review["introducer_sha"],
                "primary_fix_sha": fix(primary),
                "review_fix_sha": fix(review),
                "checks": checks,
                "disagreement_topics": topics,
                "needs_adjudication": bool(topics),
            }
        )
    (LANE / "comparison.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in comparisons)
    )
    summary = {
        "cases": len(comparisons),
        "core_agreement": sum(not row["needs_adjudication"] for row in comparisons),
        "needs_adjudication": sum(row["needs_adjudication"] for row in comparisons),
        "primary_verdicts": dict(Counter(row["primary_verdict"] for row in comparisons)),
        "review_verdicts": dict(Counter(row["review_verdict"] for row in comparisons)),
        "disagreement_topics": dict(
            Counter(topic for row in comparisons for topic in row["disagreement_topics"])
        ),
    }
    (LANE / "comparison-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
