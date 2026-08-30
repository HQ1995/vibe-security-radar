#!/usr/bin/env python3
"""Compare glm-5.3-flash primary vs independent grok review for round10."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round10-top200-20260828"
EXPECTED_KEYS = [
    "class_id", "case_id", "repo", "advisory_ids", "bug_semantics", "flaw_origin",
    "introducer_sha", "introducer_parent", "introducer_parent_absent", "squash_decomposed",
    "decomposed_shas", "ai_marker", "verdict", "fix_sha", "direct_fix_sha", "evidence",
    "reasoning", "remaining_gap",
]


def records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def marker_state(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "missing"
    if any(token in text for token in ("absent", "none on", "no ai", "no co-authored", "human; no", "no marker")):
        return "absent"
    return "present"


def fix(record: dict) -> str | None:
    return record.get("direct_fix_sha") or record.get("fix_sha")


def sha_norm(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text or text in {"none", "null"}:
        return None
    return text


def main() -> None:
    manifest = records(LANE / "manifest.jsonl")
    comparisons = []
    missing_review = []
    invalid_review = []
    for item in manifest:
        primary = json.loads((ROOT / item["primary_out"]).read_text())
        review_path = ROOT / item["review_out"]
        if not review_path.exists():
            missing_review.append(item["worker"])
            continue
        try:
            review = json.loads(review_path.read_text())
        except json.JSONDecodeError as exc:
            invalid_review.append({"worker": item["worker"], "error": str(exc)})
            continue
        if list(review.keys())[:18] != EXPECTED_KEYS and set(EXPECTED_KEYS) - set(review.keys()):
            invalid_review.append({"worker": item["worker"], "error": "missing keys", "keys": list(review.keys())})
        topics = []
        checks = {
            "verdict": primary.get("verdict") == review.get("verdict"),
            "introducer_sha": sha_norm(primary.get("introducer_sha")) == sha_norm(review.get("introducer_sha")),
            "introducer_parent": sha_norm(primary.get("introducer_parent")) == sha_norm(review.get("introducer_parent")),
            "parent_absence": bool(primary.get("introducer_parent_absent")) == bool(review.get("introducer_parent_absent")),
            "fix_sha": sha_norm(fix(primary)) == sha_norm(fix(review)),
            "repo": str(primary.get("repo") or "").lower() == str(review.get("repo") or "").lower(),
            "marker_state": marker_state(primary.get("ai_marker")) == marker_state(review.get("ai_marker")),
        }
        topics.extend(key for key, agrees in checks.items() if not agrees)
        comparisons.append(
            {
                "worker": item["worker"],
                "class_id": item["class_id"],
                "case_id": review.get("case_id") or primary.get("case_id"),
                "repo": item["repo"],
                "advisory_ids": item.get("advisory_ids"),
                "glm_verdict": primary.get("verdict"),
                "grok_verdict": review.get("verdict"),
                "glm_introducer_sha": sha_norm(primary.get("introducer_sha")),
                "grok_introducer_sha": sha_norm(review.get("introducer_sha")),
                "glm_introducer_parent": sha_norm(primary.get("introducer_parent")),
                "grok_introducer_parent": sha_norm(review.get("introducer_parent")),
                "glm_fix_sha": sha_norm(fix(primary)),
                "grok_fix_sha": sha_norm(fix(review)),
                "glm_ai_marker": primary.get("ai_marker"),
                "grok_ai_marker": review.get("ai_marker"),
                "glm_remaining_gap": primary.get("remaining_gap"),
                "grok_remaining_gap": review.get("remaining_gap"),
                "glm_bug_semantics": primary.get("bug_semantics"),
                "grok_bug_semantics": review.get("bug_semantics"),
                "glm_flaw_origin": primary.get("flaw_origin"),
                "grok_flaw_origin": review.get("flaw_origin"),
                "glm_reasoning": primary.get("reasoning"),
                "grok_reasoning": review.get("reasoning"),
                "checks": checks,
                "disagreement_topics": topics,
                "verdict_disagreement": not checks["verdict"],
                "needs_adjudication": bool(topics),
            }
        )
    (LANE / "comparison.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in comparisons)
    )
    verdict_pairs = Counter((row["glm_verdict"], row["grok_verdict"]) for row in comparisons if row["verdict_disagreement"])
    summary = {
        "cases_compared": len(comparisons),
        "missing_review": missing_review,
        "invalid_review": invalid_review,
        "core_agreement": sum(not row["needs_adjudication"] for row in comparisons),
        "needs_adjudication": sum(row["needs_adjudication"] for row in comparisons),
        "verdict_disagreements": sum(row["verdict_disagreement"] for row in comparisons),
        "glm_verdicts": dict(Counter(row["glm_verdict"] for row in comparisons)),
        "grok_verdicts": dict(Counter(row["grok_verdict"] for row in comparisons)),
        "disagreement_topics": dict(
            Counter(topic for row in comparisons for topic in row["disagreement_topics"])
        ),
        "verdict_pair_matrix": {f"{a}->{b}": n for (a, b), n in verdict_pairs.items()},
        "verdict_disagree_workers": [row["worker"] for row in comparisons if row["verdict_disagreement"]],
        "any_disagree_workers": [row["worker"] for row in comparisons if row["needs_adjudication"]],
    }
    (LANE / "comparison-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
