#!/usr/bin/env python3
"""Finalize round11 freeze: pair manifest->primary, dual-gate, write artifacts."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round11-top500-20260829"
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
GATE_SCRIPT = ROOT / "scripts/audit_record_gates.py"
RECORDS = LANE / "records.jsonl"
SCRATCH = Path("/home/hanqing/sort-tmp/tmp/grok-goal-3aaa842afb41/implementer")

EXPECTED = [
    "class_id", "case_id", "repo", "advisory_ids", "bug_semantics", "flaw_origin",
    "introducer_sha", "introducer_parent", "introducer_parent_absent", "squash_decomposed",
    "decomposed_shas", "ai_marker", "verdict", "fix_sha", "direct_fix_sha", "evidence",
    "reasoning", "remaining_gap",
]


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> int:
    manifest = jsonl(LANE / "manifest.jsonl")
    summary = json.loads((LANE / "selection-summary.json").read_text())

    records = []
    roster = []
    missing = []
    problems = []
    for item in manifest:
        path = ROOT / item["primary_out"]
        row = {
            "worker": item["worker"],
            "class_id": item["class_id"],
            "repo": item["repo"],
            "advisory_ids": item["advisory_ids"],
            "output": item["primary_out"],
            "exists": path.exists(),
        }
        if not path.exists():
            missing.append(item["worker"])
            row["status"] = "missing"
            roster.append(row)
            continue
        record = json.loads(path.read_text())
        row["status"] = "present"
        row["verdict"] = record.get("verdict")
        if list(record)[: len(EXPECTED)] != EXPECTED:
            problems.append(f"{item['worker']}: key order mismatch")
        if record.get("class_id") != item["class_id"]:
            problems.append(f"{item['worker']}: class_id mismatch")
        if record.get("repo") != item["repo"]:
            problems.append(f"{item['worker']}: repo mismatch")
        if record.get("advisory_ids") != item["advisory_ids"]:
            problems.append(f"{item['worker']}: advisory_ids mismatch")
        if not str(record.get("evidence") or "").strip():
            problems.append(f"{item['worker']}: empty evidence")
        records.append(record)
        roster.append(row)

    present_ids = [r["class_id"] for r in records]
    unique_ids = set(present_ids)
    duplicates = len(present_ids) - len(unique_ids)

    # round10 overlap
    round10_manifest = jsonl(ROOT / "research/round10-top200-20260828/manifest.jsonl")
    r10_classes = {m["class_id"] for m in round10_manifest}
    r10_advs = {a for m in round10_manifest for a in (m["advisory_ids"] or [])}
    overlap_class = len(unique_ids & r10_classes)
    overlap_adv = sum(1 for r in records if any(a in r10_advs for a in (r["advisory_ids"] or [])))

    # write paired records + roster
    RECORDS.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records))
    (LANE / "worker-roster.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in roster)
    )

    # dual gate
    gate_out = []
    for _ in range(2):
        p = subprocess.run(
            [sys.executable, str(GATE_SCRIPT), str(RECORDS)],
            capture_output=True, text=True,
        )
        gate_out.append((p.stdout.strip(), p.returncode))
    agree = gate_out[0] == gate_out[1]
    gate_ok = all(rc == 0 and "ok" in out.lower() for out, rc in gate_out)

    ledger_sha_freeze = summary["ledger_sha256_at_freeze"]
    ledger_sha_live = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    ledger_mutated = ledger_sha_freeze != ledger_sha_live
    round11_in_ledger = sum(1 for line in LEDGER.read_text().splitlines() if "round11" in line)

    verdict_histogram = dict(Counter(r.get("verdict") for r in records))

    coverage = {
        "selected": len(manifest),
        "present": len(records),
        "missing": len(missing),
        "unique_class_ids": len(unique_ids),
        "duplicates": duplicates,
        "round10_class_overlap": overlap_class,
        "round10_advisory_overlap": overlap_adv,
        "problems": len(problems),
        "gate_runs": len(gate_out),
        "gate_runs_agree": agree,
        "gate_result": "ok" if gate_ok else "FAIL",
        "verdict_histogram": verdict_histogram,
        "missing_workers": missing,
        "incomplete": True,
        "stop_reason": "token budget; no new launches; snapshot after in-flight drain",
        "ledger_sha256_at_freeze": ledger_sha_freeze,
        "ledger_sha256_live": ledger_sha_live,
        "ledger_mutated": ledger_mutated,
        "round11_fields_in_ledger": round11_in_ledger,
    }
    coverage["problems_detail"] = problems[:50]
    (LANE / "coverage.json").write_text(json.dumps(coverage, indent=1) + "\n")

    # ---- report ----
    tp_rows = [
        r for r in records
        if r["verdict"] in ("AI_ROOT_CAUSE", "AI_CODE_FLAWED")
    ]
    fp_rows = [r for r in records if r["verdict"] == "FALSE_POSITIVE"]
    by_worker = {i["worker"]: i for i in manifest}
    by_w = {r["class_id"]: None for r in records}
    manifest_by_cid = {m["class_id"]: m for m in manifest}

    # unfinished-by-repo (from manifest of missing workers)
    missing_set = set(missing)
    unf_m = [m for m in manifest if m["worker"] in missing_set]
    unf_by_repo = sorted(
        Counter(m["repo"] for m in unf_m).items(),
        key=lambda kv: (-kv[1], kv[0]),
    )

    lines = []
    lines.append("# Round11 top-500 remaining-open TP-likelihood audits")
    lines.append("")
    lines.append("Wave of 500 `UNANALYZED`/`PARTIALLY_ANALYZED` ledger cases ranked for")
    lines.append("true-positive likelihood after excluding every class/advisory in")
    lines.append("`research/round10-top200-20260828/`. Protocol: `docs/AUDIT-PROTOCOL.md`.")
    lines.append("This wave does **not** land ledger rows.")
    lines.append("")
    lines.append("**Status: incomplete.** Token budget ran out; no new workers after the stop.")
    lines.append(f"Freeze snapshot: **{len(records)}/500** unique completed records, "
                 f"**{len(problems)}** gate problems.")
    lines.append(f"**{len(missing)}** frozen cases were not finished and are listed below.")
    lines.append("Do not treat unfinished rows as `NOT_AI` or `EVIDENCE_GAP`.")
    lines.append("")
    lines.append("## Selection")
    lines.append("")
    lines.append(f"- eligible open after round10 exclude: {summary['eligible']}")
    lines.append(f"- selected: {summary['target']}")
    lines.append(f"- statuses: `{summary['selected_statuses']}`")
    lines.append(f"- repositories: {summary['selected_repositories']} (cap {summary['repo_cap']})")
    lines.append(f"- score range: {summary['score_max']} .. {summary['score_min']}")
    lines.append(f"- clone-ready at freeze: {summary['clone_ready_cases']}")
    lines.append(f"- known-TP-repo cases: {summary['known_tp_repo_cases']}")
    lines.append(f"- excluded overlap: {summary['excluded_overlap']}")
    lines.append(f"- ledger sha256 at freeze: `{summary['ledger_sha256_at_freeze']}`")
    lines.append(f"- ledger sha256 live: `{ledger_sha_live}` (unchanged={not ledger_mutated})")
    lines.append("")
    lines.append("## Coverage (this freeze)")
    lines.append("")
    lines.append(f"- completed unique class_ids: **{len(records)} / 500**")
    lines.append(f"- missing: **{len(missing)}**")
    lines.append(f"- duplicates: {duplicates}")
    lines.append(f"- round10 class overlap: {overlap_class}")
    lines.append(f"- round10 advisory overlap: {overlap_adv}")
    lines.append(f"- problems: {len(problems)}")
    lines.append("")
    lines.append("## Verdict histogram (completed only)")
    lines.append("")
    for verdict, count in sorted(
        verdict_histogram.items(), key=lambda kv: (-kv[1], kv[0])
    ):
        lines.append(f"- `{verdict}`: {count}")
    lines.append("")
    lines.append("### Closed TPs")
    lines.append("")
    lines.append("| worker | verdict | repo | case_id | introducer |")
    lines.append("|---|---|---|---|---|")
    for r in sorted(tp_rows, key=lambda x: manifest_by_cid[x["class_id"]]["ordinal"]):
        m = manifest_by_cid[r["class_id"]]
        lines.append(
            "| {w} | `{v}` | {repo} | {case} | `{intro}` |".format(
                w=m["worker"], v=r["verdict"], repo=r["repo"],
                case=(r.get("case_id") or ""),
                intro=(r.get("introducer_sha") or "")[:12] or "—",
            )
        )
    if fp_rows:
        lines.append("")
        lines.append("### FALSE_POSITIVE")
        lines.append("")
        for r in sorted(fp_rows, key=lambda x: manifest_by_cid[x["class_id"]]["ordinal"]):
            m = manifest_by_cid[r["class_id"]]
            lines.append(f"- {m['worker']} `{r.get('case_id') or ''}` `{r['repo']}`")
    lines.append("")
    lines.append("## Unfinished cases (not audited in time)")
    lines.append("")
    lines.append(f"{len(missing)} frozen class_ids have no `primary/wXXX.json`. They stay")
    lines.append("`UNANALYZED`/`PARTIALLY_ANALYZED` on the live ledger. Resume from this list;")
    lines.append("do not re-freeze the 500.")
    lines.append("")
    if unf_by_repo:
        lines.append("Unfinished by repo:")
        lines.append("")
        for repo, cnt in unf_by_repo:
            lines.append(f"- `{repo}`: {cnt}")
        lines.append("")
    lines.append("| worker | class_id | repo | advisory_ids | score | status_at_selection |")
    lines.append("|---|---|---|---|---|---|")
    for m in sorted(unf_m, key=lambda m: m["ordinal"]):
        lines.append(
            "| {w} | `{cid}` | {repo} | {adv} | {score} | {status} |".format(
                w=m["worker"], cid=m["class_id"], repo=m["repo"],
                adv=", ".join(m["advisory_ids"] or []),
                score=m["score"], status=m["status_at_selection"],
            )
        )
    lines.append("")
    lines.append("## Completed cases")
    lines.append("")
    lines.append("| worker | class_id | case_id | repo | verdict | introducer | fix |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in sorted(records, key=lambda x: manifest_by_cid[x["class_id"]]["ordinal"]):
        m = manifest_by_cid[r["class_id"]]
        if isinstance(r.get("unpatched"), dict):
            fix = "unpatched"
        else:
            fix = (r.get("fix_sha") or r.get("direct_fix_sha") or "")[:12] or "—"
        lines.append(
            "| {w} | `{cid}` | {case} | {repo} | {v} | `{intro}` | `{fix}` |".format(
                w=m["worker"], cid=r["class_id"], case=(r.get("case_id") or ""),
                repo=r["repo"], v=r["verdict"],
                intro=(r.get("introducer_sha") or "")[:12] or "—",
                fix=fix,
            )
        )
    lines.append("")
    (LANE / "report.md").write_text("\n".join(lines))

    # ---- scratch copies ----
    SCRATCH.mkdir(parents=True, exist_ok=True)
    for name in ("coverage.json", "worker-roster.jsonl", "report.md", "records.jsonl"):
        (SCRATCH / name).write_bytes((LANE / name).read_bytes())
    (SCRATCH / "collect-snapshot.json").write_text(json.dumps(coverage, indent=1) + "\n")
    gate_log = "\n".join(out for out, _ in gate_out) + (
        "\nagree\n" if agree else "\nDISAGREE\n"
    )
    (SCRATCH / "record-gates.log").write_text(gate_log)
    (SCRATCH / "selection-summary.json").write_text(
        (LANE / "selection-summary.json").read_text()
    )

    result = {
        "selected": len(manifest),
        "present": len(records),
        "missing": len(missing),
        "unique": len(unique_ids),
        "duplicates": duplicates,
        "problems": len(problems),
        "gate_ok": gate_ok,
        "gate_agree": agree,
        "gate_output": gate_out,
        "verdict_histogram": verdict_histogram,
        "ledger_mutated": ledger_mutated,
        "round11_in_ledger": round11_in_ledger,
    }
    print(json.dumps(result, indent=1))
    if problems:
        print("\n".join(problems[:50]), file=sys.stderr)
    return 0 if (not problems and gate_ok and agree) else 1


if __name__ == "__main__":
    raise SystemExit(main())
