#!/usr/bin/env python3
"""Audit NOT_AI rows against saved raw dossiers, without ledger backfill."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
DIR = ROOT / ".ai-slop/state/notai-review"
STATE = ROOT / ".ai-slop/state"
OUT = DIR / "notai-independent-source-manifest-20260819.jsonl"
SUMMARY = DIR / "notai-independent-source-manifest-20260819.md"
DIRECT_SOURCE = DIR / "notai-direct-recheck-20260819.jsonl"
SOURCES = [
    DIR / "notai-direct-recheck-20260819.jsonl",
    STATE / "partial-wave/reaudit/results/reaudit-003-out.jsonl",
    STATE / "partial-wave/results/shard-044-out.jsonl",
    STATE / "partial-wave/results/shard-086-out.jsonl",
    STATE / "partial-wave/results/shard-066-out.jsonl",
    DIR / "semantic-deep-review-20260819.jsonl",
    *(DIR / f"worker-notai-{i}-20260819.jsonl" for i in range(1, 6)),
    DIR / "ciguard-causal-20260819.jsonl",
    DIR / "kiota-causal-20260819.jsonl",
    DIR / "legacy-9router-causal-20260819.jsonl",
]
PREFERRED_SOURCE = {
    "alias-0c380461ae4138186d439d81": DIR / "notai-direct-recheck-20260819.jsonl",
    "alias-d2b57eecffd6a2a1d9ea9b01": DIR / "notai-direct-recheck-20260819.jsonl",
    "alias-5bf288d2dae54c4dfa567ae4": DIR / "notai-direct-recheck-20260819.jsonl",
    "alias-732fb9f6a6675f0449e17bbb": DIR / "notai-direct-recheck-20260819.jsonl",
    "alias-7a29676428f04954d7f2922b": DIR / "notai-direct-recheck-20260819.jsonl",
    "alias-a980dddcc49cb92b3037839d": DIR / "notai-direct-recheck-20260819.jsonl",
    "alias-b858e3081ab03a6a2cfebc2d": DIR / "notai-direct-recheck-20260819.jsonl",
    "alias-eea2ebfdbde386ab2c84d329": DIR / "notai-direct-recheck-20260819.jsonl",
    "alias-f2f92442a504e89f43c170a0": DIR / "notai-direct-recheck-20260819.jsonl",
}

def source_priority(path):
    name = path.name
    if name == "notai-direct-recheck-20260819.jsonl":
        return 0
    if "partial-wave" in str(path):
        return 1
    return 2

def read(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def present(value):
    return value not in (None, "", [], {})

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def normalized(raw):
    # Explicitly normalize only raw aliases; never read ledger causal fields.
    text = " ".join(str(raw.get(k) or "") for k in ("evidence", "reasoning", "remaining_gap"))
    no_fix_text = bool(re.search(r'no (?:direct )?fix|no fix upstream|still reads? (?:any|arbitrary)|head still .*vulnerab|no patch', text, re.I))
    return {
        "case_id": raw.get("case_id"),
        "repo": raw.get("repo"),
        "verdict": raw.get("verdict"),
        "bug_semantics": raw.get("bug_semantics") or raw.get("mechanism"),
        "flaw_origin": raw.get("flaw_origin"),
        "introducer_sha": raw.get("introducer_sha"),
        "introducer_parent": raw.get("introducer_parent"),
        "introducer_parent_absent": raw.get("introducer_parent_absent"),
        "direct_fix_sha": raw.get("direct_fix_sha") or raw.get("fix_sha"),
        "no_fix_proven": raw.get("no_fix_proven") is True,
        "no_fix_derived_from_raw_text": no_fix_text,
        "ai_marker": raw.get("ai_marker"),
        "squash_decomposed": raw.get("squash_decomposed"),
        "decomposed_shas": raw.get("decomposed_shas") or [],
        "introducer_shas": raw.get("introducer_shas") or [],
        "introducer_roles": raw.get("introducer_roles") or {},
        "introducer_parent_map": raw.get("introducer_parent_map") or {},
        "evidence": raw.get("evidence"),
        "reasoning": raw.get("reasoning"),
        "remaining_gap": raw.get("remaining_gap"),
        "review_state": raw.get("review_state"),
        "source_kind": raw.get("source_kind"),
        "source_repo": raw.get("source_repo"),
        "source_commands": raw.get("source_commands") or [],
    }

def main():
    ledger_rows = read(LEDGER)
    current = {r["class_id"]: r for r in ledger_rows if r.get("status") == "NOT_AI"}
    if len(ledger_rows) != 23861:
        raise SystemExit(f"unexpected ledger shape rows={len(ledger_rows)}")

    records = {}
    duplicates = []
    file_meta = {}
    for path in SOURCES:
        lines = path.read_text(encoding="utf-8").splitlines()
        file_meta[path.name] = {"sha256": sha256(path), "rows": sum(bool(x.strip()) for x in lines)}
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            cid = raw.get("class_id")
            if cid not in current:
                continue
            preferred = PREFERRED_SOURCE.get(cid)
            if preferred is not None and path != preferred:
                continue
            if preferred is None and "partial-wave" in str(path):
                continue
            norm = normalized(raw)
            missing = [k for k in ("case_id", "repo", "verdict", "bug_semantics", "flaw_origin", "introducer_sha", "ai_marker", "evidence", "reasoning") if not present(norm.get(k))]
            if not present(norm["direct_fix_sha"]) and not (norm["no_fix_proven"] or norm["no_fix_derived_from_raw_text"]):
                missing.append("direct_fix_sha_or_no_fix_proven")
            aliases = ["mechanism->bug_semantics"] if "mechanism" in raw and "bug_semantics" not in raw else []
            strength = "SOURCE_FIELD_GAP" if missing else ("SOURCE_FIELD_ALIAS" if aliases else "SOURCE_COMPLETE")
            candidate = {
                "class_id": cid,
                "source_file": str(path.relative_to(ROOT)),
                "source_line": line_number,
                "source_sha256": file_meta[path.name]["sha256"],
                "source_field_names": sorted(raw),
                "source_field_aliases": aliases,
                "source_missing_fields": missing,
                "evidence_strength": strength,
                "normalized_source": norm,
            }
            if cid in records:
                if source_priority(path) >= source_priority(Path(records[cid]["source_file"])):
                    continue
            records[cid] = candidate

    missing_ids = sorted(set(current) - set(records))
    if missing_ids:
        raise SystemExit(json.dumps({"missing": missing_ids, "duplicates": duplicates}, ensure_ascii=False))

    identity_mismatches = []
    projection_differences = []
    canonical_source_mismatches = []
    for cid, item in records.items():
        src = item["normalized_source"]
        row = current[cid]
        research = row.get("causal_research") or {}
        for key in ("case_id", "verdict"):
            if present(src.get(key)) and src[key] != research.get(key):
                identity_mismatches.append({"class_id": cid, "field": key, "source": src.get(key), "ledger": research.get(key)})
        if present(src.get("repo")) and src["repo"] != row.get("repo"):
            identity_mismatches.append({"class_id": cid, "field": "repo", "source": src.get("repo"), "ledger": row.get("repo")})
        for key in ("bug_semantics", "flaw_origin"):
            if present(src.get(key)) and present(research.get(key)) and src[key] != research[key]:
                projection_differences.append({"class_id": cid, "field": key})
        if item["source_file"] == str(DIRECT_SOURCE.relative_to(ROOT)):
            ledger_norm = normalized(research)
            for key in (
                "case_id", "repo", "verdict", "bug_semantics", "flaw_origin",
                "introducer_sha", "introducer_parent", "introducer_parent_absent",
                "direct_fix_sha", "no_fix_proven", "ai_marker",
                "squash_decomposed", "decomposed_shas", "introducer_shas",
                "introducer_roles", "introducer_parent_map", "remaining_gap",
                "review_state",
            ):
                if src.get(key) != ledger_norm.get(key):
                    canonical_source_mismatches.append({
                        "class_id": cid, "field": key,
                        "source": src.get(key), "ledger": ledger_norm.get(key),
                    })
    if identity_mismatches:
        raise SystemExit(json.dumps({"identity_mismatches": identity_mismatches}, ensure_ascii=False))
    if canonical_source_mismatches:
        raise SystemExit(json.dumps({"canonical_source_mismatches": canonical_source_mismatches}, ensure_ascii=False))

    output = [dict(records[cid], normalized_source_digest=hashlib.sha256(json.dumps(records[cid]["normalized_source"], ensure_ascii=False, sort_keys=True).encode()).hexdigest()) for cid in sorted(records)]
    OUT.write_text("".join(json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n" for x in output), encoding="utf-8")

    counts = Counter(x["evidence_strength"] for x in output)
    source_counts = Counter(x["source_file"] for x in output)
    SUMMARY.write_text("\n".join([
        "# NOT_AI independent source manifest", "",
        "Generated from saved raw research files only; missing fields are not filled from ledger causal_research.", "",
        f"- Current NOT_AI rows: {len(current)}",
        f"- Independent source rows: {len(output)}",
        f"- Evidence strength: {dict(sorted(counts.items()))}",
        f"- Source files: {dict(sorted(source_counts.items()))}",
        f"- Ledger/source identity mismatches: {len(identity_mismatches)}",
        f"- Direct-source/canonical-ledger mismatches: {len(canonical_source_mismatches)}",
        f"- Raw-to-ledger semantic text projection differences: {len(projection_differences)} (not treated as source failure)",
        "- The ledger is read-only for this audit; the manifest is the independent evidence pointer.",
        "",
        "SOURCE_COMPLETE contains all required fields. SOURCE_FIELD_ALIAS uses an explicit raw alias. SOURCE_FIELD_GAP lacks at least one required field in the raw dossier.",
        "",
    ]) + "\n", encoding="utf-8")
    print(json.dumps({"rows": len(output), "evidence_strength": dict(sorted(counts.items())), "identity_mismatches": len(identity_mismatches), "projection_differences": len(projection_differences), "manifest": str(OUT)}, ensure_ascii=False))

if __name__ == "__main__":
    main()
