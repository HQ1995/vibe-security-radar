#!/usr/bin/env python3
"""Audit current BLOCKED and NOT_AI rows using the canonical ledger only."""
from collections import Counter
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
BLOCKED_OUT = ROOT / ".ai-slop/state/blocked-deepwave/canonical-blocked-audit-20260819.jsonl"
NOTAI_OUT = ROOT / ".ai-slop/state/notai-review/canonical-notai-audit-20260819.jsonl"
BLOCKED_SUMMARY = ROOT / ".ai-slop/state/blocked-deepwave/canonical-blocked-audit-20260819.md"
NOTAI_SUMMARY = ROOT / ".ai-slop/state/notai-review/canonical-notai-audit-20260819.md"
NOTAI_SEMANTIC_OUT = ROOT / ".ai-slop/state/notai-review/canonical-notai-semantic-review-20260819.jsonl"
STRUCTURED_NOTAI = ROOT / ".ai-slop/state/notai-review/notai-causal-canonical-20260819.jsonl"
NO_FIX_RE = re.compile(
    r"no (?:direct )?fix|no fix upstream|unfixed|still (?:has )?vulnerab|"
    r"remains? vulnerable|project has not responded|no patch|not fixed",
    re.I,
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

def present(value):
    return value not in (None, "", [], {})

def readable_text(value, minimum=30):
    return isinstance(value, str) and len(value.strip()) >= minimum

def full_sha(value):
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None

def ledger_rows():
    return [json.loads(line) for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.strip()]

def object_stream(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        try:
            value, end = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            newline = text.find("\n", pos)
            if newline < 0:
                break
            pos = newline + 1
            continue
        pos = end
        if isinstance(value, dict):
            yield value
        elif isinstance(value, list):
            yield from (item for item in value if isinstance(item, dict))

rows = ledger_rows()
assert len(rows) == len({row["class_id"] for row in rows})

blocked = [row for row in rows if row.get("status") == "BLOCKED"]
blocked_ids = {row["class_id"] for row in blocked}
candidate_by_id = {}
for path in sorted((ROOT / ".ai-slop/state/blocked-deepwave").glob("*.jsonl")):
    for item in object_stream(path):
        cid = item.get("class_id")
        if cid not in blocked_ids:
            continue
        score = sum(present(item.get(key)) for key in ("bug_semantics", "evidence", "reasoning", "remaining_gap"))
        score += 4 if item.get("causal_closure") is True else 0
        score += 2 if item.get("verdict") == "BLOCKED" else 0
        candidate = (score, path.name, item)
        if cid not in candidate_by_id or candidate[:2] > candidate_by_id[cid][:2]:
            candidate_by_id[cid] = candidate

blocked_audit = []
for row in blocked:
    cid = row["class_id"]
    identity = row.get("advisory_identity") or {}
    if not identity.get("member_ids"):
        records = (row.get("advisory_research") or {}).get("records") or []
        recovered_ids = []
        for record in records:
            advisory_id = record.get("advisory_id") if isinstance(record, dict) else None
            if advisory_id and advisory_id not in recovered_ids:
                recovered_ids.append(advisory_id)
        if recovered_ids:
            identity = {"member_ids": recovered_ids, "source": "canonical.advisory_research.records"}
    # The row's refreshed boundary dossier is the canonical current record.
    # Historical shard files are only fallbacks; otherwise a well-researched
    # BLOCKED row appears empty simply because its evidence was materialized
    # under a different artifact filename.
    row_dossier = (
        row.get("blocked_boundary_review_20260819")
        or row.get("blocked_boundary_review")
        or row.get("blocked_deepwave_research")
        or {}
    )
    candidate = candidate_by_id.get(cid)
    dossier = row_dossier or (candidate[2] if candidate else {})
    dossier_source = (
        row.get("blocked_boundary_review_ref")
        if row.get("blocked_boundary_review_ref")
        else "ledger.blocked_boundary_review_20260819"
        if row.get("blocked_boundary_review_20260819")
        else "ledger.blocked_boundary_review"
        if row.get("blocked_boundary_review")
        else "ledger.blocked_deepwave_research"
        if row.get("blocked_deepwave_research")
        else candidate[1]
        if candidate
        else None
    )
    implementation_boundary = (
        row.get("blocked_implementation_boundary")
        or dossier.get("implementation_boundary")
    )
    causal_status = row.get("blocked_causal_status") or dossier.get("causal_status")
    fix_status = row.get("blocked_fix_status") or dossier.get("fix_status")
    ai_role_status = row.get("blocked_ai_role_status") or dossier.get("ai_role_status")
    evidence_ref = (
        row.get("blocked_package_evidence_ref")
        or row.get("published_package_audit_ref")
        or (".ai-slop/state/blocked-deepwave/arnold-final-bounded-20260819.jsonl"
            if row.get("repo") == "autodesk/arnold-usd" else None)
        or dossier.get("published_package_audit_ref")
        or dossier.get("evidence_ref")
    )
    if not identity.get("member_ids"):
        disposition = "IDENTITY_MISSING"
    elif causal_status == "CLOSED_SOURCE_BOUNDARY" or row.get("repo") == "autodesk/arnold-usd":
        disposition = "CLOSED_SOURCE_BOUNDARY"
    elif dossier.get("causal_closure") is True and causal_status not in {"SOURCE_UNAVAILABLE", "CAUSAL_CHAIN_OPEN"}:
        disposition = "CANDIDATE_CLOSED_REQUIRES_REVIEW"
    elif causal_status == "SOURCE_UNAVAILABLE" or row.get("repo") == "anthropics/claude-code":
        disposition = "SOURCE_UNAVAILABLE"
    elif candidate:
        disposition = "CAUSAL_CHAIN_OPEN"
    else:
        disposition = "NO_CURRENT_DOSSIER"
    blocked_audit.append({
        "class_id": cid,
        "repo": row.get("repo"),
        "advisory_ids": identity.get("member_ids", []),
        "dossier_source": dossier_source,
        "evidence_ref": evidence_ref,
        "dossier_verdict": dossier.get("verdict") or row.get("status"),
        "causal_closure": dossier.get("causal_closure") is True,
        "bug_semantics_present": present(dossier.get("bug_semantics")),
        "implementation_boundary": implementation_boundary,
        "mechanism_understood": present(dossier.get("bug_semantics")) and present(dossier.get("evidence")),
        "causal_status": causal_status,
        "fix_status": fix_status,
        "ai_role_status": ai_role_status,
        "git_lineage_available": dossier.get("git_lineage_available"),
        "introducer_sha": dossier.get("introducer_sha"),
        "direct_fix_sha": dossier.get("direct_fix_sha") or dossier.get("fix_sha"),
        "remaining_gap": dossier.get("remaining_gap"),
        "recommended_disposition": disposition,
    })
assert len(blocked_audit) == len(blocked)
assert len({item["class_id"] for item in blocked_audit}) == len(blocked)

notai_audit = []
structured_notai = {item['class_id']: item for item in (json.loads(x) for x in STRUCTURED_NOTAI.read_text(encoding='utf-8').splitlines() if x.strip())}
for row in rows:
    if row.get("status") != "NOT_AI":
        continue
    research = row.get("causal_research") or {}
    evidence = research.get("evidence")
    evidence_text = json.dumps(evidence, ensure_ascii=False) if evidence is not None else ""
    shape = structured_notai.get(row["class_id"], {})
    parent_absence = (
        shape.get("parent_sha_verified") is True
        or shape.get("root_boundary_verified") is True
        or shape.get("multi_introducer_parent_map") is True
    )
    identity_ids = (row.get("advisory_identity") or {}).get("member_ids") or []
    case_id = research.get("case_id") or next((item for item in identity_ids if str(item).startswith("GHSA-")), None) or (identity_ids[0] if identity_ids else None)
    flags = {
        "identity": bool((row.get("advisory_identity") or {}).get("member_ids")) or present(research.get("advisory_ids")) or present(research.get("case_id")),
        "mechanism": present(research.get("bug_semantics")),
        "atomic_introducer": present(research.get("introducer_sha")),
        "parent_absence": parent_absence,
        "direct_fix_or_explicit_no_fix": (
            present(research.get("direct_fix_sha"))
            or present(research.get("fix_sha"))
            or research.get("no_fix_proven") is True
            or research.get("head_still_vulnerable") is True
            or bool(NO_FIX_RE.search(
                evidence_text + " " + str(research.get("no_fix_evidence", "")) + " "
                + str(research.get("reasoning", ""))
            ))
        ),
        "evidence": readable_text(evidence),
        "reasoning": readable_text(research.get("reasoning")),
        "ai_role": present(research.get("ai_marker")),
        "squash_reviewed": (
            shape.get("squash_shape_valid", False)
            and all(full_sha(value) for value in (research.get("decomposed_shas") or []))
            and (not research.get("squash_decomposed") or bool(research.get("decomposed_shas")))
        ),
        "single_or_mapped_lineage": (
            len(research.get("introducer_shas") or ([research.get("introducer_sha")] if present(research.get("introducer_sha")) else [])) <= 1
            or shape.get("multi_introducer_parent_map", False)
        ),
    }
    commit_values = (
        [research.get("introducer_sha"), research.get("introducer_parent"),
         research.get("direct_fix_sha"), research.get("fix_sha")]
        + (research.get("introducer_shas") or [])
        + (research.get("decomposed_shas") or [])
    )
    flags["commit_references_are_full_sha"] = all(
        full_sha(value) for value in commit_values if present(value)
    )
    gate_pass = research.get("verdict") == "NOT_AI" and all(flags.values())
    notai_audit.append({
        "class_id": row["class_id"],
        "repo": row.get("repo"),
        "case_id": case_id,
        "attribution_status": research.get("attribution_status"),
        "remediation_status": research.get("remediation_status"),
        "lineage_status": research.get("lineage_status"),
        "causal_review_status": research.get("causal_review_status"),
        "introducer_sha": research.get("introducer_sha"),
        "direct_fix_sha": research.get("direct_fix_sha") or research.get("fix_sha"),
        "verdict": research.get("verdict"),
        "flags": flags,
        "missing": [key for key, value in flags.items() if not value],
        "lineage_gap": shape.get("lineage_gap", True),
        "parent_boundary": shape.get("parent_boundary"),
        "gate_pass": gate_pass,
    })
assert len(notai_audit) == len([row for row in rows if row.get("status") == "NOT_AI"])
assert len({item["class_id"] for item in notai_audit}) == len(notai_audit)
current_notai_coverage = f"{len(notai_audit)}/{len(notai_audit)}"
for row in rows:
    if row.get("status") == "NOT_AI" and row.get("notai_second_review_coverage") != current_notai_coverage:
        raise ValueError(
            f"stale NOT_AI coverage metadata for {row['class_id']}: "
            f"{row.get('notai_second_review_coverage')!r} != {current_notai_coverage!r}"
        )

notai_semantic = []
for row in rows:
    if row.get("status") != "NOT_AI":
        continue
    research = row.get("causal_research") or {}
    identity_ids = (row.get("advisory_identity") or {}).get("member_ids") or []
    case_id = research.get("case_id") or next((item for item in identity_ids if str(item).startswith("GHSA-")), None) or (identity_ids[0] if identity_ids else None)
    notai_semantic.append({
        "class_id": row["class_id"],
        "case_id": case_id,
        "repo": row.get("repo"),
        "mechanism": research.get("bug_semantics"),
        "flaw_origin": research.get("flaw_origin"),
        "introducer_sha": research.get("introducer_sha"),
        "introducer_parent": research.get("introducer_parent"),
        "parent_absence": research.get("introducer_parent_absent") is True or present(research.get("parent_absence")),
        "direct_fix_sha": research.get("direct_fix_sha") or research.get("fix_sha"),
        "no_fix_proven": research.get("no_fix_proven") is True,
        "ai_marker": research.get("ai_marker"),
        "squash_decomposed": research.get("squash_decomposed"),
        "decomposed_shas": research.get("decomposed_shas", []),
        "verdict": research.get("verdict"),
        "evidence": research.get("evidence"),
        "reasoning": research.get("reasoning"),
    })

BLOCKED_OUT.parent.mkdir(parents=True, exist_ok=True)
NOTAI_OUT.parent.mkdir(parents=True, exist_ok=True)
BLOCKED_OUT.write_text("".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in blocked_audit), encoding="utf-8")
NOTAI_OUT.write_text("".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in notai_audit), encoding="utf-8")
NOTAI_SEMANTIC_OUT.write_text("".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in notai_semantic), encoding="utf-8")
blocked_counts = Counter(item["recommended_disposition"] for item in blocked_audit)
notai_counts = Counter(item["causal_review_status"] or "DIMENSIONS_MISSING" for item in notai_audit)
BLOCKED_SUMMARY.write_text("# Canonical BLOCKED audit\n\nThe current ledger's BLOCKED rows are the only denominator. Historical files are evidence candidates, not additional rows.\n\n" + "\n".join(f"- {key}: {blocked_counts[key]}" for key in sorted(blocked_counts)) + f"\n\nTotal current BLOCKED rows audited: {len(blocked_audit)}\n", encoding="utf-8")
NOTAI_SUMMARY.write_text("# Canonical NOT_AI audit\n\nOnly canonical ledger causal_research is evaluated; NOT_AI is attribution, not a claim that remediation is complete.\n\n" + "\n".join(f"- {key}: {notai_counts[key]}" for key in sorted(notai_counts)) + f"\n\nRows audited: {len(notai_audit)}\nEvidence-gate rows: {sum(item['gate_pass'] for item in notai_audit)}\n", encoding="utf-8")
print("blocked", len(blocked_audit), dict(sorted(blocked_counts.items())))
print("notai", len(notai_audit), dict(sorted(notai_counts.items())))
