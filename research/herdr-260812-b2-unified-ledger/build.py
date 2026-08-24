#!/usr/bin/env python3
"""Build the snapshot-only unified ledger. Reads only ./snapshot."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SNAPSHOT = ROOT / "snapshot"
SNAPSHOT_AT = "2026-08-12T13:03:38-04:00"
ID_RE = re.compile(r"(?:CVE-\d{4}-\d+|GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})", re.I)


def read_json(path: Path):
    return json.loads(path.read_text())


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ids(values) -> list[str]:
    return sorted({value.upper() for value in values})


def ids_from_text(value: str) -> list[str]:
    return ids(ID_RE.findall(value or ""))


def ref(path: Path, locator: str | None = None) -> dict:
    item = {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256(path)}
    if locator:
        item["locator"] = locator
    return item


STRICT_LEDGER = SNAPSHOT / "strict/ledger.jsonl"
STRICT_REPORT = SNAPSHOT / "strict/RESEARCH-STRICT-200-CLOSURE-2026-08-12.md"
ALIAS_LEDGER = SNAPSHOT / "batch1/alias-qa/ledger.jsonl"
ALIAS_SUMMARY = SNAPSHOT / "batch1/alias-qa/summary.json"
ALIAS_REPORT = SNAPSHOT / "batch1/alias-qa/report.md"
LEDGER_QA = SNAPSHOT / "batch1/ledger-qa/reconciliation.json"
NEGATIVE_REPORT = SNAPSHOT / "batch1/negative-controls/report.md"
NEGATIVE_RESULT = SNAPSHOT / "batch1/negative-controls/result.json"
UNKNOWN_LEDGER = SNAPSHOT / "batch1/unknown-recovery/recommendation-ledger.jsonl"
UNKNOWN_REPORT = SNAPSHOT / "batch1/unknown-recovery/report.md"
SQUASH_SNAPSHOT = SNAPSHOT / "batch1/squash-lineage/snapshot.json"
SQUASH_REPORT = SNAPSHOT / "batch1/squash-lineage/report.md"
FRESH_REPORT = SNAPSHOT / "batch1/fresh-advisories/report.md"
MCP_REPORT = SNAPSHOT / "batch1/mcp-js-ecosystem/report.md"

POST_DOCS = {
    "Batch-A": SNAPSHOT / "post-strict/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md",
    "Main": SNAPSHOT / "post-strict/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md",
    "OpenClaw": SNAPSHOT / "post-strict/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md",
    "Batch-B": SNAPSHOT / "post-strict/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md",
    "Batch-C": SNAPSHOT / "post-strict/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md",
    "Batch-D": SNAPSHOT / "post-strict/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md",
    "Batch-E": SNAPSHOT / "post-strict/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md",
}

CONTROL_OUTCOMES = {
    "bsv-arc-status": ("S01", "KEEP"),
    "bsv-certificate-signature": ("S02", "KEEP"),
    "claude-cache-statusline-injection": ("S03", "KEEP"),
    "hermes-first-user-takeover": ("S04", "KEEP"),
    "hermes-profile-search": ("S05", "NARROW"),
    "coolify-trust-host-cache": ("S06", "UNKNOWN"),
    "openclaw-minimax-redirect": ("S07", "KEEP"),
    "openclaw-gateway-url": ("S08", "KEEP"),
    "openclaw-prompt-image": ("S09", "KEEP"),
    "openclaw-browserbase-dns": ("S10", "KEEP"),
    "scriban-parser-depth": ("E01", "KEEP"),
    "gitea-oauth-reactivation": ("E02", "REJECT"),
    "praisonai-jwt-default": ("E03", "KEEP"),
    "coolify-shell-grammar": ("E04", "KEEP"),
    "gitpython-joined-short-option": ("E05", "KEEP"),
    "gitpython-config-reserialize": ("E13", "KEEP"),
    "gitpython-separate-git-dir": ("E14", "KEEP"),
    "gitpython-blame-contents": ("E15", "KEEP"),
    "gitpython-tag-positional-file": ("E16", "REJECT"),
    "scriban-lazy-range": ("E17", "REJECT"),
}

CONTROL_LINES = {
    sample: str(111 + index)
    for index, sample in enumerate(
        [
            "S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10",
            "E01", "E02", "E03", "E04", "E05", "E13", "E14", "E15", "E16", "E17",
        ]
    )
}

CONTROL_REASONS = {
    "S05": "Retain only the distinct session-search hunk/mechanism; candidate SHA already occurs in the frozen baseline.",
    "S06": "Cold-cache contribution is code-supported, but durable atomic AI attribution remains unresolved.",
    "E02": "A later human member weakened the safe AI predicate; the shipped residual is not the AI hunk.",
    "E16": "Same TagReference.create --file arbitrary-read residual series as GHSA-3F7W-8RR8-F37F.",
    "E17": "Same array-multiplication LoopLimit residual series as GHSA-Q6RR-FM2G-G5X8.",
}


def source_doc_ref(source: str) -> dict:
    prefix, locator = source.split(":", 1)
    return ref(POST_DOCS[prefix], locator)


def edge_view(edge: dict) -> dict:
    return {
        key: edge[key]
        for key in ("candidate_sha", "carrier_sha", "fix_sha", "origin_kind")
        if edge.get(key) is not None
    }


strict_rows = read_jsonl(STRICT_LEDGER)
alias_rows = read_jsonl(ALIAS_LEDGER)
alias_summary = read_json(ALIAS_SUMMARY)
ledger_qa = read_json(LEDGER_QA)
negative_result = read_json(NEGATIVE_RESULT)

assert len(strict_rows) == 110
assert len(ids(public_id for row in strict_rows for public_id in row["public_ids"])) == 200
assert len(alias_rows) == 76 and len({row["row_id"] for row in alias_rows}) == 74
assert Counter(row["action"] for row in alias_rows) == Counter(alias_summary["actions"])
assert negative_result["counts"] | {"keep": 15, "reject": 3, "narrow": 1, "unknown": 1} == negative_result["counts"]
assert ledger_qa["reconciled_totals"]["strict_released_components"]["reconciled"] == 125
assert ledger_qa["reconciled_totals"]["broad_released_components"]["after_exact_identity_deduplication"] == 172
assert ledger_qa["reconciled_totals"]["widest_commit_level_workset_components"]["after_exact_identity_deduplication"] == 184

rows: list[dict] = []

for line_number, raw in enumerate(strict_rows, 1):
    evidence = raw.get("evidence", [])
    mechanisms = [item.get("mechanism") or item.get("reason") for item in evidence]
    repositories = [item.get("repository_identity") for item in evidence]
    amendments = [
        {
            "public_id": item.get("public_id"),
            "relationship": item.get("relationship"),
            "excluded_public_ids": ids(item.get("excluded_public_ids", [])),
        }
        for item in evidence
        if item.get("kind") == "public_id_alias_amendment"
    ]
    rows.append(
        {
            "schema_version": 1,
            "record_kind": "COMPONENT_ROW",
            "row_key": f"strict-200-v3:{raw['component_id']}",
            "canonical_component_id": raw["component_id"],
            "source_layer": "STRICT_200_BASELINE",
            "source_instance": "strict-200-v3",
            "source_tier": "STRICT_RELEASED",
            "row_state": "PASS",
            "state_axes": {
                "source_verdict": "PASS",
                "alias_qa_action": "FROZEN_BASELINE",
                "negative_control_outcome": "NOT_REOPENED",
                "integration_state": "COUNTED_SOURCE_BASELINE",
            },
            "counting": {
                "canonical_instance": True,
                "strict_document_max": True,
                "broad_released_max": True,
                "widest_max": True,
            },
            "primary_id": raw.get("primary_id"),
            "public_ids": ids(raw["public_ids"]),
            "declared_public_ids": ids(raw["public_ids"]),
            "repository": next((value for value in repositories if value), None),
            "mechanism": next((value for value in mechanisms if value), None),
            "candidate_fix_edges": [
                edge_view(edge)
                for item in evidence
                for edge in item.get("accepted_edges", [])
            ],
            "proposed_fixes": [],
            "alias_amendments": amendments,
            "duplicate_of": None,
            "source_refs": [ref(STRICT_LEDGER, str(line_number)), ref(STRICT_REPORT, "11-25")],
            "notes": [],
        }
    )

for raw in alias_rows:
    is_duplicate = raw["action"] == "REMOVE_ID"
    sample_id, control = CONTROL_OUTCOMES.get(raw["row_id"], (None, "NOT_SAMPLED"))
    if is_duplicate:
        sample_id, control = None, "NOT_APPLICABLE_DUPLICATE_INSTANCE"
    filebrowser_unknown = raw["row_id"] == "filebrowser-scoped-fs"

    if is_duplicate:
        state = "DUPLICATE"
    elif control == "REJECT":
        state = "REJECT"
    elif control == "UNKNOWN" or filebrowser_unknown or raw["action"] == "UNKNOWN":
        state = "UNKNOWN"
    elif control == "NARROW" or raw["action"] == "SPLIT":
        state = "NARROW"
    else:
        state = "PASS"

    canonical = not is_duplicate
    strict_released = raw["tier"] == "STRICT_RELEASED"
    released = raw["tier"] in {"STRICT_RELEASED", "INCOMPLETE_RELEASED"}
    notes = list(raw.get("reasons", []))
    if sample_id:
        notes.append(CONTROL_REASONS.get(sample_id, "All sampled falsification gates passed."))
    if filebrowser_unknown:
        notes.append(
            "UNKNOWN_POSSIBLE_SEMANTIC_DOUBLE_COUNT: same 847d08bd -> 7c2c0a11 -> 64511ce4 chain and residual mechanisms as the two Batch D split rows."
        )

    source_refs = [source_doc_ref(raw["source"]), ref(ALIAS_LEDGER, raw["key"])]
    if sample_id:
        source_refs.append(ref(NEGATIVE_REPORT, CONTROL_LINES[sample_id]))
    if is_duplicate or filebrowser_unknown:
        source_refs.append(ref(LEDGER_QA, "discrepancies"))

    rows.append(
        {
            "schema_version": 1,
            "record_kind": "COMPONENT_ROW",
            "row_key": f"post:{raw['key']}",
            "canonical_component_id": f"post:{raw['row_id']}",
            "source_layer": "POST_STRICT_DOCUMENTS",
            "source_instance": raw["instance"],
            "source_tier": raw["tier"],
            "row_state": state,
            "state_axes": {
                "source_verdict": "PASS",
                "alias_qa_action": raw["action"],
                "negative_control_outcome": control,
                "integration_state": {
                    "DUPLICATE": "EXCLUDED_EXACT_DUPLICATE",
                    "REJECT": "EXCLUDED_BY_BATCH1_CONTROL",
                    "UNKNOWN": "UNRESOLVED",
                    "NARROW": "COUNT_ONLY_NARROWED_SCOPE",
                    "PASS": "SOURCE_MAXIMUM_ROW",
                }[state],
            },
            "counting": {
                "canonical_instance": canonical,
                "strict_document_max": canonical and strict_released,
                "broad_released_max": canonical and released,
                "widest_max": canonical,
            },
            "primary_id": (raw.get("official_ids") or raw["ids"])[0],
            "public_ids": ids(raw.get("official_ids") or raw["ids"]),
            "declared_public_ids": ids(raw["ids"]),
            "repository": raw.get("repo"),
            "mechanism": raw.get("mechanism"),
            "candidate_fix_edges": [],
            "proposed_fixes": sorted(raw.get("proposed_fixes", [])),
            "alias_amendments": [
                {"public_id": value.upper(), "relationship": "BATCH1_ADD_ALIAS"}
                for value in raw.get("add_aliases", [])
            ],
            "duplicate_of": (
                f"post:{raw['row_id']}@main" if is_duplicate else None
            ),
            "source_refs": source_refs,
            "notes": notes,
        }
    )

# Machine-readable Batch 1 route controls remain outside every component maximum.
for raw in read_jsonl(UNKNOWN_LEDGER):
    recommendation = raw["recommendation"]
    state = {
        "RESOLVED_REJECT": "REJECT",
        "STILL_BLOCKED": "BLOCKED",
        "STILL_UNKNOWN": "UNKNOWN",
    }[recommendation]
    rows.append(
        {
            "schema_version": 1,
            "record_kind": "BATCH1_ROUTE_CONTROL",
            "row_key": f"unknown-recovery:{raw['rank']}:{raw['class_id']}",
            "canonical_component_id": raw["class_id"],
            "source_layer": "BATCH1_DIAGNOSTIC_CONTROL",
            "source_instance": "unknown-recovery",
            "source_tier": "OUTSIDE_CURRENT_SOURCE_CENSUS",
            "row_state": state,
            "state_axes": {
                "source_verdict": recommendation,
                "alias_qa_action": "NOT_APPLICABLE",
                "negative_control_outcome": "NOT_APPLICABLE",
                "integration_state": "NONCOUNTING_NAMED_ROUTE_CONTROL",
            },
            "counting": {"canonical_instance": False, "strict_document_max": False, "broad_released_max": False, "widest_max": False},
            "primary_id": ids(raw.get("public_ids", []))[0] if raw.get("public_ids") else None,
            "public_ids": ids(raw.get("public_ids", [])),
            "declared_public_ids": ids(raw.get("public_ids", [])),
            "repository": raw.get("component"),
            "mechanism": raw.get("mechanism"),
            "candidate_fix_edges": [],
            "proposed_fixes": [],
            "alias_amendments": [],
            "duplicate_of": None,
            "source_refs": [ref(UNKNOWN_LEDGER, f"rank={raw['rank']}"), ref(UNKNOWN_REPORT, "95-106")],
            "notes": [raw.get("claim_boundary", ""), *raw.get("blockers", [])],
        }
    )

for raw in read_json(SQUASH_SNAPSHOT)["selected_edges"]:
    state = "UNKNOWN" if raw["verdict"] == "UNKNOWN" else "REJECT"
    rows.append(
        {
            "schema_version": 1,
            "record_kind": "BATCH1_ROUTE_CONTROL",
            "row_key": f"squash-lineage:{raw['priority']}:{raw['member']}",
            "canonical_component_id": raw["class_id"],
            "source_layer": "BATCH1_DIAGNOSTIC_CONTROL",
            "source_instance": "squash-lineage",
            "source_tier": "OUTSIDE_CURRENT_SOURCE_CENSUS",
            "row_state": state,
            "state_axes": {
                "source_verdict": raw["verdict"],
                "alias_qa_action": "NOT_APPLICABLE",
                "negative_control_outcome": "NOT_APPLICABLE",
                "integration_state": "NONCOUNTING_NAMED_ROUTE_CONTROL",
            },
            "counting": {"canonical_instance": False, "strict_document_max": False, "broad_released_max": False, "widest_max": False},
            "primary_id": ids_from_text(raw.get("public_identity", ""))[0] if ids_from_text(raw.get("public_identity", "")) else None,
            "public_ids": ids_from_text(raw.get("public_identity", "")),
            "declared_public_ids": ids_from_text(raw.get("public_identity", "")),
            "repository": raw.get("repository"),
            "mechanism": "Named multi-member squash route; verdict is scoped to this member/carrier/fix edge.",
            "candidate_fix_edges": [{"candidate_sha": raw["member"], "carrier_sha": raw["carrier"], "fix_sha": raw["fix"]}],
            "proposed_fixes": [raw["fix"]],
            "alias_amendments": [],
            "duplicate_of": None,
            "source_refs": [ref(SQUASH_SNAPSHOT, f"selected_edges priority={raw['priority']}"), ref(SQUASH_REPORT, "73-146")],
            "notes": ["Patch survival and ancestry are diagnostic; the row does not enter a component maximum."],
        }
    )

# New Batch 1 positives are visible but do not silently supersede the requested current maxima.
proposals = [
    {
        "key": "autogpt-webhook-provider-confusion",
        "tier": "PROPOSED_STRICT_RELEASED",
        "ids": ["CVE-2026-72922", "GHSA-349P-3C3R-8MJR"],
        "repo": "Significant-Gravitas/AutoGPT",
        "mechanism": "URL-selected webhook manager bypasses the configured provider signature verifier.",
        "edges": [{"candidate_sha": "3b0d43230901ef353c39cc3bbac36e6d81f049dc", "carrier_sha": "7f08a16deed57c93654356058667293534de6994", "fix_sha": "646dd5b8cfad1206e92ec7bcc3b8312657e2a92e"}],
        "report": FRESH_REPORT,
        "locator": "74,89-100",
    },
    {
        "key": "n8n-mcp-session-health",
        "tier": "PROPOSED_STRICT_RELEASED",
        "ids": ["GHSA-75HX-XJ24-MQRW"],
        "repo": "czlonkowski/n8n-mcp",
        "mechanism": "Unauthenticated live-session GET/DELETE dispatch and sensitive health metadata.",
        "edges": [{"candidate_sha": "a597ef5a924ebe17a6a202bbb841965f52328032", "fix_sha": "ca9d4b3df6419b8338983be98f7940400f78bde3"}],
        "report": MCP_REPORT,
        "locator": "102,115-126",
    },
    {
        "key": "n8n-mcp-api-path-segments",
        "tier": "PROPOSED_STRICT_RELEASED",
        "ids": ["GHSA-8G7G-HMWM-6RV2"],
        "repo": "czlonkowski/n8n-mcp",
        "mechanism": "Caller-controlled IDs enter authenticated management API path segments.",
        "edges": [{"candidate_sha": "74f05e937fa7d94babe3507510caa17ce17a698c", "fix_sha": "1cfe9c6bddb4b1634e6e23323c18ea35fd196999"}],
        "report": MCP_REPORT,
        "locator": "103,128-138",
    },
    {
        "key": "n8n-mcp-redirect-ssrf",
        "tier": "PROPOSED_STRICT_RELEASED",
        "ids": ["GHSA-8G7G-HMWM-6RV2"],
        "repo": "czlonkowski/n8n-mcp",
        "mechanism": "Form/chat trigger validates only the initial URL before redirect-following requests.",
        "edges": [
            {"candidate_sha": "3f698cc62d2f820f83713a51fce23f71e9cc4654", "carrier_sha": "33690c5650e680b2c9cfbae75cac81a761742389", "fix_sha": "1cfe9c6bddb4b1634e6e23323c18ea35fd196999"},
            {"candidate_sha": "7d81204aecb58ba09c70497ae643b886f0d9edc4", "carrier_sha": "33690c5650e680b2c9cfbae75cac81a761742389", "fix_sha": "1cfe9c6bddb4b1634e6e23323c18ea35fd196999"},
        ],
        "report": MCP_REPORT,
        "locator": "103,140-146",
    },
    {
        "key": "n8n-mcp-telemetry-residual",
        "tier": "PROPOSED_INCOMPLETE_RELEASED",
        "ids": ["GHSA-8G7G-HMWM-6RV2"],
        "repo": "czlonkowski/n8n-mcp",
        "mechanism": "AI sanitization leaves operation diffs, validation objects, and errors raw in mutation telemetry.",
        "edges": [{"candidate_sha": "7ac748e73f69bcd3b43d0a321b38d79078013b91", "carrier_sha": "99c5907b71a6c3228d345a2f0879cd893f30cd7e", "fix_sha": "1cfe9c6bddb4b1634e6e23323c18ea35fd196999"}],
        "report": MCP_REPORT,
        "locator": "103,148-154",
    },
]

for proposal in proposals:
    rows.append(
        {
            "schema_version": 1,
            "record_kind": "BATCH1_PENDING_PROPOSAL",
            "row_key": f"batch1-proposal:{proposal['key']}",
            "canonical_component_id": f"batch1-proposal:{proposal['key']}",
            "source_layer": "BATCH1_UNINTEGRATED_PROPOSAL",
            "source_instance": proposal["report"].parent.name,
            "source_tier": proposal["tier"],
            "row_state": "UNKNOWN",
            "state_axes": {
                "source_verdict": "PASS",
                "alias_qa_action": "NOT_RUN_AGAINST_CURRENT_184_ROW_ENVELOPE",
                "negative_control_outcome": "NOT_SAMPLED",
                "integration_state": "PENDING_CROSS_SHARD_RECONCILIATION",
            },
            "counting": {"canonical_instance": False, "strict_document_max": False, "broad_released_max": False, "widest_max": False},
            "primary_id": ids(proposal["ids"])[0],
            "public_ids": ids(proposal["ids"]),
            "declared_public_ids": ids(proposal["ids"]),
            "repository": proposal["repo"],
            "mechanism": proposal["mechanism"],
            "candidate_fix_edges": proposal["edges"],
            "proposed_fixes": sorted({edge["fix_sha"] for edge in proposal["edges"]}),
            "alias_amendments": [],
            "duplicate_of": None,
            "source_refs": [ref(proposal["report"], proposal["locator"])],
            "notes": ["Source shard reports PASS; excluded from current maxima until cross-shard identity, duplicate, and control coverage closes."],
        }
    )

ledger_path = ROOT / "ledger.jsonl"
ledger_path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows))

component_rows = [row for row in rows if row["record_kind"] == "COMPONENT_ROW"]
canonical_rows = [row for row in component_rows if row["counting"]["canonical_instance"]]
post_rows = [row for row in component_rows if row["source_layer"] == "POST_STRICT_DOCUMENTS"]
post_canonical = [row for row in post_rows if row["counting"]["canonical_instance"]]
baseline_rows = [row for row in component_rows if row["source_layer"] == "STRICT_200_BASELINE"]

source_envelopes = {
    key: sum(row["counting"][field] for row in component_rows)
    for key, field in {
        "strict_document_rows": "strict_document_max",
        "broad_released_max": "broad_released_max",
        "widest_max": "widest_max",
    }.items()
}

def projected(field: str, excluded_states: set[str], extra_excluded: set[str] = set()) -> int:
    return sum(
        row["counting"][field]
        and row["row_state"] not in excluded_states
        and row["canonical_component_id"] not in extra_excluded
        for row in component_rows
    )


terminal_results = []
for result_path in sorted((SNAPSHOT / "batch1").glob("*/result.json")):
    result = read_json(result_path)
    terminal_results.append(
        {
            "shard": result_path.parent.name,
            "status": result.get("status"),
            "task": result.get("task"),
            "counts": result.get("counts", {}),
            "blockers": result.get("blockers", []),
            "claim_boundary": result.get("claim_boundary"),
            "source_ref": ref(result_path),
        }
    )

def original_source(path: Path) -> str:
    relative = path.relative_to(SNAPSHOT)
    if relative.parts[0] == "post-strict":
        return f"docs/{relative.name}"
    if relative.parts[0] == "strict":
        if relative.name.startswith("RESEARCH-"):
            return f"docs/{relative.name}"
        return f"autoresearch/orchestrator-260811-atomic150/strict-200-v3/{relative.name}"
    return f"autoresearch/herdr-260812-{relative.parts[1]}/{relative.name}"


manifest = [
    {
        "path": path.relative_to(ROOT).as_posix(),
        "source_path": original_source(path),
        "sha256": sha256(path),
        "bytes": path.stat().st_size,
    }
    for path in sorted(SNAPSHOT.rglob("*"))
    if path.is_file()
]

summary = {
    "schema_version": 1,
    "task": "snapshot-only canonical unified row ledger",
    "status": "COMPLETE",
    "integration_ready": False,
    "snapshot_at": SNAPSHOT_AT,
    "snapshot_boundary": "All 57 live source files matched their frozen bytes at snapshot_at; later changes cannot alter this ledger.",
    "snapshot_file_count": len(manifest),
    "snapshot_manifest": manifest,
    "ledger_sha256": sha256(ledger_path),
    "counts": {
        "ledger_records": len(rows),
        "component_row_instances": len(component_rows),
        "canonical_source_components": len(canonical_rows),
        "strict_baseline_components": len(baseline_rows),
        "post_strict_row_instances": len(post_rows),
        "post_strict_canonical_components": len(post_canonical),
        "exact_duplicate_instances": sum(row["row_state"] == "DUPLICATE" for row in component_rows),
        "batch1_route_controls": sum(row["record_kind"] == "BATCH1_ROUTE_CONTROL" for row in rows),
        "batch1_pending_proposals": sum(row["record_kind"] == "BATCH1_PENDING_PROPOSAL" for row in rows),
        "component_rows_by_tier": dict(sorted(Counter(row["source_tier"] for row in canonical_rows).items())),
        "component_instances_by_state": dict(sorted(Counter(row["row_state"] for row in component_rows).items())),
        "all_records_by_state": dict(sorted(Counter(row["row_state"] for row in rows).items())),
    },
    "source_envelopes": {
        **source_envelopes,
        "strict_formula": "110 frozen strict + 15 post-strict strict document rows = 125",
        "broad_formula": "125 strict document rows + 47 deduplicated incomplete-remediation released rows <= 172",
        "widest_formula": "172 broad released maximum + 12 deduplicated commit-only rows <= 184",
        "final_count": None,
    },
    "status_projections_not_final_counts": {
        "after_three_known_rejects": {
            "strict_document_rows": projected("strict_document_max", {"REJECT", "DUPLICATE"}),
            "broad_released": projected("broad_released_max", {"REJECT", "DUPLICATE"}),
            "widest": projected("widest_max", {"REJECT", "DUPLICATE"}),
        },
        "after_three_rejects_and_sampled_causal_unknown": {
            "strict_document_rows": projected("strict_document_max", {"REJECT", "DUPLICATE"}, {"post:coolify-trust-host-cache"}),
            "broad_released": projected("broad_released_max", {"REJECT", "DUPLICATE"}, {"post:coolify-trust-host-cache"}),
            "widest": projected("widest_max", {"REJECT", "DUPLICATE"}, {"post:coolify-trust-host-cache"}),
        },
        "if_filebrowser_umbrella_is_duplicate_too": {
            "broad_released": projected("broad_released_max", {"REJECT", "DUPLICATE"}, {"post:coolify-trust-host-cache", "post:filebrowser-scoped-fs"}),
            "widest": projected("widest_max", {"REJECT", "DUPLICATE"}, {"post:coolify-trust-host-cache", "post:filebrowser-scoped-fs"}),
        },
        "warning": "These are bounded projections, not an exhaustive publication-grade census. Alias UNKNOWN rows and unsampled causal rows forbid a final count.",
    },
    "public_id_inventory": {
        "strict_baseline_unique_ids": len(ids(value for row in baseline_rows for value in row["public_ids"])),
        "post_strict_declared_unique_ids": len(ids(value for row in post_canonical for value in row["declared_public_ids"])),
        "post_strict_official_unique_ids_after_alias_qa": len(ids(value for row in post_canonical for value in row["public_ids"])),
        "baseline_post_overlap": len(
            set(value for row in baseline_rows for value in row["public_ids"])
            & set(value for row in post_canonical for value in row["public_ids"])
        ),
        "combined_source_inventory_unique_ids_not_a_claim_count": len(ids(value for row in canonical_rows for value in row["public_ids"])),
    },
    "alias_qa": {
        "strict_baseline_alias_amendments": sum(len(row["alias_amendments"]) for row in baseline_rows),
        "post_strict_actions_by_instance": dict(sorted(Counter(row["state_axes"]["alias_qa_action"] for row in post_rows).items())),
        "add_alias_rows": [row["row_key"] for row in post_rows if row["state_axes"]["alias_qa_action"] == "ADD_ALIAS"],
        "split_rows": [row["row_key"] for row in post_rows if row["state_axes"]["alias_qa_action"] == "SPLIT"],
        "duplicate_remove_rows": [row["row_key"] for row in post_rows if row["state_axes"]["alias_qa_action"] == "REMOVE_ID"],
        "unknown_rows": [row["row_key"] for row in post_rows if row["state_axes"]["alias_qa_action"] == "UNKNOWN"],
    },
    "negative_control_audit": {
        "sampled_rows": len(CONTROL_OUTCOMES),
        "outcomes": dict(sorted(Counter(outcome for _, outcome in CONTROL_OUTCOMES.values()).items())),
        "rows": [
            {"row_key": row["row_key"], "outcome": row["state_axes"]["negative_control_outcome"], "row_state": row["row_state"]}
            for row in post_rows
            if row["state_axes"]["negative_control_outcome"] in {"KEEP", "REJECT", "NARROW", "UNKNOWN"}
        ],
    },
    "batch1_terminal_outcomes": terminal_results,
    "coverage": {
        "strict_positive_rows_materialized": True,
        "post_strict_positive_instances_materialized": True,
        "exact_duplicate_instances_materialized": True,
        "negative_control_sample_materialized": True,
        "alias_actions_materialized": True,
        "all_post_strict_rejected_and_unknown_controls_materialized": False,
        "all_batch1_report_rows_materialized": False,
        "all_post_strict_rows_have_machine_parsed_candidate_edges": False,
    },
    "blockers": [
        "Only 20 of 74 post-strict semantic rows received the Batch 1 adversarial causal-control audit; unsampled rows were not reopened.",
        "File Browser CVE-2026-54094 may be an umbrella for the two Batch D split residuals; no final component count is forced.",
        "Six post-strict rows retain alias-QA UNKNOWN actions and the Feishu webhook row requires scoped SPLIT handling.",
        "Five newly reported Batch 1 positive proposals are non-counting until cross-shard identity, duplicate, negative-control, and released-containment integration supersedes the current maxima.",
        "Post-strict candidate edges remain document pointers rather than exhaustively machine-parsed edge objects.",
        "Negative/unknown rows in several Batch 1 diagnostic reports are snapshotted but not exhaustively normalized to component-grain records.",
    ],
    "claim_boundary": "The ledger unifies frozen rows, source tiers, identity actions, exact duplicates, sampled controls, and diagnostic route outcomes. It does not independently prove AI causality, exploitability, advisory identity, or released containment. Routing, ancestry, tests, source recovery, and shared fix objects remain diagnostic. REJECT is scoped to the named edge or duplicate count; NARROW is valid only at the recorded scope; BLOCKED and UNKNOWN remain unresolved; commit-only rows are never released rows.",
}

(ROOT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(f"built {len(rows)} records; source maxima {source_envelopes}")
