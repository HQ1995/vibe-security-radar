#!/usr/bin/env python3
"""Build the post-hold canonical ledger from the frozen Batch 2 ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path):
    return json.loads(path.read_text())


def load_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def compact_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def source_hashes(manifest: dict) -> dict[str, str]:
    return {item["path"]: item["sha256"] for item in manifest["sources"]}


def mechanism_fingerprint(row: dict) -> str:
    payload = {
        "repository": row["repository"].lower(),
        "attacker_input": row["attacker_input"],
        "sink": row["sink"],
        "invariant": row["invariant"],
        "mechanism_key": row["mechanism_key"],
        "release_fix_sha": row["release_fix_sha"],
    }
    return sha256_bytes(compact_json(payload).encode())


def canonical_mechanism_fingerprint(row: dict) -> str:
    edges = []
    for edge in row.get("candidate_fix_edges", []):
        edges.append({key: edge[key] for key in sorted(edge) if key.endswith("_sha")})
    payload = {
        "repository": (row.get("repository") or "").lower(),
        "mechanism": " ".join(row["mechanism"].lower().split()),
        "edges": edges,
    }
    return sha256_bytes(compact_json(payload).encode())


def component_id(row: dict) -> str:
    payload = {
        "repository": row["repository"].lower(),
        "public_ids": sorted(row["public_ids"]),
        "mechanism_key": row["mechanism_key"],
    }
    return "posthold-" + sha256_bytes(compact_json(payload).encode())[:24]


def build_component(row: dict, hashes: dict[str, str]) -> dict:
    carrier = row.get("carrier_sha")
    edge = {
        "candidate_sha": row["candidate_sha"],
        "fix_sha": row["release_fix_sha"],
        "origin_kind": "squash_member" if carrier else "direct_commit",
    }
    if carrier:
        edge["carrier_sha"] = carrier
    ids = sorted(set(row["public_ids"]))
    return {
        "schema_version": 2,
        "record_kind": "COMPONENT_ROW",
        "row_key": row["row_key"],
        "canonical_component_id": component_id(row),
        "row_state": row["admission"],
        "source_layer": "POST_HOLD_REDTEAM",
        "source_instance": "posthold-canonical-20260812",
        "source_tier": row["source_tier"],
        "counting": {
            "canonical_instance": True,
            "strict_document_max": row["source_tier"] == "STRICT_RELEASED",
            "broad_released_max": True,
            "widest_max": True,
        },
        "primary_id": next((value for value in ids if value.startswith("CVE-")), ids[0]),
        "public_ids": ids,
        "declared_public_ids": ids,
        "identity_relation": row["identity_relation"],
        "alias_amendments": [],
        "repository": row["repository"],
        "mechanism": f'{row["attacker_input"]} -> {row["sink"]}; invariant: {row["invariant"]}',
        "mechanism_key": row["mechanism_key"],
        "mechanism_fingerprint": mechanism_fingerprint(row),
        "causal_class": row["causal_class"],
        "causal_evidence": row["causal_evidence"],
        "candidate_fix_edges": [edge],
        "atomic_fix_members": row["fix_member_shas"],
        "ai_provenance": {
            "marker_sha": row["ai_marker_sha"],
            "scope": "PR_LEVEL_AI_GENERATED_HUMAN_REVIEWED"
            if row["candidate_sha"] == "3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161"
            else "ATOMIC_COMMIT",
        },
        "release_evidence": {
            "repo_cache": row["repo_cache"],
            "candidate_sha": carrier or row["candidate_sha"],
            "fix_sha": row["release_fix_sha"],
            "vulnerable_tag": row["vulnerable_tag"],
            "fixed_tag": row["fixed_tag"],
        },
        "reuse_justification": row.get("reuse_justification"),
        "narrow_scope": row.get("narrow_scope"),
        "duplicate_of": None,
        "proposed_fixes": [],
        "source_refs": [
            {
                "path": row["source_doc"],
                "sha256": hashes[row["source_doc"]],
                "locator": row["source_locator"],
            }
        ],
        "state_axes": {
            "source_verdict": "PASS",
            "alias_qa_action": "CHECKED_NO_PUBLIC_ID_OVERLAP",
            "negative_control_outcome": row["admission"],
            "integration_state": "ADMITTED_TO_HOLD_LEDGER",
        },
        "notes": row["notes"],
    }


def build_control(row: dict, hashes: dict[str, str]) -> dict:
    ids = sorted(set(row["public_ids"]))
    return {
        "schema_version": 2,
        "record_kind": "POST_HOLD_ROUTE_CONTROL",
        "row_key": row["row_key"],
        "row_state": row["row_state"],
        "source_layer": "POST_HOLD_REDTEAM",
        "source_instance": "posthold-canonical-20260812",
        "source_tier": "NON_COUNTING_CONTROL",
        "counting": {
            "canonical_instance": False,
            "strict_document_max": False,
            "broad_released_max": False,
            "widest_max": False,
        },
        "primary_id": next((value for value in ids if value.startswith("CVE-")), ids[0]),
        "public_ids": ids,
        "declared_public_ids": ids,
        "repository": row["repository"],
        "candidate_fix_edges": [{"candidate_sha": row["candidate_sha"], "origin_kind": "rejected_route"}],
        "reason": row["reason"],
        "source_refs": [
            {
                "path": row["source_doc"],
                "sha256": hashes[row["source_doc"]],
                "locator": row["source_locator"],
            }
        ],
        "state_axes": {
            "source_verdict": row["row_state"],
            "alias_qa_action": "NOT_COUNTED",
            "negative_control_outcome": row["row_state"],
            "integration_state": "NON_COUNTING_CONTROL",
        },
    }


def apply_inherited_corrections(rows: list[dict], correction_doc: dict, hashes: dict[str, str]) -> None:
    by_key = {row["row_key"]: row for row in rows}
    report = correction_doc["source_report"]
    assert report in hashes
    seen = set()
    for correction in correction_doc["corrections"]:
        row_key = correction["row_key"]
        assert row_key not in seen
        seen.add(row_key)
        row = by_key[row_key]
        assert row["row_state"] == correction["expected_row_state"]
        row["row_state"] = correction["new_row_state"]
        row["schema_version"] = 2
        row["correction_decision"] = correction["decision"]
        for field in (
            "candidate_fix_edges",
            "atomic_fix_members",
            "ai_provenance",
            "release_evidence",
            "causal_class",
            "repository",
            "mechanism",
            "mechanism_key",
            "identity_relation",
            "counting",
            "overlap_with",
            "reuse_justification",
        ):
            if field in correction:
                row[field] = correction[field]
        row.setdefault("state_axes", {}).update(correction["state_axes_updates"])
        row.setdefault("notes", []).extend(correction["notes_append"])
        row.setdefault("source_refs", []).append(
            {"path": report, "sha256": hashes[report], "locator": correction["source_locator"]}
        )


def build_outputs() -> tuple[str, str]:
    manifest = load_json(HERE / "source_manifest.json")
    adjudications = load_json(HERE / "adjudications.json")
    corrections = load_json(HERE / "inherited_corrections.json")
    hashes = source_hashes(manifest)
    base_path = ROOT / "autoresearch/herdr-260812-b2-unified-ledger/ledger.jsonl"
    base = load_jsonl(base_path)
    apply_inherited_corrections(base, corrections, hashes)
    additions = [build_component(row, hashes) for row in adjudications["components"]]
    controls = [build_control(row, hashes) for row in adjudications["route_controls"]]
    ledger = base + additions + controls
    ledger_text = "".join(compact_json(row) + "\n" for row in ledger)

    components = [row for row in ledger if row["record_kind"] == "COMPONENT_ROW"]
    canonical = [row for row in components if row["counting"]["canonical_instance"]]
    released = [row for row in canonical if row["source_tier"].endswith("_RELEASED")]
    summary = {
        "schema_version": 3,
        "status": "HOLD",
        "integration_ready": False,
        "source_manifest_sha256": sha256_file(HERE / "source_manifest.json"),
        "adjudications_sha256": sha256_file(HERE / "adjudications.json"),
        "inherited_corrections_sha256": sha256_file(HERE / "inherited_corrections.json"),
        "ledger_sha256": sha256_bytes(ledger_text.encode()),
        "counts": {
            "ledger_records": len(ledger),
            "component_row_instances": len(components),
            "canonical_source_components": len(canonical),
            "posthold_components": len(additions),
            "posthold_route_controls": len(controls),
            "posthold_admission": dict(Counter(row["row_state"] for row in additions)),
            "component_rows_by_state": dict(Counter(row["row_state"] for row in canonical)),
            "released_rows_by_state": dict(Counter(row["row_state"] for row in released)),
            "component_rows_by_tier": dict(Counter(row["source_tier"] for row in canonical)),
            "posthold_public_ids": len({value for row in additions for value in row["public_ids"]}),
        },
        "source_envelopes": {
            "strict_document_rows": sum(row["counting"]["strict_document_max"] for row in canonical),
            "broad_released_max": sum(row["counting"]["broad_released_max"] for row in canonical),
            "widest_max": sum(row["counting"]["widest_max"] for row in canonical),
            "final_count": None,
        },
        "claim_boundary": {
            "released_pass_rows": sum(row["row_state"] == "PASS" for row in released),
            "released_narrow_rows": sum(row["row_state"] == "NARROW" for row in released),
            "released_unknown_rows": sum(row["row_state"] == "UNKNOWN" for row in released),
            "released_reject_rows": sum(row["row_state"] == "REJECT" for row in released),
            "source_envelope_is_not_final_count": True,
        },
        "blockers": [
            "The 199 broad released value is a source envelope containing three REJECT, one UNKNOWN, and four NARROW rows; it is not a confirmed count.",
            "Only 20 of the original 74 post-strict rows received Batch 1 adversarial causal-control review.",
            "One released component remains UNKNOWN and three remain REJECT after inherited-row closure.",
            "Four released rows are NARROW after combining Batch 2 and post-hold adjudications.",
            "Three commit-only component rows remain UNKNOWN.",
            "Batch H admitted zero of 24 OpenClaw/ChurchCRM routes; the QQBot regression remains a non-counting attribution UNKNOWN.",
            "Current live release replay covers 33 targeted rows rather than every inherited released row.",
        ],
    }
    summary_text = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return ledger_text, summary_text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    ledger_text, summary_text = build_outputs()
    expected = {HERE / "ledger.jsonl": ledger_text, HERE / "summary.json": summary_text}
    if args.check:
        for path, text in expected.items():
            assert path.is_file() and path.read_text() == text, f"stale generated artifact: {path}"
        print("PASS: generated ledger and summary are byte-identical")
        return
    for path, text in expected.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json")


if __name__ == "__main__":
    main()
