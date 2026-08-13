#!/usr/bin/env python3
"""Build the fp211-adjudicated canonical HOLD ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE_LEDGER = "autoresearch/orchestrator-260812-posthold-canonical/ledger.jsonl"
BASE_SUMMARY = "autoresearch/orchestrator-260812-posthold-canonical/summary.json"
AUDIT_META = "autoresearch/orchestrator-260813-fp211-audit/manifest.json"
AUDIT_MANIFEST = "autoresearch/orchestrator-260813-fp211-audit/manifest.jsonl"
AUDIT_ROWS = "autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl"
AUDIT_DISPOSITIONS = (
    "autoresearch/orchestrator-260813-fp211-audit/public_id_dispositions.jsonl"
)
AUDIT_SUMMARY = "autoresearch/orchestrator-260813-fp211-audit/summary.json"
AUDIT_OUTPUT_MANIFEST = (
    "autoresearch/orchestrator-260813-fp211-audit/output_manifest.json"
)
VERDICT_TO_STATE = {
    "CONFIRM": "PASS",
    "NARROW": "NARROW",
    "FALSE_POSITIVE": "REJECT",
    "UNKNOWN": "UNKNOWN",
    "BLOCKED": "BLOCKED",
}
GATE_FIELDS = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
)
HAN = re.compile(r"[\u3400-\u9fff]")


def compact_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path):
    return json.loads(path.read_text())


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def source_hashes(manifest: dict) -> dict[str, str]:
    return {item["path"]: item["sha256"] for item in manifest["sources"]}


def primary_id(public_ids: list[str]) -> str:
    return next(
        (value for value in public_ids if value.startswith("CVE-")), public_ids[0]
    )


def fp211_source_ref(audit: dict, hashes: dict[str, str]) -> dict:
    return {
        "path": AUDIT_ROWS,
        "sha256": hashes[AUDIT_ROWS],
        "locator": f"ordinal:{audit['ordinal']}",
    }


def apply_fp211(row: dict, audit: dict, hashes: dict[str, str]) -> None:
    baseline_causal_class = row.get("causal_class")
    baseline_ids = list(row["public_ids"])
    source_ref = fp211_source_ref(audit, hashes)
    state = VERDICT_TO_STATE[audit["verdict"]]
    strict_confirmed = (
        audit["verdict"] == "CONFIRM"
        and audit["confidence"] == "HIGH"
        and all(audit[field] in {"PASS", "NA"} for field in GATE_FIELDS)
    )
    released_admitted = (
        strict_confirmed
        and row["source_tier"].endswith("_RELEASED")
        and audit["release_gate"] == "PASS"
    )

    adjudication = dict(audit)
    adjudication.update(
        {
            "authoritative": True,
            "baseline_causal_class": baseline_causal_class,
            "edge_authority": "candidate_set/carrier_set/minimum_fix_set",
            "legacy_top_level_edge_policy": "PRESERVED_HISTORICAL_ROUTING_EVIDENCE",
            "row_state_projection": state,
            "source_ref": source_ref,
        }
    )

    row["schema_version"] = 3
    row["row_state"] = state
    row["causal_class"] = audit["causal_class"]
    if HAN.search(row.get("mechanism", "")):
        row["mechanism"] = audit["lesson"]
    # The audit population was frozen from the effective public_ids projection.
    # Preserve that complete pre-fp211 set even where an older declared field was stale.
    row["declared_public_ids"] = baseline_ids
    row["public_ids"] = list(audit["public_ids_keep"])
    row["primary_id"] = primary_id(row["public_ids"])
    row["fp211_adjudication"] = adjudication
    row["source_refs"].append(source_ref)
    row["counting"].update(
        {
            "fp211_causal_valid": audit["verdict"] in {"CONFIRM", "NARROW"},
            "fp211_released_publication_admitted": released_admitted,
            "fp211_strict_confirmed": strict_confirmed,
        }
    )
    row["state_axes"].update(
        {
            "fp211_confidence": audit["confidence"],
            "fp211_integration_state": "ABSORBED",
            "fp211_verdict": audit["verdict"],
        }
    )


def load_sources() -> tuple[
    dict, dict[str, str], list[dict], list[dict], list[dict], dict
]:
    manifest = load_json(HERE / "source_manifest.json")
    hashes = source_hashes(manifest)
    assert len(hashes) == len(manifest["sources"])
    for relative, expected in hashes.items():
        path = ROOT / relative
        assert path.is_file(), relative
        assert sha256_file(path) == expected, relative

    output_manifest = load_json(ROOT / AUDIT_OUTPUT_MANIFEST)
    output_hashes = {item["path"]: item["sha256"] for item in output_manifest["files"]}
    for relative in (AUDIT_ROWS, AUDIT_DISPOSITIONS, AUDIT_SUMMARY):
        name = Path(relative).name
        assert output_hashes[name] == hashes[relative]

    audit_meta = load_json(ROOT / AUDIT_META)
    assert audit_meta["ledger_path"] == BASE_LEDGER
    assert audit_meta["ledger_sha256"] == hashes[BASE_LEDGER]
    assert audit_meta["manifest_sha256"] == hashes[AUDIT_MANIFEST]
    assert audit_meta["canonical_components"] == 211

    return (
        manifest,
        hashes,
        load_jsonl(ROOT / BASE_LEDGER),
        load_jsonl(ROOT / AUDIT_ROWS),
        load_jsonl(ROOT / AUDIT_DISPOSITIONS),
        load_json(ROOT / AUDIT_SUMMARY),
    )


def build_outputs() -> dict[Path, str]:
    manifest, hashes, ledger, audits, dispositions, audit_summary = load_sources()
    canonical = [
        row
        for row in ledger
        if row.get("record_kind") == "COMPONENT_ROW"
        and row["counting"]["canonical_instance"]
    ]
    assert len(canonical) == len(audits) == 211
    assert [row["row_key"] for row in canonical] == [row["row_key"] for row in audits]
    assert [row["ordinal"] for row in audits] == list(range(1, 212))

    for row, audit in zip(canonical, audits, strict=True):
        apply_fp211(row, audit, hashes)

    ledger_text = "".join(compact_json(row) + "\n" for row in ledger)
    released = [row for row in canonical if row["source_tier"].endswith("_RELEASED")]
    declared_list = [value for row in canonical for value in row["declared_public_ids"]]
    kept_list = [value for row in canonical for value in row["public_ids"]]
    declared_ids = set(declared_list)
    kept_ids = set(kept_list)
    removed_ids = sorted(declared_ids - kept_ids)
    audit_counts = Counter(row["verdict"] for row in audits)
    state_counts = Counter(row["row_state"] for row in canonical)
    strict_confirmed = sum(
        row["counting"]["fp211_strict_confirmed"] for row in canonical
    )
    released_admitted = sum(
        row["counting"]["fp211_released_publication_admitted"] for row in canonical
    )
    causal_valid = sum(row["counting"]["fp211_causal_valid"] for row in canonical)

    assert audit_counts == Counter(
        {"CONFIRM": 65, "NARROW": 83, "FALSE_POSITIVE": 54, "UNKNOWN": 9}
    )
    assert state_counts == Counter(
        {"PASS": 65, "NARROW": 83, "REJECT": 54, "UNKNOWN": 9}
    )
    assert Counter(row["row_state"] for row in released) == Counter(
        {"PASS": 60, "NARROW": 83, "REJECT": 49, "UNKNOWN": 7}
    )
    assert len(declared_list) == len(declared_ids) == 381
    assert len(kept_list) == len(kept_ids) == 371 and len(removed_ids) == 10
    assert strict_confirmed == 51 and released_admitted == 48 and causal_valid == 148
    assert audit_summary["mechanism_verdicts"] == dict(audit_counts)
    assert Counter(row["disposition"] for row in dispositions) == Counter(
        {"KEPT": 371, "REMOVED_IDENTITY": 10}
    )
    assert {
        row["public_id"]
        for row in dispositions
        if row["disposition"] == "REMOVED_IDENTITY"
    } == set(removed_ids)
    assert audit_summary["input_sha256"]["manifest.jsonl"] == hashes[AUDIT_MANIFEST]

    source_envelopes = {
        "broad_released_max": sum(
            row["counting"]["broad_released_max"] for row in canonical
        ),
        "final_count": None,
        "input_only": True,
        "strict_document_rows": sum(
            row["counting"]["strict_document_max"] for row in canonical
        ),
        "widest_max": sum(row["counting"]["widest_max"] for row in canonical),
    }
    summary = {
        "schema_version": 1,
        "status": "HOLD",
        "fp211_absorbed": True,
        "canonical_overlay_ready": True,
        "integration_ready": False,
        "integration_scope": "fp211 canonical overlay is absorbed; global unified/publication integration remains closed",
        "publication_ready": False,
        "source_manifest_sha256": sha256_file(HERE / "source_manifest.json"),
        "base_ledger_sha256": hashes[BASE_LEDGER],
        "fp211_final_mechanisms_sha256": hashes[AUDIT_ROWS],
        "ledger_sha256": sha256_bytes(ledger_text.encode()),
        "counts": {
            "audit_mechanism_verdicts": dict(audit_counts),
            "canonical_hypotheses": len(canonical),
            "canonical_rows_by_state": dict(state_counts),
            "causal_valid_mechanisms": causal_valid,
            "component_row_instances": sum(
                row.get("record_kind") == "COMPONENT_ROW" for row in ledger
            ),
            "confirm_medium_needing_review": sum(
                row["verdict"] == "CONFIRM" and row["confidence"] == "MEDIUM"
                for row in audits
            ),
            "confirmed_mechanisms": audit_counts["CONFIRM"],
            "kept_public_ids": len(kept_ids),
            "ledger_records": len(ledger),
            "noncanonical_records": len(ledger) - len(canonical),
            "released_publication_admitted_mechanisms": released_admitted,
            "released_rows_by_state": dict(
                Counter(row["row_state"] for row in released)
            ),
            "removed_public_ids": len(removed_ids),
            "route_controls": sum(
                row.get("record_kind") == "POST_HOLD_ROUTE_CONTROL" for row in ledger
            ),
            "source_declared_public_ids": len(declared_ids),
            "strict_confirmed_mechanisms": strict_confirmed,
            "tiers": dict(Counter(row["source_tier"] for row in canonical)),
        },
        "source_envelopes": source_envelopes,
        "removed_public_ids": removed_ids,
        "claim_boundary": {
            "causal_valid_includes_narrow_scope": True,
            "only_confirm_high_with_all_gates_closed_is_strict_confirmed": True,
            "public_200_claim_supported": False,
            "row_state_pass_is_not_publication_admission": True,
            "source_envelopes_are_input_only": True,
        },
        "blockers": [
            "14 CONFIRM/MEDIUM mechanisms require another review before strict confirmation.",
            "83 NARROW mechanisms require narrowed-scope projection before publication consumption.",
            "9 UNKNOWN mechanisms remain non-admitted.",
            "3 strict-confirmed commit-only mechanisms lack released containment and are excluded from released publication admission.",
            "Publication consumers and full release evidence have not been replayed against this overlay; source envelopes remain input-only.",
        ],
    }
    assert source_envelopes == {
        "broad_released_max": 199,
        "final_count": None,
        "input_only": True,
        "strict_document_rows": 134,
        "widest_max": 211,
    }
    summary_text = (
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    result = {
        "schema_version": 1,
        "status": "HOLD",
        "validation": "PASS",
        "fp211_absorbed": True,
        "canonical_overlay_ready": True,
        "integration_ready": False,
        "integration_scope": summary["integration_scope"],
        "publication_ready": False,
        "source_manifest_sha256": summary["source_manifest_sha256"],
        "ledger_sha256": summary["ledger_sha256"],
        "summary_sha256": sha256_bytes(summary_text.encode()),
        "structural_counts": summary["counts"],
        "gate_status": {
            "deterministic_generation": "PASS",
            "fp211_211_row_join": "PASS",
            "fp211_strict_publication": "HOLD",
            "frozen_base_conservation": "PASS",
            "public_id_conservation": "PASS",
            "source_hashes": "PASS",
        },
        "blockers": summary["blockers"],
    }
    result_text = (
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    return {
        HERE / "ledger.jsonl": ledger_text,
        HERE / "summary.json": summary_text,
        HERE / "result.json": result_text,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = build_outputs()
    if args.check:
        for path, text in outputs.items():
            assert path.is_file() and path.read_text() == text, (
                f"stale generated artifact: {path}"
            )
        print("PASS: fp211 canonical ledger, summary, and result are byte-identical")
        return
    for path, text in outputs.items():
        path.write_text(text)
    print("WROTE: ledger.jsonl summary.json result.json")


if __name__ == "__main__":
    main()
