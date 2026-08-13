#!/usr/bin/env python3
"""Fail closed on fp211 overlay provenance, conservation, and admission."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import build


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXPECTED_SOURCE_MANIFEST_SHA256 = (
    "679dbac540bf2f8dad0a24a85d8fc309c613977a2b58a1ad44b40e5a85798ccb"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HAN = re.compile(r"[\u3400-\u9fff]")
GATE_VALUES = {"PASS", "FAIL", "NARROW", "UNKNOWN", "BLOCKED", "NA"}
GATE_FIELDS = (
    "identity_gate",
    "ai_hunk_gate",
    "topology_gate",
    "but_for_gate",
    "fix_reversal_gate",
    "release_gate",
    "uniqueness_gate",
)


def load_json(path: Path):
    return json.loads(path.read_text())


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify() -> tuple[dict, list[dict]]:
    assert sha256(HERE / "source_manifest.json") == EXPECTED_SOURCE_MANIFEST_SHA256
    manifest = load_json(HERE / "source_manifest.json")
    hashes = {item["path"]: item["sha256"] for item in manifest["sources"]}
    assert len(hashes) == len(manifest["sources"])
    for relative, expected in hashes.items():
        path = ROOT / relative
        assert path.is_file() and sha256(path) == expected, relative

    outputs = build.build_outputs()
    for path, expected in outputs.items():
        assert path.is_file() and path.read_text() == expected, path.name

    ledger = load_jsonl(HERE / "ledger.jsonl")
    assert not HAN.search((HERE / "ledger.jsonl").read_text())
    summary = load_json(HERE / "summary.json")
    result = load_json(HERE / "result.json")
    base = load_jsonl(ROOT / build.BASE_LEDGER)
    audits = load_jsonl(ROOT / build.AUDIT_ROWS)
    audit_manifest = load_jsonl(ROOT / build.AUDIT_MANIFEST)
    dispositions = load_jsonl(ROOT / build.AUDIT_DISPOSITIONS)
    assert len(ledger) == len(base) == 273
    assert len(audits) == len(audit_manifest) == 211
    build.assert_semantic_controls(audits)

    base_canonical = [
        row
        for row in base
        if row.get("record_kind") == "COMPONENT_ROW"
        and row["counting"]["canonical_instance"]
    ]
    canonical = [
        row
        for row in ledger
        if row.get("record_kind") == "COMPONENT_ROW"
        and row["counting"]["canonical_instance"]
    ]
    assert [row["row_key"] for row in canonical] == [
        row["row_key"] for row in base_canonical
    ]
    assert [row["row_key"] for row in canonical] == [row["row_key"] for row in audits]
    assert [row["row_key"] for row in canonical] == [
        row["row_key"] for row in audit_manifest
    ]

    canonical_keys = {row["row_key"] for row in canonical}
    assert [row for row in ledger if row["row_key"] not in canonical_keys] == [
        row for row in base if row["row_key"] not in canonical_keys
    ]

    disposition_by_id = {row["public_id"]: row for row in dispositions}
    assert len(disposition_by_id) == len(dispositions) == 381
    for row, baseline, audit, frozen in zip(
        canonical, base_canonical, audits, audit_manifest, strict=True
    ):
        assert row["row_key"] == audit["row_key"] == frozen["row_key"]
        assert row["schema_version"] == 3
        assert row["row_state"] == build.VERDICT_TO_STATE[audit["verdict"]]
        assert (
            row["declared_public_ids"] == baseline["public_ids"] == frozen["public_ids"]
        )
        assert set(baseline.get("declared_public_ids", [])) <= set(
            row["declared_public_ids"]
        )
        assert row["public_ids"] == audit["public_ids_keep"]
        assert set(audit["public_ids_keep"]) | set(audit["public_ids_remove"]) == set(
            row["declared_public_ids"]
        )
        assert not set(audit["public_ids_keep"]) & set(audit["public_ids_remove"])
        for public_id in row["declared_public_ids"]:
            expected = "KEPT" if public_id in row["public_ids"] else "REMOVED_IDENTITY"
            assert disposition_by_id[public_id]["disposition"] == expected
            assert disposition_by_id[public_id]["row_key"] == row["row_key"]
            assert disposition_by_id[public_id]["mechanism_verdict"] == audit["verdict"]

        embedded = row["fp211_adjudication"]
        assert {key: embedded[key] for key in audit} == audit
        assert embedded["authoritative"] is True
        assert embedded["edge_authority"] == "candidate_set/carrier_set/minimum_fix_set"
        assert embedded["row_state_projection"] == row["row_state"]
        assert embedded["source_ref"] == row["source_refs"][-1]
        assert embedded["source_ref"] == {
            "path": build.AUDIT_ROWS,
            "sha256": hashes[build.AUDIT_ROWS],
            "locator": f"ordinal:{audit['ordinal']}",
        }
        for field in GATE_FIELDS:
            assert embedded[field] in GATE_VALUES
        for field in ("candidate_set", "carrier_set", "minimum_fix_set"):
            assert embedded[field] == sorted(set(embedded[field]))
            assert all(SHA_RE.fullmatch(value) for value in embedded[field])

        strict = build.strict_confirmed(audit)
        released_admitted = build.released_publication_admitted(
            audit, row["source_tier"]
        )
        assert row["counting"]["fp211_strict_confirmed"] is strict
        assert (
            row["counting"]["fp211_released_publication_admitted"] is released_admitted
        )
        assert row["counting"]["fp211_causal_valid"] == (
            audit["verdict"] in {"CONFIRM", "NARROW"}
        )
        assert row["state_axes"]["fp211_verdict"] == audit["verdict"]
        assert row["state_axes"]["fp211_confidence"] == audit["confidence"]
        assert row["state_axes"]["fp211_integration_state"] == "ABSORBED"

        # fp211 sets supersede these legacy routing fields without inventing pairings.
        for field in ("candidate_fix_edges", "atomic_fix_members", "release_evidence"):
            assert row.get(field) == baseline.get(field)
        for field in (
            "canonical_instance",
            "strict_document_max",
            "broad_released_max",
            "widest_max",
        ):
            assert row["counting"][field] == baseline["counting"][field]

    assert Counter(row["verdict"] for row in audits) == Counter(
        {"CONFIRM": 65, "NARROW": 83, "FALSE_POSITIVE": 54, "UNKNOWN": 9}
    )
    assert Counter(row["row_state"] for row in canonical) == Counter(
        {"PASS": 65, "NARROW": 83, "REJECT": 54, "UNKNOWN": 9}
    )
    released = [row for row in canonical if row["source_tier"].endswith("_RELEASED")]
    assert Counter(row["row_state"] for row in released) == Counter(
        {"PASS": 60, "NARROW": 83, "REJECT": 49, "UNKNOWN": 7}
    )
    assert (
        sum(row["counting"]["fp211_released_publication_admitted"] for row in canonical)
        == 48
    )
    assert sum(row["counting"]["fp211_causal_valid"] for row in canonical) == 148
    assert (
        sum(len(row["fp211_adjudication"]["public_ids_remove"]) for row in canonical)
        == 10
    )
    assert all(
        not row["counting"]["fp211_released_publication_admitted"]
        for row in canonical
        if row["row_state"] in {"REJECT", "UNKNOWN", "BLOCKED"}
    )
    for ordinal in (67, 68):
        row = canonical[ordinal - 1]
        assert row["row_state"] == "REJECT"
        assert row["fp211_adjudication"]["verdict"] == "FALSE_POSITIVE"
        assert row["fp211_adjudication"]["duplicate_of"] in canonical_keys

    assert canonical[164]["row_key"] == "post:filebrowser-delete-scope@canonical"
    assert canonical[165]["row_key"] == "post:filebrowser-dangling-write@canonical"

    assert (
        summary["fp211_absorbed"] is True and summary["canonical_overlay_ready"] is True
    )
    assert summary["integration_ready"] is False
    assert summary["publication_ready"] is False and summary["status"] == "HOLD"
    assert summary["counts"]["audit_mechanism_verdicts"] == {
        "CONFIRM": 65,
        "FALSE_POSITIVE": 54,
        "NARROW": 83,
        "UNKNOWN": 9,
    }
    assert summary["counts"]["released_rows_by_state"] == {
        "NARROW": 83,
        "PASS": 60,
        "REJECT": 49,
        "UNKNOWN": 7,
    }
    assert summary["counts"]["released_publication_admitted_mechanisms"] == 48
    assert summary["counts"]["causal_valid_mechanisms"] == 148
    assert summary["counts"]["removed_public_ids"] == 10
    assert summary["source_envelopes"] == {
        "broad_released_max": 199,
        "final_count": None,
        "input_only": True,
        "strict_document_rows": 134,
        "widest_max": 211,
    }
    assert (
        summary["ledger_sha256"]
        == result["ledger_sha256"]
        == sha256(HERE / "ledger.jsonl")
    )
    assert (
        summary["source_manifest_sha256"]
        == result["source_manifest_sha256"]
        == sha256(HERE / "source_manifest.json")
    )
    assert result["summary_sha256"] == sha256(HERE / "summary.json")
    assert result["validation"] == "PASS" and result["canonical_overlay_ready"] is True
    assert result["integration_ready"] is False and result["publication_ready"] is False
    return summary, canonical


def main() -> None:
    summary, _ = verify()
    counts = summary["counts"]["audit_mechanism_verdicts"]
    print(
        f"PASS: fp211 absorbed for 211 hypotheses; verdicts={counts}; publication=HOLD"
    )


if __name__ == "__main__":
    main()
