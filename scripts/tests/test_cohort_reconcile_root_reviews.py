"""Focused test for blinded root-review reconciliation."""

from __future__ import annotations

import hashlib
import json

import cohort_reconcile_root_reviews as reconcile


def _write_json(path, value) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _write_jsonl(path, rows) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _decision(packet_id, decision, selected_ids):
    return {
        "packet_id": packet_id,
        "decision": decision,
        "selected_ids": selected_ids,
        "confidence": "high",
        "rationale": "bounded evidence supports this decision",
        "missing_evidence": "",
    }


def test_reconcile_requires_two_votes_and_keeps_unknowns(tmp_path) -> None:
    packet_dir = tmp_path / "packets"
    packet_dir.mkdir()
    packets = [
        {
            "schema_version": 1,
            "packet_id": packet_id,
            "target_id": f"target-{packet_id}",
            "vulnerability_description": "missing check",
            "candidates": [
                {
                    "candidate_id": "C01",
                    "authored_date": "2026-01-01",
                    "subject": "repair",
                    "body_excerpt": "",
                    "changed_paths": ["a.py"],
                    "patch_excerpt": "+ check()",
                    "patch_truncated": False,
                    "evidence_status": "READY",
                    "evidence_reason": "",
                }
            ],
        }
        for packet_id in ("p1", "p2")
    ]
    packets_path = packet_dir / "packets.jsonl"
    _write_jsonl(packets_path, packets)
    _write_json(
        packet_dir / "sealed_candidate_map.json",
        {
            "schema_version": 1,
            "artifact_kind": "sealed_root_candidate_map",
            "rows": [
                {
                    "packet_id": packet_id,
                    "repository_identity": f"github.com/acme/{packet_id}",
                    "advisory": f"CVE-2026-{1000 + index}",
                    "candidates": [{"candidate_id": "C01", "sha": str(index) * 40}],
                }
                for index, packet_id in enumerate(("p1", "p2"), start=1)
            ],
        },
    )
    packet_hash = hashlib.sha256(packets_path.read_bytes()).hexdigest()
    selection = tmp_path / "selection.json"
    protocol = tmp_path / "protocol.json"
    _write_json(
        selection,
        {
            "split_id": "heldout",
            "prelabel_artifacts": {"root_packets_jsonl_sha256": packet_hash},
        },
    )
    _write_json(
        protocol,
        {"split_id": "heldout", "root_packets_jsonl_sha256": packet_hash},
    )
    review_a = tmp_path / "a.jsonl"
    review_b = tmp_path / "b.jsonl"
    review_c = tmp_path / "c.jsonl"
    _write_jsonl(
        review_a,
        [_decision("p1", "select", ["C01"]), _decision("p2", "select", ["C01"])],
    )
    _write_jsonl(
        review_b,
        [_decision("p1", "select", ["C01"]), _decision("p2", "abstain", [])],
    )
    _write_jsonl(review_c, [_decision("p2", "abstain", [])])
    output = tmp_path / "output"

    assert (
        reconcile.main(
            [
                "--packet-dir",
                str(packet_dir),
                "--review-a",
                str(review_a),
                "--review-b",
                str(review_b),
                "--review-c",
                str(review_c),
                "--selection",
                str(selection),
                "--protocol",
                str(protocol),
                "--frozen-at",
                "2026-08-03T00:00:00Z",
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )
    result = json.loads((output / "result.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "fix_manifest.json").read_text(encoding="utf-8"))
    assert result["resolved_case_count"] == 1
    assert result["unresolved_case_count"] == 1
    assert result["primary_disagreement_count"] == 1
    assert [row["fix_sha"] for row in manifest["fixes"]] == ["1" * 40]
