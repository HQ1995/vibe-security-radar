from __future__ import annotations

import build_source_audit_packet as audit
from cve_analyzer.source_matcher import MATCHER_CONTRACT


def _source() -> dict:
    rows = []
    for module in audit.MODULES:
        for lane in audit.LANES:
            for index in range(3):
                rows.append(
                    {
                        "case_id": f"{module}-{lane}-{index}",
                        "repository_identity": f"github.com/example/{module}-{lane}-{index}",
                        "commit_sha": f"{index + 1:040x}",
                        "source_module": module,
                        "lane": lane,
                        "commit": {
                            "author_name": "Human",
                            "author_email": "human@example.com",
                            "committer_name": "Human",
                            "committer_email": "human@example.com",
                            "message": "fixture",
                            "authored_date": "2026-01-01T00:00:00Z",
                        },
                    }
                )
    return {
        "schema_version": 1,
        "matcher_contract": MATCHER_CONTRACT,
        "rows": rows,
    }


def test_packet_is_deterministic_blind_and_repo_disjoint() -> None:
    first, predictions = audit.build_packet(_source(), per_cell=2)
    second, _ = audit.build_packet(_source(), per_cell=2)

    assert first == second
    assert first["case_count"] == 12
    assert len(
        {case["repository_identity"] for case in first["cases"]}
    ) == first["case_count"]
    assert all("source_module" not in case for case in first["cases"])
    assert all("lane" not in case for case in first["cases"])
    assert set(predictions["predictions"]) == {
        case["case_id"] for case in first["cases"]
    }


def test_dual_labels_must_be_independent_complete_and_agree() -> None:
    packet, predictions = audit.build_packet(_source(), per_cell=1)
    labels = {
        case_id: prediction["predicted_positive"]
        for case_id, prediction in predictions["predictions"].items()
    }
    first = {
        "schema_version": 1,
        "packet_sha256": packet["packet_sha256"],
        "adjudicator_id": "reviewer-a",
        "labels": labels,
    }
    second = {
        **first,
        "adjudicator_id": "reviewer-b",
    }

    report = audit.evaluate_labels(packet, predictions, first, second)

    assert report["quality_claim_ready"] is True
    assert all(
        counts == {"tp": 1, "fp": 0, "fn": 0, "tn": 1}
        for counts in report["confusion_by_module"].values()
    )

    second["labels"] = {**labels, next(iter(labels)): "inconclusive"}
    report = audit.evaluate_labels(packet, predictions, first, second)
    assert report["quality_claim_ready"] is False
    assert report["confusion_by_module"] is None
