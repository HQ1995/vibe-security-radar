from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import build_publication_adjudications as builder
from cohort.publication_admission import GATE_FIELDS


_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "build_publication_adjudications.py"
_CORPUS = _REPO_ROOT / "scripts" / "publication_adjudications.json"


def _rows() -> list[dict]:
    return json.loads(_CORPUS.read_text(encoding="utf-8"))["adjudications"]


def _labels_by_subject() -> dict[str, str]:
    return {
        subject.upper(): row["label"]
        for row in _rows()
        for subject in [row["cve_id"], *row.get("aliases", [])]
    }


def test_generated_publication_corpus_is_current_and_conservative() -> None:
    checked = subprocess.run(
        [sys.executable, str(_SCRIPT), "--verify-committed"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert checked.returncode == 0, checked.stdout + checked.stderr

    payload = json.loads(_CORPUS.read_text(encoding="utf-8"))
    rows = payload["adjudications"]
    assert payload["publication_ready"] is False
    assert len(rows) == 257
    assert Counter(row["label"] for row in rows) == {
        "AI_CAUSAL": 55,
        "NOT_AI_CAUSAL": 81,
        "INCONCLUSIVE": 121,
    }
    assert payload["summary"]["preserved_base_count"] == 45
    assert payload["summary"]["replaced_base_count"] == 33
    assert payload["summary"]["fp211_public_case_count"] == 212
    assert payload["summary"]["fp211_mechanism_count"] == 211
    assert payload["summary"]["supersession_count"] == 2
    assert len(payload["summary"]["removed_public_ids"]) == 10
    assert all("excluded_aliases" in row for row in rows if "fp211" in row)


def test_fp211_lessons_replace_old_publication_labels() -> None:
    labels = _labels_by_subject()
    for subject_id in (
        "CVE-2026-32247",
        "CVE-2026-27627",
        "CVE-2026-33890",
    ):
        assert labels[subject_id] == "NOT_AI_CAUSAL"
    for subject_id in (
        "CVE-2026-1979",
        "CVE-2025-55526",
        "CVE-2026-2376",
        "CVE-2025-13120",
        "CVE-2026-25481",
        "GHSA-G353-MGV3-8PCJ",
        "CVE-2026-54362",
        "GHSA-CJP7-PM9Q-XHQG",
    ):
        assert labels[subject_id] == "INCONCLUSIVE"


def test_removed_identities_are_absent_and_nonoverlap_base_is_preserved() -> None:
    payload = json.loads(_CORPUS.read_text(encoding="utf-8"))
    rows = payload["adjudications"]
    subjects = {
        subject.upper()
        for row in rows
        for subject in [row["cve_id"], *row.get("aliases", [])]
    }
    assert subjects.isdisjoint(payload["summary"]["removed_public_ids"])
    excluded = {
        alias.upper() for row in rows for alias in row.get("excluded_aliases", [])
    }
    assert excluded == set(payload["summary"]["removed_public_ids"])

    base = json.loads(
        (_REPO_ROOT / "scripts" / "audit_adjudications.json").read_text(
            encoding="utf-8"
        )
    )["adjudications"]
    expected = next(row for row in base if row["cve_id"] == "CVE-2025-64420")
    assert next(row for row in rows if row["cve_id"] == "CVE-2025-64420") == expected


def test_release_only_failure_is_not_relabelled_noncausal() -> None:
    final = {
        "verdict": "FALSE_POSITIVE",
        **{field: "PASS" for field in GATE_FIELDS},
        "release_gate": "FAIL",
    }
    assert builder._label(final, {"may_publish": False}) == "INCONCLUSIVE"
    final["but_for_gate"] = "FAIL"
    assert builder._label(final, {"may_publish": False}) == "NOT_AI_CAUSAL"

    final["but_for_gate"] = "PASS"
    final["release_gate"] = "PASS"
    final["uniqueness_gate"] = "FAIL"
    assert builder._label(final, {"may_publish": False}) == "INCONCLUSIVE"


def _supersession(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "cve_id": "GHSA-AAAA-BBBB-CCCC",
        "aliases": ["CVE-2026-12345"],
        "label": "AI_CAUSAL",
        "audited": "2026-08-30",
        "source": "research/current-review.jsonl",
        "reason": "Later atomic-history evidence identifies the causal writer.",
        "supersedes": {
            "label": "NOT_AI_CAUSAL",
            "source": "scripts/audit_results/old.json",
        },
    }
    row.update(changes)
    return row


def _apply_supersession(row: dict[str, object]) -> list[dict[str, object]]:
    return builder._apply_supersessions(
        [
            {
                "cve_id": "GHSA-AAAA-BBBB-CCCC",
                "aliases": ["CVE-2026-12345"],
                "label": "NOT_AI_CAUSAL",
                "source": "scripts/audit_results/old.json",
                "audited": "2026-07-18",
                "confidence": 0.99,
            }
        ],
        {
            "schema_version": 1,
            "artifact_kind": "publication_adjudication_supersessions",
            "supersessions": [row],
        },
        input_hashes={"research/current-review.jsonl": "a" * 64},
    )


def test_supersession_preserves_prior_provenance() -> None:
    [updated] = _apply_supersession(_supersession())
    assert updated["label"] == "AI_CAUSAL"
    assert updated["source"] == "research/current-review.jsonl"
    assert updated["audited"] == "2026-08-30"
    assert updated["supersession"] == {
        "reason": "Later atomic-history evidence identifies the causal writer.",
        "superseded": {
            "label": "NOT_AI_CAUSAL",
            "source": "scripts/audit_results/old.json",
            "audited": "2026-07-18",
            "confidence": 0.99,
        },
    }


def test_supersession_requires_exact_identity_and_prior_decision() -> None:
    bad_rows = [
        _supersession(aliases=[]),
        _supersession(label="NOT_AI_CAUSAL"),
        _supersession(supersedes={"label": "AI_CAUSAL", "source": "wrong"}),
        _supersession(source="research/unhashed-review.jsonl"),
    ]
    for row in bad_rows:
        try:
            _apply_supersession(row)
        except builder.PublicationCorpusError:
            continue
        raise AssertionError(f"supersession unexpectedly accepted: {row!r}")


if __name__ == "__main__":
    tests = [
        value
        for name, value in globals().copy().items()
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"{len(tests)} publication adjudication tests passed")
