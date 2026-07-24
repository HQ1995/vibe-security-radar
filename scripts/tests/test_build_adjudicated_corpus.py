from __future__ import annotations

import json
from pathlib import Path

import build_adjudicated_corpus as corpus


def _payload() -> dict:
    return {
        "schema_version": 1,
        "adjudications": [
            {"cve_id": "CVE-2026-0002", "label": "NOT_AI_CAUSAL"},
            {"cve_id": "CVE-2026-0001", "label": "AI_CAUSAL"},
            {"cve_id": "CVE-2026-0003", "label": "INCONCLUSIVE"},
        ],
    }


def test_build_corpus_is_sorted_and_reports_conclusive_denominator() -> None:
    content, report = corpus.build_corpus(_payload())

    assert content == (
        b"CVE-2026-0001\nCVE-2026-0002\nCVE-2026-0003\n"
    )
    assert report["subject_count"] == 3
    assert report["conclusive_count"] == 2


def test_check_fails_closed_when_output_is_stale(tmp_path: Path) -> None:
    source = tmp_path / "adjudications.json"
    output = tmp_path / "subjects.txt"
    source.write_text(json.dumps(_payload()), encoding="utf-8")
    output.write_text("CVE-OLD\n", encoding="utf-8")

    assert corpus.main([
        "--input", str(source), "--output", str(output), "--check"
    ]) == 2
    assert corpus.main([
        "--input", str(source), "--output", str(output)
    ]) == 0
    assert corpus.main([
        "--input", str(source), "--output", str(output), "--check"
    ]) == 0


def test_duplicate_subject_is_rejected() -> None:
    payload = _payload()
    payload["adjudications"].append(payload["adjudications"][0])

    try:
        corpus.build_corpus(payload)
    except corpus.CorpusBuildError as exc:
        assert "unique" in str(exc)
    else:  # pragma: no cover - fail explicitly without pytest dependency
        raise AssertionError("duplicate corpus entry was accepted")
