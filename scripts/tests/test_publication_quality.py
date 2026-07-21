"""Tests for the adjudication-backed publication-curation consistency gate."""

from __future__ import annotations

import json
import math

import pytest

import evaluate_publication_quality as quality


def _labels(*, positives: int, negatives: int = 0) -> dict[str, str]:
    labels = {f"POS-{index}": "AI_CAUSAL" for index in range(positives)}
    labels.update({f"NEG-{index}": "NOT_AI_CAUSAL" for index in range(negatives)})
    return labels


@pytest.mark.parametrize(
    ("successes", "trials", "expected"),
    [
        (0, 0, 0.0),
        (0, 10, 0.0),
        (5, 10, 0.2224411010081294),
        (6, 6, 0.6069622310029172),
        (59, 59, 0.950492390111773),
    ],
)
def test_one_sided_exact_clopper_pearson_lower_bound(
    successes: int,
    trials: int,
    expected: float,
) -> None:
    actual = quality.clopper_pearson_lower_bound(successes, trials)

    assert math.isclose(actual, expected, rel_tol=0, abs_tol=1e-12)


def test_confusion_matrix_excludes_inconclusive_and_tracks_hard_failures() -> None:
    labels = {
        "TP": "AI_CAUSAL",
        "FN": "AI_CAUSAL",
        "FP": "NOT_AI_CAUSAL",
        "TN": "NOT_AI_CAUSAL",
        "SKIP": "INCONCLUSIVE",
    }

    report = quality.evaluate(labels, {"TP", "FP", "SKIP", "UNLABELED"})

    assert report["counts"] == {
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "adjudicated_positive": 2,
        "adjudicated_negative": 2,
        "inconclusive_excluded": 1,
        "inconclusive_published": 1,
        "published_total": 4,
        "published_adjudicated": 3,
        "published_unadjudicated": 1,
    }
    assert report["confusion_ids"] == {
        "tp": ["TP"],
        "fp": ["FP"],
        "fn": ["FN"],
        "tn": ["TN"],
    }
    assert report["schema_version"] == 2
    assert report["evaluation_kind"] == "publication_curation_consistency"
    assert report["curation_precision"]["point"] == 0.5
    assert report["curation_recall"]["point"] == 0.5
    assert report["known_negative_published"] == ["FP"]
    assert report["known_inconclusive_published"] == ["SKIP"]
    assert report["curation_hard_fail"] is True
    assert report["curation_consistent"] is False
    assert report["curation_certified"] is False


def test_inconclusive_publication_hard_fails_without_changing_rates() -> None:
    labels = {
        "TP": "AI_CAUSAL",
        "TN": "NOT_AI_CAUSAL",
        "REVIEW": "INCONCLUSIVE",
    }

    clean = quality.evaluate(labels, {"TP"})
    leaked = quality.evaluate(labels, {"TP", "REVIEW"})

    assert leaked["curation_precision"] == clean["curation_precision"]
    assert leaked["curation_recall"] == clean["curation_recall"]
    assert leaked["confusion_ids"] == clean["confusion_ids"]
    assert leaked["counts"]["inconclusive_excluded"] == 1
    assert leaked["counts"]["inconclusive_published"] == 1
    assert leaked["known_inconclusive_published"] == ["REVIEW"]
    assert leaked["curation_hard_fail"] is True
    assert leaked["curation_certified"] is False


def test_six_zero_false_positives_remains_uncertified_without_sample_rule() -> None:
    labels = _labels(positives=6)

    report = quality.evaluate(labels, set(labels))

    assert report["curation_precision"]["point"] == 1.0
    assert report["curation_precision"]["trials"] == 6
    assert math.isclose(
        report["curation_precision"]["lower_bound"],
        0.6069622310029172,
        rel_tol=0,
        abs_tol=1e-12,
    )
    assert report["curation_precision"]["meets_target"] is False
    assert report["curation_certified"] is False


def test_exact_bound_naturally_certifies_at_fifty_nine_zero_fp_samples() -> None:
    labels_58 = _labels(positives=58)
    labels_59 = _labels(positives=59)

    report_58 = quality.evaluate(labels_58, set(labels_58))
    report_59 = quality.evaluate(labels_59, set(labels_59))

    assert report_58["curation_precision"]["lower_bound"] < 0.95
    assert report_58["curation_certified"] is False
    assert report_59["curation_precision"]["lower_bound"] >= 0.95
    assert report_59["curation_certified"] is True


def test_statistical_certification_requires_recall_lower_bound() -> None:
    labels = _labels(positives=60)
    published = {f"POS-{index}" for index in range(59)}

    report = quality.evaluate(labels, published)

    assert report["curation_certified"] is False
    assert report["curation_precision"]["meets_target"] is True
    assert report["curation_recall"]["point"] == pytest.approx(59 / 60)
    assert report["curation_recall"]["meets_target"] is False
    assert report["curation_consistent"] is True
    assert report["curation_recall_certified"] is False
    assert report["counts"]["fn"] == 1


def test_release_safety_requires_point_recall_target() -> None:
    labels = _labels(positives=37, negatives=37)

    report = quality.evaluate(labels, {"POS-0"})

    assert report["curation_precision"]["point"] == 1.0
    assert report["curation_recall"]["point"] == pytest.approx(1 / 37)
    assert report["curation_hard_fail"] is False
    assert report["curation_consistent"] is False
    assert report["curation_certified"] is False


def test_adjudication_loader_rejects_duplicate_ids(tmp_path) -> None:
    path = tmp_path / "adjudications.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "adjudications": [
                    {"cve_id": "CVE-1", "label": "AI_CAUSAL"},
                    {"cve_id": "CVE-1", "label": "NOT_AI_CAUSAL"},
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate adjudication"):
        quality.load_adjudications(path)


def test_alias_equivalence_is_counted_once_and_catches_negative_leaks(
    tmp_path,
) -> None:
    path = tmp_path / "adjudications.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "adjudications": [
                    {
                        "cve_id": "CVE-POS",
                        "aliases": ["GHSA-POS"],
                        "label": "AI_CAUSAL",
                    },
                    {
                        "cve_id": "CVE-NEG",
                        "aliases": ["GHSA-NEG"],
                        "label": "NOT_AI_CAUSAL",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    corpus = quality.load_adjudications(path)
    report = quality.evaluate(corpus, {"GHSA-POS", "GHSA-NEG"})

    assert report["counts"]["tp"] == 1
    assert report["counts"]["fp"] == 1
    assert report["counts"]["fn"] == 0
    assert report["known_negative_published"] == ["GHSA-NEG"]
    assert report["confusion_ids"]["tp"] == ["CVE-POS"]
    assert report["confusion_ids"]["fp"] == ["CVE-NEG"]


def test_source_alias_equivalence_catches_undeclared_negative_alias(
    tmp_path,
) -> None:
    path = tmp_path / "adjudications.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "adjudications": [
                    {
                        "cve_id": "GHSA-g353-mgv3-8pcj",
                        "label": "NOT_AI_CAUSAL",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    alias_group = {"GHSA-g353-mgv3-8pcj", "CVE-2026-32974"}

    corpus = quality.load_adjudications(
        path,
        alias_map={subject_id: alias_group for subject_id in alias_group},
    )
    report = quality.evaluate(corpus, {"CVE-2026-32974"})

    assert report["counts"]["fp"] == 1
    assert report["known_negative_published"] == ["CVE-2026-32974"]


def test_adjudication_loader_rejects_alias_shared_across_classes(tmp_path) -> None:
    path = tmp_path / "adjudications.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "adjudications": [
                    {
                        "cve_id": "CVE-1",
                        "aliases": ["GHSA-SHARED"],
                        "label": "AI_CAUSAL",
                    },
                    {
                        "cve_id": "CVE-2",
                        "aliases": ["GHSA-SHARED"],
                        "label": "NOT_AI_CAUSAL",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate adjudication subject"):
        quality.load_adjudications(path)


def test_main_hard_fails_when_a_known_negative_is_published(
    monkeypatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        quality,
        "load_adjudications",
        lambda _path, **_kwargs: {"CVE-NEG": "NOT_AI_CAUSAL"},
    )
    monkeypatch.setattr(quality, "build_alias_map", lambda: {})
    monkeypatch.setattr(quality, "load_published_ids", lambda _path: {"CVE-NEG"})

    exit_code = quality.main([])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert report["known_negative_published"] == ["CVE-NEG"]
    assert report["curation_hard_fail"] is True


def test_main_hard_fails_when_an_inconclusive_is_published(
    monkeypatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        quality,
        "load_adjudications",
        lambda _path, **_kwargs: {"CVE-REVIEW": "INCONCLUSIVE"},
    )
    monkeypatch.setattr(quality, "build_alias_map", lambda: {})
    monkeypatch.setattr(
        quality,
        "load_published_ids",
        lambda _path: {"CVE-REVIEW"},
    )

    exit_code = quality.main([])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert report["known_inconclusive_published"] == ["CVE-REVIEW"]
    assert report["curation_hard_fail"] is True


def test_main_fails_when_precision_is_not_statistically_certified(
    monkeypatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    labels = _labels(positives=6)
    monkeypatch.setattr(quality, "build_alias_map", lambda: {})
    monkeypatch.setattr(
        quality,
        "load_adjudications",
        lambda _path, **_kwargs: labels,
    )
    monkeypatch.setattr(quality, "load_published_ids", lambda _path: set(labels))

    exit_code = quality.main(["--require-certified"])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert report["curation_hard_fail"] is False
    assert report["curation_certified"] is False


def test_default_cli_accepts_both_point_targets_before_certification(
    monkeypatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    labels = _labels(positives=6)
    monkeypatch.setattr(quality, "build_alias_map", lambda: {})
    monkeypatch.setattr(
        quality,
        "load_adjudications",
        lambda _path, **_kwargs: labels,
    )
    monkeypatch.setattr(quality, "load_published_ids", lambda _path: set(labels))

    exit_code = quality.main([])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert report["curation_consistent"] is True
    assert report["curation_precision_certified"] is False
    assert report["curation_recall_certified"] is False


def test_cli_help_renders_percentage_text(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        quality.main(["--help"])

    assert exc_info.value.code == 0
    assert "one-sided 95% curation-consistency lower" in capsys.readouterr().out
