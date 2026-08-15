#!/usr/bin/env python3
"""Evaluate publication-curation consistency against its adjudications.

The gate treats publication as a binary curation decision at CVE granularity:

* ``AI_CAUSAL`` and published -> true positive
* ``AI_CAUSAL`` and absent -> false negative
* ``NOT_AI_CAUSAL`` and published -> false positive and hard failure
* ``NOT_AI_CAUSAL`` and absent -> true negative
* ``INCONCLUSIVE`` and published -> release-safety hard failure

``INCONCLUSIVE`` adjudications remain outside curation precision and curation
recall regardless of publication state.  These adjudications also govern the
publication allowlist and exclusions, so this report measures implementation
consistency at that boundary.  Independent detector accuracy is measured by
``heldout_quality_gate.py``.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from web_data.loader import build_alias_map, expand_audit_adjudications
from web_data.writer import PublishedDataError, load_published_web_data

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_DEFAULT_ADJUDICATIONS = _SCRIPT_DIR / "publication_adjudications.json"
_DEFAULT_PUBLICATION = _REPO_ROOT / "web" / "data"

_ALLOWED_LABELS = frozenset({"AI_CAUSAL", "NOT_AI_CAUSAL", "INCONCLUSIVE"})
_CONFIDENCE_LEVEL = 0.95
_DEFAULT_TARGET = 0.95
_SCHEMA_VERSION = 2
_EVALUATION_KIND = "publication_curation_consistency"


@dataclass(frozen=True, slots=True)
class AdjudicationEntry:
    """One vulnerability equivalence class and its curation label."""

    canonical_id: str
    label: str
    aliases: frozenset[str] = frozenset()
    excluded_aliases: frozenset[str] = frozenset()

    @property
    def subject_ids(self) -> frozenset[str]:
        return frozenset((self.canonical_id, *self.aliases))


@dataclass(frozen=True, slots=True)
class AdjudicationCorpus:
    """Validated CVE/GHSA equivalence classes for quality measurement."""

    entries: tuple[AdjudicationEntry, ...]


def _binomial_upper_tail(successes: int, trials: int, probability: float) -> float:
    """Return P[X >= successes] for X ~ Binomial(trials, probability)."""
    if successes <= 0:
        return 1.0
    if probability <= 0.0:
        return 0.0
    if probability >= 1.0:
        return 1.0

    log_probability = math.log(probability)
    log_complement = math.log1p(-probability)
    log_terms = [
        (
            math.lgamma(trials + 1)
            - math.lgamma(outcome + 1)
            - math.lgamma(trials - outcome + 1)
            + outcome * log_probability
            + (trials - outcome) * log_complement
        )
        for outcome in range(successes, trials + 1)
    ]
    largest = max(log_terms)
    return math.exp(largest) * math.fsum(
        math.exp(log_term - largest) for log_term in log_terms
    )


def clopper_pearson_lower_bound(
    successes: int,
    trials: int,
    *,
    confidence_level: float = _CONFIDENCE_LEVEL,
) -> float:
    """Return the one-sided exact binomial lower confidence bound.

    This is the ``alpha`` quantile of ``Beta(successes,
    trials-successes+1)``. A deterministic bisection over the equivalent
    binomial upper-tail equation keeps the implementation in the standard
    library. Zero trials yield 0.0 so an empty sample cannot certify quality.
    """
    if isinstance(successes, bool) or not isinstance(successes, int):
        raise TypeError("successes must be an integer")
    if isinstance(trials, bool) or not isinstance(trials, int):
        raise TypeError("trials must be an integer")
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("require 0 <= successes <= trials")
    if not 0.0 < confidence_level < 1.0:
        raise ValueError("confidence_level must be between 0 and 1")
    if trials == 0 or successes == 0:
        return 0.0

    alpha = 1.0 - confidence_level
    if successes == trials:
        return alpha ** (1.0 / trials)

    lower = 0.0
    upper = successes / trials
    for _ in range(120):
        candidate = (lower + upper) / 2.0
        tail = _binomial_upper_tail(successes, trials, candidate)
        if tail < alpha:
            lower = candidate
        else:
            upper = candidate
    return (lower + upper) / 2.0


def load_adjudications(
    path: Path,
    *,
    alias_map: dict[str, set[str]] | None = None,
) -> AdjudicationCorpus:
    """Load and validate the versioned CVE-level adjudication corpus."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read adjudications at {path}: {exc}") from exc

    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("Adjudications require schema_version 1")
    entries = payload.get("adjudications")
    if not isinstance(entries, list):
        raise ValueError("Adjudications must contain an adjudications array")

    entries_by_id: dict[str, AdjudicationEntry] = {}
    subject_owner: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Every adjudication must be an object")
        cve_id = entry.get("cve_id")
        label = entry.get("label")
        if not isinstance(cve_id, str) or not cve_id.strip():
            raise ValueError("Every adjudication requires a non-empty cve_id")
        if cve_id in entries_by_id:
            raise ValueError(f"Duplicate adjudication for {cve_id}")
        if label not in _ALLOWED_LABELS:
            raise ValueError(f"Invalid adjudication label for {cve_id}: {label!r}")
        raw_aliases = entry.get("aliases", [])
        if not isinstance(raw_aliases, list) or not all(
            isinstance(alias, str) and alias.strip() for alias in raw_aliases
        ):
            raise ValueError(f"Invalid aliases for {cve_id}")
        aliases = frozenset(alias.strip() for alias in raw_aliases)
        if len(aliases) != len(raw_aliases):
            raise ValueError(f"Duplicate aliases for {cve_id}")
        if cve_id in aliases:
            raise ValueError(f"Canonical ID repeated as alias for {cve_id}")
        raw_excluded_aliases = entry.get("excluded_aliases", [])
        if not isinstance(raw_excluded_aliases, list) or not all(
            isinstance(alias, str) and alias.strip() for alias in raw_excluded_aliases
        ):
            raise ValueError(f"Invalid excluded aliases for {cve_id}")
        excluded_aliases = frozenset(alias.strip() for alias in raw_excluded_aliases)
        if len(excluded_aliases) != len(raw_excluded_aliases):
            raise ValueError(f"Duplicate excluded aliases for {cve_id}")
        if {subject.upper() for subject in (cve_id, *aliases)} & {
            alias.upper() for alias in excluded_aliases
        }:
            raise ValueError(f"Aliases and excluded aliases overlap for {cve_id}")

        adjudication = AdjudicationEntry(
            cve_id, label, aliases, excluded_aliases
        )
        for subject_id in adjudication.subject_ids:
            owner = subject_owner.get(subject_id)
            if owner is not None:
                raise ValueError(
                    f"Duplicate adjudication subject {subject_id}: {owner} and {cve_id}"
                )
            subject_owner[subject_id] = cve_id
        entries_by_id[cve_id] = adjudication
    validated = tuple(entries_by_id.values())
    if alias_map is None:
        return AdjudicationCorpus(validated)

    expanded = expand_audit_adjudications(
        [
            {
                "cve_id": entry.canonical_id,
                "label": entry.label,
                "aliases": sorted(entry.aliases),
                "excluded_aliases": sorted(entry.excluded_aliases),
            }
            for entry in validated
        ],
        alias_map,
    )
    return AdjudicationCorpus(
        tuple(
            AdjudicationEntry(
                entry["cve_id"],
                entry["label"],
                frozenset(entry.get("aliases", [])),
                frozenset(entry.get("excluded_aliases", [])),
            )
            for entry in expanded
        )
    )


def load_published_ids(path: Path) -> set[str]:
    """Load IDs from one fail-closed, generation-consistent publication."""
    published = load_published_web_data(path)
    return {entry["id"] for entry in published.entries}


def _rate_report(
    successes: int,
    trials: int,
    *,
    target: float,
) -> dict[str, float | int | bool | None]:
    point = successes / trials if trials else None
    lower_bound = clopper_pearson_lower_bound(successes, trials)
    meets_target = point is not None and point >= target and lower_bound >= target
    return {
        "successes": successes,
        "trials": trials,
        "point": point,
        "lower_bound": lower_bound,
        "meets_target": meets_target,
    }


def evaluate(
    adjudications: Mapping[str, str] | AdjudicationCorpus,
    published_ids: set[str],
    *,
    precision_target: float = _DEFAULT_TARGET,
    recall_target: float = _DEFAULT_TARGET,
) -> dict:
    """Build the adjudication/publication curation-consistency report."""
    for target_name, target in (
        ("precision_target", precision_target),
        ("recall_target", recall_target),
    ):
        if isinstance(target, bool) or not isinstance(target, (int, float)):
            raise TypeError(f"{target_name} must be numeric")
        if not 0.0 <= float(target) <= 1.0:
            raise ValueError(f"{target_name} must be between 0 and 1")

    if isinstance(adjudications, AdjudicationCorpus):
        entries = adjudications.entries
    else:
        entries = tuple(
            AdjudicationEntry(cve_id, label) for cve_id, label in adjudications.items()
        )

    invalid_labels = sorted({entry.label for entry in entries} - _ALLOWED_LABELS)
    if invalid_labels:
        raise ValueError(f"Invalid adjudication labels: {invalid_labels}")

    tp_ids: list[str] = []
    fp_ids: list[str] = []
    fn_ids: list[str] = []
    tn_ids: list[str] = []
    known_negative_published: set[str] = set()
    inconclusive_published_ids: set[str] = set()
    positive_count = 0
    negative_count = 0
    inconclusive_count = 0
    adjudicated_subject_ids: set[str] = set()

    for entry in entries:
        adjudicated_subject_ids.update(entry.subject_ids)
        matched_published = entry.subject_ids & published_ids
        is_published = bool(matched_published)
        if entry.label == "AI_CAUSAL":
            positive_count += 1
            (tp_ids if is_published else fn_ids).append(entry.canonical_id)
        elif entry.label == "NOT_AI_CAUSAL":
            negative_count += 1
            (fp_ids if is_published else tn_ids).append(entry.canonical_id)
            known_negative_published.update(matched_published)
        else:
            inconclusive_count += 1
            inconclusive_published_ids.update(matched_published)

    tp_ids.sort()
    fp_ids.sort()
    fn_ids.sort()
    tn_ids.sort()
    known_negative_published_ids = sorted(known_negative_published)
    known_inconclusive_published_ids = sorted(inconclusive_published_ids)

    precision = _rate_report(
        len(tp_ids),
        len(tp_ids) + len(fp_ids),
        target=float(precision_target),
    )
    recall = _rate_report(
        len(tp_ids),
        len(tp_ids) + len(fn_ids),
        target=float(recall_target),
    )
    unadjudicated_published_ids = sorted(published_ids - adjudicated_subject_ids)
    hard_fail = bool(
        fp_ids or inconclusive_published_ids or unadjudicated_published_ids
    )
    point_precision_meets_target = bool(
        precision["point"] is not None and precision["point"] >= float(precision_target)
    )
    point_recall_meets_target = bool(
        recall["point"] is not None and recall["point"] >= float(recall_target)
    )
    release_safe = bool(
        point_precision_meets_target and point_recall_meets_target and not hard_fail
    )
    conclusive_count = positive_count + negative_count
    total_adjudications = conclusive_count + inconclusive_count

    return {
        "schema_version": _SCHEMA_VERSION,
        "evaluation_kind": _EVALUATION_KIND,
        "measurement_boundary": {
            "claim": (
                "published IDs are consistent with the adjudication corpus "
                "that governs publication inclusion and exclusion"
            ),
            "scope_exclusions": [
                "independent detector precision",
                "independent detector recall",
            ],
            "independent_quality_gate": "scripts/heldout_quality_gate.py",
        },
        "confidence_level": _CONFIDENCE_LEVEL,
        "targets": {
            "curation_precision": float(precision_target),
            "curation_recall": float(recall_target),
        },
        "counts": {
            "tp": len(tp_ids),
            "fp": len(fp_ids),
            "fn": len(fn_ids),
            "tn": len(tn_ids),
            "adjudicated_positive": positive_count,
            "adjudicated_negative": negative_count,
            # Every inconclusive label is excluded from the metric sample,
            # including any that leaked into the publication.
            "inconclusive_excluded": inconclusive_count,
            "inconclusive_published": len(inconclusive_published_ids),
            "published_total": len(published_ids),
            "published_adjudicated": len(published_ids)
            - len(unadjudicated_published_ids),
            "published_unadjudicated": len(unadjudicated_published_ids),
        },
        "confusion_ids": {
            "tp": tp_ids,
            "fp": fp_ids,
            "fn": fn_ids,
            "tn": tn_ids,
        },
        "curation_precision": precision,
        "curation_recall": recall,
        "known_negative_published": known_negative_published_ids,
        "known_inconclusive_published": known_inconclusive_published_ids,
        "unadjudicated_published": unadjudicated_published_ids,
        "audit_coverage": (
            (len(published_ids) - len(unadjudicated_published_ids)) / len(published_ids)
            if published_ids
            else 1.0
        ),
        "conclusive_coverage": (
            conclusive_count / total_adjudications if total_adjudications else None
        ),
        "curation_recall_unresolved_sensitive": {
            "lower": (
                len(tp_ids) / (positive_count + inconclusive_count)
                if positive_count + inconclusive_count
                else None
            ),
            "upper": len(tp_ids) / positive_count if positive_count else None,
        },
        "curation_hard_fail": hard_fail,
        "curation_consistent": release_safe,
        "curation_precision_certified": bool(
            precision["meets_target"] and not hard_fail
        ),
        "curation_recall_certified": bool(recall["meets_target"] and not hard_fail),
        "curation_certified": bool(
            precision["meets_target"] and recall["meets_target"] and not hard_fail
        ),
    }


def _probability(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number between 0 and 1") from exc
    if not 0.0 <= parsed <= 1.0:
        raise argparse.ArgumentTypeError("must be a number between 0 and 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate publication curation against its adjudications."
    )
    parser.add_argument(
        "--adjudications",
        type=Path,
        default=_DEFAULT_ADJUDICATIONS,
        help=f"Adjudication JSON path (default: {_DEFAULT_ADJUDICATIONS})",
    )
    parser.add_argument(
        "--publication-dir",
        type=Path,
        default=_DEFAULT_PUBLICATION,
        help=f"Published web data directory (default: {_DEFAULT_PUBLICATION})",
    )
    parser.add_argument(
        "--curation-precision-target",
        type=_probability,
        dest="precision_target",
        default=_DEFAULT_TARGET,
        help=(
            "Required curation-precision point estimate and lower bound (default: 0.95)"
        ),
    )
    parser.add_argument(
        "--precision-target",
        type=_probability,
        dest="precision_target",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--curation-recall-target",
        type=_probability,
        dest="recall_target",
        default=_DEFAULT_TARGET,
        help=(
            "Required curation-recall point estimate and lower bound (default: 0.95)"
        ),
    )
    parser.add_argument(
        "--recall-target",
        type=_probability,
        dest="recall_target",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--require-certified",
        action="store_true",
        help="Require both one-sided 95%% curation-consistency lower bounds.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        alias_map = build_alias_map()
        adjudications = load_adjudications(
            args.adjudications,
            alias_map=alias_map,
        )
        published_ids = load_published_ids(args.publication_dir)
        report = evaluate(
            adjudications,
            published_ids,
            precision_target=args.precision_target,
            recall_target=args.recall_target,
        )
    except (OSError, UnicodeError, ValueError, PublishedDataError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "evaluation_kind": _EVALUATION_KIND,
                    "curation_hard_fail": True,
                    "curation_consistent": False,
                    "curation_precision_certified": False,
                    "curation_recall_certified": False,
                    "curation_certified": False,
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    report["inputs"] = {
        "adjudications": str(args.adjudications),
        "publication_dir": str(args.publication_dir),
    }
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    required_gate = (
        "curation_certified" if args.require_certified else "curation_consistent"
    )
    return 0 if report[required_gate] else 1


if __name__ == "__main__":
    raise SystemExit(main())
