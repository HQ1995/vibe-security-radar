"""Release gates for the tracked Web data artifacts."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

from web_data.loader import build_alias_map
from web_data.writer import PublishedWebData, load_published_web_data


_REPO_ROOT = Path(__file__).resolve().parents[2]
_WEB_DATA_DIR = _REPO_ROOT / "web" / "data"
_AUDIT_OVERRIDES_PATH = _REPO_ROOT / "scripts" / "audit_overrides.json"
_AUDIT_ADJUDICATIONS_PATH = _REPO_ROOT / "scripts" / "audit_adjudications.json"
_LEGACY_UNSCOPED_MODELS = {"claude-code", "investigator-override"}


@cache
def _published() -> PublishedWebData:
    return load_published_web_data(_WEB_DATA_DIR)


@cache
def _source_alias_map() -> dict[str, set[str]]:
    return build_alias_map()


def test_published_generation_is_complete_and_self_consistent() -> None:
    published = _published()

    assert published.index["total"] == len(published.entries)
    assert published.index["ids"] == [entry["id"] for entry in published.entries]
    assert published.stats["total_cves"] == len(published.entries)
    assert published.stats["generated_at"] == published.index["generated_at"]


def test_published_verifications_exclude_legacy_unscoped_models() -> None:
    """Synthetic CVE-level fallbacks must never reappear as per-BIC evidence."""
    violations: list[str] = []

    for entry in _published().entries:
        for bug_commit in entry.get("bug_commits", []):
            verification = bug_commit.get("verification") or {}
            models = verification.get("models") or []
            if isinstance(models, str):
                models = [models]
            observed = {str(model).lower() for model in models}
            observed.update(
                str(verdict.get("model", "")).lower()
                for verdict in verification.get("agent_verdicts", []) or []
                if isinstance(verdict, dict)
            )
            legacy_models = sorted(observed & _LEGACY_UNSCOPED_MODELS)
            if legacy_models or verification.get("legacy_unscoped"):
                violations.append(
                    f"{entry['id']}:{bug_commit.get('sha', '')}:{','.join(legacy_models) or 'legacy_unscoped'}"
                )

    assert violations == []


def test_published_unscoped_entries_exclude_cve_level_contributions() -> None:
    """A quarantined CVE-level verdict cannot retain its causal narrative."""
    violations = [
        entry["id"]
        for entry in _published().entries
        if entry.get("ai_involved") is None and entry.get("ai_contribution")
    ]

    assert violations == []


def test_published_totals_are_internally_consistent() -> None:
    published = _published()

    assert published.index["total"] == len(published.entries)
    assert published.stats["total_cves"] == published.index["total"]


def test_all_independent_audit_true_positives_are_published() -> None:
    """Every audited positive class retains one canonical publication row."""
    overrides = json.loads(_AUDIT_OVERRIDES_PATH.read_text(encoding="utf-8"))
    expected = {entry["cve_id"] for entry in overrides if isinstance(entry, dict) and entry.get("cve_id")}
    published = {entry["id"] for entry in _published().entries}
    alias_map = _source_alias_map()
    missing = sorted(
        subject_id
        for subject_id in expected
        if published.isdisjoint(alias_map.get(subject_id, {subject_id}))
    )

    assert missing == [], f"missing audit override classes: {missing}"


def test_published_data_honors_cve_level_adjudications() -> None:
    corpus = json.loads(_AUDIT_ADJUDICATIONS_PATH.read_text(encoding="utf-8"))
    labels = {item["cve_id"]: item["label"] for item in corpus["adjudications"]}
    published = {entry["id"] for entry in _published().entries}
    alias_map = _source_alias_map()
    expected = {cve_id for cve_id, label in labels.items() if label == "AI_CAUSAL"}
    forbidden = {cve_id for cve_id, label in labels.items() if label in {"NOT_AI_CAUSAL", "INCONCLUSIVE"}}
    missing = sorted(
        subject_id
        for subject_id in expected
        if published.isdisjoint(alias_map.get(subject_id, {subject_id}))
    )
    leaked = sorted(
        subject_id
        for subject_id in forbidden
        if not published.isdisjoint(alias_map.get(subject_id, {subject_id}))
    )

    assert missing == [], f"missing adjudicated positive classes: {missing}"
    assert leaked == [], f"published release-blocking adjudication classes: {leaked}"


def test_adjudication_evidence_sources_are_present_and_contained() -> None:
    corpus = json.loads(_AUDIT_ADJUDICATIONS_PATH.read_text(encoding="utf-8"))
    repo_root = _REPO_ROOT.resolve()
    for item in corpus["adjudications"]:
        source = item.get("source")
        assert isinstance(source, str) and source, item["cve_id"]
        path = (_REPO_ROOT / source).resolve()
        assert path.is_relative_to(repo_root), item["cve_id"]
        assert path.is_file() and not path.is_symlink(), item["cve_id"]


def test_every_audit_result_is_bound_to_a_quality_decision() -> None:
    """Keep independently produced audit evidence out of orphaned files."""
    corpus = json.loads(_AUDIT_ADJUDICATIONS_PATH.read_text(encoding="utf-8"))
    overrides = json.loads(_AUDIT_OVERRIDES_PATH.read_text(encoding="utf-8"))
    referenced = {
        (_REPO_ROOT / item["source"]).resolve()
        for item in corpus["adjudications"]
        if str(item.get("source", "")).startswith("scripts/audit_results/")
    }
    override_ids = {
        item["cve_id"]
        for item in overrides
        if isinstance(item, dict) and isinstance(item.get("cve_id"), str)
    }

    orphaned: list[str] = []
    for path in sorted((_REPO_ROOT / "scripts" / "audit_results").glob("*.json")):
        if path.resolve() in referenced:
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("cve_id") not in override_ids:
            orphaned.append(path.name)

    assert orphaned == []


def test_published_bug_commits_have_complete_unique_subject_identity() -> None:
    """Every public BIC is a unique concrete fix/BIC/file subject."""
    violations: list[str] = []

    for entry in _published().entries:
        subjects: set[tuple[str, str, str]] = set()
        for bug_commit in entry.get("bug_commits", []):
            subject = (
                bug_commit.get("fix_commit_sha", ""),
                bug_commit.get("sha", ""),
                bug_commit.get("blamed_file", ""),
            )
            if not all(subject) or subject[2].startswith("(") or subject in subjects:
                violations.append(f"{entry['id']}:{subject!r}")
            subjects.add(subject)

    assert violations == []


def test_published_data_excludes_independently_rejected_bic_subjects() -> None:
    """CVE-level positives must omit BIC subjects rejected by the audit."""
    corpus = json.loads(_AUDIT_ADJUDICATIONS_PATH.read_text(encoding="utf-8"))
    exclusions_by_id: dict[str, set[tuple[str, str, str]]] = {}
    for item in corpus["adjudications"]:
        excluded = {
            (
                subject["fix_commit_sha"],
                subject["commit_sha"],
                subject["blamed_file"],
            )
            for subject in item.get("excluded_bic_subjects", [])
        }
        for subject_id in [item["cve_id"], *item.get("aliases", [])]:
            exclusions_by_id[subject_id] = excluded

    violations: list[str] = []
    for entry in _published().entries:
        excluded = exclusions_by_id.get(entry["id"], set())
        for bug_commit in entry.get("bug_commits", []):
            projected_shas = {
                bug_commit.get("sha", ""),
                bug_commit.get("squash_merge_sha", ""),
            }
            for commit_sha in projected_shas - {""}:
                subject = (
                    bug_commit.get("fix_commit_sha", ""),
                    commit_sha,
                    bug_commit.get("blamed_file", ""),
                )
                if subject in excluded:
                    violations.append(f"{entry['id']}:{subject!r}")

    assert violations == []
