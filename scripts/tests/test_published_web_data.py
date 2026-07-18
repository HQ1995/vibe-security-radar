"""Release gates for the tracked Web data artifacts."""

from __future__ import annotations

import json
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_WEB_DATA_DIR = _REPO_ROOT / "web" / "data"
_LEGACY_UNSCOPED_MODELS = {"claude-code", "investigator-override"}


def _load(name: str) -> dict:
    return json.loads((_WEB_DATA_DIR / name).read_text(encoding="utf-8"))


def _load_entries() -> list[dict]:
    """All published CVE entries in manifest order (per-CVE layout)."""
    index = _load("index.json")
    return [
        json.loads((_WEB_DATA_DIR / "cves" / f"{cve_id}.json").read_text(encoding="utf-8"))
        for cve_id in index["ids"]
    ]


def test_published_verifications_exclude_legacy_unscoped_models() -> None:
    """Synthetic CVE-level fallbacks must never reappear as per-BIC evidence."""
    violations: list[str] = []

    for entry in _load_entries():
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
                    f"{entry['id']}:{bug_commit.get('sha', '')}:"
                    f"{','.join(legacy_models) or 'legacy_unscoped'}"
                )

    assert violations == []


def test_published_totals_are_internally_consistent() -> None:
    index = _load("index.json")
    stats = _load("stats.json")
    on_disk = sorted(p.stem for p in (_WEB_DATA_DIR / "cves").glob("*.json"))

    assert index["total"] == len(index["ids"])
    assert stats["total_cves"] == index["total"]
    # No stale or missing per-CVE files: disk matches the manifest exactly.
    assert sorted(index["ids"]) == on_disk


def test_published_bug_commits_have_complete_unique_subject_identity() -> None:
    """Every public BIC is a unique concrete fix/BIC/file subject."""
    violations: list[str] = []

    for entry in _load_entries():
        subjects: set[tuple[str, str, str]] = set()
        for bug_commit in entry.get("bug_commits", []):
            subject = (
                bug_commit.get("fix_commit_sha", ""),
                bug_commit.get("sha", ""),
                bug_commit.get("blamed_file", ""),
            )
            if (
                not all(subject)
                or subject[2].startswith("(")
                or subject in subjects
            ):
                violations.append(f"{entry['id']}:{subject!r}")
            subjects.add(subject)

    assert violations == []
