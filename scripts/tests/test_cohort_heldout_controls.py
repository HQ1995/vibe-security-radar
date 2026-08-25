"""Repository-level contract for the frozen independent held-out split."""

from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HELDOUT_PATH = REPO_ROOT / "scripts" / "cohort_heldout_controls.json"
DEVELOPMENT_PATH = REPO_ROOT / "scripts" / "cohort_positive_controls.json"


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _contains_string(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return value.lower() == expected.lower()
    if isinstance(value, list):
        return any(_contains_string(item, expected) for item in value)
    if isinstance(value, dict):
        return any(_contains_string(item, expected) for item in value.values())
    return False


def test_heldout_split_is_frozen_and_disjoint_from_development() -> None:
    heldout = _load(HELDOUT_PATH)
    development = _load(DEVELOPMENT_PATH)
    controls = heldout["controls"]
    assert heldout["schema_version"] == 1
    assert heldout["split_id"] == "recall-first-heldout-v1"
    assert heldout["frozen_at"]
    assert isinstance(controls, list) and len(controls) == 5

    heldout_advisories = {row["advisory"] for row in controls}
    heldout_repositories = {row["repository_identity"] for row in controls}
    development_advisories = {
        row["advisory"] for row in development["controls"]
    }
    development_repositories = {
        row["repository_identity"] for row in development["controls"]
    }
    assert len(heldout_repositories) == len(controls)
    assert heldout_advisories.isdisjoint(development_advisories)
    assert heldout_repositories.isdisjoint(development_repositories)
    assert set(heldout["development_advisories"]) == development_advisories
    assert set(heldout["development_repositories"]) == development_repositories


def test_every_heldout_control_is_bound_to_manual_audit_evidence() -> None:
    controls = _load(HELDOUT_PATH)["controls"]
    assert isinstance(controls, list)
    for control in controls:
        source_path = REPO_ROOT / control["source"]
        audit = _load(source_path)
        assert audit["audit_verdict"] == "TRUE_POSITIVE"
        assert audit["ai_authored_vulnerability"] is True
        assert audit["cve_id"] == control["advisory"]
        assert _contains_string(audit, control["atomic_origin_sha"])
        assert _contains_string(audit, control["fix_sha"])
        if "expected_landed_sha" in control:
            assert _contains_string(audit, control["expected_landed_sha"])


def test_inferred_repository_identities_have_frozen_public_provenance() -> None:
    controls = _load(HELDOUT_PATH)["controls"]
    assert isinstance(controls, list)
    for control in controls:
        repository_source = control.get("source") or control.get("repository_source")
        if not repository_source:
            audit_text = (REPO_ROOT / control["source"]).read_text(encoding="utf-8")
            assert control["repository_identity"].removeprefix("github.com/") in audit_text
            continue
        source_text = (REPO_ROOT / repository_source).read_text(encoding="utf-8")
        suffix = control["repository_identity"].removeprefix("github.com/")
        provenance = (
            source_text.lower()
            + _ledger_repos(control["advisory"])
            + _historical_repo_text(control["advisory"]).lower()
        )
        assert suffix in provenance


def _ledger_repos(advisory: str) -> str:
    """Repository identities for an advisory from the canonical funnel ledger."""
    ledger = REPO_ROOT / "artifacts" / "funnel-account-20260817.jsonl"
    needle = str(advisory).lower()
    repos = []
    for line in ledger.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("repo") and needle in json.dumps(row).lower():
            repos.append(str(row["repo"]).lower())
    return "\n".join(repos)


def _historical_repo_text(advisory: str) -> str:
    """Pre-archive web/data/cves/{advisory}.json from git history."""
    import subprocess

    path = f"web/data/cves/{advisory}.json"
    found = subprocess.run(
        ["git", "log", "--all", "--format=%H", "--", path],
        capture_output=True,
        text=True,
    )
    if not found.stdout.strip():
        return ""
    for commit in found.stdout.splitlines():
        content = subprocess.run(
            ["git", "show", f"{commit}:{path}"],
            capture_output=True,
            text=True,
        )
        if content.returncode == 0:
            return content.stdout
    return ""
