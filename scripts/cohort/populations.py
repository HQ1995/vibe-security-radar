"""Fail-closed population contracts for cohort discovery and estimation.

The same AI-attributed commit scan feeds two scientifically different
populations:

* discovery keeps every age (zero minimum follow-up), because young commits
  can already have a published security fix;
* outcome estimation requires a positive maturity window, because young
  commits have not had equal time to acquire an outcome.

Artifacts carry a content-bound contract so downstream discovery cannot
silently consume the mature estimation slice.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path


DISCOVERY_POPULATION = "all_age_discovery"
ESTIMATION_POPULATION = "mature_outcome_estimation"
POPULATION_ROLES = (DISCOVERY_POPULATION, ESTIMATION_POPULATION)
_REPO_ROOT = Path(__file__).resolve().parents[2]


class PopulationContractError(ValueError):
    """A population artifact is missing, drifted, or wired to the wrong role."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_object(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise PopulationContractError(f"population input is missing or unsafe: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PopulationContractError(f"cannot read population input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PopulationContractError(f"population input is not an object: {path}")
    return value


def _resolved_recorded_path(value: object) -> Path:
    path = Path(str(value or "").strip())
    if not str(path):
        raise PopulationContractError("population contract contains an empty path")
    return path.resolve() if path.is_absolute() else (_REPO_ROOT / path).resolve()


def validate_population_parameters(role: str, min_followup_days: int) -> None:
    """Reject a role/threshold combination with the wrong scientific meaning."""

    if role not in POPULATION_ROLES:
        raise PopulationContractError(f"unknown population role: {role}")
    if min_followup_days < 0:
        raise PopulationContractError("min_followup_days cannot be negative")
    if role == DISCOVERY_POPULATION and min_followup_days != 0:
        raise PopulationContractError(
            "all_age_discovery requires min_followup_days=0; maturity filtering can miss fixes"
        )
    if role == ESTIMATION_POPULATION and min_followup_days == 0:
        raise PopulationContractError(
            "mature_outcome_estimation requires positive follow-up; zero-day units bias rates"
        )


def build_exposure_population_contract(
    scan_dir: Path,
    *,
    role: str,
    min_followup_days: int,
) -> dict[str, object]:
    """Bind one exposure population to the exact shared scan artifacts."""

    validate_population_parameters(role, min_followup_days)
    summary_path = scan_dir / "summary.json"
    commits_path = scan_dir / "commits.jsonl"
    scan_summary = _load_object(summary_path)
    if scan_summary.get("artifact_kind") != "cohort_ai_commit_scan":
        raise PopulationContractError("scan summary has the wrong artifact_kind")
    if commits_path.is_symlink() or not commits_path.is_file():
        raise PopulationContractError(f"scan commits are missing or unsafe: {commits_path}")
    contract: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "cohort_population_contract",
        "population_role": role,
        "min_followup_days": min_followup_days,
        "scan_dir": str(scan_dir),
        "scan_summary_sha256": sha256_file(summary_path),
        "scan_commits_sha256": sha256_file(commits_path),
        "claim_boundary": (
            "all commit ages are retained for vulnerability discovery"
            if role == DISCOVERY_POPULATION
            else "only maturity-filtered units are used for fixed-window outcome estimation"
        ),
    }
    contract["contract_sha256"] = _canonical_sha256(contract)
    return contract


def validate_population_contract(
    raw: object,
    *,
    expected_role: str | None = None,
) -> dict[str, object]:
    """Validate the contract itself without trusting its descriptive label."""

    if not isinstance(raw, Mapping):
        raise PopulationContractError("population_contract must be an object")
    contract = {str(key): value for key, value in raw.items()}
    if contract.get("schema_version") != 1:
        raise PopulationContractError("population contract must use schema_version 1")
    if contract.get("artifact_kind") != "cohort_population_contract":
        raise PopulationContractError("population contract has the wrong artifact_kind")
    role = str(contract.get("population_role") or "")
    min_followup_days = contract.get("min_followup_days")
    if not isinstance(min_followup_days, int) or isinstance(min_followup_days, bool):
        raise PopulationContractError("population contract needs integer min_followup_days")
    validate_population_parameters(role, min_followup_days)
    if expected_role is not None and role != expected_role:
        raise PopulationContractError(
            f"population role mismatch: expected {expected_role}, observed {role}"
        )
    for field in ("scan_summary_sha256", "scan_commits_sha256", "contract_sha256"):
        value = str(contract.get(field) or "")
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise PopulationContractError(f"population contract has invalid {field}")
    observed_digest = str(contract["contract_sha256"])
    payload = {key: value for key, value in contract.items() if key != "contract_sha256"}
    if _canonical_sha256(payload) != observed_digest:
        raise PopulationContractError("population contract digest mismatch")
    _resolved_recorded_path(contract.get("scan_dir"))
    return contract


def load_exposure_population_contract(
    exposure_dir: Path,
    *,
    expected_role: str | None = None,
) -> dict[str, object]:
    """Validate an exposure summary and its content-bound upstream scan."""

    summary = _load_object(exposure_dir / "summary.json")
    if summary.get("artifact_kind") != "cohort_exposure_classification":
        raise PopulationContractError("exposure summary has the wrong artifact_kind")
    contract = validate_population_contract(
        summary.get("population_contract"), expected_role=expected_role
    )
    if summary.get("min_followup_days") != contract["min_followup_days"]:
        raise PopulationContractError("exposure threshold disagrees with population contract")
    if _resolved_recorded_path(summary.get("scan_dir")) != _resolved_recorded_path(
        contract.get("scan_dir")
    ):
        raise PopulationContractError("exposure scan path disagrees with population contract")
    scan_dir = _resolved_recorded_path(contract.get("scan_dir"))
    if sha256_file(scan_dir / "summary.json") != contract["scan_summary_sha256"]:
        raise PopulationContractError("upstream scan summary drifted after population freeze")
    if sha256_file(scan_dir / "commits.jsonl") != contract["scan_commits_sha256"]:
        raise PopulationContractError("upstream scan commits drifted after population freeze")
    return contract


def load_outcomes_population_contract(
    outcomes_dir: Path,
    *,
    expected_role: str | None = None,
) -> dict[str, object]:
    """Validate propagation from exposure into stated-outcome artifacts."""

    summary_path = outcomes_dir / "summary.json"
    summary = _load_object(summary_path)
    if summary.get("artifact_kind") != "cohort_stated_outcomes":
        raise PopulationContractError("outcomes summary has the wrong artifact_kind")
    contract = validate_population_contract(
        summary.get("population_contract"), expected_role=expected_role
    )
    exposure_dir = _resolved_recorded_path(summary.get("exposure_dir"))
    upstream_contract = load_exposure_population_contract(
        exposure_dir, expected_role=expected_role
    )
    if contract != upstream_contract:
        raise PopulationContractError("outcomes population contract differs from exposure")
    expected_summary_sha = str(summary.get("exposure_summary_sha256") or "")
    if sha256_file(exposure_dir / "summary.json") != expected_summary_sha:
        raise PopulationContractError("exposure summary drifted after outcomes were generated")
    return contract


def build_population_split_manifest(
    scan_dir: Path,
    discovery_exposure_dir: Path,
    estimation_exposure_dir: Path,
) -> dict[str, object]:
    """Conserve both branches and prove they came from the same scan."""

    discovery = load_exposure_population_contract(
        discovery_exposure_dir, expected_role=DISCOVERY_POPULATION
    )
    estimation = load_exposure_population_contract(
        estimation_exposure_dir, expected_role=ESTIMATION_POPULATION
    )
    expected_scan = scan_dir.resolve()
    if _resolved_recorded_path(discovery["scan_dir"]) != expected_scan:
        raise PopulationContractError("discovery branch did not use the requested scan")
    if _resolved_recorded_path(estimation["scan_dir"]) != expected_scan:
        raise PopulationContractError("estimation branch did not use the requested scan")
    if discovery["scan_summary_sha256"] != estimation["scan_summary_sha256"]:
        raise PopulationContractError("population branches have different scan summaries")
    if discovery["scan_commits_sha256"] != estimation["scan_commits_sha256"]:
        raise PopulationContractError("population branches have different scan commits")
    return {
        "schema_version": 1,
        "artifact_kind": "cohort_population_split",
        "scan_dir": str(scan_dir),
        "scan_summary_sha256": discovery["scan_summary_sha256"],
        "scan_commits_sha256": discovery["scan_commits_sha256"],
        "discovery_exposure_dir": str(discovery_exposure_dir),
        "discovery_summary_sha256": sha256_file(discovery_exposure_dir / "summary.json"),
        "discovery_contract_sha256": discovery["contract_sha256"],
        "estimation_exposure_dir": str(estimation_exposure_dir),
        "estimation_summary_sha256": sha256_file(estimation_exposure_dir / "summary.json"),
        "estimation_contract_sha256": estimation["contract_sha256"],
        "wiring_invariant": (
            "advisory discovery accepts only all_age_discovery; fixed-window rates use only"
            " mature_outcome_estimation; both branches are content-bound to the same scan"
        ),
    }
