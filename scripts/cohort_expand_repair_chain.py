#!/usr/bin/env python3
"""Expand a sealed fix manifest with earlier semantic repair-chain commits."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

from cohort.fix_manifest import normalize_fix_manifest
from cohort.root_adjudication import canonical_sha256


_SEARCH_PATTERN = (
    r"authorize|ownedByCurrentTeam|whereTeamId|assertForbidden|"
    r"GHSA-|CVE-|IDOR|cross.team|isAdmin|makeHidden|"
    r"protected.{0,12}hidden|preg_match|assertNothingSent"
)
_SIGNAL_PATTERNS = {
    "resource_authorization": re.compile(
        r"(?:\$this->authorize|Gate::authorize|->can\(|cannot\(|authorize\()"
    ),
    "team_scope": re.compile(
        r"(?:ownedByCurrentTeam|whereTeamId|where\([^\n]{0,40}team_id)"
    ),
    "authentication_boundary": re.compile(
        r"(?:middleware\([^\n]{0,80}auth|auth\(\)->user|assertUnauthenticated)"
    ),
    "forbidden_regression": re.compile(
        r"(?:assertForbidden|assertStatus\(\s*403\s*\)|abort\([^\n]{0,20}403)"
    ),
    "advisory_regression": re.compile(r"(?:GHSA-[0-9a-z-]+|CVE-\d{4}-\d+|IDOR)"),
    "cross_tenant_regression": re.compile(
        r"(?:cross[-_ ]?team|cross[-_ ]?tenant|another team|other team)",
        re.IGNORECASE,
    ),
    "sensitive_default_hiding": re.compile(
        r"(?:protected\s+\$hidden|makeHidden\(|setHidden\()"
    ),
    "command_input_validation": re.compile(
        r"(?:preg_match\(|escapeshellarg\(|escapeShellArg\(|assertNothingSent)"
    ),
}

_EXPLICIT_REGRESSION_SIGNALS = frozenset(
    {
        "advisory_regression",
        "cross_tenant_regression",
        "forbidden_regression",
    }
)
_AUTHORIZATION_SCOPE_SIGNALS = frozenset(
    {"resource_authorization", "team_scope"}
)
_BOUNDARY_SECRET_SIGNALS = frozenset(
    {"authentication_boundary", "sensitive_default_hiding"}
)
_SECURITY_SUBJECT_PATTERN = re.compile(
    r"(?:security|\bauth\b|authorization|permission|access[ -]?control|"
    r"cross[-_ ]?(?:team|tenant)|idor|authenticated[-_ ]?rce|"
    r"command[-_ ]?injection)",
    re.IGNORECASE,
)
_REPAIR_ACTION_SUBJECT_PATTERN = re.compile(
    r"(?:^fix(?:\(|:)|^refactor(?:\(auth\)|: scope)|"
    r"\b(?:enforce|prevent|restrict|validate|scope)\b)",
    re.IGNORECASE,
)


class RepairChainError(ValueError):
    """Repair-chain expansion cannot preserve its sealed-input contract."""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix-manifest", type=Path, required=True)
    parser.add_argument(
        "--repository-path",
        action="append",
        default=[],
        metavar="IDENTITY=PATH",
        help="repeat for every repository identity in the manifest",
    )
    parser.add_argument("--split-id", required=True)
    parser.add_argument("--frozen-at", required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    parser.add_argument("--output-provenance", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(source_path: Path) -> dict[str, object]:
    try:
        value = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {source_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{source_path} must contain an object")
    return value


def _repository_paths(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        identity, separator, raw_path = value.partition("=")
        normalized_identity = identity.strip().lower()
        repository = Path(raw_path).resolve()
        if not separator or not normalized_identity or not raw_path:
            raise SystemExit(f"invalid repository mapping: {value}")
        if normalized_identity in result:
            raise SystemExit(f"duplicate repository mapping: {normalized_identity}")
        if not repository.is_dir() or not (repository / ".git").exists():
            raise SystemExit(f"repository checkout unavailable: {repository}")
        result[normalized_identity] = repository
    return result


def _git(repository: Path, arguments: list[str], *, timeout: int = 180) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepairChainError(f"git {' '.join(arguments)} failed: {exc}") from exc
    if completed.returncode != 0:
        raise RepairChainError(
            f"git {' '.join(arguments)} failed: {completed.stderr[:500]}"
        )
    return completed.stdout


def _changed_paths(repository: Path, revision: str) -> list[str]:
    value = _git(
        repository,
        [
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "-r",
            revision,
        ],
    )
    paths = sorted({line.strip() for line in value.splitlines() if line.strip()})
    if not paths:
        raise RepairChainError(f"fix commit has no changed paths: {revision}")
    return paths


def _added_lines(patch: str) -> str:
    return "\n".join(
        line[1:]
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def repair_signals(patch: str) -> list[str]:
    """Classify only added repair semantics; removals never create a fix root."""

    additions = _added_lines(patch)
    return sorted(
        signal
        for signal, pattern in _SIGNAL_PATTERNS.items()
        if pattern.search(additions)
    )


def repair_review_lane(
    signals: list[str], *, already_in_seed_manifest: bool
) -> tuple[int, str]:
    """Assign every retained repair root to one review lane without filtering."""

    signal_set = set(signals)
    if already_in_seed_manifest:
        return 0, "sealed_seed_fix"
    if signal_set & _EXPLICIT_REGRESSION_SIGNALS:
        return 1, "explicit_security_regression"
    if signal_set & _AUTHORIZATION_SCOPE_SIGNALS:
        return 2, "authorization_or_tenant_scope"
    if signal_set & _BOUNDARY_SECRET_SIGNALS:
        return 3, "authentication_or_sensitive_data_boundary"
    if "command_input_validation" in signal_set:
        return 4, "command_input_validation"
    return 5, "recall_fallback"


def repair_review_score(
    signals: list[str], *, subject: str, shared_paths: list[str]
) -> tuple[int, list[str]]:
    """Rank within a lane; this score never removes or changes a review lane."""

    signal_set = set(signals)
    score = len(signal_set)
    features: list[str] = []
    if signal_set & _EXPLICIT_REGRESSION_SIGNALS:
        score += 40
        features.append("explicit_security_regression_signal")
    if any(path.startswith("tests/") for path in shared_paths):
        score += 35
        features.append("regression_test_path")
    if _SECURITY_SUBJECT_PATTERN.search(subject):
        score += 30
        features.append("security_specific_subject")
    if _REPAIR_ACTION_SUBJECT_PATTERN.search(subject):
        score += 20
        features.append("repair_action_subject")
    if len(signal_set) >= 2:
        score += 5
        features.append("multiple_repair_signals")
    return score, features


def _candidate_repair_shas(
    repository: Path,
    seed_sha: str,
    changed_paths: list[str],
) -> list[str]:
    value = _git(
        repository,
        [
            "log",
            "--format=%H",
            "--no-merges",
            "-G",
            _SEARCH_PATTERN,
            f"{seed_sha}^",
            "--",
            *changed_paths,
        ],
        timeout=600,
    )
    return list(dict.fromkeys(line.strip() for line in value.splitlines() if line.strip()))


def _commit_metadata(repository: Path, revision: str) -> tuple[str, str]:
    value = _git(repository, ["show", "-s", "--format=%aI%x00%s", revision])
    authored_at, separator, subject = value.rstrip("\n").partition("\x00")
    if not separator:
        raise RepairChainError(f"commit metadata is malformed: {revision}")
    return authored_at, subject


def expand_repair_chain(
    manifest: Mapping[str, object],
    repositories: Mapping[str, Path],
    *,
    split_id: str,
    frozen_at: str,
) -> tuple[dict[str, object], dict[str, object]]:
    """Return an add-only sealed manifest and a separate evidence ledger."""

    normalized = normalize_fix_manifest(manifest, {})
    original_fixes = normalized["fixes"]
    assert isinstance(original_fixes, list)
    original_keys = {
        (str(row["advisory"]), str(row["repository_identity"]), str(row["fix_sha"]))
        for row in original_fixes
    }
    missing_repositories = sorted(
        {identity for _advisory, identity, _sha in original_keys} - set(repositories)
    )
    if missing_repositories:
        raise RepairChainError(
            f"repository mappings missing: {missing_repositories}"
        )

    expanded_keys = set(original_keys)
    evidence_by_key: defaultdict[
        tuple[str, str, str], dict[str, object]
    ] = defaultdict(dict)
    for advisory, identity, seed_sha in sorted(original_keys):
        repository = repositories[identity]
        seed_paths = _changed_paths(repository, seed_sha)
        for candidate_sha in _candidate_repair_shas(
            repository, seed_sha, seed_paths
        ):
            candidate_paths = _changed_paths(repository, candidate_sha)
            shared_paths = sorted(set(seed_paths) & set(candidate_paths))
            if not shared_paths:
                continue
            patch = _git(
                repository,
                [
                    "show",
                    "--format=",
                    "--first-parent",
                    "--unified=0",
                    candidate_sha,
                    "--",
                    *shared_paths,
                ],
            )
            signals = repair_signals(patch)
            if not signals:
                continue
            key = (advisory, identity, candidate_sha)
            expanded_keys.add(key)
            authored_at, subject = _commit_metadata(repository, candidate_sha)
            row = evidence_by_key[key]
            row.update(
                {
                    "advisory": advisory,
                    "repository_identity": identity,
                    "repair_sha": candidate_sha,
                    "authored_at": authored_at,
                    "subject": subject,
                    "signals": sorted(set(row.get("signals", [])) | set(signals)),
                    "shared_paths": sorted(
                        set(row.get("shared_paths", [])) | set(shared_paths)
                    ),
                    "source_seed_shas": sorted(
                        set(row.get("source_seed_shas", [])) | {seed_sha}
                    ),
                }
            )

    fixes = [
        {
            "advisory": advisory,
            "repository_identity": identity,
            "fix_sha": fix_sha,
        }
        for advisory, identity, fix_sha in sorted(expanded_keys)
    ]
    expanded_manifest = normalize_fix_manifest(
        {
            "schema_version": 1,
            "artifact_kind": "sealed_fix_manifest",
            "split_id": split_id,
            "frozen_at": frozen_at,
            "fixes": fixes,
        },
        {},
    )
    if not original_keys <= expanded_keys:
        raise RepairChainError("repair-chain expansion removed a seed fix")
    added_keys = expanded_keys - original_keys
    evidence = [
        {
            **evidence_by_key[key],
            "already_in_seed_manifest": key in original_keys,
        }
        for key in sorted(evidence_by_key)
    ]
    evidence_by_repair_key = {
        (
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["repair_sha"]),
        ): row
        for row in evidence
    }
    repair_schedule = []
    for key in sorted(expanded_keys):
        advisory, identity, repair_sha = key
        repair_evidence = evidence_by_repair_key.get(key, {})
        signals = [str(signal) for signal in repair_evidence.get("signals", [])]
        subject = str(repair_evidence.get("subject") or "")
        shared_paths = [
            str(path) for path in repair_evidence.get("shared_paths", [])
        ]
        already_in_seed_manifest = key in original_keys
        review_tier, review_lane = repair_review_lane(
            signals,
            already_in_seed_manifest=already_in_seed_manifest,
        )
        review_score, review_features = repair_review_score(
            signals,
            subject=subject,
            shared_paths=shared_paths,
        )
        repair_schedule.append(
            {
                "advisory": advisory,
                "repository_identity": identity,
                "fix_sha": repair_sha,
                "already_in_seed_manifest": already_in_seed_manifest,
                "review_tier": review_tier,
                "review_lane": review_lane,
                "review_score": review_score,
                "review_features": review_features,
                "signals": signals,
                "authored_at": str(repair_evidence.get("authored_at") or ""),
                "subject": subject,
            }
        )
    repair_schedule.sort(
        key=lambda row: (
            int(row["review_tier"]),
            -int(row["review_score"]),
            str(row["advisory"]),
            str(row["repository_identity"]),
            str(row["fix_sha"]),
        )
    )
    for priority_rank, row in enumerate(repair_schedule, start=1):
        row["priority_rank"] = priority_rank
    scheduled_keys = {
        (str(row["advisory"]), str(row["repository_identity"]), str(row["fix_sha"]))
        for row in repair_schedule
    }
    if scheduled_keys != expanded_keys or len(repair_schedule) != len(expanded_keys):
        raise RepairChainError("repair review schedule did not conserve every fix root")
    lane_counts = {
        lane: sum(1 for row in repair_schedule if row["review_lane"] == lane)
        for lane in sorted({str(row["review_lane"]) for row in repair_schedule})
    }
    provenance = {
        "schema_version": 1,
        "artifact_kind": "semantic_repair_chain_expansion",
        "split_id": split_id,
        "parent_manifest_sha256": canonical_sha256(normalized),
        "expanded_manifest_sha256": canonical_sha256(expanded_manifest),
        "seed_fix_count": len(original_keys),
        "expanded_fix_count": len(expanded_keys),
        "added_fix_count": len(added_keys),
        "all_seed_fixes_retained": original_keys <= expanded_keys,
        "unbounded_history_walk": True,
        "time_window_days": None,
        "hard_candidate_cap": None,
        "repair_evidence": evidence,
        "repair_evidence_sha256": canonical_sha256(evidence),
        "repair_schedule": repair_schedule,
        "repair_schedule_sha256": canonical_sha256(repair_schedule),
        "repair_schedule_conserves_all_fixes": True,
        "repair_schedule_lane_counts": lane_counts,
        "claim_boundary": (
            "This add-only source expansion finds commits whose added lines carry "
            "repair semantics in files touched by a later sealed fix. It is a "
            "high-recall fix-root inventory, not proof that every added commit is "
            "a security repair and not a causality verdict. Review lanes only "
            "control processing order; every retained repair root remains scheduled."
        ),
    }
    return expanded_manifest, provenance


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit(f"output already exists: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    manifest = _load_json(args.fix_manifest)
    repositories = _repository_paths(args.repository_path)
    try:
        expanded, provenance = expand_repair_chain(
            manifest,
            repositories,
            split_id=args.split_id,
            frozen_at=args.frozen_at,
        )
    except RepairChainError as exc:
        raise SystemExit(f"repair-chain expansion failed: {exc}") from exc
    _atomic_json(args.output_manifest, expanded)
    _atomic_json(args.output_provenance, provenance)
    print("semantic repair-chain manifest frozen")
    print(f"  seed fixes    : {provenance['seed_fix_count']}")
    print(f"  expanded fixes: {provenance['expanded_fix_count']}")
    print(f"  added fixes   : {provenance['added_fix_count']}")
    print(f"  manifest      : {args.output_manifest}")
    print(f"  provenance    : {args.output_provenance}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
