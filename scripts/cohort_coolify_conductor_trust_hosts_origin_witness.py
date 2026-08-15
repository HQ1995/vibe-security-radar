#!/usr/bin/env python3
"""Freeze the recovered Conductor TrustHosts cold-cache bypass origin."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


REPOSITORY_IDENTITY = "github.com/coollabsio/coolify"
CANDIDATE_SHA = "e1fe58639756cf7b232458eddd6978e4ed0031f5"
CANDIDATE_PARENT_SHA = "84559a0e7d71c05be9a123a96cf589d0719500c7"
FIX_SHA = "e1d4b4682efc898ba5aa3751b2da2072f89c7e24"
FIX_PARENT_SHA = "5ed77f337ab9d69da8a82bffabaa2300e2a93dc6"
SOURCE_PATH = "app/Http/Middleware/TrustHosts.php"
CONDUCTOR_MARKER = "Changes auto-committed by Conductor"
CACHE_GET = "$fqdnHost = Cache::get('instance_settings_fqdn_host');"
CACHE_REMEMBER = "Cache::remember('instance_settings_fqdn_host', 300"
EARLY_RETURN = "if ($fqdnHost === '' || $fqdnHost === null) {"
POPULATE_CALL = "$this->hosts();"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan-dir", type=Path, required=True)
    parser.add_argument("--census-dir", type=Path, required=True)
    parser.add_argument("--topology-closure-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise SystemExit(f"{path}:{line_number} is not an object")
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot load {path}: {exc}") from exc
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text_blob(repository: Path, revision: str) -> str:
    return _git_blob(repository, revision, SOURCE_PATH).decode("utf-8")


def _line_number(source: str, marker: str) -> int:
    matches = [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one {marker!r} line, found {matches}")
    return matches[0]


def _evaluate_versions(
    baseline: str,
    candidate: str,
    fix_parent: str,
    fix: str,
) -> dict[str, bool]:
    baseline_handle = _php_method_region(baseline, "handle")
    candidate_handle = _php_method_region(candidate, "handle")
    fix_parent_handle = _php_method_region(fix_parent, "handle")
    fix_handle = _php_method_region(fix, "handle")
    return {
        "baseline_populates_cache_lazily_inside_hosts": (
            CACHE_REMEMBER in _php_method_region(baseline, "hosts")
            and CACHE_GET not in baseline_handle
            and "return parent::handle($request, $next);" in baseline_handle
        ),
        "candidate_reads_cold_cache_before_parent_validation": (
            CACHE_GET in candidate_handle
            and EARLY_RETURN in candidate_handle
            and POPULATE_CALL not in candidate_handle
            and candidate_handle.index(CACHE_GET)
            < candidate_handle.index("return parent::handle($request, $next);")
        ),
        "candidate_retains_lazy_cache_population_only_in_hosts": (
            CACHE_REMEMBER in _php_method_region(candidate, "hosts")
        ),
        "faulty_contract_survives_to_fix_parent": (
            CACHE_GET in fix_parent_handle
            and EARLY_RETURN in fix_parent_handle
            and POPULATE_CALL not in fix_parent_handle
            and CACHE_REMEMBER in _php_method_region(fix_parent, "hosts")
        ),
        "fix_populates_cache_before_testing_empty_sentinel": (
            POPULATE_CALL in fix_handle
            and CACHE_GET in fix_handle
            and fix_handle.index(POPULATE_CALL) < fix_handle.index(CACHE_GET)
        ),
        "fix_enforces_explicit_host_rejection": all(
            marker in fix
            for marker in (
                "protected function isHostTrusted",
                "X-Forwarded-Host",
                "return response('Bad Host', 400);",
            )
        ),
    }


def _commit_distance(repository: Path) -> int:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "rev-list",
            "--count",
            f"{CANDIDATE_SHA}..{FIX_SHA}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise SystemExit("cannot count candidate-to-fix commits")
    return int(completed.stdout.strip())


def _inventory_proof(ai_scan_dir: Path) -> dict[str, object]:
    summary_path = ai_scan_dir / "summary.json"
    commits_path = ai_scan_dir / "commits.jsonl"
    summary = _load_json(summary_path)
    rows = _load_jsonl(commits_path)
    matches = [row for row in rows if row.get("sha") == CANDIDATE_SHA]
    if len(matches) != 1:
        raise SystemExit("recovered candidate is absent or duplicated in AI scan")
    row = matches[0]
    checks = {
        "scan_is_complete_for_repository": (
            REPOSITORY_IDENTITY
            in summary.get("complete_repository_identities", [])
        ),
        "scan_count_matches_rows": summary.get("ai_commit_count") == len(rows),
        "candidate_has_exact_conductor_message": row.get("message") == CONDUCTOR_MARKER,
        "candidate_is_claude_explicit_attribution": (
            row.get("tools") == ["claude_code"]
            and row.get("source_modules") == ["explicit_attribution"]
            and row.get("signal_types") == ["explicit_attribution_line"]
        ),
        "candidate_has_clone_provenance": bool(row.get("observed_in_clone_paths")),
    }
    return {
        "checks": checks,
        "row": row,
        "summary_sha256": _sha256(summary_path),
        "commits_sha256": _sha256(commits_path),
    }


def _topology_proof(
    census_dir: Path,
    topology_closure_dir: Path,
) -> dict[str, object]:
    census_summary_path = census_dir / "summary.json"
    closure_summary_path = topology_closure_dir / "summary.json"
    index_path = topology_closure_dir / "ai_index.json"
    partition_path = topology_closure_dir / "pair_partition.jsonl"
    census_summary = _load_json(census_summary_path)
    closure_summary = _load_json(closure_summary_path)
    index = _load_json(index_path)
    ai_shas = index.get("ai_shas")
    if not isinstance(ai_shas, list) or CANDIDATE_SHA not in ai_shas:
        raise SystemExit("candidate is absent from topology AI index")
    candidate_bit = 1 << ai_shas.index(CANDIDATE_SHA)
    rows = _load_jsonl(partition_path)
    fix_rows = [row for row in rows if row.get("sha") == FIX_SHA]
    if len(fix_rows) != 1:
        raise SystemExit("fix is absent or duplicated in topology partition")
    fix_row = fix_rows[0]
    strict_bits = int(str(fix_row["strict_ai_ancestor_bitset_hex"]), 16)
    checks = {
        "census_and_closure_ai_counts_match": (
            census_summary.get("observed_ai_commit_count")
            == closure_summary.get("observed_ai_commit_count")
            == len(ai_shas)
        ),
        "closure_conserves_cartesian_partition": (
            closure_summary.get("pair_partition_conserved") is True
        ),
        "candidate_fix_pair_is_in_strict_ancestry_partition": bool(
            strict_bits & candidate_bit
        ),
    }
    return {
        "checks": checks,
        "fix_partition_row": fix_row,
        "census_summary_sha256": _sha256(census_summary_path),
        "closure_summary_sha256": _sha256(closure_summary_path),
        "ai_index_sha256": _sha256(index_path),
        "pair_partition_sha256": _sha256(partition_path),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline = _text_blob(repository, CANDIDATE_PARENT_SHA)
    candidate = _text_blob(repository, CANDIDATE_SHA)
    fix_parent = _text_blob(repository, FIX_PARENT_SHA)
    fix = _text_blob(repository, FIX_SHA)
    evaluation = _evaluate_versions(baseline, candidate, fix_parent, fix)
    candidate_metadata = _commit_metadata(repository, CANDIDATE_SHA)
    fix_metadata = _commit_metadata(repository, FIX_SHA)
    ancestry = {
        "candidate_parent_is_exact": candidate_metadata["parents"]
        == [CANDIDATE_PARENT_SHA],
        "fix_parent_is_exact": fix_metadata["parents"] == [FIX_PARENT_SHA],
        "candidate_strictly_precedes_fix": _is_ancestor(
            repository, CANDIDATE_SHA, FIX_SHA
        ),
        "fix_does_not_precede_candidate": not _is_ancestor(
            repository, FIX_SHA, CANDIDATE_SHA
        ),
    }
    line_origins = {
        "candidate_cold_cache_read": _blame_line(
            repository,
            CANDIDATE_SHA,
            SOURCE_PATH,
            _line_number(candidate, CACHE_GET),
            "candidate cold-cache read before parent validation",
        ),
        "surviving_cold_cache_read": _blame_line(
            repository,
            FIX_PARENT_SHA,
            SOURCE_PATH,
            _line_number(fix_parent, CACHE_GET),
            "candidate cold-cache bypass surviving to fix parent",
        ),
        "fix_eager_population": _blame_line(
            repository,
            FIX_SHA,
            SOURCE_PATH,
            _line_number(fix, POPULATE_CALL),
            "fix eager cache population before empty check",
        ),
    }
    inventory_proof = _inventory_proof(args.ai_scan_dir.resolve())
    topology_proof = _topology_proof(
        args.census_dir.resolve(),
        args.topology_closure_dir.resolve(),
    )
    commit_distance_including_fix = _commit_distance(repository)
    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and candidate_metadata["message"] == CONDUCTOR_MARKER
        and "Fix circular cache dependency in TrustHosts"
        in str(fix_metadata["message"])
        and all(evaluation.values())
        and all(ancestry.values())
        and line_origins["candidate_cold_cache_read"]["origin_sha"]
        == CANDIDATE_SHA
        and line_origins["surviving_cold_cache_read"]["origin_sha"]
        == CANDIDATE_SHA
        and line_origins["fix_eager_population"]["origin_sha"] == FIX_SHA
        and all(inventory_proof["checks"].values())
        and all(topology_proof["checks"].values())
        and commit_distance_including_fix == 1966
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_conductor_trust_hosts_origin_witness",
        "repository_identity": REPOSITORY_IDENTITY,
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "candidate_metadata": candidate_metadata,
        "fix_metadata": fix_metadata,
        "evaluation": evaluation,
        "ancestry": ancestry,
        "line_origins": line_origins,
        "inventory_proof": inventory_proof,
        "topology_proof": topology_proof,
        "candidate_to_fix_commit_count_including_fix": commit_distance_including_fix,
        "intervening_commit_count": commit_distance_including_fix - 1,
        "confirmed_edges": [
            {
                "candidate_sha": CANDIDATE_SHA,
                "fix_sha": FIX_SHA,
                "causal_role": "DIRECT_AI_ORIGIN",
            }
        ],
        "witness_passed": witness_passed,
        "causal_adjudication": "CONFIRMED_DIRECT_AI_ORIGIN",
        "mechanism_group": "trust_hosts_cold_cache_validation_bypass",
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The exact Conductor auto-commit adds a Cache::get/empty early-return "
            "before Laravel's parent TrustHosts handler can call hosts(), while "
            "hosts() remains the only code that populates that cache. The same "
            "candidate-authored read survives unchanged to the repair parent, and "
            "the repair explicitly calls hosts() before the read and names the "
            "circular dependency. This proves direct origin of the cold-cache host "
            "validation bypass. It does not attribute the older trusted-host regex "
            "semantics, X-Forwarded-Host handling, or reset-link request-context "
            "issue to this candidate."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify Conductor TrustHosts witness failed")
    print("Coolify Conductor TrustHosts origin witness frozen")
    print(f"  candidate: {CANDIDATE_SHA}")
    print(f"  repair   : {FIX_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
