#!/usr/bin/env python3
"""Freeze the Coolify concurrent-index migration type-contract witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


BASELINE_SHA = "9481247ef423920ae222e5e3da6df31b00e92d82"
CANDIDATE_SHA = "9c2ef0aa21e2c5a9809d9748253e6b134dfe2019"
FIX_PARENT_SHA = "3501d200d3e35e8632e98039e4937f2fc80243e3"
FIX_SHA = "e256e765e74a0d506c96e768b9246efb1ec7d80c"
CANONICAL_FOLLOWUP_SHA = "36573ecbf0e822984eb01f5541eac77c84d5440e"

MIGRATION_PATH = (
    "database/migrations/2025_06_26_131350_optimize_activity_log_indexes.php"
)
COMPOSER_LOCK_PATH = "composer.lock"
MECHANISM_GROUP = "laravel_migration_within_transaction_property_type_invariance"

FRAMEWORK_VERSION = "v12.21.0"
FRAMEWORK_REF = "ac8c4e73bf1b5387b709f7736d41427e6af1c93b"
FRAMEWORK_SOURCE_SPECS = {
    "migration": {
        "url": (
            "https://raw.githubusercontent.com/laravel/framework/"
            f"{FRAMEWORK_REF}/src/Illuminate/Database/Migrations/Migration.php"
        ),
        "sha256": "4d9b168c3d4e161e8200746799f606b0b7cfd388047a2ba0c770880e10ff7a5b",
    },
    "migrator": {
        "url": (
            "https://raw.githubusercontent.com/laravel/framework/"
            f"{FRAMEWORK_REF}/src/Illuminate/Database/Migrations/Migrator.php"
        ),
        "sha256": "f9a441f75aa49dab1ccc798d7e61afc0b37a91f6f32eedcc776a93ce3d40e693",
    },
    "transactions": {
        "url": (
            "https://raw.githubusercontent.com/laravel/framework/"
            f"{FRAMEWORK_REF}/src/Illuminate/Database/Concerns/"
            "ManagesTransactions.php"
        ),
        "sha256": "e21c89ff4e818bbb4100b5a1f58938c4cc969389c5c2969da13bf050da683407",
    },
}
POSTGRESQL_CREATE_INDEX_DOC = "https://www.postgresql.org/docs/15/sql-createindex.html"
PHP_IMAGE = (
    "php@sha256:26e3f1de7f6aa3e8ea15584d803c5e088c57df89ff02a3ecf2dc855a4282d8d7"
)

CANDIDATE_PROPERTY = "public bool $withinTransaction = false;"
CANONICAL_PROPERTY = "public $withinTransaction = false;"
CANDIDATE_OVERRIDE_BLOCK = """    /**
     * Disable transactions for this migration because CREATE INDEX CONCURRENTLY
     * cannot run inside a transaction block in PostgreSQL.
     */
    public bool $withinTransaction = false;

"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--php-image", default=PHP_IMAGE)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(
    repository: Path, revision: str, source_path: str
) -> dict[str, object]:
    value = _git_blob(repository, revision, source_path)
    object_id = _git(
        repository,
        ["rev-parse", f"{revision}:{source_path}"],
        text=True,
    )
    assert isinstance(object_id, str)
    return {
        "revision": revision,
        "path": source_path,
        "git_blob_oid": object_id.strip(),
        "byte_count": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def _diff_record(
    repository: Path,
    before: str,
    after: str,
    source_paths: Sequence[str],
) -> dict[str, object]:
    transitions: list[dict[str, str]] = []
    for source_path in source_paths:
        before_object = _git(
            repository,
            ["rev-parse", f"{before}:{source_path}"],
            text=True,
        )
        after_object = _git(
            repository,
            ["rev-parse", f"{after}:{source_path}"],
            text=True,
        )
        assert isinstance(before_object, str)
        assert isinstance(after_object, str)
        transitions.append(
            {
                "path": source_path,
                "before_blob_oid": before_object.strip(),
                "after_blob_oid": after_object.strip(),
            }
        )
    canonical = json.dumps(
        transitions,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "before_revision": before,
        "after_revision": after,
        "paths": list(source_paths),
        "blob_transitions": transitions,
        "fingerprint_byte_count": len(canonical),
        "fingerprint_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _changed_paths(repository: Path, revision: str) -> list[str]:
    value = _git(
        repository,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", revision],
        text=True,
    )
    assert isinstance(value, str)
    return [line for line in value.splitlines() if line]


def _line_number(source: str, marker: str) -> int:
    matches = [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if marker in line
    ]
    if len(matches) != 1:
        raise SystemExit(f"expected one marker {marker!r}, found {matches}")
    return matches[0]


def _line_in_method(source: str, method: str, marker: str) -> int:
    region = _php_method_region(source, method)
    offset = source.index(region)
    return source[:offset].count("\n") + _line_number(region, marker)


def _ordered(source: str, markers: Sequence[str]) -> bool:
    position = -1
    for marker in markers:
        next_position = source.find(marker, position + 1)
        if next_position < 0:
            return False
        position = next_position
    return True


def _locked_framework_package(composer_lock: str) -> dict[str, object]:
    try:
        value = json.loads(composer_lock)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid composer.lock: {exc}") from exc
    packages = value.get("packages")
    if not isinstance(packages, list):
        raise SystemExit("composer.lock packages is absent")
    matches = [
        package
        for package in packages
        if isinstance(package, dict) and package.get("name") == "laravel/framework"
    ]
    if len(matches) != 1:
        raise SystemExit(f"laravel/framework resolved to {len(matches)} packages")
    package = matches[0]
    source = package.get("source")
    return {
        "name": package.get("name"),
        "version": package.get("version"),
        "source_url": source.get("url") if isinstance(source, dict) else None,
        "source_reference": (
            source.get("reference") if isinstance(source, dict) else None
        ),
    }


def _fetch_framework_sources() -> tuple[dict[str, str], list[dict[str, object]]]:
    sources: dict[str, str] = {}
    records: list[dict[str, object]] = []
    for name, spec in FRAMEWORK_SOURCE_SPECS.items():
        url = spec["url"]
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "ai-slop-causal-witness/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                value = response.read()
        except (OSError, urllib.error.URLError) as exc:
            raise SystemExit(
                f"cannot fetch pinned framework source {url}: {exc}"
            ) from exc
        digest = hashlib.sha256(value).hexdigest()
        if digest != spec["sha256"]:
            raise SystemExit(f"framework source digest mismatch for {name}: {digest}")
        sources[name] = value.decode("utf-8")
        records.append(
            {
                "name": name,
                "url": url,
                "framework_ref": FRAMEWORK_REF,
                "byte_count": len(value),
                "sha256": digest,
            }
        )
    return sources, records


def _evaluate_framework_contract(
    package: Mapping[str, object], sources: Mapping[str, str]
) -> dict[str, bool]:
    migration = sources["migration"]
    migrator = sources["migrator"]
    transactions = sources["transactions"]
    return {
        "composer_locks_expected_laravel_version": (
            package.get("name") == "laravel/framework"
            and package.get("version") == FRAMEWORK_VERSION
            and package.get("source_reference") == FRAMEWORK_REF
        ),
        "migration_base_property_is_untyped": (
            "public $withinTransaction = true;" in migration
            and "public bool $withinTransaction" not in migration
        ),
        "migrator_wraps_supported_migration_when_property_true": _ordered(
            migrator,
            (
                "supportsSchemaTransactions()",
                "$migration->withinTransaction",
                "$connection->transaction($callback)",
            ),
        ),
        "connection_commit_exits_outer_transaction": all(
            marker in transactions
            for marker in (
                "if ($this->transactionLevel() == 1)",
                "$this->getPdo()->commit();",
                "max(0, $this->transactions - 1)",
            )
        ),
        "connection_begin_reenters_at_level_zero": all(
            marker in transactions
            for marker in (
                "if ($this->transactions == 0)",
                "$this->getPdo()->beginTransaction();",
                "$this->transactions++;",
            )
        ),
    }


def _run_php(image: str, source: str) -> dict[str, object]:
    try:
        completed = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                image,
                "php",
                "-d",
                "display_errors=1",
                "-r",
                source,
            ],
            capture_output=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"pinned PHP runtime failed: {exc}") from exc
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    return {"exit_code": completed.returncode, "output": output.strip()}


def _evaluate_php_runtime(runs: Mapping[str, Mapping[str, object]]) -> dict[str, bool]:
    candidate = runs["candidate_typed_override"]
    intermediate = runs["intermediate_no_override"]
    canonical = runs["canonical_untyped_override"]
    return {
        "candidate_typed_override_is_rejected": (
            candidate.get("exit_code") == 255
            and "Type of CandidateMigration::$withinTransaction must not be defined"
            in str(candidate.get("output"))
        ),
        "intermediate_repair_without_override_loads": (
            intermediate.get("exit_code") == 0
            and "intermediate_load_ok PHP=8.4" in str(intermediate.get("output"))
        ),
        "canonical_untyped_override_loads": (
            canonical.get("exit_code") == 0
            and "canonical_load_ok PHP=8.4" in str(canonical.get("output"))
        ),
    }


def _php_runtime_witness(image: str) -> dict[str, object]:
    base = "class FrameworkMigration { public $withinTransaction = true; } "
    runs = {
        "candidate_typed_override": _run_php(
            image,
            base + "class CandidateMigration extends FrameworkMigration "
            "{ public bool $withinTransaction = false; }",
        ),
        "intermediate_no_override": _run_php(
            image,
            base + "class IntermediateMigration extends FrameworkMigration {} "
            'echo "intermediate_load_ok PHP=".PHP_MAJOR_VERSION.".".'
            "PHP_MINOR_VERSION;",
        ),
        "canonical_untyped_override": _run_php(
            image,
            base + "class CanonicalMigration extends FrameworkMigration "
            "{ public $withinTransaction = false; } "
            'echo "canonical_load_ok PHP=".PHP_MAJOR_VERSION.".".'
            "PHP_MINOR_VERSION;",
        ),
    }
    checks = _evaluate_php_runtime(runs)
    return {
        "image": image,
        "runs": runs,
        "checks": checks,
        "passed": all(checks.values()),
    }


def _evaluate_versions(
    baseline: str,
    candidate: str,
    fix_parent: str,
    repair: str,
    canonical_followup: str,
) -> dict[str, bool]:
    baseline_up = _php_method_region(baseline, "up")
    baseline_down = _php_method_region(baseline, "down")
    candidate_up = _php_method_region(candidate, "up")
    candidate_down = _php_method_region(candidate, "down")
    repair_up = _php_method_region(repair, "up")
    repair_down = _php_method_region(repair, "down")
    canonical_up = _php_method_region(canonical_followup, "up")
    canonical_down = _php_method_region(canonical_followup, "down")
    return {
        "concurrent_ddl_predates_candidate": (
            baseline_up.count("CREATE INDEX CONCURRENTLY") == 2
            and baseline_down.count("DROP INDEX CONCURRENTLY") == 2
            and "withinTransaction" not in baseline
        ),
        "candidate_only_adds_typed_override_to_migration": (
            CANDIDATE_PROPERTY in candidate
            and candidate.replace(CANDIDATE_OVERRIDE_BLOCK, "", 1) == baseline
        ),
        "candidate_retains_preexisting_concurrent_ddl": (
            candidate_up.count("CREATE INDEX CONCURRENTLY")
            == baseline_up.count("CREATE INDEX CONCURRENTLY")
            and candidate_down.count("DROP INDEX CONCURRENTLY")
            == baseline_down.count("DROP INDEX CONCURRENTLY")
        ),
        "typed_override_survives_unchanged_to_fix_parent": (
            fix_parent == candidate and CANDIDATE_PROPERTY in fix_parent
        ),
        "intermediate_repair_removes_incompatible_property": (
            CANDIDATE_PROPERTY not in repair and CANONICAL_PROPERTY not in repair
        ),
        "intermediate_up_commits_runs_concurrent_ddl_and_reenters": _ordered(
            repair_up,
            (
                "DB::commit();",
                "CREATE INDEX CONCURRENTLY",
                "CREATE INDEX CONCURRENTLY",
                "DB::beginTransaction();",
            ),
        ),
        "intermediate_down_commits_runs_concurrent_ddl_and_reenters": _ordered(
            repair_down,
            (
                "DB::commit();",
                "DROP INDEX CONCURRENTLY",
                "DROP INDEX CONCURRENTLY",
                "DB::beginTransaction();",
            ),
        ),
        "canonical_followup_uses_untyped_framework_override": (
            CANONICAL_PROPERTY in canonical_followup
            and CANDIDATE_PROPERTY not in canonical_followup
            and "DB::commit();" not in canonical_up
            and "DB::beginTransaction();" not in canonical_up
            and "DB::commit();" not in canonical_down
            and "DB::beginTransaction();" not in canonical_down
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    baseline = _text_blob(repository, BASELINE_SHA, MIGRATION_PATH)
    candidate = _text_blob(repository, CANDIDATE_SHA, MIGRATION_PATH)
    fix_parent = _text_blob(repository, FIX_PARENT_SHA, MIGRATION_PATH)
    repair = _text_blob(repository, FIX_SHA, MIGRATION_PATH)
    canonical_followup = _text_blob(repository, CANONICAL_FOLLOWUP_SHA, MIGRATION_PATH)
    composer_lock = _text_blob(repository, CANDIDATE_SHA, COMPOSER_LOCK_PATH)

    candidate_metadata = _commit_metadata(repository, CANDIDATE_SHA)
    fix_parent_metadata = _commit_metadata(repository, FIX_PARENT_SHA)
    repair_metadata = _commit_metadata(repository, FIX_SHA)
    canonical_metadata = _commit_metadata(repository, CANONICAL_FOLLOWUP_SHA)
    package = _locked_framework_package(composer_lock)
    framework_sources, framework_source_records = _fetch_framework_sources()
    framework_checks = _evaluate_framework_contract(package, framework_sources)
    evaluation = _evaluate_versions(
        baseline, candidate, fix_parent, repair, canonical_followup
    )
    php_runtime = _php_runtime_witness(args.php_image)

    candidate_changed_paths = _changed_paths(repository, CANDIDATE_SHA)
    repair_changed_paths = _changed_paths(repository, FIX_SHA)
    canonical_changed_paths = _changed_paths(repository, CANONICAL_FOLLOWUP_SHA)
    repair_message = " ".join(str(repair_metadata["message"]).split())
    canonical_message = " ".join(str(canonical_metadata["message"]).split())
    ancestry = {
        "baseline_is_candidate_only_parent": candidate_metadata["parents"]
        == [BASELINE_SHA],
        "candidate_is_fix_parent_first_parent": (
            bool(fix_parent_metadata["parents"])
            and fix_parent_metadata["parents"][0] == CANDIDATE_SHA
        ),
        "fix_parent_is_repair_only_parent": repair_metadata["parents"]
        == [FIX_PARENT_SHA],
        "repair_is_canonical_followup_only_parent": canonical_metadata["parents"]
        == [FIX_SHA],
        "candidate_to_repair": _is_ancestor(repository, CANDIDATE_SHA, FIX_SHA),
        "repair_to_canonical_followup": _is_ancestor(
            repository, FIX_SHA, CANONICAL_FOLLOWUP_SHA
        ),
    }
    line_origins = {
        "candidate_incompatible_typed_override": _blame_line(
            repository,
            CANDIDATE_SHA,
            MIGRATION_PATH,
            _line_number(candidate, CANDIDATE_PROPERTY),
            "candidate typed withinTransaction override",
        ),
        "fix_parent_incompatible_typed_override": _blame_line(
            repository,
            FIX_PARENT_SHA,
            MIGRATION_PATH,
            _line_number(fix_parent, CANDIDATE_PROPERTY),
            "typed override surviving through the merge fix parent",
        ),
        "intermediate_repair_up_commit": _blame_line(
            repository,
            FIX_SHA,
            MIGRATION_PATH,
            _line_in_method(repair, "up", "DB::commit();"),
            "intermediate repair exits migration transaction in up",
        ),
        "canonical_untyped_override": _blame_line(
            repository,
            CANONICAL_FOLLOWUP_SHA,
            MIGRATION_PATH,
            _line_number(canonical_followup, CANONICAL_PROPERTY),
            "canonical untyped withinTransaction override",
        ),
    }
    attribution = {
        "candidate_changed_paths": candidate_changed_paths,
        "repair_changed_paths": repair_changed_paths,
        "canonical_followup_changed_paths": canonical_changed_paths,
        "candidate_changes_only_target_migration": candidate_changed_paths
        == [MIGRATION_PATH],
        "repair_changes_only_target_migration": repair_changed_paths
        == [MIGRATION_PATH],
        "repair_adds_no_project_test": not any(
            path.startswith("tests/") for path in repair_changed_paths
        ),
        "canonical_followup_changes_only_target_migration": (
            canonical_changed_paths == [MIGRATION_PATH]
        ),
        "repair_message_names_property_type_error": (
            "redefining the $withinTransaction property (which causes a type error)"
            in repair_message
        ),
        "canonical_message_names_php_84_type_error_and_proper_laravel_way": (
            "PHP 8.4 error" in canonical_message
            and "proper Laravel way" in canonical_message
        ),
    }

    witness_passed = bool(
        candidate_metadata["explicit_claude_signal"] is True
        and all(ancestry.values())
        and all(framework_checks.values())
        and all(evaluation.values())
        and php_runtime["passed"] is True
        and all(
            value
            for key, value in attribution.items()
            if key
            not in {
                "candidate_changed_paths",
                "repair_changed_paths",
                "canonical_followup_changed_paths",
            }
        )
        and line_origins["candidate_incompatible_typed_override"]["origin_sha"]
        == CANDIDATE_SHA
        and line_origins["fix_parent_incompatible_typed_override"]["origin_sha"]
        == CANDIDATE_SHA
        and line_origins["intermediate_repair_up_commit"]["origin_sha"] == FIX_SHA
        and line_origins["canonical_untyped_override"]["origin_sha"]
        == CANONICAL_FOLLOWUP_SHA
    )

    payload = {
        "schema_version": 1,
        "artifact_kind": (
            "coolify_concurrent_index_migration_transaction_contract_witness"
        ),
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_sha": CANDIDATE_SHA,
        "fix_sha": FIX_SHA,
        "canonical_followup_sha": CANONICAL_FOLLOWUP_SHA,
        "candidate_metadata": candidate_metadata,
        "fix_parent_metadata": fix_parent_metadata,
        "fix_metadata": repair_metadata,
        "canonical_followup_metadata": canonical_metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "framework_package": package,
        "framework_contract_checks": framework_checks,
        "framework_source_artifacts": framework_source_records,
        "php_runtime_witness": php_runtime,
        "attribution": attribution,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, revision, MIGRATION_PATH)
            for revision in (
                BASELINE_SHA,
                CANDIDATE_SHA,
                FIX_PARENT_SHA,
                FIX_SHA,
                CANONICAL_FOLLOWUP_SHA,
            )
        ]
        + [_blob_record(repository, CANDIDATE_SHA, COMPOSER_LOCK_PATH)],
        "diffs": {
            "candidate": _diff_record(
                repository, BASELINE_SHA, CANDIDATE_SHA, (MIGRATION_PATH,)
            ),
            "intermediate_repair": _diff_record(
                repository, FIX_PARENT_SHA, FIX_SHA, (MIGRATION_PATH,)
            ),
            "canonical_followup": _diff_record(
                repository, FIX_SHA, CANONICAL_FOLLOWUP_SHA, (MIGRATION_PATH,)
            ),
        },
        "external_contract_references": {
            "postgresql_create_index": POSTGRESQL_CREATE_INDEX_DOC,
            "laravel_framework_ref": FRAMEWORK_REF,
            "php_runtime_image": args.php_image,
        },
        "witness_passed": witness_passed,
        "causal_adjudication": (
            "CONFIRMED_DIRECT_AI_MIGRATION_TRANSACTION_PROPERTY_TYPE_CONTRACT_BREAK"
        ),
        "mechanism_group": MECHANISM_GROUP,
        "counting": {
            "candidate_fix_true_positive_edge_count": 1,
            "unique_ai_candidate_count": 1,
            "mechanism_group_count": 1,
            "unique_advisory_increment_not_asserted": True,
        },
        "non_counted_related_commits": [
            {
                "sha": CANONICAL_FOLLOWUP_SHA,
                "role": "canonical_untyped_property_repair_after_intermediate_fix",
            }
        ],
        "claim_boundary": (
            "The concurrent CREATE and DROP INDEX statements predate the Claude "
            "candidate, so this witness does not attribute PostgreSQL's original "
            "transaction-block failure to that commit. It attributes the narrower "
            "new defect: the candidate adds a bool type to Laravel 12.21's inherited "
            "untyped withinTransaction property. A pinned PHP 8.4 runtime rejects that "
            "class definition before up or down can run, and blame shows the typed line "
            "survives unchanged through the merge fix parent. The requested fix removes "
            "the incompatible declaration and manually exits and re-enters the framework "
            "transaction around concurrent DDL, restoring class loading; it adds no "
            "project test and is treated only as an intermediate repair. The immediately "
            "following commit supplies the canonical Laravel-compatible untyped false "
            "override. No live PostgreSQL migration, exhaustive error-path safety, "
            "security impact, or unique advisory increment is asserted."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify concurrent-index transaction witness failed")

    print("Coolify concurrent-index transaction contract witness frozen")
    print(f"  candidate: {CANDIDATE_SHA}")
    print(f"  repair   : {FIX_SHA}")
    print(f"  canonical: {CANONICAL_FOLLOWUP_SHA}")
    print(f"  output   : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
