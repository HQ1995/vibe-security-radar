#!/usr/bin/env python3
"""Freeze exact-preimage Coolify regressions recovered from the full ledger."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
)
from cohort_coolify_security_frontier_preservation_witness import _blame_line


COMPOSE_CANDIDATE_SHAS = (
    "1094ab7a46452ac0e42e60e5c1e705df6484f95f",
    "f8e3bb54a3cb48da842351cc75490c8a20134807",
)
COMPOSE_REPAIR_SHAS = (
    "2eeb2b94ec3385fcd066cf43e9c8c108be7cdeea",
    "f86ccfaa9af572a5487da8ea46b0a125a4854cf6",
)
GIT_SHA_CANDIDATE_SHA = "bf0040597194e3a9b835b7a800b735f65bc2c34c"
GIT_SHA_REPAIR_SHA = "893093fad3cb6a54fa28be7da6991654460153fa"

DEPLOYMENT_JOB_PATH = "app/Jobs/ApplicationDeploymentJob.php"
COMPOSE_HELPER_PATH = "bootstrap/helpers/docker.php"
COMPOSE_TEST_PATH = "tests/Unit/ApplicationDeploymentCustomBuildCommandTest.php"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(repository: Path, revision: str, source_path: str) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _nth_line(source: str, marker: str, occurrence: int = 1) -> int:
    matches = [
        index + 1
        for index, line in enumerate(source.splitlines())
        if marker in line
    ]
    if occurrence < 1 or len(matches) < occurrence:
        raise SystemExit(
            f"expected marker {marker!r} occurrence {occurrence}, found {matches}"
        )
    return matches[occurrence - 1]


def _stable_patch_id(repository: Path, revision: str) -> str:
    try:
        patch = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "show",
                "--pretty=format:",
                "--no-ext-diff",
                revision,
            ],
            capture_output=True,
            check=False,
            timeout=60,
        )
        if patch.returncode != 0:
            reason = patch.stderr.decode("utf-8", errors="replace")[:500]
            raise SystemExit(f"cannot render patch for {revision}: {reason}")
        patch_id = subprocess.run(
            ["git", "patch-id", "--stable"],
            input=patch.stdout,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"cannot compute stable patch id for {revision}: {exc}") from exc
    if patch_id.returncode != 0:
        reason = patch_id.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"cannot compute stable patch id for {revision}: {reason}")
    fields = patch_id.stdout.decode("ascii", errors="strict").split()
    if not fields:
        raise SystemExit(f"empty stable patch id for {revision}")
    return fields[0]


def _candidate_compose_rewrite(command: str) -> str:
    if "--env-file" in command:
        return command
    return command.replace(
        "docker compose",
        "docker compose --env-file /artifacts/build-time.env",
    )


def _repair_compose_rewrite(command: str) -> str:
    replacement = "docker compose"
    if re.search(r"(?:^|\s)(?:-f(?:[=\s]|\S)|--file(?:=|\s))", command) is None:
        replacement += " -f /artifacts/deployment/docker-compose.yaml"
    if re.search(r"(?:^|\s)--env-file(?:=|\s)", command) is None:
        replacement += " --env-file /artifacts/build-time.env"
    return re.sub(r"docker\s+compose", replacement, command, count=1)


def _evaluate_compose_rewrite(
    candidate_job: str,
    candidate_test: str,
    repair_job: str,
    repair_helper: str,
    repair_test: str,
) -> dict[str, bool]:
    chained = "docker compose pull && docker compose build"
    tabbed = "docker\tcompose build"
    candidate_chained = _candidate_compose_rewrite(chained)
    repair_chained = _repair_compose_rewrite(chained)
    candidate_tabbed = _candidate_compose_rewrite(tabbed)
    repair_tabbed = _repair_compose_rewrite(tabbed)
    return {
        "candidate_uses_global_literal_replacement": all(
            marker in candidate_job
            for marker in (
                "if (! str_contains($build_command, '--env-file'))",
                "$build_command = str_replace(",
                "'docker compose --env-file /artifacts/build-time.env'",
            )
        ),
        "candidate_test_accepts_all_occurrences": (
            "str_replace replaces ALL occurrences, which is acceptable" in candidate_test
        ),
        "candidate_rewrites_both_chained_commands": (
            candidate_chained.count("--env-file /artifacts/build-time.env") == 2
        ),
        "candidate_misses_non_space_whitespace": (
            candidate_tabbed == tabbed
        ),
        "repair_routes_build_through_helper": (
            "// Auto-inject -f (compose file) and --env-file flags using helper function"
            in repair_job
            and "$build_command = injectDockerComposeFlags(" in repair_job
        ),
        "repair_replaces_first_flexible_occurrence": (
            "return preg_replace('/docker\\s+compose/', $dockerComposeReplacement, $command, 1);"
            in repair_helper
        ),
        "repair_recognizes_flag_forms": all(
            marker in repair_helper
            for marker in (
                "(?:-f(?:[=\\s]|\\S)|--file(?:=|\\s))",
                "(?:^|\\s)--env-file(?:=|\\s)",
            )
        ),
        "repair_rewrites_only_first_chained_command": (
            repair_chained.count("--env-file /artifacts/build-time.env") == 1
            and repair_chained.endswith("&& docker compose build")
        ),
        "repair_handles_non_space_whitespace": (
            repair_tabbed != tabbed
            and repair_tabbed.count("--env-file /artifacts/build-time.env") == 1
        ),
        "repair_has_scope_and_bypass_regressions": all(
            marker in repair_test
            for marker in (
                "only replaces first docker compose occurrence in chained commands",
                "does not modify docker compose string in echo statements",
                "does not modify docker compose string in bash comments",
                "detects -f flag with equals sign format (bypass vector)",
                "detects --env-file flag with tab character whitespace (bypass vector)",
            )
        ),
    }


def _evaluate_git_sha_regex(candidate_job: str, repair_job: str) -> dict[str, bool]:
    candidate_pattern = re.compile(r"([0-9a-f]{40})\s*\t")
    repair_pattern = re.compile(r"\b([0-9a-fA-F]{40})(?=\s*\t)")
    lowercase_sha = "a" * 40 + "\trefs/heads/main"
    uppercase_sha = "A" * 40 + "\trefs/heads/main"
    longer_object_id = "b" * 64 + "\trefs/heads/main"
    candidate_long = candidate_pattern.search(longer_object_id)
    return {
        "candidate_installs_lowercase_unbounded_regex": (
            "preg_match('/([0-9a-f]{40})\\s*\\t/', $output, $matches);"
            in candidate_job
        ),
        "repair_installs_bounded_case_insensitive_hex_regex": (
            "preg_match('/\\b([0-9a-fA-F]{40})(?=\\s*\\t)/', $output, $matches);"
            in repair_job
        ),
        "both_accept_normal_lowercase_sha1": (
            candidate_pattern.search(lowercase_sha) is not None
            and repair_pattern.search(lowercase_sha) is not None
        ),
        "candidate_false_matches_suffix_of_longer_object_id": (
            candidate_long is not None and candidate_long.start(1) == 24
        ),
        "repair_rejects_suffix_of_longer_object_id": (
            repair_pattern.search(longer_object_id) is None
        ),
        "candidate_rejects_uppercase_hex": (
            candidate_pattern.search(uppercase_sha) is None
        ),
        "repair_accepts_uppercase_hex": (
            repair_pattern.search(uppercase_sha) is not None
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    candidate_jobs = {
        sha: _text_blob(repository, sha, DEPLOYMENT_JOB_PATH)
        for sha in COMPOSE_CANDIDATE_SHAS
    }
    candidate_tests = {
        sha: _text_blob(repository, sha, COMPOSE_TEST_PATH)
        for sha in COMPOSE_CANDIDATE_SHAS
    }
    repair_jobs = {
        sha: _text_blob(repository, sha, DEPLOYMENT_JOB_PATH)
        for sha in COMPOSE_REPAIR_SHAS
    }
    repair_helpers = {
        sha: _text_blob(repository, sha, COMPOSE_HELPER_PATH)
        for sha in COMPOSE_REPAIR_SHAS
    }
    repair_tests = {
        sha: _text_blob(repository, sha, COMPOSE_TEST_PATH)
        for sha in COMPOSE_REPAIR_SHAS
    }
    sha_candidate_job = _text_blob(
        repository, GIT_SHA_CANDIDATE_SHA, DEPLOYMENT_JOB_PATH
    )
    sha_repair_job = _text_blob(repository, GIT_SHA_REPAIR_SHA, DEPLOYMENT_JOB_PATH)

    compose_evaluations = {
        f"{candidate}->{repair}": _evaluate_compose_rewrite(
            candidate_jobs[candidate],
            candidate_tests[candidate],
            repair_jobs[repair],
            repair_helpers[repair],
            repair_tests[repair],
        )
        for candidate, repair in zip(
            COMPOSE_CANDIDATE_SHAS, COMPOSE_REPAIR_SHAS, strict=True
        )
    }
    sha_evaluation = _evaluate_git_sha_regex(sha_candidate_job, sha_repair_job)

    edges = [
        *[
            {
                "candidate_sha": candidate,
                "fix_sha": repair,
                "causal_adjudication": (
                    "CONFIRMED_AI_GLOBAL_DOCKER_COMPOSE_REWRITE_REGRESSION"
                ),
                "mechanism_group": "docker_compose_custom_command_rewrite_scope",
                "patch_equivalent_candidate_group": "compose_env_injection_patch_11fb0175",
            }
            for candidate, repair in zip(
                COMPOSE_CANDIDATE_SHAS, COMPOSE_REPAIR_SHAS, strict=True
            )
        ],
        {
            "candidate_sha": GIT_SHA_CANDIDATE_SHA,
            "fix_sha": GIT_SHA_REPAIR_SHA,
            "causal_adjudication": "CONFIRMED_AI_UNBOUNDED_GIT_SHA_REGEX_REGRESSION",
            "mechanism_group": "git_ls_remote_sha_extraction",
            "patch_equivalent_candidate_group": "git_sha_parser_patch_bf004059",
        },
    ]
    candidate_shas = (*COMPOSE_CANDIDATE_SHAS, GIT_SHA_CANDIDATE_SHA)
    metadata = {
        sha: _commit_metadata(repository, sha) for sha in candidate_shas
    }
    git_sha_repair_metadata = _commit_metadata(repository, GIT_SHA_REPAIR_SHA)
    ancestry = {
        f"{edge['candidate_sha']}->{edge['fix_sha']}": _is_ancestor(
            repository, str(edge["candidate_sha"]), str(edge["fix_sha"])
        )
        for edge in edges
    }
    patch_ids = {
        sha: _stable_patch_id(repository, sha)
        for sha in (*COMPOSE_CANDIDATE_SHAS, *COMPOSE_REPAIR_SHAS)
    }

    line_origins: dict[str, dict[str, object]] = {}
    expected_origins: dict[str, str] = {}
    for index, (candidate, repair) in enumerate(
        zip(COMPOSE_CANDIDATE_SHAS, COMPOSE_REPAIR_SHAS, strict=True), start=1
    ):
        records = {
            f"compose_candidate_global_replace_{index}": (
                candidate,
                DEPLOYMENT_JOB_PATH,
                candidate_jobs[candidate],
                "$build_command = str_replace(",
                "candidate global docker compose replacement",
            ),
            f"compose_repair_first_replace_{index}": (
                repair,
                COMPOSE_HELPER_PATH,
                repair_helpers[repair],
                "return preg_replace('/docker\\s+compose/'",
                "repair first-occurrence docker compose replacement",
            ),
        }
        for key, (revision, source_path, source, marker, label) in records.items():
            line_origins[key] = _blame_line(
                repository,
                revision,
                source_path,
                _nth_line(source, marker),
                label,
            )
            expected_origins[key] = revision

    sha_records = {
        "git_sha_candidate_regex": (
            GIT_SHA_CANDIDATE_SHA,
            sha_candidate_job,
            "preg_match('/([0-9a-f]{40})",
            "candidate lowercase unbounded SHA regex",
        ),
        "git_sha_repair_regex": (
            GIT_SHA_REPAIR_SHA,
            sha_repair_job,
            "preg_match('/\\b([0-9a-fA-F]{40})",
            "repair bounded hexadecimal SHA regex",
        ),
    }
    for key, (revision, source, marker, label) in sha_records.items():
        line_origins[key] = _blame_line(
            repository,
            revision,
            DEPLOYMENT_JOB_PATH,
            _nth_line(source, marker),
            label,
        )
        expected_origins[key] = revision

    candidate_patch_ids = {patch_ids[sha] for sha in COMPOSE_CANDIDATE_SHAS}
    repair_patch_ids = {patch_ids[sha] for sha in COMPOSE_REPAIR_SHAS}
    witness_passed = bool(
        all(item["explicit_claude_signal"] is True for item in metadata.values())
        and all(ancestry.values())
        and all(
            all(checks.values()) for checks in compose_evaluations.values()
        )
        and all(sha_evaluation.values())
        and len(candidate_patch_ids) == 1
        and len(repair_patch_ids) == 1
        and all(
            line_origins[key]["origin_sha"] == expected
            for key, expected in expected_origins.items()
        )
        and git_sha_repair_metadata["parents"] == [GIT_SHA_CANDIDATE_SHA]
    )

    source_pairs = [
        *[
            (revision, source_path)
            for revision in COMPOSE_CANDIDATE_SHAS
            for source_path in (DEPLOYMENT_JOB_PATH, COMPOSE_TEST_PATH)
        ],
        *[
            (revision, source_path)
            for revision in COMPOSE_REPAIR_SHAS
            for source_path in (
                DEPLOYMENT_JOB_PATH,
                COMPOSE_HELPER_PATH,
                COMPOSE_TEST_PATH,
            )
        ],
        (GIT_SHA_CANDIDATE_SHA, DEPLOYMENT_JOB_PATH),
        (GIT_SHA_REPAIR_SHA, DEPLOYMENT_JOB_PATH),
    ]
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_exact_preimage_recovery_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_edges": edges,
        "candidate_metadata": metadata,
        "ancestry": ancestry,
        "stable_patch_ids": patch_ids,
        "patch_equivalence": {
            "compose_candidate_patches_equal": len(candidate_patch_ids) == 1,
            "compose_repair_patches_equal": len(repair_patch_ids) == 1,
        },
        "compose_evaluations": compose_evaluations,
        "git_sha_evaluation": sha_evaluation,
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, revision, source_path)
            for revision, source_path in source_pairs
        ],
        "witness_passed": witness_passed,
        "counting": {
            "candidate_fix_true_positive_edge_count": len(edges),
            "unique_ai_candidate_sha_count": len(candidate_shas),
            "logical_ai_patch_count": 2,
            "mechanism_group_count": 2,
            "branch_replica_edges_retained": 2,
            "branch_replica_inflation_avoided": True,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The two Docker Compose edges are distinct retained commit edges but "
            "patch-equivalent branch replicas, so they count as one logical AI patch "
            "and one mechanism. That AI patch globally replaced every literal docker "
            "compose occurrence and missed flexible whitespace; the later patch uses a "
            "single regex replacement and adds explicit chained-command, comment, and "
            "flag-form regression tests. The Git edge is an immediate-parent repair of "
            "the AI-installed SHA regex: the original accepts a 40-character suffix of "
            "a longer object id and rejects uppercase hex, while the repair adds a word "
            "boundary and case-complete hex class. These are source and deterministic "
            "behavioral claims, not unique vulnerability or advisory counts."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify exact-preimage recovery witness failed")

    print("Coolify exact-preimage recovery witness frozen")
    print(f"  candidate-fix TP edges : {len(edges)}")
    print(f"  unique AI SHAs         : {len(candidate_shas)}")
    print("  logical AI patches     : 2")
    print("  mechanism groups       : 2")
    print(f"  output                 : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
