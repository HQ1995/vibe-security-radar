#!/usr/bin/env python3
"""Freeze the Coolify AI git-ls-remote incomplete-hardening witness."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import (
    _atomic_json,
    _commit_metadata,
    _git_blob,
    _is_ancestor,
    _php_method_region,
)
from cohort_coolify_security_frontier_preservation_witness import (
    _blame_line,
    _line_in_method,
    _line_number,
)


PARTIAL_HARDENING_SHA = "b81baff4b178b8264a9ae4ab704f7902c841fa1b"
BRANCH_COMPLETION_SHA = "8f8c90b7ae8da113c63315c2e5b6f1bf81da1964"
WRAPPER_REPAIR_SHA = "992b922df35b6f7d57be8c664a3d51b1207854cd"
APPLICATION_PATH = "app/Models/Application.php"
APPLICATION_TEST_PATH = "tests/Unit/ApplicationGitSecurityTest.php"
DOCKER_HELPER_PATH = "bootstrap/helpers/docker.php"
WRAPPER_TEST_PATH = "tests/Unit/ExecuteInDockerEscapingTest.php"
PROBE_MARKER = "__AI_SLOP_SHELL_PROBE_EXECUTED__"
PROBE_PAYLOAD = "repo$(ai_slop_shell_probe)"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _text_blob(repository: Path, revision: str, source_path: str) -> str:
    return _git_blob(repository, revision, source_path).decode("utf-8")


def _blob_record(
    repository: Path, revision: str, source_path: str
) -> dict[str, str]:
    blob = _git_blob(repository, revision, source_path)
    return {
        "revision": revision,
        "path": source_path,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def _shell_single_quote(value: str) -> str:
    """Model PHP escapeshellarg for the ASCII probe used by this witness."""
    return "'" + value.replace("'", "'\\''") + "'"


def _execute_in_docker(command: str, *, repaired: bool) -> str:
    if repaired:
        command = command.replace("'", "'\\''")
    return f"docker exec probe-container bash -c '{command}'"


def _run_shell_probe(*, repaired: bool) -> dict[str, object]:
    """Exercise both shell layers with inert docker/git/probe functions."""
    quoted_repository = _shell_single_quote(PROBE_PAYLOAD)
    inner_command = f"git ls-remote {quoted_repository}"
    wrapper = _execute_in_docker(inner_command, repaired=repaired)
    harness = r'''ai_slop_shell_probe() {
    printf '__AI_SLOP_SHELL_PROBE_EXECUTED__'
}
git() {
    printf 'GIT_ARG<%s>\n' "$@"
}
docker() {
    printf 'DOCKER_COMMAND<%s>\n' "$5"
    if [ "$4" = '-c' ]; then
        bash -c "$5"
    fi
}
export -f ai_slop_shell_probe git docker
'''
    completed = subprocess.run(
        ["/bin/bash", "-c", harness + wrapper],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    return {
        "payload": PROBE_PAYLOAD,
        "quoted_repository": quoted_repository,
        "inner_command": inner_command,
        "wrapper": wrapper,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "probe_executed": PROBE_MARKER in completed.stdout,
        "payload_preserved_as_one_git_argument": (
            f"GIT_ARG<{PROBE_PAYLOAD}>" in completed.stdout
        ),
    }


def _evaluate_versions(
    partial_parent: str,
    partial: str,
    branch_completion: str,
    branch_test: str,
    wrapper_parent: str,
    wrapper_repair: str,
    wrapper_test: str,
    unsafe_probe: dict[str, object],
    repaired_probe: dict[str, object],
) -> dict[str, bool]:
    parent_method = _php_method_region(
        partial_parent, "generateGitLsRemoteCommands"
    )
    partial_method = _php_method_region(partial, "generateGitLsRemoteCommands")
    completion_method = _php_method_region(
        branch_completion, "generateGitLsRemoteCommands"
    )
    return {
        "partial_parent_other_branch_uses_raw_repository": (
            '$base_command = "{$base_command} {$customRepository}";'
            in parent_method
        ),
        "partial_commit_hardens_only_other_branch": (
            "$this->deploymentType() === 'other'" in partial_method
            and "$escapedCustomRepository = escapeshellarg($customRepository);"
            in partial_method
            and '$base_command = "{$base_command} {$escapedCustomRepository}";'
            in partial_method
        ),
        "partial_commit_leaves_source_branch_raw": all(
            marker in partial_method
            for marker in (
                '$base_command = "{$base_command} {$this->source->html_url}/{$customRepository}";',
                '$base_command = "{$base_command} $source_html_url_scheme://x-access-token:$github_access_token@$source_html_url_host/{$customRepository}.git";',
            )
        ),
        "partial_commit_leaves_deploy_key_branch_raw": (
            '{$base_command} {$customRepository}";' in partial_method
            and "str_replace(\"'\", \"'\\\\''\", $customRepository)"
            not in partial_method
        ),
        "completion_hardens_source_variants": (
            '$escapedRepoUrl = escapeshellarg("{$this->source->html_url}/{$customRepository}");'
            in completion_method
            and completion_method.count("$escapedRepoUrl = escapeshellarg($repoUrl);")
            == 2
            and completion_method.count(
                '$base_command = "{$base_command} {$escapedRepoUrl}";'
            )
            == 3
        ),
        "completion_hardens_deploy_key_variant": (
            "$escapedCustomRepository = str_replace(\"'\", \"'\\\\''\", $customRepository);"
            in completion_method
            and "{$base_command} '{$escapedCustomRepository}'" in completion_method
        ),
        "completion_test_has_contradictory_deploy_key_assertions": (
            "toContain(\"'git@github.com:user/repo.git;curl" in branch_test
            and "not->toContain('repo.git;curl')" in branch_test
        ),
        "completion_test_only_inspects_generated_command": (
            "generateGitLsRemoteCommands($deploymentUuid, true)" in branch_test
            and "subprocess" not in branch_test
            and "bash -c" not in branch_test
        ),
        "wrapper_parent_directly_nests_unescaped_command": (
            "return \"docker exec {$containerId} bash -c '{$command}'\";"
            in wrapper_parent
            and "$escapedCommand" not in wrapper_parent
        ),
        "wrapper_repair_escapes_before_outer_shell": (
            "$escapedCommand = str_replace(\"'\", \"'\\\\''\", $command);"
            in wrapper_repair
            and "return \"docker exec {$containerId} bash -c '{$escapedCommand}'\";"
            in wrapper_repair
        ),
        "wrapper_repair_adds_quote_breakout_regression": (
            "prevents command injection via single quote breakout" in wrapper_test
            and "build'; id; #" in wrapper_test
        ),
        "pre_repair_command_substitution_executes": (
            unsafe_probe["returncode"] == 0
            and unsafe_probe["probe_executed"] is True
            and unsafe_probe["payload_preserved_as_one_git_argument"] is False
        ),
        "post_repair_payload_is_inert_single_git_argument": (
            repaired_probe["returncode"] == 0
            and repaired_probe["probe_executed"] is False
            and repaired_probe["payload_preserved_as_one_git_argument"] is True
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")

    partial_parent_revision = f"{PARTIAL_HARDENING_SHA}^"
    wrapper_parent_revision = f"{WRAPPER_REPAIR_SHA}^"
    partial_parent = _text_blob(
        repository, partial_parent_revision, APPLICATION_PATH
    )
    partial = _text_blob(repository, PARTIAL_HARDENING_SHA, APPLICATION_PATH)
    branch_completion = _text_blob(
        repository, BRANCH_COMPLETION_SHA, APPLICATION_PATH
    )
    branch_test = _text_blob(
        repository, BRANCH_COMPLETION_SHA, APPLICATION_TEST_PATH
    )
    wrapper_parent = _text_blob(
        repository, wrapper_parent_revision, DOCKER_HELPER_PATH
    )
    wrapper_repair = _text_blob(
        repository, WRAPPER_REPAIR_SHA, DOCKER_HELPER_PATH
    )
    wrapper_test = _text_blob(
        repository, WRAPPER_REPAIR_SHA, WRAPPER_TEST_PATH
    )
    unsafe_probe = _run_shell_probe(repaired=False)
    repaired_probe = _run_shell_probe(repaired=True)
    evaluation = _evaluate_versions(
        partial_parent,
        partial,
        branch_completion,
        branch_test,
        wrapper_parent,
        wrapper_repair,
        wrapper_test,
        unsafe_probe,
        repaired_probe,
    )
    metadata = {
        "partial_hardening": _commit_metadata(repository, PARTIAL_HARDENING_SHA),
        "branch_completion": _commit_metadata(repository, BRANCH_COMPLETION_SHA),
        "wrapper_repair": _commit_metadata(repository, WRAPPER_REPAIR_SHA),
    }
    ancestry = {
        "partial_parent_to_partial": _is_ancestor(
            repository, partial_parent_revision, PARTIAL_HARDENING_SHA
        ),
        "partial_to_branch_completion": _is_ancestor(
            repository, PARTIAL_HARDENING_SHA, BRANCH_COMPLETION_SHA
        ),
        "branch_completion_to_wrapper_repair": _is_ancestor(
            repository, BRANCH_COMPLETION_SHA, WRAPPER_REPAIR_SHA
        ),
    }
    line_origins = {
        "partial_other_escape_at_introduction": _blame_line(
            repository,
            PARTIAL_HARDENING_SHA,
            APPLICATION_PATH,
            _line_in_method(
                partial,
                "generateGitLsRemoteCommands",
                '$base_command = "{$base_command} {$escapedCustomRepository}";',
            ),
            "AI partial hardening command for the other deployment type",
        ),
        "partial_other_escape_preserved_at_wrapper_repair": _blame_line(
            repository,
            WRAPPER_REPAIR_SHA,
            APPLICATION_PATH,
            _line_in_method(
                _text_blob(repository, WRAPPER_REPAIR_SHA, APPLICATION_PATH),
                "generateGitLsRemoteCommands",
                '$base_command = "{$base_command} {$escapedCustomRepository}";',
            ),
            "wrapper repair preserves the first AI hardened command",
        ),
        "completion_source_escape_at_introduction": _blame_line(
            repository,
            BRANCH_COMPLETION_SHA,
            APPLICATION_PATH,
            _line_in_method(
                branch_completion,
                "generateGitLsRemoteCommands",
                '$escapedRepoUrl = escapeshellarg("{$this->source->html_url}/{$customRepository}");',
            ),
            "AI source-branch completion escape",
        ),
        "completion_source_escape_preserved_at_wrapper_repair": _blame_line(
            repository,
            WRAPPER_REPAIR_SHA,
            APPLICATION_PATH,
            _line_in_method(
                _text_blob(repository, WRAPPER_REPAIR_SHA, APPLICATION_PATH),
                "generateGitLsRemoteCommands",
                '$escapedRepoUrl = escapeshellarg("{$this->source->html_url}/{$customRepository}");',
            ),
            "wrapper repair preserves the second AI local escape",
        ),
        "wrapper_escape_repair": _blame_line(
            repository,
            WRAPPER_REPAIR_SHA,
            DOCKER_HELPER_PATH,
            _line_number(
                wrapper_repair,
                "$escapedCommand = str_replace(\"'\", \"'\\\\''\", $command);",
            ),
            "outer executeInDocker shell-boundary repair",
        ),
    }
    expected_origins = {
        "partial_other_escape_at_introduction": PARTIAL_HARDENING_SHA,
        "partial_other_escape_preserved_at_wrapper_repair": PARTIAL_HARDENING_SHA,
        "completion_source_escape_at_introduction": BRANCH_COMPLETION_SHA,
        "completion_source_escape_preserved_at_wrapper_repair": (
            BRANCH_COMPLETION_SHA
        ),
        "wrapper_escape_repair": WRAPPER_REPAIR_SHA,
    }
    witness_passed = bool(
        metadata["partial_hardening"]["explicit_claude_signal"] is True
        and metadata["branch_completion"]["explicit_claude_signal"] is True
        and "all git commands now use properly escaped repository urls"
        in str(metadata["partial_hardening"]["message"]).casefold()
        and "already fixed in commit b81baff4b"
        in str(metadata["branch_completion"]["message"]).casefold()
        and "completes the security fix for all deployment types"
        in str(metadata["branch_completion"]["message"]).casefold()
        and all(ancestry.values())
        and all(evaluation.values())
        and all(
            line_origins[key]["origin_sha"] == origin
            for key, origin in expected_origins.items()
        )
    )
    confirmed_edges = [
        {
            "candidate_sha": PARTIAL_HARDENING_SHA,
            "fix_sha": BRANCH_COMPLETION_SHA,
            "causal_adjudication": (
                "CONFIRMED_AI_INCOMPLETE_GIT_LS_REMOTE_BRANCH_COVERAGE"
            ),
            "mechanism_group": "git_ls_remote_deployment_type_coverage",
        },
        {
            "candidate_sha": PARTIAL_HARDENING_SHA,
            "fix_sha": WRAPPER_REPAIR_SHA,
            "causal_adjudication": (
                "CONFIRMED_AI_INCOMPLETE_NESTED_SHELL_ESCAPING"
            ),
            "mechanism_group": "nested_execute_in_docker_shell_quoting",
        },
        {
            "candidate_sha": BRANCH_COMPLETION_SHA,
            "fix_sha": WRAPPER_REPAIR_SHA,
            "causal_adjudication": (
                "CONFIRMED_AI_INCOMPLETE_NESTED_SHELL_ESCAPING"
            ),
            "mechanism_group": "nested_execute_in_docker_shell_quoting",
        },
    ]
    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_git_ls_remote_incomplete_hardening_witness",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_shas": [PARTIAL_HARDENING_SHA, BRANCH_COMPLETION_SHA],
        "fix_shas": [BRANCH_COMPLETION_SHA, WRAPPER_REPAIR_SHA],
        "metadata": metadata,
        "ancestry": ancestry,
        "evaluation": evaluation,
        "shell_probes": {
            "before_wrapper_repair": unsafe_probe,
            "after_wrapper_repair": repaired_probe,
        },
        "line_origins": line_origins,
        "source_blobs": [
            _blob_record(repository, partial_parent_revision, APPLICATION_PATH),
            _blob_record(repository, PARTIAL_HARDENING_SHA, APPLICATION_PATH),
            _blob_record(repository, BRANCH_COMPLETION_SHA, APPLICATION_PATH),
            _blob_record(
                repository, BRANCH_COMPLETION_SHA, APPLICATION_TEST_PATH
            ),
            _blob_record(repository, wrapper_parent_revision, DOCKER_HELPER_PATH),
            _blob_record(repository, WRAPPER_REPAIR_SHA, APPLICATION_PATH),
            _blob_record(repository, WRAPPER_REPAIR_SHA, DOCKER_HELPER_PATH),
            _blob_record(repository, WRAPPER_REPAIR_SHA, WRAPPER_TEST_PATH),
        ],
        "confirmed_edges": confirmed_edges,
        "witness_passed": witness_passed,
        "counting": {
            "candidate_fix_true_positive_edge_count": 3,
            "unique_ai_candidate_count": 2,
            "mechanism_group_count": 2,
            "unique_advisory_increment_not_asserted": True,
        },
        "claim_boundary": (
            "The first Claude-attributed commit does not originate the older raw "
            "git-ls-remote command construction. It explicitly claims complete "
            "repository-URL shell hardening but changes only the other deployment "
            "type; the next Claude-attributed commit explicitly cites that commit "
            "and adds the missing source and deploy_key variants. Both local quote "
            "transforms are then preserved until the later executeInDocker repair. "
            "A side-effect-free two-shell probe shows that command substitution in "
            "the quoted repository executes before that wrapper repair and remains "
            "one inert Git argument afterward. This counts three exact candidate-fix "
            "edges in two shared mechanism groups, not three independent "
            "vulnerabilities, root origin of the command sink, CVE linkage, or proof "
            "that every shell-command construction is safe after the wrapper repair."
        ),
    }
    _atomic_json(args.output, payload)
    if not witness_passed:
        raise SystemExit("Coolify git-ls-remote hardening witness failed")
    print("Coolify git-ls-remote incomplete-hardening witness frozen")
    print(f"  edges  : {len(confirmed_edges)}")
    print(f"  output : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
