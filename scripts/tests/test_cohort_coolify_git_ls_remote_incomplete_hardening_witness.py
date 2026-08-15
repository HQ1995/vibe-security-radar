"""Tests for the Coolify AI git-ls-remote hardening witness."""

from __future__ import annotations

import cohort_coolify_git_ls_remote_incomplete_hardening_witness as witness


def test_shell_single_quote_matches_php_ascii_contract() -> None:
    assert witness._shell_single_quote("plain") == "'plain'"
    assert witness._shell_single_quote("a'b") == "'a'\\''b'"


def test_nested_shell_probe_exposes_pre_repair_command_substitution() -> None:
    result = witness._run_shell_probe(repaired=False)

    assert result["returncode"] == 0
    assert result["probe_executed"] is True
    assert result["payload_preserved_as_one_git_argument"] is False


def test_nested_shell_probe_is_inert_after_wrapper_repair() -> None:
    result = witness._run_shell_probe(repaired=True)

    assert result["returncode"] == 0
    assert result["probe_executed"] is False
    assert result["payload_preserved_as_one_git_argument"] is True


def test_version_evaluation_requires_both_incomplete_hardening_layers() -> None:
    parent = r'''
public function generateGitLsRemoteCommands(
    string $deployment_uuid,
    bool $exec_in_docker = true
) {
    if ($this->deploymentType() === 'other') {
        $base_command = "{$base_command} {$customRepository}";
    }
}
'''
    partial = r'''
public function generateGitLsRemoteCommands(
    string $deployment_uuid,
    bool $exec_in_docker = true
) {
    if ($this->deploymentType() === 'source') {
        $base_command = "{$base_command} {$this->source->html_url}/{$customRepository}";
        $base_command = "{$base_command} $source_html_url_scheme://x-access-token:$github_access_token@$source_html_url_host/{$customRepository}.git";
    }
    if ($this->deploymentType() === 'deploy_key') {
        $base_comamnd = "{$base_command} {$customRepository}";
    }
    if ($this->deploymentType() === 'other') {
        $escapedCustomRepository = escapeshellarg($customRepository);
        $base_command = "{$base_command} {$escapedCustomRepository}";
    }
}
'''
    completion = r'''
public function generateGitLsRemoteCommands(
    string $deployment_uuid,
    bool $exec_in_docker = true
) {
    if ($this->deploymentType() === 'source') {
        $escapedRepoUrl = escapeshellarg("{$this->source->html_url}/{$customRepository}");
        $base_command = "{$base_command} {$escapedRepoUrl}";
        $escapedRepoUrl = escapeshellarg($repoUrl);
        $base_command = "{$base_command} {$escapedRepoUrl}";
        $escapedRepoUrl = escapeshellarg($repoUrl);
        $base_command = "{$base_command} {$escapedRepoUrl}";
    }
    if ($this->deploymentType() === 'deploy_key') {
        $escapedCustomRepository = str_replace("'", "'\\''", $customRepository);
        $base_comamnd = "{$base_command} '{$escapedCustomRepository}'";
    }
}
'''
    branch_test = r'''
$result = $application->generateGitLsRemoteCommands($deploymentUuid, true);
expect($command)->toContain("'git@github.com:user/repo.git;curl");
expect($command)->not->toContain('repo.git;curl');
'''
    wrapper_parent = r'''
function executeInDocker(string $containerId, string $command)
{
    return "docker exec {$containerId} bash -c '{$command}'";
}
'''
    wrapper_repair = r'''
function executeInDocker(string $containerId, string $command)
{
    $escapedCommand = str_replace("'", "'\\''", $command);
    return "docker exec {$containerId} bash -c '{$escapedCommand}'";
}
'''
    wrapper_test = "prevents command injection via single quote breakout: build'; id; #"
    unsafe = witness._run_shell_probe(repaired=False)
    repaired = witness._run_shell_probe(repaired=True)

    evaluation = witness._evaluate_versions(
        parent,
        partial,
        completion,
        branch_test,
        wrapper_parent,
        wrapper_repair,
        wrapper_test,
        unsafe,
        repaired,
    )

    assert all(evaluation.values())
