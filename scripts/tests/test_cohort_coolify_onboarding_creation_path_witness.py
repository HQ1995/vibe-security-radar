"""Tests for the AI onboarding resource-creation path witness."""

from __future__ import annotations

from cohort_coolify_onboarding_creation_path_witness import _evaluate_versions


def _mount() -> str:
    return """
public function mount() {
    if (auth()->user()?->isMember() && auth()->user()->currentTeam()->show_boarding === true) { return; }
}
"""


def _save_methods(*, authorized: bool) -> str:
    private_key_auth = (
        "$this->authorize('create', PrivateKey::class);" if authorized else ""
    )
    server_auth = "$this->authorize('create', Server::class);" if authorized else ""
    return f"""
public function savePrivateKey() {{
    {private_key_auth}
    PrivateKey::createAndStore([]);
}}
public function saveServer() {{
    {server_auth}
    Server::create([]);
}}
"""


def test_onboarding_path_extension_requires_removed_diversion_and_later_guards() -> None:
    baseline = _mount() + """
public function setServerType(string $type) {
    $this->servers = Server::ownedByCurrentTeam()->get();
    $this->currentState = 'select-existing-server';
    return;
}
public function selectExistingServer() {}
""" + _save_methods(authorized=False)
    candidate_path = _mount() + """
public function setServerType(string $type) {
    // Onboarding always creates new servers
    $this->currentState = 'private-key';
}
"""
    candidate = candidate_path + _save_methods(authorized=False)
    repair = candidate_path + _save_methods(authorized=True)
    view = "wire:submit='savePrivateKey' wire:submit='saveServer'"

    result = _evaluate_versions(baseline, candidate, view, repair)

    assert all(result.values())


def test_onboarding_path_extension_fails_when_existing_server_diversion_remains() -> None:
    baseline = _mount() + """
public function setServerType(string $type) {
    $this->servers = Server::ownedByCurrentTeam()->get();
    $this->currentState = 'select-existing-server';
    return;
}
public function selectExistingServer() {}
""" + _save_methods(authorized=False)
    repair = _mount() + """
public function setServerType(string $type) {
    $this->servers = Server::ownedByCurrentTeam()->get();
    $this->currentState = 'select-existing-server';
    return;
}
public function selectExistingServer() {}
""" + _save_methods(authorized=True)

    result = _evaluate_versions(
        baseline,
        baseline,
        "wire:submit='savePrivateKey' wire:submit='saveServer'",
        repair,
    )

    assert result["candidate_removes_existing_server_branch"] is False
    assert result["candidate_removes_select_existing_server_action"] is False
