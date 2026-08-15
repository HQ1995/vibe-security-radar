"""Tests for Coolify fix-preimage lineage recovery witness predicates."""

from __future__ import annotations

from cohort_coolify_lineage_recovery_witness import (
    _evaluate_api_role_origin,
    _evaluate_validate_activation,
    _evaluate_webhook,
)


def test_webhook_ui_preservation_requires_state_and_render_repair() -> None:
    checks = _evaluate_webhook(
        baseline_view='<x-forms.input type="url" id="webhookUrl" />',
        candidate_view=(
            '<x-forms.input canGate="update" :canResource="$settings" '
            'type="password" id="webhookUrl" />'
        ),
        candidate_component="$this->webhookUrl = $this->settings->webhook_url;",
        repair_view=(
            "@can('update', $settings) secret @else "
            "Hidden (only admins can view) @endcan"
        ),
        repair_component=(
            "$this->webhookUrl = auth()->user()->can('update', $this->settings)\n"
            "    ? $this->settings->webhook_url\n    : null;"
        ),
        policy=(
            "return $user->teams->contains('id', $notificationSettings->team->id);\n"
            "return $user->isAdminOfTeam($teamId);"
        ),
    )

    assert all(checks.values())


def test_validate_rename_is_reachability_extension_until_policy_repair() -> None:
    vulnerable_body = """\
    public function validate(Request $request)
    {
        $cloudToken = CloudProviderToken::whereTeamId($teamId)->first();
        Http::withHeaders(['Authorization' => $cloudToken->token]);
    }
"""
    candidate_body = vulnerable_body.replace("function validate(", "function validateToken(")
    repair_body = candidate_body.replace(
        "Http::withHeaders",
        "$this->authorize('view', $cloudToken);\n        Http::withHeaders",
    )
    checks = _evaluate_validate_activation(
        base_controller="use AuthorizesRequests, ValidatesRequests;",
        parent_controller=vulnerable_body,
        parent_routes=(
            "Route::post('/cloud-tokens/{uuid}/validate', "
            "[CloudProviderTokensController::class, 'validate']);"
        ),
        candidate_controller=candidate_body,
        candidate_routes=(
            "Route::post('/cloud-tokens/{uuid}/validate', "
            "[CloudProviderTokensController::class, 'validateToken']);"
        ),
        repair_parent_controller=candidate_body,
        repair_controller=repair_body,
        cloud_policy=(
            "public function view(User $user, CloudProviderToken $token) { "
            "return $user->isAdmin(); }"
        ),
    )

    assert all(checks.values())


def test_api_origin_requires_all_mutation_policy_checks() -> None:
    def controller(*, repaired: bool) -> str:
        methods = []
        for method, ability in (
            ("show", "view"),
            ("store", "create"),
            ("update", "update"),
            ("destroy", "delete"),
        ):
            authorization = (
                f"$this->authorize('{ability}', $token);" if repaired else ""
            )
            methods.append(
                f"public function {method}(Request $request) {{ "
                f"$teamId = getTeamIdFromToken(); {authorization} }}"
            )
        return "\n".join(methods)

    hetzner_parent = (
        "public function createServer(Request $request) { "
        "$teamId = getTeamIdFromToken(); }"
    )
    hetzner_repair = hetzner_parent.replace(
        "}", "$this->authorize('create', [Server::class]); }"
    )
    cloud_policy = "\n".join(
        f"public function {ability}() {{ return $user->isAdmin(); }}"
        for ability in ("view", "create", "update", "delete")
    )
    checks = _evaluate_api_role_origin(
        candidate_cloud=controller(repaired=False),
        candidate_hetzner=hetzner_parent,
        repair_parent_cloud=controller(repaired=False),
        repair_parent_hetzner=hetzner_parent,
        repair_cloud=controller(repaired=True),
        repair_hetzner=hetzner_repair,
        cloud_policy=cloud_policy,
        server_policy_before="public function create() { return true; }",
        server_policy_after=(
            "public function create() { return $user->isAdmin(); }"
        ),
    )

    assert all(checks.values())
