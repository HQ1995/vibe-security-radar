"""Tests for the Coolify mixed-origin webhook-secret witness."""

from __future__ import annotations

import cohort_coolify_webhook_notification_secret_compositional_witness as witness


DIRECT_COMPONENT = """<?php
class Webhook
{
    public ?string $webhookUrl = null;

    public function mount()
    {
        $this->team = auth()->user()->currentTeam();
        $this->settings = $this->team->webhookNotificationSettings;
        $this->authorize('view', $this->settings);
        $this->syncData();
    }

    public function syncData(bool $toModel = false)
    {
        if ($toModel) {
            $this->authorize('update', $this->settings);
        } else {
            $this->webhookUrl = $this->settings->webhook_url;
        }
    }
}
"""


GATED_COMPONENT = DIRECT_COMPONENT.replace(
    "$this->webhookUrl = $this->settings->webhook_url;",
    "$this->webhookUrl = auth()->user()->can('update', $this->settings)\n"
    "                ? $this->settings->webhook_url\n"
    "                : null;",
)


MODEL = """<?php
class WebhookNotificationSettings
{
    protected function casts(): array
    {
        return [
            'webhook_url' => 'encrypted',
        ];
    }
}
"""


PERMISSIVE_POLICY = """<?php
class NotificationPolicy
{
    public function view(User $user, Model $notificationSettings): bool
    {
        return true;
    }

    public function update(User $user, Model $notificationSettings): bool
    {
        // return $user->isAdmin();
        return true;
    }
}
"""


SEPARATED_POLICY = """<?php
class NotificationPolicy
{
    public function view(User $user, Model $notificationSettings): bool
    {
        return $user->teams->contains('id', $notificationSettings->team->id);
    }

    public function update(User $user, Model $notificationSettings): bool
    {
        $teamId = $notificationSettings->team->id;
        return $user->isAdminOfTeam($teamId);
    }
}
"""


AUTH_PROVIDER = """<?php
protected $policies = [
    WebhookNotificationSettings::class => NotificationPolicy::class,
];
"""


ROUTES = """<?php
Route::middleware(['auth', 'verified'])->group(function () {
    Route::prefix('notifications')->group(function () {
        Route::get('/webhook', NotificationWebhook::class)->name('notifications.webhook');
    });
});
"""


OPEN_BLADE = """
<x-forms.input canGate="update" :canResource="$settings" type="password"
    required id="webhookUrl" label="Webhook URL (POST)" />
"""


GATED_BLADE = """
@can('update', $settings)
    <x-forms.input type="password" required id="webhookUrl" label="Webhook URL (POST)" />
@else
    <x-forms.input disabled value="Hidden (only admins can view)" />
@endcan
"""


def _evaluate(*, separated: bool, repaired: bool) -> dict[str, object]:
    return witness._evaluate_sources(
        GATED_COMPONENT if repaired else DIRECT_COMPONENT,
        MODEL,
        GATED_BLADE if repaired else OPEN_BLADE,
        SEPARATED_POLICY if separated else PERMISSIVE_POLICY,
        AUTH_PROVIDER,
        ROUTES,
    )


def test_ai_state_is_latent_before_view_update_role_separation() -> None:
    result = _evaluate(separated=False, repaired=False)

    assert result["same_team_non_admin_permissions"] == {
        "view": True,
        "update": True,
    }
    assert result["same_team_non_admin_secret_loaded_into_public_state"] is True
    assert result["view_update_roles_are_separated"] is False
    assert result["least_privilege_violation_active"] is False


def test_human_policy_change_activates_the_latent_secret_exposure() -> None:
    result = _evaluate(separated=True, repaired=False)

    assert result["same_team_non_admin_permissions"] == {
        "view": True,
        "update": False,
    }
    assert result["component_secret_flow"]["read_strategy"] == "unconditional_copy"
    assert result["same_team_non_admin_secret_loaded_into_public_state"] is True
    assert result["least_privilege_violation_active"] is True


def test_repair_blocks_member_secret_copy_and_hides_bound_field() -> None:
    result = _evaluate(separated=True, repaired=True)

    assert result["component_secret_flow"]["read_strategy"] == (
        "update_permission_gate"
    )
    assert result["same_team_non_admin_secret_loaded_into_public_state"] is False
    assert result["least_privilege_violation_active"] is False
    assert result["blade_secret_field"]["admin_only_bound_field"] is True


def test_exposure_requires_policy_mapping_and_authenticated_route() -> None:
    without_mapping = witness._evaluate_sources(
        DIRECT_COMPONENT,
        MODEL,
        OPEN_BLADE,
        SEPARATED_POLICY,
        "<?php protected $policies = [];",
        ROUTES,
    )
    without_route = witness._evaluate_sources(
        DIRECT_COMPONENT,
        MODEL,
        OPEN_BLADE,
        SEPARATED_POLICY,
        AUTH_PROVIDER,
        "<?php Route::get('/webhook', NotificationWebhook::class);",
    )

    assert without_mapping["least_privilege_violation_active"] is False
    assert without_route["least_privilege_violation_active"] is False


def test_repair_test_contract_requires_member_and_admin_assertions() -> None:
    source = """
test('member cannot view notification secrets', function () {
    $componentTest->assertSet($property, null)->assertDontSee($value);
});
'generic webhook';
'webhook_url' => 'https://example.com/secret-webhook';
test('admin can view notification secrets', function () {
    $componentTest->assertSet($property, $value);
});
"""

    assert all(witness._repair_test_contract(source).values())


def test_claude_signal_requires_explicit_commit_metadata() -> None:
    assert witness._explicit_claude_signal(
        "Andras Bacsai",
        "andras@example.com",
        "Generated with [Claude Code]\n\n"
        "Co-Authored-By: Claude <noreply@anthropic.com>",
    )
    assert not witness._explicit_claude_signal(
        "Andras Bacsai",
        "andras@example.com",
        "fix(security): hide notification secrets from non-admins",
    )
