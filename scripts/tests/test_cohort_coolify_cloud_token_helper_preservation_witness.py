"""Tests for cloud-token helper preservation witness predicates."""

from __future__ import annotations

from cohort_coolify_cloud_token_helper_preservation_witness import (
    _evaluate_preservation,
)


def _method(name: str, body: str) -> str:
    return f"public function {name}(Request $request)\n{{\n{body}\n}}\n"


def test_structural_refactor_preserves_both_missing_policy_boundaries() -> None:
    parent = _method(
        "validateToken",
        "Http::withHeaders(['Authorization' => $cloudToken->token]);",
    )
    candidate = (
        "private function validateProviderToken(string $provider, string $token)\n"
        "{\nHttp::withHeaders(['Authorization' => 'Bearer '.$token]);\n}\n"
        + _method(
            "validateToken",
            "$this->validateProviderToken($cloudToken->provider, $cloudToken->token);",
        )
        + _method(
            "store",
            "$body = $request->json()->all();\n"
            "$this->validateProviderToken($body['provider'], $body['token']);",
        )
        + _method(
            "update",
            "$body = $request->json()->all();\n$request->route('uuid');",
        )
    )
    credential_repair = candidate.replace(
        "$this->validateProviderToken($cloudToken->provider, $cloudToken->token);",
        "$this->authorize('view', $cloudToken);\n"
        "$this->validateProviderToken($cloudToken->provider, $cloudToken->token);",
        1,
    )
    role_repair = candidate.replace(
        "$body = $request->json()->all();\n"
        "$this->validateProviderToken($body['provider'], $body['token']);",
        "$body = $request->json()->all();\n"
        "$this->authorize('create', [CloudProviderToken::class]);\n"
        "$this->validateProviderToken($body['provider'], $body['token']);",
    ).replace(
        "$body = $request->json()->all();\n$request->route('uuid');",
        "$body = $request->json()->all();\n$request->route('uuid');\n"
        "$this->authorize('update', $token);",
    )
    policy = "\n".join(
        f"public function {ability}() {{ return $user->isAdmin(); }}"
        for ability in ("view", "create", "update")
    )

    checks = _evaluate_preservation(
        parent=parent,
        candidate=candidate,
        credential_repair_parent=candidate,
        credential_repair=credential_repair,
        role_repair_parent=candidate,
        role_repair=role_repair,
        policy=policy,
    )

    assert all(checks.values())
