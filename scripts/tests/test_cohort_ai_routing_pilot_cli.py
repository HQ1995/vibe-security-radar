"""Prompt-evidence tests for the recall-safe AI routing pilot CLI."""

from __future__ import annotations

from decimal import Decimal

import pytest

import cohort_ai_routing_pilot as pilot


def test_priority_path_fix_evidence_survives_global_truncation(monkeypatch, tmp_path) -> None:
    calls: list[list[str]] = []

    def fake_run_git(
        _repo,
        arguments: list[str],
        *,
        timeout: int = 120,
        allow_lazy_fetch: bool = False,
    ) -> str:
        calls.append(arguments)
        if "--no-patch" in arguments:
            return "security fix\x1f2026-01-01T00:00:00+00:00\n"
        if "--" in arguments:
            return "diff --git a/target.py b/target.py\n-old\n+guard\n"
        return "diff --git a/aaa.py b/aaa.py\n" + ("noise\n" * 100)

    monkeypatch.setattr(pilot, "_run_git", fake_run_git)

    _subject, _date, diff = pilot._commit_view(
        tmp_path,
        "f" * 40,
        200,
        priority_paths=["target.py"],
    )

    assert diff.startswith("# Candidate-path-priority fix evidence")
    assert "+guard" in diff
    assert "# Global fix evidence" in diff
    assert any(arguments[-2:] == ["--", "target.py"] for arguments in calls)
    assert all(
        "--first-parent" in arguments
        for arguments in calls
        if "--no-patch" not in arguments
    )

    _subject, _date, shared_diff = pilot._commit_view(
        tmp_path,
        "f" * 40,
        200,
        priority_paths=["target.py"],
        priority_label="Candidate/fix shared-path candidate evidence",
    )
    assert shared_diff.startswith(
        "# Candidate/fix shared-path candidate evidence"
    )

    _subject, _date, bridged_diff = pilot._commit_view(
        tmp_path,
        "f" * 40,
        240,
        priority_paths=["target.py"],
        priority_label="Candidate/fix shared-path candidate evidence",
        priority_evidence=[
            (
                "Cross-file security-surface candidate evidence",
                "diff --git a/routes/new.py b/routes/new.py\n+@router.post('/new')",
            )
        ],
    )
    assert bridged_diff.startswith(
        "# Cross-file security-surface candidate evidence"
    )
    assert bridged_diff.index("@router.post") < bridged_diff.index(
        "# Candidate/fix shared-path candidate evidence"
    )


def test_priority_path_order_survives_git_path_sorting(monkeypatch, tmp_path) -> None:
    def fake_run_git(
        _repo,
        arguments: list[str],
        *,
        timeout: int = 120,
        allow_lazy_fetch: bool = False,
    ) -> str:
        del timeout, allow_lazy_fetch
        if "--no-patch" in arguments:
            return "security fix\x1f2026-01-01T00:00:00+00:00\n"
        if "--" in arguments:
            path = arguments[-1]
            return f"diff --git a/{path} b/{path}\n+guard-for-{path}\n"
        return "diff --git a/global.py b/global.py\n" + ("noise\n" * 100)

    monkeypatch.setattr(pilot, "_run_git", fake_run_git)

    _subject, _date, diff = pilot._commit_view(
        tmp_path,
        "f" * 40,
        300,
        priority_paths=["z-new-security.py", "a-old-noise.py"],
    )

    assert "guard-for-z-new-security.py" in diff
    assert diff.index("z-new-security.py") < diff.index("a-old-noise.py")


def test_cross_file_security_bridge_exposes_route_and_global_guard(
    monkeypatch, tmp_path
) -> None:
    candidate_sha = "c" * 40
    fix_sha = "f" * 40
    candidate_route_patch = """\
diff --git a/backend/app/api/routes/printers.py b/backend/app/api/routes/printers.py
--- a/backend/app/api/routes/printers.py
+++ b/backend/app/api/routes/printers.py
@@ -1,2 +1,2 @@
-value = 1
+value = 2
@@ -100,0 +101,8 @@
+@router.post("/{printer_id}/debug/simulate-print-complete")
+async def simulate_print_complete(printer_id: int):
+    await mutate_printer_state(printer_id)
+    return {"success": True}
"""
    global_guard_patch = """\
diff --git a/backend/app/main.py b/backend/app/main.py
--- a/backend/app/main.py
+++ b/backend/app/main.py
@@ -200,0 +201,8 @@
+# Authentication Middleware - Secures ALL API routes by default
+@app.middleware("http")
+async def auth_middleware(request, call_next):
+    if not request.headers.get("Authorization"):
+        return unauthorized()
+    return await call_next(request)
"""

    def fake_path_patch(
        _repo,
        sha: str,
        path: str,
        *,
        allow_lazy_fetch: bool = False,
    ) -> str:
        del allow_lazy_fetch
        if sha == candidate_sha and path.endswith("routes/printers.py"):
            return candidate_route_patch
        if sha == fix_sha and path == "backend/app/main.py":
            return global_guard_patch
        return ""

    monkeypatch.setattr(pilot, "_path_patch", fake_path_patch)
    bridge = pilot._cross_file_security_bridge(
        tmp_path,
        candidate_sha,
        fix_sha,
        ["backend/app/api/routes/printers.py", "backend/app/main.py"],
        ["backend/app/core/auth.py", "backend/app/main.py"],
        limit=4000,
    )

    assert bridge["applied"] is True
    assert bridge["candidate_paths"] == ["backend/app/api/routes/printers.py"]
    assert bridge["fix_paths"] == ["backend/app/main.py"]
    assert "simulate-print-complete" in bridge["candidate_evidence"]
    assert "auth_middleware" in bridge["fix_evidence"]


def test_cross_file_security_bridge_requires_a_global_guard(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        pilot,
        "_path_patch",
        lambda *_args, **_kwargs: (
            "diff --git a/api/routes/x.py b/api/routes/x.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+@router.post('/mutate')\n"
            "+async def mutate(): pass\n"
        ),
    )

    bridge = pilot._cross_file_security_bridge(
        tmp_path,
        "c" * 40,
        "f" * 40,
        ["api/routes/x.py"],
        ["unrelated.py"],
        limit=1000,
    )

    assert bridge["applied"] is False


@pytest.mark.parametrize(
    "api_base",
    [
        "http://127.0.0.1:8317/v1",
        "http://[::1]:8317/v1",
        "http://localhost:8317/v1",
    ],
)
def test_loopback_cliproxy_endpoint_detection(api_base: str) -> None:
    assert pilot._is_loopback_api_base(api_base) is True


def test_remote_cliproxy_endpoint_requires_separate_authorization() -> None:
    assert pilot._is_loopback_api_base("https://proxy.example.test/v1") is False


def test_cliproxy_budget_requires_explicit_operator_price_assumptions() -> None:
    with pytest.raises(pilot.RoutingPilotContractError, match="price contract"):
        pilot._budget_prices("cliproxyapi", None, None)

    assert pilot._budget_prices("cliproxyapi", "0.20", "1.20") == (
        "0.20",
        "1.20",
    )
    assert pilot._budget_prices("litellm", None, None) == (
        pilot.DEFAULT_INPUT_PRICE,
        pilot.DEFAULT_OUTPUT_PRICE,
    )


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self._payload


class _FakeClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.requested_url = ""

    def get(self, url: str, **_kwargs) -> _FakeResponse:
        self.requested_url = url
        return _FakeResponse(self.payload)


def test_cliproxy_contract_requires_exact_exposed_request_alias() -> None:
    client = _FakeClient(
        {
            "data": [
                {"id": "gemini-3.5-flash-low"},
                {"id": "gpt-oss-120b-medium"},
            ]
        }
    )

    contract = pilot._live_cliproxy_contract(
        client,
        "http://127.0.0.1:8317/v1",
        {"Authorization": "Bearer local"},
        "gemini-3.5-flash-low",
        timeout=1,
    )

    assert client.requested_url.endswith("/models")
    assert contract["backend"] == "cliproxyapi"
    assert contract["exposed_model_count"] == 2
    assert contract["input_cost_per_token"] == 0
    with pytest.raises(SystemExit, match="exactly once"):
        pilot._live_cliproxy_contract(
            client,
            "http://127.0.0.1:8317/v1",
            {"Authorization": "Bearer local"},
            "missing-model",
            timeout=1,
        )


def test_cliproxy_chat_provenance_retains_proxy_reported_alias() -> None:
    valid, reason, observed = pilot._validate_response_provenance(
        {
            "model": "gemini-default",
            "choices": [
                {"finish_reason": "stop", "message": {"content": "{}"}}
            ],
        },
        backend="cliproxyapi",
        requested_model="gemini-3.5-flash-low",
    )

    assert valid is True
    assert reason == ""
    assert observed == "gemini-default"


def test_chat_request_and_usage_support_openai_compatibility_keys() -> None:
    endpoint, body = pilot._request_contract(
        backend="cliproxyapi",
        api_base="http://127.0.0.1:8317/v1",
        model="gpt-5.6-terra",
        system_prompt="system",
        user_prompt="user",
        max_output_tokens=2000,
        reasoning_effort="medium",
    )

    assert endpoint.endswith("/chat/completions")
    assert body["messages"] == [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]
    assert body["max_tokens"] == 2000
    assert body["reasoning_effort"] == "medium"
    assert pilot._usage_counts(
        {"prompt_tokens": 123, "completion_tokens": 45}
    ) == (123, 45)


def test_chat_request_can_defer_reasoning_to_an_exposed_model_alias() -> None:
    _endpoint, body = pilot._request_contract(
        backend="cliproxyapi",
        api_base="http://127.0.0.1:8317/v1",
        model="gemini-3.5-flash-low",
        system_prompt="system",
        user_prompt="user",
        max_output_tokens=512,
        reasoning_effort="backend-alias",
    )

    assert "reasoning_effort" not in body


def test_usage_counts_reconcile_provider_reasoning_conventions() -> None:
    # Gemini reports hidden reasoning outside completion_tokens.
    assert pilot._usage_counts(
        {
            "prompt_tokens": 100,
            "completion_tokens": 10,
            "total_tokens": 200,
            "completion_tokens_details": {"reasoning_tokens": 90},
        }
    ) == (100, 100)

    # Terra reports hidden reasoning inside completion_tokens.
    assert pilot._usage_counts(
        {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
            "completion_tokens_details": {"reasoning_tokens": 20},
        }
    ) == (100, 50)

    # Without total_tokens, conservatively include separately reported reasoning.
    assert pilot._usage_counts(
        {
            "prompt_tokens": 100,
            "completion_tokens": 10,
            "completion_tokens_details": {"reasoning_tokens": 90},
        }
    ) == (100, 100)


def test_usage_cost_applies_frozen_operator_price_assumptions() -> None:
    assert pilot._usage_cost(
        47_131,
        879,
        Decimal("0.20") / Decimal(1_000_000),
        Decimal("1.20") / Decimal(1_000_000),
    ) == Decimal("0.010481")


def test_chat_request_rejects_an_unknown_reasoning_effort() -> None:
    with pytest.raises(ValueError, match="reasoning effort"):
        pilot._request_contract(
            backend="cliproxyapi",
            api_base="http://127.0.0.1:8317/v1",
            model="gpt-5.6-terra",
            system_prompt="system",
            user_prompt="user",
            max_output_tokens=512,
            reasoning_effort="whatever",
        )


def test_backend_alias_requires_an_effort_suffix_in_the_model_id() -> None:
    with pytest.raises(ValueError, match="explicit effort suffix"):
        pilot._request_contract(
            backend="cliproxyapi",
            api_base="http://127.0.0.1:8317/v1",
            model="gpt-5.6-terra",
            system_prompt="system",
            user_prompt="user",
            max_output_tokens=512,
            reasoning_effort="backend-alias",
        )
