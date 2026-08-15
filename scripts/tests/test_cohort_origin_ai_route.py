"""Unit tests for recall-safe origin model routing."""

from __future__ import annotations

import json

import cohort_origin_ai_route as route


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload
        self.content = json.dumps(payload).encode("utf-8")

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self._payload


def test_parse_failure_records_finish_reason_and_remains_blocked(
    monkeypatch, tmp_path
) -> None:
    payload = {
        "model": "deepseek-v4-flash",
        "choices": [
            {
                "finish_reason": "length",
                "message": {"content": "", "reasoning_content": "still thinking"},
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20},
    }
    monkeypatch.setattr(
        route.httpx,
        "post",
        lambda *_args, **_kwargs: _FakeResponse(payload),
    )
    responses = tmp_path / "responses"
    responses.mkdir()

    result = route._call_one(
        {
            "item_id": "candidate-1",
            "sequence": 1,
            "system_prompt": "system",
            "user_prompt": "user",
        },
        api_base="http://127.0.0.1:8317/v1",
        api_key="local-test-key",
        model="deepseek-v4-flash",
        reasoning_effort="low",
        max_output_tokens=100,
        timeout=1,
        responses_dir=responses,
    )

    assert result["result_status"] == "parse_error"
    assert result["finish_reason"] == "length"
    assert result["reason"] == "model_json_parse_failed:finish_reason=length"
    assert (responses / "001.json").exists()
