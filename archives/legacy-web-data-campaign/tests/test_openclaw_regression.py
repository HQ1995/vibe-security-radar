"""Tests for the independent OpenClaw regression entry point."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import run_openclaw_regression as openclaw_regression


def test_parser_has_no_formal_campaign_batch_controls() -> None:
    parser = openclaw_regression.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["pilot", "--batch", "grouped-001"])


def test_pilot_dispatches_to_release_ineligible_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_pilot = MagicMock(return_value={"pilot_id": "a" * 64})
    monkeypatch.setattr(openclaw_regression.refresh, "run_openclaw_pilot", run_pilot)
    monkeypatch.setattr(
        openclaw_regression.refresh,
        "_pilot_pricing_from_args",
        MagicMock(return_value="pricing"),
    )
    monkeypatch.setattr(
        openclaw_regression.refresh.RunnerPaths,
        "defaults",
        MagicMock(return_value="paths"),
    )

    exit_code = openclaw_regression.main(
        [
            "pilot",
            "--screening-input-usd-per-million-tokens",
            "1",
            "--screening-output-usd-per-million-tokens",
            "1",
            "--verification-input-usd-per-million-tokens",
            "1",
            "--verification-output-usd-per-million-tokens",
            "6",
            "--screening-max-input-tokens",
            "100",
            "--screening-max-output-tokens",
            "100",
            "--verification-max-input-tokens",
            "100",
            "--verification-max-output-tokens",
            "100",
            "--screening-max-calls-per-candidate",
            "1",
            "--verification-max-calls-per-candidate",
            "1",
            "--pilot-cost-ceiling-usd",
            "5",
        ]
    )

    assert exit_code == 0
    run_pilot.assert_called_once_with("paths", "pricing", dry_run=False)


def test_smoke_requires_explicit_budget(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = openclaw_regression.main(["smoke", "--dry-run"])

    assert exit_code == 2
    assert "smoke requires explicit pilot and budget inputs" in capsys.readouterr().err
