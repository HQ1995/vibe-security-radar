#!/usr/bin/env python3
"""Run the release-ineligible OpenClaw regression independently.

OpenClaw is a focused regression population, not a prerequisite for the formal
all-repository campaign.  This entry point intentionally exposes only the
pilot/smoke controls needed by that regression.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import run_data_refresh as refresh


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        choices=("pilot", "smoke"),
        help="run the bounded pilot or the full regression population",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    parser.add_argument("--pilot-id")
    for stage in ("screening", "verification"):
        parser.add_argument(f"--{stage}-input-usd-per-million-tokens")
        parser.add_argument(f"--{stage}-output-usd-per-million-tokens")
        parser.add_argument(f"--{stage}-max-input-tokens", type=int)
        parser.add_argument(f"--{stage}-max-output-tokens", type=int)
        parser.add_argument(f"--{stage}-max-calls-per-candidate", type=int)
    parser.add_argument("--pilot-cost-ceiling-usd")
    parser.add_argument("--pilot-max-attempts", type=int)
    parser.add_argument("--smoke-cost-ceiling-usd")
    parser.add_argument("--smoke-max-attempts", type=int)
    return parser


def _reject_irrelevant_options(args: argparse.Namespace) -> None:
    pilot_pricing = (
        args.screening_input_usd_per_million_tokens,
        args.screening_output_usd_per_million_tokens,
        args.verification_input_usd_per_million_tokens,
        args.verification_output_usd_per_million_tokens,
        args.screening_max_input_tokens,
        args.screening_max_output_tokens,
        args.verification_max_input_tokens,
        args.verification_max_output_tokens,
        args.screening_max_calls_per_candidate,
        args.verification_max_calls_per_candidate,
        args.pilot_cost_ceiling_usd,
        args.pilot_max_attempts,
    )
    if args.mode == "pilot":
        forbidden = (
            ("--pilot-id", args.pilot_id),
            ("--smoke-cost-ceiling-usd", args.smoke_cost_ceiling_usd),
            ("--smoke-max-attempts", args.smoke_max_attempts),
        )
    else:
        forbidden = (
            *((name, value) for name, value in zip(
                (
                    "--screening-input-usd-per-million-tokens",
                    "--screening-output-usd-per-million-tokens",
                    "--verification-input-usd-per-million-tokens",
                    "--verification-output-usd-per-million-tokens",
                    "--screening-max-input-tokens",
                    "--screening-max-output-tokens",
                    "--verification-max-input-tokens",
                    "--verification-max-output-tokens",
                    "--screening-max-calls-per-candidate",
                    "--verification-max-calls-per-candidate",
                    "--pilot-cost-ceiling-usd",
                    "--pilot-max-attempts",
                ),
                pilot_pricing,
                strict=True,
            )),
        )
    supplied = [name for name, value in forbidden if value is not None]
    if supplied:
        raise refresh.RunnerError(
            f"{args.mode} does not accept: {', '.join(supplied)}"
        )


def _run(args: argparse.Namespace) -> Any:
    _reject_irrelevant_options(args)
    paths = refresh.RunnerPaths.defaults(args.repo_root)
    if args.mode == "pilot":
        return refresh.run_openclaw_pilot(
            paths,
            refresh._pilot_pricing_from_args(args),
            dry_run=args.dry_run,
        )

    missing = [
        name
        for name, value in (
            ("--pilot-id", args.pilot_id),
            ("--smoke-cost-ceiling-usd", args.smoke_cost_ceiling_usd),
            ("--smoke-max-attempts", args.smoke_max_attempts),
        )
        if value is None
    ]
    if missing:
        raise refresh.RunnerError(
            "smoke requires explicit pilot and budget inputs: "
            + ", ".join(missing)
        )
    return refresh.run_openclaw_smoke(
        paths,
        pilot_id=str(args.pilot_id),
        max_attempts=args.smoke_max_attempts,
        max_cost_microusd=refresh._smoke_cost_ceiling_microusd(
            str(args.smoke_cost_ceiling_usd)
        ),
        dry_run=args.dry_run,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with refresh._campaign_signal_handlers():
            results = _run(args)
    except refresh.CampaignSignalInterrupt as exc:
        print(
            f"OpenClaw regression interrupted by {exc.signal_name}; "
            "child process group terminated",
            file=sys.stderr,
        )
        return 128 + exc.signum
    except refresh.RunnerError as exc:
        print(f"OpenClaw regression failed closed: {exc}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "schema_version": 1,
                "formal_release_eligible": False,
                "mode": args.mode,
                "dry_run": args.dry_run,
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
