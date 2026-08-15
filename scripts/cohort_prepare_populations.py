#!/usr/bin/env python3
"""Build discovery and estimation populations from one content-bound scan."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import cohort_classify_exposure
from cohort.populations import (
    DISCOVERY_POPULATION,
    ESTIMATION_POPULATION,
    PopulationContractError,
    build_population_split_manifest,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scan-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--as-of", default=None)
    parser.add_argument("--mature-followup-days", type=int, default=180)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--repo", action="append", default=[])
    parser.add_argument("--frame", type=Path, default=None)
    parser.add_argument("--limit-repos", type=int, default=0)
    parser.add_argument("--no-fetch", action="store_true")
    parser.add_argument("--fetch-batch", type=int, default=20)
    parser.add_argument("--repo-timeout", type=int, default=600)
    return parser.parse_args(argv)


def _atomic_write_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _classification_args(
    args: argparse.Namespace,
    *,
    role: str,
    min_followup_days: int,
    output_dir: Path,
) -> list[str]:
    values = [
        "--scan-dir",
        str(args.scan_dir),
        "--population-role",
        role,
        "--min-followup-days",
        str(min_followup_days),
        "--workers",
        str(args.workers),
        "--limit-repos",
        str(args.limit_repos),
        "--fetch-batch",
        str(args.fetch_batch),
        "--repo-timeout",
        str(args.repo_timeout),
        "--output-dir",
        str(output_dir),
    ]
    if args.as_of:
        values.extend(["--as-of", args.as_of])
    if args.no_fetch:
        values.append("--no-fetch")
    if args.frame is not None:
        values.extend(["--frame", str(args.frame)])
    for repository in args.repo:
        values.extend(["--repo", repository])
    return values


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.mature_followup_days <= 0:
        raise SystemExit("mature-followup-days must be positive")
    if args.workers < 1 or args.limit_repos < 0:
        raise SystemExit("workers must be positive and limit-repos cannot be negative")

    discovery_dir = args.output_dir / "discovery"
    estimation_dir = args.output_dir / "estimation"
    discovery_result = cohort_classify_exposure.main(
        _classification_args(
            args,
            role=DISCOVERY_POPULATION,
            min_followup_days=0,
            output_dir=discovery_dir,
        )
    )
    if discovery_result != 0:
        raise SystemExit("discovery population classification failed")
    estimation_result = cohort_classify_exposure.main(
        _classification_args(
            args,
            role=ESTIMATION_POPULATION,
            min_followup_days=args.mature_followup_days,
            output_dir=estimation_dir,
        )
    )
    if estimation_result != 0:
        raise SystemExit("estimation population classification failed")

    try:
        manifest = build_population_split_manifest(
            args.scan_dir, discovery_dir, estimation_dir
        )
    except PopulationContractError as exc:
        raise SystemExit(f"population split failed: {exc}") from exc
    manifest["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["mature_followup_days"] = args.mature_followup_days
    _atomic_write_json(args.output_dir / "population_split.json", manifest)

    print("\nPopulation split complete")
    print(f"  discovery : {discovery_dir}")
    print(f"  estimation: {estimation_dir}")
    print(f"  manifest  : {args.output_dir / 'population_split.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
