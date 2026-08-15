#!/usr/bin/env python3
"""Freeze stable patch-equivalence groups for retained Coolify AI candidates."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

from cohort_coolify_postgresql_query_idor_path_extension_witness import _atomic_json


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--candidate-inventory", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object: {path}")
    return value


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"row {line_number} is not an object")
                rows.append(value)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _git(repository: Path, arguments: list[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"git {' '.join(arguments)} failed: {exc}") from exc
    if completed.returncode != 0:
        reason = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"git {' '.join(arguments)} failed: {reason}")
    return completed.stdout


def _patch_id(repository: Path, sha: str) -> str | None:
    patch = _git(
        repository,
        ["show", "--format=", "--no-ext-diff", "--first-parent", sha],
    )
    if not patch.strip():
        return None
    value = _git(repository, ["patch-id", "--stable"], input_bytes=patch)
    fields = value.decode("ascii", errors="strict").strip().split()
    if len(fields) < 2 or len(fields[0]) != 40:
        raise SystemExit(f"cannot compute stable patch-id for {sha}")
    return fields[0]


def _patch_groups(
    patch_ids: Mapping[str, str | None]
) -> tuple[list[dict[str, object]], dict[str, str]]:
    grouped: defaultdict[str, list[str]] = defaultdict(list)
    candidate_identities: dict[str, str] = {}
    for sha, patch_id in sorted(patch_ids.items()):
        identity = patch_id if patch_id is not None else f"empty:{sha}"
        grouped[identity].append(sha)
        candidate_identities[sha] = identity
    groups = [
        {
            "code_change_identity": identity,
            "stable_patch_id": (
                None if identity.startswith("empty:") else identity
            ),
            "candidate_shas": shas,
            "physical_candidate_count": len(shas),
            "patch_equivalent": len(shas) > 1,
            "empty_patch": identity.startswith("empty:"),
        }
        for identity, shas in sorted(grouped.items())
    ]
    return groups, candidate_identities


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    inventory_rows = _load_jsonl(args.candidate_inventory.resolve())
    candidate_shas = sorted({str(row.get("sha") or "") for row in inventory_rows})
    if any(len(sha) != 40 for sha in candidate_shas):
        raise SystemExit("candidate inventory contains malformed SHA")
    if not all(row.get("retained") is True for row in inventory_rows):
        raise SystemExit("candidate inventory contains a dropped edge")

    patch_ids = {sha: _patch_id(repository, sha) for sha in candidate_shas}
    groups, identities = _patch_groups(patch_ids)
    duplicate_groups = [group for group in groups if group["patch_equivalent"] is True]
    empty_groups = [group for group in groups if group["empty_patch"] is True]

    ledger = _load_json(args.ledger.resolve())
    edge_ledger = ledger.get("edge_ledger")
    if not isinstance(edge_ledger, list):
        raise SystemExit("causal ledger edge rows are malformed")
    confirmed_edges = [
        row
        for row in edge_ledger
        if isinstance(row, Mapping) and row.get("status") == "CONFIRMED_TRUE_POSITIVE"
    ]
    confirmed_candidates = {
        str(row.get("candidate_sha") or "") for row in confirmed_edges
    }
    if not confirmed_candidates <= set(candidate_shas):
        raise SystemExit("confirmed ledger candidate is absent from inventory")
    confirmed_identities = {identities[sha] for sha in confirmed_candidates}
    confirmed_duplicate_groups = [
        {
            **group,
            "confirmed_candidate_shas": sorted(
                set(group["candidate_shas"]) & confirmed_candidates
            ),
        }
        for group in duplicate_groups
        if len(set(group["candidate_shas"]) & confirmed_candidates) > 1
    ]

    payload = {
        "schema_version": 1,
        "artifact_kind": "coolify_ai_candidate_patch_equivalence",
        "repository_identity": "github.com/coollabsio/coolify",
        "candidate_inventory": {
            "path": str(args.candidate_inventory.resolve()),
            "retained_edge_count": len(inventory_rows),
            "unique_physical_candidate_count": len(candidate_shas),
        },
        "summary": {
            "unique_physical_candidate_count": len(candidate_shas),
            "unique_code_change_identity_count": len(groups),
            "empty_patch_candidate_count": len(empty_groups),
            "duplicate_patch_group_count": len(duplicate_groups),
            "patch_redundant_physical_candidate_count": sum(
                int(group["physical_candidate_count"]) - 1
                for group in duplicate_groups
            ),
            "confirmed_unique_physical_candidate_count": len(confirmed_candidates),
            "confirmed_unique_code_change_identity_count": len(
                confirmed_identities
            ),
            "confirmed_duplicate_patch_group_count": len(
                confirmed_duplicate_groups
            ),
        },
        "duplicate_patch_groups": duplicate_groups,
        "confirmed_duplicate_patch_groups": confirmed_duplicate_groups,
        "candidate_patch_records": [
            {
                "candidate_sha": sha,
                "stable_patch_id": patch_ids[sha],
                "code_change_identity": identities[sha],
                "confirmed_any_edge": sha in confirmed_candidates,
            }
            for sha in candidate_shas
        ],
        "conservation": {
            "physical_candidate_count": len(candidate_shas),
            "grouped_physical_candidate_count": sum(
                int(group["physical_candidate_count"]) for group in groups
            ),
            "hard_delete_count": 0,
            "passed": sum(
                int(group["physical_candidate_count"]) for group in groups
            )
            == len(candidate_shas),
        },
        "claim_boundary": (
            "Stable patch-id groups identical code deltas for reporting only. They "
            "must not hard-collapse candidate generation: the same patch at a "
            "different ancestry position can relate to a different later repair. "
            "Patch equivalence also does not decompose a squash; squash PR members "
            "must be expanded and adjudicated separately before this presentation "
            "layer."
        ),
    }
    if payload["conservation"]["passed"] is not True:
        raise SystemExit("patch-equivalence conservation failed")
    _atomic_json(args.output, payload)
    print("Coolify candidate patch-equivalence frozen")
    print(f"  physical candidates : {len(candidate_shas)}")
    print(f"  code-change units   : {len(groups)}")
    print(f"  duplicate groups    : {len(duplicate_groups)}")
    print(f"  confirmed physical  : {len(confirmed_candidates)}")
    print(f"  confirmed code units: {len(confirmed_identities)}")
    print(f"  output              : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
