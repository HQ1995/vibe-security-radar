#!/usr/bin/env python3
"""Attach recall-first source hints to a frozen prospective all-commit universe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cohort.fix_sources import (
    FixSourceContractError,
    load_description_search_sources,
    public_fix_observations,
    resolve_source_observations,
    scan_repository_reference_carriers,
)
from cohort.relations import normalize_repository_aliases
from cohort.root_masks import (
    RootMaskContractError,
    build_repository_root_masks,
    canonical_sha256,
)


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_DESCRIPTION_SEARCH = Path.home() / ".cache/cve-analyzer/desc-search"
DEFAULT_CVELIST = Path.home() / ".cache/cve-analyzer/cvelistV5/cves"
DEFAULT_PUBLIC_REFERENCES = (
    _REPO_ROOT
    / ".ai-slop/state/cohort-v1/advisory-candidates-controls-20260731-v1"
    / "public_fix_references.jsonl"
)
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intake-dir", type=Path, required=True)
    parser.add_argument("--universe-dir", type=Path, required=True)
    parser.add_argument(
        "--description-search-dir", type=Path, default=DEFAULT_DESCRIPTION_SEARCH
    )
    parser.add_argument("--cvelist-dir", type=Path, default=DEFAULT_CVELIST)
    parser.add_argument(
        "--public-references", type=Path, default=DEFAULT_PUBLIC_REFERENCES
    )
    parser.add_argument("--repository-aliases", type=Path, default=DEFAULT_ALIASES)
    parser.add_argument("--repo-timeout", type=int, default=300)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _jsonl_text(rows: list[dict[str, object]]) -> str:
    return "".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows
    )


def _aliases(path: Path) -> dict[str, str]:
    payload = _load_json(path)
    rows = payload.get("aliases") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or not isinstance(rows, list)
    ):
        raise SystemExit("repository aliases are malformed")
    try:
        return normalize_repository_aliases(rows)
    except ValueError as exc:
        raise SystemExit(f"repository aliases are malformed: {exc}") from exc


def _selected(intake_dir: Path) -> list[dict[str, object]]:
    intake = _load_json(intake_dir / "intake.json")
    rows = _load_jsonl(intake_dir / "selected.jsonl")
    if (
        not isinstance(intake, dict)
        or intake.get("gate_status") != "READY_FOR_HISTORY_ENUMERATION"
        or intake.get("selected") != rows
    ):
        raise SystemExit("prospective intake is not frozen and ready")
    return rows


def _repository_views(
    universe_summary: Mapping[str, object],
) -> tuple[dict[str, Path], dict[str, list[str]]]:
    repositories: dict[str, Path] = {}
    global_arguments: dict[str, list[str]] = {}
    raw_rows = universe_summary.get("repository_provenance")
    if not isinstance(raw_rows, list):
        raise SystemExit("universe repository provenance is malformed")
    for raw in raw_rows:
        if not isinstance(raw, dict):
            raise SystemExit("universe repository provenance is malformed")
        identity = str(raw.get("repository_identity") or "").strip().lower()
        path = Path(str(raw.get("repository_path") or ""))
        if not identity or not path.is_dir():
            raise SystemExit(f"universe repository path is unavailable: {identity}")
        repositories[identity] = path
        if raw.get("history_view") == (
            "complete_local_object_graph_ignoring_shallow_marker"
        ):
            global_arguments[identity] = ["--shallow-file", ""]
    return repositories, global_arguments


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.repo_timeout < 1:
        raise SystemExit("repo-timeout must be positive")
    selected = _selected(args.intake_dir)
    selected_pairs = {
        (
            str(row["repository_identity"]).strip().lower(),
            str(row["advisory"]).strip(),
        )
        for row in selected
    }
    identities = {pair[0] for pair in selected_pairs}
    aliases = _aliases(args.repository_aliases)
    universe_campaign = _load_json(args.universe_dir / "summary.json")
    if not isinstance(universe_campaign, dict):
        raise SystemExit("all-commit universe summary is malformed")
    repositories, git_global_arguments = _repository_views(universe_campaign)
    if set(repositories) != identities:
        raise SystemExit("universe repositories do not match frozen intake")

    description_sources = load_description_search_sources(
        args.description_search_dir,
        identities,
        aliases,
        cvelist_dir=args.cvelist_dir,
    )
    associations = [
        dict(row)
        for row in description_sources["associations"]
        if (
            str(row.get("repository_identity") or "").strip().lower(),
            str(row.get("advisory") or "").strip(),
        )
        in selected_pairs
    ]
    description_observations = [
        dict(row)
        for row in description_sources["observations"]
        if (
            str(row.get("repository_identity") or "").strip().lower(),
            str(row.get("advisory") or "").strip(),
        )
        in selected_pairs
    ]
    if {
        (
            str(row.get("repository_identity") or "").strip().lower(),
            str(row.get("advisory") or "").strip(),
        )
        for row in associations
    } != selected_pairs:
        raise SystemExit("selected advisory association conservation failed")

    public_rows = [
        row
        for row in _load_jsonl(args.public_references)
        if (
            str(row.get("repository_identity") or "").strip().lower(),
            str(row.get("advisory") or "").strip(),
        )
        in selected_pairs
        and len(str(row.get("fix_sha") or "").strip()) == 40
    ]
    try:
        public_observations = public_fix_observations(public_rows)
        carrier_observations, carrier_stats = scan_repository_reference_carriers(
            repositories,
            associations,
            timeout=args.repo_timeout,
            git_global_arguments_by_repository=git_global_arguments,
        )
        combined = {
            str(row["observation_id"]): dict(row)
            for row in [
                *public_observations,
                *description_observations,
                *carrier_observations,
            ]
        }
        observations, _fixes_by_repo, resolution_stats = resolve_source_observations(
            [combined[key] for key in sorted(combined)],
            repositories,
            timeout=args.repo_timeout,
        )
    except FixSourceContractError as exc:
        raise SystemExit(f"prospective fix-source contract failed: {exc}") from exc

    summaries = _load_jsonl(args.universe_dir / "repository_universes.jsonl")
    summary_by_repository = {
        str(row["repository_identity"]): row for row in summaries
    }
    commits_by_repository: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in _load_jsonl(args.universe_dir / "commit_universe.jsonl"):
        commits_by_repository[str(row["repository_identity"])].append(row)
    observations_by_repository: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in observations:
        observations_by_repository[str(row["repository_identity"])].append(row)

    root_rows: list[dict[str, object]] = []
    membership_rows: list[dict[str, object]] = []
    blocked_observations: list[dict[str, object]] = []
    mask_summaries: list[dict[str, object]] = []
    try:
        for identity in sorted(identities):
            built = build_repository_root_masks(
                summary_by_repository[identity],
                commits_by_repository[identity],
                observations_by_repository[identity],
            )
            root_rows.extend(dict(row) for row in built["root_rows"])
            membership_rows.extend(dict(row) for row in built["membership_rows"])
            blocked_observations.extend(
                dict(row) for row in built["blocked_observations"]
            )
            mask_summaries.append(dict(built["summary"]))
    except RootMaskContractError as exc:
        raise SystemExit(f"source-root mask contract failed: {exc}") from exc

    root_rows.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            int(row["bit_index"]),
        )
    )
    membership_rows.sort(
        key=lambda row: (str(row["repository_identity"]), str(row["sha"]))
    )
    blocked_observations.sort(key=lambda row: str(row["observation_id"]))
    evidence_counts = Counter(str(row.get("evidence_kind") or "") for row in observations)
    selected_with_resolved_root = {
        (str(row["repository_identity"]), advisory)
        for row in root_rows
        for advisory in row["advisories"]
    }
    fallback_rows = _load_jsonl(args.universe_dir / "repository_fallbacks.jsonl")
    fallback_pairs = {
        (str(row["repository_identity"]), str(row["advisory"]))
        for row in fallback_rows
    }
    if fallback_pairs != selected_pairs:
        raise SystemExit("source-independent fallback conservation failed")

    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_write(
        args.output_dir / "repository_advisory_associations.jsonl",
        _jsonl_text(associations),
    )
    _atomic_write(
        args.output_dir / "fix_source_observations.jsonl",
        _jsonl_text(observations),
    )
    _atomic_write(args.output_dir / "source_roots.jsonl", _jsonl_text(root_rows))
    _atomic_write(
        args.output_dir / "root_membership.jsonl", _jsonl_text(membership_rows)
    )
    _atomic_write(
        args.output_dir / "blocked_source_observations.jsonl",
        _jsonl_text(blocked_observations),
    )
    _atomic_write(
        args.output_dir / "repository_root_masks.jsonl",
        _jsonl_text(mask_summaries),
    )
    summary = {
        "schema_version": 1,
        "artifact_kind": "prospective_zero_token_source_replay",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "claim_boundary": (
            "Public exact roots, cached enriched selections, ranked search rows, and "
            "repository-message carriers are candidate root hints, not causal labels. "
            "Their ancestry is a compressed prioritization overlay. All-commit "
            "repository fallbacks remain unchanged, including for missing or wrong "
            "roots; BLOCKED is unknown, never negative."
        ),
        "selected_pair_count": len(selected_pairs),
        "association_count": len(associations),
        "source_observation_count": len(observations),
        "source_observation_status_counts": dict(
            sorted(Counter(str(row["resolution_status"]) for row in observations).items())
        ),
        "source_evidence_kind_counts": dict(sorted(evidence_counts.items())),
        "resolved_root_hint_count": len(root_rows),
        "resolved_root_coverage_count": sum(
            row["status"] == "RESOLVED" for row in root_rows
        ),
        "blocked_root_coverage_count": sum(
            row["status"] == "BLOCKED" for row in root_rows
        ),
        "pairs_with_resolved_source_root_count": len(
            selected_pairs & selected_with_resolved_root
        ),
        "pairs_without_resolved_source_root_count": len(
            selected_pairs - selected_with_resolved_root
        ),
        "root_membership_row_count": len(membership_rows),
        "fallback_count": len(fallback_rows),
        "carrier_scan_stats": carrier_stats,
        "source_resolution_stats": resolution_stats,
        "conservation": {
            "selected_associations_conserved": len(associations) == len(selected_pairs),
            "source_observations_conserved": (
                len(observations)
                == sum(
                    1
                    for _row in observations
                    if _row["resolution_status"] in {"RESOLVED", "BLOCKED"}
                )
            ),
            "repository_fallbacks_conserved": fallback_pairs == selected_pairs,
            "fallback_scope_unchanged": all(
                row["fallback_scope_unchanged"] is True for row in mask_summaries
            ),
        },
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
        "associations_sha256": canonical_sha256(associations),
        "source_observations_sha256": canonical_sha256(observations),
        "source_roots_sha256": canonical_sha256(root_rows),
        "root_membership_sha256": canonical_sha256(membership_rows),
        "repository_root_masks_sha256": canonical_sha256(mask_summaries),
        "input_provenance": {
            "intake_selected_path": str(
                (args.intake_dir / "selected.jsonl").resolve()
            ),
            "intake_selected_sha256": _sha256_file(
                args.intake_dir / "selected.jsonl"
            ),
            "universe_summary_path": str(
                (args.universe_dir / "summary.json").resolve()
            ),
            "universe_summary_sha256": _sha256_file(
                args.universe_dir / "summary.json"
            ),
            "commit_universe_path": str(
                (args.universe_dir / "commit_universe.jsonl").resolve()
            ),
            "commit_universe_sha256": _sha256_file(
                args.universe_dir / "commit_universe.jsonl"
            ),
            "public_references_path": str(args.public_references.resolve()),
            "public_references_sha256": _sha256_file(args.public_references),
            "description_search_dir": str(args.description_search_dir.resolve()),
            "repository_aliases_path": str(args.repository_aliases.resolve()),
            "repository_aliases_sha256": _sha256_file(args.repository_aliases),
        },
    }
    summary["summary_sha256"] = canonical_sha256(summary)
    _atomic_write(args.output_dir / "summary.json", _json_text(summary))
    print("prospective zero-token source replay completed")
    print(f"  selected pairs        : {len(selected_pairs)}")
    print(f"  source observations   : {len(observations)}")
    print(f"  root hints            : {len(root_rows)}")
    print(f"  root membership rows  : {len(membership_rows):,}")
    print(f"  repository fallbacks  : {len(fallback_rows)}")
    print("  model calls           : 0")
    print(f"  output                : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
