#!/usr/bin/env python3
"""Join all local OSV GIT-introduced boundaries to explicit AI commits."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path

from cohort.advisories import index_advisory_observations
from cohort.relations import canonical_repository_identity, normalize_repository_aliases
from cohort.root_adjudication import canonical_sha256


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osv-dir", type=Path, required=True)
    parser.add_argument("--ai-scan", type=Path, required=True)
    parser.add_argument("--ai-summary", type=Path, required=True)
    parser.add_argument("--repository-aliases", type=Path, required=True)
    parser.add_argument("--alias-classes", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _alias_index(path: Path) -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            for public_id in row["member_ids"]:
                key = str(public_id).upper()
                if key in index and index[key]["class_id"] != row["class_id"]:
                    raise SystemExit(f"public ID belongs to multiple alias classes: {key}")
                index[key] = row
    return index


def join_matches(
    introduced_by_repo: Mapping[str, Iterable[Mapping[str, object]]],
    ai_rows: Iterable[Mapping[str, object]],
    *,
    aliases: Mapping[str, str],
    alias_by_public_id: Mapping[str, Mapping[str, object]],
) -> tuple[list[dict[str, object]], int]:
    """Return exact repository+SHA joins; OSV boundaries remain routing evidence."""

    introduced: defaultdict[
        tuple[str, str], dict[str, dict[str, object]]
    ] = defaultdict(dict)
    for raw_identity, observations in introduced_by_repo.items():
        identity = canonical_repository_identity(raw_identity, aliases)
        for raw in observations:
            sha = str(raw.get("introduced_sha") or "").lower()
            if not _SHA_RE.fullmatch(sha):
                continue
            observation = {
                "record_id": str(raw.get("record_id") or ""),
                "public_ids": sorted(
                    {str(value).upper() for value in raw.get("public_ids", [])}
                ),
                "published": str(raw.get("published") or ""),
                "source_repository_identity": raw_identity,
            }
            introduced[(identity, sha)][canonical_sha256(observation)] = observation

    matches: dict[tuple[str, str], dict[str, object]] = {}
    binding_digests: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    ai_row_count = 0
    for raw in ai_rows:
        ai_row_count += 1
        try:
            identity = canonical_repository_identity(
                str(raw.get("repository_identity") or ""), aliases
            )
        except ValueError:
            continue
        sha = str(raw.get("sha") or "").lower()
        key = (identity, sha)
        observations = introduced.get(key)
        if not observations or not raw.get("signal_types"):
            continue
        binding = dict(raw)
        digest = canonical_sha256(binding)
        if digest in binding_digests[key]:
            continue
        binding_digests[key].add(digest)
        if key not in matches:
            evidence = [observations[value] for value in sorted(observations)]
            public_ids = sorted(
                {
                    public_id
                    for observation in evidence
                    for public_id in observation["public_ids"]
                }
            )
            class_rows = {
                str(alias_by_public_id[public_id]["class_id"]): alias_by_public_id[
                    public_id
                ]
                for public_id in public_ids
                if public_id in alias_by_public_id
            }
            matches[key] = {
                "repository_identity": identity,
                "introduced_sha": sha,
                "public_ids": public_ids,
                "class_ids": sorted(class_rows),
                "active_class_ids": sorted(
                    class_id
                    for class_id, row in class_rows.items()
                    if "ACTIVE" in row.get("states", [])
                ),
                "introduction_observations": evidence,
                "ai_bindings": [],
                "history_boundary_source": "official_osv_git_range_introduced_event",
                "status": "ROUTING_ONLY",
            }
        matches[key]["ai_bindings"].append(binding)

    rows = [matches[key] for key in sorted(matches)]
    for row in rows:
        row["ai_bindings"].sort(key=canonical_sha256)
        row["merge_topologies"] = sorted(
            {str(binding.get("merge_topology") or "") for binding in row["ai_bindings"]}
        )
        row["atomicity_status"] = (
            "DIRECT_ATOMIC_AI_SIGNAL"
            if row["merge_topologies"] == ["direct"]
            else "SQUASH_CARRIER_REQUIRES_MEMBER_RESOLUTION"
        )
    return rows, ai_row_count


def main() -> int:
    args = _parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")

    alias_rows = json.loads(args.repository_aliases.read_text(encoding="utf-8"))[
        "aliases"
    ]
    aliases = normalize_repository_aliases(alias_rows)
    ai_summary = json.loads(args.ai_summary.read_text(encoding="utf-8"))
    repositories = {
        canonical_repository_identity(str(value), aliases)
        for value in ai_summary["scanned_repository_identities"]
    }
    join_identities = repositories | {
        alias for alias, canonical in aliases.items() if canonical in repositories
    }
    _fixes, introduced_by_repo, index_stats = index_advisory_observations(
        args.osv_dir,
        join_identities,
        cache_dir=args.cache_dir,
    )

    ai_digest = hashlib.sha256()

    def ai_rows() -> Iterable[dict[str, object]]:
        with args.ai_scan.open("rb") as handle:
            for line_number, line in enumerate(handle, start=1):
                ai_digest.update(line)
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{args.ai_scan}:{line_number} is not an object")
                yield row

    rows, ai_row_count = join_matches(
        introduced_by_repo,
        ai_rows(),
        aliases=aliases,
        alias_by_public_id=_alias_index(args.alias_classes),
    )
    direct = [row for row in rows if row["atomicity_status"] == "DIRECT_ATOMIC_AI_SIGNAL"]
    squash = [
        row
        for row in rows
        if row["atomicity_status"] == "SQUASH_CARRIER_REQUIRES_MEMBER_RESOLUTION"
    ]

    summary = {
        "schema_version": 1,
        "artifact_kind": "all_local_osv_introduced_ai_exact_join",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "ai_scan_row_count": ai_row_count,
        "ai_scan_sha256": ai_digest.hexdigest(),
        "ai_summary_sha256": _sha256_file(args.ai_summary),
        "repository_aliases_sha256": _sha256_file(args.repository_aliases),
        "alias_classes_sha256": _sha256_file(args.alias_classes),
        "osv_index_stats": index_stats,
        "exact_repo_sha_match_count": len(rows),
        "matched_repository_count": len({row["repository_identity"] for row in rows}),
        "matched_active_alias_class_count": len(
            {class_id for row in rows for class_id in row["active_class_ids"]}
        ),
        "direct_match_count": len(direct),
        "direct_active_alias_class_count": len(
            {class_id for row in direct for class_id in row["active_class_ids"]}
        ),
        "squash_carrier_match_count": len(squash),
        "squash_active_alias_class_count": len(
            {class_id for row in squash for class_id in row["active_class_ids"]}
        ),
        "matches_sha256": canonical_sha256(rows),
        "claim_boundary": (
            "Exact OSV introduced-SHA and explicit AI-commit joins are routing evidence. "
            "Direct commits still require mechanism validation; squash carriers require "
            "member-level resolution before any causal promotion."
        ),
    }

    args.output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{args.output_dir.name}.", dir=args.output_dir.parent
    ) as temporary:
        temporary_path = Path(temporary)
        with (temporary_path / "matches.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        (temporary_path / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary_path, args.output_dir)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
