#!/usr/bin/env python3
"""Build a public-exact squash seed without treating routing as causality."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path

from cohort_atomic_same_file_screen import _atomic_json, _atomic_jsonl, _jsonl


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--fix-source-observations", type=Path, required=True)
    parser.add_argument("--alias-classes", type=Path, required=True)
    parser.add_argument("--excluded-public-ids", type=Path, required=True)
    parser.add_argument("--excluded-adjudications", type=Path, action="append", default=[])
    parser.add_argument("--member-scope", choices=("single", "multi"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_rows(
    candidates: Iterable[Mapping[str, object]],
    *,
    aliases_by_id: Mapping[str, str],
    public_exact: set[tuple[str, str, str]],
    excluded_class_ids: set[str],
    excluded_public_ids: set[str],
    member_scope: str,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for raw in candidates:
        member_count = raw.get("n_members")
        if (
            raw.get("route") != "assistant_squash"
            or raw.get("merge_topology") != "squash"
            or raw.get("tier") != "B_decomposed"
            or raw.get("root_coverage_status") != "RESOLVED"
            or raw.get("squash_attribution_only") is True
            or not isinstance(member_count, int)
            or (member_count != 1 if member_scope == "single" else member_count <= 1)
        ):
            continue
        identity = str(raw.get("repository_identity") or "")
        fix_sha = str(raw.get("fix_sha") or "").lower()
        advisories = [
            dict(value)
            for value in raw.get("advisories", [])
            if isinstance(value, Mapping)
            and (public_id := str(value.get("id") or "").upper())
            and public_id not in excluded_public_ids
            and aliases_by_id.get(public_id) not in excluded_class_ids
        ]
        if not any(
            (identity, str(advisory["id"]).upper(), fix_sha) in public_exact
            for advisory in advisories
        ):
            continue
        row = dict(raw)
        row["advisories"] = advisories
        rows.append(row)
    return rows


def main() -> int:
    args = _parse_args()
    if args.output_dir.exists():
        raise SystemExit("output directory must be new")
    alias_rows = list(_jsonl(args.alias_classes))
    aliases_by_id = {
        str(public_id).upper(): str(row["class_id"])
        for row in alias_rows
        for public_id in row.get("member_ids", [])
    }
    excluded_public_ids = {
        str(value).upper()
        for value in json.loads(args.excluded_public_ids.read_text(encoding="utf-8"))
    }
    excluded_class_ids = {
        aliases_by_id[public_id]
        for public_id in excluded_public_ids
        if public_id in aliases_by_id
    }
    for path in args.excluded_adjudications:
        payload = json.loads(path.read_text(encoding="utf-8"))
        excluded_class_ids.update(
            str(row["class_id"])
            for row in payload.get("adjudications", [])
            if isinstance(row, Mapping) and row.get("class_id")
        )
    for row in alias_rows:
        if str(row["class_id"]) in excluded_class_ids:
            excluded_public_ids.update(str(value).upper() for value in row.get("member_ids", []))
    public_exact = {
        (
            str(row.get("repository_identity") or ""),
            str(row.get("advisory") or "").upper(),
            str(row.get("fix_sha") or "").lower(),
        )
        for row in _jsonl(args.fix_source_observations)
        if row.get("resolution_status") == "RESOLVED"
        and row.get("evidence_kind") == "public_exact"
    }
    rows = select_rows(
        _jsonl(args.candidates),
        aliases_by_id=aliases_by_id,
        public_exact=public_exact,
        excluded_class_ids=excluded_class_ids,
        excluded_public_ids=excluded_public_ids,
        member_scope=args.member_scope,
    )
    args.output_dir.mkdir(parents=True)
    _atomic_jsonl(args.output_dir / "candidates.jsonl", rows)
    _atomic_json(args.output_dir / "excluded-public-ids.json", sorted(excluded_public_ids))
    summary = {
        "schema_version": 1,
        "artifact_kind": "assistant_squash_public_exact_seed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "member_scope": args.member_scope,
        "candidate_edge_count": len(rows),
        "squash_root_count": len({(row["repository_identity"], row["candidate_sha"]) for row in rows}),
        "repository_count": len({row["repository_identity"] for row in rows}),
        "public_id_count": len({str(a["id"]).upper() for row in rows for a in row["advisories"]}),
        "excluded_class_count": len(excluded_class_ids),
        "candidates_file_sha256": _sha256(args.output_dir / "candidates.jsonl"),
        "selection_boundary": (
            "resolved exposure-decomposed assistant squash plus public_exact fix; "
            "previously adjudicated alias classes excluded; routing only until "
            "PR-member recovery and causal review"
        ),
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
