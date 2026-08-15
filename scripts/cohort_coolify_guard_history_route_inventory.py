#!/usr/bin/env python3
"""Convert Coolify guard-history schedules into a lossless AI route inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path

from cohort.root_adjudication import canonical_sha256


_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PRIORITY_SIGNAL_RE = re.compile(r"^p\d+_")
_SUPPORTED_KINDS = {
    "coolify_guard_method_history_review_schedule": "guard_method_history",
    "coolify_guard_surface_history_review_schedule": "guard_surface_history",
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--schedule",
        type=Path,
        action="append",
        required=True,
        help="guard-history schedule; repeat to union independent lanes",
    )
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--label-neutral",
        action="store_true",
        help=(
            "remove adjudication-derived fields, priority classes, and ordering "
            "from the model-facing candidate inventory"
        ),
    )
    return parser.parse_args(argv)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object in {path}")
    return value


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_jsonl(path: Path, rows: Iterable[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _full_sha(value: object, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _FULL_SHA_RE.fullmatch(normalized):
        raise SystemExit(f"{label} must be a full Git SHA: {value!r}")
    return normalized


def _advisory(fix_sha: str) -> str:
    return f"COOLIFY-GUARD-FIX-{fix_sha.upper()}"


def _row_signal_values(row: Mapping[str, object], lane: str) -> set[str]:
    values = {lane, str(row.get("priority_class") or "unknown").casefold()}
    if int(row.get("candidate_exposure_line_count") or 0) > 0:
        values.add("candidate_exposure_delta")
    if row.get("whole_file_addition") is True:
        values.add("candidate_whole_file_addition")
    if row.get("candidate_merge_topology") == "merge_carrier_parent":
        values.add("merge_carrier_parent")
    return values


def _build_inventory(
    schedules: Iterable[tuple[str, Mapping[str, object]]],
    *,
    repository: Path,
    label_neutral: bool = False,
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, object]]:
    pair_rows: defaultdict[
        tuple[str, str, str], list[tuple[str, Mapping[str, object]]]
    ] = defaultdict(list)
    identities: set[str] = set()
    input_row_count = 0
    schedule_kinds: set[str] = set()

    for source, payload in schedules:
        kind = str(payload.get("artifact_kind") or "")
        if kind not in _SUPPORTED_KINDS:
            raise SystemExit(f"unsupported schedule kind in {source}: {kind!r}")
        lane = _SUPPORTED_KINDS[kind]
        schedule_kinds.add(kind)
        identity = str(payload.get("repository_identity") or "").strip().lower()
        if not identity:
            raise SystemExit(f"schedule has no repository identity: {source}")
        identities.add(identity)
        rows = payload.get("rows")
        if not isinstance(rows, list):
            raise SystemExit(f"schedule rows are malformed: {source}")
        for row in rows:
            if not isinstance(row, Mapping):
                raise SystemExit(f"schedule row is not an object: {source}")
            candidate_sha = _full_sha(row.get("candidate_sha"), "candidate sha")
            fix_sha = _full_sha(row.get("fix_sha"), "fix sha")
            if row.get("retained_for_review") is not True:
                raise SystemExit(f"schedule contains a non-retained row: {source}")
            pair_rows[(identity, fix_sha, candidate_sha)].append((lane, row))
            input_row_count += 1

    if len(identities) != 1:
        raise SystemExit(f"schedules disagree on repository identity: {identities}")
    identity = next(iter(identities))
    candidates: list[dict[str, object]] = []
    fix_metadata: defaultdict[tuple[str, str], list[Mapping[str, object]]] = (
        defaultdict(list)
    )
    known_candidate_coverage_pair_count = 0
    exact_status_counts: defaultdict[str, int] = defaultdict(int)

    for (row_identity, fix_sha, candidate_sha), sources in sorted(pair_rows.items()):
        rows = [row for _, row in sources]
        lanes = sorted({lane for lane, _ in sources})
        subjects = {str(row.get("candidate_subject") or "") for row in rows}
        if len(subjects) != 1:
            raise SystemExit(f"candidate subject conflict for {candidate_sha}")
        authored_dates = {
            str(row.get("candidate_authored_date") or "") for row in rows
        }
        authored_dates.discard("")
        merge_topologies = {
            str(row.get("candidate_merge_topology") or "") for row in rows
        }
        merge_topologies.discard("")
        paths = sorted({str(row.get("path") or "") for row in rows if row.get("path")})
        signals = sorted(
            set().union(
                *(
                    _row_signal_values(row, lane)
                    for lane, row in sources
                )
            )
        )
        if label_neutral:
            signals = [
                signal
                for signal in signals
                if not _PRIORITY_SIGNAL_RE.match(signal)
                and "confirmed" not in signal
                and "positive_control" not in signal
            ]
        known_candidate_coverage = any(
            row.get("candidate_confirmed_anywhere") is True for row in rows
        )
        known_candidate_coverage_pair_count += int(known_candidate_coverage)
        edge_statuses = {
            str(row.get("input_edge_status") or "UNSPECIFIED") for row in rows
        }
        if len(edge_statuses) != 1:
            raise SystemExit(
                f"input edge status conflict for {candidate_sha}->{fix_sha}"
            )
        input_edge_status = next(iter(edge_statuses))
        exact_status_counts[input_edge_status] += 1
        priority_tier = min(int(row.get("priority_tier") or 9) for row in rows)
        candidates.append(
            {
                "advisory": _advisory(fix_sha),
                "repository_identity": row_identity,
                "sha": candidate_sha,
                "fix_sha": fix_sha,
                "retained": True,
                "observed_ai_unit": True,
                "materialization": "exact_guard_history_pair",
                "priority_rank": 1 if label_neutral else priority_tier + 1,
                **(
                    {
                        "priority_class": min(
                            str(row.get("priority_class") or "") for row in rows
                        )
                    }
                    if not label_neutral
                    else {}
                ),
                "signals": signals,
                "signal_types": ["explicit_ai_signal"],
                "commit_subject": next(iter(subjects)),
                "fix_file_overlap": paths,
                "fix_file_overlap_count": len(paths),
                "changed_files": paths,
                "guard_history_lanes": lanes,
                "guard_history_source_row_count": len(sources),
                **(
                    {
                        "candidate_confirmed_anywhere": known_candidate_coverage,
                        "input_edge_status": input_edge_status,
                    }
                    if not label_neutral
                    else {}
                ),
                **(
                    {"authored_date": next(iter(authored_dates))}
                    if len(authored_dates) == 1
                    else {}
                ),
                **(
                    {"merge_topology": next(iter(merge_topologies))}
                    if len(merge_topologies) == 1
                    else {}
                ),
            }
        )
        fix_metadata[(row_identity, fix_sha)].extend(rows)

    fixes: list[dict[str, object]] = []
    for (row_identity, fix_sha), rows in sorted(fix_metadata.items()):
        subjects = {str(row.get("fix_subject") or "") for row in rows}
        if len(subjects) != 1:
            raise SystemExit(f"fix subject conflict for {fix_sha}")
        fixes.append(
            {
                "advisory": _advisory(fix_sha),
                "repository_identity": row_identity,
                "fix_sha": fix_sha,
                "status": "RESOLVED",
                "repository_path": str(repository),
                "fix_subject": next(iter(subjects)),
                "retained_candidate_count": sum(
                    candidate["fix_sha"] == fix_sha for candidate in candidates
                ),
            }
        )

    conservation = {
        "input_schedule_row_count": input_row_count,
        "unique_candidate_fix_pair_count": len(candidates),
        "duplicate_lane_or_hunk_row_count": input_row_count - len(candidates),
        "known_candidate_coverage_pair_count": known_candidate_coverage_pair_count,
        "candidate_not_yet_confirmed_pair_count": (
            len(candidates) - known_candidate_coverage_pair_count
        ),
        "exact_input_edge_status_counts": dict(sorted(exact_status_counts.items())),
        "all_input_rows_accounted_for": (
            sum(int(row["guard_history_source_row_count"]) for row in candidates)
            == input_row_count
        ),
        "hard_delete_count": 0,
        "passed": True,
    }
    conservation["passed"] = bool(conservation["all_input_rows_accounted_for"])
    metadata = {
        "repository_identity": identity,
        "schedule_kinds": sorted(schedule_kinds),
        "conservation": conservation,
    }
    return candidates, fixes, metadata


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    repository = args.repository.resolve()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise SystemExit(f"repository is not a Git checkout: {repository}")
    schedule_paths = [path.resolve() for path in args.schedule]
    schedule_inputs = [
        (str(path), _load_json(path)) for path in schedule_paths
    ]
    candidates, fixes, metadata = _build_inventory(
        schedule_inputs,
        repository=repository,
        label_neutral=args.label_neutral,
    )
    if not metadata["conservation"]["passed"]:  # type: ignore[index]
        raise SystemExit("guard-history inventory conservation failed")

    conservation = dict(metadata["conservation"])
    if args.label_neutral:
        for key in (
            "known_candidate_coverage_pair_count",
            "candidate_not_yet_confirmed_pair_count",
            "exact_input_edge_status_counts",
        ):
            conservation.pop(key, None)
        conservation.update(
            {
                "label_fields_removed_from_candidates": True,
                "adjudication_priority_removed_from_candidates": True,
                "candidate_order_key_label_independent": True,
            }
        )
    summary = {
        "schema_version": 1,
        "artifact_kind": "proof_carrying_origin_candidate_reduction",
        "split_id": (
            "coolify-guard-history-exact-pairs-label-neutral"
            if args.label_neutral
            else "coolify-guard-history-exact-pairs"
        ),
        "label_neutral": args.label_neutral,
        "repository_identity": metadata["repository_identity"],
        "candidate_count": len(candidates),
        "fix_count": len(fixes),
        "candidate_rows_sha256": canonical_sha256(candidates),
        "fix_rows_sha256": canonical_sha256(fixes),
        "all_candidates_retained": True,
        "schedule_inputs": [
            {
                "path": str(path),
                "sha256": _sha256_file(path),
                "artifact_kind": str(payload.get("artifact_kind") or ""),
                "row_count": len(payload.get("rows") or []),
            }
            for path, (_, payload) in zip(schedule_paths, schedule_inputs, strict=True)
        ],
        "conservation": conservation,
        "claim_boundary": (
            "This is a lossless, label-neutral model input. Exact adjudication "
            "fields and adjudication-derived priority are absent; labels must be "
            "joined from a separately frozen inventory only after routing. Model "
            "negatives remain retained, and only an exact source witness may change "
            "the causal ledger."
            if args.label_neutral
            else (
                "This is a lossless review inventory, not a causal adjudication. "
                "Known candidates remain as positive controls, model negatives remain "
                "retained, and only an exact source witness may change the causal ledger."
            )
        ),
    }
    args.output_dir.mkdir(parents=True)
    _atomic_jsonl(args.output_dir / "candidates.jsonl", candidates)
    _atomic_jsonl(args.output_dir / "fixes.jsonl", fixes)
    _atomic_json(args.output_dir / "summary.json", summary)
    print("Coolify guard-history route inventory frozen")
    print(f"  exact pairs : {len(candidates)}")
    print(f"  fixes       : {len(fixes)}")
    if args.label_neutral:
        print("  label fields: removed")
        print("  priority    : neutralized")
    else:
        print(
            "  new-candidate pairs: "
            f"{metadata['conservation']['candidate_not_yet_confirmed_pair_count']}"
        )
        print(
            "  known-candidate coverage pairs: "
            f"{metadata['conservation']['known_candidate_coverage_pair_count']}"
        )
    print(f"  output      : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
