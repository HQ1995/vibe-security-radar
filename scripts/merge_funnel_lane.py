#!/usr/bin/env python3
"""Merge lane outputs into the funnel ledger with atomic write and schema check.

Usage:
  merge_funnel_lane.py LEDGER LANE_OUTPUT... [--check-only] [--status STATUS]

Each LANE_OUTPUT is a JSON array or JSONL where every item carries a
``class_id`` and the fields the lane wants to record on that case (e.g.
``status``, ``reason``, ``fix_sha``).  Matching is by ``class_id`` only:
ledger rows do not carry public IDs, so a lane item without ``class_id`` is
rejected.

Merge semantics (leader-only, serialized by flock):
  * Fields of a lane item are upserted onto the row; existing row fields
    that the lane does not mention are preserved.
  * A lane item without ``status`` leaves the row status untouched.
  * Unknown class_id creates a new UNANALYZED row.
  * Two lane items that claim the same class_id with different status are a
    conflict: the merge aborts and nothing is written.
  * The merged ledger is validated before writing: every line parses,
    class_id is non-empty and unique, status is known, and no row is lost.
  * Write is atomic (tmp file + os.replace), so readers never see a torn
    ledger.

--check-only validates and prints the summary without writing.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import sys
from pathlib import Path

KNOWN_STATUS = {
    "UNANALYZED",
    "PARTIALLY_ANALYZED",
    "NOT_AI",
    "AI_ROOT_CAUSE",
    "AI_CODE_FLAWED",
    "BLOCKED",
}


def load_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"{path}: non-object row: {line[:80]}")
        rows.append(row)
    return rows


def load_lane_items(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        payload = json.loads(text)
        if not isinstance(payload, list):
            raise ValueError(f"{path}: expected JSON array")
        return payload
    items = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError(f"{path}: non-object lane item")
        items.append(item)
    return items


def row_identity(row: dict) -> set[str]:
    """Official advisory identities a TP row claims.

    Dedup happens at ledger level: two terminal-TP rows that claim the
    same vulnerability must not both exist. Sources, in order:
    advisory_identity.member_ids, roundN_research advisory_ids,
    squash_audit[*].case_id.
    """
    ids: set[str] = set()
    identity = row.get("advisory_identity") or {}
    for value in identity.get("member_ids") or []:
        ids.add(str(value).upper())
    for key, value in row.items():
        if key.endswith("_research") and isinstance(value, dict):
            for item in value.get("advisory_ids") or []:
                ids.add(str(item).upper())
    audit = row.get("squash_audit") or []
    if isinstance(audit, list):
        for item in audit:
            if isinstance(item, dict) and item.get("case_id"):
                ids.add(str(item["case_id"]).upper())
    return ids


def detect_duplicate_tps(rows: list[dict]) -> list[str]:
    """Find terminal-TP rows that claim the same advisory identity."""
    terminal = {"AI_ROOT_CAUSE", "AI_CODE_FLAWED"}
    owners: dict[str, str] = {}
    problems: list[str] = []
    for row in rows:
        if row.get("status") not in terminal:
            continue
        if (row.get("site_publication") or {}).get("publish") is False:
            continue
        class_id = str(row.get("class_id") or "")
        for oid in row_identity(row):
            if oid in owners and owners[oid] != class_id:
                problems.append(
                    f"{oid}: claimed by both {owners[oid]} and {class_id} "
                    f"(dedup must happen at ledger level, not at publish)"
                )
            owners[oid] = class_id
    return problems


def validate_rows(rows: list[dict], path: str) -> list[str]:
    errors: list[str] = []
    seen: dict[str, int] = {}
    for idx, row in enumerate(rows):
        class_id = str(row.get("class_id") or "")
        if not class_id:
            errors.append(f"row {idx}: missing class_id")
            continue
        if class_id in seen:
            errors.append(f"row {idx}: duplicate class_id {class_id} (also row {seen[class_id]})")
        seen[class_id] = idx
        status = row.get("status")
        if status not in KNOWN_STATUS:
            errors.append(f"row {idx} ({class_id}): unknown status {status!r}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path, help="path to the funnel ledger JSONL")
    parser.add_argument("lane_outputs", type=Path, nargs="*", help="lane result JSON/JSONL files")
    parser.add_argument("--check-only", action="store_true", help="validate without writing")
    args = parser.parse_args()

    if not args.ledger.is_file():
        print(f"error: ledger not found: {args.ledger}", file=sys.stderr)
        return 2

    lock_path = args.ledger.with_suffix(args.ledger.suffix + ".lock")
    lock_fd = lock_path.open("a+")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)

    try:
        rows = load_rows(args.ledger)
        before = {str(r.get("class_id") or "") for r in rows if r.get("class_id")}

        updated = 0
        created = 0
        conflicts: list[str] = []
        lane_items = 0
        for path in args.lane_outputs:
            items = load_lane_items(path)
            lane_items += len(items)
            for item in items:
                class_id = str(item.get("class_id") or "")
                if not class_id:
                    conflicts.append(f"{path}: item without class_id: {json.dumps(item)[:120]}")
                    continue
                lane_status = item.get("status")
                if lane_status is not None and lane_status not in KNOWN_STATUS:
                    conflicts.append(
                        f"{path}: {class_id}: unknown status {lane_status!r}"
                    )
                    continue
                if class_id in before:
                    row = next(r for r in rows if r.get("class_id") == class_id)
                    if (
                        lane_status is not None
                        and row.get("status") not in (None, lane_status)
                        and row.get("status") != lane_status
                    ):
                        conflicts.append(
                            f"{path}: {class_id}: status conflict "
                            f"{row.get('status')!r} vs {lane_status!r}"
                        )
                        continue
                    for key, value in item.items():
                        if key == "class_id":
                            continue
                        row[key] = value
                    updated += 1
                else:
                    row = {"class_id": class_id, "status": lane_status or "UNANALYZED"}
                    for key, value in item.items():
                        if key != "class_id":
                            row[key] = value
                    rows.append(row)
                    before.add(class_id)
                    created += 1

        if conflicts:
            print("merge aborted, nothing written:", file=sys.stderr)
            for line in conflicts[:20]:
                print(f"  {line}", file=sys.stderr)
            if len(conflicts) > 20:
                print(f"  ... and {len(conflicts) - 20} more", file=sys.stderr)
            return 1

        dupes = detect_duplicate_tps(rows)
        if dupes:
            print("duplicate TP rows detected, nothing written:", file=sys.stderr)
            for line in dupes[:20]:
                print(f"  {line}", file=sys.stderr)
            if len(dupes) > 20:
                print(f"  ... and {len(dupes) - 20} more", file=sys.stderr)
            return 1

        errors = validate_rows(rows, str(args.ledger))
        if errors:
            print("schema check failed, nothing written:", file=sys.stderr)
            for line in errors[:20]:
                print(f"  {line}", file=sys.stderr)
            if len(errors) > 20:
                print(f"  ... and {len(errors) - 20} more", file=sys.stderr)
            return 1

        print(
            json.dumps(
                {
                    "ledger": str(args.ledger),
                    "rows_before": len(rows) - created,
                    "rows_after": len(rows),
                    "lane_items": lane_items,
                    "updated": updated,
                    "created": created,
                    "check_only": args.check_only,
                }
            )
        )

        if args.check_only:
            return 0

        tmp = args.ledger.with_suffix(args.ledger.suffix + ".tmp")
        tmp.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )
        tmp.replace(args.ledger)
        return 0
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


if __name__ == "__main__":
    sys.exit(main())
