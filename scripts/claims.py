#!/usr/bin/env python3
"""Append-only claim ledger for parallel case work: one writer per (class_id, slot)."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLAIMS = ROOT / "artifacts/claims/claims.jsonl"
DEFAULT_LEDGER = ROOT / "artifacts/funnel-account-20260817.jsonl"
OPEN_STATUSES = ("UNANALYZED", "PARTIALLY_ANALYZED")
DEFAULT_LEASE_HOURS = 24.0
DEFAULT_SLOT = "main"


class ClaimsError(Exception):
    """Refused claim operation."""


def _iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def state(events: list[dict], at: str | None = None) -> dict[tuple[str, str], dict]:
    """Reduce the append-only log to the current claim per (class_id, slot)."""
    at = at or _iso(datetime.now(timezone.utc))
    out: dict[tuple[str, str], dict] = {}
    for event in events:
        slot = event.get("slot", DEFAULT_SLOT)
        cur = out.setdefault((event["class_id"], slot), {"class_id": event["class_id"], "slot": slot})
        if event["action"] == "CLAIM":
            cur.update({
                "state": "ACTIVE",
                "owner": event["owner"],
                "run_id": event.get("run_id"),
                "scope": event.get("scope", ""),
                "claimed_at": event["ts"],
                "lease_until": event["lease_until"],
                "next_question": event.get("next_question", ""),
                "output_path": event.get("output_path", ""),
                "prev": event.get("prev"),
                "supersedes": event.get("supersedes"),
            })
        else:
            cur.update({
                "state": event["action"],
                "closed_by": event["owner"],
                "closed_at": event["ts"],
                "result": event.get("result", ""),
            })
    for cur in out.values():
        if cur.get("state") == "ACTIVE" and cur.get("lease_until", "") < at:
            cur["state"] = "STALE"
    return out


def open_rows(ledger: Path, statuses=OPEN_STATUSES):
    with Path(ledger).open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("status") in statuses:
                yield row


def _transact(path: Path, build):
    """Read-modify-append under an exclusive lock; nothing is written if build raises."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        fh.seek(0)
        events = [json.loads(line) for line in fh.read().splitlines() if line.strip()]
        new_events = build(state(events))
        for event in new_events:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
        fh.flush()
        return new_events


def _claim_event(class_id: str, slot: str, owner: str, hours: float, cur: dict | None, *,
                 scope: str = "", next_question: str = "", output_path: str = "",
                 run_id: str | None = None) -> dict:
    if cur and cur["state"] == "ACTIVE" and cur["owner"] != owner:
        raise ClaimsError(f"{class_id} slot {slot} held by {cur['owner']} until {cur['lease_until']}")
    now = datetime.now(timezone.utc)
    event = {
        "action": "CLAIM",
        "class_id": class_id,
        "slot": slot,
        "owner": owner,
        "run_id": run_id,
        "scope": scope,
        "ts": _iso(now),
        "lease_until": _iso(now + timedelta(hours=hours)),
        "next_question": next_question,
        "output_path": output_path,
    }
    if cur:
        if cur["state"] == "STALE":
            event["supersedes"] = cur["owner"]
        elif cur["state"] in ("DONE", "RELEASED"):
            event["prev"] = f"{cur['state']}:{cur.get('owner', '')}"
    return event


def claim(path: Path, class_id: str, owner: str, *, slot: str = DEFAULT_SLOT, scope: str = "",
          hours: float = DEFAULT_LEASE_HOURS, next_question: str = "", output_path: str = "",
          run_id: str | None = None) -> dict:
    """Take or refresh a (class_id, slot); refuses an unexpired claim held by someone else."""
    events = _transact(path, lambda current: [
        _claim_event(class_id, slot, owner, hours, current.get((class_id, slot)),
                     scope=scope, next_question=next_question, output_path=output_path, run_id=run_id)
    ])
    return events[0]


def pick(path: Path, ledger: Path, owner: str, *, limit: int = 1, slot: str = DEFAULT_SLOT,
         scope: str = "", statuses=OPEN_STATUSES, hours: float = DEFAULT_LEASE_HOURS,
         next_question: str = "", run_id: str | None = None) -> list[dict]:
    """Claim the first <limit> cases in ledger order that nobody holds in <slot>."""
    rows = list(open_rows(ledger, statuses))

    def build(current):
        taken = {key for key, cur in current.items() if cur["state"] == "ACTIVE"}
        events = []
        for row in rows:
            if len(events) >= limit:
                break
            key = (row["class_id"], slot)
            if key in taken:
                continue
            events.append(_claim_event(row["class_id"], slot, owner, hours, current.get(key),
                                       scope=scope, next_question=next_question, run_id=run_id))
            taken.add(key)
        return events

    return _transact(path, build)


def close(path: Path, class_id: str, owner: str, action: str, *, slot: str = DEFAULT_SLOT,
          result: str = "") -> dict:
    """Finish (DONE) or hand back (RELEASED) a claim; the holder only."""
    def build(current):
        cur = current.get((class_id, slot))
        if not cur or cur["state"] not in ("ACTIVE", "STALE"):
            raise ClaimsError(f"{class_id} slot {slot} has no open claim")
        if cur["owner"] != owner:
            raise ClaimsError(f"{class_id} slot {slot} held by {cur['owner']}, not {owner}")
        return [{"action": action, "class_id": class_id, "slot": slot, "owner": owner,
                 "ts": _iso(datetime.now(timezone.utc)), "result": result}]

    return _transact(path, build)[0]


def _owner(args) -> str:
    owner = args.owner or os.environ.get("CLAIM_OWNER")
    if not owner:
        raise ClaimsError("pass --owner or set CLAIM_OWNER")
    return owner


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claims-file", type=Path, default=DEFAULT_CLAIMS)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    sub = parser.add_subparsers(dest="cmd", required=True)

    take = sub.add_parser("claim", help="claim one known class_id")
    take.add_argument("--class-id", required=True)
    take.add_argument("--slot", default=DEFAULT_SLOT)
    take.add_argument("--scope", default="")
    take.add_argument("--next-question", default="")
    take.add_argument("--output-path", default="")
    take.add_argument("--run-id")
    take.add_argument("--hours", type=float, default=DEFAULT_LEASE_HOURS)
    take.add_argument("--owner", default="")

    auto = sub.add_parser("pick", help="claim the next unclaimed open cases of a batch")
    auto.add_argument("--scope", required=True, help="agent-independent batch label")
    auto.add_argument("--limit", type=int, default=1)
    auto.add_argument("--slot", default=DEFAULT_SLOT)
    auto.add_argument("--status", action="append", default=None)
    auto.add_argument("--next-question", default="")
    auto.add_argument("--run-id")
    auto.add_argument("--hours", type=float, default=DEFAULT_LEASE_HOURS)
    auto.add_argument("--owner", default="")

    listing = sub.add_parser("list", help="show claims (open by default)")
    listing.add_argument("--owner")
    listing.add_argument("--scope")
    listing.add_argument("--slot")
    listing.add_argument("--all", action="store_true")

    for name, help_text in (("done", "close with a recorded result"), ("release", "hand the case back")):
        closer = sub.add_parser(name, help=help_text)
        closer.add_argument("--class-id", required=True)
        closer.add_argument("--slot", default=DEFAULT_SLOT)
        closer.add_argument("--result", default="")
        closer.add_argument("--owner", default="")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "claim":
            event = claim(args.claims_file, args.class_id, _owner(args), slot=args.slot, scope=args.scope,
                          hours=args.hours, next_question=args.next_question,
                          output_path=args.output_path, run_id=args.run_id)
            print(f"{event['class_id']} slot {event['slot']} claimed by {event['owner']} until {event['lease_until']}")
        elif args.cmd == "pick":
            statuses = tuple(args.status) if args.status else OPEN_STATUSES
            events = pick(args.claims_file, args.ledger, _owner(args), limit=args.limit, slot=args.slot,
                          scope=args.scope, statuses=statuses, hours=args.hours,
                          next_question=args.next_question, run_id=args.run_id)
            for event in events:
                print(f"{event['class_id']} slot {event['slot']} claimed by {event['owner']} until {event['lease_until']}")
            if not events:
                print("no unclaimed open cases", file=sys.stderr)
        elif args.cmd == "list":
            for (class_id, slot), cur in sorted(state(load(args.claims_file)).items()):
                if args.owner and cur.get("owner") != args.owner:
                    continue
                if args.scope and cur.get("scope") != args.scope:
                    continue
                if args.slot and slot != args.slot:
                    continue
                if not args.all and cur["state"] in ("DONE", "RELEASED"):
                    continue
                print("\t".join([class_id, slot, cur["state"], cur.get("owner", ""),
                                 cur.get("lease_until", ""), cur.get("scope", ""), cur.get("next_question", "")]))
        else:
            action = "DONE" if args.cmd == "done" else "RELEASED"
            event = close(args.claims_file, args.class_id, _owner(args), action, slot=args.slot, result=args.result)
            print(f"{event['class_id']} slot {event['slot']} {event['action']} by {event['owner']}")
    except ClaimsError as exc:
        print(f"claims: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
