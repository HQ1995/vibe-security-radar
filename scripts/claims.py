#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLAIMS = ROOT / "artifacts/claims/claims.jsonl"
DEFAULT_LEASE_HOURS = 24.0
DEFAULT_SLOT = "main"


class ClaimsError(Exception):
    pass


def _iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: Path) -> list[dict]:
    try:
        with Path(path).open(encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            return [json.loads(line) for line in fh if line.strip()]
    except FileNotFoundError:
        return []


def state(events: list[dict], at: str | None = None) -> dict[tuple[str, str], dict]:
    at = at or _iso(datetime.now(timezone.utc))
    current = {}
    for event in events:
        key = (event["class_id"], event.get("slot", DEFAULT_SLOT))
        if event["action"] == "CLAIM":
            legacy = not event.get("claim_id")
            token = event.get("claim_id") or "legacy-" + hashlib.sha256(
                json.dumps(event, sort_keys=True).encode()
            ).hexdigest()
            prior = current.get(key)
            if prior and prior["claimed"] and not prior["legacy"] and (
                token != prior["claim_id"] or event["owner"] != prior["owner"]
                or event.get("scope", "") != prior["scope"]
            ):
                raise ClaimsError(f"{key}: cannot replace an unreleased claim")
            current[key] = {
                "class_id": key[0], "slot": key[1], "claimed": True,
                "owner": event["owner"], "scope": event.get("scope", ""),
                "claim_id": token, "legacy": legacy,
                "claimed_at": event.get("claimed_at", event["ts"]),
                "lease_until": event.get("lease_until", ""),
            }
        elif event["action"] in ("DONE", "RELEASED", "RELEASE"):
            cur = current.get(key)
            if cur is None:
                raise ClaimsError(f"{key}: release without a preceding claim")
            token = event.get("claim_id")
            if (token and token != cur["claim_id"]) or (not token and not cur["legacy"]):
                raise ClaimsError(f"{key}: release does not match the current claim_id")
            if token and event["owner"] != cur["owner"]:
                raise ClaimsError(f"{key}: release owner does not match")
            cur["claimed"] = False
        else:
            raise ClaimsError(f"unknown claim action: {event['action']}")
    for cur in current.values():
        cur["expired"] = bool(cur["claimed"] and cur["lease_until"] and cur["lease_until"] <= at)
    return current


def _transact(path: Path, build):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        fh.seek(0)
        current = state([json.loads(line) for line in fh if line.strip()])
        event = build(current)
        if event is not None:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return event


def claim(path: Path, class_id: str, owner: str, *, scope: str,
          claim_id: str | None = None, hours: float = DEFAULT_LEASE_HOURS,
          slot: str = DEFAULT_SLOT) -> dict:
    if not all(isinstance(value, str) and value.strip() for value in (class_id, owner, scope)):
        raise ClaimsError("class_id, owner and scope must be nonempty")
    if slot != DEFAULT_SLOT:
        raise ClaimsError("new slot claims are disabled; the leader claims the whole case")
    if not math.isfinite(hours) or hours <= 0:
        raise ClaimsError("hours must be finite and positive")

    def build(current):
        held = [cur for (cid, _), cur in current.items() if cid == class_id and cur["claimed"]]
        cur = current.get((class_id, DEFAULT_SLOT))
        if claim_id:
            if (len(held) != 1 or not cur or not cur["claimed"] or cur["legacy"]
                    or cur["owner"] != owner or cur["scope"] != scope or cur["claim_id"] != claim_id):
                raise ClaimsError("renewal must match the current owner, scope and claim_id")
        elif held:
            detail = "; ".join(f"{c['owner']} (slot {c['slot']})" for c in held)
            raise ClaimsError(f"{class_id} already claimed by {detail}; expiry does not release it")
        now = datetime.now(timezone.utc)
        try:
            until = _iso(now + timedelta(hours=hours))
        except OverflowError as exc:
            raise ClaimsError("hours exceeds the supported lease range") from exc
        return {
            "action": "CLAIM", "class_id": class_id, "slot": DEFAULT_SLOT,
            "owner": owner, "scope": scope, "claim_id": claim_id or str(uuid.uuid4()),
            "ts": _iso(now), "claimed_at": cur["claimed_at"] if claim_id else _iso(now),
            "lease_until": until,
        }

    return _transact(path, build)


def release(path: Path, class_id: str, owner: str, *, claim_id: str | None = None,
            slot: str = DEFAULT_SLOT) -> dict | None:
    def build(current):
        cur = current.get((class_id, slot))
        if not cur or cur["owner"] != owner:
            raise ClaimsError(f"{class_id} slot {slot}: no claim held by {owner}")
        if (not claim_id and not cur["legacy"]) or (claim_id and claim_id != cur["claim_id"]):
            raise ClaimsError("release requires the current claim_id; an old receipt cannot release new work")
        if not cur["claimed"]:
            return None
        return {"action": "RELEASED", "class_id": class_id, "slot": slot, "owner": owner,
                "claim_id": cur["claim_id"], "ts": _iso(datetime.now(timezone.utc))}

    return _transact(path, build)


def occupancy(current: dict, class_id: str) -> dict:
    holders = [cur for (cid, _), cur in sorted(current.items()) if cid == class_id and cur["claimed"]]
    return {"class_id": class_id, "claimed": bool(holders), "holders": holders}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Case occupancy only: leader claim -> release')
    parser.add_argument("--claims-file", type=Path, default=DEFAULT_CLAIMS)
    sub = parser.add_subparsers(dest="cmd", required=True)
    take = sub.add_parser("claim", help="leader acquires a whole case; --claim-id renews it")
    take.add_argument("--class-id", required=True)
    take.add_argument("--scope", required=True)
    take.add_argument("--owner", default="")
    take.add_argument("--claim-id")
    take.add_argument("--hours", type=float, default=DEFAULT_LEASE_HOURS)
    take.add_argument("--slot", default=DEFAULT_SLOT, help=argparse.SUPPRESS)
    listing = sub.add_parser("list", help="JSONL case occupancy; no research status")
    listing.add_argument("--class-id")
    listing.add_argument("--owner")
    listing.add_argument("--scope")
    listing.add_argument("--all", action="store_true", help="include unclaimed historical cases")
    closer = sub.add_parser("release", help="release occupancy")
    closer.add_argument("--class-id", required=True)
    closer.add_argument("--owner", default="")
    closer.add_argument("--claim-id")
    closer.add_argument("--slot", default=DEFAULT_SLOT, help="historical slot to close")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "list":
            current = state(load(args.claims_file))
            ids = {args.class_id} if args.class_id else {cid for cid, _ in current}
            for cid in sorted(ids):
                rows = [row for (key, _), row in current.items() if key == cid]
                if (args.owner or args.scope) and not any(
                    (not args.owner or row["owner"] == args.owner)
                    and (not args.scope or row["scope"] == args.scope) for row in rows
                ):
                    continue
                item = occupancy(current, cid)
                if item["claimed"] or args.all or args.class_id:
                    print(json.dumps(item, sort_keys=True))
            return 0
        owner = args.owner or os.environ.get("CLAIM_OWNER")
        if not owner:
            raise ClaimsError("pass --owner or set CLAIM_OWNER")
        if args.cmd == "claim":
            event = claim(args.claims_file, args.class_id, owner, scope=args.scope,
                          claim_id=args.claim_id, hours=args.hours, slot=args.slot)
            print(json.dumps(state([event])[(args.class_id, DEFAULT_SLOT)], sort_keys=True))
        else:
            release(args.claims_file, args.class_id, owner, claim_id=args.claim_id, slot=args.slot)
            print(json.dumps(occupancy(state(load(args.claims_file)), args.class_id), sort_keys=True))
    except (ClaimsError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"claims: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
