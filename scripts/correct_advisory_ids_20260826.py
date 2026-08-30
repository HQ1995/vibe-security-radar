#!/usr/bin/env python3
"""correct_advisory_ids_20260826.py

Authoritative advisory-identity correction for artifacts/funnel-account-20260817.jsonl.

Authoritative sources (zero inference, cryptographic or verbatim):
  1. census_alias_map  : .ai-slop/state/research-queue/round6/.alias_class_member_map.json
                         (class_id -> exact member set, census case; verbatim copy)
  2. hash_pin          : /tmp/pool_pins.json
                         (class_id -> member set proven by sha256('\n'.join(sorted(m))+'\n')[:24]
                          == class_id suffix; census case, taken from the cohort pool)

Rules:
  - Rows with an authoritative set get advisory_ids rewritten to the authoritative set.
  - Rows without one (pool too large / no match / want>2) are left untouched.
  - Only advisory_ids and advisory_ids_source may change; every other key must be
    byte-identical (verified via pre-mutation snapshot).
  - status / research-block verdicts are NEVER touched.

Provenance of /tmp/pool_pins.json (recomputable):
  class_id = 'alias-' + sha256('\\n'.join(sorted(member_ids)) + '\\n').hexdigest()[:24],
  member_ids in census canonical case (GHSA- prefix upper + body lower; everything
  else upper). Formula validated 100% on all 80,259 census map rows (1990 single +
  78269 multi). Pins found by scanning per-repo cohort pools
  (.ai-slop/state/cohort-v1/advisory-repos-since-2025-05.json) for the unique subset
  whose 24-hex sha256 suffix equals class_id[6:]. All 5,867 hits are unique
  (no multi-hits). 96-bit hash match => the subset IS the census member set.
"""
import hashlib
import json
import shutil
import sys
from collections import Counter

LEDGER = "artifacts/funnel-account-20260817.jsonl"
MAP = ".ai-slop/state/research-queue/round6/.alias_class_member_map.json"
PINS = "/tmp/pool_pins.json"
BACKUP = LEDGER + ".bak-advisory-correct-20260826"
REPORT = "artifacts/advisory-correct-report-20260826.json"

TOTAL_ROWS = 23861
STATUS_INVAR = {
    "NOT_AI": 1172,
    "AI_ROOT_CAUSE": 189,
    "AI_CODE_FLAWED": 59,
    "PARTIALLY_ANALYZED": 6162,
    "BLOCKED": 31,
    "UNANALYZED": 16248,
}
TP_INVAR = 248  # AI_ROOT_CAUSE + AI_CODE_FLAWED


def H(s):
    return hashlib.sha256(s.encode()).hexdigest()[:24]


def suffix_of(members):
    return H("\n".join(sorted(members)) + "\n")


def main():
    m = json.load(open(MAP))
    pins = json.load(open(PINS))
    # sanity: pins must not collide with map keys
    assert not (set(pins) & set(m)), "pins collide with census map keys"

    rows = [json.loads(l) for l in open(LEDGER) if l.strip()]
    assert len(rows) == TOTAL_ROWS, f"row count {len(rows)} != {TOTAL_ROWS}"

    # fresh backup of the pre-correction (post-backfill) state
    shutil.copy2(LEDGER, BACKUP)

    # pre-mutation snapshot of every key except the two mutable ones
    snap = {
        r["class_id"]: {k: v for k, v in r.items() if k not in ("advisory_ids", "advisory_ids_source")}
        for r in rows
    }

    stats = Counter()
    changed = []
    for r in rows:
        cid = r["class_id"]
        auth = m.get(cid)
        src = "census_alias_map" if auth is not None else None
        if auth is None:
            pin = pins.get(cid)
            if pin:
                auth, src = pin, "hash_pin_20260826"
        if auth is None:
            stats["no_authoritative"] += 1
            continue
        old = r.get("advisory_ids")
        new = list(auth)  # census case (map verbatim; pins from pool in census case)
        # cryptographic self-check: the authoritative set must reproduce class_id
        assert suffix_of(new) == cid[6:], f"auth set fails hash check for {cid}"
        if old is None:
            r["advisory_ids"] = new
            r["advisory_ids_source"] = src
            stats["added"] += 1
            changed.append((cid, None, new, src, "added"))
        elif old != new:
            r["advisory_ids"] = new
            r["advisory_ids_source"] = src
            if set(x.lower() if x.startswith("GHSA") else x for x in old) == set(
                x.lower() if x.startswith("GHSA") else x for x in new
            ):
                stats["case_normalized"] += 1
                cat = "case_normalized"
            else:
                stats["corrected"] += 1
                cat = "corrected"
            changed.append((cid, old, new, src, cat))
        else:
            stats["unchanged"] += 1

    # ---- verification: every key except the two mutable ones is byte-identical
    for r in rows:
        s = snap[r["class_id"]]
        now = {k: v for k, v in r.items() if k not in ("advisory_ids", "advisory_ids_source")}
        assert s == now, f"unexpected mutation on {r['class_id']}"

    # ---- invariants
    sc = Counter(r.get("status") for r in rows)
    assert dict(sc) == STATUS_INVAR, f"status counts changed: {dict(sc)}"
    tp = sum(1 for r in rows if r.get("status") in ("AI_ROOT_CAUSE", "AI_CODE_FLAWED"))
    assert tp == TP_INVAR, f"TP changed: {tp}"

    # ---- hash re-verify of EVERY row that now has an authoritative set
    expected_verified = sum(1 for r in rows if r["class_id"] in m or r["class_id"] in pins)
    n_verified = 0
    for r in rows:
        if r["class_id"] in m or r["class_id"] in pins:
            assert r.get("advisory_ids"), f"missing advisory_ids on {r['class_id']}"
            assert suffix_of(r["advisory_ids"]) == r["class_id"][6:], \
                f"post-fix hash verify failed: {r['class_id']}"
            n_verified += 1
    assert n_verified == expected_verified

    with open(LEDGER, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    json.dump(
        {
            "stats": dict(stats),
            "verified_by_hash": n_verified,
            "changed": changed,
        },
        open(REPORT, "w"),
        ensure_ascii=False,
        indent=1,
    )
    print("stats:", dict(stats))
    print(f"hash re-verified: {n_verified}/{len(m) + len(pins)}")
    print(f"backup: {BACKUP}")
    print(f"report: {REPORT}")
    print("OK")


if __name__ == "__main__":
    sys.exit(main())
