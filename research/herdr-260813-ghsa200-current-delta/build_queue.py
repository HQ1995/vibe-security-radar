#!/usr/bin/env python3
"""Phase 4: build the deterministic 731-ID routing queue with odd/even partition
proof, emit mechanical rows for the ODD partition, and separately review the
148 modified github-reviewed advisories for identity/alias/range changes.

Emits: routing-queue.jsonl (731 rows, partition + routing), cases.jsonl
(starts as ODD-partition mechanical rows; deep adjudication appended later).
"""
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from build_delta import OWN, sha256_file  # noqa: E402

QA_ADDED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/github_reviewed_window_added_ids.txt")


def nibble(gid: str) -> int:
    return int(hashlib.sha256(gid.upper().encode()).hexdigest()[-1], 16)


def main() -> int:
    qa_ids = sorted({l.strip().upper() for l in QA_ADDED.read_text().splitlines() if l.strip()})
    assert len(qa_ids) == 731, f"QA manifest has {len(qa_ids)} ids, expected 731"

    reviewed = {}
    for line in (OWN / "reviewed-delta.jsonl").open():
        r = json.loads(line)
        reviewed[r["ghsa"]] = r
    assert {r["ghsa"] for r in reviewed.values() if r["triage"] == "ADDED_REVIEWED"} == set(qa_ids), \
        "my enumerated added-reviewed set != QA 731 set"

    odd = sorted(g for g in qa_ids if nibble(g) % 2 == 1)
    even = sorted(g for g in qa_ids if nibble(g) % 2 == 0)
    assert len(set(odd) | set(even)) == 731 and not (set(odd) & set(even))

    queue = []
    for g in sorted(qa_ids):
        r = reviewed[g]
        queue.append({
            "ghsa": g,
            "sha256_hex": hashlib.sha256(g.encode()).hexdigest(),
            "last_nibble": f"{nibble(g):x}",
            "parity": "ODD" if nibble(g) % 2 else "EVEN",
            "owner": "current-delta" if nibble(g) % 2 else "grok",
            "status_in_delta": r["status"],
            "path": r["path"],
            "new_blob_sha1": r["new_blob_sha1"],
            "blob_sha256": r["blob_sha256"],
            "aliases": r["new"]["aliases"],
            "ecosystems": r["new"].get("ecosystems") or [],
            "packages": r["new"].get("packages") or [],
            "published": r["new"].get("published"),
            "collisions": r["collisions"],
            "excluded_baseline": any(c.startswith("baseline") for c in r["collisions"]),
            "routing": "ROUTE_BASELINE_COLLISION" if any(c.startswith("baseline") for c in r["collisions"])
                       else "OWNED_PARTITION",
        })
    qpath = OWN / "routing-queue.jsonl"
    with open(qpath, "w") as f:
        for q in queue:
            f.write(json.dumps(q, sort_keys=True) + "\n")

    # ---- modified reviewed: identity/alias/range change review ----
    mod_rows = [json.loads(l) for l in (OWN / "reviewed-delta.jsonl").open()
                if json.loads(l)["triage"] == "MODIFIED_REVIEWED"]
    # NOTE: each line is parsed twice above; rewrite cleanly
    mod_rows = []
    for line in (OWN / "reviewed-delta.jsonl").open():
        r = json.loads(line)
        if r["triage"] == "MODIFIED_REVIEWED":
            mod_rows.append(r)
    changes = []
    for r in mod_rows:
        o, n = r["old"], r["new"]
        alias_added = sorted(set(n.get("aliases") or []) - set(o.get("aliases") or []))
        alias_removed = sorted(set(o.get("aliases") or []) - set(n.get("aliases") or []))
        old_rng = json.dumps(o.get("ranges") or [], sort_keys=True)
        new_rng = json.dumps(n.get("ranges") or [], sort_keys=True)
        range_changed = old_rng != new_rng
        withdrawn_new = n.get("withdrawn") if n.get("withdrawn") is not None else (o.get("withdrawn"))
        changes.append({
            "row_kind": "modified_reviewed_review",
            "ghsa": r["ghsa"],
            "counted_as_new_id": False,
            "alias_added": alias_added,
            "alias_removed": alias_removed,
            "range_changed": range_changed,
            "old_ranges": o.get("ranges"),
            "new_ranges": n.get("ranges"),
            "old_modified": o.get("modified"),
            "new_modified": n.get("modified"),
            "withdrawn": withdrawn_new,
            "review": "identity/alias/range change note only; not a new countable identity",
        })
    changed_rows = [c for c in changes
                    if c["alias_added"] or c["alias_removed"] or c["range_changed"] or c["withdrawn"]]
    mpath = OWN / "modified-148-review.jsonl"
    with open(mpath, "w") as f:
        for c in changes:
            f.write(json.dumps(c, sort_keys=True) + "\n")

    print(f"queue rows: {len(queue)} (odd={len(odd)}, even={len(even)})")
    print(f"modified reviewed rows: {len(mod_rows)}; with alias/range/withdrawn changes: {len(changed_rows)}")
    print(f"routing-queue sha256: {sha256_file(qpath)}")
    print(f"modified-148-review sha256: {sha256_file(mpath)}")
    kinds = Counter(c["row_kind"] for c in changed_rows)
    print(dict(kinds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
