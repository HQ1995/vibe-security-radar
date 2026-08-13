#!/usr/bin/env python3
"""Build deterministic third-review packets for first/second-pass differences."""

import json
from pathlib import Path

from verify import HERE, load_jsonl


DETAIL_FIELDS = (
    "verdict", "confidence", "identity_gate", "ai_hunk_gate", "topology_gate",
    "but_for_gate", "fix_reversal_gate", "release_gate", "uniqueness_gate",
    "public_ids_keep", "public_ids_remove", "candidate_set", "carrier_set",
    "minimum_fix_set", "duplicate_of", "causal_class", "false_positive_class",
)

# First-pass owner by shard; second-pass reviewer from verify_crossreviews.py.
SECOND_REVIEWER = {1: 4, 2: 5, 3: 6, 4: 1, 5: 2, 6: 3}


def compact(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def main() -> None:
    manifest = {row["ordinal"]: row for row in load_jsonl(HERE / "manifest.jsonl")}
    first = {}
    second = {}
    for path in sorted((HERE / "shards").glob("*.jsonl")):
        first.update({row["ordinal"]: row for row in load_jsonl(path)})
    for path in sorted((HERE / "crossreviews").glob("*.jsonl")):
        second.update({row["ordinal"]: row for row in load_jsonl(path)})
    conflicts = []
    for ordinal in range(1, 212):
        changed = [field for field in DETAIL_FIELDS if first[ordinal][field] != second[ordinal][field]]
        if changed:
            conflicts.append({
                "schema_version": 1,
                "ordinal": ordinal,
                "row_key": manifest[ordinal]["row_key"],
                "changed_fields": changed,
                "manifest": manifest[ordinal],
                "first_pass": first[ordinal],
                "second_pass": second[ordinal],
            })
    assert len(conflicts) == 45
    packets = {number: [] for number in range(1, 7)}
    for conflict in conflicts:
        shard = min((conflict["ordinal"] - 1) // 36 + 1, 6)
        excluded = {shard, SECOND_REVIEWER[shard]}
        reviewer = min((len(packets[number]), number) for number in packets if number not in excluded)[1]
        conflict["first_reviewer"] = shard
        conflict["second_reviewer"] = SECOND_REVIEWER[shard]
        conflict["third_reviewer"] = reviewer
        packets[reviewer].append(conflict)
    output = HERE / "conflict_inputs"
    output.mkdir(exist_ok=True)
    for number, rows in packets.items():
        (output / f"reviewer-{number:02d}.jsonl").write_text("".join(compact(row) + "\n" for row in rows))
    print("WROTE:", {number: len(rows) for number, rows in packets.items()})


if __name__ == "__main__":
    main()
