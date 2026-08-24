#!/usr/bin/env python3
"""Verify rotated second-pass coverage and report verdict disagreements."""

from collections import Counter

from verify import HERE, load_jsonl, verify_row


ROTATION = {1: 4, 2: 5, 3: 6, 4: 1, 5: 2, 6: 3}  # reviewer -> shard


def main() -> None:
    manifest = load_jsonl(HERE / "manifest.jsonl")
    expected = {row["ordinal"]: row for row in manifest}
    first = {}
    second = []
    for shard in range(1, 7):
        for row in load_jsonl(HERE / "shards" / f"shard-{shard:02d}.jsonl"):
            first[row["ordinal"]] = row
    for reviewer, shard in ROTATION.items():
        path = HERE / "crossreviews" / f"shard-{shard:02d}-by-{reviewer:02d}.jsonl"
        rows = load_jsonl(path)
        assert all(row["ordinal"] in range((shard - 1) * 36 + 1, min(shard * 36, 211) + 1) for row in rows)
        second.extend(rows)
        assert (HERE / "crossreports" / f"shard-{shard:02d}-by-{reviewer:02d}.md").is_file()
    assert len(second) == len({row["ordinal"] for row in second}) == 211
    for row in second:
        verify_row(row, expected[row["ordinal"]])
    disagreements = [row["ordinal"] for row in second if row["verdict"] != first[row["ordinal"]]["verdict"]]
    counts = Counter(row["verdict"] for row in second)
    print(f"PASS: 211/211 cross-reviewed; verdicts={dict(sorted(counts.items()))}; disagreements={len(disagreements)}")
    print("DISAGREEMENTS:", disagreements)


if __name__ == "__main__":
    main()
