#!/usr/bin/env python3
"""Fail closed on final mechanism, case, and public-ID conservation."""

import json
import subprocess
from collections import Counter

from verify import HERE, load_jsonl, verify_row


def main() -> None:
    subprocess.run(["python3", str(HERE / "build_final.py"), "--check"], check=True)
    manifest = {row["ordinal"]: row for row in load_jsonl(HERE / "manifest.jsonl")}
    mechanisms = load_jsonl(HERE / "final_mechanisms.jsonl")
    cases = load_jsonl(HERE / "public_cases.jsonl")
    dispositions = load_jsonl(HERE / "public_id_dispositions.jsonl")
    summary = json.loads((HERE / "summary.json").read_text())

    assert [row["ordinal"] for row in mechanisms] == list(range(1, 212))
    for row in mechanisms:
        verify_row(row, manifest[row["ordinal"]])
    assert Counter(row["verdict"] for row in mechanisms) == {
        "CONFIRM": 65, "NARROW": 83, "FALSE_POSITIVE": 54, "UNKNOWN": 9,
    }

    assert len(cases) == len({row["case_id"] for row in cases}) == 212
    assert all(row["case_id"].startswith("GHSA-") for row in cases)
    assert Counter(row["verdict"] for row in cases) == {
        "CONFIRM": 65, "NARROW": 84, "FALSE_POSITIVE": 54, "UNKNOWN": 9,
    }
    by_ordinal = Counter(row["ordinal"] for row in cases)
    assert by_ordinal[200] == 2 and all(count == 1 for ordinal, count in by_ordinal.items() if ordinal != 200)
    assert all(row["strict_confirmed"] == (row["verdict"] == "CONFIRM") for row in cases)
    assert all(row["causal_valid"] == (row["verdict"] in {"CONFIRM", "NARROW"}) for row in cases)

    assert len(dispositions) == len({row["public_id"] for row in dispositions}) == 381
    assert Counter(row["disposition"] for row in dispositions) == {"KEPT": 371, "REMOVED_IDENTITY": 10}
    kept = [row for row in dispositions if row["disposition"] == "KEPT"]
    removed = [row for row in dispositions if row["disposition"] == "REMOVED_IDENTITY"]
    assert all(len(row["case_ids"]) == 1 for row in kept)
    assert all(not row["case_ids"] for row in removed)
    assert sum(row["id_type"] == "GHSA" for row in kept) == 212
    assert sum(row["id_type"] == "CVE" for row in kept) == 159
    assert {row["public_id"] for row in removed} == {
        "CVE-2026-43571", "CVE-2026-44109", "CVE-2026-45001", "CVE-2026-61462", "CVE-2026-62188",
        "GHSA-5383-J2P9-QFG3", "GHSA-82QX-6VJ7-P8M2", "GHSA-9FC9-8V4X-F5CP",
        "GHSA-W8WF-3QVJ-6XQF", "GHSA-XH72-V6V9-MWHC",
    }

    assert summary["mechanism_rows"] == 211
    assert summary["causal_valid_mechanisms"] == 148
    assert summary["public_cases"] == 212
    assert summary["strict_confirmed_cases"] == 65
    assert summary["causal_valid_cases"] == 149
    assert summary["unresolved_cases"] == 9
    assert summary["public_200_claim_supported"] is False
    assert summary["public_ids"] == 381
    print("PASS: 211 mechanisms, 212 public cases, and 381 public IDs conserve exactly")


if __name__ == "__main__":
    main()
