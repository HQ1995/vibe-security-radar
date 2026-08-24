#!/usr/bin/env python3
"""Hash the durable final audit outputs."""

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
FILES = [
    "FINAL_REPORT.md", "final_mechanisms.jsonl", "public_cases.jsonl",
    "public_id_dispositions.jsonl", "experience.json", "summary.json",
    "build_final.py", "verify_final.py", "build_conflicts.py",
    "verify_crossreviews.py",
]


def build() -> str:
    rows = []
    for name in FILES:
        path = HERE / name
        rows.append({"path": name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return json.dumps({"schema_version": 1, "files": rows}, indent=2, sort_keys=True) + "\n"


def main() -> None:
    path = HERE / "output_manifest.json"
    text = build()
    if "--check" in __import__("sys").argv:
        assert path.is_file() and path.read_text() == text
        print("PASS: output manifest is byte-identical")
    else:
        path.write_text(text)
        print("WROTE: output_manifest.json")


if __name__ == "__main__":
    main()
