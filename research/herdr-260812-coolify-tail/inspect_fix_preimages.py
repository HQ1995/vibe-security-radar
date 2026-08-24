#!/usr/bin/env python3
"""List exact deleted-line owners for a bounded set of Coolify security fixes."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
BLAME_RE = re.compile(r"^\^?([0-9a-f]{40}) (\d+) (\d+)(?: (\d+))?$")

FIXES = {
    "CVE-2026-41896": "bafb9a5a8baf8518a5b9c1cda59f158f5e726436",
    "CVE-2026-41899": "e7bbd45408f97e9c2703c6c66c91cc758aa04905",
    "CVE-2026-42143": "410a9a6195a2b939d4a429f6c464ff56e61177f8",
    "CVE-2026-42145": "af0a8badb3cd9f470cb55c5f714263f63425d40b",
    "CVE-2026-42147": "297e9c41e19958f6237919794c28c3fb1d4cda32",
    "CVE-2026-42153": "64753b41364010f5e8d539194a567feea1d1d520",
    "CVE-2026-42172": "90ddbb357231ca3808f277eb87a63c8f650417e6",
    "CVE-2026-42200": "a05d4e3a4b024719cda512244549fb5c949180c3",
    "CVE-2026-42201": "03313e54cc790f3a6df6cb4fa9274c27437083e7",
    "CVE-2026-57498": "a478ac66eb7037837c178d64006f83a13eca12d2",
}


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if done.returncode:
        raise RuntimeError(f"git {args[0]} failed: {done.stderr.strip()[:300]}")
    return done.stdout


def changed_old_ranges(repo: Path, parent: str, fix: str) -> tuple[list[tuple[str, int, int]], int]:
    patch = git(repo, "diff", "--unified=0", "--no-color", "--no-ext-diff", parent, fix, "--")
    path = ""
    ranges: list[tuple[str, int, int]] = []
    add_only = 0
    for line in patch.splitlines():
        if line.startswith("--- a/"):
            path = line[6:]
            continue
        match = HUNK_RE.match(line)
        if not match or not path:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or 1)
        if count:
            ranges.append((path, start, start + count - 1))
        else:
            add_only += 1
    return ranges, add_only


def blame(repo: Path, revision: str, path: str, start: int, end: int) -> list[dict[str, object]]:
    text = git(repo, "blame", "--line-porcelain", "-L", f"{start},{end}", revision, "--", path)
    rows: list[dict[str, object]] = []
    current: tuple[str, int] | None = None
    for line in text.splitlines():
        header = BLAME_RE.match(line)
        if header:
            current = (header.group(1), int(header.group(3)))
        elif current and line.startswith("\t"):
            rows.append({"sha": current[0], "line": current[1], "content": line[1:]})
            current = None
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ai-scan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    ai = {row["sha"]: row for row in map(json.loads, args.ai_scan.read_text().splitlines())}
    result: list[dict[str, object]] = []
    for public_id, fix in FIXES.items():
        parent = git(args.repository, "rev-parse", f"{fix}^1").strip()
        ranges, add_only = changed_old_ranges(args.repository, parent, fix)
        changed_files = git(args.repository, "diff", "--name-only", parent, fix, "--").splitlines()
        owners: Counter[str] = Counter()
        samples: dict[str, list[dict[str, object]]] = defaultdict(list)
        for path, start, end in ranges:
            for row in blame(args.repository, parent, path, start, end):
                sha = str(row["sha"])
                owners[sha] += 1
                if len(samples[sha]) < 4:
                    samples[sha].append({"path": path, "line": row["line"], "content": row["content"]})
        ai_owners = []
        for sha, line_count in owners.most_common():
            if sha not in ai:
                continue
            ai_owners.append({
                "candidate_sha": sha,
                "owned_changed_lines": line_count,
                "authored_date": ai[sha]["authored_date"],
                "subject": ai[sha]["message"].splitlines()[0],
                "samples": samples[sha],
            })
        history = git(args.repository, "log", "--format=%H", parent, "--", *changed_files).splitlines()
        same_file_ai = []
        for sha in history:
            if sha not in ai or any(row["candidate_sha"] == sha for row in same_file_ai):
                continue
            overlap = sorted(set(changed_files) & set(ai[sha].get("changed_files", [])))
            same_file_ai.append({
                "candidate_sha": sha,
                "authored_date": ai[sha]["authored_date"],
                "subject": ai[sha]["message"].splitlines()[0],
                "overlap_files": overlap,
            })
            if len(same_file_ai) == 8:
                break
        result.append({
            "public_id": public_id,
            "fix_member_sha": fix,
            "fix_parent_sha": parent,
            "old_line_ranges": len(ranges),
            "add_only_hunks": add_only,
            "distinct_preimage_owners": len(owners),
            "ai_preimage_owners": ai_owners,
            "same_file_ai_ancestors": same_file_ai,
        })
    payload = {
        "schema_version": 1,
        "artifact_kind": "diagnostic_fix_preimage_owner_screen",
        "claim_boundary": "Exact deleted-line ownership schedules review only; it is not causal or publication-grade evidence.",
        "rows": result,
        "counts": {
            "fixes": len(result),
            "fixes_with_ai_preimage_owner": sum(bool(row["ai_preimage_owners"]) for row in result),
            "ai_owner_observations": sum(len(row["ai_preimage_owners"]) for row in result),
        },
    }
    assert set(FIXES) == {row["public_id"] for row in result}
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
