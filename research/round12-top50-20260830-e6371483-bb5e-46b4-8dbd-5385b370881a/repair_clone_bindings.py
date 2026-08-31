#!/usr/bin/env python3
"""Replace accidental repository-root clone bindings with source repo clones."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LANE = Path(__file__).resolve().parent


def git(clone: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(clone), *args],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()


def write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def main() -> None:
    manifest = [json.loads(line) for line in (LANE / "manifest.jsonl").read_text().splitlines() if line.strip()]
    repaired = []
    for row in manifest:
        if row["clone_dir"] != ".":
            continue
        clone = ROOT / ".ai-slop/state/repos" / row["repo"].replace("/", "_")
        assert (clone / ".git").exists(), clone
        bundle_path = ROOT / row["bundle"]
        bundle = json.loads(bundle_path.read_text())
        values = {
            "clone_dir": str(clone),
            "clone_head_sha": git(clone, "rev-parse", "HEAD"),
            "clone_shallow": git(clone, "rev-parse", "--is-shallow-repository"),
            "clone_promisor": git(clone, "config", "--get", "remote.origin.promisor") == "true",
            "clone_partial_filter": git(clone, "config", "--get", "remote.origin.partialclonefilter") or None,
        }
        assert values["clone_shallow"] == "false"
        bundle.update(values)
        write(bundle_path, json.dumps(bundle, ensure_ascii=False, indent=1) + "\n")
        row.update(values)
        row["bundle_sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        repaired.append(row["worker"])
    write(LANE / "manifest.jsonl", "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in manifest))
    print(json.dumps({"repaired": len(repaired), "workers": repaired}))


if __name__ == "__main__":
    main()
