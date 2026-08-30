#!/usr/bin/env python3
"""Remove only clean public clones created by this campaign."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"


def main() -> None:
    prepared = json.loads((LANE / "clone-prep.json").read_text())
    removed = []
    preserved = []
    freed = 0
    for item in prepared:
        if not item.get("created"):
            continue
        path = Path(item["clone_dir"])
        if not path.exists():
            continue
        dirty = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain"],
            text=True,
            capture_output=True,
        ).stdout.strip()
        if dirty:
            preserved.append(
                {"repo": item["repo"], "path": str(path), "dirty": True}
            )
            continue
        size = sum(file.stat().st_size for file in path.rglob("*") if file.is_file())
        shutil.rmtree(path)
        freed += size
        removed.append({"repo": item["repo"], "path": str(path), "bytes": size})
    result = {"removed": removed, "preserved": preserved, "freed_bytes": freed}
    (LANE / "clone-cleanup.json").write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({"removed": len(removed), "preserved": len(preserved), "freed_bytes": freed}))


if __name__ == "__main__":
    main()
