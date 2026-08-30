#!/usr/bin/env python3
"""Validate or blobless-clone every repository in the frozen manifest."""
from __future__ import annotations

import concurrent.futures
import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
LANE = ROOT / "research/round9-top200-20260828"
MANIFEST = LANE / "manifest.jsonl"


def normalize_remote(value: str) -> str:
    text = value.strip().removesuffix(".git").lower()
    if text.startswith("git@") and ":" in text:
        host, path = text[4:].split(":", 1)
        return f"{host}/{path}"
    if "://" in text:
        parsed = urlparse(text)
        return f"{parsed.hostname}/{parsed.path.lstrip('/')}"
    return text


def expected_identity(repo: str) -> str:
    return repo if repo.startswith("gitlab.") else f"github.com/{repo}"


def valid(path: Path, repo: str) -> bool:
    if not (path / ".git").exists():
        return False
    remote = subprocess.run(
        ["git", "-C", str(path), "remote", "get-url", "origin"],
        text=True,
        capture_output=True,
    )
    head = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
    )
    return (
        remote.returncode == 0
        and head.returncode == 0
        and normalize_remote(remote.stdout) == expected_identity(repo)
        and not (path / ".git/shallow").exists()
    )


def prepare(item: dict) -> dict:
    repo = item["repo"]
    current = Path(item["clone_dir"])
    if valid(current, repo):
        return {"repo": repo, "clone_dir": str(current), "created": False, "ok": True}
    target = ROOT / ".ai-slop/state/repos" / repo.replace("/", "_")
    if target.exists() and not valid(target, repo):
        target = target.with_name(target.name + "_round9")
    if not target.exists():
        result = subprocess.run(
            [
                "numactl", "--cpunodebind=1", "--membind=1",
                "git", "clone", "--filter=blob:none", item["clone_url"], str(target),
            ],
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            return {
                "repo": repo,
                "clone_dir": str(target),
                "created": False,
                "ok": False,
                "error": (result.stderr or result.stdout)[-500:],
            }
        created = True
    else:
        created = False
    return {
        "repo": repo,
        "clone_dir": str(target),
        "created": created,
        "ok": valid(target, repo),
    }


def main() -> None:
    manifest = [json.loads(line) for line in MANIFEST.read_text().splitlines() if line.strip()]
    unique = {item["repo"]: item for item in manifest}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(prepare, unique.values()))
    by_repo = {result["repo"]: result for result in results}
    failures = [result for result in results if not result["ok"]]
    if failures:
        (LANE / "clone-prep.json").write_text(json.dumps(results, indent=1) + "\n")
        raise SystemExit(f"clone preparation failed for {len(failures)} repos")
    for item in manifest:
        item["clone_dir"] = by_repo[item["repo"]]["clone_dir"]
        bundle_path = ROOT / item["bundle"]
        bundle = json.loads(bundle_path.read_text())
        bundle["clone_dir"] = item["clone_dir"]
        bundle_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=1) + "\n")
        import hashlib
        item["bundle_sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    MANIFEST.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in manifest))
    (LANE / "clone-prep.json").write_text(json.dumps(results, indent=1) + "\n")
    print(json.dumps({
        "repos": len(results),
        "created": sum(result["created"] for result in results),
        "reused": sum(not result["created"] for result in results),
        "failures": 0,
    }))


if __name__ == "__main__":
    main()
