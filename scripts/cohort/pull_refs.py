"""Materialize and read GitHub pull-request heads without API tokens."""

from __future__ import annotations

import subprocess
from pathlib import Path


COHORT_PULL_NAMESPACE = "refs/cohort/pull"
MAX_PR_MEMBERS = 500


def _run_git(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def fetch_pull_refs(
    repo_path: Path,
    pr_numbers: list[int],
    *,
    batch: int,
    timeout: int,
) -> tuple[int, str]:
    """Fetch requested PR heads into a disposable namespace."""

    fetched = 0
    failed = 0
    for start in range(0, len(pr_numbers), batch):
        chunk = pr_numbers[start : start + batch]
        refspecs = [
            f"+refs/pull/{number}/head:{COHORT_PULL_NAMESPACE}/{number}"
            for number in chunk
        ]
        command = [
            "git",
            "-C",
            str(repo_path),
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--quiet",
            "origin",
        ]
        try:
            completed = _run_git([*command, *refspecs], timeout=timeout)
        except subprocess.TimeoutExpired:
            return fetched, "fetch_timeout"
        except (OSError, subprocess.SubprocessError) as exc:
            return fetched, f"fetch_exception:{type(exc).__name__}"
        if completed.returncode == 0:
            fetched += len(chunk)
            continue

        # One deleted PR must not hide usable refs from the rest of the batch.
        for refspec in refspecs:
            try:
                single = _run_git([*command, refspec], timeout=timeout)
            except subprocess.TimeoutExpired:
                failed += 1
                continue
            except (OSError, subprocess.SubprocessError):
                failed += 1
                continue
            if single.returncode == 0:
                fetched += 1
            else:
                failed += 1
    return fetched, f"fetch_nonzero:{failed}" if failed else ""


def pull_members(
    repo_path: Path,
    landed_sha: str,
    pr_number: int,
    *,
    timeout: int,
    max_members: int = MAX_PR_MEMBERS,
) -> list[str] | None:
    """Return PR-only commits using the landed squash's parent as the base cut."""

    ref = f"{COHORT_PULL_NAMESPACE}/{pr_number}"
    try:
        completed = _run_git(
            [
                "git",
                "-C",
                str(repo_path),
                "rev-list",
                "--no-merges",
                f"--max-count={max_members + 1}",
                ref,
                "--not",
                f"{landed_sha}^",
            ],
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    members = [line.strip().lower() for line in completed.stdout.splitlines() if line.strip()]
    return members or None
