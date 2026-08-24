#!/usr/bin/env python3
"""Commit-first AI-marker mine for assigned G-N repositories.

Clones only under /home/hanqing/.cache/ghsa200-worker-clones/commit-gn.
Does not edit shared code. AI-marker hits are routing, never causal proof.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

OUT = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gn")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones")
REF_ROOT = Path("/home/hanqing/.cache/cve-analyzer/repos")
WORKERS = 12
CLONE_TIMEOUT = 180
SCAN_TIMEOUT = 120
SINCE = "2022-01-01"

# Single POSIX ERE for git log --grep. Hits remain routing until seven-gate review.
MESSAGE_ERE = (
    "Co-authored-by:[[:space:]]*.*(Claude|Cursor|Copilot|Codex|Jules|Gemini|"
    "aider|Aider|OpenAI|anthropic)"
    "|noreply@anthropic\\.com|claude@anthropic\\.com|cursoragent@cursor\\.com"
    "|copilot@github\\.com|codex@openai\\.com|noreply@openai\\.com"
    "|Generated with Claude|Generated-by:[[:space:]]*.*Claude"
    "|Assisted-by:[[:space:]]*.*(Claude|Cursor|Copilot|Codex|Gemini)"
    "|google-labs-jules|devin-ai-integration|openai-code-agent"
    "|anthropic-code-agent"
)
AUTHOR_ERES = [
    "noreply@anthropic.com",
    "cursoragent@cursor.com",
    "copilot@github.com",
    "codex@openai.com",
    "claude-bot@bun.sh",
    "google-labs-jules",
    "devin-ai-integration",
    "copilot-swe-agent",
    "chatgpt-codex-connector",
]
MARKER_RES = [
    r"Co-authored-by:.*(?:Claude|Cursor|Copilot|Codex|Jules|Gemini|aider|Aider|OpenAI|anthropic)",
    r"noreply@anthropic\.com",
    r"claude@anthropic\.com",
    r"cursoragent@cursor\.com",
    r"copilot@github\.com",
    r"codex@openai\.com",
    r"noreply@openai\.com",
    r"Generated with Claude",
    r"Generated-by:.*Claude",
    r"Assisted-by:.*(?:Claude|Cursor|Copilot|Codex|Gemini)",
    r"google-labs-jules",
    r"devin-ai-integration",
    r"openai-code-agent",
    r"anthropic-code-agent",
]

FORMAT = "%H%x00%an%x00%ae%x00%aI%x00%s%x00%b%x00%x00"


def repo_dest(repository: str) -> Path:
    owner, name = repository.split("/", 1)
    return CLONE_ROOT / f"{owner}__{name}"


def local_reference(repository: str) -> Path | None:
    owner, name = repository.split("/", 1)
    candidates = [
        REF_ROOT / f"{owner}_{name}".lower(),
        REF_ROOT / f"{owner}_{name}",
        REF_ROOT / f"{owner.lower()}_{name}",
    ]
    for path in candidates:
        git_dir = path / ".git" if (path / ".git").exists() else path if (path / "HEAD").exists() else None
        if git_dir is None:
            continue
        try:
            shallow = run(
                ["git", "-C", str(path), "rev-parse", "--is-shallow-repository"],
                15,
            )
        except subprocess.TimeoutExpired:
            return None
        if shallow.returncode == 0 and shallow.stdout.strip() == "true":
            return None
        return path
    return None


def run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
    )


def ensure_clone(repository: str) -> dict:
    dest = repo_dest(repository)
    url = f"https://github.com/{repository}.git"
    if (dest / ".git").exists() or (dest / "HEAD").exists():
        return {"repository": repository, "path": str(dest), "status": "exists"}
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "git",
        "clone",
        "--filter=blob:none",
        "--no-checkout",
        "--single-branch",
        "--no-tags",
    ]
    ref = local_reference(repository)
    if ref is not None:
        cmd.extend(["--reference", str(ref)])
    cmd.extend([url, str(dest)])
    try:
        completed = run(cmd, CLONE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"repository": repository, "path": str(dest), "status": "TIMEOUT"}
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip().splitlines()
        tail = err[-1] if err else "clone_failed"
        if dest.exists():
            # leave failed partial dirs named so replay can see them
            pass
        return {
            "repository": repository,
            "path": str(dest),
            "status": "CLONE_FAIL",
            "error": tail[:300],
        }
    return {
        "repository": repository,
        "path": str(dest),
        "status": "cloned",
        "used_reference": str(ref) if ref else None,
    }


def scan_ai(repository: str, path: Path) -> dict:
    grep_cmd = [
        "git",
        "-C",
        str(path),
        "log",
        "--all",
        f"--since={SINCE}",
        "--regexp-ignore-case",
        "--extended-regexp",
        f"--grep={MESSAGE_ERE}",
        f"--format={FORMAT}",
    ]
    author_cmd = [
        "git",
        "-C",
        str(path),
        "log",
        "--all",
        f"--since={SINCE}",
        "--regexp-ignore-case",
        "--extended-regexp",
        f"--format={FORMAT}",
    ]
    for pat in AUTHOR_ERES:
        author_cmd.append(f"--author={pat}")
    commits: dict[str, dict] = {}
    errors = []
    for name, cmd in (("message", grep_cmd), ("author", author_cmd)):
        try:
            completed = run(cmd, SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            errors.append(f"{name}_timeout")
            continue
        if completed.returncode != 0:
            errors.append(f"{name}_rc{completed.returncode}")
            continue
        chunks = (completed.stdout or "").split("\x00\x00\n")
        if (completed.stdout or "").endswith("\x00\x00"):
            chunks = (completed.stdout or "").split("\x00\x00")
        for chunk in chunks:
            chunk = chunk.strip("\n")
            if not chunk:
                continue
            parts = chunk.split("\x00")
            if len(parts) < 5:
                continue
            sha, an, ae, when, subject = parts[:5]
            body = parts[5] if len(parts) > 5 else ""
            marker = None
            blob = f"{subject}\n{body}\n{an} <{ae}>"
            for pat in MARKER_RES:
                if re.search(pat, blob, re.IGNORECASE):
                    marker = pat
                    break
            commits[sha] = {
                "sha": sha,
                "author_name": an,
                "author_email": ae,
                "date": when,
                "subject": subject[:240],
                "marker_pattern": marker,
                "scan": name,
            }
    return {
        "repository": repository,
        "path": str(path),
        "ai_commit_count": len(commits),
        "ai_commits": sorted(commits.values(), key=lambda r: r["date"]),
        "scan_errors": errors,
    }


def process(repository: str) -> dict:
    clone_info = ensure_clone(repository)
    result = {
        "repository": repository,
        "clone": clone_info,
        "ai_commit_count": 0,
        "ai_commits": [],
        "status": clone_info["status"],
    }
    if clone_info["status"] not in {"exists", "cloned"}:
        return result
    path = Path(clone_info["path"])
    scan = scan_ai(repository, path)
    result.update(scan)
    result["status"] = "SCANNED"
    if scan["scan_errors"]:
        result["status"] = "SCAN_PARTIAL"
    return result


def main() -> int:
    assigned = [
        json.loads(line)
        for line in (OUT / "assigned.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    repos = sorted({row["repository"] for row in assigned if row.get("repository")})
    CLONE_ROOT.mkdir(parents=True, exist_ok=True)
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = {pool.submit(process, repo): repo for repo in repos}
        for i, fut in enumerate(as_completed(futs), 1):
            repo = futs[fut]
            try:
                row = fut.result()
            except Exception as exc:
                row = {"repository": repo, "status": "EXCEPTION", "error": type(exc).__name__}
            results.append(row)
            if i % 25 == 0 or i == len(repos):
                print(f"progress {i}/{len(repos)} last={repo} status={row.get('status')}", flush=True)
    results.sort(key=lambda r: r["repository"])
    with (OUT / "ai-commit-scans.jsonl").open("w", encoding="utf-8") as fh:
        for row in results:
            slim = {
                "repository": row["repository"],
                "status": row.get("status"),
                "path": row.get("path") or (row.get("clone") or {}).get("path"),
                "clone_status": (row.get("clone") or {}).get("status"),
                "ai_commit_count": row.get("ai_commit_count", 0),
                "scan_errors": row.get("scan_errors") or [],
                "error": row.get("error") or (row.get("clone") or {}).get("error"),
                "ai_commits": row.get("ai_commits") or [],
            }
            fh.write(json.dumps(slim, sort_keys=True, ensure_ascii=False) + "\n")
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repos": len(repos),
        "scanned": sum(1 for r in results if r.get("status") in {"SCANNED", "SCAN_PARTIAL"}),
        "clone_fail": sum(1 for r in results if r.get("status") in {"CLONE_FAIL", "TIMEOUT", "EXCEPTION"}),
        "repos_with_ai_commits": sum(1 for r in results if r.get("ai_commit_count", 0) > 0),
        "ai_commits_total": sum(r.get("ai_commit_count", 0) for r in results),
        "note": "AI-marker hits are routing only and are not causal proof.",
    }
    (OUT / "ai-commit-scan-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
