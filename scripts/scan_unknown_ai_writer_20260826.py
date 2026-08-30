#!/usr/bin/env python3
"""Cheap funnel cut: drop only 0% AI-introduced product-source repos.

Blobless clone of every remote branch + Source v3 scan since 2025-05-01.
Author/coauthor/attribution matcher hits and AI committer identity are HAS_AI
traces. Agent config files (AGENTS.md, .claude, .codex, ...) are keep-in, not
HAS_AI. Does not judge TPs and does not write the ledger. Resume-safe via
append-only results.jsonl.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_ai_writer_gate_20260826 as gate
import oss_git_repos as oss
import recover_advisory_ids_20260826 as rec

ROOT = rec.ROOT
CLUSTERS = rec.STATE / "upstream-deduped-20260826.jsonl"
PASS = rec.STATE / "ai-writer-pass-20260826.jsonl"
EXISTING_REPOS = ROOT / ".ai-slop/state/repos"
WORK = ROOT / ".ai-slop/state/funnel-ai-writer-20260826"
CLONES = WORK / "clones"
RESULTS = WORK / "scan-results.jsonl"
QUEUE = WORK / "unknown-repos.json"
SINCE = "2025-05-01"
RETRY_UNKNOWN = "--retry-unknown" in sys.argv
# --shallow-since breaks many GitHub repos (fatal: error processing shallow info: 4).
CLONE_SHALLOW_SINCE = None if RETRY_UNKNOWN else SINCE


def clone_url(ident: str) -> str | None:
    return oss.clone_url(ident)


def dest_for(ident: str) -> Path:
    return CLONES / ident.replace("/", "__")


def row_is_done(row: dict) -> bool:
    """Last-row-wins resume: traces, clone/scan failures, and all-refs NO_AI."""
    if not row.get("repo"):
        return False
    if not row.get("clone_ok"):
        return True
    if row.get("has_ai"):
        return True
    if not row.get("scan_complete"):
        return True
    return (
        "agent_configs" in row
        and "committer_ai_count" in row
        and bool(row.get("all_refs"))
    )


def latest_rows() -> dict[str, dict]:
    latest: dict[str, dict] = {}
    if not RESULTS.is_file():
        return latest
    with RESULTS.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            repo = row.get("repo")
            if repo:
                latest[repo] = row
    return latest


def load_done() -> set[str]:
    return {repo for repo, row in latest_rows().items() if row_is_done(row)}


def backfill_agent_configs() -> int:
    """Re-label old complete NO_AI rows with HEAD agent-config paths. No rematch."""
    pending = [
        row
        for row in latest_rows().values()
        if row.get("clone_ok")
        and row.get("scan_complete")
        and not row.get("has_ai")
        and "agent_configs" not in row
        and Path(row.get("clone_path") or "").exists()
    ]
    if not pending:
        return 0
    n = 0
    with RESULTS.open("a", encoding="utf-8") as handle:
        for row in pending:
            path = Path(row["clone_path"])
            configs = list_agent_configs(path)
            if configs is None:
                continue
            updated = dict(row)
            updated["agent_configs"] = configs
            updated["droppable"] = not configs
            handle.write(json.dumps(updated, ensure_ascii=False) + "\n")
            n += 1
        handle.flush()
    return n


def backfill_committer_traces() -> int:
    """Re-scan complete NO_AI clones for AI committer identity. No rematch of authors."""
    pending = [
        row
        for row in latest_rows().values()
        if row.get("clone_ok")
        and row.get("scan_complete")
        and not row.get("has_ai")
        and "committer_ai_count" not in row
        and Path(row.get("clone_path") or "").exists()
    ]
    if not pending:
        return 0
    n = 0
    with RESULTS.open("a", encoding="utf-8") as handle:
        for row in pending:
            counted = count_ai_committer_commits(Path(row["clone_path"]))
            if counted is None:
                continue
            updated = dict(row)
            updated["committer_ai_count"] = counted
            updated["has_ai"] = counted > 0
            configs = updated.get("agent_configs") or []
            updated["droppable"] = (
                not updated["has_ai"]
                and "agent_configs" in updated
                and not configs
            )
            handle.write(json.dumps(updated, ensure_ascii=False) + "\n")
            n += 1
        handle.flush()
    return n


def list_agent_configs(repo_path: Path) -> list[str] | None:
    """HEAD tree paths from AI_CONFIG_FILES. Works on blob:none clones (no blob fetch).

    Returns None if git cannot answer, so the caller must not treat that as absence.
    """
    from cve_analyzer.ai_signatures import AI_CONFIG_FILES

    payload = "".join(f"HEAD:{cfg}\n" for cfg in AI_CONFIG_FILES)
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(repo_path),
                "cat-file",
                "--batch-check",
            ],
            input=payload,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = completed.stdout.splitlines()
    if len(lines) != len(AI_CONFIG_FILES):
        return None
    hits: list[str] = []
    for cfg, line in zip(AI_CONFIG_FILES, lines):
        if line and " missing" not in line:
            hits.append(cfg)
    return hits


def count_ai_committer_commits(repo_path: Path) -> int | None:
    """Count commits whose committer matches the same identities as author.

    Uses git log --committer with the production author prefilter. Failure is
    unknown, never zero.
    """
    from cve_analyzer.git_ops import run_git
    from cve_analyzer.provenance import (
        ProvenanceError,
        _INDEX_COMMIT_FORMAT,
        _author_prefilter_eres,
        _parse_index_commits,
    )
    from cve_analyzer.source_matcher import match_committer_identity

    command = [
        "git",
        "-C",
        str(repo_path),
        "log",
        "--all",
        f"--since={SINCE}",
        "--regexp-ignore-case",
        "--extended-regexp",
        *(f"--committer={pattern}" for pattern in _author_prefilter_eres()),
        f"--format={_INDEX_COMMIT_FORMAT}",
    ]
    try:
        completed = run_git(
            command,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            no_lazy_fetch=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    try:
        commits = _parse_index_commits(completed.stdout or "")
    except ProvenanceError:
        return None
    return sum(1 for commit in commits if match_committer_identity(commit))


def load_retry_unknown_repos() -> dict[str, int]:
    """Repos still in the unknown bucket that look recoverable."""
    import apply_zero_pct_gate_20260826 as z

    writer = z.load_inventory_writer()
    scan = z.latest_scan_rows()
    counts: Counter[str] = Counter()
    skipped_gone = 0
    with CLUSTERS.open(encoding="utf-8") as handle:
        for line in handle:
            cluster = json.loads(line)
            if not (cluster.get("in_window") and cluster.get("repo")):
                continue
            if z.classify_cluster(cluster, writer, scan) != "unknown":
                continue
            repo = cluster["repo"]
            err = (scan.get(repo) or {}).get("clone_error") or ""
            if "user-attachments/" in repo:
                skipped_gone += 1
                continue
            if "Repository not found" in err and "googlesource.com" not in repo:
                skipped_gone += 1
                continue
            counts[repo] += 1
    print(f"retry skip gone/not-a-repo clusters {skipped_gone}", flush=True)
    return dict(counts)


def load_unknown_repos() -> dict[str, int]:
    pass_ids = set()
    with PASS.open(encoding="utf-8") as handle:
        for line in handle:
            pass_ids.add(json.loads(line)["class_id"])
    counts: Counter[str] = Counter()
    with CLUSTERS.open(encoding="utf-8") as handle:
        for line in handle:
            cluster = json.loads(line)
            if not (cluster.get("in_window") and cluster.get("repo")):
                continue
            if cluster["class_id"] in pass_ids:
                continue
            counts[cluster["repo"]] += 1
    return dict(counts)


def existing_clone_index() -> dict[str, str]:
    cache = WORK / "existing-clone-index.json"
    if cache.is_file():
        return json.loads(cache.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    if not EXISTING_REPOS.is_dir():
        return out
    for entry in sorted(EXISTING_REPOS.iterdir()):
        if not entry.is_dir():
            continue
        try:
            completed = subprocess.run(
                ["git", "-C", str(entry), "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        url = (completed.stdout or "").strip()
        if not url:
            continue
        ident = url
        if ident.endswith(".git"):
            ident = ident[:-4]
        ident = ident.replace("https://", "").replace("http://", "").replace("git@", "")
        ident = ident.replace("github.com:", "github.com/")
        keys = gate.identity_keys(ident)
        for key in keys:
            out[key] = str(entry)
    cache.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


def blobless_clone(ident: str, dest: Path) -> dict:
    url = clone_url(ident)
    started = time.monotonic()
    if dest.exists() and ((dest / ".git").exists() or (dest / "HEAD").exists()):
        return {"ok": True, "path": str(dest), "reused": True, "elapsed_s": 0}
    if not url:
        return {"ok": False, "error": "no_clone_url", "elapsed_s": 0}
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    cmd = [
        "git",
        "--no-optional-locks",
        "clone",
        "--filter=blob:none",
        "--no-tags",
    ]
    if CLONE_SHALLOW_SINCE:
        cmd.append(f"--shallow-since={CLONE_SHALLOW_SINCE}")
    cmd.extend([url, str(dest)])
    timeout_s = 600 if RETRY_UNKNOWN else 300
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False, env=env
        )
    except subprocess.TimeoutExpired:
        subprocess.run(["rm", "-rf", str(dest)], check=False)
        return {"ok": False, "error": "timeout", "elapsed_s": timeout_s}
    if completed.returncode == 0 or (dest / ".git").exists() or (dest / "HEAD").exists():
        return {
            "ok": True,
            "path": str(dest),
            "reused": False,
            "elapsed_s": round(time.monotonic() - started, 2),
        }
    subprocess.run(["rm", "-rf", str(dest)], check=False)
    err = (completed.stderr or completed.stdout or "")[-300:]
    return {
        "ok": False,
        "error": err or f"exit {completed.returncode}",
        "elapsed_s": round(time.monotonic() - started, 2),
    }


def origin_fetch_covers_all_heads(repo_path: Path) -> bool:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), "config", "--get-all", "remote.origin.fetch"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return any("refs/heads/*" in line for line in completed.stdout.splitlines())


def remote_head_count(repo_path: Path) -> int:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), "branch", "-r"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    return sum(
        1
        for line in completed.stdout.splitlines()
        if line.strip() and " -> " not in line
    )


def ensure_all_refs(repo_path: Path) -> dict:
    """Widen a clone so git log --all sees every head.

    Failure is unknown, never absence. Do not skip fetch just because the
    fetch spec is already wide: a prior --single-branch clone can have the
    spec rewritten and still only hold origin/HEAD.
    """
    already_wide = origin_fetch_covers_all_heads(repo_path) and remote_head_count(
        repo_path
    ) > 1
    if already_wide and not RETRY_UNKNOWN:
        return {"ok": True, "fetched": False}
    try:
        configured = subprocess.run(
            [
                "git",
                "-C",
                str(repo_path),
                "config",
                "remote.origin.fetch",
                "+refs/heads/*:refs/remotes/origin/*",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if configured.returncode != 0:
            err = configured.stderr or "config fetch failed"
            return {"ok": False, "error": err[-200:]}
        fetch = [
            "git",
            "-C",
            str(repo_path),
            "fetch",
            "--filter=blob:none",
            "--no-tags",
            "--prune",
            "origin",
        ]
        if CLONE_SHALLOW_SINCE:
            fetch.insert(-1, f"--shallow-since={CLONE_SHALLOW_SINCE}")
        completed = subprocess.run(
            fetch,
            capture_output=True,
            text=True,
            timeout=600 if RETRY_UNKNOWN else 300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "fetch_timeout"}
    except OSError as exc:
        return {"ok": False, "error": f"fetch:{exc}"}
    if completed.returncode != 0:
        err = completed.stderr or completed.stdout or "fetch failed"
        return {"ok": False, "error": err[-200:]}
    return {"ok": True, "fetched": True}


def scan_clone(ident: str, path: Path) -> dict:
    from cve_analyzer.provenance import scan_repo_ai_commit_index

    started = time.monotonic()
    host, owner, name = oss.split_identity(ident)
    identity = (
        f"github.com/{owner}/{name}"
        if host == "github.com"
        else ident.lower()
    )
    payload = scan_repo_ai_commit_index(path, identity, since=SINCE)
    commits = payload.get("commits") or []
    author_n = len(commits)
    committer_n = 0 if author_n else count_ai_committer_commits(path)
    return {
        "complete": bool(payload.get("complete")),
        "error": str(payload.get("error") or ""),
        "ai_commit_count": author_n,
        "committer_ai_count": committer_n,
        "elapsed_s": round(time.monotonic() - started, 2),
    }


def process_one(ident: str, n_classes: int, clone_map: dict[str, str]) -> dict:
    started = time.monotonic()
    existing = None
    for key in gate.identity_keys(ident):
        if key in clone_map:
            existing = clone_map[key]
            break
    if existing:
        clone = {"ok": True, "path": existing, "reused": True, "elapsed_s": 0}
    else:
        clone = blobless_clone(ident, dest_for(ident))
    row = {
        "repo": ident,
        "classes": n_classes,
        "clone_ok": bool(clone.get("ok")),
        "clone_path": clone.get("path") or "",
        "clone_reused": bool(clone.get("reused")),
        "clone_error": clone.get("error") or "",
        "has_ai": False,
        "ai_commit_count": 0,
        "droppable": False,
        "scan_complete": False,
        "scan_error": "",
        "all_refs": False,
        "elapsed_s": 0,
    }
    if not clone.get("ok"):
        row["elapsed_s"] = round(time.monotonic() - started, 2)
        return row
    clone_path = Path(clone["path"])
    widened = ensure_all_refs(clone_path)
    if not widened.get("ok"):
        row["scan_error"] = f"all_refs:{widened.get('error') or 'failed'}"
        row["elapsed_s"] = round(time.monotonic() - started, 2)
        return row
    row["all_refs"] = True
    try:
        scanned = scan_clone(ident, clone_path)
    except Exception as exc:  # noqa: BLE001
        row["scan_error"] = f"{type(exc).__name__}:{exc}"
        row["elapsed_s"] = round(time.monotonic() - started, 2)
        return row
    row["scan_complete"] = bool(scanned.get("complete"))
    row["scan_error"] = scanned.get("error") or ""
    row["ai_commit_count"] = int(scanned.get("ai_commit_count") or 0)
    committer_n = scanned.get("committer_ai_count")
    if committer_n is None:
        extra = "committer_scan_failed"
        row["scan_error"] = f"{row['scan_error']};{extra}" if row["scan_error"] else extra
    else:
        row["committer_ai_count"] = int(committer_n)
    row["has_ai"] = row["ai_commit_count"] > 0 or int(committer_n or 0) > 0
    configs = list_agent_configs(clone_path)
    if configs is None:
        extra = "agent_config_check_failed"
        row["scan_error"] = f"{row['scan_error']};{extra}" if row["scan_error"] else extra
    else:
        row["agent_configs"] = configs
        row["droppable"] = (
            row["scan_complete"]
            and not row["has_ai"]
            and not configs
            and "committer_ai_count" in row
            and row.get("all_refs")
        )
    row["elapsed_s"] = round(time.monotonic() - started, 2)
    return row


def main() -> int:
    os.environ.setdefault("CVE_ANALYZER_FROZEN_LOCAL_SOURCES", "1")
    os.environ.setdefault("CVE_GIT_CONCURRENCY", "8")
    WORK.mkdir(parents=True, exist_ok=True)
    CLONES.mkdir(parents=True, exist_ok=True)
    if RETRY_UNKNOWN:
        unknown = load_retry_unknown_repos()
        done: set[str] = set()
        print("retry-unknown: no shallow-since, fetch all heads", flush=True)
    else:
        unknown = load_unknown_repos()
        n_backfill = backfill_agent_configs()
        if n_backfill:
            print(f"backfilled agent_configs on {n_backfill} old NO_AI rows", flush=True)
        n_committer = backfill_committer_traces()
        if n_committer:
            print(f"backfilled committer traces on {n_committer} old NO_AI rows", flush=True)
        done = load_done()
    QUEUE.write_text(json.dumps(unknown, indent=2) + "\n", encoding="utf-8")
    github = []
    other = []
    for repo, count in sorted(unknown.items(), key=lambda item: (-item[1], item[0])):
        if repo in done:
            continue
        host, _, _ = oss.split_identity(repo)
        if host == "github.com":
            github.append((repo, count))
        else:
            other.append((repo, count))
    queue = github + other
    print(
        f"unknown repos {len(unknown)} already_done {len(done)} remaining {len(queue)} "
        f"(github {len(github)} other {len(other)})",
        flush=True,
    )
    print("indexing existing clones...", flush=True)
    clone_map = existing_clone_index()
    print(f"existing clone keys {len(clone_map)}", flush=True)
    workers = 6
    ok = has_ai = keep_config = droppable = fail = 0
    with RESULTS.open("a", encoding="utf-8") as handle, ThreadPoolExecutor(
        max_workers=workers
    ) as pool:
        futs = {
            pool.submit(process_one, repo, count, clone_map): repo
            for repo, count in queue
        }
        for i, fut in enumerate(as_completed(futs), 1):
            row = fut.result()
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush()
            configs = row.get("agent_configs") or []
            if row["has_ai"]:
                has_ai += 1
            elif row["clone_ok"] and row["scan_complete"] and configs:
                keep_config += 1
            elif row.get("droppable"):
                droppable += 1
            else:
                fail += 1
            if row["clone_ok"]:
                ok += 1
            if i % 20 == 0 or row["has_ai"] or configs or not row["clone_ok"]:
                extra = ",".join(configs) if configs else (
                    row.get("clone_error") or row.get("scan_error") or row["elapsed_s"]
                )
                print(
                    f"  {i}/{len(queue)} {row['repo']} has_ai={row['has_ai']} "
                    f"n={row['ai_commit_count']} cn={row.get('committer_ai_count', '-')} "
                    f"configs={bool(configs)} droppable={row.get('droppable')} "
                    f"clone={row['clone_ok']} {extra}",
                    flush=True,
                )
    print(
        f"done clone_ok={ok} HAS_AI={has_ai} keep_config={keep_config} "
        f"droppable={droppable} fail={fail}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
