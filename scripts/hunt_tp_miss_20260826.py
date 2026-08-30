#!/usr/bin/env python3
"""Hunt true positives among in-window product-source classes not on the ledger.

Pool is the AI-writer-repo miss set (reviewed/unreviewed/NVD all kept).
Dedicated clone pool lives on /home under .ai-slop/state/tp-miss-20260826/.
Does not write the ledger unless --apply-lane is passed after candidates exist.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_ai_writer_gate_20260826 as gate
import oss_git_repos as oss
import recover_advisory_ids_20260826 as rec
from cohort.advisories import commit_reference_rows_from_record

ROOT = rec.ROOT
STATE = rec.STATE
WORK = ROOT / ".ai-slop/state/tp-miss-20260826"
CLONES = WORK / "clones"
PASS = STATE / "ai-writer-pass-20260826.jsonl"
CLUSTERS = STATE / "upstream-deduped-20260826.jsonl"
COMMITS = STATE / "ai-scan-state-repos/commits.jsonl"
SCAN_SUMMARY = STATE / "ai-scan-state-repos/summary.json"
LEDGER = rec.LEDGER
GHSA_ROOT = rec.GHSA_ROOT
ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b", re.I)
SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")


def clone_url(ident: str) -> str | None:
    host, owner, name = oss.split_identity(ident)
    if not owner or not name:
        return None
    if host == "github.com":
        return f"https://github.com/{owner}/{name}.git"
    if host == "gitlab.com":
        path = ident if ident.startswith("gitlab.com/") else f"gitlab.com/{owner}/{name}"
        return f"https://{path}.git"
    if ident.startswith("gitlab."):
        return f"https://{ident}.git"
    return None


def dest_for(ident: str) -> Path:
    return CLONES / ident.replace("/", "__").replace(":", "_")


def load_miss() -> tuple[list[dict], dict[str, dict]]:
    clusters: dict[str, dict] = {}
    with CLUSTERS.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            clusters[row["class_id"]] = row
    miss: list[dict] = []
    with PASS.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("in_ledger"):
                continue
            cluster = clusters.get(row["class_id"]) or {}
            row = {
                **row,
                "public_ids": list(cluster.get("public_ids") or []),
                "published": cluster.get("published"),
            }
            miss.append(row)
    return miss, clusters


def load_existing_scan_map() -> dict[str, dict]:
    payload = json.loads(SCAN_SUMMARY.read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for rec_row in payload.get("repositories") or []:
        ident = rec_row.get("repository_identity") or ""
        for key in gate.identity_keys(ident):
            out[key] = rec_row
    return out


def index_ai_commits() -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    by_sha: dict[str, list[dict]] = defaultdict(list)
    by_repo: dict[str, list[dict]] = defaultdict(list)
    with COMMITS.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            sha = str(row.get("sha") or "").lower()
            ident = str(row.get("repository_identity") or "").lower()
            if sha:
                by_sha[sha].append(row)
            if ident:
                by_repo[ident].append(row)
                for key in gate.identity_keys(ident):
                    by_repo[key].append(row)
    return by_sha, by_repo


def load_ghsa_by_id(wanted: set[str]) -> dict[str, dict]:
    wanted_l = {x.lower() for x in wanted if str(x).upper().startswith("GHSA-")}
    found: dict[str, dict] = {}
    if not GHSA_ROOT.is_dir() or not wanted_l:
        return found
    completed = subprocess.run(
        ["find", str(GHSA_ROOT), "-type", "f", "-name", "GHSA-*.json"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    for raw in completed.stdout.splitlines():
        path = Path(raw)
        stem = path.stem.lower()
        if stem not in wanted_l:
            continue
        try:
            rec_row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        found[stem] = rec_row
    return found


def explicit_id_hits(miss: list[dict], by_repo: dict[str, list[dict]]) -> list[dict]:
    """Map public IDs → miss classes, then scan each AI commit message once."""

    id_to_rows: dict[str, list[dict]] = defaultdict(list)
    for row in miss:
        for ident in row.get("public_ids") or []:
            id_to_rows[str(ident).upper()].append(row)
    if not id_to_rows:
        return []
    repo_keys_needed: set[str] = set()
    for row in miss:
        repo_keys_needed.update(gate.identity_keys(row["repo"]))
    hits: list[dict] = []
    seen_pair: set[tuple[str, str]] = set()
    scanned = set()
    for key in repo_keys_needed:
        for commit in by_repo.get(key) or []:
            sha = str(commit.get("sha") or "")
            ident = str(commit.get("repository_identity") or "")
            stamp = (ident, sha)
            if not sha or stamp in scanned:
                continue
            scanned.add(stamp)
            named = {
                match.upper()
                for match in ID_RE.findall(commit.get("message") or "")
                if match.upper() in id_to_rows
            }
            if not named:
                continue
            tools = sorted(
                {
                    m.get("tool")
                    for m in (commit.get("source_matches") or [])
                    if m.get("tool")
                }
            )
            for pub in named:
                for row in id_to_rows[pub]:
                    pair = (row["class_id"], sha)
                    if pair in seen_pair:
                        continue
                    seen_pair.add(pair)
                    hits.append(
                        {
                            "class_id": row["class_id"],
                            "repo": row["repo"],
                            "kind": row["kind"],
                            "public_ids": row.get("public_ids") or [],
                            "named_ids": sorted(named & {str(x).upper() for x in (row.get("public_ids") or [])}),
                            "sha": sha,
                            "authored_date": commit.get("authored_date"),
                            "tools": tools,
                            "changed_files": commit.get("changed_files") or [],
                            "route": "explicit_id_in_ai_commit",
                        }
                    )
    return hits


def fix_sha_hits(
    miss: list[dict], ghsa: dict[str, dict], by_sha: dict[str, list[dict]]
) -> list[dict]:
    hits: list[dict] = []
    for row in miss:
        shas: list[tuple[str, str]] = []
        for ident in row.get("public_ids") or []:
            rec_row = ghsa.get(str(ident).lower())
            if not rec_row:
                continue
            for ref in commit_reference_rows_from_record(rec_row):
                sha = str(ref.get("fix_sha") or "").lower()
                if SHA_RE.fullmatch(sha):
                    shas.append((sha, ref.get("reference_kind") or ""))
        seen = set()
        for sha, kind in shas:
            if sha in seen:
                continue
            commits = by_sha.get(sha) or []
            if not commits:
                continue
            seen.add(sha)
            commit = commits[0]
            hits.append(
                {
                    "class_id": row["class_id"],
                    "repo": row["repo"],
                    "kind": row["kind"],
                    "public_ids": row.get("public_ids") or [],
                    "sha": sha,
                    "reference_kind": kind,
                    "authored_date": commit.get("authored_date"),
                    "tools": sorted(
                        {
                            m.get("tool")
                            for m in (commit.get("source_matches") or [])
                            if m.get("tool")
                        }
                    ),
                    "changed_files": commit.get("changed_files") or [],
                    "route": "advisory_fix_sha_is_ai_commit",
                }
            )
    return hits


def blobless_clone(ident: str) -> dict:
    url = clone_url(ident)
    dest = dest_for(ident)
    started = time.monotonic()
    if dest.exists() and (dest / ".git").exists() or (dest / "HEAD").exists():
        return {
            "repo": ident,
            "ok": True,
            "path": str(dest),
            "reused": True,
            "elapsed_s": round(time.monotonic() - started, 2),
        }
    if not url:
        return {"repo": ident, "ok": False, "error": "no_clone_url", "elapsed_s": 0}
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "git",
        "--no-optional-locks",
        "clone",
        "--filter=blob:none",
        "--shallow-since=2025-05-01",
        url,
        str(dest),
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
    except subprocess.TimeoutExpired:
        subprocess.run(["rm", "-rf", str(dest)], check=False)
        return {"repo": ident, "ok": False, "error": "timeout", "elapsed_s": 240}
    if completed.returncode == 0:
        return {
            "repo": ident,
            "ok": True,
            "path": str(dest),
            "reused": False,
            "elapsed_s": round(time.monotonic() - started, 2),
        }
    # shallow-since unsupported → blobless full
    subprocess.run(["rm", "-rf", str(dest)], check=False)
    cmd2 = [
        "git",
        "--no-optional-locks",
        "clone",
        "--filter=blob:none",
        url,
        str(dest),
    ]
    try:
        completed = subprocess.run(
            cmd2,
            capture_output=True,
            text=True,
            timeout=420,
            check=False,
        )
    except subprocess.TimeoutExpired:
        subprocess.run(["rm", "-rf", str(dest)], check=False)
        return {"repo": ident, "ok": False, "error": "timeout_full", "elapsed_s": 420}
    if completed.returncode == 0:
        return {
            "repo": ident,
            "ok": True,
            "path": str(dest),
            "reused": False,
            "fallback": "blobless_full",
            "elapsed_s": round(time.monotonic() - started, 2),
        }
    subprocess.run(["rm", "-rf", str(dest)], check=False)
    err = (completed.stderr or completed.stdout or "")[-400:]
    return {
        "repo": ident,
        "ok": False,
        "error": err or f"exit {completed.returncode}",
        "elapsed_s": round(time.monotonic() - started, 2),
    }


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    do_clone = "--clone" in args
    workers = 8
    WORK.mkdir(parents=True, exist_ok=True)
    CLONES.mkdir(parents=True, exist_ok=True)
    miss, _clusters = load_miss()
    scan_map = load_existing_scan_map()
    by_repo_need: dict[str, int] = defaultdict(int)
    already_local = 0
    for row in miss:
        keys = gate.identity_keys(row["repo"])
        if any(k in scan_map for k in keys):
            already_local += 1
        else:
            by_repo_need[row["repo"]] += 1
    (WORK / "miss-classes.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in miss),
        encoding="utf-8",
    )
    print(
        f"miss classes {len(miss)}; already in local scan {already_local}; "
        f"need clone {len(by_repo_need)} repos / {sum(by_repo_need.values())} classes",
        flush=True,
    )

    print("indexing existing AI commits...", flush=True)
    by_sha, by_repo = index_ai_commits()
    wanted_ghsa = {
        str(ident)
        for row in miss
        for ident in (row.get("public_ids") or [])
        if str(ident).upper().startswith("GHSA-")
    }
    print(f"loading {len(wanted_ghsa)} GHSA records for fix SHAs...", flush=True)
    ghsa = load_ghsa_by_id(wanted_ghsa)
    print(f"loaded {len(ghsa)} GHSA files", flush=True)
    explicit = explicit_id_hits(miss, by_repo)
    fixes = fix_sha_hits(miss, ghsa, by_sha)
    hits_path = WORK / "tp-candidates-existing-scan.jsonl"
    with hits_path.open("w", encoding="utf-8") as handle:
        for hit in explicit + fixes:
            handle.write(json.dumps(hit, ensure_ascii=False) + "\n")
    summary = {
        "miss_classes": len(miss),
        "already_local_scan_classes": already_local,
        "need_clone_repos": len(by_repo_need),
        "need_clone_classes": sum(by_repo_need.values()),
        "explicit_id_hits": len(explicit),
        "explicit_id_classes": len({h["class_id"] for h in explicit}),
        "fix_sha_is_ai_hits": len(fixes),
        "fix_sha_is_ai_classes": len({h["class_id"] for h in fixes}),
        "explicit_by_kind": {
            k: sum(1 for h in explicit if h["kind"] == k)
            for k in ("reviewed", "unreviewed", "nvd_only")
        },
        "clone_pool": str(CLONES),
        "top_explicit_repos": sorted(
            (
                (sum(1 for h in explicit if h["repo"] == repo), repo)
                for repo in {h["repo"] for h in explicit}
            ),
            reverse=True,
        )[:20],
    }
    (WORK / "phase1-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2), flush=True)

    if do_clone:
        skip_huge = {
            "gitlab.com/gitlab-org/gitlab",
            "gitlab.com/wireshark/wireshark",
            "git.kernel.org/pub/scm/linux/kernel/git/stable/linux",
        }
        queue = [repo for repo in sorted(by_repo_need) if repo not in skip_huge]
        print(f"cloning {len(queue)} repos into {CLONES} workers={workers}", flush=True)
        results = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(blobless_clone, repo): repo for repo in queue}
            for i, fut in enumerate(as_completed(futs), 1):
                rec_row = fut.result()
                results.append(rec_row)
                if i % 10 == 0 or not rec_row.get("ok"):
                    print(
                        f"  {i}/{len(queue)} {rec_row.get('repo')} ok={rec_row.get('ok')} "
                        f"{rec_row.get('error') or rec_row.get('elapsed_s')}",
                        flush=True,
                    )
        (WORK / "clone-results.json").write_text(
            json.dumps(results, indent=2) + "\n", encoding="utf-8"
        )
        ok_n = sum(1 for r in results if r.get("ok"))
        print(f"clone done ok={ok_n}/{len(results)}", flush=True)
    return 0


if __name__ == "__main__":
    os.environ.setdefault("CVE_ANALYZER_FROZEN_LOCAL_SOURCES", "1")
    raise SystemExit(main())
