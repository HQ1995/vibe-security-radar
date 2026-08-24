#!/usr/bin/env python3
"""ABORTED. File-density ranking is not a review census. Do not run."""
raise SystemExit("aborted: file-density ranking must not be re-run for this shard")


SHA-equal advisory-ref AND AI-commit hits were already reviewed in the frozen
G-N packet. Remaining G-J rows are ranked by AI-marked commits that appear in
the file history of the advisory-cited fix (parent..files). Line blame is a
refinement on the top file-history hits.

Hits remain routing until seven-gate review.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

GN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gn")
OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-commitfirst-gj-grok46-medium")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones")
OWNER_PREFIXES = frozenset("ghij")
FIXISH = re.compile(
    r"^(fix|fixes|fixed|hotfix|security|sec|patch|chore|docs|test|ci|bump|release)\b",
    re.I,
)
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
WORKERS = 8


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def git(path: Path, *args: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(path), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(exc.cmd, 124, "", "timeout")


def repo_dest(repository: str) -> Path:
    owner, name = repository.split("/", 1)
    return CLONE_ROOT / f"{owner}__{name}"


def parse_deleted_ranges(diff: str) -> dict[str, list[tuple[int, int]]]:
    files: dict[str, list[tuple[int, int]]] = defaultdict(list)
    current = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current = None
            continue
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            current = None if path == "/dev/null" else path
            continue
        if current is None:
            continue
        m = HUNK_RE.match(line)
        if not m:
            continue
        old_start = int(m.group(1))
        old_len = int(m.group(2) or "1")
        if old_len:
            files[current].append((old_start, old_len))
    return files


def file_history_hits(clone: Path, parent: str, files: list[str], ai_index: dict[str, dict]) -> dict[str, set[str]]:
    hits: dict[str, set[str]] = defaultdict(set)
    for path in files[:6]:
        hist = git(clone, "log", "--pretty=%H", "-n", "40", parent, "--", path, timeout=12)
        for sha in hist.stdout.splitlines():
            sha = sha.strip().lower()
            if sha in ai_index:
                hits[sha].add(path)
    return hits


def blame_hits(
    clone: Path, parent: str, ranges: dict[str, list[tuple[int, int]]], ai_index: dict[str, dict], allow_files: set[str]
) -> dict[str, dict]:
    out: dict[str, dict] = {}
    spans_done = 0
    for path, spans in ranges.items():
        if path not in allow_files:
            continue
        for start, length in spans:
            if length > 40 or spans_done >= 12:
                continue
            end = start + length - 1
            completed = git(clone, "blame", "-l", f"-L{start},{end}", parent, "--", path, timeout=6)
            spans_done += 1
            if completed.returncode != 0:
                continue
            for line in completed.stdout.splitlines():
                sha = line.split(" ", 1)[0].lstrip("^")[:40].lower()
                if sha not in ai_index:
                    continue
                rec = out.setdefault(sha, {"lines": 0, "files": set()})
                rec["lines"] += 1
                rec["files"].add(path)
    return out


def analyze_row(row: dict, scan: dict) -> dict:
    refs = [r for r in (row.get("commit_refs") or []) if r]
    if not refs:
        return {"ghsa_id": row["ghsa_id"], "status": "skip", "reason": "no_commit_refs"}
    ai_commits = scan.get("ai_commits") or []
    if not ai_commits:
        return {"ghsa_id": row["ghsa_id"], "status": "skip", "reason": "no_ai_commits"}
    clone = Path(scan.get("path") or repo_dest(row["repository"]))
    if not clone.exists():
        return {"ghsa_id": row["ghsa_id"], "status": "skip", "reason": "clone_missing"}
    ai_index = {c["sha"].lower(): c for c in ai_commits}
    hits: list[dict] = []
    for ref in refs[:3]:
        exists = git(clone, "cat-file", "-t", ref, timeout=8)
        if exists.returncode != 0 or exists.stdout.strip() != "commit":
            continue
        parent_ck = git(clone, "rev-parse", f"{ref}^", timeout=8)
        if parent_ck.returncode != 0:
            continue
        parent = parent_ck.stdout.strip()
        names = git(clone, "diff", "--name-only", parent, ref, timeout=12)
        changed = [line.strip() for line in names.stdout.splitlines() if line.strip()]
        if not changed:
            continue
        file_map = file_history_hits(clone, parent, changed, ai_index)
        blamed: dict[str, dict] = {}
        if file_map:
            diff = git(clone, "diff", "-U0", parent, ref, timeout=12)
            ranges = parse_deleted_ranges(diff.stdout) if diff.returncode == 0 else {}
            allow = set().union(*file_map.values())
            blamed = blame_hits(clone, parent, ranges, ai_index, allow)
        source_shas = set(blamed) | set(file_map)
        for sha in source_shas:
            commit = ai_index[sha]
            subject = commit.get("subject") or ""
            files = sorted((blamed.get(sha) or {}).get("files") or file_map.get(sha) or [])
            hits.append(
                {
                    "fix_sha": ref.lower(),
                    "intro_sha": sha,
                    "intro_subject": subject,
                    "intro_date": commit.get("date"),
                    "marker_pattern": commit.get("marker_pattern"),
                    "blamed_lines": int((blamed.get(sha) or {}).get("lines") or 0),
                    "files": files,
                    "evidence": "blame" if sha in blamed else "file_history",
                    "fixish_subject": bool(FIXISH.match(subject)),
                }
            )
    if not hits:
        return {"ghsa_id": row["ghsa_id"], "status": "skip", "reason": "no_ai_intersection_with_fix_files"}
    hits.sort(key=lambda h: (0 if h["evidence"] == "blame" else 1, -h["blamed_lines"], h["intro_sha"]))
    best = hits[0]
    return {
        "status": "ranked",
        "ghsa_id": row["ghsa_id"],
        "repository": row["repository"],
        "summary": row.get("summary"),
        "aliases": row.get("aliases") or [],
        "advisory_path": row.get("path"),
        "severity": row.get("severity"),
        "commit_refs": refs,
        "hit_count": len(hits),
        "total_blamed_lines": sum(h["blamed_lines"] for h in hits),
        "best": best,
        "hits": hits[:8],
        "routing_only": True,
    }


def rank_key(item: dict) -> tuple:
    best = item["best"]
    return (
        0 if best.get("evidence") == "blame" else 1,
        0 if not best["fixish_subject"] else 1,
        -best["blamed_lines"],
        -item["total_blamed_lines"],
        -len(best["files"]),
        item["ghsa_id"],
    )


def main() -> None:
    assigned = load_jsonl(GN / "assigned.jsonl")
    cases = load_jsonl(GN / "cases.jsonl")
    scans = load_jsonl(GN / "ai-commit-scans.jsonl")
    reviewed = {row["case_id"].upper() for row in cases}
    scan_by_repo = {row["repository"]: row for row in scans}
    gj = [
        row
        for row in assigned
        if row.get("owner", "").casefold()[:1] in OWNER_PREFIXES and row["ghsa_id"].upper() not in reviewed
    ]
    ranked: list[dict] = []
    skipped: dict[str, int] = defaultdict(int)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = [pool.submit(analyze_row, row, scan_by_repo.get(row["repository"]) or {}) for row in gj]
        for fut in as_completed(futs):
            result = fut.result()
            if result.get("status") == "ranked":
                ranked.append(result)
            else:
                skipped[result.get("reason") or "unknown"] += 1
    ranked.sort(key=rank_key)
    payload = {
        "algorithm": (
            "Population: frozen G-N assigned.jsonl, owner prefix G-J, exclude G-N cases.jsonl "
            "identities and therefore all baseline/final-review GHSAs already in that packet. "
            "Exact SHA advisory-ref AND AI-commit intersections were exhausted (44 G-J, all reviewed). "
            "Remaining rank: AI-marked commits in git log of files changed by parent(advisory_commit_ref); "
            "line-blame refinement when file-history hits exist. "
            "Order: blame evidence, non-fix subject, blamed-line count, GHSA id. Routing only."
        ),
        "gj_unreviewed": len(gj),
        "ranked": len(ranked),
        "skipped_by_reason": dict(sorted(skipped.items())),
        "top30": ranked[:30],
        "all_ranked_ids": [r["ghsa_id"] for r in ranked],
    }
    (OWNED / "origin-rank.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (OWNED / "origin-rank.jsonl").open("w", encoding="utf-8") as fh:
        for row in ranked:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    print(
        json.dumps(
            {
                "ranked": len(ranked),
                "skipped": dict(skipped),
                "top": [
                    {
                        "id": r["ghsa_id"],
                        "repo": r["repository"],
                        "ev": r["best"]["evidence"],
                        "lines": r["best"]["blamed_lines"],
                        "fixish": r["best"]["fixish_subject"],
                        "subj": r["best"]["intro_subject"][:90],
                    }
                    for r in ranked[:30]
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
