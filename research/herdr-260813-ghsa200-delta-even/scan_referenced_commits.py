#!/usr/bin/env python3
"""Fetch official-referenced commits and scan for AI trailers. Lane-only."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from paths import resolve_existing_or_new

LANE = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-delta-even")
# Reuse the existing /tmp commit_cache. A brand-new cache dir would be created under NEW_CLONE_ROOT.
CACHE = resolve_existing_or_new("commit_cache")
CACHE.mkdir(parents=True, exist_ok=True)
OUT = LANE / "commit_scan.jsonl"

sys.path.insert(0, "/home/hanqing/agents/ai-slop/cve-analyzer/src")
from cve_analyzer.ai_signatures import detect_ai_signals, detect_ai_signals_in_text  # noqa: E402
from cve_analyzer.models import AiSignal, CommitInfo  # noqa: E402


def gh_json(path: str) -> tuple[int, dict | list | None, str]:
    proc = subprocess.run(
        ["gh", "api", path],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return proc.returncode, None, (proc.stderr or proc.stdout)[:400]
    try:
        return 0, json.loads(proc.stdout), ""
    except json.JSONDecodeError as exc:
        return 2, None, str(exc)


def signal_rows(text: str) -> list[dict]:
    if not text:
        return []
    out = []
    for sig in detect_ai_signals_in_text(text):
        if isinstance(sig, AiSignal):
            out.append(
                {
                    "tool": getattr(sig.tool, "value", str(sig.tool)),
                    "signal_type": sig.signal_type,
                    "matched_text": sig.matched_text,
                    "confidence": sig.confidence,
                }
            )
        else:
            out.append({"raw": str(sig)})
    return out


def main() -> None:
    rows = [json.loads(l) for l in (LANE / "routing.jsonl").read_text().splitlines()]
    assigned = [r for r in rows if r["route"] == "ASSIGNED_TRIAGE"]
    jobs = []
    seen = set()
    for r in assigned:
        repo = r.get("repository")
        for sha in r.get("commit_refs") or []:
            key = (repo, sha.lower())
            if not repo or key in seen:
                continue
            seen.add(key)
            jobs.append({"ghsa_id": r["ghsa_id"], "repository": repo, "sha": sha})

    results = []
    for i, job in enumerate(jobs, 1):
        owner, name = job["repository"].split("/", 1)
        cache_path = CACHE / f"{owner}__{name}__{job['sha']}.json"
        if cache_path.exists():
            payload = json.loads(cache_path.read_text())
        else:
            code, data, err = gh_json(f"repos/{owner}/{name}/commits/{job['sha']}")
            if code != 0:
                payload = {"ok": False, "error": err, "http_code": code}
            else:
                commit = data.get("commit") or {}
                author = commit.get("author") or {}
                committer = commit.get("committer") or {}
                msg = commit.get("message") or ""
                info = CommitInfo(
                    sha=data.get("sha") or job["sha"],
                    author_name=author.get("name") or "",
                    author_email=author.get("email") or "",
                    committer_name=committer.get("name") or "",
                    committer_email=committer.get("email") or "",
                    message=msg,
                    authored_date=author.get("date") or "",
                )
                commit_signals = []
                for sig in detect_ai_signals(info):
                    commit_signals.append(
                        {
                            "tool": getattr(sig.tool, "value", str(sig.tool)),
                            "signal_type": sig.signal_type,
                            "matched_text": sig.matched_text,
                            "confidence": sig.confidence,
                        }
                    )
                payload = {
                    "ok": True,
                    "sha": data.get("sha"),
                    "html_url": data.get("html_url"),
                    "message": msg,
                    "author_name": author.get("name"),
                    "author_email": author.get("email"),
                    "committer_name": committer.get("name"),
                    "committer_email": committer.get("email"),
                    "date": author.get("date"),
                    "ai_signals": commit_signals,
                    "message_ai_signals": signal_rows(msg),
                }
            cache_path.write_text(json.dumps(payload, ensure_ascii=True))
            time.sleep(0.05)
        rec = {**job, **payload}
        results.append(rec)
        if i % 25 == 0 or rec.get("ai_signals") or rec.get("message_ai_signals"):
            hits = rec.get("message_ai_signals") or rec.get("ai_signals") or []
            print(f"{i}/{len(jobs)} {job['repository']} {job['sha'][:10]} hits={len(hits)}", flush=True)

    OUT.write_text("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in results))
    hit_ids = sorted({r["ghsa_id"] for r in results if r.get("ok") and (r.get("message_ai_signals") or r.get("ai_signals"))})
    print("jobs", len(jobs), "ok", sum(1 for r in results if r.get("ok")), "ai_hit_ids", len(hit_ids))
    print("\n".join(hit_ids))


if __name__ == "__main__":
    main()
