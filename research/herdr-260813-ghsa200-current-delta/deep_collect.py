#!/usr/bin/env python3
"""Phase 5: bounded deep evidence collection for one GHSA case.

Clones (blobless, shallow) the vulnerable repo under scratch/repos/, fetches the
advisory's fix commit SHAs, locates the introducing commits of the fixed lines
via blame at the fix parent, and dumps machine-readable evidence to
scratch/evidence/<GHSA>.json. Adjudication is done by the worker afterwards;
this script only collects first-party git facts.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from build_delta import OWN, SCRATCH  # noqa: E402

# NEW clones/large objects go under /home cache (resource directive 2026-08-13);
# existing /tmp data stays in place. Mixed paths recorded explicitly.
NEW_BASE = Path("/home/hanqing/.cache/ghsa200-worker-clones/current-delta")
NEW_BASE.mkdir(parents=True, exist_ok=True)

AI_TRAILER_RE = re.compile(
    r"(copilot|claude|chatgpt|gpt-?[0-9o]|gemini|codex|aider|openclaw|cursor|qwen|devin|"
    r"windsurf|amazon q|codewhisperer|tabnine|codeium|perplexity|grok|deepseek|sonnet|opus|o1|o3)",
    re.IGNORECASE)
AI_MSG_RE = re.compile(
    r"(generated (with|by)|authored by ai|ai[- ]assisted|written by ai|prompt:|"
    r"\bcopilot\b|\bclaude\b|chatgpt|\bgpt-?[0-9o]\b|\bgemini\b|\bcodex\b|\baider\b|"
    r"openclaw|cursor ai|\bqwen\b|\bdevin\b|windsurf|amazon q|codewhisperer|tabnine|codeium|"
    r"\bdeepseek\b|\bgrok\b|\bsonnet\b|\bopus\b)",
    re.IGNORECASE)


def sh(cmd, cwd=None, timeout=300):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def collect(ghsa_id: str) -> dict:
    rows = {}
    for line in (OWN / "reviewed-delta.jsonl").open():
        r = json.loads(line)
        rows[r["ghsa"]] = r
    if ghsa_id not in rows:
        raise SystemExit(f"{ghsa_id} not in reviewed-delta")
    adv = rows[ghsa_id]["new"]
    ev = {
        "ghsa": ghsa_id,
        "aliases": adv.get("aliases"),
        "published": adv.get("published"),
        "summary": adv.get("summary"),
        "packages": adv.get("packages"),
        "ecosystems": adv.get("ecosystems"),
        "ranges": adv.get("ranges"),
        "ref_urls": adv.get("ref_urls"),
        "ref_repos": adv.get("ref_repos"),
        "fix_shas": adv.get("ref_commit_shas"),
        "ai_kw_hits_in_details": adv.get("ai_kw_hits"),
    }
    repos = adv.get("ref_repos") or []
    if not repos:
        ev["blocked"] = "no github repo reference in advisory"
        return ev
    repo = max(set(repos), key=lambda r: sum(1 for u in adv.get("ref_urls") if r in u))
    ev["repo"] = repo
    slug = repo.replace("/", "__")
    repodir = NEW_BASE / "repos" / slug
    repodir.mkdir(parents=True, exist_ok=True)
    if not (repodir / ".git").exists():
        sh(["git", "init", "-q", str(repodir)])
        sh(["git", "-C", str(repodir), "remote", "add", "origin", f"https://github.com/{repo}.git"])
    ev["fetch"] = []
    for sha in adv.get("ref_commit_shas") or []:
        if not re.match(r"^[0-9a-f]{40}$", sha):
            continue
        out = sh(["git", "-C", str(repodir), "fetch", "-q", "--depth=300", "--filter=blob:none",
                  "origin", sha], timeout=420)
        ev["fetch"].append({"sha": sha, "rc": out.returncode})

    fix_analysis = []
    for sha in adv.get("ref_commit_shas") or []:
        if not re.match(r"^[0-9a-f]{40}$", sha):
            continue
        exists = sh(["git", "-C", str(repodir), "cat-file", "-e", f"{sha}^{{commit}}"])
        if exists.returncode != 0:
            fix_analysis.append({"sha": sha, "missing": True})
            continue
        parent = sh(["git", "-C", str(repodir), "rev-parse", f"{sha}^"]).stdout.strip()
        msg = sh(["git", "-C", str(repodir), "log", "-1", "--format=%H%n%an%n%ae%n%ad%n%B", sha]).stdout
        stat = sh(["git", "-C", str(repodir), "show", "--stat", "--format=", sha]).stdout
        files = sh(["git", "-C", str(repodir), "diff-tree", "--no-commit-id", "--name-only", "-r", sha]).stdout.splitlines()
        # per-file recent history at fix parent
        file_logs = []
        for f in files[:12]:
            if not f:
                continue
            log = sh(["git", "-C", str(repodir), "log", "--format=%H|%s", "-12", parent, "--", f]).stdout.splitlines()
            file_logs.append({"file": f, "recent_log": log})
        # blame vulnerable lines at fix parent for the first changed file
        patch = sh(["git", "-C", str(repodir), "show", "--format=", "--unified=0", sha]).stdout
        hunk_ranges = []
        cur_file = None
        for line in patch.splitlines():
            m = re.match(r"^diff --git a/(.*) b/(.*)$", line)
            if m:
                cur_file = m.group(1)
                continue
            m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+", line)
            if m and cur_file:
                hunk_ranges.append((cur_file, int(m.group(1)), int(m.group(2) or "1")))
        blame_owners = []
        for fname, start, cnt in hunk_ranges[:10]:
            bl = sh(["git", "-C", str(repodir), "blame", "--line-porcelain", "-L", f"{start},{cnt}",
                     parent, "--", fname], timeout=180)
            owners = set()
            for ln in bl.stdout.splitlines():
                m = re.match(r"^([0-9a-f]{40}) \d+ \d+ \d+$", ln)
                if m:
                    owners.add(m.group(1))
            for own in owners:
                omsg = sh(["git", "-C", str(repodir), "log", "-1", "--format=%H|%an|%ae|%s|%B", own]).stdout
                blame_owners.append({"file": fname, "lines": f"{start}-{start+cnt-1}",
                                     "commit": own, "message": omsg[:900],
                                     "ai_trailer_hits": [t for t in omsg.splitlines() if AI_TRAILER_RE.search(t)],
                                     "ai_msg_hits": [l for l in omsg.splitlines() if AI_MSG_RE.search(l)]})
        fix_analysis.append({
            "sha": sha, "parent": parent,
            "message": msg[:2000], "stat": stat[:1500],
            "files": files[:40],
            "ai_trailer_hits": [t for t in msg.splitlines() if AI_TRAILER_RE.search(t)],
            "ai_msg_hits": [ln for ln in msg.splitlines() if AI_MSG_RE.search(ln)],
            "file_logs": file_logs,
            "blame_owners": blame_owners,
        })
    versions = []
    for rng in adv.get("ranges") or []:
        for fv in rng.get("fixed") or []:
            versions.append(fv)
    ev["fixed_versions"] = sorted(set(versions))
    ev["tags"] = []
    lsr = sh(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"], timeout=120)
    for line in lsr.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        tsha, ref = parts
        tag = ref.replace("refs/tags/", "")
        for v in sorted(set(versions)):
            vv = v.lstrip("vV")
            if tag in (v, f"v{v}", f"V{v}", f"{vv}") or tag.endswith(f"/{v}"):
                ev["tags"].append({"version": v, "tag": tag, "sha": tsha})
    ev["fix_analysis"] = fix_analysis
    ev_out = NEW_BASE / "evidence" / f"{ghsa_id}.json"
    ev_out.parent.mkdir(exist_ok=True)
    ev_out.write_text(json.dumps(ev, indent=2, sort_keys=True))
    ev["evidence_file"] = str(ev_out)
    ev["evidence_sha256"] = sha256_bytes(ev_out.read_bytes())
    return ev


def main() -> int:
    gid = sys.argv[1].upper()
    ev = collect(gid)
    print(json.dumps({k: v for k, v in ev.items() if k not in ("fix_analysis",)},
                     indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
