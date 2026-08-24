#!/usr/bin/env python3
"""Locate introducing hunks beyond official closers and scan them for AI."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

CACHE = Path("/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2")
LANE = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-delta-even-batch2")
SKIP_NAME = re.compile(
    r"(changelog|changes|news|history|security\.md|readme|license|authors|"
    r"package-lock|yarn\.lock|pnpm-lock|go\.sum|cargo\.lock|\.min\.js$|"
    r"(^|/)(package\.json|jsr\.json|composer\.json|pyproject\.toml)$)",
    re.I,
)
GENERIC_TOKENS = {
    "import", "return", "const", "function", "export", "class", "public", "private",
    "version", "string", "number", "object", "undefined", "null", "true", "false",
    "error", "message", "value", "result", "config", "options", "default",
}
SKIP_DIR = re.compile(r"(^|/)(docs?|website|examples?|fixtures?)/", re.I)

sys.path.insert(0, "/home/hanqing/agents/ai-slop/cve-analyzer/src")
from cve_analyzer.ai_signatures import detect_ai_signals  # noqa: E402
from cve_analyzer.models import CommitInfo  # noqa: E402


def run(repo: Path, args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**dict(**{k: v for k, v in __import__("os").environ.items()}), "GIT_OPTIONAL_LOCKS": "0"},
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def dest_for(spec: str) -> Path:
    return CACHE / spec.replace("/", "__")


def resolve_sha(repo: Path, ref: str) -> str | None:
    code, out, _ = run(repo, ["rev-parse", "--verify", ref])
    if code == 0 and out.strip():
        return out.strip()
    code, out, _ = run(repo, ["rev-parse", "--verify", ref[:12]])
    if code == 0 and out.strip():
        return out.strip()
    return None


def commit_meta(repo: Path, sha: str) -> dict:
    fmt = "%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%aI%x1f%s%x1f%B"
    code, out, err = run(repo, ["log", "-1", f"--format={fmt}", sha])
    if code != 0 or not out.strip():
        return {"ok": False, "sha": sha, "error": err[:300]}
    parts = out.split("\x1f", 7)
    if len(parts) < 8:
        return {"ok": False, "sha": sha, "error": "parse"}
    sha_f, an, ae, cn, ce, ad, subj, body = parts
    info = CommitInfo(
        sha=sha_f.strip(),
        author_name=an,
        author_email=ae,
        committer_name=cn,
        committer_email=ce,
        message=body,
        authored_date=ad,
    )
    signals = []
    for sig in detect_ai_signals(info):
        signals.append(
            {
                "tool": getattr(sig.tool, "value", str(sig.tool)),
                "signal_type": sig.signal_type,
                "matched_text": sig.matched_text,
                "confidence": sig.confidence,
            }
        )
    return {
        "ok": True,
        "sha": sha_f.strip(),
        "author_name": an,
        "author_email": ae,
        "committer_name": cn,
        "committer_email": ce,
        "authored_date": ad,
        "subject": subj.strip(),
        "ai_signals": signals,
        "parent_count": int(run(repo, ["rev-list", "--parents", "-n", "1", sha_f.strip()])[1].count(" ")),
    }


def first_tags(repo: Path, sha: str) -> list[str]:
    code, out, _ = run(repo, ["describe", "--contains", "--always", sha], timeout=15)
    if code == 0 and out.strip():
        return [out.strip().split("\n")[0][:80]]
    code, out, _ = run(repo, ["tag", "--contains", sha], timeout=15)
    tags = [t.strip() for t in out.splitlines() if t.strip()]
    # keep a short prefix; prefer semver-looking
    return tags[:12]


def changed_files(repo: Path, sha: str) -> list[str]:
    code, out, _ = run(repo, ["diff-tree", "--no-commit-id", "--name-only", "-r", sha])
    if code != 0:
        return []
    files = []
    for line in out.splitlines():
        path = line.strip()
        if not path or SKIP_NAME.search(path) or SKIP_DIR.search(path):
            continue
        files.append(path)
    return files[:30]


def blame_origin_shas(repo: Path, fix: str, files: list[str]) -> list[str]:
    """SHAs that last touched lines deleted by the fix (parent blame)."""
    parent = resolve_sha(repo, f"{fix}^")
    if not parent:
        return []
    shas: set[str] = set()
    for path in files[:4]:
        code, diff, _ = run(repo, ["diff", "-U0", parent, fix, "--", path], timeout=20)
        if code != 0 or not diff:
            continue
        ranges = []
        for line in diff.splitlines():
            m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+", line)
            if not m:
                continue
            start = int(m.group(1))
            count = int(m.group(2) or "1")
            if count == 0:
                continue
            ranges.append((start, start + count - 1))
        for start, end in ranges[:3]:
            code, blame, _ = run(
                repo,
                ["blame", "-l", "-w", f"-L{start},{end}", parent, "--", path],
                timeout=12,
            )
            if code != 0:
                continue
            for bl in blame.splitlines():
                m = re.match(r"^([0-9a-f]{40})", bl)
                if m and not m.group(1).startswith("0" * 8):
                    shas.add(m.group(1))
        if len(shas) >= 20:
            break
    return sorted(shas)


def pick_search_tokens(repo: Path, fix: str, files: list[str]) -> list[str]:
    tokens = []
    for path in files[:6]:
        code, diff, _ = run(repo, ["diff", "-U0", f"{fix}^", fix, "--", path], timeout=30)
        if code != 0:
            continue
        for line in diff.splitlines():
            if not line.startswith("-") or line.startswith("---"):
                continue
            text = line[1:].strip()
            if len(text) < 12 or len(text) > 80:
                continue
            if re.fullmatch(r"[{}();,]+", text):
                continue
            ident = re.findall(r"[A-Za-z_][A-Za-z0-9_]{5,}", text)
            for tok in ident:
                if tok.lower() not in GENERIC_TOKENS:
                    tokens.append(tok)
            if len(tokens) >= 12:
                return tokens
    return tokens[:12]


def log_s_origins(repo: Path, fix: str, tokens: list[str], files: list[str]) -> list[str]:
    shas: set[str] = set()
    parent = f"{fix}^"
    for tok in tokens[:6]:
        args = ["log", "--format=%H", "-n", "8", "-S", tok, parent]
        if files:
            args += ["--", *files[:8]]
        code, out, _ = run(repo, args, timeout=20)
        if code == 0:
            for line in out.splitlines():
                if re.fullmatch(r"[0-9a-f]{40}", line.strip()):
                    shas.add(line.strip())
        if len(shas) >= 15:
            break
    return sorted(shas)


def review_one(packet: dict) -> dict:
    gid = packet["ghsa_id"]
    spec = packet["repository"]
    repo = dest_for(spec)
    rec = {
        "ghsa_id": gid,
        "repository": spec,
        "repo_path": str(repo),
        "clone_ok": (repo / ".git").exists(),
        "fix_shas": [],
        "origin_candidates": [],
        "ai_origin_hits": [],
        "resolution": None,
        "notes": [],
    }
    if not rec["clone_ok"]:
        rec["resolution"] = "BLOCKED_CLONE"
        rec["notes"].append("Repository clone missing under batch2 cache")
        return rec
    fix_shas = []
    for ref in packet.get("commit_refs") or []:
        sha = resolve_sha(repo, ref)
        if sha:
            fix_shas.append(sha)
        else:
            rec["notes"].append(f"official commit ref not in clone: {ref}")
    rec["fix_shas"] = fix_shas
    if not fix_shas:
        rec["resolution"] = "BLOCKED_NO_FIX_SHA"
        rec["notes"].append("No official fix commit resolved in the clone")
        return rec

    origin_shas: list[str] = []
    for fix in fix_shas[:3]:
        files = changed_files(repo, fix)
        rec.setdefault("fix_files", [])
        rec["fix_files"].extend(files)
        blamed = blame_origin_shas(repo, fix, files)
        tokens = pick_search_tokens(repo, fix, files)
        logged = log_s_origins(repo, fix, tokens, files)
        for sha in blamed + logged:
            if sha not in fix_shas and sha not in origin_shas:
                origin_shas.append(sha)
    rec["origin_candidate_shas"] = origin_shas
    metas = []
    ai_hits = []
    for sha in origin_shas[:20]:
        meta = commit_meta(repo, sha)
        metas.append(meta)
        if meta.get("ok") and meta.get("ai_signals"):
            ai_hits.append(meta)
    rec["origin_candidates"] = metas
    rec["ai_origin_hits"] = ai_hits
    # also record closer meta
    rec["fix_meta"] = [commit_meta(repo, sha) for sha in fix_shas[:3]]
    rec["fix_first_tags"] = {sha[:12]: first_tags(repo, sha) for sha in fix_shas[:3]}

    if ai_hits:
        rec["resolution"] = "AI_ORIGIN_CANDIDATE"
        rec["notes"].append("At least one introducing-hunk candidate has an AI marker; needs gate review")
    elif origin_shas:
        rec["resolution"] = "HUMAN_ORIGIN_RESOLVED"
        rec["notes"].append("Introducing-hunk candidates resolved; none carry an AI marker")
    else:
        rec["resolution"] = "UNKNOWN_ORIGIN_UNRESOLVED"
        rec["notes"].append("Could not attribute deleted/changed hunks to a prior introducing commit")
    return rec


def main() -> None:
    packets = [json.loads(l) for l in (LANE / "advisory_packets.jsonl").read_text().splitlines() if l.strip()]
    out = LANE / "origin_scan.jsonl"
    existing = {}
    if out.exists():
        for line in out.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                existing[row["ghsa_id"]] = row
    results = []
    for i, packet in enumerate(packets, 1):
        prev = existing.get(packet["ghsa_id"])
        if prev and prev.get("clone_ok") and prev.get("resolution") in {
            "HUMAN_ORIGIN_RESOLVED",
            "AI_ORIGIN_CANDIDATE",
            "UNKNOWN_ORIGIN_UNRESOLVED",
            "BLOCKED_NO_FIX_SHA",
        }:
            rec = prev
            print(f"{i}/80 skip {packet['ghsa_id']} {rec.get('resolution')}", flush=True)
        else:
            print(f"{i}/80 review {packet['ghsa_id']} {packet['repository']}", flush=True)
            try:
                rec = review_one(packet)
            except Exception as exc:  # noqa: BLE001
                rec = {
                    "ghsa_id": packet["ghsa_id"],
                    "repository": packet["repository"],
                    "clone_ok": True,
                    "resolution": "UNKNOWN_ORIGIN_UNRESOLVED",
                    "notes": [f"review exception: {type(exc).__name__}: {exc}"],
                    "origin_candidates": [],
                    "ai_origin_hits": [],
                }
        results.append(rec)
        if i % 5 == 0:
            out.write_text("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in results))
    out.write_text("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in results))
    from collections import Counter
    print(json.dumps(Counter(r.get("resolution") for r in results), indent=2))
    print("ai_origin_ids", [r["ghsa_id"] for r in results if r.get("ai_origin_hits")])


if __name__ == "__main__":
    main()
