#!/usr/bin/env python3
import json, re, subprocess
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones")
COMMIT_RE = re.compile(r"https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")
PKG_RE = re.compile(r"https://github.com/([^/]+)/([^/]+)$")
AI_RE = re.compile(
    r"(Co-Authored-By:|Assisted-by:|Authored-by:|Generated-by:|\bCodex\b|\bClaude (Code|Opus|Sonnet)\b|\bGitHub Copilot\b|\bCopilot\b|\bCursor\b|\bDevin\b|\bJules\b|\bRovo\b|\bQwen Code\b|\bOpenWork\b|\bQoder\b|\bCodeRabbit\b|\bKimi\b|\bGrok\b|\bTrae\b|\bOpenAI\b|\bChatGPT\b)",
    re.I,
)
PREFERRED = [
    "current-delta/repos",
    "commit-oz/repos",
    "commit-gn/clones",
    "commit-af/repos",
    "delta-even-batch2",
]

def git(cwd, *args, timeout=20):
    return subprocess.run(
        ["git", "--no-optional-locks", "-C", str(cwd), *args],
        capture_output=True, text=True, timeout=timeout,
    )

def find_clone(owner, name):
    key = f"{owner}__{name}"
    for pref in PREFERRED:
        p = CLONE_ROOT / pref / key
        if (p / ".git").exists() or (p / ".git").is_file():
            return p
    for m in CLONE_ROOT.glob(f"**/{key}"):
        if (m / ".git").exists() or (m / ".git").is_file():
            return m
    return None

def main():
    rows = [json.loads(l) for l in (OWNED / "advisory_extract.jsonl").read_text().splitlines() if l.strip()]
    out = []
    for r in rows:
        refs = r.get("references") or []
        commits = []
        repos = []
        for ref in refs:
            url = (ref.get("url") or "") if isinstance(ref, dict) else str(ref)
            m = COMMIT_RE.search(url)
            if m:
                owner, name, sha = m.group(1), m.group(2), m.group(3)
                commits.append({"owner": owner, "name": name, "sha": sha, "url": url})
                repos.append(f"{owner}/{name}")
            m2 = PKG_RE.search(url.rstrip("/"))
            if m2 and "github.com" in url and "/commit/" not in url and "/security/" not in url and "/releases/" not in url and "/issues/" not in url and "/pull/" not in url:
                repos.append(f"{m2.group(1)}/{m2.group(2)}")
        seen = []
        for x in repos:
            if x not in seen and x not in ("FriendsOfPHP/security-advisories",):
                seen.append(x)
        repo = seen[0] if seen else None
        clone = find_clone(*repo.split("/", 1)) if repo else None
        rec = {
            "ghsa": r["ghsa"],
            "id": r.get("id"),
            "summary": r.get("summary"),
            "aliases": r.get("aliases") or [],
            "packages": r.get("packages") or [],
            "repo": repo,
            "repos": seen,
            "clone": str(clone) if clone else None,
            "commit_urls": commits,
            "shas": [],
        }
        shas = []
        for c in commits:
            if c["sha"] not in shas:
                shas.append(c["sha"])
        if clone:
            for sha in shas:
                exists = git(clone, "cat-file", "-e", f"{sha}^{{commit}}")
                body = ""
                if exists.returncode == 0:
                    msg = git(clone, "log", "-1", "--format=%H%n%an <%ae>%n%s%n%b", sha)
                    body = msg.stdout if msg.returncode == 0 else ""
                rec["shas"].append({
                    "sha": sha,
                    "exists": exists.returncode == 0,
                    "ai": bool(AI_RE.search(body)),
                    "head": body[:500],
                })
        else:
            rec["shas"] = [{"sha": s, "exists": False, "ai": False, "head": ""} for s in shas]
        out.append(rec)
    (OWNED / "sha_inspect.json").write_text(json.dumps(out, indent=2))
    print("wrote", len(out), "ai", sum(1 for r in out for s in r["shas"] if s.get("ai")), "exists", sum(1 for r in out for s in r["shas"] if s.get("exists")))

if __name__ == "__main__":
    main()
