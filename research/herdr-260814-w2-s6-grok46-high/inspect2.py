#!/usr/bin/env python3
import json, re, subprocess
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones")
AI_RE = re.compile(
    r"(Co-Authored-By:|Assisted-by:|Authored-by:|Generated-by:|\\bCodex\\b|\\bClaude (Code|Opus|Sonnet)\\b|\\bGitHub Copilot\\b|\\bCopilot\\b|\\bCursor\\b|\\bDevin\\b|\\bJules\\b|\\bRovo\\b|\\bQwen Code\\b|\\bOpenWork\\b|\\bQoder\\b|\\bCodeRabbit\\b|\\bKimi\\b|\\bGrok\\b|\\bTrae\\b|\\bOpenAI\\b|\\bChatGPT\\b)",
    re.I,
)
COMMIT_RE = re.compile(r"https://github.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")
PKG_RE = re.compile(r"https://github.com/([^/]+)/([^/]+?)(?:\.git)?(?:/|$)")
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


def parse_row(r):
    repos = []
    shas = []
    for ref in r.get("references") or []:
        url = ref.get("url") or ""
        m = COMMIT_RE.search(url)
        if m:
            owner, name, sha = m.group(1), m.group(2), m.group(3)
            repos.append(f"{owner}/{name}")
            shas.append((sha, owner, name))
            continue
        if "/commit/" in url:
            continue
        m = PKG_RE.search(url)
        if m and ref.get("type") in ("PACKAGE", "WEB", "") and "security/advisories" not in url and "/releases/" not in url and "/issues/" not in url and "/pull/" not in url:
            repos.append(f"{m.group(1)}/{m.group(2)}")
    # unique preserve
    seen = set(); urepos = []
    for x in repos:
        if x not in seen and "FriendsOfPHP" not in x:
            seen.add(x); urepos.append(x)
    return urepos, shas


def main():
    rows = [json.loads(l) for l in (OWNED / "advisory_extract.jsonl").read_text().splitlines() if l.strip()]
    out = []
    for r in rows:
        repos, shas = parse_row(r)
        rec = {
            "ghsa": r["ghsa"],
            "id": r.get("id"),
            "summary": (r.get("summary") or "")[:120],
            "aliases": r.get("aliases") or [],
            "repos": repos,
            "withdrawn": r.get("withdrawn"),
            "shas": [],
        }
        for sha, owner, name in shas:
            clone = find_clone(owner, name)
            item = {"sha": sha, "repo": f"{owner}/{name}", "clone": str(clone) if clone else None, "exists": False, "ai": False, "head": ""}
            if clone:
                exists = git(clone, "cat-file", "-e", f"{sha}^{{commit}}")
                item["exists"] = exists.returncode == 0
                if item["exists"]:
                    msg = git(clone, "log", "-1", "--format=%H%n%an <%ae>%n%s%n%b", sha)
                    body = msg.stdout if msg.returncode == 0 else ""
                    item["ai"] = bool(AI_RE.search(body))
                    item["head"] = body[:500]
            rec["shas"].append(item)
        rec["clone"] = None
        if repos:
            o, _, n = repos[0].partition("/")
            c = find_clone(o, n)
            rec["clone"] = str(c) if c else None
        out.append(rec)
    (OWNED / "sha_inspect.json").write_text(json.dumps(out, indent=2))
    print("wrote", len(out))


if __name__ == "__main__":
    main()
