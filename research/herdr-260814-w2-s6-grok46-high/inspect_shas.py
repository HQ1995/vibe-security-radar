#!/usr/bin/env python3
import json, re, subprocess
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones")
AI_RE = re.compile(
    r"(Co-Authored-By:|Assisted-by:|Authored-by:|Generated-by:|\bCodex\b|\bClaude (Code|Opus|Sonnet)\b|\bGitHub Copilot\b|\bCopilot\b|\bCursor\b|\bDevin\b|\bJules\b|\bRovo\b|\bQwen Code\b|\bOpenWork\b|\bQoder\b|\bCodeRabbit\b|\bKimi\b|\bGrok\b|\bTrae\b|\bOpenAI\b|\bChatGPT\b)",
    re.I,
)

REPO_MAP = {
    "craftcms/cms": "craftcms__cms",
    "PHPCSStandards/PHP_CodeSniffer": "PHPCSStandards__PHP_CodeSniffer",
    "uhop/node-re2": "uhop__node-re2",
    "stephanrauh/ngx-extended-pdf-viewer": "stephanrauh__ngx-extended-pdf-viewer",
    "mozilla/pdf.js": "mozilla__pdf.js",
    "jhy/jsoup": "jhy__jsoup",
    "thephpleague/commonmark": "thephpleague__commonmark",
    "nodeca/js-yaml": "nodeca__js-yaml",
    "silverstripe/silverstripe-cms": "silverstripe__silverstripe-cms",
    "aws/aws-cli": "aws__aws-cli",
    "nrwl/nx": "nrwl__nx",
    "mermaid-js/mermaid": "mermaid-js__mermaid",
    "contao/contao": "contao__contao",
}

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
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def find_clone(repo):
    key = REPO_MAP.get(repo)
    if not key:
        return None
    for pref in PREFERRED:
        p = CLONE_ROOT / pref / key
        if (p / ".git").exists() or (p / ".git").is_file():
            return p
        p2 = CLONE_ROOT / pref / key
        if p2.exists() and ((p2 / ".git").exists() or (p2 / ".git").is_file()):
            return p2
    matches = list(CLONE_ROOT.glob(f"**/{key}"))
    for m in matches:
        if (m / ".git").exists() or (m / ".git").is_file():
            return m
    return None


def main():
    rows = [json.loads(l) for l in (OWNED / "advisory_extract.jsonl").read_text().splitlines() if l.strip()]
    out = []
    for r in rows:
        repos = r.get("repos") or []
        repo = next((x for x in repos if x in REPO_MAP), repos[0] if repos else None)
        clone = find_clone(repo) if repo else None
        rec = {
            "ghsa": r["ghsa"],
            "id": r.get("id"),
            "repo": repo,
            "clone": str(clone) if clone else None,
            "shas": [],
        }
        shas = [s.strip() for s in (r.get("shas") or "").split(",") if s.strip()]
        if clone:
            for sha in shas:
                exists = git(clone, "cat-file", "-e", f"{sha}^{{commit}}")
                msg = git(clone, "log", "-1", "--format=%H%n%an <%ae>%n%s%n%b", sha) if exists.returncode == 0 else None
                body = msg.stdout if msg and msg.returncode == 0 else ""
                rec["shas"].append({
                    "sha": sha,
                    "exists": exists.returncode == 0,
                    "ai": bool(AI_RE.search(body)),
                    "head": body[:400],
                })
        else:
            rec["shas"] = [{"sha": s, "exists": False, "ai": False, "head": ""} for s in shas]
        out.append(rec)
    (OWNED / "sha_inspect.json").write_text(json.dumps(out, indent=2))
    print("wrote", len(out))


if __name__ == "__main__":
    main()
