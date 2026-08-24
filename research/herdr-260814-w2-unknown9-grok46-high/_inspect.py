#!/usr/bin/env python3
from pathlib import Path
import json, subprocess, os, hashlib, re

ROOT = Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-w2-unknown9-grok46-high"
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/slice-01.jsonl"
CACHE = Path("/home/hanqing/.cache/ghsa200-worker-clones")
ADV_ROOTS = [
    Path("/home/hanqing/.cache/ghsa200-advisory-database"),
    Path("/home/hanqing/.cache/advisory-database"),
    ROOT / ".ai-slop/cache",
]

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]

repo_map = {
    "psd-tools/psd-tools": CACHE/"commit-oz/repos/psd-tools__psd-tools",
    "vercel/workflow": CACHE/"commit-oz/repos/vercel__workflow",
    "shopware/shopware": CACHE/"commit-oz/repos/shopware__shopware",
    "stellar/rs-soroban-sdk": CACHE/"commit-oz/repos/stellar__rs-soroban-sdk",
    "withastro/astro": CACHE/"commit-oz/repos/withastro__astro",
    "OpenC3/cosmos": CACHE/"commit-oz/repos/OpenC3__cosmos",
    "silverbucket/webfinger.js": CACHE/"commit-oz/repos/silverbucket__webfinger.js",
    "OpenListTeam/OpenList": CACHE/"commit-oz/repos/OpenListTeam__OpenList",
    "rustfs/rustfs": CACHE/"commit-oz/repos/rustfs__rustfs",
    "zitadel/zitadel": CACHE/"commit-oz/repos/zitadel__zitadel",
    "quic-go/quic-go": CACHE/"commit-oz/repos/quic-go__quic-go",
    "gofiber/fiber": CACHE/"commit-gn/clones/gofiber__fiber",
    "google/clasp": CACHE/"commit-gn/clones/google__clasp",
    "modelcontextprotocol/python-sdk": CACHE/"commit-gn/clones/modelcontextprotocol__python-sdk",
    "jahlives/openssl_encrypt": CACHE/"commit-gn/clones/jahlives__openssl_encrypt",
    "go-vikunja/vikunja": CACHE/"commit-gn/clones/go-vikunja__vikunja",
    "locutusjs/locutus": CACHE/"commit-gn/clones/locutusjs__locutus",
    "lobehub/lobehub": CACHE/"commit-gn/clones/lobehub__lobehub",
    "modelcontextprotocol/go-sdk": CACHE/"commit-gn/clones/modelcontextprotocol__go-sdk",
    "gogs/gogs": CACHE/"commit-gn/clones/gogs__gogs",
    "MontFerret/ferret": CACHE/"commit-gn/clones/MontFerret__ferret",
    "Basekick-Labs/arc": CACHE/"commit-af/repos/Basekick-Labs__arc",
    "coder/coder": CACHE/"commit-af/repos/coder/coder",
    "babylonlabs-io/babylon": CACHE/"commit-af/repos/babylonlabs-io__babylon",
    "anthropic-experimental/sandbox-runtime": CACHE/"commit-af/repos/anthropic-experimental__sandbox-runtime",
}

# also try underscore variants
def find_clone(repo):
    p = repo_map.get(repo)
    if p and p.exists():
        return str(p)
    owner, name = repo.split("/", 1)
    for cand in [
        CACHE/f"commit-af/repos/{owner}__{name}",
        CACHE/f"commit-af/repos/{owner}/{name}",
        CACHE/f"commit-gn/clones/{owner}__{name}",
        CACHE/f"commit-oz/repos/{owner}__{name}",
    ]:
        if cand.exists():
            return str(cand)
    return None

AI_RE = re.compile(
    r"(Co-authored-by:.*Claude|Generated-by:.*Claude|Claude Code|GPT-|ChatGPT|Copilot|Cursor|Gemini|OpenAI|anthropic|aider|codex|llm|AI-generated|Generated with)",
    re.I,
)

def git(cwd, *args):
    r = subprocess.run(["git","-C",cwd,*args], capture_output=True, text=True)
    return r.returncode, (r.stdout or "")[:4000], (r.stderr or "")[:1000]

out_rows = []
for i,r in enumerate(rows):
    repo = r.get("repository")
    b = r.get("best") or {}
    ai = b.get("ai_sha")
    fix = b.get("fix")
    parent = b.get("parent")
    clone = find_clone(repo)
    rec = {
        "i": i,
        "ghsa": r.get("ghsa_id"),
        "repo": repo,
        "ai": ai,
        "fix": fix,
        "parent": parent,
        "clone": clone,
        "clone_exists": bool(clone and Path(clone).exists()),
    }
    if clone:
        rec["is_git"] = (Path(clone)/".git").exists() or (Path(clone)/"HEAD").exists()
        for label, sha in [("ai", ai), ("fix", fix), ("parent", parent)]:
            if not sha:
                continue
            code, stdout, stderr = git(clone, "cat-file", "-t", sha)
            rec[f"{label}_type"] = stdout.strip() if code==0 else f"missing:{stderr.strip()[:80]}"
            code, stdout, stderr = git(clone, "log", "-1", "--format=%H%n%an <%ae>%n%cn <%ce>%n%s%n%b", sha)
            rec[f"{label}_log"] = stdout[:1500] if code==0 else stderr[:200]
            rec[f"{label}_ai_match"] = bool(AI_RE.search(stdout)) if code==0 else False
            code, stdout, stderr = git(clone, "show", "-s", "--format=%P %T", sha)
            rec[f"{label}_parents_tree"] = stdout.strip()[:200] if code==0 else ""
    out_rows.append(rec)

OWNED.mkdir(parents=True, exist_ok=True)
(OWNED/"_inspect.json").write_text(json.dumps(out_rows, indent=2))
print("WROTE", len(out_rows), "clone_hits", sum(1 for x in out_rows if x.get("clone_exists")))
