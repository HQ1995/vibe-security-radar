#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high")
CLONE_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones")
ROWS = json.loads_lines = None

def git(cwd, *args):
    return subprocess.run(["git","--no-optional-locks","-C",str(cwd),*args], capture_output=True, text=True, timeout=20)

def main():
    rows = [json.loads(l) for l in (OWNED/"advisory_extract.jsonl").read_text().splitlines() if l.strip()]
    clones = []
    for p in CLONE_ROOT.iterdir():
        if not p.is_dir():
            continue
        for gitdir in p.rglob(".git"):
            if gitdir.is_dir() or gitdir.is_file():
                clones.append(gitdir.parent if gitdir.name == ".git" else gitdir)
    wanted = set()
    for r in rows:
        wanted.update(r.get("repos") or [])
        for sha in (r.get("shas") or "").split(","):
            sha = sha.strip()
            if sha:
                wanted.add(sha)
    hits = []
    for clone in clones:
        url = git(clone, "remote", "get-url", "origin").stdout.strip()
        name = str(clone)
        for w in wanted:
            if w and (w in url or w.replace("/", "__") in name):
                hits.append({"clone": name, "url": url, "want": w})
    (OWNED/"clone_hits.json").write_text(json.dumps(hits, indent=2))
    print("clones_scanned", len(clones), "hits", len(hits))

if __name__ == "__main__":
    main()
