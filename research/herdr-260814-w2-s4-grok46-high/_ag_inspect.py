#!/usr/bin/env python3
import json, hashlib, os, re, subprocess, glob
from pathlib import Path
from datetime import datetime, timezone

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s4-grok46-high")
ROOT = Path("/home/hanqing/agents/ai-slop")
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-1.jsonl"
SPEC = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md"
CONTRACT = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
SCAN = ROOT / "autoresearch/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/scan.jsonl"
UNIQ = ROOT / "autoresearch/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/uniqueness.json"
ADV_ROOTS = [
    Path("/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"),
]
CLONE_ROOTS = list(Path("/home/hanqing/.cache/ghsa200-worker-clones").glob("*/repos")) + list(Path("/home/hanqing/.cache/ghsa200-worker-clones").glob("*/clones"))
AI_RE = re.compile(
    r"(Co-authored-by:.*(?:Copilot|ChatGPT|OpenAI|Claude|Cursor|Codex)|"
    r"Generated-by:|Made-with:\s*Cursor|Signed-off-by:\s*Copilot|"
    r"copilot-swe-agent|cursor\[bot\]|openai-codex|"
    r"GPT-4|ChatGPT|Claude 3|anthropic|gemini-)",
    re.I,
)

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()

def load_jsonl(p):
    rows = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def find_advisory(gid):
    slug = gid.lower()
    parts = slug.split("-")
    name = f"GHSA-{parts[1]}-{parts[2]}-{parts[3]}"
    for root in ADV_ROOTS:
        hits = list(root.glob(f"advisories/github-reviewed/*/*/{name}/{name}.json"))
        if hits:
            adv = json.loads(hits[0].read_text())
            rel = str(hits[0].relative_to(root))
            return adv, rel, str(hits[0])
    return None, None, None

def find_clone(repo):
    owner, name = repo.split("/", 1)
    key = f"{owner}__{name}"
    for root in CLONE_ROOTS:
        cand = root / key
        if (cand / ".git").exists() or (cand / "HEAD").exists():
            return str(cand)
    extra = list(Path("/home/hanqing/.cache/ghsa200-worker-clones").glob(f"*/*/{key}"))
    for cand in extra:
        if (cand / ".git").exists() or (cand / "HEAD").exists():
            return str(cand)
    return None

def git(clone, args):
    return subprocess.run(["git", "-C", clone, *args], capture_output=True, text=True)

def inspect_sha(clone, sha):
    info = {"sha": sha, "present": False, "ai_marker": False, "subject": None, "author": None, "committer": None, "body_excerpt": None, "error": None}
    if not clone:
        info["error"] = "no_local_clone"
        return info
    t = git(clone, ["cat-file", "-t", sha])
    if t.returncode != 0 or t.stdout.strip() != "commit":
        info["error"] = (t.stderr or t.stdout or "missing_object")[:240]
        return info
    info["present"] = True
    meta = git(clone, ["log", "-1", "--format=%H%n%an <%ae>%n%cn <%ce>%n%s%n%b", sha])
    text = meta.stdout or ""
    lines = text.splitlines()
    info["author"] = lines[1] if len(lines) > 1 else None
    info["committer"] = lines[2] if len(lines) > 2 else None
    info["subject"] = lines[3] if len(lines) > 3 else None
    info["body_excerpt"] = "\n".join(lines[4:20])[:800]
    info["ai_marker"] = bool(AI_RE.search(text))
    return info

rows = load_jsonl(SLICE)
scan = {}
if SCAN.exists():
    for rec in load_jsonl(SCAN):
        scan[rec.get("ghsa_id") or rec.get("advisory_id")] = rec
uniq = json.loads(UNIQ.read_text()) if UNIQ.exists() else {}
canonical_ids = set(uniq.get("assigned_in_canonical84_strict") or [])

out = []
for rec in rows:
    gid = rec["ghsa_id"]
    repo = rec["repository"]
    shas = rec.get("commit_refs") or []
    adv, rel, abs_path = find_advisory(gid)
    clone = find_clone(repo)
    sha_info = [inspect_sha(clone, s) for s in shas]
    out.append({
        "row": rec,
        "advisory_rel": rel,
        "advisory_abs": abs_path,
        "advisory": adv,
        "clone": clone,
        "sha_info": sha_info,
        "scan": scan.get(gid),
        "in_canonical84": gid in canonical_ids,
    })

(OWNED / "_ag_evidence.json").write_text(json.dumps({
    "n": len(out),
    "slice_sha256": sha256_file(SLICE),
    "spec_sha256": sha256_file(SPEC) if SPEC.exists() else None,
    "contract_sha256": sha256_file(CONTRACT) if CONTRACT.exists() else None,
    "canonical84_ids": sorted(canonical_ids),
    "rows": [{
        "ghsa_id": x["row"]["ghsa_id"],
        "repository": x["row"]["repository"],
        "commit_refs": x["row"].get("commit_refs"),
        "advisory_rel": x["advisory_rel"],
        "withdrawn": (x["advisory"] or {}).get("withdrawn"),
        "aliases": (x["advisory"] or {}).get("aliases"),
        "summary": (x["advisory"] or {}).get("summary"),
        "published": (x["advisory"] or {}).get("published"),
        "packages": [((a.get("package") or {}).get("name")) for a in (x["advisory"] or {}).get("affected") or []],
        "ecosystems": [((a.get("package") or {}).get("ecosystem")) for a in (x["advisory"] or {}).get("affected") or []],
        "database_specific": (x["advisory"] or {}).get("database_specific"),
        "refs": [r.get("url") for r in (x["advisory"] or {}).get("references") or []][:16],
        "clone": x["clone"],
        "sha_info": x["sha_info"],
        "scan_notes": (x["scan"] or {}).get("notes"),
        "scan_added": (x["scan"] or {}).get("added_source_files"),
        "scan_status": (x["scan"] or {}).get("status"),
        "hard_hit": (x["scan"] or {}).get("hard_hit"),
        "in_canonical84": x["in_canonical84"],
    } for x in out],
}, indent=2, default=str))
print("wrote", OWNED / "_ag_evidence.json")
print("n", len(out))
print("adv", sum(1 for x in out if x["advisory"]))
print("clone", sum(1 for x in out if x["clone"]))
print("ai", sum(1 for x in out for s in x["sha_info"] if s.get("ai_marker")))
