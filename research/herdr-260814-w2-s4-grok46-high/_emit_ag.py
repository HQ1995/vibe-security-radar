#!/usr/bin/env python3
import json, hashlib, os, re, subprocess, glob
from datetime import datetime, timezone
from pathlib import Path

OWN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s4-grok46-high")
ROOT = Path("/home/hanqing/agents/ai-slop")
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/ag-slice-1.jsonl"
SPEC = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md"
CONTRACT = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
SCAN = ROOT / "autoresearch/herdr-260814-ghsa200-additiveguard-first30-grok46-high/work/scan.jsonl"
ADV_ROOTS = [
    Path("/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database"),
    ROOT / ".ai-slop/cache/advisory-database",
]
CLONE_ROOTS = [
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/repos"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/clones"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones"),
]
AI_RE = re.compile(
r"(Co-authored-by:.*(?:Copilot|ChatGPT|OpenAI|Claude|Gemini|Cursor|Codex)|Generated-by:|Signed-off-by: Copilot|Made-with: Cursor|\bcopilot\[bot\]|\bcursor\[bot\]|\bcodex\b|ChatGPT|OpenAI Codex|anthropic|Claude Code|Generated with Cursor)", re.I)

def sha256_file(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for chunk in iter(lambda: f.read(1<<16), b""):
            h.update(chunk)
    return h.hexdigest()

def find_adv(gid):
    slug=gid.lower()
    name=f"GHSA-{slug[5:]}" if slug.startswith("ghsa-") else slug
    # gid already GHSA-...
    folder=gid.lower()
    hits=[]
    for root in ADV_ROOTS:
        if not root.exists():
            continue
        for p in root.glob(f"advisories/github-reviewed/*/*/{folder}/{folder}.json"):
            hits.append(p)
        if hits:
            break
    return hits[0] if hits else None

def find_clone(repo):
    owner, name = repo.split("/",1)
    key=f"{owner}__{name}"
    cands=[]
    for root in CLONE_ROOTS:
        if not root.exists():
            continue
        p=root/key
        if (p/".git").exists() or (p/"HEAD").exists():
            return p
        for p in root.rglob(key):
            if p.is_dir() and ((p/".git").exists() or (p/"HEAD").exists()):
                return p
    return None

def git(cwd, args, timeout=20):
    try:
        r=subprocess.run(["git","-C",str(cwd)]+args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 99, "", str(e)

rows=[]
with SLICE.open() as f:
    for line in f:
        line=line.strip()
        if line:
            rows.append(json.loads(line))
scan={}
if SCAN.exists():
    with SCAN.open() as f:
        for line in f:
            rec=json.loads(line)
            scan[rec.get("ghsa_id") or rec.get("advisory_id")]=rec

evidence=[]
for rec in rows:
    gid=rec["ghsa_id"]
    repo=rec["repository"]
    shas=rec.get("commit_refs") or []
    adv_path=find_adv(gid)
    adv=json.loads(adv_path.read_text()) if adv_path else None
    clone=find_clone(repo)
    sha_info=[]
    any_ai=False
    for sha in shas:
        info={"sha":sha,"exists":False,"ai":False,"subject":None,"author":None,"error":None}
        if clone is None:
            info["error"]="no_local_clone"
            sha_info.append(info); continue
        code,out,err=git(clone,["cat-file","-t",sha])
        if code!=0 or out.strip()!="commit":
            info["error"]=(err or out or "missing_object").strip()[:300]
            sha_info.append(info); continue
        info["exists"]=True
        code,out,err=git(clone,["log","-1","--format=%H%n%an <%ae>%n%cn <%ce>%n%s%n%b",sha])
        info["meta"]=out[:2500]
        info["subject"]=(out.splitlines()[3] if len(out.splitlines())>3 else "")[:200]
        info["author"]=(out.splitlines()[1] if len(out.splitlines())>1 else "")[:200]
        info["ai"]=bool(AI_RE.search(out or ""))
        if info["ai"]:
            any_ai=True
        sha_info.append(info)
    evidence.append({
        "row": rec,
        "adv_path": str(adv_path) if adv_path else None,
        "adv": adv,
        "clone": str(clone) if clone else None,
        "sha_info": sha_info,
        "any_ai": any_ai,
        "scan": scan.get(gid, {}),
    })

(OWN/"_ag_evidence.json").write_text(json.dumps([
    {k:v for k,v in e.items() if k!="adv"} | {"adv_summary": (e["adv"] or {}).get("summary"), "adv_aliases": (e["adv"] or {}).get("aliases"), "adv_withdrawn": (e["adv"] or {}).get("withdrawn"), "adv_refs": [r.get("url") for r in ((e["adv"] or {}).get("references") or [])][:15], "adv_affected": [{"ecosystem":(a.get("package") or {}).get("ecosystem"), "name":(a.get("package") or {}).get("name")} for a in ((e["adv"] or {}).get("affected") or [])], "adv_database_specific": (e["adv"] or {}).get("database_specific")}
    for e in evidence
], indent=2, default=str))
print("wrote evidence", len(evidence))
print("adv", sum(1 for e in evidence if e["adv_path"]))
print("clone", sum(1 for e in evidence if e["clone"]))
print("any_ai", sum(1 for e in evidence if e["any_ai"]))
