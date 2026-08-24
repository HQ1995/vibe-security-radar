#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path

OWNED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-dr3-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-3.jsonl")
ADV = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database")
POOL = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
print("rows", len(rows))

def find_adv(cid):
    # dirs are GHSA- + lowercase remainder
    rest = cid.split("-", 1)[1].lower()
    needle = f"GHSA-{rest}"
    hits = list(ADV.glob(f"advisories/github-reviewed/*/*/{needle}/{needle}.json"))
    if hits:
        return str(hits[0])
    hits = list(ADV.glob(f"advisories/**/{needle}.json"))
    return str(hits[0]) if hits else None

def git(repo, args):
    p = subprocess.run(["git","--no-optional-locks","-C",str(repo)]+args, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr

out = []
for r in rows:
    cid = r["case_id"]
    adv = find_adv(cid)
    rec = {"case_id": cid, "advisory_path": adv, "repository": r["repository"], "fix_ref": r["fix_ref"], "ai_ancestor": r["ai_ancestor"], "overlap_files": r.get("overlap_files"), "subject": r.get("subject")}
    if adv:
        j = json.loads(Path(adv).read_text())
        rec["ghsa_id"] = j.get("id") or j.get("GHSA")
        rec["summary"] = (j.get("summary") or "")[:400]
        rec["details_head"] = (j.get("details") or "")[:800]
        rec["aliases"] = j.get("aliases")
        rec["withdrawn"] = j.get("withdrawn")
        rec["refs"] = [x.get("url") for x in (j.get("references") or []) if isinstance(x, dict)][:12]
        rec["affected"] = []
        for pkg in (j.get("affected") or [])[:3]:
            rec["affected"].append({
                "package": (pkg.get("package") or {}),
                "ranges": pkg.get("ranges"),
                "versions": (pkg.get("versions") or [])[:8],
            })
    repo = POOL / r["repository"].replace("/", "__")
    rec["repo_path"] = str(repo)
    rec["repo_exists"] = repo.exists()
    if repo.exists():
        code, stdout, stderr = git(repo, ["cat-file", "-t", r["ai_ancestor"]])
        rec["ai_type"] = stdout.strip() or stderr[:200]
        code, stdout, stderr = git(repo, ["cat-file", "-t", r["fix_ref"]])
        rec["fix_type"] = stdout.strip() or stderr[:200]
        code, stdout, err = git(repo, ["show", "-s", "--format=%H%n%s%n%an <%ae>%n%b", r["ai_ancestor"]])
        rec["ai_show"] = stdout[:2500]
        code, stdout, err = git(repo, ["diff-tree", "--no-commit-id", "-r", "--name-only", "-c", r["ai_ancestor"]])
        rec["ai_files"] = [x for x in stdout.splitlines() if x][:80]
        code, stdout, err = git(repo, ["diff-tree", "--no-commit-id", "-r", "--name-only", "-c", r["fix_ref"]])
        rec["fix_files"] = [x for x in stdout.splitlines() if x][:80]
        overlap = r.get("overlap_files") or []
        rec["ai_stat"] = {}
        rec["fix_stat"] = {}
        for f in overlap:
            c1, o1, e1 = git(repo, ["show", "--stat", "--format=", r["ai_ancestor"], "--", f])
            rec["ai_stat"][f] = (o1 or e1)[:400]
            c2, o2, e2 = git(repo, ["show", "--stat", "--format=", r["fix_ref"], "--", f])
            rec["fix_stat"][f] = (o2 or e2)[:400]
    out.append(rec)
    print("done", cid, rec.get("summary","")[:80], rec.get("ai_type"), rec.get("fix_type"))

(OWNED / "work").mkdir(exist_ok=True)
(OWNED / "work" / "collect.json").write_text(json.dumps(out, indent=2))
print("wrote", len(out))
