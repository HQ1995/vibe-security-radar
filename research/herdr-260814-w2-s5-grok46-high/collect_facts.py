#!/usr/bin/env python3
import json, os, subprocess, hashlib, glob
from pathlib import Path

OWN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s5-grok46-high")
PACKETS = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-3.jsonl")
ADVISORY_ROOTS = [
    Path("/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/current-delta/advisory-database"),
]

def run(cmd, cwd=None, timeout=20):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def find_advisory(ghsa):
    slug = ghsa.lower()
    hits = []
    for root in ADVISORY_ROOTS:
        if not root.exists():
            continue
        pattern = str(root / "advisories" / "github-reviewed" / "*" / "*" / slug / f"{slug}.json")
        hits.extend(glob.glob(pattern))
        # also search more broadly
        for p in root.rglob(f"{slug}.json"):
            hits.append(str(p))
    uniq = []
    seen = set()
    for h in hits:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq

def git(clone, *args):
    rc, out, err = run(["git", "-C", clone, *args])
    return rc, out, err

rows = []
with open(PACKETS) as f:
    packets = [json.loads(l) for l in f if l.strip()]

for i, pkt in enumerate(packets, 1):
    ghsa = pkt["ghsa_id"]
    clone = pkt["clone"]
    cand = pkt["candidate_sha"]
    fixes = pkt.get("fix_refs") or []
    rec = {
        "ord": i,
        "ghsa_id": ghsa,
        "repository": pkt["repository"],
        "clone": clone,
        "clone_exists": os.path.isdir(clone),
        "candidate_sha": cand,
        "candidate_message": (pkt.get("candidate_message") or "")[:400],
        "fix_refs": fixes,
        "best": pkt.get("best"),
        "advisories": [],
        "candidate": {},
        "fixes": [],
    }
    advs = find_advisory(ghsa)
    for ap in advs[:3]:
        try:
            obj = json.loads(Path(ap).read_text())
        except Exception as e:
            rec["advisories"].append({"path": ap, "error": str(e)})
            continue
        rec["advisories"].append({
            "path": ap,
            "id": obj.get("id"),
            "summary": obj.get("summary"),
            "withdrawn": obj.get("withdrawn"),
            "published": obj.get("published"),
            "aliases": obj.get("aliases"),
            "affected": obj.get("affected"),
            "references": obj.get("references"),
            "details": (obj.get("details") or "")[:2500],
            "database_specific": obj.get("database_specific"),
        })
    if rec["clone_exists"]:
        rc, head, _ = git(clone, "rev-parse", "--is-inside-work-tree")
        rec["git_ok"] = rc == 0
        rc, exists, _ = git(clone, "cat-file", "-t", cand)
        rec["candidate"]["exists"] = exists == "commit"
        if rec["candidate"]["exists"]:
            rc, meta, _ = git(clone, "show", "-s", "--format=%H%n%P%n%an <%ae>%n%cn <%ce>%n%s%n%b", cand)
            rec["candidate"]["show"] = meta[:2500]
            rc, stat, _ = git(clone, "show", "--stat", "--format=", cand)
            rec["candidate"]["stat"] = stat[:2000]
            rc, names, _ = git(clone, "diff-tree", "--no-commit-id", "-r", "--name-only", cand)
            rec["candidate"]["files"] = names.splitlines()[:80]
            rc, patch, _ = git(clone, "show", "--format=", "--unified=2", cand)
            rec["candidate"]["patch"] = patch[:4000]
        for fx in fixes:
            item = {"sha": fx}
            rc, exists, _ = git(clone, "cat-file", "-t", fx)
            item["exists"] = exists == "commit"
            if item["exists"]:
                rc, meta, _ = git(clone, "show", "-s", "--format=%H%n%P%n%an <%ae>%n%cn <%ce>%n%s%n%b", fx)
                item["show"] = meta[:2500]
                rc, names, _ = git(clone, "diff-tree", "--no-commit-id", "-r", "--name-only", fx)
                item["files"] = names.splitlines()[:80]
                rc, patch, _ = git(clone, "show", "--format=", "--unified=2", fx)
                item["patch"] = patch[:4000]
                rc, anc, _ = git(clone, "merge-base", "--is-ancestor", cand, fx)
                item["candidate_ancestor_of_fix"] = (rc == 0)
                rc, tags, _ = git(clone, "tag", "--contains", fx)
                item["tags_containing"] = tags.splitlines()[:30]
            rec["fixes"].append(item)
        if rec["candidate"].get("exists"):
            rc, tags, _ = git(clone, "tag", "--contains", cand)
            rec["candidate"]["tags_containing"] = tags.splitlines()[:30]
    rows.append(rec)

outp = OWN / "work" / "facts.json"
outp.parent.mkdir(exist_ok=True)
outp.write_text(json.dumps({"packet_sha256": sha256(PACKETS), "n": len(rows), "rows": rows}, indent=2))
print("wrote", outp, "bytes", outp.stat().st_size, "n", len(rows))
