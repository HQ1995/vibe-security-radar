#!/usr/bin/env python3
import hashlib, json, os, re, subprocess, sys
from pathlib import Path

OWN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale7-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-7.jsonl")
POOL = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")
ADV_CANDIDATES = [
    Path("/home/hanqing/.cache/cve-analyzer/advisory-database"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database"),
    Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-fresh-advisories/advisory-database"),
]

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def run(cmd, cwd=None, env=None, timeout=30):
    e = os.environ.copy()
    if env:
        e.update(env)
    e.setdefault("GIT_NO_LAZY_FETCH", "1")
    try:
        p = subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as ex:
        return 99, "", str(ex)

def find_adv(ghsa):
    ghsa_l = ghsa.lower()
    letter = ghsa_l.split("-")[1][0]
    rel = Path("advisories/github-reviewed") / letter / ghsa_l / f"{ghsa_l}.json"
    hits = []
    for root in ADV_CANDIDATES:
        p = root / rel
        if p.is_file():
            hits.append(str(p))
    # fallback glob
    if not hits:
        for root in ADV_CANDIDATES:
            if not root.exists():
                continue
            for p in root.rglob(f"{ghsa_l}.json"):
                hits.append(str(p))
                break
    return hits

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
out = {"n": len(rows), "advisories": {}, "rows": []}

# find any advisory db
adv_roots = []
for r in ADV_CANDIDATES:
    adv_roots.append({"path": str(r), "exists": r.exists()})
out["adv_roots"] = adv_roots

for row in rows:
    rec = dict(row)
    owner, repo = row["repository"].split("/", 1)
    pool = POOL / f"{owner}__{repo}"
    rec["pool"] = str(pool)
    rec["pool_exists"] = pool.exists()
    rec["adv_paths"] = find_adv(row["case_id"])
    rec["adv"] = None
    if rec["adv_paths"]:
        try:
            adv = json.loads(Path(rec["adv_paths"][0]).read_text())
            rec["adv"] = {
                "id": adv.get("id") or adv.get("ghsaId") or adv.get("schema_version"),
                "summary": (adv.get("summary") or "")[:400],
                "details": (adv.get("details") or "")[:800],
                "severity": adv.get("severity") or (adv.get("database_specific") or {}).get("severity"),
                "withdrawn": adv.get("withdrawn") or (adv.get("database_specific") or {}).get("withdrawn"),
                "aliases": adv.get("aliases") or [],
                "affected": [],
            }
            for a in (adv.get("affected") or [])[:4]:
                rec["adv"]["affected"].append({
                    "pkg": (a.get("package") or {}).get("name"),
                    "ecosystem": (a.get("package") or {}).get("ecosystem"),
                    "ranges": a.get("ranges"),
                    "versions": (a.get("versions") or [])[:8],
                })
            rec["adv_keys"] = sorted(adv.keys())
        except Exception as ex:
            rec["adv_error"] = str(ex)
    if rec["pool_exists"]:
        code, stdout, stderr = run(["git", "cat-file", "-t", row["ai_ancestor"]], cwd=str(pool))
        rec["ancestor_type"] = stdout.strip()
        rec["ancestor_type_err"] = stderr[-200:]
        code, stdout, stderr = run(["git", "cat-file", "-t", row["fix_ref"]], cwd=str(pool))
        rec["fix_type"] = stdout.strip()
        rec["fix_type_err"] = stderr[-200:]
        code, stdout, stderr = run(["git", "log", "-1", "--format=%s%n%b", row["ai_ancestor"]], cwd=str(pool))
        rec["ancestor_msg"] = stdout[:1500]
        rec["ancestor_msg_err"] = stderr[-200:]
        code, stdout, stderr = run(["git", "log", "-1", "--format=%s%n%b", row["fix_ref"]], cwd=str(pool))
        rec["fix_msg"] = stdout[:1500]
        rec["fix_msg_err"] = stderr[-200:]
        code, stdout, stderr = run(["git", "merge-base", "--is-ancestor", row["ai_ancestor"], row["fix_ref"]], cwd=str(pool))
        rec["is_ancestor"] = code == 0
        rec["is_ancestor_err"] = (stderr or stdout)[-200:]
        files = row.get("overlap_files") or []
        code, stdout, stderr = run(["git", "diff-tree", "--no-commit-id", "-r", "--name-status", row["ai_ancestor"]], cwd=str(pool))
        rec["ancestor_name_status"] = stdout[:4000]
        rec["ancestor_name_status_err"] = stderr[-300:]
        code, stdout, stderr = run(["git", "show", "--stat", "--format=fuller", "--no-patch", row["ai_ancestor"]], cwd=str(pool))
        rec["ancestor_stat"] = stdout[:2500]
        # overlap diffs
        rec["overlap_diffs"] = {}
        rec["overlap_diff_errs"] = {}
        for f in files:
            code, stdout, stderr = run(["git", "show", f"{row['ai_ancestor']}", "--", f], cwd=str(pool), timeout=20)
            rec["overlap_diffs"][f] = stdout[:6000]
            rec["overlap_diff_errs"][f] = stderr[-400:]
        code, stdout, stderr = run(["git", "diff-tree", "--no-commit-id", "-r", "--name-status", row["fix_ref"]], cwd=str(pool))
        rec["fix_name_status"] = stdout[:4000]
        rec["fix_name_status_err"] = stderr[-300:]
        rec["fix_overlap_diffs"] = {}
        rec["fix_overlap_diff_errs"] = {}
        for f in files:
            code, stdout, stderr = run(["git", "show", f"{row['fix_ref']}", "--", f], cwd=str(pool), timeout=20)
            rec["fix_overlap_diffs"][f] = stdout[:6000]
            rec["fix_overlap_diff_errs"][f] = stderr[-400:]
    out["rows"].append(rec)

(OWN / "work").mkdir(exist_ok=True)
(OWN / "work" / "raw.json").write_text(json.dumps(out, indent=2))
print("wrote", OWN / "work" / "raw.json", "rows", len(out["rows"]))
print("adv found", sum(1 for r in out["rows"] if r.get("adv_paths")))
print("pools", sum(1 for r in out["rows"] if r.get("pool_exists")))
