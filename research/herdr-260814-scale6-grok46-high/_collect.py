#!/usr/bin/env python3
import json, os, subprocess, hashlib
from pathlib import Path

OWN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale6-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-6.jsonl")
POOL = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")
ADV_ROOTS = [
    Path("/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/advisory-database/advisories/github-reviewed"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database/advisories/github-reviewed"),
]

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def git(cwd, args, timeout=20):
    env = os.environ.copy()
    env["GIT_NO_LAZY_FETCH"] = "1"
    try:
        r = subprocess.run(["git", "--no-optional-locks", "-C", str(cwd), *args],
                           capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 99, "", str(e)

def find_adv(cid, published):
    cid_l = cid.lower()
    year = published[:4]
    month = published[5:7]
    for root in ADV_ROOTS:
        p = root / year / month / cid_l / f"{cid_l}.json"
        if p.is_file():
            return str(p)
    for root in ADV_ROOTS:
        if not root.exists():
            continue
        for y in sorted(root.iterdir()):
            if not y.is_dir():
                continue
            for m in y.iterdir():
                cand = m / cid_l / f"{cid_l}.json"
                if cand.is_file():
                    return str(cand)
    return None

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
out = []
for row in rows:
    rec = dict(row)
    rec["advisory_path"] = find_adv(row["case_id"], row["published"])
    rec["advisory"] = None
    if rec["advisory_path"]:
        data = json.loads(Path(rec["advisory_path"]).read_text())
        rec["advisory"] = {
            "id": data.get("id"),
            "summary": (data.get("summary") or "")[:500],
            "details": (data.get("details") or "")[:1500],
            "severity": data.get("severity") or (data.get("database_specific") or {}).get("severity"),
            "withdrawn": data.get("withdrawn_at") or data.get("withdrawn"),
            "aliases": data.get("aliases") or [],
            "refs": [r.get("url") for r in (data.get("references") or [])[:16]],
            "affected": [
                {
                    "package": (a.get("package") or {}).get("name"),
                    "ecosystem": (a.get("package") or {}).get("ecosystem"),
                    "ranges": a.get("ranges"),
                }
                for a in (data.get("affected") or [])[:4]
            ],
        }
    owner, repo = row["repository"].split("/", 1)
    pool = POOL / f"{owner}__{repo}"
    rec["pool"] = str(pool)
    rec["pool_exists"] = pool.exists()
    rec["ancestor_type"] = None
    rec["fix_type"] = None
    rec["ancestor_msg"] = None
    rec["fix_msg"] = None
    rec["is_ancestor"] = None
    rec["ancestor_files"] = []
    rec["fix_files"] = []
    rec["ancestor_stat"] = None
    rec["fix_stat"] = None
    rec["ai_markers"] = []
    rec["overlap_anc_diff"] = {}
    rec["overlap_fix_diff"] = {}
    if pool.exists():
        code, outp, err = git(pool, ["cat-file", "-t", row["ai_ancestor"]])
        rec["ancestor_type"] = outp.strip() if code == 0 else f"ERR {err.strip()[:200]}"
        code, outp, err = git(pool, ["cat-file", "-t", row["fix_ref"]])
        rec["fix_type"] = outp.strip() if code == 0 else f"ERR {err.strip()[:200]}"
        code, outp, err = git(pool, ["log", "-1", "--format=%an%n%s%n%n%b", row["ai_ancestor"]])
        rec["ancestor_msg"] = (outp if code == 0 else err)[:2500]
        code, outp, err = git(pool, ["log", "-1", "--format=%an%n%s%n%n%b", row["fix_ref"]])
        rec["fix_msg"] = (outp if code == 0 else err)[:2500]
        code, outp, err = git(pool, ["merge-base", "--is-ancestor", row["ai_ancestor"], row["fix_ref"]])
        rec["is_ancestor"] = (code == 0)
        code, outp, err = git(pool, ["diff-tree", "--no-commit-id", "--name-only", "-r", row["ai_ancestor"]])
        rec["ancestor_files"] = [x for x in outp.splitlines() if x][:80]
        code, outp, err = git(pool, ["diff-tree", "--no-commit-id", "--name-only", "-r", row["fix_ref"]])
        rec["fix_files"] = [x for x in outp.splitlines() if x][:80]
        code, outp, err = git(pool, ["diff-tree", "--stat", "-r", row["ai_ancestor"]])
        rec["ancestor_stat"] = (outp if code == 0 else err)[:2000]
        code, outp, err = git(pool, ["diff-tree", "--stat", "-r", row["fix_ref"]])
        rec["fix_stat"] = (outp if code == 0 else err)[:2000]
        msg = rec["ancestor_msg"] or ""
        for needle in ["Co-authored-by: Copilot", "Co-Authored-By: Claude", "noreply@anthropic.com",
                       "copilot@users.noreply.github.com", "Generated by", "Claude", "Copilot",
                       "Cursor", "GPT", "ChatGPT", "codex", "OpenAI", "Assisted-by"]:
            if needle.lower() in msg.lower():
                rec["ai_markers"].append(needle)
        for f in (row.get("overlap_files") or [])[:4]:
            code, outp, err = git(pool, ["show", "--stat", "--format=", f"{row['ai_ancestor']}", "--", f], timeout=15)
            rec["overlap_anc_diff"][f] = {"code": code, "out": (outp or "")[:2500], "err": (err or "")[:300]}
            code, outp, err = git(pool, ["show", "--stat", "--format=", f"{row['fix_ref']}", "--", f], timeout=15)
            rec["overlap_fix_diff"][f] = {"code": code, "out": (outp or "")[:2500], "err": (err or "")[:300]}
    out.append(rec)

(OWN / "_evidence.json").write_text(json.dumps({
    "n": len(out),
    "slice_sha256": sha256(SLICE),
    "rows": out,
}, indent=2))
print("wrote evidence", len(out))
