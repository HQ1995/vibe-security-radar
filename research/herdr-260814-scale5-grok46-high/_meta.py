#!/usr/bin/env python3
import json, os, subprocess
from pathlib import Path

SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-5.jsonl")
ADV_ROOTS = [
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database/advisories/github-reviewed"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/advisory-database/advisories/github-reviewed"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database/advisories/github-reviewed"),
]
POOL = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")
OUT = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale5-grok46-high/_meta.json")

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]

def git(cwd, args):
    env = os.environ.copy()
    env["GIT_NO_LAZY_FETCH"] = "1"
    r = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, env=env)
    return r.returncode, r.stdout, r.stderr

def find_adv(case_id, published):
    year = published[:4]
    month = published[5:7]
    names = [case_id, case_id.lower(), case_id.upper()]
    for root in ADV_ROOTS:
        for cid in names:
            p = root / year / month / cid / f"{cid}.json"
            if p.exists():
                return str(p)
            p2 = root / year / month / cid.lower() / f"{cid.lower()}.json"
            if p2.exists():
                return str(p2)
    # glob last
    needle = case_id.lower()
    for root in ADV_ROOTS:
        if not root.exists():
            continue
        for y in root.iterdir():
            if not y.is_dir():
                continue
            for m in y.iterdir():
                if not m.is_dir():
                    continue
                for d in m.iterdir():
                    if d.is_dir() and d.name.lower() == needle:
                        cand = d / f"{d.name}.json"
                        if cand.exists():
                            return str(cand)
    return None

out = []
for row in rows:
    rec = {
        "case_id": row["case_id"],
        "repository": row["repository"],
        "fix_ref": row["fix_ref"],
        "ai_ancestor": row["ai_ancestor"],
        "subject": row["subject"],
        "published": row["published"],
        "overlap_files": row["overlap_files"],
    }
    rec["advisory_json"] = find_adv(row["case_id"], row["published"])
    rec["advisory"] = None
    if rec["advisory_json"]:
        data = json.loads(Path(rec["advisory_json"]).read_text())
        rec["advisory"] = {
            "id": data.get("id") or data.get("ghsa_id"),
            "summary": (data.get("summary") or "")[:500],
            "details": (data.get("details") or "")[:1800],
            "severity": data.get("severity"),
            "withdrawn_at": data.get("withdrawn_at"),
            "aliases": data.get("aliases") or [],
            "database_specific": {
                "cwe_ids": ((data.get("database_specific") or {}).get("cwe_ids")),
                "github_reviewed": ((data.get("database_specific") or {}).get("github_reviewed")),
                "nvd_published_at": ((data.get("database_specific") or {}).get("nvd_published_at")),
            },
            "affected_packages": [
                {
                    "name": (a.get("package") or {}).get("name"),
                    "ecosystem": (a.get("package") or {}).get("ecosystem"),
                }
                for a in (data.get("affected") or [])[:6]
            ],
            "refs": [r.get("url") for r in (data.get("references") or [])[:16]],
        }
    owner, repo = row["repository"].split("/", 1)
    pool = POOL / f"{owner}__{repo}"
    rec["commit_pool"] = str(pool)
    rec["pool_exists"] = pool.exists()
    rec["ancestor_type"] = None
    rec["fix_type"] = None
    rec["ancestor_msg"] = None
    rec["fix_msg"] = None
    rec["is_ancestor"] = None
    rec["ai_marker"] = []
    rec["ancestor_parents"] = None
    rec["fix_parents"] = None
    if pool.exists():
        code, outp, err = git(pool, ["cat-file", "-t", row["ai_ancestor"]])
        rec["ancestor_type"] = outp.strip() if code == 0 else ("ERR " + err.strip()[:240])
        code, outp, err = git(pool, ["cat-file", "-t", row["fix_ref"]])
        rec["fix_type"] = outp.strip() if code == 0 else ("ERR " + err.strip()[:240])
        code, outp, err = git(pool, ["log", "-1", "--format=%H%n%P%n%s%n%n%b", row["ai_ancestor"]])
        rec["ancestor_msg"] = (outp if code == 0 else err)[:3000]
        code, outp, err = git(pool, ["log", "-1", "--format=%H%n%P%n%s%n%n%b", row["fix_ref"]])
        rec["fix_msg"] = (outp if code == 0 else err)[:3000]
        code, outp, err = git(pool, ["rev-parse", f"{row['ai_ancestor']}^@"])
        rec["ancestor_parents"] = outp.split() if code == 0 else [err.strip()[:200]]
        code, outp, err = git(pool, ["rev-parse", f"{row['fix_ref']}^@"])
        rec["fix_parents"] = outp.split() if code == 0 else [err.strip()[:200]]
        code, outp, err = git(pool, ["merge-base", "--is-ancestor", row["ai_ancestor"], row["fix_ref"]])
        rec["is_ancestor"] = (code == 0)
        msg = rec["ancestor_msg"] or ""
        for needle in ["Co-authored-by: Copilot", "Co-Authored-By: Claude", "Generated by Cursor", "Generated by", "Cursor", "GPT", "ChatGPT", "Claude", "Copilot", "codex", "OpenAI", "Made-with: Cursor"]:
            if needle.lower() in msg.lower():
                rec["ai_marker"].append(needle)
    out.append(rec)

OUT.write_text(json.dumps(out, indent=2))
print("wrote", OUT, "rows", len(out), "adv", sum(1 for r in out if r["advisory_json"]))
