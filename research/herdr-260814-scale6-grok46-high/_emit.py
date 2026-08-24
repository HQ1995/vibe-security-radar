#!/usr/bin/env python3
import hashlib, json, os, subprocess, time
from pathlib import Path

OWN = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-scale6-grok46-high")
SLICE = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-6.jsonl")
CONTRACT = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md")
DRSPEC = Path("/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md")
POOL = Path("/home/hanqing/.cache/ghsa200-sweep-fetch")
ADV_ROOTS = [
    Path("/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-af/advisory-database/advisories/github-reviewed"),
    Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database/advisories/github-reviewed"),
]
AI_RE = (
    "co-authored-by:",
    "assisted-by:",
    "generated with",
    "github copilot",
    "copilot",
    "claude",
    "cursor",
    "codex",
    "noreply@anthropic.com",
)

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def git(cwd, args, timeout=8):
    env = os.environ.copy()
    env["GIT_NO_LAZY_FETCH"] = "1"
    try:
        p = subprocess.run(["git", "--no-optional-locks", "-C", str(cwd), *args],
                           capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, (p.stdout or "")[:4000], (p.stderr or "")[:400]
    except Exception as ex:
        return 99, "", str(ex)[:400]

def find_adv(cid):
    needle = cid.lower()
    for root in ADV_ROOTS:
        if not root.exists():
            continue
        for y in sorted(root.iterdir()):
            if not y.is_dir():
                continue
            for m in y.iterdir():
                p = m / needle / f"{needle}.json"
                if p.is_file():
                    return p
    return None

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
reviewed = []
for i, row in enumerate(rows, 1):
    rec = dict(row)
    rec["ord"] = i
    rec["advisory_path"] = None
    rec["advisory"] = None
    rec["pool"] = None
    rec["pool_exists"] = False
    rec["ancestor_type"] = None
    rec["fix_type"] = None
    rec["ancestor_msg"] = None
    rec["fix_msg"] = None
    rec["is_ancestor"] = None
    rec["ancestor_files"] = []
    rec["fix_files"] = []
    rec["ai_markers"] = []
    rec["withdrawn"] = None
    rec["aliases"] = []
    rec["summary"] = None
    rec["packages"] = []
    rec["ecosystems"] = []
    rec["refs"] = []
    rec["affected_ranges"] = []
    p = find_adv(row["case_id"])
    if p:
        rec["advisory_path"] = str(p)
        try:
            adv = json.loads(p.read_text())
            rec["summary"] = (adv.get("summary") or "")[:400]
            rec["aliases"] = adv.get("aliases") or []
            rec["withdrawn"] = adv.get("withdrawn_at") or adv.get("withdrawn")
            rec["refs"] = [r.get("url") for r in (adv.get("references") or [])[:12] if r.get("url")]
            for a in (adv.get("affected") or [])[:6]:
                pkg = (a.get("package") or {})
                rec["packages"].append(pkg.get("name"))
                rec["ecosystems"].append(pkg.get("ecosystem"))
                rec["affected_ranges"].append(a.get("ranges"))
            rec["advisory"] = {
                "summary": rec["summary"],
                "details": (adv.get("details") or "")[:900],
                "severity": adv.get("severity") or (adv.get("database_specific") or {}).get("severity"),
            }
        except Exception as ex:
            rec["advisory_error"] = str(ex)[:200]
    owner, repo = row["repository"].split("/", 1)
    pool = POOL / f"{owner}__{repo}"
    rec["pool"] = str(pool)
    rec["pool_exists"] = pool.exists()
    if rec["pool_exists"]:
        code, out, err = git(pool, ["cat-file", "-t", row["ai_ancestor"]])
        rec["ancestor_type"] = out.strip() if code == 0 else f"ERR {err.strip()}"
        code, out, err = git(pool, ["cat-file", "-t", row["fix_ref"]])
        rec["fix_type"] = out.strip() if code == 0 else f"ERR {err.strip()}"
        code, out, err = git(pool, ["log", "-1", "--format=%s%n%n%b", row["ai_ancestor"]])
        rec["ancestor_msg"] = out[:1800] if code == 0 else err[:400]
        code, out, err = git(pool, ["log", "-1", "--format=%s%n%n%b", row["fix_ref"]])
        rec["fix_msg"] = out[:1200] if code == 0 else err[:400]
        code, out, err = git(pool, ["merge-base", "--is-ancestor", row["ai_ancestor"], row["fix_ref"]])
        rec["is_ancestor"] = (code == 0)
        code, out, err = git(pool, ["diff-tree", "--no-commit-id", "--name-only", "-r", row["ai_ancestor"]])
        rec["ancestor_files"] = [x for x in out.splitlines() if x][:80]
        code, out, err = git(pool, ["diff-tree", "--no-commit-id", "--name-only", "-r", row["fix_ref"]])
        rec["fix_files"] = [x for x in out.splitlines() if x][:80]
        msg = (rec["ancestor_msg"] or "").lower()
        rec["ai_markers"] = [n for n in AI_RE if n in msg]
    reviewed.append(rec)

(OWN / "_evidence.json").write_text(json.dumps(reviewed, indent=2))
print("evidence", len(reviewed), "adv", sum(1 for r in reviewed if r["advisory_path"]), "pool", sum(1 for r in reviewed if r["pool_exists"]))
