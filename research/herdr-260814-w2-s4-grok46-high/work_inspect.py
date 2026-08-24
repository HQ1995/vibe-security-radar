#!/usr/bin/env python3
import json, os, re, subprocess
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
SRC = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/adjudication-2.jsonl"
OUT = ROOT / "autoresearch/herdr-260814-w2-s4-grok46-high/_inspect_adj.py.out.json"
CACHE = Path("/home/hanqing/.cache")

rows = [json.loads(l) for l in SRC.read_text().splitlines() if l.strip()]

def find_advisory(ghsa):
    needle = ghsa.lower()
    hits = []
    for base in [
        CACHE / "ghsa200-worker-clones",
        ROOT / ".ai-slop",
    ]:
        if not base.exists():
            continue
        for p in base.rglob(f"*{needle}*"):
            if p.is_file() and p.suffix == ".json" and needle in p.name.lower():
                hits.append(str(p))
                if len(hits) >= 6:
                    return hits
    return hits

def git(repo, *args):
    try:
        r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=20)
        return r.returncode, (r.stdout or "")[:4000], (r.stderr or "")[:800]
    except Exception as e:
        return 99, "", str(e)

AI_RE = re.compile(r"(Co-Authored-By:.*Claude|Co-authored-by:.*[Cc]opilot|Generated with \[[Cc]laude|[Cc]opilot@users\.noreply|google-labs-jules|openai|anthropic|cursor\[bot\]|devin-ai)", re.I)

out = []
for i, row in enumerate(rows):
    ghsa = row["ghsa_id"]
    repo = row["repository"]
    clone = row.get("clone")
    cand = row.get("candidate_sha") or (row.get("best") or {}).get("ai_sha")
    fix = (row.get("best") or {}).get("fix") or (row.get("fix_refs") or [None])[0]
    rec = {
        "i": i,
        "ghsa": ghsa,
        "repo": repo,
        "clone_exists": bool(clone and Path(clone).exists()),
        "clone": clone,
        "cand": cand,
        "fix": fix,
        "cand_exists": False,
        "fix_exists": False,
        "cand_msg": "",
        "fix_msg": "",
        "cand_stat": "",
        "fix_stat": "",
        "n_parents": None,
        "ai_in_cand": False,
        "ai_in_fix": False,
        "advisory_hits": [],
        "advisory_summary": None,
        "advisory_refs": [],
        "advisory_aliases": [],
        "advisory_withdrawn": None,
        "advisory_repo": None,
    }
    if rec["clone_exists"]:
        code, stdout, err = git(clone, "cat-file", "-t", cand)
        rec["cand_exists"] = stdout.strip() == "commit"
        code, stdout, err = git(clone, "cat-file", "-t", fix)
        rec["fix_exists"] = stdout.strip() == "commit"
        if rec["cand_exists"]:
            _, rec["cand_msg"], _ = git(clone, "log", "-1", "--format=%P%n%an <%ae>%n%s%n%b", cand)
            _, rec["cand_stat"], _ = git(clone, "show", "--stat", "--format=", cand)
            rec["n_parents"] = len(rec["cand_msg"].splitlines()[0].split()) if rec["cand_msg"] else None
            rec["ai_in_cand"] = bool(AI_RE.search(rec["cand_msg"]))
        if rec["fix_exists"]:
            _, rec["fix_msg"], _ = git(clone, "log", "-1", "--format=%P%n%an <%ae>%n%s%n%b", fix)
            _, rec["fix_stat"], _ = git(clone, "show", "--stat", "--format=", fix)
            rec["ai_in_fix"] = bool(AI_RE.search(rec["fix_msg"]))
    rec["advisory_hits"] = find_advisory(ghsa)
    if rec["advisory_hits"]:
        try:
            adv = json.loads(Path(rec["advisory_hits"][0]).read_text())
            rec["advisory_summary"] = (adv.get("summary") or adv.get("details") or "")[:300]
            rec["advisory_aliases"] = adv.get("aliases") or []
            rec["advisory_withdrawn"] = adv.get("withdrawn")
            rec["advisory_refs"] = [r.get("url") if isinstance(r, dict) else r for r in (adv.get("references") or [])][:12]
            rec["advisory_repo"] = (((adv.get("affected") or [{}])[0].get("database_specific") or {}).get("source"))
        except Exception as e:
            rec["advisory_err"] = str(e)
    out.append(rec)

OUT.write_text(json.dumps(out, indent=2))
print("wrote", OUT, "rows", len(out))
for rec in out:
    print(f"{rec['i']:02d} {rec['ghsa']} clone={rec['clone_exists']} cand={rec['cand_exists']} fix={rec['fix_exists']} ai_cand={rec['ai_in_cand']} adv={len(rec['advisory_hits'])}")
