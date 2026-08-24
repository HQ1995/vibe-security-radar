#!/usr/bin/env python3
import hashlib, json, os, re, subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-w2-unknown9-grok46-high"
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/slice-01.jsonl"
CACHE = Path("/home/hanqing/.cache/ghsa200-worker-clones")
LEDGER = ROOT / "autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl"
ADV_HINTS = [
    Path("/home/hanqing/.cache/advisory-database"),
    Path("/home/hanqing/.cache/github-advisory-database"),
    ROOT / ".ai-slop/cache",
    Path("/home/hanqing/.cache/ghsa200-advisory-database"),
]

def sh(cmd, cwd=None, timeout=20):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 99, "", str(e)

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()

rows = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]
slice_bytes = SLICE.read_bytes()
slice_sha = sha256_bytes(slice_bytes)

# map repo -> clone
wanted = {r["repository"].replace("/", "__") for r in rows}
repo_map = {}
for camp in sorted(CACHE.iterdir() if CACHE.exists() else []):
    for sub in ("repos", "clones"):
        d = camp / sub
        if not d.is_dir():
            continue
        for child in d.iterdir():
            if child.name in wanted and child.name not in repo_map:
                repo_map[child.name] = str(child)

# uniqueness vs L0
l0_ids = set()
if LEDGER.exists():
    for line in LEDGER.read_text().splitlines():
        if not line.strip():
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        cid = (o.get("case_id") or o.get("ghsa_id") or "").upper()
        if cid:
            l0_ids.add(cid)

# advisory search roots
adv_roots = []
for p in ADV_HINTS:
    if p.exists():
        adv_roots.append(str(p))
# also scan common cache names quickly
for p in Path("/home/hanqing/.cache").glob("*advisory*"):
    adv_roots.append(str(p))
for p in Path("/home/hanqing/.cache").glob("*osv*"):
    adv_roots.append(str(p))
osv = ROOT / ".ai-slop/cache/osv-advisory-fix-index-v1"
if osv.exists():
    adv_roots.append(str(osv))

def find_advisory(ghsa):
    slug = ghsa.lower()
    names = [slug, slug.replace("ghsa-", ""), ghsa, ghsa.upper()]
    hits = []
    # direct glob in known roots, bounded
    for root in adv_roots:
        rp = Path(root)
        # typical github advisory-database layout: advisories/github-reviewed/*/GHSA-*.json
        for dirpath, dirnames, filenames in os.walk(rp):
            # prune huge trees
            base = os.path.basename(dirpath).lower()
            if base in {".git", "node_modules"}:
                dirnames[:] = []
                continue
            for fn in filenames:
                fl = fn.lower()
                if slug in fl or ghsa.lower() in fl:
                    hits.append(os.path.join(dirpath, fn))
                    if len(hits) >= 3:
                        return hits
            if len(hits) >= 3:
                return hits
            # don't walk too deep
            depth = dirpath[len(str(rp)):].count(os.sep)
            if depth > 6:
                dirnames[:] = []
    return hits

def git_show(clone, spec):
    rc, out, err = sh(["git", "-C", clone, "show", "-s", "--format=%H%n%P%n%an%n%ae%n%s%n%b", spec])
    return rc, out, err

def git_files(clone, sha):
    rc, out, err = sh(["git", "-C", clone, "diff-tree", "--no-commit-id", "--name-only", "-r", sha])
    files = [l for l in out.splitlines() if l.strip()] if rc == 0 else []
    return rc, files, err

def git_stat(clone, sha):
    rc, out, err = sh(["git", "-C", clone, "show", "--stat", "--format=", sha])
    return rc, out[:2000], err

AI_PAT = re.compile(
    r"(Co-Authored-By:\s*Claude|Co-authored-by:\s*Claude|noreply@anthropic\.com|"
    r"Generated with \[Claude Code\]|Copilot@users\.noreply\.github\.com|"
    r"Co-authored-by:\s*Copilot|Gemini|chatgpt|OpenAI Codex|cursor\[bot\])",
    re.I,
)

explicit_claude = re.compile(r"Co-[Aa]uthored-[Bb]y:\s*Claude\b|Generated with \[Claude Code\]|noreply@anthropic\.com")
explicit_copilot = re.compile(r"Copilot@users\.noreply\.github\.com|Co-[Aa]uthored-[Bb]y:\s*Copilot\b")
explicit_gemini = re.compile(r"Gemini|gemini-code-assist", re.I)

evidence = []
for i, r in enumerate(rows):
    b = r.get("best") or {}
    repo = r["repository"]
    key = repo.replace("/", "__")
    clone = repo_map.get(key)
    ai = b.get("ai_sha")
    fix = b.get("fix")
    parent = b.get("parent")
    rec = {
        "i": i,
        "ghsa_id": r.get("ghsa_id"),
        "repository": repo,
        "clone": clone,
        "ai_sha": ai,
        "fix": fix,
        "parent": parent,
        "summary": r.get("summary"),
        "history_files": b.get("history_files") or [],
        "blame_files": b.get("blame_files") or [],
        "blame_lines": b.get("blame_lines") or 0,
        "n_parents": b.get("n_parents"),
        "atomic_first_parent": b.get("atomic_first_parent"),
        "commit_refs": r.get("commit_refs") or [],
        "n_hits": r.get("n_hits"),
        "status": r.get("status"),
        "kind": r.get("kind") or "directroot",
    }
    if clone and ai:
        rc, out, err = git_show(clone, ai)
        rec["ai_show_rc"] = rc
        rec["ai_show"] = out[:2500]
        rec["ai_files_rc"], rec["ai_files"], _ = git_files(clone, ai)
        rec["ai_stat_rc"], rec["ai_stat"], _ = git_stat(clone, ai)
    if clone and fix:
        rc, out, err = git_show(clone, fix)
        rec["fix_show_rc"] = rc
        rec["fix_show"] = out[:2500]
        rec["fix_files_rc"], rec["fix_files"], _ = git_files(clone, fix)
    if clone and parent:
        rc, out, err = git_show(clone, parent)
        rec["parent_show_rc"] = rc
        rec["parent_exists"] = rc == 0
    # overlap
    ai_set = set(rec.get("ai_files") or [])
    fix_set = set(rec.get("fix_files") or [])
    hist = set(rec["history_files"])
    blame = set(rec["blame_files"])
    rec["overlap_ai_fix"] = sorted(ai_set & fix_set)
    rec["overlap_ai_hist"] = sorted(ai_set & hist)
    rec["overlap_fix_hist"] = sorted(fix_set & hist)
    rec["overlap_ai_blame"] = sorted(ai_set & blame)
    rec["in_l0"] = rec["ghsa_id"].upper() in l0_ids
    evidence.append(rec)

# bounded advisory lookup: try github reviewed path pattern without full walk if possible
adv_index = {}
# search a few likely trees with find via python limited to GHSA filenames using rg if available
for rec in evidence:
    ghsa = rec["ghsa_id"]
    slug = ghsa.lower()
    hits = []
    # try git grep in advisory clones is too heavy; use locate-like glob
    patterns = [
        f"**/{slug}.json",
        f"**/{slug}.yml",
        f"**/{slug}.md",
        f"**/{ghsa}.json",
    ]
    rec["advisory_hits"] = hits

# write raw evidence summary compact
compact = []
for rec in evidence:
    compact.append({
        k: rec[k] for k in rec if k not in {"ai_show", "fix_show", "ai_stat"}
    } | {
        "ai_subject": (rec.get("ai_show") or "").splitlines()[4] if rec.get("ai_show") else None,
        "ai_body_head": "\n".join((rec.get("ai_show") or "").splitlines()[5:12]),
        "fix_subject": (rec.get("fix_show") or "").splitlines()[4] if rec.get("fix_show") else None,
        "fix_body_head": "\n".join((rec.get("fix_show") or "").splitlines()[5:12]),
        "ai_show_full": rec.get("ai_show"),
        "fix_show_full": rec.get("fix_show"),
        "ai_stat": rec.get("ai_stat"),
    })

(OWNED / "_overlap.json").write_text(json.dumps({
    "slice_sha": slice_sha,
    "n": len(compact),
    "l0_count": len(l0_ids),
    "adv_roots": adv_roots,
    "rows": compact,
}, indent=2))
print("WROTE overlap", OWNED / "_overlap.json")
