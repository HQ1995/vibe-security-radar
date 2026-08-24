#!/usr/bin/env zsh
set -euo pipefail
ROOT="${0:A:h:h:h:h}"
# Script lives at autoresearch/<lane>/replay.zsh -> four :h reaches repo root only if
# 0 is .../replay.zsh, :h = lane dir. Use lane-relative instead.
LANE="${0:A:h}"
REPO="$(cd "$LANE/../.." && pwd)"
cd "$REPO"

python3 - <<'PY'
import hashlib, json, os, subprocess, sys
from pathlib import Path

repo = Path.cwd()
owned = repo / "autoresearch/herdr-260814-cf2-kn-remediation-grok46-xhigh"
work = owned / "work"
fail = 0

def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def git(cmd, timeout=25):
    env = os.environ.copy()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=env)

# ASCII
for name in ("assignment.jsonl", "cases.jsonl", "result.json", "report.md", "replay.zsh"):
    raw = (owned / name).read_bytes()
    try:
        raw.decode("ascii")
    except UnicodeDecodeError:
        print("FAIL ascii", name)
        fail += 1
    else:
        print("OK ascii", name)

result = json.loads((owned / "result.json").read_text(encoding="ascii"))
freeze = json.loads((work / "freeze.json").read_text(encoding="ascii"))
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text(encoding="ascii").splitlines() if l.strip()]
assign = [json.loads(l) for l in (owned / "assignment.jsonl").read_text(encoding="ascii").splitlines() if l.strip()]

# conservation
unresolved = freeze["unresolved_n"]
skipped = sum(freeze["skip_stats"].values())
scored = freeze["scored_with_security_ai_n"]
selected = freeze["selected_n"]
if unresolved != skipped + scored:
    print("FAIL conservation unresolved", unresolved, skipped, scored)
    fail += 1
else:
    print("OK conservation unresolved", unresolved, "=", skipped, "+", scored)
if selected != 28 or len(cases) != 28 or len(assign) != 28:
    print("FAIL inspected counts", selected, len(cases), len(assign))
    fail += 1
else:
    print("OK inspected 28")
if scored - selected != 18:
    print("FAIL leftover", scored - selected)
    fail += 1
else:
    print("OK leftover 18 unreviewed")

# hashes
src = freeze["source_hashes"]
checks = {
    "CONTRACT.md": repo / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md",
    "canonical85/summary.json": repo / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json",
    "canvas/foundation.jsonl": repo / "autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl",
    "kn/ranking.jsonl": repo / "autoresearch/herdr-260813-ghsa200-commitfirst-kn-grok46-low/ranking.jsonl",
    "kn/unresolved-ids.txt": repo / "autoresearch/herdr-260813-ghsa200-commitfirst-kn-grok46-low/unresolved-ids.txt",
    "kn/selected-ids.txt": repo / "autoresearch/herdr-260813-ghsa200-commitfirst-kn-grok46-low/selected-ids.txt",
}
for key, path in checks.items():
    got = sha(path)
    exp = src[key]
    if got != exp:
        print("FAIL hash", key)
        fail += 1
    else:
        print("OK hash", key)

# no PASS and all seven gates not all PASS
pass_n = 0
for c in cases:
    g = c["gates"]
    if all(g[k] == "PASS" for k in (
        "identity_gate","ai_hunk_gate","topology_gate","but_for_gate",
        "fix_reversal_gate","release_gate","uniqueness_gate",
    )):
        pass_n += 1
        print("FAIL unexpected PASS", c["case_id"])
        fail += 1
    if c["worker_verdict"] != "REJECT":
        print("FAIL verdict", c["case_id"], c["worker_verdict"])
        fail += 1
    if c.get("countable"):
        print("FAIL countable", c["case_id"])
        fail += 1
if pass_n != 0 or result["counts"]["PASS_PROPOSAL"] != 0:
    print("FAIL pass count")
    fail += 1
else:
    print("OK zero PASS_PROPOSAL")

# assignment IDs frozen vs cases
ids_a = [r["case_id"] for r in assign]
ids_c = [r["case_id"] for r in cases]
if ids_a != ids_c or ids_a != freeze["selected_ids"]:
    print("FAIL id order")
    fail += 1
else:
    print("OK frozen id order")

# object existence + sample ancestry
samples = [
    ("GHSA-4CWX-7WF7-3272", "992c6d84069054b2bd23e1803fc4cec6ade56cce", "4fe5bc5fefe5ac81a200fc8e1cf84b8bf8464451", "YES"),
    ("GHSA-9C54-GXH7-PPJC", "ce8297fc12adb298edd3334f3eb4ad52aa8d5682", "b79089ff30c5d9ae77e6b903c408e1c26ad5c055", "YES"),
    ("GHSA-JGMV-J7WW-JX2X", "769fd75cc6b3d1f4e0c0c0c0c0c0c0c0c0c0c0c0", None, None),
]
# use live SHAs from cases
want_anc = {
    "GHSA-4CWX-7WF7-3272": "YES",
    "GHSA-9C54-GXH7-PPJC": "YES",
    "GHSA-JGMV-J7WW-JX2X": "NO",
    "GHSA-C9RC-MG46-23W3": "NO",
}
checked = 0
for c in cases:
    if c["case_id"] not in want_anc:
        continue
    clone = c.get("clone_path")
    if not clone or not Path(clone).exists():
        print("FAIL clone missing", c["case_id"])
        fail += 1
        continue
    pairs = c.get("pairs") or []
    if not pairs:
        print("FAIL no pairs", c["case_id"])
        fail += 1
        continue
    p0 = pairs[0]
    for sha in (p0["ai"], p0["closer"]):
        r = git(["git", "-C", clone, "cat-file", "-t", sha])
        if r.stdout.strip() != "commit":
            print("FAIL object", c["case_id"], sha, r.stdout, r.stderr[:120])
            fail += 1
        else:
            print("OK object", c["case_id"], sha[:12])
    r = git(["git", "-C", clone, "merge-base", "--is-ancestor", p0["ai"], p0["closer"]])
    got = "YES" if r.returncode == 0 else "NO" if r.returncode == 1 else "UNK"
    exp = want_anc[c["case_id"]]
    # For 4CWX first pair is 992c6d which is YES; for 9C54 first pair 6e646 is YES; for JGMV first is NO; keras first is NO
    if got != exp:
        print("FAIL ancestry", c["case_id"], got, "expected", exp, p0["ai"][:12], p0["closer"][:12])
        fail += 1
    else:
        print("OK ancestry", c["case_id"], got)
    tags = git(["git", "-C", clone, "tag"])
    if tags.stdout.strip():
        print("NOTE tags present", c["case_id"], len(tags.stdout.splitlines()))
    else:
        print("OK no local tags", c["case_id"], "release UNKNOWN")
    checked += 1
if checked != 4:
    print("FAIL sample count", checked)
    fail += 1

# exclude source-shard 30
src30 = set(p.strip().upper() for p in (repo / "autoresearch/herdr-260813-ghsa200-commitfirst-kn-grok46-low/selected-ids.txt").read_text().splitlines() if p.strip())
overlap = src30.intersection(ids_c)
if overlap:
    print("FAIL source-shard overlap", overlap)
    fail += 1
else:
    print("OK no source-shard 30 overlap")

canon = json.loads((repo / "autoresearch/orchestrator-260814-ghsa200-canonical85/summary.json").read_text())
canon_ids = set(x.upper() for x in canon["strict_released_case_ids"])
if canon_ids.intersection(ids_c):
    print("FAIL canonical85 overlap")
    fail += 1
else:
    print("OK no canonical85 overlap")

if fail:
    print("REPLAY FAIL", fail)
    sys.exit(1)
print("REPLAY OK")
PY
