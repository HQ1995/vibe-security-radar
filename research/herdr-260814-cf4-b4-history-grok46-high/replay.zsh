#!/usr/bin/env zsh
set -euo pipefail
unset GIT_NO_LAZY_FETCH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_NOSYSTEM=1
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

OWNED="autoresearch/herdr-260814-cf4-b4-history-grok46-high"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OWNED_ABS="$ROOT/$OWNED"
F2="/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database"
U39="/home/hanqing/.cache/cve-analyzer/advisory-database"
LEDGER="$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl"
SUMMARY="$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json"
CONTRACT="$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"
FICK="/home/hanqing/.cache/cve-analyzer/repos/trailofbits_fickling"
HERM="/home/hanqing/.cache/cve-analyzer/repos/github.com_nesquena_hermes-webui"

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

expect_hash() {
  local p="$1" h="$2"
  local g
  g="$(sha256sum "$p" | awk '{print $1}')"
  [[ "$g" == "$h" ]] || fail "hash $p"
}

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921

[[ "$(git -C "$F2" rev-parse HEAD)" == "f2c6ab3202aeafb36fbea6e76d892532acfca1a6" ]] || fail "f2c6 HEAD"
[[ -d "$F2/advisories/github-reviewed" ]] || fail "f2c6 reviewed subtree"
[[ ! -d "$F2/advisories/unreviewed" ]] || fail "f2c6 must not supply unreviewed"
[[ "$(git -C "$U39" rev-parse HEAD)" == "39d8887723797efc1804585dd06585c9fd751226" ]] || fail "39d888 HEAD"
[[ -d "$U39/advisories/unreviewed" ]] || fail "39d unreviewed subtree"

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED_ABS/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b:
    raise SystemExit(1)
b.decode("ascii")
if b.endswith(b" ") or b" \n" in b:
    raise SystemExit(1)
PY
done

python3 - "$OWNED_ABS" "$ROOT" "$F2" "$U39" "$LEDGER" "$SUMMARY" <<'PY' || fail "conservation"
import hashlib, json, re, sys
from pathlib import Path
owned, root, f2, u39, ledger, summary = map(Path, sys.argv[1:])
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
ID_FIELDS = {"case_id", "ghsa_id", "reviewed_case_ids", "assigned_ids", "strict_released_case_ids"}
OWNED_NAME = "herdr-260814-cf4-b4-history-grok46-high"
SURFACE = {
    "GHSA-P2QQ-M885-CM42","GHSA-XQ6P-PM3C-F228","GHSA-9CQV-QVMJ-XRC4",
    "GHSA-MJRQ-XG2M-QG94","GHSA-GV7X-PQ3J-C5MJ","GHSA-9CF6-6J4G-MW9R",
    "GHSA-PXHC-H7Q5-6QRG","GHSA-4HGQ-JJGJ-6JWM","GHSA-5J37-RF54-82Q2",
    "GHSA-WWX5-JQ7H-RP7V","GHSA-HQ7F-WV7C-W9MP","GHSA-4HHQ-38M9-MGG7",
}
skip_dirs = {".git", "node_modules", "work", "notes", "pages", "snapshot", "caches", "tmp"}

def norm(s):
    if not isinstance(s, str):
        return None
    u = s.strip().upper()
    return u if GHSA_RE.fullmatch(u) else None

def bucket(gid):
    return int(hashlib.sha256(gid.encode("ascii")).hexdigest(), 16) % 6

def walk_collect(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ID_FIELDS:
                if isinstance(v, str):
                    n = norm(v)
                    if n:
                        out.add(n)
                elif isinstance(v, list):
                    for item in v:
                        n = norm(item) if isinstance(item, str) else None
                        if n:
                            out.add(n)
            else:
                walk_collect(v, out)
    elif isinstance(obj, list):
        for item in obj:
            walk_collect(item, out)

assign = [json.loads(l) for l in (owned/"assignment.jsonl").read_text().splitlines() if l.strip()]
cases = [json.loads(l) for l in (owned/"cases.jsonl").read_text().splitlines() if l.strip()]
res = json.loads((owned/"result.json").read_text())
assert len(assign) == 2 and len(cases) == 2
aids = [a["case_id"] for a in assign]
cids = [c["case_id"] for c in cases]
assert aids == cids == res["conservation"]["reviewed_case_ids"]
assert res["counts"]["PASS"] == 0 and res["counts"]["REJECT"] == 2
assert res["counts"]["PASS_PROPOSAL"] == 0
assert res["counts"]["reviewed"] == 2 and res["did_not_pad"] is True
assert all(c["verdict"] == "REJECT" for c in cases)
assert all(c.get("proposed_pass") is False for c in cases)
assert all(bucket(i) == 4 for i in aids)
assert set(aids).isdisjoint(SURFACE)
assert res["bound"]["eligible"] == 529
assert res["bound"]["inspected_prefix"] == 529
assert res["bound"]["max_inspect"] == 600
assert res["bound"]["stop_rule"] == "prefix_exhausted"
assert res["bound"]["hits"] == 2
assert res["bound"]["shortfall"] == 10

excluded = set()
auto = root / "autoresearch"
for p in sorted(auto.iterdir()):
    if not p.is_dir():
        continue
    if p.name == OWNED_NAME:
        continue
    if not (p.name.startswith("herdr-") or p.name.startswith("orchestrator-")):
        continue
    for f in p.rglob("*"):
        if not f.is_file() or f.suffix not in {".json", ".jsonl"}:
            continue
        if set(f.parts) & skip_dirs:
            continue
        if f.stat().st_size > 50_000_000:
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        if f.suffix == ".jsonl":
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    walk_collect(json.loads(line), excluded)
                except Exception:
                    continue
        else:
            try:
                walk_collect(json.loads(text), excluded)
            except Exception:
                continue

canon = set()
for line in ledger.read_text().splitlines():
    if line.strip():
        walk_collect(json.loads(line), canon)
walk_collect(json.loads(summary.read_text()), canon)
excluded |= canon
assert not (set(aids) & excluded), "exclusion overlap"
strict = set(json.loads(summary.read_text())["strict_released_case_ids"])
assert not (set(aids) & strict), "canonical88 overlap"
assert len(strict) == 88
assert SURFACE <= excluded

f2_ids = set()
for pth in (f2 / "advisories/github-reviewed").rglob("*.json"):
    n = norm(pth.stem)
    if n:
        f2_ids.add(n)
for a in assign:
    ap = Path(a["advisory_path"])
    ufile = u39 / ap
    assert ufile.is_file(), a["case_id"]
    rec = json.loads(ufile.read_text())
    assert rec["id"].upper() == a["case_id"]
    assert rec.get("affected") == []
    assert a["case_id"] not in f2_ids, a["case_id"] + " f2c6 reviewed collision"
print("json_ok")
print("exclusion_ok")
print("bucket4_ok")
print("no_overlap_ok")
print("source_split_ok")
print("bound_ok")
print("proposal_count 0")
print("conservation 2=2+0")
PY

gitq() { git -c advice.detachedHead=false "$@" 2>/dev/null; }

[[ -e "$FICK/.git" || -f "$FICK/.git" ]] || fail "missing fickling clone"
[[ -e "$HERM/.git" || -f "$HERM/.git" ]] || fail "missing hermes clone"

gitq -C "$FICK" cat-file -t e5e34bbc18ff2cba54ed7787f87fa32d70dd56f2 | grep -qx commit || fail "missing cand fickling"
gitq -C "$FICK" cat-file -t 41ce7cb01edd97072994039574a2301ebb3f463d | grep -qx commit || fail "missing fix fickling"
gitq -C "$FICK" merge-base --is-ancestor e5e34bbc18ff2cba54ed7787f87fa32d70dd56f2 41ce7cb01edd97072994039574a2301ebb3f463d || fail "cand not ancestor of fix fickling"
gitq -C "$FICK" merge-base --is-ancestor 41ce7cb01edd97072994039574a2301ebb3f463d v0.1.12 || fail "fix not in v0.1.12"
if gitq -C "$FICK" merge-base --is-ancestor 41ce7cb01edd97072994039574a2301ebb3f463d v0.1.11; then
  fail "fix unexpectedly in v0.1.11"
fi
gitq -C "$FICK" merge-base --is-ancestor e5e34bbc18ff2cba54ed7787f87fa32d70dd56f2 v0.1.11 || fail "cand not in v0.1.11"
gitq -C "$FICK" log -1 --format=%B e5e34bbc18ff2cba54ed7787f87fa32d70dd56f2 | grep -q "Co-Authored-By: Claude Opus 4.5" || fail "fickling AI marker"
gitq -C "$FICK" log -1 --format=%B 41ce7cb01edd97072994039574a2301ebb3f463d | grep -q "Co-Authored-By: Claude Opus 4.7" || fail "fickling AI-on-fix"

gitq -C "$HERM" cat-file -t 7a80e73eb28fff2408dad31148e14f6407e652e9 | grep -qx commit || fail "missing cand hermes"
gitq -C "$HERM" cat-file -t 2a7a5ddfaf39e3b0094b7ac37e9f1dbcf40a3918 | grep -qx commit || fail "missing fix hermes"
gitq -C "$HERM" merge-base --is-ancestor 7a80e73eb28fff2408dad31148e14f6407e652e9 2a7a5ddfaf39e3b0094b7ac37e9f1dbcf40a3918 || fail "cand not ancestor of fix hermes"
gitq -C "$HERM" merge-base --is-ancestor 2a7a5ddfaf39e3b0094b7ac37e9f1dbcf40a3918 v0.50.34 || fail "fix not in v0.50.34"
if gitq -C "$HERM" merge-base --is-ancestor 2a7a5ddfaf39e3b0094b7ac37e9f1dbcf40a3918 v0.50.33; then
  fail "fix unexpectedly in v0.50.33"
fi
gitq -C "$HERM" merge-base --is-ancestor 7a80e73eb28fff2408dad31148e14f6407e652e9 v0.50.33 || fail "cand not in v0.50.33"
[[ "$(gitq -C "$HERM" rev-parse v0.50.34)" == "2a7a5ddfaf39e3b0094b7ac37e9f1dbcf40a3918" ]] || fail "v0.50.34 peel"
gitq -C "$HERM" log -1 --format=%B 7a80e73eb28fff2408dad31148e14f6407e652e9 | grep -q "Co-Authored-By: Claude Opus 4.6" || fail "hermes AI marker"

print "git_ok"
print "REPLAY_OK"
