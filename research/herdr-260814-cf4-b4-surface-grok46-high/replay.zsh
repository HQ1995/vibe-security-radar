#!/usr/bin/env zsh
set -euo pipefail
unset GIT_NO_LAZY_FETCH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_NOSYSTEM=1

OWNED="autoresearch/herdr-260814-cf4-b4-surface-grok46-high"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OWNED_ABS="$ROOT/$OWNED"
F2="/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database"
U39="/home/hanqing/.cache/cve-analyzer/advisory-database"
LEDGER="$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl"
SUMMARY="$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json"
CONTRACT="$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"

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
PY
done

python3 - "$OWNED_ABS" "$ROOT" "$F2" "$U39" "$LEDGER" "$SUMMARY" <<'PY' || fail "conservation"
import hashlib, json, re, sys
from pathlib import Path
owned, root, f2, u39, ledger, summary = map(Path, sys.argv[1:])
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
ID_FIELDS = {"case_id", "ghsa_id", "reviewed_case_ids", "assigned_ids", "strict_released_case_ids"}
OWNED_NAME = "herdr-260814-cf4-b4-surface-grok46-high"
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
assert len(assign) == 12 and len(cases) == 12
aids = [a["case_id"] for a in assign]
cids = [c["case_id"] for c in cases]
assert aids == cids == res["conservation"]["reviewed_case_ids"]
assert res["counts"]["PASS"] == 0 and res["counts"]["REJECT"] == 12
assert res["counts"]["reviewed"] == 12 and res["did_not_pad"] is True
assert all(c["verdict"] == "REJECT" for c in cases)
assert all(c.get("proposed_pass") is False for c in cases)
assert all(bucket(i) == 4 for i in aids)

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

# source split: each frozen id is in 39d unreviewed and not in f2c6 reviewed
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
    assert a["case_id"] not in f2_ids, a["case_id"] + " f2c6 reviewed collision"
print("json_ok")
print("exclusion_ok")
print("bucket4_ok")
print("no_overlap_ok")
print("source_split_ok")
print("proposal_count 0")
print("conservation 12=12+0")
PY

gitq() { git -c advice.detachedHead=false "$@" 2>/dev/null; }

check_local() {
  local repo="$1" cand="$2" fix="$3" vtag="$4" ftag="$5"
  [[ -e "$repo/.git" || -f "$repo/.git" ]] || fail "missing clone $repo"
  gitq -C "$repo" cat-file -t "$cand" | grep -qx commit || fail "missing cand $cand"
  gitq -C "$repo" cat-file -t "$fix" | grep -qx commit || fail "missing fix $fix"
  gitq -C "$repo" merge-base --is-ancestor "$cand" "$fix" || fail "not ancestor $cand $fix"
  if [[ -n "$ftag" ]]; then
    gitq -C "$repo" merge-base --is-ancestor "$fix" "$ftag" || fail "fix not in $ftag"
  fi
  if [[ -n "$vtag" ]]; then
    if gitq -C "$repo" merge-base --is-ancestor "$fix" "$vtag"; then
      fail "fix unexpectedly in $vtag"
    fi
  fi
}

G_GOCLAW="/home/hanqing/.cache/cve-analyzer/repos/github.com_nextlevelbuilder_goclaw"
G_HERMES="/home/hanqing/.cache/cve-analyzer/repos/github.com_nesquena_hermes-webui"
G_MP="/home/hanqing/.cache/cve-analyzer/repos/github.com_jxxghp_moviepilot"

check_local "$G_GOCLAW" f3f4c67b36980b6fd0740c60353fb12e74c02b9f 406022e79f4a18b3070a446712080571eff11e30 v3.8.5 v3.9.0
gitq -C "$G_GOCLAW" log -1 --format=%B f3f4c67b36980b6fd0740c60353fb12e74c02b9f | grep -q "Co-Authored-By: Claude Opus 4.6" || fail "goclaw AI marker"
check_local "$G_HERMES" c60ff543b5921175825eedf56df82f82b4c9888c 4d90577e25d5537cb07290eca3fb8abff3bab316 v0.51.441 v0.51.442
check_local "$G_HERMES" c60ff543b5921175825eedf56df82f82b4c9888c 58528a4d88b0fa4f7b822e31d6051c669769bd3b v0.51.269 v0.51.270
check_local "$G_HERMES" 8ae198e88c26bf5c8f5ad62a7d0c3779756d70ed ce272d9cd5f8e5a4521278f56eb5388010901646 "" v0.51.468
check_local "$G_MP" b181af40cd50a3b58e3d50c15e5933665f8bc661 0b7854a0af8751160b68c43c46ded48d2bd8a212 "" v2.13.2

TMP="$(mktemp -d /tmp/cf4-b4-replay-XXXXXX)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

clone_check() {
  local spec="$1" dest="$2" sha="$3" ftag="$4" mode="${5:-contains}"
  gitq clone -q --filter=blob:none --single-branch --no-tags "https://github.com/${spec}.git" "$dest" || fail "clone $spec"
  gitq -C "$dest" fetch -q --filter=blob:none origin tag "$ftag" || true
  gitq -C "$dest" cat-file -t "$sha" | grep -qx commit || fail "missing sha $spec $sha"
  if gitq -C "$dest" rev-parse "$ftag" >/dev/null; then
    if [[ "$mode" == "contains" ]]; then
      gitq -C "$dest" merge-base --is-ancestor "$sha" "$ftag" || fail "fix not in $spec $ftag"
    else
      if gitq -C "$dest" merge-base --is-ancestor "$sha" "$ftag"; then
        fail "fix unexpectedly in $spec $ftag"
      fi
    fi
  fi
}

clone_check TencentCloudBase/CloudBase-MCP "$TMP/CloudBase-MCP" 3f678a1e7bd400cd76469d61024097d4920dc6b5 v2.17.1
clone_check tugcantopaloglu/godot-mcp "$TMP/godot-mcp" eb63add552aa4bd9205395cf91b40654654a3cf2 v3.0.0
clone_check HKUDS/Vibe-Trading "$TMP/Vibe-Trading" f45fd85392f07b5e404e41d4fcb0ef0d6c2f87ab v0.1.10 absent
clone_check HKUDS/nanobot "$TMP/nanobot" 232df45126bcf0f8fccd123d73714f202c8e8612 v0.2.1
clone_check parseablehq/parseable "$TMP/parseable" f307c4989cc9f3ff4204fd383dec7a39924e6b2a v2.9.2
clone_check heymrun/heym "$TMP/heym" 835843e6d2bf7d018cbb8e50f28f0426eaa20c84 v0.0.21
clone_check new-usemame/Calibre-Web-NextGen "$TMP/Calibre-Web-NextGen" 9f50bb2c16160564c9f8777dc2ceed3eb95e4807 v4.0.7

print "git_ok"
print "REPLAY_OK"
