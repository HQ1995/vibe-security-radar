#!/usr/bin/env zsh
set -euo pipefail
OWNED="autoresearch/herdr-260814-cf3-confirm5-grok46-high"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OWNED_ABS="$ROOT/$OWNED"
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

# Fail-closed git: drop only the known harmless broken-alternates line.
# Any other stderr, including other git errors, fails the replay.
REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d)"
GITQ_N=0
gitq() {
  GITQ_N=$((GITQ_N + 1))
  local outfile errfile rc filtered
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  filtered="$(grep -v -E -- '^error: unable to normalize alternate object path:' "$errfile" || true)"
  if [[ -n "$filtered" ]]; then
    rm -f "$outfile" "$errfile"
    fail "git stderr: $filtered"
  fi
  cat "$outfile"
  rm -f "$outfile" "$errfile"
  return $rc
}

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh replay.txt; do
  python3 - "$OWNED_ABS/$f" <<'PY' || fail "ascii $f"
import sys
p=sys.argv[1]
b=open(p,"rb").read()
if b"\x00" in b:
    raise SystemExit(1)
try:
    b.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(1)
PY
done

python3 - "$OWNED_ABS" <<'PY' || fail "json parse/conservation"
import json,sys
from pathlib import Path
d=Path(sys.argv[1])
assign=[json.loads(l) for l in (d/"assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in (d/"cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads((d/"result.json").read_text())
assert len(assign)==5 and len(cases)==5
aids=[a["case_id"] for a in assign]
cids=[c["case_id"] for c in cases]
expect=["GHSA-G8MR-85JM-7XHM","GHSA-M63V-2G9W-2W6V","GHSA-P5RM-JG5C-8C77","GHSA-X2W7-XR2G-QHJR","GHSA-X8QQ-M4QC-RPJ5"]
assert aids==cids==expect==res["conservation"]["reviewed_case_ids"]
assert res["conservation"]["equation"]=="5=5+0"
assert res["conservation"]["holds"] is True
assert res["counts"]["assigned"]==5 and res["counts"]["reviewed"]==5
assert res["counts"]["PASS"]==0 and res["counts"]["NARROW"]==5
assert res["pass_proposals"]==[]
assert res["packet_delta"]==0
assert res["canonical_strict_count_untouched"]==86
assert all(c["verdict"]=="NARROW" for c in cases)
assert all(c.get("proposed_pass") is False for c in cases)
assert all(c["gates"]["release_gate"]!="PASS" for c in cases)
assert all(v=="PASS" or v=="FAIL" or v=="NARROW" or v=="UNKNOWN" or v=="BLOCKED" for c in cases for v in c["gates"].values())
print("json_ok")
PY

need_obj() {
  local repo="$1" sha="$2"
  [[ -e "$repo/.git" || -f "$repo/.git" ]] || fail "missing clone $repo"
  gitq -C "$repo" cat-file -t "$sha" | grep -qx commit || fail "missing commit $sha in $repo"
}

V="/home/hanqing/.cache/cve-analyzer/repos/vitest-dev_vitest"
F="/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/fission"
K="/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2/microsoft__kiota"
W="/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/wacrm"
P="/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-even/clones/prospero-flow-crm"

need_obj "$V" af88b1f5d82844a4761ea9a977156c98e2b14ca8
need_obj "$V" 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7
gitq -C "$V" merge-base --is-ancestor af88b1f5d82844a4761ea9a977156c98e2b14ca8 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7 || fail "g8mr ancestry"
[[ -z "$(gitq -C "$V" tag --contains af88b1f5d82844a4761ea9a977156c98e2b14ca8 --no-contains 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7)" ]] || fail "g8mr residual tags"

need_obj "$F" 2db76f65dbfe4f657b4a4efb506ed63b24623e92
need_obj "$F" e484df8460bb4e8026e24210120602aa7f181f64
need_obj "$F" 695d3e97e3a20463ab7c8c081843e69e65e952e5
if gitq -C "$F" merge-base --is-ancestor 2db76f65dbfe4f657b4a4efb506ed63b24623e92 695d3e97e3a20463ab7c8c081843e69e65e952e5; then
  fail "m63v member unexpectedly ancestor of closer"
fi
[[ -z "$(gitq -C "$F" tag --contains 2db76f65dbfe4f657b4a4efb506ed63b24623e92)" ]] || fail "m63v member in tags"

need_obj "$K" f51f4971ea3459cd410b363b34e156a116b530f4
need_obj "$K" de3d18d9fe31ced4ac749728d3a2f94811f59268
need_obj "$K" 430008e9d700b3fe80f206c672415cfbd8e830e7
if gitq -C "$K" merge-base --is-ancestor f51f4971ea3459cd410b363b34e156a116b530f4 430008e9d700b3fe80f206c672415cfbd8e830e7; then
  fail "p5rm member unexpectedly ancestor of closer"
fi
[[ -z "$(gitq -C "$K" tag --contains f51f4971ea3459cd410b363b34e156a116b530f4)" ]] || fail "p5rm member in tags"

need_obj "$W" 4afa9bea32cd4538af19cbba45a874dbb614be8d
need_obj "$W" b4f18537bbf6787d18a9abafce53c557ac36f475
gitq -C "$W" merge-base --is-ancestor 4afa9bea32cd4538af19cbba45a874dbb614be8d b4f18537bbf6787d18a9abafce53c557ac36f475 || fail "x2w7 ancestry"
[[ "$(gitq -C "$W" tag | wc -l | tr -d ' ')" == "0" ]] || fail "x2w7 unexpected tags"

need_obj "$P" 56ea64c80fd36840fe3c84d0c6a6a38296a8f111
need_obj "$P" 86f406519fd208f9be09cd7cf32cd24d292779fd
need_obj "$P" 9a859c4de3d49674916773d346c60d89ad7febe0
gitq -C "$P" merge-base --is-ancestor 56ea64c80fd36840fe3c84d0c6a6a38296a8f111 9a859c4de3d49674916773d346c60d89ad7febe0 || fail "x8qq order ancestry"
gitq -C "$P" merge-base --is-ancestor 86f406519fd208f9be09cd7cf32cd24d292779fd 9a859c4de3d49674916773d346c60d89ad7febe0 || fail "x8qq item ancestry"
[[ -z "$(gitq -C "$P" tag --contains 56ea64c80fd36840fe3c84d0c6a6a38296a8f111 --no-contains 9a859c4de3d49674916773d346c60d89ad7febe0)" ]] || fail "x8qq residual tags"

python3 - "$OWNED_ABS" <<'PY' || fail "hash mismatch"
import hashlib, json, sys
from pathlib import Path
d=Path(sys.argv[1])
res=json.loads((d/"result.json").read_text())
for name, expected in res["artifact_hashes"].items():
    got=hashlib.sha256((d/name).read_bytes()).hexdigest()
    if got!=expected:
        raise SystemExit(f"{name} {got} != {expected}")
print("hashes_ok")
PY

# owned dir must not contain durable pages/clones/packages/caches
python3 - "$OWNED_ABS" <<'PY' || fail "durable extras"
import sys
from pathlib import Path
d=Path(sys.argv[1])
allowed={"assignment.jsonl","cases.jsonl","result.json","report.md","replay.zsh","replay.txt"}
names={p.name for p in d.iterdir()}
extra=names-allowed
if extra:
    raise SystemExit(f"extra {sorted(extra)}")
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=5 PASS_proposal=0 NARROW=5 REJECT=0 UNKNOWN=0 BLOCKED=0"
