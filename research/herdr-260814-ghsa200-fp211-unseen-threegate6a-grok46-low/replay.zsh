#!/usr/bin/env zsh
# Fail-closed zsh replay for herdr-260814-ghsa200-fp211-unseen-threegate6a-grok46-low.
# English only. Do not print credentials or environment values.
# Do not clone, commit, push, or modify shared caches.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# Do not name a local 'path': zsh ties path to PATH.
# PASS is a proposal only. This script does not admit any row.
# Canonical baseline is 84. Packet delta is 0. Terminal NARROW. Zero PASS.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-ghsa200-fp211-unseen-threegate6a-grok46-low
export TMPDIR=$OWNED/work
OC=/home/hanqing/.cache/ghsa200-worker-clones/redbase/clones/openclaw
MA=/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/marten

QJ_M=78d08fc574af8742c674cd6b986cd61a46d811e6
QJ_C=4b3e9c0f339d3b0af21dbbd699b378899ec6e193
QJ_F=a7f4a53ce80c98ba1452eb90802d447fca9bf3d6
CV_M=079af0d0b02ca2c722f90b6c4e38e27ba16227b4
CV_F=40a292619e1f2be3a3b1db663d7494c9c2dc0abf
JF_M=bb6d608d12b75a473ecf285bb64815a460144308
JF_C=8befe7f8a7fea496e1566eecc3fbf0a1d46e3642
HH_M=b9b47f50023d9f6384372bad6eee1a181b98c48e
HH_F=ee52f64226a03efadfdf1e3b759e13424a3d4e41
W4_M=8d74578ceb0c3b913555dff6265821eb0fc09749
W4_F1=4fd7feb0fd4ec16c48ed983980dba79a09b3aaf5
W4_F2=93880717f1cd34feaa45e74e939b7a5256288901
VM_M=3408b01ec7989ed0fc8d2f1059e81dc3d95c3947
VM_C=18c8d9b463dc31f429bb1684b83967ca42c751f2
VM_F=626249656829860b9c55895b5b6046b61a2a695f

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing file: %s\n' "$1" >&2
    exit 1
  fi
}

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  if [[ $got != "$expected" ]]; then
    printf 'hash mismatch %s\n expected %s\n got      %s\n' "$target" "$expected" "$got" >&2
    exit 1
  fi
}

g() {
  local repo=$1
  shift
  local errf=$OWNED/work/.giterr
  set +e
  /usr/bin/timeout 40 "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ $rc -eq 124 ]]; then
    printf 'git timeout\n' >&2
    exit 1
  fi
  if grep -qE 'could not fetch|bad object|not our ref|could not get object info' "$errf" 2>/dev/null; then
    printf 'missing object (fail closed)\n' >&2
    cat "$errf" >&2
    rm -f "$errf"
    exit 1
  fi
  if [[ -s $errf ]]; then
    grep -vF 'unable to normalize alternate object path' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

assert_ancestor() {
  g "$1" merge-base --is-ancestor "$2" "$3"
}

assert_not_ancestor() {
  if g "$1" merge-base --is-ancestor "$2" "$3"; then
    printf 'unexpected ancestor: %s is ancestor of %s\n' "$2" "$3" >&2
    exit 1
  fi
}

require_commit() {
  local t
  t=$(g "$1" cat-file -t "$2")
  if [[ $t != commit ]]; then
    printf 'not a commit: %s\n' "$2" >&2
    exit 1
  fi
}

require_dir "$OWNED"
require_dir "$OC/.git"
require_dir "$MA/.git"
require_file "$OWNED/selected.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/report.md"
require_file "$OWNED/result.json"
require_file "$OWNED/replay.zsh"
require_file "$OWNED/compact_facts.json"
require_file "$OWNED/notes/README.md"
require_file "$OWNED/notes/freeze.txt"
require_file "$OWNED/notes/facts/README.md"
require_file "$OWNED/notes/diffs/README.md"
require_file "$OWNED/work/freeze.json"
require_file "$OWNED/work/uniqueness.json"

expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl" \
  0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl" \
  a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical84/summary.json" \
  6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a
expect_hash "$OWNED/selected.jsonl" \
  1f12a7c4c157f3a456b69e1a3ad9dc3e9eb2bd548e69fad21f4a2cdc7d9e97fa
expect_hash "$OWNED/cases.jsonl" \
  e659ca109247801526d53326fefce0f614ea3d29be3c1e688cdcc569ac693b57
expect_hash "$OWNED/report.md" \
  c104ab4e615d6bd4b0ac828c8a93d1f1586b41f83d11c4c5d7ed5d7371c97454
expect_hash "$OWNED/result.json" \
  9a75c72993e9b22ba6660b0035164a9ca3cd1e600da7cf461af19fe27a7bd174
expect_hash "$OWNED/compact_facts.json" \
  1a588f7a972646025b220987047eb4403fcaa6d2853af366df7cfaee0be5ac3e
expect_hash "$OWNED/notes/README.md" \
  78210b49094dc05233b0204a7ee6d2c38bd986fcf63bbffcb8e3d8e7ab0b7042
expect_hash "$OWNED/notes/freeze.txt" \
  b3ccdfae80da40c2e49a7a3114a1c4ec7abc55981e7a835eb4c14504b46075c2
expect_hash "$OWNED/notes/facts/README.md" \
  3f20db22f55c2e526dffe1dec8423b50e15079d0d35b4206ff58966dd97cfab3
expect_hash "$OWNED/notes/diffs/README.md" \
  6d419fdf36e6280aed0519f78e2c759a1b789b57e618e69a4a60208f21e470f5
expect_hash "$OWNED/notes/releases/README.md" \
  dd929ba4c17db078e193ae241d39daa9c33d2fc5a86bf5f5e2d92615d4f9ee35
expect_hash "$OWNED/notes/releases/npm_openclaw.json" \
  b8884ffc50207329c913b34a8d293c6e3de7bdd8d94b8b631e81f1d7794eb0a6
expect_hash "$OWNED/notes/releases/marten_tags.json" \
  2653382dc833a8bc962ce135d63082fd577ce66dd87e3d9824b734a432c2209d
expect_hash "$OWNED/work/freeze.json" \
  6d9b6d7a736bb6fdc034fc3a3ff993daadb5f0807a90739f1033efd2ad0b3c3c
expect_hash "$OWNED/work/uniqueness.json" \
  bca1e7a015d497c568ac88a671f5ecf175544a6b399f578029b8abf3388319e7
expect_hash "$OWNED/notes/facts/GHSA-QJ77-C3C8-9C3Q.compact.json" \
  e6624abe3809125935c798e49e82bf155d83419b6f8cd0e3fff503d9949f2d03
expect_hash "$OWNED/notes/facts/GHSA-3CVX-236H-M9FJ.compact.json" \
  60bd0f988015a0246ed91ef6736ee7ca2dec34882f27df489cadaedd56e204b7
expect_hash "$OWNED/notes/facts/GHSA-JFV4-H8MC-JCP8.compact.json" \
  eefaa3e156bf0619587baf27724b774ae0c12c1636ecf397d8bb91012b8638ed
expect_hash "$OWNED/notes/facts/GHSA-HHFF-FJ5F-QG48.compact.json" \
  ff0c8cab85d7e9f0a689a2f969811b8e2388359dce618984612b8ba02654a48d
expect_hash "$OWNED/notes/facts/GHSA-W4H3-GPV2-82QC.compact.json" \
  ed89d4b59a673b02f03611c3b3e3e811a8692bd775cd52a171076fc9eb936ebd
expect_hash "$OWNED/notes/facts/GHSA-VMW2-QWM8-X84C.compact.json" \
  d9c1776da6f05187ff962044b00378131c488167a92a88086d2c55e719bce1a1

python3 - "$OWNED" << 'PY'
import json, sys
from pathlib import Path
owned = Path(sys.argv[1])
sel = [json.loads(l) for l in (owned / "selected.jsonl").read_text().splitlines() if l]
cases = [json.loads(l) for l in (owned / "cases.jsonl").read_text().splitlines() if l]
want = [
    "GHSA-QJ77-C3C8-9C3Q",
    "GHSA-3CVX-236H-M9FJ",
    "GHSA-JFV4-H8MC-JCP8",
    "GHSA-HHFF-FJ5F-QG48",
    "GHSA-W4H3-GPV2-82QC",
    "GHSA-VMW2-QWM8-X84C",
]
if [r["case_id"] for r in sel] != want:
    raise SystemExit("selected order")
if [r["case_id"] for r in cases] != want:
    raise SystemExit("cases order")
if any(r.get("worker_verdict") == "PASS" or r.get("countable") for r in cases):
    raise SystemExit("unexpected PASS")
res = json.loads((owned / "result.json").read_text())
if res["counts"]["PASS"] != 0 or res["packet_delta"] != 0 or res["canonical_strict_count_untouched"] != 84:
    raise SystemExit("result conservation")
if res["conservation"]["equation"] != "6=6+0":
    raise SystemExit("conservation equation")
PY

for sha in $QJ_M $QJ_C $QJ_F $CV_M $CV_F $JF_M $JF_C $HH_M $HH_F $W4_M $W4_F1 $W4_F2; do
  require_commit "$OC" "$sha"
done
for sha in $VM_M $VM_C $VM_F; do
  require_commit "$MA" "$sha"
done

# QJ77: member absent from vulnerable tag; carrier present; fix in v2026.2.2 only.
assert_not_ancestor "$OC" "$QJ_M" v2026.2.1
assert_ancestor "$OC" "$QJ_C" v2026.2.1
assert_not_ancestor "$OC" "$QJ_F" v2026.2.1
assert_ancestor "$OC" "$QJ_F" v2026.2.2
qj_m=$(g "$OC" rev-parse "${QJ_M}:src/agents/bash-tools.exec.ts")
qj_c=$(g "$OC" rev-parse "${QJ_C}:src/agents/bash-tools.exec.ts")
if [[ $qj_m == "$qj_c" ]]; then
  printf 'QJ77 unexpected equal blob\n' >&2
  exit 1
fi
qj_parents=$(g "$OC" rev-list --parents -n 1 "$QJ_M")
print -r -- "$qj_parents" | /usr/bin/awk '{ if (NF != 2) { print "QJ77 candidate not atomic" > "/dev/stderr"; exit 1 } }'

# 3CVX: any-ancestor of v2026.2.19; closer absent there; closer in v2026.2.21.
assert_ancestor "$OC" "$CV_M" v2026.2.19
assert_not_ancestor "$OC" "$CV_F" v2026.2.19
assert_ancestor "$OC" "$CV_F" v2026.2.21
cv_parents=$(g "$OC" rev-list --parents -n 1 "$CV_M")
print -r -- "$cv_parents" | /usr/bin/awk '{ if (NF != 2) { print "3CVX candidate not atomic" > "/dev/stderr"; exit 1 } }'
cv_m=$(g "$OC" rev-parse "${CV_M}:src/gateway/server/ws-connection/message-handler.ts")
cv_t=$(g "$OC" rev-parse "v2026.2.19:src/gateway/server/ws-connection/message-handler.ts")
if [[ $cv_m == "$cv_t" ]]; then
  printf '3CVX unexpected equal released blob\n' >&2
  exit 1
fi

# JFV4: member not in carrier or v2026.1.15; carrier is.
assert_not_ancestor "$OC" "$JF_M" "$JF_C"
assert_not_ancestor "$OC" "$JF_M" v2026.1.15
assert_ancestor "$OC" "$JF_C" v2026.1.15
jf_parents=$(g "$OC" rev-list --parents -n 1 "$JF_M")
print -r -- "$jf_parents" | /usr/bin/awk '{ if (NF != 2) { print "JFV4 candidate not atomic" > "/dev/stderr"; exit 1 } }'

# HHFF: member first-parent of v2026.3.28; closer absent; closer in v2026.3.31.
assert_ancestor "$OC" "$HH_M" v2026.3.28
assert_not_ancestor "$OC" "$HH_F" v2026.3.28
assert_ancestor "$OC" "$HH_F" v2026.3.31
hh_tree=$(g "$OC" ls-tree v2026.3.28 -- src/discord/monitor/message-handler.preflight.ts)
if [[ -n $hh_tree ]]; then
  printf 'HHFF unexpected member path in tag\n' >&2
  exit 1
fi
hh_parents=$(g "$OC" rev-list --parents -n 1 "$HH_M")
print -r -- "$hh_parents" | /usr/bin/awk '{ if (NF != 2) { print "HHFF candidate not atomic" > "/dev/stderr"; exit 1 } }'

# W4H3: member in v2026.1.20; closers absent; media.ts unchanged versus parent blob id.
assert_ancestor "$OC" "$W4_M" v2026.1.20
assert_not_ancestor "$OC" "$W4_F1" v2026.1.20
assert_not_ancestor "$OC" "$W4_F2" v2026.1.20
assert_ancestor "$OC" "$W4_F1" v2026.3.22
assert_ancestor "$OC" "$W4_F2" v2026.3.22
w4_parents=$(g "$OC" rev-list --parents -n 1 "$W4_M")
print -r -- "$w4_parents" | /usr/bin/awk '{ if (NF != 2) { print "W4H3 candidate not atomic" > "/dev/stderr"; exit 1 } }'
w4_m=$(g "$OC" rev-parse "${W4_M}:src/web/media.ts")
w4_p=$(g "$OC" rev-parse "${W4_M}^:src/web/media.ts")
if [[ $w4_m != "$w4_p" ]]; then
  printf 'W4H3 media.ts unexpectedly changed\n' >&2
  exit 1
fi

# VMW2: member absent from V8.36.0; carrier present; PrefixSearch blobs equal; fragment sink unchanged.
assert_not_ancestor "$MA" "$VM_M" V8.36.0
assert_ancestor "$MA" "$VM_C" V8.36.0
assert_not_ancestor "$MA" "$VM_F" V8.36.0
assert_ancestor "$MA" "$VM_F" V8.37.0
vm_parents=$(g "$MA" rev-list --parents -n 1 "$VM_M")
print -r -- "$vm_parents" | /usr/bin/awk '{ if (NF != 2) { print "VMW2 candidate not atomic" > "/dev/stderr"; exit 1 } }'
vm_m=$(g "$MA" rev-parse "${VM_M}:src/Marten/Linq/Parsing/Methods/FullText/PrefixSearch.cs")
vm_c=$(g "$MA" rev-parse "${VM_C}:src/Marten/Linq/Parsing/Methods/FullText/PrefixSearch.cs")
if [[ $vm_m != "$vm_c" ]]; then
  printf 'VMW2 PrefixSearch blob mismatch\n' >&2
  exit 1
fi
vm_frag_m=$(g "$MA" rev-parse "${VM_M}:src/Marten/Linq/SqlGeneration/Filters/FullTextWhereFragment.cs")
vm_frag_p=$(g "$MA" rev-parse "${VM_M}^:src/Marten/Linq/SqlGeneration/Filters/FullTextWhereFragment.cs")
if [[ $vm_frag_m != "$vm_frag_p" ]]; then
  printf 'VMW2 fragment unexpectedly changed on member\n' >&2
  exit 1
fi

printf 'replay ok packet_delta=0 canonical84=84 terminal=NARROW pass=0\n'
