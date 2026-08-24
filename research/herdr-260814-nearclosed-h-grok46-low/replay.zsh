#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-h-grok46-low.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-h-grok46-low}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
BB=${BB:-/home/hanqing/.cache/cve-analyzer/repos/maziggy_bambuddy}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
ADV=${ADV:-/home/hanqing/.cache/cve-analyzer/advisory-database}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1 }

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

git_path_absent() {
  local outfile errfile rc
  GITQ_N=$((GITQ_N + 1))
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    rm -f "$outfile" "$errfile"
    return 1
  fi
  rm -f "$outfile" "$errfile"
  return 0
}

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
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

hash_check() {
  local f=$1 want=$2
  local got
  got=$(sha256sum "$f" | awk '{print $1}')
  if [[ $got != $want ]]; then
    fail "HASH_MISMATCH $f got=$got want=$want"
  fi
  print -r -- "HASH_OK $(basename "$f")"
}

echo "== input hashes =="
hash_check "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
hash_check "$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md" \
  70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/summary.json" \
  5222879219a975fa4388f3f07f5c62cd6687a642b6509afe48a4250fb4be81ef
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/ledger.jsonl" \
  daf706e14d514ad62d197e61aa8ec7f52eefd958bc19a4a7c58591a0be8654ec
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ADV/advisories/github-reviewed/2026/02/GHSA-gc24-px2r-5qmf/GHSA-gc24-px2r-5qmf.json" \
  95c5fa5eca9f24d385fe3ec3ec7437bae36cb48ca0973d81b962bffbb51c7667
hash_check "$ADV/advisories/github-reviewed/2026/03/GHSA-hff7-ccv5-52f8/GHSA-hff7-ccv5-52f8.json" \
  17d5fce562c257e64f9685ac96ad9e7df45b13f460e8b40e5e7a1587c8a100b8
hash_check "$ADV/advisories/github-reviewed/2026/02/GHSA-q447-rj3r-2cgh/GHSA-q447-rj3r-2cgh.json" \
  9d5a4294f2d0886bfbf8c4130ab9edc803c36190d068abda475b798009e0c812

echo "== conservation 3=3+0 =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
aids = [a["case_id"] for a in ass]
cids = [c["case_id"] for c in cas]
want = [
    "GHSA-GC24-PX2R-5QMF",
    "GHSA-HFF7-CCV5-52F8",
    "GHSA-Q447-RJ3R-2CGH",
]
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [37, 40, 47]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 1 or n_nar != 2 or n_rej != 0 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != ["GHSA-Q447-RJ3R-2CGH"]:
    print("PASS_LIST_FAIL", res["pass_proposals"]); sys.exit(1)
if res["canonical_strict_count_untouched"] != 90 or res["counts"]["countable_pass"] != 0:
    print("FLAG_FAIL"); sys.exit(1)
if cas[0]["verdict"] != "NARROW" or cas[1]["verdict"] != "NARROW":
    print("NARROW_DRIFT"); sys.exit(1)
if cas[0]["gates"]["but_for_gate"] != "NARROW" or cas[1]["gates"]["but_for_gate"] != "NARROW":
    print("BUT_FOR_NOT_NARROW"); sys.exit(1)
need_pass = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
rec = cas[2]
g = rec["gates"]
for k in need_pass:
    if g[k] != "PASS":
        print("GATE_NOT_PASS", rec["case_id"], k, g[k]); sys.exit(1)
if rec["verdict"] != "PASS_PROPOSAL" or rec.get("proposed_pass") is not True:
    print("PROPOSAL_FLAG", rec["case_id"]); sys.exit(1)
if rec.get("seven_gates_exact_pass") is not True:
    print("SEVEN_PASS_FLAG", rec["case_id"]); sys.exit(1)
if rec.get("osv_introduced_used_as_causal_proof") is not False:
    print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
if rec.get("countable_proposal") is not True:
    print("COUNTABLE_PROPOSAL_FLAG", rec["case_id"]); sys.exit(1)
if rec.get("authorship_transfer") is not False:
    print("TRANSFER_FLAG"); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=2 REJECT=0 PASS_PROPOSAL=1")
PY

echo "== uniqueness vs canonical90 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical90", hit); sys.exit(1)
if "GHSA-XMXX-7P24-H892" not in strict:
    print("XMXX_MISSING_FROM_CANON90"); sys.exit(1)
if len(strict) != 90:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "xmxx_counted_distinct_sha_ok")
PY

echo "== git facts =="
[[ -d $BB && -d $OC ]] || fail "CLONE_ABSENT"

# GC24 ordinal 37
C=a7319f0e7087cee59f1aa658c52c6408f1fb71e8
F1=c31f2968889c855f1ffacb700c2c9970deb2a6fb
F2=a82f9278d2d587b7042a0858aab79fd8b6e3add9
P=e248b41fad552d28b1f47c03f7f1e7d1be227423
gitq -C "$BB" cat-file -t "$C" >/dev/null
parents=$(gitq -C "$BB" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "GC24_PARENTS $parents"
gitq -C "$BB" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "GC24_MARKER"
if gitq -C "$BB" grep -q simulate-print-complete "$P" -- backend/app/api/routes/printers.py; then
  fail "GC24_PARENT_HAS_SIMULATE"
fi
gitq -C "$BB" grep -q simulate-print-complete "$C" -- backend/app/api/routes/printers.py || fail "GC24_CAND_SIMULATE"
gitq -C "$BB" grep -q simulate-print-complete v0.1.6 -- backend/app/api/routes/printers.py || fail "GC24_V016_SIMULATE"
gitq -C "$BB" grep -q 'bambuddy-secret-key-change-in-production' v0.1.6 -- backend/app/core/auth.py || fail "GC24_V016_JWT"
gitq -C "$BB" grep -q 'RequirePermissionIfAuthEnabled(Permission.PRINTERS_CONTROL)' v0.1.7 -- backend/app/api/routes/printers.py || fail "GC24_V017_PERM"
gitq -C "$BB" merge-base --is-ancestor "$C" v0.1.6 || fail "GC24_CAND_TAG"
gitq -C "$BB" merge-base --is-ancestor "$F1" v0.1.6 && fail "GC24_F1_IN_VULN" || true
gitq -C "$BB" merge-base --is-ancestor "$F2" v0.1.6 && fail "GC24_F2_IN_VULN" || true
gitq -C "$BB" merge-base --is-ancestor "$F1" v0.1.7 || fail "GC24_F1_TAG"
gitq -C "$BB" merge-base --is-ancestor "$F2" v0.1.7 || fail "GC24_F2_TAG"
peel=$(gitq -C "$BB" rev-parse 'v0.1.6^{commit}')
[[ $peel == 1209e181a48dcff04f3cf061c6609a0724928114 ]] || fail "GC24_PEEL016 $peel"
echo "GC24_OK"

# HFF7 ordinal 40
C=f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f
F=356d61aacfa5b0f1d5830716ec59d70682a3e7b8
P=7f6e87e9180b9f236aa88b90936be8f6f7988bc2
gitq -C "$OC" cat-file -t "$C" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "HFF7_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "HFF7_MARKER"
git_path_absent -C "$OC" cat-file -e "${P}:src/gateway/openresponses-http.ts" || fail "HFF7_PARENT_HAS_FILE"
gitq -C "$OC" grep -q authorizeGatewayConnect "$P" -- src/gateway/openai-http.ts || fail "HFF7_PARENT_OPENAI_AUTH"
gitq -C "$OC" grep -q authorizeGatewayConnect "$C" -- src/gateway/openresponses-http.ts || fail "HFF7_CAND_RESPONSES_AUTH"
gitq -C "$OC" grep -q allowTailscaleHeaderAuth "$F" -- src/gateway/auth.ts || fail "HFF7_FIX_FLAG"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"scope tailscale tokenless auth to websocket"* ]] || fail "HFF7_FIX_SUBJ $fsubj"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.2.19 || fail "HFF7_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.2.19 && fail "HFF7_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.2.21 || fail "HFF7_FIX_TAG"
peel=$(gitq -C "$OC" rev-parse 'v2026.2.19^{commit}')
[[ $peel == 2c05cbb43e48ebad03626d3125746fb1b9a8520f ]] || fail "HFF7_PEEL219 $peel"
echo "HFF7_OK"

# Q447 ordinal 47
M=b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517
CAR=5c2cb6c591e4b63c2df0549ad2202403256e2a96
F=3cbcba10cf30c2ffb898f0d8c7dfb929f15f8930
CP=49c60e9065d98a6848e62c717315eb91eeaa6038
gitq -C "$OC" cat-file -t "$M" >/dev/null
gitq -C "$OC" cat-file -t "$CAR" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$CAR")
[[ $parents == "$CAR $CP" ]] || fail "Q447_CAR_PARENTS $parents"
gitq -C "$OC" cat-file -p "$CAR" | LC_ALL=C grep -q 'Co-authored-by: Claude Opus 4.6' || fail "Q447_CAR_MARKER"
gitq -C "$OC" merge-base --is-ancestor "$M" "$CAR" && fail "Q447_MEMBER_TRANSFER" || true
if gitq -C "$OC" grep -q adaptDefault "$CP" -- extensions/feishu/src/monitor.ts; then
  fail "Q447_CARRIER_PARENT_HAS_ADAPT"
fi
gitq -C "$OC" grep -q adaptDefault "$CAR" -- extensions/feishu/src/monitor.ts || fail "Q447_CAR_ADAPT"
blob_m=$(gitq -C "$OC" rev-parse "${M}:extensions/feishu/src/monitor.ts")
blob_c=$(gitq -C "$OC" rev-parse "${CAR}:extensions/feishu/src/monitor.ts")
blob_v=$(gitq -C "$OC" rev-parse "v2026.2.12:extensions/feishu/src/monitor.ts")
[[ $blob_m == 31a890c2f92da2586c0c1f96c1d47a71100be610 ]] || fail "Q447_MEMBER_BLOB $blob_m"
[[ $blob_c == "$blob_m" ]] || fail "Q447_CAR_BLOB $blob_c"
[[ $blob_v == "$blob_m" ]] || fail "Q447_V212_BLOB $blob_v"
gitq -C "$OC" grep -q 'req.on("data"' "$CP" -- src/line/monitor.ts || fail "Q447_PARENT_LINE"
gitq -C "$OC" grep -q FEISHU_WEBHOOK_MAX_BODY_BYTES "$F" -- extensions/feishu/src/monitor.ts || fail "Q447_FIX_MAXBYTES"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"bounded webhook body handling"* ]] || fail "Q447_FIX_SUBJ $fsubj"
gitq -C "$OC" merge-base --is-ancestor "$M" v2026.2.12 && fail "Q447_MEMBER_IN_TAG" || true
gitq -C "$OC" merge-base --is-ancestor "$CAR" v2026.2.12 || fail "Q447_CAR_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.2.12 && fail "Q447_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.2.13 || fail "Q447_FIX_TAG"
blob_f=$(gitq -C "$OC" rev-parse "${F}:extensions/feishu/src/monitor.ts")
blob_t=$(gitq -C "$OC" rev-parse "v2026.2.13:extensions/feishu/src/monitor.ts")
[[ $blob_f == 51af5a4aeb48d3732c02bcfaf7538172cfd17ea0 ]] || fail "Q447_FIX_BLOB $blob_f"
[[ $blob_f == "$blob_t" ]] || fail "Q447_FIX_TAG_BLOB $blob_t"
echo "Q447_OK"

python3 - "$OWNED" <<'PY' || fail "artifact_hashes"
import hashlib, json, sys
from pathlib import Path
d=Path(sys.argv[1])
res=json.loads((d/"result.json").read_text())
for name in ("assignment.jsonl","cases.jsonl","report.md","replay.zsh"):
    got=hashlib.sha256((d/name).read_bytes()).hexdigest()
    want=res["artifact_hashes"][name]
    if got!=want:
        print("ARTIFACT_HASH_FAIL", name, got, want)
        raise SystemExit(1)
print("ARTIFACT_HASH_OK")
PY

python3 - "$OWNED" <<'PY' || fail "durable extras"
import sys
from pathlib import Path
d=Path(sys.argv[1])
allowed={"assignment.jsonl","cases.jsonl","result.json","report.md","replay.zsh"}
names={p.name for p in d.iterdir()}
extra=names-allowed
if extra:
    raise SystemExit(f"extra {sorted(extra)}")
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=3 PASS_proposal=1 NARROW=2 REJECT=0 UNKNOWN=0 BLOCKED=0"
