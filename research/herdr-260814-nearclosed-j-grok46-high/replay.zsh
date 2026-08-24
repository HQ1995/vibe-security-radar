#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-j-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
CO=${CO:-/home/hanqing/.cache/cve-analyzer/repos/conductor-oss_conductor}
ADV=${ADV:-/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database}
CADV=${CADV:-/home/hanqing/.cache/cve-analyzer/advisory-database}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

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
  echo "HASH_OK $(basename "$f")"
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
hash_check "$ADV/advisories/github-reviewed/2026/03/GHSA-rqpp-rjj8-7wv8/GHSA-rqpp-rjj8-7wv8.json" \
  c69b13e29caa4b9c3278a83e1bf1017e67cfaabd3f2dff8278e7958e7140830a
hash_check "$ADV/advisories/github-reviewed/2026/04/GHSA-g5cg-8x5w-7jpm/GHSA-g5cg-8x5w-7jpm.json" \
  51d6530aaa37e753f8f3cc4da18bc51b6d554cee636d013896c063b6a605c589
hash_check "$ADV/advisories/github-reviewed/2026/02/GHSA-rv39-79c4-7459/GHSA-rv39-79c4-7459.json" \
  d2bff0f8f95098e8a844042e942b77ff76fe890c0620b6eddcb7dd9cd40d584b
hash_check "$CADV/advisories/unreviewed/2026/06/GHSA-7x5q-8f6h-rjrc/GHSA-7x5q-8f6h-rjrc.json" \
  b747b92a75137398b7acfdf8890fb3d51e68a6e8c8dfc28b2cb7f7cd0dade604
adv_head=$(gitq -C "$ADV" rev-parse HEAD)
[[ $adv_head == a42c436870111aa3f221257c9d56126a93173ccc ]] || fail "ADV_HEAD $adv_head"
cadv_head=$(gitq -C "$CADV" rev-parse HEAD)
[[ $cadv_head == 39d8887723797efc1804585dd06585c9fd751226 ]] || fail "CADV_HEAD $cadv_head"

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
    "GHSA-RQPP-RJJ8-7WV8",
    "GHSA-7X5Q-8F6H-RJRC",
    "GHSA-G5CG-8X5W-7JPM",
]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
okv = ("PASS","FAIL","UNKNOWN","NARROW","BLOCKED")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [80, 86, 95]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 0 or n_nar != 3 or n_rej != 0 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposal_ids"] != []:
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 90:
    print("FLAG_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if g[k] not in okv:
            print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER", rec["case_id"]); sys.exit(1)
    if rec.get("proposed_pass") is not False:
        print("PROPOSED", rec["case_id"]); sys.exit(1)
    if rec["verdict"] != "NARROW" or rec["seven_gates_exact_pass"] is not False:
        print("NOT_NARROW", rec["case_id"]); sys.exit(1)
    if g["uniqueness_gate"] != "PASS":
        print("UNIQ_NOT_PASS", rec["case_id"]); sys.exit(1)
if cas[0]["gates"]["but_for_gate"] != "NARROW":
    print("RQPP_BUTFOR"); sys.exit(1)
if cas[0]["candidate_set"] != ["079af0d0b02ca2c722f90b6c4e38e27ba16227b4"]:
    print("RQPP_CAND"); sys.exit(1)
if cas[0].get("distinct_from_rv39") is not True:
    print("RQPP_RV39_FLAG"); sys.exit(1)
if "CVE-2026-28472" in cas[0].get("aliases", []):
    print("RQPP_PACKED_RV39_ALIAS"); sys.exit(1)
if cas[1]["gates"]["identity_gate"] != "NARROW":
    print("7X5Q_IDENTITY"); sys.exit(1)
if cas[1]["candidate_set"] != ["840ec19c1f68f46b1c9c6a68e6bfa0d9481c3434"]:
    print("7X5Q_CAND"); sys.exit(1)
if "d874e6e551a3354ade452ee5c9b99e3b453ee334" in cas[1]["candidate_set"]:
    print("7X5Q_MERGE_IN_CAND"); sys.exit(1)
if cas[2]["gates"]["but_for_gate"] != "NARROW":
    print("G5CG_BUTFOR"); sys.exit(1)
if cas[2]["candidate_set"] != ["483fba41b9f9fb57964f31b90a2ddacb185d54d7"]:
    print("G5CG_CAND"); sys.exit(1)
if "01d568c9f54585d2df3002e1090067c9dd621e43" in cas[2]["candidate_set"]:
    print("G5CG_MEMBER_IN_CAND"); sys.exit(1)
if cas[2]["gates"]["topology_gate"] != "PASS":
    print("G5CG_TOPO"); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=3 PASS_PROPOSAL=0")
PY

echo "== uniqueness vs pinned canonical90 and RV39 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical90", hit); sys.exit(1)
if "GHSA-8RW6-P7M8-63JP" in ids:
    print("UNIQUENESS_FAIL 8RW6"); sys.exit(1)
if "GHSA-RV39-79C4-7459" in ids:
    print("UNIQUENESS_FAIL RV39_COUNTED"); sys.exit(1)
if len(strict) != 90:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
if "GHSA-RV39-79C4-7459" not in strict:
    print("RV39_MISSING_FROM_CANON90"); sys.exit(1)
a_rq = json.loads(Path("$ADV/advisories/github-reviewed/2026/03/GHSA-rqpp-rjj8-7wv8/GHSA-rqpp-rjj8-7wv8.json").read_text())
a_rv = json.loads(Path("$ADV/advisories/github-reviewed/2026/02/GHSA-rv39-79c4-7459/GHSA-rv39-79c4-7459.json").read_text())
a_g5 = json.loads(Path("$ADV/advisories/github-reviewed/2026/04/GHSA-g5cg-8x5w-7jpm/GHSA-g5cg-8x5w-7jpm.json").read_text())
a_7x = json.loads(Path("$CADV/advisories/unreviewed/2026/06/GHSA-7x5q-8f6h-rjrc/GHSA-7x5q-8f6h-rjrc.json").read_text())
ids_rq = {a_rq.get("id","").lower()} | {x.lower() for x in a_rq.get("aliases", [])}
ids_rv = {a_rv.get("id","").lower()} | {x.lower() for x in a_rv.get("aliases", [])}
if ids_rq & ids_rv:
    print("ALIAS_OVERLAP", ids_rq & ids_rv); sys.exit(1)
if a_rq.get("aliases") != ["CVE-2026-22172"]:
    print("RQPP_ALIAS", a_rq.get("aliases")); sys.exit(1)
if a_rv.get("aliases") != ["CVE-2026-28472"]:
    print("RV39_ALIAS", a_rv.get("aliases")); sys.exit(1)
if a_g5.get("aliases") != ["CVE-2026-41329"]:
    print("G5CG_ALIAS", a_g5.get("aliases")); sys.exit(1)
if a_rq.get("database_specific",{}).get("github_reviewed") is not True:
    print("RQPP_NOT_REVIEWED"); sys.exit(1)
if a_g5.get("database_specific",{}).get("github_reviewed") is not True:
    print("G5CG_NOT_REVIEWED"); sys.exit(1)
if a_7x.get("database_specific",{}).get("github_reviewed") is not False:
    print("7X5Q_REVIEWED"); sys.exit(1)
if a_7x.get("affected") not in ([], None):
    print("7X5Q_AFFECTED", a_7x.get("affected")); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "RQPP_DISTINCT_FROM_RV39")
PY

echo "== git facts =="
[[ -d $OC && -d $CO ]] || fail "CLONE_ABSENT"

# RQPP ordinal 80
CAND=079af0d0b02ca2c722f90b6c4e38e27ba16227b4
FIX=5e389d5e7c9233ec91026ab2fea299ebaf3249f6
P=5c5745dee52bc5e2ab00b81f8160714b14da01d8
MG=ec51bb700ca8c4f6f9e7bd5f99a9a1c59f4c8a46
HF=src/gateway/server/ws-connection/message-handler.ts
gitq -C "$OC" cat-file -t "$CAND" >/dev/null
gitq -C "$OC" cat-file -t "$FIX" >/dev/null
gitq -C "$OC" cat-file -t "$MG" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $P" ]] || fail "RQPP_PARENTS $parents"
gitq -C "$OC" cat-file -p "$CAND" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "RQPP_MARKER"
mgparents=$(gitq -C "$OC" rev-list --parents -n 1 "$MG")
[[ $mgparents == "$MG 051d518078c15c409ee2da61bd164b6d1d9b97e9 $CAND" ]] || fail "RQPP_MERGE_PARENTS $mgparents"
gitq -C "$OC" cat-file -p "$MG" | LC_ALL=C grep -q 'Co-Authored-By: Claude' && fail "RQPP_MERGE_HAS_CLAUDE" || true
if gitq -C "$OC" grep -q hasTokenAuth "$P" -- "$HF"; then
  fail "RQPP_PARENT_HAS_TOKENAUTH"
fi
gitq -C "$OC" grep -q hasTokenAuth "$CAND" -- "$HF" || fail "RQPP_CAND_MISSING_TOKENAUTH"
gitq -C "$OC" grep -q 'connectParams.scopes' "$P" -- "$HF" || fail "RQPP_PARENT_SCOPES"
if gitq -C "$OC" show "$CAND" -- "$HF" | LC_ALL=C grep -q scope; then
  fail "RQPP_CAND_SCOPE_HUNK"
fi
blob_c=$(gitq -C "$OC" rev-parse "${CAND}:$HF")
blob_v=$(gitq -C "$OC" rev-parse "v2026.3.11:$HF")
[[ $blob_c == e4a8dbd58fe9b10326bbe985a1485d3a0c0f3484 ]] || fail "RQPP_CAND_BLOB $blob_c"
[[ $blob_v == 0897b51e93798369ce4f21ae1cf0cc7eac9820f8 ]] || fail "RQPP_V311_BLOB $blob_v"
[[ $blob_c != "$blob_v" ]] || fail "RQPP_BLOB_EQUAL"
gitq -C "$OC" merge-base --is-ancestor "$CAND" v2026.3.11 || fail "RQPP_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$FIX" v2026.3.11 && fail "RQPP_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$FIX" v2026.3.12 || fail "RQPP_FIX_TAG"
pk=$(gitq -C "$OC" log --first-parent -S hasTokenAuth --format='%H' v2026.3.11 -- "$HF")
print -r -- "$pk" | LC_ALL=C grep -q '^079af0d0b02ca2c722f90b6c4e38e27ba16227b4' && fail "RQPP_CAND_FIRST_PARENT_PICKAXE" || true
print -r -- "$pk" | LC_ALL=C grep -q '^ec51bb700ca8c4f6f9e7bd5f99a9a1c59f4c8a46' || fail "RQPP_MERGE_PICKAXE $pk"
gitq -C "$OC" grep -q 'scopes.length > 0 && !controlUiAuthPolicy.allowBypass && !sharedAuthOk' v2026.3.11 -- "$HF" || fail "RQPP_V311_EXCEPTION"
if gitq -C "$OC" grep -q 'scopes.length > 0 && !controlUiAuthPolicy.allowBypass && !sharedAuthOk' "$FIX" -- "$HF"; then
  fail "RQPP_FIX_STILL_EXCEPTION"
fi
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$FIX")
[[ $fsubj == *"clear unbound scopes"* ]] || fail "RQPP_FIX_SUBJ $fsubj"
peel=$(gitq -C "$OC" rev-parse 'v2026.3.11^{commit}')
[[ $peel == 29dc65403faf41dc52944c02a0db9fa4b8457395 ]] || fail "RQPP_PEEL311 $peel"
peel=$(gitq -C "$OC" rev-parse 'v2026.3.12^{commit}')
[[ $peel == 70d7a0854c54c489eaefd56bb406ad885f2b3ea2 ]] || fail "RQPP_PEEL312 $peel"
echo "RQPP_OK"

# 7X5Q ordinal 86
M=840ec19c1f68f46b1c9c6a68e6bfa0d9481c3434
CAR=d874e6e551a3354ade452ee5c9b99e3b453ee334
F1=87a7d96aabbb706d6e84f812b93da5165028d18f
F2=c691e35e768caeb802c9f06ecdd9674c80081af1
MP=a9af7fa919d4e56e0c97e94801559349d1b0f802
SE=core/src/main/java/com/netflix/conductor/core/events/ScriptEvaluator.java
PE=core/src/main/java/com/netflix/conductor/core/execution/evaluators/PythonEvaluator.java
gitq -C "$CO" cat-file -t "$M" >/dev/null
gitq -C "$CO" cat-file -t "$CAR" >/dev/null
gitq -C "$CO" cat-file -t "$F1" >/dev/null
gitq -C "$CO" cat-file -t "$F2" >/dev/null
parents=$(gitq -C "$CO" rev-list --parents -n 1 "$M")
[[ $parents == "$M $MP" ]] || fail "7X5Q_PARENTS $parents"
gitq -C "$CO" cat-file -p "$M" | LC_ALL=C grep -q 'Co-Authored-By: Claude' || fail "7X5Q_MARKER"
carparents=$(gitq -C "$CO" rev-list --parents -n 1 "$CAR")
[[ $carparents == "$CAR $MP 02c8b68ef6a2b83f46a3a46594b565dac1885328" ]] || fail "7X5Q_CAR_PARENTS $carparents"
gitq -C "$CO" cat-file -p "$CAR" | LC_ALL=C grep -q 'Co-Authored-By: Claude' && fail "7X5Q_CAR_HAS_CLAUDE" || true
gitq -C "$CO" merge-base --is-ancestor "$M" "$CAR" || fail "7X5Q_MEM_ANC_CAR"
gitq -C "$CO" merge-base --is-ancestor "$M" "$MP" && fail "7X5Q_MEM_ANC_FIRST_PARENT" || true
gitq -C "$CO" merge-base --is-ancestor "$M" 02c8b68ef6a2b83f46a3a46594b565dac1885328 || fail "7X5Q_MEM_ANC_SECOND_PARENT"
gitq -C "$CO" grep -q 'factory.getScriptEngine("--no-java")' "$MP" -- "$SE" || fail "7X5Q_PARENT_NASHORN"
gitq -C "$CO" grep -q 'allowHostAccess(HostAccess.ALL)' "$M" -- "$SE" || fail "7X5Q_MEM_HOSTACCESS"
blob_py_p=$(gitq -C "$CO" rev-parse "${MP}:$PE")
blob_py_m=$(gitq -C "$CO" rev-parse "${M}:$PE")
[[ $blob_py_p == "$blob_py_m" ]] || fail "7X5Q_PYTHON_CHANGED $blob_py_p $blob_py_m"
[[ $blob_py_p == 1a71ee9b8635a8fd00307ffcc4187d56a6afd21a ]] || fail "7X5Q_PYTHON_BLOB $blob_py_p"
gitq -C "$CO" grep -q 'allowAllAccess(true)' "$MP" -- "$PE" || fail "7X5Q_PARENT_PYTHON"
blob_se_m=$(gitq -C "$CO" rev-parse "${M}:$SE")
blob_se_c=$(gitq -C "$CO" rev-parse "${CAR}:$SE")
blob_se_v=$(gitq -C "$CO" rev-parse "v3.21.21:$SE")
[[ $blob_se_m == "$blob_se_c" ]] || fail "7X5Q_SE_MEM_CAR"
[[ $blob_se_m == "$blob_se_v" ]] || fail "7X5Q_SE_MEM_TAG"
[[ $blob_se_m == 1a5feb7dade54c2bede6fae6963b909d825aab14 ]] || fail "7X5Q_SE_BLOB $blob_se_m"
gitq -C "$CO" merge-base --is-ancestor "$M" v3.21.21 || fail "7X5Q_MEM_TAG"
gitq -C "$CO" merge-base --is-ancestor "$CAR" v3.21.21 || fail "7X5Q_CAR_TAG"
gitq -C "$CO" merge-base --is-ancestor "$F1" v3.21.21 && fail "7X5Q_F1_IN_VULN" || true
gitq -C "$CO" merge-base --is-ancestor "$F2" v3.21.21 && fail "7X5Q_F2_IN_VULN" || true
gitq -C "$CO" merge-base --is-ancestor "$F1" v3.30.1 || fail "7X5Q_F1_3301"
gitq -C "$CO" merge-base --is-ancestor "$F2" v3.30.1 && fail "7X5Q_F2_IN_3301" || true
gitq -C "$CO" merge-base --is-ancestor "$F2" v3.30.2 || fail "7X5Q_F2_3302"
gitq -C "$CO" grep -q 'HostAccess.newBuilder(HostAccess.ALL)' v3.30.1 -- "$SE" || fail "7X5Q_3301_HOSTACCESS"
if gitq -C "$CO" grep -q 'option("js.load", "false")' v3.30.1 -- "$SE"; then
  fail "7X5Q_3301_HAS_JSLOAD_FALSE"
fi
gitq -C "$CO" grep -q 'option("js.load", "false")' "$F2" -- "$SE" || fail "7X5Q_F2_JSLOAD"
gitq -C "$CO" grep -q 'HostAccess.newBuilder(HostAccess.ALL)' "$F2" -- "$SE" || fail "7X5Q_F2_STILL_ALL"
fsubj=$(gitq -C "$CO" log -1 --format='%s' "$F1")
[[ $fsubj == *"Deny access to some classes"* ]] || fail "7X5Q_F1_SUBJ $fsubj"
peel=$(gitq -C "$CO" rev-parse 'v3.21.21^{commit}')
[[ $peel == b9f50bbcc6ed9b8f3f8de2aacec9974b55abcca4 ]] || fail "7X5Q_PEEL321 $peel"
peel=$(gitq -C "$CO" rev-parse 'v3.30.2^{commit}')
[[ $peel == 2bea5078f916c0d529cd0f32a55f79425b65a5b8 ]] || fail "7X5Q_PEEL302 $peel"
echo "7X5Q_OK"

# G5CG ordinal 95
MEM=01d568c9f54585d2df3002e1090067c9dd621e43
SQ=483fba41b9f9fb57964f31b90a2ddacb185d54d7
FX=a30214a624946fc5c85c9558a27c1580172374fd
SP=fe7436a1f679f4b98704fba81c5971180ae45da1
HR=src/infra/heartbeat-runner.ts
gitq -C "$OC" cat-file -t "$MEM" >/dev/null
gitq -C "$OC" cat-file -t "$SQ" >/dev/null
gitq -C "$OC" cat-file -t "$FX" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $SP" ]] || fail "G5CG_PARENTS $parents"
gitq -C "$OC" cat-file -p "$SQ" | LC_ALL=C grep -q 'Co-authored-by: Claude Opus 4.5' || fail "G5CG_SQ_MARKER"
gitq -C "$OC" cat-file -p "$MEM" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "G5CG_MEM_MARKER"
gitq -C "$OC" merge-base --is-ancestor "$MEM" "$SQ" && fail "G5CG_MEM_ANC_SQ" || true
gitq -C "$OC" merge-base --is-ancestor "$MEM" v2026.3.28 && fail "G5CG_MEM_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$MEM" v2026.3.31 && fail "G5CG_MEM_IN_FIX" || true
blob_m=$(gitq -C "$OC" rev-parse "${MEM}:$HR")
blob_s=$(gitq -C "$OC" rev-parse "${SQ}:$HR")
blob_p=$(gitq -C "$OC" rev-parse "${SP}:$HR")
blob_v=$(gitq -C "$OC" rev-parse "v2026.3.28:$HR")
blob_f=$(gitq -C "$OC" rev-parse "${FX}:$HR")
blob_t=$(gitq -C "$OC" rev-parse "v2026.3.31:$HR")
[[ $blob_m == "$blob_s" ]] || fail "G5CG_BLOB_MEM_SQ"
[[ $blob_m == 71c41394acf02333ee7eecd9d0db64c4fddab3a9 ]] || fail "G5CG_MEM_BLOB $blob_m"
[[ $blob_p == d02bcc5818506501344f5c62cc974c6e4dc3016b ]] || fail "G5CG_PARENT_BLOB $blob_p"
[[ $blob_v == b4c863b9ca46b8342079fb747ce27beb221660a0 ]] || fail "G5CG_V28_BLOB $blob_v"
[[ $blob_f == "$blob_t" ]] || fail "G5CG_FIX_NE_V31"
[[ $blob_f == 85b6b54d1128ef33487dfecbe1d0122bfcfe4509 ]] || fail "G5CG_FIX_BLOB $blob_f"
[[ $blob_s != "$blob_v" ]] || fail "G5CG_SQ_EQ_V28"
gitq -C "$OC" grep -q EXEC_EVENT_PROMPT "$SQ" -- "$HR" || fail "G5CG_SQ_PROMPT"
if gitq -C "$OC" grep -q EXEC_EVENT_PROMPT v2026.3.28 -- "$HR"; then
  fail "G5CG_V28_STILL_PROMPT"
fi
if gitq -C "$OC" grep -q EXEC_EVENT_PROMPT "$SP" -- "$HR"; then
  fail "G5CG_PARENT_PROMPT"
fi
gitq -C "$OC" grep -q 'reason: "exec-event"' "$SP" -- src/gateway/server-node-events.ts || fail "G5CG_PARENT_EXEC_EVENT"
gitq -C "$OC" grep -q 'reason: "exec-event"' "$SP" -- src/agents/bash-tools.exec.ts || fail "G5CG_PARENT_BASH_EXEC"
pk=$(gitq -C "$OC" log --first-parent -S EXEC_EVENT_PROMPT --format='%H' v2026.3.28 -- "$HR")
print -r -- "$pk" | LC_ALL=C grep -q '^483fba41b9f9fb57964f31b90a2ddacb185d54d7' || fail "G5CG_SQ_PICKAXE $pk"
print -r -- "$pk" | LC_ALL=C grep -q '^e2362d352d14617a7f725d8b2254ed5fe4c450aa' || fail "G5CG_REMOVE_PICKAXE $pk"
gitq -C "$OC" cat-file -p e2362d352d14617a7f725d8b2254ed5fe4c450aa | LC_ALL=C grep -q 'Co-Authored-By: Claude' && fail "G5CG_REMOVE_HAS_CLAUDE" || true
gitq -C "$OC" merge-base --is-ancestor "$SQ" v2026.3.28 || fail "G5CG_SQ_TAG"
gitq -C "$OC" merge-base --is-ancestor "$FX" v2026.3.28 && fail "G5CG_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$FX" v2026.3.31 || fail "G5CG_FIX_TAG"
gitq -C "$OC" grep -q 'ForceSenderIsOwnerFalse: hasExecCompletion' "$FX" -- "$HR" || fail "G5CG_FIX_FLAG"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$FX")
[[ $fsubj == *"block owner-only auth inheritance for exec events"* ]] || fail "G5CG_FIX_SUBJ $fsubj"
peel=$(gitq -C "$OC" rev-parse 'v2026.3.28^{commit}')
[[ $peel == f9b1079283a8ee25a7cee77c8f8225d5c813bc30 ]] || fail "G5CG_PEEL28 $peel"
peel=$(gitq -C "$OC" rev-parse 'v2026.3.31^{commit}')
[[ $peel == 213a704b71f4996dc82a583288ee53785215f627 ]] || fail "G5CG_PEEL31 $peel"
echo "G5CG_OK"

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
    raise SystemExit("extra %s" % sorted(extra))
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=3 PASS_proposal=0 NARROW=3 REJECT=0 UNKNOWN=0 BLOCKED=0"
