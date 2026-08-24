#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-b-grok46-medium.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-b-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
DT=${DT:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/dynatrace-mcp}
CH=${CH:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/claude-hud}
ADV_REV=${ADV_REV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database}
ADV_UN=${ADV_UN:-/home/hanqing/.cache/cve-analyzer/advisory-database}
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json" \
  81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl" \
  35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ADV_REV/advisories/github-reviewed/2026/04/GHSA-xmxx-7p24-h892/GHSA-xmxx-7p24-h892.json" \
  f2384546dfbc5261f2923beb20aa5357eabb5f8ae55fac9964194cc6cf00bcea
hash_check "$ADV_REV/advisories/github-reviewed/2026/07/GHSA-pqh8-p93p-2rx7/GHSA-pqh8-p93p-2rx7.json" \
  0541ead092d603ed925538f10fa1d4e38737575a925edef819deff947e5aa819
hash_check "$ADV_UN/advisories/unreviewed/2026/05/GHSA-4524-x6pc-rr9x/GHSA-4524-x6pc-rr9x.json" \
  c3618e69006d91d3648a7dd4c8de0ef5dc007a5d41719ad8ef9a4b6260e9aca2

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
    "GHSA-XMXX-7P24-H892",
    "GHSA-PQH8-P93P-2RX7",
    "GHSA-4524-X6PC-RR9X",
]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
okv = ("PASS","FAIL","UNKNOWN","NARROW","BLOCKED")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [29, 30, 74]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 2 or n_nar != 0 or n_rej != 1 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != ["GHSA-XMXX-7P24-H892", "GHSA-PQH8-P93P-2RX7"]:
    print("PASS_LIST_FAIL", res["pass_proposals"]); sys.exit(1)
if res["canonical_strict_count_untouched"] != 88 or res["counts"]["countable_pass"] != 0:
    print("FLAG_FAIL"); sys.exit(1)
need_pass = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
for rec in cas[:2]:
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
if cas[2]["verdict"] != "REJECT":
    print("4524_NOT_REJECT"); sys.exit(1)
if cas[2]["gates"]["fix_reversal_gate"] != "FAIL":
    print("4524_REVERSAL_NOT_FAIL"); sys.exit(1)
if cas[2]["gates"]["identity_gate"] != "FAIL":
    print("4524_IDENTITY_NOT_FAIL"); sys.exit(1)
if cas[2].get("realpath_only_blocks_arbitrary_absolute_reads") is not False:
    print("4524_REALPATH_FLAG"); sys.exit(1)
if cas[2].get("proposed_pass") is not False or cas[2].get("seven_gates_exact_pass") is not False:
    print("4524_PROPOSAL_DRIFT"); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=0 REJECT=1 PASS_PROPOSAL=2")
PY

echo "== uniqueness vs canonical88 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical88", hit); sys.exit(1)
if "GHSA-8RW6-P7M8-63JP" in ids:
    print("UNIQUENESS_FAIL 8RW6"); sys.exit(1)
if len(strict) != 88:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== git facts =="
[[ -d $OC && -d $DT && -d $CH ]] || fail "CLONE_ABSENT"

# XMXX ordinal 29
C=f4b03599f0fb9c2f76e8dbe5fde13948d68dbc3f
F=acd4e0a32f12e1ad85f3130f63b42443ce90f094
P=7f6e87e9180b9f236aa88b90936be8f6f7988bc2
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "XMXX_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "XMXX_MARKER"
gitq -C "$OC" grep -q 'handleOpenAiHttpRequest(req, res, { auth: resolvedAuth })' "$P" -- src/gateway/server-http.ts || fail "XMXX_PARENT_OPENAI"
if gitq -C "$OC" grep -q handleOpenResponsesHttpRequest "$P" -- src/gateway/server-http.ts; then
  fail "XMXX_PARENT_HAS_RESPONSES"
fi
git_path_absent -C "$OC" cat-file -e "${P}:src/gateway/openresponses-http.ts" || fail "XMXX_PARENT_HAS_FILE"
gitq -C "$OC" grep -q handleOpenResponsesHttpRequest "$C" -- src/gateway/server-http.ts || fail "XMXX_CAND_RESPONSES"
gitq -C "$OC" grep -q 'auth: resolvedAuth' "$C" -- src/gateway/server-http.ts || fail "XMXX_CAND_CAPTURED_AUTH"
gitq -C "$OC" grep -q authorizeGatewayConnect "$C" -- src/gateway/openresponses-http.ts || fail "XMXX_CAND_AUTHORIZE"
gitq -C "$OC" grep -q handleOpenResponsesHttpRequest v2026.4.14 -- src/gateway/server-http.ts || fail "XMXX_V14_RESPONSES"
gitq -C "$OC" grep -q 'auth: resolvedAuth' v2026.4.14 -- src/gateway/server-http.ts || fail "XMXX_V14_CAPTURED_AUTH"
gitq -C "$OC" grep -q getResolvedAuth "$F" -- src/gateway/server-http.ts || fail "XMXX_FIX_GETRESOLVED"
gitq -C "$OC" grep -q handleOpenResponsesHttpRequest "$F" -- src/gateway/server-http.ts || fail "XMXX_FIX_STILL_HAS_RESPONSES"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"re-resolve HTTP auth per-request"* ]] || fail "XMXX_FIX_SUBJ $fsubj"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.4.14 || fail "XMXX_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.14 && fail "XMXX_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.15 || fail "XMXX_FIX_TAG"
peel=$(gitq -C "$OC" rev-parse 'v2026.4.14^{commit}')
[[ $peel == 323493fa1b6adc1e10b9954a68d5eaa5a6ef1170 ]] || fail "XMXX_PEEL14 $peel"
echo "XMXX_OK"

# PQH8 ordinal 30
C=66ff2a7c8bedc23939d6d70ab4c3bdce53673843
F=15d3546c0618ffbaeaeca477337e08e92f2151bc
P=c11191125271e676109e78fef32df4a61bfa4ce6
gitq -C "$DT" cat-file -t "$C" >/dev/null
gitq -C "$DT" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$DT" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "PQH8_PARENTS $parents"
an=$(gitq -C "$DT" log -1 --format='%an' "$C")
[[ $an == "copilot-swe-agent[bot]" ]] || fail "PQH8_AUTHOR $an"
gitq -C "$DT" grep -q 'now()-${timeframe}' "$P" -- src/capabilities/list-problems.ts || fail "PQH8_PARENT_PROBLEMS"
if gitq -C "$DT" grep -q 'now()-${timeframe}' "$P" -- src/capabilities/list-vulnerabilities.ts; then
  fail "PQH8_PARENT_VULN_HAS_TF"
fi
if gitq -C "$DT" grep -q 'now()-${timeframe}' "$P" -- src/capabilities/get-events-for-cluster.ts; then
  fail "PQH8_PARENT_EVENTS_HAS_TF"
fi
gitq -C "$DT" grep -q 'now()-${timeframe}' "$C" -- src/capabilities/list-vulnerabilities.ts || fail "PQH8_CAND_VULN"
gitq -C "$DT" grep -q 'now()-${timeframe}' "$C" -- src/capabilities/get-events-for-cluster.ts || fail "PQH8_CAND_EVENTS"
gitq -C "$DT" grep -q 'now()-${timeframe}' v1.2.0 -- src/capabilities/list-vulnerabilities.ts || fail "PQH8_V12_VULN"
gitq -C "$DT" grep -q 'now()-${timeframe}' v1.2.0 -- src/capabilities/get-events-for-cluster.ts || fail "PQH8_V12_EVENTS"
blob_v=$(gitq -C "$DT" rev-parse "${C}:src/capabilities/list-vulnerabilities.ts")
blob_r=$(gitq -C "$DT" rev-parse "v1.2.0:src/capabilities/list-vulnerabilities.ts")
[[ $blob_v == "$blob_r" ]] || fail "PQH8_VULN_BLOB $blob_v $blob_r"
gitq -C "$DT" grep -q validateTimeframe "$F" -- src/capabilities/list-vulnerabilities.ts || fail "PQH8_FIX_VULN_VALIDATE"
gitq -C "$DT" grep -q validateTimeframe "$F" -- src/capabilities/get-events-for-cluster.ts || fail "PQH8_FIX_EVENTS_VALIDATE"
fsubj=$(gitq -C "$DT" log -1 --format='%s' "$F")
[[ $fsubj == *"GHSA-pqh8-p93p-2rx7"* ]] || fail "PQH8_FIX_SUBJ $fsubj"
gitq -C "$DT" merge-base --is-ancestor "$C" v1.2.0 || fail "PQH8_CAND_TAG"
gitq -C "$DT" merge-base --is-ancestor "$F" v1.2.0 && fail "PQH8_FIX_IN_VULN" || true
gitq -C "$DT" merge-base --is-ancestor "$F" v2.1.1 || fail "PQH8_FIX_TAG"
blob_f=$(gitq -C "$DT" rev-parse "${F}:src/capabilities/list-vulnerabilities.ts")
blob_t=$(gitq -C "$DT" rev-parse "v2.1.1:src/capabilities/list-vulnerabilities.ts")
[[ $blob_f == "$blob_t" ]] || fail "PQH8_FIX_BLOB $blob_f $blob_t"
echo "PQH8_OK"

# 4524 ordinal 74
C=26a3e984e442382f83297b545626f7293f4379b4
F=234d9aad919b51326a43bcf90b45ae35c23afc30
P=c94b88e9d97e5beb69690ee31bdfe9350f4fc64e
gitq -C "$CH" cat-file -t "$C" >/dev/null
gitq -C "$CH" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$CH" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "X4524_PARENTS $parents"
gitq -C "$CH" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "X4524_MARKER"
git_path_absent -C "$CH" cat-file -e "${P}:src/transcript.ts" || fail "X4524_PARENT_HAS_TRANSCRIPT"
gitq -C "$CH" cat-file -e "${C}:src/transcript.ts" >/dev/null || fail "X4524_CAND_TRANSCRIPT"
gitq -C "$CH" grep -q 'fs.createReadStream(transcriptPath)' "$C" -- src/transcript.ts || fail "X4524_CAND_READ"
gitq -C "$CH" grep -q transcript_path "$P" -- scripts/capture-event.sh || fail "X4524_PARENT_STORES_PATH"
fsubj=$(gitq -C "$CH" log -1 --format='%s' "$F")
[[ $fsubj == *"harden links and Windows version lookup"* ]] || fail "X4524_FIX_SUBJ $fsubj"
gitq -C "$CH" grep -q realpathSync "$F" -- src/transcript.ts || fail "X4524_FIX_REALPATH"
if gitq -C "$CH" grep -q startsWith v0.1.0 -- src/transcript.ts; then
  fail "X4524_V010_HAS_STARTSWITH"
fi
if gitq -C "$CH" grep -qi allowlist v0.1.0 -- src/transcript.ts; then
  fail "X4524_V010_HAS_ALLOWLIST"
fi
blob_c=$(gitq -C "$CH" rev-parse "${C}:src/transcript.ts")
blob_v=$(gitq -C "$CH" rev-parse "v0.0.12:src/transcript.ts")
[[ $blob_c == 1eb1b450d0329c4922847f3468db28fd90d4cbf1 ]] || fail "X4524_CAND_BLOB $blob_c"
[[ $blob_v == d92ddf92c2e1e33af0a4f735bb5669cc3e97782c ]] || fail "X4524_V0012_BLOB $blob_v"
[[ $blob_c != "$blob_v" ]] || fail "X4524_BLOB_EQUAL"
gitq -C "$CH" merge-base --is-ancestor "$C" v0.0.12 || fail "X4524_CAND_TAG"
gitq -C "$CH" merge-base --is-ancestor "$F" v0.0.12 && fail "X4524_FIX_IN_VULN" || true
gitq -C "$CH" merge-base --is-ancestor "$F" v0.1.0 || fail "X4524_FIX_TAG"
echo "X4524_GIT_OK"

echo "== 4524 realpath residual =="
python3 - << PY
import os, subprocess, sys
ch = "$CH"
blob = subprocess.check_output(
    ["git", "-C", ch, "show", "v0.1.0:src/transcript.ts"],
    text=True,
)
fn = blob.split("function canonicalizeTranscriptPath")[1].split("function ")[0]
if "realpathSync" not in fn:
    print("NO_REALPATH"); sys.exit(1)
if "startsWith" in fn or "allowlist" in fn.lower():
    print("UNEXPECTED_ROOT_CHECK"); sys.exit(1)
resolved = os.path.realpath("/etc/passwd")
if not os.path.isabs(resolved):
    print("NOT_ABS", resolved); sys.exit(1)
if "etc/passwd" not in resolved.replace("\\\\", "/"):
    print("ABS_READ_NOT_PRESERVED", resolved); sys.exit(1)
print("REALPATH_ONLY_INCOMPLETE closer does not block arbitrary absolute-file reads")
PY

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

echo "REPLAY_OK reviewed=3 PASS_proposal=2 NARROW=0 REJECT=1 UNKNOWN=0 BLOCKED=0"
