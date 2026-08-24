#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-8jqh-release-hostile-grok46-medium.
# English only. Anonymous public access only. No credentials. No GitHub API.
# Never print environment variable names or values. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-8jqh-release-hostile-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}

# Unset credential-bearing variables before any network command. Do not print.
typeset -a _strip_names
_strip_names=()
for _n in ${(k)parameters}; do
  if [[ $_n == *TOKEN* || $_n == *KEY* || $_n == *SECRET* || $_n == *PASSWORD* || $_n == *AUTH* ]]; then
    _strip_names+=("$_n")
  fi
done
for _n in "${_strip_names[@]}"; do
  unset "$_n"
done
unset _n _strip_names

export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d /tmp/8jqh-hostile.XXXXXX)"

GITQ_N=0
gitq() {
  GITQ_N=$((GITQ_N + 1))
  local outfile errfile rc filtered
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git -c credential.helper= "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  filtered="$(grep -v -E -- '^error: unable to normalize alternate object path:|^warning: |^Cloning into' "$errfile" || true)"
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
if b.endswith(b" ") or b" \n" in b:
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json" \
  c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl" \
  7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096

echo "== conservation 1=1+0 =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
aids = [a["case_id"] for a in ass]
cids = [c["case_id"] for c in cas]
want = ["GHSA-8JQH-598V-RFXC"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [53]:
    print("ORDINAL_FAIL"); sys.exit(1)
if len(cas) != 1 or cas[0]["verdict"] != "NARROW":
    print("COUNT_FAIL", cas[0]["verdict"] if cas else None); sys.exit(1)
if res["conservation"]["equation"] != "1=1+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res.get("pass_proposal_ids"):
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 94:
    print("FLAG_FAIL"); sys.exit(1)
rec = cas[0]
g = rec["gates"]
for k in need:
    if k not in g:
        print("MISSING_GATE", k); sys.exit(1)
if g["identity_gate"] != "PASS" or g["ai_hunk_gate"] != "PASS" or g["topology_gate"] != "PASS":
    print("EXPECTED_PASS_GATES", g); sys.exit(1)
if g["but_for_gate"] != "PASS" or g["fix_reversal_gate"] != "PASS" or g["uniqueness_gate"] != "PASS":
    print("EXPECTED_PASS_GATES2", g); sys.exit(1)
if g["release_gate"] != "NARROW":
    print("EXPECTED_RELEASE_NARROW", g); sys.exit(1)
if rec.get("osv_introduced_used_as_causal_proof") is not False:
    print("OSV_USED_AS_PROOF"); sys.exit(1)
if rec.get("authorship_transfer") is not False:
    print("TRANSFER"); sys.exit(1)
if rec["seven_gates_exact_pass"] is not False:
    print("SEVEN_SHOULD_NOT_PASS"); sys.exit(1)
if rec["contribution_class"] != "AI_DIRECT_ROOT":
    print("CLASS"); sys.exit(1)
if rec["candidate_set"] != ["b7b362ae427ccf4b33b8e8cd147f16410f3ce800"]:
    print("CAND"); sys.exit(1)
if rec["carrier_set"] != []:
    print("CARRIER"); sys.exit(1)
if rec["minimum_fix_set"] != ["7d1ddbfdb8296058ab787f7c57b8943c0214d14d"]:
    print("FIXSET"); sys.exit(1)
if rec.get("aliases") != ["CVE-2026-67530"]:
    print("ALIASES"); sys.exit(1)
if rec.get("normalized_advisory_sha256") != "3022771b5afe158962eeaffc23a7bc9526692c50c15cc336fbcd22a0ff1920f1":
    print("ADV_HASH"); sys.exit(1)
print("CONSERVATION_OK 1=1+0 NARROW=1")
PY

echo "== uniqueness vs pinned canonical94 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical94", hit); sys.exit(1)
if "GHSA-8JQH-598V-RFXC" in strict:
    print("UNIQUENESS_FAIL 8JQH_COUNTED"); sys.exit(1)
if len(strict) != 94:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "8JQH_ABSENT_CANONICAL94")
PY

echo "== git clone and facts =="
Z="$REPLAY_TMP/wacrm"
if ! gitq clone --quiet --no-checkout https://github.com/ArnasDon/wacrm.git "$Z"; then
  fail "ANON_NETWORK_BLOCKED clone"
fi
CAND=b7b362ae427ccf4b33b8e8cd147f16410f3ce800
PARENT=66dd4ef97edfc734c423a4252bd4ebd19e1cff80
FIX=7d1ddbfdb8296058ab787f7c57b8943c0214d14d
FIXP=1d7829e68aed5e5530895370a0fcae5652337d9f
MERGE=23838a9959550e975d732ae08a44a3a2f0cc084b
NAMED=274db1c7ce42540f989ab3f3f069d1ce7166855a
M31=e8c952b129511f4a1486f5ac27a821e0fa827a38
MAIN=6ed9191189e71d2e69d9380422f9415ecc589266
parents=$(gitq -C "$Z" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PARENT" ]] || fail "PARENTS $parents"
gitq -C "$Z" cat-file -p "$CAND" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.7 (1M context)' || fail "CAND_MARKER"
gitq -C "$Z" cat-file -p "$FIX" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.8' || fail "FIX_MARKER"
blob_c=$(gitq -C "$Z" rev-parse "${CAND}:src/lib/automations/engine.ts")
[[ $blob_c == af7673d0e4e2c867e444487d85a984de621d65d0 ]] || fail "BLOB_C $blob_c"
parent_engine=$(gitq -C "$Z" ls-tree --name-only "$PARENT" -- src/lib/automations/engine.ts)
[[ -z "$parent_engine" ]] || fail "PARENT_HAS_ENGINE"
gitq -C "$Z" grep -q "case 'send_webhook'" "$CAND" -- src/lib/automations/engine.ts || fail "CAND_CASE"
gitq -C "$Z" grep -q 'fetch(cfg.url' "$CAND" -- src/lib/automations/engine.ts || fail "CAND_FETCH"
if gitq -C "$Z" grep -q 'isDeliverableUrl' "$CAND" -- src/lib/automations/engine.ts; then
  fail "CAND_HAS_GUARD"
fi
blob_n=$(gitq -C "$Z" rev-parse "${NAMED}:src/lib/automations/engine.ts")
blob_p=$(gitq -C "$Z" rev-parse "${FIXP}:src/lib/automations/engine.ts")
blob_f=$(gitq -C "$Z" rev-parse "${FIX}:src/lib/automations/engine.ts")
[[ $blob_n == c21a25cd5b4ecd541c5ff038317ec46bdf45ee93 ]] || fail "BLOB_N $blob_n"
[[ $blob_p == "$blob_n" ]] || fail "FIXP_NE_NAMED"
[[ $blob_f == 535b1f64e5b2a2bcf3726e40973a6cb952f5f9d5 ]] || fail "BLOB_F $blob_f"
gitq -C "$Z" grep -q 'isDeliverableUrl' "$FIX" -- src/lib/automations/engine.ts || fail "FIX_GUARD"
gitq -C "$Z" grep -q 'destination not allowed' "$FIX" -- src/lib/automations/engine.ts || fail "FIX_THROW"
if gitq -C "$Z" grep -q 'isDeliverableUrl' "$NAMED" -- src/lib/automations/engine.ts; then
  fail "NAMED_HAS_ENGINE_GUARD"
fi
mparents=$(gitq -C "$Z" rev-list --parents -n 1 "$MERGE")
[[ $mparents == "$MERGE 03e851bea56dcf6bb21ff1b80ba531372bf3269f $FIX" ]] || fail "MERGE_PARENTS $mparents"
m31=$(gitq -C "$Z" rev-list --parents -n 1 "$M31")
[[ $m31 == "$M31 8e61aa5302c3740880ccb6da757a1c877a075af5 $CAND" ]] || fail "M31 $m31"
gitq -C "$Z" merge-base --is-ancestor "$CAND" "$NAMED" || fail "CAND_NAMED"
gitq -C "$Z" merge-base --is-ancestor "$FIX" "$NAMED" && fail "FIX_IN_NAMED" || true
gitq -C "$Z" merge-base --is-ancestor "$FIX" "$MERGE" || fail "FIX_MERGE"
gitq -C "$Z" merge-base --is-ancestor "$CAND" "$MAIN" || fail "CAND_MAIN"
gitq -C "$Z" merge-base --is-ancestor "$FIX" "$MAIN" || fail "FIX_MAIN"
echo "GIT_OK"

echo "== tags and npm =="
if ! tags=$(gitq ls-remote --tags https://github.com/ArnasDon/wacrm.git); then
  fail "ANON_NETWORK_BLOCKED ls-remote"
fi
[[ -z "$tags" ]] || fail "TAGS_NONEMPTY"
python3 - <<'PY' || fail "ANON_NETWORK_BLOCKED npm"
import os, sys, urllib.error, urllib.request
for k in list(os.environ):
    u = k.upper()
    if any(s in u for s in ("TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH")):
        os.environ.pop(k, None)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for url in ("https://registry.npmjs.org/wacrm", "https://registry.npmjs.org/@arnasdon/wacrm"):
    req = urllib.request.Request(url, method="GET")
    try:
        opener.open(req, timeout=60)
        print("NPM_NOT_404", url)
        sys.exit(1)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print("NPM_ANON_FAIL", e.code)
            sys.exit(1)
    except Exception:
        print("NPM_ANON_FAIL")
        sys.exit(1)
print("NPM_404_OK")
PY
echo "RELEASE_CHANNELS_OK"

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

echo "REPLAY_OK reviewed=1 PASS_proposal=0 REJECT=0 NARROW=1 UNKNOWN=0 BLOCKED=0"
