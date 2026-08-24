#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf3-butfor5-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
DT=${DT:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/dynatrace-mcp}
FS=${FS:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/fission}
OC=${OC:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/openclaw}
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
  echo "HASH_OK $(basename "$f")"
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl" \
  0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687
hash_check "$ROOT/autoresearch/herdr-260814-cf3-nextqueue-grok46-medium/assignment.jsonl" \
  c358ad2bb4384080f0f051e377a09f15ac3ce47249dfe697b54159c295b601cf
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json" \
  8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9

echo "== conservation 5=5+0 =="
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
    "GHSA-PQH8-P93P-2RX7",
    "GHSA-R5JH-Q2MW-GCX4",
    "GHSA-W85G-3H6X-4XH2",
    "GHSA-XMXX-7P24-H892",
    "GHSA-XQ94-R468-QWGJ",
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
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
if n_pass != 0 or n_nar != 5 or len(cas) != 5:
    print("COUNT_FAIL", n_pass, n_nar); sys.exit(1)
if res["conservation"]["equation"] != "5=5+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != [] or res["canonical_strict_count_untouched"] != 88:
    print("FLAG_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if g[k] not in okv:
            print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
    if rec["verdict"] == "PASS_PROPOSAL":
        print("PROMOTED_PASS", rec["case_id"]); sys.exit(1)
    if rec["verdict"] != "NARROW" or g["but_for_gate"] != "NARROW":
        print("BUTFOR_NOT_NARROW", rec["case_id"]); sys.exit(1)
    if rec.get("proposed_pass") is not False:
        print("PROPOSED_PASS_FLAG", rec["case_id"]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec["case_id"] == "GHSA-R5JH-Q2MW-GCX4" and rec.get("authorship_transfer") is not False:
        print("R5JH_TRANSFER"); sys.exit(1)
print("CONSERVATION_OK 5=5+0 NARROW=5 PASS_PROPOSAL=0")
PY

echo "== uniqueness vs canonical88 + current cf3 =="
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
cf3 = {
    "GHSA-2Q7J-2VHX-56G8","GHSA-2QRV-RC5X-2G2H","GHSA-2X93-H3HG-2XFP","GHSA-37MF-VQ43-5QP9",
    "GHSA-3FP5-V549-9V66","GHSA-3J8Q-FWPJ-F8J5","GHSA-42M6-XH7C-6XM4","GHSA-4524-X6PC-RR9X",
    "GHSA-5GVR-V6QV-H5MM","GHSA-5WP8-Q9MX-8JX8","GHSA-6C8G-7P36-R338","GHSA-7C3W-FXGH-FRC7",
    "GHSA-7JX6-764P-FGG9","GHSA-7X5Q-8F6H-RJRC","GHSA-92VG-F4FQ-FXM9","GHSA-9C3V-684M-579C",
    "GHSA-C4M7-2GWP-VW76","GHSA-CW23-QWR7-C655","GHSA-F2FQ-4RMP-9X8C","GHSA-F38V-77QJ-H4JQ",
    "GHSA-F7FH-QG34-X2XH","GHSA-G353-MGV3-8PCJ","GHSA-G5CG-8X5W-7JPM","GHSA-G8MR-85JM-7XHM",
    "GHSA-H2VW-PH2C-JVWF","GHSA-HFF7-CCV5-52F8","GHSA-HHFF-FJ5F-QG48","GHSA-J4CX-JVQ7-79VM",
    "GHSA-JX5R-P82P-2P8M","GHSA-M63V-2G9W-2W6V","GHSA-MGXW-V6RH-WCV6","GHSA-P5RM-JG5C-8C77",
    "GHSA-PQGX-6WG3-GMVR","GHSA-Q6QF-4P5J-R25G","GHSA-QJPC-QF9M-XWMR","GHSA-RQPP-RJJ8-7WV8",
    "GHSA-V396-V7Q4-X2QJ","GHSA-W4H3-GPV2-82QC","GHSA-WP73-F3GG-W4VR","GHSA-X2W7-XR2G-QHJR",
    "GHSA-X34R-63HX-W57F","GHSA-X8QQ-M4QC-RPJ5",
}
hit2 = [i for i in ids if i in cf3]
if hit2:
    print("UNIQUENESS_FAIL in_cf3", hit2); sys.exit(1)
if len(strict) != 88:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== git facts =="
[[ -d $DT && -d $FS && -d $OC ]] || fail "CLONE_ABSENT"

# PQH8
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
fsubj=$(gitq -C "$DT" log -1 --format='%s' "$F")
[[ $fsubj == *"GHSA-pqh8-p93p-2rx7"* ]] || fail "PQH8_FIX_SUBJ $fsubj"
gitq -C "$DT" merge-base --is-ancestor "$C" v1.2.0 || fail "PQH8_CAND_TAG"
gitq -C "$DT" merge-base --is-ancestor "$F" v1.2.0 && fail "PQH8_FIX_IN_VULN" || true
gitq -C "$DT" merge-base --is-ancestor "$F" v2.1.1 || fail "PQH8_FIX_TAG"
echo "PQH8_OK"

# R5JH
S=5a3d68a349b001302b1acb6e838f05283160548d
M=0d851525a35ba517dda7fe892333df5d0919dffc
F=8298e33ea7457702f893eae11077987cf905edb4
P=c4125e170a222a4bf1539a5c4167533e35612588
gitq -C "$FS" cat-file -t "$S" >/dev/null
gitq -C "$FS" cat-file -t "$M" >/dev/null
gitq -C "$FS" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$FS" rev-list --parents -n 1 "$S")
[[ $parents == "$S $P" ]] || fail "R5JH_PARENTS $parents"
gitq -C "$FS" cat-file -p "$S" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.7' || fail "R5JH_MARKER"
gitq -C "$FS" grep -q 'strings.HasPrefix(normalizedPath, safedir)' "$P" -- pkg/utils/utils.go || fail "R5JH_PARENT_HASPREFIX"
gitq -C "$FS" grep -q SanitizeFilePath "$P" -- pkg/fetcher/fetcher.go || fail "R5JH_PARENT_FETCHER"
gitq -C "$FS" show "${P}:pkg/builder/builder.go" | LC_ALL=C grep -A25 'func (builder \*Builder) Clean' | LC_ALL=C grep -q SanitizeFilePath && fail "R5JH_PARENT_CLEAN_HAS_SANITIZE" || true
gitq -C "$FS" show "${S}:pkg/builder/builder.go" | LC_ALL=C grep -A25 'func (builder \*Builder) Clean' | LC_ALL=C grep -q SanitizeFilePath || fail "R5JH_SQUASH_CLEAN_MISSING"
gitq -C "$FS" merge-base --is-ancestor "$M" "$S" && fail "R5JH_MEMBER_ANC_SQUASH" || true
gitq -C "$FS" merge-base --is-ancestor "$M" v1.24.0 && fail "R5JH_MEMBER_IN_VULN" || true
gitq -C "$FS" merge-base --is-ancestor "$S" v1.24.0 || fail "R5JH_SQUASH_TAG"
gitq -C "$FS" merge-base --is-ancestor "$F" v1.24.0 && fail "R5JH_FIX_IN_VULN" || true
gitq -C "$FS" merge-base --is-ancestor "$F" v1.25.0 || fail "R5JH_FIX_TAG"
fsubj=$(gitq -C "$FS" log -1 --format='%s' "$F")
[[ $fsubj == *"os.Root"* ]] || fail "R5JH_FIX_SUBJ $fsubj"
echo "R5JH_OK"

# W85G
C=8d74578ceb0c3b913555dff6265821eb0fc09749
F=0ed4f8a72bb140045962e97ab01c94c076b758a4
P=f7123ec30af8c96bb2cb4da198e19bc03312ba16
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "W85G_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "W85G_MARKER"
gitq -C "$OC" grep -q sipsMetadataFromBuffer "$P" -- src/media/image-ops.ts || fail "W85G_PARENT_SIPS"
git_path_absent -C "$OC" cat-file -e "${P}:src/agents/pi-embedded-runner/run/images.ts" || fail "W85G_PARENT_HAS_IMAGES"
gitq -C "$OC" cat-file -e "${C}:src/agents/pi-embedded-runner/run/images.ts" >/dev/null || fail "W85G_CAND_IMAGES"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"oversized image inputs"* ]] || fail "W85G_FIX_SUBJ $fsubj"
names=$(gitq -C "$OC" diff-tree --no-commit-id --name-only -r "$F")
print -r -- "$names" | LC_ALL=C grep -qx 'src/media/image-ops.ts' || fail "W85G_FIX_IMAGE_OPS"
print -r -- "$names" | LC_ALL=C grep -q 'images.ts' && fail "W85G_FIX_TOUCHES_IMAGES" || true
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.3.28 || fail "W85G_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.3.28 && fail "W85G_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.3.31 || fail "W85G_FIX_TAG"
echo "W85G_OK"

# XMXX
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
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"re-resolve HTTP auth per-request"* ]] || fail "XMXX_FIX_SUBJ $fsubj"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.4.14 || fail "XMXX_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.14 && fail "XMXX_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.15 || fail "XMXX_FIX_TAG"
echo "XMXX_OK"

# XQ94
C=75602014dbc5088b80e9b236146dfe5fdcc59e20
F=121c452d666d4749744dc2089287d0227aae2ed3
P=3cf75f760c0f89adbad9415b3d5fdb5b83f2dd82
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "XQ94_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "XQ94_MARKER"
gitq -C "$OC" grep -q '/json/version' "$P" -- src/browser/cdp.ts || fail "XQ94_PARENT_JSON"
if gitq -C "$OC" grep -q isWebSocketUrl "$P" -- src/browser/cdp.ts; then
  fail "XQ94_PARENT_HAS_WS"
fi
gitq -C "$OC" grep -q isWebSocketUrl "$C" -- src/browser/cdp.ts || fail "XQ94_CAND_WS"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"hostname navigation"* ]] || fail "XQ94_FIX_SUBJ $fsubj"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.4.5 || fail "XQ94_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.5 && fail "XQ94_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.14 || fail "XQ94_FIX_TAG"
echo "XQ94_OK"

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

echo "REPLAY_OK reviewed=5 PASS_proposal=0 NARROW=5 REJECT=0 UNKNOWN=0 BLOCKED=0"
