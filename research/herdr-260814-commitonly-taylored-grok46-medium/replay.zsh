#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-commitonly-taylored-grok46-medium.
# English only. No network. No clone/commit/push. Canonical88 read-only.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export LC_ALL=C

OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-commitonly-taylored-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
REPO=${REPO:-/home/hanqing/.cache/cve-analyzer/repos/tailot_taylored}
ADV=${ADV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database}
REPOADV=${REPOADV:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low/work/pages}

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
  filtered="$(grep -v -E -- '^error: unable to normalize alternate object path:|^fatal: lazy fetching disabled' "$errfile" || true)"
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
  if [[ $got != "$want" ]]; then
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
hash_check "$ADV/advisories/github-reviewed/2025/06/GHSA-8g98-m4j9-qww5/GHSA-8g98-m4j9-qww5.json" \
  f9f1f975f2d2223b8e8b98c55217a39a989ade18e61aa5625b70252c863cce79
hash_check "$ADV/advisories/github-reviewed/2025/06/GHSA-vh5j-5fhq-9xwg/GHSA-vh5j-5fhq-9xwg.json" \
  7b4729eb07a7f4aaf96697dd628f51dae1b55e9148600ae5e33d382fb02b23b6
hash_check "$REPOADV/repo/GHSA-8g98-m4j9-qww5.json" \
  397f5a234aabbc5933fdff8331160968ccda5dbf52e5179c405139a324032d6e
hash_check "$REPOADV/repo/GHSA-vh5j-5fhq-9xwg.json" \
  900b9b27da6bb1fa10d044fe128d6244a931399f4fc0698c03ba8bda00ed258d

[[ -d $REPO/.git ]] || fail "CLONE_ABSENT"
head=$(gitq -C "$REPO" rev-parse HEAD)
[[ $head == 05da9137527cb7be236bb8e63f1c3b0dffcc6b2a ]] || fail "CLONE_HEAD $head"
advhead=$(gitq -C "$ADV" rev-parse HEAD)
[[ $advhead == f2c6ab3202aeafb36fbea6e76d892532acfca1a6 ]] || fail "ADV_HEAD $advhead"

C8=c139c021f68a09d22c2af88641b61c00f67f2af4
P8=610281a664bd4e8c8d0c7052116bedaea5c8a4c6
F8=57b7634391959dbbdb39b387ac4dc68157cd58a1
CV=57b7634391959dbbdb39b387ac4dc68157cd58a1
FV=fdf67a6fba0deae30912905a79fb5a9e83751a79
H5=5e5a80b5ffd0b6fccf7bdc2d8793e8b01cb83844
D812=d6f5477f05ed015a3846ff282dd31423af730ed2

echo "== GHSA-8G98 git facts =="
parents=$(gitq -C "$REPO" rev-list --parents -n 1 "$C8")
[[ $parents == "$C8 $P8" ]] || fail "8G98_PARENTS $parents"
an=$(gitq -C "$REPO" log -1 --format='%an' "$C8")
[[ $an == 'google-labs-jules[bot]' ]] || fail "8G98_AUTHOR $an"
git_path_absent -C "$REPO" cat-file -e "${P8}:templates/backend-in-a-box/index.js" || fail "8G98_PARENT_HAS_INDEX"
gitq -C "$REPO" cat-file -e "${C8}:templates/backend-in-a-box/index.js" >/dev/null || fail "8G98_CAND_INDEX"
blobc=$(gitq -C "$REPO" rev-parse "${C8}:templates/backend-in-a-box/index.js")
[[ $blobc == 0dd0853c7f2c5b9443f9d5564d79a7b96d179bc7 ]] || fail "8G98_CAND_BLOB $blobc"
gitq -C "$REPO" grep -q 'webhookEvent = req.body' "$C8" -- templates/backend-in-a-box/index.js || fail "8G98_CAND_BODY"
if gitq -C "$REPO" grep -q verifyAndGetWebhookEvent "$C8" -- templates/backend-in-a-box/index.js; then
  fail "8G98_CAND_HAS_VERIFY"
fi
parents=$(gitq -C "$REPO" rev-list --parents -n 1 "$F8")
[[ $parents == "$F8 $C8" ]] || fail "8G98_FIX_PARENTS $parents"
fan=$(gitq -C "$REPO" log -1 --format='%an' "$F8")
[[ $fan == 'google-labs-jules[bot]' ]] || fail "8G98_FIX_AUTHOR $fan"
blobf=$(gitq -C "$REPO" rev-parse "${F8}:templates/backend-in-a-box/index.js")
[[ $blobf == 8a5317f90c56685b73d643b5757679a2c9ba177c ]] || fail "8G98_FIX_BLOB $blobf"
gitq -C "$REPO" grep -q verifyAndGetWebhookEvent "$F8" -- templates/backend-in-a-box/index.js || fail "8G98_FIX_VERIFY"
if gitq -C "$REPO" grep -q 'webhookEvent = req.body' "$F8" -- templates/backend-in-a-box/index.js; then
  fail "8G98_FIX_STILL_BODY"
fi
gitq -C "$REPO" merge-base --is-ancestor "$C8" "$F8" || fail "8G98_CAND_NOT_ANC_FIX"
gitq -C "$REPO" merge-base --is-ancestor "$F8" 8.2.4 || fail "8G98_FIX_NOT_IN_824"
empty=$(gitq -C "$REPO" tag --contains "$C8" --no-contains "$F8")
[[ -z $empty ]] || fail "8G98_VULN_TAG $empty"
echo "8G98_OK"

echo "== GHSA-VH5J git facts =="
parents=$(gitq -C "$REPO" rev-list --parents -n 1 "$CV")
[[ $parents == "$CV $C8" ]] || fail "VH5J_PARENTS $parents"
gitq -C "$REPO" grep -q token_used_at "$CV" -- templates/backend-in-a-box/index.js || fail "VH5J_CAND_TOKEN"
if gitq -C "$REPO" grep -q token_used_at "$C8" -- templates/backend-in-a-box/index.js; then
  fail "VH5J_PARENT_HAS_TOKEN"
fi
gitq -C "$REPO" grep -q 'SELECT id, patch_id, purchase_token, status, token_used_at' "$CV" -- templates/backend-in-a-box/index.js || fail "VH5J_CAND_SELECT"
if gitq -C "$REPO" grep -q 'token_used_at IS NULL' "$CV" -- templates/backend-in-a-box/index.js; then
  fail "VH5J_CAND_ALREADY_ATOMIC"
fi
parents=$(gitq -C "$REPO" rev-list --parents -n 1 "$FV")
[[ $parents == "$FV f4d210457781256860c0779cc2090f957d1ebf3d" ]] || fail "VH5J_FIX_PARENTS $parents"
van=$(gitq -C "$REPO" log -1 --format='%an' "$FV")
[[ $van == vincenzo ]] || fail "VH5J_FIX_AUTHOR $van"
blobv=$(gitq -C "$REPO" rev-parse "${FV}:templates/backend-in-a-box/index.js")
[[ $blobv == 4cc255d79c158e4f2552ac1f7efcf0742bbedd81 ]] || fail "VH5J_FIX_BLOB $blobv"
gitq -C "$REPO" grep -q 'token_used_at IS NULL' "$FV" -- templates/backend-in-a-box/index.js || fail "VH5J_FIX_ATOMIC"
if gitq -C "$REPO" grep -q 'SELECT id, token_used_at FROM purchases' "$FV" -- templates/backend-in-a-box/index.js; then
  fail "VH5J_FIX_STILL_SELECT"
fi
gitq -C "$REPO" merge-base --is-ancestor "$CV" "$FV" || fail "VH5J_CAND_NOT_ANC_FIX"
blobh=$(gitq -C "$REPO" rev-parse "${H5}:templates/backend-in-a-box/index.js")
[[ $blobh == 472511e7590c3b5c681bebf851b87ad9e16cf81b ]] || fail "VH5J_HUMAN_BLOB $blobh"
gitq -C "$REPO" grep -q 'SELECT id, token_used_at FROM purchases' "$H5" -- templates/backend-in-a-box/index.js || fail "VH5J_HUMAN_SELECT"
han=$(gitq -C "$REPO" log -1 --format='%an' "$H5")
[[ $han == vincenzo ]] || fail "VH5J_HUMAN_AUTHOR $han"
gitq -C "$REPO" merge-base --is-ancestor "$CV" "$D812" || fail "VH5J_CAND_NOT_IN_812COMMIT"
gitq -C "$REPO" merge-base --is-ancestor "$FV" "$D812" && fail "VH5J_FIX_IN_812COMMIT" || true
empty=$(gitq -C "$REPO" tag --contains "$CV" --no-contains "$FV")
[[ -z $empty ]] || fail "VH5J_VULN_TAG $empty"
echo "VH5J_OK"

echo "== conservation and gates =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
root = Path("$ROOT")
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
report = owned.joinpath("report.md").read_text()
aids = [a["case_id"] for a in ass]
cids = [c["case_id"] for c in cas]
want = ["GHSA-8G98-M4J9-QWW5", "GHSA-VH5J-5FHQ-9XWG"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
causal = need[:-2] + ("uniqueness_gate",)
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if any(a.get("shared_sha_is_not_dedupe") is not True for a in ass):
    print("SHARED_SHA_FLAG_FAIL"); sys.exit(1)
if ass[0]["hypothesized_fix"] != ass[1]["hypothesized_candidate"]:
    print("SHARED_SHA_ROLE_FAIL"); sys.exit(1)
if ass[0]["hypothesized_fix"] != "57b7634391959dbbdb39b387ac4dc68157cd58a1":
    print("SHARED_SHA_VALUE_FAIL"); sys.exit(1)
if cas[0]["minimum_fix_set"] != ["57b7634391959dbbdb39b387ac4dc68157cd58a1"]:
    print("8G98_FIXSET"); sys.exit(1)
if cas[1]["candidate_set"] != ["57b7634391959dbbdb39b387ac4dc68157cd58a1"]:
    print("VH5J_CANDSET"); sys.exit(1)
if cas[0]["mechanism_key"] == cas[1]["mechanism_key"]:
    print("MECH_COLLAPSE"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS")
n_prop = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
if n_pass != 0 or n_prop != 2 or len(cas) != 2:
    print("COUNT_FAIL", n_pass, n_prop); sys.exit(1)
if res["conservation"]["equation"] != "2=2+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["counts"]["PASS"] != 0 or res["counts"]["PASS_PROPOSAL"] != 2:
    print("RES_COUNT_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 88:
    print("CANON_FAIL"); sys.exit(1)
if res["causal_admission"] is not False or res["pass_proposals"] != want:
    print("FLAG_FAIL", res.get("pass_proposals")); sys.exit(1)
if res["counts"]["countable_pass"] != 0:
    print("COUNTABLE_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if k not in g:
            print("MISSING_GATE", rec["case_id"], k); sys.exit(1)
    for k in causal:
        if g[k] != "PASS":
            print("CAUSAL_NOT_PASS", rec["case_id"], k, g[k]); sys.exit(1)
    if g["release_gate"] != "UNKNOWN":
        print("RELEASE_NOT_UNKNOWN", rec["case_id"], g["release_gate"]); sys.exit(1)
    if rec["verdict"] != "PASS_PROPOSAL":
        print("VERDICT_FAIL", rec["case_id"]); sys.exit(1)
    if rec.get("countable") is not False or rec.get("countable_proposal") is not False:
        print("COUNTABLE_FLAG", rec["case_id"]); sys.exit(1)
    if rec.get("proposed_pass") is not True:
        print("PROPOSED_PASS_FLAG", rec["case_id"]); sys.exit(1)
    if rec.get("inherited_pass_is_not_proof") is not True:
        print("INHERIT_PROOF", rec["case_id"]); sys.exit(1)
canon = json.loads((root/"autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
if len(strict) != 88:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
hit = [i for i in want if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical88", hit); sys.exit(1)
if "PASS_PROPOSAL" not in report or "57b76343" not in report:
    print("REPORT_FAIL"); sys.exit(1)
if "Canonical88 stays 88" not in report:
    print("REPORT_CANON_FAIL"); sys.exit(1)
print("CONSERVATION_OK 2=2+0 PASS_PROPOSAL=2 countable=0")
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
    raise SystemExit("extra " + ",".join(sorted(extra)))
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=2 PASS_proposal=2 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0 countable=0"
