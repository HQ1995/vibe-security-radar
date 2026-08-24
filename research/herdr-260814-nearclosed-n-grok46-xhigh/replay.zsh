#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-n-grok46-xhigh.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-n-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
HE=${HE:-/home/hanqing/.cache/cve-analyzer/repos/github.com_nesquena_hermes-webui}
TI=${TI:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/titra}
GP=${GP:-/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-odd/clones/GitPython}
ADV=${ADV:-/home/hanqing/.cache/cve-analyzer/advisory-database}
PQGX_ADV=${PQGX_ADV:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/pages/repo/kromitgmbh__titra__GHSA-pqgx-6wg3-gmvr.json}
P538_ADV=${P538_ADV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database/advisories/github-reviewed/2026/08/GHSA-p538-c434-8v24/GHSA-p538-c434-8v24.json}
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
  filtered="$(grep -v -E -- '^warning: lazy fetching disabled; some objects may not be available$|^error: unable to normalize alternate object path:' "$errfile" || true)"
  if [[ -n "$filtered" ]]; then
    rm -f "$outfile" "$errfile"
    fail "git stderr: $filtered"
  fi
  cat "$outfile"
  rm -f "$outfile" "$errfile"
  return $rc
}

git_expect_fail() {
  local outfile errfile rc
  GITQ_N=$((GITQ_N + 1))
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  rm -f "$outfile" "$errfile"
  if [[ $rc -eq 0 ]]; then
    return 1
  fi
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
  print -r -- "HASH_OK $(basename "$f")"
}

echo "== input hashes =="
hash_check "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" \
  cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
hash_check "$ROOT/docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md" \
  70410ba05b9c8280e2102f01e8b9c45bb7b6dd517d92203b826d09833f98cf6f
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json" \
  ab47f927a20f374a9b0e3253a1a5a0778e355dda9414189927022325d81ad86f
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/ledger.jsonl" \
  70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ADV/advisories/unreviewed/2026/06/GHSA-5wqv-fhmr-pjgh/GHSA-5wqv-fhmr-pjgh.json" \
  cb0b77e829ea7053fe87ea9896a55af6b39bc14b7a0df75c72e30de10b466247
hash_check "$PQGX_ADV" \
  14e43955de48d1f3730c5cd9658a3975e0e3508912dd2b5509588f2bb5aa5143
hash_check "$P538_ADV" \
  36966e718fea2e749abc60a87c91b69808e24b230840b24717b5164ec97053d9

echo "== first-party advisory identities =="
python3 - << PY
import json, sys
from pathlib import Path
g5 = json.loads(Path("$ADV/advisories/unreviewed/2026/06/GHSA-5wqv-fhmr-pjgh/GHSA-5wqv-fhmr-pjgh.json").read_text())
pq = json.loads(Path("$PQGX_ADV").read_text())
p5 = json.loads(Path("$P538_ADV").read_text())
if g5.get("id") != "GHSA-5wqv-fhmr-pjgh":
    print("G5_ID"); sys.exit(1)
if g5.get("database_specific", {}).get("github_reviewed") is not False:
    print("G5_REVIEWED"); sys.exit(1)
if g5.get("affected") != []:
    print("G5_AFFECTED"); sys.exit(1)
if "/api/session" not in g5.get("details", ""):
    print("G5_NO_ENDPOINT"); sys.exit(1)
if g5.get("aliases") != ["CVE-2026-55197"]:
    print("G5_ALIAS"); sys.exit(1)
rev = Path("$ADV/advisories/github-reviewed/2026/06/GHSA-5wqv-fhmr-pjgh/GHSA-5wqv-fhmr-pjgh.json")
if rev.exists():
    print("G5_REVIEWED_FILE"); sys.exit(1)
if pq.get("ghsa_id") != "GHSA-pqgx-6wg3-gmvr":
    print("PQ_ID"); sys.exit(1)
if pq.get("cve_id") != "CVE-2025-69288":
    print("PQ_CVE"); sys.exit(1)
if pq.get("state") != "published":
    print("PQ_STATE"); sys.exit(1)
det = pq.get("description", "")
if "timeEntryRule" not in det or "NodeVM" not in det:
    print("PQ_NO_MECH"); sys.exit(1)
if "titraio/titra/security/advisories/GHSA-pqgx-6wg3-gmvr" not in (pq.get("html_url") or ""):
    print("PQ_NO_REPO_ADV"); sys.exit(1)
if p5.get("id") != "GHSA-p538-c434-8v24":
    print("P5_ID"); sys.exit(1)
if p5.get("database_specific", {}).get("github_reviewed") is not True:
    print("P5_REVIEWED"); sys.exit(1)
if "Commit.count" not in p5.get("details", "") or "--output" not in p5.get("details", ""):
    print("P5_NO_MECH"); sys.exit(1)
if p5.get("aliases") != []:
    print("P5_ALIAS"); sys.exit(1)
aff = p5.get("affected") or []
if not aff or aff[0].get("package", {}).get("name") != "GitPython":
    print("P5_PKG"); sys.exit(1)
print("ADVISORY_OK")
PY

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
    "GHSA-5WQV-FHMR-PJGH",
    "GHSA-PQGX-6WG3-GMVR",
    "GHSA-P538-C434-8V24",
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
if [a["fp211_ordinal"] for a in ass] != [10, 25, 143]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
if n_pass != 0 or n_nar != 3 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != [] or res["canonical_strict_count_untouched"] != 91:
    print("FLAG_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if g[k] not in okv:
            print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
        if rec["verdict"] == "PASS_PROPOSAL" and g[k] != "PASS":
            print("PROMOTED_NONPASS", rec["case_id"], k, g[k]); sys.exit(1)
    if rec["verdict"] == "PASS_PROPOSAL":
        print("PROMOTED_PASS", rec["case_id"]); sys.exit(1)
    if rec["verdict"] != "NARROW":
        print("NOT_NARROW", rec["case_id"]); sys.exit(1)
    if rec.get("proposed_pass") is not False:
        print("PROPOSED_PASS_FLAG", rec["case_id"]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("seven_gates_exact_pass") is not False:
        print("SEVEN_PASS_FLAG", rec["case_id"]); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER", rec["case_id"]); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=3 PASS_PROPOSAL=0")
PY

echo "== uniqueness vs canonical91 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical91", hit); sys.exit(1)
if "GHSA-5WP8-Q9MX-8JX8" not in strict:
    print("COUNTED_5WP8_MISSING"); sys.exit(1)
if "GHSA-VVFR-G83F-8QCV" not in strict:
    print("COUNTED_VVFR_MISSING"); sys.exit(1)
if "GHSA-R9MR-M37C-5FR3" not in strict or "GHSA-539M-9XH6-Q6RR" not in strict:
    print("COUNTED_GITPYTHON_MISSING"); sys.exit(1)
if "GHSA-VVFR-G83F-8QCV" in ids or "GHSA-R9MR-M37C-5FR3" in ids or "GHSA-539M-9XH6-Q6RR" in ids:
    print("MERGED_COUNTED"); sys.exit(1)
if len(strict) != 91:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "canonical91", len(strict))
PY

echo "== git facts =="
[[ -d $HE ]] || fail "HE_CLONE_ABSENT"
[[ -d $TI ]] || fail "TI_CLONE_ABSENT"
[[ -d $GP ]] || fail "GP_CLONE_ABSENT"

# 5WQV ordinal 10
CAND=ee672df463e285791e4466e6132297e5feb4a1df
PAR=465b97a9f5e5b7bd733eaab6fe251d73e815df6e
FIX=2a3baa71b81ca92da8ece8616a09f15894beec71
ROUT=api/routes.py
MODL=api/models.py
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" cat-file -t "$CAND" >/dev/null
parents=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PAR" ]] || fail "G5_PARENTS $parents"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" cat-file -p "$CAND" | LC_ALL=C grep -q 'Co-Authored-By: Claude Sonnet 4.6' || fail "G5_MARKER"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q 'get_state_db_session_messages(sid)' "$PAR" -- "$ROUT" || fail "G5_PAR_NO_SID"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q 'get_state_db_session_messages(sid, profile=_session_profile)' "$CAND" -- "$ROUT" || fail "G5_CAND_NO_PROFILE"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q _session_visible_to_active_profile v0.51.442 -- "$ROUT" || fail "G5_V442_HAS_VISIBLE"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q _session_visible_to_active_profile "$FIX" -- "$ROUT" || fail "G5_FIX_NO_VISIBLE"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q 'profile=None' "$CAND" -- "$MODL" || fail "G5_CAND_NO_KWARG"
blobc=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "${CAND}:${ROUT}")
blobv=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "v0.51.442:${ROUT}")
blobf=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "${FIX}:${ROUT}")
blobm=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "${CAND}:${MODL}")
blobmv=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "v0.51.442:${MODL}")
blobmf=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "${FIX}:${MODL}")
[[ $blobc == e6d0ffda61279e61ee51da554115998278416067 ]] || fail "G5_BLOB_CAND_ROUT $blobc"
[[ $blobv == dd07d9b5b9a54ce432508e109e1193db504e4a2a ]] || fail "G5_BLOB_V442_ROUT $blobv"
[[ $blobf == de239d5a9f371b7cb5ed1b7ee81e90fa69aa66fe ]] || fail "G5_BLOB_FIX_ROUT $blobf"
[[ $blobm == 1fde1b510bcb0476249717c87f40d9e9bb793519 ]] || fail "G5_BLOB_CAND_MOD $blobm"
[[ $blobmv == 439a07ab1b604c2b8cdc4f07435d585c80bfda1f ]] || fail "G5_BLOB_V442_MOD $blobmv"
[[ $blobmf == "$blobmv" ]] || fail "G5_MODELS_REVERSED"
[[ $blobc != "$blobv" && $blobm != "$blobmv" ]] || fail "G5_BLOB_COLLAPSE"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" merge-base --is-ancestor "$CAND" v0.51.442 || fail "G5_CAND_NOT_VULN"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" merge-base --is-ancestor "$FIX" v0.51.442 && fail "G5_FIX_IN_VULN" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" merge-base --is-ancestor "$FIX" v0.51.443 || fail "G5_FIX_NOT_FIXED"
fpwalk=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" log --first-parent -n 8000 --format=%H v0.51.442)
[[ $'\n'"$fpwalk"$'\n' == *$'\n'"$CAND"$'\n'* ]] && fail "G5_CAND_IS_FP" || true
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse 'v0.51.442^{commit}')
[[ $peel == 4d90577e25d5537cb07290eca3fb8abff3bab316 ]] || fail "G5_PEEL442 $peel"
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse 'v0.51.443^{commit}')
[[ $peel == 2a3baa71b81ca92da8ece8616a09f15894beec71 ]] || fail "G5_PEEL443 $peel"
[[ $peel == "$FIX" ]] || fail "G5_TAG_NOT_FIX"
echo "G5WQV_OK"

# PQGX ordinal 25
MEM=40331e610075e7c9a076873cc5b3655362d136db
CAR=67c7b7663219c9e28fce487b1803706b333c2a4f
FIX=2e2ac5cbeed47a76720b21c7fde0214a242e065e
CPAR=62fe0533d792ca72794af098cd6b1d3301514ff7
METH=imports/api/timecards/server/methods.js
SANDB=imports/utils/vm_sandbox.js
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" cat-file -t "$CAR" >/dev/null
parents=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" rev-list --parents -n 1 "$CAR")
[[ $parents == "$CAR $CPAR" ]] || fail "PQ_CAR_PARENTS $parents"
an=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" log -1 --format='%an' "$CAR")
[[ $an == "Copilot" ]] || fail "PQ_AUTHOR $an"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" grep -F -q "from 'vm2'" "$CPAR" -- "$METH" || fail "PQ_PARENT_VM2"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" grep -F -q timeEntryRule "$CPAR" -- "$METH" || fail "PQ_PARENT_RULE"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" grep -F -q vm_sandbox.js "$CAR" -- "$METH" || fail "PQ_SQUASH_SANDBOX"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" grep -F -q validateSandboxCode "$CAR" -- "$SANDB" || fail "PQ_SQUASH_HAS_VALIDATE"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" grep -F -q validateSandboxCode "$FIX" -- "$SANDB" || fail "PQ_FIX_VALIDATE"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" merge-base --is-ancestor "$MEM" "$CAR" && fail "PQ_MEMBER_ANC_SQUASH" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" merge-base --is-ancestor "$MEM" 0.99.48 && fail "PQ_MEMBER_IN_VULN" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" merge-base --is-ancestor "$CAR" 0.99.48 || fail "PQ_SQUASH_TAG"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" merge-base --is-ancestor "$FIX" 0.99.48 && fail "PQ_FIX_IN_VULN" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" merge-base --is-ancestor "$FIX" 0.99.49 || fail "PQ_FIX_TAG"
blobm=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" rev-parse "${MEM}:${SANDB}")
blobc=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" rev-parse "${CAR}:${SANDB}")
blobv=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" rev-parse "0.99.48:${SANDB}")
blobf=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" rev-parse "${FIX}:${SANDB}")
[[ $blobm == 0c9ccb7cd6b0071944110bb276183f49f3fc8168 ]] || fail "PQ_BLOB_MEM $blobm"
[[ $blobc == a8cef4021e5cec591e3d843477e4b4544b44ee5f ]] || fail "PQ_BLOB_CAR $blobc"
[[ $blobv == "$blobc" ]] || fail "PQ_BLOB_V48"
[[ $blobf == 0d5acbdd4c4d6e1b7414ac038dd689623b4c8ad8 ]] || fail "PQ_BLOB_FIX $blobf"
[[ $blobm != "$blobc" ]] || fail "PQ_MEMBER_BLOB_EQ"
fpwalk=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" log --first-parent -n 4000 --format=%H 0.99.48)
[[ $'\n'"$fpwalk"$'\n' == *$'\n'"$CAR"$'\n'* ]] || fail "PQ_CAR_NOT_FP"
[[ $'\n'"$fpwalk"$'\n' == *$'\n'"$MEM"$'\n'* ]] && fail "PQ_MEM_IS_FP" || true
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" rev-parse '0.99.48^{commit}')
[[ $peel == 433d1092e6e0a584a617cae61f45a88a1eed3e0d ]] || fail "PQ_PEEL48 $peel"
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$TI" rev-parse '0.99.49^{commit}')
[[ $peel == 2e2ac5cbeed47a76720b21c7fde0214a242e065e ]] || fail "PQ_PEEL49 $peel"
[[ $peel == "$FIX" ]] || fail "PQ_TAG_NOT_FIX"
echo "PQGX_OK"

# P538 ordinal 143
CAND=701ce32fe5ba8cb622c0e0342a376a6beb47d738
PAR=65a72839c92768754bd51a37381235842a5ae0d8
FIX=38553b6fddc7f6a667cdb45a6762343a08fc72b2
COM=git/objects/commit.py
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" cat-file -t "$CAND" >/dev/null
parents=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PAR" ]] || fail "P5_PARENTS $parents"
an=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" log -1 --format='%an' "$CAND")
[[ $an == "GPT 5.6" ]] || fail "P5_AUTHOR $an"
an=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" log -1 --format='%an' "$FIX")
[[ $an == "Sebastian Thiel" ]] || fail "P5_FIX_AUTHOR $an"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" cat-file -p "$CAND" | LC_ALL=C grep -q 'GHSA-956x-8gvw-wg5v' || fail "P5_CAND_NOT_956X"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" cat-file -p "$FIX" | LC_ALL=C grep -q 'Co-authored-by: GPT 5.6' || fail "P5_FIX_HAS_GPT"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" grep -F -q check_unsafe_options "$PAR" -- "$COM" || fail "P5_PAR_HAS_CHECK"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" grep -F -q unsafe_git_rev_options "$PAR" -- "$COM" || fail "P5_PAR_HAS_LIST"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" grep -F -q unsafe_git_rev_options "$CAND" -- "$COM" || fail "P5_CAND_NO_LIST"
hits=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" grep -n check_unsafe_options "$CAND" -- "$COM")
[[ $hits == *":341:"* ]] || fail "P5_CAND_NO_ITER $hits"
[[ $hits == *$'\n'* ]] && fail "P5_CAND_MULTI_CHECK $hits" || true
hits=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" grep -n check_unsafe_options "$FIX" -- "$COM")
[[ $hits == *":296:"* && $hits == *":354:"* ]] || fail "P5_FIX_CHECKS $hits"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" grep -F -q check_unsafe_options 3.1.50 -- "$COM" || fail "P5_350_HAS_CHECK"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" grep -n check_unsafe_options 3.1.55 -- "$COM" | LC_ALL=C grep -q ':341:' || fail "P5_355_NO_ITER"
blobp=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-parse "${PAR}:${COM}")
blobc=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-parse "${CAND}:${COM}")
blobv=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-parse "3.1.55:${COM}")
blobf=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-parse "${FIX}:${COM}")
blobt=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-parse "3.1.56:${COM}")
[[ $blobp == d98664da5d592e0c9b3ca926e18031197ef98136 ]] || fail "P5_BLOB_PAR $blobp"
[[ $blobc == 1d8e8f071f3f39ca27618301ec4e4278846b9f3a ]] || fail "P5_BLOB_CAND $blobc"
[[ $blobv == "$blobc" ]] || fail "P5_BLOB_355"
[[ $blobf == 3e435453dfecebbdc1cded48d182948b367bc64c ]] || fail "P5_BLOB_FIX $blobf"
[[ $blobt == "$blobf" ]] || fail "P5_BLOB_356"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" merge-base --is-ancestor "$CAND" 3.1.50 && fail "P5_CAND_IN_350" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" merge-base --is-ancestor "$CAND" 3.1.55 || fail "P5_CAND_NOT_355"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" merge-base --is-ancestor "$FIX" 3.1.55 && fail "P5_FIX_IN_355" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" merge-base --is-ancestor "$FIX" 3.1.56 || fail "P5_FIX_NOT_356"
fpwalk=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" log --first-parent -n 800 --format=%H 3.1.55)
[[ $'\n'"$fpwalk"$'\n' == *$'\n'"$CAND"$'\n'* ]] && fail "P5_CAND_IS_FP" || true
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-parse '3.1.50^{commit}')
[[ $peel == 5a294a6fc7ed5dc0946d4b576257bf926178f269 ]] || fail "P5_PEEL350 $peel"
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-parse '3.1.55^{commit}')
[[ $peel == 681c82c9c296f934635c81fa8294d4b6b6791b7e ]] || fail "P5_PEEL355 $peel"
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$GP" rev-parse '3.1.56^{commit}')
[[ $peel == e3221f1252346259513e14afeed32f0a203512a7 ]] || fail "P5_PEEL356 $peel"
echo "P538_OK"

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
