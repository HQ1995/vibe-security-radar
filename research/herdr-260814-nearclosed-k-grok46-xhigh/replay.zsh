#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-k-grok46-xhigh.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-k-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
CM=${CM:-/home/hanqing/.cache/cve-analyzer/repos/github.com_thedotmack_claude-mem}
OU=${OU:-/home/hanqing/.cache/ghsa200-worker-clones/contributor-redteam/clones/ouroboros}
HE=${HE:-/home/hanqing/.cache/cve-analyzer/repos/github.com_nesquena_hermes-webui}
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/summary.json" \
  5222879219a975fa4388f3f07f5c62cd6687a642b6509afe48a4250fb4be81ef
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/ledger.jsonl" \
  daf706e14d514ad62d197e61aa8ec7f52eefd958bc19a4a7c58591a0be8654ec
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ADV/advisories/github-reviewed/2026/06/GHSA-5gvr-v6qv-h5mm/GHSA-5gvr-v6qv-h5mm.json" \
  0de1f53d38bce75a729efe3e4157db4ae2297a9a1659de169a2f2f043c798e16
hash_check "$ADV/advisories/github-reviewed/2026/05/GHSA-c4m7-2gwp-vw76/GHSA-c4m7-2gwp-vw76.json" \
  778bcd22592c4b8b543141c6df15b81ace8724c5b2efb5a838b2c4f8c94668e6
hash_check "$ADV/advisories/unreviewed/2026/06/GHSA-mgxw-v6rh-wcv6/GHSA-mgxw-v6rh-wcv6.json" \
  5396f7ae89319dbc3e04bfa238730fd363904ee5d19ac2edd384f9fcc88c0882

echo "== first-party advisory identities =="
python3 - << PY
import json, sys
from pathlib import Path
adv = Path("$ADV")
g5 = json.loads((adv / "advisories/github-reviewed/2026/06/GHSA-5gvr-v6qv-h5mm/GHSA-5gvr-v6qv-h5mm.json").read_text())
c4 = json.loads((adv / "advisories/github-reviewed/2026/05/GHSA-c4m7-2gwp-vw76/GHSA-c4m7-2gwp-vw76.json").read_text())
mg = json.loads((adv / "advisories/unreviewed/2026/06/GHSA-mgxw-v6rh-wcv6/GHSA-mgxw-v6rh-wcv6.json").read_text())
if g5.get("id") != "GHSA-5gvr-v6qv-h5mm":
    print("G5_ID"); sys.exit(1)
if g5.get("database_specific", {}).get("github_reviewed") is not True:
    print("G5_REVIEWED"); sys.exit(1)
if "computeObservationContentHash" not in g5.get("details", ""):
    print("G5_NO_FN"); sys.exit(1)
if "thedotmack" not in g5.get("details", "") and "thedotmack" not in json.dumps(g5.get("references", [])):
    print("G5_NO_REPO"); sys.exit(1)
if g5.get("aliases") != ["CVE-2026-11330"]:
    print("G5_ALIAS"); sys.exit(1)
if c4.get("id") != "GHSA-c4m7-2gwp-vw76":
    print("C4_ID"); sys.exit(1)
if c4.get("database_specific", {}).get("github_reviewed") is not True:
    print("C4_REVIEWED"); sys.exit(1)
det = c4.get("details", "")
if "OUROBOROS_CLI_PATH" not in det or ".env" not in det:
    print("C4_NO_ENV"); sys.exit(1)
if "Q00/ouroboros/security/advisories/GHSA-c4m7-2gwp-vw76" not in json.dumps(c4.get("references", [])):
    print("C4_NO_REPO_ADV"); sys.exit(1)
if mg.get("id") != "GHSA-mgxw-v6rh-wcv6":
    print("MG_ID"); sys.exit(1)
if mg.get("database_specific", {}).get("github_reviewed") is not False:
    print("MG_REVIEWED"); sys.exit(1)
if mg.get("affected") != []:
    print("MG_AFFECTED"); sys.exit(1)
if "active-profile" not in mg.get("details", ""):
    print("MG_NO_PROFILE"); sys.exit(1)
if any("security/advisories" in (r.get("url") or "") for r in mg.get("references", [])):
    print("MG_HAS_REPO_ADV"); sys.exit(1)
rev = adv / "advisories/github-reviewed/2026/06/GHSA-mgxw-v6rh-wcv6/GHSA-mgxw-v6rh-wcv6.json"
if rev.exists():
    print("MG_REVIEWED_FILE"); sys.exit(1)
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
    "GHSA-5GVR-V6QV-H5MM",
    "GHSA-C4M7-2GWP-VW76",
    "GHSA-MGXW-V6RH-WCV6",
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
if [a["fp211_ordinal"] for a in ass] != [98, 100, 115]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
if n_pass != 0 or n_nar != 3 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != [] or res["canonical_strict_count_untouched"] != 90:
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
if "GHSA-8RW6-P7M8-63JP" in ids:
    print("UNIQUENESS_FAIL 8RW6"); sys.exit(1)
if "GHSA-VVFR-G83F-8QCV" not in strict:
    print("COUNTED_VVFR_MISSING"); sys.exit(1)
if "GHSA-VVFR-G83F-8QCV" in ids:
    print("MERGED_VVFR"); sys.exit(1)
if "GHSA-XMXX-7P24-H892" not in strict or "GHSA-PQH8-P93P-2RX7" not in strict:
    print("CANON90_PROMOTIONS_MISSING"); sys.exit(1)
if len(strict) != 90:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "canonical90", len(strict))
PY

echo "== git facts =="
[[ -d $CM ]] || fail "CM_CLONE_ABSENT"
[[ -d $OU ]] || fail "OU_CLONE_ABSENT"
[[ -d $HE ]] || fail "HE_CLONE_ABSENT"

# 5GVR ordinal 98
MEM=924a11eeca832ddaafc200eb51cff5657354ba4a
CAR=c6f932988a71e4eb0bf15108c91eec7d9eb64349
FIXM=f32fda8b35e9fe9329f87da65c31149362a03f97
FIXA=9cfa57d4984f068be8492be5489727ae04fa9203
CPAR=d9a30cc7d45c91f53bd44f5251d048b2e897138f
STORE=src/services/sqlite/observations/store.ts
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" cat-file -t "$CAR" >/dev/null
parents=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" rev-list --parents -n 1 "$CAR")
[[ $parents == "$CAR $CPAR" ]] || fail "G5_PARENTS $parents"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" cat-file -p "$CAR" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "G5_MARKER"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" grep -F -q computeObservationContentHash "$CPAR" -- "$STORE" || fail "G5_PARENT_HAS_HASH"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" grep -F -q computeObservationContentHash "$CAR" -- "$STORE" || fail "G5_CAR_NO_HASH"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" grep -F -q "slice(0, 16)" "$CAR" -- "$STORE" || fail "G5_CAR_NO_SLICE"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" grep -F -q "join('\\x00')" "$FIXA" -- "$STORE" || fail "G5_FIX_NO_NUL"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" grep -F -q "slice(0, 16)" "$FIXA" -- "$STORE" || fail "G5_FIX_DROPPED_SLICE"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" grep -F -q "slice(0, 16)" v12.0.0 -- "$STORE" || fail "G5_V12_DROPPED_SLICE"
blobm=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" rev-parse "${MEM}:${STORE}")
blobc=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" rev-parse "${CAR}:${STORE}")
blobv=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" rev-parse "v11.0.0:${STORE}")
blobp=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" rev-parse "${CPAR}:${STORE}")
[[ $blobm == 20727332fc3b71bc780f83e59e43fbd9f6950017 ]] || fail "G5_BLOB_MEM $blobm"
[[ $blobc == "$blobm" && $blobv == "$blobm" ]] || fail "G5_BLOB_EQ"
[[ $blobp == 6007c9d28a66ea2881f68cb555fef817fd18f187 ]] || fail "G5_BLOB_PARENT $blobp"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" merge-base --is-ancestor "$MEM" v11.0.0 && fail "G5_MEM_IN_1100" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" merge-base --is-ancestor "$CAR" v11.0.0 || fail "G5_CAR_NOT_1100"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" merge-base --is-ancestor "$FIXM" v11.0.1 && fail "G5_FIX_IN_1101" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" merge-base --is-ancestor "$FIXM" v12.0.0 || fail "G5_FIX_NOT_1200"
fpars=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" rev-list --parents -n 1 "$FIXM")
[[ $fpars == "$FIXM 4509da1409376afa77102031b12df74c0aea476a $FIXA" ]] || fail "G5_FIX_NOT_MERGE $fpars"
fpwalk=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" log --first-parent -n 1200 --format=%H v12.0.0)
[[ $'\n'"$fpwalk"$'\n' == *$'\n'"$CAR"$'\n'* ]] || fail "G5_CAR_NOT_FP"
[[ $'\n'"$fpwalk"$'\n' == *$'\n'"$FIXM"$'\n'* ]] && fail "G5_FIX_IS_FP" || true
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" rev-parse 'v11.0.0^{commit}')
[[ $peel == a7ebc35ee0da659aab3630b669fcf20b4162dedd ]] || fail "G5_PEEL1100 $peel"
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" rev-parse 'v11.0.1^{commit}')
[[ $peel == 18aa5dc4e7b0bd74f71cb5dabc6740eb67ab6c7b ]] || fail "G5_PEEL1101 $peel"
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$CM" rev-parse 'v12.0.0^{commit}')
[[ $peel == 25ccf46ac0e388808332e9ead3ea7de0817b5830 ]] || fail "G5_PEEL1200 $peel"
echo "G5VR_OK"

# C4M7 ordinal 100
MEM=d30b61759b8efe4554978438abbcc5a9d698d055
CAR=4aaf9147a6c6f76aecc775defcd1a542537cf01f
FIX=4e70b760b4eb157469b58645339ba831f6513d37
MPAR=9ed95f0f6498ba50beb7590a2c0f3192eff23353
CPAR=797441d9005cf35aa4c4d12cb074710b1cb6e0d1
ADAP=src/ouroboros/providers/claude_code_adapter.py
LOAD=src/ouroboros/config/loader.py
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" cat-file -t "$MEM" >/dev/null
parents=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" rev-list --parents -n 1 "$MEM")
[[ $parents == "$MEM $MPAR" ]] || fail "C4_MEM_PARENTS $parents"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" cat-file -p "$MEM" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "C4_MEM_MARKER"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" cat-file -p "$CAR" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "C4_CAR_MARKER"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" grep -F -q OUROBOROS_CLI_PATH "$MPAR" -- "$ADAP" || fail "C4_MPAR_HAS_PATH"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" grep -F -q 'os.environ.get("OUROBOROS_CLI_PATH")' "$MEM" -- "$ADAP" || fail "C4_MEM_NO_ENVGET"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" grep -F -q OUROBOROS_CLI_PATH "$CPAR" -- "$ADAP" || fail "C4_CPAR_HAS_PATH"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" cat-file -e 9f9cf8d3965828ea466cb8fd5d4d2685810887a5 || fail "C4_CAR_BLOB_PRESENT"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" grep -F -q OUROBOROS_CLI_PATH v0.38.2 -- "$ADAP" || fail "C4_V382_NO_PATH"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" grep -F -q get_cli_path v0.38.2 -- "$ADAP" || fail "C4_V382_NO_GET"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" grep -F -q 'Path(".env")' "$CAR" -- "$LOAD" || fail "C4_CAR_HAS_DOTENV"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" grep -F -q 'Path(".env")' v0.38.2 -- "$LOAD" || fail "C4_V382_NO_DOTENV"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" grep -F -q _UNTRUSTED_ENV_DENYLIST "$FIX" -- "$LOAD" || fail "C4_FIX_NO_DENY"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" grep -F -q OUROBOROS_CLI_PATH "$FIX" -- "$ADAP" || fail "C4_FIX_DROPPED_PATH"
blobm=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" rev-parse "${MEM}:${ADAP}")
blobv=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" rev-parse "v0.38.2:${ADAP}")
[[ $blobm == 4163a58dbdca84c085fcd04c9c61b257209ef6aa ]] || fail "C4_BLOB_MEM $blobm"
[[ $blobv == 25239e62f94a69187056107d822538f2057d0e6d ]] || fail "C4_BLOB_V382 $blobv"
[[ $blobm != "$blobv" ]] || fail "C4_BLOB_EQUAL"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" merge-base --is-ancestor "$MEM" v0.38.2 && fail "C4_MEM_IN_VULN" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" merge-base --is-ancestor "$CAR" v0.38.2 || fail "C4_CAR_NOT_VULN"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" merge-base --is-ancestor "$FIX" v0.38.2 && fail "C4_FIX_IN_VULN" || true
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" merge-base --is-ancestor "$FIX" v0.39.0 || fail "C4_FIX_NOT_FIXED"
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" rev-parse 'v0.38.2^{commit}')
[[ $peel == eb5e0868cef164f98304dc42502fbf0ed4a407c9 ]] || fail "C4_PEEL382 $peel"
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$OU" rev-parse 'v0.39.0^{commit}')
[[ $peel == 2014af0cbce27d88c290347513dee770c8bf2f44 ]] || fail "C4_PEEL390 $peel"
echo "C4M7_OK"

# MGXW ordinal 115
CAND=d2b27f6f1edb83634730f93dc8f19721d877bd07
PAR=af73a5d8fde4c0408b35666613ef45c3e1c46eab
FM=8d8ae89d27a4547b2edc388a986ef0d55549f7d4
FS=2c7b530071bb29ae4184e83e33be5799d529568e
ROUT=api/routes.py
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" cat-file -t "$CAND" >/dev/null
parents=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PAR" ]] || fail "MG_PARENTS $parents"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" cat-file -p "$CAND" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "MG_MARKER"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q "for s in all_sessions():" "$PAR" -- "$ROUT" || fail "MG_PAR_NO_SEARCH"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q "for s in all_sessions():" "$CAND" -- "$ROUT" || fail "MG_CAND_NO_SEARCH"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q _profiles_match "$CAND" -- "$ROUT" || fail "MG_CAND_HAS_MATCH"
git_expect_fail --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" cat-file -e "${PAR}:api/profiles.py" || fail "MG_PAR_HAS_PROFILES"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" cat-file -e "${CAND}:api/profiles.py" >/dev/null || fail "MG_CAND_NO_PROFILES"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q "for s in all_sessions():" v0.51.268 -- "$ROUT" || fail "MG_V268_SCOPED"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" grep -F -q "_profiles_match(s.get(\"profile\"), active_profile)" v0.51.269 -- "$ROUT" || fail "MG_V269_NO_FILTER"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" log -1 --format=%B "$FM" | LC_ALL=C grep -qi 'Co-Authored-By: Claude' && fail "MG_FIX_HAS_CLAUDE" || true
blobc=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "${CAND}:${ROUT}")
blobv=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "v0.51.268:${ROUT}")
blobf=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "${FM}:${ROUT}")
blobt=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse "v0.51.269:${ROUT}")
[[ $blobc == b90c8e97f8565aafc6ba7e195d0ee0cb40dd75f7 ]] || fail "MG_BLOB_CAND $blobc"
[[ $blobv == fc3fab70de41c1ab76951d7879ed45589f0eb7d1 ]] || fail "MG_BLOB_V268 $blobv"
[[ $blobf == d5c5be6ab34c2bb9c76baef09c81ac88be040ecd ]] || fail "MG_BLOB_FIX $blobf"
[[ $blobt == 433317aeb3e3f87d9ca226cf48e14ca3b84a6fef ]] || fail "MG_BLOB_TAG $blobt"
[[ $blobc != "$blobv" && $blobf != "$blobt" ]] || fail "MG_BLOB_COLLAPSE"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" merge-base --is-ancestor "$CAND" v0.51.268 || fail "MG_CAND_NOT_VULN"
gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" merge-base --is-ancestor "$FM" v0.51.269 && fail "MG_FIXMEM_IN_TAG" || true
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse 'v0.51.268^{commit}')
[[ $peel == 442b033e674f9615fd3aa0919ea78736a1363a03 ]] || fail "MG_PEEL268 $peel"
peel=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" rev-parse 'v0.51.269^{commit}')
[[ $peel == 2c7b530071bb29ae4184e83e33be5799d529568e ]] || fail "MG_PEEL269 $peel"
[[ $peel == "$FS" ]] || fail "MG_TAG_NOT_SQUASH"
fpwalk=$(gitq --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -C "$HE" log --first-parent -n 4000 --format=%H v0.51.268)
[[ $'\n'"$fpwalk"$'\n' == *$'\n'"$CAND"$'\n'* ]] && fail "MG_CAND_IS_FP" || true
echo "MGXW_OK"

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

echo "REPLAY_OK reviewed=3 PASS_proposal=0 NARROW=3 REJECT=0 UNKNOWN=0 BLOCKED=0"
