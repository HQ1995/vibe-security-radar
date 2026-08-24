#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-confirmhigh-4fxp-grok46-low.
# English only. No credentials. Shared caches read-only. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-confirmhigh-4fxp-grok46-low}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
Z=${Z:-/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-even/clones/prospero-flow-crm}
ADV_R=${ADV_R:-/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database}
ADV_U=${ADV_U:-/home/hanqing/.cache/cve-analyzer/advisory-database}
GHSA_CACHE=${GHSA_CACHE:-/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-even/pages/ghsa-4fxp.global.json}
REPO_CACHE=${REPO_CACHE:-/home/hanqing/.cache/ghsa200-worker-clones/baseline-increm-even/pages/ghsa-4fxp.repo.json}
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
REPLAY_TMP="$(mktemp -d /tmp/4fxp-hostile.XXXXXX)"

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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json" \
  ab47f927a20f374a9b0e3253a1a5a0778e355dda9414189927022325d81ad86f
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/ledger.jsonl" \
  70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e
hash_check "$GHSA_CACHE" \
  ec7239df80f6c39dcf9fe9e43727749ab15436ca7110a1c87193a87c562e14cd
hash_check "$REPO_CACHE" \
  790eded25807b4eba5072a42f10b85b0dfc1712aaadb2e4b4fb39d0e3026223f
adv_r=$(gitq -C "$ADV_R" rev-parse HEAD)
[[ $adv_r == a42c436870111aa3f221257c9d56126a93173ccc ]] || fail "ADV_R_HEAD $adv_r"
adv_u=$(gitq -C "$ADV_U" rev-parse HEAD)
[[ $adv_u == 39d8887723797efc1804585dd06585c9fd751226 ]] || fail "ADV_U_HEAD $adv_u"
REV_PATH=advisories/github-reviewed/2026/08/GHSA-4fxp-2m36-qv64/GHSA-4fxp-2m36-qv64.json
UNREV_PATH=advisories/unreviewed/2026/08/GHSA-4fxp-2m36-qv64/GHSA-4fxp-2m36-qv64.json
if command git -C "$ADV_R" cat-file -e "HEAD:$REV_PATH" 2>/dev/null; then
  fail "ADV_R_HAS_REVIEWED"
fi
command git -C "$ADV_R" cat-file -e "HEAD:$UNREV_PATH" 2>/dev/null || fail "ADV_R_MISSING_UNREVIEWED"
python3 - << PY
import hashlib, json, subprocess, sys
adv=r"$ADV_R"
p="$UNREV_PATH"
b=subprocess.check_output(["git","-C",adv,"show","HEAD:"+p])
if hashlib.sha256(b).hexdigest() != "aa57ef638c0da67d2eea41601b525264022afcd0dd91a44ac29e66dc951f4584":
    print("UNREV_HASH"); sys.exit(1)
j=json.loads(b)
if j.get("id","").upper() != "GHSA-4FXP-2M36-QV64":
    print("UNREV_ID"); sys.exit(1)
if j.get("affected"):
    print("UNREV_AFFECTED"); sys.exit(1)
if j.get("database_specific",{}).get("github_reviewed") is not False:
    print("UNREV_REVIEWED"); sys.exit(1)
print("UNREV_DB_OK")
PY

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
want = ["GHSA-4FXP-2M36-QV64"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if any(a.get("prior_confirm_high_is_routing_only") is not True for a in ass):
    print("ROUTING_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [148]:
    print("ORDINAL_FAIL"); sys.exit(1)
if len(cas) != 1 or cas[0]["verdict"] != "NARROW":
    print("COUNT_FAIL", cas[0]["verdict"] if cas else None); sys.exit(1)
if res["conservation"]["equation"] != "1=1+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res.get("pass_proposal_ids"):
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 91:
    print("FLAG_FAIL"); sys.exit(1)
rec = cas[0]
g = rec["gates"]
for k in need:
    if k not in g:
        print("MISSING_GATE", k); sys.exit(1)
if g["identity_gate"] != "NARROW":
    print("BAD_IDENTITY", g["identity_gate"]); sys.exit(1)
for k in ("ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"):
    if g[k] != "PASS":
        print("BAD_GATE", k, g[k]); sys.exit(1)
if rec.get("osv_introduced_used_as_causal_proof") is not False:
    print("OSV_USED_AS_PROOF"); sys.exit(1)
if rec.get("authorship_transfer") is not False:
    print("TRANSFER"); sys.exit(1)
if rec.get("prior_confirm_high_is_routing_only") is not True:
    print("CASE_ROUTING_FLAG"); sys.exit(1)
if rec["seven_gates_exact_pass"] is not False:
    print("SEVEN_SHOULD_FAIL"); sys.exit(1)
if rec["contribution_class"] != "AI_INCOMPLETE_REMEDIATION":
    print("CLASS"); sys.exit(1)
if rec["candidate_set"] != ["52e5e1938ba7db9191ab75fc6f81d92cf667dd4d"]:
    print("CAND"); sys.exit(1)
if "e2fd5b10a0513c16b7b96877b318581bca566f56" in rec["candidate_set"]:
    print("MEMBER_IN_CAND"); sys.exit(1)
if rec["minimum_fix_set"] != ["86a7d6557bd111518a221f4575ad6e36087e19d3"]:
    print("FIXSET"); sys.exit(1)
if rec["unresolved_or_failed_gate"] != "identity_gate":
    print("FAILED_GATE"); sys.exit(1)
print("CONSERVATION_OK 1=1+0 NARROW=1")
PY

echo "== uniqueness vs pinned canonical91 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
down = set(x.upper() for x in canon["checkpoint"]["downgraded"])
narrow = set(x.upper() for x in canon["checkpoint"]["narrow_noncounting"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical91", hit); sys.exit(1)
if "GHSA-4FXP-2M36-QV64" in strict:
    print("UNIQUENESS_FAIL 4FXP_COUNTED"); sys.exit(1)
if "GHSA-4FXP-2M36-QV64" not in down:
    print("DOWNGRADE_MISSING"); sys.exit(1)
if "GHSA-4FXP-2M36-QV64" not in narrow:
    print("NARROW_LIST_MISSING"); sys.exit(1)
if len(strict) != 91:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
if "GHSA-5WP8-Q9MX-8JX8" not in strict:
    print("5WP8_MISSING_COUNTED"); sys.exit(1)
if "GHSA-X8QQ-M4QC-RPJ5" in strict:
    print("X8QQ_COUNTED"); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "4FXP_ABSENT_CANONICAL91 DISTINCT_5WP8_X8QQ")
PY

echo "== first-party advisory =="
python3 - << PY
import json, hashlib, sys
from pathlib import Path
frozen = Path("$GHSA_CACHE").read_bytes()
if hashlib.sha256(frozen).hexdigest() != "ec7239df80f6c39dcf9fe9e43727749ab15436ca7110a1c87193a87c562e14cd":
    print("FROZEN_HASH"); sys.exit(1)
j = json.loads(frozen)
if j.get("ghsa_id","").upper() != "GHSA-4FXP-2M36-QV64":
    print("ADV_ID", j.get("ghsa_id")); sys.exit(1)
if j.get("type") != "unreviewed":
    print("ADV_TYPE", j.get("type")); sys.exit(1)
if j.get("vulnerabilities"):
    print("ADV_VULNS"); sys.exit(1)
if j.get("repository_advisory_url") not in (None, ""):
    print("ADV_REPO_URL"); sys.exit(1)
if j.get("source_code_location"):
    print("ADV_SRC"); sys.exit(1)
if j.get("github_reviewed_at") not in (None, ""):
    print("ADV_REVIEWED"); sys.exit(1)
if j.get("cve_id") != "CVE-2026-59233":
    print("ADV_CVE"); sys.exit(1)
repo = json.loads(Path("$REPO_CACHE").read_text())
if repo.get("status") != "404" and repo.get("message") != "Not Found":
    print("REPO_CACHE", repo); sys.exit(1)
print("ADVISORY_OK unreviewed empty-range repo404-cache")
PY

echo "== git facts =="
[[ -d $Z ]] || fail "CLONE_ABSENT"
C=52e5e1938ba7db9191ab75fc6f81d92cf667dd4d
P=27d0a272dd5f48e9128bee05f56eda6f7b78d69c
M=e2fd5b10a0513c16b7b96877b318581bca566f56
F=86a7d6557bd111518a221f4575ad6e36087e19d3
CTRL=app/Http/Controllers/Permission/PermissionSaveController.php
REQ=app/Http/Requests/PermissionSaveRequest.php
gitq -C "$Z" cat-file -t "$C" >/dev/null
gitq -C "$Z" cat-file -t "$P" >/dev/null
gitq -C "$Z" cat-file -t "$M" >/dev/null
gitq -C "$Z" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$Z" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "PARENTS $parents"
gitq -C "$Z" cat-file -p "$C" | LC_ALL=C grep -q 'Co-authored-by: Claude Sonnet 4.6' || fail "SQUASH_MARKER"
gitq -C "$Z" cat-file -p "$C" | LC_ALL=C grep -q 'GHSA-rx76-rw4p-84j7' || fail "SQUASH_RX76_ALIAS"
gitq -C "$Z" cat-file -p "$F" | LC_ALL=C grep -q 'Co-Authored-By: Claude Haiku 4.5' || fail "FIX_AI_ON_FIX"
gitq -C "$Z" grep -q 'class PermissionSaveController extends Controller' "$P" -- "$CTRL" || fail "PARENT_CONTROLLER"
gitq -C "$Z" grep -q 'class PermissionSaveController extends MainController' "$C" -- "$CTRL" || fail "SQUASH_MAIN"
gitq -C "$Z" grep -q 'syncPermissions' "$P" -- "$CTRL" || fail "PARENT_SYNC"
gitq -C "$Z" grep -q 'syncPermissions' "$C" -- "$CTRL" || fail "SQUASH_SYNC"
if command git -C "$Z" cat-file -e "$C:$REQ" 2>/dev/null; then
  fail "SQUASH_HAS_REQUEST"
fi
gitq -C "$Z" grep -q 'PermissionSaveRequest' "$F" -- "$CTRL" || fail "FIX_USES_REQUEST"
gitq -C "$Z" grep -q "hasRole('SuperAdmin')" "$F" -- "$REQ" || fail "FIX_AUTHORIZE"
pk=$(gitq -C "$Z" log --first-parent -S 'class PermissionSaveController extends MainController' --format='%H' v4.6.0 -- "$CTRL")
print -r -- "$pk" | LC_ALL=C grep -q '^52e5e1938ba7db9191ab75fc6f81d92cf667dd4d' || fail "PICKAXE $pk"
gitq -C "$Z" merge-base --is-ancestor "$M" "$C" && fail "MEMBER_ANC_SQUASH" || true
gitq -C "$Z" merge-base --is-ancestor "$M" v4.6.0 && fail "MEMBER_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$M" "$F" && fail "MEMBER_ANC_FIX" || true
gitq -C "$Z" merge-base --is-ancestor "$C" v4.6.0 || fail "SQUASH_TAG"
gitq -C "$Z" merge-base --is-ancestor "$F" v4.6.0 && fail "FIX_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$F" v5.5.3 || fail "FIX_TAG"
if command git -C "$Z" rev-parse 'v5.2.1^{commit}' >/dev/null 2>&1; then
  fail "NAMED_521_TAG_EXISTS"
fi
if command git -C "$Z" rev-parse 'v5.2.0^{commit}' >/dev/null 2>&1; then
  fail "NAMED_520_TAG_EXISTS"
fi
peel=$(gitq -C "$Z" rev-parse 'v4.6.0^{commit}')
[[ $peel == 4c15d20a57c4225bb3853bad2c5b01b3da11121f ]] || fail "PEEL460 $peel"
peel=$(gitq -C "$Z" rev-parse 'v5.5.3^{commit}')
[[ $peel == 584f315878b8366244c95fe3cb016b3a63f05db8 ]] || fail "PEEL553 $peel"
blob_p=$(gitq -C "$Z" rev-parse "${P}:${CTRL}")
blob_c=$(gitq -C "$Z" rev-parse "${C}:${CTRL}")
blob_m=$(gitq -C "$Z" rev-parse "${M}:${CTRL}")
blob_v=$(gitq -C "$Z" rev-parse "v4.6.0:${CTRL}")
blob_f=$(gitq -C "$Z" rev-parse "${F}:${CTRL}")
blob_v2=$(gitq -C "$Z" rev-parse "v5.5.3:${CTRL}")
[[ $blob_p == a558cb64686a3e7ca152e051ddb1edc829a61a4f ]] || fail "BLOB_P $blob_p"
[[ $blob_c == f0da620c7b4f2a3708979a684eb2d4eba35db9a6 ]] || fail "BLOB_C $blob_c"
[[ $blob_m == "$blob_c" ]] || fail "MEMBER_NE_SQUASH_BLOB"
[[ $blob_v == "$blob_c" ]] || fail "V460_NE_SQUASH_BLOB"
[[ $blob_f == afb716d4eae059a3478472ba6267451265815491 ]] || fail "BLOB_F $blob_f"
[[ $blob_f == "$blob_v2" ]] || fail "FIX_CTRL_NE_V553"
req_f=$(gitq -C "$Z" rev-parse "${F}:${REQ}")
req_v=$(gitq -C "$Z" rev-parse "v5.5.3:${REQ}")
[[ $req_f == 3107cf83543b598b8f9c82cf4d4a6a42e544ba93 ]] || fail "REQ_F $req_f"
[[ $req_v == 795a4c17894ec14d52d5052dda8add0713246ab9 ]] || fail "REQ_V $req_v"
[[ $req_f != "$req_v" ]] || fail "REQ_BLOBS_EQUAL"
echo "GIT_OK"

echo "== github releases =="
# Draft/prerelease flags were verified against GitHub Releases during the audit.
# Replay pins git tags and peels only, so it stays identical without live HTTP.
gitq -C "$Z" rev-parse v4.6.0 >/dev/null
gitq -C "$Z" rev-parse v5.5.3 >/dev/null
echo "RELEASES_OK git-tags-pinned"

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

echo "REPLAY_OK reviewed=1 PASS_proposal=0 NARROW=1 REJECT=0 UNKNOWN=0 BLOCKED=0"
