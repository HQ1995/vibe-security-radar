#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-causalonly-releasefail-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
FLY=${FLY:-/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/flytohub__flyto-core}
FLYTAGS=${FLYTAGS:-/home/hanqing/.cache/ghsa200-worker-clones/delta-even-batch2/flytohub__flyto-core}
OC=${OC:-/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/openclaw__openclaw}
OE=${OE:-/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/jahlives__openssl_encrypt}
ADVHR=${ADVHR:-/home/hanqing/.cache/ghsa200-worker-clones/commit-af/advisory-database/advisories/github-reviewed/2026/07/GHSA-hr7p-wg7r-hg9m/GHSA-hr7p-wg7r-hg9m.json}
ADV98=${ADV98:-/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/advisory-database/advisories/github-reviewed/2026/03/GHSA-98hh-7ghg-x6rq/GHSA-98hh-7ghg-x6rq.json}
ADVC65=${ADVC65:-/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-c65f-x25w-62jv/GHSA-c65f-x25w-62jv.json}
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
    text=b.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(1)
if any(ord(ch) > 127 for ch in text):
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json" \
  8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9
hash_check "$ADVHR" 860520c0187ab10dd72f689dd97ad0e4906ab744a20aeeacb2b203060cdb516c
hash_check "$ADV98" 1c6eee7feb93e5cf00d974f049462e88724a6824e45472bc7b78f773a73d22a3
hash_check "$ADVC65" d69ab759b983a02a64f7fc27bfc61594de0b1d774f10650dc1ebbab1dcd21498

echo "== first-party advisory identities =="
python3 - << PY
import json, sys
from pathlib import Path
hr=json.loads(Path("$ADVHR").read_text())
x6=json.loads(Path("$ADV98").read_text())
c65=json.loads(Path("$ADVC65").read_text())
if hr.get("id") != "GHSA-hr7p-wg7r-hg9m":
    print("HR_ID", hr.get("id")); sys.exit(1)
if "os.getenv" not in hr.get("details",""):
    print("HR_NO_GETENV"); sys.exit(1)
if x6.get("id") != "GHSA-98hh-7ghg-x6rq":
    print("X6_ID"); sys.exit(1)
if "execApprovals.approvers" not in x6.get("summary",""):
    print("X6_SUMMARY"); sys.exit(1)
if c65.get("id") != "GHSA-c65f-x25w-62jv":
    print("C65_ID"); sys.exit(1)
pkg=(c65.get("affected") or [{}])[0].get("package",{})
if pkg.get("ecosystem") != "PyPI" or pkg.get("name") != "openssl-encrypt":
    print("C65_PKG", pkg); sys.exit(1)
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
    "GHSA-HR7P-WG7R-HG9M",
    "GHSA-98HH-7GHG-X6RQ",
    "GHSA-C65F-X25W-62JV",
]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
causal = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","uniqueness_gate")
okv = ("PASS","FAIL","UNKNOWN","NARROW","BLOCKED")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if any(a.get("never_upgrade_release") is not True for a in ass):
    print("NEVER_UPGRADE_ASSIGN"); sys.exit(1)
n_cop = sum(1 for c in cas if c["verdict"] == "CAUSAL_ONLY_PASS")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_cop != 1 or n_rej != 2 or len(cas) != 3:
    print("COUNT_FAIL", n_cop, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 88:
    print("CANON_FAIL"); sys.exit(1)
if res["pass_proposals"] != [] or res["counts"]["countable_pass"] != 0:
    print("COUNTABLE_FAIL"); sys.exit(1)
if res["never_upgrade_release"] is not True:
    print("NEVER_UPGRADE_RES"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if g[k] not in okv:
            print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
    if g["release_gate"] != "FAIL":
        print("RELEASE_UPGRADED", rec["case_id"], g["release_gate"]); sys.exit(1)
    if rec.get("countable_proposal") is not False:
        print("COUNTABLE_PROPOSAL", rec["case_id"]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    six = all(g[k] == "PASS" for k in causal)
    if rec["verdict"] == "CAUSAL_ONLY_PASS":
        if not six or rec["case_id"] != "GHSA-98HH-7GHG-X6RQ":
            print("BAD_CAUSAL_ONLY", rec["case_id"], g); sys.exit(1)
    else:
        if six:
            print("SIX_PASS_NOT_MARKED", rec["case_id"]); sys.exit(1)
        if rec["verdict"] != "REJECT":
            print("BAD_REJECT", rec["case_id"], rec["verdict"]); sys.exit(1)
hr = next(c for c in cas if c["case_id"] == "GHSA-HR7P-WG7R-HG9M")
if hr["gates"]["ai_hunk_gate"] != "FAIL" or hr["gates"]["but_for_gate"] != "FAIL":
    print("HR7P_GATES", hr["gates"]); sys.exit(1)
c65 = next(c for c in cas if c["case_id"] == "GHSA-C65F-X25W-62JV")
if c65["gates"]["identity_gate"] != "FAIL" or c65.get("package_mismatch") is not True:
    print("C65_GATES", c65["gates"]); sys.exit(1)
print("CONSERVATION_OK 3=3+0 CAUSAL_ONLY_PASS=1 REJECT=2")
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
[[ -d $FLY && -d $FLYTAGS && -d $OC && -d $OE ]] || fail "CLONE_ABSENT"

# HR7P
C=68af171dcf42b89fb5d3f5f3f60c2ae25f91e5ce
F=d5f89d71303e3c1e6418d347c5c55fcd173cc8cc
P=21d5f5d092c28b51bd507303f421bc989c9175fa
gitq -C "$FLY" cat-file -t "$C" >/dev/null
gitq -C "$FLY" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$FLY" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "HR7P_PARENTS $parents"
gitq -C "$FLY" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.8' || fail "HR7P_MARKER"
git_path_absent -C "$FLY" cat-file -e "${P}:src/core/module_policy.py" || fail "HR7P_PARENT_HAS_POLICY"
gitq -C "$FLY" cat-file -e "${C}:src/core/module_policy.py" >/dev/null || fail "HR7P_CAND_POLICY"
gitq -C "$FLY" grep -q "return os.getenv(env_var)" "$P" -- src/core/engine/variable_resolver.py || fail "HR7P_PARENT_GETENV"
resolver_delta=$(gitq -C "$FLY" diff --name-only "$P" "$C" -- src/core/engine/variable_resolver.py)
[[ -z $resolver_delta ]] || fail "HR7P_CAND_TOUCHED_RESOLVER $resolver_delta"
gitq -C "$FLY" grep -q 'env.get' "$C" -- src/core/module_policy.py || fail "HR7P_CAND_DENYLIST"
gitq -C "$FLY" merge-base --is-ancestor "$C" "$F" || fail "HR7P_NOT_ANC"
gitq -C "$FLY" diff "${F}^" "$F" -- src/core/module_policy.py | LC_ALL=C grep -q is_env_var_allowed || fail "HR7P_FIX_POLICY"
gitq -C "$FLY" diff "${F}^" "$F" -- src/core/engine/variable_resolver.py | LC_ALL=C grep -q is_env_var_allowed || fail "HR7P_FIX_RESOLVER"
gitq -C "$FLYTAGS" merge-base --is-ancestor "$C" v2.26.4 && fail "HR7P_CAND_IN_V264" || true
gitq -C "$FLYTAGS" merge-base --is-ancestor "$F" v2.26.4 && fail "HR7P_FIX_IN_V264" || true
gitq -C "$FLYTAGS" merge-base --is-ancestor "$C" v2.26.6 || fail "HR7P_CAND_NOT_V266"
gitq -C "$FLYTAGS" merge-base --is-ancestor "$F" v2.26.6 || fail "HR7P_FIX_NOT_V266"
peel264=$(gitq -C "$FLYTAGS" rev-parse 'v2.26.4^{commit}')
peel266=$(gitq -C "$FLYTAGS" rev-parse 'v2.26.6^{commit}')
[[ $peel264 == 50d0d327a1278c8cec9495ba5f6f010dd67ef19c ]] || fail "HR7P_PEEL264 $peel264"
[[ $peel266 == 2471c6e774102fcca21c61eb66cae057c0f0cecf ]] || fail "HR7P_PEEL266 $peel266"
echo "HR7P_OK"

# 98HH
C=483fba41b9f9fb57964f31b90a2ddacb185d54d7
F=355abe5eba28012e6a95b9923a32831fcf870344
P=fe7436a1f679f4b98704fba81c5971180ae45da1
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "X6_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "X6_MARKER"
git_path_absent -C "$OC" cat-file -e "${P}:src/auto-reply/reply/commands-approve.ts" || fail "X6_PARENT_HAS_APPROVE"
gitq -C "$OC" cat-file -e "${C}:src/auto-reply/reply/commands-approve.ts" >/dev/null || fail "X6_CAND_APPROVE"
gitq -C "$OC" grep -q 'exec.approval.resolve' "$C" -- src/auto-reply/reply/commands-approve.ts || fail "X6_CAND_RESOLVE"
gitq -C "$OC" grep -q isAuthorizedSender "$C" -- src/auto-reply/reply/commands-approve.ts || fail "X6_CAND_AUTH"
if gitq -C "$OC" grep -q isDiscordExecApprovalApprover "$C" -- src/auto-reply/reply/commands-approve.ts; then
  fail "X6_CAND_ALREADY_DISCORD"
fi
gitq -C "$OC" grep -q 'config.approvers' "$C" -- src/discord/monitor/exec-approvals.ts || fail "X6_CAND_DM_APPROVERS"
gitq -C "$OC" merge-base --is-ancestor "$C" "$F" || fail "X6_NOT_ANC"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"approver checks for text approvals"* ]] || fail "X6_FIX_SUBJ $fsubj"
gitq -C "$OC" diff "${F}^" "$F" -- src/auto-reply/reply/commands-approve.ts | LC_ALL=C grep -q isDiscordExecApprovalApprover || fail "X6_FIX_TEXT"
ntags_c=$(gitq -C "$OC" tag --contains "$C" | wc -l)
ntags_f=$(gitq -C "$OC" tag --contains "$F" | wc -l)
[[ $ntags_c -eq 0 && $ntags_f -eq 0 ]] || fail "X6_TAGS_NONEMPTY $ntags_c $ntags_f"
echo "X6_OK"

# C65F
C1=fafdfeed1b279cfe61e86cd8adc132b206eef8d4
C2=4c7ae852c784c9986d087c5956a77fa563a05a35
F=809416b74d2749cdcffb484cd65b057e1685cc13
P2=457f88d09cc365cdbb85b083a29f0956804730be
gitq -C "$OE" cat-file -t "$C1" >/dev/null
gitq -C "$OE" cat-file -t "$C2" >/dev/null
gitq -C "$OE" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OE" rev-list --parents -n 1 "$C2")
[[ $parents == "$C2 $P2" ]] || fail "C65_C2_PARENTS $parents"
parents=$(gitq -C "$OE" rev-list --parents -n 1 "$C1")
[[ $parents == "$C1 $C2" ]] || fail "C65_C1_PARENTS $parents"
gitq -C "$OE" cat-file -p "$C1" | LC_ALL=C grep -q 'Co-Authored-By: Claude Sonnet 4.5' || fail "C65_C1_MARKER"
gitq -C "$OE" cat-file -p "$C2" | LC_ALL=C grep -q 'Co-Authored-By: Claude Sonnet 4.5' || fail "C65_C2_MARKER"
git_path_absent -C "$OE" cat-file -e "${P2}:server/telemetry-server/app/config.py" || fail "C65_P2_HAS_TELE"
git_path_absent -C "$OE" cat-file -e "${C2}:server/key-server/app/config.py" || fail "C65_C2_HAS_KEY"
gitq -C "$OE" grep -F -q 'cors_origins: list = ["*"]' "$C2" -- server/telemetry-server/app/config.py || fail "C65_C2_CORS"
gitq -C "$OE" grep -F -q 'cors_origins: List[str] = ["*"]' "$C1" -- server/key-server/app/config.py || fail "C65_C1_CORS"
gitq -C "$OE" merge-base --is-ancestor "$C1" "$F" || fail "C65_C1_NOT_ANC"
gitq -C "$OE" merge-base --is-ancestor "$C2" "$F" || fail "C65_C2_NOT_ANC"
gitq -C "$OE" diff "${F}^" "$F" -- server/key-server/app/config.py | LC_ALL=C grep -F -q 'cors_origins: List[str] = []' || fail "C65_FIX_KEY"
gitq -C "$OE" diff "${F}^" "$F" -- server/telemetry-server/app/config.py | LC_ALL=C grep -F -q 'cors_origins: list = []' || fail "C65_FIX_TELE"
git_path_absent -C "$OE" cat-file -e "${F}:server/__init__.py" || fail "C65_HAS_SERVER_INIT"
gitq -C "$OE" grep -q 'packages=find_packages()' "$F" -- setup.py || fail "C65_FIND_PACKAGES"
gitq -C "$OE" grep -q 'validation_alias="CORS_ORIGINS"' "$F" -- openssl_encrypt_server/config.py || fail "C65_UNIFIED_EMPTY"
gitq -C "$OE" cat-file -p "$F" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "C65_CLOSER_MARKER"
ntags=$(gitq -C "$OE" tag | wc -l)
[[ $ntags -eq 0 ]] || fail "C65_TAGS_NONEMPTY $ntags"
echo "C65_OK"

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

echo "REPLAY_OK reviewed=3 CAUSAL_ONLY_PASS=1 REJECT=2 countable_pass=0"
