#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-c-grok46-high.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-c-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
IR=${IR:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-topologyonly3-grok46-xhigh/work/clones/ironclaw}
SC=${SC:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-singlegate5-grok46-xhigh/work/clones/solidcam-gppl-ide}
ADV_REV=${ADV_REV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database}
ADV_F7=${ADV_F7:-$ADV_REV/advisories/github-reviewed/2026/04/GHSA-f7fh-qg34-x2xh/GHSA-f7fh-qg34-x2xh.json}
ADV_CW=${ADV_CW:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/pages/ghsa/GHSA-cw23-qwr7-c655.json}
ADV_92=${ADV_92:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/pages/repo/anzory__solidcam-gppl-ide__GHSA-92vg-f4fq-fxm9.json}
ADV_CW_REPO=${ADV_CW_REPO:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/pages/repo/ironclaw-GHSA-cw23-qwr7-c655.json}
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
hash_check "$ADV_F7" \
  20ff4bfe650275308f2c39f0fade0e07d654f6ddb5fc79a2a47052d75f77a9a2
hash_check "$ADV_CW" \
  4985880dff303da44d8dc98a4a3fb40a2c865efab23c6041de458dccf413937b
hash_check "$ADV_92" \
  2f379d016bd2fd1e89638f4c2acfcb3c7f3438347a866c1abc1caf851c1faa5d
hash_check "$ADV_CW_REPO" \
  790eded25807b4eba5072a42f10b85b0dfc1712aaadb2e4b4fb39d0e3026223f

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
    "GHSA-F7FH-QG34-X2XH",
    "GHSA-CW23-QWR7-C655",
    "GHSA-92VG-F4FQ-FXM9",
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
if [a["fp211_ordinal"] for a in ass] != [78, 107, 110]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 0 or n_nar != 2 or n_rej != 1 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != [] or res["canonical_strict_count_untouched"] != 88:
    print("FLAG_FAIL"); sys.exit(1)
byid = {c["case_id"]: c for c in cas}
if byid["GHSA-F7FH-QG34-X2XH"]["verdict"] != "NARROW":
    print("F7FH_VERDICT"); sys.exit(1)
if byid["GHSA-F7FH-QG34-X2XH"]["gates"]["identity_gate"] != "NARROW":
    print("F7FH_IDENTITY"); sys.exit(1)
if byid["GHSA-F7FH-QG34-X2XH"]["gates"]["release_gate"] != "PASS":
    print("F7FH_RELEASE"); sys.exit(1)
if byid["GHSA-CW23-QWR7-C655"]["verdict"] != "REJECT":
    print("CW23_VERDICT"); sys.exit(1)
if byid["GHSA-CW23-QWR7-C655"]["gates"]["identity_gate"] != "FAIL":
    print("CW23_IDENTITY"); sys.exit(1)
if byid["GHSA-CW23-QWR7-C655"]["gates"]["topology_gate"] != "FAIL":
    print("CW23_TOPOLOGY"); sys.exit(1)
if byid["GHSA-CW23-QWR7-C655"].get("authorship_transfer") is not False:
    print("CW23_TRANSFER"); sys.exit(1)
if byid["GHSA-92VG-F4FQ-FXM9"]["verdict"] != "NARROW":
    print("92VG_VERDICT"); sys.exit(1)
if byid["GHSA-92VG-F4FQ-FXM9"]["gates"]["ai_hunk_gate"] != "NARROW":
    print("92VG_AIHUNK"); sys.exit(1)
if byid["GHSA-92VG-F4FQ-FXM9"]["gates"]["identity_gate"] != "PASS":
    print("92VG_IDENTITY"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if g[k] not in okv:
            print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
    if rec["verdict"] == "PASS_PROPOSAL":
        print("PROMOTED_PASS", rec["case_id"]); sys.exit(1)
        if any(g[k] != "PASS" for k in need):
            print("PASS_WITH_NONPASS_GATE", rec["case_id"]); sys.exit(1)
    if rec.get("proposed_pass") is not False:
        print("PROPOSED_PASS_FLAG", rec["case_id"]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec["seven_gates_exact_pass"] is not False:
        print("SEVEN_PASS_FLAG", rec["case_id"]); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=2 REJECT=1 PASS_PROPOSAL=0")
PY

echo "== uniqueness vs pinned canonical88 =="
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

echo "== advisory identity =="
python3 - << PY
import json, sys
from pathlib import Path
f7 = json.loads(Path("$ADV_F7").read_text())
if f7.get("id") != "GHSA-f7fh-qg34-x2xh":
    print("F7FH_ID"); sys.exit(1)
if "json/version" not in f7.get("summary", "").lower() and "json/version" not in f7.get("details", "").lower():
    print("F7FH_SUMMARY"); sys.exit(1)
if not f7.get("database_specific", {}).get("github_reviewed"):
    print("F7FH_NOT_REVIEWED"); sys.exit(1)
details = f7.get("details", "")
if "webSocketDebuggerUrl" not in details:
    print("F7FH_IMPACT"); sys.exit(1)
if "direct CDP WebSocket" not in details:
    print("F7FH_TECH"); sys.exit(1)
cw = json.loads(Path("$ADV_CW").read_text())
if cw.get("type") != "unreviewed":
    print("CW23_TYPE", cw.get("type")); sys.exit(1)
if cw.get("github_reviewed_at") not in (None, ""):
    print("CW23_REVIEWED"); sys.exit(1)
if cw.get("vulnerabilities"):
    print("CW23_VULNS"); sys.exit(1)
if cw.get("repository_advisory_url") not in (None, ""):
    print("CW23_REPO_URL"); sys.exit(1)
repo = json.loads(Path("$ADV_CW_REPO").read_text())
if repo.get("status") != "404" and repo.get("message") != "Not Found":
    print("CW23_REPO_NOT_404"); sys.exit(1)
vg = json.loads(Path("$ADV_92").read_text())
if vg.get("state") != "published":
    print("92VG_STATE"); sys.exit(1)
if vg.get("withdrawn_at") not in (None, ""):
    print("92VG_WITHDRAWN"); sys.exit(1)
desc = vg.get("description", "")
if "XDocument.Load" not in desc:
    print("92VG_XDOCUMENT"); sys.exit(1)
if "4939a1b" not in desc:
    print("92VG_NAMED_FIX"); sys.exit(1)
print("ADVISORY_OK")
PY

echo "== git facts =="
[[ -d $OC && -d $IR && -d $SC ]] || fail "CLONE_ABSENT"

# F7FH
C=75602014dbc5088b80e9b236146dfe5fdcc59e20
F=bc356cc8c2beaa747c71dd86cceab8f804699665
P=3cf75f760c0f89adbad9415b3d5fdb5b83f2dd82
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "F7FH_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "F7FH_MARKER"
gitq -C "$OC" grep -q json/version "$P" -- src/browser/cdp.ts || fail "F7FH_PARENT_HOP"
if gitq -C "$OC" grep -q isWebSocketUrl "$P" -- src/browser; then
  fail "F7FH_PARENT_HAS_ISWS"
fi
gitq -C "$OC" grep -q isWebSocketUrl "$C" -- src/browser/cdp.ts || fail "F7FH_CAND_ISWS"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"direct CDP websocket"* ]] || fail "F7FH_FIX_SUBJ $fsubj"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.4.1 || fail "F7FH_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.1 && fail "F7FH_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.5 || fail "F7FH_FIX_TAG"
echo "F7FH_OK"

# CW23
M=b20880c12837df41d7f49de6a33ebe4562b27c5b
CAR=b58b421535e593b165393846a4c37d74283060ad
FX=a1d7c3ba428ed575900469b207fb5668725f9a71
MP=f3a0c71bc759bc91c7330ff59b575d37b48eb3b5
gitq -C "$IR" cat-file -t "$M" >/dev/null
gitq -C "$IR" cat-file -t "$CAR" >/dev/null
gitq -C "$IR" cat-file -t "$FX" >/dev/null
parents=$(gitq -C "$IR" rev-list --parents -n 1 "$M")
[[ $parents == "$M $MP" ]] || fail "CW23_PARENTS $parents"
gitq -C "$IR" cat-file -p "$M" | LC_ALL=C grep -q 'Co-Authored-By: Claude Sonnet 4.6' || fail "CW23_MARKER"
gitq -C "$IR" merge-base --is-ancestor "$M" "$CAR" && fail "CW23_MEMBER_ANC_CARRIER" || true
gitq -C "$IR" merge-base --is-ancestor "$M" ironclaw-v0.29.1 && fail "CW23_MEMBER_IN_VULN" || true
gitq -C "$IR" merge-base --is-ancestor "$CAR" ironclaw-v0.29.1 || fail "CW23_CARRIER_ANY_PARENT"
fp_hit=$(gitq -C "$IR" log --first-parent --pretty=%H ironclaw-v0.29.1 | grep -c "^${CAR}$" || true)
[[ $fp_hit == 0 ]] || fail "CW23_CARRIER_FIRST_PARENT"
mb=$(gitq -C "$IR" rev-parse "${M}:src/tools/builtin/shell.rs")
cb=$(gitq -C "$IR" rev-parse "${CAR}:src/tools/builtin/shell.rs")
vb=$(gitq -C "$IR" rev-parse "ironclaw-v0.29.1:src/tools/builtin/shell.rs")
fb=$(gitq -C "$IR" rev-parse "${FX}:src/tools/builtin/shell.rs")
[[ $mb != "$cb" && $mb != "$vb" && $vb != "$fb" ]] || fail "CW23_BLOB_EQUAL"
[[ $mb == 4798d0c3c1a9a5c59c30cd878e9fb85564cddacf ]] || fail "CW23_MEMBER_BLOB $mb"
[[ $vb == 8f574e900eecc8aa344fe8989641689b4cbfe659 ]] || fail "CW23_VULN_BLOB $vb"
gitq -C "$IR" merge-base --is-ancestor "$FX" ironclaw-v1.0.0 || fail "CW23_FIX_TAG"
echo "CW23_OK"

# 92VG
C=d1944bca6e984665fb98f5ea824c6c370fd618d6
F=9d0ba808afd143ede448026a5dc681bfdc5c138d
P=5fbda15f093015f33929b3ebc8d0a943d5fa5592
gitq -C "$SC" cat-file -t "$C" >/dev/null
gitq -C "$SC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$SC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "92VG_PARENTS $parents"
gitq -C "$SC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "92VG_MARKER"
got0=$(gitq -C "$SC" rev-parse "v1.0.0^{commit}")
got2=$(gitq -C "$SC" rev-parse "v1.0.2^{commit}")
[[ $got0 == "$C" ]] || fail "92VG_V100 $got0"
[[ $got2 == "$F" ]] || fail "92VG_V102 $got2"
names=$(gitq -C "$SC" diff-tree --no-commit-id --name-only -r "$C")
print -r -- "$names" | LC_ALL=C grep -q '\.cs$' && fail "92VG_CS_IN_DIFF" || true
tree=$(gitq -C "$SC" ls-tree -r --name-only "$C")
print -r -- "$tree" | LC_ALL=C grep -q '\.cs$' && fail "92VG_CS_IN_TREE" || true
print -r -- "$names" | LC_ALL=C grep -q 'SolidCAM.GPPL.Server.exe' || fail "92VG_NO_EXE"
git_expect_fail -C "$SC" cat-file -t 4939a1b || fail "92VG_ADVISORY_FIX_PRESENT"
gitq -C "$SC" merge-base --is-ancestor "$C" v1.0.1 || fail "92VG_CAND_V101"
gitq -C "$SC" merge-base --is-ancestor "$F" v1.0.1 && fail "92VG_FIX_IN_V101" || true
echo "92VG_OK"

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

echo "REPLAY_OK reviewed=3 PASS_proposal=0 NARROW=2 REJECT=1 UNKNOWN=0 BLOCKED=0"
