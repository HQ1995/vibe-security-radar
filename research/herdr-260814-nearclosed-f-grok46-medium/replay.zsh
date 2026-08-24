#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-f-grok46-medium.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-f-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
LR=${LR:-/home/hanqing/.cache/cve-analyzer/repos/langroid_langroid}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
CR=${CR:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/clones/churchcrm}
ADV_REV=${ADV_REV:-/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database}
ADV_X34=${ADV_X34:-$ADV_REV/advisories/github-reviewed/2026/02/GHSA-x34r-63hx-w57f/GHSA-x34r-63hx-w57f.json}
ADV_X34_REPO=${ADV_X34_REPO:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/pages/repo-advisory/langroid__langroid__ghsa-x34r-63hx-w57f.json}
ADV_7JX=${ADV_7JX:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/pages/repo-advisory/openclaw__openclaw__ghsa-7jx6-764p-fgg9.json}
ADV_3J8=${ADV_3J8:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/pages/repo-advisory/ChurchCRM__CRM__ghsa-3j8q-fwpj-f8j5.json}
ADV_JJC=${ADV_JJC:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/pages/repo-advisory/ChurchCRM__CRM__ghsa-jjcj-h3cm-p7x7.json}
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
hash_check "$ADV_X34" \
  0c16293e6f117e0540ed811aa6dcaeba22053db47d96f6574cf1b7212fc212ea
hash_check "$ADV_X34_REPO" \
  b6313c7ce0d9b2a61651488e6b35f33ac7582c13cd6fac6b34b27b27729ad313
hash_check "$ADV_7JX" \
  cff87da200bdc6eb32cd7881483bde231a14e0d5fbb9f1cf689573bf423c9e33
hash_check "$ADV_3J8" \
  d7a8e07d1ec5ccbb518fc23d52960d24f0b23e9b2efa205bc7772fbfa2ca8842
hash_check "$ADV_JJC" \
  6adf183d73f119c35d70d387a1739669197404996e2568ab54e76cf8c3f0fc9e

echo "== conservation 4=4+0 =="
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
    "GHSA-X34R-63HX-W57F",
    "GHSA-7JX6-764P-FGG9",
    "GHSA-3J8Q-FWPJ-F8J5",
    "GHSA-JJCJ-H3CM-P7X7",
]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [156, 198, 200, 200]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 0 or n_nar != 2 or n_rej != 2 or len(cas) != 4:
    print("COUNT_FAIL", n_pass, n_nar, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "4=4+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != []:
    print("PASS_LIST_FAIL", res["pass_proposals"]); sys.exit(1)
if res["canonical_strict_count_untouched"] != 88 or res["counts"]["countable_pass"] != 0:
    print("FLAG_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if k not in g:
            print("GATE_MISSING", rec["case_id"], k); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("proposed_pass") is not False or rec.get("seven_gates_exact_pass") is not False:
        print("PROPOSAL_DRIFT", rec["case_id"]); sys.exit(1)
if cas[0]["verdict"] != "REJECT" or cas[0]["gates"]["topology_gate"] != "FAIL":
    print("X34R_NOT_REJECT"); sys.exit(1)
if cas[0]["gates"]["ai_hunk_gate"] != "FAIL":
    print("X34R_AI_NOT_FAIL"); sys.exit(1)
if cas[0].get("authorship_transfer") is not False:
    print("X34R_TRANSFER"); sys.exit(1)
if cas[1]["verdict"] != "NARROW" or cas[1]["gates"]["but_for_gate"] != "NARROW":
    print("7JX6_NOT_NARROW"); sys.exit(1)
if cas[1]["contribution_class"] != "AI_INCOMPLETE_REMEDIATION":
    print("7JX6_CLASS"); sys.exit(1)
if cas[1]["patch_delta_rule"]["ghsa_explicitly_names_residual_of_that_boundary"] is not False:
    print("7JX6_PATCH_DELTA"); sys.exit(1)
if cas[2]["verdict"] != "NARROW" or cas[2]["gates"]["identity_gate"] != "NARROW":
    print("3J8Q_NOT_NARROW"); sys.exit(1)
if cas[3]["verdict"] != "REJECT" or cas[3]["gates"]["uniqueness_gate"] != "FAIL":
    print("JJCJ_NOT_REJECT"); sys.exit(1)
if cas[3].get("duplicate_mechanism_of") != "GHSA-3J8Q-FWPJ-F8J5":
    print("JJCJ_DUP_FLAG"); sys.exit(1)
print("CONSERVATION_OK 4=4+0 NARROW=2 REJECT=2 PASS_PROPOSAL=0")
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
[[ -d $LR && -d $OC && -d $CR ]] || fail "CLONE_ABSENT"

# X34R ordinal 156
C=b1c45e3fc0f3578a5dea9844c0216044321ae1c8
CAR=0d9e4a7bb3ae2eef8d38f2e970ff916599a2b2a6
F=30abbc1a854dee22fbd2f8b2f575dfdabdb603ea
P=556196b88149b5b494ad9e676f9923001f9aecb9
TC=langroid/agent/special/table_chat_agent.py
PU=langroid/utils/pandas_utils.py
gitq -C "$LR" cat-file -t "$C" >/dev/null
gitq -C "$LR" cat-file -t "$CAR" >/dev/null
gitq -C "$LR" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$LR" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "X34R_PARENTS $parents"
gitq -C "$LR" cat-file -p "$C" | LC_ALL=C grep -q 'Co-authored-by: Copilot' || fail "X34R_MEMBER_MARKER"
gitq -C "$LR" cat-file -p "$CAR" | LC_ALL=C grep -q 'Co-authored-by: Copilot' || fail "X34R_CAR_COPILOT"
gitq -C "$LR" cat-file -p "$CAR" | LC_ALL=C grep -q 'Co-Authored-By: Claude' || fail "X34R_CAR_CLAUDE"
gitq -C "$LR" grep -q 'if not config.full_eval' "$P" -- "$TC" || fail "X34R_PARENT_NAMEERROR"
gitq -C "$LR" grep -q 'if not self.config.full_eval' "$C" -- "$TC" || fail "X34R_MEMBER_SELF_CONFIG"
gitq -C "$LR" grep -q 'if not self.config.full_eval' "$CAR" -- "$TC" || fail "X34R_CAR_SELF_CONFIG"
files=$(gitq -C "$LR" diff-tree --no-commit-id --name-only -r "$C")
[[ $files == "$TC" ]] || fail "X34R_MEMBER_FILES $files"
blob_p=$(gitq -C "$LR" rev-parse "${P}:${PU}")
blob_c=$(gitq -C "$LR" rev-parse "${C}:${PU}")
[[ $blob_p == "$blob_c" ]] || fail "X34R_PANDAS_MEMBER_CHANGED $blob_p $blob_c"
blob_m=$(gitq -C "$LR" rev-parse "${C}:${TC}")
blob_car=$(gitq -C "$LR" rev-parse "${CAR}:${TC}")
blob_v=$(gitq -C "$LR" rev-parse "0.59.31:$TC")
blob_f=$(gitq -C "$LR" rev-parse "${F}:${TC}")
[[ $blob_m == ba8bc96c26093765086ccaef31f48c24b9101db0 ]] || fail "X34R_MEMBER_TC $blob_m"
[[ $blob_car == c7b320658aaa0cbb6d9bae916485780f3ae7ff31 ]] || fail "X34R_CAR_TC $blob_car"
[[ $blob_v == 28c3c288b1198f8b7b539c7fc11bbbeb4a7be79f ]] || fail "X34R_VULN_TC $blob_v"
[[ $blob_f == "$blob_v" ]] || fail "X34R_FIX_TOUCHED_TC $blob_f"
git_expect_fail -C "$LR" merge-base --is-ancestor "$C" "$CAR" || fail "X34R_MEMBER_OF_CARRIER"
git_expect_fail -C "$LR" merge-base --is-ancestor "$C" 0.59.31 || fail "X34R_MEMBER_OF_TAG"
gitq -C "$LR" merge-base --is-ancestor "$CAR" 0.59.31 || fail "X34R_CAR_TAG"
git_expect_fail -C "$LR" merge-base --is-ancestor "$F" 0.59.31 || fail "X34R_FIX_IN_VULN"
gitq -C "$LR" merge-base --is-ancestor "$F" 0.59.32 || fail "X34R_FIX_TAG"
git_expect_fail -C "$LR" grep -q visit_Attribute 0.59.31 -- "$PU" || fail "X34R_VULN_HAS_VISIT"
gitq -C "$LR" grep -q visit_Attribute "$F" -- "$PU" || fail "X34R_FIX_VISIT"
peel=$(gitq -C "$LR" rev-parse '0.59.31^{commit}')
[[ $peel == 6815fb6814a37c47e1908f326a12aaf6e01c373a ]] || fail "X34R_PEEL31 $peel"
peel=$(gitq -C "$LR" rev-parse '0.59.32^{commit}')
[[ $peel == 65f2e5ecafafdb5027236a94253021fce287cdac ]] || fail "X34R_PEEL32 $peel"
echo "X34R_OK"

# 7JX6 ordinal 198
C=6e498a1f628873b16aaeeecfbc3dc249b9a1d8bf
F=08a73dbe4b09e6a15db591649ddec81b48c59584
P=2ec1a27c9fba56ac30e4a8b35a89343029be9492
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "7JX6_PARENTS $parents"
gitq -C "$OC" log -1 --format='%s' "$C" | LC_ALL=C grep -q '\[AI\]' || fail "7JX6_MARKER"
gitq -C "$OC" show "${P}:extensions/qqbot/src/bridge/approval/capability.ts" >"$REPLAY_TMP/7jx6.parent.cap.ts"
gitq -C "$OC" show "${C}:extensions/qqbot/src/exec-approvals.ts" >"$REPLAY_TMP/7jx6.cand.ts"
gitq -C "$OC" show "${F}:extensions/qqbot/src/exec-approvals.ts" >"$REPLAY_TMP/7jx6.fix.ts"
gitq -C "$OC" show "${F}:extensions/qqbot/src/engine/gateway/interaction-handler.ts" >"$REPLAY_TMP/7jx6.fix.ih.ts"
python3 - "$REPLAY_TMP/7jx6.parent.cap.ts" <<'PY' || fail "7JX6_PARENT_HAS_AUTHORIZE"
import sys
t=open(sys.argv[1]).read()
if "authorizeQQBotApprovalAction" in t:
    raise SystemExit("PARENT_HAS")
print("7JX6_PARENT_LACKS_OK")
PY
python3 - "$REPLAY_TMP/7jx6.cand.ts" "$REPLAY_TMP/7jx6.fix.ts" "$REPLAY_TMP/7jx6.fix.ih.ts" <<'PY' || fail "7JX6_IMPLICIT"
import sys
cand=open(sys.argv[1]).read()
fix=open(sys.argv[2]).read()
ih=open(sys.argv[3]).read()
fn="export function authorizeQQBotApprovalAction"
cb=cand.split(fn,1)[1].split("export ",1)[0]
fb=fix.split(fn,1)[1].split("export ",1)[0]
if "authorizeQQBotApprovalAction" not in cand:
    raise SystemExit("CAND_NO_AUTHORIZE")
if "markImplicitSameChatApprovalAuthorization" in cb:
    raise SystemExit("CAND_ALREADY_MARKED")
if "authorized: true" not in cb:
    raise SystemExit("CAND_NO_TRUE")
if "markImplicitSameChatApprovalAuthorization" not in fb:
    raise SystemExit("FIX_NO_MARK")
if "resolveSlashCommandAuth" not in ih:
    raise SystemExit("FIX_NO_SLASH")
print("7JX6_IMPLICIT_OK")
PY
blob_c=$(gitq -C "$OC" rev-parse "${C}:extensions/qqbot/src/exec-approvals.ts")
blob_v=$(gitq -C "$OC" rev-parse "v2026.5.26:extensions/qqbot/src/exec-approvals.ts")
blob_f=$(gitq -C "$OC" rev-parse "${F}:extensions/qqbot/src/exec-approvals.ts")
blob_t=$(gitq -C "$OC" rev-parse "v2026.5.27:extensions/qqbot/src/exec-approvals.ts")
[[ $blob_c == "$blob_v" ]] || fail "7JX6_VULN_BLOB $blob_c $blob_v"
[[ $blob_f == "$blob_t" ]] || fail "7JX6_FIX_BLOB $blob_f $blob_t"
[[ $blob_c != "$blob_f" ]] || fail "7JX6_BLOB_EQUAL"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.5.26 || fail "7JX6_CAND_TAG"
git_expect_fail -C "$OC" merge-base --is-ancestor "$F" v2026.5.26 || fail "7JX6_FIX_IN_VULN"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.5.27 || fail "7JX6_FIX_TAG"
python3 - "$ADV_7JX" <<'PY' || fail "7JX6_GHSA"
import json,sys
d=json.load(open(sys.argv[1]))
assert d["state"]=="published"
assert d.get("withdrawn_at") in (None,"")
s=(d.get("summary") or "")
if "authorizeQQBotApprovalAction" in s or "same-chat" in s.lower():
    raise SystemExit("GHSA_NAMES_RESIDUAL")
if "non-allowlisted" not in s:
    raise SystemExit("GHSA_SUMMARY")
print("7JX6_GHSA_GENERIC_OK")
PY
echo "7JX6_OK"

# 3J8Q / JJCJ ordinal 200
C=b3edc22580116beb6bc8463d1876f2a7c9b96a28
F=83c19611701b96300872390071440151360dfb48
P=51e49adbc1b3b40ec93988267dcad7ffa02d0372
gitq -C "$CR" cat-file -t "$C" >/dev/null
gitq -C "$CR" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$CR" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "3J8Q_PARENTS $parents"
gitq -C "$CR" cat-file -p "$C" | LC_ALL=C grep -q 'Co-authored-by: Claude Sonnet 4.6' || fail "3J8Q_MARKER"
git_expect_fail -C "$CR" cat-file -e "${P}:src/api/routes/people/notes.php" || fail "3J8Q_PARENT_HAS_NOTES"
gitq -C "$CR" cat-file -e "${C}:src/api/routes/people/notes.php" >/dev/null || fail "3J8Q_CAND_NOTES"
gitq -C "$CR" ls-tree --name-only "$P" -- src/api/routes/people/people-family.php | LC_ALL=C grep -q people-family.php || fail "JJCJ_PARENT_FAMILY"
git_expect_fail -C "$CR" cat-file -e "${P}:src/api/routes/people/timeline.php" || fail "JJCJ_PARENT_HAS_TIMELINE"
files=$(gitq -C "$CR" diff-tree --no-commit-id --name-only -r "$C")
print -r -- "$files" | LC_ALL=C grep -q 'src/api/routes/people/notes.php' || fail "3J8Q_CAND_FILE"
print -r -- "$files" | LC_ALL=C grep -q timeline.php && fail "3J8Q_CAND_ADDS_TIMELINE" || true
git_expect_fail -C "$CR" grep -q canEditPerson "$C" -- src/api/routes/people/notes.php || fail "3J8Q_CAND_HAS_CANEDIT"
git_expect_fail -C "$CR" grep -q canEditPerson 7.3.3 -- src/api/routes/people/notes.php || fail "3J8Q_VULN_HAS_CANEDIT"
gitq -C "$CR" grep -q canEditPerson "$F" -- src/api/routes/people/notes.php || fail "3J8Q_FIX_CANEDIT"
gitq -C "$CR" log -1 --format='%B' "$F" | LC_ALL=C grep -q 'GHSA-jjcj-h3cm-p7x7' || fail "3J8Q_FIX_NAMES_JJCJ"
blob_c=$(gitq -C "$CR" rev-parse "${C}:src/api/routes/people/notes.php")
blob_v=$(gitq -C "$CR" rev-parse "7.3.3:src/api/routes/people/notes.php")
blob_f=$(gitq -C "$CR" rev-parse "${F}:src/api/routes/people/notes.php")
blob_t=$(gitq -C "$CR" rev-parse "7.4.0:src/api/routes/people/notes.php")
[[ $blob_c == 00773c583aa923494ba85ca84ef442275f8833c1 ]] || fail "3J8Q_CAND_BLOB $blob_c"
[[ $blob_v == 2df274e2920dc3b458e074f87cf59cd755494dbc ]] || fail "3J8Q_VULN_BLOB $blob_v"
[[ $blob_f == "$blob_t" ]] || fail "3J8Q_FIX_BLOB $blob_f $blob_t"
[[ $blob_c != "$blob_v" ]] || fail "3J8Q_BLOB_EQUAL_VULN"
gitq -C "$CR" merge-base --is-ancestor "$C" 7.3.3 || fail "3J8Q_CAND_TAG"
git_expect_fail -C "$CR" merge-base --is-ancestor "$F" 7.3.3 || fail "3J8Q_FIX_IN_VULN"
gitq -C "$CR" merge-base --is-ancestor "$F" 7.4.0 || fail "3J8Q_FIX_TAG"
peel=$(gitq -C "$CR" rev-parse '7.3.3^{commit}')
[[ $peel == da7ffe51e09dfab869750d6f56e94e03960346d1 ]] || fail "3J8Q_PEEL733 $peel"
peel=$(gitq -C "$CR" rev-parse '7.4.0^{commit}')
[[ $peel == 66a731a1cf9b56e96b9a27de1bcb16364bbd986a ]] || fail "3J8Q_PEEL740 $peel"
python3 - "$ADV_3J8" "$ADV_JJC" <<'PY' || fail "ORD200_IDS"
import json,sys
a=json.load(open(sys.argv[1]))
b=json.load(open(sys.argv[2]))
assert a["state"]=="published" and b["state"]=="published"
assert a.get("withdrawn_at") in (None,"")
assert b.get("withdrawn_at") in (None,"")
ia=set(i["value"].upper() for i in a["identifiers"])
ib=set(i["value"].upper() for i in b["identifiers"])
if ia & ib:
    raise SystemExit("FORMAL_ALIAS")
desc=a.get("description") or ""
if "VULN-02" not in desc or "notes.php" not in desc:
    raise SystemExit("3J8Q_NOTES")
if "VULN-01" not in desc:
    raise SystemExit("3J8Q_NOT_OMNIBUS")
d=(b.get("description") or "")
if "/api/family/{familyId}/notes" not in d:
    raise SystemExit("JJCJ_NOTES")
if "/api/family/{familyId}" not in d or "timeline" not in d:
    raise SystemExit("JJCJ_SIBLINGS")
print("ORD200_NARROW_SCOPE_OK")
PY
echo "ORD200_OK"

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

echo "REPLAY_OK reviewed=4 PASS_proposal=0 NARROW=2 REJECT=2 UNKNOWN=0 BLOCKED=0"
