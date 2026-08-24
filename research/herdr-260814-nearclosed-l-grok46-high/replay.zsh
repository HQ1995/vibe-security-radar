#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-l-grok46-high.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-l-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
CRM=${CRM:-/home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm}
ADV=${ADV:-/home/hanqing/.cache/cve-analyzer/advisory-database}
ADV_G353=${ADV_G353:-$ADV/advisories/github-reviewed/2026/03/GHSA-g353-mgv3-8pcj/GHSA-g353-mgv3-8pcj.json}
ADV_XH72=${ADV_XH72:-$ADV/advisories/github-reviewed/2026/04/GHSA-xh72-v6v9-mwhc/GHSA-xh72-v6v9-mwhc.json}
ADV_Q447=${ADV_Q447:-$ADV/advisories/github-reviewed/2026/02/GHSA-q447-rj3r-2cgh/GHSA-q447-rj3r-2cgh.json}
ADV_MFMP=${ADV_MFMP:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/pages/repo-advisory/ChurchCRM__CRM__ghsa-mfmp-q643-vj39.json}
ADV_M649=${ADV_M649:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-b/pages/repo-advisory/ChurchCRM__CRM__ghsa-m649-24q9-q6r4.json}
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/summary.json" \
  5222879219a975fa4388f3f07f5c62cd6687a642b6509afe48a4250fb4be81ef
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical90/ledger.jsonl" \
  daf706e14d514ad62d197e61aa8ec7f52eefd958bc19a4a7c58591a0be8654ec
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ADV_G353" \
  efd6c3ef3fd0c944db26b799456c9298d733dad672756f0a2ea8d1652265006a
hash_check "$ADV_XH72" \
  463dc5cff66f0f528929aeefc4cbaa286dfabe01173ab088045679dce6004914
hash_check "$ADV_Q447" \
  9d5a4294f2d0886bfbf8c4130ab9edc803c36190d068abda475b798009e0c812
hash_check "$ADV_MFMP" \
  03ce95709380bf8b82e38b1a50d62dc2879d584469ee9bddd5b6f4bc62824d1a
hash_check "$ADV_M649" \
  cc616c8adcf6534958a19a1b30481c875854d92ab718bfc6b87ed5fc62b76a09
adv_head=$(gitq -C "$ADV" rev-parse HEAD)
[[ $adv_head == 39d8887723797efc1804585dd06585c9fd751226 ]] || fail "ADV_HEAD $adv_head"

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
    "GHSA-G353-MGV3-8PCJ",
    "GHSA-MFMP-Q643-VJ39",
    "GHSA-M649-24Q9-Q6R4",
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
if [a["fp211_ordinal"] for a in ass] != [124, 183, 184]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 3 or n_nar != 0 or n_rej != 0 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposal_ids"] != want:
    print("PASS_IDS_FAIL", res["pass_proposal_ids"]); sys.exit(1)
if res["canonical_strict_count_untouched"] != 90 or res["counts"]["countable_pass"] != 0:
    print("FLAG_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if k not in g or g[k] != "PASS":
            print("GATE_NOT_PASS", rec["case_id"], k, g.get(k)); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER", rec["case_id"]); sys.exit(1)
    if rec.get("proposed_pass") is not True or rec.get("seven_gates_exact_pass") is not True:
        print("PROPOSAL_DRIFT", rec["case_id"]); sys.exit(1)
    if rec["verdict"] != "PASS_PROPOSAL":
        print("NOT_PASS", rec["case_id"]); sys.exit(1)
    if rec["contribution_class"] != "AI_NEW_SURFACE_CONTRIBUTOR":
        print("CLASS_FAIL", rec["case_id"]); sys.exit(1)
    if rec.get("n_parents") != 1:
        print("PARENTS", rec["case_id"]); sys.exit(1)
if cas[0]["candidate_set"] != ["5c2cb6c591e4b63c2df0549ad2202403256e2a96"]:
    print("G353_CAND"); sys.exit(1)
if "b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517" in cas[0]["candidate_set"]:
    print("G353_MEMBER_IN_CAND"); sys.exit(1)
if cas[0].get("distinct_from_xh72") is not True or cas[0].get("distinct_from_q447") is not True:
    print("G353_DISTINCT_FLAGS"); sys.exit(1)
if cas[1]["candidate_set"] != ["80a3e620a4aa046c2644937a5a2fa799a2e750d6"]:
    print("MFMP_CAND"); sys.exit(1)
if "0ea20d01050cd25b30bca1418bb821fbd3bcb7ab" in cas[1]["candidate_set"]:
    print("MFMP_MEMBER_IN_CAND"); sys.exit(1)
if cas[1].get("distinct_from_m649") is not True:
    print("MFMP_DISTINCT_FLAG"); sys.exit(1)
if cas[2]["candidate_set"] != ["80a3e620a4aa046c2644937a5a2fa799a2e750d6"]:
    print("M649_CAND"); sys.exit(1)
if cas[2]["minimum_fix_set"] != ["ae2b73550452056cc45a65a4165340ae17c2c3e5"]:
    print("M649_FIX"); sys.exit(1)
if cas[2].get("distinct_from_mfmp") is not True:
    print("M649_DISTINCT_FLAG"); sys.exit(1)
if cas[1]["candidate_set"] != cas[2]["candidate_set"]:
    print("SHARED_CAND_MISMATCH"); sys.exit(1)
if cas[1]["case_id"] == cas[2]["case_id"]:
    print("DUP_CASE_ID"); sys.exit(1)
print("CONSERVATION_OK 3=3+0 PASS_PROPOSAL=3")
PY

echo "== uniqueness vs canonical90 and sibling identities =="
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
if len(strict) != 90:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
g353 = json.loads(Path("$ADV_G353").read_text())
xh72 = json.loads(Path("$ADV_XH72").read_text())
q447 = json.loads(Path("$ADV_Q447").read_text())
mfmp = json.loads(Path("$ADV_MFMP").read_text())
m649 = json.loads(Path("$ADV_M649").read_text())
ids353 = {g353.get("id","").lower()} | {x.lower() for x in g353.get("aliases", [])}
idsxh = {xh72.get("id","").lower()} | {x.lower() for x in xh72.get("aliases", [])}
idsq = {q447.get("id","").lower()} | {x.lower() for x in q447.get("aliases", [])}
if ids353 & idsxh:
    print("ALIAS_OVERLAP_XH72", ids353 & idsxh); sys.exit(1)
if ids353 & idsq:
    print("ALIAS_OVERLAP_Q447", ids353 & idsq); sys.exit(1)
if g353.get("aliases") != ["CVE-2026-32974"]:
    print("G353_ALIAS", g353.get("aliases")); sys.exit(1)
if xh72.get("aliases") != ["CVE-2026-44109"]:
    print("XH72_ALIAS", xh72.get("aliases")); sys.exit(1)
if mfmp.get("ghsa_id","").lower() != "ghsa-mfmp-q643-vj39":
    print("MFMP_ID"); sys.exit(1)
if m649.get("ghsa_id","").lower() != "ghsa-m649-24q9-q6r4":
    print("M649_ID"); sys.exit(1)
if mfmp.get("state") != "published" or m649.get("state") != "published":
    print("NOT_PUBLISHED"); sys.exit(1)
if mfmp.get("withdrawn_at") not in (None, "") or m649.get("withdrawn_at") not in (None, ""):
    print("WITHDRAWN"); sys.exit(1)
if mfmp.get("ghsa_id") == m649.get("ghsa_id"):
    print("MFMP_M649_SAME_ID"); sys.exit(1)
desc = (m649.get("description") or "") + (m649.get("summary") or "")
if "GHSA-mfmp-q643-vj39" not in desc:
    print("M649_MISSING_MFMP_DISTINCTION"); sys.exit(1)
if "escapeHtml" not in desc or "attribute" not in desc.lower():
    print("M649_MISSING_ENCODER_DISTINCTION"); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "183_184_DISTINCT", "G353_DISTINCT_FROM_XH72_Q447")
PY

echo "== git facts =="
[[ -d $OC && -d $CRM ]] || fail "CLONE_ABSENT"

# G353 ordinal 124
SQ=5c2cb6c591e4b63c2df0549ad2202403256e2a96
M=b0c67ea0b5ae60a8f53b883ecfbc18da3ebbb517
F=7844bc89a1612800810617c823eb0c76ef945804
P=49c60e9065d98a6848e62c717315eb91eeaa6038
F496=496ca3a6373a3c1203b7a0b82ed8c93acfbb22e0
F82=c8003f1b33ed2924be5f62131bd28742c5a41aae
MON=extensions/feishu/src/monitor.ts
SCH=extensions/feishu/src/config-schema.ts
gitq -C "$OC" cat-file -t "$SQ" >/dev/null
gitq -C "$OC" cat-file -t "$M" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $P" ]] || fail "G353_PARENTS $parents"
gitq -C "$OC" cat-file -p "$SQ" | LC_ALL=C grep -q 'Co-authored-by: Claude Opus 4.6' || fail "G353_MARKER"
gitq -C "$OC" grep -q 'webhook mode not implemented in monitor' "$P" -- "$MON" || fail "G353_PARENT_UNIMPL"
git_expect_fail -C "$OC" grep -q adaptDefault "$P" -- extensions/feishu || fail "G353_PARENT_HAS_ADAPT"
gitq -C "$OC" grep -q adaptDefault "$SQ" -- "$MON" || fail "G353_SQUASH_ADAPT"
gitq -C "$OC" grep -q 'encryptKey: z.string().optional()' "$SQ" -- "$SCH" || fail "G353_SQUASH_OPTIONAL"
gitq -C "$OC" grep -q 'connectionMode="webhook" requires channels.feishu.encryptKey' "$F" -- "$SCH" || fail "G353_FIX_REQUIRE"
pk=$(gitq -C "$OC" log --first-parent -S adaptDefault --format='%H' v2026.2.12 -- extensions/feishu)
print -r -- "$pk" | LC_ALL=C grep -q '^5c2cb6c591e4b63c2df0549ad2202403256e2a96' || fail "G353_PICKAXE $pk"
blob_m=$(gitq -C "$OC" rev-parse "${M}:$MON")
blob_sq=$(gitq -C "$OC" rev-parse "${SQ}:$MON")
blob_p=$(gitq -C "$OC" rev-parse "${P}:$MON")
blob_v12=$(gitq -C "$OC" rev-parse "v2026.2.12:$MON")
[[ $blob_p == 24ba1211c9c10be9b895674831abdf92fd296a6c ]] || fail "G353_PARENT_BLOB $blob_p"
[[ $blob_sq == 31a890c2f92da2586c0c1f96c1d47a71100be610 ]] || fail "G353_SQUASH_BLOB $blob_sq"
[[ $blob_m == "$blob_sq" && $blob_sq == "$blob_v12" ]] || fail "G353_SHIPPED_BLOB"
blob_fsch=$(gitq -C "$OC" rev-parse "${F}:$SCH")
blob_tsch=$(gitq -C "$OC" rev-parse "v2026.3.12:$SCH")
[[ $blob_fsch == b78404de6f821f4a630167b09275aa450d79fec1 ]] || fail "G353_FIX_SCH $blob_fsch"
[[ $blob_fsch == "$blob_tsch" ]] || fail "G353_FIX_TAG_SCH"
git_expect_fail -C "$OC" merge-base --is-ancestor "$M" "$SQ" || fail "G353_MEMBER_ANC_SQUASH"
git_expect_fail -C "$OC" merge-base --is-ancestor "$M" v2026.3.11 || fail "G353_MEMBER_IN_VULN"
gitq -C "$OC" merge-base --is-ancestor "$SQ" v2026.3.11 || fail "G353_SQUASH_TAG"
git_expect_fail -C "$OC" merge-base --is-ancestor "$F" v2026.3.11 || fail "G353_FIX_IN_VULN"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.3.12 || fail "G353_FIX_TAG"
git_expect_fail -C "$OC" merge-base --is-ancestor "$F496" v2026.3.11 || fail "G353_496_IN_VULN"
gitq -C "$OC" merge-base --is-ancestor "$F496" v2026.3.12 || fail "G353_496_TAG"
git_expect_fail -C "$OC" merge-base --is-ancestor "$F82" v2026.3.12 || fail "G353_XH72_FIX_IN_312"
gitq -C "$OC" merge-base --is-ancestor "$F82" v2026.4.15 || fail "G353_XH72_FIX_TAG"
peel=$(gitq -C "$OC" rev-parse 'v2026.3.11^{commit}')
[[ $peel == 29dc65403faf41dc52944c02a0db9fa4b8457395 ]] || fail "G353_PEEL311 $peel"
peel=$(gitq -C "$OC" rev-parse 'v2026.3.12^{commit}')
[[ $peel == 70d7a0854c54c489eaefd56bb406ad885f2b3ea2 ]] || fail "G353_PEEL312 $peel"
python3 - "$ADV_G353" "$ADV_XH72" <<'PY' || fail "G353_GHSA"
import json,sys
a=json.load(open(sys.argv[1]))
x=json.load(open(sys.argv[2]))
assert a["id"].lower()=="ghsa-g353-mgv3-8pcj"
assert a["database_specific"]["github_reviewed"] is True
assert a.get("aliases")==["CVE-2026-32974"]
s=(a.get("details") or "")+(a.get("summary") or "")
assert "verificationToken" in s and "encryptKey" in s
assert x["id"].lower()=="ghsa-xh72-v6v9-mwhc"
assert x.get("aliases")==["CVE-2026-44109"]
print("G353_GHSA_OK")
PY
echo "G353_OK"

# MFMP ordinal 183 and shared squash with 184
SQ=80a3e620a4aa046c2644937a5a2fa799a2e750d6
M=0ea20d01050cd25b30bca1418bb821fbd3bcb7ab
F330=330d0d6a2e6995f017d5943bd3b4806d713b181c
F3B8=3b8b474519272e0d6bb2a7f07c4f1202d2a02bf4
F367=367dd18e4b017a5bc893e1fab1ce55cc34647f08
F563=5631bb084da530732dbef5aa2f3f71c67c739298
FAE=ae2b73550452056cc45a65a4165340ae17c2c3e5
P=9166d9983afcc59df343cf19c7595351d6f750af
GV=src/skin/js/GroupView.js
GR=src/skin/js/GroupRoles.js
gitq -C "$CRM" cat-file -t "$SQ" >/dev/null
gitq -C "$CRM" cat-file -t "$M" >/dev/null
gitq -C "$CRM" cat-file -t "$F330" >/dev/null
gitq -C "$CRM" cat-file -t "$FAE" >/dev/null
parents=$(gitq -C "$CRM" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $P" ]] || fail "MFMP_PARENTS $parents"
gitq -C "$CRM" cat-file -p "$SQ" | LC_ALL=C grep -q 'Co-authored-by: Claude Sonnet 4.6' || fail "MFMP_MARKER"
git_expect_fail -C "$CRM" grep -q buildRolePills "$P" -- "$GV" || fail "MFMP_PARENT_HAS_PILLS"
gitq -C "$CRM" grep -q buildRolePills "$SQ" -- "$GV" || fail "MFMP_SQUASH_PILLS"
gitq -C "$CRM" grep -q 'i18next.t(role.OptionName)' "$SQ" -- "$GV" || fail "MFMP_SQUASH_UNESC"
gitq -C "$CRM" grep -q 'window.CRM.escapeHtml(i18next.t(role.OptionName))' "$F330" -- "$GV" || fail "MFMP_FIX_ESC"
git_expect_fail -C "$CRM" grep -q tel: "$P" -- "$GV" || fail "M649_PARENT_HAS_TEL"
git_expect_fail -C "$CRM" grep -q mailto: "$P" -- "$GV" || fail "M649_PARENT_HAS_MAIL"
gitq -C "$CRM" grep -q 'href="tel:' "$SQ" -- "$GV" || fail "M649_SQUASH_TEL"
gitq -C "$CRM" grep -q 'href="mailto:' "$SQ" -- "$GV" || fail "M649_SQUASH_MAIL"
gitq -C "$CRM" grep -q data-name "$P" -- "$GV" || fail "M649_PARENT_DATANAME"
gitq -C "$CRM" grep -q 'window.CRM.escapeAttribute(data)' "$FAE" -- "$GV" || fail "M649_FIX_ATTR"
pk=$(gitq -C "$CRM" log --first-parent -S buildRolePills --format='%H' 7.4.2 -- "$GV")
print -r -- "$pk" | LC_ALL=C grep -q '^80a3e620a4aa046c2644937a5a2fa799a2e750d6' || fail "MFMP_PICKAXE $pk"
pk=$(gitq -C "$CRM" log --first-parent -S tel: --format='%H' 7.5.1 -- "$GV")
print -r -- "$pk" | LC_ALL=C grep -q '^80a3e620a4aa046c2644937a5a2fa799a2e750d6' || fail "M649_TEL_PICKAXE $pk"
pk=$(gitq -C "$CRM" log --first-parent -S mailto: --format='%H' 7.5.1 -- "$GV")
print -r -- "$pk" | LC_ALL=C grep -q '^80a3e620a4aa046c2644937a5a2fa799a2e750d6' || fail "M649_MAIL_PICKAXE $pk"
pk=$(gitq -C "$CRM" log --first-parent -S data-name --format='%H' 7.5.1 -- "$GV")
print -r -- "$pk" | LC_ALL=C grep -q '^ede1bfb08633e6d1157744e99d176e258fc58aba' || fail "M649_DATANAME_PICKAXE $pk"
blob_p=$(gitq -C "$CRM" rev-parse "${P}:$GV")
blob_m=$(gitq -C "$CRM" rev-parse "${M}:$GV")
blob_sq=$(gitq -C "$CRM" rev-parse "${SQ}:$GV")
blob_742=$(gitq -C "$CRM" rev-parse "7.4.2:$GV")
blob_330=$(gitq -C "$CRM" rev-parse "${F330}:$GV")
blob_743=$(gitq -C "$CRM" rev-parse "7.4.3:$GV")
blob_751=$(gitq -C "$CRM" rev-parse "7.5.1:$GV")
blob_ae=$(gitq -C "$CRM" rev-parse "${FAE}:$GV")
blob_760=$(gitq -C "$CRM" rev-parse "7.6.0:$GV")
[[ $blob_p == 32b10e7ebc49494ba79eaefe8a034c4488855268 ]] || fail "CRM_PARENT_GV $blob_p"
[[ $blob_m == 6d1eae1066039f7e0b32b870cf4c82ddc3b3d815 ]] || fail "CRM_MEMBER_GV $blob_m"
[[ $blob_sq == 23fb4f55f25d6e1e881163891152fe2a3cb6ccaa ]] || fail "CRM_SQUASH_GV $blob_sq"
[[ $blob_m != "$blob_sq" && $blob_sq != "$blob_742" ]] || fail "CRM_BLOB_COLLAPSE"
[[ $blob_330 == 116f1bffe566960053ee9aff479dfa3c02e8d9a7 ]] || fail "MFMP_FIX_GV $blob_330"
[[ $blob_330 == "$blob_743" ]] || fail "MFMP_FIX_TAG_GV"
[[ $blob_ae == 041a9794dc64be0b0c3931edba027ca7a1030a47 ]] || fail "M649_FIX_GV $blob_ae"
[[ $blob_ae == "$blob_760" ]] || fail "M649_FIX_TAG_GV"
blob_grp=$(gitq -C "$CRM" rev-parse "${P}:$GR")
blob_grsq=$(gitq -C "$CRM" rev-parse "${SQ}:$GR")
[[ $blob_grp == 62dfbce14ca2bd0f7ff7a0e5f69152ef289ea2b0 ]] || fail "CRM_PARENT_GR $blob_grp"
[[ $blob_grp == "$blob_grsq" ]] || fail "CRM_GR_CHANGED_BY_SQUASH"
git_expect_fail -C "$CRM" merge-base --is-ancestor "$M" "$SQ" || fail "CRM_MEMBER_ANC_SQUASH"
git_expect_fail -C "$CRM" merge-base --is-ancestor "$M" 7.4.2 || fail "CRM_MEMBER_IN_742"
git_expect_fail -C "$CRM" merge-base --is-ancestor "$M" 7.5.1 || fail "CRM_MEMBER_IN_751"
gitq -C "$CRM" merge-base --is-ancestor "$SQ" 7.4.2 || fail "MFMP_SQUASH_742"
gitq -C "$CRM" merge-base --is-ancestor "$SQ" 7.5.1 || fail "M649_SQUASH_751"
git_expect_fail -C "$CRM" merge-base --is-ancestor "$F330" 7.4.2 || fail "MFMP_FIX_IN_VULN"
gitq -C "$CRM" merge-base --is-ancestor "$F330" 7.4.3 || fail "MFMP_FIX_TAG"
git_expect_fail -C "$CRM" merge-base --is-ancestor "$F3B8" 7.4.3 || fail "MFMP_3B8_IN_TAG"
git_expect_fail -C "$CRM" merge-base --is-ancestor "$F367" 7.4.3 || fail "MFMP_367_IN_TAG"
git_expect_fail -C "$CRM" merge-base --is-ancestor "$FAE" 7.5.1 || fail "M649_FIX_IN_VULN"
gitq -C "$CRM" merge-base --is-ancestor "$FAE" 7.6.0 || fail "M649_FIX_TAG"
git_expect_fail -C "$CRM" merge-base --is-ancestor "$F563" 7.6.0 || fail "M649_563_IN_TAG"
peel=$(gitq -C "$CRM" rev-parse '7.4.2^{commit}')
[[ $peel == f54eea0ff476d4a343e98be0cbbaee42440c436f ]] || fail "MFMP_PEEL742 $peel"
peel=$(gitq -C "$CRM" rev-parse '7.4.3^{commit}')
[[ $peel == dbdc6133165b906a84c5bf4d919c74ee797c192b ]] || fail "MFMP_PEEL743 $peel"
peel=$(gitq -C "$CRM" rev-parse '7.5.1^{commit}')
[[ $peel == 9ee9c00c6ea99582a7d65b5d1d8c6197b51a77a8 ]] || fail "M649_PEEL751 $peel"
peel=$(gitq -C "$CRM" rev-parse '7.6.0^{commit}')
[[ $peel == 9b5993c0918ce45522e57f28114929ac75a29b9b ]] || fail "M649_PEEL760 $peel"
python3 - "$ADV_MFMP" "$ADV_M649" <<'PY' || fail "CRM_GHSA"
import json,sys
a=json.load(open(sys.argv[1]))
b=json.load(open(sys.argv[2]))
assert a["ghsa_id"].lower()=="ghsa-mfmp-q643-vj39"
assert b["ghsa_id"].lower()=="ghsa-m649-24q9-q6r4"
assert a["state"]=="published" and b["state"]=="published"
assert a.get("cve_id") in (None,"")
assert b.get("cve_id") in (None,"")
da=(a.get("description") or "")+(a.get("summary") or "")
db=(b.get("description") or "")+(b.get("summary") or "")
assert "GroupView.js" in da and "GroupRoles.js" in da
assert "tel:" in db and "mailto:" in db and "data-name" in db
assert "GHSA-mfmp-q643-vj39" in db
print("CRM_GHSA_OK")
PY
echo "MFMP_M649_OK"

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

echo "REPLAY_OK reviewed=3 PASS_proposal=3 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0"
