#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearclosed-m-grok46-low.
# English only. No credentials. Shared caches read-only. No clone, fetch, commit, or push.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-m-grok46-low}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
GHSA_REPO=${GHSA_REPO:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-ghsa200-fp211-identity-butfor3-grok46-high/work/pages/repo-advisory/GHSA-2Q7J-2VHX-56G8.json}
CVE=${CVE:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260812-alias-qa/api-cache/cve/CVE-2026-62187.json}
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
hash_check "$GHSA_REPO" \
  b8d6ffe532416d495b1780985c50523e86c89d4714700a3c2f86c67727687086
hash_check "$CVE" \
  a41970add7c993d48dad1396753535c768008f9c232eaf14d33da49fcc8da6f3

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
want = ["GHSA-2Q7J-2VHX-56G8"]
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [125]:
    print("ORDINAL_FAIL"); sys.exit(1)
n_pass = sum(1 for c in cas if c["verdict"] == "PASS_PROPOSAL")
n_nar = sum(1 for c in cas if c["verdict"] == "NARROW")
n_rej = sum(1 for c in cas if c["verdict"] == "REJECT")
if n_pass != 1 or n_nar != 0 or n_rej != 0 or len(cas) != 1:
    print("COUNT_FAIL", n_pass, n_nar, n_rej); sys.exit(1)
if res["conservation"]["equation"] != "1=1+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != ["GHSA-2Q7J-2VHX-56G8"]:
    print("PASS_LIST_FAIL", res["pass_proposals"]); sys.exit(1)
if res["canonical_strict_count_untouched"] != 90 or res["counts"]["countable_pass"] != 0:
    print("FLAG_FAIL"); sys.exit(1)
need_pass = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
rec = cas[0]
g = rec["gates"]
for k in need_pass:
    if g[k] != "PASS":
        print("GATE_NOT_PASS", rec["case_id"], k, g[k]); sys.exit(1)
if rec["verdict"] != "PASS_PROPOSAL" or rec.get("proposed_pass") is not True:
    print("PROPOSAL_FLAG", rec["case_id"]); sys.exit(1)
if rec.get("seven_gates_exact_pass") is not True:
    print("SEVEN_PASS_FLAG", rec["case_id"]); sys.exit(1)
if rec.get("osv_introduced_used_as_causal_proof") is not False:
    print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
if rec.get("countable_proposal") is not True:
    print("COUNTABLE_PROPOSAL_FLAG", rec["case_id"]); sys.exit(1)
if rec.get("authorship_transfer") is not False:
    print("TRANSFER_FLAG"); sys.exit(1)
if rec["candidate_set"] != ["5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6"]:
    print("CAND_FAIL"); sys.exit(1)
if rec["minimum_fix_set"] != ["d4f11d3005a56abc709ebc8e715972593ebed96e"]:
    print("FIX_FAIL"); sys.exit(1)
print("CONSERVATION_OK 1=1+0 NARROW=0 REJECT=0 PASS_PROPOSAL=1")
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
if "GHSA-VJ3G-5PX3-GR46" not in strict:
    print("VJ3G_MISSING_FROM_CANON90"); sys.exit(1)
if "GHSA-W8WF-3QVJ-6XQF" in strict:
    print("W8WF_UNEXPECTEDLY_COUNTED"); sys.exit(1)
if len(strict) != 90:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
adv = json.loads(Path("$GHSA_REPO").read_text())
if adv.get("ghsa_id") != "GHSA-2q7j-2vhx-56g8":
    print("GHSA_ID_FAIL"); sys.exit(1)
if adv.get("state") != "published" or adv.get("withdrawn_at") is not None:
    print("GHSA_STATE_FAIL"); sys.exit(1)
if "per-account disablement" not in (adv.get("summary") or ""):
    print("GHSA_SUMMARY_FAIL"); sys.exit(1)
if adv.get("cve_id") is not None:
    print("CVE_ID_NOT_NULL"); sys.exit(1)
vuln = adv["vulnerabilities"][0]
if vuln["package"]["name"] != "@openclaw/feishu":
    print("PKG_FAIL"); sys.exit(1)
if vuln["vulnerable_version_range"] != "<= 2026.6.6" or vuln["patched_versions"] != "2026.6.9":
    print("RANGE_FAIL"); sys.exit(1)
cve = json.loads(Path("$CVE").read_text())
refs = json.dumps(cve)
if "GHSA-2q7j-2vhx-56g8" not in refs:
    print("CNA_REF_FAIL"); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "vj3g_counted_distinct_ok")
PY

echo "== git facts =="
[[ -d $OC ]] || fail "CLONE_ABSENT"

C=5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6
P=7e005acd3c02f0cd26445c2c443f0b03c4dafbe5
F=d4f11d3005a56abc709ebc8e715972593ebed96e
LATER=125dc322f5c5aa09576442916b5b6a64437cbc55

gitq -C "$OC" cat-file -t "$C" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "PARENTS $parents"
gitq -C "$OC" log -1 --format='%b' "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "MARKER"
csubj=$(gitq -C "$OC" log -1 --format='%s' "$C")
[[ $csubj == *"multi-account support"* ]] || fail "C_SUBJ $csubj"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"enforce account tool family gates"* ]] || fail "F_SUBJ $fsubj"

if gitq -C "$OC" grep -q mergeFeishuAccountConfig "$P" -- extensions/feishu/src/accounts.ts; then
  fail "PARENT_HAS_MERGE"
fi
gitq -C "$OC" grep -q mergeFeishuAccountConfig "$C" -- extensions/feishu/src/accounts.ts || fail "CAND_MERGE"
gitq -C "$OC" grep -q 'resolveToolsConfig(feishuCfg.tools)' "$P" -- extensions/feishu/src/docx.ts || fail "PARENT_GLOBAL_TOOLS"
gitq -C "$OC" grep -q 'resolveToolsConfig(firstAccount.config.tools)' "$C" -- extensions/feishu/src/docx.ts || fail "CAND_FIRST_ACCOUNT"
gitq -C "$OC" grep -q 'resolveToolsConfig(firstAccount.config.tools)' "$C" -- extensions/feishu/src/drive.ts || fail "CAND_DRIVE"
gitq -C "$OC" grep -q 'resolveToolsConfig(firstAccount.config.tools)' "$C" -- extensions/feishu/src/wiki.ts || fail "CAND_WIKI"
git_path_absent -C "$OC" cat-file -e "${C}:extensions/feishu/src/tool-account.ts" || fail "CAND_HAS_TOOL_ACCOUNT"
git_path_absent -C "$OC" cat-file -e "${P}:extensions/feishu/src/tool-account.ts" || fail "PARENT_HAS_TOOL_ACCOUNT"

gitq -C "$OC" merge-base --is-ancestor "$C" "$LATER" || fail "C_NOT_ANC_LATER"
gitq -C "$OC" log -1 --format='%an' "$LATER" | LC_ALL=C grep -q 'Peter Steinberger' || fail "LATER_AUTHOR"
gitq -C "$OC" cat-file -p "$LATER" | LC_ALL=C grep -q 'Co-Authored-By: Claude' && fail "LATER_CLAUDE_TRANSFER" || true

gitq -C "$OC" grep -q requiredTool "$F" -- extensions/feishu/src/tool-account.ts || fail "FIX_REQUIRED"
gitq -C "$OC" grep -q 'family: "doc"' "$F" -- extensions/feishu/src/docx.ts || fail "FIX_DOC"
gitq -C "$OC" grep -q 'family: "drive"' "$F" -- extensions/feishu/src/drive.ts || fail "FIX_DRIVE"
gitq -C "$OC" grep -q 'family: "wiki"' "$F" -- extensions/feishu/src/wiki.ts || fail "FIX_WIKI"
if gitq -C "$OC" grep -q requiredTool "$C" -- extensions/feishu; then
  fail "CAND_HAS_REQUIRED"
fi

gitq -C "$OC" merge-base --is-ancestor "$C" v2026.6.6 || fail "CAND_TAG666"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.6.6 && fail "FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.6.9 || fail "FIX_TAG669"
peel666=$(gitq -C "$OC" rev-parse 'v2026.6.6^{commit}')
[[ $peel666 == 8c802aa683510c7f7503597b54c3021733245e59 ]] || fail "PEEL666 $peel666"
peel669=$(gitq -C "$OC" rev-parse 'v2026.6.9^{commit}')
[[ $peel669 == c645ec4555c017931de0e35ad9847dffae2741ef ]] || fail "PEEL669 $peel669"
blob_c=$(gitq -C "$OC" rev-parse "${C}:extensions/feishu/src/docx.ts")
blob_v26=$(gitq -C "$OC" rev-parse "v2026.2.6:extensions/feishu/src/docx.ts")
[[ $blob_c == 97475c26e743c85c65ee0cc121ffdbdc08408ea0 ]] || fail "DOCX_C $blob_c"
[[ $blob_c == "$blob_v26" ]] || fail "DOCX_V26 $blob_v26"
blob_f=$(gitq -C "$OC" rev-parse "${F}:extensions/feishu/src/tool-account.ts")
blob_t=$(gitq -C "$OC" rev-parse "v2026.6.9:extensions/feishu/src/tool-account.ts")
blob_v=$(gitq -C "$OC" rev-parse "v2026.6.6:extensions/feishu/src/tool-account.ts")
[[ $blob_f == 92d1e8f64263511054a114205e3362e68cedecda ]] || fail "FIX_BLOB $blob_f"
[[ $blob_f == "$blob_t" ]] || fail "FIX_TAG_BLOB $blob_t"
[[ $blob_v == e6d35aff8ba0b563ad08ccb7af0e4bd9a3266a86 ]] || fail "VULN_BLOB $blob_v"
echo "2Q7J_OK"

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

echo "REPLAY_OK reviewed=1 PASS_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0"
