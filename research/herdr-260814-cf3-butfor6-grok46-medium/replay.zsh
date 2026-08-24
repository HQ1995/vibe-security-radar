#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-cf3-butfor6-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
OC=${OC:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
SC=${SC:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/sharpcompress}
GM=${GM:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/gitlab-mcp}
TI=${TI:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/titra}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

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

# Expected-absent tree path: git prints a fatal line. Do not treat that as replay failure.
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical87/summary.json" \
  17487d40720f4c20475df7df270e5bb1139726887c42bc50d999f0f7e713a722
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical87/ledger.jsonl" \
  b6dc7e781017e60a94725696b5a08b229a5cb026ffd098e6306e9a8941f9fdbe
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl" \
  0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687
hash_check "$ROOT/autoresearch/herdr-260814-cf3-nextqueue-grok46-medium/assignment.jsonl" \
  c358ad2bb4384080f0f051e377a09f15ac3ce47249dfe697b54159c295b601cf
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json" \
  8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9

echo "== conservation 6=6+0 =="
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
    "GHSA-2Q7J-2VHX-56G8",
    "GHSA-6C8G-7P36-R338",
    "GHSA-7C3W-FXGH-FRC7",
    "GHSA-7JX6-764P-FGG9",
    "GHSA-H2VW-PH2C-JVWF",
    "GHSA-PQGX-6WG3-GMVR",
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
if n_pass != 0 or n_nar != 6 or len(cas) != 6:
    print("COUNT_FAIL", n_pass, n_nar); sys.exit(1)
if res["conservation"]["equation"] != "6=6+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != [] or res["canonical_strict_count_untouched"] != 87:
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
    if rec["case_id"] == "GHSA-PQGX-6WG3-GMVR" and rec.get("authorship_transfer") is not False:
        print("PQGX_TRANSFER"); sys.exit(1)
print("CONSERVATION_OK 6=6+0 NARROW=6 PASS_PROPOSAL=0")
PY

echo "== uniqueness vs canonical87 + 8RW6 + cf3_19 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical87/summary.json").read_text())
acc = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical87", hit); sys.exit(1)
if acc["case_id"].upper() in ids:
    print("UNIQUENESS_FAIL 8RW6"); sys.exit(1)
if acc["repository"] in ("openclaw/openclaw","adamhathcock/sharpcompress","zereight/gitlab-mcp","kromitgmbh/titra"):
    print("UNIQUENESS_FAIL 8RW6_REPO"); sys.exit(1)
cf3_19 = {
    "GHSA-2QRV-RC5X-2G2H","GHSA-2X93-H3HG-2XFP","GHSA-3J8Q-FWPJ-F8J5","GHSA-4524-X6PC-RR9X",
    "GHSA-5WP8-Q9MX-8JX8","GHSA-92VG-F4FQ-FXM9","GHSA-9C3V-684M-579C","GHSA-CW23-QWR7-C655",
    "GHSA-F2FQ-4RMP-9X8C","GHSA-F38V-77QJ-H4JQ","GHSA-F7FH-QG34-X2XH","GHSA-G8MR-85JM-7XHM",
    "GHSA-M63V-2G9W-2W6V","GHSA-P5RM-JG5C-8C77","GHSA-V396-V7Q4-X2QJ","GHSA-WP73-F3GG-W4VR",
    "GHSA-X2W7-XR2G-QHJR","GHSA-X34R-63HX-W57F","GHSA-X8QQ-M4QC-RPJ5",
}
hit2 = [i for i in ids if i in cf3_19]
if hit2:
    print("UNIQUENESS_FAIL in_cf3_19", hit2); sys.exit(1)
if len(strict) != 87:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== git facts =="
[[ -d $OC && -d $SC && -d $GM && -d $TI ]] || fail "CLONE_ABSENT"

# 2Q7J
C=5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6
F=d4f11d3005a56abc709ebc8e715972593ebed96e
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C 7e005acd3c02f0cd26445c2c443f0b03c4dafbe5" ]] || fail "2Q7J_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "2Q7J_MARKER"
gitq -C "$OC" grep -q 'resolveToolsConfig(feishuCfg.tools)' "${C}^" -- extensions/feishu/src/docx.ts || fail "2Q7J_PARENT_GATE"
gitq -C "$OC" grep -q 'resolveToolsConfig(firstAccount.config.tools)' "$C" -- extensions/feishu/src/docx.ts || fail "2Q7J_CAND_FIRST"
git_path_absent -C "$OC" cat-file -e "${C}^:extensions/feishu/src/tool-account.ts" || fail "2Q7J_PARENT_HAS_TOOL_ACCOUNT"
gitq -C "$OC" cat-file -e "${F}:extensions/feishu/src/tool-account.ts" >/dev/null || fail "2Q7J_FIX_TOOL_ACCOUNT"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.6.6 || fail "2Q7J_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.6.6 && fail "2Q7J_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.6.9 || fail "2Q7J_FIX_TAG"
echo "2Q7J_OK"

# 6C8G
C=8b95e0a76d6b387533175730e2895ccd16772d07
F=2021a06626d0555a4d69471386e763ca5f5d5dfb
gitq -C "$SC" cat-file -t "$C" >/dev/null
gitq -C "$SC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$SC" rev-list --parents -n 1 "$C")
[[ $parents == "$C 3f9986c13c973f5e9b8e08da8bfb5e8259044a44" ]] || fail "6C8G_PARENTS $parents"
an=$(gitq -C "$SC" log -1 --format='%an' "$C")
[[ $an == "copilot-swe-agent[bot]" ]] || fail "6C8G_AUTHOR $an"
gitq -C "$SC" grep -q 'Path.Combine(destination, entry.Key' "${C}^" -- src/SharpCompress/Archives/IArchiveExtensions.cs || fail "6C8G_PARENT_COMBINE"
gitq -C "$SC" merge-base --is-ancestor "$C" 0.47.4 || fail "6C8G_CAND_TAG"
gitq -C "$SC" merge-base --is-ancestor "$F" 0.47.4 && fail "6C8G_FIX_IN_VULN" || true
gitq -C "$SC" merge-base --is-ancestor "$F" 0.48.0 || fail "6C8G_FIX_TAG"
echo "6C8G_OK"

# 7C3W
C=c156ac7675207e3dbc0c6a4b3ed6931dc96513c2
F=e2a81a047ab8750fa5bfa1763b5d85e5616f3994
gitq -C "$GM" cat-file -t "$C" >/dev/null
gitq -C "$GM" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$GM" rev-list --parents -n 1 "$C")
[[ $parents == "$C dc16faa9e2a186ffd4b4a96fc1a9cd2b94f9236a" ]] || fail "7C3W_PARENTS $parents"
gitq -C "$GM" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "7C3W_MARKER"
gitq -C "$GM" grep -q '/jobs/${jobId}/trace' "${C}^" -- index.ts || fail "7C3W_PARENT_TRACE"
gitq -C "$GM" grep -q '/jobs/${jobId}/artifacts' "$C" -- index.ts || fail "7C3W_CAND_ARTIFACTS"
gitq -C "$GM" grep -q 'list_job_artifacts' "${C}^" -- index.ts && fail "7C3W_PARENT_HAS_ARTIFACTS" || true
gitq -C "$GM" merge-base --is-ancestor "$C" v2.0.32 || fail "7C3W_CAND_TAG"
gitq -C "$GM" merge-base --is-ancestor "$F" v2.0.32 && fail "7C3W_FIX_IN_VULN" || true
gitq -C "$GM" merge-base --is-ancestor "$F" v2.1.32 || fail "7C3W_FIX_TAG"
echo "7C3W_OK"

# 7JX6
C=6e498a1f628873b16aaeeecfbc3dc249b9a1d8bf
F=08a73dbe4b09e6a15db591649ddec81b48c59584
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C 2ec1a27c9fba56ac30e4a8b35a89343029be9492" ]] || fail "7JX6_PARENTS $parents"
subj=$(gitq -C "$OC" log -1 --format='%s' "$C")
[[ $subj == *"[AI]"* ]] || fail "7JX6_MARKER $subj"
if gitq -C "$OC" grep -q 'authorizeQQBotApprovalAction' "${C}^" -- '*.ts'; then
  fail "7JX6_PARENT_HAS_AUTH"
fi
gitq -C "$OC" grep -q 'authorizeQQBotApprovalAction' "$C" -- extensions/qqbot/src/exec-approvals.ts || fail "7JX6_CAND_AUTH"
fsubj=$(gitq -C "$OC" log -1 --format='%s' "$F")
[[ $fsubj == *"gate fallback approval buttons"* ]] || fail "7JX6_FIX_SUBJ $fsubj"
gitq -C "$OC" diff "${F}^" "$F" -- extensions/qqbot/src/command-auth.test.ts | LC_ALL=C grep -q 'resolveSlashCommandAuthorization' || fail "7JX6_SIBLING"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.5.26 || fail "7JX6_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.5.26 && fail "7JX6_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.5.27 || fail "7JX6_FIX_TAG"
echo "7JX6_OK"

# H2VW
C=7d7f5d85b4ff0bf9a135ced8022d8860a1979a06
F=2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1
gitq -C "$OC" cat-file -t "$C" >/dev/null
gitq -C "$OC" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$OC" rev-list --parents -n 1 "$C")
[[ $parents == "$C 49d962a82f67203994c39cc577b39aa47632fef4" ]] || fail "H2VW_PARENTS $parents"
gitq -C "$OC" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "H2VW_MARKER"
gitq -C "$OC" grep -q 'MINIMAX_API_HOST' "${C}^" -- src/agents/minimax-vlm.ts || fail "H2VW_PARENT_VLM"
git_path_absent -C "$OC" cat-file -e "${C}^:extensions/minimax/speech-provider.ts" || fail "H2VW_PARENT_HAS_TTS"
gitq -C "$OC" grep -q 'MINIMAX_API_HOST' "$C" -- extensions/minimax/speech-provider.ts || fail "H2VW_CAND_TTS"
gitq -C "$OC" merge-base --is-ancestor 36a02b3e6755c65ed4df4dc4d0de1dd93fa8bbc5 v2026.3.22 || fail "H2VW_VLM_OLD_TAG"
gitq -C "$OC" merge-base --is-ancestor "$C" v2026.4.5 || fail "H2VW_CAND_TAG"
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.5 && fail "H2VW_FIX_IN_VULN" || true
gitq -C "$OC" merge-base --is-ancestor "$F" v2026.4.20 || fail "H2VW_FIX_TAG"
echo "H2VW_OK"

# PQGX
S=67c7b7663219c9e28fce487b1803706b333c2a4f
M=40331e610075e7c9a076873cc5b3655362d136db
F=2e2ac5cbeed47a76720b21c7fde0214a242e065e
gitq -C "$TI" cat-file -t "$S" >/dev/null
gitq -C "$TI" cat-file -t "$M" >/dev/null
gitq -C "$TI" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$TI" rev-list --parents -n 1 "$S")
[[ $parents == "$S 62fe0533d792ca72794af098cd6b1d3301514ff7" ]] || fail "PQGX_PARENTS $parents"
an=$(gitq -C "$TI" log -1 --format='%an' "$S")
[[ $an == "Copilot" ]] || fail "PQGX_AUTHOR $an"
gitq -C "$TI" grep -q "from 'vm2'" "${S}^" -- imports/api/timecards/server/methods.js || fail "PQGX_PARENT_VM2"
gitq -C "$TI" grep -q 'timeEntryRule' "${S}^" -- imports/api/timecards/server/methods.js || fail "PQGX_PARENT_RULE"
gitq -C "$TI" grep -q 'vm_sandbox.js' "$S" -- imports/api/timecards/server/methods.js || fail "PQGX_SQUASH_NATIVE"
gitq -C "$TI" grep -q 'validateSandboxCode' "$F" -- imports/utils/vm_sandbox.js || fail "PQGX_FIX_VALIDATE"
gitq -C "$TI" merge-base --is-ancestor "$M" "$S" && fail "PQGX_MEMBER_ANC_SQUASH" || true
gitq -C "$TI" merge-base --is-ancestor "$M" 0.99.48 && fail "PQGX_MEMBER_IN_VULN" || true
gitq -C "$TI" merge-base --is-ancestor "$S" 0.99.48 || fail "PQGX_SQUASH_TAG"
gitq -C "$TI" merge-base --is-ancestor "$F" 0.99.48 && fail "PQGX_FIX_IN_VULN" || true
gitq -C "$TI" merge-base --is-ancestor "$F" 0.99.49 || fail "PQGX_FIX_TAG"
echo "PQGX_OK"

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

echo "REPLAY_OK reviewed=6 PASS_proposal=0 NARROW=6 REJECT=0 UNKNOWN=0 BLOCKED=0"
