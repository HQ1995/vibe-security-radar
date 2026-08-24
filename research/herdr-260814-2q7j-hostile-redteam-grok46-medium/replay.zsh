#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-2q7j-hostile-redteam-grok46-medium.
# English only. No credentials. Shared caches read-only. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-2q7j-hostile-redteam-grok46-medium}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
Z=${Z:-/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export GH_PAGER=cat

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d /tmp/2q7j-hostile.XXXXXX)"

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
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if any(a.get("nearclosed_m_is_not_evidence") is not True for a in ass):
    print("NEARCLOSED_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [125]:
    print("ORDINAL_FAIL"); sys.exit(1)
if len(cas) != 1 or cas[0]["verdict"] != "REJECT":
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
if g["identity_gate"] != "PASS" or g["topology_gate"] != "PASS" or g["uniqueness_gate"] != "PASS":
    print("EXPECTED_PASS_GATES", g); sys.exit(1)
if g["ai_hunk_gate"] != "FAIL" or g["but_for_gate"] != "FAIL" or g["fix_reversal_gate"] != "FAIL" or g["release_gate"] != "FAIL":
    print("EXPECTED_FAIL_GATES", g); sys.exit(1)
if rec.get("osv_introduced_used_as_causal_proof") is not False:
    print("OSV_USED_AS_PROOF"); sys.exit(1)
if rec.get("authorship_transfer") is not False:
    print("TRANSFER"); sys.exit(1)
if rec.get("nearclosed_m_is_not_evidence") is not True:
    print("CASE_NEARCLOSED_FLAG"); sys.exit(1)
if rec["seven_gates_exact_pass"] is not False:
    print("SEVEN_SHOULD_NOT_PASS"); sys.exit(1)
if rec["contribution_class"] != "AI_NEW_SURFACE_CONTRIBUTOR":
    print("CLASS"); sys.exit(1)
if rec["candidate_set"] != ["5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6"]:
    print("CAND"); sys.exit(1)
if "125dc322f5c5aa09576442916b5b6a64437cbc55" in rec["candidate_set"]:
    print("HUMAN_IN_CAND"); sys.exit(1)
if rec["minimum_fix_set"] != ["d4f11d3005a56abc709ebc8e715972593ebed96e"]:
    print("FIXSET"); sys.exit(1)
if rec.get("aliases"):
    print("ALIASES_SHOULD_BE_EMPTY"); sys.exit(1)
print("CONSERVATION_OK 1=1+0 REJECT=1")
PY

echo "== uniqueness vs pinned canonical91 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical91", hit); sys.exit(1)
if "GHSA-2Q7J-2VHX-56G8" in strict:
    print("UNIQUENESS_FAIL 2Q7J_COUNTED"); sys.exit(1)
if "GHSA-W8WF-3QVJ-6XQF" in strict:
    print("UNIQUENESS_FAIL W8WF_COUNTED"); sys.exit(1)
if len(strict) != 91:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
if "GHSA-8JPQ-5H99-FF5R" not in strict or "GHSA-J4XF-96QF-RX69" not in strict:
    print("COUNTED_FEISHU_MISSING"); sys.exit(1)
if "GHSA-5WP8-Q9MX-8JX8" not in strict:
    print("5WP8_MISSING_COUNTED"); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "2Q7J_ABSENT_CANONICAL91 DISTINCT_8JPQ_J4XF_W8WF")
PY

echo "== first-party identity =="
python3 - <<'PY' || fail "identity"
import json, os, subprocess, sys
env=os.environ.copy()
env["GH_PAGER"]="cat"
p=subprocess.run(["gh","api","repos/openclaw/openclaw/security-advisories/GHSA-2q7j-2vhx-56g8"],
                 capture_output=True, text=True, env=env, timeout=60)
if p.returncode!=0:
    print("GH_REPO_ADV_FAIL", p.stderr[:400]); sys.exit(1)
d=json.loads(p.stdout)
if d.get("ghsa_id","").lower()!="ghsa-2q7j-2vhx-56g8":
    print("ADV_ID", d.get("ghsa_id")); sys.exit(1)
if d.get("state")!="published" or d.get("withdrawn_at") not in (None,""):
    print("ADV_STATE", d.get("state"), d.get("withdrawn_at")); sys.exit(1)
if d.get("cve_id") not in (None,""):
    print("ADV_CVE_SHOULD_BE_NULL", d.get("cve_id")); sys.exit(1)
if "per-account disablement" not in (d.get("summary") or ""):
    print("ADV_SUMMARY", d.get("summary")); sys.exit(1)
v=d.get("vulnerabilities") or []
if not v or v[0].get("package",{}).get("name")!="@openclaw/feishu":
    print("ADV_PKG", v); sys.exit(1)
if v[0].get("vulnerable_version_range")!="<= 2026.6.6" or v[0].get("patched_versions")!="2026.6.9":
    print("ADV_RANGE", v[0]); sys.exit(1)
p2=subprocess.run(["gh","api","/advisories/GHSA-2q7j-2vhx-56g8"], capture_output=True, text=True, env=env, timeout=60)
if p2.returncode==0:
    print("GLOBAL_SHOULD_404"); sys.exit(1)
if "404" not in (p2.stderr+p2.stdout):
    print("GLOBAL_NOT_404", p2.returncode, p2.stderr[:200]); sys.exit(1)
p3=subprocess.run(["gh","api","/advisories","-X","GET","-f","cve_id=CVE-2026-62187"],
                  capture_output=True, text=True, env=env, timeout=60)
if p3.returncode!=0:
    print("CVE_LOOKUP_FAIL", p3.stderr[:400]); sys.exit(1)
cves=json.loads(p3.stdout)
ids=sorted({x.get("ghsa_id","").upper() for x in cves})
if "GHSA-MM88-H44M-W2GP" not in ids:
    print("CVE_NOT_MM88", ids); sys.exit(1)
if "GHSA-2Q7J-2VHX-56G8" in ids:
    print("CVE_BINDS_2Q7J"); sys.exit(1)
print("IDENTITY_OK")
PY

echo "== git facts =="
[[ -d $Z ]] || fail "CLONE_ABSENT"
CAND=5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6
PARENT=7e005acd3c02f0cd26445c2c443f0b03c4dafbe5
FIX=d4f11d3005a56abc709ebc8e715972593ebed96e
HUM=125dc322f5c5aa09576442916b5b6a64437cbc55
OLD=0223416c6177d76d816ee2274ceb2e1980349f25
PLUG=2267d58afcc70fe19408b8f0dce108c340f3426d
FIXP=62563c2cfc482b8aa9997c16f02dcd453b13c925
gitq -C "$Z" cat-file -t "$CAND" >/dev/null
gitq -C "$Z" cat-file -t "$FIX" >/dev/null
parents=$(gitq -C "$Z" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PARENT" ]] || fail "PARENTS $parents"
gitq -C "$Z" cat-file -p "$CAND" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.5' || fail "CAND_MARKER"
gitq -C "$Z" cat-file -p "$HUM" | LC_ALL=C grep -E -q 'Co-Authored-By:|Co-authored-by:|Claude|Codex|Copilot' && fail "HUMAN_MARKER" || true
gitq -C "$Z" cat-file -p "$FIX" | LC_ALL=C grep -E -q 'Co-Authored-By:|Co-authored-by:|Claude|Codex|Copilot' && fail "FIX_MARKER" || true
gitq -C "$Z" grep -q 'function mergeFeishuAccountConfig' "$OLD" -- src/feishu/accounts.ts || fail "OLD_MERGE"
if gitq -C "$Z" grep -q 'function mergeFeishuAccountConfig' "$PARENT" -- extensions/feishu/src/accounts.ts; then
  fail "PARENT_HAS_MERGE"
fi
gitq -C "$Z" grep -q 'resolveToolsConfig(feishuCfg.tools)' "$PARENT" -- extensions/feishu/src/docx.ts || fail "PARENT_GLOBAL"
gitq -C "$Z" grep -q 'resolveToolsConfig(firstAccount.config.tools)' "$CAND" -- extensions/feishu/src/docx.ts || fail "CAND_FIRST"
gitq -C "$Z" grep -q 'createFeishuClient(firstAccount)' "$CAND" -- extensions/feishu/src/docx.ts || fail "CAND_EXEC_FIRST"
if gitq -C "$Z" grep -q 'resolveToolsConfig(firstAccount.config.tools)' v2026.6.6 -- extensions/feishu/src/docx.ts; then
  fail "V666_DOCX_STILL_FIRST"
fi
gitq -C "$Z" grep -q 'resolveAnyEnabledFeishuToolsConfig' v2026.6.6 -- extensions/feishu/src/docx.ts || fail "V666_OR_MERGE"
if gitq -C "$Z" grep -q 'requiredTool' v2026.6.6 -- extensions/feishu/src/tool-account.ts; then
  fail "V666_HAS_REQUIRED"
fi
gitq -C "$Z" grep -q 'requiredTool' "$FIX" -- extensions/feishu/src/tool-account.ts || fail "FIX_REQUIRED"
gitq -C "$Z" grep -q 'resolveToolsConfig(firstAccount.config.tools)' v2026.6.9 -- extensions/feishu/src/chat.ts || fail "CHAT_LEFTOVER"
gitq -C "$Z" merge-base --is-ancestor "$CAND" v2026.6.6 || fail "CAND_TAG"
gitq -C "$Z" merge-base --is-ancestor "$FIX" v2026.6.6 && fail "FIX_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$FIX" v2026.6.9 || fail "FIX_TAG"
gitq -C "$Z" merge-base --is-ancestor "$HUM" v2026.6.6 || fail "HUM_TAG"
gitq -C "$Z" merge-base --is-ancestor "$PLUG" "$PARENT" || fail "PLUG_ANC_PARENT"
peel=$(gitq -C "$Z" rev-parse 'v2026.6.6^{commit}')
[[ $peel == 8c802aa683510c7f7503597b54c3021733245e59 ]] || fail "PEEL666 $peel"
peel=$(gitq -C "$Z" rev-parse 'v2026.6.9^{commit}')
[[ $peel == c645ec4555c017931de0e35ad9847dffae2741ef ]] || fail "PEEL669 $peel"
blob_h=$(gitq -C "$Z" rev-parse "${HUM}:extensions/feishu/src/tool-account.ts")
blob_v=$(gitq -C "$Z" rev-parse "v2026.6.6:extensions/feishu/src/tool-account.ts")
blob_p=$(gitq -C "$Z" rev-parse "${FIXP}:extensions/feishu/src/tool-account.ts")
blob_f=$(gitq -C "$Z" rev-parse "${FIX}:extensions/feishu/src/tool-account.ts")
blob_v2=$(gitq -C "$Z" rev-parse "v2026.6.9:extensions/feishu/src/tool-account.ts")
[[ $blob_h == 72b5db9b7775af9910fe18dec9089a61662838d1 ]] || fail "BLOB_H $blob_h"
[[ $blob_v == e6d35aff8ba0b563ad08ccb7af0e4bd9a3266a86 ]] || fail "BLOB_V $blob_v"
[[ $blob_p == "$blob_v" ]] || fail "FIXP_NE_V666"
[[ $blob_f == 92d1e8f64263511054a114205e3362e68cedecda ]] || fail "BLOB_F $blob_f"
[[ $blob_f == "$blob_v2" ]] || fail "FIX_BLOB $blob_f $blob_v2"
[[ $blob_h != "$blob_v" ]] || fail "HUMAN_EQUALS_V666"
[[ $blob_v != "$blob_f" ]] || fail "VULN_EQUALS_FIX"
echo "GIT_OK"

echo "== npm archives =="
curl -fsSL -o "$REPLAY_TMP/feishu-2026.6.6.tgz" \
  https://registry.npmjs.org/@openclaw/feishu/-/feishu-2026.6.6.tgz
curl -fsSL -o "$REPLAY_TMP/feishu-2026.6.9.tgz" \
  https://registry.npmjs.org/@openclaw/feishu/-/feishu-2026.6.9.tgz
c1=$(sha256sum "$REPLAY_TMP/feishu-2026.6.6.tgz" | awk '{print $1}')
c2=$(sha256sum "$REPLAY_TMP/feishu-2026.6.9.tgz" | awk '{print $1}')
s1=$(sha1sum "$REPLAY_TMP/feishu-2026.6.6.tgz" | awk '{print $1}')
s2=$(sha1sum "$REPLAY_TMP/feishu-2026.6.9.tgz" | awk '{print $1}')
[[ $c1 == 73a2c6888dcfa7e5c88d50bce62eef2ded9bba278260955097e03b0bde9e9cf7 ]] || fail "TGZ666 $c1"
[[ $c2 == 056103475336035a85db6ac379a854c439fd4b9ad7a16461f795c8b48260a858 ]] || fail "TGZ669 $c2"
[[ $s1 == 5bf888ce902fd54049dc9fa0c59265e0f45c2f26 ]] || fail "SHA1_666 $s1"
[[ $s2 == 5f04724c4b96eec91d498d23cc2898a84422888b ]] || fail "SHA1_669 $s2"
mkdir "$REPLAY_TMP/n666" "$REPLAY_TMP/n669"
tar -C "$REPLAY_TMP/n666" -xzf "$REPLAY_TMP/feishu-2026.6.6.tgz"
tar -C "$REPLAY_TMP/n669" -xzf "$REPLAY_TMP/feishu-2026.6.9.tgz"
LC_ALL=C grep -q 'function resolveAnyEnabledFeishuToolsConfig' \
  "$REPLAY_TMP/n666/package/dist/"*.js || fail "NPM666_OR"
if LC_ALL=C grep -q 'params.requiredTool' "$REPLAY_TMP/n666/package/dist/"*.js; then
  fail "NPM666_REQUIRED"
fi
LC_ALL=C grep -q 'params.requiredTool' "$REPLAY_TMP/n669/package/dist/"*.js || fail "NPM669_REQUIRED"
LC_ALL=C grep -q 'firstAccount.config.tools).chat' \
  "$REPLAY_TMP/n666/package/dist/"*.js || fail "NPM666_CHAT_FIRST"
LC_ALL=C grep -q 'firstAccount.config.tools).chat' \
  "$REPLAY_TMP/n669/package/dist/"*.js || fail "NPM669_CHAT_FIRST"
echo "NPM_OK"

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

echo "REPLAY_OK reviewed=1 PASS_proposal=0 REJECT=1 NARROW=0 UNKNOWN=0 BLOCKED=0"
