#!/usr/bin/env zsh
# Deterministic replay for herdr-260815-v273-hostile-grok46-high.
# English only. Anonymous public access only. No credentials. No GitHub API.
# Never print environment variable names or values. mktemp clone cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260815-v273-hostile-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}

typeset -a _strip_names
_strip_names=()
for _n in ${(k)parameters}; do
  if [[ $_n == *TOKEN* || $_n == *KEY* || $_n == *SECRET* || $_n == *PASSWORD* || $_n == *AUTH* ]]; then
    _strip_names+=("$_n")
  fi
done
for _n in "${_strip_names[@]}"; do
  unset "$_n"
done
unset _n _strip_names

export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_PAGER=cat
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d /tmp/v273-hostile.XXXXXX)"

GITQ_N=0
gitq() {
  GITQ_N=$((GITQ_N + 1))
  local outfile errfile rc filtered
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git -c credential.helper= "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  filtered="$(grep -v -E -- '^error: unable to normalize alternate object path:|^warning: |^Cloning into|^Updating files:|^From https://|^remote: |^Receiving objects:|^Resolving deltas:|^ \* \[new ' "$errfile" || true)"
  if [[ -n "$filtered" ]]; then
    rm -f "$outfile" "$errfile"
    fail "git stderr: $filtered"
  fi
  cat "$outfile"
  rm -f "$outfile" "$errfile"
  return $rc
}

for f in result.json report.md replay.zsh; do
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json" \
  c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl" \
  7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096
ADV_JSON=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database/advisories/github-reviewed/2026/04/GHSA-v273-448j-v4qj/GHSA-v273-448j-v4qj.json
hash_check "$ADV_JSON" 023dc373f50b6f30503202755c1283426a94a3d6579e719f5880833f7658b9a3

echo "== conservation 1=1+0 =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
res = json.loads(owned.joinpath("result.json").read_text())
want = ["GHSA-V273-448J-V4QJ"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if res["conservation"]["reviewed_case_ids"] != want:
    print("ID_ORDER_FAIL", res["conservation"]["reviewed_case_ids"]); sys.exit(1)
if res["conservation"]["equation"] != "1=1+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res.get("pass_proposal_ids"):
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 94:
    print("FLAG_FAIL"); sys.exit(1)
if res["per_case"]["GHSA-V273-448J-V4QJ"] != "REJECT":
    print("VERDICT_FAIL"); sys.exit(1)
if res["terminal_status"] != "REJECT":
    print("TERMINAL_FAIL"); sys.exit(1)
g = res["gate_vector"]
for k in need:
    if k not in g:
        print("MISSING_GATE", k); sys.exit(1)
if g["identity_gate"] != "PASS":
    print("BAD_IDENTITY"); sys.exit(1)
if g["ai_hunk_gate"] != "FAIL":
    print("BAD_AI_HUNK"); sys.exit(1)
if g["but_for_gate"] != "FAIL":
    print("BAD_BUT_FOR"); sys.exit(1)
if g["fix_reversal_gate"] != "FAIL":
    print("BAD_FIX_REV"); sys.exit(1)
if g["topology_gate"] != "PASS":
    print("BAD_TOPO"); sys.exit(1)
if g["release_gate"] != "PASS":
    print("BAD_RELEASE"); sys.exit(1)
if g["uniqueness_gate"] != "PASS":
    print("BAD_UNIQ"); sys.exit(1)
if res["counts"]["REJECT"] != 1 or res["counts"]["KEEP"] != 0:
    print("COUNT_FAIL"); sys.exit(1)
if res["counts"]["countable_pass"] != 0 or res["packet_delta"] != 0:
    print("DELTA_FAIL"); sys.exit(1)
print("CONSERVATION_OK 1=1+0 REJECT=1")
PY

echo "== uniqueness vs pinned canonical94 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
if len(strict) != 94:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
if "GHSA-V273-448J-V4QJ" in strict:
    print("UNIQUENESS_FAIL V273_COUNTED"); sys.exit(1)
if "GHSA-4RC3-7J7W-M548" in strict:
    print("UNIQUENESS_FAIL 4RC3_COUNTED"); sys.exit(1)
led = Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl").read_text().upper()
if "GHSA-V273-448J-V4QJ" in led or "HARTTLE/LIQUIDJS" in led:
    print("UNIQUENESS_FAIL LEDGER"); sys.exit(1)
adv = json.loads(Path("$ADV_JSON").read_text())
if adv.get("id","").lower() != "ghsa-v273-448j-v4qj":
    print("ADV_ID", adv.get("id")); sys.exit(1)
if adv.get("withdrawn_at"):
    print("ADV_WITHDRAWN"); sys.exit(1)
if adv["database_specific"].get("github_reviewed") is not True:
    print("ADV_NOT_REVIEWED"); sys.exit(1)
if adv.get("aliases") != ["CVE-2026-39859"]:
    print("ADV_ALIASES", adv.get("aliases")); sys.exit(1)
details = adv.get("details","")
if "type !== LookupType.Root" not in details:
    print("ADV_MISSING_SKIP"); sys.exit(1)
if "renderFile" not in details:
    print("ADV_MISSING_RENDERFILE"); sys.exit(1)
if "10.25.0" not in details:
    print("ADV_MISSING_10250"); sys.exit(1)
if "CVE-2026-30952" not in details:
    print("ADV_MISSING_30952"); sys.exit(1)
print("UNIQUENESS_OK V273_ABSENT_CANONICAL94 DISTINCT_4RC3")
PY

echo "== throwaway clone =="
REPO="$REPLAY_TMP/liquidjs"
gitq clone --quiet https://github.com/harttle/liquidjs.git "$REPO"
CAND=529dd67eeb6b125637623d6a723601f0938d3613
PARENT=abc058be0f33d6372cd2216f4945183167abeb25
FIX=f41c1fc02fe901598f3328118b42b13bc6bc9b04
FIXP=db4348507e6aa205ab2ba5e3fa273c40767e6764
M1=cca3da6147fbc59a5a78875015295327a9ee59e9
M2=b181b08543ed69b081c72fc3ba59f6b5159d9fe9
M3=3538864119abdc7e2b82705950c9f3235c5c2235
PR870=484ba7f07863735af65fc2eed8e51c311298bdba
SKIP=822ba0be0f1cfbedd50376aff8ac49eee71bd48c
MAR=3cd024d652dc883c46307581e979fe32302adbac
gitq -C "$REPO" fetch --quiet origin \
  "$M1" "$M2" "$M3" "$PR870" \
  refs/pull/867/head:refs/pull/867/head \
  refs/pull/870/head:refs/pull/870/head

echo "== git topology =="
parents=$(gitq -C "$REPO" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PARENT" ]] || fail "CAND_PARENTS $parents"
parents=$(gitq -C "$REPO" rev-list --parents -n 1 "$FIX")
[[ $parents == "$FIX $FIXP" ]] || fail "FIX_PARENTS $parents"
tree=$(gitq -C "$REPO" rev-parse "${CAND}^{tree}")
[[ $tree == 1c07d2741651bcf021038890a0e349d28a4cea81 ]] || fail "CAND_TREE $tree"
tree=$(gitq -C "$REPO" rev-parse "${M3}^{tree}")
[[ $tree == 1c07d2741651bcf021038890a0e349d28a4cea81 ]] || fail "M3_TREE $tree"
tree=$(gitq -C "$REPO" rev-parse "${FIX}^{tree}")
[[ $tree == fd13094721f33a6e475f5d99c47539ccb36f437d ]] || fail "FIX_TREE $tree"
tree=$(gitq -C "$REPO" rev-parse "${PR870}^{tree}")
[[ $tree == fd13094721f33a6e475f5d99c47539ccb36f437d ]] || fail "PR870_TREE $tree"
gitq -C "$REPO" merge-base --is-ancestor "$CAND" "$FIX" || fail "CAND_NOT_ANC_FIX"
gitq -C "$REPO" merge-base --is-ancestor "$CAND" v10.25.0 && fail "CAND_IN_V10250" || true
gitq -C "$REPO" merge-base --is-ancestor "$CAND" v10.25.4 || fail "CAND_NOT_IN_V10254"
gitq -C "$REPO" merge-base --is-ancestor "$FIX" v10.25.4 && fail "FIX_IN_V10254" || true
gitq -C "$REPO" merge-base --is-ancestor "$FIX" v10.25.5 || fail "FIX_NOT_IN_V10255"
peel=$(gitq -C "$REPO" rev-parse 'v10.25.0^{commit}')
[[ $peel == 93c38c7c6d1f3e4a3c64fc5f205cf6bff4be46a6 ]] || fail "PEEL250 $peel"
peel=$(gitq -C "$REPO" rev-parse 'v10.25.4^{commit}')
[[ $peel == "$FIXP" ]] || fail "PEEL254 $peel"
peel=$(gitq -C "$REPO" rev-parse 'v10.25.5^{commit}')
[[ $peel == 4af7be695cb715bf227113729d36396d45ee922a ]] || fail "PEEL255 $peel"
blob=$(gitq -C "$REPO" rev-parse "${PARENT}:src/fs/loader.ts")
[[ $blob == 2c58e231c93e244e5fffb9af1ad19aa508e82810 ]] || fail "BLOB_PARENT $blob"
blob=$(gitq -C "$REPO" rev-parse "${M1}:src/fs/loader.ts")
[[ $blob == 4a42cd650e4026df19f137231481e7c771b0110f ]] || fail "BLOB_M1 $blob"
blob=$(gitq -C "$REPO" rev-parse "${M2}:src/fs/loader.ts")
[[ $blob == 4a42cd650e4026df19f137231481e7c771b0110f ]] || fail "BLOB_M2 $blob"
blob=$(gitq -C "$REPO" rev-parse "${CAND}:src/fs/loader.ts")
[[ $blob == b0e471e1147021a16dc85e423b84454574bf5457 ]] || fail "BLOB_CAND $blob"
blob=$(gitq -C "$REPO" rev-parse "v10.25.4:src/fs/loader.ts")
[[ $blob == b0e471e1147021a16dc85e423b84454574bf5457 ]] || fail "BLOB_V254 $blob"
blob=$(gitq -C "$REPO" rev-parse "${FIX}:src/fs/loader.ts")
[[ $blob == bf2fc8261f7d39991689bacb1c58814c3a534e9b ]] || fail "BLOB_FIX $blob"
blob=$(gitq -C "$REPO" rev-parse "v10.25.5:src/fs/loader.ts")
[[ $blob == bf2fc8261f7d39991689bacb1c58814c3a534e9b ]] || fail "BLOB_V255 $blob"
blob=$(gitq -C "$REPO" rev-parse "v10.25.0:src/fs/loader.ts")
[[ $blob == 62c061a1a6b4ccc78ba93eb86657eaf9d8ae01f6 ]] || fail "BLOB_V250 $blob"

echo "== markers and skip strings =="
gitq -C "$REPO" log -1 --format=%B "$CAND" | LC_ALL=C grep -q 'Made-with: Cursor' || fail "CAND_MARKER"
gitq -C "$REPO" log -1 --format=%s "$CAND" | LC_ALL=C grep -q '(#867)' || fail "CAND_SUBJECT"
gitq -C "$REPO" log -1 --format=%B "$FIX" | LC_ALL=C grep -q 'Made-with: Cursor' || fail "FIX_MARKER"
gitq -C "$REPO" log -1 --format=%s "$FIX" | LC_ALL=C grep -q '(#870)' || fail "FIX_SUBJECT"
gitq -C "$REPO" log -1 --format=%B "$M1" | LC_ALL=C grep -E -q 'Made-with:|Co-authored-by:|Co-Authored-By:' && fail "M1_HAS_MARKER" || true
gitq -C "$REPO" log -1 --format=%B "$M2" | LC_ALL=C grep -q 'Made-with: Cursor' || fail "M2_MARKER"
gitq -C "$REPO" log -1 --format=%B "$M3" | LC_ALL=C grep -q 'Made-with: Cursor' || fail "M3_MARKER"
gitq -C "$REPO" grep -q 'type !== LookupType.Root' "$PARENT" -- src/fs/loader.ts || fail "PARENT_SKIP"
gitq -C "$REPO" grep -q 'candidates(file, dirs, currentFile, type !== LookupType.Root)' "$PARENT" -- src/fs/loader.ts || fail "PARENT_CANDIDATES_SKIP"
gitq -C "$REPO" grep -q 'const enforceRoot = type !== LookupType.Root' "$CAND" -- src/fs/loader.ts || fail "CAND_RELOCATED_SKIP"
if gitq -C "$REPO" grep -q 'candidates(file, dirs, currentFile, type !== LookupType.Root)' "$CAND" -- src/fs/loader.ts; then
  fail "CAND_STILL_OLD_FORM"
fi
gitq -C "$REPO" grep -q 'candidates(file, dirs, currentFile, type !== LookupType.Root)' v10.25.0 -- src/fs/loader.ts || fail "V250_SKIP"
if gitq -C "$REPO" grep -q 'type !== LookupType.Root' "$FIX" -- src/fs/loader.ts; then
  fail "FIX_STILL_SKIP"
fi
gitq -C "$REPO" grep -q 'realpath' "$CAND" -- src/fs/fs-impl.ts || fail "CAND_REALPATH"
if gitq -C "$REPO" grep -q 'realpath' v10.25.0 -- src/fs/fs-impl.ts; then
  fail "V250_HAS_REALPATH"
fi
if gitq -C "$REPO" grep -q 'const enforceRoot = type !== LookupType.Root' "$M3" -- src/fs/loader.ts; then
  true
else
  fail "M3_MISSING_SKIP"
fi
subj=$(gitq -C "$REPO" log -1 --format=%s "$SKIP")
[[ $subj == 'fix: skip root check for renderFile()' ]] || fail "SKIP_SUBJ $subj"
gitq -C "$REPO" grep -q '!enforceRoot || referenced.startsWith(dir)' "$SKIP" -- src/fs/loader.ts || fail "SKIP_INTRO_FORM"
gitq -C "$REPO" grep -q 'if (!enforceRoot) return true' "$MAR" -- src/fs/loader.ts || fail "MAR_KEEPS_SKIP"

echo "== pickaxe skip origin =="
pk=$(gitq -C "$REPO" log --first-parent origin/master -S 'type !== LookupType.Root' --format='%H' -- src/fs/loader.ts)
print -r -- "$pk" | LC_ALL=C grep -q "^${FIX}$" || fail "PICKAXE_FIX $pk"
print -r -- "$pk" | LC_ALL=C grep -q "^${SKIP}$" || fail "PICKAXE_SKIP $pk"
print -r -- "$pk" | LC_ALL=C grep -q "^${CAND}$" && fail "PICKAXE_CAND" || true
n=$(print -r -- "$pk" | awk 'NF' | wc -l)
[[ ${n// /} == 2 ]] || fail "PICKAXE_COUNT $n"

echo "== github first-party advisory and releases =="
curl -fsSL -A 'ai-slop-research' -o "$REPLAY_TMP/ghsa.html" \
  'https://github.com/harttle/liquidjs/security/advisories/GHSA-v273-448j-v4qj'
LC_ALL=C grep -q 'GHSA-v273-448j-v4qj' "$REPLAY_TMP/ghsa.html" || fail "HTML_ID"
LC_ALL=C grep -q 'CVE-2026-39859' "$REPLAY_TMP/ghsa.html" || fail "HTML_CVE"
LC_ALL=C grep -q 'LookupType.Root' "$REPLAY_TMP/ghsa.html" || fail "HTML_SKIP"
LC_ALL=C grep -q 'type !== LookupType.Root' "$REPLAY_TMP/ghsa.html" || fail "HTML_PRED"
code=$(curl -fsS -o /dev/null -w '%{http_code}' -A 'ai-slop-research' \
  'https://github.com/harttle/liquidjs/releases/tag/v10.25.4')
[[ $code == 200 ]] || fail "REL254 $code"
code=$(curl -fsS -o /dev/null -w '%{http_code}' -A 'ai-slop-research' \
  'https://github.com/harttle/liquidjs/releases/tag/v10.25.5')
[[ $code == 200 ]] || fail "REL255 $code"

echo "== npm artifacts =="
curl -fsSL -A 'ai-slop-research' -o "$REPLAY_TMP/liquidjs-10.25.0.tgz" \
  https://registry.npmjs.org/liquidjs/-/liquidjs-10.25.0.tgz
curl -fsSL -A 'ai-slop-research' -o "$REPLAY_TMP/liquidjs-10.25.4.tgz" \
  https://registry.npmjs.org/liquidjs/-/liquidjs-10.25.4.tgz
curl -fsSL -A 'ai-slop-research' -o "$REPLAY_TMP/liquidjs-10.25.5.tgz" \
  https://registry.npmjs.org/liquidjs/-/liquidjs-10.25.5.tgz
h=$(sha256sum "$REPLAY_TMP/liquidjs-10.25.0.tgz" | awk '{print $1}')
[[ $h == 0f8859d7cfc72f0daa3da2862c9d9a9ad6889140dec90c7bbe2d7407a7f40c8f ]] || fail "NPM250 $h"
h=$(sha256sum "$REPLAY_TMP/liquidjs-10.25.4.tgz" | awk '{print $1}')
[[ $h == 1f1b47d7b1c99ca90eb26269434ae043ab15153819c42c233ef33ddfa635e9d9 ]] || fail "NPM254 $h"
h=$(sha256sum "$REPLAY_TMP/liquidjs-10.25.5.tgz" | awk '{print $1}')
[[ $h == 312633854786a9dc3d26a966986fc133ba3461e00f73c6d2db7ef1dc4ef13a2d ]] || fail "NPM255 $h"
mkdir "$REPLAY_TMP/n0" "$REPLAY_TMP/n4" "$REPLAY_TMP/n5"
tar -xzf "$REPLAY_TMP/liquidjs-10.25.0.tgz" -C "$REPLAY_TMP/n0"
tar -xzf "$REPLAY_TMP/liquidjs-10.25.4.tgz" -C "$REPLAY_TMP/n4"
tar -xzf "$REPLAY_TMP/liquidjs-10.25.5.tgz" -C "$REPLAY_TMP/n5"
LC_ALL=C grep -q 'type !== LookupType.Root' "$REPLAY_TMP/n0/package/dist/liquid.node.mjs" || fail "NPM250_SKIP"
if LC_ALL=C grep -q 'realpath' "$REPLAY_TMP/n0/package/dist/liquid.node.mjs"; then
  fail "NPM250_REALPATH"
fi
LC_ALL=C grep -q 'const enforceRoot = type !== LookupType.Root' \
  "$REPLAY_TMP/n4/package/dist/liquid.node.mjs" || fail "NPM254_SKIP"
LC_ALL=C grep -q 'realpath' "$REPLAY_TMP/n4/package/dist/liquid.node.mjs" || fail "NPM254_REALPATH"
if LC_ALL=C grep -q 'type !== LookupType.Root' "$REPLAY_TMP/n5/package/dist/liquid.node.mjs"; then
  fail "NPM255_STILL_SKIP"
fi
LC_ALL=C grep -q 'realpath' "$REPLAY_TMP/n5/package/dist/liquid.node.mjs" || fail "NPM255_REALPATH"
echo "NPM_OK"

python3 - "$OWNED" <<'PY' || fail "artifact_hashes"
import hashlib, json, sys
from pathlib import Path
d=Path(sys.argv[1])
res=json.loads((d/"result.json").read_text())
for name in ("report.md","replay.zsh"):
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
allowed={"result.json","report.md","replay.zsh"}
names={p.name for p in d.iterdir()}
extra=names-allowed
if extra:
    raise SystemExit("extra %s" % sorted(extra))
print("hygiene_ok")
PY

echo "REPLAY_OK reviewed=1 KEEP=0 NARROW=0 REJECT=1 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=94"
