#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearpass-x8qq-65h7-grok46-medium.
# English only. Anonymous public access only. No credentials. No GitHub API.
# Never print environment variable names or values. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearpass-x8qq-65h7-grok46-medium}
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
export GIT_NO_LAZY_FETCH=1
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
REPLAY_TMP="$(mktemp -d /tmp/nearpass-x8qq-65h7.XXXXXX)"

GITQ_N=0
gitq() {
  GITQ_N=$((GITQ_N + 1))
  local outfile errfile rc filtered
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  command git -c credential.helper= -c gc.auto=0 "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  filtered="$(grep -v -E -- '^error: unable to normalize alternate object path:|^warning: |^Cloning into|^hint: ' "$errfile" || true)"
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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json" \
  c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/ledger.jsonl" \
  7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096

echo "== conservation 2=2+0 =="
python3 - << PY
import json, sys
from pathlib import Path
owned = Path("$OWNED")
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
aids = [a["case_id"] for a in ass]
cids = [c["case_id"] for c in cas]
want = ["GHSA-X8QQ-M4QC-RPJ5", "GHSA-65H7-C7C4-MGHX"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if len(cas) != 2:
    print("COUNT_FAIL"); sys.exit(1)
if [c["verdict"] for c in cas] != ["NARROW", "NARROW"]:
    print("VERDICT_FAIL", [c["verdict"] for c in cas]); sys.exit(1)
if res["conservation"]["equation"] != "2=2+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res.get("pass_proposal_ids"):
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 94:
    print("FLAG_FAIL"); sys.exit(1)
if res["counts"]["NARROW"] != 2 or res["counts"]["PASS"] != 0:
    print("COUNTS_FAIL"); sys.exit(1)
for rec, ident, ai, rel in (
    (cas[0], "NARROW", "PASS", "NARROW"),
    (cas[1], "PASS", "NARROW", "PASS"),
):
    g = rec["gates"]
    for k in need:
        if k not in g:
            print("MISSING_GATE", rec["case_id"], k); sys.exit(1)
    if g["identity_gate"] != ident or g["ai_hunk_gate"] != ai or g["release_gate"] != rel:
        print("GATE_FAIL", rec["case_id"], g); sys.exit(1)
    if g["topology_gate"] != "PASS" or g["but_for_gate"] != "PASS" or g["fix_reversal_gate"] != "PASS" or g["uniqueness_gate"] != "PASS":
        print("EXPECTED_PASS", rec["case_id"], g); sys.exit(1)
    if rec["seven_gates_exact_pass"] is not False:
        print("SEVEN_SHOULD_NOT_PASS", rec["case_id"]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF"); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER"); sys.exit(1)
if cas[0]["candidate_set"] != ["56ea64c80fd36840fe3c84d0c6a6a38296a8f111","86f406519fd208f9be09cd7cf32cd24d292779fd"]:
    print("CAND_A"); sys.exit(1)
if cas[0]["carrier_set"] != []:
    print("CARRIER_A"); sys.exit(1)
if cas[0]["minimum_fix_set"] != ["9a859c4de3d49674916773d346c60d89ad7febe0"]:
    print("FIX_A"); sys.exit(1)
if cas[0].get("normalized_advisory_sha256") != "309f08e3ff27f20eb12e2fc378fe8a34ab89041cedaee91b842ae565e1c85624":
    print("ADV_A"); sys.exit(1)
if cas[1]["candidate_set"] != ["3094ab608b1d91bff5830d5a89aa042ccd3c9acc"]:
    print("CAND_B"); sys.exit(1)
if cas[1]["carrier_set"] != ["3094ab608b1d91bff5830d5a89aa042ccd3c9acc"]:
    print("CARRIER_B"); sys.exit(1)
if cas[1]["minimum_fix_set"] != ["64aa0ab7207f9c649b59ba1a5f40d82196817389"]:
    print("FIX_B"); sys.exit(1)
if cas[1].get("normalized_advisory_sha256") != "82b1200e2e8ee1a93629751cbdd9c6a32cae0852129df149b55b06519d10cc85":
    print("ADV_B"); sys.exit(1)
print("CONSERVATION_OK 2=2+0 NARROW=2")
PY

echo "== uniqueness vs pinned canonical94 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical94/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical94", hit); sys.exit(1)
if len(strict) != 94:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "BOTH_ABSENT_CANONICAL94")
PY

echo "== advisory objects =="
python3 - <<'PY' || fail "ANON_NETWORK_BLOCKED advisory"
import os, sys, json, hashlib, urllib.request, urllib.error
for k in list(os.environ):
    u = k.upper()
    if any(s in u for s in ("TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH")):
        os.environ.pop(k, None)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ua = {"User-Agent": "Mozilla/5.0"}

def get(url):
    return opener.open(urllib.request.Request(url, headers=ua), timeout=60)

def http_code(url):
    try:
        get(url)
        return 200
    except urllib.error.HTTPError as e:
        return e.code

a = get("https://raw.githubusercontent.com/github/advisory-database/main/advisories/unreviewed/2026/07/GHSA-x8qq-m4qc-rpj5/GHSA-x8qq-m4qc-rpj5.json").read()
if hashlib.sha256(a).hexdigest() != "309f08e3ff27f20eb12e2fc378fe8a34ab89041cedaee91b842ae565e1c85624":
    print("ADV_HASH_A"); sys.exit(1)
ja = json.loads(a)
if ja.get("database_specific", {}).get("github_reviewed") is not False:
    print("REVIEWED_A"); sys.exit(1)
if ja.get("affected") != []:
    print("AFFECTED_A"); sys.exit(1)
if http_code("https://github.com/Roskus/prospero-flow-crm/security/advisories/GHSA-x8qq-m4qc-rpj5") != 404:
    print("REPO_ADV_A"); sys.exit(1)
if http_code("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/07/GHSA-x8qq-m4qc-rpj5/GHSA-x8qq-m4qc-rpj5.json") != 404:
    print("REVIEWED_PATH_A"); sys.exit(1)
html_a = get("https://github.com/advisories/GHSA-x8qq-m4qc-rpj5").read().decode("utf-8", "replace")
if html_a.count("Unreviewed") < 1:
    print("UNREVIEWED_HTML_A"); sys.exit(1)

b = get("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/05/GHSA-65h7-c7c4-mghx/GHSA-65h7-c7c4-mghx.json").read()
if hashlib.sha256(b).hexdigest() != "82b1200e2e8ee1a93629751cbdd9c6a32cae0852129df149b55b06519d10cc85":
    print("ADV_HASH_B"); sys.exit(1)
jb = json.loads(b)
if jb.get("database_specific", {}).get("github_reviewed") is not True:
    print("REVIEWED_B"); sys.exit(1)
pkg = jb["affected"][0]["package"]
if pkg["ecosystem"] != "PyPI" or pkg["name"] != "mlflow":
    print("PKG_B", pkg); sys.exit(1)
if http_code("https://github.com/mlflow/mlflow/security/advisories/GHSA-65h7-c7c4-mghx") != 404:
    print("REPO_ADV_B"); sys.exit(1)
html_b = get("https://github.com/advisories/GHSA-65h7-c7c4-mghx").read().decode("utf-8", "replace")
if html_b.count("GitHub Reviewed") < 1:
    print("REVIEWED_HTML_B"); sys.exit(1)
print("ADVISORY_OK")
PY

echo "== git clone A Roskus/prospero-flow-crm =="
Z="$REPLAY_TMP/prospero"
if ! gitq clone --quiet --no-checkout https://github.com/Roskus/prospero-flow-crm.git "$Z"; then
  fail "ANON_NETWORK_BLOCKED clone_prospero"
fi
C1=56ea64c80fd36840fe3c84d0c6a6a38296a8f111
C2=86f406519fd208f9be09cd7cf32cd24d292779fd
FIXA=9a859c4de3d49674916773d346c60d89ad7febe0
P1=260a0fe319f88bed77dec8a3d331457d6c13fbd9
P2=e8b53c9c781468f03c3a57925811dff110e0420e
FPA=66646511579bd28743373b9ced945864e910fdcf
T460=4c15d20a57c4225bb3853bad2c5b01b3da11121f
T553=584f315878b8366244c95fe3cb016b3a63f05db8
parents=$(gitq -C "$Z" rev-list --parents -n 1 "$C1")
[[ $parents == "$C1 $P1" ]] || fail "PARENTS_C1 $parents"
parents=$(gitq -C "$Z" rev-list --parents -n 1 "$C2")
[[ $parents == "$C2 $P2" ]] || fail "PARENTS_C2 $parents"
parents=$(gitq -C "$Z" rev-list --parents -n 1 "$FIXA")
[[ $parents == "$FIXA $FPA" ]] || fail "PARENTS_FIXA $parents"
gitq -C "$Z" cat-file -p "$C1" | LC_ALL=C grep -q 'Co-Authored-By: Claude Haiku 4.5' || fail "C1_MARKER"
gitq -C "$Z" cat-file -p "$C2" | LC_ALL=C grep -q 'Co-Authored-By: Claude Haiku 4.5' || fail "C2_MARKER"
if gitq -C "$Z" cat-file -p "$FIXA" | LC_ALL=C grep -q 'Co-Authored-By:'; then
  fail "FIXA_MARKER"
fi
blob=$(gitq -C "$Z" rev-parse "${C1}:app/Http/Controllers/Api/Order/OrderReadController.php")
[[ $blob == c3082407aceb561ef47dd89c91ccefe31aa80912 ]] || fail "BLOB_C1_READ $blob"
blob=$(gitq -C "$Z" rev-parse "${C2}:app/Http/Controllers/Api/Order/OrderItemReadController.php")
[[ $blob == 26865a54e8d5c357d51189354031e635da331688 ]] || fail "BLOB_C2_ITEM $blob"
blob=$(gitq -C "$Z" rev-parse "${FIXA}:app/Http/Controllers/Api/Order/OrderReadController.php")
[[ $blob == d2e097debc95c4d936afbc94b0a8ecf29885e676 ]] || fail "BLOB_FIXA_READ $blob"
blob=$(gitq -C "$Z" rev-parse "${FIXA}:app/Http/Controllers/Api/Order/OrderItemReadController.php")
[[ $blob == f3b308b37f65ea395e0a94ff1170e038d68db154 ]] || fail "BLOB_FIXA_ITEM $blob"
parent_read=$(gitq -C "$Z" ls-tree --name-only "$P1" -- app/Http/Controllers/Api/Order/OrderReadController.php)
[[ -z "$parent_read" ]] || fail "P1_HAS_ORDERREAD"
parent_item=$(gitq -C "$Z" ls-tree --name-only "$P2" -- app/Http/Controllers/Api/Order/OrderItemReadController.php)
[[ -z "$parent_item" ]] || fail "P2_HAS_ITEMREAD"
gitq -C "$Z" grep -q 'Order::find($id)' "$C1" -- app/Http/Controllers/Api/Order/OrderReadController.php || fail "C1_FIND"
if gitq -C "$Z" grep -q "company_id" "$C1" -- app/Http/Controllers/Api/Order/OrderReadController.php; then
  fail "C1_HAS_COMPANY"
fi
gitq -C "$Z" grep -q 'Item::find($id)' "$C2" -- app/Http/Controllers/Api/Order/OrderItemReadController.php || fail "C2_FIND"
gitq -C "$Z" grep -q "company_id" "$FIXA" -- app/Http/Controllers/Api/Order/OrderReadController.php || fail "FIXA_COMPANY"
[[ $(gitq -C "$Z" rev-parse "v4.6.0^{commit}") == "$T460" ]] || fail "T460"
[[ $(gitq -C "$Z" rev-parse "v5.5.3^{commit}") == "$T553" ]] || fail "T553"
gitq -C "$Z" merge-base --is-ancestor "$C1" "$FIXA" || fail "C1_ANC_FIX"
gitq -C "$Z" merge-base --is-ancestor "$C2" "$FIXA" || fail "C2_ANC_FIX"
gitq -C "$Z" merge-base --is-ancestor "$C1" v5.5.3 || fail "C1_553"
gitq -C "$Z" merge-base --is-ancestor "$FIXA" v5.5.3 || fail "FIXA_553"
gitq -C "$Z" merge-base --is-ancestor "$C1" v4.6.0 && fail "C1_IN_460" || true
blob=$(gitq -C "$Z" rev-parse "v5.5.3:app/Http/Controllers/Api/Order/OrderReadController.php")
[[ $blob == d2e097debc95c4d936afbc94b0a8ecf29885e676 ]] || fail "553_EQUALS_FIX"
missing_460=$(gitq -C "$Z" ls-tree --name-only "v4.6.0" -- app/Http/Controllers/Api/Order/OrderReadController.php)
[[ -z "$missing_460" ]] || fail "460_HAS_ORDERREAD"
echo "GIT_A_OK"

echo "== git clone B mlflow/mlflow =="
export GIT_NO_LAZY_FETCH=0
M="$REPLAY_TMP/mlflow"
if ! gitq clone --quiet --filter=blob:none --no-checkout https://github.com/mlflow/mlflow.git "$M"; then
  fail "ANON_NETWORK_BLOCKED clone_mlflow"
fi
if ! gitq -C "$M" fetch --quiet --filter=blob:none origin \
  tag v3.2.0 tag v3.3.0 tag v3.9.0 tag v3.10.0 tag v3.11.1 \
  3094ab608b1d91bff5830d5a89aa042ccd3c9acc \
  64aa0ab7207f9c649b59ba1a5f40d82196817389 \
  4a724addefd1950a43b62eb4c89894b4e75e01c6 \
  24dcf3f8a9ef3c5161edb654ae3d435f693a1877; then
  fail "ANON_NETWORK_BLOCKED fetch_mlflow"
fi
CAND=3094ab608b1d91bff5830d5a89aa042ccd3c9acc
FIXB=64aa0ab7207f9c649b59ba1a5f40d82196817389
PB=4a724addefd1950a43b62eb4c89894b4e75e01c6
FPB=24dcf3f8a9ef3c5161edb654ae3d435f693a1877
parents=$(gitq -C "$M" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PB" ]] || fail "PARENTS_CAND $parents"
parents=$(gitq -C "$M" rev-list --parents -n 1 "$FIXB")
[[ $parents == "$FIXB $FPB" ]] || fail "PARENTS_FIXB $parents"
gitq -C "$M" cat-file -p "$CAND" | LC_ALL=C grep -q 'Co-authored-by: Claude <noreply@anthropic.com>' || fail "CAND_MARKER"
if gitq -C "$M" cat-file -p "$FIXB" | LC_ALL=C grep -q 'Co-authored-by: Claude'; then
  fail "FIXB_MARKER"
fi
nfiles=$(gitq -C "$M" diff-tree --no-commit-id --name-only -r "$CAND" | wc -l | awk '{print $1}')
[[ $nfiles == 41 ]] || fail "NFILES $nfiles"
blob=$(gitq -C "$M" rev-parse "${CAND}:mlflow/webhooks/delivery.py")
[[ $blob == aac46a21a5fe97d695ab95304a1ce23abf277cf0 ]] || fail "BLOB_DEL_CAND $blob"
parent_del=$(gitq -C "$M" ls-tree --name-only "$PB" -- mlflow/webhooks/delivery.py)
[[ -z "$parent_del" ]] || fail "PARENT_HAS_DELIVERY"
blob=$(gitq -C "$M" rev-parse "${FIXB}:mlflow/webhooks/delivery.py")
[[ $blob == 2d7c7c88cf30436128dbddcfdd17dbcd76065709 ]] || fail "BLOB_DEL_FIX $blob"
gitq -C "$M" grep -q 'session.post(webhook.url' "$CAND" -- mlflow/webhooks/delivery.py || fail "CAND_POST"
if gitq -C "$M" grep -q '_validate_webhook_url(webhook.url)' "$CAND" -- mlflow/webhooks/delivery.py; then
  fail "CAND_DELIVERY_VALIDATE"
fi
if gitq -C "$M" grep -q 'ip.is_global' "$CAND" -- mlflow/utils/validation.py; then
  fail "CAND_IS_GLOBAL"
fi
gitq -C "$M" grep -q 'ip.is_global' "$FIXB" -- mlflow/utils/validation.py || fail "FIX_IS_GLOBAL"
gitq -C "$M" grep -q '_validate_webhook_url(webhook.url)' "$FIXB" -- mlflow/webhooks/delivery.py || fail "FIX_DELIVERY_VALIDATE"
[[ $(gitq -C "$M" rev-parse "v3.2.0^{commit}") == e1de6be10b4044f4b4a493ae9dabc3e6827ad41e ]] || fail "T320"
[[ $(gitq -C "$M" rev-parse "v3.3.0^{commit}") == f2266fa9f4583612aa1eb0ca9b63046f12153ce1 ]] || fail "T330"
[[ $(gitq -C "$M" rev-parse "v3.9.0^{commit}") == cf3d582a7b8a6f234e4d28ef6987bb8076c6ee54 ]] || fail "T390"
[[ $(gitq -C "$M" rev-parse "v3.11.1^{commit}") == 09179c65741c4d40df2e934950e32f526a2c0e9e ]] || fail "T3111"
gitq -C "$M" merge-base --is-ancestor "$CAND" v3.3.0 || fail "CAND_330"
gitq -C "$M" merge-base --is-ancestor "$CAND" v3.2.0 && fail "CAND_IN_320" || true
gitq -C "$M" merge-base --is-ancestor "$FIXB" v3.11.1 || fail "FIX_3111"
gitq -C "$M" merge-base --is-ancestor "$FIXB" v3.9.0 && fail "FIX_IN_390" || true
gitq -C "$M" merge-base --is-ancestor "$CAND" "$FIXB" || fail "CAND_ANC_FIXB"
missing_320=$(gitq -C "$M" ls-tree --name-only "v3.2.0" -- mlflow/webhooks/delivery.py)
[[ -z "$missing_320" ]] || fail "320_HAS_DELIVERY"
blob=$(gitq -C "$M" rev-parse "v3.3.0:mlflow/webhooks/delivery.py")
[[ $blob == aac46a21a5fe97d695ab95304a1ce23abf277cf0 ]] || fail "330_DEL $blob"
echo "GIT_B_OK"

echo "== release channels =="
python3 - <<'PY' || fail "ANON_NETWORK_BLOCKED release"
import os, sys, json, hashlib, io, zipfile, urllib.request, urllib.error
for k in list(os.environ):
    u = k.upper()
    if any(s in u for s in ("TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH")):
        os.environ.pop(k, None)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ua = {"User-Agent": "Mozilla/5.0"}

def get(url):
    return opener.open(urllib.request.Request(url, headers=ua), timeout=120)

def code(url):
    try:
        get(url)
        return 200
    except urllib.error.HTTPError as e:
        return e.code

if code("https://github.com/Roskus/prospero-flow-crm/releases/tag/v5.5.3") != 200:
    print("REL_553"); sys.exit(1)
if code("https://github.com/Roskus/prospero-flow-crm/releases/tag/v4.6.0") != 200:
    print("REL_460"); sys.exit(1)
if code("https://repo.packagist.org/p2/roskus/prospero-flow-crm.json") != 404:
    print("PACKAGIST"); sys.exit(1)
if code("https://github.com/mlflow/mlflow/releases/tag/v3.3.0") != 200:
    print("REL_330"); sys.exit(1)
if code("https://github.com/mlflow/mlflow/releases/tag/v3.11.1") != 200:
    print("REL_3111"); sys.exit(1)

want = {
    "3.3.0": ("f05786d5fcb45cf6fa21ea3c59116b58e47c2d3566e79651de229c29db70819c", False, True, False),
    "3.9.0": ("280f94854e5ece42fc5538180b276661c62dbfb2c848a98e8873e78915379ac6", False, True, False),
    "3.11.1": ("8f6bf1238ac04f97664c229dd480380c5c254a78bdb3c0e433e3a0397508b1af", True, True, True),
}
for ver, (sha, is_global, has_post, has_call) in want.items():
    meta = json.loads(get("https://pypi.org/pypi/mlflow/%s/json" % ver).read())
    url = None
    digest = None
    for f in meta["urls"]:
        if f["filename"].endswith("py3-none-any.whl"):
            url = f["url"]
            digest = f["digests"]["sha256"]
            break
    if digest != sha:
        print("PYPI_META", ver, digest); sys.exit(1)
    data = get(url).read()
    if hashlib.sha256(data).hexdigest() != sha:
        print("PYPI_SHA", ver); sys.exit(1)
    z = zipfile.ZipFile(io.BytesIO(data))
    val = z.read("mlflow/utils/validation.py").decode("utf-8")
    deliv = z.read("mlflow/webhooks/delivery.py").decode("utf-8")
    if ("is_global" in val) is not is_global:
        print("WHEEL_GLOBAL", ver); sys.exit(1)
    if ("post(webhook.url" in deliv) is not has_post:
        print("WHEEL_POST", ver); sys.exit(1)
    if ("_validate_webhook_url(webhook.url)" in deliv) is not has_call:
        print("WHEEL_CALL", ver); sys.exit(1)
print("RELEASE_OK")
PY

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

echo "REPLAY_OK reviewed=2 PASS_proposal=0 REJECT=0 NARROW=2 UNKNOWN=0 BLOCKED=0"
