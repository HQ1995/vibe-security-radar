#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearpass-release3-grok46-xhigh.
# English only. Anonymous public access only. No credentials. No GitHub API.
# Never print environment variable names or values. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearpass-release3-grok46-xhigh}
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

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d /tmp/nearpass-release3.XXXXXX)"
mkdir -p "$REPLAY_TMP/home"

ANON_ENV=(
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  HOME="$REPLAY_TMP/home"
  GIT_TERMINAL_PROMPT=0
  GIT_OPTIONAL_LOCKS=0
  GIT_PAGER=cat
  GIT_CONFIG_NOSYSTEM=1
  GIT_CONFIG_GLOBAL=/dev/null
  GIT_CONFIG_SYSTEM=/dev/null
  GIT_ALLOW_PROTOCOL=https:git
  LC_ALL=C
)

anon() {
  /usr/bin/env -i "${ANON_ENV[@]}" "$@"
}

GITQ_N=0
gitq() {
  GITQ_N=$((GITQ_N + 1))
  local outfile errfile rc filtered
  outfile="$REPLAY_TMP/out.$GITQ_N"
  errfile="$REPLAY_TMP/err.$GITQ_N"
  set +e
  anon /usr/bin/git -c credential.helper= -c protocol.https.allow=always \
    -c init.defaultBranch=main "$@" >"$outfile" 2>"$errfile"
  rc=$?
  set -e
  filtered="$(grep -v -E -- '^error: unable to normalize alternate object path:|^warning: |^Cloning into|^remote: |Receiving objects:|Resolving deltas:|Enumerating objects:|Counting objects:|Compressing objects:|hint: |filter-process|partial clone|origin/HEAD|FETCH_HEAD|Clone succeeded|Filtering content|^From https://github.com/|^Updating files:|^ \* |^[[:space:]]*$' "$errfile" || true)"
  if [[ -n "$filtered" ]]; then
    rm -f "$outfile" "$errfile"
    fail "git stderr: $filtered"
  fi
  cat "$outfile"
  rm -f "$outfile" "$errfile"
  return $rc
}

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'ENDASCII' || fail "ascii $f"
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
if not b.endswith(b"\n"):
    raise SystemExit(1)
ENDASCII
done

hash_check() {
  local f=$1 want=$2
  local got
  got=$(sha256sum "$f" | awk '{print $1}')
  if [[ $got != "$want" ]]; then
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

echo "== conservation 3=3+0 =="
python3 - << ENDCONS
import json, sys
from pathlib import Path
owned = Path("$OWNED")
ass = [json.loads(l) for l in owned.joinpath("assignment.jsonl").open() if l.strip()]
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
aids = [a["case_id"] for a in ass]
cids = [c["case_id"] for c in cas]
want = ["GHSA-8G98-M4J9-QWW5", "GHSA-VH5J-5FHQ-9XWG", "GHSA-G8MR-85JM-7XHM"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [56, 84, 157]:
    print("ORDINAL_FAIL"); sys.exit(1)
if len(cas) != 3 or any(c["verdict"] != "NARROW" for c in cas):
    print("COUNT_FAIL", [c["verdict"] for c in cas]); sys.exit(1)
if res["conservation"]["equation"] != "3=3+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res.get("pass_proposal_ids"):
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 94:
    print("FLAG_FAIL"); sys.exit(1)
if res["counts"]["NARROW"] != 3 or res["counts"]["PASS_PROPOSAL"] != 0:
    print("COUNTS_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if k not in g:
            print("MISSING_GATE", rec["case_id"], k); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER", rec["case_id"]); sys.exit(1)
    if rec["seven_gates_exact_pass"] is not False:
        print("SEVEN_SHOULD_NOT_PASS", rec["case_id"]); sys.exit(1)
    if rec["gates"]["release_gate"] != "NARROW":
        print("RELEASE_NOT_NARROW", rec["case_id"]); sys.exit(1)
    if rec["gates"]["uniqueness_gate"] != "PASS":
        print("UNIQ_NOT_PASS", rec["case_id"]); sys.exit(1)
    if rec["gates"]["identity_gate"] != "PASS":
        print("ID_NOT_PASS", rec["case_id"]); sys.exit(1)
c0, c1, c2 = cas
if c0["candidate_set"] != ["c139c021f68a09d22c2af88641b61c00f67f2af4"]:
    print("CAND0"); sys.exit(1)
if c0["carrier_set"] != []:
    print("CAR0"); sys.exit(1)
if c0["minimum_fix_set"] != ["57b7634391959dbbdb39b387ac4dc68157cd58a1"]:
    print("FIX0"); sys.exit(1)
if c0["gates"]["ai_hunk_gate"] != "PASS" or c0["gates"]["but_for_gate"] != "PASS":
    print("G0A"); sys.exit(1)
if c0["gates"]["topology_gate"] != "PASS" or c0["gates"]["fix_reversal_gate"] != "NARROW":
    print("G0B"); sys.exit(1)
if c1["candidate_set"] != ["57b7634391959dbbdb39b387ac4dc68157cd58a1"]:
    print("CAND1"); sys.exit(1)
if c1["carrier_set"] != []:
    print("CAR1"); sys.exit(1)
if c1["minimum_fix_set"] != ["fdf67a6fba0deae30912905a79fb5a9e83751a79"]:
    print("FIX1"); sys.exit(1)
if c1["contribution_class"] != "AI_INCOMPLETE_REMEDIATION":
    print("CLASS1"); sys.exit(1)
if c1["gates"]["fix_reversal_gate"] != "PASS" or c1["gates"]["ai_hunk_gate"] != "PASS":
    print("G1"); sys.exit(1)
if c2["candidate_set"] != ["af88b1f5d82844a4761ea9a977156c98e2b14ca8"]:
    print("CAND2"); sys.exit(1)
if c2["minimum_fix_set"] != ["385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7"]:
    print("FIX2"); sys.exit(1)
if c2["aliases"] != ["CVE-2026-53633"]:
    print("ALIASES2"); sys.exit(1)
if c2["gates"]["ai_hunk_gate"] != "NARROW" or c2["gates"]["but_for_gate"] != "NARROW":
    print("G2"); sys.exit(1)
if c2["gates"]["fix_reversal_gate"] != "PASS":
    print("G2FIX"); sys.exit(1)
if c0["normalized_advisory_sha256"] != "f4fedb15f8a2111c0cea29d6395ded0a6cd1fe485323445869adbac9ad7e6d5b":
    print("ADV0"); sys.exit(1)
if c1["normalized_advisory_sha256"] != "09de4af70be2e8832a22d07a3a7fca661eed55966e728d4236b17784278ab198":
    print("ADV1"); sys.exit(1)
if c2["normalized_advisory_sha256"] != "68b456ebbcb07bafe0e82a7589c0a73cce8e43d648a0fea1119a4fe3f9f016e4":
    print("ADV2"); sys.exit(1)
print("CONSERVATION_OK 3=3+0 NARROW=3")
ENDCONS

echo "== uniqueness vs pinned canonical94 =="
python3 - << ENDUNIQ
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
print("UNIQUENESS_OK", len(ids), "ABSENT_CANONICAL94")
ENDUNIQ

echo "== git fetch taylored =="
ZT="$REPLAY_TMP/taylored.git"
gitq -c init.defaultBranch=main init -q --bare "$ZT" >/dev/null
gitq --git-dir="$ZT" remote add origin https://github.com/tailot/taylored.git
if ! gitq --git-dir="$ZT" fetch --quiet --no-progress --filter=blob:none origin \
  +c139c021f68a09d22c2af88641b61c00f67f2af4:refs/repro/c139 \
  +57b7634391959dbbdb39b387ac4dc68157cd58a1:refs/repro/57b7 \
  +5e5a80b5ffd0b6fccf7bdc2d8793e8b01cb83844:refs/repro/5e5a \
  +fdf67a6fba0deae30912905a79fb5a9e83751a79:refs/repro/fdf6 \
  +refs/tags/8.2.4:refs/tags/8.2.4; then
  fail "ANON_NETWORK_BLOCKED fetch_taylored"
fi

C139=c139c021f68a09d22c2af88641b61c00f67f2af4
P139=610281a664bd4e8c8d0c7052116bedaea5c8a4c6
F57=57b7634391959dbbdb39b387ac4dc68157cd58a1
H5E=5e5a80b5ffd0b6fccf7bdc2d8793e8b01cb83844
FDF=fdf67a6fba0deae30912905a79fb5a9e83751a79
PFDF=f4d210457781256860c0779cc2090f957d1ebf3d
TPL=templates/backend-in-a-box/index.js

parents=$(gitq --git-dir="$ZT" rev-list --parents -n 1 "$C139")
[[ $parents == "$C139 $P139" ]] || fail "C139_PARENTS $parents"
parents=$(gitq --git-dir="$ZT" rev-list --parents -n 1 "$F57")
[[ $parents == "$F57 $C139" ]] || fail "F57_PARENTS $parents"
parents=$(gitq --git-dir="$ZT" rev-list --parents -n 1 "$H5E")
[[ $parents == "$H5E $F57" ]] || fail "H5E_PARENTS $parents"
parents=$(gitq --git-dir="$ZT" rev-list --parents -n 1 "$FDF")
[[ $parents == "$FDF $PFDF" ]] || fail "FDF_PARENTS $parents"

an=$(gitq --git-dir="$ZT" log -1 --format='%an' "$C139")
[[ $an == "google-labs-jules[bot]" ]] || fail "C139_AUTHOR $an"
an=$(gitq --git-dir="$ZT" log -1 --format='%an' "$F57")
[[ $an == "google-labs-jules[bot]" ]] || fail "F57_AUTHOR $an"
an=$(gitq --git-dir="$ZT" log -1 --format='%an' "$H5E")
[[ $an == "vincenzo" ]] || fail "H5E_AUTHOR $an"
an=$(gitq --git-dir="$ZT" log -1 --format='%an' "$FDF")
[[ $an == "vincenzo" ]] || fail "FDF_AUTHOR $an"

blob=$(gitq --git-dir="$ZT" rev-parse "${C139}:${TPL}")
[[ $blob == 0dd0853c7f2c5b9443f9d5564d79a7b96d179bc7 ]] || fail "TPL_C139 $blob"
blob=$(gitq --git-dir="$ZT" rev-parse "${F57}:${TPL}")
[[ $blob == 8a5317f90c56685b73d643b5757679a2c9ba177c ]] || fail "TPL_F57 $blob"
blob=$(gitq --git-dir="$ZT" rev-parse "${H5E}:${TPL}")
[[ $blob == 472511e7590c3b5c681bebf851b87ad9e16cf81b ]] || fail "TPL_H5E $blob"
blob=$(gitq --git-dir="$ZT" rev-parse "${PFDF}:${TPL}")
[[ $blob == 5356a651a490b2709849401ae92d90579c75ddcd ]] || fail "TPL_PFDF $blob"
blob=$(gitq --git-dir="$ZT" rev-parse "${FDF}:${TPL}")
[[ $blob == 4cc255d79c158e4f2552ac1f7efcf0742bbedd81 ]] || fail "TPL_FDF $blob"
blob=$(gitq --git-dir="$ZT" rev-parse "8.2.4:${TPL}")
[[ $blob == 706a6e1da64c99778f8e5cfe9cf0a143998a1e2f ]] || fail "TPL_824 $blob"

missing=$(gitq --git-dir="$ZT" ls-tree --name-only "$P139" -- "$TPL")
[[ -z "$missing" ]] || fail "PARENT_HAS_TEMPLATE"

gitq --git-dir="$ZT" merge-base --is-ancestor "$C139" 8.2.4 || fail "C139_ANC_824"
gitq --git-dir="$ZT" merge-base --is-ancestor "$F57" 8.2.4 || fail "F57_ANC_824"
gitq --git-dir="$ZT" merge-base --is-ancestor "$FDF" 8.2.4 || fail "FDF_ANC_824"

peel=$(gitq --git-dir="$ZT" rev-parse '8.2.4^{commit}')
[[ $peel == 05da9137527cb7be236bb8e63f1c3b0dffcc6b2a ]] || fail "PEEL824 $peel"

gitq --git-dir="$ZT" show "${C139}:${TPL}" >"$REPLAY_TMP/c139.index.js"
gitq --git-dir="$ZT" show "${F57}:${TPL}" >"$REPLAY_TMP/57b7.index.js"
gitq --git-dir="$ZT" show "${FDF}:${TPL}" >"$REPLAY_TMP/fdf6.index.js"
python3 - "$REPLAY_TMP/c139.index.js" "$REPLAY_TMP/57b7.index.js" "$REPLAY_TMP/fdf6.index.js" <<'ENDTPL' || fail "TPL_MARKERS"
from pathlib import Path
import sys
c139=Path(sys.argv[1]).read_text()
b57=Path(sys.argv[2]).read_text()
fdf=Path(sys.argv[3]).read_text()
if "PBKDF2_ITERATIONS = 100000" not in c139:
    raise SystemExit("c139 pbkdf2")
if "token_used_at" in c139:
    raise SystemExit("c139 token")
if "path.basename" in c139:
    raise SystemExit("c139 basename")
if "verifyAndGetWebhookEvent" not in b57:
    raise SystemExit("57b7 webhook")
if "token_used_at" not in b57:
    raise SystemExit("57b7 token")
if "path.basename" in b57:
    raise SystemExit("57b7 basename unexpected")
if "token_used_at IS NULL" not in fdf:
    raise SystemExit("fdf atomic")
if "SELECT id, token_used_at FROM purchases" in fdf:
    raise SystemExit("fdf still two-step")
print("TPL_MARKERS_OK")
ENDTPL

if ! tags=$(gitq ls-remote --tags https://github.com/tailot/taylored.git); then
  fail "ANON_NETWORK_BLOCKED ls-remote_taylored"
fi
print -r -- "$tags" | LC_ALL=C grep -q '^05da9137527cb7be236bb8e63f1c3b0dffcc6b2a[[:space:]]refs/tags/8.2.4$' || fail "LSREMOTE_824"
n_tags=$(print -r -- "$tags" | grep -c 'refs/tags/' || true)
[[ ${n_tags// /} == 1 ]] || fail "TAYLORED_TAG_COUNT $n_tags"
echo "TAYLORED_GIT_OK"

echo "== git fetch vitest =="
ZV="$REPLAY_TMP/vitest.git"
gitq -c init.defaultBranch=main init -q --bare "$ZV" >/dev/null
gitq --git-dir="$ZV" remote add origin https://github.com/vitest-dev/vitest.git
if ! gitq --git-dir="$ZV" fetch --quiet --no-progress --filter=blob:none origin \
  +af88b1f5d82844a4761ea9a977156c98e2b14ca8:refs/repro/af88 \
  +385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7:refs/repro/385a \
  +refs/tags/v3.2.4:refs/tags/v3.2.4 \
  +refs/tags/v3.2.5:refs/tags/v3.2.5; then
  fail "ANON_NETWORK_BLOCKED fetch_vitest"
fi

CAND=af88b1f5d82844a4761ea9a977156c98e2b14ca8
PAR=5a7d56e2235d63441a23c54dc85ecffcbfe7cf44
FIX=385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7
RPC=packages/browser/src/node/rpc.ts

parents=$(gitq --git-dir="$ZV" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PAR" ]] || fail "CAND_PARENTS $parents"
parents=$(gitq --git-dir="$ZV" rev-list --parents -n 1 "$FIX")
[[ $parents == "$FIX $CAND" ]] || fail "FIX_PARENTS $parents"
gitq --git-dir="$ZV" log -1 --format='%b' "$CAND" | LC_ALL=C grep -q 'Co-authored-by: Codex <noreply@openai.com>' || fail "CAND_CODEX"
gitq --git-dir="$ZV" log -1 --format='%b' "$FIX" | LC_ALL=C grep -q 'Co-authored-by: Codex <noreply@openai.com>' || fail "FIX_CODEX"

blob=$(gitq --git-dir="$ZV" rev-parse "${PAR}:${RPC}")
[[ $blob == 7619c5f0fc4b66ea0992e61e357331c6280e4a29 ]] || fail "RPC_PAR $blob"
blob=$(gitq --git-dir="$ZV" rev-parse "${CAND}:${RPC}")
[[ $blob == 358ac355f89983297c18932c68e5aea7d78020ea ]] || fail "RPC_CAND $blob"
blob=$(gitq --git-dir="$ZV" rev-parse "${FIX}:${RPC}")
[[ $blob == 72818584f0669b58db74b6e093e04173c083293e ]] || fail "RPC_FIX $blob"
blob=$(gitq --git-dir="$ZV" rev-parse "v3.2.4:${RPC}")
[[ $blob == 7619c5f0fc4b66ea0992e61e357331c6280e4a29 ]] || fail "RPC_324 $blob"
blob=$(gitq --git-dir="$ZV" rev-parse "v3.2.5:${RPC}")
[[ $blob == 72818584f0669b58db74b6e093e04173c083293e ]] || fail "RPC_325 $blob"

gitq --git-dir="$ZV" merge-base --is-ancestor "$CAND" v3.2.4 && fail "CAND_IN_324" || true
gitq --git-dir="$ZV" merge-base --is-ancestor "$FIX" v3.2.4 && fail "FIX_IN_324" || true
gitq --git-dir="$ZV" merge-base --is-ancestor "$CAND" v3.2.5 || fail "CAND_325"
gitq --git-dir="$ZV" merge-base --is-ancestor "$FIX" v3.2.5 || fail "FIX_325"

peel=$(gitq --git-dir="$ZV" rev-parse 'v3.2.4^{commit}')
[[ $peel == c666d149a4516761bae92ca56ce1336d2fd352c3 ]] || fail "PEEL324 $peel"
peel=$(gitq --git-dir="$ZV" rev-parse 'v3.2.5^{commit}')
[[ $peel == 2cbad0a923c48c6144266df3cd25f93547cb5221 ]] || fail "PEEL325 $peel"

if ! tags=$(gitq ls-remote --tags https://github.com/vitest-dev/vitest.git refs/tags/v3.2.4 refs/tags/v3.2.5); then
  fail "ANON_NETWORK_BLOCKED ls-remote_vitest"
fi
print -r -- "$tags" | LC_ALL=C grep -q 'refs/tags/v3.2.4$' || fail "LSREMOTE_324"
print -r -- "$tags" | LC_ALL=C grep -q 'refs/tags/v3.2.5$' || fail "LSREMOTE_325"
echo "VITEST_GIT_OK"

echo "== advisory npm tarballs =="
anon /usr/bin/python3 - <<'ENDNET' || fail "ANON_NETWORK_BLOCKED advisory_or_tar"
import hashlib, io, json, os, sys, tarfile, urllib.error, urllib.request

for k in list(os.environ):
    u = k.upper()
    if any(s in u for s in ("TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH")):
        os.environ.pop(k, None)

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def fetch(url, timeout=180):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.getcode(), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""

def git_blob(content):
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()

def ident_hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()

code, data = fetch("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2025/06/GHSA-8g98-m4j9-qww5/GHSA-8g98-m4j9-qww5.json")
if code != 200:
    print("ADVDB_8G98", code); sys.exit(1)
d = json.loads(data)
if d.get("id") != "GHSA-8g98-m4j9-qww5" or d.get("withdrawn"):
    print("ADVDB_8G98_ID"); sys.exit(1)
pkg = d["affected"][0]["package"]
if pkg["ecosystem"] != "npm" or pkg["name"] != "taylored":
    print("ADVDB_8G98_PKG"); sys.exit(1)
ident = {
    "aliases": [],
    "cwe_ids": ["CWE-22", "CWE-294", "CWE-345", "CWE-916"],
    "first_patched_version": "7.0.8",
    "ghsa_id": "GHSA-8g98-m4j9-qww5",
    "html_url": "https://github.com/tailot/taylored/security/advisories/GHSA-8g98-m4j9-qww5",
    "package_ecosystem": "npm",
    "package_name": "taylored",
    "repository": "tailot/taylored",
    "severity": "critical",
    "state": "published",
    "summary": "Taylored webhook validation vulnerabilities",
    "vulnerable_version_range": ">= 7.0.5, < 7.0.8",
    "withdrawn_at": None,
}
if ident_hash(ident) != "f4fedb15f8a2111c0cea29d6395ded0a6cd1fe485323445869adbac9ad7e6d5b":
    print("IDENT_8G98", ident_hash(ident)); sys.exit(1)

code, data = fetch("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2025/06/GHSA-vh5j-5fhq-9xwg/GHSA-vh5j-5fhq-9xwg.json")
if code != 200:
    print("ADVDB_VH5J", code); sys.exit(1)
d = json.loads(data)
if d.get("id") != "GHSA-vh5j-5fhq-9xwg" or d.get("withdrawn"):
    print("ADVDB_VH5J_ID"); sys.exit(1)
ident = {
    "aliases": [],
    "cwe_ids": ["CWE-362"],
    "first_patched_version": "8.1.3",
    "ghsa_id": "GHSA-vh5j-5fhq-9xwg",
    "html_url": "https://github.com/tailot/taylored/security/advisories/GHSA-vh5j-5fhq-9xwg",
    "package_ecosystem": "npm",
    "package_name": "taylored",
    "repository": "tailot/taylored",
    "severity": "low",
    "state": "published",
    "summary": "Taylor has race condition in /get-patch that allows purchase token replay",
    "vulnerable_version_range": "<= 8.1.2",
    "withdrawn_at": None,
}
if ident_hash(ident) != "09de4af70be2e8832a22d07a3a7fca661eed55966e728d4236b17784278ab198":
    print("IDENT_VH5J", ident_hash(ident)); sys.exit(1)

code, data = fetch("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/06/GHSA-g8mr-85jm-7xhm/GHSA-g8mr-85jm-7xhm.json")
if code != 200:
    print("ADVDB_G8MR", code); sys.exit(1)
d = json.loads(data)
if d.get("id") != "GHSA-g8mr-85jm-7xhm" or "CVE-2026-53633" not in (d.get("aliases") or []):
    print("ADVDB_G8MR_ID"); sys.exit(1)
if d.get("withdrawn"):
    print("ADVDB_G8MR_WITHDRAWN"); sys.exit(1)
ident = {
    "aliases": ["CVE-2026-53633"],
    "cwe_ids": ["CWE-749", "CWE-862"],
    "first_patched_versions": {
        "@vitest/browser": ["3.2.5", "4.1.8", "5.0.0-beta.4"],
        "vite-plus": ["0.1.24"],
    },
    "ghsa_id": "GHSA-g8mr-85jm-7xhm",
    "html_url": "https://github.com/vitest-dev/vitest/security/advisories/GHSA-g8mr-85jm-7xhm",
    "package_ecosystem": "npm",
    "package_names": ["@vitest/browser", "vite-plus"],
    "repository": "vitest-dev/vitest",
    "severity": "critical",
    "state": "published",
    "summary": "Vitest Browser: Exposed Browser Mode API Can Proxy CDP and Overwrite Config Files, Leading to RCE",
    "vulnerable_version_ranges": [
        ">= 5.0.0-beta.0, <= 5.0.0-beta.3",
        ">= 4.0.0, <= 4.1.7",
        ">= 3.0.0, <= 3.2.4",
        "vite-plus <= 0.1.23",
    ],
    "withdrawn_at": None,
}
if ident_hash(ident) != "68b456ebbcb07bafe0e82a7589c0a73cce8e43d648a0fea1119a4fe3f9f016e4":
    print("IDENT_G8MR", ident_hash(ident)); sys.exit(1)

code, html = fetch("https://github.com/tailot/taylored/security/advisories/GHSA-8g98-m4j9-qww5")
if code != 200 or b"GHSA-8g98-m4j9-qww5" not in html or b"taylored" not in html:
    print("REPO_8G98"); sys.exit(1)
code, html = fetch("https://github.com/tailot/taylored/security/advisories/GHSA-vh5j-5fhq-9xwg")
if code != 200 or b"GHSA-vh5j-5fhq-9xwg" not in html:
    print("REPO_VH5J"); sys.exit(1)
code, html = fetch("https://github.com/vitest-dev/vitest/security/advisories/GHSA-g8mr-85jm-7xhm")
if code != 200 or b"CVE-2026-53633" not in html or b"@vitest/browser" not in html:
    print("REPO_G8MR"); sys.exit(1)

code, html = fetch("https://github.com/tailot/taylored/releases")
if code != 200 or b"any releases here" not in html:
    print("REL_TAYLORED"); sys.exit(1)
code, html = fetch("https://github.com/vitest-dev/vitest/releases/tag/v3.2.4")
if code != 200 or b"released this" not in html or b"v3.2.4" not in html:
    print("REL324"); sys.exit(1)
code, html = fetch("https://github.com/vitest-dev/vitest/releases/tag/v3.2.5")
if code != 200 or b"released this" not in html or b"v3.2.5" not in html:
    print("REL325"); sys.exit(1)

for ver in ("7.0.5", "7.0.6", "7.0.7", "7.0.8", "8.1.2", "8.1.3"):
    code, data = fetch("https://registry.npmjs.org/taylored/" + ver)
    if code != 404:
        print("NPM_VER_NOT_404", ver, code); sys.exit(1)
    code, data = fetch("https://registry.npmjs.org/taylored/-/taylored-%s.tgz" % ver)
    if code != 404:
        print("NPM_TGZ_NOT_404", ver, code); sys.exit(1)

code, data = fetch("https://pypi.org/pypi/taylored/json")
if code != 404:
    print("PYPI_NOT_404", code); sys.exit(1)

code, data = fetch("https://registry.npmjs.org/taylored/-/taylored-8.2.4.tgz")
if code != 200:
    print("TARBALL_824_HTTP", code); sys.exit(1)
got = hashlib.sha256(data).hexdigest()
if got != "932bd516fdc4e42ba349cd5c2fd3937021bb0a731eb593262d1807df811ef9ec":
    print("TARBALL_824_SHA", got); sys.exit(1)
tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
content = tf.extractfile("package/dist/templates/backend-in-a-box/index.js").read()
if git_blob(content) != "706a6e1da64c99778f8e5cfe9cf0a143998a1e2f":
    print("TARBALL_824_BLOB", git_blob(content)); sys.exit(1)
text = content.decode("utf-8")
if "token_used_at IS NULL" not in text or "path.basename" not in text:
    print("TARBALL_824_MARKERS"); sys.exit(1)
if "SELECT id, token_used_at FROM purchases" in text:
    print("TARBALL_824_TWO_STEP"); sys.exit(1)

want_tars = {
    "3.2.4": ("a24c6adef75dbebadbadbb1eef2723ad5dd44e4c3509e4c46370310646cb5f38", "3ca37317074fd085a94a7e83c07982c6e19718e5", False, False),
    "3.2.5": ("0f4e1678d753e9f0cd70d0f29326561dafcb1242156b8010fa83c914fb19120b", "e1ef861c36aa06c5dade121a8b155ecb7a61dc37", True, True),
}
for ver, (tsha, blob, has_cw, has_assert) in want_tars.items():
    url = "https://registry.npmjs.org/@vitest/browser/-/browser-%s.tgz" % ver
    code, data = fetch(url)
    if code != 200:
        print("BROWSER_HTTP", ver, code); sys.exit(1)
    got = hashlib.sha256(data).hexdigest()
    if got != tsha:
        print("BROWSER_SHA", ver, got); sys.exit(1)
    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    content = tf.extractfile("package/dist/index.js").read()
    if git_blob(content) != blob:
        print("BROWSER_BLOB", ver, git_blob(content)); sys.exit(1)
    text = content.decode("utf-8")
    if "sendCdpEvent" not in text:
        print("BROWSER_CDP", ver); sys.exit(1)
    if ("canWrite" in text) is not has_cw:
        print("BROWSER_CW", ver); sys.exit(1)
    if ("assertCdpAllowed" in text) is not has_assert:
        print("BROWSER_ASSERT", ver); sys.exit(1)

print("ADV_OK")
print("RELEASE_TARBALL_OK")
ENDNET

python3 - "$OWNED" <<'ENDHASH' || fail "artifact_hashes"
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
ENDHASH

python3 - "$OWNED" <<'ENDEXTRA' || fail "durable extras"
import sys
from pathlib import Path
d=Path(sys.argv[1])
allowed={"assignment.jsonl","cases.jsonl","result.json","report.md","replay.zsh"}
names={p.name for p in d.iterdir()}
extra=names-allowed
if extra:
    raise SystemExit("extra %s" % sorted(extra))
print("hygiene_ok")
ENDEXTRA

echo "REPLAY_OK reviewed=3 PASS_proposal=0 REJECT=0 NARROW=3 UNKNOWN=0 BLOCKED=0"
