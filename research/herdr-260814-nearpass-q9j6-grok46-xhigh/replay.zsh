#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearpass-q9j6-grok46-xhigh.
# English only. Anonymous public access only. No credentials. No GitHub API.
# Never print environment variable names or values. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearpass-q9j6-grok46-xhigh}
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
REPLAY_TMP="$(mktemp -d /tmp/q9j6-hostile.XXXXXX)"
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
if not b.endswith(b"\n"):
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
want = ["GHSA-Q9J6-XCVX-PX63"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [34]:
    print("ORDINAL_FAIL"); sys.exit(1)
if len(cas) != 1 or cas[0]["verdict"] != "NARROW":
    print("COUNT_FAIL", cas[0]["verdict"] if cas else None); sys.exit(1)
if res["conservation"]["equation"] != "1=1+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res.get("pass_proposal_ids"):
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 94:
    print("FLAG_FAIL"); sys.exit(1)
rec = cas[0]
g = rec["gates"]
for k in need:
    if k not in g:
        print("MISSING_GATE", k); sys.exit(1)
if g["identity_gate"] != "PASS" or g["ai_hunk_gate"] != "PASS" or g["topology_gate"] != "PASS":
    print("EXPECTED_PASS_GATES", g); sys.exit(1)
if g["release_gate"] != "PASS" or g["uniqueness_gate"] != "PASS":
    print("EXPECTED_PASS_GATES2", g); sys.exit(1)
if g["but_for_gate"] != "NARROW" or g["fix_reversal_gate"] != "NARROW":
    print("EXPECTED_CAUSAL_NARROW", g); sys.exit(1)
if rec.get("osv_introduced_used_as_causal_proof") is not False:
    print("OSV_USED_AS_PROOF"); sys.exit(1)
if rec.get("authorship_transfer") is not False:
    print("TRANSFER"); sys.exit(1)
if rec["seven_gates_exact_pass"] is not False:
    print("SEVEN_SHOULD_NOT_PASS"); sys.exit(1)
if rec["contribution_class"] != "AI_NEW_SURFACE_CONTRIBUTOR":
    print("CLASS"); sys.exit(1)
if rec["candidate_set"] != ["bbb2aa9ad4e0c14517d32272b5e6d83318fde493"]:
    print("CAND"); sys.exit(1)
if rec["carrier_set"] != ["4d4254b591ede243b38df7b678cf36619cb25825"]:
    print("CARRIER"); sys.exit(1)
if rec["minimum_fix_set"] != ["48ba4ece3c1b43cb4b9627438c0ff4e4251e3511","f267a28cb2badc7e712c4592af4d79d090fe5063"]:
    print("FIXSET"); sys.exit(1)
if rec.get("aliases") != ["CVE-2026-34599"]:
    print("ALIASES"); sys.exit(1)
if rec.get("normalized_advisory_sha256") != "8212cc1cca6f67e2218d9763ce844265baea6aead463c212d040b20e3c9c4c8e":
    print("ADV_HASH"); sys.exit(1)
print("CONSERVATION_OK 1=1+0 NARROW=1")
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
if "GHSA-Q9J6-XCVX-PX63" in strict:
    print("UNIQUENESS_FAIL Q9J6_COUNTED"); sys.exit(1)
if "GHSA-X9QH-W4C4-54F9" not in strict:
    print("X9QH_MISSING_FROM_STRICT"); sys.exit(1)
if len(strict) != 94:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "Q9J6_ABSENT_CANONICAL94")
PY

echo "== git fetch and facts =="
Z="$REPLAY_TMP/coolify.git"
gitq -c init.defaultBranch=main init -q --bare "$Z" >/dev/null
gitq --git-dir="$Z" remote add origin https://github.com/coollabsio/coolify.git
if ! gitq --git-dir="$Z" fetch --quiet --no-progress --filter=blob:none origin \
  +refs/tags/v4.0.0-beta.470:refs/tags/v4.0.0-beta.470 \
  +refs/tags/v4.0.0-beta.471:refs/tags/v4.0.0-beta.471; then
  fail "ANON_NETWORK_BLOCKED fetch"
fi

CAND=bbb2aa9ad4e0c14517d32272b5e6d83318fde493
PARENT=b484c0cc253ff9845fda130671004f5451fea84f
PPP=b7e0f5577df5326db02da52a2e06bdd70c80e73b
CAR=4d4254b591ede243b38df7b678cf36619cb25825
CARP1=8be1a9b5de3aa287cebf705ed7bd39400d4f7291
FIXM=48ba4ece3c1b43cb4b9627438c0ff4e4251e3511
FIXC=f267a28cb2badc7e712c4592af4d79d090fe5063
FIXCP1=7b3b6fa6efcbe8047870de41b083d7b387281494
FIXCP2=b3256d4df14e21c6d8936d972f45cbc47e07cca4
A980=a980fd460a2ef7ce7766171d034a8c645322299b
FILE=app/Livewire/Project/Shared/GetLogs.php
TEST=tests/Feature/GetLogsCommandInjectionTest.php
BLADE=resources/views/livewire/project/shared/get-logs.blade.php

parents=$(gitq --git-dir="$Z" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PARENT" ]] || fail "PARENTS $parents"
cparents=$(gitq --git-dir="$Z" rev-list --parents -n 1 "$CAR")
[[ $cparents == "$CAR $CARP1 $CAND" ]] || fail "CAR_PARENTS $cparents"
mparents=$(gitq --git-dir="$Z" rev-list --parents -n 1 "$FIXM")
[[ $mparents == "$FIXM e39678aea584be533f89052d4e2939f2d8834449" ]] || fail "FIXM_PARENTS $mparents"
xparents=$(gitq --git-dir="$Z" rev-list --parents -n 1 "$FIXC")
[[ $xparents == "$FIXC $FIXCP1 $FIXCP2" ]] || fail "FIXC_PARENTS $xparents"
ap=$(gitq --git-dir="$Z" rev-list --parents -n 1 "$A980")
[[ $ap == "$A980 $CAND" ]] || fail "A980_PARENTS $ap"

an=$(gitq --git-dir="$Z" log -1 --format='%an <%ae>' "$CAND")
[[ $an == "Claude <noreply@anthropic.com>" ]] || fail "CAND_AUTHOR $an"
if gitq --git-dir="$Z" log -1 --format='%b' "$CAND" | LC_ALL=C grep -q 'Co-Authored-By'; then
  fail "CAND_TRAILER"
fi
car_an=$(gitq --git-dir="$Z" log -1 --format='%an' "$CAR")
[[ $car_an == "Andras Bacsai" ]] || fail "CAR_AUTHOR $car_an"
if gitq --git-dir="$Z" log -1 --format='%b' "$CAR" | LC_ALL=C grep -q 'Co-Authored-By: Claude'; then
  fail "CAR_CLAUDE_TRAILER"
fi
gitq --git-dir="$Z" log -1 --format='%b' "$FIXM" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.6' || fail "FIXM_MARKER"

blob_p=$(gitq --git-dir="$Z" rev-parse "${PARENT}:${FILE}")
blob_c=$(gitq --git-dir="$Z" rev-parse "${CAND}:${FILE}")
blob_a=$(gitq --git-dir="$Z" rev-parse "${A980}:${FILE}")
blob_470=$(gitq --git-dir="$Z" rev-parse "v4.0.0-beta.470:${FILE}")
blob_fm=$(gitq --git-dir="$Z" rev-parse "${FIXM}:${FILE}")
blob_fx=$(gitq --git-dir="$Z" rev-parse "${FIXC}:${FILE}")
blob_471=$(gitq --git-dir="$Z" rev-parse "v4.0.0-beta.471:${FILE}")
[[ $blob_p == 0f8c4ad155f1b5d28a4089deb705fb806c009718 ]] || fail "BLOB_P $blob_p"
[[ $blob_c == 5f8046efd857caf8cba80b8b5cc6800c7396277d ]] || fail "BLOB_C $blob_c"
[[ $blob_a == 22605e1bbe01954901a78178677dcd186da25dae ]] || fail "BLOB_A $blob_a"
[[ $blob_470 == "$blob_a" ]] || fail "BLOB_470 $blob_470"
[[ $blob_fm == d0121bdc51768e57e1db709eccb317528264a591 ]] || fail "BLOB_FM $blob_fm"
[[ $blob_fx == "$blob_fm" && $blob_471 == "$blob_fm" ]] || fail "BLOB_FIX_NE"

tree=$(gitq --git-dir="$Z" rev-parse "${CAND}^{tree}")
[[ $tree == c1d07534ff0b366624540d7e90169e9b080be651 ]] || fail "TREE $tree"

stat=$(gitq --git-dir="$Z" diff --numstat "$PARENT" "$CAND" -- "$FILE")
[[ $stat == $'44\t0\t'"$FILE" ]] || fail "NUMSTAT $stat"

gitq --git-dir="$Z" grep -q 'docker logs' "$PARENT" -- "$FILE" || fail "PARENT_GETLOGS"
gitq --git-dir="$Z" grep -q 'docker logs' "$PPP" -- "$FILE" || fail "PPP_GETLOGS"
if gitq --git-dir="$Z" grep -q downloadAllLogs "$PARENT" -- "$FILE"; then
  fail "PARENT_HAS_DOWNLOAD"
fi
if gitq --git-dir="$Z" grep -q downloadAllLogs "$PPP" -- "$FILE"; then
  fail "PPP_HAS_DOWNLOAD"
fi
if gitq --git-dir="$Z" grep -q '#\[Locked\]' "$PARENT" -- "$FILE"; then
  fail "PARENT_LOCKED"
fi
if gitq --git-dir="$Z" grep -q '#\[Locked\]' "$CAND" -- "$FILE"; then
  fail "CAND_LOCKED"
fi
gitq --git-dir="$Z" grep -q downloadAllLogs "$CAND" -- "$FILE" || fail "CAND_DOWNLOAD"
gitq --git-dir="$Z" grep -q 'docker logs' "$CAND" -- "$FILE" || fail "CAND_INTERP"
if gitq --git-dir="$Z" grep -q '#\[Locked\]' v4.0.0-beta.470 -- "$FILE"; then
  fail "470_LOCKED"
fi
gitq --git-dir="$Z" grep -q downloadAllLogs v4.0.0-beta.470 -- "$FILE" || fail "470_DOWNLOAD"
gitq --git-dir="$Z" grep -q '#\[Locked\]' "$FIXM" -- "$FILE" || fail "FIXM_LOCKED"
gitq --git-dir="$Z" grep -q ownedByCurrentTeam "$FIXM" -- "$FILE" || fail "FIXM_AUTH"
gitq --git-dir="$Z" grep -q downloadAllLogs "$FIXM" -- "$FILE" || fail "FIXM_DOWNLOAD"
gitq --git-dir="$Z" grep -q 'docker logs' "$FIXM" -- "$FILE" || fail "FIXM_STILL_INTERP"
gitq --git-dir="$Z" grep -q downloadAllLogs v4.0.0-beta.471 -- "$BLADE" || fail "471_BLADE_CALLER"

t_fm=$(gitq --git-dir="$Z" rev-parse "${FIXM}:${TEST}")
t_fx=$(gitq --git-dir="$Z" rev-parse "${FIXC}:${TEST}")
t_471=$(gitq --git-dir="$Z" rev-parse "v4.0.0-beta.471:${TEST}")
[[ $t_fm == 34824b48bd9909e0a12078942bb8a6e08310b740 ]] || fail "TEST_FM $t_fm"
[[ $t_fx == 3e5a33b661fd5c70bc35bec2ceeb73ae33e8daac ]] || fail "TEST_FX $t_fx"
[[ $t_471 == c0b17c3bd74c80555d017fa00ec22725c3fed453 ]] || fail "TEST_471 $t_471"
[[ $t_fm != "$t_fx" && $t_fx != "$t_471" ]] || fail "TEST_SHOULD_DIFFER"

nfiles=$(gitq --git-dir="$Z" diff --name-only "$FIXCP1" "$FIXC" | wc -l)
[[ ${nfiles// /} == 27 ]] || fail "FIXC_FILECOUNT $nfiles"
gitq --git-dir="$Z" diff --name-only "$FIXCP1" "$FIXC" | LC_ALL=C grep -q 'app/Models/Application.php' || fail "FIXC_UNRELATED"

gitq --git-dir="$Z" merge-base --is-ancestor "$CAND" "$CAR" || fail "CAND_ANC_CAR"
gitq --git-dir="$Z" merge-base --is-ancestor "$CAND" v4.0.0-beta.470 || fail "CAND_V470"
gitq --git-dir="$Z" merge-base --is-ancestor "$CAR" v4.0.0-beta.470 || fail "CAR_V470"
gitq --git-dir="$Z" merge-base --is-ancestor "$FIXM" v4.0.0-beta.470 && fail "FIXM_IN_VULN" || true
gitq --git-dir="$Z" merge-base --is-ancestor "$FIXC" v4.0.0-beta.470 && fail "FIXC_IN_VULN" || true
gitq --git-dir="$Z" merge-base --is-ancestor "$FIXM" v4.0.0-beta.471 || fail "FIXM_FIXED"
gitq --git-dir="$Z" merge-base --is-ancestor "$FIXC" v4.0.0-beta.471 || fail "FIXC_FIXED"
gitq --git-dir="$Z" merge-base --is-ancestor "$FIXM" "$FIXCP1" && fail "FIXM_IN_P1" || true
gitq --git-dir="$Z" merge-base --is-ancestor "$FIXM" "$FIXCP2" || fail "FIXM_IN_P2"

peel470=$(gitq --git-dir="$Z" rev-parse 'v4.0.0-beta.470^{commit}')
peel471=$(gitq --git-dir="$Z" rev-parse 'v4.0.0-beta.471^{commit}')
[[ $peel470 == 575b0766d12bad2a78febff72ab59c017772bcf7 ]] || fail "PEEL470 $peel470"
[[ $peel471 == 914d7e0b50505bc1fd56c34974fca09ad354e92a ]] || fail "PEEL471 $peel471"

gitq --git-dir="$Z" show "${PARENT}:${FILE}" >"$REPLAY_TMP/parent.GetLogs.php"
gitq --git-dir="$Z" show "${CAND}:${FILE}" >"$REPLAY_TMP/cand.GetLogs.php"
python3 - "$REPLAY_TMP/parent.GetLogs.php" "$REPLAY_TMP/cand.GetLogs.php" <<'PY' || fail "GETLOGS_NOT_IDENTICAL"
import re, sys
from pathlib import Path
def methods(src):
    parts=re.split(r"(    public function )", src)
    out={}
    i=1
    while i < len(parts)-1:
        name=parts[i+1].split("(")[0]
        out[name]=parts[i]+parts[i+1]
        i+=2
    return out
parent=Path(sys.argv[1]).read_text()
cand=Path(sys.argv[2]).read_text()
pm=methods(parent)
cm=methods(cand)
if pm["getLogs"] != cm["getLogs"]:
    raise SystemExit("getLogs changed")
if "downloadAllLogs" in pm:
    raise SystemExit("parent has downloadAllLogs")
if "downloadAllLogs" not in cm:
    raise SystemExit("cand missing downloadAllLogs")
if "#[Locked]" in parent or "#[Locked]" in cand:
    raise SystemExit("locked too early")
print("GETLOGS_IDENTICAL_OK")
PY

if ! tags=$(gitq ls-remote --tags https://github.com/coollabsio/coolify.git refs/tags/v4.0.0-beta.470 refs/tags/v4.0.0-beta.471); then
  fail "ANON_NETWORK_BLOCKED ls-remote"
fi
print -r -- "$tags" | LC_ALL=C grep -q '^575b0766d12bad2a78febff72ab59c017772bcf7[[:space:]]refs/tags/v4.0.0-beta.470$' || fail "LSREMOTE_470"
print -r -- "$tags" | LC_ALL=C grep -q '^914d7e0b50505bc1fd56c34974fca09ad354e92a[[:space:]]refs/tags/v4.0.0-beta.471$' || fail "LSREMOTE_471"
echo "GIT_OK"

echo "== advisory and tarballs =="
anon /usr/bin/python3 - <<'PY' || fail "ANON_NETWORK_BLOCKED advisory_or_tar"
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
        return e.code, e.read()

code, data = fetch("https://github.com/coollabsio/coolify/security/advisories/GHSA-q9j6-xcvx-px63")
if code != 200:
    print("ADV_HTTP", code)
    sys.exit(1)
text = data.decode("utf-8", "replace")
need_true = [
    "CVE-2026-34599",
    "GHSA-q9j6-xcvx-px63",
    "Authenticated Remote Code Execution in GetLogs Livewire Component",
    "CWE-78",
    "coollabsio/coolify",
    "&lt;= 4.0.0-beta.470",
    "4.0.0-beta.471",
    "interpolated directly",
    "Lines 136",
    "203, 205, 209, 211",
    "getLogs",
    "#[Locked]",
    "docker logs",
]
for s in need_true:
    if s not in text:
        print("ADV_MISSING", s)
        sys.exit(1)
if "withdrawn" in text.lower():
    print("ADV_WITHDRAWN")
    sys.exit(1)
if "downloadAllLogs" in text:
    print("ADV_NAMES_DOWNLOADALLLOGS")
    sys.exit(1)
ident = {
    "cve_id": "CVE-2026-34599",
    "cwe_ids": ["CWE-78"],
    "ghsa_id": "GHSA-q9j6-xcvx-px63",
    "html_url": "https://github.com/coollabsio/coolify/security/advisories/GHSA-q9j6-xcvx-px63",
    "patched_versions": "4.0.0-beta.471",
    "repository": "coollabsio/coolify",
    "severity": "high",
    "state": "published",
    "summary": "Authenticated Remote Code Execution in GetLogs Livewire Component",
    "vulnerable_version_range": "<= 4.0.0-beta.470",
    "withdrawn_at": None,
}
got = hashlib.sha256(json.dumps(ident, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
if got != "8212cc1cca6f67e2218d9763ce844265baea6aead463c212d040b20e3c9c4c8e":
    print("ADV_NORM_HASH", got)
    sys.exit(1)

code, data = fetch("https://github.com/advisories/GHSA-q9j6-xcvx-px63")
if code != 404:
    print("GLOBAL_ADV_NOT_404", code)
    sys.exit(1)

relpath = "app/Livewire/Project/Shared/GetLogs.php"
want = {
    "v4.0.0-beta.470": ("22605e1bbe01954901a78178677dcd186da25dae", False, True),
    "v4.0.0-beta.471": ("d0121bdc51768e57e1db709eccb317528264a591", True, True),
}
for tag, (blob, locked, has_dl) in want.items():
    url = "https://codeload.github.com/coollabsio/coolify/tar.gz/refs/tags/" + tag
    code, blobdata = fetch(url)
    if code != 200:
        print("TAR_HTTP", tag, code)
        sys.exit(1)
    tf = tarfile.open(fileobj=io.BytesIO(blobdata), mode="r:gz")
    matches = [n for n in tf.getnames() if n.endswith(relpath)]
    if len(matches) != 1:
        print("TAR_PATH", tag, matches)
        sys.exit(1)
    content = tf.extractfile(matches[0]).read()
    git_blob = b"blob " + str(len(content)).encode() + b"\0" + content
    gotb = hashlib.sha1(git_blob).hexdigest()
    if gotb != blob:
        print("TAR_BLOB", tag, gotb)
        sys.exit(1)
    textc = content.decode("utf-8")
    if ("#[Locked]" in textc) is not locked:
        print("TAR_LOCKED", tag)
        sys.exit(1)
    if ("downloadAllLogs" in textc) is not has_dl:
        print("TAR_DL", tag)
        sys.exit(1)
    if tag.endswith("470") and "ownedByCurrentTeam" in textc:
        print("TAR_470_AUTH")
        sys.exit(1)
    if tag.endswith("471") and "ownedByCurrentTeam" not in textc:
        print("TAR_471_NO_AUTH")
        sys.exit(1)

code, data = fetch("https://github.com/coollabsio/coolify/releases/tag/v4.0.0-beta.470")
if code != 200 or b"released this" not in data or b"v4.0.0-beta.470" not in data:
    print("REL470")
    sys.exit(1)
code, data = fetch("https://github.com/coollabsio/coolify/releases/tag/v4.0.0-beta.471")
if code != 200 or b"released this" not in data or b"v4.0.0-beta.471" not in data:
    print("REL471")
    sys.exit(1)
print("ADV_OK")
print("RELEASE_TARBALL_OK")
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

echo "REPLAY_OK reviewed=1 PASS_proposal=0 REJECT=0 NARROW=1 UNKNOWN=0 BLOCKED=0"
