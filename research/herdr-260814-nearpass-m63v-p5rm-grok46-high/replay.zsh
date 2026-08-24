#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-nearpass-m63v-p5rm-grok46-high.
# English only. Anonymous public access only. No credentials. No GitHub API.
# Never print environment variable names or values. mktemp cleaned.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearpass-m63v-p5rm-grok46-high}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}

# Unset credential-bearing variables before any network command. Do not print.
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
export PYTHONPATH="$ROOT/cve-analyzer/src"

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d /tmp/nearpass-m63v-p5rm.XXXXXX)"

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
  filtered="$(grep -v -E -- 'error: unable to normalize alternate object path:|From https://github.com/|Cloning into |Updating files:|^remote: |Receiving objects:|Resolving deltas:|Enumerating objects:|Counting objects:|Compressing objects:|hint: |warning: |filter-process|partial clone|origin/HEAD|FETCH_HEAD|Clone succeeded|Filtering content|\[new tag\]|\[new ref\]|\[new branch\]' "$errfile" || true)"
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
want = ["GHSA-M63V-2G9W-2W6V", "GHSA-P5RM-JG5C-8C77"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c or "clone" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if [a["fp211_ordinal"] for a in ass] != [132, 136]:
    print("ORDINAL_FAIL"); sys.exit(1)
if len(cas) != 2 or [c["verdict"] for c in cas] != ["NARROW", "NARROW"]:
    print("COUNT_FAIL", [c.get("verdict") for c in cas]); sys.exit(1)
if res["conservation"]["equation"] != "2=2+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res.get("pass_proposal_ids"):
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 94:
    print("FLAG_FAIL"); sys.exit(1)
if res["counts"]["NARROW"] != 2 or res["counts"]["reviewed"] != 2 or res["counts"]["unreviewed"] != 0:
    print("COUNTS_FAIL"); sys.exit(1)
for rec, cand, carr, fix, first in zip(
    cas,
    ["2db76f65dbfe4f657b4a4efb506ed63b24623e92", "f51f4971ea3459cd410b363b34e156a116b530f4"],
    ["e484df8460bb4e8026e24210120602aa7f181f64", "de3d18d9fe31ced4ac749728d3a2f94811f59268"],
    ["695d3e97e3a20463ab7c8c081843e69e65e952e5", "430008e9d700b3fe80f206c672415cfbd8e830e7"],
    ["topology_gate", "topology_gate"],
):
    g = rec["gates"]
    for k in need:
        if k not in g:
            print("MISSING_GATE", rec["case_id"], k); sys.exit(1)
    if g["identity_gate"] != "PASS" or g["ai_hunk_gate"] != "PASS":
        print("EXPECTED_PASS_GATES", rec["case_id"], g); sys.exit(1)
    if g["but_for_gate"] != "PASS" or g["fix_reversal_gate"] != "PASS" or g["uniqueness_gate"] != "PASS":
        print("EXPECTED_PASS_GATES2", rec["case_id"], g); sys.exit(1)
    if g["topology_gate"] != "NARROW" or g["release_gate"] != "NARROW":
        print("EXPECTED_NARROW_GATES", rec["case_id"], g); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF"); sys.exit(1)
    if rec.get("authorship_transfer") is not False:
        print("TRANSFER"); sys.exit(1)
    if rec["seven_gates_exact_pass"] is not False:
        print("SEVEN_SHOULD_NOT_PASS"); sys.exit(1)
    if rec["contribution_class"] != "AI_INCOMPLETE_REMEDIATION_COMMIT_ONLY":
        print("CLASS"); sys.exit(1)
    if rec["candidate_set"] != [cand]:
        print("CAND"); sys.exit(1)
    if rec["carrier_set"] != [carr]:
        print("CARRIER"); sys.exit(1)
    if rec["minimum_fix_set"] != [fix]:
        print("FIXSET"); sys.exit(1)
    if rec["unresolved_or_failed_gate"] != first:
        print("FIRST_FAIL", rec["unresolved_or_failed_gate"]); sys.exit(1)
    if carr in rec["candidate_set"] or fix in rec["candidate_set"]:
        print("TRANSFER_INTO_CAND"); sys.exit(1)
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
if "GHSA-M63V-2G9W-2W6V" in strict or "GHSA-P5RM-JG5C-8C77" in strict:
    print("UNIQUENESS_FAIL COUNTED"); sys.exit(1)
if "GHSA-QF5V-M7P4-95RP" not in strict:
    print("QF5V_MISSING"); sys.exit(1)
if len(strict) != 94:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "M63V_P5RM_ABSENT_CANONICAL94 DISTINCT_QF5V")
PY

echo "== first-party identity =="
python3 - "$OWNED" "$REPLAY_TMP" <<'PY' || fail "ANON_NETWORK_BLOCKED identity"
import hashlib, json, os, sys, urllib.request
from pathlib import Path
owned = Path(sys.argv[1])
tmp = Path(sys.argv[2])
for k in list(os.environ):
    u = k.upper()
    if any(s in u for s in ("TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH")):
        os.environ.pop(k, None)
CANON_KEYS = (
    "aliases",
    "first_party_url",
    "ghsa_id",
    "github_reviewed",
    "global_catalog",
    "package_ecosystem",
    "package_name",
    "patched_version",
    "published_at",
    "repository",
    "retrieved_at",
    "state",
    "vulnerable_version_range",
    "withdrawn",
)
WANT_OSV = {
    "GHSA-M63V-2G9W-2W6V": (
        "https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/06/GHSA-m63v-2g9w-2w6v/GHSA-m63v-2g9w-2w6v.json",
        "8d44b004900cb4a07a927ff305e871f90b1144e0f686a6045ef97720f220b42a",
    ),
    "GHSA-P5RM-JG5C-8C77": (
        "https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/07/GHSA-p5rm-jg5c-8c77/GHSA-p5rm-jg5c-8c77.json",
        "1ed6f5bf2ae6f480ba0a11fdbedc31abf6a355895c403a337347e34b11905753",
    ),
}
WANT_SHA = {
    "GHSA-M63V-2G9W-2W6V": "bdcc9f5556d090d034098b8896a80e48a418c4100c4bdd93f76d832a302310b0",
    "GHSA-P5RM-JG5C-8C77": "5d89678c4d79cac692424abc5e48baadf744293c919a53d8b6bcb481d851e5df",
}
WANT_FIELDS = {
    "GHSA-M63V-2G9W-2W6V": {
        "aliases": ["CVE-2026-50566"],
        "first_party_url": "https://github.com/fission/fission/security/advisories/GHSA-m63v-2g9w-2w6v",
        "ghsa_id": "GHSA-M63V-2G9W-2W6V",
        "github_reviewed": True,
        "global_catalog": "present",
        "package_ecosystem": "Go",
        "package_name": "github.com/fission/fission",
        "patched_version": "1.24.0",
        "published_at": "2026-06-30T18:20:39Z",
        "repository": "fission/fission",
        "retrieved_at": "2026-08-15T03:10:00Z",
        "state": "published",
        "vulnerable_version_range": "<= 1.23.0",
        "withdrawn": False,
    },
    "GHSA-P5RM-JG5C-8C77": {
        "aliases": [],
        "first_party_url": "https://github.com/microsoft/kiota/security/advisories/GHSA-p5rm-jg5c-8c77",
        "ghsa_id": "GHSA-P5RM-JG5C-8C77",
        "github_reviewed": True,
        "global_catalog": "present",
        "package_ecosystem": "NuGet",
        "package_name": "Microsoft.OpenApi.Kiota",
        "patched_version": "1.34.0",
        "published_at": "2026-07-24T16:14:56Z",
        "repository": "microsoft/kiota",
        "retrieved_at": "2026-08-15T03:10:00Z",
        "state": "published",
        "vulnerable_version_range": "<= 1.33.0",
        "withdrawn": False,
    },
}

def canon_sha(proj):
    body_obj = {k: proj[k] for k in CANON_KEYS}
    body = json.dumps(body_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(body.encode("ascii")).hexdigest(), body_obj

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
catalog = res.get("advisory_projections") or {}
if set(catalog) != set(WANT_SHA):
    print("CATALOG_KEYS", sorted(catalog)); sys.exit(1)
for gid, pin in WANT_SHA.items():
    url, osv_pin = WANT_OSV[gid]
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
    try:
        with opener.open(req, timeout=60) as r:
            raw = r.read()
    except Exception:
        print("OSV_FETCH_FAIL", gid); sys.exit(1)
    got = hashlib.sha256(raw).hexdigest()
    if got != osv_pin:
        print("OSV_SHA", gid, got); sys.exit(1)
    osv = json.loads(raw.decode("utf-8"))
    if osv.get("id", "").upper() != gid:
        print("OSV_ID", gid); sys.exit(1)
    if not osv.get("database_specific", {}).get("github_reviewed"):
        print("OSV_NOT_REVIEWED", gid); sys.exit(1)
    if "withdrawn" in osv:
        print("OSV_WITHDRAWN", gid); sys.exit(1)
    proj = catalog[gid]
    sha, body_obj = canon_sha(proj)
    if sha != proj.get("sha256") or sha != pin:
        print("PROJ_SHA_MISMATCH", gid, sha, proj.get("sha256"), pin); sys.exit(1)
    want = WANT_FIELDS[gid]
    for k in CANON_KEYS:
        if body_obj[k] != want[k]:
            print("PROJ_FIELD", gid, k, body_obj[k], want[k]); sys.exit(1)
    if body_obj["state"] != "published" or body_obj["withdrawn"] is not False:
        print("PROJ_STATE", gid); sys.exit(1)
for rec, gid in zip(cas, WANT_SHA):
    sha, _ = canon_sha(rec["identity_projection"])
    if sha != WANT_SHA[gid]:
        print("CASE_PROJ_SHA", gid, sha); sys.exit(1)
print("IDENTITY_OK github_advisory_database_osv")
PY

echo "== git clone fission (public, no credentials) =="
gitq clone --filter=blob:none --no-tags --single-branch \
  https://github.com/fission/fission.git "$REPLAY_TMP/fission" >/dev/null
gitq -C "$REPLAY_TMP/fission" fetch --filter=blob:none origin \
  tag v1.23.0 tag v1.24.0 \
  2db76f65dbfe4f657b4a4efb506ed63b24623e92 \
  e484df8460bb4e8026e24210120602aa7f181f64 \
  695d3e97e3a20463ab7c8c081843e69e65e952e5 \
  pull/3391/head:refs/pull/3391/head \
  pull/3406/head:refs/pull/3406/head >/dev/null
F="$REPLAY_TMP/fission"
CAND=2db76f65dbfe4f657b4a4efb506ed63b24623e92
CARR=e484df8460bb4e8026e24210120602aa7f181f64
FIX=695d3e97e3a20463ab7c8c081843e69e65e952e5
PARENT=8fa799417c77ce8a0189d9858bfe11ece29b84a6
FIXP=9a2e6b07df6524bca18343983cfe2510c0b1c3f8
V123=710d8431bbbcdb82d7a1ac2b93c068baa829959b
V124=ce617120c41b9e4a51d577f81b441238264e88fd
PR3391=c9ed98a158d06876eadf179e4897fe9d0db5c3e8
PATHF=pkg/apis/core/v1/podspec_safety.go
VAL=pkg/apis/core/v1/validation.go
MERGE=pkg/executor/util/merge.go

parents=$(gitq -C "$F" rev-list --parents -n 1 "$CAND")
[[ $parents == "$CAND $PARENT" ]] || fail "M63V_PARENTS $parents"
cp=$(gitq -C "$F" rev-list --parents -n 1 "$CARR")
[[ $cp == "$CARR $PARENT" ]] || fail "M63V_CARR_PARENTS $cp"
fp=$(gitq -C "$F" rev-list --parents -n 1 "$FIX")
[[ $fp == "$FIX $FIXP" ]] || fail "M63V_FIX_PARENTS $fp"
prh=$(gitq -C "$F" rev-parse refs/pull/3391/head)
[[ $prh == "$PR3391" ]] || fail "M63V_PR3391 $prh"
gitq -C "$F" merge-base --is-ancestor "$CAND" refs/pull/3391/head || fail "M63V_CAND_NOT_IN_PR"
gitq -C "$F" cat-file -p "$CAND" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.7' || fail "M63V_CAND_MARKER"
gitq -C "$F" cat-file -p "$CARR" | LC_ALL=C grep -q 'Co-Authored-By: Claude Opus 4.7' || fail "M63V_CARR_MARKER"
gitq -C "$F" cat-file -p "$FIX" | LC_ALL=C grep -q 'GHSA-m63v-2g9w-2w6v' || fail "M63V_FIX_NAMES"

ws_parent=$(gitq -C "$F" ls-tree "$PARENT" -- "$PATHF")
[[ -z $ws_parent ]] || fail "M63V_PARENT_HAS_PODSPEC $ws_parent"
ws_v123=$(gitq -C "$F" ls-tree v1.23.0 -- "$PATHF")
[[ -z $ws_v123 ]] || fail "M63V_V123_HAS_PODSPEC $ws_v123"
gitq -C "$F" grep -F -q ValidatePodSpecSafety "$CAND" -- "$PATHF" || fail "M63V_CAND_VPS"
if gitq -C "$F" grep -F -q ValidateContainerSafety "$CAND" -- "$PATHF"; then
  fail "M63V_CAND_HAS_VCS"
fi
if gitq -C "$F" grep -F -q ValidateContainerSafety "$CARR" -- "$PATHF"; then
  fail "M63V_CARR_HAS_VCS"
fi
if gitq -C "$F" grep -F -q ValidateContainerSafety "$FIXP" -- "$PATHF"; then
  fail "M63V_FIXP_HAS_VCS"
fi
gitq -C "$F" grep -F -q ValidateContainerSafety "$FIX" -- "$PATHF" || fail "M63V_FIX_MISSING_VCS"
gitq -C "$F" grep -F -q 'ValidateContainerSafety("Environment.spec.runtime.container"' "$FIX" -- "$VAL" || fail "M63V_FIX_VALIDATE"
if gitq -C "$F" grep -F -q 'ValidateContainerSafety("Environment.spec.runtime.container"' "$CAND" -- "$VAL"; then
  fail "M63V_CAND_HAS_CONTAINER_VALIDATE"
fi
if gitq -C "$F" grep -F -q sanitizeContainerSecurityContext "$CAND" -- "$MERGE"; then
  fail "M63V_CAND_HAS_SANITIZE"
fi
gitq -C "$F" grep -F -q 'sanitizeContainerSecurityContext(&dstC)' "$FIX" -- "$MERGE" || fail "M63V_FIX_SANITIZE"

gitq -C "$F" merge-base --is-ancestor "$CAND" "$CARR" && fail "M63V_CAND_IN_CARR" || true
gitq -C "$F" merge-base --is-ancestor "$CAND" "$FIX" && fail "M63V_CAND_IN_FIX" || true
gitq -C "$F" merge-base --is-ancestor "$CAND" v1.24.0 && fail "M63V_CAND_IN_V124" || true
gitq -C "$F" merge-base --is-ancestor "$CARR" v1.24.0 || fail "M63V_CARR_NOT_IN_V124"
gitq -C "$F" merge-base --is-ancestor "$FIX" v1.24.0 || fail "M63V_FIX_NOT_IN_V124"
gitq -C "$F" merge-base --is-ancestor "$CARR" v1.23.0 && fail "M63V_CARR_IN_V123" || true
tags=$(gitq -C "$F" tag --contains "$CAND")
[[ -z $tags ]] || fail "M63V_CAND_TAGS $tags"
tags=$(gitq -C "$F" tag --contains "$CARR" --no-contains "$FIX")
[[ -z $tags ]] || fail "M63V_CARR_NO_FIX_TAGS $tags"

peel=$(gitq -C "$F" rev-parse 'v1.23.0^{commit}')
[[ $peel == "$V123" ]] || fail "M63V_PEEL123 $peel"
peel=$(gitq -C "$F" rev-parse 'v1.24.0^{commit}')
[[ $peel == "$V124" ]] || fail "M63V_PEEL124 $peel"
blob_m=$(gitq -C "$F" rev-parse "$CAND:$PATHF")
blob_s=$(gitq -C "$F" rev-parse "$CARR:$PATHF")
blob_f=$(gitq -C "$F" rev-parse "$FIX:$PATHF")
blob_v=$(gitq -C "$F" rev-parse "v1.24.0:$PATHF")
[[ $blob_m == af473d2601a9299a035166c4d4bf67927abc50df ]] || fail "M63V_BLOB_M $blob_m"
[[ $blob_s == 330fccee042945fac9ccfcdb3d62f52036e63b5e ]] || fail "M63V_BLOB_S $blob_s"
[[ $blob_f == 1d7219e7f592cc6ea631866328820475617141bd ]] || fail "M63V_BLOB_F $blob_f"
[[ $blob_v == "$blob_f" ]] || fail "M63V_BLOB_V $blob_v"
[[ $blob_m != "$blob_s" ]] || fail "M63V_MEMBER_EQUALS_SQUASH"
[[ $blob_s != "$blob_f" ]] || fail "M63V_SQUASH_EQUALS_CLOSER"

python3 - "$F" "$CAND" "$PARENT" "$CARR" "$FIX" <<'PY' || fail "M63V_matcher"
import os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
repo, origin, parent, carr, fix = sys.argv[1:]
env = dict(os.environ)
env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")
for k in list(env):
    u = k.upper()
    if any(s in u for s in ("TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH")):
        env.pop(k, None)

def git(*a):
    r = subprocess.run(["git","--no-optional-locks","-c","credential.helper=","-C",repo,*a], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise SystemExit(r.stderr)
    return r.stdout

def ci(sha):
    rec = git("log","-1","--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B", sha)
    parts = rec.split("\n", 6)
    while len(parts) < 7:
        parts.append("")
    return CommitInfo(sha=parts[0].strip(), author_name=parts[1], author_email=parts[2],
                      committer_name=parts[3], committer_email=parts[4],
                      authored_date=parts[5], message=parts[6])

want = "ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4"
if MATCHER_CONTRACT != want:
    print("CONTRACT", MATCHER_CONTRACT); sys.exit(1)
ms = matches_for_commit(ci(origin))
if not any(m.tool == "claude_code" and m.source_module == "coauthor_trailer" for m in ms):
    print("ORIGIN_MATCH", ms); sys.exit(1)
if not any(m.tool == "claude_code" and m.source_module == "coauthor_trailer" for m in matches_for_commit(ci(carr))):
    print("CARR_MATCH"); sys.exit(1)
if not any(m.tool == "claude_code" and m.source_module == "coauthor_trailer" for m in matches_for_commit(ci(fix))):
    print("FIX_MATCH_MISSING"); sys.exit(1)
print("MATCHER_OK_M63V")
PY
echo "GIT_OK_M63V"

echo "== git clone kiota (public, no credentials) =="
gitq clone --filter=blob:none --no-tags --single-branch \
  https://github.com/microsoft/kiota.git "$REPLAY_TMP/kiota" >/dev/null
gitq -C "$REPLAY_TMP/kiota" fetch --filter=blob:none origin \
  tag v1.32.5 tag v1.33.0 tag v1.34.0 \
  f51f4971ea3459cd410b363b34e156a116b530f4 \
  de3d18d9fe31ced4ac749728d3a2f94811f59268 \
  430008e9d700b3fe80f206c672415cfbd8e830e7 \
  pull/7910/head:refs/pull/7910/head \
  pull/7913/head:refs/pull/7913/head >/dev/null
K="$REPLAY_TMP/kiota"
CANDK=f51f4971ea3459cd410b363b34e156a116b530f4
CARRK=de3d18d9fe31ced4ac749728d3a2f94811f59268
FIXK=430008e9d700b3fe80f206c672415cfbd8e830e7
PARENTK=2350f233a1db7268eb8438bda1e8ae4dd1493053
V133=f4fe1db024d8aa09563e69cd9a444b60b3d6442b
V134=9d4f80e2006eeebc2b3a641d92edecdad70be2de
PATHK=src/Kiota.Builder/OpenApiExtensions/OpenApiAiCapabilitiesExtension.cs

parents=$(gitq -C "$K" rev-list --parents -n 1 "$CANDK")
[[ $parents == "$CANDK $PARENTK" ]] || fail "P5RM_PARENTS $parents"
cp=$(gitq -C "$K" rev-list --parents -n 1 "$CARRK")
[[ $cp == "$CARRK $PARENTK" ]] || fail "P5RM_CARR_PARENTS $cp"
fp=$(gitq -C "$K" rev-list --parents -n 1 "$FIXK")
[[ $fp == "$FIXK $CARRK" ]] || fail "P5RM_FIX_PARENTS $fp"
prh=$(gitq -C "$K" rev-parse refs/pull/7910/head)
[[ $prh == "$CANDK" ]] || fail "P5RM_PR7910 $prh"
gitq -C "$K" cat-file -p "$CANDK" | LC_ALL=C grep -q 'Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>' || fail "P5RM_CAND_MARKER"
gitq -C "$K" cat-file -p "$CARRK" | LC_ALL=C grep -q 'Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>' || fail "P5RM_CARR_MARKER"
gitq -C "$K" cat-file -p "$FIXK" | LC_ALL=C grep -q 'Harden IsSafeFileReference' || fail "P5RM_FIX_SUBJECT"
gitq -C "$K" grep -F -q MaxPercentDecodePasses "$CANDK" -- "$PATHK" || fail "P5RM_CAND_DECODE"
if gitq -C "$K" grep -F -q MaxPercentDecodePasses "$PARENTK" -- "$PATHK"; then
  fail "P5RM_PARENT_HAS_DECODE"
fi
if gitq -C "$K" grep -F -q 'embedded NUL' "$CANDK" -- "$PATHK"; then
  fail "P5RM_CAND_HAS_NUL_GUARD"
fi
gitq -C "$K" grep -F -q 'embedded NUL' "$FIXK" -- "$PATHK" || fail "P5RM_FIX_MISSING_NUL"

gitq -C "$K" merge-base --is-ancestor "$CANDK" "$CARRK" && fail "P5RM_CAND_IN_CARR" || true
gitq -C "$K" merge-base --is-ancestor "$CANDK" "$FIXK" && fail "P5RM_CAND_IN_FIX" || true
gitq -C "$K" merge-base --is-ancestor "$CANDK" v1.34.0 && fail "P5RM_CAND_IN_V134" || true
gitq -C "$K" merge-base --is-ancestor "$CARRK" v1.34.0 || fail "P5RM_CARR_NOT_IN_V134"
gitq -C "$K" merge-base --is-ancestor "$FIXK" v1.34.0 || fail "P5RM_FIX_NOT_IN_V134"
gitq -C "$K" merge-base --is-ancestor "$CARRK" v1.33.0 && fail "P5RM_CARR_IN_V133" || true
tags=$(gitq -C "$K" tag --contains "$CANDK")
[[ -z $tags ]] || fail "P5RM_CAND_TAGS $tags"
tags=$(gitq -C "$K" tag --contains "$CARRK" --no-contains "$FIXK")
[[ -z $tags ]] || fail "P5RM_CARR_NO_FIX_TAGS $tags"

peel=$(gitq -C "$K" rev-parse 'v1.33.0^{commit}')
[[ $peel == "$V133" ]] || fail "P5RM_PEEL133 $peel"
peel=$(gitq -C "$K" rev-parse 'v1.34.0^{commit}')
[[ $peel == "$V134" ]] || fail "P5RM_PEEL134 $peel"
blob_m=$(gitq -C "$K" rev-parse "$CANDK:$PATHK")
blob_s=$(gitq -C "$K" rev-parse "$CARRK:$PATHK")
blob_p=$(gitq -C "$K" rev-parse "$PARENTK:$PATHK")
blob_f=$(gitq -C "$K" rev-parse "$FIXK:$PATHK")
blob_33=$(gitq -C "$K" rev-parse "v1.33.0:$PATHK")
blob_34=$(gitq -C "$K" rev-parse "v1.34.0:$PATHK")
[[ $blob_m == 782a03f5a90908d179e6b2ddc971762ce2818cd3 ]] || fail "P5RM_BLOB_M $blob_m"
[[ $blob_s == "$blob_m" ]] || fail "P5RM_BLOB_S $blob_s"
[[ $blob_p == 1391bf0c317ededff61d42336eb20cc168c584f5 ]] || fail "P5RM_BLOB_P $blob_p"
[[ $blob_f == 1b62b65383747873569474fbcf4d2895976ad405 ]] || fail "P5RM_BLOB_F $blob_f"
[[ $blob_33 == "$blob_p" ]] || fail "P5RM_BLOB_33 $blob_33"
[[ $blob_34 == "$blob_f" ]] || fail "P5RM_BLOB_34 $blob_34"

python3 - "$K" "$CANDK" "$PARENTK" "$CARRK" "$FIXK" <<'PY' || fail "P5RM_matcher"
import os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
repo, origin, parent, carr, fix = sys.argv[1:]
env = dict(os.environ)
env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")
for k in list(env):
    u = k.upper()
    if any(s in u for s in ("TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH")):
        env.pop(k, None)

def git(*a):
    r = subprocess.run(["git","--no-optional-locks","-c","credential.helper=","-C",repo,*a], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise SystemExit(r.stderr)
    return r.stdout

def ci(sha):
    rec = git("log","-1","--format=%H%n%an%n%ae%n%cn%n%ce%n%aI%n%B", sha)
    parts = rec.split("\n", 6)
    while len(parts) < 7:
        parts.append("")
    return CommitInfo(sha=parts[0].strip(), author_name=parts[1], author_email=parts[2],
                      committer_name=parts[3], committer_email=parts[4],
                      authored_date=parts[5], message=parts[6])

want = "ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4"
if MATCHER_CONTRACT != want:
    print("CONTRACT", MATCHER_CONTRACT); sys.exit(1)
ms = matches_for_commit(ci(origin))
if not any(m.tool == "github_copilot" and m.source_module == "coauthor_trailer" for m in ms):
    print("ORIGIN_MATCH", ms); sys.exit(1)
if matches_for_commit(ci(parent)):
    print("PARENT_MATCH"); sys.exit(1)
if not any(m.tool == "github_copilot" and m.source_module == "coauthor_trailer" for m in matches_for_commit(ci(carr))):
    print("CARR_MATCH"); sys.exit(1)
if not any(m.tool == "github_copilot" and m.source_module == "coauthor_trailer" for m in matches_for_commit(ci(fix))):
    print("FIX_MATCH_MISSING"); sys.exit(1)
print("MATCHER_OK_P5RM")
PY
echo "GIT_OK_P5RM"

echo "== released artifacts (public, no credentials) =="
python3 - "$REPLAY_TMP" "$F" <<'PY' || fail "ANON_NETWORK_BLOCKED artifacts"
import hashlib, io, json, os, sys, zipfile, urllib.request
from pathlib import Path
tmp = Path(sys.argv[1])
repo = sys.argv[2]
for k in list(os.environ):
    u = k.upper()
    if any(s in u for s in ("TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH")):
        os.environ.pop(k, None)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
    with opener.open(req, timeout=120) as r:
        return r.read()

info123 = json.loads(get("https://proxy.golang.org/github.com/fission/fission/@v/v1.23.0.info"))
info124 = json.loads(get("https://proxy.golang.org/github.com/fission/fission/@v/v1.24.0.info"))
if info123["Origin"]["Hash"] != "710d8431bbbcdb82d7a1ac2b93c068baa829959b":
    print("GO123_HASH"); sys.exit(1)
if info124["Origin"]["Hash"] != "ce617120c41b9e4a51d577f81b441238264e88fd":
    print("GO124_HASH"); sys.exit(1)
z123 = get("https://proxy.golang.org/github.com/fission/fission/@v/v1.23.0.zip")
z124 = get("https://proxy.golang.org/github.com/fission/fission/@v/v1.24.0.zip")
if hashlib.sha256(z123).hexdigest() != "d4f4c507f880d887e7b35cd413be5bc34b3051874a1b0161e5d8c6bc4904fdcc":
    print("GO123_ZIP"); sys.exit(1)
if hashlib.sha256(z124).hexdigest() != "0d165622d83747fe24ea996a8ecfd85ae678ca79fb907d241a9e29b30ef667eb":
    print("GO124_ZIP"); sys.exit(1)
with zipfile.ZipFile(io.BytesIO(z123)) as z:
    if any(n.endswith("podspec_safety.go") for n in z.namelist()):
        print("GO123_HAS_PODSPEC"); sys.exit(1)
with zipfile.ZipFile(io.BytesIO(z124)) as z:
    blob = z.read("github.com/fission/fission@v1.24.0/pkg/apis/core/v1/podspec_safety.go")
if blob.count(b"ValidateContainerSafety") != 4:
    print("GO124_VCS", blob.count(b"ValidateContainerSafety")); sys.exit(1)
import subprocess
gitblob = subprocess.check_output(
    ["git","-c","credential.helper=","-C",repo,"cat-file","blob","v1.24.0:pkg/apis/core/v1/podspec_safety.go"]
)
if gitblob != blob:
    print("GO124_NE_GIT"); sys.exit(1)

n133 = get("https://api.nuget.org/v3-flatcontainer/microsoft.openapi.kiota/1.33.0/microsoft.openapi.kiota.1.33.0.nupkg")
n134 = get("https://api.nuget.org/v3-flatcontainer/microsoft.openapi.kiota/1.34.0/microsoft.openapi.kiota.1.34.0.nupkg")
if hashlib.sha256(n133).hexdigest() != "b1e83319c5737de9f8009ca53f9cc81cb2ea3d00c944cfba0861558f41bf6465":
    print("NUPKG133"); sys.exit(1)
if hashlib.sha256(n134).hexdigest() != "2176337844ba0b6328d949a39a7600f211fc591d60671db1e4fcde6aa5398a8e":
    print("NUPKG134"); sys.exit(1)

def nuspec_commit(raw, version, want_commit, want_decode):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        spec = z.read("Microsoft.OpenApi.Kiota.nuspec").decode("utf-8")
        if f"<version>{version}</version>" not in spec:
            print("NUSPEC_VER", version); sys.exit(1)
        if f'commit="{want_commit}"' not in spec:
            print("NUSPEC_COMMIT", version); sys.exit(1)
        dll = z.read("tools/net8.0/any/Kiota.Builder.dll")
        has = b"MaxPercentDecodePasses" in dll or "MaxPercentDecodePasses".encode("utf-16le") in dll
        if has != want_decode:
            print("DLL_DECODE", version, has); sys.exit(1)

nuspec_commit(n133, "1.33.0", "f4fe1db024d8aa09563e69cd9a444b60b3d6442b", False)
nuspec_commit(n134, "1.34.0", "9d4f80e2006eeebc2b3a641d92edecdad70be2de", True)
print("ARTIFACTS_OK")
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
