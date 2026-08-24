#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-76pc-hostile-redteam-grok46-xhigh.
# English only. No credentials. Shared caches read-only. mktemp cleaned.
# Identity is pinned offline. Public git clone and npm tarball fetch only.
set -euo pipefail
unsetopt xtrace
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-76pc-hostile-redteam-grok46-xhigh}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_PAGER=cat
export GH_PAGER=cat
unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN
export PYTHONPATH="$ROOT/cve-analyzer/src"

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }

REPLAY_TMP=""
cleanup_replay_tmp() {
  if [[ -n "${REPLAY_TMP:-}" && -d "$REPLAY_TMP" ]]; then
    rm -rf "$REPLAY_TMP"
  fi
}
trap cleanup_replay_tmp EXIT
REPLAY_TMP="$(mktemp -d /tmp/76pc-hostile.XXXXXX)"

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
  filtered="$(grep -v -E -- 'error: unable to normalize alternate object path:|From https://github.com/|Cloning into |Updating files:|^remote: |Receiving objects:|Resolving deltas:|Enumerating objects:|Counting objects:|Compressing objects:|hint: |warning: |filter-process|partial clone|origin/HEAD|FETCH_HEAD|Clone succeeded|Filtering content' "$errfile" || true)"
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
want = ["GHSA-76PC-MQXP-3RQ5"]
need = ("identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate")
if aids != cids or cids != want or want != res["conservation"]["reviewed_case_ids"]:
    print("ID_ORDER_FAIL", aids, cids); sys.exit(1)
if any("clone_path" in a or "clone" in a for a in ass):
    print("ASSIGN_CLONE_KEY"); sys.exit(1)
if any("clone_path" in c for c in cas):
    print("CASE_CLONE_KEY"); sys.exit(1)
if any(a.get("inherited_verdict_forbidden") is not True for a in ass):
    print("INHERIT_FLAG_FAIL"); sys.exit(1)
if any(a.get("delta3_is_not_evidence") is not True for a in ass):
    print("DELTA3_FLAG_FAIL"); sys.exit(1)
if any(a.get("no_carrier") is not True for a in ass):
    print("NO_CARRIER_FLAG"); sys.exit(1)
if len(cas) != 1 or cas[0]["verdict"] != "PASS_PROPOSAL":
    print("COUNT_FAIL", cas[0]["verdict"] if cas else None); sys.exit(1)
if res["conservation"]["equation"] != "1=1+0" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposal_ids"] != ["GHSA-76PC-MQXP-3RQ5"]:
    print("PASS_IDS_FAIL"); sys.exit(1)
if res["canonical_strict_count_untouched"] != 91:
    print("FLAG_FAIL"); sys.exit(1)
rec = cas[0]
g = rec["gates"]
for k in need:
    if g[k] != "PASS":
        print("BAD_GATE", k, g[k]); sys.exit(1)
if rec.get("osv_introduced_used_as_causal_proof") is not False:
    print("OSV_USED_AS_PROOF"); sys.exit(1)
if rec.get("authorship_transfer") is not False:
    print("TRANSFER"); sys.exit(1)
if rec.get("delta3_is_not_evidence") is not True:
    print("CASE_DELTA3_FLAG"); sys.exit(1)
if rec["seven_gates_exact_pass"] is not True:
    print("SEVEN_NOT_PASS"); sys.exit(1)
if rec["contribution_class"] != "AI_DIRECT_ROOT":
    print("CLASS"); sys.exit(1)
if rec["candidate_set"] != ["051f27474d85d7f3299b56fc61bfcb0666a4e198"]:
    print("CAND"); sys.exit(1)
if rec["carrier_set"] != []:
    print("CARRIER"); sys.exit(1)
if "90e3a4b8d2719cf027e8079510ac41521ee1c60e" in rec["candidate_set"]:
    print("MERGE_IN_CAND"); sys.exit(1)
if "b4ee96dac799cbfba0a9f9c17844ce9d613cbcc7" in rec["candidate_set"]:
    print("FIX_IN_CAND"); sys.exit(1)
if rec["minimum_fix_set"] != ["b4ee96dac799cbfba0a9f9c17844ce9d613cbcc7"]:
    print("FIXSET"); sys.exit(1)
if rec.get("identity_source") != "offline_normalized_projection":
    print("IDENTITY_SOURCE_FAIL"); sys.exit(1)
if rec.get("identity_network_used_at_replay") is not False:
    print("IDENTITY_NETWORK_FLAG"); sys.exit(1)
if res.get("identity_source") != "offline_normalized_projection":
    print("RES_IDENTITY_SOURCE"); sys.exit(1)
rsrc = owned.joinpath("replay.zsh").read_text()
if ("gh" " api") in rsrc:
    print("LIVE_GH_API_IN_REPLAY"); sys.exit(1)
print("CONSERVATION_OK 1=1+0 PASS_PROPOSAL=1")
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
if len(strict) != 91:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
if "GHSA-76PC-MQXP-3RQ5" in strict:
    print("76PC_COUNTED"); sys.exit(1)
if "GHSA-49MQ-FC6Q-3H46" in strict:
    print("49MQ_COUNTED"); sys.exit(1)
print("UNIQUENESS_OK", len(ids), "76PC_ABSENT_CANONICAL91 DISTINCT_49MQ")
PY

echo "== first-party identity =="
python3 - "$OWNED" <<'PY' || fail "identity"
import hashlib, json, sys
from pathlib import Path
owned = Path(sys.argv[1])
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
WANT_SHA = {
    "GHSA-76PC-MQXP-3RQ5": "68f6243932a4fce66b3682ebcde01a677d10d9367ac3fde5f07b72cde92a679c",
    "GHSA-49MQ-FC6Q-3H46": "689caf376ed75d52b3dc1c879dffad651905501f9e3f34028ff2c44fd5d8d83c",
}
WANT_FIELDS = {
    "GHSA-76PC-MQXP-3RQ5": {
        "aliases": ["CVE-2026-55156"],
        "first_party_url": "https://github.com/ooples/token-optimizer-mcp/security/advisories/GHSA-76pc-mqxp-3rq5",
        "ghsa_id": "GHSA-76PC-MQXP-3RQ5",
        "github_reviewed": True,
        "global_catalog": "present",
        "package_ecosystem": "npm",
        "package_name": "@ooples/token-optimizer-mcp",
        "patched_version": "5.1.0",
        "published_at": "2026-06-10T18:04:31Z",
        "repository": "ooples/token-optimizer-mcp",
        "retrieved_at": "2026-08-15T01:30:00Z",
        "state": "published",
        "vulnerable_version_range": "5.0.1",
        "withdrawn": False,
    },
    "GHSA-49MQ-FC6Q-3H46": {
        "aliases": ["CVE-2026-55157"],
        "first_party_url": "https://github.com/ooples/token-optimizer-mcp/security/advisories/GHSA-49mq-fc6q-3h46",
        "ghsa_id": "GHSA-49MQ-FC6Q-3H46",
        "github_reviewed": True,
        "global_catalog": "present",
        "package_ecosystem": "npm",
        "package_name": "@ooples/token-optimizer-mcp",
        "patched_version": "5.1.0",
        "published_at": "2026-06-10T18:04:09Z",
        "repository": "ooples/token-optimizer-mcp",
        "retrieved_at": "2026-08-15T01:30:00Z",
        "state": "published",
        "vulnerable_version_range": "5.0.1",
        "withdrawn": False,
    },
}

def canon_sha(proj):
    missing = [k for k in CANON_KEYS if k not in proj]
    if missing:
        print("PROJ_MISSING_KEYS", missing); sys.exit(1)
    body_obj = {k: proj[k] for k in CANON_KEYS}
    body = json.dumps(body_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if not body.isascii():
        print("PROJ_NON_ASCII"); sys.exit(1)
    return hashlib.sha256(body.encode("ascii")).hexdigest(), body_obj

cas = [json.loads(l) for l in owned.joinpath("cases.jsonl").open() if l.strip()]
res = json.loads(owned.joinpath("result.json").read_text())
catalog = res.get("advisory_projections") or {}
if set(catalog) != set(WANT_SHA):
    print("CATALOG_KEYS", sorted(catalog)); sys.exit(1)
for gid, pin in WANT_SHA.items():
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
case_proj = cas[0]["identity_projection"]
sha, _ = canon_sha(case_proj)
if sha != WANT_SHA["GHSA-76PC-MQXP-3RQ5"]:
    print("CASE_PROJ_SHA", sha); sys.exit(1)
print("IDENTITY_OK offline_normalized_projection")
PY

echo "== git clone (public, no credentials) =="
gitq clone --filter=blob:none --single-branch --branch master \
  https://github.com/ooples/token-optimizer-mcp.git "$REPLAY_TMP/token-optimizer-mcp" >/dev/null
gitq -C "$REPLAY_TMP/token-optimizer-mcp" fetch --filter=blob:none origin \
  tag v5.0.0 tag v5.0.1 tag v5.1.0 tag v5.1.1 >/dev/null
Z="$REPLAY_TMP/token-optimizer-mcp"

echo "== git facts =="
ORIGIN=051f27474d85d7f3299b56fc61bfcb0666a4e198
PARENT=5fe1380e53eee6d08ec47980fd7b32a08eb077b6
FIX=b4ee96dac799cbfba0a9f9c17844ce9d613cbcc7
FIXP=4ae7c351659b3a1a7f741f6dc427577aead9fdd8
MERGE=90e3a4b8d2719cf027e8079510ac41521ee1c60e
V500=0b9b1d3fb6c06fa7b94b772490ac432bfb7369d9
V501=8138f3a6d32eff80387f24d6068039ae8fb7bfa9
V510=94815a16e3322101694e97561fc1dc8b5af904dc
V511=687b55460d752fa4ee011c58535c733191b831c8
TYPO=8137147c028771510271d5b4c7ea44134fbf866b
LATER=0408bee1a476814be830d12adec05a4165eeff95
PATH_WS=src/server/web-server.ts

parents=$(gitq -C "$Z" rev-list --parents -n 1 "$ORIGIN")
[[ $parents == "$ORIGIN $PARENT" ]] || fail "PARENTS $parents"
gitq -C "$Z" cat-file -p "$ORIGIN" | LC_ALL=C grep -q 'Co-Authored-By: Claude <noreply@anthropic.com>' || fail "ORIGIN_MARKER"
mp=$(gitq -C "$Z" rev-list --parents -n 1 "$MERGE")
[[ $mp == "$MERGE 7f49dde1a811bb8d952f844c303387abc0d8b92a 9f1cea9a8fcba17e9aac700d3bc00b293bea9f81" ]] || fail "MERGE_PARENTS $mp"
gitq -C "$Z" cat-file -p "$MERGE" | LC_ALL=C grep -E -q 'Co-Authored-By: Claude|Co-authored-by: Claude' && fail "MERGE_MARKER" || true
fp=$(gitq -C "$Z" rev-list --parents -n 1 "$FIX")
[[ $fp == "$FIX $FIXP" ]] || fail "FIX_PARENTS $fp"
gitq -C "$Z" cat-file -p "$FIX" | LC_ALL=C grep -q 'GHSA-76pc-mqxp-3rq5' || fail "FIX_NAMES_76PC"

ws_parent=$(gitq -C "$Z" ls-tree "$PARENT" -- "$PATH_WS")
[[ -z $ws_parent ]] || fail "PARENT_HAS_WEB_SERVER $ws_parent"
gitq -C "$Z" grep -F -q 'session-log-${sessionId}.jsonl' "$ORIGIN" -- "$PATH_WS" || fail "ORIGIN_SINK"
if gitq -C "$Z" grep -F -q isValidSessionId "$ORIGIN" -- "$PATH_WS"; then
  fail "ORIGIN_HAS_VALIDATOR"
fi
gitq -C "$Z" grep -F -q isValidSessionId "$FIX" -- "$PATH_WS" || fail "FIX_MISSING_VALIDATOR"
gitq -C "$Z" grep -F -q 'SESSION_ID_RE = /^[A-Za-z0-9_-]{1,64}$/' "$FIX" -- "$PATH_WS" || fail "FIX_RE"
if gitq -C "$Z" grep -F -q isValidSessionId "$FIXP" -- "$PATH_WS"; then
  fail "FIXP_ALREADY_VALIDATOR"
fi
gitq -C "$Z" grep -F -q 'session-log-${sessionId}.jsonl' "$V501" -- "$PATH_WS" || fail "V501_SINK"
if gitq -C "$Z" grep -F -q isValidSessionId "$V501" -- "$PATH_WS"; then
  fail "V501_HAS_VALIDATOR"
fi
gitq -C "$Z" grep -F -q isValidSessionId "$V510" -- "$PATH_WS" || fail "V510_MISSING_VALIDATOR"
gitq -C "$Z" grep -F -q isValidSessionId "$V511" -- "$PATH_WS" || fail "V511_MISSING_VALIDATOR"

pk=$(gitq -C "$Z" log -S 'session-log-${sessionId}.jsonl' --format='%H' "$V501" -- "$PATH_WS")
print -r -- "$pk" | LC_ALL=C grep -qx "$ORIGIN" || fail "PICKAXE_SINK $pk"
print -r -- "$pk" | LC_ALL=C grep -qx "$MERGE" && fail "MERGE_PICKAXE_SINK" || true
fpk=$(gitq -C "$Z" log --first-parent -S 'session-log-${sessionId}.jsonl' --format='%H' "$V501" -- "$PATH_WS")
print -r -- "$fpk" | LC_ALL=C grep -qx "$MERGE" || fail "FIRST_PARENT_PICKAXE $fpk"
print -r -- "$fpk" | LC_ALL=C grep -qx "$ORIGIN" && fail "ORIGIN_ON_FIRST_PARENT" || true
ipk=$(gitq -C "$Z" log --first-parent -S isValidSessionId --format='%H' "$V511" -- "$PATH_WS")
print -r -- "$ipk" | LC_ALL=C grep -qx "$FIX" || fail "PICKAXE_FIX $ipk"

gitq -C "$Z" merge-base --is-ancestor "$ORIGIN" "$V501" || fail "ORIGIN_NOT_IN_V501"
gitq -C "$Z" merge-base --is-ancestor "$ORIGIN" "$V500" || fail "ORIGIN_NOT_IN_V500"
gitq -C "$Z" merge-base --is-ancestor "$FIX" "$V501" && fail "FIX_IN_VULN" || true
gitq -C "$Z" merge-base --is-ancestor "$FIX" "$V510" || fail "FIX_NOT_IN_V510"
gitq -C "$Z" merge-base --is-ancestor "$FIX" "$V511" || fail "FIX_NOT_IN_V511"
gitq -C "$Z" merge-base --is-ancestor "$TYPO" "$V501" && fail "TYPO_IS_V501" || true
gitq -C "$Z" merge-base --is-ancestor "$LATER" "$V510" || fail "LATER_NOT_IN_V510"

peel=$(gitq -C "$Z" rev-parse 'v5.0.1^{commit}')
[[ $peel == "$V501" ]] || fail "PEEL501 $peel"
peel=$(gitq -C "$Z" rev-parse 'v5.1.0^{commit}')
[[ $peel == "$V510" ]] || fail "PEEL510 $peel"
peel=$(gitq -C "$Z" rev-parse 'v5.1.1^{commit}')
[[ $peel == "$V511" ]] || fail "PEEL511 $peel"

blob_o=$(gitq -C "$Z" rev-parse "$ORIGIN:$PATH_WS")
blob_m=$(gitq -C "$Z" rev-parse "$MERGE:$PATH_WS")
blob_v=$(gitq -C "$Z" rev-parse "$V501:$PATH_WS")
blob_f=$(gitq -C "$Z" rev-parse "$FIX:$PATH_WS")
blob_10=$(gitq -C "$Z" rev-parse "$V510:$PATH_WS")
blob_11=$(gitq -C "$Z" rev-parse "$V511:$PATH_WS")
[[ $blob_o == 1cdd93c63455f91d58d5b8fbac667e7760858667 ]] || fail "BLOB_O $blob_o"
[[ $blob_m == b2038a0995ae3aaf3258ba4d6ccc8444b09ed99b ]] || fail "BLOB_M $blob_m"
[[ $blob_v == d8cf67f68b5bebb4fbf063de863065bc4d78d769 ]] || fail "BLOB_V $blob_v"
[[ $blob_f == 3f750e6ce7bed24a41395c8578e8ca98ad094f15 ]] || fail "BLOB_F $blob_f"
[[ $blob_10 == 40e8be9bbd27d877285cddb7192249eed40f202b ]] || fail "BLOB_10 $blob_10"
[[ $blob_11 == "$blob_10" ]] || fail "BLOB_11 $blob_11"
[[ $blob_o != "$blob_m" ]] || fail "ORIGIN_EQUALS_MERGE"
[[ $blob_f != "$blob_10" ]] || fail "FIX_EQUALS_V510"

python3 - "$Z" "$ORIGIN" "$PARENT" "$FIX" <<'PY' || fail "matcher"
import os, subprocess, sys
sys.path.insert(0, os.environ["PYTHONPATH"])
from cve_analyzer.models import CommitInfo
from cve_analyzer.source_matcher import MATCHER_CONTRACT, matches_for_commit
repo, origin, parent, fix = sys.argv[1:]
env = dict(os.environ)
env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")

def git(*a):
    r = subprocess.run(["git","--no-optional-locks","-C",repo,*a], capture_output=True, text=True, env=env)
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
if matches_for_commit(ci(parent)):
    print("PARENT_MATCH"); sys.exit(1)
if not any(m.tool == "claude_code" and m.source_module == "coauthor_trailer" for m in matches_for_commit(ci(fix))):
    print("FIX_MATCH_MISSING"); sys.exit(1)
print("MATCHER_OK")
PY
echo "GIT_OK"

echo "== npm tarballs (public registry, no credentials) =="
python3 - "$REPLAY_TMP" <<'PY' || fail "npm"
import hashlib, io, json, sys, tarfile, urllib.error, urllib.request
from pathlib import Path
tmp = Path(sys.argv[1])
want = {
    "5.0.1": ("4594c2d6140c20dd64d85fb5ceee660c8f943ff76f779d610d8554eea7267761", "5838756a76cda2ae775e9b7d141bfcecef36e811", False),
    "5.1.1": ("1828e97d1c7dabfb7d6d27ac786b88e1977c5fa95f3da1f12bb1630533e670da", "0b21bd9dd55c1e95a35a60e732cad6c0ea3d59d4", True),
}
for ver, (sha256, sha1, must_valid) in want.items():
    url = "https://registry.npmjs.org/@ooples/token-optimizer-mcp/-/token-optimizer-mcp-" + ver + ".tgz"
    dest = tmp / ("token-optimizer-mcp-" + ver + ".tgz")
    urllib.request.urlretrieve(url, dest)
    raw = dest.read_bytes()
    got256 = hashlib.sha256(raw).hexdigest()
    got1 = hashlib.sha1(raw).hexdigest()
    if got256 != sha256 or got1 != sha1:
        print("TGZ_HASH", ver, got256, got1); sys.exit(1)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as t:
        js = t.extractfile("package/dist/server/web-server.js").read().decode("utf-8")
    if "session-log-" not in js:
        print("JS_NO_SINK", ver); sys.exit(1)
    has_valid = "isValidSessionId" in js
    if has_valid != must_valid:
        print("JS_VALIDATOR", ver, has_valid); sys.exit(1)
req = urllib.request.Request("https://registry.npmjs.org/@ooples/token-optimizer-mcp/5.1.0")
try:
    urllib.request.urlopen(req, timeout=60)
    print("NPM510_NOT_404"); sys.exit(1)
except urllib.error.HTTPError as e:
    if e.code != 404:
        print("NPM510", e.code); sys.exit(1)
print("NPM_OK")
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

echo "REPLAY_OK reviewed=1 PASS_proposal=1 NARROW=0 REJECT=0 UNKNOWN=0 BLOCKED=0"
