#!/usr/bin/env zsh
set -euo pipefail
unsetopt xtrace
OWNED=${OWNED:-/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-nearclosed-a-grok46-low}
ROOT=${ROOT:-/home/hanqing/agents/ai-slop}
H=${H:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/hermes-webui}
S=${S:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/sharpcompress}
T=${T:-/home/hanqing/.cache/ghsa200-worker-clones/upgrade-a/clones/titra}
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

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
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json" \
  81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl" \
  35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
hash_check "$ROOT/autoresearch/orchestrator-260813-fp211-audit/public_cases.jsonl" \
  e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257
hash_check "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/8rw6_acceptance.json" \
  8cb85b42f405595b834a4ccae9b782c488b8dfa340900ad5717bb0dac71cfae9

echo "== conservation 3=2+1 =="
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
    "GHSA-5WQV-FHMR-PJGH",
    "GHSA-6C8G-7P36-R338",
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
if n_pass != 1 or n_nar != 2 or len(cas) != 3:
    print("COUNT_FAIL", n_pass, n_nar); sys.exit(1)
if res["conservation"]["equation"] != "3=2+1" or res["conservation"]["holds"] is not True:
    print("EQ_FAIL"); sys.exit(1)
if res["pass_proposals"] != ["GHSA-6C8G-7P36-R338"] or res["canonical_strict_count_untouched"] != 88:
    print("FLAG_FAIL"); sys.exit(1)
for rec in cas:
    g = rec["gates"]
    for k in need:
        if g[k] not in okv:
            print("BAD_GATE", rec["case_id"], k, g[k]); sys.exit(1)
    if rec.get("osv_introduced_used_as_causal_proof") is not False:
        print("OSV_USED_AS_PROOF", rec["case_id"]); sys.exit(1)
    if rec["case_id"] == "GHSA-PQGX-6WG3-GMVR" and rec.get("authorship_transfer") is not False:
        print("PQGX_TRANSFER"); sys.exit(1)
    if g["release_gate"] != "PASS":
        print("RELEASE_NOT_PASS", rec["case_id"]); sys.exit(1)
    if rec["case_id"] == "GHSA-6C8G-7P36-R338":
        if rec["verdict"] != "PASS_PROPOSAL" or rec.get("proposed_pass") is not True:
            print("6C8G_NOT_PASS", rec["verdict"]); sys.exit(1)
        if any(g[k] != "PASS" for k in need):
            print("6C8G_GATE", g); sys.exit(1)
        if rec["contribution_class"] != "AI_NEW_SURFACE_CONTRIBUTOR":
            print("6C8G_CLASS"); sys.exit(1)
    else:
        if rec["verdict"] != "NARROW" or g["but_for_gate"] != "NARROW":
            print("BUTFOR_NOT_NARROW", rec["case_id"]); sys.exit(1)
        if rec.get("proposed_pass") is not False:
            print("PROPOSED_PASS_FLAG", rec["case_id"]); sys.exit(1)
print("CONSERVATION_OK 3=2+1 NARROW=2 PASS_PROPOSAL=1")
PY

echo "== uniqueness vs pinned canonical88 =="
python3 - << PY
import json, sys
from pathlib import Path
canon = json.loads(Path("$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json").read_text())
strict = set(x.upper() for x in canon["strict_released_case_ids"])
ids = [json.loads(l)["case_id"].upper() for l in Path("$OWNED/assignment.jsonl").open() if l.strip()]
hit = [i for i in ids if i in strict]
if hit:
    print("UNIQUENESS_FAIL in_canonical88", hit); sys.exit(1)
if "GHSA-8RW6-P7M8-63JP" in ids:
    print("UNIQUENESS_FAIL 8RW6"); sys.exit(1)
if len(strict) != 88:
    print("CANON_COUNT_FAIL", len(strict)); sys.exit(1)
print("UNIQUENESS_OK", len(ids))
PY

echo "== git facts =="
[[ -d $H && -d $S && -d $T ]] || fail "CLONE_ABSENT"

# 5WQV
C=ee672df463e285791e4466e6132297e5feb4a1df
F=2a3baa71b81ca92da8ece8616a09f15894beec71
P=465b97a9f5e5b7bd733eaab6fe251d73e815df6e
gitq -C "$H" cat-file -t "$C" >/dev/null
gitq -C "$H" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$H" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "5WQV_PARENTS $parents"
gitq -C "$H" cat-file -p "$C" | LC_ALL=C grep -q 'Co-Authored-By: Claude Sonnet 4.6' || fail "5WQV_MARKER"
gitq -C "$H" grep -q 'get_state_db_session_messages(sid)' "$P" -- api/routes.py || fail "5WQV_PARENT_CALL"
if gitq -C "$H" grep -q 'profile=_session_profile' "$P" -- api/routes.py; then
  fail "5WQV_PARENT_HAS_PROFILE_KWARG"
fi
gitq -C "$H" grep -q 'profile=_session_profile' "$C" -- api/routes.py || fail "5WQV_CAND_PROFILE"
gitq -C "$H" grep -q _session_visible_to_active_profile "$F" -- api/routes.py || fail "5WQV_FIX_VISIBLE"
fsubj=$(gitq -C "$H" log -1 --format='%s' "$F")
[[ $fsubj == *"scope session by-id reads"* ]] || fail "5WQV_FIX_SUBJ $fsubj"
gitq -C "$H" merge-base --is-ancestor "$C" v0.51.442 || fail "5WQV_CAND_TAG"
gitq -C "$H" merge-base --is-ancestor "$F" v0.51.442 && fail "5WQV_FIX_IN_VULN" || true
gitq -C "$H" merge-base --is-ancestor "$F" v0.51.443 || fail "5WQV_FIX_TAG"
echo "5WQV_OK"

# 6C8G
C=8b95e0a76d6b387533175730e2895ccd16772d07
F=2021a06626d0555a4d69471386e763ca5f5d5dfb
P=3f9986c13c973f5e9b8e08da8bfb5e8259044a44
gitq -C "$S" cat-file -t "$C" >/dev/null
gitq -C "$S" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$S" rev-list --parents -n 1 "$C")
[[ $parents == "$C $P" ]] || fail "6C8G_PARENTS $parents"
an=$(gitq -C "$S" log -1 --format='%an' "$C")
[[ $an == "copilot-swe-agent[bot]" ]] || fail "6C8G_AUTHOR $an"
gitq -C "$S" grep -q ExtractToDirectory "$P" -- src/SharpCompress/Archives/IArchiveExtensions.cs || fail "6C8G_PARENT_EXTRACT"
gitq -C "$S" grep -q 'Path.Combine(destination, entry.Key' "$P" -- src/SharpCompress/Archives/IArchiveExtensions.cs || fail "6C8G_PARENT_COMBINE"
if gitq -C "$S" grep -q WriteToDirectoryAsync "$P" -- src/SharpCompress/Archives/IArchiveExtensions.cs; then
  fail "6C8G_PARENT_HAS_ASYNC"
fi
gitq -C "$S" grep -q WriteToDirectoryAsync "$C" -- src/SharpCompress/Archives/IArchiveExtensions.cs || fail "6C8G_CAND_ASYNC"
gitq -C "$S" grep -q 'Path.Combine' "$C" -- src/SharpCompress/Archives/IArchiveExtensions.cs || fail "6C8G_CAND_COMBINE"
GITQ_N=$((GITQ_N + 1))
outfile="$REPLAY_TMP/out.$GITQ_N"
errfile="$REPLAY_TMP/err.$GITQ_N"
set +e
command git -C "$S" cat-file -e "${C}:src/SharpCompress/Archives/IAsyncArchiveExtensions.cs" >"$outfile" 2>"$errfile"
async_rc=$?
set -e
rm -f "$outfile" "$errfile"
[[ $async_rc -ne 0 ]] || fail "6C8G_CAND_HAS_ASYNC_FILE"
gitq -C "$S" grep -q WriteToDirectoryAsyncInternal 0.47.4 -- src/SharpCompress/Archives/IAsyncArchiveExtensions.cs || fail "6C8G_0474_INTERNAL"
gitq -C "$S" grep -q 'Path.Combine' 0.47.4 -- src/SharpCompress/Archives/IAsyncArchiveExtensions.cs || fail "6C8G_0474_COMBINE"
if gitq -C "$S" grep -q GetFullDestinationDirectoryPath 0.47.4 -- src/SharpCompress/Archives/IAsyncArchiveExtensions.cs; then
  fail "6C8G_0474_ALREADY_FIXED"
fi
gitq -C "$S" grep -q GetFullPath "$F" -- src/SharpCompress/Archives/IAsyncArchiveExtensions.cs || fail "6C8G_FIX_GETFULLPATH"
gitq -C "$S" grep -q GetFullDestinationDirectoryPath 0.48.0 -- src/SharpCompress/Archives/IAsyncArchiveExtensions.cs || fail "6C8G_048_HELPER"
fsubj=$(gitq -C "$S" log -1 --format='%s' "$F")
[[ $fsubj == *"zipslip"* ]] || fail "6C8G_FIX_SUBJ $fsubj"
gitq -C "$S" merge-base --is-ancestor "$C" 0.47.4 || fail "6C8G_CAND_TAG"
gitq -C "$S" merge-base --is-ancestor "$F" 0.47.4 && fail "6C8G_FIX_IN_VULN" || true
gitq -C "$S" merge-base --is-ancestor "$F" 0.48.0 || fail "6C8G_FIX_TAG"
peel0474=$(gitq -C "$S" rev-parse 0.47.4)
peel0480=$(gitq -C "$S" rev-parse 0.48.0)
[[ $peel0474 == 5758b08236b275b926bc2c3d97604a96d21546c0 ]] || fail "6C8G_PEEL_0474 $peel0474"
[[ $peel0480 == 6e59c7d7bbf8c19a8a92c3c382599906684bb93d ]] || fail "6C8G_PEEL_0480 $peel0480"
python3 - "$REPLAY_TMP" <<'PY' || fail "6C8G_NUGET"
import hashlib, sys, urllib.request, zipfile
from pathlib import Path
d = Path(sys.argv[1])
want = {
    "0.47.4": ("987d11f9a976194a26218922798b9d4e61759809c852289f40f4e9d77794160f", "5758b08236b275b926bc2c3d97604a96d21546c0"),
    "0.48.0": ("d8c5da8a76d325eb81c1103a78953e025513f22ade36b5b11d8342324146f0b7", "6e59c7d7bbf8c19a8a92c3c382599906684bb93d"),
}
for ver, (sha, commit) in want.items():
    url = "https://api.nuget.org/v3-flatcontainer/sharpcompress/%s/sharpcompress.%s.nupkg" % (ver, ver)
    dest = d / ("sharpcompress.%s.nupkg" % ver)
    urllib.request.urlretrieve(url, dest)
    got = hashlib.sha256(dest.read_bytes()).hexdigest()
    if got != sha:
        raise SystemExit("nupkg hash %s %s" % (ver, got))
    z = zipfile.ZipFile(dest)
    spec = z.read("SharpCompress.nuspec").decode("utf-8")
    if 'commit="%s"' % commit not in spec:
        raise SystemExit("nuspec commit %s" % ver)
    dll = z.read("lib/net8.0/SharpCompress.dll")
    if b"WriteToDirectoryAsyncInternal" not in dll and "WriteToDirectoryAsyncInternal".encode("utf-16le") not in dll:
        raise SystemExit("dll missing async internal %s" % ver)
print("NUGET_OK")
PY
echo "6C8G_OK"

# PQGX
SQ=67c7b7663219c9e28fce487b1803706b333c2a4f
M=40331e610075e7c9a076873cc5b3655362d136db
F=2e2ac5cbeed47a76720b21c7fde0214a242e065e
P=62fe0533d792ca72794af098cd6b1d3301514ff7
gitq -C "$T" cat-file -t "$SQ" >/dev/null
gitq -C "$T" cat-file -t "$M" >/dev/null
gitq -C "$T" cat-file -t "$F" >/dev/null
parents=$(gitq -C "$T" rev-list --parents -n 1 "$SQ")
[[ $parents == "$SQ $P" ]] || fail "PQGX_PARENTS $parents"
an=$(gitq -C "$T" log -1 --format='%an' "$SQ")
[[ $an == "Copilot" ]] || fail "PQGX_AUTHOR $an"
gitq -C "$T" grep -q "from 'vm2'" "$P" -- imports/api/timecards/server/methods.js || fail "PQGX_PARENT_VM2"
gitq -C "$T" grep -q timeEntryRule "$P" -- imports/api/timecards/server/methods.js || fail "PQGX_PARENT_RULE"
gitq -C "$T" grep -q vm_sandbox.js "$SQ" -- imports/api/timecards/server/methods.js || fail "PQGX_SQUASH_SANDBOX"
if gitq -C "$T" grep -q validateSandboxCode "$SQ" -- imports/utils/vm_sandbox.js; then
  fail "PQGX_SQUASH_HAS_VALIDATE"
fi
gitq -C "$T" grep -q validateSandboxCode "$F" -- imports/utils/vm_sandbox.js || fail "PQGX_FIX_VALIDATE"
gitq -C "$T" merge-base --is-ancestor "$M" "$SQ" && fail "PQGX_MEMBER_ANC_SQUASH" || true
gitq -C "$T" merge-base --is-ancestor "$M" 0.99.48 && fail "PQGX_MEMBER_IN_VULN" || true
gitq -C "$T" merge-base --is-ancestor "$SQ" 0.99.48 || fail "PQGX_SQUASH_TAG"
gitq -C "$T" merge-base --is-ancestor "$F" 0.99.48 && fail "PQGX_FIX_IN_VULN" || true
gitq -C "$T" merge-base --is-ancestor "$F" 0.99.49 || fail "PQGX_FIX_TAG"
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

echo "REPLAY_OK reviewed=3 PASS_proposal=1 NARROW=2 REJECT=0 UNKNOWN=0 BLOCKED=0"
