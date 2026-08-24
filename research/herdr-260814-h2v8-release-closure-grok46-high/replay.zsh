#!/usr/bin/env zsh
# Deterministic replay for herdr-260814-h2v8-release-closure-grok46-high.
# English only. No credentials. Shared caches read-only. mktemp network cache removed.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-h2v8-release-closure-grok46-high
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical88/summary.json
ADV_UN=/home/hanqing/.cache/cve-analyzer/advisory-database
ADV_JSON=$ADV_UN/advisories/unreviewed/2025/11/GHSA-h2v8-4c3f-vqgv/GHSA-h2v8-4c3f-vqgv.json
CLONE=/home/hanqing/.cache/cve-analyzer/repos/brentmid_evernote-mcp-server
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

PARENT=9f7c1b36d698845ea8bd968ad7446550995a2a3d
CAND=e08547bcdb42aaa86190c6e2dfc64159fcd3a146
FIX=1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579
CAND_TREE=98e79e9a9233d08fe614e5dcf860be77d5270377
BLOB_CAND=e9729ced5fc86193f3bb7705776def88f960dc22
BLOB_FIXP=9cbeb76daf6fc36e57808f0d48fb8d79412e3d6e
BLOB_FIX=24f6ccebb1a188a4e45d966da45bb90fe4fb12f9

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1 }

expect_eq() {
  if [[ $1 != "$2" ]]; then
    print -r -- "mismatch $3 expected=$2 got=$1" >&2
    exit 1
  fi
}

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  expect_eq "$got" "$2" "$1"
}

gitx() {
  local repo=$1
  shift
  local errf
  errf=$(mktemp /tmp/h2v8-giterr.XXXXXX)
  set +e
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  local rc=$?
  set -e
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

require_file() { [[ -f $1 ]] || fail "missing $1" }
require_dir() { [[ -d $1 ]] || fail "missing $1" }

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_file "$ADV_JSON"
require_dir "$CLONE"

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b: raise SystemExit(1)
b.decode("ascii")
PY
done

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074
expect_hash "$SUMMARY" 81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921
expect_hash "$ADV_JSON" eea310ecbf64f4e0d5b929965eb3c32a4fbb2c422ee62a4654655bad9883607b

n_assign=$(/usr/bin/wc -l < "$OWNED/assignment.jsonl" | /usr/bin/tr -d ' ')
n_cases=$(/usr/bin/wc -l < "$OWNED/cases.jsonl" | /usr/bin/tr -d ' ')
expect_eq "$n_assign" 1 assignment_rows
expect_eq "$n_cases" 1 cases_rows

python3 - "$OWNED" "$SUMMARY" "$ADV_JSON" <<'PY' || fail "python conservation"
import hashlib, json, sys
from pathlib import Path
owned, summary_p, adv = map(Path, sys.argv[1:])
assigns=[json.loads(l) for l in owned.joinpath("assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in owned.joinpath("cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads(owned.joinpath("result.json").read_text())
assert len(assigns)==1 and len(cases)==1
assert assigns[0]["case_id"]==cases[0]["case_id"]=="GHSA-H2V8-4C3F-VQGV"
assert assigns[0]["did_not_inherit_cf4_b2_unknown"] is True
assert cases[0]["verdict"]=="UNKNOWN"
assert cases[0]["proposed_pass"] is False
assert cases[0]["gates"]["identity_gate"]=="PASS"
assert cases[0]["gates"]["ai_hunk_gate"]=="PASS"
assert cases[0]["gates"]["topology_gate"]=="PASS"
assert cases[0]["gates"]["but_for_gate"]=="PASS"
assert cases[0]["gates"]["fix_reversal_gate"]=="PASS"
assert cases[0]["gates"]["release_gate"]=="UNKNOWN"
assert cases[0]["gates"]["uniqueness_gate"]=="PASS"
assert cases[0]["unknown_gates"]==["release_gate"]
assert res["counts"]["PASS"]==0 and res["counts"]["UNKNOWN"]==1
assert res["conservation"]["equation"]=="1=1+0"
gid="GHSA-H2V8-4C3F-VQGV"
assert int(hashlib.sha256(gid.encode("ascii")).hexdigest(),16)%6==2
summary=json.loads(summary_p.read_text())
counted={str(x).upper() for x in summary["strict_released_case_ids"]}
assert len(counted)==88
assert gid not in counted
adv=json.loads(adv.read_text())
assert adv["id"]=="GHSA-h2v8-4c3f-vqgv"
assert "CVE-2025-12489" in adv["aliases"]
assert adv["database_specific"]["github_reviewed"] is False
assert any("1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579" in (r.get("url") or "") for r in adv["references"])
print("conservation_ok")
PY

expect_eq "$(gitx "$CLONE" cat-file -t "$PARENT")" commit parent_type
expect_eq "$(gitx "$CLONE" cat-file -t "$CAND")" commit cand_type
expect_eq "$(gitx "$CLONE" cat-file -t "$FIX")" commit fix_type
expect_eq "$(gitx "$CLONE" rev-parse "${CAND}^{tree}")" "$CAND_TREE" cand_tree
expect_eq "$(gitx "$CLONE" rev-list --parents -n 1 "$CAND")" "$CAND $PARENT" cand_parents
gitx "$CLONE" merge-base --is-ancestor "$CAND" "$FIX" || fail "candidate not ancestor of fix"

if "${git_cmd[@]}" -C "$CLONE" cat-file -e "${PARENT}:auth.js" >/dev/null 2>&1; then fail "parent has auth.js"; fi
expect_eq "$(gitx "$CLONE" rev-parse "${CAND}:auth.js")" "$BLOB_CAND" cand_auth_blob
expect_eq "$(gitx "$CLONE" rev-parse "${FIX}^:auth.js")" "$BLOB_FIXP" fix_parent_auth_blob
expect_eq "$(gitx "$CLONE" rev-parse "${FIX}:auth.js")" "$BLOB_FIX" fix_auth_blob

gitx "$CLONE" grep -q 'exec(`${command} "${url}"`' "$CAND" -- auth.js || fail "candidate missing exec interpolation"
gitx "$CLONE" grep -q 'exec(`${command} "${url}"`' "${FIX}^" -- auth.js || fail "fix parent missing exec interpolation"
if gitx "$CLONE" grep -q 'exec(`${command} "${url}"`' "$FIX" -- auth.js; then fail "fix still has exec interpolation"; fi
gitx "$CLONE" grep -q 'spawn(command, args' "$FIX" -- auth.js || fail "fix missing spawn"

body=$(gitx "$CLONE" log -1 --format='%B' "$CAND")
print -r -- "$body" | /usr/bin/grep -q 'Generated with' || fail "candidate missing Generated with"
print -r -- "$body" | /usr/bin/grep -q 'Co-Authored-By: Claude <noreply@anthropic.com>' || fail "candidate missing Claude trailer"
fixbody=$(gitx "$CLONE" log -1 --format='%B' "$FIX")
print -r -- "$fixbody" | /usr/bin/grep -q 'Co-Authored-By: Claude <noreply@anthropic.com>' || fail "fix missing Claude trailer"
print -r -- "$fixbody" | /usr/bin/grep -q 'ZDI-CAN-27913' || fail "fix missing ZDI id"

tag_n=$(gitx "$CLONE" tag | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$tag_n" 0 local_tags
remote_tags=$(gitx "$CLONE" ls-remote --tags origin | /usr/bin/wc -l | /usr/bin/tr -d ' ')
expect_eq "$remote_tags" 0 origin_tags

WORKDIR=$(mktemp -d /tmp/h2v8-replay.XXXXXX)
cleanup() { rm -rf "$WORKDIR" }
trap cleanup EXIT

/usr/bin/curl -sS -L --max-time 25 -o "$WORKDIR/npm.json" -A 'ai-slop-research/h2v8-release-closure' 'https://registry.npmjs.org/evernote-mcp-server' || fail "npm meta fetch"
python3 - "$WORKDIR/npm.json" "$WORKDIR" <<'PY' || fail "npm collision check"
import json, sys, urllib.request, tarfile, io, hashlib
from pathlib import Path
meta, out = Path(sys.argv[1]), Path(sys.argv[2])
d=json.loads(meta.read_text())
assert d["name"]=="evernote-mcp-server"
author=d.get("author") or {}
assert author.get("name")=="yasuhiroki"
assert set(d.get("versions") or {})=={"0.0.2","0.0.3"}
v2=d["versions"]["0.0.2"]
v3=d["versions"]["0.0.3"]
assert v2.get("gitHead")=="406e50aa27ebad4016d35bf8d600c1353af9e969"
assert v3.get("gitHead")=="78ebf186d303deed788c944802aa3d8b72bcd35c"
assert v2["dist"]["integrity"]=="sha512-F4/nkNG8R5NJc/bXbCXgyIU+QtPIs0IjsKz8wNCrqJwgscggtiJ5LDqO8ryFu8ZdH7HYZLqn33VK4+F1s+FSIg=="
assert v3["dist"]["integrity"]=="sha512-HMg9sg8mWx9Er7KoqlHeEnBUclVV/NznX5yxRDDRQXbziTc8ks1onKpqbxb2LzzhW0Hm368RV7dXhafjA+pJQQ=="
ua={"User-Agent":"ai-slop-research/h2v8-release-closure"}
want={
  "0.0.2":"f3caba45b2d68a4be472ab2b880b62dbb7a687ed4a0932b32090d197b980b0cc",
  "0.0.3":"098f5a1d96317cab57c258708853a9d95b19c573b7cc9c1c4a664088f9efcc9e",
}
for ver, spec in (("0.0.2", v2), ("0.0.3", v3)):
    data=urllib.request.urlopen(urllib.request.Request(spec["dist"]["tarball"], headers=ua), timeout=30).read()
    got=hashlib.sha256(data).hexdigest()
    assert got==want[ver], (ver, got)
    tf=tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    names=tf.getnames()
    assert not any(n.endswith("auth.js") for n in names)
    pj=json.loads(tf.extractfile("package/package.json").read())
    assert pj["name"]=="evernote-mcp-server"
    assert pj["version"]==ver
    assert "yasuhiroki" in str(pj.get("author"))
print("npm_collision_ok")
PY

print -r -- "REPLAY_OK reviewed=1 PASS_proposal=0 REJECT=0 UNKNOWN=1 packet_delta=0 canonical_strict=88"
