#!/usr/bin/env zsh
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export GIT_NO_LAZY_FETCH=1
export GIT_PAGER=cat
export PYTHONPATH=/home/hanqing/agents/ai-slop/cve-analyzer/src

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-new-surface-unseen20-grok46-high
CONTRACT=$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md
LEDGER=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/ledger.jsonl
SUMMARY=$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical91/summary.json
ADV=/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
KUMA=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kumahq__kuma
OTEL=/home/hanqing/.cache/cve-analyzer/repos/jenkinsci_opentelemetry-plugin
BLAZE=/home/hanqing/.cache/cve-analyzer/repos/jenkinsci_blazemeter-plugin
MAXM=/home/hanqing/.cache/cve-analyzer/repos/oschwald_maxminddb-rust
PGAD=/home/hanqing/.cache/cve-analyzer/repos/pgadmin-org_pgadmin4

fail() { print -r -- "REPLAY_FAIL $*" >&2; exit 1; }

require_file() { [[ -f $1 ]] || fail "missing $1"; }
require_dir() { [[ -d $1 ]] || fail "missing $1"; }
require_absent() { [[ ! -e $1 ]] || fail "must be absent: $1"; }

require_file "$OWNED/assignment.jsonl"
require_file "$OWNED/cases.jsonl"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"
require_file "$OWNED/replay.zsh"
require_file "$CONTRACT"
require_file "$LEDGER"
require_file "$SUMMARY"
require_dir "$ADV/advisories/github-reviewed"
require_absent "$OWNED/work"
require_absent "$OWNED/notes"
require_absent "$OWNED/pages"
require_absent "$OWNED/clones"

n_owned=$(/usr/bin/ls -1 "$OWNED" | /usr/bin/wc -l | /usr/bin/tr -d ' ')
[[ $n_owned == 5 ]] || fail "owned_file_count $n_owned"

for f in assignment.jsonl cases.jsonl result.json report.md replay.zsh; do
  python3 - "$OWNED/$f" <<'PY' || fail "ascii $f"
import sys
b=open(sys.argv[1],"rb").read()
if b"\x00" in b:
    raise SystemExit(1)
b.decode("ascii")
PY
done

python3 - "$OWNED" <<'PY' || fail "json conservation"
import json,sys
from pathlib import Path
d=Path(sys.argv[1])
assign=[json.loads(l) for l in (d/"assignment.jsonl").read_text().splitlines() if l.strip()]
cases=[json.loads(l) for l in (d/"cases.jsonl").read_text().splitlines() if l.strip()]
res=json.loads((d/"result.json").read_text())
expect=["GHSA-3VCP-CHFH-F6R2","GHSA-F696-867G-2759","GHSA-FXP5-37MH-VFF5","GHSA-MJ73-J457-8X9Q","GHSA-P58C-Q354-6C4F"]
assert [a["case_id"] for a in assign]==expect
assert [c["case_id"] for c in cases]==expect
assert res["conservation"]["reviewed_case_ids"]==expect
assert res["conservation"]["equation"]=="5=5+0"
assert res["conservation"]["holds"] is True
assert res["counts"]["assigned"]==5 and res["counts"]["reviewed"]==5
assert res["counts"]["PASS"]==0 and res["counts"]["REJECT"]==5
assert res["did_not_pad"] is True
assert res["pass_proposals"]==[]
assert res["packet_delta"]==0
assert res["canonical_strict_count_untouched"]==91
assert all(c["verdict"]=="REJECT" for c in cases)
assert all(c.get("proposed_pass") is False for c in cases)
assert all(c["gates"][g] in ("PASS","FAIL","NARROW","UNKNOWN","BLOCKED") for c in cases for g in c["gates"])
assert not any(all(v=="PASS" for v in c["gates"].values()) for c in cases)
print("json_ok")
PY

expect_hash() {
  local got
  got=$(/usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}')
  [[ $got == "$2" ]] || fail "hash $1 $got != $2"
}

expect_hash "$CONTRACT" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$LEDGER" 70b7658fadf41f18c72734a2006601961a2180681bf81353373bccab95ff659e
expect_hash "$SUMMARY" ab47f927a20f374a9b0e3253a1a5a0778e355dda9414189927022325d81ad86f

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0)
gitx() {
  local repo=$1
  shift
  local errf rc
  errf=$(mktemp /tmp/unseen20-giterr.XXXXXX)
  setopt localoptions noerrexit
  "${git_cmd[@]}" -C "$repo" "$@" 2>"$errf"
  rc=$?
  if [[ -s $errf ]]; then
    /usr/bin/grep -vE 'unable to normalize alternate object path|lazy fetching disabled' "$errf" >&2 || true
  fi
  rm -f "$errf"
  return $rc
}

head_n=$(gitx "$ADV" rev-parse HEAD)
[[ $head_n == f2c6ab3202aeafb36fbea6e76d892532acfca1a6 ]] || fail "advisory head $head_n"

check_atomic_anc() {
  local repo=$1 ai=$2 fix=$3
  gitx "$repo" cat-file -t "$ai" | grep -qx commit || fail "missing ai $ai"
  gitx "$repo" cat-file -t "$fix" | grep -qx commit || fail "missing fix $fix"
  local parents
  parents=$(gitx "$repo" rev-list --parents -n 1 "$ai")
  [[ $parents == "$ai "* && $parents != *" "*" "* ]] || fail "not atomic $ai $parents"
  gitx "$repo" merge-base --is-ancestor "$ai" "$fix" || fail "not ancestor $ai $fix"
}

check_atomic_anc "$KUMA" a7a023a7b9a7ae1a2cb9c63dc34f1e46930b0edd 8fefa8595d44eb68d922405702ed7a0826322907
check_atomic_anc "$OTEL" 4c49f605a16fed0c48e115d38938b1c6ba5152b5 f5a4ec123769096ad9a4930ede56588b0fee40f3
check_atomic_anc "$BLAZE" 3f34e690851529ccdb7b98d35932bd62749b8061 9fe5ed70f063c18fd6b64bb4db3cbdb612f653d4
check_atomic_anc "$MAXM" 11fc430078dbdd04595b923c7f7216b0dc93e61f 98f0e4fff9678c841ed33f3b8a46322f6163c32a
check_atomic_anc "$PGAD" b3aa78c0a59747e758ef4bbfd49589ff4fcb6631 24485fe9649860dcb632bb8029d4fa8efbafbc04

gitx "$KUMA" grep -q LocalhostIsAdmin a7a023a7b9a7ae1a2cb9c63dc34f1e46930b0edd^ -- pkg/config/api-server/config.go || fail "kuma parent localhost"
gitx "$OTEL" merge-base --is-ancestor f5a4ec123769096ad9a4930ede56588b0fee40f3 3.1520.vd981c197a_43f && fail "otel fix should be absent from 3.1520"
gitx "$BLAZE" merge-base --is-ancestor 3f34e690851529ccdb7b98d35932bd62749b8061 BlazeMeterJenkinsPlugin-4.26 && fail "blaze cand should be absent from 4.26"
gitx "$MAXM" merge-base --is-ancestor 98f0e4fff9678c841ed33f3b8a46322f6163c32a v0.27.0 || fail "maxmind fix in v0.27.0"
gitx "$PGAD" merge-base --is-ancestor b3aa78c0a59747e758ef4bbfd49589ff4fcb6631 REL-9_14 || fail "pgadmin cand in 9.14"
gitx "$PGAD" merge-base --is-ancestor 24485fe9649860dcb632bb8029d4fa8efbafbc04 REL-9_14 && fail "pgadmin fix should be absent from 9.14"
gitx "$PGAD" grep -q ollama_api_url b3aa78c0a59747e758ef4bbfd49589ff4fcb6631^ -- web/pgadmin/llm/__init__.py || fail "pgadmin parent ollama url"

python3 - "$OWNED" <<'PY' || fail "artifact hash mismatch"
import hashlib, json, sys
from pathlib import Path
d=Path(sys.argv[1])
res=json.loads((d/"result.json").read_text())
for rel, expect in res["artifact_hashes"].items():
    got=hashlib.sha256((d/rel).read_bytes()).hexdigest()
    if got!=expect:
        raise SystemExit(f"{rel} {got} != {expect}")
print("hashes_ok")
PY

print "REPLAY_OK reviewed=5 PASS_proposal=0 REJECT=5 packet_delta=0 canonical_strict=91"
