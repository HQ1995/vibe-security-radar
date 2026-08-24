#!/usr/bin/env zsh
# Fail-fast zsh replay for herdr-260814-v52w-hostile-grok46-low.
# English only. Do not print credentials. Do not clone, commit, or push.
# git_cmd is a zsh array expanded with "${git_cmd[@]}".
# KEEP is a proposal. Packet delta is 0. This script does not admit GHSA-V52W.
set -euo pipefail
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0

ROOT=/home/hanqing/agents/ai-slop
OWNED=$ROOT/autoresearch/herdr-260814-v52w-hostile-grok46-low
REPO=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kozou-dev__kozou
ADV=/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/06/GHSA-v52w-28xh-v562/GHSA-v52w-28xh-v562.json

git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false -c advice.detachedHead=false)

CAND=4f86724bd112b07e68033098562c1c4ddc37d93b
PARENT=c84c70c7088f70718a5411d4ef20fabbfe3a429c
SQUASH=bc9dc69d62aaa567a2ccefee12d28a58b96d96c4
FIX=7c3ae2e3b7c996571acc07c96222b6dc2de01a3e
PR11=088497087274c822a64be1cdf7598eb0f511657f
V180=e631527918dc2e90c3f324d64af6cf75db8f8aa2
V181=17f3207e24ca0e7858d6836824539bfb0628415b
BLOB_INTRO=1c4a96662fa37741472954bae28a834156802ded
BLOB_V180=9643e54351d621ce8af90ef5b8f8365d6b9cd643
BLOB_FIX=91cc618dbf3ccc448f13deb0e72e0f48b7616898
TREE=c743d1b43bd3739c9a255d4f3520361e2a373ba6
FILE=packages/mcp/src/startHttpServer.ts

TMP=$(mktemp -d /tmp/v52w-replay.XXXXXX)
cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

require_dir() {
  if [[ ! -d $1 ]]; then
    printf 'missing directory: %s\n' "$1" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f $1 ]]; then
    printf 'missing file: %s\n' "$1" >&2
    exit 1
  fi
}

expect_eq() {
  local got=$1 expected=$2 label=$3
  if [[ $got != "$expected" ]]; then
    printf 'mismatch %s\n expected %s\n got      %s\n' "$label" "$expected" "$got" >&2
    exit 1
  fi
}

expect_hash() {
  local target=$1 expected=$2
  local got
  got=$(/usr/bin/sha256sum "$target" | /usr/bin/awk '{print $1}')
  expect_eq "$got" "$expected" "$target"
}

gitx() {
  local repo=$1
  shift
  "${git_cmd[@]}" -C "$repo" "$@"
}

require_dir "$OWNED"
require_dir "$REPO"
require_file "$ADV"
require_file "$OWNED/case.json"
require_file "$OWNED/result.json"
require_file "$OWNED/report.md"

expect_hash "$ADV" 5a3fd521f60310ef71eff595cf1959a999b5c73fdab83a08c08cba5b4df3e59b
expect_hash "$ROOT/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md" cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3
expect_hash "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl" 2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568

/usr/bin/python3 - "$ADV" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d["id"]=="GHSA-v52w-28xh-v562"
assert d.get("withdrawn_at") is None
assert d["database_specific"]["github_reviewed"] is True
assert "MCP HTTP server lacked DNS-rebinding" in d["details"]
assert "Unbounded request-body buffering" in d["details"]
print("advisory_ok")
PY

expect_eq "$(gitx "$REPO" rev-parse "$CAND^")" "$PARENT" cand_parent
expect_eq "$(gitx "$REPO" rev-parse "$SQUASH^")" "$PARENT" squash_parent
expect_eq "$(gitx "$REPO" rev-parse "$CAND^{tree}")" "$TREE" cand_tree
expect_eq "$(gitx "$REPO" rev-parse "$SQUASH^{tree}")" "$TREE" squash_tree
expect_eq "$(gitx "$REPO" rev-parse "$CAND:$FILE")" "$BLOB_INTRO" cand_blob
expect_eq "$(gitx "$REPO" rev-parse "$SQUASH:$FILE")" "$BLOB_INTRO" squash_blob
expect_eq "$(gitx "$REPO" rev-parse "$FIX:$FILE")" "$BLOB_FIX" fix_blob
expect_eq "$(gitx "$REPO" rev-parse "$V180:$FILE")" "$BLOB_V180" v180_blob
expect_eq "$(gitx "$REPO" rev-parse "$V181:$FILE")" "$BLOB_FIX" v181_blob

if gitx "$REPO" cat-file -e "$PARENT:$FILE" 2>/dev/null; then
  printf 'parent unexpectedly has %s\n' "$FILE" >&2
  exit 1
fi

gitx "$REPO" merge-base --is-ancestor "$SQUASH" "$FIX"
gitx "$REPO" merge-base --is-ancestor "$FIX" "$V181"
if gitx "$REPO" merge-base --is-ancestor "$CAND" origin/main; then
  printf 'candidate unexpectedly on main\n' >&2
  exit 1
fi
if gitx "$REPO" merge-base --is-ancestor "$FIX" "$V180"; then
  printf 'fix unexpectedly in v1.8.0\n' >&2
  exit 1
fi

gitx "$REPO" log -1 --format=%B "$CAND" | /usr/bin/grep -F 'Co-Authored-By: Claude Opus 4.7' >/dev/null
gitx "$REPO" log -1 --format=%B "$CAND" | /usr/bin/grep -F 'Codex 5th-pass N2' >/dev/null
gitx "$REPO" log -1 --format=%s "$CAND" | /usr/bin/grep -F '(#11)' >/dev/null
gitx "$REPO" log -1 --format=%s "$SQUASH" | /usr/bin/grep -F '(#20)' >/dev/null

if gitx "$REPO" show "$CAND:$FILE" | /usr/bin/grep -F 'allowedHosts' >/dev/null; then
  printf 'cand has allowedHosts\n' >&2
  exit 1
fi
gitx "$REPO" show "$CAND:$FILE" | /usr/bin/grep -F 'for await (const chunk of req)' >/dev/null
if gitx "$REPO" show "$V180:$FILE" | /usr/bin/grep -F 'allowedHosts' >/dev/null; then
  printf 'v180 has allowedHosts\n' >&2
  exit 1
fi
gitx "$REPO" show "$V181:$FILE" | /usr/bin/grep -F 'allowedHosts' >/dev/null
gitx "$REPO" show "$V181:$FILE" | /usr/bin/grep -F 'maxBodyBytes' >/dev/null

/usr/bin/python3 - "$ROOT/autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl" "$ROOT/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl" <<'PY'
import sys
from pathlib import Path
for p in sys.argv[1:]:
    t=Path(p).read_text()
    if 'GHSA-V52W' in t.upper() or 'GHSA-v52w' in t:
        raise SystemExit(f'uniqueness hit in {p}')
print('uniqueness_ok')
PY

"${git_cmd[@]}" ls-remote https://github.com/kozou-dev/kozou.git refs/pull/11/head refs/pull/20/head refs/tags/v1.8.0 refs/tags/v1.8.1^{} >"$TMP/ls-remote.txt"
/usr/bin/grep -F "$PR11	refs/pull/11/head" "$TMP/ls-remote.txt" >/dev/null
/usr/bin/grep -F "$CAND	refs/pull/20/head" "$TMP/ls-remote.txt" >/dev/null
/usr/bin/grep -F "$V181	refs/tags/v1.8.1^{}" "$TMP/ls-remote.txt" >/dev/null

# peel PR11 file list in a throwaway fetch
"${git_cmd[@]}" init -q "$TMP/pr11"
"${git_cmd[@]}" -C "$TMP/pr11" remote add origin https://github.com/kozou-dev/kozou.git
"${git_cmd[@]}" -C "$TMP/pr11" fetch --quiet --filter=blob:none --depth=1 origin "$PR11"
if "${git_cmd[@]}" -C "$TMP/pr11" cat-file -e "$PR11:$FILE" 2>/dev/null; then
  printf 'PR11 unexpectedly has startHttpServer\n' >&2
  exit 1
fi

/usr/bin/curl -fsSL -A 'ai-slop-research' -o "$TMP/pr20.html" 'https://github.com/kozou-dev/kozou/pull/20/commits'
/usr/bin/grep -F '1 commit' "$TMP/pr20.html" >/dev/null

/usr/bin/curl -fsSL -A 'ai-slop-research' -o "$TMP/npm180.json" 'https://registry.npmjs.org/@kozou/mcp/1.8.0'
/usr/bin/curl -fsSL -A 'ai-slop-research' -o "$TMP/npm181.json" 'https://registry.npmjs.org/@kozou/mcp/1.8.1'
TB180=$(/usr/bin/python3 -c 'import json;print(json.load(open("'"$TMP"'/npm180.json"))["dist"]["tarball"])')
TB181=$(/usr/bin/python3 -c 'import json;print(json.load(open("'"$TMP"'/npm181.json"))["dist"]["tarball"])')
/usr/bin/curl -fsSL -o "$TMP/mcp180.tgz" "$TB180"
/usr/bin/curl -fsSL -o "$TMP/mcp181.tgz" "$TB181"
expect_hash "$TMP/mcp180.tgz" bf19ad97d101a2a08327811c9b91aee9c38eb3d48be633a2d1511e79e52d6ff2
expect_hash "$TMP/mcp181.tgz" d785844b2c97d7c274a5fc5b08523daaab9338fd181b251b6d818a27f51b7eb8
mkdir -p "$TMP/e180" "$TMP/e181"
/usr/bin/tar -xzf "$TMP/mcp180.tgz" -C "$TMP/e180"
/usr/bin/tar -xzf "$TMP/mcp181.tgz" -C "$TMP/e181"
/usr/bin/grep -F 'for await' "$TMP/e180/package/dist/startHttpServer.js" >/dev/null
if /usr/bin/grep -F 'allowedHosts' "$TMP/e180/package/dist/startHttpServer.js" >/dev/null; then
  printf 'npm 1.8.0 has allowedHosts\n' >&2
  exit 1
fi
/usr/bin/grep -F 'allowedHosts' "$TMP/e181/package/dist/startHttpServer.js" >/dev/null
/usr/bin/grep -F 'maxBodyBytes' "$TMP/e181/package/dist/startHttpServer.js" >/dev/null

printf 'REPLAY_OK reviewed=1 KEEP_proposal=1 REJECT=0 NARROW=0 UNKNOWN=0 BLOCKED=0 packet_delta=0 current_leader_accepted_count=85\n'
