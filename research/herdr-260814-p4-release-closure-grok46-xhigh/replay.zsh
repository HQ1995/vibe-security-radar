#!/usr/bin/env zsh
set -euo pipefail
OWN="$(cd -- "$(dirname -- "$0")" && pwd)"
export GIT_NO_LAZY_FETCH=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
git_cmd=(/usr/bin/git --no-optional-locks -c gc.auto=0 -c maintenance.auto=false)

fail() { echo "REPLAY_FAIL $*" >&2; exit 1; }
anc() { "${git_cmd[@]}" -C "$1" merge-base --is-ancestor "$2" "$3"; }
not_anc() { if anc "$1" "$2" "$3"; then fail "$4"; fi }

E=/home/hanqing/.cache/cve-analyzer/repos/electron_electron
M=/home/hanqing/.cache/cve-analyzer/repos/mermaid-js_mermaid
U=/home/hanqing/.cache/cve-analyzer/repos/nodejs_undici
S=/home/hanqing/.cache/cve-analyzer/repos/seaweedfs_seaweedfs
O=/home/hanqing/.cache/cve-analyzer/repos/open-webui_open-webui
MX=/home/hanqing/.cache/cve-analyzer/repos/matrix-org_matrix-rust-sdk
N=/home/hanqing/.cache/cve-analyzer/repos/netty_netty
K=/home/hanqing/.cache/cve-analyzer/repos/keycloak_keycloak
EK=/home/hanqing/.cache/cve-analyzer/repos/lf-edge_ekuiper
N8=/home/hanqing/.cache/cve-analyzer/repos/n8n-io_n8n

for p in "$E" "$M" "$U" "$S" "$O" "$MX" "$N" "$K" "$EK" "$N8"; do
  [[ -d "$p/.git" || -f "$p/HEAD" || -d "$p" ]] || fail "missing clone $p"
done

CAND_E=fe477ce3aa65316f4e63b0907d117723a1d4c8bc
FIX_4F78=969741f9f847c5c583f6bbc63ca22549dbd954ce
FIX_F2R8=10fb5b39c5287f70c4bbcab4c24197f3871ec322
CAND_M=dea0572457f903295d41c92efcaf1f52a6a377d9
FIX_M=2cd6dcf735533b323507e3e889ffdea870540b43
CAND_U=90775009148e5956ac58ace0eb493001db8b2b7c
FIX_U85=85a240551c9feb8b8a0ecc56c84b2b3015add8a9
FIX_UCB=cb105d7c79069150982fa11acada0dd94a60dbbc
CAND_S=10a30a83e1bdfca25c19506ef4d0d39d22e17628
FIX_S=dd1b4287899eed3dfd73c2f3b1de001996fda229
CAND_O=823b9a6dd96e51d6bbb5e162d13ae043fcf59408
FIX_O=b190dcf3caa00dc8b7b9c7312828298d9143f60d
CAND_MX=ce3b67f801446387972ff120e907ca828a9f1207
REAL_MX=476fe5f9d2bc4c7c7dde62875311d37d419f354f
CAND_N=1782e8c2060a244c4d4e6f9d9112d5517ca05120
CAND_K=754c070cf8ca187dcc71f0f72ff3130ff2195328
CAND_EK=58362b089c76f08c400fe0dbb3667e6e871eaffd
CAND_N8=ae0669a736cc496beeb296e115267862727ae838

# GHSA-4F78: same-line 41.x peel, not cartesian 42.x
anc "$E" "$CAND_E" v41.0.0 || fail "4F78 cand not in v41.0.0"
not_anc "$E" "$FIX_4F78" v41.0.0 "4F78 closer in v41.0.0"
anc "$E" "$FIX_4F78" v41.2.0 || fail "4F78 closer not in v41.2.0"
"${git_cmd[@]}" -C "$E" grep -q 'dock_state_' "$CAND_E^" -- shell/browser/ui/inspectable_web_contents.cc || fail "4F78 parent missing dock_state_"
"${git_cmd[@]}" -C "$E" grep -q 'kValidDockStates' v41.2.0 -- shell/browser/ui/inspectable_web_contents.cc || fail "4F78 v41.2.0 missing allowlist"
if "${git_cmd[@]}" -C "$E" grep -q 'kValidDockStates' v41.0.0 -- shell/browser/ui/inspectable_web_contents.cc; then fail "4F78 allowlist already in v41.0.0"; fi
e_parents=$("${git_cmd[@]}" -C "$E" rev-list --parents -n 1 "$CAND_E")
[[ "$e_parents" == "$CAND_E bab6bd3dae351d8f49203a26468d58482f754c84" ]] || fail "electron true parent"

# GHSA-F2R8: listed closer 10fb5b39 on 42.x
anc "$E" "$CAND_E" v42.0.0-alpha.1 || fail "F2R8 cand not in v42.0.0-alpha.1"
not_anc "$E" "$FIX_F2R8" v42.0.0-alpha.1 "F2R8 listed closer in v42.0.0-alpha.1"
anc "$E" "$FIX_F2R8" v42.0.0-beta.3 || fail "F2R8 listed closer not in v42.0.0-beta.3"
"${git_cmd[@]}" -C "$E" grep -q 'OpenPath' v42.0.0-alpha.1 -- shell/browser/ui/inspectable_web_contents.cc || fail "F2R8 alpha missing OpenPath"
if "${git_cmd[@]}" -C "$E" grep -q 'OpenPath' v42.0.0-beta.3 -- shell/browser/ui/inspectable_web_contents.cc; then fail "F2R8 beta.3 still OpenPath"; fi
"${git_cmd[@]}" -C "$E" grep -q 'OpenPath' "$CAND_E^" -- shell/browser/ui/inspectable_web_contents.cc || fail "F2R8 parent missing OpenPath"

# GHSA-C4C3: mermaid tags on cve-analyzer clone
anc "$M" "$CAND_M" 'mermaid@11.16.0' || fail "mermaid cand not in 11.16.0"
not_anc "$M" "$FIX_M" 'mermaid@11.16.0' "mermaid closer in 11.16.0"
anc "$M" "$FIX_M" 'mermaid@11.16.1' || fail "mermaid closer not in 11.16.1"
if "${git_cmd[@]}" -C "$M" diff --name-only "$CAND_M^" "$CAND_M" | grep -q assignWithDepth; then fail "mermaid cand touched assignWithDepth"; fi
m_parents=$("${git_cmd[@]}" -C "$M" rev-list --parents -n 1 "$CAND_M")
[[ "$m_parents" == "$CAND_M 980db3f8510d007c0941aee2c8f3356aa49eba62" ]] || fail "mermaid true parent"

# GHSA-JR45: local 7.x peel plus fetched advisory tags
anc "$U" "$CAND_U" v7.24.5 || fail "undici cand not in v7.24.5"
not_anc "$U" "$FIX_U85" v7.24.5 "undici 85 in v7.24.5"
anc "$U" "$FIX_U85" v7.28.0 || fail "undici 85 not in v7.28.0"
anc "$U" "$CAND_U" v8.0.0 || fail "undici cand not in v8.0.0"
not_anc "$U" "$FIX_UCB" v8.0.0 "undici cb in v8.0.0"
anc "$U" "$FIX_UCB" v8.5.0 || fail "undici cb not in v8.5.0"
if "${git_cmd[@]}" -C "$U" diff --name-only "$CAND_U^" "$CAND_U" | grep -q 'lib/util/cache.js'; then fail "undici cand touched cache.js"; fi

WORKDIR="$OWN/work/clones"
mkdir -p "$WORKDIR"
clone_fetch() {
  local name="$1" src="$2" url="$3"
  shift 3
  local dest="$WORKDIR/$name"
  if [[ ! -d "$dest/.git" ]]; then
    "${git_cmd[@]}" clone --no-checkout --shared "$src" "$dest"
  fi
  "${git_cmd[@]}" -C "$dest" remote get-url github >/dev/null 2>&1 || "${git_cmd[@]}" -C "$dest" remote add github "$url"
  "${git_cmd[@]}" -C "$dest" fetch --no-recurse-submodules --no-tags github "$@"
}

clone_fetch undici "$U" https://github.com/nodejs/undici.git tag v7.29.0 tag v8.9.0
UN="$WORKDIR/undici"
anc "$UN" "$CAND_U" v7.29.0 || fail "undici cand not in fetched v7.29.0"
anc "$UN" "$FIX_U85" v7.29.0 || fail "undici 85 not in fetched v7.29.0"
anc "$UN" "$CAND_U" v8.9.0 || fail "undici cand not in fetched v8.9.0"
anc "$UN" "$FIX_UCB" v8.9.0 || fail "undici cb not in fetched v8.9.0"
[[ "$("${git_cmd[@]}" -C "$UN" rev-parse v7.29.0)" == 9e38fc121d2eb26086d41c7d9379b47a6fada1c5 ]] || fail "undici v7.29.0 sha"
[[ "$("${git_cmd[@]}" -C "$UN" rev-parse v8.9.0)" == 21a8e1ed1843e74c3004a2926c12bb0ceaca6b71 ]] || fail "undici v8.9.0 sha"

# GHSA-W62W: 4.29 without closer, 4.30 with closer
anc "$S" "$CAND_S" 4.29 || fail "seaweed cand not in 4.29"
not_anc "$S" "$FIX_S" 4.29 "seaweed closer in 4.29"
anc "$S" "$FIX_S" 4.30 || fail "seaweed closer not in 4.30"
[[ "$("${git_cmd[@]}" -C "$S" rev-parse 4.29)" == 1355c7a102194d6c461baf090eff50367b575afb ]] || fail "seaweed 4.29 sha"
"${git_cmd[@]}" -C "$S" grep -q 'SkipClean(true)' "$CAND_S^" -- weed/command/s3.go || fail "seaweed parent missing SkipClean"

# GHSA-RQ84: fetch v0.11.0
clone_fetch open-webui "$O" https://github.com/open-webui/open-webui.git tag v0.11.0 tag v0.10.0 tag v0.9.0
OW="$WORKDIR/open-webui"
anc "$O" "$CAND_O" v0.8.0 || fail "openwebui cand not in v0.8.0"
not_anc "$O" "$FIX_O" v0.8.0 "openwebui closer in v0.8.0"
anc "$OW" "$CAND_O" v0.10.0 || fail "openwebui cand not in v0.10.0"
not_anc "$OW" "$FIX_O" v0.10.0 "openwebui closer in v0.10.0"
anc "$OW" "$FIX_O" v0.11.0 || fail "openwebui closer not in v0.11.0"
[[ "$("${git_cmd[@]}" -C "$OW" rev-parse v0.11.0)" == f9590b8017199e56d5e953657e6498e3cef1d246 ]] || fail "openwebui v0.11.0 sha"
"${git_cmd[@]}" -C "$O" diff "$CAND_O^" "$CAND_O" -- backend/open_webui/models/auths.py | grep -q SRC_LOG_LEVELS || fail "openwebui auths not log-level"

# GHSA-QHJ8: changelog-only; 0.14.1 does not contain assigned SHA; real closer is 476fe5f9
mx_files=$("${git_cmd[@]}" -C "$MX" diff --name-only "$CAND_MX^" "$CAND_MX")
[[ "$mx_files" == "bindings/matrix-sdk-ffi/CHANGELOG.md" ]] || fail "matrix not changelog-only"
not_anc "$MX" "$CAND_MX" matrix-sdk-base-0.14.1 "QHJ8 assigned SHA in 0.14.1"
anc "$MX" "$REAL_MX" matrix-sdk-base-0.14.1 || fail "QHJ8 real closer not in 0.14.1"
not_anc "$MX" "$REAL_MX" matrix-sdk-base-0.14.0 "QHJ8 real closer in 0.14.0"
anc "$MX" "$CAND_MX" matrix-sdk-base-0.16.0 || fail "QHJ8 assigned SHA not in 0.16.0"

# GHSA-JQ43: same first tag 4.2.7.Final
not_anc "$N" "$CAND_N" netty-4.2.6.Final "netty closer in 4.2.6"
anc "$N" "$CAND_N" netty-4.2.7.Final || fail "netty closer not in 4.2.7"
"${git_cmd[@]}" -C "$N" show -s --format='%an' "$CAND_N" | grep -q 'DepthFirst' || fail "netty author"

# GHSA-4HX9: same first tag 26.4.6
not_anc "$K" "$CAND_K" 26.4.5 "keycloak closer in 26.4.5"
anc "$K" "$CAND_K" 26.4.6 || fail "keycloak closer not in 26.4.6"
"${git_cmd[@]}" -C "$K" show -s --format='%s' "$CAND_K" | grep -q 'LDAP URL' || fail "keycloak subject"

# GHSA-RJ4J: named 2.3.0 lacks SHA; first tag v2.4.0-alpha.2
not_anc "$EK" "$CAND_EK" v2.3.0 "ekuiper SHA in v2.3.0"
not_anc "$EK" "$CAND_EK" v2.4.0-alpha.1 "ekuiper SHA in v2.4.0-alpha.1"
anc "$EK" "$CAND_EK" v2.4.0-alpha.2 || fail "ekuiper SHA not in v2.4.0-alpha.2"
[[ "$("${git_cmd[@]}" -C "$EK" rev-parse v2.3.0)" == bda2bbcc6120804810ac9cf6a9366f5d11e9f68b ]] || fail "ekuiper v2.3.0 sha"
[[ "$("${git_cmd[@]}" -C "$EK" rev-parse v2.4.0-alpha.2)" == 5619323822bf34c24c44d7c86f0f0950556d2993 ]] || fail "ekuiper alpha.2 sha"
"${git_cmd[@]}" -C "$EK" show -s --format='%s' "$CAND_EK" | grep -q 'path validation' || fail "ekuiper subject"

# GHSA-7C4H: same first tag n8n@1.120.3
not_anc "$N8" "$CAND_N8" 'n8n@1.120.2' "n8n closer in 1.120.2"
anc "$N8" "$CAND_N8" 'n8n@1.120.3' || fail "n8n closer not in 1.120.3"
"${git_cmd[@]}" -C "$N8" show -s --format='%s' "$CAND_N8" | grep -q 'package version' || fail "n8n subject"

# conservation: 11 rows, no KEEP
[[ "$(wc -l < "$OWN/cases.jsonl" | tr -d ' ')" == 11 ]] || fail "cases.jsonl row count"
if grep -q '"final_verdict":"KEEP"' "$OWN/cases.jsonl"; then fail "KEEP present"; fi
if grep -q '"final_verdict":"UNKNOWN"' "$OWN/cases.jsonl"; then fail "UNKNOWN present"; fi
if grep -q 'GHSA-87X5-VMC3-756J' "$OWN/cases.jsonl"; then fail "reopened 87X5"; fi
if grep -q 'GHSA-XC48-889X-5QMW' "$OWN/cases.jsonl"; then fail "reopened XC48"; fi
if grep -q 'GHSA-26GQ-GRMH-6XM6' "$OWN/cases.jsonl"; then fail "reopened 26GQ"; fi

rm -rf "$OWN/work/clones" "$OWN/work/pages"
echo "REPLAY_OK reviewed=11 KEEP=0 REJECT=11 UNKNOWN=0 PASS_PROPOSAL=0 packet_delta=0 current_leader_accepted_count=85"
